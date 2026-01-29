#include "parsers/network/ipv4.h"
#include "parsers/context.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "checksum.h"

// static void print_protocol_type(uint8_t byte) {
    // if (byte == IPPROTO_TCP) {
        // printf("TCP");
    // } else if (byte == IPPROTO_UDP) {
        // printf("UDP");
    // } else {
        // printf("Other");
    // }
// }

int parse_ipv4_header(packet_ctx_t* packet_ctx) {
    // Check if version and IHL byte is in packet before accessing memory
    if (packet_ctx->remaining_len < 1) {
        fprintf(stderr, "Packet doesn't contain version/IHL byte in IP header, continuing\n");
        return -1;
    }
    uint8_t ver_ihl = *packet_ctx->current_pos;
    uint8_t ihl = ver_ihl & 0xF; 
    size_t num_bytes_ip_header = ihl*4; // ihl in header represents num of 32 bit words, multiply by 4 to get num bytes
    if (packet_ctx->remaining_len < num_bytes_ip_header) {
        fprintf(stderr, "Packet length not long enough to contain ip header, continuing\n");
        return -1;
    }
    struct iphdr *ip_header = (struct iphdr*) (packet_ctx->current_pos); 
    char source_ip_address[INET_ADDRSTRLEN];
    char dest_ip_address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->saddr), source_ip_address, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dest_ip_address, INET_ADDRSTRLEN);

    packet_ctx->ipv4.source_ip_address = ip_header->saddr;
    packet_ctx->ipv4.dest_ip_address = ip_header->daddr;

    strcpy(packet_ctx->ipv4.source_ip_address_dotted_quad, source_ip_address);
    strcpy(packet_ctx->ipv4.dest_ip_address_dotted_quad, dest_ip_address);

    uint16_t checksum_res = ones_complement_sum((uint16_t*)ip_header, num_bytes_ip_header/2);
    packet_ctx->ipv4.checksum_is_valid = checksum_res == 0;

    // printf("       IP Source Address: ");
    // printf("%s", source_ip_address);
    // printf("\n");
    // printf("       IP Destination Address: ");
    // printf("%s", dest_ip_address);
    // printf("\n");
    // printf("       Protocol Type: ");
    // print_protocol_type(ip_header->protocol);
    // printf("\n");
    // printf("       IP Header Checksum: "); 
    // Including result of checksum in ones complement calculation will always yield 0, use this property for validation
    // uint16_t checksum_res = ones_complement_sum((uint16_t*)ip_header, num_bytes_ip_header/2);
    // if (checksum_res == 0) {
        // printf("VALID");
    // } else {
        // printf("INVALID");
    // }
    // printf("\n");
               
    switch(ip_header->protocol) {
        case(IPPROTO_TCP):
            packet_ctx->transport_protocol = TRANSPORT_PROTO_TCP;
            packet_ctx->current_pos = packet_ctx->current_pos + num_bytes_ip_header;
            packet_ctx->remaining_len = packet_ctx->remaining_len - num_bytes_ip_header;
            return 0;
        default:
            return -1;
    }
}
