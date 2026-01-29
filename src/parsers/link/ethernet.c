#include "parsers/link/ethernet.h"
#include "parsers/context.h"
#include <stdio.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

// static void print_mac_address(unsigned char* bytes) {
    // printf("%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]); 
// }

int parse_ethernet_header(packet_ctx_t* packet_ctx) {
    if (packet_ctx->remaining_len < sizeof(struct ethhdr)) {
        fprintf(stderr, "Frame too small to contain ethernet header, continuing\n");
        return -1;
    }

    struct ethhdr *ethernet_header = (struct ethhdr *)packet_ctx->current_pos;
    // printf("   Ethernet host destination: ");
    // print_mac_address(ethernet_header->h_dest);
    // printf("\n");
    // printf("   Ethernet host source: "); 
    // print_mac_address(ethernet_header->h_source);
    // printf("\n");
    
    switch(ntohs(ethernet_header->h_proto)) {
        case(ETH_P_IP):
            packet_ctx->network_protocol = NETWORK_PROTO_IP;
            packet_ctx->current_pos = packet_ctx->current_pos + ETH_HLEN;
            packet_ctx->remaining_len = packet_ctx->remaining_len - ETH_HLEN;
            return 0;
        case(ETH_P_IPV6):
            return -1;
        default:
            return -1;
    }
}