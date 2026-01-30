#include "parsers/link/ethernet.h"
#include "parsers/context.h"
#include <stdio.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>

int copy_mac_address(char* dest, unsigned char* bytes){
    return snprintf(
        dest, 
        18, 
        "%02x:%02x:%02x:%02x:%02x:%02x",
        bytes[0],
        bytes[1],
        bytes[2], 
        bytes[3],
        bytes[4], 
        bytes[5]
    );
}

parse_status_t parse_ethernet_header(packet_ctx_t* packet_ctx) {
    if (packet_ctx->remaining_len < sizeof(struct ethhdr)) {
        fprintf(stderr, "Frame too small to contain ethernet header, continuing\n");
        return ERR_TRUNCATED;
    }

    struct ethhdr *ethernet_header = (struct ethhdr *)packet_ctx->current_pos;
    
    if (copy_mac_address(packet_ctx->eth.host_destination, ethernet_header->h_dest) == -1) {
        return ERR_INTENAL; 
    }

    if (copy_mac_address(packet_ctx->eth.host_source, ethernet_header->h_source) == -1) {
        return ERR_INTENAL; 
    }
    
    packet_ctx->current_pos = packet_ctx->current_pos + ETH_HLEN;
    packet_ctx->remaining_len = packet_ctx->remaining_len - ETH_HLEN;

    switch(ntohs(ethernet_header->h_proto)) {
        case(ETH_P_IP):
            packet_ctx->network_protocol = NETWORK_PROTO_IP;
            break;
        case(ETH_P_IPV6):
            packet_ctx->network_protocol = NETWORK_PROTO_IPV6;
            break;
        case(ETH_P_ARP):
            packet_ctx->network_protocol = NETWORK_PROTO_ARP;
            break;
        default:
            packet_ctx->network_protocol = NETWORK_PROTO_OTHER;
            break;
    }

    return PARSE_OK;
}