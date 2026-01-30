#pragma once

#include <stddef.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include "parsers/types.h"

typedef struct packet_ctx packet_ctx_t;

typedef struct {
    transport_protocol_t transport_protocol_t;

    // Addresses are stored in network byte order
    uint32_t source_ip_address;
    uint32_t dest_ip_address;

    char source_ip_address_dotted_quad[INET_ADDRSTRLEN];
    char dest_ip_address_dotted_quad[INET_ADDRSTRLEN];

    bool checksum_is_valid;
    
    const unsigned char* payload;
    size_t payload_len;
} ipv4_result_t;

parse_status_t parse_ipv4_header(packet_ctx_t* packet_ctx);