#pragma once

#include <stddef.h>

typedef struct packet_ctx packet_ctx_t;

typedef struct {
    const unsigned char* payload;
    size_t payload_len;
} ethresult_t;

int parse_ethernet_header(packet_ctx_t* packet_ctx);