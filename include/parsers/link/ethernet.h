#pragma once

#include <stddef.h>
#include "parsers/types.h"

#define MAC_ADDRESS_LEN 18

typedef struct packet_ctx packet_ctx_t;


typedef struct {
    char host_destination[MAC_ADDRESS_LEN];
    char host_source[MAC_ADDRESS_LEN];
} ethresult_t;

parse_status_t parse_ethernet_header(packet_ctx_t* packet_ctx);