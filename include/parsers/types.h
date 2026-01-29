#pragma once

typedef enum {
    NETWORK_PROTO_INVALID = -1,
    NETWORK_PROTO_OTHER = 0, 
    NETWORK_PROTO_IP = 0x0800,
    NETWORK_PROTO_IPV6 = 0x86DD,
    NETWORK_PROTO_ARP = 0x0806
} network_protocol_t;

typedef enum {
    TRANSPORT_PROTO_OTHER = 0,
    TRANSPORT_PROTO_ICMP = 1,
    TRANSPORT_PROTO_TCP = 6,
    TRANSPORT_PROTO_UDP = 17
} transport_protocol_t;

typedef enum {
    PARSE_OK = 0,
    ERR_TRUNCATED,   // Packet shorter than header says
    ERR_BAD_CHECKSUM,
    ERR_UNKNOWN_PROTO,
    ERR_INVALID_VAL
} parse_status_t;