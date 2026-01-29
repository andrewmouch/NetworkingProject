#include "parsers/dispatch.h"

void dispatch_link_layer(packet_ctx_t* ctx) {
    parse_ethernet_header(ctx);
}

void dispatch_network_layer(packet_ctx_t* ctx) {
    switch (ctx->network_protocol) {
        case NETWORK_PROTO_IP:
            parse_ipv4_header(ctx);
            break;
        default:
            printf("Unsupported protocol: 0x%04x\n", ctx->network_protocol);
    }
}

void dispatch_transport_layer(packet_ctx_t* ctx) {
    switch (ctx->transport_protocol) {
        case TRANSPORT_PROTO_TCP:
            parse_tcp_header(ctx);
            break;
        default:
            printf("Unsupported protocol: 0x%04x\n", ctx->network_protocol);
    }
}