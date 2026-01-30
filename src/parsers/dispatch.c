#include "parsers/dispatch.h"

void dispatch_link_layer(packet_ctx_t* ctx) {
    // Linux normalizes headers into ethernet framing (irrespective of whether it may be Wi-Fi or another protocol)
    // Hence why I'm able to call parse ethernet header on all the incoming packets
    // I think better practice here is to check the ifreq object to see exactly what protocol/family it is
    // But I don't think we'll ever receive anything other than an ethernet frame
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