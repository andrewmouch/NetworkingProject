#define _DEFAULT_SOURCE

#include "parsers/transport/tcp.h"
#include "parsers/context.h"
#include <inttypes.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

void print_tcp_set_flags(uint8_t flags) {
    int first = 1;
    printf("[");
    
    if (flags & TH_FIN) {
        printf("FIN");
        first = 0;
    }
    if (flags & TH_SYN) {
        if (!first) printf(",");
        printf("SYN");
        first = 0;
    }
    if (flags & TH_RST) {
        if (!first) printf(",");
        printf("RST");
        first = 0;
    }
    if (flags & TH_PUSH) {
        if (!first) printf(",");
        printf("PSH");
        first = 0;
    }
    if (flags & TH_ACK) {
        if (!first) printf(",");
        printf("ACK");
        first = 0;
    }
    if (flags & TH_URG) {
        if (!first) printf(",");
        printf("URG");
        first = 0;
    }
    
    if (first) {
        printf("NONE"); 
    }
    
    printf("]");
}

int parse_tcp_header(packet_ctx_t* packet_ctx) {
    if (packet_ctx->remaining_len < sizeof(struct tcphdr)) {
        fprintf(stderr, "Segment too small to contain a tcp header");
        return -1;
    }
    struct tcphdr *tcp_header = (struct tcphdr*) (packet_ctx->current_pos);
    // printf("          TCP Source Port: %" PRIu16 "\n", ntohs(tcp_header->th_sport));
    // printf("          TCP Destination Port: %" PRIu16 "\n", ntohs(tcp_header->th_dport));
    // printf("          TCP Sequence Number: %" PRIu32 "\n", ntohl(tcp_header->th_seq));
    // printf("          TCP Acknowledgement Number: %" PRIu32 "\n", ntohl(tcp_header->th_ack));
    // printf("          TCP Set Flags: ");
    // print_tcp_set_flags(tcp_header->th_flags);
    // printf("\n");
    
    packet_ctx->tcp.source_port = ntohs(tcp_header->th_sport);
    packet_ctx->tcp.dest_port = ntohs(tcp_header->th_dport);
    packet_ctx->tcp.seq_number = ntohl(tcp_header->th_seq);
    packet_ctx->tcp.ack_number = ntohl(tcp_header->th_ack);
    packet_ctx->tcp.flag_syn = tcp_header->th_flags & TH_SYN;
    packet_ctx->tcp.flag_ack = tcp_header->th_flags & TH_ACK;
    packet_ctx->tcp.flag_fin = tcp_header->th_flags & TH_FIN;
    packet_ctx->tcp.flag_rst = tcp_header->th_flags & TH_RST;
    packet_ctx->tcp.flag_psh = tcp_header->th_flags & TH_PUSH;
    packet_ctx->tcp.flag_urg = tcp_header->th_flags & TH_URG;

    return 0;
}