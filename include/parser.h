#ifndef PARSER_H
#define PARSER_H

#include <arpa/inet.h>
#include <stdint.h>

typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char protocol[16];

    uint16_t src_port;
    uint16_t dst_port;

    uint8_t ttl;
    uint16_t ip_header_len;
    uint16_t ip_len;
    uint16_t frame_len;

    uint8_t tcp_syn;
    uint8_t tcp_ack;
    uint8_t tcp_fin;
    uint8_t tcp_rst;
    uint8_t tcp_psh;
    uint8_t tcp_urg;

    uint8_t icmp_type;
    uint8_t icmp_code;

    int valid;
} PacketInfo;

PacketInfo parse_packet(const unsigned char *packet, int packet_len);

#endif
