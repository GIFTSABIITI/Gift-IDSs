#include "parser.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TCP_HEADER_MIN_LEN 20
#define UDP_HEADER_LEN 8
#define ICMP_HEADER_MIN_LEN 8

static int has_bytes(int packet_len, int offset, size_t needed)
{
    if (packet_len < 0 || offset < 0 || offset > packet_len) {
        return 0;
    }

    return (size_t)(packet_len - offset) >= needed;
}

static uint16_t read_u16_network_order(const unsigned char *bytes)
{
    uint16_t value;

    memcpy(&value, bytes, sizeof(value));

    /*
     * Network packets store multi-byte numbers in network byte order.
     * ntohs() converts a 16-bit value from network order to this computer's
     * host byte order so port numbers and lengths print correctly.
     */
    return ntohs(value);
}

static PacketInfo empty_packet_info(int packet_len)
{
    PacketInfo info;

    memset(&info, 0, sizeof(info));
    if (packet_len > UINT16_MAX) {
        info.frame_len = UINT16_MAX;
    } else if (packet_len > 0) {
        info.frame_len = (uint16_t)packet_len;
    }

    return info;
}

static void parse_tcp(const unsigned char *packet, int packet_len, int offset, PacketInfo *info)
{
    const unsigned char *tcp_header;
    uint8_t tcp_header_len;
    uint8_t flags;

    /*
     * Bounds checking matters because captured frames can be malformed or
     * truncated. Reading past the captured buffer could crash the program.
     */
    if (!has_bytes(packet_len, offset, TCP_HEADER_MIN_LEN)) {
        return;
    }

    tcp_header = packet + offset;
    tcp_header_len = (uint8_t)((tcp_header[12] >> 4) * 4);
    if (tcp_header_len < TCP_HEADER_MIN_LEN || !has_bytes(packet_len, offset, tcp_header_len)) {
        return;
    }

    /*
     * TCP and UDP ports are 16-bit network-order values at the start of the
     * transport header.
     */
    info->src_port = read_u16_network_order(tcp_header);
    info->dst_port = read_u16_network_order(tcp_header + 2);

    flags = tcp_header[13];
    info->tcp_fin = (flags & 0x01) ? 1 : 0;
    info->tcp_syn = (flags & 0x02) ? 1 : 0;
    info->tcp_rst = (flags & 0x04) ? 1 : 0;
    info->tcp_psh = (flags & 0x08) ? 1 : 0;
    info->tcp_ack = (flags & 0x10) ? 1 : 0;
    info->tcp_urg = (flags & 0x20) ? 1 : 0;
    info->valid = 1;
}

static void parse_udp(const unsigned char *packet, int packet_len, int offset, PacketInfo *info)
{
    const unsigned char *udp_header;
    uint16_t udp_len;

    if (!has_bytes(packet_len, offset, UDP_HEADER_LEN)) {
        return;
    }

    udp_header = packet + offset;
    udp_len = read_u16_network_order(udp_header + 4);
    if (udp_len < UDP_HEADER_LEN) {
        return;
    }

    info->src_port = read_u16_network_order(udp_header);
    info->dst_port = read_u16_network_order(udp_header + 2);
    info->valid = 1;
}

static void parse_icmp(const unsigned char *packet, int packet_len, int offset, PacketInfo *info)
{
    const unsigned char *icmp_header;

    if (!has_bytes(packet_len, offset, ICMP_HEADER_MIN_LEN)) {
        return;
    }

    /*
     * For this learning phase we only need the first ICMP fields: type and
     * code. Type 8, for example, is an echo request used by ping.
     */
    icmp_header = packet + offset;
    info->icmp_type = icmp_header[0];
    info->icmp_code = icmp_header[1];
    info->valid = 1;
}

PacketInfo parse_packet(const unsigned char *packet, int packet_len)
{
    PacketInfo info = empty_packet_info(packet_len);
    const struct ethhdr *eth_header;
    const struct iphdr *ip_header;
    uint16_t ether_type;
    uint16_t ip_header_len;
    uint16_t ip_total_len;
    int ip_offset = (int)sizeof(struct ethhdr);
    int ip_end;
    int transport_offset;

    if (packet == NULL) {
        return info;
    }

    /*
     * Ethernet header parsing:
     * Every Ethernet frame starts with destination MAC, source MAC, and
     * EtherType. EtherType tells us what kind of payload follows.
     */
    if (!has_bytes(packet_len, 0, sizeof(struct ethhdr))) {
        return info;
    }

    eth_header = (const struct ethhdr *)packet;
    ether_type = ntohs(eth_header->h_proto);

    if (ether_type != ETH_P_IP) {
        return info;
    }

    /*
     * IPv4 header parsing:
     * The IPv4 header comes after the Ethernet header. The IHL field tells us
     * the real IPv4 header length because options can make it larger than 20
     * bytes.
     */
    if (!has_bytes(packet_len, ip_offset, sizeof(struct iphdr))) {
        return info;
    }

    ip_header = (const struct iphdr *)(packet + ip_offset);
    ip_header_len = (uint16_t)(ip_header->ihl * 4);
    ip_total_len = ntohs(ip_header->tot_len);

    if (ip_header->version != 4) {
        return info;
    }

    if (ip_header_len < sizeof(struct iphdr) || ip_total_len < ip_header_len) {
        return info;
    }

    if (!has_bytes(packet_len, ip_offset, ip_total_len)) {
        return info;
    }

    info.ttl = ip_header->ttl;
    info.ip_header_len = ip_header_len;
    info.ip_len = ip_total_len;
    ip_end = ip_offset + (int)ip_total_len;

    /*
     * inet_ntop() converts binary network addresses into readable strings,
     * such as "192.168.1.10".
     */
    if (inet_ntop(AF_INET, &ip_header->saddr, info.src_ip, sizeof(info.src_ip)) == NULL) {
        return info;
    }

    if (inet_ntop(AF_INET, &ip_header->daddr, info.dst_ip, sizeof(info.dst_ip)) == NULL) {
        return info;
    }

    transport_offset = ip_offset + ip_header_len;

    /*
     * TCP, UDP, and ICMP parsing:
     * The IPv4 protocol field tells us which transport header comes next.
     * Unsupported protocols are ignored for now because Phase 4 detection is
     * intentionally out of scope.
     */
    switch (ip_header->protocol) {
    case IPPROTO_TCP:
        snprintf(info.protocol, sizeof(info.protocol), "TCP");
        parse_tcp(packet, ip_end, transport_offset, &info);
        break;
    case IPPROTO_UDP:
        snprintf(info.protocol, sizeof(info.protocol), "UDP");
        parse_udp(packet, ip_end, transport_offset, &info);
        break;
    case IPPROTO_ICMP:
        snprintf(info.protocol, sizeof(info.protocol), "ICMP");
        parse_icmp(packet, ip_end, transport_offset, &info);
        break;
    default:
        return info;
    }

    return info;
}
