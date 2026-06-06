#include "test_utils.h"

#include "parser.h"

#include <stdint.h>
#include <string.h>

#define ETH_LEN 14
#define IPV4_LEN 20
#define TCP_LEN 20
#define UDP_LEN 8
#define ICMP_LEN 8

/*
 * Parser tests use raw packet bytes because parsing bugs usually live at byte
 * offsets and length checks. These tiny fixtures make malformed packet cases
 * repeatable without requiring a live interface.
 */

static void set_u16_be(unsigned char *bytes, uint16_t value)
{
    bytes[0] = (unsigned char)((value >> 8) & 0xff);
    bytes[1] = (unsigned char)(value & 0xff);
}

static void fill_ethernet_ipv4(unsigned char *packet, uint8_t protocol, uint16_t ip_total_len)
{
    memset(packet, 0, ETH_LEN + IPV4_LEN);

    packet[12] = 0x08;
    packet[13] = 0x00;

    packet[ETH_LEN + 0] = 0x45;
    set_u16_be(packet + ETH_LEN + 2, ip_total_len);
    packet[ETH_LEN + 8] = 64;
    packet[ETH_LEN + 9] = protocol;

    packet[ETH_LEN + 12] = 192;
    packet[ETH_LEN + 13] = 168;
    packet[ETH_LEN + 14] = 1;
    packet[ETH_LEN + 15] = 10;

    packet[ETH_LEN + 16] = 192;
    packet[ETH_LEN + 17] = 168;
    packet[ETH_LEN + 18] = 1;
    packet[ETH_LEN + 19] = 20;
}

static int test_parse_tcp_packet(void)
{
    unsigned char packet[ETH_LEN + IPV4_LEN + TCP_LEN];
    unsigned char *tcp = packet + ETH_LEN + IPV4_LEN;
    PacketInfo info;

    TEST_BEGIN("parser Ethernet IPv4 TCP");
    fill_ethernet_ipv4(packet, 6, IPV4_LEN + TCP_LEN);
    set_u16_be(tcp, 12345);
    set_u16_be(tcp + 2, 80);
    tcp[12] = 0x50;
    tcp[13] = 0x02;

    info = parse_packet(packet, sizeof(packet));

    ASSERT_EQ_INT(1, info.valid, "TCP packet should parse as valid");
    ASSERT_STR_EQ("TCP", info.protocol, "protocol should be TCP");
    ASSERT_STR_EQ("192.168.1.10", info.src_ip, "wrong TCP source IP");
    ASSERT_STR_EQ("192.168.1.20", info.dst_ip, "wrong TCP destination IP");
    ASSERT_EQ_INT(12345, info.src_port, "wrong TCP source port");
    ASSERT_EQ_INT(80, info.dst_port, "wrong TCP destination port");
    ASSERT_EQ_INT(1, info.tcp_syn, "TCP SYN flag should be set");
    ASSERT_EQ_INT(0, info.tcp_ack, "TCP ACK flag should not be set");

    TEST_PASS();
}

static int test_parse_udp_packet(void)
{
    unsigned char packet[ETH_LEN + IPV4_LEN + UDP_LEN];
    unsigned char *udp = packet + ETH_LEN + IPV4_LEN;
    PacketInfo info;

    TEST_BEGIN("parser Ethernet IPv4 UDP");
    fill_ethernet_ipv4(packet, 17, IPV4_LEN + UDP_LEN);
    set_u16_be(udp, 5353);
    set_u16_be(udp + 2, 53);
    set_u16_be(udp + 4, UDP_LEN);

    info = parse_packet(packet, sizeof(packet));

    ASSERT_EQ_INT(1, info.valid, "UDP packet should parse as valid");
    ASSERT_STR_EQ("UDP", info.protocol, "protocol should be UDP");
    ASSERT_STR_EQ("192.168.1.10", info.src_ip, "wrong UDP source IP");
    ASSERT_STR_EQ("192.168.1.20", info.dst_ip, "wrong UDP destination IP");
    ASSERT_EQ_INT(5353, info.src_port, "wrong UDP source port");
    ASSERT_EQ_INT(53, info.dst_port, "wrong UDP destination port");

    TEST_PASS();
}

static int test_parse_icmp_packet(void)
{
    unsigned char packet[ETH_LEN + IPV4_LEN + ICMP_LEN];
    unsigned char *icmp = packet + ETH_LEN + IPV4_LEN;
    PacketInfo info;

    TEST_BEGIN("parser Ethernet IPv4 ICMP");
    fill_ethernet_ipv4(packet, 1, IPV4_LEN + ICMP_LEN);
    icmp[0] = 8;
    icmp[1] = 0;

    info = parse_packet(packet, sizeof(packet));

    ASSERT_EQ_INT(1, info.valid, "ICMP packet should parse as valid");
    ASSERT_STR_EQ("ICMP", info.protocol, "protocol should be ICMP");
    ASSERT_STR_EQ("192.168.1.10", info.src_ip, "wrong ICMP source IP");
    ASSERT_STR_EQ("192.168.1.20", info.dst_ip, "wrong ICMP destination IP");
    ASSERT_EQ_INT(8, info.icmp_type, "wrong ICMP type");
    ASSERT_EQ_INT(0, info.icmp_code, "wrong ICMP code");

    TEST_PASS();
}

static int test_parse_short_ethernet_header(void)
{
    unsigned char packet[ETH_LEN];
    PacketInfo info;

    TEST_BEGIN("parser truncated Ethernet header");
    memset(packet, 0, sizeof(packet));
    info = parse_packet(packet, ETH_LEN - 1);

    ASSERT_EQ_INT(0, info.valid, "short Ethernet packet should be invalid");
    TEST_PASS();
}

static int test_parse_short_ipv4_header(void)
{
    unsigned char packet[ETH_LEN + IPV4_LEN];
    PacketInfo info;

    TEST_BEGIN("parser truncated IPv4 header");
    memset(packet, 0, sizeof(packet));
    packet[12] = 0x08;
    packet[13] = 0x00;
    info = parse_packet(packet, ETH_LEN + 10);

    ASSERT_EQ_INT(0, info.valid, "short IPv4 packet should be invalid");
    TEST_PASS();
}

static int test_parse_short_tcp_header(void)
{
    unsigned char packet[ETH_LEN + IPV4_LEN + TCP_LEN];
    PacketInfo info;

    TEST_BEGIN("parser truncated TCP header");
    fill_ethernet_ipv4(packet, 6, IPV4_LEN + TCP_LEN - 1);
    packet[ETH_LEN + IPV4_LEN + 12] = 0x50;

    info = parse_packet(packet, ETH_LEN + IPV4_LEN + TCP_LEN - 1);

    ASSERT_EQ_INT(0, info.valid, "short TCP packet should be invalid");
    TEST_PASS();
}

static int test_parse_short_udp_header(void)
{
    unsigned char packet[ETH_LEN + IPV4_LEN + UDP_LEN];
    PacketInfo info;

    TEST_BEGIN("parser truncated UDP header");
    fill_ethernet_ipv4(packet, 17, IPV4_LEN + UDP_LEN - 1);

    info = parse_packet(packet, ETH_LEN + IPV4_LEN + UDP_LEN - 1);

    ASSERT_EQ_INT(0, info.valid, "short UDP packet should be invalid");
    TEST_PASS();
}

static int test_parse_short_icmp_header(void)
{
    unsigned char packet[ETH_LEN + IPV4_LEN + ICMP_LEN];
    PacketInfo info;

    TEST_BEGIN("parser truncated ICMP header");
    fill_ethernet_ipv4(packet, 1, IPV4_LEN + ICMP_LEN - 1);

    info = parse_packet(packet, ETH_LEN + IPV4_LEN + ICMP_LEN - 1);

    ASSERT_EQ_INT(0, info.valid, "short ICMP packet should be invalid");
    TEST_PASS();
}

void run_parser_tests(TestStats *stats)
{
    RUN_TEST(stats, test_parse_tcp_packet);
    RUN_TEST(stats, test_parse_udp_packet);
    RUN_TEST(stats, test_parse_icmp_packet);
    RUN_TEST(stats, test_parse_short_ethernet_header);
    RUN_TEST(stats, test_parse_short_ipv4_header);
    RUN_TEST(stats, test_parse_short_tcp_header);
    RUN_TEST(stats, test_parse_short_udp_header);
    RUN_TEST(stats, test_parse_short_icmp_header);
}
