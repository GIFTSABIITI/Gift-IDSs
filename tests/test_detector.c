#include "test_utils.h"

#include "config.h"
#include "detector.h"
#include "parser.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/*
 * Detector tests use fake PacketInfo structs because the detector should not
 * care whether a packet came from a real network card, a PCAP file, or a small
 * test fixture. This keeps rule tests focused and quick.
 */

static GiftIDSConfig test_config(void)
{
    GiftIDSConfig config;

    config_set_defaults(&config);
    config.port_scan_threshold = 3;
    config.port_scan_window_seconds = 10;
    config.syn_flood_threshold = 3;
    config.syn_flood_window_seconds = 10;
    config.icmp_flood_threshold = 3;
    config.icmp_flood_window_seconds = 10;
    config.alert_cooldown_seconds = 0;

    return config;
}

static PacketInfo make_packet(const char *protocol, const char *src_ip, const char *dst_ip)
{
    PacketInfo pkt;

    memset(&pkt, 0, sizeof(pkt));
    pkt.valid = 1;
    pkt.timestamp = 1000;
    snprintf(pkt.protocol, sizeof(pkt.protocol), "%s", protocol);
    snprintf(pkt.src_ip, sizeof(pkt.src_ip), "%s", src_ip);
    snprintf(pkt.dst_ip, sizeof(pkt.dst_ip), "%s", dst_ip);
    return pkt;
}

static PacketInfo make_tcp_syn(const char *src_ip, const char *dst_ip, uint16_t dst_port)
{
    PacketInfo pkt = make_packet("TCP", src_ip, dst_ip);

    pkt.src_port = 40000;
    pkt.dst_port = dst_port;
    pkt.tcp_syn = 1;
    pkt.tcp_ack = 0;
    return pkt;
}

static PacketInfo make_tcp_ack_to_port(uint16_t dst_port)
{
    PacketInfo pkt = make_packet("TCP", "10.0.0.10", "10.0.0.20");

    pkt.src_port = 40000;
    pkt.dst_port = dst_port;
    pkt.tcp_ack = 1;
    return pkt;
}

static PacketInfo make_udp_to_port(uint16_t dst_port)
{
    PacketInfo pkt = make_packet("UDP", "10.0.0.10", "10.0.0.20");

    pkt.src_port = 40000;
    pkt.dst_port = dst_port;
    return pkt;
}

static PacketInfo make_icmp_echo(const char *src_ip, const char *dst_ip)
{
    PacketInfo pkt = make_packet("ICMP", src_ip, dst_ip);

    pkt.icmp_type = 8;
    pkt.icmp_code = 0;
    return pkt;
}

static int test_tcp_syn_watch_rule(void)
{
    GiftIDSConfig config = test_config();
    PacketInfo pkt = make_tcp_syn("10.0.0.1", "10.0.0.2", 8080);
    DetectionResult result;

    TEST_BEGIN("TCP SYN Watch rule");
    detector_init(&config);
    result = detect_packet(&pkt);

    ASSERT_EQ_INT(1, result.alert, "TCP SYN packet should alert");
    ASSERT_STR_EQ("TCP SYN Watch", result.type, "wrong alert type for TCP SYN Watch");
    TEST_PASS();
}

static int test_icmp_echo_request_rule(void)
{
    GiftIDSConfig config = test_config();
    PacketInfo pkt = make_icmp_echo("10.0.0.1", "10.0.0.2");
    DetectionResult result;

    TEST_BEGIN("ICMP Echo Request rule");
    detector_init(&config);
    result = detect_packet(&pkt);

    ASSERT_EQ_INT(1, result.alert, "ICMP echo request should alert");
    ASSERT_STR_EQ("ICMP Echo Request", result.type, "wrong alert type for ICMP echo");
    TEST_PASS();
}

static int test_suspicious_port_rule(void)
{
    GiftIDSConfig config = test_config();
    PacketInfo pkt = make_tcp_ack_to_port(445);
    DetectionResult result;

    TEST_BEGIN("Suspicious Port rule");
    detector_init(&config);
    result = detect_packet(&pkt);

    ASSERT_EQ_INT(1, result.alert, "traffic to port 445 should alert");
    ASSERT_STR_EQ("Suspicious Port", result.type, "wrong alert type for suspicious port");
    TEST_PASS();
}

static int test_port_scan_detection(void)
{
    GiftIDSConfig config = test_config();
    DetectionResult result;
    PacketInfo pkt;

    TEST_BEGIN("Possible Port Scan detection");
    detector_init(&config);

    pkt = make_tcp_syn("10.0.0.3", "10.0.0.4", 8001);
    detect_packet(&pkt);
    pkt = make_tcp_syn("10.0.0.3", "10.0.0.4", 8002);
    detect_packet(&pkt);
    pkt = make_tcp_syn("10.0.0.3", "10.0.0.4", 8003);
    result = detect_packet(&pkt);

    ASSERT_EQ_INT(1, result.alert, "three unique SYN destination ports should alert");
    ASSERT_STR_EQ("Possible Port Scan", result.type, "wrong alert type for port scan");
    TEST_PASS();
}

static int test_syn_flood_detection(void)
{
    GiftIDSConfig config = test_config();
    DetectionResult result;
    PacketInfo pkt;

    TEST_BEGIN("Possible SYN Flood detection");
    detector_init(&config);

    pkt = make_tcp_syn("10.0.0.5", "10.0.0.6", 9000);
    detect_packet(&pkt);
    detect_packet(&pkt);
    result = detect_packet(&pkt);

    ASSERT_EQ_INT(1, result.alert, "three SYN packets to one port should alert");
    ASSERT_STR_EQ("Possible SYN Flood", result.type, "wrong alert type for SYN flood");
    TEST_PASS();
}

static int test_icmp_flood_detection(void)
{
    GiftIDSConfig config = test_config();
    DetectionResult result;
    PacketInfo pkt = make_icmp_echo("10.0.0.7", "10.0.0.8");

    TEST_BEGIN("Possible ICMP Flood detection");
    detector_init(&config);

    detect_packet(&pkt);
    detect_packet(&pkt);
    result = detect_packet(&pkt);

    ASSERT_EQ_INT(1, result.alert, "three ICMP echo requests should alert");
    ASSERT_STR_EQ("Possible ICMP Flood", result.type, "wrong alert type for ICMP flood");
    TEST_PASS();
}

static int test_disabled_tcp_syn_watch_rule(void)
{
    GiftIDSConfig config = test_config();
    PacketInfo pkt = make_tcp_syn("10.0.0.9", "10.0.0.10", 8080);
    DetectionResult result;

    TEST_BEGIN("disabled TCP SYN Watch rule");
    config.enable_tcp_syn_watch_rule = 0;
    detector_init(&config);
    result = detect_packet(&pkt);

    ASSERT_EQ_INT(0, result.alert, "disabled TCP SYN Watch rule should not alert");
    TEST_PASS();
}

static int test_disabled_icmp_echo_rule(void)
{
    GiftIDSConfig config = test_config();
    PacketInfo pkt = make_icmp_echo("10.0.0.11", "10.0.0.12");
    DetectionResult result;

    TEST_BEGIN("disabled ICMP Echo rule");
    config.enable_icmp_echo_rule = 0;
    detector_init(&config);
    result = detect_packet(&pkt);

    ASSERT_EQ_INT(0, result.alert, "disabled ICMP Echo rule should not alert on one packet");
    TEST_PASS();
}

static int test_disabled_suspicious_port_rule(void)
{
    GiftIDSConfig config = test_config();
    PacketInfo pkt = make_udp_to_port(445);
    DetectionResult result;

    TEST_BEGIN("disabled Suspicious Port rule");
    config.enable_suspicious_port_rule = 0;
    detector_init(&config);
    result = detect_packet(&pkt);

    ASSERT_EQ_INT(0, result.alert, "disabled Suspicious Port rule should not alert");
    TEST_PASS();
}

static int test_disabled_port_scan_detection(void)
{
    GiftIDSConfig config = test_config();
    DetectionResult result;
    PacketInfo pkt;

    TEST_BEGIN("disabled Port Scan detection");
    config.enable_port_scan_detection = 0;
    config.enable_syn_flood_detection = 0;
    config.enable_tcp_syn_watch_rule = 0;
    detector_init(&config);

    pkt = make_tcp_syn("10.0.0.13", "10.0.0.14", 8101);
    detect_packet(&pkt);
    pkt = make_tcp_syn("10.0.0.13", "10.0.0.14", 8102);
    detect_packet(&pkt);
    pkt = make_tcp_syn("10.0.0.13", "10.0.0.14", 8103);
    result = detect_packet(&pkt);

    ASSERT_EQ_INT(0, result.alert, "disabled port scan detection should not alert");
    TEST_PASS();
}

static int test_disabled_syn_flood_detection(void)
{
    GiftIDSConfig config = test_config();
    DetectionResult result;
    PacketInfo pkt = make_tcp_syn("10.0.0.15", "10.0.0.16", 9100);

    TEST_BEGIN("disabled SYN Flood detection");
    config.enable_syn_flood_detection = 0;
    config.enable_port_scan_detection = 0;
    config.enable_tcp_syn_watch_rule = 0;
    detector_init(&config);

    detect_packet(&pkt);
    detect_packet(&pkt);
    result = detect_packet(&pkt);

    ASSERT_EQ_INT(0, result.alert, "disabled SYN flood detection should not alert");
    TEST_PASS();
}

static int test_disabled_icmp_flood_detection(void)
{
    GiftIDSConfig config = test_config();
    DetectionResult result;
    PacketInfo pkt = make_icmp_echo("10.0.0.17", "10.0.0.18");

    TEST_BEGIN("disabled ICMP Flood detection");
    config.enable_icmp_flood_detection = 0;
    config.enable_icmp_echo_rule = 0;
    detector_init(&config);

    detect_packet(&pkt);
    detect_packet(&pkt);
    result = detect_packet(&pkt);

    ASSERT_EQ_INT(0, result.alert, "disabled ICMP flood detection should not alert");
    TEST_PASS();
}

static int test_reenabled_rules_trigger_normally(void)
{
    GiftIDSConfig config = test_config();
    PacketInfo pkt = make_tcp_ack_to_port(445);
    DetectionResult result;

    TEST_BEGIN("re-enabled rules trigger normally");
    config.enable_suspicious_port_rule = 1;
    detector_init(&config);
    result = detect_packet(&pkt);

    ASSERT_EQ_INT(1, result.alert, "re-enabled Suspicious Port rule should alert");
    ASSERT_STR_EQ("Suspicious Port", result.type, "wrong alert type after re-enabling rule");
    TEST_PASS();
}

void run_detector_tests(TestStats *stats)
{
    RUN_TEST(stats, test_tcp_syn_watch_rule);
    RUN_TEST(stats, test_icmp_echo_request_rule);
    RUN_TEST(stats, test_suspicious_port_rule);
    RUN_TEST(stats, test_port_scan_detection);
    RUN_TEST(stats, test_syn_flood_detection);
    RUN_TEST(stats, test_icmp_flood_detection);
    RUN_TEST(stats, test_disabled_tcp_syn_watch_rule);
    RUN_TEST(stats, test_disabled_icmp_echo_rule);
    RUN_TEST(stats, test_disabled_suspicious_port_rule);
    RUN_TEST(stats, test_disabled_port_scan_detection);
    RUN_TEST(stats, test_disabled_syn_flood_detection);
    RUN_TEST(stats, test_disabled_icmp_flood_detection);
    RUN_TEST(stats, test_reenabled_rules_trigger_normally);
}
