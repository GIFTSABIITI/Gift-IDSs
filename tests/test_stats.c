#include "test_utils.h"

#include "stats.h"

#include <stdio.h>
#include <string.h>

static PacketInfo make_stats_packet(const char *protocol)
{
    PacketInfo pkt;

    memset(&pkt, 0, sizeof(pkt));
    pkt.valid = 1;
    snprintf(pkt.protocol, sizeof(pkt.protocol), "%s", protocol);
    return pkt;
}

static DetectionResult make_alert(Severity severity, const char *type)
{
    DetectionResult result;

    memset(&result, 0, sizeof(result));
    result.alert = 1;
    result.severity = severity;
    snprintf(result.type, sizeof(result.type), "%s", type);
    return result;
}

static int test_stats_init_resets_counters(void)
{
    PacketInfo pkt = make_stats_packet("TCP");
    GiftIDSStats snapshot;

    TEST_BEGIN("stats init resets counters");
    stats_init();
    stats_update_packet(&pkt, 60);
    stats_init();
    snapshot = stats_get_snapshot();

    ASSERT_EQ_INT(0, snapshot.total_packets, "total packets should reset");
    ASSERT_EQ_INT(0, snapshot.tcp_packets, "TCP packets should reset");
    ASSERT_TRUE(snapshot.start_time != 0, "start time should be initialized");
    TEST_PASS();
}

static int test_stats_packet_protocol_counts(void)
{
    PacketInfo tcp = make_stats_packet("TCP");
    PacketInfo udp = make_stats_packet("UDP");
    PacketInfo icmp = make_stats_packet("ICMP");
    GiftIDSStats snapshot;

    TEST_BEGIN("stats packet protocol counts");
    stats_init();
    stats_update_packet(&tcp, 60);
    stats_update_packet(&udp, 70);
    stats_update_packet(&icmp, 80);
    stats_update_packet(NULL, 10);
    snapshot = stats_get_snapshot();

    ASSERT_EQ_INT(4, snapshot.total_packets, "total packet count should include invalid packets");
    ASSERT_EQ_INT(3, snapshot.valid_packets, "valid packet count should include parsed packets");
    ASSERT_EQ_INT(1, snapshot.invalid_packets, "invalid packet count should increment");
    ASSERT_EQ_INT(1, snapshot.tcp_packets, "TCP count should increment");
    ASSERT_EQ_INT(1, snapshot.udp_packets, "UDP count should increment");
    ASSERT_EQ_INT(1, snapshot.icmp_packets, "ICMP count should increment");
    ASSERT_EQ_INT(220, snapshot.bytes_seen, "bytes seen should add raw packet lengths");
    TEST_PASS();
}

static int test_stats_alert_severity_counts(void)
{
    DetectionResult low = make_alert(SEVERITY_LOW, "TCP SYN Watch");
    DetectionResult medium = make_alert(SEVERITY_MEDIUM, "Possible Port Scan");
    DetectionResult high = make_alert(SEVERITY_HIGH, "Possible SYN Flood");
    GiftIDSStats snapshot;

    TEST_BEGIN("stats alert severity counts");
    stats_init();
    stats_update_alert(&low);
    stats_update_alert(&medium);
    stats_update_alert(&high);
    snapshot = stats_get_snapshot();

    ASSERT_EQ_INT(3, snapshot.total_alerts, "total alerts should increment");
    ASSERT_EQ_INT(1, snapshot.low_alerts, "low alert count should increment");
    ASSERT_EQ_INT(1, snapshot.medium_alerts, "medium alert count should increment");
    ASSERT_EQ_INT(1, snapshot.high_alerts, "high alert count should increment");
    ASSERT_EQ_INT(1, snapshot.tcp_syn_watch_alerts, "TCP SYN Watch type count should increment");
    ASSERT_EQ_INT(1, snapshot.port_scan_alerts, "Port Scan type count should increment");
    ASSERT_EQ_INT(1, snapshot.syn_flood_alerts, "SYN Flood type count should increment");
    TEST_PASS();
}

void run_stats_tests(TestStats *stats)
{
    RUN_TEST(stats, test_stats_init_resets_counters);
    RUN_TEST(stats, test_stats_packet_protocol_counts);
    RUN_TEST(stats, test_stats_alert_severity_counts);
}
