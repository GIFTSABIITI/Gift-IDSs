#include "test_utils.h"

#include "json_output.h"
#include "stats.h"

#include <stdio.h>
#include <string.h>

static PacketInfo make_json_packet(void)
{
    PacketInfo pkt;

    memset(&pkt, 0, sizeof(pkt));
    pkt.valid = 1;
    pkt.timestamp = 1000;
    snprintf(pkt.src_ip, sizeof(pkt.src_ip), "%s", "192.168.1.5");
    snprintf(pkt.dst_ip, sizeof(pkt.dst_ip), "%s", "8.8.8.8");
    snprintf(pkt.protocol, sizeof(pkt.protocol), "%s", "UDP");
    pkt.src_port = 55320;
    pkt.dst_port = 53;
    pkt.ttl = 64;
    pkt.ip_len = 60;
    pkt.frame_len = 74;
    return pkt;
}

static DetectionResult make_json_alert(void)
{
    DetectionResult alert;

    memset(&alert, 0, sizeof(alert));
    alert.alert = 1;
    alert.severity = SEVERITY_MEDIUM;
    snprintf(alert.type, sizeof(alert.type), "%s", "Possible Port Scan");
    snprintf(alert.src_ip, sizeof(alert.src_ip), "%s", "192.168.1.20");
    snprintf(alert.dst_ip, sizeof(alert.dst_ip), "%s", "192.168.1.10");
    snprintf(alert.protocol, sizeof(alert.protocol), "%s", "TCP");
    alert.src_port = 51544;
    alert.dst_port = 80;
    alert.observed_count = 12;
    alert.unique_ports = 12;
    alert.threshold = 10;
    alert.window_seconds = 10;
    alert.last_seen = 1004;
    snprintf(alert.evidence, sizeof(alert.evidence), "%s",
             "Source contacted 12 unique destination ports on the same target within 10 seconds.");
    snprintf(alert.recommendation, sizeof(alert.recommendation), "%s",
             "Investigate the source host and verify whether port scanning or service discovery was authorized.");
    return alert;
}

static int test_json_string_escaping(void)
{
    char escaped[128];

    TEST_BEGIN("JSON string escaping");
    json_escape_string("quote\" slash\\ line\n tab\t cr\r", escaped, sizeof(escaped));

    ASSERT_TRUE(strstr(escaped, "quote\\\"") != NULL, "quote should be escaped");
    ASSERT_TRUE(strstr(escaped, "slash\\\\") != NULL, "backslash should be escaped");
    ASSERT_TRUE(strstr(escaped, "line\\n") != NULL, "newline should be escaped");
    ASSERT_TRUE(strstr(escaped, "tab\\t") != NULL, "tab should be escaped");
    ASSERT_TRUE(strstr(escaped, "cr\\r") != NULL, "carriage return should be escaped");
    TEST_PASS();
}

static int test_packet_json_contains_event_type(void)
{
    PacketInfo pkt = make_json_packet();
    char output[1024];

    TEST_BEGIN("packet JSON contains event type");
    ASSERT_EQ_INT(0, json_format_packet(&pkt, 0, output, sizeof(output)), "packet JSON should format");
    ASSERT_TRUE(strstr(output, "\"event_type\":\"packet\"") != NULL, "packet JSON should include event type");
    ASSERT_TRUE(strstr(output, "\"protocol\":\"UDP\"") != NULL, "packet JSON should include protocol");
    TEST_PASS();
}

static int test_alert_json_contains_evidence(void)
{
    DetectionResult alert = make_json_alert();
    char output[4096];

    TEST_BEGIN("alert JSON contains evidence");
    ASSERT_EQ_INT(0, json_format_alert(&alert, output, sizeof(output)), "alert JSON should format");
    ASSERT_TRUE(strstr(output, "\"event_type\":\"alert\"") != NULL, "alert JSON should include event type");
    ASSERT_TRUE(strstr(output, "\"evidence\":\"Source contacted") != NULL, "alert JSON should include evidence");
    ASSERT_TRUE(strstr(output, "\"recommendation\":\"Investigate") != NULL, "alert JSON should include recommendation");
    TEST_PASS();
}

static int test_alert_json_handles_empty_strings(void)
{
    DetectionResult alert;
    char output[2048];

    TEST_BEGIN("alert JSON handles empty strings");
    memset(&alert, 0, sizeof(alert));
    alert.alert = 1;
    alert.severity = SEVERITY_NONE;

    ASSERT_EQ_INT(0, json_format_alert(&alert, output, sizeof(output)), "empty alert JSON should format");
    ASSERT_TRUE(strstr(output, "\"event_type\":\"alert\"") != NULL, "empty alert JSON should still include event type");
    TEST_PASS();
}

static int test_stats_and_completion_json(void)
{
    char stats_output[1024];
    char complete_output[1024];

    TEST_BEGIN("stats and completion JSON");
    stats_init();

    ASSERT_EQ_INT(0, json_format_stats_event(stats_output, sizeof(stats_output)), "stats JSON should format");
    ASSERT_EQ_INT(0, json_format_session_complete(complete_output, sizeof(complete_output)), "completion JSON should format");
    ASSERT_TRUE(strstr(stats_output, "\"event_type\":\"stats\"") != NULL, "stats JSON should include event type");
    ASSERT_TRUE(strstr(complete_output, "\"event_type\":\"session_complete\"") != NULL,
                "completion JSON should include event type");
    TEST_PASS();
}

void run_json_output_tests(TestStats *stats)
{
    RUN_TEST(stats, test_json_string_escaping);
    RUN_TEST(stats, test_packet_json_contains_event_type);
    RUN_TEST(stats, test_alert_json_contains_evidence);
    RUN_TEST(stats, test_alert_json_handles_empty_strings);
    RUN_TEST(stats, test_stats_and_completion_json);
}
