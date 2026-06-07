#include "test_utils.h"

#include "cli.h"

static int parse_args(int argc, char **argv, GiftIDSRuntimeOptions *options)
{
    return cli_parse_args(argc, argv, options);
}

static int test_cli_interface_option(void)
{
    GiftIDSRuntimeOptions options;
    char *argv[] = {"giftids", "--interface", "wlan0"};

    TEST_BEGIN("CLI --interface");
    ASSERT_EQ_INT(0, parse_args(3, argv, &options), "--interface should parse");
    ASSERT_STR_EQ("wlan0", options.interface_name, "interface name did not parse");
    ASSERT_EQ_INT(MODE_LIVE_CAPTURE, options.mode, "interface should keep live mode");
    TEST_PASS();
}

static int test_cli_read_option(void)
{
    GiftIDSRuntimeOptions options;
    char *argv[] = {"giftids", "--read", "samples/test.pcap"};

    TEST_BEGIN("CLI --read");
    ASSERT_EQ_INT(0, parse_args(3, argv, &options), "--read should parse");
    ASSERT_STR_EQ("samples/test.pcap", options.pcap_file, "PCAP path did not parse");
    ASSERT_EQ_INT(MODE_PCAP_READ, options.mode, "--read should enable PCAP mode");
    TEST_PASS();
}

static int test_cli_config_option(void)
{
    GiftIDSRuntimeOptions options;
    char *argv[] = {"giftids", "--config", "config/test.conf"};

    TEST_BEGIN("CLI --config");
    ASSERT_EQ_INT(0, parse_args(3, argv, &options), "--config should parse");
    ASSERT_STR_EQ("config/test.conf", options.config_path, "config path did not parse");
    TEST_PASS();
}

static int test_cli_log_overrides(void)
{
    GiftIDSRuntimeOptions options;
    char *argv[] = {
        "giftids",
        "--packet-log",
        "logs/test_packets.log",
        "--alert-log",
        "logs/test_alerts.log"
    };

    TEST_BEGIN("CLI log overrides");
    ASSERT_EQ_INT(0, parse_args(5, argv, &options), "log overrides should parse");
    ASSERT_STR_EQ("logs/test_packets.log", options.packet_log_override, "packet log override did not parse");
    ASSERT_STR_EQ("logs/test_alerts.log", options.alert_log_override, "alert log override did not parse");
    TEST_PASS();
}

static int test_cli_output_flags(void)
{
    GiftIDSRuntimeOptions options;
    char *argv[] = {"giftids", "--stats", "--verbose", "--json"};

    TEST_BEGIN("CLI output flags");
    ASSERT_EQ_INT(0, parse_args(4, argv, &options), "stats, verbose, and JSON should parse");
    ASSERT_EQ_INT(1, options.show_stats, "--stats should enable stats");
    ASSERT_EQ_INT(1, options.verbose, "--verbose should enable verbose output");
    ASSERT_EQ_INT(1, options.json_output, "--json should enable JSON output");
    ASSERT_EQ_INT(0, options.quiet, "quiet should remain disabled");
    TEST_PASS();
}

static int test_cli_quiet_flag(void)
{
    GiftIDSRuntimeOptions options;
    char *argv[] = {"giftids", "--quiet"};

    TEST_BEGIN("CLI quiet flag");
    ASSERT_EQ_INT(0, parse_args(2, argv, &options), "quiet should parse");
    ASSERT_EQ_INT(1, options.quiet, "--quiet should enable quiet output");
    TEST_PASS();
}

static int test_cli_verbose_and_quiet_conflict(void)
{
    GiftIDSRuntimeOptions options;
    char *argv[] = {"giftids", "--verbose", "--quiet"};

    TEST_BEGIN("CLI verbose quiet conflict");
    ASSERT_TRUE(parse_args(3, argv, &options) != 0, "--verbose and --quiet should fail together");
    TEST_PASS();
}

static int test_cli_unknown_option(void)
{
    GiftIDSRuntimeOptions options;
    char *argv[] = {"giftids", "--mystery"};

    TEST_BEGIN("CLI unknown option");
    ASSERT_TRUE(parse_args(2, argv, &options) != 0, "unknown option should fail");
    TEST_PASS();
}

static int test_cli_missing_interface_value(void)
{
    GiftIDSRuntimeOptions options;
    char *argv[] = {"giftids", "--interface"};

    TEST_BEGIN("CLI missing interface value");
    ASSERT_TRUE(parse_args(2, argv, &options) != 0, "missing interface value should fail");
    TEST_PASS();
}

static int test_cli_interface_and_read_conflict(void)
{
    GiftIDSRuntimeOptions options;
    char *argv[] = {"giftids", "--interface", "wlan0", "--read", "samples/test.pcap"};

    TEST_BEGIN("CLI interface read conflict");
    ASSERT_TRUE(parse_args(5, argv, &options) != 0, "--interface and --read should fail together");
    TEST_PASS();
}

static int test_cli_rule_disable_options(void)
{
    GiftIDSRuntimeOptions options;
    GiftIDSConfig config;
    char *argv[] = {
        "giftids",
        "--disable-suspicious-port",
        "--disable-syn-watch",
        "--disable-icmp-echo",
        "--disable-port-scan",
        "--disable-syn-flood",
        "--disable-icmp-flood"
    };

    TEST_BEGIN("CLI rule disable options");
    ASSERT_EQ_INT(0, parse_args(7, argv, &options), "rule disable options should parse");
    config_set_defaults(&config);
    cli_apply_config_overrides(&options, &config);

    ASSERT_EQ_INT(0, config.enable_suspicious_port_rule, "CLI should disable Suspicious Port rule");
    ASSERT_EQ_INT(0, config.enable_tcp_syn_watch_rule, "CLI should disable TCP SYN Watch rule");
    ASSERT_EQ_INT(0, config.enable_icmp_echo_rule, "CLI should disable ICMP Echo rule");
    ASSERT_EQ_INT(0, config.enable_port_scan_detection, "CLI should disable port scan detection");
    ASSERT_EQ_INT(0, config.enable_syn_flood_detection, "CLI should disable SYN flood detection");
    ASSERT_EQ_INT(0, config.enable_icmp_flood_detection, "CLI should disable ICMP flood detection");
    TEST_PASS();
}

static int test_cli_report_options(void)
{
    GiftIDSRuntimeOptions options;
    char *argv[] = {
        "giftids",
        "--report",
        "reports/session_report.json",
        "--report-format",
        "json"
    };

    TEST_BEGIN("CLI report options");
    ASSERT_EQ_INT(0, parse_args(5, argv, &options), "report options should parse");
    ASSERT_EQ_INT(1, options.report_enabled, "--report should enable report generation");
    ASSERT_STR_EQ("reports/session_report.json", options.report_path, "report path did not parse");
    ASSERT_STR_EQ("json", options.report_format, "report format did not parse");
    TEST_PASS();
}

static int test_cli_report_inline_options(void)
{
    GiftIDSRuntimeOptions options;
    char *argv[] = {
        "giftids",
        "--report=reports/session_report.txt",
        "--report-format=txt"
    };

    TEST_BEGIN("CLI inline report options");
    ASSERT_EQ_INT(0, parse_args(3, argv, &options), "inline report options should parse");
    ASSERT_EQ_INT(1, options.report_enabled, "inline --report should enable report generation");
    ASSERT_STR_EQ("reports/session_report.txt", options.report_path, "inline report path did not parse");
    ASSERT_STR_EQ("txt", options.report_format, "inline report format did not parse");
    TEST_PASS();
}

static int test_cli_invalid_report_format(void)
{
    GiftIDSRuntimeOptions options;
    char *argv[] = {"giftids", "--report-format", "xml"};

    TEST_BEGIN("CLI invalid report format");
    ASSERT_TRUE(parse_args(3, argv, &options) != 0, "invalid report format should fail");
    TEST_PASS();
}

static int test_cli_missing_report_values(void)
{
    GiftIDSRuntimeOptions options;
    char *argv_report[] = {"giftids", "--report"};
    char *argv_format[] = {"giftids", "--report-format"};

    TEST_BEGIN("CLI missing report values");
    ASSERT_TRUE(parse_args(2, argv_report, &options) != 0, "missing report path should fail");
    ASSERT_TRUE(parse_args(2, argv_format, &options) != 0, "missing report format should fail");
    TEST_PASS();
}

void run_cli_tests(TestStats *stats)
{
    RUN_TEST(stats, test_cli_interface_option);
    RUN_TEST(stats, test_cli_read_option);
    RUN_TEST(stats, test_cli_config_option);
    RUN_TEST(stats, test_cli_log_overrides);
    RUN_TEST(stats, test_cli_output_flags);
    RUN_TEST(stats, test_cli_quiet_flag);
    RUN_TEST(stats, test_cli_verbose_and_quiet_conflict);
    RUN_TEST(stats, test_cli_unknown_option);
    RUN_TEST(stats, test_cli_missing_interface_value);
    RUN_TEST(stats, test_cli_interface_and_read_conflict);
    RUN_TEST(stats, test_cli_rule_disable_options);
    RUN_TEST(stats, test_cli_report_options);
    RUN_TEST(stats, test_cli_report_inline_options);
    RUN_TEST(stats, test_cli_invalid_report_format);
    RUN_TEST(stats, test_cli_missing_report_values);
}
