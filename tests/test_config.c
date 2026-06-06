#include "test_utils.h"

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define TMP_DIR "tests/tmp"

static void ensure_tmp_dir(void)
{
    mkdir(TMP_DIR, 0755);
}

static int write_temp_config(const char *path, const char *contents)
{
    FILE *file;

    ensure_tmp_dir();
    file = fopen(path, "w");
    if (file == NULL) {
        return 0;
    }

    fputs(contents, file);
    fclose(file);
    return 1;
}

static int test_config_defaults(void)
{
    GiftIDSConfig config;

    TEST_BEGIN("config defaults");
    config_set_defaults(&config);

    ASSERT_EQ_INT(10, config.port_scan_threshold, "default port scan threshold changed");
    ASSERT_EQ_INT(10, config.port_scan_window_seconds, "default port scan window changed");
    ASSERT_EQ_INT(30, config.syn_flood_threshold, "default SYN flood threshold changed");
    ASSERT_EQ_INT(10, config.syn_flood_window_seconds, "default SYN flood window changed");
    ASSERT_EQ_INT(20, config.icmp_flood_threshold, "default ICMP flood threshold changed");
    ASSERT_EQ_INT(10, config.icmp_flood_window_seconds, "default ICMP flood window changed");
    ASSERT_EQ_INT(10, config.alert_cooldown_seconds, "default alert cooldown changed");
    ASSERT_EQ_INT(1, config.enable_suspicious_port_rule, "suspicious port rule should default on");
    ASSERT_EQ_INT(1, config.enable_tcp_syn_watch_rule, "TCP SYN Watch rule should default on");
    ASSERT_EQ_INT(1, config.enable_icmp_echo_rule, "ICMP Echo rule should default on");
    ASSERT_EQ_INT(1, config.enable_port_scan_detection, "port scan detection should default on");
    ASSERT_EQ_INT(1, config.enable_syn_flood_detection, "SYN flood detection should default on");
    ASSERT_EQ_INT(1, config.enable_icmp_flood_detection, "ICMP flood detection should default on");
    ASSERT_STR_EQ(GIFTIDS_DEFAULT_PACKET_LOG_FILE, config.packet_log_file, "default packet log path changed");
    ASSERT_STR_EQ(GIFTIDS_DEFAULT_ALERT_LOG_FILE, config.alert_log_file, "default alert log path changed");

    TEST_PASS();
}

static int test_config_load_valid_file(void)
{
    GiftIDSConfig config;
    const char *path = TMP_DIR "/valid.conf";

    TEST_BEGIN("config load valid file");
    ASSERT_TRUE(write_temp_config(path,
                                  "port_scan_threshold=3\n"
                                  "port_scan_window_seconds=4\n"
                                  "syn_flood_threshold=5\n"
                                  "syn_flood_window_seconds=6\n"
                                  "icmp_flood_threshold=7\n"
                                  "icmp_flood_window_seconds=8\n"
                                  "alert_cooldown_seconds=0\n"
                                  "enable_suspicious_port_rule=false\n"
                                  "enable_tcp_syn_watch_rule=yes\n"
                                  "enable_icmp_echo_rule=0\n"
                                  "enable_port_scan_detection=1\n"
                                  "enable_syn_flood_detection=no\n"
                                  "enable_icmp_flood_detection=true\n"
                                  "packet_log_file=tests/tmp/packets.log\n"
                                  "alert_log_file=tests/tmp/alerts.log\n"),
                "could not write valid config fixture");

    config_set_defaults(&config);
    ASSERT_EQ_INT(0, config_load(path, &config), "valid config should load");
    ASSERT_EQ_INT(3, config.port_scan_threshold, "port scan threshold did not load");
    ASSERT_EQ_INT(4, config.port_scan_window_seconds, "port scan window did not load");
    ASSERT_EQ_INT(5, config.syn_flood_threshold, "SYN flood threshold did not load");
    ASSERT_EQ_INT(6, config.syn_flood_window_seconds, "SYN flood window did not load");
    ASSERT_EQ_INT(7, config.icmp_flood_threshold, "ICMP flood threshold did not load");
    ASSERT_EQ_INT(8, config.icmp_flood_window_seconds, "ICMP flood window did not load");
    ASSERT_EQ_INT(0, config.alert_cooldown_seconds, "alert cooldown should accept zero");
    ASSERT_EQ_INT(0, config.enable_suspicious_port_rule, "false boolean did not load");
    ASSERT_EQ_INT(1, config.enable_tcp_syn_watch_rule, "yes boolean did not load");
    ASSERT_EQ_INT(0, config.enable_icmp_echo_rule, "0 boolean did not load");
    ASSERT_EQ_INT(1, config.enable_port_scan_detection, "1 boolean did not load");
    ASSERT_EQ_INT(0, config.enable_syn_flood_detection, "no boolean did not load");
    ASSERT_EQ_INT(1, config.enable_icmp_flood_detection, "true boolean did not load");
    ASSERT_STR_EQ("tests/tmp/packets.log", config.packet_log_file, "packet log path did not load");
    ASSERT_STR_EQ("tests/tmp/alerts.log", config.alert_log_file, "alert log path did not load");

    remove(path);
    TEST_PASS();
}

static int test_config_unknown_keys_are_ignored(void)
{
    GiftIDSConfig config;
    const char *path = TMP_DIR "/unknown.conf";

    TEST_BEGIN("config unknown keys ignored");
    ASSERT_TRUE(write_temp_config(path,
                                  "unknown_key=surprise\n"
                                  "another_unknown=42\n"),
                "could not write unknown-key config fixture");

    config_set_defaults(&config);
    ASSERT_EQ_INT(0, config_load(path, &config), "unknown keys should not fail config load");
    ASSERT_EQ_INT(10, config.port_scan_threshold, "unknown keys should not change defaults");
    ASSERT_EQ_INT(1, config.enable_tcp_syn_watch_rule, "unknown keys should not change rule defaults");

    remove(path);
    TEST_PASS();
}

static int test_config_invalid_numeric_keeps_default(void)
{
    GiftIDSConfig config;
    const char *path = TMP_DIR "/invalid_numeric.conf";

    TEST_BEGIN("config invalid numeric keeps default");
    ASSERT_TRUE(write_temp_config(path,
                                  "port_scan_threshold=banana\n"
                                  "syn_flood_threshold=-4\n"
                                  "icmp_flood_window_seconds=0\n"),
                "could not write invalid numeric config fixture");

    config_set_defaults(&config);
    ASSERT_EQ_INT(0, config_load(path, &config), "invalid numeric values should warn but keep loading");
    ASSERT_EQ_INT(10, config.port_scan_threshold, "bad port scan threshold should keep default");
    ASSERT_EQ_INT(30, config.syn_flood_threshold, "negative SYN flood threshold should keep default");
    ASSERT_EQ_INT(10, config.icmp_flood_window_seconds, "zero window should keep default");

    remove(path);
    TEST_PASS();
}

static int test_config_missing_file_keeps_defaults(void)
{
    GiftIDSConfig config;

    TEST_BEGIN("config missing file keeps defaults");
    config_set_defaults(&config);

    ASSERT_EQ_INT(-1, config_load(TMP_DIR "/does-not-exist.conf", &config),
                  "missing config should return an error code");
    ASSERT_EQ_INT(10, config.port_scan_threshold, "missing config should preserve defaults");
    ASSERT_EQ_INT(1, config.enable_icmp_echo_rule, "missing config should preserve rule defaults");

    TEST_PASS();
}

static int test_config_invalid_boolean_keeps_default(void)
{
    GiftIDSConfig config;
    const char *path = TMP_DIR "/invalid_bool.conf";

    TEST_BEGIN("config invalid boolean keeps default");
    ASSERT_TRUE(write_temp_config(path,
                                  "enable_tcp_syn_watch_rule=maybe\n"
                                  "enable_icmp_echo_rule=almost\n"),
                "could not write invalid boolean config fixture");

    config_set_defaults(&config);
    ASSERT_EQ_INT(0, config_load(path, &config), "invalid booleans should warn but keep loading");
    ASSERT_EQ_INT(1, config.enable_tcp_syn_watch_rule, "invalid boolean should keep TCP SYN Watch default");
    ASSERT_EQ_INT(1, config.enable_icmp_echo_rule, "invalid boolean should keep ICMP Echo default");

    remove(path);
    TEST_PASS();
}

void run_config_tests(TestStats *stats)
{
    RUN_TEST(stats, test_config_defaults);
    RUN_TEST(stats, test_config_load_valid_file);
    RUN_TEST(stats, test_config_unknown_keys_are_ignored);
    RUN_TEST(stats, test_config_invalid_numeric_keeps_default);
    RUN_TEST(stats, test_config_missing_file_keeps_defaults);
    RUN_TEST(stats, test_config_invalid_boolean_keeps_default);
}
