#include "test_utils.h"

#include "cli.h"
#include "config.h"
#include "report.h"
#include "stats.h"

#include <stdio.h>
#include <string.h>

static int file_contains(const char *path, const char *needle)
{
    FILE *file;
    char buffer[8192];
    size_t bytes_read;

    file = fopen(path, "r");
    if (file == NULL) {
        return 0;
    }

    bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file);
    fclose(file);
    buffer[bytes_read] = '\0';

    return strstr(buffer, needle) != NULL;
}

static int test_text_report_file_created(void)
{
    GiftIDSRuntimeOptions options;
    GiftIDSConfig config;
    const char *path = "tests/tmp/session_report.txt";

    TEST_BEGIN("text report file created");
    cli_set_defaults(&options);
    config_set_defaults(&config);
    stats_init();
    remove(path);

    ASSERT_EQ_INT(0, report_generate_text(path, &options, &config), "text report should generate");
    ASSERT_TRUE(file_contains(path, "Gift IDS Session Report"), "text report should include title");
    ASSERT_TRUE(file_contains(path, "Runtime Summary"), "text report should include runtime summary");
    ASSERT_TRUE(file_contains(path, "Detection Configuration"), "text report should include detection configuration");
    TEST_PASS();
}

static int test_json_report_file_created(void)
{
    GiftIDSRuntimeOptions options;
    GiftIDSConfig config;
    const char *path = "tests/tmp/session_report.json";

    TEST_BEGIN("JSON report file created");
    cli_set_defaults(&options);
    config_set_defaults(&config);
    stats_init();
    remove(path);

    ASSERT_EQ_INT(0, report_generate_json(path, &options, &config), "JSON report should generate");
    ASSERT_TRUE(file_contains(path, "\"project\": \"Gift IDS\""), "JSON report should include project field");
    ASSERT_TRUE(file_contains(path, "\"runtime_summary\""), "JSON report should include runtime summary object");
    ASSERT_TRUE(file_contains(path, "\"detection_config\""), "JSON report should include detection config object");
    TEST_PASS();
}

static int test_unsupported_report_format_rejected(void)
{
    GiftIDSRuntimeOptions options;
    GiftIDSConfig config;

    TEST_BEGIN("unsupported report format rejected");
    cli_set_defaults(&options);
    config_set_defaults(&config);

    ASSERT_TRUE(report_generate("tests/tmp/bad_report.xml", "xml", &options, &config) != 0,
                "unsupported report format should fail");
    TEST_PASS();
}

void run_report_tests(TestStats *stats)
{
    RUN_TEST(stats, test_text_report_file_created);
    RUN_TEST(stats, test_json_report_file_created);
    RUN_TEST(stats, test_unsupported_report_format_rejected);
}
