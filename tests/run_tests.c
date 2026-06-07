#include "test_utils.h"

#include <stdio.h>

void run_config_tests(TestStats *stats);
void run_detector_tests(TestStats *stats);
void run_parser_tests(TestStats *stats);
void run_cli_tests(TestStats *stats);
void run_stats_tests(TestStats *stats);
void run_report_tests(TestStats *stats);
void run_json_output_tests(TestStats *stats);

int main(void)
{
    TestStats stats = {0, 0, 0};

    printf("Running Gift IDS tests...\n");
    /*
     * Several negative tests intentionally trigger config warnings and CLI
     * errors. Keep the test runner focused on the pass/fail lines.
     */
    freopen("/dev/null", "w", stderr);

    run_config_tests(&stats);
    run_detector_tests(&stats);
    run_parser_tests(&stats);
    run_cli_tests(&stats);
    run_stats_tests(&stats);
    run_report_tests(&stats);
    run_json_output_tests(&stats);

    printf("Tests run: %d\n", stats.tests_run);
    printf("Passed: %d\n", stats.passed);
    printf("Failed: %d\n", stats.failed);

    return stats.failed == 0 ? 0 : 1;
}
