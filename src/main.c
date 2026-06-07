#include "capture.h"
#include "cli.h"
#include "config.h"
#include "detector.h"
#include "json_output.h"
#include "logger.h"
#include "pcap_reader.h"
#include "processor.h"
#include "report.h"
#include "stats.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define LIVE_STATS_INTERVAL_SECONDS 5

typedef struct {
    const GiftIDSRuntimeOptions *options;
    time_t last_stats_print;
} AppContext;

static void handle_shutdown(int signo)
{
    (void)signo;
    /*
     * Ctrl+C should stop capture cleanly so main can flush logs, close files,
     * and print a final summary instead of exiting in the middle of a write.
     */
    capture_stop();
}

static void maybe_print_live_stats(AppContext *context)
{
    time_t now;

    if (context == NULL || context->options == NULL || !context->options->show_stats) {
        return;
    }

    now = time(NULL);
    if (context->last_stats_print == 0 ||
        difftime(now, context->last_stats_print) >= LIVE_STATS_INTERVAL_SECONDS) {
        if (context->options->json_output) {
            json_print_stats_event();
        } else {
            stats_print_live();
        }
        context->last_stats_print = now;
    }
}

static void handle_idle(void *user_data)
{
    AppContext *context = (AppContext *)user_data;

    maybe_print_live_stats(context);
}

static void handle_packet(const unsigned char *packet, int packet_len, void *user_data)
{
    AppContext *context = (AppContext *)user_data;

    process_packet_event(packet, packet_len, context->options);
    maybe_print_live_stats(context);
}

int main(int argc, char **argv)
{
    GiftIDSRuntimeOptions options;
    GiftIDSConfig config;
    AppContext context;
    const char *interface = NULL;
    int result;

    if (cli_parse_args(argc, argv, &options) != 0) {
        fprintf(stderr, "Run '%s --help' for usage.\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (options.show_help) {
        cli_print_help(argv[0]);
        return EXIT_SUCCESS;
    }

    if (options.show_version) {
        cli_print_version();
        return EXIT_SUCCESS;
    }

    /*
     * Startup order:
     * defaults, config file, CLI overrides, logger, detector, then capture.
     * This keeps config files useful while still letting one command override
     * paths or runtime behavior for a single lab session.
     */
    config_set_defaults(&config);
    config_load(options.config_path, &config);
    cli_apply_config_overrides(&options, &config);

    logger_set_packet_logging_enabled(options.packet_logging_enabled);
    logger_set_alert_logging_enabled(options.alert_logging_enabled);
    if (logger_init(&config) != 0) {
        fprintf(stderr,
                "Warning: one or more enabled log files could not be opened; console output will continue.\n");
    }

    detector_init(&config);
    stats_init();

    context.options = &options;
    context.last_stats_print = time(NULL);

    if (options.mode == MODE_PCAP_READ) {
        result = pcap_reader_run(options.pcap_file, &options);
    } else {
        signal(SIGINT, handle_shutdown);
        signal(SIGTERM, handle_shutdown);

        if (options.interface_name[0] != '\0') {
            interface = options.interface_name;
        } else if (!options.quiet && !options.json_output) {
            printf("No interface specified; using the existing raw socket capture behavior.\n");
        }

        capture_set_idle_handler(handle_idle, &context);
        result = capture_packets(interface, options.max_packets, handle_packet, &context);
    }

    logger_close();

    if (options.report_enabled) {
        if (report_generate(options.report_path, options.report_format, &options, &config) != 0) {
            result = -1;
        } else if (!options.quiet && !options.json_output) {
            printf("Report: %s\n", options.report_path);
        }
    }

    if (options.json_output) {
        if (options.show_stats) {
            json_print_stats_event();
        }
        json_print_session_complete();
    } else {
        stats_print_summary();
    }

    if (!options.quiet && !options.json_output) {
        if (options.packet_logging_enabled) {
            printf("Packet log: %s\n", config.packet_log_file);
        } else {
            printf("Packet logging disabled.\n");
        }

        if (options.alert_logging_enabled) {
            printf("Alert log: %s\n", config.alert_log_file);
        } else {
            printf("Alert logging disabled.\n");
        }
    }

    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
