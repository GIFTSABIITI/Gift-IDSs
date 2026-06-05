#include "capture.h"
#include "cli.h"
#include "config.h"
#include "detector.h"
#include "logger.h"
#include "parser.h"
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
        stats_print_live();
        context->last_stats_print = now;
    }
}

static void handle_idle(void *user_data)
{
    AppContext *context = (AppContext *)user_data;

    maybe_print_live_stats(context);
}

static void print_packet_for_mode(const PacketInfo *info, const GiftIDSRuntimeOptions *options)
{
    if (options->quiet) {
        return;
    }

    if (options->verbose) {
        logger_print_packet_verbose(info);
    } else {
        logger_print_packet(info);
    }
}

static void handle_packet(const unsigned char *packet, int packet_len, void *user_data)
{
    AppContext *context = (AppContext *)user_data;
    DetectionResult detection;
    PacketInfo info;

    info = parse_packet(packet, packet_len);

    /*
     * stats_update_packet() receives both the parsed result and the raw frame
     * length. Calling it once here avoids double-counting while still letting
     * the stats module track invalid frames and raw bytes seen.
     */
    stats_update_packet(info.valid ? &info : NULL, packet_len);

    if (!info.valid) {
        maybe_print_live_stats(context);
        return;
    }

    print_packet_for_mode(&info, context->options);
    logger_log_packet(&info);

    detection = detect_packet(&info);
    if (detection.alert) {
        stats_update_alert(&detection);
        logger_print_alert(&detection);
        log_alert(&detection);
    }

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

    signal(SIGINT, handle_shutdown);
    signal(SIGTERM, handle_shutdown);

    if (options.interface_name[0] != '\0') {
        interface = options.interface_name;
    } else if (!options.quiet) {
        printf("No interface specified; using the existing raw socket capture behavior.\n");
    }

    capture_set_idle_handler(handle_idle, &context);
    result = capture_packets(interface, options.max_packets, handle_packet, &context);

    logger_close();
    stats_print_summary();

    if (!options.quiet) {
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
