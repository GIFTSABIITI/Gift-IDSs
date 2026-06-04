#include "capture.h"
#include "detector.h"
#include "logger.h"
#include "parser.h"

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    long valid_packets;
    long alerts;
} AppStats;

static void print_usage(const char *program)
{
    printf("Usage: %s [-i interface] [-c count]\n", program);
    printf("\n");
    printf("Options:\n");
    printf("  -i <interface>  Capture from a specific interface\n");
    printf("  -c <count>      Stop after this many raw frames\n");
    printf("  -h              Show this help message\n");
}

static void handle_shutdown(int signo)
{
    (void)signo;
    capture_stop();
}

static void handle_packet(const unsigned char *packet, int packet_len, void *user_data)
{
    AppStats *stats = (AppStats *)user_data;
    DetectionResult detection;
    PacketInfo info;

    info = parse_packet(packet, packet_len);
    if (!info.valid) {
        return;
    }

    stats->valid_packets++;
    logger_print_packet(&info);
    logger_log_packet(&info);

    detection = detect_packet(&info);
    if (detection.alert) {
        stats->alerts++;
        logger_print_alert(&detection);
        log_alert(&detection);
    }
}

int main(int argc, char **argv)
{
    const char *interface = NULL;
    long max_packets = 0;
    AppStats stats = {0};
    int opt;
    int result;

    while ((opt = getopt(argc, argv, "i:c:h")) != -1) {
        switch (opt) {
        case 'i':
            interface = optarg;
            break;
        case 'c':
            max_packets = strtol(optarg, NULL, 10);
            if (max_packets <= 0) {
                fprintf(stderr, "Packet count must be a positive number\n");
                return EXIT_FAILURE;
            }
            break;
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (logger_open(GIFTIDS_LOG_FILE) != 0) {
        fprintf(stderr,
                "Failed to open log files: %s or %s\n",
                GIFTIDS_PACKET_LOG_FILE,
                GIFTIDS_ALERT_LOG_FILE);
        return EXIT_FAILURE;
    }

    signal(SIGINT, handle_shutdown);
    signal(SIGTERM, handle_shutdown);

    result = capture_packets(interface, max_packets, handle_packet, &stats);

    logger_close();
    if (result == 0) {
        printf("Logged %ld valid IPv4 packet%s to %s.\n",
               stats.valid_packets,
               stats.valid_packets == 1 ? "" : "s",
               GIFTIDS_LOG_FILE);
        printf("Logged %ld alert%s to %s.\n",
               stats.alerts,
               stats.alerts == 1 ? "" : "s",
               GIFTIDS_ALERT_LOG_FILE);
    } else if (stats.valid_packets > 0) {
        fprintf(stderr, "Capture stopped after logging %ld valid IPv4 packet%s to %s.\n",
                stats.valid_packets,
                stats.valid_packets == 1 ? "" : "s",
                GIFTIDS_LOG_FILE);
    }

    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
