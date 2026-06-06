#include "processor.h"

#include "detector.h"
#include "logger.h"
#include "parser.h"
#include "stats.h"

static void print_packet_for_mode(const PacketInfo *info, const GiftIDSRuntimeOptions *options)
{
    if (options != NULL && options->quiet) {
        return;
    }

    if (options != NULL && options->verbose) {
        logger_print_packet_verbose(info);
    } else {
        logger_print_packet(info);
    }
}

void process_packet_event(const unsigned char *packet,
                          int packet_len,
                          const GiftIDSRuntimeOptions *options)
{
    process_packet_event_at_time(packet, packet_len, 0, options);
}

void process_packet_event_at_time(const unsigned char *packet,
                                  int packet_len,
                                  time_t packet_timestamp,
                                  const GiftIDSRuntimeOptions *options)
{
    DetectionResult detection;
    PacketInfo info;

    /*
     * Live capture and PCAP reading should agree about what a packet means.
     * Keeping parse, stats, logging, and detection in one function makes
     * offline tests a realistic rehearsal for live monitoring.
     */
    info = parse_packet_with_timestamp(packet, packet_len, packet_timestamp);

    stats_update_packet(info.valid ? &info : NULL, packet_len);
    if (!info.valid) {
        return;
    }

    print_packet_for_mode(&info, options);
    logger_log_packet(&info);

    detection = detect_packet(&info);
    if (detection.alert) {
        stats_update_alert(&detection);
        logger_print_alert(&detection);
        log_alert(&detection);
    }
}
