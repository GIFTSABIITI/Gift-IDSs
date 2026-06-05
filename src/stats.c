#include "stats.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static GiftIDSStats stats;

static void format_runtime(char *buffer, size_t buffer_size)
{
    time_t now;
    unsigned long long total_seconds;
    unsigned long long hours;
    unsigned long long minutes;
    unsigned long long seconds;

    now = time(NULL);
    if (stats.start_time == 0 || now < stats.start_time) {
        total_seconds = 0;
    } else {
        total_seconds = (unsigned long long)difftime(now, stats.start_time);
    }

    hours = total_seconds / 3600;
    minutes = (total_seconds % 3600) / 60;
    seconds = total_seconds % 60;

    snprintf(buffer, buffer_size, "%02llu:%02llu:%02llu", hours, minutes, seconds);
}

static void format_bytes(unsigned long long bytes, char *buffer, size_t buffer_size)
{
    double value = (double)bytes;
    const char *unit = "B";

    if (value >= 1024.0 * 1024.0 * 1024.0) {
        value /= 1024.0 * 1024.0 * 1024.0;
        unit = "GB";
    } else if (value >= 1024.0 * 1024.0) {
        value /= 1024.0 * 1024.0;
        unit = "MB";
    } else if (value >= 1024.0) {
        value /= 1024.0;
        unit = "KB";
    }

    if (strcmp(unit, "B") == 0) {
        snprintf(buffer, buffer_size, "%llu B", bytes);
    } else {
        snprintf(buffer, buffer_size, "%.1f %s", value, unit);
    }
}

static void print_alert_type(const char *name, unsigned long long count)
{
    if (count > 0) {
        printf("  %s: %llu\n", name, count);
    }
}

void stats_init(void)
{
    memset(&stats, 0, sizeof(stats));
    stats.start_time = time(NULL);
}

void stats_update_packet(const PacketInfo *pkt, int raw_packet_len)
{
    /*
     * Runtime statistics are useful in network monitoring because they show
     * whether the IDS is seeing traffic, which protocols dominate, and whether
     * alerts are rare events or a steady stream.
     *
     * bytes_seen uses the raw captured frame length. That is the amount of
     * traffic the IDS actually received, while IP length only describes the
     * IPv4 payload inside one kind of frame.
     */
    stats.total_packets++;
    if (raw_packet_len > 0) {
        stats.bytes_seen += (unsigned long long)raw_packet_len;
    }

    if (pkt == NULL || !pkt->valid) {
        stats.invalid_packets++;
        return;
    }

    stats.valid_packets++;
    if (strcmp(pkt->protocol, "TCP") == 0) {
        stats.tcp_packets++;
    } else if (strcmp(pkt->protocol, "UDP") == 0) {
        stats.udp_packets++;
    } else if (strcmp(pkt->protocol, "ICMP") == 0) {
        stats.icmp_packets++;
    } else {
        stats.other_packets++;
    }
}

void stats_update_alert(const DetectionResult *result)
{
    if (result == NULL || !result->alert) {
        return;
    }

    stats.total_alerts++;
    switch (result->severity) {
    case SEVERITY_LOW:
        stats.low_alerts++;
        break;
    case SEVERITY_MEDIUM:
        stats.medium_alerts++;
        break;
    case SEVERITY_HIGH:
        stats.high_alerts++;
        break;
    case SEVERITY_NONE:
    default:
        break;
    }

    if (strcmp(result->type, "Suspicious Port") == 0) {
        stats.suspicious_port_alerts++;
    } else if (strcmp(result->type, "TCP SYN Watch") == 0) {
        stats.tcp_syn_watch_alerts++;
    } else if (strcmp(result->type, "ICMP Echo Request") == 0) {
        stats.icmp_echo_alerts++;
    } else if (strcmp(result->type, "Possible Port Scan") == 0) {
        stats.port_scan_alerts++;
    } else if (strcmp(result->type, "Possible SYN Flood") == 0) {
        stats.syn_flood_alerts++;
    } else if (strcmp(result->type, "Possible ICMP Flood") == 0) {
        stats.icmp_flood_alerts++;
    }
}

void stats_print_live(void)
{
    char runtime[32];
    char bytes[32];
    int printed_alert_type = 0;

    format_runtime(runtime, sizeof(runtime));
    format_bytes(stats.bytes_seen, bytes, sizeof(bytes));

    printf("\n================ Gift IDS Live Stats ================\n");
    printf("Runtime: %s\n", runtime);
    printf("Packets captured: %llu\n", stats.total_packets);
    printf("Valid packets: %llu\n", stats.valid_packets);
    printf("Invalid packets: %llu\n", stats.invalid_packets);
    printf("TCP: %llu | UDP: %llu | ICMP: %llu | Other: %llu\n",
           stats.tcp_packets,
           stats.udp_packets,
           stats.icmp_packets,
           stats.other_packets);
    printf("Bytes seen: %s\n", bytes);
    printf("Alerts: %llu\n", stats.total_alerts);
    printf("Low: %llu | Medium: %llu | High: %llu\n",
           stats.low_alerts,
           stats.medium_alerts,
           stats.high_alerts);
    printf("Top alert types:\n");

    printed_alert_type = stats.suspicious_port_alerts > 0 ||
                         stats.tcp_syn_watch_alerts > 0 ||
                         stats.icmp_echo_alerts > 0 ||
                         stats.port_scan_alerts > 0 ||
                         stats.syn_flood_alerts > 0 ||
                         stats.icmp_flood_alerts > 0;

    if (printed_alert_type) {
        print_alert_type("Suspicious Port", stats.suspicious_port_alerts);
        print_alert_type("TCP SYN Watch", stats.tcp_syn_watch_alerts);
        print_alert_type("ICMP Echo Request", stats.icmp_echo_alerts);
        print_alert_type("Possible Port Scan", stats.port_scan_alerts);
        print_alert_type("Possible SYN Flood", stats.syn_flood_alerts);
        print_alert_type("Possible ICMP Flood", stats.icmp_flood_alerts);
    } else {
        printf("  None yet\n");
    }

    printf("=====================================================\n");
}

void stats_print_summary(void)
{
    char runtime[32];
    char bytes[32];

    format_runtime(runtime, sizeof(runtime));
    format_bytes(stats.bytes_seen, bytes, sizeof(bytes));

    printf("\n================ Gift IDS Final Summary ================\n");
    printf("Runtime: %s\n", runtime);
    printf("Packets captured: %llu\n", stats.total_packets);
    printf("Valid packets: %llu\n", stats.valid_packets);
    printf("Invalid packets: %llu\n", stats.invalid_packets);
    printf("TCP packets: %llu\n", stats.tcp_packets);
    printf("UDP packets: %llu\n", stats.udp_packets);
    printf("ICMP packets: %llu\n", stats.icmp_packets);
    printf("Other packets: %llu\n", stats.other_packets);
    printf("Bytes seen: %s\n", bytes);
    printf("Total alerts: %llu\n", stats.total_alerts);
    printf("Low alerts: %llu\n", stats.low_alerts);
    printf("Medium alerts: %llu\n", stats.medium_alerts);
    printf("High alerts: %llu\n", stats.high_alerts);
    printf("========================================================\n");
}
