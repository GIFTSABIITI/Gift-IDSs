#ifndef STATS_H
#define STATS_H

#include "detector.h"
#include "parser.h"

#include <time.h>

typedef struct {
    unsigned long long total_packets;
    unsigned long long valid_packets;
    unsigned long long invalid_packets;
    unsigned long long tcp_packets;
    unsigned long long udp_packets;
    unsigned long long icmp_packets;
    unsigned long long other_packets;
    unsigned long long total_alerts;
    unsigned long long low_alerts;
    unsigned long long medium_alerts;
    unsigned long long high_alerts;
    unsigned long long suspicious_port_alerts;
    unsigned long long tcp_syn_watch_alerts;
    unsigned long long icmp_echo_alerts;
    unsigned long long port_scan_alerts;
    unsigned long long syn_flood_alerts;
    unsigned long long icmp_flood_alerts;
    unsigned long long bytes_seen;
    time_t start_time;
} GiftIDSStats;

void stats_init(void);
void stats_update_packet(const PacketInfo *pkt, int raw_packet_len);
void stats_update_alert(const DetectionResult *result);
void stats_print_summary(void);
void stats_print_live(void);

#endif
