#ifndef CLI_H
#define CLI_H

#include "config.h"

#define GIFTIDS_VERSION "0.14.0"

typedef enum {
    MODE_LIVE_CAPTURE = 0,
    MODE_PCAP_READ
} GiftIDSRunMode;

typedef struct {
    GiftIDSRunMode mode;
    char interface_name[64];
    char pcap_file[256];
    char config_path[256];

    int show_stats;
    int verbose;
    int quiet;

    int packet_logging_enabled;
    int alert_logging_enabled;

    char packet_log_override[256];
    char alert_log_override[256];

    char report_path[256];
    char report_format[16];
    int report_enabled;

    int json_output;

    long max_packets;
    int show_help;
    int show_version;

    int disable_suspicious_port_rule;
    int disable_tcp_syn_watch_rule;
    int disable_icmp_echo_rule;
    int disable_port_scan_detection;
    int disable_syn_flood_detection;
    int disable_icmp_flood_detection;
} GiftIDSRuntimeOptions;

void cli_set_defaults(GiftIDSRuntimeOptions *options);
int cli_parse_args(int argc, char **argv, GiftIDSRuntimeOptions *options);
void cli_apply_config_overrides(const GiftIDSRuntimeOptions *options, GiftIDSConfig *config);
void cli_print_help(const char *program);
void cli_print_version(void);

#endif
