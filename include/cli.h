#ifndef CLI_H
#define CLI_H

#include "config.h"

#define GIFTIDS_VERSION "0.8.0"

typedef struct {
    char interface_name[64];
    char config_path[256];

    int show_stats;
    int verbose;
    int quiet;

    int packet_logging_enabled;
    int alert_logging_enabled;

    char packet_log_override[256];
    char alert_log_override[256];

    long max_packets;
    int show_help;
    int show_version;
} GiftIDSRuntimeOptions;

void cli_set_defaults(GiftIDSRuntimeOptions *options);
int cli_parse_args(int argc, char **argv, GiftIDSRuntimeOptions *options);
void cli_apply_config_overrides(const GiftIDSRuntimeOptions *options, GiftIDSConfig *config);
void cli_print_help(const char *program);
void cli_print_version(void);

#endif
