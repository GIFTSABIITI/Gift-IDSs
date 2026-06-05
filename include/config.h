#ifndef CONFIG_H
#define CONFIG_H

#define GIFTIDS_CONFIG_PATH "config/giftids.conf"
#define GIFTIDS_DEFAULT_PACKET_LOG_FILE "logs/giftids.log"
#define GIFTIDS_DEFAULT_ALERT_LOG_FILE "logs/giftids_alerts.log"

typedef struct {
    int port_scan_threshold;
    int port_scan_window_seconds;

    int syn_flood_threshold;
    int syn_flood_window_seconds;

    int icmp_flood_threshold;
    int icmp_flood_window_seconds;

    int alert_cooldown_seconds;

    char packet_log_file[256];
    char alert_log_file[256];
} GiftIDSConfig;

void config_set_defaults(GiftIDSConfig *config);
int config_load(const char *path, GiftIDSConfig *config);

#endif
