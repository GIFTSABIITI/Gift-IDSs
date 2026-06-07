#include "report.h"

#include "json_output.h"
#include "stats.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static void make_timestamp(time_t timestamp, char *buffer, size_t buffer_size)
{
    struct tm local_time;

    if (timestamp == 0) {
        timestamp = time(NULL);
    }

    if (localtime_r(&timestamp, &local_time) == NULL) {
        snprintf(buffer, buffer_size, "unknown-time");
        return;
    }

    strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", &local_time);
}

static unsigned long long runtime_seconds_from_stats(const GiftIDSStats *snapshot)
{
    time_t now;

    if (snapshot == NULL || snapshot->start_time == 0) {
        return 0;
    }

    now = time(NULL);
    if (now < snapshot->start_time) {
        return 0;
    }

    return (unsigned long long)difftime(now, snapshot->start_time);
}

static const char *bool_text(int enabled)
{
    return enabled ? "enabled" : "disabled";
}

static const char *json_bool(int enabled)
{
    return enabled ? "true" : "false";
}

static const char *run_mode_label(const GiftIDSRuntimeOptions *options)
{
    if (options != NULL && options->mode == MODE_PCAP_READ) {
        return "PCAP Read";
    }

    return "Live Capture";
}

static const char *run_mode_json(const GiftIDSRuntimeOptions *options)
{
    if (options != NULL && options->mode == MODE_PCAP_READ) {
        return "pcap_read";
    }

    return "live_capture";
}

static const char *safe_text(const char *value)
{
    if (value == NULL) {
        return "";
    }

    return value;
}

static int ensure_parent_directory(const char *path)
{
    char directory[256];
    const char *slash;
    size_t directory_len;

    if (path == NULL) {
        return -1;
    }

    slash = strrchr(path, '/');
    if (slash == NULL || slash == path) {
        return 0;
    }

    directory_len = (size_t)(slash - path);
    if (directory_len >= sizeof(directory)) {
        fprintf(stderr, "Error: report directory path is too long for '%s'\n", path);
        return -1;
    }

    memcpy(directory, path, directory_len);
    directory[directory_len] = '\0';

    if (mkdir(directory, 0755) == 0 || errno == EEXIST) {
        return 0;
    }

    fprintf(stderr, "Error: could not create report directory '%s': %s\n", directory, strerror(errno));
    return -1;
}

static FILE *open_report_file(const char *path)
{
    FILE *file;

    if (path == NULL || *path == '\0') {
        fprintf(stderr, "Error: report path is empty\n");
        return NULL;
    }

    if (ensure_parent_directory(path) != 0) {
        return NULL;
    }

    file = fopen(path, "w");
    if (file == NULL) {
        fprintf(stderr, "Error: could not create report file '%s': %s\n", path, strerror(errno));
        return NULL;
    }

    return file;
}

static const GiftIDSRuntimeOptions *active_options_or_defaults(const GiftIDSRuntimeOptions *options,
                                                               GiftIDSRuntimeOptions *defaults)
{
    if (options != NULL) {
        return options;
    }

    cli_set_defaults(defaults);
    return defaults;
}

static const GiftIDSConfig *active_config_or_defaults(const GiftIDSConfig *config, GiftIDSConfig *defaults)
{
    if (config != NULL) {
        return config;
    }

    config_set_defaults(defaults);
    return defaults;
}

int report_generate(const char *path,
                    const char *format,
                    const GiftIDSRuntimeOptions *options,
                    const GiftIDSConfig *config)
{
    if (format == NULL || *format == '\0' || strcmp(format, "txt") == 0) {
        return report_generate_text(path, options, config);
    }

    if (strcmp(format, "json") == 0) {
        return report_generate_json(path, options, config);
    }

    fprintf(stderr, "Error: unsupported report format '%s' (supported: txt, json)\n", format);
    return -1;
}

int report_generate_text(const char *path,
                         const GiftIDSRuntimeOptions *options,
                         const GiftIDSConfig *config)
{
    GiftIDSRuntimeOptions default_options;
    GiftIDSConfig default_config;
    const GiftIDSRuntimeOptions *active_options;
    const GiftIDSConfig *active_config;
    GiftIDSStats snapshot;
    char generated_at[32];
    FILE *file;

    file = open_report_file(path);
    if (file == NULL) {
        return -1;
    }

    active_options = active_options_or_defaults(options, &default_options);
    active_config = active_config_or_defaults(config, &default_config);
    snapshot = stats_get_snapshot();
    make_timestamp(time(NULL), generated_at, sizeof(generated_at));

    /*
     * Reports preserve the end-of-session story after terminal output scrolls
     * away. They are especially useful when tuning thresholds with repeatable
     * PCAP runs or reviewing a lab capture after the fact.
     */
    fprintf(file, "Gift IDS Session Report\n");
    fprintf(file, "=======================\n\n");
    fprintf(file, "Generated At:\n- %s\n\n", generated_at);
    fprintf(file, "Run Mode:\n- %s\n\n", run_mode_label(active_options));
    fprintf(file, "Interface:\n- %s\n\n", safe_text(active_options->interface_name));
    fprintf(file, "PCAP File:\n- %s\n\n", safe_text(active_options->pcap_file));
    fprintf(file, "Config File:\n- %s\n\n", safe_text(active_options->config_path));

    fprintf(file, "Runtime Summary:\n");
    fprintf(file, "- Runtime: %llu seconds\n", runtime_seconds_from_stats(&snapshot));
    fprintf(file, "- Packets captured: %llu\n", snapshot.total_packets);
    fprintf(file, "- Valid packets: %llu\n", snapshot.valid_packets);
    fprintf(file, "- Invalid packets: %llu\n", snapshot.invalid_packets);
    fprintf(file, "- TCP packets: %llu\n", snapshot.tcp_packets);
    fprintf(file, "- UDP packets: %llu\n", snapshot.udp_packets);
    fprintf(file, "- ICMP packets: %llu\n", snapshot.icmp_packets);
    fprintf(file, "- Other packets: %llu\n", snapshot.other_packets);
    fprintf(file, "- Bytes seen: %llu\n\n", snapshot.bytes_seen);

    fprintf(file, "Alert Summary:\n");
    fprintf(file, "- Total alerts: %llu\n", snapshot.total_alerts);
    fprintf(file, "- Low alerts: %llu\n", snapshot.low_alerts);
    fprintf(file, "- Medium alerts: %llu\n", snapshot.medium_alerts);
    fprintf(file, "- High alerts: %llu\n\n", snapshot.high_alerts);

    fprintf(file, "Alert Type Breakdown:\n");
    fprintf(file, "- Suspicious Port: %llu\n", snapshot.suspicious_port_alerts);
    fprintf(file, "- TCP SYN Watch: %llu\n", snapshot.tcp_syn_watch_alerts);
    fprintf(file, "- ICMP Echo Request: %llu\n", snapshot.icmp_echo_alerts);
    fprintf(file, "- Possible Port Scan: %llu\n", snapshot.port_scan_alerts);
    fprintf(file, "- Possible SYN Flood: %llu\n", snapshot.syn_flood_alerts);
    fprintf(file, "- Possible ICMP Flood: %llu\n\n", snapshot.icmp_flood_alerts);

    fprintf(file, "Detection Configuration:\n");
    fprintf(file, "- Port scan threshold: %d\n", active_config->port_scan_threshold);
    fprintf(file, "- Port scan window seconds: %d\n", active_config->port_scan_window_seconds);
    fprintf(file, "- SYN flood threshold: %d\n", active_config->syn_flood_threshold);
    fprintf(file, "- SYN flood window seconds: %d\n", active_config->syn_flood_window_seconds);
    fprintf(file, "- ICMP flood threshold: %d\n", active_config->icmp_flood_threshold);
    fprintf(file, "- ICMP flood window seconds: %d\n", active_config->icmp_flood_window_seconds);
    fprintf(file, "- Alert cooldown seconds: %d\n", active_config->alert_cooldown_seconds);
    fprintf(file, "- Suspicious Port rule: %s\n", bool_text(active_config->enable_suspicious_port_rule));
    fprintf(file, "- TCP SYN Watch rule: %s\n", bool_text(active_config->enable_tcp_syn_watch_rule));
    fprintf(file, "- ICMP Echo Request rule: %s\n", bool_text(active_config->enable_icmp_echo_rule));
    fprintf(file, "- Port scan detection: %s\n", bool_text(active_config->enable_port_scan_detection));
    fprintf(file, "- SYN flood detection: %s\n", bool_text(active_config->enable_syn_flood_detection));
    fprintf(file, "- ICMP flood detection: %s\n\n", bool_text(active_config->enable_icmp_flood_detection));

    fprintf(file, "Log Files:\n");
    fprintf(file, "- Packet log path: %s\n", active_config->packet_log_file);
    fprintf(file, "- Alert log path: %s\n\n", active_config->alert_log_file);

    fprintf(file, "Recommendations:\n");
    fprintf(file, "- Review high severity alerts first.\n");
    fprintf(file, "- Investigate repeated alerts from the same source IP.\n");
    fprintf(file, "- Tune thresholds in config/giftids.conf to match the lab environment.\n");
    fprintf(file, "- Use PCAP mode for repeatable testing.\n");

    if (fclose(file) != 0) {
        fprintf(stderr, "Error: could not finish report file '%s': %s\n", path, strerror(errno));
        return -1;
    }

    return 0;
}

int report_generate_json(const char *path,
                         const GiftIDSRuntimeOptions *options,
                         const GiftIDSConfig *config)
{
    GiftIDSRuntimeOptions default_options;
    GiftIDSConfig default_config;
    const GiftIDSRuntimeOptions *active_options;
    const GiftIDSConfig *active_config;
    GiftIDSStats snapshot;
    char generated_at[32];
    char escaped_generated_at[128];
    char escaped_run_mode[64];
    char escaped_interface[512];
    char escaped_pcap_file[512];
    char escaped_config_file[512];
    char escaped_packet_log[512];
    char escaped_alert_log[512];
    FILE *file;

    file = open_report_file(path);
    if (file == NULL) {
        return -1;
    }

    active_options = active_options_or_defaults(options, &default_options);
    active_config = active_config_or_defaults(config, &default_config);
    snapshot = stats_get_snapshot();
    make_timestamp(time(NULL), generated_at, sizeof(generated_at));

    json_escape_string(generated_at, escaped_generated_at, sizeof(escaped_generated_at));
    json_escape_string(run_mode_json(active_options), escaped_run_mode, sizeof(escaped_run_mode));
    json_escape_string(active_options->interface_name, escaped_interface, sizeof(escaped_interface));
    json_escape_string(active_options->pcap_file, escaped_pcap_file, sizeof(escaped_pcap_file));
    json_escape_string(active_options->config_path, escaped_config_file, sizeof(escaped_config_file));
    json_escape_string(active_config->packet_log_file, escaped_packet_log, sizeof(escaped_packet_log));
    json_escape_string(active_config->alert_log_file, escaped_alert_log, sizeof(escaped_alert_log));

    fprintf(file, "{\n");
    fprintf(file, "  \"project\": \"Gift IDS\",\n");
    fprintf(file, "  \"report_type\": \"session_report\",\n");
    fprintf(file, "  \"generated_at\": \"%s\",\n", escaped_generated_at);
    fprintf(file, "  \"run_mode\": \"%s\",\n", escaped_run_mode);
    fprintf(file, "  \"interface\": \"%s\",\n", escaped_interface);
    fprintf(file, "  \"pcap_file\": \"%s\",\n", escaped_pcap_file);
    fprintf(file, "  \"config_file\": \"%s\",\n", escaped_config_file);
    fprintf(file, "  \"runtime_summary\": {\n");
    fprintf(file, "    \"runtime_seconds\": %llu,\n", runtime_seconds_from_stats(&snapshot));
    fprintf(file, "    \"total_packets\": %llu,\n", snapshot.total_packets);
    fprintf(file, "    \"valid_packets\": %llu,\n", snapshot.valid_packets);
    fprintf(file, "    \"invalid_packets\": %llu,\n", snapshot.invalid_packets);
    fprintf(file, "    \"tcp_packets\": %llu,\n", snapshot.tcp_packets);
    fprintf(file, "    \"udp_packets\": %llu,\n", snapshot.udp_packets);
    fprintf(file, "    \"icmp_packets\": %llu,\n", snapshot.icmp_packets);
    fprintf(file, "    \"other_packets\": %llu,\n", snapshot.other_packets);
    fprintf(file, "    \"bytes_seen\": %llu\n", snapshot.bytes_seen);
    fprintf(file, "  },\n");
    fprintf(file, "  \"alert_summary\": {\n");
    fprintf(file, "    \"total_alerts\": %llu,\n", snapshot.total_alerts);
    fprintf(file, "    \"low_alerts\": %llu,\n", snapshot.low_alerts);
    fprintf(file, "    \"medium_alerts\": %llu,\n", snapshot.medium_alerts);
    fprintf(file, "    \"high_alerts\": %llu\n", snapshot.high_alerts);
    fprintf(file, "  },\n");
    fprintf(file, "  \"alert_type_breakdown\": {\n");
    fprintf(file, "    \"suspicious_port\": %llu,\n", snapshot.suspicious_port_alerts);
    fprintf(file, "    \"tcp_syn_watch\": %llu,\n", snapshot.tcp_syn_watch_alerts);
    fprintf(file, "    \"icmp_echo_request\": %llu,\n", snapshot.icmp_echo_alerts);
    fprintf(file, "    \"possible_port_scan\": %llu,\n", snapshot.port_scan_alerts);
    fprintf(file, "    \"possible_syn_flood\": %llu,\n", snapshot.syn_flood_alerts);
    fprintf(file, "    \"possible_icmp_flood\": %llu\n", snapshot.icmp_flood_alerts);
    fprintf(file, "  },\n");
    fprintf(file, "  \"detection_config\": {\n");
    fprintf(file, "    \"port_scan_threshold\": %d,\n", active_config->port_scan_threshold);
    fprintf(file, "    \"port_scan_window_seconds\": %d,\n", active_config->port_scan_window_seconds);
    fprintf(file, "    \"syn_flood_threshold\": %d,\n", active_config->syn_flood_threshold);
    fprintf(file, "    \"syn_flood_window_seconds\": %d,\n", active_config->syn_flood_window_seconds);
    fprintf(file, "    \"icmp_flood_threshold\": %d,\n", active_config->icmp_flood_threshold);
    fprintf(file, "    \"icmp_flood_window_seconds\": %d,\n", active_config->icmp_flood_window_seconds);
    fprintf(file, "    \"alert_cooldown_seconds\": %d,\n", active_config->alert_cooldown_seconds);
    fprintf(file, "    \"enable_suspicious_port_rule\": %s,\n", json_bool(active_config->enable_suspicious_port_rule));
    fprintf(file, "    \"enable_tcp_syn_watch_rule\": %s,\n", json_bool(active_config->enable_tcp_syn_watch_rule));
    fprintf(file, "    \"enable_icmp_echo_rule\": %s,\n", json_bool(active_config->enable_icmp_echo_rule));
    fprintf(file, "    \"enable_port_scan_detection\": %s,\n", json_bool(active_config->enable_port_scan_detection));
    fprintf(file, "    \"enable_syn_flood_detection\": %s,\n", json_bool(active_config->enable_syn_flood_detection));
    fprintf(file, "    \"enable_icmp_flood_detection\": %s\n", json_bool(active_config->enable_icmp_flood_detection));
    fprintf(file, "  },\n");
    fprintf(file, "  \"log_files\": {\n");
    fprintf(file, "    \"packet_log_path\": \"%s\",\n", escaped_packet_log);
    fprintf(file, "    \"alert_log_path\": \"%s\"\n", escaped_alert_log);
    fprintf(file, "  },\n");
    fprintf(file, "  \"recommendations\": [\n");
    fprintf(file, "    \"Review high severity alerts first.\",\n");
    fprintf(file, "    \"Investigate repeated alerts from the same source IP.\",\n");
    fprintf(file, "    \"Tune thresholds in config/giftids.conf to match the lab environment.\",\n");
    fprintf(file, "    \"Use PCAP mode for repeatable testing.\"\n");
    fprintf(file, "  ]\n");
    fprintf(file, "}\n");

    if (fclose(file) != 0) {
        fprintf(stderr, "Error: could not finish report file '%s': %s\n", path, strerror(errno));
        return -1;
    }

    return 0;
}
