#include "logger.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static FILE *log_file = NULL;
static FILE *alert_log_file = NULL;
static int packet_logging_enabled = 1;
static int alert_logging_enabled = 1;

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

static void append_flag(char *buffer, size_t buffer_size, const char *flag)
{
    size_t used;

    used = strlen(buffer);
    if (used + 1 >= buffer_size) {
        return;
    }

    if (buffer[0] != '\0') {
        strncat(buffer, ",", buffer_size - used - 1);
        used = strlen(buffer);
        if (used + 1 >= buffer_size) {
            return;
        }
    }

    strncat(buffer, flag, buffer_size - used - 1);
}

static void make_tcp_flags(const PacketInfo *info, char *buffer, size_t buffer_size)
{
    buffer[0] = '\0';

    if (info->tcp_syn) {
        append_flag(buffer, buffer_size, "SYN");
    }
    if (info->tcp_ack) {
        append_flag(buffer, buffer_size, "ACK");
    }
    if (info->tcp_fin) {
        append_flag(buffer, buffer_size, "FIN");
    }
    if (info->tcp_rst) {
        append_flag(buffer, buffer_size, "RST");
    }
    if (info->tcp_psh) {
        append_flag(buffer, buffer_size, "PSH");
    }
    if (info->tcp_urg) {
        append_flag(buffer, buffer_size, "URG");
    }

    if (buffer[0] == '\0') {
        snprintf(buffer, buffer_size, "NONE");
    }
}

static void make_packet_summary(const PacketInfo *info, char *buffer, size_t buffer_size, int detailed)
{
    int written;

    if (detailed) {
        written = snprintf(buffer, buffer_size,
                           "frame_len=%u IPv4 %s -> %s proto=%s ttl=%u ip_len=%u",
                           info->frame_len,
                           info->src_ip,
                           info->dst_ip,
                           info->protocol,
                           info->ttl,
                           info->ip_len);
    } else {
        written = snprintf(buffer, buffer_size,
                           "IPv4 %s -> %s proto=%s",
                           info->src_ip,
                           info->dst_ip,
                           info->protocol);
    }

    if (written < 0 || (size_t)written >= buffer_size) {
        return;
    }

    if (strcmp(info->protocol, "TCP") == 0) {
        if (detailed) {
            char flags[64];

            make_tcp_flags(info, flags, sizeof(flags));
            snprintf(buffer + written, buffer_size - (size_t)written,
                     " sport=%u dport=%u flags=%s",
                     info->src_port,
                     info->dst_port,
                     flags);
        } else {
            snprintf(buffer + written, buffer_size - (size_t)written,
                     " sport=%u dport=%u",
                     info->src_port,
                     info->dst_port);
        }
    } else if (strcmp(info->protocol, "UDP") == 0) {
        snprintf(buffer + written, buffer_size - (size_t)written,
                 " sport=%u dport=%u",
                 info->src_port,
                 info->dst_port);
    } else if (strcmp(info->protocol, "ICMP") == 0) {
        snprintf(buffer + written, buffer_size - (size_t)written,
                 " icmp_type=%u icmp_code=%u",
                 info->icmp_type,
                 info->icmp_code);
    }
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
        fprintf(stderr, "Warning: log directory path is too long for '%s'\n", path);
        return -1;
    }

    memcpy(directory, path, directory_len);
    directory[directory_len] = '\0';

    if (mkdir(directory, 0755) == 0 || errno == EEXIST) {
        return 0;
    }

    fprintf(stderr, "Warning: could not create log directory '%s': %s\n", directory, strerror(errno));
    return -1;
}

static int open_log_target(const char *path, FILE **target, const char *label)
{
    if (path == NULL || *path == '\0') {
        fprintf(stderr, "Warning: %s log path is empty; file logging disabled for this log\n", label);
        return -1;
    }

    if (ensure_parent_directory(path) != 0) {
        fprintf(stderr, "Warning: %s log file '%s' was not opened\n", label, path);
        return -1;
    }

    *target = fopen(path, "a");
    if (*target == NULL) {
        fprintf(stderr, "Warning: could not open %s log file '%s': %s\n", label, path, strerror(errno));
        return -1;
    }

    return 0;
}

int logger_init(const GiftIDSConfig *config)
{
    GiftIDSConfig defaults;
    const GiftIDSConfig *active_config = config;
    int status = 0;

    if (active_config == NULL) {
        config_set_defaults(&defaults);
        active_config = &defaults;
    }

    logger_close();

    if (packet_logging_enabled &&
        open_log_target(active_config->packet_log_file, &log_file, "packet") != 0) {
        status = -1;
    }

    if (alert_logging_enabled &&
        open_log_target(active_config->alert_log_file, &alert_log_file, "alert") != 0) {
        status = -1;
    }

    return status;
}

int logger_open(const char *path)
{
    GiftIDSConfig config;

    config_set_defaults(&config);
    if (path != NULL && *path != '\0') {
        snprintf(config.packet_log_file, sizeof(config.packet_log_file), "%s", path);
    }

    return logger_init(&config);
}

void logger_set_packet_logging_enabled(int enabled)
{
    packet_logging_enabled = enabled ? 1 : 0;
}

void logger_set_alert_logging_enabled(int enabled)
{
    alert_logging_enabled = enabled ? 1 : 0;
}

void logger_close(void)
{
    /*
     * Graceful shutdown matters for an IDS because Ctrl+C should not leave
     * buffered log entries hidden in memory. fclose() flushes before closing.
     */
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }

    if (alert_log_file != NULL) {
        fclose(alert_log_file);
        alert_log_file = NULL;
    }
}

void logger_print_packet(const PacketInfo *info)
{
    char timestamp[32];
    char summary[512];

    if (info == NULL || !info->valid) {
        return;
    }

    make_timestamp(info->timestamp, timestamp, sizeof(timestamp));
    make_packet_summary(info, summary, sizeof(summary), 0);
    printf("[%s] %s\n", timestamp, summary);
}

void logger_print_packet_verbose(const PacketInfo *info)
{
    char timestamp[32];
    char summary[512];

    if (info == NULL || !info->valid) {
        return;
    }

    make_timestamp(info->timestamp, timestamp, sizeof(timestamp));
    make_packet_summary(info, summary, sizeof(summary), 1);
    printf("[%s] %s\n", timestamp, summary);
}

void logger_log_packet(const PacketInfo *info)
{
    char timestamp[32];
    char summary[512];

    if (!packet_logging_enabled || log_file == NULL || info == NULL || !info->valid) {
        return;
    }

    make_timestamp(info->timestamp, timestamp, sizeof(timestamp));
    make_packet_summary(info, summary, sizeof(summary), 1);
    fprintf(log_file, "[%s] %s\n", timestamp, summary);

    /*
     * Flushing after each packet is slower, but it makes sure a beginner can
     * stop the IDS and immediately see the latest events in the log file.
     */
    fflush(log_file);
}

void logger_print_alert(const DetectionResult *result)
{
    const char *evidence;

    if (result == NULL || !result->alert) {
        return;
    }

    evidence = result->evidence[0] != '\0' ? result->evidence : result->message;
    printf("[ALERT] %s %s %s -> %s evidence=\"%s\"\n",
           severity_to_string(result->severity),
           result->type,
           result->src_ip,
           result->dst_ip,
           evidence);
}

void logger_print_alert_verbose(const DetectionResult *result)
{
    if (result == NULL || !result->alert) {
        return;
    }

    printf("[ALERT]\n");
    printf("Severity: %s\n", severity_to_string(result->severity));
    printf("Type: %s\n", result->type);
    printf("Source: %s\n", result->src_ip);
    printf("Destination: %s\n", result->dst_ip);
    printf("Protocol: %s\n", result->protocol);

    if (result->src_port > 0) {
        printf("Source Port: %u\n", result->src_port);
    }

    if (result->dst_port > 0) {
        printf("Destination Port: %u\n", result->dst_port);
    }

    if (result->observed_count > 0) {
        printf("Observed Count: %d\n", result->observed_count);
    }

    if (result->unique_ports > 0) {
        printf("Unique Ports: %d\n", result->unique_ports);
    }

    if (result->threshold > 0) {
        printf("Threshold: %d\n", result->threshold);
    }

    if (result->window_seconds > 0) {
        printf("Window: %d seconds\n", result->window_seconds);
    }

    printf("Evidence: %s\n", result->evidence[0] != '\0' ? result->evidence : result->message);

    if (result->recommendation[0] != '\0') {
        printf("Recommendation: %s\n", result->recommendation);
    }
}

void log_alert(const DetectionResult *result)
{
    char timestamp[32];
    const char *evidence;
    const char *recommendation;

    if (!alert_logging_enabled || alert_log_file == NULL || result == NULL || !result->alert) {
        return;
    }

    make_timestamp(time(NULL), timestamp, sizeof(timestamp));
    evidence = result->evidence[0] != '\0' ? result->evidence : result->message;
    recommendation = result->recommendation[0] != '\0' ? result->recommendation : "";
    fprintf(alert_log_file,
            "[%s] [ALERT] severity=%s type=\"%s\" src=%s dst=%s protocol=%s src_port=%u dst_port=%u observed_count=%d unique_ports=%d threshold=%d window=%d evidence=\"%s\" recommendation=\"%s\"\n",
            timestamp,
            severity_to_string(result->severity),
            result->type,
            result->src_ip,
            result->dst_ip,
            result->protocol,
            result->src_port,
            result->dst_port,
            result->observed_count,
            result->unique_ports,
            result->threshold,
            result->window_seconds,
            evidence,
            recommendation);
    fflush(alert_log_file);
}
