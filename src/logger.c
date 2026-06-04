#include "logger.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static FILE *log_file = NULL;
static FILE *alert_log_file = NULL;

static void make_timestamp(char *buffer, size_t buffer_size)
{
    time_t now;
    struct tm local_time;

    now = time(NULL);
    localtime_r(&now, &local_time);
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

static void make_packet_summary(const PacketInfo *info, char *buffer, size_t buffer_size)
{
    int written;

    written = snprintf(buffer, buffer_size,
                       "frame_len=%u IPv4 %s -> %s proto=%s ttl=%u ip_len=%u",
                       info->frame_len,
                       info->src_ip,
                       info->dst_ip,
                       info->protocol,
                       info->ttl,
                       info->ip_len);

    if (written < 0 || (size_t)written >= buffer_size) {
        return;
    }

    if (strcmp(info->protocol, "TCP") == 0) {
        char flags[64];

        make_tcp_flags(info, flags, sizeof(flags));
        snprintf(buffer + written, buffer_size - (size_t)written,
                 " sport=%u dport=%u flags=%s",
                 info->src_port,
                 info->dst_port,
                 flags);
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

static int ensure_log_directory(void)
{
    if (mkdir("logs", 0755) == 0 || errno == EEXIST) {
        return 0;
    }

    perror("mkdir logs");
    return -1;
}

int logger_open(const char *path)
{
    if (ensure_log_directory() != 0) {
        return -1;
    }

    log_file = fopen(path, "a");
    if (log_file == NULL) {
        perror(path);
        return -1;
    }

    alert_log_file = fopen(GIFTIDS_ALERT_LOG_FILE, "a");
    if (alert_log_file == NULL) {
        perror(GIFTIDS_ALERT_LOG_FILE);
        fclose(log_file);
        log_file = NULL;
        return -1;
    }

    return 0;
}

void logger_close(void)
{
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

    make_timestamp(timestamp, sizeof(timestamp));
    make_packet_summary(info, summary, sizeof(summary));
    printf("[%s] %s\n", timestamp, summary);
}

void logger_log_packet(const PacketInfo *info)
{
    char timestamp[32];
    char summary[512];

    if (log_file == NULL || info == NULL || !info->valid) {
        return;
    }

    make_timestamp(timestamp, sizeof(timestamp));
    make_packet_summary(info, summary, sizeof(summary));
    fprintf(log_file, "[%s] %s\n", timestamp, summary);

    /*
     * Flushing after each packet is slower, but it makes sure a beginner can
     * stop the IDS and immediately see the latest events in the log file.
     */
    fflush(log_file);
}

void logger_print_alert(const DetectionResult *result)
{
    if (result == NULL || !result->alert) {
        return;
    }

    printf("[ALERT] %s %s %s -> %s %s\n",
           severity_to_string(result->severity),
           result->type,
           result->src_ip,
           result->dst_ip,
           result->message);
}

void log_alert(const DetectionResult *result)
{
    char timestamp[32];

    if (alert_log_file == NULL || result == NULL || !result->alert) {
        return;
    }

    make_timestamp(timestamp, sizeof(timestamp));
    fprintf(alert_log_file,
            "[%s] [ALERT] severity=%s type=\"%s\" src=%s dst=%s message=\"%s\"\n",
            timestamp,
            severity_to_string(result->severity),
            result->type,
            result->src_ip,
            result->dst_ip,
            result->message);
    fflush(alert_log_file);
}
