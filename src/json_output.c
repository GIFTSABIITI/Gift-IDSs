#include "json_output.h"

#include "stats.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
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

static int appendf(char *buffer, size_t buffer_size, size_t *used, const char *format, ...)
{
    va_list args;
    int written;

    if (buffer == NULL || buffer_size == 0 || used == NULL || *used >= buffer_size) {
        return -1;
    }

    va_start(args, format);
    written = vsnprintf(buffer + *used, buffer_size - *used, format, args);
    va_end(args);

    if (written < 0 || (size_t)written >= buffer_size - *used) {
        buffer[buffer_size - 1] = '\0';
        *used = buffer_size - 1;
        return -1;
    }

    *used += (size_t)written;
    return 0;
}

void json_escape_string(const char *input, char *output, size_t output_size)
{
    size_t in_index = 0;
    size_t out_index = 0;
    static const char hex[] = "0123456789abcdef";

    if (output == NULL || output_size == 0) {
        return;
    }

    if (input == NULL) {
        input = "";
    }

    /*
     * JSON strings cannot safely contain raw quotes, backslashes, newlines, or
     * control characters. Escaping keeps terminal JSON lines valid even when a
     * message or file path contains text that would otherwise break parsing.
     */
    while (input[in_index] != '\0' && out_index + 1 < output_size) {
        unsigned char c = (unsigned char)input[in_index++];

        if (c == '"' || c == '\\') {
            if (out_index + 2 >= output_size) {
                break;
            }
            output[out_index++] = '\\';
            output[out_index++] = (char)c;
        } else if (c == '\n') {
            if (out_index + 2 >= output_size) {
                break;
            }
            output[out_index++] = '\\';
            output[out_index++] = 'n';
        } else if (c == '\r') {
            if (out_index + 2 >= output_size) {
                break;
            }
            output[out_index++] = '\\';
            output[out_index++] = 'r';
        } else if (c == '\t') {
            if (out_index + 2 >= output_size) {
                break;
            }
            output[out_index++] = '\\';
            output[out_index++] = 't';
        } else if (c < 0x20) {
            if (out_index + 6 >= output_size) {
                break;
            }
            output[out_index++] = '\\';
            output[out_index++] = 'u';
            output[out_index++] = '0';
            output[out_index++] = '0';
            output[out_index++] = hex[(c >> 4) & 0x0f];
            output[out_index++] = hex[c & 0x0f];
        } else {
            output[out_index++] = (char)c;
        }
    }

    output[out_index] = '\0';
}

int json_format_packet(const PacketInfo *pkt, int verbose, char *buffer, size_t buffer_size)
{
    char timestamp[32];
    char src_ip[64];
    char dst_ip[64];
    char protocol[32];
    size_t used = 0;

    if (pkt == NULL || !pkt->valid || buffer == NULL || buffer_size == 0) {
        return -1;
    }

    make_timestamp(pkt->timestamp, timestamp, sizeof(timestamp));
    json_escape_string(pkt->src_ip, src_ip, sizeof(src_ip));
    json_escape_string(pkt->dst_ip, dst_ip, sizeof(dst_ip));
    json_escape_string(pkt->protocol, protocol, sizeof(protocol));

    if (appendf(buffer, buffer_size, &used,
                "{\"event_type\":\"packet\",\"timestamp\":\"%s\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"%s\",\"src_port\":%u,\"dst_port\":%u,\"ttl\":%u,\"ip_len\":%u,\"frame_len\":%u",
                timestamp,
                src_ip,
                dst_ip,
                protocol,
                pkt->src_port,
                pkt->dst_port,
                pkt->ttl,
                pkt->ip_len,
                pkt->frame_len) != 0) {
        return -1;
    }

    if (verbose) {
        if (appendf(buffer, buffer_size, &used,
                    ",\"tcp_syn\":%u,\"tcp_ack\":%u,\"tcp_fin\":%u,\"tcp_rst\":%u,\"tcp_psh\":%u,\"tcp_urg\":%u,\"icmp_type\":%u,\"icmp_code\":%u",
                    pkt->tcp_syn,
                    pkt->tcp_ack,
                    pkt->tcp_fin,
                    pkt->tcp_rst,
                    pkt->tcp_psh,
                    pkt->tcp_urg,
                    pkt->icmp_type,
                    pkt->icmp_code) != 0) {
            return -1;
        }
    }

    return appendf(buffer, buffer_size, &used, "}");
}

int json_format_alert(const DetectionResult *alert, char *buffer, size_t buffer_size)
{
    char timestamp[32];
    char severity[32];
    char type[160];
    char src_ip[64];
    char dst_ip[64];
    char protocol[64];
    char evidence[1200];
    char recommendation[1200];
    time_t event_time;
    size_t used = 0;

    if (alert == NULL || !alert->alert || buffer == NULL || buffer_size == 0) {
        return -1;
    }

    event_time = alert->last_seen != 0 ? alert->last_seen : time(NULL);
    make_timestamp(event_time, timestamp, sizeof(timestamp));
    json_escape_string(severity_to_string(alert->severity), severity, sizeof(severity));
    json_escape_string(alert->type, type, sizeof(type));
    json_escape_string(alert->src_ip, src_ip, sizeof(src_ip));
    json_escape_string(alert->dst_ip, dst_ip, sizeof(dst_ip));
    json_escape_string(alert->protocol, protocol, sizeof(protocol));
    json_escape_string(alert->evidence, evidence, sizeof(evidence));
    json_escape_string(alert->recommendation, recommendation, sizeof(recommendation));

    return appendf(buffer, buffer_size, &used,
                   "{\"event_type\":\"alert\",\"timestamp\":\"%s\",\"severity\":\"%s\",\"type\":\"%s\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"%s\",\"src_port\":%u,\"dst_port\":%u,\"observed_count\":%d,\"unique_ports\":%d,\"threshold\":%d,\"window_seconds\":%d,\"evidence\":\"%s\",\"recommendation\":\"%s\"}",
                   timestamp,
                   severity,
                   type,
                   src_ip,
                   dst_ip,
                   protocol,
                   alert->src_port,
                   alert->dst_port,
                   alert->observed_count,
                   alert->unique_ports,
                   alert->threshold,
                   alert->window_seconds,
                   evidence,
                   recommendation);
}

int json_format_stats_event(char *buffer, size_t buffer_size)
{
    GiftIDSStats snapshot;
    char timestamp[32];
    size_t used = 0;

    if (buffer == NULL || buffer_size == 0) {
        return -1;
    }

    snapshot = stats_get_snapshot();
    make_timestamp(time(NULL), timestamp, sizeof(timestamp));

    return appendf(buffer, buffer_size, &used,
                   "{\"event_type\":\"stats\",\"timestamp\":\"%s\",\"runtime_seconds\":%llu,\"total_packets\":%llu,\"valid_packets\":%llu,\"invalid_packets\":%llu,\"tcp_packets\":%llu,\"udp_packets\":%llu,\"icmp_packets\":%llu,\"total_alerts\":%llu}",
                   timestamp,
                   runtime_seconds_from_stats(&snapshot),
                   snapshot.total_packets,
                   snapshot.valid_packets,
                   snapshot.invalid_packets,
                   snapshot.tcp_packets,
                   snapshot.udp_packets,
                   snapshot.icmp_packets,
                   snapshot.total_alerts);
}

int json_format_session_complete(char *buffer, size_t buffer_size)
{
    GiftIDSStats snapshot;
    char timestamp[32];
    size_t used = 0;

    if (buffer == NULL || buffer_size == 0) {
        return -1;
    }

    snapshot = stats_get_snapshot();
    make_timestamp(time(NULL), timestamp, sizeof(timestamp));

    return appendf(buffer, buffer_size, &used,
                   "{\"event_type\":\"session_complete\",\"timestamp\":\"%s\",\"runtime_seconds\":%llu,\"total_packets\":%llu,\"total_alerts\":%llu}",
                   timestamp,
                   runtime_seconds_from_stats(&snapshot),
                   snapshot.total_packets,
                   snapshot.total_alerts);
}

void json_print_packet(const PacketInfo *pkt, int verbose)
{
    char buffer[2048];

    /*
     * JSON Lines are a good fit for terminal streams because each packet,
     * alert, stats update, or completion notice is one complete object that
     * automation and SIEM-style tools can parse incrementally.
     */
    if (json_format_packet(pkt, verbose, buffer, sizeof(buffer)) == 0) {
        printf("%s\n", buffer);
    }
}

void json_print_alert(const DetectionResult *alert)
{
    char buffer[4096];

    if (json_format_alert(alert, buffer, sizeof(buffer)) == 0) {
        printf("%s\n", buffer);
    }
}

void json_print_stats_event(void)
{
    char buffer[1024];

    if (json_format_stats_event(buffer, sizeof(buffer)) == 0) {
        printf("%s\n", buffer);
    }
}

void json_print_session_complete(void)
{
    char buffer[1024];

    if (json_format_session_complete(buffer, sizeof(buffer)) == 0) {
        printf("%s\n", buffer);
    }
}
