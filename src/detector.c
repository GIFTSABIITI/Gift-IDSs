#include "detector.h"

#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define MAX_TRACKED_HOSTS 256
#define MAX_TRACKED_PORTS 128
#define MAX_ALERT_HISTORY 256
#define MAX_TRACKED_EVENTS 128

typedef struct {
    uint16_t port;
    time_t last_seen;
} TrackedPort;

typedef struct {
    int in_use;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    TrackedPort ports[MAX_TRACKED_PORTS];
    size_t port_count;
} PortScanState;

typedef struct {
    int in_use;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t dst_port;
    time_t events[MAX_TRACKED_EVENTS];
    size_t event_count;
} SynFloodState;

typedef struct {
    int in_use;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    time_t events[MAX_TRACKED_EVENTS];
    size_t event_count;
} IcmpFloodState;

typedef struct {
    int in_use;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char type[64];
    uint16_t dst_port;
    int has_port;
    time_t last_alert;
} AlertHistory;

typedef struct {
    uint16_t port;
    const char *service;
    Severity severity;
} RiskyPort;

static const RiskyPort risky_ports[] = {
    {21, "FTP", SEVERITY_LOW},
    {22, "SSH", SEVERITY_LOW},
    {23, "Telnet", SEVERITY_MEDIUM},
    {25, "SMTP", SEVERITY_LOW},
    {53, "DNS", SEVERITY_LOW},
    {110, "POP3", SEVERITY_LOW},
    {139, "NetBIOS", SEVERITY_LOW},
    {143, "IMAP", SEVERITY_LOW},
    {445, "SMB", SEVERITY_MEDIUM},
    {3389, "RDP", SEVERITY_MEDIUM}
};

static GiftIDSConfig detector_config;
static int detector_configured = 0;

static PortScanState port_scan_states[MAX_TRACKED_HOSTS];
static SynFloodState syn_flood_states[MAX_TRACKED_HOSTS];
static IcmpFloodState icmp_flood_states[MAX_TRACKED_HOSTS];
static AlertHistory alert_history[MAX_ALERT_HISTORY];

const char *severity_to_string(Severity severity)
{
    switch (severity) {
    case SEVERITY_LOW:
        return "LOW";
    case SEVERITY_MEDIUM:
        return "MEDIUM";
    case SEVERITY_HIGH:
        return "HIGH";
    case SEVERITY_NONE:
    default:
        return "NONE";
    }
}

void detector_init(const GiftIDSConfig *config)
{
    if (config != NULL) {
        detector_config = *config;
    } else {
        config_set_defaults(&detector_config);
    }

    memset(port_scan_states, 0, sizeof(port_scan_states));
    memset(syn_flood_states, 0, sizeof(syn_flood_states));
    memset(icmp_flood_states, 0, sizeof(icmp_flood_states));
    memset(alert_history, 0, sizeof(alert_history));

    detector_configured = 1;

    if (detector_config.port_scan_threshold > MAX_TRACKED_PORTS) {
        fprintf(stderr,
                "Warning: port scan threshold %d is above the tracked port limit %d\n",
                detector_config.port_scan_threshold,
                MAX_TRACKED_PORTS);
    }

    if (detector_config.syn_flood_threshold > MAX_TRACKED_EVENTS) {
        fprintf(stderr,
                "Warning: SYN flood threshold %d is above the tracked event limit %d\n",
                detector_config.syn_flood_threshold,
                MAX_TRACKED_EVENTS);
    }

    if (detector_config.icmp_flood_threshold > MAX_TRACKED_EVENTS) {
        fprintf(stderr,
                "Warning: ICMP flood threshold %d is above the tracked event limit %d\n",
                detector_config.icmp_flood_threshold,
                MAX_TRACKED_EVENTS);
    }
}

static void ensure_detector_ready(void)
{
    if (!detector_configured) {
        detector_init(NULL);
    }
}

static void copy_text(char *dst, size_t dst_size, const char *src)
{
    if (dst_size == 0) {
        return;
    }

    if (src == NULL) {
        src = "";
    }

    snprintf(dst, dst_size, "%s", src);
}

static DetectionResult empty_detection_result(const PacketInfo *pkt)
{
    DetectionResult result;

    memset(&result, 0, sizeof(result));
    result.severity = SEVERITY_NONE;

    if (pkt != NULL) {
        copy_text(result.src_ip, sizeof(result.src_ip), pkt->src_ip);
        copy_text(result.dst_ip, sizeof(result.dst_ip), pkt->dst_ip);
        copy_text(result.protocol, sizeof(result.protocol), pkt->protocol);
        result.src_port = pkt->src_port;
        result.dst_port = pkt->dst_port;
    }

    return result;
}

static void set_alert(DetectionResult *result, Severity severity, const char *type, const char *message)
{
    result->alert = 1;
    result->severity = severity;
    copy_text(result->type, sizeof(result->type), type);
    copy_text(result->message, sizeof(result->message), message);
}

static void set_alert_details(DetectionResult *result,
                              int threshold,
                              int observed_count,
                              int unique_ports,
                              int window_seconds,
                              time_t first_seen,
                              time_t last_seen,
                              const char *evidence,
                              const char *recommendation)
{
    if (result == NULL) {
        return;
    }

    /*
     * Evidence turns an alert from "the IDS said so" into a small, auditable
     * explanation. Recommendations keep the learning workflow practical by
     * giving the analyst a next step instead of only a warning.
     */
    result->threshold = threshold;
    result->observed_count = observed_count;
    result->unique_ports = unique_ports;
    result->window_seconds = window_seconds;
    result->first_seen = first_seen;
    result->last_seen = last_seen;
    copy_text(result->evidence, sizeof(result->evidence), evidence);
    copy_text(result->recommendation, sizeof(result->recommendation), recommendation);
}

static time_t packet_time(const PacketInfo *pkt)
{
    if (pkt != NULL && pkt->timestamp != 0) {
        return pkt->timestamp;
    }

    return time(NULL);
}

static int is_within_window(time_t now, time_t seen, int window_seconds)
{
    if (seen == 0 || window_seconds <= 0) {
        return 0;
    }

    return difftime(now, seen) <= (double)window_seconds;
}

static int same_ip_pair(const char *src_ip, const char *dst_ip, const PacketInfo *pkt)
{
    return strcmp(src_ip, pkt->src_ip) == 0 && strcmp(dst_ip, pkt->dst_ip) == 0;
}

static int is_tcp_syn_without_ack(const PacketInfo *pkt)
{
    return strcmp(pkt->protocol, "TCP") == 0 && pkt->tcp_syn && !pkt->tcp_ack;
}

static int is_tcp_or_udp(const PacketInfo *pkt)
{
    return strcmp(pkt->protocol, "TCP") == 0 || strcmp(pkt->protocol, "UDP") == 0;
}

static void compact_port_scan_state(PortScanState *state, time_t now)
{
    size_t read_index;
    size_t write_index = 0;

    if (!state->in_use) {
        return;
    }

    /*
     * A time window keeps old behavior from counting forever. A host that
     * contacts 10 ports over a day is very different from a host that contacts
     * 10 ports in a few seconds.
     */
    for (read_index = 0; read_index < state->port_count; read_index++) {
        if (is_within_window(now, state->ports[read_index].last_seen,
                             detector_config.port_scan_window_seconds)) {
            if (write_index != read_index) {
                state->ports[write_index] = state->ports[read_index];
            }
            write_index++;
        }
    }

    state->port_count = write_index;
    if (state->port_count == 0) {
        state->in_use = 0;
    }
}

static void compact_event_times(time_t *events, size_t *event_count, time_t now, int window_seconds)
{
    size_t read_index;
    size_t write_index = 0;

    for (read_index = 0; read_index < *event_count; read_index++) {
        if (is_within_window(now, events[read_index], window_seconds)) {
            if (write_index != read_index) {
                events[write_index] = events[read_index];
            }
            write_index++;
        }
    }

    *event_count = write_index;
}

static PortScanState *find_port_scan_state(const PacketInfo *pkt, time_t now)
{
    PortScanState *available = NULL;
    size_t i;

    for (i = 0; i < MAX_TRACKED_HOSTS; i++) {
        if (port_scan_states[i].in_use) {
            compact_port_scan_state(&port_scan_states[i], now);
        }

        if (port_scan_states[i].in_use) {
            if (same_ip_pair(port_scan_states[i].src_ip, port_scan_states[i].dst_ip, pkt)) {
                return &port_scan_states[i];
            }
        } else if (available == NULL) {
            available = &port_scan_states[i];
        }
    }

    if (available == NULL) {
        return NULL;
    }

    memset(available, 0, sizeof(*available));
    available->in_use = 1;
    copy_text(available->src_ip, sizeof(available->src_ip), pkt->src_ip);
    copy_text(available->dst_ip, sizeof(available->dst_ip), pkt->dst_ip);
    return available;
}

static void remember_unique_port(PortScanState *state, uint16_t dst_port, time_t now)
{
    size_t i;

    for (i = 0; i < state->port_count; i++) {
        if (state->ports[i].port == dst_port) {
            state->ports[i].last_seen = now;
            return;
        }
    }

    if (state->port_count >= MAX_TRACKED_PORTS) {
        return;
    }

    state->ports[state->port_count].port = dst_port;
    state->ports[state->port_count].last_seen = now;
    state->port_count++;
}

static SynFloodState *find_syn_flood_state(const PacketInfo *pkt, time_t now)
{
    SynFloodState *available = NULL;
    size_t i;

    for (i = 0; i < MAX_TRACKED_HOSTS; i++) {
        if (syn_flood_states[i].in_use) {
            compact_event_times(syn_flood_states[i].events,
                                &syn_flood_states[i].event_count,
                                now,
                                detector_config.syn_flood_window_seconds);
            if (syn_flood_states[i].event_count == 0) {
                syn_flood_states[i].in_use = 0;
            }
        }

        if (syn_flood_states[i].in_use) {
            if (same_ip_pair(syn_flood_states[i].src_ip, syn_flood_states[i].dst_ip, pkt) &&
                syn_flood_states[i].dst_port == pkt->dst_port) {
                return &syn_flood_states[i];
            }
        } else if (available == NULL) {
            available = &syn_flood_states[i];
        }
    }

    if (available == NULL) {
        return NULL;
    }

    memset(available, 0, sizeof(*available));
    available->in_use = 1;
    available->dst_port = pkt->dst_port;
    copy_text(available->src_ip, sizeof(available->src_ip), pkt->src_ip);
    copy_text(available->dst_ip, sizeof(available->dst_ip), pkt->dst_ip);
    return available;
}

static IcmpFloodState *find_icmp_flood_state(const PacketInfo *pkt, time_t now)
{
    IcmpFloodState *available = NULL;
    size_t i;

    for (i = 0; i < MAX_TRACKED_HOSTS; i++) {
        if (icmp_flood_states[i].in_use) {
            compact_event_times(icmp_flood_states[i].events,
                                &icmp_flood_states[i].event_count,
                                now,
                                detector_config.icmp_flood_window_seconds);
            if (icmp_flood_states[i].event_count == 0) {
                icmp_flood_states[i].in_use = 0;
            }
        }

        if (icmp_flood_states[i].in_use) {
            if (same_ip_pair(icmp_flood_states[i].src_ip, icmp_flood_states[i].dst_ip, pkt)) {
                return &icmp_flood_states[i];
            }
        } else if (available == NULL) {
            available = &icmp_flood_states[i];
        }
    }

    if (available == NULL) {
        return NULL;
    }

    memset(available, 0, sizeof(*available));
    available->in_use = 1;
    copy_text(available->src_ip, sizeof(available->src_ip), pkt->src_ip);
    copy_text(available->dst_ip, sizeof(available->dst_ip), pkt->dst_ip);
    return available;
}

static void remember_event(time_t *events, size_t *event_count, time_t now)
{
    if (*event_count >= MAX_TRACKED_EVENTS) {
        return;
    }

    events[*event_count] = now;
    (*event_count)++;
}

static int size_to_int(size_t value)
{
    if (value > (size_t)INT_MAX) {
        return INT_MAX;
    }

    return (int)value;
}

static void event_time_bounds(const time_t *events, size_t event_count, time_t *first_seen, time_t *last_seen)
{
    size_t i;
    time_t first = 0;
    time_t last = 0;

    for (i = 0; i < event_count; i++) {
        if (events[i] == 0) {
            continue;
        }

        if (first == 0 || events[i] < first) {
            first = events[i];
        }

        if (last == 0 || events[i] > last) {
            last = events[i];
        }
    }

    if (first_seen != NULL) {
        *first_seen = first;
    }

    if (last_seen != NULL) {
        *last_seen = last;
    }
}

static void port_time_bounds(const PortScanState *state, time_t *first_seen, time_t *last_seen)
{
    size_t i;
    time_t first = 0;
    time_t last = 0;

    if (state != NULL) {
        for (i = 0; i < state->port_count; i++) {
            time_t seen = state->ports[i].last_seen;

            if (seen == 0) {
                continue;
            }

            if (first == 0 || seen < first) {
                first = seen;
            }

            if (last == 0 || seen > last) {
                last = seen;
            }
        }
    }

    if (first_seen != NULL) {
        *first_seen = first;
    }

    if (last_seen != NULL) {
        *last_seen = last;
    }
}

static int alert_key_matches(const AlertHistory *history,
                             const PacketInfo *pkt,
                             const char *type,
                             int has_port,
                             uint16_t dst_port)
{
    return strcmp(history->src_ip, pkt->src_ip) == 0 &&
           strcmp(history->dst_ip, pkt->dst_ip) == 0 &&
           strcmp(history->type, type) == 0 &&
           history->has_port == has_port &&
           (!has_port || history->dst_port == dst_port);
}

static void save_alert_history(AlertHistory *history,
                               const PacketInfo *pkt,
                               const char *type,
                               int has_port,
                               uint16_t dst_port,
                               time_t now)
{
    memset(history, 0, sizeof(*history));
    history->in_use = 1;
    history->has_port = has_port;
    history->dst_port = dst_port;
    history->last_alert = now;
    copy_text(history->src_ip, sizeof(history->src_ip), pkt->src_ip);
    copy_text(history->dst_ip, sizeof(history->dst_ip), pkt->dst_ip);
    copy_text(history->type, sizeof(history->type), type);
}

static int should_emit_alert(const PacketInfo *pkt,
                             const char *type,
                             int has_port,
                             uint16_t dst_port,
                             time_t now)
{
    AlertHistory *available = NULL;
    size_t i;

    /*
     * Cooldowns reduce alert spam. Once a rule has warned about the same
     * source, target, rule type, and destination port, repeated packets during
     * the cooldown are treated as the same incident instead of new alerts.
     */
    if (detector_config.alert_cooldown_seconds <= 0) {
        return 1;
    }

    for (i = 0; i < MAX_ALERT_HISTORY; i++) {
        if (!alert_history[i].in_use) {
            if (available == NULL) {
                available = &alert_history[i];
            }
            continue;
        }

        if (alert_key_matches(&alert_history[i], pkt, type, has_port, dst_port)) {
            if (is_within_window(now,
                                 alert_history[i].last_alert,
                                 detector_config.alert_cooldown_seconds)) {
                return 0;
            }

            alert_history[i].last_alert = now;
            return 1;
        }

        if (!is_within_window(now,
                              alert_history[i].last_alert,
                              detector_config.alert_cooldown_seconds) &&
            available == NULL) {
            available = &alert_history[i];
        }
    }

    if (available != NULL) {
        save_alert_history(available, pkt, type, has_port, dst_port, now);
    }

    return 1;
}

static int check_syn_flood(const PacketInfo *pkt, DetectionResult *result, time_t now)
{
    SynFloodState *state;

    if (!is_tcp_syn_without_ack(pkt)) {
        return 0;
    }

    /*
     * A SYN flood is modeled here as many new TCP connection attempts to one
     * target port. This is simplified: it does not yet track whether the TCP
     * handshakes completed.
     */
    state = find_syn_flood_state(pkt, now);
    if (state == NULL) {
        return 0;
    }

    remember_event(state->events, &state->event_count, now);
    if (state->event_count >= (size_t)detector_config.syn_flood_threshold) {
        const char *type = "Possible SYN Flood";

        if (should_emit_alert(pkt, type, 1, pkt->dst_port, now)) {
            char message[256];
            char evidence[512];
            time_t first_seen;
            time_t last_seen;

            snprintf(message, sizeof(message),
                     "Source sent %zu SYN packets to destination port %u within %d seconds",
                     state->event_count,
                     pkt->dst_port,
                     detector_config.syn_flood_window_seconds);
            set_alert(result, SEVERITY_HIGH, type, message);
            event_time_bounds(state->events, state->event_count, &first_seen, &last_seen);
            snprintf(evidence, sizeof(evidence),
                     "Source sent %zu SYN packets to destination port %u within %d seconds.",
                     state->event_count,
                     pkt->dst_port,
                     detector_config.syn_flood_window_seconds);
            set_alert_details(result,
                              detector_config.syn_flood_threshold,
                              size_to_int(state->event_count),
                              0,
                              detector_config.syn_flood_window_seconds,
                              first_seen,
                              last_seen,
                              evidence,
                              "Check whether the target service is experiencing abnormal connection attempts.");
        }

        return 1;
    }

    return 0;
}

static int check_port_scan(const PacketInfo *pkt, DetectionResult *result, time_t now)
{
    PortScanState *state;

    if (!is_tcp_syn_without_ack(pkt)) {
        return 0;
    }

    /*
     * Port scans usually touch many destination ports on the same target.
     * Counting unique ports is more useful than counting packets because a
     * scanner may retry one port several times.
     */
    state = find_port_scan_state(pkt, now);
    if (state == NULL) {
        return 0;
    }

    remember_unique_port(state, pkt->dst_port, now);
    if (state->port_count >= (size_t)detector_config.port_scan_threshold) {
        const char *type = "Possible Port Scan";

        if (should_emit_alert(pkt, type, 0, 0, now)) {
            char message[256];
            char evidence[512];
            time_t first_seen;
            time_t last_seen;

            snprintf(message, sizeof(message),
                     "Source contacted %zu unique ports on target within %d seconds",
                     state->port_count,
                     detector_config.port_scan_window_seconds);
            set_alert(result, SEVERITY_MEDIUM, type, message);
            port_time_bounds(state, &first_seen, &last_seen);
            snprintf(evidence, sizeof(evidence),
                     "Source contacted %zu unique destination ports on the same target within %d seconds.",
                     state->port_count,
                     detector_config.port_scan_window_seconds);
            set_alert_details(result,
                              detector_config.port_scan_threshold,
                              size_to_int(state->port_count),
                              size_to_int(state->port_count),
                              detector_config.port_scan_window_seconds,
                              first_seen,
                              last_seen,
                              evidence,
                              "Investigate the source host and verify whether port scanning or service discovery was authorized.");
        }

        return 1;
    }

    return 0;
}

static int check_icmp_flood(const PacketInfo *pkt, DetectionResult *result, time_t now)
{
    IcmpFloodState *state;

    if (strcmp(pkt->protocol, "ICMP") != 0 || pkt->icmp_type != 8) {
        return 0;
    }

    /*
     * ICMP echo requests are normal ping packets, but many echo requests in a
     * short window can indicate a flood or noisy discovery activity.
     */
    state = find_icmp_flood_state(pkt, now);
    if (state == NULL) {
        return 0;
    }

    remember_event(state->events, &state->event_count, now);
    if (state->event_count >= (size_t)detector_config.icmp_flood_threshold) {
        const char *type = "Possible ICMP Flood";

        if (should_emit_alert(pkt, type, 0, 0, now)) {
            char message[256];
            char evidence[512];
            time_t first_seen;
            time_t last_seen;

            snprintf(message, sizeof(message),
                     "Source sent %zu ICMP echo requests to target within %d seconds",
                     state->event_count,
                     detector_config.icmp_flood_window_seconds);
            set_alert(result, SEVERITY_MEDIUM, type, message);
            event_time_bounds(state->events, state->event_count, &first_seen, &last_seen);
            snprintf(evidence, sizeof(evidence),
                     "Source sent %zu ICMP echo requests to the same target within %d seconds.",
                     state->event_count,
                     detector_config.icmp_flood_window_seconds);
            set_alert_details(result,
                              detector_config.icmp_flood_threshold,
                              size_to_int(state->event_count),
                              0,
                              detector_config.icmp_flood_window_seconds,
                              first_seen,
                              last_seen,
                              evidence,
                              "Check whether the ICMP traffic is expected or part of a flood/ping scan.");
        }

        return 1;
    }

    return 0;
}

static int check_suspicious_port(const PacketInfo *pkt, DetectionResult *result, time_t now)
{
    size_t i;

    if (!is_tcp_or_udp(pkt)) {
        return 0;
    }

    /*
     * Stateless Phase 4 rule:
     * These ports are not automatically malicious, but they are useful to
     * watch because attackers often probe login, file sharing, mail, and name
     * service ports while learning about a network.
     */
    for (i = 0; i < sizeof(risky_ports) / sizeof(risky_ports[0]); i++) {
        if (pkt->dst_port == risky_ports[i].port) {
            const char *type = "Suspicious Port";

            if (should_emit_alert(pkt, type, 1, pkt->dst_port, now)) {
                char message[256];
                char evidence[512];
                char recommendation[512];

                snprintf(message, sizeof(message),
                         "Traffic to %s port %u detected",
                         risky_ports[i].service,
                         risky_ports[i].port);
                set_alert(result, risky_ports[i].severity, type, message);
                snprintf(evidence, sizeof(evidence),
                         "Destination port %u is commonly associated with %s traffic.",
                         risky_ports[i].port,
                         risky_ports[i].service);
                snprintf(recommendation, sizeof(recommendation),
                         "Verify whether %s traffic is expected between these hosts.",
                         risky_ports[i].service);
                set_alert_details(result,
                                  0,
                                  1,
                                  0,
                                  0,
                                  now,
                                  now,
                                  evidence,
                                  recommendation);
            }

            return 1;
        }
    }

    return 0;
}

static int check_icmp_echo_request(const PacketInfo *pkt, DetectionResult *result, time_t now)
{
    if (strcmp(pkt->protocol, "ICMP") != 0 || pkt->icmp_type != 8) {
        return 0;
    }

    /*
     * ICMP echo requests are normal ping packets. They are useful to observe
     * in an IDS because simple host discovery and ping scans often use them.
     */
    if (should_emit_alert(pkt, "ICMP Echo Request", 0, 0, now)) {
        set_alert(result,
                  SEVERITY_LOW,
                  "ICMP Echo Request",
                  "ICMP echo request detected");
        set_alert_details(result,
                          0,
                          1,
                          0,
                          0,
                          now,
                          now,
                          "ICMP echo request observed from source to destination.",
                          "Check whether this is normal connectivity testing or part of scanning activity.");
    }

    return 1;
}

static int check_tcp_syn_watch(const PacketInfo *pkt, DetectionResult *result, time_t now)
{
    if (!is_tcp_syn_without_ack(pkt)) {
        return 0;
    }

    /*
     * A SYN packet without ACK is the usual first step of a TCP connection.
     * This beginner rule helps us see connection attempts, but it is not
     * advanced attack detection by itself.
     */
    if (should_emit_alert(pkt, "TCP SYN Watch", 1, pkt->dst_port, now)) {
        set_alert(result,
                  SEVERITY_LOW,
                  "TCP SYN Watch",
                  "TCP SYN connection attempt detected");
        set_alert_details(result,
                          0,
                          1,
                          0,
                          0,
                          now,
                          now,
                          "TCP SYN packet observed without ACK flag, indicating a connection attempt.",
                          "Monitor for repeated SYN attempts or failed connection patterns.");
    }

    return 1;
}

DetectionResult detect_packet(const PacketInfo *pkt)
{
    DetectionResult result = empty_detection_result(pkt);
    time_t now;

    ensure_detector_ready();

    if (pkt == NULL || !pkt->valid) {
        return result;
    }

    now = packet_time(pkt);

    /*
     * Stateful detection keeps short-lived memory about previous packets.
     * That lets Gift IDS detect behavior over time, while the fixed arrays
     * keep this learning version small and predictable. It is still simplified
     * IDS logic: there is no TCP handshake tracking, no IP fragmentation
     * handling, no persistence, and no blocking.
     */
    if (detector_config.enable_syn_flood_detection &&
        check_syn_flood(pkt, &result, now)) {
        return result;
    }

    if (detector_config.enable_port_scan_detection &&
        check_port_scan(pkt, &result, now)) {
        return result;
    }

    if (detector_config.enable_icmp_flood_detection &&
        check_icmp_flood(pkt, &result, now)) {
        return result;
    }

    if (detector_config.enable_suspicious_port_rule &&
        check_suspicious_port(pkt, &result, now)) {
        return result;
    }

    if (detector_config.enable_icmp_echo_rule &&
        check_icmp_echo_request(pkt, &result, now)) {
        return result;
    }

    if (detector_config.enable_tcp_syn_watch_rule &&
        check_tcp_syn_watch(pkt, &result, now)) {
        return result;
    }

    return result;
}
