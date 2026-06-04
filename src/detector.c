#include "detector.h"

#include <stdio.h>
#include <string.h>

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

static DetectionResult empty_detection_result(const PacketInfo *pkt)
{
    DetectionResult result;

    memset(&result, 0, sizeof(result));
    result.severity = SEVERITY_NONE;

    if (pkt != NULL) {
        snprintf(result.src_ip, sizeof(result.src_ip), "%s", pkt->src_ip);
        snprintf(result.dst_ip, sizeof(result.dst_ip), "%s", pkt->dst_ip);
    }

    return result;
}

static void set_alert(DetectionResult *result, Severity severity, const char *type, const char *message)
{
    result->alert = 1;
    result->severity = severity;
    snprintf(result->type, sizeof(result->type), "%s", type);
    snprintf(result->message, sizeof(result->message), "%s", message);
}

static int is_tcp_or_udp(const PacketInfo *pkt)
{
    return strcmp(pkt->protocol, "TCP") == 0 || strcmp(pkt->protocol, "UDP") == 0;
}

static int check_suspicious_port(const PacketInfo *pkt, DetectionResult *result)
{
    size_t i;

    if (!is_tcp_or_udp(pkt)) {
        return 0;
    }

    /*
     * Detection rule:
     * A rule is a simple condition that turns packet fields into an alert.
     * These ports are not automatically evil, but they are useful to watch
     * because attackers often probe login, file sharing, mail, and name
     * service ports while learning about a network.
     */
    for (i = 0; i < sizeof(risky_ports) / sizeof(risky_ports[0]); i++) {
        if (pkt->dst_port == risky_ports[i].port) {
            char message[256];

            snprintf(message, sizeof(message),
                     "Traffic to %s port %u detected",
                     risky_ports[i].service,
                     risky_ports[i].port);
            set_alert(result, risky_ports[i].severity, "Suspicious Port", message);
            return 1;
        }
    }

    return 0;
}

static int check_icmp_echo_request(const PacketInfo *pkt, DetectionResult *result)
{
    if (strcmp(pkt->protocol, "ICMP") != 0 || pkt->icmp_type != 8) {
        return 0;
    }

    /*
     * ICMP echo requests are normal ping packets. They are useful to observe
     * in an IDS because simple host discovery and ping scans often use them.
     */
    set_alert(result,
              SEVERITY_LOW,
              "ICMP Echo Request",
              "ICMP echo request detected");
    return 1;
}

static int check_tcp_syn_watch(const PacketInfo *pkt, DetectionResult *result)
{
    if (strcmp(pkt->protocol, "TCP") != 0 || !pkt->tcp_syn || pkt->tcp_ack) {
        return 0;
    }

    /*
     * A SYN packet without ACK is the usual first step of a TCP connection.
     * This beginner rule helps us see connection attempts, but it is not
     * advanced attack detection by itself.
     */
    set_alert(result,
              SEVERITY_LOW,
              "TCP SYN Watch",
              "TCP SYN connection attempt detected");
    return 1;
}

DetectionResult detect_packet(const PacketInfo *pkt)
{
    DetectionResult result = empty_detection_result(pkt);

    if (pkt == NULL || !pkt->valid) {
        return result;
    }

    /*
     * Phase 4 is stateless: it looks at one packet at a time and does not keep
     * counters or time windows. That keeps the code beginner-friendly, but it
     * also means this is not yet true advanced attack detection.
     */
    if (check_suspicious_port(pkt, &result)) {
        return result;
    }

    if (check_icmp_echo_request(pkt, &result)) {
        return result;
    }

    if (check_tcp_syn_watch(pkt, &result)) {
        return result;
    }

    return result;
}
