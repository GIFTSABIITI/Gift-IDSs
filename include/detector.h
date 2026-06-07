#ifndef DETECTOR_H
#define DETECTOR_H

#include "config.h"
#include "parser.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <time.h>

typedef enum {
    SEVERITY_NONE = 0,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH
} Severity;

typedef struct {
    int alert;
    Severity severity;

    char type[64];
    char message[256];

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    char protocol[16];

    uint16_t src_port;
    uint16_t dst_port;

    int threshold;
    int observed_count;
    int unique_ports;
    int window_seconds;

    time_t first_seen;
    time_t last_seen;

    char evidence[512];
    char recommendation[512];
} DetectionResult;

void detector_init(const GiftIDSConfig *config);
DetectionResult detect_packet(const PacketInfo *pkt);
const char *severity_to_string(Severity severity);

#endif
