#ifndef DETECTOR_H
#define DETECTOR_H

#include "config.h"
#include "parser.h"

#include <arpa/inet.h>

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
} DetectionResult;

void detector_init(const GiftIDSConfig *config);
DetectionResult detect_packet(const PacketInfo *pkt);
const char *severity_to_string(Severity severity);

#endif
