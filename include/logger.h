#ifndef LOGGER_H
#define LOGGER_H

#include "detector.h"
#include "parser.h"

#define GIFTIDS_PACKET_LOG_FILE "logs/giftids.log"
#define GIFTIDS_ALERT_LOG_FILE "logs/giftids_alerts.log"
#define GIFTIDS_LOG_FILE GIFTIDS_PACKET_LOG_FILE

int logger_open(const char *path);
void logger_close(void);
void logger_print_packet(const PacketInfo *info);
void logger_log_packet(const PacketInfo *info);
void logger_print_alert(const DetectionResult *result);
void log_alert(const DetectionResult *result);

#endif
