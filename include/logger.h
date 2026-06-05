#ifndef LOGGER_H
#define LOGGER_H

#include "config.h"
#include "detector.h"
#include "parser.h"

#define GIFTIDS_PACKET_LOG_FILE GIFTIDS_DEFAULT_PACKET_LOG_FILE
#define GIFTIDS_ALERT_LOG_FILE GIFTIDS_DEFAULT_ALERT_LOG_FILE
#define GIFTIDS_LOG_FILE GIFTIDS_PACKET_LOG_FILE

int logger_init(const GiftIDSConfig *config);
int logger_open(const char *path);
void logger_set_packet_logging_enabled(int enabled);
void logger_set_alert_logging_enabled(int enabled);
void logger_close(void);
void logger_print_packet(const PacketInfo *info);
void logger_print_packet_verbose(const PacketInfo *info);
void logger_log_packet(const PacketInfo *info);
void logger_print_alert(const DetectionResult *result);
void log_alert(const DetectionResult *result);

#endif
