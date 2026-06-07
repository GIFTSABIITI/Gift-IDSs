#ifndef JSON_OUTPUT_H
#define JSON_OUTPUT_H

#include "detector.h"
#include "parser.h"

#include <stddef.h>

void json_escape_string(const char *input, char *output, size_t output_size);

int json_format_packet(const PacketInfo *pkt, int verbose, char *buffer, size_t buffer_size);
int json_format_alert(const DetectionResult *alert, char *buffer, size_t buffer_size);
int json_format_stats_event(char *buffer, size_t buffer_size);
int json_format_session_complete(char *buffer, size_t buffer_size);

void json_print_packet(const PacketInfo *pkt, int verbose);
void json_print_alert(const DetectionResult *alert);
void json_print_stats_event(void);
void json_print_session_complete(void);

#endif
