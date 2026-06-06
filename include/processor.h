#ifndef PROCESSOR_H
#define PROCESSOR_H

#include "cli.h"

#include <time.h>

void process_packet_event(const unsigned char *packet,
                          int packet_len,
                          const GiftIDSRuntimeOptions *options);

void process_packet_event_at_time(const unsigned char *packet,
                                  int packet_len,
                                  time_t packet_timestamp,
                                  const GiftIDSRuntimeOptions *options);

#endif
