#ifndef PCAP_READER_H
#define PCAP_READER_H

#include "cli.h"

int pcap_reader_run(const char *pcap_path, const GiftIDSRuntimeOptions *options);

#endif
