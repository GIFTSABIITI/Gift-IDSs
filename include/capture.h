#ifndef CAPTURE_H
#define CAPTURE_H

#define CAPTURE_SNAPSHOT_LEN 65536

typedef void (*PacketHandler)(const unsigned char *packet, int packet_len, void *user_data);

void capture_stop(void);
int capture_packets(const char *interface, long max_packets, PacketHandler handler, void *user_data);

#endif
