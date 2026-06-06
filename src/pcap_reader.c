#include "pcap_reader.h"

#include "processor.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PCAP_GLOBAL_HEADER_LEN 24
#define PCAP_PACKET_HEADER_LEN 16
#define PCAP_LINKTYPE_ETHERNET 1
#define PCAP_MAX_PACKET_LEN 262144U

typedef struct {
    int little_endian;
    int nanosecond_precision;
} PcapFormat;

static uint16_t read_u16_le(const unsigned char *bytes)
{
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

static uint16_t read_u16_be(const unsigned char *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | (uint16_t)bytes[1]);
}

static uint32_t read_u32_le(const unsigned char *bytes)
{
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static uint32_t read_u32_be(const unsigned char *bytes)
{
    return ((uint32_t)bytes[0] << 24) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) |
           (uint32_t)bytes[3];
}

static uint16_t read_pcap_u16(const unsigned char *bytes, const PcapFormat *format)
{
    return format->little_endian ? read_u16_le(bytes) : read_u16_be(bytes);
}

static uint32_t read_pcap_u32(const unsigned char *bytes, const PcapFormat *format)
{
    return format->little_endian ? read_u32_le(bytes) : read_u32_be(bytes);
}

static int parse_magic(const unsigned char *header, PcapFormat *format)
{
    if (header[0] == 0xd4 && header[1] == 0xc3 && header[2] == 0xb2 && header[3] == 0xa1) {
        format->little_endian = 1;
        format->nanosecond_precision = 0;
        return 0;
    }

    if (header[0] == 0xa1 && header[1] == 0xb2 && header[2] == 0xc3 && header[3] == 0xd4) {
        format->little_endian = 0;
        format->nanosecond_precision = 0;
        return 0;
    }

    if (header[0] == 0x4d && header[1] == 0x3c && header[2] == 0xb2 && header[3] == 0xa1) {
        format->little_endian = 1;
        format->nanosecond_precision = 1;
        return 0;
    }

    if (header[0] == 0xa1 && header[1] == 0xb2 && header[2] == 0x3c && header[3] == 0x4d) {
        format->little_endian = 0;
        format->nanosecond_precision = 1;
        return 0;
    }

    return -1;
}

static int read_global_header(FILE *file, const char *pcap_path, PcapFormat *format)
{
    unsigned char header[PCAP_GLOBAL_HEADER_LEN];
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t linktype;
    size_t bytes_read;

    bytes_read = fread(header, 1, sizeof(header), file);
    if (bytes_read != sizeof(header)) {
        fprintf(stderr, "Error: '%s' is not a valid PCAP file; global header is incomplete\n", pcap_path);
        return -1;
    }

    if (parse_magic(header, format) != 0) {
        fprintf(stderr, "Error: '%s' is not a valid classic PCAP file; bad magic number\n", pcap_path);
        return -1;
    }

    version_major = read_pcap_u16(header + 4, format);
    version_minor = read_pcap_u16(header + 6, format);
    linktype = read_pcap_u32(header + 20, format);

    if (version_major != 2 || version_minor != 4) {
        fprintf(stderr,
                "Error: unsupported PCAP version %u.%u in '%s'\n",
                version_major,
                version_minor,
                pcap_path);
        return -1;
    }

    if (linktype != PCAP_LINKTYPE_ETHERNET) {
        fprintf(stderr,
                "Error: unsupported PCAP link-layer type %u in '%s'; Gift IDS expects Ethernet frames\n",
                linktype,
                pcap_path);
        return -1;
    }

    return 0;
}

int pcap_reader_run(const char *pcap_path, const GiftIDSRuntimeOptions *options)
{
    PcapFormat format;
    FILE *file;
    unsigned long packets_seen = 0;
    int status = 0;

    if (pcap_path == NULL || *pcap_path == '\0') {
        fprintf(stderr, "Error: no PCAP file was provided\n");
        return -1;
    }

    file = fopen(pcap_path, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: could not open PCAP file '%s': %s\n", pcap_path, strerror(errno));
        return -1;
    }

    if (read_global_header(file, pcap_path, &format) != 0) {
        fclose(file);
        return -1;
    }

    if (options == NULL || !options->quiet) {
        printf("Analyzing PCAP file '%s'.\n", pcap_path);
    }

    for (;;) {
        unsigned char packet_header[PCAP_PACKET_HEADER_LEN];
        unsigned char *packet = NULL;
        uint32_t ts_sec;
        uint32_t ts_fraction;
        uint32_t incl_len;
        uint32_t orig_len;
        size_t bytes_read;

        bytes_read = fread(packet_header, 1, sizeof(packet_header), file);
        if (bytes_read == 0) {
            if (feof(file)) {
                break;
            }

            fprintf(stderr, "Error: could not read from PCAP file '%s'\n", pcap_path);
            status = -1;
            break;
        }

        if (bytes_read != sizeof(packet_header)) {
            fprintf(stderr, "Error: truncated packet header in PCAP file '%s'\n", pcap_path);
            status = -1;
            break;
        }

        ts_sec = read_pcap_u32(packet_header, &format);
        ts_fraction = read_pcap_u32(packet_header + 4, &format);
        incl_len = read_pcap_u32(packet_header + 8, &format);
        orig_len = read_pcap_u32(packet_header + 12, &format);

        /*
         * Gift IDS parses Ethernet/IP/TCP/UDP/ICMP headers, so very large
         * captured records are outside this beginner PCAP reader's needs.
         */
        if (incl_len > PCAP_MAX_PACKET_LEN || incl_len > (uint32_t)INT_MAX) {
            fprintf(stderr,
                    "Error: packet %lu in '%s' has an unsupported captured length %u\n",
                    packets_seen + 1,
                    pcap_path,
                    incl_len);
            status = -1;
            break;
        }

        if (orig_len < incl_len) {
            fprintf(stderr,
                    "Warning: packet %lu in '%s' has original length smaller than captured length\n",
                    packets_seen + 1,
                    pcap_path);
        }

        if (incl_len > 0) {
            packet = (unsigned char *)malloc(incl_len);
            if (packet == NULL) {
                fprintf(stderr, "Error: out of memory while reading PCAP packet\n");
                status = -1;
                break;
            }

            if (fread(packet, 1, incl_len, file) != incl_len) {
                fprintf(stderr, "Error: truncated packet data in PCAP file '%s'\n", pcap_path);
                free(packet);
                status = -1;
                break;
            }
        }

        /*
         * The parser only stores whole-second time_t values. That is enough
         * for current stateful windows, while the fraction is still validated
         * here so malformed timestamps do not go completely unnoticed.
         */
        if ((!format.nanosecond_precision && ts_fraction >= 1000000U) ||
            (format.nanosecond_precision && ts_fraction >= 1000000000U)) {
            fprintf(stderr,
                    "Warning: packet %lu in '%s' has an unusual timestamp fraction %u\n",
                    packets_seen + 1,
                    pcap_path,
                    ts_fraction);
        }

        process_packet_event_at_time(packet, (int)incl_len, (time_t)ts_sec, options);
        free(packet);

        packets_seen++;
        if (options != NULL && options->max_packets > 0 &&
            packets_seen >= (unsigned long)options->max_packets) {
            break;
        }
    }

    if (status == 0 && packets_seen == 0) {
        fprintf(stderr, "Warning: PCAP file '%s' did not contain any packets\n", pcap_path);
    }

    if (status == 0 && (options == NULL || !options->quiet)) {
        printf("Analyzed %lu packet%s from '%s'.\n",
               packets_seen,
               packets_seen == 1 ? "" : "s",
               pcap_path);
    }

    fclose(file);
    return status;
}
