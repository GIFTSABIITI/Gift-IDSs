#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define SNAPSHOT_LEN 65536

static volatile sig_atomic_t keep_running = 1;

static void handle_signal(int signo)
{
    (void)signo;
    keep_running = 0;
}

static void print_usage(const char *program)
{
    printf("Usage: %s [-i interface] [-c count]\n", program);
    printf("\n");
    printf("Options:\n");
    printf("  -i <interface>  Capture from a specific interface\n");
    printf("  -c <count>      Stop after this many packets\n");
    printf("  -h              Show this help message\n");
}

static void format_mac(const uint8_t mac[ETH_ALEN], char *out, size_t out_len)
{
    snprintf(out, out_len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void format_timestamp(char *out, size_t out_len)
{
    struct timeval tv;
    struct tm local_tm;
    time_t seconds;

    gettimeofday(&tv, NULL);
    seconds = tv.tv_sec;
    localtime_r(&seconds, &local_tm);

    strftime(out, out_len, "%Y-%m-%d %H:%M:%S", &local_tm);
    snprintf(out + strlen(out), out_len - strlen(out), ".%06ld", (long)tv.tv_usec);
}

static const char *ip_protocol_name(uint8_t protocol)
{
    switch (protocol) {
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_UDP:
        return "UDP";
    case IPPROTO_ICMP:
        return "ICMP";
    default:
        return "OTHER";
    }
}

static void print_ipv4_details(const uint8_t *packet, ssize_t packet_len)
{
    const struct ethhdr *eth = (const struct ethhdr *)packet;
    const uint8_t *ip_start = packet + sizeof(*eth);
    ssize_t ip_available = packet_len - (ssize_t)sizeof(*eth);
    const struct iphdr *ip;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t ip_header_len;
    uint16_t total_len;

    if (ip_available < (ssize_t)sizeof(struct iphdr)) {
        printf("IPv4 truncated header");
        return;
    }

    ip = (const struct iphdr *)ip_start;
    ip_header_len = (uint16_t)(ip->ihl * 4);
    total_len = ntohs(ip->tot_len);

    if (ip->version != 4 || ip_header_len < sizeof(struct iphdr) || ip_available < ip_header_len) {
        printf("IPv4 malformed header");
        return;
    }

    inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

    printf("IPv4 %s -> %s proto=%s ttl=%u ip_len=%u ",
           src_ip, dst_ip, ip_protocol_name(ip->protocol), ip->ttl, total_len);

    if (ip->protocol == IPPROTO_TCP) {
        const struct tcphdr *tcp;
        ssize_t tcp_available = ip_available - ip_header_len;

        if (tcp_available < (ssize_t)sizeof(struct tcphdr)) {
            printf("TCP truncated header");
            return;
        }

        tcp = (const struct tcphdr *)(ip_start + ip_header_len);
        printf("sport=%u dport=%u flags=%c%c%c%c%c%c",
               ntohs(tcp->source),
               ntohs(tcp->dest),
               tcp->urg ? 'U' : '-',
               tcp->ack ? 'A' : '-',
               tcp->psh ? 'P' : '-',
               tcp->rst ? 'R' : '-',
               tcp->syn ? 'S' : '-',
               tcp->fin ? 'F' : '-');
    } else if (ip->protocol == IPPROTO_UDP) {
        const struct udphdr *udp;
        ssize_t udp_available = ip_available - ip_header_len;

        if (udp_available < (ssize_t)sizeof(struct udphdr)) {
            printf("UDP truncated header");
            return;
        }

        udp = (const struct udphdr *)(ip_start + ip_header_len);
        printf("sport=%u dport=%u udp_len=%u",
               ntohs(udp->source),
               ntohs(udp->dest),
               ntohs(udp->len));
    } else if (ip->protocol == IPPROTO_ICMP) {
        const struct icmphdr *icmp;
        ssize_t icmp_available = ip_available - ip_header_len;

        if (icmp_available < (ssize_t)sizeof(struct icmphdr)) {
            printf("ICMP truncated header");
            return;
        }

        icmp = (const struct icmphdr *)(ip_start + ip_header_len);
        printf("type=%u code=%u", icmp->type, icmp->code);
    }
}

static void print_packet(const uint8_t *packet, ssize_t packet_len)
{
    const struct ethhdr *eth;
    char timestamp[64];
    char src_mac[18];
    char dst_mac[18];
    uint16_t ether_type;

    if (packet_len < (ssize_t)sizeof(struct ethhdr)) {
        return;
    }

    eth = (const struct ethhdr *)packet;
    ether_type = ntohs(eth->h_proto);

    format_timestamp(timestamp, sizeof(timestamp));
    format_mac(eth->h_source, src_mac, sizeof(src_mac));
    format_mac(eth->h_dest, dst_mac, sizeof(dst_mac));

    printf("[%s] frame_len=%zd eth=%s -> %s type=0x%04x ",
           timestamp, packet_len, src_mac, dst_mac, ether_type);

    if (ether_type == ETH_P_IP) {
        print_ipv4_details(packet, packet_len);
    } else if (ether_type == ETH_P_IPV6) {
        printf("IPv6 not parsed yet");
    } else if (ether_type == ETH_P_ARP) {
        printf("ARP");
    } else {
        printf("non-IP");
    }

    printf("\n");
}

static int bind_to_interface(int sockfd, const char *interface)
{
    struct sockaddr_ll socket_address;
    struct packet_mreq membership;
    unsigned int ifindex;

    ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "Unknown interface '%s': %s\n", interface, strerror(errno));
        return -1;
    }

    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ALL);
    socket_address.sll_ifindex = (int)ifindex;

    if (bind(sockfd, (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0) {
        perror("bind");
        return -1;
    }

    memset(&membership, 0, sizeof(membership));
    membership.mr_ifindex = (int)ifindex;
    membership.mr_type = PACKET_MR_PROMISC;

    if (setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &membership, sizeof(membership)) < 0) {
        perror("setsockopt PACKET_ADD_MEMBERSHIP");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    const char *interface = NULL;
    long max_packets = 0;
    long packets_seen = 0;
    int opt;
    int sockfd;

    while ((opt = getopt(argc, argv, "i:c:h")) != -1) {
        switch (opt) {
        case 'i':
            interface = optarg;
            break;
        case 'c':
            max_packets = strtol(optarg, NULL, 10);
            if (max_packets <= 0) {
                fprintf(stderr, "Packet count must be a positive number\n");
                return EXIT_FAILURE;
            }
            break;
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        fprintf(stderr, "Hint: run with sudo or grant CAP_NET_RAW to this binary.\n");
        return EXIT_FAILURE;
    }

    if (interface != NULL && bind_to_interface(sockfd, interface) < 0) {
        close(sockfd);
        return EXIT_FAILURE;
    }

    printf("Capturing packets%s%s. Press Ctrl+C to stop.\n",
           interface != NULL ? " on " : "",
           interface != NULL ? interface : "");

    while (keep_running && (max_packets == 0 || packets_seen < max_packets)) {
        uint8_t buffer[SNAPSHOT_LEN];
        ssize_t bytes_read;

        bytes_read = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue;
            }

            perror("recvfrom");
            close(sockfd);
            return EXIT_FAILURE;
        }

        packets_seen++;
        print_packet(buffer, bytes_read);
    }

    printf("Captured %ld packet%s.\n", packets_seen, packets_seen == 1 ? "" : "s");
    close(sockfd);
    return EXIT_SUCCESS;
}
