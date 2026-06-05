#include "capture.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static volatile sig_atomic_t keep_running = 1;
static CaptureIdleHandler idle_handler = NULL;
static void *idle_user_data = NULL;

void capture_stop(void)
{
    keep_running = 0;
}

void capture_set_idle_handler(CaptureIdleHandler handler, void *user_data)
{
    idle_handler = handler;
    idle_user_data = user_data;
}

static void run_idle_handler(void)
{
    if (idle_handler != NULL) {
        idle_handler(idle_user_data);
    }
}

static void set_receive_timeout(int sockfd)
{
    struct timeval timeout;

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        fprintf(stderr, "Warning: could not set socket receive timeout: %s\n", strerror(errno));
    }
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

int capture_packets(const char *interface, long max_packets, PacketHandler handler, void *user_data)
{
    int sockfd;
    long packets_seen = 0;

    if (handler == NULL) {
        fprintf(stderr, "No packet handler was provided\n");
        return -1;
    }

    keep_running = 1;

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        fprintf(stderr, "Hint: run with sudo or grant CAP_NET_RAW to this binary.\n");
        return -1;
    }
    set_receive_timeout(sockfd);

    if (interface != NULL && bind_to_interface(sockfd, interface) < 0) {
        close(sockfd);
        return -1;
    }

    printf("Capturing packets%s%s. Press Ctrl+C to stop.\n",
           interface != NULL ? " on " : "",
           interface != NULL ? interface : "");

    while (keep_running && (max_packets == 0 || packets_seen < max_packets)) {
        unsigned char buffer[CAPTURE_SNAPSHOT_LEN];
        ssize_t bytes_read;

        bytes_read = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue;
            }

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                run_idle_handler();
                continue;
            }

            perror("recvfrom");
            close(sockfd);
            return -1;
        }

        packets_seen++;
        handler(buffer, (int)bytes_read, user_data);
    }

    printf("Captured %ld raw frame%s.\n", packets_seen, packets_seen == 1 ? "" : "s");
    close(sockfd);
    return 0;
}
