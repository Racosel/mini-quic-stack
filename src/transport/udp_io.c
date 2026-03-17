#define _GNU_SOURCE
#include "udp_io.h"
#include "pkt_decode.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>

#define BATCH_SIZE 32
#define MAX_UDP_PAYLOAD 1500

static struct mmsghdr msgs[BATCH_SIZE];
static struct iovec iovecs[BATCH_SIZE];
static uint8_t bufs[BATCH_SIZE][MAX_UDP_PAYLOAD];
static int last_valid_count;

static int udp_fallback_receive_batch(int udp_fd) {
    int total_pkts = 0;

    for (int i = 0; i < BATCH_SIZE; i++) {
        struct msghdr hdr;
        ssize_t rc;

        memset(&hdr, 0, sizeof(hdr));
        hdr.msg_iov = &iovecs[i];
        hdr.msg_iovlen = 1;

        rc = recvmsg(udp_fd, &hdr, MSG_DONTWAIT);
        if (rc < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            return total_pkts > 0 ? total_pkts : -1;
        }

        msgs[i].msg_len = (unsigned int)rc;
        total_pkts++;
    }

    return total_pkts;
}

void udp_io_init() {
    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < BATCH_SIZE; i++) {
        iovecs[i].iov_base = bufs[i];
        iovecs[i].iov_len = MAX_UDP_PAYLOAD;
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        // 如果需要获取源 IP/Port，可在此处配置 msg_name 和 msg_namelen
    }
}

int udp_last_valid_count(void) {
    return last_valid_count;
}

int udp_receive_batch(int udp_fd) {
    int total_pkts = 0;
    int total_valid = 0;
    int idle_polls = 0;

    for (; idle_polls < 3;) {
        int num_pkts;
        struct pollfd pfd;

        pfd.fd = udp_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        if (poll(&pfd, 1, total_pkts == 0 ? 20 : 5) <= 0) {
            num_pkts = udp_fallback_receive_batch(udp_fd);
            if (num_pkts <= 0) {
                idle_polls++;
                continue;
            }
        } else {
            for (int i = 0; i < BATCH_SIZE; i++) {
                msgs[i].msg_len = 0;
            }

            num_pkts = recvmmsg(udp_fd, msgs, BATCH_SIZE, MSG_DONTWAIT, NULL);
            if (num_pkts < 0 && errno == EPERM) {
                num_pkts = udp_fallback_receive_batch(udp_fd);
            }
        }
        if (num_pkts < 0) {
            if ((errno == EAGAIN || errno == EWOULDBLOCK) && total_pkts > 0) {
                idle_polls++;
                continue;
            }
            return -1;
        }
        if (num_pkts == 0) {
            idle_polls++;
            continue;
        }

        idle_polls = 0;
        total_pkts += num_pkts;

        for (int i = 0; i < num_pkts; i++) {
            uint8_t *pkt_data = bufs[i];
            size_t pkt_len = msgs[i].msg_len;
            quic_pkt_header_meta_t meta;
            int ret = quic_parse_header_meta(pkt_data, pkt_len, &meta);

            if (ret == 0) {
                total_valid++;
                // 预检成功，下一步交由 dispatcher 进行 Version Routing 和 CID 匹配
                // quic_dispatcher_route(&meta, pkt_data, pkt_len);
            }
        }

        (void)num_pkts;
    }

    last_valid_count = total_valid;
    return total_pkts;
}
