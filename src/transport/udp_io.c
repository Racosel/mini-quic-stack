#define _GNU_SOURCE
#include "udp_io.h"
#include "pkt_decode.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#define BATCH_SIZE 32
#define MAX_UDP_PAYLOAD 1500

static struct mmsghdr msgs[BATCH_SIZE];
static struct iovec iovecs[BATCH_SIZE];
static uint8_t bufs[BATCH_SIZE][MAX_UDP_PAYLOAD];

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

int udp_receive_batch(int udp_fd) {
    int num_pkts = recvmmsg(udp_fd, msgs, BATCH_SIZE, 0, NULL);
    if (num_pkts < 0) {
        return -1;
    }

    for (int i = 0; i < num_pkts; i++) {
        uint8_t *pkt_data = bufs[i];
        size_t pkt_len = msgs[i].msg_len;
        
        quic_pkt_header_meta_t meta;
        int ret = quic_parse_header_meta(pkt_data, pkt_len, &meta);
        
        if (ret == 0) {
            // 预检成功，下一步交由 dispatcher 进行 Version Routing 和 CID 匹配
            // quic_dispatcher_route(&meta, pkt_data, pkt_len);
        } else {
            // 丢弃无效数据包或记录日志
        }
    }
    
    return num_pkts;
}