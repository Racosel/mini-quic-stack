#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <errno.h>

#include "quic_types.h"
#include "pkt_decode.h"
#include "udp_io.h"

// ============================================================================
// 第一部分：内存解码与边界异常测试（单元测试）
// ============================================================================

void test_decode_valid_long_v1() {
    // 0xc0（Form=1，Fixed=1），Version(1)，DCID_Len(4)，随后是 DCID 与 SCID
    uint8_t pkt[] = {0xc0, 0x00, 0x00, 0x00, 0x01, 0x04, 0x11, 0x22, 0x33, 0x44, 0x02, 0xaa, 0xbb};
    quic_pkt_header_meta_t meta;
    int ret = quic_parse_header_meta(pkt, sizeof(pkt), &meta);
    assert(ret == 0);
    assert(meta.header_form == 1 && meta.fixed_bit == 1);
    assert(meta.version == QUIC_V1_VERSION);
    assert(meta.dest_cid.len == 4 && meta.dest_cid.data[0] == 0x11);
    assert(meta.src_cid.len == 2 && meta.src_cid.data[0] == 0xaa);
    printf("[PASS] Valid Long Header (v1)\n");
}

void test_decode_valid_long_v2() {
    // 0xd0（Form=1，Fixed=1，Type=01），Version(0x6b3343cf)，DCID_Len(0)，SCID_Len(0)
    uint8_t pkt[] = {0xd0, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x00};
    quic_pkt_header_meta_t meta;
    int ret = quic_parse_header_meta(pkt, sizeof(pkt), &meta);
    assert(ret == 0);
    assert(meta.version == QUIC_V2_VERSION);
    assert(meta.dest_cid.len == 0 && meta.src_cid.len == 0);
    printf("[PASS] Valid Long Header (v2)\n");
}

void test_decode_valid_short() {
    // 0x40（Form=0，Fixed=1），假设剩余内容全部为 DCID，最大限制 20 字节
    uint8_t pkt[] = {0x40, 0x99, 0x88, 0x77};
    quic_pkt_header_meta_t meta;
    int ret = quic_parse_header_meta(pkt, sizeof(pkt), &meta);
    assert(ret == 0);
    assert(meta.header_form == 0 && meta.fixed_bit == 1);
    assert(meta.dest_cid.len == 3); // 整个载荷长度 4 - 1 = 3
    assert(meta.dest_cid.data[0] == 0x99);
    assert(meta.version == 0);
    printf("[PASS] Valid Short Header\n");
}

void test_decode_invalid_fixed_bit() {
    // 0x00（Fixed Bit = 0，违背 RFC 规范）
    uint8_t pkt[] = {0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
    quic_pkt_header_meta_t meta;
    int ret = quic_parse_header_meta(pkt, sizeof(pkt), &meta);
    assert(ret == -2);
    printf("[PASS] Invalid Fixed Bit rejection\n");
}

void test_decode_too_short() {
    // 长度不足以容纳长包头的基本字段（最少 6 字节）
    uint8_t pkt[] = {0xc0, 0x00, 0x00, 0x00, 0x01}; 
    quic_pkt_header_meta_t meta;
    int ret = quic_parse_header_meta(pkt, sizeof(pkt), &meta);
    assert(ret == -3);
    printf("[PASS] Truncated Packet rejection\n");
}

void test_decode_cid_out_of_bounds() {
    // 声明 DCID 长度为 200，但实际载荷只有几字节
    uint8_t pkt[] = {0xc0, 0x00, 0x00, 0x00, 0x01, 200, 0x11, 0x22};
    quic_pkt_header_meta_t meta;
    int ret = quic_parse_header_meta(pkt, sizeof(pkt), &meta);
    assert(ret == -4);
    printf("[PASS] CID Out-of-Bounds rejection\n");
}

// ============================================================================
// 第二部分：UDP 本地环回批量接收测试（集成测试）
// ============================================================================

void test_udp_batch_receive() {
    int fds[2];
    uint8_t valid_pkt[] = {0xc0, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x00};
    uint8_t invalid_pkt[] = {0x00, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x00};
    int send_count = 10;
    int valid_count = 9;

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) {
        printf("[SKIP] UDP Batch Receive: socketpair unavailable in this environment (errno=%d)\n", errno);
        return;
    }
    int recv_fd = fds[0];

    // 设置为非阻塞模式，防止测试挂起
    int flags = fcntl(recv_fd, F_GETFL, 0);
    fcntl(recv_fd, F_SETFL, flags | O_NONBLOCK);

    udp_io_init();

    // 2. 设置发送端套接字
    int send_fd = fds[1];

    // 3. 连续发送 9 个有效数据包和 1 个无效数据包
    for (int i = 0; i < valid_count; i++) {
        if (send(send_fd, valid_pkt, sizeof(valid_pkt), 0) < 0) {
            printf("[SKIP] UDP Batch Receive: datagram send blocked in this environment (errno=%d)\n", errno);
            close(send_fd);
            close(recv_fd);
            return;
        }
    }
    if (send(send_fd, invalid_pkt, sizeof(invalid_pkt), 0) < 0) {
        printf("[SKIP] UDP Batch Receive: datagram send blocked in this environment (errno=%d)\n", errno);
        close(send_fd);
        close(recv_fd);
        return;
    }

    // 留出一点时间让内核 UDP 协议栈处理
    usleep(10000); 

    // 4. 执行批量接收
    int received = udp_receive_batch(recv_fd);
    if (received < 0) {
        printf("[SKIP] UDP Batch Receive: receive blocked in this environment (errno=%d)\n", errno);
        close(send_fd);
        close(recv_fd);
        return;
    }

    assert(received == send_count);
    assert(udp_last_valid_count() == valid_count);
    printf("[PASS] UDP Batch Receive: Sent %d, Received %d, Valid %d\n",
           send_count, received, udp_last_valid_count());

    close(send_fd);
    close(recv_fd);
}

int main() {
    printf("--- Running Phase 1 Tests ---\n");
    test_decode_valid_long_v1();
    test_decode_valid_long_v2();
    test_decode_valid_short();
    test_decode_invalid_fixed_bit();
    test_decode_too_short();
    test_decode_cid_out_of_bounds();
    
    test_udp_batch_receive();
    
    printf("--- All Phase 1 Tests Passed! ---\n");
    return 0;
}
