#include <stdio.h>
#include <assert.h>
#include "quic_recovery.h"

void test_in_flight_management() {
    quic_in_flight_queue_t q;
    quic_queue_init(&q);

    // 模拟发送 3 个包
    quic_on_packet_sent(&q, 100, 1200, 1);
    quic_on_packet_sent(&q, 101, 1200, 1);
    quic_on_packet_sent(&q, 102, 500, 0); // 非 ACK 触发型数据包

    assert(q.bytes_in_flight == 2400);

    // 确认包 100
    quic_on_packet_acked(&q, 100);
    assert(q.bytes_in_flight == 1200);
    assert(q.largest_acked_packet == 100);

    // 确认包 102
    quic_on_packet_acked(&q, 102);
    assert(q.bytes_in_flight == 1200); // 102 不计入飞行字节

    printf("[PASS] In-flight Queue management\n");
}

int main() {
    test_in_flight_management();
    return 0;
}
