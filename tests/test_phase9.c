#include <assert.h>
#include <stdio.h>

#include "quic_ack.h"
#include "quic_recovery.h"

static void test_ack_frame_parsing() {
    uint8_t frame[] = {
        0x03,
        0x0a,
        0x02,
        0x01,
        0x02,
        0x01, 0x00,
        0x05, 0x06, 0x07
    };
    quic_ack_frame_t ack;
    size_t consumed = 0;

    assert(quic_ack_parse_frame(frame, sizeof(frame), &ack, &consumed) == 0);
    assert(consumed == sizeof(frame));
    assert(ack.has_ecn == 1);
    assert(ack.largest_acked == 10);
    assert(ack.ack_delay == 2);
    assert(ack.ack_range_count == 2);
    assert(ack.ranges[0].largest == 10 && ack.ranges[0].smallest == 8);
    assert(ack.ranges[1].largest == 5 && ack.ranges[1].smallest == 5);
    assert(ack.ect0_count == 5 && ack.ect1_count == 6 && ack.ecn_ce_count == 7);

    printf("[PASS] ACK frame parsing with ranges and ECN\n");
}

static void test_ack_frame_applies_to_inflight_queue() {
    uint8_t frame[] = { 0x02, 0x0a, 0x00, 0x01, 0x02, 0x01, 0x00 };
    quic_ack_frame_t ack;
    quic_in_flight_queue_t q;
    size_t consumed = 0;
    size_t acked_packets = 0;

    quic_queue_init(&q);
    quic_on_packet_sent(&q, 5, 100, 1);
    quic_on_packet_sent(&q, 6, 100, 1);
    quic_on_packet_sent(&q, 7, 100, 1);
    quic_on_packet_sent(&q, 8, 100, 1);
    quic_on_packet_sent(&q, 9, 100, 1);
    quic_on_packet_sent(&q, 10, 100, 1);

    assert(quic_ack_parse_frame(frame, sizeof(frame), &ack, &consumed) == 0);
    assert(quic_on_ack_frame(&q, &ack, &acked_packets) == 0);
    assert(acked_packets == 4);
    assert(q.bytes_in_flight == 200);
    assert(q.largest_acked_packet == 10);

    printf("[PASS] ACK frame application to in-flight queue\n");
}

int main() {
    printf("--- Running Phase 9 Tests ---\n");
    test_ack_frame_parsing();
    test_ack_frame_applies_to_inflight_queue();
    printf("--- All Phase 9 Tests Passed! ---\n");
    return 0;
}
