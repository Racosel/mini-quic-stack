#include "quic_ack.h"
#include "quic_connection.h"
#include "quic_recovery.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void init_single_ack(quic_ack_frame_t *ack, uint64_t packet_number) {
    memset(ack, 0, sizeof(*ack));
    ack->largest_acked = packet_number;
    ack->ack_range_count = 1;
    ack->ranges[0].smallest = packet_number;
    ack->ranges[0].largest = packet_number;
}

static void test_stage4_rtt_and_ack_delay(void) {
    quic_recovery_state_t state;
    quic_in_flight_queue_t queue;
    quic_ack_frame_t ack;
    size_t acked_packets = 0;
    size_t lost_packets = 0;

    quic_recovery_init(&state, 1200);
    quic_queue_init(&queue);
    quic_recovery_set_peer_completed_address_validation(&state, 1);

    quic_recovery_on_packet_sent(&state,
                                 &queue,
                                 1,
                                 QUIC_PN_SPACE_APPLICATION,
                                 1200,
                                 1,
                                 1,
                                 0,
                                 0,
                                 0,
                                 0,
                                 1000,
                                 NULL);
    init_single_ack(&ack, 1);
    assert(quic_recovery_on_ack_received(&state,
                                         &queue,
                                         &ack,
                                         QUIC_PN_SPACE_APPLICATION,
                                         40,
                                         1100,
                                         NULL,
                                         NULL,
                                         NULL,
                                         &acked_packets,
                                         &lost_packets) == 0);
    assert(acked_packets == 1);
    assert(lost_packets == 0);
    assert(state.latest_rtt_ms == 100);
    assert(state.min_rtt_ms == 100);
    assert(state.smoothed_rtt_ms == 100);
    assert(state.rttvar_ms == 50);

    quic_recovery_set_handshake_confirmed(&state, 1);
    quic_recovery_set_max_ack_delay(&state, 25);
    quic_recovery_on_packet_sent(&state,
                                 &queue,
                                 2,
                                 QUIC_PN_SPACE_APPLICATION,
                                 1200,
                                 1,
                                 1,
                                 0,
                                 0,
                                 0,
                                 0,
                                 1200,
                                 NULL);
    init_single_ack(&ack, 2);
    assert(quic_recovery_on_ack_received(&state,
                                         &queue,
                                         &ack,
                                         QUIC_PN_SPACE_APPLICATION,
                                         40,
                                         1350,
                                         NULL,
                                         NULL,
                                         NULL,
                                         &acked_packets,
                                         &lost_packets) == 0);
    assert(state.latest_rtt_ms == 150);
    assert(state.min_rtt_ms == 100);
    assert(state.smoothed_rtt_ms == 103);
    assert(state.rttvar_ms == 43);

    printf("[PASS] Stage 4 RTT estimation applies ACK delay only after handshake confirmation\n");
}

static void test_stage4_packet_and_time_threshold_loss(void) {
    quic_recovery_state_t state;
    quic_in_flight_queue_t queue;
    quic_ack_frame_t ack;
    size_t acked_packets = 0;
    size_t lost_packets = 0;

    quic_recovery_init(&state, 1200);
    quic_queue_init(&queue);
    quic_recovery_set_peer_completed_address_validation(&state, 1);

    quic_recovery_on_packet_sent(&state, &queue, 1, QUIC_PN_SPACE_APPLICATION, 1200, 1, 1, 0, 0, 0, 0, 0, NULL);
    quic_recovery_on_packet_sent(&state, &queue, 2, QUIC_PN_SPACE_APPLICATION, 1200, 1, 1, 0, 0, 0, 0, 10020, NULL);
    quic_recovery_on_packet_sent(&state, &queue, 3, QUIC_PN_SPACE_APPLICATION, 1200, 1, 1, 0, 0, 0, 0, 10025, NULL);
    quic_recovery_on_packet_sent(&state, &queue, 4, QUIC_PN_SPACE_APPLICATION, 1200, 1, 1, 0, 0, 0, 0, 10030, NULL);

    init_single_ack(&ack, 4);
    assert(quic_recovery_on_ack_received(&state,
                                         &queue,
                                         &ack,
                                         QUIC_PN_SPACE_APPLICATION,
                                         0,
                                         10130,
                                         NULL,
                                         NULL,
                                         NULL,
                                         &acked_packets,
                                         &lost_packets) == 0);
    assert(acked_packets == 1);
    assert(lost_packets == 1);
    assert(state.congestion_window == 6000);
    assert(state.bytes_in_flight == 2400);
    assert(queue.bytes_in_flight == 2400);
    assert(queue.head && queue.head->packet_number == 2);
    assert(queue.tail && queue.tail->packet_number == 3);

    quic_queue_clear(&queue);
    quic_recovery_init(&state, 1200);
    quic_queue_init(&queue);
    quic_recovery_set_peer_completed_address_validation(&state, 1);

    quic_recovery_on_packet_sent(&state, &queue, 10, QUIC_PN_SPACE_APPLICATION, 1200, 1, 1, 0, 0, 0, 0, 0, NULL);
    quic_recovery_on_packet_sent(&state, &queue, 11, QUIC_PN_SPACE_APPLICATION, 1200, 1, 1, 0, 0, 0, 0, 100, NULL);
    memset(&ack, 0, sizeof(ack));
    ack.largest_acked = 11;
    ack.ack_range_count = 1;
    ack.ranges[0].smallest = 11;
    ack.ranges[0].largest = 11;
    assert(quic_recovery_on_ack_received(&state,
                                         &queue,
                                         &ack,
                                         QUIC_PN_SPACE_APPLICATION,
                                         0,
                                         200,
                                         NULL,
                                         NULL,
                                         NULL,
                                         &acked_packets,
                                         &lost_packets) == 0);
    assert(lost_packets == 1);
    assert(queue.head == NULL);
    assert(queue.tail == NULL);
    quic_queue_clear(&queue);

    printf("[PASS] Stage 4 packet-threshold and time-threshold loss detection remove only eligible packets\n");
}

static void test_stage4_pto_and_discarded_space_cleanup(void) {
    quic_recovery_state_t state;
    quic_in_flight_queue_t initial_queue;
    quic_in_flight_queue_t handshake_queue;
    quic_in_flight_queue_t application_queue;
    const quic_in_flight_queue_t *queues[QUIC_RECOVERY_PACKET_SPACE_COUNT];
    quic_recovery_timer_t timer;

    quic_recovery_init(&state, 1200);
    quic_queue_init(&initial_queue);
    quic_queue_init(&handshake_queue);
    quic_queue_init(&application_queue);
    quic_recovery_set_peer_completed_address_validation(&state, 0);

    quic_recovery_on_packet_sent(&state,
                                 &initial_queue,
                                 0,
                                 QUIC_PN_SPACE_INITIAL,
                                 1200,
                                 1,
                                 1,
                                 1,
                                 0,
                                 0,
                                 0,
                                 100,
                                 NULL);
    queues[0] = &initial_queue;
    queues[1] = &handshake_queue;
    queues[2] = &application_queue;

    assert(quic_recovery_get_timer(&state, queues, 0, 0, 100, &timer) == 1);
    assert(timer.mode == QUIC_RECOVERY_TIMER_PTO);
    assert(timer.packet_number_space == QUIC_PN_SPACE_INITIAL);
    assert(timer.deadline_ms > 100);

    state.loss_time_ms[QUIC_PN_SPACE_HANDSHAKE] = 500;
    assert(quic_recovery_get_timer(&state, queues, 0, 1, 200, &timer) == 1);
    assert(timer.mode == QUIC_RECOVERY_TIMER_LOSS);
    assert(timer.packet_number_space == QUIC_PN_SPACE_HANDSHAKE);
    assert(timer.deadline_ms == 500);

    quic_recovery_discard_space(&state, &initial_queue, QUIC_PN_SPACE_INITIAL);
    quic_recovery_set_peer_completed_address_validation(&state, 1);
    state.loss_time_ms[QUIC_PN_SPACE_HANDSHAKE] = 0;
    assert(state.bytes_in_flight == 0);
    assert(initial_queue.head == NULL);
    assert(quic_recovery_get_timer(&state, queues, 0, 1, 200, &timer) == 0);

    printf("[PASS] Stage 4 PTO selection and packet number space discard cleanup follow RFC 9002 state rules\n");
}

int main(void) {
    test_stage4_rtt_and_ack_delay();
    test_stage4_packet_and_time_threshold_loss();
    test_stage4_pto_and_discarded_space_cleanup();
    printf("Phase 15 tests passed.\n");
    return 0;
}
