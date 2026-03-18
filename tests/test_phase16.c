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

static void test_stage4_no_cwnd_growth_when_flow_or_application_limited(void) {
    quic_recovery_state_t state;
    quic_in_flight_queue_t queue;
    quic_ack_frame_t ack;
    size_t acked_packets = 0;
    size_t lost_packets = 0;
    uint64_t initial_cwnd;

    quic_recovery_init(&state, 1200);
    quic_queue_init(&queue);
    quic_recovery_set_peer_completed_address_validation(&state, 1);
    quic_recovery_set_handshake_confirmed(&state, 1);
    initial_cwnd = state.congestion_window;

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
                                 1,
                                 100,
                                 NULL);
    init_single_ack(&ack, 1);
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
    assert(state.congestion_window == initial_cwnd);

    quic_recovery_on_packet_sent(&state,
                                 &queue,
                                 2,
                                 QUIC_PN_SPACE_APPLICATION,
                                 1200,
                                 1,
                                 1,
                                 0,
                                 0,
                                 1,
                                 0,
                                 300,
                                 NULL);
    init_single_ack(&ack, 2);
    assert(quic_recovery_on_ack_received(&state,
                                         &queue,
                                         &ack,
                                         QUIC_PN_SPACE_APPLICATION,
                                         0,
                                         400,
                                         NULL,
                                         NULL,
                                         NULL,
                                         &acked_packets,
                                         &lost_packets) == 0);
    assert(state.congestion_window == initial_cwnd);

    quic_recovery_on_packet_sent(&state,
                                 &queue,
                                 3,
                                 QUIC_PN_SPACE_APPLICATION,
                                 1200,
                                 1,
                                 1,
                                 0,
                                 0,
                                 0,
                                 0,
                                 500,
                                 NULL);
    init_single_ack(&ack, 3);
    assert(quic_recovery_on_ack_received(&state,
                                         &queue,
                                         &ack,
                                         QUIC_PN_SPACE_APPLICATION,
                                         0,
                                         600,
                                         NULL,
                                         NULL,
                                         NULL,
                                         &acked_packets,
                                         &lost_packets) == 0);
    assert(state.congestion_window == initial_cwnd + 1200);

    printf("[PASS] Stage 4 congestion window does not grow for flow-control-limited or application-limited packets\n");
}

static void test_stage4_congestion_avoidance_growth(void) {
    quic_recovery_state_t state;
    quic_in_flight_queue_t queue;
    quic_ack_frame_t ack;
    size_t acked_packets = 0;
    size_t lost_packets = 0;

    quic_recovery_init(&state, 1200);
    quic_queue_init(&queue);
    quic_recovery_set_peer_completed_address_validation(&state, 1);
    quic_recovery_set_handshake_confirmed(&state, 1);
    state.congestion_window = 2400;
    state.ssthresh = 2400;

    quic_recovery_on_packet_sent(&state,
                                 &queue,
                                 10,
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
    init_single_ack(&ack, 10);
    assert(quic_recovery_on_ack_received(&state,
                                         &queue,
                                         &ack,
                                         QUIC_PN_SPACE_APPLICATION,
                                         0,
                                         1100,
                                         NULL,
                                         NULL,
                                         NULL,
                                         &acked_packets,
                                         &lost_packets) == 0);
    assert(state.congestion_window == 3000);

    printf("[PASS] Stage 4 congestion avoidance follows the RFC 9002 additive increase formula\n");
}

static void test_stage4_persistent_congestion_collapses_cwnd(void) {
    quic_recovery_state_t state;
    quic_in_flight_queue_t queue;
    quic_ack_frame_t ack;
    size_t acked_packets = 0;
    size_t lost_packets = 0;

    quic_recovery_init(&state, 1200);
    quic_queue_init(&queue);
    quic_recovery_set_peer_completed_address_validation(&state, 1);
    quic_recovery_set_handshake_confirmed(&state, 1);
    quic_recovery_set_max_ack_delay(&state, 0);
    state.first_rtt_sample_ms = 50;
    state.latest_rtt_ms = 100;
    state.smoothed_rtt_ms = 100;
    state.rttvar_ms = 0;
    state.congestion_window = 6000;

    quic_recovery_on_packet_sent(&state, &queue, 1, QUIC_PN_SPACE_APPLICATION, 1200, 1, 1, 0, 0, 0, 0, 100, NULL);
    quic_recovery_on_packet_sent(&state, &queue, 2, QUIC_PN_SPACE_APPLICATION, 1200, 1, 1, 0, 0, 0, 0, 500, NULL);
    quic_recovery_on_packet_sent(&state, &queue, 5, QUIC_PN_SPACE_APPLICATION, 1200, 1, 1, 0, 0, 0, 0, 900, NULL);

    init_single_ack(&ack, 5);
    assert(quic_recovery_on_ack_received(&state,
                                         &queue,
                                         &ack,
                                         QUIC_PN_SPACE_APPLICATION,
                                         0,
                                         1000,
                                         NULL,
                                         NULL,
                                         NULL,
                                         &acked_packets,
                                         &lost_packets) == 0);
    assert(lost_packets == 2);
    assert(state.congestion_window == 2400);

    printf("[PASS] Stage 4 persistent congestion reduces the congestion window to the minimum window\n");
}

int main(void) {
    test_stage4_no_cwnd_growth_when_flow_or_application_limited();
    test_stage4_congestion_avoidance_growth();
    test_stage4_persistent_congestion_collapses_cwnd();
    printf("Phase 16 tests passed.\n");
    return 0;
}
