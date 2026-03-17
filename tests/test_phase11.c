#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "quic_connection.h"
#include "quic_packet_protection.h"
#include "quic_types.h"

static const quic_cid_t k_test_dcid = {
    .len = 8,
    .data = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
};

static void test_conn_backbone_init() {
    quic_connection_t conn;

    quic_conn_init(&conn);
    assert(conn.state == QUIC_CONN_STATE_NEW);
    assert(conn.version == 0);
    assert(conn.last_event_type == QUIC_CONN_EVENT_NONE);

    for (size_t i = 0; i < QUIC_PN_SPACE_COUNT; i++) {
        assert(conn.spaces[i].id == (quic_pn_space_id_t)i);
        assert(conn.spaces[i].largest_received_packet == 0);
        assert(conn.spaces[i].last_received_packet == 0);
        assert(conn.spaces[i].next_packet_number == 0);
        assert(conn.spaces[i].rx_keys_ready == 0);
        assert(conn.spaces[i].tx_keys_ready == 0);
        assert(conn.spaces[i].in_flight.bytes_in_flight == 0);
    }

    for (size_t i = 0; i < QUIC_CONN_TIMER_COUNT; i++) {
        assert(conn.timers[i].armed == 0);
        assert(conn.timers[i].deadline_ms == 0);
    }

    printf("[PASS] Stage 0 connection backbone initialization\n");
}

static void test_initial_keys_bind_to_initial_space() {
    quic_connection_t conn;

    quic_conn_init(&conn);
    assert(quic_conn_set_initial_keys(&conn, QUIC_V2_VERSION, &k_test_dcid) == QUIC_CONN_OK);
    assert(conn.state == QUIC_CONN_STATE_HANDSHAKING);
    assert(conn.version == QUIC_V2_VERSION);
    assert(conn.version_ops != NULL);
    assert(conn.original_dcid.len == k_test_dcid.len);
    assert(memcmp(conn.original_dcid.data, k_test_dcid.data, k_test_dcid.len) == 0);

    assert(conn.spaces[QUIC_PN_SPACE_INITIAL].rx_keys_ready == 1);
    assert(conn.spaces[QUIC_PN_SPACE_INITIAL].tx_keys_ready == 1);
    assert(conn.spaces[QUIC_PN_SPACE_HANDSHAKE].rx_keys_ready == 0);
    assert(conn.spaces[QUIC_PN_SPACE_HANDSHAKE].tx_keys_ready == 0);
    assert(conn.spaces[QUIC_PN_SPACE_APPLICATION].rx_keys_ready == 0);
    assert(conn.spaces[QUIC_PN_SPACE_APPLICATION].tx_keys_ready == 0);

    printf("[PASS] Stage 0 Initial keys are isolated to Initial space\n");
}

static void test_unified_recv_path_routes_spaces() {
    quic_connection_t conn;
    uint8_t header[] = {
        0xd3, 0x6b, 0x33, 0x43, 0xcf, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
        0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x02
    };
    uint8_t plaintext[] = { 0x06, 0x00, 0x01, 0x42, 0x00, 0x00 };
    uint8_t packet[128];
    uint8_t handshake_packet[] = { 0xf0, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x00 };
    uint8_t short_packet[] = { 0x40, 0x11, 0x22, 0x33, 0x44 };
    size_t packet_len = 0;

    quic_conn_init(&conn);
    assert(quic_conn_set_initial_keys(&conn, QUIC_V2_VERSION, &k_test_dcid) == QUIC_CONN_OK);
    assert(quic_packet_protect(&conn.spaces[QUIC_PN_SPACE_INITIAL].rx_crypto,
                               2,
                               header,
                               sizeof(header),
                               sizeof(header) - 4,
                               plaintext,
                               sizeof(plaintext),
                               packet,
                               sizeof(packet),
                               &packet_len) == 0);

    assert(quic_conn_recv_packet(&conn, packet, packet_len) == QUIC_CONN_OK);
    assert(conn.last_recv_space == QUIC_PN_SPACE_INITIAL);
    assert(conn.spaces[QUIC_PN_SPACE_INITIAL].last_received_packet == 2);

    assert(quic_conn_recv_packet(&conn, handshake_packet, sizeof(handshake_packet)) == QUIC_CONN_ERR_UNSUPPORTED);
    assert(conn.last_recv_space == QUIC_PN_SPACE_HANDSHAKE);

    assert(quic_conn_recv_packet(&conn, short_packet, sizeof(short_packet)) == QUIC_CONN_ERR_UNSUPPORTED);
    assert(conn.last_recv_space == QUIC_PN_SPACE_APPLICATION);

    printf("[PASS] Stage 0 unified receive path distinguishes packet number spaces\n");
}

static void test_send_skeleton_and_event_timer_entry() {
    quic_connection_t conn;
    quic_conn_tx_plan_t initial_plan;
    quic_conn_tx_plan_t handshake_plan;
    quic_conn_event_t event;
    quic_conn_event_result_t result;

    quic_conn_init(&conn);
    assert(quic_conn_set_initial_keys(&conn, QUIC_V2_VERSION, &k_test_dcid) == QUIC_CONN_OK);
    assert(quic_conn_install_space_keys(&conn,
                                        QUIC_PN_SPACE_HANDSHAKE,
                                        &conn.spaces[QUIC_PN_SPACE_INITIAL].rx_crypto,
                                        &conn.spaces[QUIC_PN_SPACE_INITIAL].tx_crypto) == QUIC_CONN_OK);
    assert(quic_conn_install_space_keys(&conn,
                                        QUIC_PN_SPACE_APPLICATION,
                                        &conn.spaces[QUIC_PN_SPACE_INITIAL].rx_crypto,
                                        &conn.spaces[QUIC_PN_SPACE_INITIAL].tx_crypto) == QUIC_CONN_OK);
    assert(conn.state == QUIC_CONN_STATE_ACTIVE);

    assert(quic_conn_prepare_send(&conn, QUIC_PN_SPACE_INITIAL, 128, 1, &initial_plan) == QUIC_CONN_OK);
    assert(initial_plan.space == QUIC_PN_SPACE_INITIAL);
    assert(initial_plan.packet_number == 0);
    assert(initial_plan.header_form == 1);

    assert(quic_conn_prepare_send(&conn, QUIC_PN_SPACE_HANDSHAKE, 64, 1, &handshake_plan) == QUIC_CONN_OK);
    assert(handshake_plan.space == QUIC_PN_SPACE_HANDSHAKE);
    assert(handshake_plan.packet_number == 0);
    assert(handshake_plan.header_form == 1);

    memset(&event, 0, sizeof(event));
    event.type = QUIC_CONN_EVENT_PREPARE_SEND;
    event.data.tx_prepare.space = QUIC_PN_SPACE_APPLICATION;
    event.data.tx_prepare.payload_len = 48;
    event.data.tx_prepare.ack_eliciting = 1;
    assert(quic_conn_handle_event(&conn, &event, &result) == QUIC_CONN_OK);
    assert(result.type == QUIC_CONN_EVENT_PREPARE_SEND);
    assert(result.space == QUIC_PN_SPACE_APPLICATION);
    assert(result.tx_plan.packet_number == 0);
    assert(result.tx_plan.header_form == 0);

    quic_conn_arm_timer(&conn, QUIC_CONN_TIMER_LOSS_DETECTION, 100);
    memset(&event, 0, sizeof(event));
    event.type = QUIC_CONN_EVENT_TIMER_EXPIRED;
    event.data.timer.timer_id = QUIC_CONN_TIMER_LOSS_DETECTION;
    event.data.timer.now_ms = 120;
    assert(quic_conn_handle_event(&conn, &event, &result) == QUIC_CONN_OK);
    assert(result.timer_id == QUIC_CONN_TIMER_LOSS_DETECTION);
    assert(conn.timers[QUIC_CONN_TIMER_LOSS_DETECTION].armed == 0);
    assert(conn.last_event_type == QUIC_CONN_EVENT_TIMER_EXPIRED);

    quic_conn_arm_timer(&conn, QUIC_CONN_TIMER_IDLE, 200);
    assert(quic_conn_on_timer(&conn, QUIC_CONN_TIMER_IDLE, 250) == QUIC_CONN_OK);
    assert(conn.state == QUIC_CONN_STATE_DRAINING);
    quic_conn_arm_timer(&conn, QUIC_CONN_TIMER_IDLE, 260);
    assert(quic_conn_on_timer(&conn, QUIC_CONN_TIMER_IDLE, 300) == QUIC_CONN_OK);
    assert(conn.state == QUIC_CONN_STATE_CLOSED);

    printf("[PASS] Stage 0 send skeleton and unified event/timer entry\n");
}

int main() {
    printf("--- Running Phase 11 Tests ---\n");
    test_conn_backbone_init();
    test_initial_keys_bind_to_initial_space();
    test_unified_recv_path_routes_spaces();
    test_send_skeleton_and_event_timer_entry();
    printf("--- All Phase 11 Tests Passed! ---\n");
    return 0;
}
