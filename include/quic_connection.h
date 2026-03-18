#ifndef QUIC_CONNECTION_H
#define QUIC_CONNECTION_H

#include "quic_ack.h"
#include "quic_crypto.h"
#include "quic_initial.h"
#include "quic_recovery.h"
#include <stddef.h>
#include <stdint.h>

typedef enum {
    QUIC_CONN_STATE_NEW = 0,
    QUIC_CONN_STATE_HANDSHAKING = 1,
    QUIC_CONN_STATE_ACTIVE = 2,
    QUIC_CONN_STATE_CLOSING = 3,
    QUIC_CONN_STATE_DRAINING = 4,
    QUIC_CONN_STATE_CLOSED = 5
} quic_conn_state_t;

typedef enum {
    QUIC_PN_SPACE_INITIAL = 0,
    QUIC_PN_SPACE_HANDSHAKE = 1,
    QUIC_PN_SPACE_APPLICATION = 2,
    QUIC_PN_SPACE_COUNT = 3
} quic_pn_space_id_t;

typedef enum {
    QUIC_CONN_TIMER_LOSS_DETECTION = 0,
    QUIC_CONN_TIMER_ACK = 1,
    QUIC_CONN_TIMER_IDLE = 2,
    QUIC_CONN_TIMER_COUNT = 3
} quic_conn_timer_id_t;

typedef enum {
    QUIC_CONN_EVENT_NONE = 0,
    QUIC_CONN_EVENT_RX_PACKET = 1,
    QUIC_CONN_EVENT_PREPARE_SEND = 2,
    QUIC_CONN_EVENT_TIMER_EXPIRED = 3
} quic_conn_event_type_t;

enum {
    QUIC_CONN_OK = 0,
    QUIC_CONN_ERR_INVALID_ARGUMENT = -1,
    QUIC_CONN_ERR_UNSUPPORTED = -2,
    QUIC_CONN_ERR_DECODE = -3,
    QUIC_CONN_ERR_STATE = -4,
    QUIC_CONN_ERR_KEYS_UNAVAILABLE = -5
};

typedef struct {
    uint8_t armed;
    uint64_t deadline_ms;
} quic_conn_timer_state_t;

typedef struct {
    quic_pn_space_id_t id;
    quic_in_flight_queue_t in_flight;
    quic_ack_range_t ack_ranges[QUIC_MAX_ACK_RANGES];
    size_t ack_range_count;
    uint64_t largest_received_packet;
    uint64_t last_received_packet;
    uint64_t next_packet_number;
    uint8_t rx_keys_ready;
    uint8_t tx_keys_ready;
    quic_crypto_level_ctx_t rx_crypto;
    quic_crypto_level_ctx_t tx_crypto;
} quic_conn_pn_space_t;

typedef struct {
    quic_pn_space_id_t space;
    uint64_t packet_number;
    size_t packet_number_len;
    size_t payload_len;
    uint8_t ack_eliciting;
    uint8_t header_form;
} quic_conn_tx_plan_t;

typedef struct {
    quic_conn_event_type_t type;
    union {
        struct {
            uint8_t *packet;
            size_t packet_len;
        } rx_packet;
        struct {
            quic_pn_space_id_t space;
            size_t payload_len;
            uint8_t ack_eliciting;
        } tx_prepare;
        struct {
            quic_conn_timer_id_t timer_id;
            uint64_t now_ms;
        } timer;
    } data;
} quic_conn_event_t;

typedef struct {
    int status;
    quic_conn_event_type_t type;
    quic_pn_space_id_t space;
    quic_conn_timer_id_t timer_id;
    quic_conn_tx_plan_t tx_plan;
} quic_conn_event_result_t;

typedef struct {
    quic_conn_state_t state;
    uint32_t version;
    quic_cid_t original_dcid;
    const quic_version_ops_t *version_ops;
    quic_conn_pn_space_t spaces[QUIC_PN_SPACE_COUNT];
    quic_recovery_state_t recovery;
    quic_conn_timer_state_t timers[QUIC_CONN_TIMER_COUNT];
    quic_pn_space_id_t last_recv_space;
    quic_conn_event_type_t last_event_type;
    quic_conn_timer_id_t last_timer_id;
    uint64_t last_received_packet;
    uint64_t last_crypto_offset;
    uint64_t last_crypto_length;
    size_t last_plaintext_len;
    size_t last_frames_parsed;
    size_t last_acked_packets;
} quic_connection_t;

void quic_conn_init(quic_connection_t *conn);
int quic_conn_install_rx_keys(
    quic_connection_t *conn,
    quic_pn_space_id_t space_id,
    const quic_crypto_level_ctx_t *rx_ctx
);
int quic_conn_install_tx_keys(
    quic_connection_t *conn,
    quic_pn_space_id_t space_id,
    const quic_crypto_level_ctx_t *tx_ctx
);
int quic_conn_install_space_keys(
    quic_connection_t *conn,
    quic_pn_space_id_t space_id,
    const quic_crypto_level_ctx_t *rx_ctx,
    const quic_crypto_level_ctx_t *tx_ctx
);
void quic_conn_discard_space(quic_connection_t *conn, quic_pn_space_id_t space_id);
int quic_conn_set_initial_keys(quic_connection_t *conn, uint32_t version, const quic_cid_t *original_dcid);
int quic_conn_prepare_send(
    quic_connection_t *conn,
    quic_pn_space_id_t space_id,
    size_t payload_len,
    uint8_t ack_eliciting,
    quic_conn_tx_plan_t *out_plan
);
int quic_conn_recv_packet(quic_connection_t *conn, uint8_t *packet, size_t packet_len);
int quic_conn_recv_initial(quic_connection_t *conn, uint8_t *packet, size_t packet_len);
void quic_conn_arm_timer(quic_connection_t *conn, quic_conn_timer_id_t timer_id, uint64_t deadline_ms);
void quic_conn_disarm_timer(quic_connection_t *conn, quic_conn_timer_id_t timer_id);
int quic_conn_on_timer(quic_connection_t *conn, quic_conn_timer_id_t timer_id, uint64_t now_ms);
int quic_conn_handle_event(
    quic_connection_t *conn,
    const quic_conn_event_t *event,
    quic_conn_event_result_t *out_result
);

#endif // QUIC_CONNECTION_H：头文件保护结束
