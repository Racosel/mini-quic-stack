#include "quic_tls.h"
#include "pkt_decode.h"
#include "quic_crypto.h"
#include "quic_frame.h"
#include "quic_initial.h"
#include "quic_packet_protection.h"
#include "quic_retry.h"
#include "quic_varint.h"
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define QUIC_TLS_CIPHER_AES_128_GCM_SHA256 0x1301
#define QUIC_TLS_MAX_CRYPTO_CHUNK 1000
#define QUIC_STREAM_MAX_OFFSET ((1ULL << 62) - 1)
#define QUIC_TLS_STREAM_PACKET_RESERVE 64
#define QUIC_TLS_CLOSE_TIMEOUT_MS (QUIC_TLS_RETRANSMIT_TIMEOUT_MS * 3ULL)

static const uint8_t quic_tls_alpn[] = { 0x07, 'a', 'i', '-', 'q', 'u', 'i', 'c' };

typedef struct {
    uint8_t kind;
    quic_pkt_header_meta_t meta;
    uint8_t packet_type;
    quic_pn_space_id_t space;
    enum ssl_encryption_level_t level;
    size_t pn_offset;
    size_t token_offset;
    size_t token_length;
} quic_tls_packet_header_t;

enum {
    QUIC_TLS_PACKET_STANDARD = 0,
    QUIC_TLS_PACKET_VERSION_NEGOTIATION = 1,
    QUIC_TLS_PACKET_RETRY = 2
};

typedef struct {
    uint8_t active;
    uint8_t send_open;
    uint8_t fin_sent;
    uint8_t fin_in_flight;
    uint8_t stop_sending_pending;
    uint8_t stop_sending_in_flight;
    uint8_t reset_pending;
    uint8_t reset_in_flight;
    uint8_t max_stream_data_pending;
    uint8_t max_stream_data_in_flight;
    uint8_t send_final_size_known;
    uint64_t send_highest_offset;
    uint64_t send_final_size;
    size_t flight_start;
    size_t flight_end;
    size_t send_offset;
    uint8_t flight_pending;
    size_t retransmit_range_count;
    quic_stream_send_range_t retransmit_ranges[QUIC_STREAM_MAX_RETRANSMIT_RANGES];
} quic_tls_app_stream_snapshot_t;

typedef struct {
    uint64_t send_connection_highest;
    uint8_t max_data_pending;
    uint8_t max_data_in_flight;
    uint8_t max_streams_bidi_pending;
    uint8_t max_streams_bidi_in_flight;
    uint8_t max_streams_uni_pending;
    uint8_t max_streams_uni_in_flight;
    quic_tls_app_stream_snapshot_t streams[QUIC_STREAM_MAX_COUNT];
} quic_tls_app_send_snapshot_t;

static uint64_t quic_tls_now_ms(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

static void quic_tls_arm_loss_timer(quic_tls_conn_t *conn);
static int quic_tls_prepare_connection_close(quic_tls_conn_t *conn,
                                             uint64_t error_code,
                                             int enter_draining_after_send);
static void quic_tls_on_packet_acked(void *ctx, const quic_sent_packet_t *packet);
static void quic_tls_on_packet_lost(void *ctx, const quic_sent_packet_t *packet);

static enum ssl_encryption_level_t quic_tls_level_from_space(quic_pn_space_id_t space) {
    switch (space) {
        case QUIC_PN_SPACE_INITIAL:
            return ssl_encryption_initial;
        case QUIC_PN_SPACE_HANDSHAKE:
            return ssl_encryption_handshake;
        case QUIC_PN_SPACE_APPLICATION:
            return ssl_encryption_application;
        default:
            return ssl_encryption_initial;
    }
}

static int quic_tls_server_alpn_cb(SSL *ssl,
                                   const uint8_t **out,
                                   uint8_t *out_len,
                                   const uint8_t *in,
                                   unsigned int in_len,
                                   void *arg) {
    size_t offset = 0;
    (void)ssl;
    (void)arg;

    while (offset < in_len) {
        uint8_t proto_len = in[offset++];
        if (offset + proto_len > in_len) {
            break;
        }
        if (proto_len == quic_tls_alpn[0] &&
            memcmp(in + offset, quic_tls_alpn + 1, proto_len) == 0) {
            *out = quic_tls_alpn + 1;
            *out_len = proto_len;
            return SSL_TLSEXT_ERR_OK;
        }
        offset += proto_len;
    }

    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static void quic_tls_set_error(quic_tls_conn_t *conn, const char *message) {
    if (!conn || !message) {
        return;
    }
    snprintf(conn->error_message, sizeof(conn->error_message), "%s", message);
}

static int quic_tls_fail(quic_tls_conn_t *conn, const char *message) {
    quic_tls_set_error(conn, message);
    return -1;
}

static int quic_tls_fail_ssl(quic_tls_conn_t *conn, const char *prefix) {
    unsigned long err = ERR_get_error();
    char detail[160];

    if (err != 0) {
        ERR_error_string_n(err, detail, sizeof(detail));
    } else {
        snprintf(detail, sizeof(detail), "unknown ssl error");
    }
    snprintf(conn->error_message, sizeof(conn->error_message), "%s: %s", prefix, detail);
    return -1;
}

static quic_tls_conn_t *quic_tls_from_ssl(SSL *ssl) {
    return (quic_tls_conn_t *)SSL_get_app_data(ssl);
}

static size_t quic_tls_varint_len(uint64_t value) {
    uint8_t scratch[8];
    int rc = quic_encode_varint(value, scratch, sizeof(scratch));
    return rc < 0 ? 0 : (size_t)rc;
}

static uint64_t quic_tls_transport_param_value(const quic_transport_varint_param_t *param) {
    return (param && param->present) ? param->value : 0;
}

static int quic_tls_peer_completed_address_validation(const quic_tls_conn_t *conn) {
    if (!conn) {
        return 0;
    }
    if (conn->role == QUIC_ROLE_SERVER) {
        return 1;
    }
    return conn->received_handshake_packet || conn->handshake_complete;
}

static int quic_tls_has_handshake_keys(const quic_tls_conn_t *conn) {
    return conn && conn->conn.spaces[QUIC_PN_SPACE_HANDSHAKE].tx_keys_ready;
}

static uint64_t quic_tls_peer_ack_delay_exponent(const quic_tls_conn_t *conn) {
    if (!conn || !conn->peer_transport_params.ack_delay_exponent.present) {
        return 3;
    }
    return conn->peer_transport_params.ack_delay_exponent.value;
}

static uint64_t quic_tls_peer_max_ack_delay_ms(const quic_tls_conn_t *conn) {
    if (!conn || !conn->peer_transport_params.max_ack_delay.present) {
        return 25;
    }
    return conn->peer_transport_params.max_ack_delay.value;
}

static uint64_t quic_tls_decode_ack_delay_ms(const quic_tls_conn_t *conn, const quic_ack_frame_t *ack) {
    uint64_t exponent;
    uint64_t ack_delay_us;

    if (!conn || !ack) {
        return 0;
    }

    exponent = quic_tls_peer_ack_delay_exponent(conn);
    if (exponent >= 20) {
        exponent = 20;
    }
    ack_delay_us = ack->ack_delay << exponent;
    return (ack_delay_us + 999ULL) / 1000ULL;
}

static void quic_tls_sync_recovery_state(quic_tls_conn_t *conn) {
    if (!conn) {
        return;
    }

    quic_recovery_set_handshake_confirmed(&conn->conn.recovery, conn->handshake_complete);
    quic_recovery_set_peer_completed_address_validation(&conn->conn.recovery,
                                                        quic_tls_peer_completed_address_validation(conn));
    quic_recovery_set_max_ack_delay(&conn->conn.recovery, quic_tls_peer_max_ack_delay_ms(conn));
}

static int quic_tls_has_ack_eliciting_buffered_data(const quic_tls_conn_t *conn) {
    size_t i;

    if (!conn) {
        return 0;
    }

    if (conn->ping_pending || conn->handshake_done_pending || quic_stream_map_has_buffered_send_data(&conn->streams)) {
        return 1;
    }

    for (i = 0; i <= ssl_encryption_application; i++) {
        if (quic_crypto_sendbuf_has_pending(&conn->levels[i].send)) {
            return 1;
        }
    }

    return 0;
}

static int quic_tls_is_flow_control_limited(const quic_tls_conn_t *conn) {
    return conn ? quic_stream_map_is_flow_control_limited(&conn->streams) : 0;
}

static void quic_tls_snapshot_application_send_state(const quic_tls_conn_t *conn,
                                                     quic_tls_app_send_snapshot_t *snapshot) {
    size_t i;

    if (!conn || !snapshot) {
        return;
    }

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->send_connection_highest = conn->streams.send_connection_highest;
    snapshot->max_data_pending = conn->streams.max_data_pending;
    snapshot->max_data_in_flight = conn->streams.max_data_in_flight;
    snapshot->max_streams_bidi_pending = conn->streams.max_streams_bidi_pending;
    snapshot->max_streams_bidi_in_flight = conn->streams.max_streams_bidi_in_flight;
    snapshot->max_streams_uni_pending = conn->streams.max_streams_uni_pending;
    snapshot->max_streams_uni_in_flight = conn->streams.max_streams_uni_in_flight;

    for (i = 0; i < QUIC_STREAM_MAX_COUNT; i++) {
        const quic_stream_t *stream = &conn->streams.streams[i];
        quic_tls_app_stream_snapshot_t *saved = &snapshot->streams[i];

        saved->active = stream->active;
        saved->send_open = stream->send_open;
        saved->fin_sent = stream->fin_sent;
        saved->fin_in_flight = stream->fin_in_flight;
        saved->stop_sending_pending = stream->stop_sending_pending;
        saved->stop_sending_in_flight = stream->stop_sending_in_flight;
        saved->reset_pending = stream->reset_pending;
        saved->reset_in_flight = stream->reset_in_flight;
        saved->max_stream_data_pending = stream->max_stream_data_pending;
        saved->max_stream_data_in_flight = stream->max_stream_data_in_flight;
        saved->send_final_size_known = stream->send_final_size_known;
        saved->send_highest_offset = stream->send_highest_offset;
        saved->send_final_size = stream->send_final_size;
        saved->flight_start = stream->sendbuf.flight_start;
        saved->flight_end = stream->sendbuf.flight_end;
        saved->send_offset = stream->sendbuf.send_offset;
        saved->flight_pending = stream->sendbuf.flight_pending;
        saved->retransmit_range_count = stream->retransmit_range_count;
        memcpy(saved->retransmit_ranges,
               stream->retransmit_ranges,
               sizeof(saved->retransmit_ranges));
    }
}

static void quic_tls_restore_application_send_state(quic_tls_conn_t *conn,
                                                    const quic_tls_app_send_snapshot_t *snapshot) {
    size_t i;

    if (!conn || !snapshot) {
        return;
    }

    conn->streams.send_connection_highest = snapshot->send_connection_highest;
    conn->streams.max_data_pending = snapshot->max_data_pending;
    conn->streams.max_data_in_flight = snapshot->max_data_in_flight;
    conn->streams.max_streams_bidi_pending = snapshot->max_streams_bidi_pending;
    conn->streams.max_streams_bidi_in_flight = snapshot->max_streams_bidi_in_flight;
    conn->streams.max_streams_uni_pending = snapshot->max_streams_uni_pending;
    conn->streams.max_streams_uni_in_flight = snapshot->max_streams_uni_in_flight;

    for (i = 0; i < QUIC_STREAM_MAX_COUNT; i++) {
        quic_stream_t *stream = &conn->streams.streams[i];
        const quic_tls_app_stream_snapshot_t *saved = &snapshot->streams[i];

        if (!saved->active || !stream->active) {
            continue;
        }
        stream->send_open = saved->send_open;
        stream->fin_sent = saved->fin_sent;
        stream->fin_in_flight = saved->fin_in_flight;
        stream->stop_sending_pending = saved->stop_sending_pending;
        stream->stop_sending_in_flight = saved->stop_sending_in_flight;
        stream->reset_pending = saved->reset_pending;
        stream->reset_in_flight = saved->reset_in_flight;
        stream->max_stream_data_pending = saved->max_stream_data_pending;
        stream->max_stream_data_in_flight = saved->max_stream_data_in_flight;
        stream->send_final_size_known = saved->send_final_size_known;
        stream->send_highest_offset = saved->send_highest_offset;
        stream->send_final_size = saved->send_final_size;
        stream->sendbuf.flight_start = saved->flight_start;
        stream->sendbuf.flight_end = saved->flight_end;
        stream->sendbuf.send_offset = saved->send_offset;
        stream->sendbuf.flight_pending = saved->flight_pending;
        stream->retransmit_range_count = saved->retransmit_range_count;
        memcpy(stream->retransmit_ranges,
               saved->retransmit_ranges,
               sizeof(saved->retransmit_ranges));
    }
}

static void quic_tls_clear_stream_inflight(quic_tls_conn_t *conn,
                                           const quic_sent_packet_t *packet,
                                           int schedule_retransmit) {
    quic_stream_t *stream;

    if (!conn || !packet) {
        return;
    }
    if (!packet->meta.includes_stream &&
        !packet->meta.includes_stop_sending &&
        !packet->meta.includes_reset_stream &&
        !packet->meta.includes_max_stream_data) {
        return;
    }

    if (packet->meta.includes_stop_sending) {
        stream = quic_stream_map_find(&conn->streams, packet->meta.control_stream_id);
        if (!stream) {
            return;
        }
        stream->stop_sending_in_flight = 0;
        if (schedule_retransmit) {
            stream->stop_sending_pending = 1;
        }
    }
    if (packet->meta.includes_reset_stream) {
        stream = quic_stream_map_find(&conn->streams, packet->meta.control_stream_id);
        if (!stream) {
            return;
        }
        stream->reset_in_flight = 0;
        if (schedule_retransmit) {
            stream->reset_pending = 1;
        }
    }
    if (packet->meta.includes_max_stream_data) {
        stream = quic_stream_map_find(&conn->streams, packet->meta.control_stream_id);
        if (!stream) {
            return;
        }
        stream->max_stream_data_in_flight = 0;
        if (schedule_retransmit) {
            stream->max_stream_data_pending = 1;
        }
    }
    if (packet->meta.includes_stream) {
        stream = quic_stream_map_find(&conn->streams, packet->meta.stream_id);
        if (!stream) {
            return;
        }
        if (schedule_retransmit) {
            quic_stream_map_on_stream_lost(&conn->streams,
                                           packet->meta.stream_id,
                                           packet->meta.stream_offset,
                                           (size_t)packet->meta.stream_length);
        } else {
            quic_stream_map_on_stream_acked(&conn->streams,
                                            packet->meta.stream_id,
                                            packet->meta.stream_offset,
                                            (size_t)packet->meta.stream_length);
        }
        if (packet->meta.stream_fin && stream->fin_in_flight) {
            if (schedule_retransmit) {
                stream->fin_sent = 0;
            } else {
                stream->fin_in_flight = 0;
            }
        }
    }
}

static void quic_tls_apply_packet_side_effects(quic_tls_conn_t *conn,
                                               const quic_sent_packet_t *packet,
                                               int schedule_retransmit) {
    enum ssl_encryption_level_t level;

    if (!conn || !packet) {
        return;
    }

    if (packet->meta.includes_ping) {
        conn->ping_in_flight = 0;
        if (schedule_retransmit) {
            conn->ping_pending = 1;
        }
    }
    if (packet->meta.includes_handshake_done) {
        conn->handshake_done_in_flight = 0;
        if (schedule_retransmit) {
            conn->handshake_done_pending = 1;
        }
    }
    if (packet->meta.includes_max_data) {
        conn->streams.max_data_in_flight = 0;
        if (schedule_retransmit) {
            conn->streams.max_data_pending = 1;
        }
    }
    if (packet->meta.includes_max_streams_bidi) {
        conn->streams.max_streams_bidi_in_flight = 0;
        if (schedule_retransmit) {
            conn->streams.max_streams_bidi_pending = 1;
        }
    }
    if (packet->meta.includes_max_streams_uni) {
        conn->streams.max_streams_uni_in_flight = 0;
        if (schedule_retransmit) {
            conn->streams.max_streams_uni_pending = 1;
        }
    }
    quic_tls_clear_stream_inflight(conn, packet, schedule_retransmit);

    if (packet->is_crypto_packet) {
        level = quic_tls_level_from_space((quic_pn_space_id_t)packet->packet_number_space);
        if (schedule_retransmit) {
            quic_crypto_sendbuf_restart_flight(&conn->levels[level].send);
        }
    }
}

static void quic_tls_on_packet_acked(void *ctx, const quic_sent_packet_t *packet) {
    quic_tls_apply_packet_side_effects((quic_tls_conn_t *)ctx, packet, 0);
}

static void quic_tls_on_packet_lost(void *ctx, const quic_sent_packet_t *packet) {
    quic_tls_apply_packet_side_effects((quic_tls_conn_t *)ctx, packet, 1);
}

static int quic_tls_append_varint(uint64_t value, uint8_t *out, size_t out_len, size_t *offset) {
    int rc;

    if (!out || !offset || *offset > out_len) {
        return -1;
    }
    rc = quic_encode_varint(value, out + *offset, out_len - *offset);
    if (rc < 0) {
        return -1;
    }
    *offset += (size_t)rc;
    return 0;
}

static quic_pn_space_id_t quic_tls_space_from_level(enum ssl_encryption_level_t level) {
    switch (level) {
        case ssl_encryption_initial:
            return QUIC_PN_SPACE_INITIAL;
        case ssl_encryption_early_data:
            return QUIC_PN_SPACE_APPLICATION;
        case ssl_encryption_handshake:
            return QUIC_PN_SPACE_HANDSHAKE;
        case ssl_encryption_application:
            return QUIC_PN_SPACE_APPLICATION;
        default:
            return QUIC_PN_SPACE_COUNT;
    }
}

static int quic_tls_is_supported_level(enum ssl_encryption_level_t level) {
    return level == ssl_encryption_initial ||
           level == ssl_encryption_early_data ||
           level == ssl_encryption_handshake ||
           level == ssl_encryption_application;
}

static int quic_tls_close_state_active(const quic_tls_conn_t *conn) {
    return conn &&
           (conn->conn.state == QUIC_CONN_STATE_CLOSING ||
            conn->conn.state == QUIC_CONN_STATE_DRAINING);
}

static int quic_tls_should_discard_without_processing(const quic_tls_conn_t *conn,
                                                      const quic_tls_packet_header_t *header) {
    if (!conn || !header) {
        return 0;
    }

    if (header->level == ssl_encryption_early_data && conn->role == QUIC_ROLE_CLIENT) {
        return 1;
    }

    // RFC 9001 5.7: endpoints MUST NOT process incoming 1-RTT packets
    // before the handshake is complete. Servers may send them earlier,
    // but receivers have to defer or discard them.
    if (header->level == ssl_encryption_application && !conn->handshake_complete) {
        return 1;
    }

    return 0;
}

static void quic_tls_enter_draining(quic_tls_conn_t *conn, uint64_t deadline_ms) {
    if (!conn) {
        return;
    }

    conn->conn.state = QUIC_CONN_STATE_DRAINING;
    conn->close_pending = 0;
    conn->close_enter_draining_after_send = 0;
    if (deadline_ms != 0) {
        conn->close_deadline_ms = deadline_ms;
    } else if (conn->close_deadline_ms == 0) {
        conn->close_deadline_ms = quic_tls_now_ms() + QUIC_TLS_CLOSE_TIMEOUT_MS;
    }
}

static enum ssl_encryption_level_t quic_tls_ack_level_for_rx(enum ssl_encryption_level_t level) {
    return level == ssl_encryption_early_data ? ssl_encryption_application : level;
}

static int quic_tls_server_amplification_limited(const quic_tls_conn_t *conn, size_t packet_len) {
    uint64_t budget;

    if (!conn || conn->role != QUIC_ROLE_SERVER || conn->peer_address_validated) {
        return 0;
    }

    budget = conn->bytes_received * 3;
    return conn->bytes_sent + packet_len > budget;
}

static void quic_tls_note_packet_sent(quic_tls_conn_t *conn, size_t packet_len) {
    if (!conn) {
        return;
    }
    conn->amplification_blocked = 0;
    conn->bytes_sent += packet_len;
}

static void quic_tls_note_packet_received(quic_tls_conn_t *conn, size_t packet_len) {
    if (!conn) {
        return;
    }
    conn->bytes_received += packet_len;
    if (conn->amplification_blocked) {
        conn->amplification_blocked = 0;
        quic_tls_arm_loss_timer(conn);
    }
}

static int quic_tls_build_blocked(quic_tls_conn_t *conn, size_t *written) {
    if (written) {
        *written = 0;
    }
    if (conn) {
        conn->amplification_blocked = 1;
        quic_tls_arm_loss_timer(conn);
    }
    return QUIC_TLS_BUILD_BLOCKED;
}

static int quic_tls_level_has_sendable_output(const quic_tls_conn_t *conn, enum ssl_encryption_level_t level) {
    quic_pn_space_id_t space = quic_tls_space_from_level(level);
    int has_stream_output = 0;

    if (!conn || space == QUIC_PN_SPACE_COUNT) {
        return 0;
    }
    if (level == ssl_encryption_application) {
        has_stream_output = quic_stream_map_has_pending_output(&conn->streams);
    }
    return (quic_crypto_sendbuf_has_pending(&conn->levels[level].send) ||
            conn->levels[level].ack_pending ||
            has_stream_output) &&
           conn->conn.spaces[space].tx_keys_ready;
}

static int quic_tls_queue_special_packet(quic_tls_conn_t *conn, const uint8_t *packet, size_t packet_len) {
    if (!conn || !packet || packet_len == 0 || packet_len > sizeof(conn->special_packet)) {
        return quic_tls_fail(conn, "invalid special packet");
    }
    memcpy(conn->special_packet, packet, packet_len);
    conn->special_packet_len = packet_len;
    conn->special_packet_pending = 1;
    quic_tls_arm_loss_timer(conn);
    return 0;
}

static void quic_tls_arm_loss_timer(quic_tls_conn_t *conn) {
    quic_recovery_timer_t timer;
    const quic_in_flight_queue_t *queues[QUIC_RECOVERY_PACKET_SPACE_COUNT];

    if (!conn) {
        return;
    }
    if (quic_tls_close_state_active(conn)) {
        if (conn->close_deadline_ms != 0) {
            quic_conn_arm_timer(&conn->conn,
                                QUIC_CONN_TIMER_LOSS_DETECTION,
                                conn->close_deadline_ms);
        } else {
            quic_conn_disarm_timer(&conn->conn, QUIC_CONN_TIMER_LOSS_DETECTION);
        }
        return;
    }

    quic_tls_sync_recovery_state(conn);
    queues[0] = &conn->conn.spaces[QUIC_PN_SPACE_INITIAL].in_flight;
    queues[1] = &conn->conn.spaces[QUIC_PN_SPACE_HANDSHAKE].in_flight;
    queues[2] = &conn->conn.spaces[QUIC_PN_SPACE_APPLICATION].in_flight;
    if (quic_recovery_get_timer(&conn->conn.recovery,
                                queues,
                                conn->role == QUIC_ROLE_SERVER &&
                                    conn->amplification_blocked &&
                                    !conn->peer_address_validated,
                                quic_tls_has_handshake_keys(conn),
                                quic_tls_now_ms(),
                                &timer) > 0) {
        quic_conn_arm_timer(&conn->conn,
                            QUIC_CONN_TIMER_LOSS_DETECTION,
                            timer.deadline_ms);
    } else {
        quic_conn_disarm_timer(&conn->conn, QUIC_CONN_TIMER_LOSS_DETECTION);
    }
}

static int quic_tls_update_peer_transport_params(quic_tls_conn_t *conn) {
    const uint8_t *params = NULL;
    size_t params_len = 0;

    if (!conn || !conn->ssl || conn->peer_transport_params_ready) {
        return 0;
    }

    SSL_get_peer_quic_transport_params(conn->ssl, &params, &params_len);
    if (!params || params_len == 0) {
        return 0;
    }
    if (params_len > sizeof(conn->peer_transport_params_bytes)) {
        return quic_tls_fail(conn, "peer transport params too large");
    }

    memcpy(conn->peer_transport_params_bytes, params, params_len);
    conn->peer_transport_params_len = params_len;
    if (quic_transport_params_decode(conn->peer_transport_params_bytes,
                                     conn->peer_transport_params_len,
                                     &conn->peer_transport_params) != 0) {
        return quic_tls_fail(conn, "failed to decode peer transport params");
    }

    quic_stream_map_set_peer_limits(&conn->streams,
                                    quic_tls_transport_param_value(&conn->peer_transport_params.initial_max_data),
                                    quic_tls_transport_param_value(&conn->peer_transport_params.initial_max_stream_data_bidi_local),
                                    quic_tls_transport_param_value(&conn->peer_transport_params.initial_max_stream_data_bidi_remote),
                                    quic_tls_transport_param_value(&conn->peer_transport_params.initial_max_stream_data_uni),
                                    quic_tls_transport_param_value(&conn->peer_transport_params.initial_max_streams_bidi),
                                    quic_tls_transport_param_value(&conn->peer_transport_params.initial_max_streams_uni));
    conn->peer_transport_params_ready = 1;
    quic_tls_sync_recovery_state(conn);
    return 0;
}

static int quic_tls_build_retry_token(const quic_cid_t *original_dcid,
                                      uint8_t *out,
                                      size_t out_len,
                                      size_t *written) {
    if (!original_dcid || !out || !written || original_dcid->len == 0 || out_len < (size_t)(4 + original_dcid->len)) {
        return -1;
    }

    out[0] = 'A';
    out[1] = 'I';
    out[2] = 'Q';
    out[3] = original_dcid->len;
    memcpy(out + 4, original_dcid->data, original_dcid->len);
    *written = 4 + original_dcid->len;
    return 0;
}

static int quic_tls_validate_retry_token(const uint8_t *token,
                                         size_t token_len,
                                         const quic_cid_t *original_dcid) {
    if (!token || !original_dcid || token_len < 4) {
        return 0;
    }
    if (token[0] != 'A' || token[1] != 'I' || token[2] != 'Q' || token[3] != original_dcid->len) {
        return 0;
    }
    return token_len == (size_t)(4 + original_dcid->len) &&
           memcmp(token + 4, original_dcid->data, original_dcid->len) == 0;
}

static void quic_tls_reset_initial_stream_state(quic_tls_conn_t *conn) {
    if (!conn) {
        return;
    }

    quic_conn_discard_space(&conn->conn, QUIC_PN_SPACE_INITIAL);
    quic_crypto_recvbuf_free(&conn->levels[ssl_encryption_initial].recv);
    quic_crypto_recvbuf_init(&conn->levels[ssl_encryption_initial].recv);
    quic_crypto_sendbuf_restart_flight(&conn->levels[ssl_encryption_initial].send);
    conn->levels[ssl_encryption_initial].discarded = 0;
    conn->levels[ssl_encryption_initial].read_secret_ready = 0;
    conn->levels[ssl_encryption_initial].write_secret_ready = 0;
    conn->levels[ssl_encryption_initial].ack_pending = 0;
    conn->initial_keys_discarded = 0;
}

static void quic_tls_maybe_discard_keys(quic_tls_conn_t *conn) {
    if (!conn) {
        return;
    }

    if (conn->received_handshake_packet &&
        conn->levels[ssl_encryption_initial].send.send_offset >= conn->levels[ssl_encryption_initial].send.flight_end &&
        !conn->initial_keys_discarded) {
        quic_conn_discard_space(&conn->conn, QUIC_PN_SPACE_INITIAL);
        conn->levels[ssl_encryption_initial].discarded = 1;
        conn->levels[ssl_encryption_initial].read_secret_ready = 0;
        conn->levels[ssl_encryption_initial].write_secret_ready = 0;
        conn->levels[ssl_encryption_initial].ack_pending = 0;
        conn->initial_keys_discarded = 1;
    }

    if (conn->handshake_complete &&
        conn->application_secrets_ready &&
        conn->levels[ssl_encryption_handshake].send.send_offset >= conn->levels[ssl_encryption_handshake].send.flight_end &&
        ((conn->role == QUIC_ROLE_CLIENT && (conn->handshake_done_received || conn->ping_received)) ||
         (conn->role == QUIC_ROLE_SERVER && conn->ping_received)) &&
        !conn->handshake_keys_discarded) {
        quic_conn_discard_space(&conn->conn, QUIC_PN_SPACE_HANDSHAKE);
        conn->levels[ssl_encryption_handshake].discarded = 1;
        conn->levels[ssl_encryption_handshake].read_secret_ready = 0;
        conn->levels[ssl_encryption_handshake].write_secret_ready = 0;
        conn->levels[ssl_encryption_handshake].ack_pending = 0;
        conn->handshake_keys_discarded = 1;
    }
}

static int quic_tls_set_transport_params(quic_tls_conn_t *conn) {
    int encoded_len;

    if (!conn || !conn->ssl || !conn->local_cid.len) {
        return quic_tls_fail(conn, "transport params missing local cid");
    }

    quic_transport_params_init(&conn->local_transport_params);
    conn->local_transport_params.max_udp_payload_size.present = 1;
    conn->local_transport_params.max_udp_payload_size.value = 1200;
    conn->local_transport_params.max_idle_timeout.present = 1;
    conn->local_transport_params.max_idle_timeout.value = 30000;
    conn->local_transport_params.initial_max_data.present = 1;
    conn->local_transport_params.initial_max_data.value = conn->initial_max_data;
    conn->local_transport_params.initial_max_stream_data_bidi_local.present = 1;
    conn->local_transport_params.initial_max_stream_data_bidi_local.value = conn->initial_max_stream_data_bidi_local;
    conn->local_transport_params.initial_max_stream_data_bidi_remote.present = 1;
    conn->local_transport_params.initial_max_stream_data_bidi_remote.value = conn->initial_max_stream_data_bidi_remote;
    conn->local_transport_params.initial_max_stream_data_uni.present = 1;
    conn->local_transport_params.initial_max_stream_data_uni.value = conn->initial_max_stream_data_uni;
    conn->local_transport_params.initial_max_streams_bidi.present = 1;
    conn->local_transport_params.initial_max_streams_bidi.value = conn->initial_max_streams_bidi;
    conn->local_transport_params.initial_max_streams_uni.present = 1;
    conn->local_transport_params.initial_max_streams_uni.value = conn->initial_max_streams_uni;
    conn->local_transport_params.active_connection_id_limit.present = 1;
    conn->local_transport_params.active_connection_id_limit.value = 4;
    conn->local_transport_params.initial_source_connection_id.present = 1;
    conn->local_transport_params.initial_source_connection_id.cid = conn->local_cid;
    if (conn->role == QUIC_ROLE_SERVER) {
        if (!conn->original_dcid_known) {
            return quic_tls_fail(conn, "server original dcid unavailable");
        }
        conn->local_transport_params.original_destination_connection_id.present = 1;
        conn->local_transport_params.original_destination_connection_id.cid = conn->original_dcid;
    }

    encoded_len = quic_transport_params_encode(&conn->local_transport_params,
                                               conn->local_transport_params_bytes,
                                               sizeof(conn->local_transport_params_bytes));
    if (encoded_len < 0) {
        return quic_tls_fail(conn, "failed to encode local transport params");
    }
    conn->local_transport_params_len = (size_t)encoded_len;

    if (SSL_set_quic_transport_params(conn->ssl,
                                      conn->local_transport_params_bytes,
                                      conn->local_transport_params_len) != 1) {
        return quic_tls_fail_ssl(conn, "failed to set local transport params");
    }

    quic_stream_map_set_local_limits(&conn->streams,
                                     conn->initial_max_data,
                                     conn->initial_max_stream_data_bidi_local,
                                     conn->initial_max_stream_data_bidi_remote,
                                     conn->initial_max_stream_data_uni,
                                     conn->initial_max_streams_bidi,
                                     conn->initial_max_streams_uni);
    conn->transport_params_set = 1;
    return 0;
}

static int quic_tls_install_initial_keys(quic_tls_conn_t *conn) {
    quic_crypto_context_t initial;

    if (!conn || !conn->version_ops || !conn->initial_dcid_known) {
        return quic_tls_fail(conn, "initial key prerequisites missing");
    }
    if (conn->levels[ssl_encryption_initial].read_secret_ready &&
        conn->levels[ssl_encryption_initial].write_secret_ready) {
        return 0;
    }

    if (quic_crypto_setup_initial_keys(&conn->initial_dcid, conn->version_ops, &initial) != 0) {
        return quic_tls_fail(conn, "failed to derive initial keys");
    }

    conn->conn.version = conn->version;
    conn->conn.version_ops = conn->version_ops;
    conn->conn.original_dcid = conn->initial_dcid;
    conn->conn.state = QUIC_CONN_STATE_HANDSHAKING;

    if (conn->role == QUIC_ROLE_CLIENT) {
        if (quic_conn_install_tx_keys(&conn->conn, QUIC_PN_SPACE_INITIAL, &initial.client_initial) != QUIC_CONN_OK) {
            return quic_tls_fail(conn, "failed to install client initial tx keys");
        }
        if (quic_conn_install_rx_keys(&conn->conn, QUIC_PN_SPACE_INITIAL, &initial.server_initial) != QUIC_CONN_OK) {
            return quic_tls_fail(conn, "failed to install client initial rx keys");
        }
    } else {
        if (quic_conn_install_rx_keys(&conn->conn, QUIC_PN_SPACE_INITIAL, &initial.client_initial) != QUIC_CONN_OK) {
            return quic_tls_fail(conn, "failed to install server initial rx keys");
        }
        if (quic_conn_install_tx_keys(&conn->conn, QUIC_PN_SPACE_INITIAL, &initial.server_initial) != QUIC_CONN_OK) {
            return quic_tls_fail(conn, "failed to install server initial tx keys");
        }
    }

    conn->levels[ssl_encryption_initial].read_secret_ready = 1;
    conn->levels[ssl_encryption_initial].write_secret_ready = 1;
    return 0;
}

static int quic_tls_install_secret(quic_tls_conn_t *conn,
                                   enum ssl_encryption_level_t level,
                                   const SSL_CIPHER *cipher,
                                   const uint8_t *secret,
                                   size_t secret_len,
                                   int is_write) {
    quic_crypto_level_ctx_t packet_keys;
    quic_pn_space_id_t space;
    uint16_t cipher_id;

    if (!conn || !cipher || !secret) {
        return 0;
    }
    if (!quic_tls_is_supported_level(level)) {
        quic_tls_set_error(conn, "0-rtt is not implemented");
        return 0;
    }

    cipher_id = SSL_CIPHER_get_protocol_id(cipher);
    if (cipher_id != QUIC_TLS_CIPHER_AES_128_GCM_SHA256) {
        quic_tls_set_error(conn, "only TLS_AES_128_GCM_SHA256 is supported");
        return 0;
    }
    if (quic_crypto_derive_packet_keys(secret, secret_len, conn->version_ops, &packet_keys) != 0) {
        quic_tls_set_error(conn, "failed to derive packet protection keys");
        return 0;
    }

    space = quic_tls_space_from_level(level);
    if (space == QUIC_PN_SPACE_COUNT) {
        quic_tls_set_error(conn, "invalid encryption level");
        return 0;
    }

    if (is_write) {
        if (quic_conn_install_tx_keys(&conn->conn, space, &packet_keys) != QUIC_CONN_OK) {
            quic_tls_set_error(conn, "failed to install tx keys");
            return 0;
        }
        conn->levels[level].write_secret_ready = 1;
    } else {
        if (quic_conn_install_rx_keys(&conn->conn, space, &packet_keys) != QUIC_CONN_OK) {
            quic_tls_set_error(conn, "failed to install rx keys");
            return 0;
        }
        conn->levels[level].read_secret_ready = 1;
    }

    if (level == ssl_encryption_application &&
        conn->levels[level].read_secret_ready &&
        conn->levels[level].write_secret_ready) {
        conn->application_secrets_ready = 1;
    }

    quic_tls_maybe_discard_keys(conn);
    return 1;
}

static int quic_tls_set_read_secret_cb(SSL *ssl,
                                       enum ssl_encryption_level_t level,
                                       const SSL_CIPHER *cipher,
                                       const uint8_t *secret,
                                       size_t secret_len) {
    return quic_tls_install_secret(quic_tls_from_ssl(ssl), level, cipher, secret, secret_len, 0);
}

static int quic_tls_set_write_secret_cb(SSL *ssl,
                                        enum ssl_encryption_level_t level,
                                        const SSL_CIPHER *cipher,
                                        const uint8_t *secret,
                                        size_t secret_len) {
    return quic_tls_install_secret(quic_tls_from_ssl(ssl), level, cipher, secret, secret_len, 1);
}

static int quic_tls_add_handshake_data_cb(SSL *ssl,
                                          enum ssl_encryption_level_t level,
                                          const uint8_t *data,
                                          size_t len) {
    quic_tls_conn_t *conn = quic_tls_from_ssl(ssl);

    if (!conn || !quic_tls_is_supported_level(level)) {
        return 0;
    }
    if (quic_crypto_sendbuf_append(&conn->levels[level].send, data, len) != 0) {
        quic_tls_set_error(conn, "failed to append handshake data");
        return 0;
    }
    return 1;
}

static int quic_tls_flush_flight_cb(SSL *ssl) {
    quic_tls_conn_t *conn = quic_tls_from_ssl(ssl);
    size_t i;

    if (!conn) {
        return 0;
    }

    for (i = 0; i <= ssl_encryption_application; i++) {
        quic_crypto_sendbuf_mark_flight(&conn->levels[i].send);
    }
    quic_tls_arm_loss_timer(conn);
    return 1;
}

static int quic_tls_send_alert_cb(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert) {
    quic_tls_conn_t *conn = quic_tls_from_ssl(ssl);

    if (!conn) {
        return 0;
    }
    conn->last_alert_level = (uint8_t)level;
    conn->last_alert = alert;
    return 1;
}

static const SSL_QUIC_METHOD quic_tls_quic_method = {
    .set_read_secret = quic_tls_set_read_secret_cb,
    .set_write_secret = quic_tls_set_write_secret_cb,
    .add_handshake_data = quic_tls_add_handshake_data_cb,
    .flush_flight = quic_tls_flush_flight_cb,
    .send_alert = quic_tls_send_alert_cb,
};

static int quic_tls_drive_handshake(quic_tls_conn_t *conn) {
    int ret;

    if (!conn || !conn->ssl) {
        return quic_tls_fail(conn, "tls object unavailable");
    }

    ret = SSL_do_handshake(conn->ssl);
    if (ret == 1) {
        conn->handshake_complete = 1;
        conn->conn.state = QUIC_CONN_STATE_ACTIVE;
        if (conn->role == QUIC_ROLE_SERVER) {
            conn->handshake_done_pending = 1;
        }
        if (quic_tls_update_peer_transport_params(conn) != 0) {
            return -1;
        }
        quic_tls_sync_recovery_state(conn);
        quic_tls_maybe_discard_keys(conn);
        quic_tls_arm_loss_timer(conn);
        return 0;
    }

    ret = SSL_get_error(conn->ssl, ret);
    if (ret == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE) {
        quic_tls_arm_loss_timer(conn);
        return 0;
    }

    return quic_tls_fail_ssl(conn, "tls handshake failed");
}

static int quic_tls_feed_crypto(quic_tls_conn_t *conn, enum ssl_encryption_level_t level, int *fed_anything) {
    size_t contiguous;
    const uint8_t *ptr;

    if (!conn || !fed_anything) {
        return quic_tls_fail(conn, "invalid crypto feed arguments");
    }

    while ((contiguous = quic_crypto_recvbuf_contiguous_len(&conn->levels[level].recv)) > 0) {
        ptr = quic_crypto_recvbuf_read_ptr(&conn->levels[level].recv);
        if (SSL_provide_quic_data(conn->ssl, level, ptr, contiguous) != 1) {
            return quic_tls_fail_ssl(conn, "failed to provide quic crypto data");
        }
        quic_crypto_recvbuf_consume(&conn->levels[level].recv, contiguous);
        *fed_anything = 1;
    }
    return 0;
}

static void quic_tls_mark_ack_pending(quic_tls_conn_t *conn, enum ssl_encryption_level_t received_level) {
    enum ssl_encryption_level_t ack_level;

    if (!conn) {
        return;
    }

    ack_level = quic_tls_ack_level_for_rx(received_level);
    if (!quic_tls_is_supported_level(ack_level)) {
        return;
    }
    conn->levels[ack_level].ack_pending = 1;
}

static int quic_tls_on_peer_connection_close(quic_tls_conn_t *conn) {
    uint64_t close_deadline_ms;

    if (!conn) {
        return quic_tls_fail(conn, "invalid peer close state");
    }

    conn->close_received = 1;
    close_deadline_ms = conn->close_deadline_ms != 0
                            ? conn->close_deadline_ms
                            : (quic_tls_now_ms() + QUIC_TLS_CLOSE_TIMEOUT_MS);

    if (conn->conn.state == QUIC_CONN_STATE_CLOSED || conn->conn.state == QUIC_CONN_STATE_DRAINING) {
        quic_tls_enter_draining(conn, close_deadline_ms);
        quic_tls_arm_loss_timer(conn);
        return 0;
    }
    if (conn->conn.state == QUIC_CONN_STATE_CLOSING) {
        quic_tls_enter_draining(conn, close_deadline_ms);
        quic_tls_arm_loss_timer(conn);
        return 0;
    }

    if (quic_tls_prepare_connection_close(conn, QUIC_TRANSPORT_ERROR_NO_ERROR, 1) != 0) {
        conn->close_pending = 0;
        conn->close_packet_len = 0;
        quic_tls_enter_draining(conn, close_deadline_ms);
        quic_tls_arm_loss_timer(conn);
    }
    return 0;
}

static int quic_tls_parse_frames(quic_tls_conn_t *conn,
                                 enum ssl_encryption_level_t level,
                                 const uint8_t *plaintext,
                                 size_t plaintext_len,
                                 int *fed_crypto,
                                 int *saw_ack_eliciting,
                                 int *received_connection_close) {
    size_t offset = 0;

    if (!conn || !plaintext || !fed_crypto || !saw_ack_eliciting || !received_connection_close) {
        return quic_tls_fail(conn, "invalid frame parsing arguments");
    }

    *received_connection_close = 0;

    while (offset < plaintext_len) {
        size_t frame_start = offset;
        uint64_t frame_type;

        if (quic_decode_varint(plaintext, plaintext_len, &offset, &frame_type) != 0) {
            return quic_tls_fail(conn, "failed to decode frame type");
        }

        if (frame_type >= 0x08 && frame_type <= 0x0f) {
            uint64_t stream_id;
            uint64_t stream_offset = 0;
            uint64_t stream_len;
            int has_offset = (frame_type & 0x04) != 0;
            int has_length = (frame_type & 0x02) != 0;
            int fin = (frame_type & 0x01) != 0;

            if (level != ssl_encryption_application && level != ssl_encryption_early_data) {
                return quic_tls_fail(conn, "stream frame received before application keys");
            }
            if (quic_decode_varint(plaintext, plaintext_len, &offset, &stream_id) != 0) {
                return quic_tls_fail(conn, "invalid stream frame stream id");
            }
            if (has_offset && quic_decode_varint(plaintext, plaintext_len, &offset, &stream_offset) != 0) {
                return quic_tls_fail(conn, "invalid stream frame offset");
            }
            if (has_length) {
                if (quic_decode_varint(plaintext, plaintext_len, &offset, &stream_len) != 0 ||
                    stream_len > plaintext_len - offset) {
                    return quic_tls_fail(conn, "invalid stream frame length");
                }
            } else {
                stream_len = plaintext_len - offset;
            }
            if (stream_offset > QUIC_STREAM_MAX_OFFSET ||
                stream_len > QUIC_STREAM_MAX_OFFSET ||
                stream_offset > QUIC_STREAM_MAX_OFFSET - stream_len) {
                return quic_tls_fail(conn, "stream frame exceeded valid offset range");
            }
            if (quic_stream_map_on_stream(&conn->streams,
                                          stream_id,
                                          stream_offset,
                                          plaintext + offset,
                                          (size_t)stream_len,
                                          fin,
                                          conn->error_message,
                                          sizeof(conn->error_message)) != 0) {
                return -1;
            }
            offset += (size_t)stream_len;
            *saw_ack_eliciting = 1;
            continue;
        }

        switch (frame_type) {
            case QUIC_FRAME_PADDING:
                while (offset < plaintext_len && plaintext[offset] == 0x00) {
                    offset++;
                }
                break;

            case QUIC_FRAME_PING:
                conn->ping_received = 1;
                *saw_ack_eliciting = 1;
                break;

            case QUIC_FRAME_HANDSHAKE_DONE:
                conn->handshake_done_received = 1;
                *saw_ack_eliciting = 1;
                break;

            case QUIC_FRAME_ACK:
            case QUIC_FRAME_ACK_ECN: {
                quic_ack_frame_t ack;
                size_t consumed = 0;
                size_t lost_packets = 0;
                quic_pn_space_id_t ack_space = quic_tls_space_from_level(level);

                if (quic_ack_parse_frame(plaintext + frame_start, plaintext_len - frame_start, &ack, &consumed) != 0) {
                    return quic_tls_fail(conn, "invalid ack frame");
                }
                quic_tls_sync_recovery_state(conn);
                if (quic_recovery_on_ack_received(&conn->conn.recovery,
                                                 &conn->conn.spaces[ack_space].in_flight,
                                                 &ack,
                                                 (uint8_t)ack_space,
                                                 quic_tls_decode_ack_delay_ms(conn, &ack),
                                                 quic_tls_now_ms(),
                                                 quic_tls_on_packet_acked,
                                                 quic_tls_on_packet_lost,
                                                 conn,
                                                 &conn->conn.last_acked_packets,
                                                 &lost_packets) != 0) {
                    return quic_tls_fail(conn, "failed to apply ack frame");
                }
                offset = frame_start + consumed;
                break;
            }

            case QUIC_FRAME_CRYPTO: {
                uint64_t crypto_offset;
                uint64_t crypto_len;

                if (quic_decode_varint(plaintext, plaintext_len, &offset, &crypto_offset) != 0 ||
                    quic_decode_varint(plaintext, plaintext_len, &offset, &crypto_len) != 0 ||
                    crypto_len > plaintext_len - offset) {
                    return quic_tls_fail(conn, "invalid crypto frame");
                }

                if (quic_crypto_recvbuf_insert(&conn->levels[level].recv,
                                               crypto_offset,
                                               plaintext + offset,
                                               (size_t)crypto_len) != 0) {
                    return quic_tls_fail(conn, "failed to reassemble crypto data");
                }
                offset += (size_t)crypto_len;
                *saw_ack_eliciting = 1;
                if (quic_tls_feed_crypto(conn, level, fed_crypto) != 0) {
                    return -1;
                }
                break;
            }

            case QUIC_FRAME_NEW_TOKEN: {
                uint64_t token_len;
                if (quic_decode_varint(plaintext, plaintext_len, &offset, &token_len) != 0 ||
                    token_len > plaintext_len - offset ||
                    token_len > sizeof(conn->retry_token)) {
                    return quic_tls_fail(conn, "invalid new_token frame");
                }
                memcpy(conn->retry_token, plaintext + offset, (size_t)token_len);
                conn->retry_token_len = (size_t)token_len;
                offset += (size_t)token_len;
                *saw_ack_eliciting = 1;
                break;
            }

            case QUIC_FRAME_RESET_STREAM: {
                uint64_t stream_id;
                uint64_t error_code;
                uint64_t final_size;

                if (level != ssl_encryption_application && level != ssl_encryption_early_data) {
                    return quic_tls_fail(conn, "reset_stream received before application keys");
                }
                if (quic_decode_varint(plaintext, plaintext_len, &offset, &stream_id) != 0 ||
                    quic_decode_varint(plaintext, plaintext_len, &offset, &error_code) != 0 ||
                    quic_decode_varint(plaintext, plaintext_len, &offset, &final_size) != 0) {
                    return quic_tls_fail(conn, "invalid reset_stream frame");
                }
                if (quic_stream_map_on_reset_stream(&conn->streams,
                                                    stream_id,
                                                    error_code,
                                                    final_size,
                                                    conn->error_message,
                                                    sizeof(conn->error_message)) != 0) {
                    return -1;
                }
                *saw_ack_eliciting = 1;
                break;
            }

            case QUIC_FRAME_STOP_SENDING: {
                uint64_t stream_id;
                uint64_t error_code;

                if (level != ssl_encryption_application && level != ssl_encryption_early_data) {
                    return quic_tls_fail(conn, "stop_sending received before application keys");
                }
                if (quic_decode_varint(plaintext, plaintext_len, &offset, &stream_id) != 0 ||
                    quic_decode_varint(plaintext, plaintext_len, &offset, &error_code) != 0) {
                    return quic_tls_fail(conn, "invalid stop_sending frame");
                }
                if (quic_stream_map_on_stop_sending(&conn->streams,
                                                    stream_id,
                                                    error_code,
                                                    conn->error_message,
                                                    sizeof(conn->error_message)) != 0) {
                    return -1;
                }
                *saw_ack_eliciting = 1;
                break;
            }

            case QUIC_FRAME_MAX_DATA: {
                uint64_t max_data;

                if (quic_decode_varint(plaintext, plaintext_len, &offset, &max_data) != 0) {
                    return quic_tls_fail(conn, "invalid max_data frame");
                }
                if (quic_stream_map_on_max_data(&conn->streams, max_data) != 0) {
                    return quic_tls_fail(conn, "failed to apply max_data");
                }
                *saw_ack_eliciting = 1;
                break;
            }

            case QUIC_FRAME_MAX_STREAM_DATA: {
                uint64_t stream_id;
                uint64_t max_data;

                if (quic_decode_varint(plaintext, plaintext_len, &offset, &stream_id) != 0 ||
                    quic_decode_varint(plaintext, plaintext_len, &offset, &max_data) != 0) {
                    return quic_tls_fail(conn, "invalid max_stream_data frame");
                }
                if (quic_stream_map_on_max_stream_data(&conn->streams,
                                                       stream_id,
                                                       max_data,
                                                       conn->error_message,
                                                       sizeof(conn->error_message)) != 0) {
                    return -1;
                }
                *saw_ack_eliciting = 1;
                break;
            }

            case QUIC_FRAME_MAX_STREAMS_BIDI:
            case QUIC_FRAME_MAX_STREAMS_UNI: {
                uint64_t max_streams;

                if (quic_decode_varint(plaintext, plaintext_len, &offset, &max_streams) != 0) {
                    return quic_tls_fail(conn, "invalid max_streams frame");
                }
                if (quic_stream_map_on_max_streams(&conn->streams,
                                                   frame_type == QUIC_FRAME_MAX_STREAMS_BIDI,
                                                   max_streams) != 0) {
                    return quic_tls_fail(conn, "failed to apply max_streams");
                }
                *saw_ack_eliciting = 1;
                break;
            }

            case QUIC_FRAME_DATA_BLOCKED: {
                uint64_t ignored;
                if (quic_decode_varint(plaintext, plaintext_len, &offset, &ignored) != 0) {
                    return quic_tls_fail(conn, "invalid data_blocked frame");
                }
                *saw_ack_eliciting = 1;
                break;
            }

            case QUIC_FRAME_STREAM_DATA_BLOCKED: {
                uint64_t stream_id;
                uint64_t ignored;
                if (quic_decode_varint(plaintext, plaintext_len, &offset, &stream_id) != 0 ||
                    quic_decode_varint(plaintext, plaintext_len, &offset, &ignored) != 0) {
                    return quic_tls_fail(conn, "invalid stream_data_blocked frame");
                }
                *saw_ack_eliciting = 1;
                break;
            }

            case QUIC_FRAME_STREAMS_BLOCKED_BIDI:
            case QUIC_FRAME_STREAMS_BLOCKED_UNI: {
                uint64_t ignored;
                if (quic_decode_varint(plaintext, plaintext_len, &offset, &ignored) != 0) {
                    return quic_tls_fail(conn, "invalid streams_blocked frame");
                }
                *saw_ack_eliciting = 1;
                break;
            }

            case QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT: {
                uint64_t error_code;
                uint64_t ignored_frame_type;
                uint64_t reason_len;

                if (quic_decode_varint(plaintext, plaintext_len, &offset, &error_code) != 0 ||
                    quic_decode_varint(plaintext, plaintext_len, &offset, &ignored_frame_type) != 0 ||
                    quic_decode_varint(plaintext, plaintext_len, &offset, &reason_len) != 0 ||
                    reason_len > plaintext_len - offset) {
                    return quic_tls_fail(conn, "invalid transport connection_close frame");
                }
                conn->peer_close_error_code = error_code;
                offset += (size_t)reason_len;
                *received_connection_close = 1;
                return quic_tls_on_peer_connection_close(conn);
            }

            case QUIC_FRAME_CONNECTION_CLOSE_APPLICATION: {
                uint64_t error_code;
                uint64_t reason_len;

                if (quic_decode_varint(plaintext, plaintext_len, &offset, &error_code) != 0 ||
                    quic_decode_varint(plaintext, plaintext_len, &offset, &reason_len) != 0 ||
                    reason_len > plaintext_len - offset) {
                    return quic_tls_fail(conn, "invalid application connection_close frame");
                }
                conn->peer_close_error_code = error_code;
                offset += (size_t)reason_len;
                *received_connection_close = 1;
                return quic_tls_on_peer_connection_close(conn);
            }

            default:
                return quic_tls_fail(conn, "received unsupported frame during current stage");
        }
    }

    return 0;
}

static int quic_tls_encode_long_header(uint8_t packet_type,
                                       const quic_cid_t *dcid,
                                       const quic_cid_t *scid,
                                       uint32_t version,
                                       uint64_t length,
                                       const uint8_t *token,
                                       size_t token_len,
                                       size_t pn_len,
                                       uint64_t packet_number,
                                       uint8_t *out,
                                       size_t out_len,
                                       size_t *pn_offset,
                                       size_t *header_len) {
    const quic_version_ops_t *ops;
    size_t offset = 0;
    int rc;
    uint8_t encoded_type;

    if (!dcid || !scid || !out || !pn_offset || !header_len || pn_len != 4) {
        return -1;
    }
    ops = quic_version_get_ops(version);
    if (!ops || !ops->encode_packet_type) {
        return -1;
    }
    encoded_type = ops->encode_packet_type(packet_type);

    out[offset++] = (uint8_t)(0xc0 | ((encoded_type & 0x03) << 4) | ((pn_len - 1) & 0x03));
    out[offset++] = (uint8_t)(version >> 24);
    out[offset++] = (uint8_t)(version >> 16);
    out[offset++] = (uint8_t)(version >> 8);
    out[offset++] = (uint8_t)version;

    if (offset + 1 + dcid->len + 1 + scid->len > out_len) {
        return -1;
    }
    out[offset++] = dcid->len;
    memcpy(out + offset, dcid->data, dcid->len);
    offset += dcid->len;
    out[offset++] = scid->len;
    memcpy(out + offset, scid->data, scid->len);
    offset += scid->len;

    if (packet_type == 0) {
        rc = quic_encode_varint(token_len, out + offset, out_len - offset);
        if (rc < 0) {
            return -1;
        }
        offset += (size_t)rc;
        if (offset + token_len > out_len) {
            return -1;
        }
        if (token_len > 0 && token) {
            memcpy(out + offset, token, token_len);
        }
        offset += token_len;
    }

    rc = quic_encode_varint(length, out + offset, out_len - offset);
    if (rc < 0) {
        return -1;
    }
    offset += (size_t)rc;
    *pn_offset = offset;

    if (quic_encode_packet_number(packet_number, pn_len, out + offset, out_len - offset) != 0) {
        return -1;
    }
    offset += pn_len;
    *header_len = offset;
    return 0;
}

static int quic_tls_encode_short_header(const quic_cid_t *dcid,
                                        size_t pn_len,
                                        uint64_t packet_number,
                                        uint8_t *out,
                                        size_t out_len,
                                        size_t *pn_offset,
                                        size_t *header_len) {
    size_t offset = 0;

    if (!dcid || !out || !pn_offset || !header_len || pn_len != 4) {
        return -1;
    }
    if (1 + dcid->len + pn_len > out_len) {
        return -1;
    }

    out[offset++] = (uint8_t)(0x40 | ((pn_len - 1) & 0x03));
    memcpy(out + offset, dcid->data, dcid->len);
    offset += dcid->len;
    *pn_offset = offset;

    if (quic_encode_packet_number(packet_number, pn_len, out + offset, out_len - offset) != 0) {
        return -1;
    }
    offset += pn_len;
    *header_len = offset;
    return 0;
}

static int quic_tls_parse_long_header_pn_offset(quic_tls_packet_header_t *header,
                                                const uint8_t *packet,
                                                size_t packet_len,
                                                uint8_t logical_packet_type) {
    size_t offset;
    uint64_t ignored_length;
    uint64_t token_length = 0;

    if (!header || !packet) {
        return -1;
    }
    offset = 6 + header->meta.dest_cid.len + 1 + header->meta.src_cid.len;
    if (offset > packet_len) {
        return -1;
    }

    header->token_offset = 0;
    header->token_length = 0;

    if (logical_packet_type == 0) {
        if (quic_decode_varint(packet, packet_len, &offset, &token_length) != 0) {
            return -1;
        }
        if (offset + token_length > packet_len) {
            return -1;
        }
        header->token_offset = offset;
        header->token_length = (size_t)token_length;
        offset += (size_t)token_length;
    }

    if (quic_decode_varint(packet, packet_len, &offset, &ignored_length) != 0) {
        return -1;
    }
    if (offset + 4 > packet_len) {
        return -1;
    }

    header->pn_offset = offset;
    return 0;
}

static int quic_tls_classify_packet(quic_tls_conn_t *conn,
                                    const uint8_t *packet,
                                    size_t packet_len,
                                    quic_tls_packet_header_t *header) {
    const quic_version_ops_t *ops;
    uint8_t packet_type;

    if (!conn || !packet || !header) {
        return quic_tls_fail(conn, "invalid packet classification arguments");
    }
    if (quic_parse_header_meta(packet, packet_len, &header->meta) != 0) {
        return quic_tls_fail(conn, "failed to parse packet header");
    }
    header->kind = QUIC_TLS_PACKET_STANDARD;
    header->packet_type = 0xff;
    header->token_offset = 0;
    header->token_length = 0;

    if (header->meta.header_form == 0) {
        if (conn->local_cid.len == 0 ||
            packet_len < (size_t)(1 + conn->local_cid.len + 4 + QUIC_AEAD_TAG_LEN)) {
            return quic_tls_fail(conn, "short header packet is truncated");
        }
        header->space = QUIC_PN_SPACE_APPLICATION;
        header->level = ssl_encryption_application;
        header->pn_offset = 1 + conn->local_cid.len;
        return 0;
    }

    if (header->meta.version == 0) {
        header->kind = QUIC_TLS_PACKET_VERSION_NEGOTIATION;
        return 0;
    }

    ops = quic_version_get_ops(header->meta.version);
    if (!ops) {
        return quic_tls_fail(conn, "unsupported quic version");
    }
    packet_type = ops->decode_packet_type(packet[0]);
    header->packet_type = packet_type;

    switch (packet_type) {
        case 0:
            if (quic_tls_parse_long_header_pn_offset(header, packet, packet_len, packet_type) != 0) {
                return quic_tls_fail(conn, "failed to parse initial header");
            }
            header->space = QUIC_PN_SPACE_INITIAL;
            header->level = ssl_encryption_initial;
            return 0;
        case 1:
            if (quic_tls_parse_long_header_pn_offset(header, packet, packet_len, packet_type) != 0) {
                return quic_tls_fail(conn, "failed to parse 0-rtt header");
            }
            header->space = QUIC_PN_SPACE_APPLICATION;
            header->level = ssl_encryption_early_data;
            return 0;
        case 2:
            if (quic_tls_parse_long_header_pn_offset(header, packet, packet_len, packet_type) != 0) {
                return quic_tls_fail(conn, "failed to parse handshake header");
            }
            header->space = QUIC_PN_SPACE_HANDSHAKE;
            header->level = ssl_encryption_handshake;
            return 0;
        case 3:
            if (packet_len < (size_t)(6 + header->meta.dest_cid.len + 1 + header->meta.src_cid.len + QUIC_RETRY_INTEGRITY_TAG_LEN)) {
                return quic_tls_fail(conn, "retry packet is truncated");
            }
            header->kind = QUIC_TLS_PACKET_RETRY;
            header->token_offset = 6 + header->meta.dest_cid.len + 1 + header->meta.src_cid.len;
            header->token_length = packet_len - header->token_offset - QUIC_RETRY_INTEGRITY_TAG_LEN;
            return 0;
        default:
            return quic_tls_fail(conn, "unsupported packet type");
    }
}

static int quic_tls_prepare_plan(quic_tls_conn_t *conn,
                                 quic_pn_space_id_t space,
                                 uint8_t ack_eliciting,
                                 quic_conn_tx_plan_t *plan) {
    int status;

    status = quic_conn_prepare_send(&conn->conn, space, 0, ack_eliciting, plan);
    if (status != QUIC_CONN_OK) {
        snprintf(conn->error_message,
                 sizeof(conn->error_message),
                 "failed to allocate packet number: status=%d space=%d tx_ready=%u next_pn=%lu",
                 status,
                 (int)space,
                 conn->conn.spaces[space].tx_keys_ready,
                 (unsigned long)conn->conn.spaces[space].next_packet_number);
        return -1;
    }
    plan->packet_number_len = 4;
    return 0;
}

static enum ssl_encryption_level_t quic_tls_best_close_level(const quic_tls_conn_t *conn) {
    if (!conn) {
        return ssl_encryption_initial;
    }
    if (conn->conn.spaces[QUIC_PN_SPACE_APPLICATION].tx_keys_ready) {
        return ssl_encryption_application;
    }
    if (conn->conn.spaces[QUIC_PN_SPACE_HANDSHAKE].tx_keys_ready) {
        return ssl_encryption_handshake;
    }
    return ssl_encryption_initial;
}

static int quic_tls_encode_connection_close_transport(uint64_t error_code,
                                                      uint8_t *plaintext,
                                                      size_t plaintext_cap,
                                                      size_t *plaintext_len) {
    size_t offset = 0;

    if (!plaintext || !plaintext_len || plaintext_cap == 0) {
        return -1;
    }

    plaintext[offset++] = QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT;
    if (quic_tls_append_varint(error_code, plaintext, plaintext_cap, &offset) != 0 ||
        quic_tls_append_varint(0, plaintext, plaintext_cap, &offset) != 0 ||
        quic_tls_append_varint(0, plaintext, plaintext_cap, &offset) != 0) {
        return -1;
    }

    *plaintext_len = offset;
    return 0;
}

static int quic_tls_build_control_datagram_for_level(quic_tls_conn_t *conn,
                                                     enum ssl_encryption_level_t level,
                                                     const uint8_t *plaintext,
                                                     size_t plaintext_len,
                                                     uint8_t *out,
                                                     size_t out_len,
                                                     size_t *written) {
    quic_conn_tx_plan_t plan;
    quic_pn_space_id_t space = quic_tls_space_from_level(level);
    uint8_t header[256];
    size_t pn_offset;
    size_t header_len;
    size_t packet_len = 0;
    uint64_t length_field;
    quic_crypto_level_ctx_t *tx_ctx;
    const uint8_t *initial_token = NULL;
    size_t initial_token_len = 0;
    uint8_t logical_packet_type;

    if (!conn || !plaintext || !out || !written || space == QUIC_PN_SPACE_COUNT) {
        return quic_tls_fail(conn, "invalid control packet build arguments");
    }
    if (quic_tls_prepare_plan(conn, space, 0, &plan) != 0) {
        return -1;
    }

    if (level == ssl_encryption_application) {
        if (quic_tls_encode_short_header(&conn->peer_cid,
                                         plan.packet_number_len,
                                         plan.packet_number,
                                         header,
                                         sizeof(header),
                                         &pn_offset,
                                         &header_len) != 0) {
            return quic_tls_fail(conn, "failed to encode close short header");
        }
    } else {
        if (level == ssl_encryption_initial) {
            initial_token = conn->retry_token_len > 0 ? conn->retry_token : NULL;
            initial_token_len = conn->retry_token_len;
        }
        logical_packet_type = level == ssl_encryption_initial ? 0 :
                              (level == ssl_encryption_early_data ? 1 : 2);
        length_field = plan.packet_number_len + plaintext_len + QUIC_AEAD_TAG_LEN;
        if (quic_tls_encode_long_header(logical_packet_type,
                                        &conn->peer_cid,
                                        &conn->local_cid,
                                        conn->version,
                                        length_field,
                                        initial_token,
                                        initial_token_len,
                                        plan.packet_number_len,
                                        plan.packet_number,
                                        header,
                                        sizeof(header),
                                        &pn_offset,
                                        &header_len) != 0) {
            return quic_tls_fail(conn, "failed to encode close long header");
        }
    }

    tx_ctx = &conn->conn.spaces[space].tx_crypto;
    if (quic_packet_protect(tx_ctx,
                            plan.packet_number,
                            header,
                            header_len,
                            pn_offset,
                            plaintext,
                            plaintext_len,
                            out,
                            out_len,
                            &packet_len) != 0) {
        return quic_tls_fail(conn, "failed to protect close packet");
    }

    *written = packet_len;
    return 0;
}

static int quic_tls_prepare_connection_close(quic_tls_conn_t *conn,
                                             uint64_t error_code,
                                             int enter_draining_after_send) {
    enum ssl_encryption_level_t level;
    uint8_t plaintext[32];
    size_t plaintext_len = 0;
    size_t written = 0;

    if (!conn) {
        return quic_tls_fail(conn, "invalid close arguments");
    }
    if (conn->conn.state == QUIC_CONN_STATE_CLOSED) {
        return 0;
    }

    level = quic_tls_best_close_level(conn);
    if (!conn->conn.spaces[quic_tls_space_from_level(level)].tx_keys_ready) {
        return quic_tls_fail(conn, "connection close keys unavailable");
    }
    if (!conn->peer_cid_known || conn->peer_cid.len == 0) {
        return quic_tls_fail(conn, "connection close peer cid unavailable");
    }
    if (quic_tls_encode_connection_close_transport(error_code,
                                                   plaintext,
                                                   sizeof(plaintext),
                                                   &plaintext_len) != 0) {
        return quic_tls_fail(conn, "failed to encode connection close frame");
    }
    if (quic_tls_build_control_datagram_for_level(conn,
                                                  level,
                                                  plaintext,
                                                  plaintext_len,
                                                  conn->close_packet,
                                                  sizeof(conn->close_packet),
                                                  &written) != 0) {
        return -1;
    }

    conn->close_packet_len = written;
    conn->close_pending = 1;
    conn->close_sent = 0;
    conn->close_enter_draining_after_send = enter_draining_after_send ? 1 : 0;
    conn->conn.state = QUIC_CONN_STATE_CLOSING;
    if (conn->close_deadline_ms == 0) {
        conn->close_deadline_ms = quic_tls_now_ms() + QUIC_TLS_CLOSE_TIMEOUT_MS;
    }
    quic_tls_arm_loss_timer(conn);
    return 0;
}

static int quic_tls_append_ack_frame(quic_tls_conn_t *conn,
                                     enum ssl_encryption_level_t level,
                                     uint8_t *plaintext,
                                     size_t plaintext_cap,
                                     size_t *plaintext_len,
                                     int *included_ack) {
    quic_ack_frame_t ack;
    quic_pn_space_id_t space;
    size_t written = 0;

    if (!conn || !plaintext || !plaintext_len || !included_ack) {
        return quic_tls_fail(conn, "invalid ack frame arguments");
    }

    *included_ack = 0;
    if (!conn->levels[level].ack_pending) {
        return 0;
    }

    space = quic_tls_space_from_level(level);
    if (space == QUIC_PN_SPACE_COUNT) {
        return quic_tls_fail(conn, "invalid ack level");
    }
    if (quic_ack_frame_from_ranges(conn->conn.spaces[space].ack_ranges,
                                   conn->conn.spaces[space].ack_range_count,
                                   &ack) != 0) {
        return quic_tls_fail(conn, "failed to build ack ranges");
    }

    if (quic_ack_encode_frame(&ack, plaintext + *plaintext_len, plaintext_cap - *plaintext_len, &written) != 0) {
        return quic_tls_fail(conn, "failed to encode ack frame");
    }

    *plaintext_len += written;
    *included_ack = 1;
    return 0;
}

static int quic_tls_append_crypto_frame(quic_tls_conn_t *conn,
                                        enum ssl_encryption_level_t level,
                                        uint8_t *plaintext,
                                        size_t plaintext_cap,
                                        size_t *plaintext_len,
                                        size_t *crypto_data_len) {
    quic_crypto_sendbuf_t *send = &conn->levels[level].send;
    size_t available = send->flight_end - send->send_offset;
    size_t chunk = available > QUIC_TLS_MAX_CRYPTO_CHUNK ? QUIC_TLS_MAX_CRYPTO_CHUNK : available;
    int rc;
    size_t frame_header_len;

    if (!plaintext || !plaintext_len || !crypto_data_len) {
        return quic_tls_fail(conn, "invalid crypto payload arguments");
    }
    if (available == 0) {
        *crypto_data_len = 0;
        return 0;
    }

    while (chunk > 0) {
        frame_header_len = 1 + quic_tls_varint_len(send->send_offset) + quic_tls_varint_len(chunk);
        if (*plaintext_len + frame_header_len + chunk <= plaintext_cap) {
            break;
        }
        chunk--;
    }
    if (chunk == 0) {
        return quic_tls_fail(conn, "crypto frame does not fit into packet");
    }

    plaintext[(*plaintext_len)++] = QUIC_FRAME_CRYPTO;

    rc = quic_encode_varint(send->send_offset, plaintext + *plaintext_len, plaintext_cap - *plaintext_len);
    if (rc < 0) {
        return quic_tls_fail(conn, "failed to encode crypto offset");
    }
    *plaintext_len += (size_t)rc;

    rc = quic_encode_varint(chunk, plaintext + *plaintext_len, plaintext_cap - *plaintext_len);
    if (rc < 0) {
        return quic_tls_fail(conn, "failed to encode crypto length");
    }
    *plaintext_len += (size_t)rc;

    memcpy(plaintext + *plaintext_len, send->data + send->send_offset, chunk);
    *plaintext_len += chunk;
    *crypto_data_len = chunk;
    return 0;
}

static int quic_tls_append_stream_control_frames(quic_tls_conn_t *conn,
                                                 uint8_t *plaintext,
                                                 size_t plaintext_cap,
                                                 size_t *plaintext_len,
                                                 int *ack_eliciting,
                                                 quic_sent_packet_meta_t *packet_meta) {
    size_t i;

    if (!conn || !plaintext || !plaintext_len || !ack_eliciting || !packet_meta) {
        return quic_tls_fail(conn, "invalid stream control frame arguments");
    }

    if (conn->streams.max_data_pending) {
        if (*plaintext_len + 1 + quic_tls_varint_len(conn->streams.max_data_to_send) > plaintext_cap) {
            return quic_tls_fail(conn, "max_data does not fit");
        }
        plaintext[(*plaintext_len)++] = QUIC_FRAME_MAX_DATA;
        if (quic_tls_append_varint(conn->streams.max_data_to_send, plaintext, plaintext_cap, plaintext_len) != 0) {
            return quic_tls_fail(conn, "failed to encode max_data");
        }
        conn->streams.max_data_pending = 0;
        conn->streams.max_data_in_flight = 1;
        packet_meta->includes_max_data = 1;
        *ack_eliciting = 1;
    }

    if (conn->streams.max_streams_bidi_pending) {
        if (*plaintext_len + 1 + quic_tls_varint_len(conn->streams.max_streams_bidi_to_send) > plaintext_cap) {
            return quic_tls_fail(conn, "max_streams_bidi does not fit");
        }
        plaintext[(*plaintext_len)++] = QUIC_FRAME_MAX_STREAMS_BIDI;
        if (quic_tls_append_varint(conn->streams.max_streams_bidi_to_send, plaintext, plaintext_cap, plaintext_len) != 0) {
            return quic_tls_fail(conn, "failed to encode max_streams_bidi");
        }
        conn->streams.max_streams_bidi_pending = 0;
        conn->streams.max_streams_bidi_in_flight = 1;
        packet_meta->includes_max_streams_bidi = 1;
        *ack_eliciting = 1;
    }

    if (conn->streams.max_streams_uni_pending) {
        if (*plaintext_len + 1 + quic_tls_varint_len(conn->streams.max_streams_uni_to_send) > plaintext_cap) {
            return quic_tls_fail(conn, "max_streams_uni does not fit");
        }
        plaintext[(*plaintext_len)++] = QUIC_FRAME_MAX_STREAMS_UNI;
        if (quic_tls_append_varint(conn->streams.max_streams_uni_to_send, plaintext, plaintext_cap, plaintext_len) != 0) {
            return quic_tls_fail(conn, "failed to encode max_streams_uni");
        }
        conn->streams.max_streams_uni_pending = 0;
        conn->streams.max_streams_uni_in_flight = 1;
        packet_meta->includes_max_streams_uni = 1;
        *ack_eliciting = 1;
    }

    for (i = 0; i < QUIC_STREAM_MAX_COUNT; i++) {
        quic_stream_t *stream = &conn->streams.streams[i];

        if (!stream->active) {
            continue;
        }

        if (stream->stop_sending_pending) {
            size_t needed = 1 + quic_tls_varint_len(stream->id) + quic_tls_varint_len(stream->stop_error_code);

            if (*plaintext_len + needed > plaintext_cap) {
                break;
            }
            plaintext[(*plaintext_len)++] = QUIC_FRAME_STOP_SENDING;
            if (quic_tls_append_varint(stream->id, plaintext, plaintext_cap, plaintext_len) != 0 ||
                quic_tls_append_varint(stream->stop_error_code, plaintext, plaintext_cap, plaintext_len) != 0) {
                return quic_tls_fail(conn, "failed to encode stop_sending");
            }
            stream->stop_sending_pending = 0;
            stream->stop_sending_in_flight = 1;
            packet_meta->includes_stop_sending = 1;
            packet_meta->control_stream_id = stream->id;
            *ack_eliciting = 1;
            break;
        }

        if (stream->reset_pending) {
            uint64_t final_size = stream->send_final_size_known ? stream->send_final_size : stream->send_highest_offset;
            size_t needed = 1 + quic_tls_varint_len(stream->id) +
                            quic_tls_varint_len(stream->reset_error_code) +
                            quic_tls_varint_len(final_size);

            if (*plaintext_len + needed > plaintext_cap) {
                break;
            }
            plaintext[(*plaintext_len)++] = QUIC_FRAME_RESET_STREAM;
            if (quic_tls_append_varint(stream->id, plaintext, plaintext_cap, plaintext_len) != 0 ||
                quic_tls_append_varint(stream->reset_error_code, plaintext, plaintext_cap, plaintext_len) != 0 ||
                quic_tls_append_varint(final_size, plaintext, plaintext_cap, plaintext_len) != 0) {
                return quic_tls_fail(conn, "failed to encode reset_stream");
            }
            stream->reset_pending = 0;
            stream->reset_in_flight = 1;
            packet_meta->includes_reset_stream = 1;
            packet_meta->control_stream_id = stream->id;
            *ack_eliciting = 1;
            break;
        }

        if (stream->max_stream_data_pending) {
            size_t needed = 1 + quic_tls_varint_len(stream->id) +
                            quic_tls_varint_len(stream->max_stream_data_to_send);

            if (*plaintext_len + needed > plaintext_cap) {
                break;
            }
            plaintext[(*plaintext_len)++] = QUIC_FRAME_MAX_STREAM_DATA;
            if (quic_tls_append_varint(stream->id, plaintext, plaintext_cap, plaintext_len) != 0 ||
                quic_tls_append_varint(stream->max_stream_data_to_send, plaintext, plaintext_cap, plaintext_len) != 0) {
                return quic_tls_fail(conn, "failed to encode max_stream_data");
            }
            stream->max_stream_data_pending = 0;
            stream->max_stream_data_in_flight = 1;
            packet_meta->includes_max_stream_data = 1;
            packet_meta->control_stream_id = stream->id;
            *ack_eliciting = 1;
            break;
        }
    }

    return 0;
}

static int quic_tls_append_stream_frame(quic_tls_conn_t *conn,
                                        uint8_t *plaintext,
                                        size_t plaintext_cap,
                                        size_t *plaintext_len,
                                        int *ack_eliciting,
                                        quic_sent_packet_meta_t *packet_meta) {
    quic_stream_t *stream = NULL;
    uint64_t selected_offset = 0;
    size_t data_len = 0;
    int fin_only = 0;
    int is_retransmit = 0;
    int fin = 0;
    uint64_t offset;
    size_t original_len;
    size_t packet_payload_cap;

    if (!conn || !plaintext || !plaintext_len || !ack_eliciting || !packet_meta) {
        return quic_tls_fail(conn, "invalid stream frame arguments");
    }
    if (quic_stream_map_prepare_stream_send(&conn->streams,
                                            &stream,
                                            &selected_offset,
                                            &data_len,
                                            &fin_only,
                                            &is_retransmit) < 0) {
        return quic_tls_fail(conn, "failed to select stream payload");
    }
    if (!stream) {
        return 0;
    }

    offset = selected_offset;
    original_len = data_len;
    packet_payload_cap = plaintext_cap > QUIC_TLS_STREAM_PACKET_RESERVE
                             ? plaintext_cap - QUIC_TLS_STREAM_PACKET_RESERVE
                             : 0;
    if (fin_only) {
        fin = 1;
    } else if (stream->fin_requested &&
               !stream->fin_sent &&
               offset + data_len == stream->sendbuf.len) {
        fin = 1;
    }

    for (;;) {
        size_t needed = 1 + quic_tls_varint_len(stream->id) +
                        quic_tls_varint_len(offset) +
                        quic_tls_varint_len(data_len) +
                        data_len;

        if (*plaintext_len + needed <= packet_payload_cap) {
            break;
        }
        if (data_len == 0) {
            return quic_tls_fail(conn, "stream frame does not fit");
        }
        data_len--;
        fin = 0;
    }

    plaintext[(*plaintext_len)++] = (uint8_t)(0x08 | 0x04 | 0x02 | (fin ? 0x01 : 0x00));
    if (quic_tls_append_varint(stream->id, plaintext, plaintext_cap, plaintext_len) != 0 ||
        quic_tls_append_varint(offset, plaintext, plaintext_cap, plaintext_len) != 0 ||
        quic_tls_append_varint(data_len, plaintext, plaintext_cap, plaintext_len) != 0) {
        return quic_tls_fail(conn, "failed to encode stream frame");
    }
    if (data_len > 0) {
        memcpy(plaintext + *plaintext_len, stream->sendbuf.data + offset, data_len);
        *plaintext_len += data_len;
    }

    quic_stream_map_note_stream_send(&conn->streams, stream, offset, data_len, fin, is_retransmit);
    if (data_len == 0 && !fin && original_len > 0) {
        return quic_tls_fail(conn, "stream frame lost all payload");
    }
    packet_meta->includes_stream = 1;
    packet_meta->stream_id = stream->id;
    packet_meta->stream_offset = offset;
    packet_meta->stream_length = data_len;
    packet_meta->stream_fin = (uint8_t)(fin ? 1 : 0);
    *ack_eliciting = 1;
    return 0;
}

static int quic_tls_build_payload_for_level(quic_tls_conn_t *conn,
                                            enum ssl_encryption_level_t level,
                                            uint8_t *plaintext,
                                            size_t plaintext_cap,
                                            size_t *plaintext_len,
                                            size_t *crypto_data_len,
                                            int *includes_ack,
                                            int *includes_handshake_done,
                                            int *includes_ping,
                                            int *ack_eliciting,
                                            quic_sent_packet_meta_t *packet_meta) {
    size_t offset = 0;

    if (!conn || !plaintext || !plaintext_len || !crypto_data_len || !includes_ack ||
        !includes_handshake_done || !includes_ping || !ack_eliciting || !packet_meta) {
        return quic_tls_fail(conn, "invalid payload arguments");
    }

    *crypto_data_len = 0;
    *includes_ack = 0;
    *includes_handshake_done = 0;
    *includes_ping = 0;
    *ack_eliciting = 0;

    if (quic_tls_append_ack_frame(conn, level, plaintext, plaintext_cap, &offset, includes_ack) != 0) {
        return -1;
    }

    if (level != ssl_encryption_early_data &&
        quic_crypto_sendbuf_has_pending(&conn->levels[level].send)) {
        if (quic_tls_append_crypto_frame(conn, level, plaintext, plaintext_cap, &offset, crypto_data_len) != 0) {
            return -1;
        }
        if (*crypto_data_len > 0) {
            *ack_eliciting = 1;
        }
    }

    if (level == ssl_encryption_application && conn->handshake_done_pending) {
        if (offset + 1 > plaintext_cap) {
            return quic_tls_fail(conn, "handshake_done does not fit");
        }
        plaintext[offset++] = QUIC_FRAME_HANDSHAKE_DONE;
        packet_meta->includes_handshake_done = 1;
        *includes_handshake_done = 1;
        *ack_eliciting = 1;
    }

    if (conn->ping_pending) {
        if (offset + 1 > plaintext_cap) {
            return quic_tls_fail(conn, "ping does not fit");
        }
        plaintext[offset++] = QUIC_FRAME_PING;
        packet_meta->includes_ping = 1;
        *includes_ping = 1;
        *ack_eliciting = 1;
    }

    if (level == ssl_encryption_application) {
        if (quic_tls_append_stream_control_frames(conn,
                                                  plaintext,
                                                  plaintext_cap,
                                                  &offset,
                                                  ack_eliciting,
                                                  packet_meta) != 0) {
            return -1;
        }
        if (quic_tls_append_stream_frame(conn,
                                         plaintext,
                                         plaintext_cap,
                                         &offset,
                                         ack_eliciting,
                                         packet_meta) != 0) {
            return -1;
        }
    }

    if (offset == 0) {
        return quic_tls_fail(conn, "no payload queued");
    }

    *plaintext_len = offset;
    return 0;
}

static int quic_tls_build_datagram_for_level(quic_tls_conn_t *conn,
                                             enum ssl_encryption_level_t level,
                                             uint8_t *out,
                                             size_t out_len,
                                             size_t *written) {
    quic_conn_tx_plan_t plan;
    quic_pn_space_id_t space = quic_tls_space_from_level(level);
    uint8_t header[256];
    uint8_t plaintext[QUIC_TLS_MAX_DATAGRAM_SIZE];
    size_t pn_offset;
    size_t header_len;
    size_t plaintext_len = 0;
    size_t packet_len = 0;
    size_t crypto_data_len = 0;
    uint64_t length_field;
    size_t target_total_len = 0;
    quic_crypto_level_ctx_t *tx_ctx;
    int includes_ack = 0;
    int includes_handshake_done = 0;
    int includes_ping = 0;
    int ack_eliciting = 0;
    int app_limited_after_send = 0;
    int flow_control_limited_after_send = 0;
    const uint8_t *initial_token = NULL;
    size_t initial_token_len = 0;
    uint8_t logical_packet_type;
    quic_sent_packet_meta_t packet_meta;
    quic_tls_app_send_snapshot_t app_snapshot;
    int has_app_snapshot = 0;

    memset(&packet_meta, 0, sizeof(packet_meta));

    if (!conn || !out || !written || space == QUIC_PN_SPACE_COUNT) {
        return quic_tls_fail(conn, "invalid datagram build arguments");
    }

    if (level == ssl_encryption_application) {
        // RFC 9002 Appendix A applies OnPacketSent only once a packet is
        // actually sent. If build is blocked later by cwnd or amplification,
        // any STREAM/control send-state staged during payload assembly must
        // be rolled back.
        quic_tls_snapshot_application_send_state(conn, &app_snapshot);
        has_app_snapshot = 1;
    }

    if (quic_tls_build_payload_for_level(conn,
                                         level,
                                         plaintext,
                                         sizeof(plaintext),
                                         &plaintext_len,
                                         &crypto_data_len,
                                         &includes_ack,
                                         &includes_handshake_done,
                                         &includes_ping,
                                         &ack_eliciting,
                                         &packet_meta) != 0) {
        if (has_app_snapshot) {
            quic_tls_restore_application_send_state(conn, &app_snapshot);
        }
        return -1;
    }

    if (quic_tls_prepare_plan(conn, space, ack_eliciting ? 1 : 0, &plan) != 0) {
        if (has_app_snapshot) {
            quic_tls_restore_application_send_state(conn, &app_snapshot);
        }
        return -1;
    }

    if (level == ssl_encryption_application) {
        if (quic_tls_encode_short_header(&conn->peer_cid,
                                         plan.packet_number_len,
                                         plan.packet_number,
                                         header,
                                         sizeof(header),
                                         &pn_offset,
                                         &header_len) != 0) {
            if (has_app_snapshot) {
                quic_tls_restore_application_send_state(conn, &app_snapshot);
            }
            return quic_tls_fail(conn, "failed to encode short header");
        }
    } else {
        target_total_len = 0;
        if (level == ssl_encryption_initial) {
            initial_token = conn->retry_token_len > 0 ? conn->retry_token : NULL;
            initial_token_len = conn->retry_token_len;
        }
        if (level == ssl_encryption_initial && conn->role == QUIC_ROLE_CLIENT && plan.packet_number == 0) {
            target_total_len = 1200;
        }

        for (;;) {
            size_t token_varint_len = level == ssl_encryption_initial ? quic_tls_varint_len(initial_token_len) : 0;
            size_t fixed_header_len = 1 + 4 + 1 + conn->peer_cid.len + 1 + conn->local_cid.len +
                                      (level == ssl_encryption_initial ? token_varint_len + initial_token_len : 0) +
                                      quic_tls_varint_len(plan.packet_number_len + plaintext_len + QUIC_AEAD_TAG_LEN) +
                                      plan.packet_number_len;
            size_t total_len = fixed_header_len + plaintext_len + QUIC_AEAD_TAG_LEN;

            if (target_total_len == 0 || total_len >= target_total_len) {
                break;
            }
            if (plaintext_len >= sizeof(plaintext)) {
                return quic_tls_fail(conn, "initial packet padding overflow");
            }
            plaintext[plaintext_len++] = QUIC_FRAME_PADDING;
        }

        logical_packet_type = level == ssl_encryption_initial ? 0 :
                              (level == ssl_encryption_early_data ? 1 : 2);
        length_field = plan.packet_number_len + plaintext_len + QUIC_AEAD_TAG_LEN;
        if (quic_tls_encode_long_header(logical_packet_type,
                                        &conn->peer_cid,
                                        &conn->local_cid,
                                        conn->version,
                                        length_field,
                                        initial_token,
                                        initial_token_len,
                                        plan.packet_number_len,
                                        plan.packet_number,
                                        header,
                                        sizeof(header),
                                        &pn_offset,
                                        &header_len) != 0) {
            if (has_app_snapshot) {
                quic_tls_restore_application_send_state(conn, &app_snapshot);
            }
            return quic_tls_fail(conn, "failed to encode long header");
        }
    }

    tx_ctx = &conn->conn.spaces[space].tx_crypto;
    if (quic_packet_protect(tx_ctx,
                            plan.packet_number,
                            header,
                            header_len,
                            pn_offset,
                            plaintext,
                            plaintext_len,
                            out,
                            out_len,
                            &packet_len) != 0) {
        if (has_app_snapshot) {
            quic_tls_restore_application_send_state(conn, &app_snapshot);
        }
        return quic_tls_fail(conn, "failed to protect packet");
    }

    if (quic_tls_server_amplification_limited(conn, packet_len)) {
        if (has_app_snapshot) {
            quic_tls_restore_application_send_state(conn, &app_snapshot);
        }
        return quic_tls_build_blocked(conn, written);
    }
    quic_tls_sync_recovery_state(conn);
    if (ack_eliciting && !quic_recovery_can_send(&conn->conn.recovery, packet_len)) {
        if (has_app_snapshot) {
            quic_tls_restore_application_send_state(conn, &app_snapshot);
        }
        if (written) {
            *written = 0;
        }
        return QUIC_TLS_BUILD_BLOCKED;
    }

    if (crypto_data_len > 0) {
        quic_crypto_sendbuf_advance(&conn->levels[level].send, crypto_data_len);
        packet_meta.includes_crypto = 1;
    }
    if (includes_ack) {
        conn->levels[level].ack_pending = 0;
    }
    if (level == ssl_encryption_application || level == ssl_encryption_early_data) {
        if (includes_handshake_done) {
            conn->handshake_done_pending = 0;
            conn->handshake_done_in_flight = 1;
        }
        if (includes_ping) {
            conn->ping_pending = 0;
            conn->ping_in_flight = 1;
        }
    }

    if (ack_eliciting) {
        app_limited_after_send = quic_tls_has_ack_eliciting_buffered_data(conn) ? 0 : 1;
        flow_control_limited_after_send = quic_tls_is_flow_control_limited(conn);
        quic_recovery_on_packet_sent(&conn->conn.recovery,
                                     &conn->conn.spaces[space].in_flight,
                                     plan.packet_number,
                                     (uint8_t)space,
                                     packet_len,
                                     1,
                                     1,
                                     packet_meta.includes_crypto,
                                     0,
                                     app_limited_after_send,
                                     flow_control_limited_after_send,
                                     quic_tls_now_ms(),
                                     &packet_meta);
    }

    *written = packet_len;
    quic_tls_note_packet_sent(conn, packet_len);
    quic_tls_arm_loss_timer(conn);
    return 0;
}

void quic_tls_conn_init(quic_tls_conn_t *conn) {
    size_t i;

    if (!conn) {
        return;
    }

    memset(conn, 0, sizeof(*conn));
    quic_conn_init(&conn->conn);
    quic_recovery_init(&conn->conn.recovery, QUIC_TLS_MAX_DATAGRAM_SIZE);
    quic_stream_map_init(&conn->streams, 1);
    conn->initial_max_data = 65536;
    conn->initial_max_stream_data_bidi_local = 16384;
    conn->initial_max_stream_data_bidi_remote = 16384;
    conn->initial_max_stream_data_uni = 16384;
    conn->initial_max_streams_bidi = 4;
    conn->initial_max_streams_uni = 4;
    for (i = 0; i <= ssl_encryption_application; i++) {
        quic_crypto_recvbuf_init(&conn->levels[i].recv);
        quic_crypto_sendbuf_init(&conn->levels[i].send);
    }
    quic_tls_set_error(conn, "ok");
}

void quic_tls_conn_free(quic_tls_conn_t *conn) {
    size_t i;

    if (!conn) {
        return;
    }

    if (conn->ssl) {
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    if (conn->ssl_ctx) {
        SSL_CTX_free(conn->ssl_ctx);
        conn->ssl_ctx = NULL;
    }
    for (i = 0; i <= ssl_encryption_application; i++) {
        quic_crypto_recvbuf_free(&conn->levels[i].recv);
        quic_crypto_sendbuf_free(&conn->levels[i].send);
    }
    quic_stream_map_free(&conn->streams);
    for (i = 0; i < QUIC_PN_SPACE_COUNT; i++) {
        quic_queue_clear(&conn->conn.spaces[i].in_flight);
    }
}

int quic_tls_conn_configure(quic_tls_conn_t *conn,
                            quic_role_t role,
                            uint32_t version,
                            const quic_cid_t *local_cid,
                            const quic_cid_t *peer_cid,
                            const char *cert_file,
                            const char *key_file) {
    if (!conn || !local_cid || !local_cid->len) {
        return quic_tls_fail(conn, "invalid quic tls configuration");
    }

    conn->role = role;
    conn->version = version;
    conn->version_ops = quic_version_get_ops(version);
    if (!conn->version_ops) {
        return quic_tls_fail(conn, "unsupported quic version");
    }
    conn->local_cid = *local_cid;
    quic_stream_map_free(&conn->streams);
    quic_stream_map_init(&conn->streams, role == QUIC_ROLE_CLIENT);

    if (peer_cid) {
        conn->peer_cid = *peer_cid;
        conn->peer_cid_known = 1;
    }

    conn->ssl_ctx = SSL_CTX_new(TLS_method());
    if (!conn->ssl_ctx) {
        return quic_tls_fail_ssl(conn, "failed to create ssl ctx");
    }
    if (SSL_CTX_set_min_proto_version(conn->ssl_ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(conn->ssl_ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_strict_cipher_list(conn->ssl_ctx, "ALL") != 1) {
        return quic_tls_fail_ssl(conn, "failed to configure tls version or cipher");
    }
    SSL_CTX_set_verify(conn->ssl_ctx, SSL_VERIFY_NONE, NULL);
    if (role == QUIC_ROLE_SERVER) {
        SSL_CTX_set_alpn_select_cb(conn->ssl_ctx, quic_tls_server_alpn_cb, NULL);
    }
    if (role == QUIC_ROLE_SERVER) {
        if (!cert_file || !key_file) {
            return quic_tls_fail(conn, "server certificate or key missing");
        }
        if (SSL_CTX_use_certificate_chain_file(conn->ssl_ctx, cert_file) != 1 ||
            SSL_CTX_use_PrivateKey_file(conn->ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
            return quic_tls_fail_ssl(conn, "failed to load server certificate");
        }
        SSL_CTX_set_num_tickets(conn->ssl_ctx, 0);
    }

    conn->ssl = SSL_new(conn->ssl_ctx);
    if (!conn->ssl) {
        return quic_tls_fail_ssl(conn, "failed to create ssl object");
    }
    SSL_CTX_set_early_data_enabled(conn->ssl_ctx, 1);
    SSL_set_early_data_enabled(conn->ssl, 1);
    if (SSL_set_quic_method(conn->ssl, &quic_tls_quic_method) != 1) {
        return quic_tls_fail_ssl(conn, "failed to install quic method");
    }
    SSL_set_app_data(conn->ssl, conn);
    if (role == QUIC_ROLE_CLIENT &&
        SSL_set_alpn_protos(conn->ssl, quic_tls_alpn, sizeof(quic_tls_alpn)) != 0) {
        return quic_tls_fail_ssl(conn, "failed to configure alpn");
    }

    if (role == QUIC_ROLE_CLIENT) {
        SSL_set_connect_state(conn->ssl);
        if (!peer_cid || !peer_cid->len) {
            return quic_tls_fail(conn, "client original dcid missing");
        }
        conn->original_dcid = *peer_cid;
        conn->original_dcid_known = 1;
        conn->initial_dcid = *peer_cid;
        conn->initial_dcid_known = 1;
        conn->peer_address_validated = 1;
        conn->amplification_blocked = 0;
        if (quic_tls_install_initial_keys(conn) != 0) {
            return -1;
        }
        if (quic_tls_set_transport_params(conn) != 0) {
            return -1;
        }
    } else {
        SSL_set_accept_state(conn->ssl);
    }

    return 0;
}

static int quic_tls_build_version_negotiation_packet(quic_tls_conn_t *conn,
                                                     const quic_pkt_header_meta_t *meta) {
    uint8_t packet[QUIC_TLS_MAX_DATAGRAM_SIZE];
    int packet_len;

    if (!conn || !meta) {
        return quic_tls_fail(conn, "invalid version negotiation arguments");
    }

    packet_len = quic_generate_version_negotiation(meta, packet, sizeof(packet));
    if (packet_len < 0) {
        return quic_tls_fail(conn, "failed to generate version negotiation packet");
    }
    return quic_tls_queue_special_packet(conn, packet, (size_t)packet_len);
}

static int quic_tls_build_retry_packet(quic_tls_conn_t *conn, const quic_pkt_header_meta_t *meta) {
    uint8_t packet[QUIC_TLS_MAX_DATAGRAM_SIZE];
    uint8_t token[QUIC_TLS_MAX_RETRY_TOKEN];
    uint8_t tag[QUIC_RETRY_INTEGRITY_TAG_LEN];
    uint8_t encoded_type;
    size_t token_len = 0;
    size_t offset = 0;

    if (!conn || !meta || !conn->version_ops || !conn->version_ops->encode_packet_type) {
        return quic_tls_fail(conn, "invalid retry build arguments");
    }
    if (quic_tls_build_retry_token(&conn->original_dcid, token, sizeof(token), &token_len) != 0) {
        return quic_tls_fail(conn, "failed to build retry token");
    }

    encoded_type = conn->version_ops->encode_packet_type(3);
    packet[offset++] = (uint8_t)(0xf0 | ((encoded_type & 0x03) << 4));
    packet[offset++] = (uint8_t)(conn->version >> 24);
    packet[offset++] = (uint8_t)(conn->version >> 16);
    packet[offset++] = (uint8_t)(conn->version >> 8);
    packet[offset++] = (uint8_t)conn->version;
    packet[offset++] = meta->src_cid.len;
    memcpy(packet + offset, meta->src_cid.data, meta->src_cid.len);
    offset += meta->src_cid.len;
    packet[offset++] = conn->local_cid.len;
    memcpy(packet + offset, conn->local_cid.data, conn->local_cid.len);
    offset += conn->local_cid.len;
    memcpy(packet + offset, token, token_len);
    offset += token_len;

    if (quic_retry_compute_integrity_tag(conn->version, &conn->original_dcid, packet, offset, tag) != 0) {
        return quic_tls_fail(conn, "failed to compute retry integrity tag");
    }
    memcpy(packet + offset, tag, sizeof(tag));
    offset += sizeof(tag);

    return quic_tls_queue_special_packet(conn, packet, offset);
}

static int quic_tls_client_handle_retry(quic_tls_conn_t *conn,
                                        const quic_tls_packet_header_t *header,
                                        const uint8_t *packet,
                                        size_t packet_len) {
    if (!conn || !header || !packet) {
        return quic_tls_fail(conn, "invalid retry handling arguments");
    }
    if (conn->role != QUIC_ROLE_CLIENT) {
        return 0;
    }
    if (conn->retry_processed) {
        return quic_tls_fail(conn, "duplicate retry received");
    }
    if (quic_retry_verify_integrity_tag(conn->version, &conn->original_dcid, packet, packet_len) != 0) {
        return quic_tls_fail(conn, "retry integrity verification failed");
    }
    if (header->token_length > sizeof(conn->retry_token)) {
        return quic_tls_fail(conn, "retry token too large");
    }

    memcpy(conn->retry_token, packet + header->token_offset, header->token_length);
    conn->retry_token_len = header->token_length;
    conn->peer_cid = header->meta.src_cid;
    conn->peer_cid_known = 1;
    conn->initial_dcid = header->meta.src_cid;
    conn->initial_dcid_known = 1;
    conn->retry_processed = 1;
    quic_tls_reset_initial_stream_state(conn);
    if (quic_tls_install_initial_keys(conn) != 0) {
        return -1;
    }
    return 0;
}

static int quic_tls_server_prepare_initial_context(quic_tls_conn_t *conn,
                                                   const quic_tls_packet_header_t *header) {
    if (!conn || !header) {
        return quic_tls_fail(conn, "invalid initial context arguments");
    }

    conn->peer_cid = header->meta.src_cid;
    conn->peer_cid_known = 1;

    if (!conn->original_dcid_known) {
        conn->original_dcid = header->meta.dest_cid;
        conn->original_dcid_known = 1;
    }

    if (!conn->initial_dcid_known) {
        quic_tls_reset_initial_stream_state(conn);
        conn->initial_dcid = header->meta.dest_cid;
        conn->initial_dcid_known = 1;
    }

    if (quic_tls_install_initial_keys(conn) != 0) {
        return -1;
    }
    if (!conn->transport_params_set && quic_tls_set_transport_params(conn) != 0) {
        return -1;
    }
    return 0;
}

static int quic_tls_server_maybe_require_retry(quic_tls_conn_t *conn,
                                               const quic_tls_packet_header_t *header,
                                               const uint8_t *packet) {
    const uint8_t *token;

    if (!conn || !header || conn->role != QUIC_ROLE_SERVER || !conn->retry_required || header->packet_type != 0) {
        return 0;
    }

    token = header->token_length > 0 ? packet + header->token_offset : NULL;
    if (header->token_length > 0 &&
        conn->original_dcid_known &&
        quic_tls_validate_retry_token(token, header->token_length, &conn->original_dcid)) {
        conn->peer_address_validated = 1;
        conn->amplification_blocked = 0;
        return 0;
    }

    if (!conn->original_dcid_known) {
        conn->original_dcid = header->meta.dest_cid;
        conn->original_dcid_known = 1;
    }
    conn->peer_cid = header->meta.src_cid;
    conn->peer_cid_known = 1;
    if (quic_tls_build_retry_packet(conn, &header->meta) != 0) {
        return -1;
    }
    return 1;
}

int quic_tls_conn_start(quic_tls_conn_t *conn) {
    if (!conn || conn->role != QUIC_ROLE_CLIENT) {
        return quic_tls_fail(conn, "only client may start handshake proactively");
    }
    return quic_tls_drive_handshake(conn);
}

int quic_tls_conn_handle_datagram(quic_tls_conn_t *conn, const uint8_t *packet, size_t packet_len) {
    quic_pkt_header_meta_t meta;
    quic_tls_packet_header_t header;
    uint8_t packet_copy[QUIC_TLS_MAX_DATAGRAM_SIZE];
    uint8_t plaintext[QUIC_TLS_MAX_DATAGRAM_SIZE];
    size_t header_len;
    size_t plaintext_len;
    uint64_t packet_number;
    quic_conn_pn_space_t *space;
    int fed_crypto = 0;
    int saw_ack_eliciting = 0;
    int received_connection_close = 0;

    if (!conn || !packet || packet_len == 0 || packet_len > sizeof(packet_copy)) {
        return quic_tls_fail(conn, "invalid datagram input");
    }
    if (conn->conn.state == QUIC_CONN_STATE_CLOSED) {
        return 0;
    }
    if (quic_parse_header_meta(packet, packet_len, &meta) != 0) {
        return quic_tls_fail(conn, "failed to parse datagram header");
    }
    quic_tls_note_packet_received(conn, packet_len);
    if (conn->conn.state == QUIC_CONN_STATE_DRAINING) {
        return 0;
    }

    if (meta.header_form == 1 && meta.version != 0 && quic_version_get_ops(meta.version) == NULL) {
        if (conn->role == QUIC_ROLE_SERVER) {
            return quic_tls_build_version_negotiation_packet(conn, &meta);
        }
        return quic_tls_fail(conn, "peer sent unsupported quic version");
    }

    memcpy(packet_copy, packet, packet_len);
    if (quic_tls_classify_packet(conn, packet_copy, packet_len, &header) != 0) {
        return -1;
    }

    if (header.kind == QUIC_TLS_PACKET_VERSION_NEGOTIATION) {
        if (conn->role == QUIC_ROLE_CLIENT) {
            conn->received_version_negotiation = 1;
            conn->conn.state = QUIC_CONN_STATE_CLOSED;
            return 0;
        }
        return quic_tls_fail(conn, "unexpected version negotiation packet");
    }

    if (header.kind == QUIC_TLS_PACKET_RETRY) {
        return quic_tls_client_handle_retry(conn, &header, packet, packet_len);
    }

    if (header.meta.header_form == 1) {
        if (conn->role == QUIC_ROLE_SERVER && header.space == QUIC_PN_SPACE_INITIAL) {
            int retry_status = quic_tls_server_maybe_require_retry(conn, &header, packet);

            if (retry_status < 0) {
                return -1;
            }
            if (retry_status > 0) {
                return 0;
            }
            if (quic_tls_server_prepare_initial_context(conn, &header) != 0) {
                return -1;
            }
        } else if (conn->role == QUIC_ROLE_CLIENT && header.meta.src_cid.len > 0) {
            conn->peer_cid = header.meta.src_cid;
            conn->peer_cid_known = 1;
        }
    }

    if (quic_tls_should_discard_without_processing(conn, &header)) {
        return 0;
    }

    space = &conn->conn.spaces[header.space];
    if (!space->rx_keys_ready) {
        if (header.level == ssl_encryption_early_data ||
            header.level == ssl_encryption_application) {
            return 0;
        }
        // RFC 9000 5.2.1 / RFC 9001 4.1.4: a client may drop
        // reordered Handshake packets until TLS provides the keys.
        if (conn->role == QUIC_ROLE_CLIENT && header.space == QUIC_PN_SPACE_HANDSHAKE) {
            return 0;
        }
        if ((header.space == QUIC_PN_SPACE_INITIAL && conn->initial_keys_discarded) ||
            (header.space == QUIC_PN_SPACE_HANDSHAKE && conn->handshake_keys_discarded) ||
            conn->levels[header.level].discarded) {
            return 0;
        }
        snprintf(conn->error_message,
                 sizeof(conn->error_message),
                 "receive keys unavailable for packet level: role=%d space=%d original_dcid_known=%u peer_cid_known=%u",
                 (int)conn->role,
                 (int)header.space,
                 conn->original_dcid_known,
                 conn->peer_cid_known);
        return -1;
    }

    if (quic_packet_unprotect(&space->rx_crypto,
                              space->largest_received_packet,
                              packet_copy,
                              packet_len,
                              header.pn_offset,
                              &packet_number,
                              &header_len,
                              plaintext,
                              sizeof(plaintext),
                              &plaintext_len) != 0) {
        return quic_tls_fail(conn, "failed to remove packet protection");
    }

    if (quic_ack_note_received(space->ack_ranges, &space->ack_range_count, packet_number) != 0) {
        return quic_tls_fail(conn, "failed to track received packet ranges");
    }
    if (packet_number > space->largest_received_packet) {
        space->largest_received_packet = packet_number;
    }
    space->last_received_packet = packet_number;
    conn->conn.last_recv_space = header.space;
    conn->conn.last_acked_packets = 0;

    if (quic_tls_parse_frames(conn,
                              header.level,
                              plaintext,
                              plaintext_len,
                              &fed_crypto,
                              &saw_ack_eliciting,
                              &received_connection_close) != 0) {
        return -1;
    }
    if (conn->conn.state == QUIC_CONN_STATE_CLOSING || conn->conn.state == QUIC_CONN_STATE_DRAINING) {
        if (conn->conn.state == QUIC_CONN_STATE_CLOSING && !received_connection_close) {
            conn->close_pending = 1;
        }
        quic_tls_arm_loss_timer(conn);
        return 0;
    }
    if (saw_ack_eliciting) {
        quic_tls_mark_ack_pending(conn, header.level);
    }

    if (header.space == QUIC_PN_SPACE_HANDSHAKE) {
        conn->received_handshake_packet = 1;
        if (conn->role == QUIC_ROLE_SERVER) {
            conn->peer_address_validated = 1;
            conn->amplification_blocked = 0;
        }
    }
    if (header.space == QUIC_PN_SPACE_APPLICATION && header.level == ssl_encryption_application &&
        conn->role == QUIC_ROLE_SERVER) {
        conn->peer_address_validated = 1;
        conn->amplification_blocked = 0;
    }

    if (fed_crypto) {
        if (!conn->handshake_complete) {
            if (quic_tls_drive_handshake(conn) != 0) {
                return -1;
            }
        } else if (header.level == ssl_encryption_application) {
            if (SSL_process_quic_post_handshake(conn->ssl) != 1) {
                return quic_tls_fail_ssl(conn, "failed to process post-handshake data");
            }
        }
    }

    if (conn->handshake_complete && quic_tls_update_peer_transport_params(conn) != 0) {
        return -1;
    }

    quic_tls_maybe_discard_keys(conn);
    quic_tls_arm_loss_timer(conn);
    return 0;
}

int quic_tls_conn_build_next_datagram(quic_tls_conn_t *conn, uint8_t *out, size_t out_len, size_t *written) {
    if (!conn || !out || !written) {
        return quic_tls_fail(conn, "invalid build_next_datagram arguments");
    }
    if (conn->conn.state == QUIC_CONN_STATE_DRAINING || conn->conn.state == QUIC_CONN_STATE_CLOSED) {
        return quic_tls_fail(conn, "connection is not allowed to send packets");
    }
    if (conn->role == QUIC_ROLE_SERVER &&
        conn->amplification_blocked &&
        !conn->peer_address_validated) {
        *written = 0;
        return QUIC_TLS_BUILD_BLOCKED;
    }
    if (conn->conn.state == QUIC_CONN_STATE_CLOSING) {
        if (!conn->close_pending || conn->close_packet_len == 0) {
            return quic_tls_fail(conn, "no connection close packet pending");
        }
        if (out_len < conn->close_packet_len) {
            return quic_tls_fail(conn, "connection close output buffer too small");
        }
        if (quic_tls_server_amplification_limited(conn, conn->close_packet_len)) {
            return quic_tls_build_blocked(conn, written);
        }
        memcpy(out, conn->close_packet, conn->close_packet_len);
        *written = conn->close_packet_len;
        conn->close_pending = 0;
        conn->close_sent = 1;
        if (conn->close_enter_draining_after_send) {
            quic_tls_enter_draining(conn, conn->close_deadline_ms);
        }
        quic_tls_note_packet_sent(conn, *written);
        quic_tls_arm_loss_timer(conn);
        return 0;
    }

    if (conn->special_packet_pending) {
        if (out_len < conn->special_packet_len) {
            return quic_tls_fail(conn, "special packet output buffer too small");
        }
        if (quic_tls_server_amplification_limited(conn, conn->special_packet_len)) {
            return quic_tls_build_blocked(conn, written);
        }
        memcpy(out, conn->special_packet, conn->special_packet_len);
        *written = conn->special_packet_len;
        conn->special_packet_pending = 0;
        conn->special_packet_len = 0;
        quic_tls_note_packet_sent(conn, *written);
        quic_tls_arm_loss_timer(conn);
        return 0;
    }

    if (quic_tls_level_has_sendable_output(conn, ssl_encryption_initial)) {
        return quic_tls_build_datagram_for_level(conn, ssl_encryption_initial, out, out_len, written);
    }
    if (quic_tls_level_has_sendable_output(conn, ssl_encryption_early_data) ||
        (conn->ping_pending && conn->levels[ssl_encryption_early_data].write_secret_ready &&
         !conn->handshake_complete)) {
        return quic_tls_build_datagram_for_level(conn, ssl_encryption_early_data, out, out_len, written);
    }
    if (quic_tls_level_has_sendable_output(conn, ssl_encryption_handshake)) {
        return quic_tls_build_datagram_for_level(conn, ssl_encryption_handshake, out, out_len, written);
    }
    if (quic_tls_level_has_sendable_output(conn, ssl_encryption_application) ||
        ((conn->handshake_done_pending || conn->ping_pending) &&
         conn->conn.spaces[QUIC_PN_SPACE_APPLICATION].tx_keys_ready)) {
        return quic_tls_build_datagram_for_level(conn, ssl_encryption_application, out, out_len, written);
    }

    return quic_tls_fail(conn, "no datagram pending");
}

int quic_tls_conn_has_pending_output(const quic_tls_conn_t *conn) {
    if (!conn) {
        return 0;
    }
    if (conn->conn.state == QUIC_CONN_STATE_DRAINING || conn->conn.state == QUIC_CONN_STATE_CLOSED) {
        return 0;
    }
    if (conn->conn.state == QUIC_CONN_STATE_CLOSING) {
        return conn->close_pending && conn->close_packet_len > 0;
    }
    return conn->special_packet_pending ||
           quic_tls_level_has_sendable_output(conn, ssl_encryption_initial) ||
           quic_tls_level_has_sendable_output(conn, ssl_encryption_early_data) ||
           (conn->ping_pending && conn->levels[ssl_encryption_early_data].write_secret_ready && !conn->handshake_complete) ||
           quic_tls_level_has_sendable_output(conn, ssl_encryption_handshake) ||
           quic_tls_level_has_sendable_output(conn, ssl_encryption_application) ||
           ((conn->handshake_done_pending || conn->ping_pending) &&
            conn->conn.spaces[QUIC_PN_SPACE_APPLICATION].tx_keys_ready);
}

void quic_tls_conn_on_loss_timeout(quic_tls_conn_t *conn, uint64_t now_ms) {
    quic_recovery_timer_t timer;
    quic_in_flight_queue_t *queues[QUIC_RECOVERY_PACKET_SPACE_COUNT];
    size_t lost_packets = 0;

    if (!conn) {
        return;
    }
    if (quic_tls_close_state_active(conn)) {
        if (conn->close_deadline_ms != 0 && now_ms >= conn->close_deadline_ms) {
            conn->conn.state = QUIC_CONN_STATE_CLOSED;
            conn->close_pending = 0;
            conn->close_enter_draining_after_send = 0;
            conn->close_deadline_ms = 0;
            quic_conn_disarm_timer(&conn->conn, QUIC_CONN_TIMER_LOSS_DETECTION);
        } else {
            quic_tls_arm_loss_timer(conn);
        }
        return;
    }
    if (quic_conn_on_timer(&conn->conn, QUIC_CONN_TIMER_LOSS_DETECTION, now_ms) != QUIC_CONN_OK) {
        return;
    }

    quic_tls_sync_recovery_state(conn);
    queues[0] = &conn->conn.spaces[QUIC_PN_SPACE_INITIAL].in_flight;
    queues[1] = &conn->conn.spaces[QUIC_PN_SPACE_HANDSHAKE].in_flight;
    queues[2] = &conn->conn.spaces[QUIC_PN_SPACE_APPLICATION].in_flight;
    if (quic_recovery_on_timeout(&conn->conn.recovery,
                                 queues,
                                 conn->role == QUIC_ROLE_SERVER &&
                                     conn->amplification_blocked &&
                                     !conn->peer_address_validated,
                                 quic_tls_has_handshake_keys(conn),
                                 now_ms,
                                 quic_tls_on_packet_lost,
                                 conn,
                                 &timer,
                                 &lost_packets) != 0) {
        return;
    }

    if (timer.mode == QUIC_RECOVERY_TIMER_PTO) {
        const quic_sent_packet_t *probe = quic_recovery_oldest_unacked(queues[timer.packet_number_space]);

        if (probe) {
            quic_tls_on_packet_lost(conn, probe);
            if (probe->next && probe->next->is_ack_eliciting) {
                quic_tls_on_packet_lost(conn, probe->next);
            }
        } else if (timer.packet_number_space == QUIC_PN_SPACE_APPLICATION) {
            conn->ping_pending = 1;
        } else {
            enum ssl_encryption_level_t level = quic_tls_level_from_space((quic_pn_space_id_t)timer.packet_number_space);
            quic_crypto_sendbuf_restart_flight(&conn->levels[level].send);
        }
    }
    quic_tls_arm_loss_timer(conn);
}

uint64_t quic_tls_conn_loss_deadline_ms(const quic_tls_conn_t *conn) {
    if (!conn || !conn->conn.timers[QUIC_CONN_TIMER_LOSS_DETECTION].armed) {
        return 0;
    }
    return conn->conn.timers[QUIC_CONN_TIMER_LOSS_DETECTION].deadline_ms;
}

void quic_tls_conn_enable_retry(quic_tls_conn_t *conn, int enabled) {
    if (!conn) {
        return;
    }
    conn->retry_required = enabled ? 1 : 0;
}

void quic_tls_conn_set_initial_flow_control(quic_tls_conn_t *conn,
                                            uint64_t max_data,
                                            uint64_t max_stream_data_bidi_local,
                                            uint64_t max_stream_data_bidi_remote,
                                            uint64_t max_stream_data_uni,
                                            uint64_t max_streams_bidi,
                                            uint64_t max_streams_uni) {
    if (!conn) {
        return;
    }
    conn->initial_max_data = max_data;
    conn->initial_max_stream_data_bidi_local = max_stream_data_bidi_local;
    conn->initial_max_stream_data_bidi_remote = max_stream_data_bidi_remote;
    conn->initial_max_stream_data_uni = max_stream_data_uni;
    conn->initial_max_streams_bidi = max_streams_bidi;
    conn->initial_max_streams_uni = max_streams_uni;
}

int quic_tls_conn_open_stream(quic_tls_conn_t *conn, int bidirectional, uint64_t *stream_id) {
    if (!conn) {
        return -1;
    }
    if (quic_stream_map_open(&conn->streams, bidirectional, stream_id) != 0) {
        return quic_tls_fail(conn, "failed to open stream");
    }
    quic_tls_arm_loss_timer(conn);
    return 0;
}

int quic_tls_conn_stream_write(quic_tls_conn_t *conn,
                               uint64_t stream_id,
                               const uint8_t *data,
                               size_t len,
                               int fin) {
    if (!conn) {
        return -1;
    }
    if (quic_stream_map_write(&conn->streams,
                              stream_id,
                              data,
                              len,
                              fin,
                              conn->error_message,
                              sizeof(conn->error_message)) != 0) {
        return -1;
    }
    quic_tls_arm_loss_timer(conn);
    return 0;
}

int quic_tls_conn_stream_read(quic_tls_conn_t *conn,
                              uint64_t stream_id,
                              uint8_t *out,
                              size_t out_cap,
                              size_t *out_read,
                              int *out_fin) {
    if (!conn) {
        return -1;
    }
    if (quic_stream_map_read(&conn->streams,
                             stream_id,
                             out,
                             out_cap,
                             out_read,
                             out_fin,
                             conn->error_message,
                             sizeof(conn->error_message)) != 0) {
        return -1;
    }
    quic_tls_arm_loss_timer(conn);
    return 0;
}

int quic_tls_conn_stream_peek(const quic_tls_conn_t *conn,
                              uint64_t stream_id,
                              size_t *available,
                              int *fin,
                              int *exists) {
    if (!conn) {
        return -1;
    }
    return quic_stream_map_peek(&conn->streams, stream_id, available, fin, exists);
}

int quic_tls_conn_stop_sending(quic_tls_conn_t *conn, uint64_t stream_id, uint64_t error_code) {
    if (!conn) {
        return -1;
    }
    if (quic_stream_map_stop_sending(&conn->streams,
                                     stream_id,
                                     error_code,
                                     conn->error_message,
                                     sizeof(conn->error_message)) != 0) {
        return -1;
    }
    quic_tls_arm_loss_timer(conn);
    return 0;
}

int quic_tls_conn_reset_stream(quic_tls_conn_t *conn, uint64_t stream_id, uint64_t error_code) {
    if (!conn) {
        return -1;
    }
    if (quic_stream_map_reset(&conn->streams,
                              stream_id,
                              error_code,
                              conn->error_message,
                              sizeof(conn->error_message)) != 0) {
        return -1;
    }
    quic_tls_arm_loss_timer(conn);
    return 0;
}

void quic_tls_conn_queue_ping(quic_tls_conn_t *conn) {
    if (!conn) {
        return;
    }
    conn->ping_pending = 1;
    quic_tls_arm_loss_timer(conn);
}

int quic_tls_conn_handshake_complete(const quic_tls_conn_t *conn) {
    return conn ? conn->handshake_complete : 0;
}

int quic_tls_conn_close(quic_tls_conn_t *conn, uint64_t transport_error_code) {
    if (!conn) {
        return -1;
    }
    if (quic_tls_close_state_active(conn) || conn->conn.state == QUIC_CONN_STATE_CLOSED) {
        return 0;
    }
    return quic_tls_prepare_connection_close(conn, transport_error_code, 0);
}

const char *quic_tls_conn_last_error(const quic_tls_conn_t *conn) {
    return conn ? conn->error_message : "invalid quic tls connection";
}
