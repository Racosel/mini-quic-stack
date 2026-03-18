#include "quic_connection.h"
#include "quic_frame.h"
#include "quic_packet_protection.h"
#include "quic_varint.h"
#include <string.h>

static int quic_conn_valid_space_id(quic_pn_space_id_t space_id) {
    return space_id >= QUIC_PN_SPACE_INITIAL && space_id < QUIC_PN_SPACE_COUNT;
}

static int quic_conn_valid_timer_id(quic_conn_timer_id_t timer_id) {
    return timer_id >= QUIC_CONN_TIMER_LOSS_DETECTION && timer_id < QUIC_CONN_TIMER_COUNT;
}

static quic_conn_pn_space_t *quic_conn_space(quic_connection_t *conn, quic_pn_space_id_t space_id) {
    if (!conn || !quic_conn_valid_space_id(space_id)) {
        return NULL;
    }
    return &conn->spaces[space_id];
}

static void quic_conn_note_received_packet(quic_conn_pn_space_t *space, uint64_t packet_number) {
    if (!space) {
        return;
    }

    space->last_received_packet = packet_number;
    if (packet_number > space->largest_received_packet) {
        space->largest_received_packet = packet_number;
    }
    (void)quic_ack_note_received(space->ack_ranges, &space->ack_range_count, packet_number);
}

static int quic_skip_varint(const uint8_t *payload, size_t payload_len, size_t *offset) {
    uint64_t ignored;
    return quic_decode_varint(payload, payload_len, offset, &ignored);
}

static int quic_skip_length_prefixed_bytes(const uint8_t *payload, size_t payload_len, size_t *offset) {
    uint64_t len;
    if (quic_decode_varint(payload, payload_len, offset, &len) != 0) {
        return -1;
    }
    if (*offset + len > payload_len) {
        return -1;
    }
    *offset += len;
    return 0;
}

static int quic_conn_consume_frame(
    quic_connection_t *conn,
    quic_pn_space_id_t space_id,
    const uint8_t *payload,
    size_t payload_len,
    size_t *offset
) {
    size_t frame_start = *offset;
    uint64_t frame_type;
    quic_conn_pn_space_t *space = quic_conn_space(conn, space_id);

    if (!space) {
        return QUIC_CONN_ERR_INVALID_ARGUMENT;
    }

    if (quic_decode_varint(payload, payload_len, offset, &frame_type) != 0) {
        return QUIC_CONN_ERR_DECODE;
    }

    switch (frame_type) {
        case QUIC_FRAME_PADDING:
            while (*offset < payload_len && payload[*offset] == 0x00) {
                (*offset)++;
            }
            return 0;

        case QUIC_FRAME_PING:
        case QUIC_FRAME_HANDSHAKE_DONE:
            return 0;

        case QUIC_FRAME_ACK:
        case QUIC_FRAME_ACK_ECN: {
            quic_ack_frame_t ack;
            size_t consumed = 0;
            if (quic_ack_parse_frame(payload + frame_start, payload_len - frame_start, &ack, &consumed) != 0) {
                return QUIC_CONN_ERR_DECODE;
            }
            if (quic_on_ack_frame(&space->in_flight, &ack, &conn->last_acked_packets) != 0) {
                return QUIC_CONN_ERR_DECODE;
            }
            *offset = frame_start + consumed;
            return 0;
        }

        case QUIC_FRAME_RESET_STREAM:
            return quic_skip_varint(payload, payload_len, offset) ||
                   quic_skip_varint(payload, payload_len, offset) ||
                   quic_skip_varint(payload, payload_len, offset) ? -1 : 0;

        case QUIC_FRAME_STOP_SENDING:
            return quic_skip_varint(payload, payload_len, offset) ||
                   quic_skip_varint(payload, payload_len, offset) ? -1 : 0;

        case QUIC_FRAME_CRYPTO:
            if (quic_decode_varint(payload, payload_len, offset, &conn->last_crypto_offset) != 0) return -1;
            if (quic_decode_varint(payload, payload_len, offset, &conn->last_crypto_length) != 0) return -1;
            if (*offset + conn->last_crypto_length > payload_len) return -1;
            *offset += conn->last_crypto_length;
            return 0;

        case QUIC_FRAME_NEW_TOKEN:
            return quic_skip_length_prefixed_bytes(payload, payload_len, offset);

        case QUIC_FRAME_MAX_DATA:
        case QUIC_FRAME_MAX_STREAMS_BIDI:
        case QUIC_FRAME_MAX_STREAMS_UNI:
        case QUIC_FRAME_DATA_BLOCKED:
        case QUIC_FRAME_STREAMS_BLOCKED_BIDI:
        case QUIC_FRAME_STREAMS_BLOCKED_UNI:
        case QUIC_FRAME_RETIRE_CONNECTION_ID:
            return quic_skip_varint(payload, payload_len, offset);

        case QUIC_FRAME_MAX_STREAM_DATA:
        case QUIC_FRAME_STREAM_DATA_BLOCKED:
            return quic_skip_varint(payload, payload_len, offset) ||
                   quic_skip_varint(payload, payload_len, offset) ? -1 : 0;

        case QUIC_FRAME_NEW_CONNECTION_ID: {
            uint64_t ignored;
            uint8_t cid_len;
            if (quic_decode_varint(payload, payload_len, offset, &ignored) != 0) return -1;
            if (quic_decode_varint(payload, payload_len, offset, &ignored) != 0) return -1;
            if (*offset >= payload_len) return -1;
            cid_len = payload[(*offset)++];
            if (cid_len == 0 || cid_len > MAX_CID_LEN || *offset + cid_len + 16 > payload_len) return -1;
            *offset += cid_len + 16;
            return 0;
        }

        case QUIC_FRAME_PATH_CHALLENGE:
        case QUIC_FRAME_PATH_RESPONSE:
            if (*offset + 8 > payload_len) return -1;
            *offset += 8;
            return 0;

        case QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT:
            if (quic_skip_varint(payload, payload_len, offset) != 0) return -1;
            if (quic_skip_varint(payload, payload_len, offset) != 0) return -1;
            return quic_skip_length_prefixed_bytes(payload, payload_len, offset);

        case QUIC_FRAME_CONNECTION_CLOSE_APPLICATION:
            if (quic_skip_varint(payload, payload_len, offset) != 0) return -1;
            return quic_skip_length_prefixed_bytes(payload, payload_len, offset);

        default:
            if (frame_type >= 0x08 && frame_type <= 0x0F) {
                uint64_t stream_length;
                uint8_t has_len = frame_type & 0x02;
                uint8_t has_off = frame_type & 0x04;
                if (quic_skip_varint(payload, payload_len, offset) != 0) return -1;
                if (has_off && quic_skip_varint(payload, payload_len, offset) != 0) return -1;
                if (has_len) {
                    if (quic_decode_varint(payload, payload_len, offset, &stream_length) != 0) return -1;
                } else {
                    stream_length = payload_len - *offset;
                }
                if (*offset + stream_length > payload_len) return -1;
                *offset += stream_length;
                return 0;
            }
            return QUIC_CONN_ERR_UNSUPPORTED;
    }
}

static int quic_conn_classify_space(
    const uint8_t *packet,
    size_t packet_len,
    quic_pn_space_id_t *out_space
) {
    quic_pkt_header_meta_t meta;
    const quic_version_ops_t *ops;
    uint8_t packet_type;

    if (!packet || !out_space) {
        return QUIC_CONN_ERR_INVALID_ARGUMENT;
    }
    if (quic_parse_header_meta(packet, packet_len, &meta) != 0) {
        return QUIC_CONN_ERR_DECODE;
    }
    if (meta.header_form == 0) {
        *out_space = QUIC_PN_SPACE_APPLICATION;
        return QUIC_CONN_OK;
    }

    ops = quic_version_get_ops(meta.version);
    if (!ops) {
        return QUIC_CONN_ERR_DECODE;
    }

    packet_type = ops->decode_packet_type(packet[0]);
    switch (packet_type) {
        case 0:
            *out_space = QUIC_PN_SPACE_INITIAL;
            return QUIC_CONN_OK;
        case 1:
            *out_space = QUIC_PN_SPACE_APPLICATION;
            return QUIC_CONN_OK;
        case 2:
            *out_space = QUIC_PN_SPACE_HANDSHAKE;
            return QUIC_CONN_OK;
        default:
            return QUIC_CONN_ERR_UNSUPPORTED;
    }
}

static int quic_conn_recv_initial_space(quic_connection_t *conn, uint8_t *packet, size_t packet_len) {
    quic_initial_header_t initial;
    quic_conn_pn_space_t *space = quic_conn_space(conn, QUIC_PN_SPACE_INITIAL);
    uint8_t plaintext[2048];
    size_t header_len;
    size_t plaintext_len;
    size_t offset = 0;
    uint64_t packet_number;

    if (!conn || !packet || !space) {
        return QUIC_CONN_ERR_INVALID_ARGUMENT;
    }
    if (!space->rx_keys_ready) {
        return QUIC_CONN_ERR_KEYS_UNAVAILABLE;
    }
    if (quic_parse_initial_header(packet, packet_len, &initial) != 0) {
        return QUIC_CONN_ERR_DECODE;
    }
    if (conn->version != 0 && initial.meta.version != conn->version) {
        return QUIC_CONN_ERR_STATE;
    }

    conn->version = initial.meta.version;
    conn->version_ops = initial.version_ops;
    conn->last_acked_packets = 0;
    conn->last_frames_parsed = 0;
    conn->last_crypto_offset = 0;
    conn->last_crypto_length = 0;

    if (quic_packet_unprotect(&space->rx_crypto,
                              space->largest_received_packet,
                              packet,
                              packet_len,
                              initial.pn_offset,
                              &packet_number,
                              &header_len,
                              plaintext,
                              sizeof(plaintext),
                              &plaintext_len) != 0) {
        return QUIC_CONN_ERR_DECODE;
    }

    quic_conn_note_received_packet(space, packet_number);

    conn->last_received_packet = packet_number;
    conn->last_recv_space = QUIC_PN_SPACE_INITIAL;
    conn->last_plaintext_len = plaintext_len;

    while (offset < plaintext_len) {
        int status = quic_conn_consume_frame(conn, QUIC_PN_SPACE_INITIAL, plaintext, plaintext_len, &offset);
        if (status != QUIC_CONN_OK) {
            return status;
        }
        conn->last_frames_parsed++;
    }

    return QUIC_CONN_OK;
}

void quic_conn_init(quic_connection_t *conn) {
    if (!conn) {
        return;
    }

    memset(conn, 0, sizeof(*conn));
    conn->state = QUIC_CONN_STATE_NEW;
    conn->last_event_type = QUIC_CONN_EVENT_NONE;
    conn->last_timer_id = QUIC_CONN_TIMER_LOSS_DETECTION;

    for (size_t i = 0; i < QUIC_PN_SPACE_COUNT; i++) {
        conn->spaces[i].id = (quic_pn_space_id_t)i;
        quic_queue_init(&conn->spaces[i].in_flight);
        quic_ack_ranges_init(conn->spaces[i].ack_ranges, &conn->spaces[i].ack_range_count);
    }
    quic_recovery_init(&conn->recovery, 1200);
}

int quic_conn_install_rx_keys(
    quic_connection_t *conn,
    quic_pn_space_id_t space_id,
    const quic_crypto_level_ctx_t *rx_ctx
) {
    quic_conn_pn_space_t *space = quic_conn_space(conn, space_id);

    if (!space || !rx_ctx) {
        return QUIC_CONN_ERR_INVALID_ARGUMENT;
    }

    space->rx_crypto = *rx_ctx;
    space->rx_keys_ready = 1;
    return QUIC_CONN_OK;
}

int quic_conn_install_tx_keys(
    quic_connection_t *conn,
    quic_pn_space_id_t space_id,
    const quic_crypto_level_ctx_t *tx_ctx
) {
    quic_conn_pn_space_t *space = quic_conn_space(conn, space_id);

    if (!space || !tx_ctx) {
        return QUIC_CONN_ERR_INVALID_ARGUMENT;
    }

    space->tx_crypto = *tx_ctx;
    space->tx_keys_ready = 1;

    if (space_id == QUIC_PN_SPACE_APPLICATION && conn->state == QUIC_CONN_STATE_HANDSHAKING) {
        conn->state = QUIC_CONN_STATE_ACTIVE;
    }

    return QUIC_CONN_OK;
}

int quic_conn_install_space_keys(
    quic_connection_t *conn,
    quic_pn_space_id_t space_id,
    const quic_crypto_level_ctx_t *rx_ctx,
    const quic_crypto_level_ctx_t *tx_ctx
) {
    int status;

    if (!conn || !rx_ctx || !tx_ctx) {
        return QUIC_CONN_ERR_INVALID_ARGUMENT;
    }

    status = quic_conn_install_rx_keys(conn, space_id, rx_ctx);
    if (status != QUIC_CONN_OK) {
        return status;
    }
    return quic_conn_install_tx_keys(conn, space_id, tx_ctx);
}

void quic_conn_discard_space(quic_connection_t *conn, quic_pn_space_id_t space_id) {
    quic_conn_pn_space_t *space = quic_conn_space(conn, space_id);

    if (!space) {
        return;
    }

    quic_crypto_discard_level(&space->rx_crypto);
    quic_crypto_discard_level(&space->tx_crypto);
    space->rx_keys_ready = 0;
    space->tx_keys_ready = 0;
    quic_recovery_discard_space(&conn->recovery, &space->in_flight, (uint8_t)space_id);
    quic_ack_ranges_init(space->ack_ranges, &space->ack_range_count);
    space->largest_received_packet = 0;
    space->last_received_packet = 0;
    space->next_packet_number = 0;
}

int quic_conn_set_initial_keys(quic_connection_t *conn, uint32_t version, const quic_cid_t *original_dcid) {
    quic_crypto_context_t derived;
    const quic_version_ops_t *ops;

    if (!conn || !original_dcid) {
        return QUIC_CONN_ERR_INVALID_ARGUMENT;
    }

    ops = quic_version_get_ops(version);
    if (!ops) {
        return QUIC_CONN_ERR_DECODE;
    }

    memset(&derived, 0, sizeof(derived));
    if (quic_crypto_setup_initial_keys(original_dcid, ops, &derived) != 0) {
        return QUIC_CONN_ERR_DECODE;
    }

    conn->version = version;
    conn->original_dcid = *original_dcid;
    conn->version_ops = ops;
    conn->state = QUIC_CONN_STATE_HANDSHAKING;

    return quic_conn_install_space_keys(conn,
                                        QUIC_PN_SPACE_INITIAL,
                                        &derived.client_initial,
                                        &derived.server_initial);
}

int quic_conn_prepare_send(
    quic_connection_t *conn,
    quic_pn_space_id_t space_id,
    size_t payload_len,
    uint8_t ack_eliciting,
    quic_conn_tx_plan_t *out_plan
) {
    quic_conn_pn_space_t *space = quic_conn_space(conn, space_id);

    if (!space || !out_plan) {
        return QUIC_CONN_ERR_INVALID_ARGUMENT;
    }
    if (!space->tx_keys_ready) {
        return QUIC_CONN_ERR_KEYS_UNAVAILABLE;
    }

    memset(out_plan, 0, sizeof(*out_plan));
    out_plan->space = space_id;
    out_plan->packet_number = space->next_packet_number++;
    out_plan->packet_number_len = quic_packet_number_encode_size(out_plan->packet_number, UINT64_MAX);
    out_plan->payload_len = payload_len;
    out_plan->ack_eliciting = ack_eliciting ? 1 : 0;
    out_plan->header_form = (space_id == QUIC_PN_SPACE_APPLICATION) ? 0 : 1;

    if (out_plan->packet_number_len == 0) {
        out_plan->packet_number_len = 1;
    }

    return QUIC_CONN_OK;
}

int quic_conn_recv_packet(quic_connection_t *conn, uint8_t *packet, size_t packet_len) {
    quic_pn_space_id_t space_id;
    int status;

    if (!conn || !packet) {
        return QUIC_CONN_ERR_INVALID_ARGUMENT;
    }

    status = quic_conn_classify_space(packet, packet_len, &space_id);
    if (status != QUIC_CONN_OK) {
        return status;
    }

    conn->last_recv_space = space_id;

    switch (space_id) {
        case QUIC_PN_SPACE_INITIAL:
            return quic_conn_recv_initial_space(conn, packet, packet_len);
        case QUIC_PN_SPACE_HANDSHAKE:
        case QUIC_PN_SPACE_APPLICATION:
            return QUIC_CONN_ERR_UNSUPPORTED;
        default:
            return QUIC_CONN_ERR_UNSUPPORTED;
    }
}

int quic_conn_recv_initial(quic_connection_t *conn, uint8_t *packet, size_t packet_len) {
    return quic_conn_recv_packet(conn, packet, packet_len);
}

void quic_conn_arm_timer(quic_connection_t *conn, quic_conn_timer_id_t timer_id, uint64_t deadline_ms) {
    if (!conn || !quic_conn_valid_timer_id(timer_id)) {
        return;
    }
    conn->timers[timer_id].armed = 1;
    conn->timers[timer_id].deadline_ms = deadline_ms;
}

void quic_conn_disarm_timer(quic_connection_t *conn, quic_conn_timer_id_t timer_id) {
    if (!conn || !quic_conn_valid_timer_id(timer_id)) {
        return;
    }
    conn->timers[timer_id].armed = 0;
    conn->timers[timer_id].deadline_ms = 0;
}

int quic_conn_on_timer(quic_connection_t *conn, quic_conn_timer_id_t timer_id, uint64_t now_ms) {
    quic_conn_timer_state_t *timer;

    if (!conn || !quic_conn_valid_timer_id(timer_id)) {
        return QUIC_CONN_ERR_INVALID_ARGUMENT;
    }

    timer = &conn->timers[timer_id];
    conn->last_timer_id = timer_id;
    if (!timer->armed || now_ms < timer->deadline_ms) {
        return QUIC_CONN_ERR_STATE;
    }

    quic_conn_disarm_timer(conn, timer_id);
    if (timer_id == QUIC_CONN_TIMER_IDLE) {
        if (conn->state == QUIC_CONN_STATE_DRAINING) {
            conn->state = QUIC_CONN_STATE_CLOSED;
        } else if (conn->state != QUIC_CONN_STATE_CLOSED) {
            conn->state = QUIC_CONN_STATE_DRAINING;
        }
    }

    return QUIC_CONN_OK;
}

int quic_conn_handle_event(
    quic_connection_t *conn,
    const quic_conn_event_t *event,
    quic_conn_event_result_t *out_result
) {
    int status;

    if (!conn || !event) {
        return QUIC_CONN_ERR_INVALID_ARGUMENT;
    }

    if (out_result) {
        memset(out_result, 0, sizeof(*out_result));
        out_result->type = event->type;
        out_result->space = conn->last_recv_space;
        out_result->timer_id = conn->last_timer_id;
    }

    conn->last_event_type = event->type;

    switch (event->type) {
        case QUIC_CONN_EVENT_RX_PACKET:
            status = quic_conn_recv_packet(conn, event->data.rx_packet.packet, event->data.rx_packet.packet_len);
            if (out_result) {
                out_result->space = conn->last_recv_space;
            }
            break;
        case QUIC_CONN_EVENT_PREPARE_SEND:
            status = quic_conn_prepare_send(conn,
                                            event->data.tx_prepare.space,
                                            event->data.tx_prepare.payload_len,
                                            event->data.tx_prepare.ack_eliciting,
                                            out_result ? &out_result->tx_plan : &(quic_conn_tx_plan_t){0});
            if (out_result) {
                out_result->space = event->data.tx_prepare.space;
            }
            break;
        case QUIC_CONN_EVENT_TIMER_EXPIRED:
            status = quic_conn_on_timer(conn, event->data.timer.timer_id, event->data.timer.now_ms);
            if (out_result) {
                out_result->timer_id = event->data.timer.timer_id;
            }
            break;
        default:
            status = QUIC_CONN_ERR_INVALID_ARGUMENT;
            break;
    }

    if (out_result) {
        out_result->status = status;
    }
    return status;
}
