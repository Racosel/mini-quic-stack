#include "quic_api.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static uint64_t quic_api_now_ms(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

static int quic_api_find_stream_slot(const quic_api_conn_t *conn, uint64_t stream_id) {
    size_t i;

    if (!conn) {
        return -1;
    }
    for (i = 0; i < QUIC_STREAM_MAX_COUNT; i++) {
        if (conn->tls.streams.streams[i].active && conn->tls.streams.streams[i].id == stream_id) {
            return (int)i;
        }
    }
    return -1;
}

static void quic_api_sync_metrics(quic_api_conn_t *conn) {
    size_t i;
    size_t active_streams = 0;

    if (!conn) {
        return;
    }

    // metrics 对外暴露的是连接快照，因此每次观察事件后都从底层状态重新汇总。
    for (i = 0; i < QUIC_STREAM_MAX_COUNT; i++) {
        if (conn->tls.streams.streams[i].active) {
            active_streams++;
        }
    }

    conn->metrics.bytes_sent = conn->tls.bytes_sent;
    conn->metrics.bytes_received = conn->tls.bytes_received;
    conn->metrics.bytes_in_flight = conn->tls.conn.recovery.bytes_in_flight;
    conn->metrics.congestion_window = conn->tls.conn.recovery.congestion_window;
    conn->metrics.latest_rtt_ms = conn->tls.conn.recovery.latest_rtt_ms;
    conn->metrics.smoothed_rtt_ms = conn->tls.conn.recovery.smoothed_rtt_ms;
    conn->metrics.pto_count = conn->tls.conn.recovery.pto_count;
    conn->metrics.active_streams = active_streams;
    conn->metrics.path_count = conn->tls.path_count;
    conn->metrics.active_path_index = conn->tls.active_path_index;
}

static void quic_api_push_event(quic_api_conn_t *conn,
                                quic_api_event_type_t type,
                                uint64_t stream_id,
                                size_t path_index,
                                uint64_t value_u64,
                                quic_conn_state_t state) {
    size_t slot;
    quic_api_event_t *event;

    if (!conn || type == QUIC_API_EVENT_NONE) {
        return;
    }

    // 事件队列是固定环形缓冲区；溢出时丢弃最旧事件，但保留递增序号，方便调用方发现空洞。
    if (conn->event_count == QUIC_API_MAX_EVENTS) {
        conn->event_head = (conn->event_head + 1U) % QUIC_API_MAX_EVENTS;
        conn->event_count--;
        conn->metrics.events_dropped++;
    }

    slot = (conn->event_head + conn->event_count) % QUIC_API_MAX_EVENTS;
    event = &conn->events[slot];
    memset(event, 0, sizeof(*event));
    event->sequence = ++conn->next_event_sequence;
    event->time_ms = quic_api_now_ms();
    event->type = type;
    event->stream_id = stream_id;
    event->path_index = path_index;
    event->value_u64 = value_u64;
    event->state = state;
    conn->event_count++;
    conn->metrics.events_emitted++;
}

static void quic_api_note_local_stream_open(quic_api_conn_t *conn, uint64_t stream_id) {
    int slot;

    if (!conn) {
        return;
    }

    slot = quic_api_find_stream_slot(conn, stream_id);
    if (slot >= 0) {
        conn->observed_stream_active[slot] = 1;
        conn->observed_stream_readable[slot] = 0;
        conn->observed_stream_fin[slot] = 0;
    }
    conn->metrics.streams_opened_local++;
    quic_api_push_event(conn,
                        QUIC_API_EVENT_STREAM_OPENED,
                        stream_id,
                        conn->tls.active_path_index,
                        0,
                        conn->tls.conn.state);
}

static void quic_api_observe(quic_api_conn_t *conn) {
    size_t i;

    if (!conn) {
        return;
    }

    // 这里把底层 quic_tls 的状态变化折叠成稳定 API 事件，避免应用层直接耦合内部结构字段。
    if (!conn->observed_handshake_complete && conn->tls.handshake_complete) {
        conn->observed_handshake_complete = 1;
        quic_api_push_event(conn,
                            QUIC_API_EVENT_HANDSHAKE_COMPLETE,
                            UINT64_MAX,
                            conn->tls.active_path_index,
                            0,
                            conn->tls.conn.state);
    }

    for (i = 0; i < conn->tls.path_count && i < QUIC_TLS_MAX_PATHS; i++) {
        if (conn->observed_path_state[i] != conn->tls.paths[i].state) {
            conn->observed_path_state[i] = conn->tls.paths[i].state;
            if (conn->tls.paths[i].state == QUIC_TLS_PATH_VALIDATED) {
                quic_api_push_event(conn,
                                    QUIC_API_EVENT_PATH_VALIDATED,
                                    UINT64_MAX,
                                    i,
                                    conn->tls.paths[i].addr.peer.port,
                                    conn->tls.conn.state);
            }
        }
    }

    if (conn->observed_active_path_index != conn->tls.active_path_index) {
        conn->observed_active_path_index = conn->tls.active_path_index;
        quic_api_push_event(conn,
                            QUIC_API_EVENT_ACTIVE_PATH_CHANGED,
                            UINT64_MAX,
                            conn->tls.active_path_index,
                            conn->tls.paths[conn->tls.active_path_index].addr.peer.port,
                            conn->tls.conn.state);
    }

    for (i = 0; i < QUIC_STREAM_MAX_COUNT; i++) {
        quic_stream_t *stream = &conn->tls.streams.streams[i];
        size_t available = 0;
        int fin = 0;
        int exists = 0;

        if (!stream->active) {
            conn->observed_stream_active[i] = 0;
            conn->observed_stream_readable[i] = 0;
            conn->observed_stream_fin[i] = 0;
            continue;
        }

        if (!conn->observed_stream_active[i]) {
            conn->observed_stream_active[i] = 1;
            conn->metrics.streams_opened_remote++;
            quic_api_push_event(conn,
                                QUIC_API_EVENT_STREAM_OPENED,
                                stream->id,
                                conn->tls.active_path_index,
                                0,
                                conn->tls.conn.state);
        }

        if (quic_stream_map_peek(&conn->tls.streams, stream->id, &available, &fin, &exists) != 0 || !exists) {
            conn->observed_stream_readable[i] = 0;
            continue;
        }

        // readable 事件只在从“不可读”切到“可读”时触发，避免同一批缓冲数据被重复上报。
        if (available > 0) {
            if (!conn->observed_stream_readable[i]) {
                quic_api_push_event(conn,
                                    QUIC_API_EVENT_STREAM_READABLE,
                                    stream->id,
                                    conn->tls.active_path_index,
                                    available,
                                    conn->tls.conn.state);
            }
            conn->observed_stream_readable[i] = 1;
        } else {
            conn->observed_stream_readable[i] = 0;
        }

        if (fin && !conn->observed_stream_fin[i]) {
            conn->observed_stream_fin[i] = 1;
            conn->metrics.fin_streams_received++;
            quic_api_push_event(conn,
                                QUIC_API_EVENT_STREAM_FIN_RECEIVED,
                                stream->id,
                                conn->tls.active_path_index,
                                stream->recv_final_size_known ? stream->recv_final_size : 0,
                                conn->tls.conn.state);
        }
    }

    if (conn->observed_state != conn->tls.conn.state) {
        conn->observed_state = conn->tls.conn.state;
        quic_api_push_event(conn,
                            QUIC_API_EVENT_CONNECTION_STATE_CHANGED,
                            UINT64_MAX,
                            conn->tls.active_path_index,
                            0,
                            conn->tls.conn.state);
        if (conn->tls.conn.state == QUIC_CONN_STATE_CLOSED) {
            conn->metrics.connections_closed++;
            quic_api_push_event(conn,
                                QUIC_API_EVENT_CONNECTION_CLOSED,
                                UINT64_MAX,
                                conn->tls.active_path_index,
                                0,
                                conn->tls.conn.state);
        }
    }

    quic_api_sync_metrics(conn);
}

void quic_api_conn_init(quic_api_conn_t *conn) {
    if (!conn) {
        return;
    }
    memset(conn, 0, sizeof(*conn));
    quic_tls_conn_init(&conn->tls);
    conn->observed_state = conn->tls.conn.state;
    conn->observed_active_path_index = conn->tls.active_path_index;
    quic_api_sync_metrics(conn);
}

void quic_api_conn_free(quic_api_conn_t *conn) {
    if (!conn) {
        return;
    }
    quic_tls_conn_free(&conn->tls);
    memset(conn, 0, sizeof(*conn));
}

int quic_api_conn_configure(quic_api_conn_t *conn,
                            quic_role_t role,
                            uint32_t version,
                            const quic_cid_t *local_cid,
                            const quic_cid_t *peer_cid,
                            const char *cert_file,
                            const char *key_file) {
    int rc;

    if (!conn) {
        return -1;
    }
    rc = quic_tls_conn_configure(&conn->tls, role, version, local_cid, peer_cid, cert_file, key_file);
    if (rc == 0) {
        quic_api_observe(conn);
    }
    return rc;
}

void quic_api_conn_enable_retry(quic_api_conn_t *conn, int enabled) {
    if (!conn) {
        return;
    }
    quic_tls_conn_enable_retry(&conn->tls, enabled);
    quic_api_observe(conn);
}

void quic_api_conn_set_max_idle_timeout(quic_api_conn_t *conn, uint64_t timeout_ms) {
    if (!conn) {
        return;
    }
    quic_tls_conn_set_max_idle_timeout(&conn->tls, timeout_ms);
    quic_api_observe(conn);
}

void quic_api_conn_set_initial_flow_control(quic_api_conn_t *conn,
                                            uint64_t max_data,
                                            uint64_t max_stream_data_bidi_local,
                                            uint64_t max_stream_data_bidi_remote,
                                            uint64_t max_stream_data_uni,
                                            uint64_t max_streams_bidi,
                                            uint64_t max_streams_uni) {
    if (!conn) {
        return;
    }
    quic_tls_conn_set_initial_flow_control(&conn->tls,
                                           max_data,
                                           max_stream_data_bidi_local,
                                           max_stream_data_bidi_remote,
                                           max_stream_data_uni,
                                           max_streams_bidi,
                                           max_streams_uni);
    quic_api_observe(conn);
}

int quic_api_conn_set_initial_path(quic_api_conn_t *conn, const quic_path_addr_t *path) {
    int rc;

    if (!conn) {
        return -1;
    }
    rc = quic_tls_conn_set_initial_path(&conn->tls, path);
    if (rc == 0) {
        quic_api_observe(conn);
    }
    return rc;
}

int quic_api_conn_set_server_preferred_address(quic_api_conn_t *conn,
                                               const quic_socket_addr_t *peer_addr,
                                               const quic_cid_t *cid,
                                               const uint8_t *stateless_reset_token) {
    int rc;

    if (!conn) {
        return -1;
    }
    rc = quic_tls_conn_set_server_preferred_address(&conn->tls, peer_addr, cid, stateless_reset_token);
    if (rc == 0) {
        quic_api_observe(conn);
    }
    return rc;
}

int quic_api_conn_get_peer_preferred_address(const quic_api_conn_t *conn,
                                             quic_path_addr_t *path,
                                             quic_cid_t *cid,
                                             uint8_t *stateless_reset_token) {
    if (!conn) {
        return -1;
    }
    return quic_tls_conn_get_peer_preferred_address(&conn->tls, path, cid, stateless_reset_token);
}

int quic_api_conn_begin_migration(quic_api_conn_t *conn, const quic_path_addr_t *path, int use_preferred_address) {
    int rc;

    if (!conn) {
        return -1;
    }
    rc = quic_tls_conn_begin_migration(&conn->tls, path, use_preferred_address);
    if (rc == 0) {
        quic_api_observe(conn);
    }
    return rc;
}

int quic_api_conn_start(quic_api_conn_t *conn) {
    int rc;

    if (!conn) {
        return -1;
    }
    rc = quic_tls_conn_start(&conn->tls);
    if (rc == 0) {
        quic_api_push_event(conn,
                            QUIC_API_EVENT_CONNECTION_STARTED,
                            UINT64_MAX,
                            conn->tls.active_path_index,
                            0,
                            conn->tls.conn.state);
        quic_api_observe(conn);
    }
    return rc;
}

int quic_api_conn_handle_datagram(quic_api_conn_t *conn, const uint8_t *packet, size_t packet_len) {
    int rc;

    if (!conn) {
        return -1;
    }
    rc = quic_tls_conn_handle_datagram(&conn->tls, packet, packet_len);
    if (rc == 0) {
        quic_api_observe(conn);
    }
    return rc;
}

int quic_api_conn_handle_datagram_on_path(quic_api_conn_t *conn,
                                          const uint8_t *packet,
                                          size_t packet_len,
                                          const quic_path_addr_t *path) {
    int rc;

    if (!conn) {
        return -1;
    }
    rc = quic_tls_conn_handle_datagram_on_path(&conn->tls, packet, packet_len, path);
    if (rc == 0) {
        quic_api_observe(conn);
    }
    return rc;
}

int quic_api_conn_build_next_datagram(quic_api_conn_t *conn, uint8_t *out, size_t out_len, size_t *written) {
    int rc;

    if (!conn) {
        return -1;
    }
    rc = quic_tls_conn_build_next_datagram(&conn->tls, out, out_len, written);
    if (rc == 0 || rc == QUIC_TLS_BUILD_BLOCKED) {
        quic_api_observe(conn);
    }
    return rc;
}

int quic_api_conn_build_next_datagram_on_path(quic_api_conn_t *conn,
                                              uint8_t *out,
                                              size_t out_len,
                                              size_t *written,
                                              quic_path_addr_t *out_path) {
    int rc;

    if (!conn) {
        return -1;
    }
    rc = quic_tls_conn_build_next_datagram_on_path(&conn->tls, out, out_len, written, out_path);
    if (rc == 0 || rc == QUIC_TLS_BUILD_BLOCKED) {
        quic_api_observe(conn);
    }
    return rc;
}

int quic_api_conn_has_pending_output(const quic_api_conn_t *conn) {
    return conn ? quic_tls_conn_has_pending_output(&conn->tls) : 0;
}

void quic_api_conn_on_timeout(quic_api_conn_t *conn, uint64_t now_ms) {
    if (!conn) {
        return;
    }
    quic_tls_conn_on_timeout(&conn->tls, now_ms);
    quic_api_observe(conn);
}

uint64_t quic_api_conn_next_timeout_ms(const quic_api_conn_t *conn) {
    return conn ? quic_tls_conn_next_timeout_ms(&conn->tls) : 0;
}

int quic_api_conn_get_info(const quic_api_conn_t *conn, quic_api_conn_info_t *out_info) {
    if (!conn || !out_info) {
        return -1;
    }
    memset(out_info, 0, sizeof(*out_info));
    out_info->role = conn->tls.role;
    out_info->state = conn->tls.conn.state;
    out_info->handshake_complete = conn->tls.handshake_complete;
    out_info->application_secrets_ready = conn->tls.application_secrets_ready;
    out_info->has_pending_output = quic_api_conn_has_pending_output(conn) ? 1U : 0U;
    out_info->close_received = conn->tls.close_received;
    out_info->close_sent = conn->tls.close_sent;
    out_info->stateless_reset_detected = conn->tls.stateless_reset_detected;
    out_info->ping_received = conn->tls.ping_received;
    out_info->path_count = conn->tls.path_count;
    out_info->active_path_index = conn->tls.active_path_index;
    out_info->pending_path_index = conn->tls.pending_path_index;
    return 0;
}

int quic_api_conn_get_path_info(const quic_api_conn_t *conn, size_t path_index, quic_api_path_info_t *out_info) {
    const quic_tls_path_t *path;

    if (!conn || !out_info || path_index >= conn->tls.path_count) {
        return -1;
    }
    memset(out_info, 0, sizeof(*out_info));
    path = &conn->tls.paths[path_index];
    out_info->present = path->active;
    out_info->state = path->state;
    out_info->local = path->addr.local;
    out_info->peer = path->addr.peer;
    out_info->bytes_received = path->bytes_received;
    out_info->bytes_sent_before_validation = path->bytes_sent_before_validation;
    out_info->challenge_pending = path->challenge_pending;
    out_info->challenge_in_flight = path->challenge_in_flight;
    out_info->challenge_expected = path->challenge_expected;
    out_info->response_pending = path->response_pending;
    out_info->response_in_flight = path->response_in_flight;
    out_info->mtu_validated = path->mtu_validated;
    return 0;
}

int quic_api_conn_open_stream(quic_api_conn_t *conn, int bidirectional, uint64_t *stream_id) {
    int rc;

    if (!conn) {
        return -1;
    }
    rc = quic_tls_conn_open_stream(&conn->tls, bidirectional, stream_id);
    if (rc == 0 && stream_id) {
        quic_api_note_local_stream_open(conn, *stream_id);
        quic_api_observe(conn);
    }
    return rc;
}

int quic_api_conn_stream_write(quic_api_conn_t *conn,
                               uint64_t stream_id,
                               const uint8_t *data,
                               size_t len,
                               int fin) {
    int rc;

    if (!conn) {
        return -1;
    }
    rc = quic_tls_conn_stream_write(&conn->tls, stream_id, data, len, fin);
    if (rc == 0) {
        quic_api_observe(conn);
    }
    return rc;
}

int quic_api_conn_stream_read(quic_api_conn_t *conn,
                              uint64_t stream_id,
                              uint8_t *out,
                              size_t out_cap,
                              size_t *out_read,
                              int *out_fin) {
    int rc;

    if (!conn) {
        return -1;
    }
    rc = quic_tls_conn_stream_read(&conn->tls, stream_id, out, out_cap, out_read, out_fin);
    if (rc == 0) {
        quic_api_observe(conn);
    }
    return rc;
}

int quic_api_conn_stream_peek(const quic_api_conn_t *conn,
                              uint64_t stream_id,
                              size_t *available,
                              int *fin,
                              int *exists) {
    if (!conn) {
        return -1;
    }
    return quic_tls_conn_stream_peek(&conn->tls, stream_id, available, fin, exists);
}

int quic_api_conn_get_stream_info(const quic_api_conn_t *conn, uint64_t stream_id, quic_api_stream_info_t *out_info) {
    const quic_stream_t *stream;
    size_t readable = 0;
    int fin = 0;
    int exists = 0;

    if (!conn || !out_info) {
        return -1;
    }
    memset(out_info, 0, sizeof(*out_info));
    stream = quic_stream_map_find_const(&conn->tls.streams, stream_id);
    if (!stream) {
        return 0;
    }
    out_info->exists = 1;
    out_info->local_initiated = stream->local_initiated;
    out_info->bidirectional = stream->bidirectional;
    out_info->send_open = stream->send_open;
    out_info->recv_open = stream->recv_open;
    out_info->fin_sent = stream->fin_sent;
    out_info->fin_received = stream->fin_received;
    out_info->reset_received = stream->reset_received;
    out_info->stop_sending_received = stream->stop_sending_received;
    out_info->send_highest_offset = stream->send_highest_offset;
    out_info->recv_highest_offset = stream->recv_highest_offset;
    out_info->recv_final_size_known = stream->recv_final_size_known;
    out_info->recv_final_size = stream->recv_final_size;
    if (quic_tls_conn_stream_peek(&conn->tls, stream_id, &readable, &fin, &exists) == 0 && exists) {
        out_info->readable_bytes = readable;
        if (fin) {
            out_info->fin_received = 1;
        }
    }
    return 0;
}

int quic_api_conn_stop_sending(quic_api_conn_t *conn, uint64_t stream_id, uint64_t error_code) {
    int rc;

    if (!conn) {
        return -1;
    }
    rc = quic_tls_conn_stop_sending(&conn->tls, stream_id, error_code);
    if (rc == 0) {
        quic_api_observe(conn);
    }
    return rc;
}

int quic_api_conn_reset_stream(quic_api_conn_t *conn, uint64_t stream_id, uint64_t error_code) {
    int rc;

    if (!conn) {
        return -1;
    }
    rc = quic_tls_conn_reset_stream(&conn->tls, stream_id, error_code);
    if (rc == 0) {
        quic_api_observe(conn);
    }
    return rc;
}

void quic_api_conn_queue_ping(quic_api_conn_t *conn) {
    if (!conn) {
        return;
    }
    quic_tls_conn_queue_ping(&conn->tls);
    quic_api_push_event(conn,
                        QUIC_API_EVENT_PING_QUEUED,
                        UINT64_MAX,
                        conn->tls.active_path_index,
                        0,
                        conn->tls.conn.state);
    quic_api_observe(conn);
}

int quic_api_conn_close(quic_api_conn_t *conn, uint64_t transport_error_code) {
    int rc;

    if (!conn) {
        return -1;
    }
    rc = quic_tls_conn_close(&conn->tls, transport_error_code);
    if (rc == 0) {
        quic_api_push_event(conn,
                            QUIC_API_EVENT_CONNECTION_CLOSE_REQUESTED,
                            UINT64_MAX,
                            conn->tls.active_path_index,
                            transport_error_code,
                            conn->tls.conn.state);
        quic_api_observe(conn);
    }
    return rc;
}

int quic_api_conn_handshake_complete(const quic_api_conn_t *conn) {
    return conn ? quic_tls_conn_handshake_complete(&conn->tls) : 0;
}

const char *quic_api_conn_last_error(const quic_api_conn_t *conn) {
    return conn ? quic_tls_conn_last_error(&conn->tls) : "invalid quic api connection";
}

int quic_api_conn_get_metrics(quic_api_conn_t *conn, quic_api_metrics_t *out_metrics) {
    if (!conn || !out_metrics) {
        return -1;
    }
    quic_api_observe(conn);
    *out_metrics = conn->metrics;
    return 0;
}

int quic_api_conn_poll_event(quic_api_conn_t *conn, quic_api_event_t *out_event) {
    if (!conn || !out_event || conn->event_count == 0) {
        return -1;
    }
    *out_event = conn->events[conn->event_head];
    conn->event_head = (conn->event_head + 1U) % QUIC_API_MAX_EVENTS;
    conn->event_count--;
    return 0;
}

const char *quic_api_event_name(quic_api_event_type_t type) {
    switch (type) {
        case QUIC_API_EVENT_CONNECTION_STARTED:
            return "connection_started";
        case QUIC_API_EVENT_HANDSHAKE_COMPLETE:
            return "handshake_complete";
        case QUIC_API_EVENT_STREAM_OPENED:
            return "stream_opened";
        case QUIC_API_EVENT_STREAM_READABLE:
            return "stream_readable";
        case QUIC_API_EVENT_STREAM_FIN_RECEIVED:
            return "stream_fin_received";
        case QUIC_API_EVENT_PATH_VALIDATED:
            return "path_validated";
        case QUIC_API_EVENT_ACTIVE_PATH_CHANGED:
            return "active_path_changed";
        case QUIC_API_EVENT_PING_QUEUED:
            return "ping_queued";
        case QUIC_API_EVENT_CONNECTION_CLOSE_REQUESTED:
            return "connection_close_requested";
        case QUIC_API_EVENT_CONNECTION_STATE_CHANGED:
            return "connection_state_changed";
        case QUIC_API_EVENT_CONNECTION_CLOSED:
            return "connection_closed";
        case QUIC_API_EVENT_NONE:
        default:
            return "none";
    }
}

int quic_api_event_format_json(const quic_api_event_t *event, char *out, size_t out_cap) {
    int written;

    if (!event || !out || out_cap == 0) {
        return -1;
    }

    written = snprintf(out,
                       out_cap,
                       "{\"seq\":%llu,\"time_ms\":%llu,\"event\":\"%s\",\"stream_id\":%s,"
                       "\"path_index\":%zu,\"value\":%llu,\"state\":%d}",
                       (unsigned long long)event->sequence,
                       (unsigned long long)event->time_ms,
                       quic_api_event_name(event->type),
                       event->stream_id == UINT64_MAX ? "null" : "",
                       event->path_index,
                       (unsigned long long)event->value_u64,
                       (int)event->state);
    if (written < 0 || (size_t)written >= out_cap) {
        if (out_cap > 0) {
            out[0] = '\0';
        }
        return -1;
    }

    if (event->stream_id != UINT64_MAX) {
        char buffer[256];

        written = snprintf(buffer,
                           sizeof(buffer),
                           "{\"seq\":%llu,\"time_ms\":%llu,\"event\":\"%s\",\"stream_id\":%llu,"
                           "\"path_index\":%zu,\"value\":%llu,\"state\":%d}",
                           (unsigned long long)event->sequence,
                           (unsigned long long)event->time_ms,
                           quic_api_event_name(event->type),
                           (unsigned long long)event->stream_id,
                           event->path_index,
                           (unsigned long long)event->value_u64,
                           (int)event->state);
        if (written < 0 || (size_t)written >= out_cap) {
            if (out_cap > 0) {
                out[0] = '\0';
            }
            return -1;
        }
        memcpy(out, buffer, (size_t)written + 1U);
    }

    return 0;
}

int quic_api_metrics_format_json(const quic_api_metrics_t *metrics, char *out, size_t out_cap) {
    int written;

    if (!metrics || !out || out_cap == 0) {
        return -1;
    }
    written = snprintf(out,
                       out_cap,
                       "{\"bytes_sent\":%llu,\"bytes_received\":%llu,\"bytes_in_flight\":%llu,"
                       "\"congestion_window\":%llu,\"latest_rtt_ms\":%llu,\"smoothed_rtt_ms\":%llu,"
                       "\"pto_count\":%llu,\"events_emitted\":%llu,\"events_dropped\":%llu,"
                       "\"streams_opened_local\":%llu,\"streams_opened_remote\":%llu,"
                       "\"fin_streams_received\":%llu,\"connections_closed\":%llu,"
                       "\"active_streams\":%zu,\"path_count\":%zu,\"active_path_index\":%zu}",
                       (unsigned long long)metrics->bytes_sent,
                       (unsigned long long)metrics->bytes_received,
                       (unsigned long long)metrics->bytes_in_flight,
                       (unsigned long long)metrics->congestion_window,
                       (unsigned long long)metrics->latest_rtt_ms,
                       (unsigned long long)metrics->smoothed_rtt_ms,
                       (unsigned long long)metrics->pto_count,
                       (unsigned long long)metrics->events_emitted,
                       (unsigned long long)metrics->events_dropped,
                       (unsigned long long)metrics->streams_opened_local,
                       (unsigned long long)metrics->streams_opened_remote,
                       (unsigned long long)metrics->fin_streams_received,
                       (unsigned long long)metrics->connections_closed,
                       metrics->active_streams,
                       metrics->path_count,
                       metrics->active_path_index);
    if (written < 0 || (size_t)written >= out_cap) {
        if (out_cap > 0) {
            out[0] = '\0';
        }
        return -1;
    }
    return 0;
}

const quic_tls_conn_t *quic_api_conn_raw(const quic_api_conn_t *conn) {
    return conn ? &conn->tls : NULL;
}
