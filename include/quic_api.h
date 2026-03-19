#ifndef QUIC_API_H
#define QUIC_API_H

#include "quic_tls.h"
#include <stddef.h>
#include <stdint.h>

#define QUIC_API_MAX_EVENTS 128

typedef enum {
    QUIC_API_EVENT_NONE = 0,
    QUIC_API_EVENT_CONNECTION_STARTED = 1,
    QUIC_API_EVENT_HANDSHAKE_COMPLETE = 2,
    QUIC_API_EVENT_STREAM_OPENED = 3,
    QUIC_API_EVENT_STREAM_READABLE = 4,
    QUIC_API_EVENT_STREAM_FIN_RECEIVED = 5,
    QUIC_API_EVENT_PATH_VALIDATED = 6,
    QUIC_API_EVENT_ACTIVE_PATH_CHANGED = 7,
    QUIC_API_EVENT_PING_QUEUED = 8,
    QUIC_API_EVENT_CONNECTION_CLOSE_REQUESTED = 9,
    QUIC_API_EVENT_CONNECTION_STATE_CHANGED = 10,
    QUIC_API_EVENT_CONNECTION_CLOSED = 11
} quic_api_event_type_t;

typedef struct {
    uint64_t sequence;
    uint64_t time_ms;
    quic_api_event_type_t type;
    uint64_t stream_id;
    size_t path_index;
    uint64_t value_u64;
    quic_conn_state_t state;
} quic_api_event_t;

typedef struct {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t bytes_in_flight;
    uint64_t congestion_window;
    uint64_t latest_rtt_ms;
    uint64_t smoothed_rtt_ms;
    uint64_t pto_count;
    uint64_t events_emitted;
    uint64_t events_dropped;
    uint64_t streams_opened_local;
    uint64_t streams_opened_remote;
    uint64_t fin_streams_received;
    uint64_t connections_closed;
    size_t active_streams;
    size_t path_count;
    size_t active_path_index;
} quic_api_metrics_t;

typedef struct {
    quic_tls_conn_t tls;
    quic_api_event_t events[QUIC_API_MAX_EVENTS];
    size_t event_head;
    size_t event_count;
    uint64_t next_event_sequence;
    quic_api_metrics_t metrics;
    quic_conn_state_t observed_state;
    size_t observed_active_path_index;
    uint8_t observed_handshake_complete;
    uint8_t observed_path_state[QUIC_TLS_MAX_PATHS];
    uint8_t observed_stream_active[QUIC_STREAM_MAX_COUNT];
    uint8_t observed_stream_readable[QUIC_STREAM_MAX_COUNT];
    uint8_t observed_stream_fin[QUIC_STREAM_MAX_COUNT];
} quic_api_conn_t;

void quic_api_conn_init(quic_api_conn_t *conn);
void quic_api_conn_free(quic_api_conn_t *conn);
int quic_api_conn_configure(quic_api_conn_t *conn,
                            quic_role_t role,
                            uint32_t version,
                            const quic_cid_t *local_cid,
                            const quic_cid_t *peer_cid,
                            const char *cert_file,
                            const char *key_file);
void quic_api_conn_enable_retry(quic_api_conn_t *conn, int enabled);
void quic_api_conn_set_max_idle_timeout(quic_api_conn_t *conn, uint64_t timeout_ms);
void quic_api_conn_set_initial_flow_control(quic_api_conn_t *conn,
                                            uint64_t max_data,
                                            uint64_t max_stream_data_bidi_local,
                                            uint64_t max_stream_data_bidi_remote,
                                            uint64_t max_stream_data_uni,
                                            uint64_t max_streams_bidi,
                                            uint64_t max_streams_uni);
int quic_api_conn_set_initial_path(quic_api_conn_t *conn, const quic_path_addr_t *path);
int quic_api_conn_set_server_preferred_address(quic_api_conn_t *conn,
                                               const quic_socket_addr_t *peer_addr,
                                               const quic_cid_t *cid,
                                               const uint8_t *stateless_reset_token);
int quic_api_conn_get_peer_preferred_address(const quic_api_conn_t *conn,
                                             quic_path_addr_t *path,
                                             quic_cid_t *cid,
                                             uint8_t *stateless_reset_token);
int quic_api_conn_begin_migration(quic_api_conn_t *conn, const quic_path_addr_t *path, int use_preferred_address);
int quic_api_conn_start(quic_api_conn_t *conn);
int quic_api_conn_handle_datagram(quic_api_conn_t *conn, const uint8_t *packet, size_t packet_len);
int quic_api_conn_handle_datagram_on_path(quic_api_conn_t *conn,
                                          const uint8_t *packet,
                                          size_t packet_len,
                                          const quic_path_addr_t *path);
int quic_api_conn_build_next_datagram(quic_api_conn_t *conn, uint8_t *out, size_t out_len, size_t *written);
int quic_api_conn_build_next_datagram_on_path(quic_api_conn_t *conn,
                                              uint8_t *out,
                                              size_t out_len,
                                              size_t *written,
                                              quic_path_addr_t *out_path);
int quic_api_conn_has_pending_output(const quic_api_conn_t *conn);
void quic_api_conn_on_timeout(quic_api_conn_t *conn, uint64_t now_ms);
uint64_t quic_api_conn_next_timeout_ms(const quic_api_conn_t *conn);
int quic_api_conn_open_stream(quic_api_conn_t *conn, int bidirectional, uint64_t *stream_id);
int quic_api_conn_stream_write(quic_api_conn_t *conn,
                               uint64_t stream_id,
                               const uint8_t *data,
                               size_t len,
                               int fin);
int quic_api_conn_stream_read(quic_api_conn_t *conn,
                              uint64_t stream_id,
                              uint8_t *out,
                              size_t out_cap,
                              size_t *out_read,
                              int *out_fin);
int quic_api_conn_stream_peek(const quic_api_conn_t *conn,
                              uint64_t stream_id,
                              size_t *available,
                              int *fin,
                              int *exists);
int quic_api_conn_stop_sending(quic_api_conn_t *conn, uint64_t stream_id, uint64_t error_code);
int quic_api_conn_reset_stream(quic_api_conn_t *conn, uint64_t stream_id, uint64_t error_code);
void quic_api_conn_queue_ping(quic_api_conn_t *conn);
int quic_api_conn_close(quic_api_conn_t *conn, uint64_t transport_error_code);
int quic_api_conn_handshake_complete(const quic_api_conn_t *conn);
const char *quic_api_conn_last_error(const quic_api_conn_t *conn);
int quic_api_conn_get_metrics(quic_api_conn_t *conn, quic_api_metrics_t *out_metrics);
int quic_api_conn_poll_event(quic_api_conn_t *conn, quic_api_event_t *out_event);
const char *quic_api_event_name(quic_api_event_type_t type);
int quic_api_event_format_json(const quic_api_event_t *event, char *out, size_t out_cap);
const quic_tls_conn_t *quic_api_conn_raw(const quic_api_conn_t *conn);

#endif // QUIC_API_H
