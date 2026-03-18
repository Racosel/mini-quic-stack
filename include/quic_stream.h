#ifndef QUIC_STREAM_H
#define QUIC_STREAM_H

#include "quic_crypto_stream.h"
#include <stddef.h>
#include <stdint.h>

#define QUIC_STREAM_MAX_COUNT 32
#define QUIC_STREAM_MAX_RETRANSMIT_RANGES 32

typedef struct {
    uint64_t start;
    uint64_t end;
} quic_stream_send_range_t;

typedef struct {
    uint8_t active;
    uint8_t local_initiated;
    uint8_t bidirectional;
    uint8_t send_open;
    uint8_t recv_open;
    uint8_t fin_requested;
    uint8_t fin_sent;
    uint8_t fin_in_flight;
    uint8_t fin_received;
    uint8_t stop_sending_pending;
    uint8_t stop_sending_in_flight;
    uint8_t stop_sending_received;
    uint8_t reset_pending;
    uint8_t reset_in_flight;
    uint8_t reset_received;
    uint8_t max_stream_data_pending;
    uint8_t max_stream_data_in_flight;
    uint8_t retired_for_streams_credit;
    uint64_t id;
    uint64_t send_max_data;
    uint64_t send_highest_offset;
    uint64_t send_final_size;
    uint8_t send_final_size_known;
    uint64_t recv_max_data;
    uint64_t recv_window_size;
    uint64_t recv_highest_offset;
    uint64_t recv_consumed_offset;
    uint64_t recv_final_size;
    uint8_t recv_final_size_known;
    uint64_t stop_error_code;
    uint64_t reset_error_code;
    uint64_t max_stream_data_to_send;
    quic_stream_send_range_t retransmit_ranges[QUIC_STREAM_MAX_RETRANSMIT_RANGES];
    size_t retransmit_range_count;
    quic_crypto_sendbuf_t sendbuf;
    quic_crypto_recvbuf_t recvbuf;
} quic_stream_t;

typedef struct {
    quic_stream_t streams[QUIC_STREAM_MAX_COUNT];
    uint8_t is_client;
    uint8_t local_limits_ready;
    uint8_t peer_limits_ready;
    uint64_t next_local_bidi_id;
    uint64_t next_local_uni_id;
    uint64_t local_bidi_local_limit;
    uint64_t local_bidi_remote_limit;
    uint64_t local_uni_limit;
    uint64_t peer_bidi_local_limit;
    uint64_t peer_bidi_remote_limit;
    uint64_t peer_uni_limit;
    uint64_t max_local_bidi_streams;
    uint64_t max_local_uni_streams;
    uint64_t max_remote_bidi_streams;
    uint64_t max_remote_uni_streams;
    uint64_t opened_local_bidi;
    uint64_t opened_local_uni;
    uint64_t opened_remote_bidi;
    uint64_t opened_remote_uni;
    uint64_t send_connection_max_data;
    uint64_t send_connection_highest;
    uint64_t recv_connection_max_data;
    uint64_t recv_connection_window_size;
    uint64_t recv_connection_highest;
    uint64_t recv_connection_consumed;
    uint8_t max_data_pending;
    uint8_t max_data_in_flight;
    uint64_t max_data_to_send;
    uint8_t max_streams_bidi_pending;
    uint8_t max_streams_bidi_in_flight;
    uint8_t max_streams_uni_pending;
    uint8_t max_streams_uni_in_flight;
    uint64_t max_streams_bidi_to_send;
    uint64_t max_streams_uni_to_send;
} quic_stream_map_t;

void quic_stream_map_init(quic_stream_map_t *map, int is_client);
void quic_stream_map_free(quic_stream_map_t *map);

void quic_stream_map_set_local_limits(quic_stream_map_t *map,
                                      uint64_t max_data,
                                      uint64_t bidi_local,
                                      uint64_t bidi_remote,
                                      uint64_t uni,
                                      uint64_t max_streams_bidi,
                                      uint64_t max_streams_uni);
void quic_stream_map_set_peer_limits(quic_stream_map_t *map,
                                     uint64_t max_data,
                                     uint64_t bidi_local,
                                     uint64_t bidi_remote,
                                     uint64_t uni,
                                     uint64_t max_streams_bidi,
                                     uint64_t max_streams_uni);

quic_stream_t *quic_stream_map_find(quic_stream_map_t *map, uint64_t stream_id);
const quic_stream_t *quic_stream_map_find_const(const quic_stream_map_t *map, uint64_t stream_id);

int quic_stream_map_open(quic_stream_map_t *map, int bidirectional, uint64_t *stream_id);
int quic_stream_map_write(quic_stream_map_t *map,
                          uint64_t stream_id,
                          const uint8_t *data,
                          size_t len,
                          int fin,
                          char *err,
                          size_t err_len);
int quic_stream_map_read(quic_stream_map_t *map,
                         uint64_t stream_id,
                         uint8_t *out,
                         size_t out_cap,
                         size_t *out_read,
                         int *out_fin,
                         char *err,
                         size_t err_len);
int quic_stream_map_peek(const quic_stream_map_t *map,
                         uint64_t stream_id,
                         size_t *available,
                         int *fin,
                         int *exists);
int quic_stream_map_stop_sending(quic_stream_map_t *map,
                                 uint64_t stream_id,
                                 uint64_t error_code,
                                 char *err,
                                 size_t err_len);
int quic_stream_map_reset(quic_stream_map_t *map,
                          uint64_t stream_id,
                          uint64_t error_code,
                          char *err,
                          size_t err_len);

int quic_stream_map_on_stream(quic_stream_map_t *map,
                              uint64_t stream_id,
                              uint64_t offset,
                              const uint8_t *data,
                              size_t len,
                              int fin,
                              char *err,
                              size_t err_len);
int quic_stream_map_on_reset_stream(quic_stream_map_t *map,
                                    uint64_t stream_id,
                                    uint64_t error_code,
                                    uint64_t final_size,
                                    char *err,
                                    size_t err_len);
int quic_stream_map_on_stop_sending(quic_stream_map_t *map,
                                    uint64_t stream_id,
                                    uint64_t error_code,
                                    char *err,
                                    size_t err_len);
int quic_stream_map_on_max_data(quic_stream_map_t *map, uint64_t max_data);
int quic_stream_map_on_max_stream_data(quic_stream_map_t *map,
                                       uint64_t stream_id,
                                       uint64_t max_data,
                                       char *err,
                                       size_t err_len);
int quic_stream_map_on_max_streams(quic_stream_map_t *map, int bidirectional, uint64_t max_streams);

int quic_stream_map_has_pending_output(const quic_stream_map_t *map);
int quic_stream_map_has_buffered_send_data(const quic_stream_map_t *map);
int quic_stream_map_is_flow_control_limited(const quic_stream_map_t *map);
int quic_stream_map_prepare_stream_send(quic_stream_map_t *map,
                                        quic_stream_t **out_stream,
                                        uint64_t *out_offset,
                                        size_t *out_len,
                                        int *out_fin_only,
                                        int *out_is_retransmit);
void quic_stream_map_note_stream_send(quic_stream_map_t *map,
                                      quic_stream_t *stream,
                                      uint64_t offset,
                                      size_t len,
                                      int fin,
                                      int is_retransmit);
void quic_stream_map_on_stream_acked(quic_stream_map_t *map,
                                     uint64_t stream_id,
                                     uint64_t offset,
                                     size_t len);
void quic_stream_map_on_stream_lost(quic_stream_map_t *map,
                                    uint64_t stream_id,
                                    uint64_t offset,
                                    size_t len);
void quic_stream_map_restart_flights(quic_stream_map_t *map);

#endif // QUIC_STREAM_H
