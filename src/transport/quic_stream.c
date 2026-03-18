#include "quic_stream.h"
#include <stdio.h>
#include <string.h>

static void quic_stream_set_error(char *err, size_t err_len, const char *message) {
    if (!err || err_len == 0 || !message) {
        return;
    }
    snprintf(err, err_len, "%s", message);
}

static int quic_stream_has_send_side(const quic_stream_t *stream) {
    return stream && (stream->bidirectional || stream->local_initiated);
}

static int quic_stream_is_local_initiated(const quic_stream_map_t *map, uint64_t stream_id) {
    uint8_t initiator_bit = (uint8_t)(stream_id & 0x01);
    return map && ((map->is_client && initiator_bit == 0) || (!map->is_client && initiator_bit == 1));
}

static int quic_stream_is_bidirectional(uint64_t stream_id) {
    return (stream_id & 0x02) == 0;
}

static uint64_t quic_stream_count_for_id(uint64_t stream_id) {
    return (stream_id / 4) + 1;
}

static uint64_t quic_stream_initial_send_limit(const quic_stream_map_t *map,
                                               int local_initiated,
                                               int bidirectional) {
    if (!map) {
        return 0;
    }
    if (!bidirectional) {
        return local_initiated ? map->peer_uni_limit : 0;
    }
    return local_initiated ? map->peer_bidi_remote_limit : map->peer_bidi_local_limit;
}

static uint64_t quic_stream_initial_recv_limit(const quic_stream_map_t *map,
                                               int local_initiated,
                                               int bidirectional) {
    if (!map) {
        return 0;
    }
    if (!bidirectional) {
        return local_initiated ? 0 : map->local_uni_limit;
    }
    return local_initiated ? map->local_bidi_local_limit : map->local_bidi_remote_limit;
}

static int quic_stream_can_accept_write(const quic_stream_t *stream) {
    return quic_stream_has_send_side(stream) &&
           stream->send_open &&
           !stream->fin_requested &&
           !stream->reset_pending &&
           !stream->reset_received;
}

static int quic_stream_can_transmit(const quic_stream_t *stream) {
    return quic_stream_has_send_side(stream) &&
           !stream->reset_pending &&
           !stream->reset_received &&
           (stream->send_open ||
            stream->sendbuf.flight_pending ||
            stream->sendbuf.len > stream->sendbuf.flight_end ||
            (stream->fin_requested && !stream->fin_sent) ||
            stream->fin_in_flight);
}

static int quic_stream_can_receive(const quic_stream_t *stream) {
    return stream && stream->recv_open && !stream->reset_received;
}

static int quic_stream_maybe_discard_terminal_recv(const quic_stream_t *stream,
                                                   uint64_t end_offset,
                                                   int fin,
                                                   char *err,
                                                   size_t err_len) {
    if (!stream || stream->recv_open || !stream->recv_final_size_known) {
        return 0;
    }
    if (fin && stream->recv_final_size != end_offset) {
        quic_stream_set_error(err, err_len, "stream final size changed");
        return -1;
    }
    if (end_offset > stream->recv_final_size) {
        quic_stream_set_error(err, err_len, "stream data exceeded final size");
        return -1;
    }

    // RFC 9000 3.2: once all stream data has been received, later STREAM
    // retransmissions for that final size can be discarded silently.
    return 1;
}

static size_t quic_stream_send_candidate_len(const quic_stream_map_t *map, const quic_stream_t *stream) {
    size_t pending;
    uint64_t start;
    uint64_t already_accounted = 0;
    uint64_t conn_credit;
    uint64_t stream_credit;
    uint64_t new_credit;
    uint64_t candidate;

    if (!map || !stream || !quic_stream_can_transmit(stream)) {
        return 0;
    }

    if (quic_crypto_sendbuf_has_pending(&stream->sendbuf)) {
        pending = stream->sendbuf.flight_end - stream->sendbuf.send_offset;
        start = stream->sendbuf.send_offset;
    } else if (stream->sendbuf.len > stream->sendbuf.flight_end) {
        pending = stream->sendbuf.len - stream->sendbuf.flight_end;
        start = stream->sendbuf.flight_end;
    } else {
        return 0;
    }

    if (start < stream->send_highest_offset) {
        already_accounted = stream->send_highest_offset - start;
        if (already_accounted > pending) {
            already_accounted = pending;
        }
    }

    conn_credit = map->send_connection_max_data > map->send_connection_highest
                      ? map->send_connection_max_data - map->send_connection_highest
                      : 0;
    stream_credit = stream->send_max_data > stream->send_highest_offset
                        ? stream->send_max_data - stream->send_highest_offset
                        : 0;
    new_credit = conn_credit < stream_credit ? conn_credit : stream_credit;
    candidate = already_accounted + new_credit;
    if (candidate > pending) {
        candidate = pending;
    }
    return (size_t)candidate;
}

static quic_stream_t *quic_stream_alloc(quic_stream_map_t *map,
                                        uint64_t stream_id,
                                        int local_initiated,
                                        int bidirectional) {
    size_t i;
    quic_stream_t *stream;

    if (!map) {
        return NULL;
    }

    for (i = 0; i < QUIC_STREAM_MAX_COUNT; i++) {
        if (!map->streams[i].active) {
            stream = &map->streams[i];
            memset(stream, 0, sizeof(*stream));
            stream->active = 1;
            stream->id = stream_id;
            stream->local_initiated = (uint8_t)(local_initiated ? 1 : 0);
            stream->bidirectional = (uint8_t)(bidirectional ? 1 : 0);
            stream->send_open = (uint8_t)((bidirectional || local_initiated) ? 1 : 0);
            stream->recv_open = (uint8_t)((bidirectional || !local_initiated) ? 1 : 0);
            stream->send_max_data = quic_stream_initial_send_limit(map, local_initiated, bidirectional);
            stream->recv_max_data = quic_stream_initial_recv_limit(map, local_initiated, bidirectional);
            stream->recv_window_size = stream->recv_max_data;
            stream->max_stream_data_to_send = stream->recv_max_data;
            quic_crypto_sendbuf_init(&stream->sendbuf);
            quic_crypto_recvbuf_init(&stream->recvbuf);
            return stream;
        }
    }

    return NULL;
}

static int quic_stream_open_remote(quic_stream_map_t *map,
                                   uint64_t stream_id,
                                   char *err,
                                   size_t err_len) {
    uint64_t needed_count;
    int bidirectional;

    if (!map) {
        quic_stream_set_error(err, err_len, "invalid stream map");
        return -1;
    }

    bidirectional = quic_stream_is_bidirectional(stream_id);
    needed_count = quic_stream_count_for_id(stream_id);

    if (quic_stream_is_local_initiated(map, stream_id)) {
        quic_stream_set_error(err, err_len, "remote frame referenced local-initiated stream");
        return -1;
    }

    if (bidirectional) {
        if (needed_count > map->max_remote_bidi_streams) {
            quic_stream_set_error(err, err_len, "remote opened bidirectional stream beyond limit");
            return -1;
        }
        if (needed_count > map->opened_remote_bidi) {
            map->opened_remote_bidi = needed_count;
        }
    } else {
        if (needed_count > map->max_remote_uni_streams) {
            quic_stream_set_error(err, err_len, "remote opened unidirectional stream beyond limit");
            return -1;
        }
        if (needed_count > map->opened_remote_uni) {
            map->opened_remote_uni = needed_count;
        }
    }

    if (!quic_stream_alloc(map, stream_id, 0, bidirectional)) {
        quic_stream_set_error(err, err_len, "stream table exhausted");
        return -1;
    }

    return 0;
}

static int quic_stream_maybe_raise_max_stream_data(quic_stream_t *stream) {
    uint64_t new_limit;

    if (!stream || !stream->recv_open || stream->recv_window_size == 0) {
        return 0;
    }
    if (stream->recv_max_data > stream->recv_consumed_offset &&
        stream->recv_max_data - stream->recv_consumed_offset > stream->recv_window_size / 2) {
        return 0;
    }

    new_limit = stream->recv_consumed_offset + stream->recv_window_size;
    if (new_limit <= stream->recv_max_data) {
        return 0;
    }

    stream->recv_max_data = new_limit;
    stream->max_stream_data_to_send = new_limit;
    stream->max_stream_data_pending = 1;
    return 0;
}

static void quic_stream_maybe_retire_remote(quic_stream_map_t *map, quic_stream_t *stream) {
    if (!map || !stream || stream->retired_for_streams_credit || stream->local_initiated) {
        return;
    }
    if (!stream->reset_received &&
        !(stream->recv_final_size_known && stream->recv_consumed_offset >= stream->recv_final_size)) {
        return;
    }

    stream->retired_for_streams_credit = 1;
    if (stream->bidirectional) {
        map->max_remote_bidi_streams++;
        map->max_streams_bidi_to_send = map->max_remote_bidi_streams;
        map->max_streams_bidi_pending = 1;
    } else {
        map->max_remote_uni_streams++;
        map->max_streams_uni_to_send = map->max_remote_uni_streams;
        map->max_streams_uni_pending = 1;
    }
}

void quic_stream_map_init(quic_stream_map_t *map, int is_client) {
    if (!map) {
        return;
    }
    memset(map, 0, sizeof(*map));
    map->is_client = (uint8_t)(is_client ? 1 : 0);
    map->next_local_bidi_id = is_client ? 0 : 1;
    map->next_local_uni_id = is_client ? 2 : 3;
}

void quic_stream_map_free(quic_stream_map_t *map) {
    size_t i;

    if (!map) {
        return;
    }

    for (i = 0; i < QUIC_STREAM_MAX_COUNT; i++) {
        if (!map->streams[i].active) {
            continue;
        }
        quic_crypto_sendbuf_free(&map->streams[i].sendbuf);
        quic_crypto_recvbuf_free(&map->streams[i].recvbuf);
    }
    memset(map, 0, sizeof(*map));
}

void quic_stream_map_set_local_limits(quic_stream_map_t *map,
                                      uint64_t max_data,
                                      uint64_t bidi_local,
                                      uint64_t bidi_remote,
                                      uint64_t uni,
                                      uint64_t max_streams_bidi,
                                      uint64_t max_streams_uni) {
    if (!map) {
        return;
    }
    map->local_limits_ready = 1;
    map->local_bidi_local_limit = bidi_local;
    map->local_bidi_remote_limit = bidi_remote;
    map->local_uni_limit = uni;
    map->recv_connection_max_data = max_data;
    map->recv_connection_window_size = max_data;
    map->max_remote_bidi_streams = max_streams_bidi;
    map->max_remote_uni_streams = max_streams_uni;
    map->max_streams_bidi_to_send = max_streams_bidi;
    map->max_streams_uni_to_send = max_streams_uni;
}

void quic_stream_map_set_peer_limits(quic_stream_map_t *map,
                                     uint64_t max_data,
                                     uint64_t bidi_local,
                                     uint64_t bidi_remote,
                                     uint64_t uni,
                                     uint64_t max_streams_bidi,
                                     uint64_t max_streams_uni) {
    if (!map) {
        return;
    }
    map->peer_limits_ready = 1;
    map->peer_bidi_local_limit = bidi_local;
    map->peer_bidi_remote_limit = bidi_remote;
    map->peer_uni_limit = uni;
    map->send_connection_max_data = max_data;
    map->max_local_bidi_streams = max_streams_bidi;
    map->max_local_uni_streams = max_streams_uni;
}

quic_stream_t *quic_stream_map_find(quic_stream_map_t *map, uint64_t stream_id) {
    size_t i;

    if (!map) {
        return NULL;
    }
    for (i = 0; i < QUIC_STREAM_MAX_COUNT; i++) {
        if (map->streams[i].active && map->streams[i].id == stream_id) {
            return &map->streams[i];
        }
    }
    return NULL;
}

const quic_stream_t *quic_stream_map_find_const(const quic_stream_map_t *map, uint64_t stream_id) {
    size_t i;

    if (!map) {
        return NULL;
    }
    for (i = 0; i < QUIC_STREAM_MAX_COUNT; i++) {
        if (map->streams[i].active && map->streams[i].id == stream_id) {
            return &map->streams[i];
        }
    }
    return NULL;
}

int quic_stream_map_open(quic_stream_map_t *map, int bidirectional, uint64_t *stream_id) {
    quic_stream_t *stream;

    if (!map || !stream_id || !map->peer_limits_ready) {
        return -1;
    }

    if (bidirectional) {
        if (map->opened_local_bidi >= map->max_local_bidi_streams) {
            return -1;
        }
        *stream_id = map->next_local_bidi_id;
        map->next_local_bidi_id += 4;
        map->opened_local_bidi++;
    } else {
        if (map->opened_local_uni >= map->max_local_uni_streams) {
            return -1;
        }
        *stream_id = map->next_local_uni_id;
        map->next_local_uni_id += 4;
        map->opened_local_uni++;
    }

    stream = quic_stream_alloc(map, *stream_id, 1, bidirectional);
    return stream ? 0 : -1;
}

int quic_stream_map_write(quic_stream_map_t *map,
                          uint64_t stream_id,
                          const uint8_t *data,
                          size_t len,
                          int fin,
                          char *err,
                          size_t err_len) {
    quic_stream_t *stream;

    stream = quic_stream_map_find(map, stream_id);
    if (!stream) {
        quic_stream_set_error(err, err_len, "stream does not exist");
        return -1;
    }
    if (!quic_stream_can_accept_write(stream)) {
        quic_stream_set_error(err, err_len, "stream send side is closed");
        return -1;
    }
    if (quic_crypto_sendbuf_append(&stream->sendbuf, data, len) != 0) {
        quic_stream_set_error(err, err_len, "failed to append stream data");
        return -1;
    }
    if (!quic_crypto_sendbuf_has_pending(&stream->sendbuf) &&
        stream->sendbuf.len > stream->sendbuf.flight_end) {
        quic_crypto_sendbuf_mark_flight(&stream->sendbuf);
    }
    if (fin) {
        stream->fin_requested = 1;
        stream->send_final_size_known = 1;
        stream->send_final_size = stream->sendbuf.len;
    }
    return 0;
}

int quic_stream_map_read(quic_stream_map_t *map,
                         uint64_t stream_id,
                         uint8_t *out,
                         size_t out_cap,
                         size_t *out_read,
                         int *out_fin,
                         char *err,
                         size_t err_len) {
    quic_stream_t *stream;
    size_t contiguous;
    size_t to_copy;

    if (!out_read || !out_fin) {
        quic_stream_set_error(err, err_len, "invalid stream read arguments");
        return -1;
    }

    *out_read = 0;
    *out_fin = 0;
    stream = quic_stream_map_find(map, stream_id);
    if (!stream) {
        quic_stream_set_error(err, err_len, "stream does not exist");
        return -1;
    }

    contiguous = quic_crypto_recvbuf_contiguous_len(&stream->recvbuf);
    to_copy = contiguous < out_cap ? contiguous : out_cap;
    if (to_copy > 0) {
        memcpy(out, quic_crypto_recvbuf_read_ptr(&stream->recvbuf), to_copy);
        quic_crypto_recvbuf_consume(&stream->recvbuf, to_copy);
        stream->recv_consumed_offset += to_copy;
        map->recv_connection_consumed += to_copy;
        quic_stream_maybe_raise_max_stream_data(stream);
        if (map->recv_connection_window_size > 0 &&
            (map->recv_connection_max_data <= map->recv_connection_consumed ||
             map->recv_connection_max_data - map->recv_connection_consumed <=
                 map->recv_connection_window_size / 2)) {
            map->recv_connection_max_data = map->recv_connection_consumed + map->recv_connection_window_size;
            map->max_data_to_send = map->recv_connection_max_data;
            map->max_data_pending = 1;
        }
    }

    if (stream->recv_final_size_known && stream->recv_consumed_offset >= stream->recv_final_size) {
        stream->fin_received = 1;
        stream->recv_open = 0;
        *out_fin = 1;
        quic_stream_maybe_retire_remote(map, stream);
    }

    *out_read = to_copy;
    return 0;
}

int quic_stream_map_peek(const quic_stream_map_t *map,
                         uint64_t stream_id,
                         size_t *available,
                         int *fin,
                         int *exists) {
    const quic_stream_t *stream;

    if (available) {
        *available = 0;
    }
    if (fin) {
        *fin = 0;
    }
    if (exists) {
        *exists = 0;
    }

    stream = quic_stream_map_find_const(map, stream_id);
    if (!stream) {
        return 0;
    }

    if (exists) {
        *exists = 1;
    }
    if (available) {
        *available = quic_crypto_recvbuf_contiguous_len(&stream->recvbuf);
    }
    if (fin) {
        *fin = (int)(stream->recv_final_size_known && stream->recv_consumed_offset >= stream->recv_final_size);
    }
    return 0;
}

int quic_stream_map_stop_sending(quic_stream_map_t *map,
                                 uint64_t stream_id,
                                 uint64_t error_code,
                                 char *err,
                                 size_t err_len) {
    quic_stream_t *stream = quic_stream_map_find(map, stream_id);

    if (!stream) {
        quic_stream_set_error(err, err_len, "stream does not exist");
        return -1;
    }
    if (!stream->recv_open && !stream->recv_final_size_known) {
        quic_stream_set_error(err, err_len, "stream receive side is unavailable");
        return -1;
    }
    stream->stop_sending_pending = 1;
    stream->stop_error_code = error_code;
    return 0;
}

int quic_stream_map_reset(quic_stream_map_t *map,
                          uint64_t stream_id,
                          uint64_t error_code,
                          char *err,
                          size_t err_len) {
    quic_stream_t *stream = quic_stream_map_find(map, stream_id);

    if (!stream) {
        quic_stream_set_error(err, err_len, "stream does not exist");
        return -1;
    }
    if (!quic_stream_has_send_side(stream) || stream->reset_pending || stream->reset_received) {
        quic_stream_set_error(err, err_len, "stream send side is unavailable");
        return -1;
    }
    stream->reset_pending = 1;
    stream->reset_error_code = error_code;
    stream->send_final_size_known = 1;
    stream->send_final_size = stream->send_highest_offset;
    stream->send_open = 0;
    return 0;
}

int quic_stream_map_on_stream(quic_stream_map_t *map,
                              uint64_t stream_id,
                              uint64_t offset,
                              const uint8_t *data,
                              size_t len,
                              int fin,
                              char *err,
                              size_t err_len) {
    quic_stream_t *stream;
    uint64_t end_offset;
    uint64_t delta = 0;

    if (!map) {
        quic_stream_set_error(err, err_len, "invalid stream map");
        return -1;
    }
    if (offset > UINT64_MAX - len) {
        quic_stream_set_error(err, err_len, "stream offset overflow");
        return -1;
    }
    end_offset = offset + len;

    stream = quic_stream_map_find(map, stream_id);
    if (!stream) {
        if (quic_stream_open_remote(map, stream_id, err, err_len) != 0) {
            return -1;
        }
        stream = quic_stream_map_find(map, stream_id);
    }
    if (!stream || !quic_stream_can_receive(stream)) {
        int discard = quic_stream_maybe_discard_terminal_recv(stream, end_offset, fin, err, err_len);

        if (discard > 0) {
            return 0;
        }
        if (discard < 0) {
            return -1;
        }
        quic_stream_set_error(err, err_len, "stream receive side is closed");
        return -1;
    }

    if (end_offset > stream->recv_max_data) {
        quic_stream_set_error(err, err_len, "stream flow control exceeded");
        return -1;
    }
    if (end_offset > stream->recv_highest_offset) {
        delta = end_offset - stream->recv_highest_offset;
        if (map->recv_connection_highest > UINT64_MAX - delta ||
            map->recv_connection_highest + delta > map->recv_connection_max_data) {
            quic_stream_set_error(err, err_len, "connection flow control exceeded");
            return -1;
        }
    }

    if (fin) {
        if (stream->recv_final_size_known && stream->recv_final_size != end_offset) {
            quic_stream_set_error(err, err_len, "stream final size changed");
            return -1;
        }
        if (stream->recv_highest_offset > end_offset) {
            quic_stream_set_error(err, err_len, "stream final size smaller than received offset");
            return -1;
        }
        stream->recv_final_size_known = 1;
        stream->recv_final_size = end_offset;
    } else if (stream->recv_final_size_known && end_offset > stream->recv_final_size) {
        quic_stream_set_error(err, err_len, "stream data exceeded final size");
        return -1;
    }

    if (quic_crypto_recvbuf_insert(&stream->recvbuf, offset, data, len) != 0) {
        quic_stream_set_error(err, err_len, "failed to buffer stream data");
        return -1;
    }
    if (delta > 0) {
        stream->recv_highest_offset = end_offset;
        map->recv_connection_highest += delta;
    }
    if (stream->recv_final_size_known && stream->recv_consumed_offset >= stream->recv_final_size) {
        stream->fin_received = 1;
        stream->recv_open = 0;
        quic_stream_maybe_retire_remote(map, stream);
    }
    return 0;
}

int quic_stream_map_on_reset_stream(quic_stream_map_t *map,
                                    uint64_t stream_id,
                                    uint64_t error_code,
                                    uint64_t final_size,
                                    char *err,
                                    size_t err_len) {
    quic_stream_t *stream;
    uint64_t delta = 0;

    if (!map) {
        quic_stream_set_error(err, err_len, "invalid stream map");
        return -1;
    }
    stream = quic_stream_map_find(map, stream_id);
    if (!stream) {
        if (quic_stream_open_remote(map, stream_id, err, err_len) != 0) {
            return -1;
        }
        stream = quic_stream_map_find(map, stream_id);
    }
    if (!stream || !stream->recv_open) {
        quic_stream_set_error(err, err_len, "reset stream receive side is unavailable");
        return -1;
    }
    if (final_size < stream->recv_highest_offset || final_size > stream->recv_max_data) {
        quic_stream_set_error(err, err_len, "invalid reset final size");
        return -1;
    }
    if (final_size > stream->recv_highest_offset) {
        delta = final_size - stream->recv_highest_offset;
        if (map->recv_connection_highest > UINT64_MAX - delta ||
            map->recv_connection_highest + delta > map->recv_connection_max_data) {
            quic_stream_set_error(err, err_len, "connection flow control exceeded");
            return -1;
        }
        stream->recv_highest_offset = final_size;
        map->recv_connection_highest += delta;
    }
    stream->recv_final_size_known = 1;
    stream->recv_final_size = final_size;
    stream->reset_received = 1;
    stream->reset_error_code = error_code;
    stream->recv_open = 0;
    quic_stream_maybe_retire_remote(map, stream);
    return 0;
}

int quic_stream_map_on_stop_sending(quic_stream_map_t *map,
                                    uint64_t stream_id,
                                    uint64_t error_code,
                                    char *err,
                                    size_t err_len) {
    quic_stream_t *stream = quic_stream_map_find(map, stream_id);

    if (!stream) {
        quic_stream_set_error(err, err_len, "stream does not exist");
        return -1;
    }
    if (!quic_stream_has_send_side(stream)) {
        quic_stream_set_error(err, err_len, "stop_sending on receive-only stream");
        return -1;
    }
    stream->stop_sending_received = 1;
    stream->reset_pending = 1;
    stream->reset_error_code = error_code;
    stream->send_final_size_known = 1;
    stream->send_final_size = stream->send_highest_offset;
    stream->send_open = 0;
    return 0;
}

int quic_stream_map_on_max_data(quic_stream_map_t *map, uint64_t max_data) {
    if (!map || max_data <= map->send_connection_max_data) {
        return 0;
    }
    map->send_connection_max_data = max_data;
    return 0;
}

int quic_stream_map_on_max_stream_data(quic_stream_map_t *map,
                                       uint64_t stream_id,
                                       uint64_t max_data,
                                       char *err,
                                       size_t err_len) {
    quic_stream_t *stream = quic_stream_map_find(map, stream_id);

    if (!stream) {
        quic_stream_set_error(err, err_len, "max_stream_data for unknown stream");
        return -1;
    }
    if (!quic_stream_has_send_side(stream)) {
        quic_stream_set_error(err, err_len, "max_stream_data on receive-only stream");
        return -1;
    }
    if (max_data > stream->send_max_data) {
        stream->send_max_data = max_data;
    }
    return 0;
}

int quic_stream_map_on_max_streams(quic_stream_map_t *map, int bidirectional, uint64_t max_streams) {
    if (!map) {
        return -1;
    }
    if (bidirectional) {
        if (max_streams > map->max_local_bidi_streams) {
            map->max_local_bidi_streams = max_streams;
        }
    } else if (max_streams > map->max_local_uni_streams) {
        map->max_local_uni_streams = max_streams;
    }
    return 0;
}

int quic_stream_map_has_pending_output(const quic_stream_map_t *map) {
    size_t i;

    if (!map) {
        return 0;
    }
    if (map->max_data_pending ||
        map->max_streams_bidi_pending ||
        map->max_streams_uni_pending) {
        return 1;
    }

    for (i = 0; i < QUIC_STREAM_MAX_COUNT; i++) {
        const quic_stream_t *stream = &map->streams[i];

        if (!stream->active) {
            continue;
        }
        if (stream->stop_sending_pending ||
            stream->reset_pending ||
            stream->max_stream_data_pending ||
            (stream->fin_requested && !stream->fin_sent &&
             !quic_crypto_sendbuf_has_pending(&stream->sendbuf) &&
             stream->sendbuf.send_offset >= stream->sendbuf.flight_end)) {
            return 1;
        }
        if (quic_stream_send_candidate_len(map, stream) > 0) {
            return 1;
        }
    }

    return 0;
}

int quic_stream_map_prepare_stream_send(quic_stream_map_t *map,
                                        quic_stream_t **out_stream,
                                        size_t *out_len,
                                        int *out_fin_only) {
    size_t i;

    if (out_stream) {
        *out_stream = NULL;
    }
    if (out_len) {
        *out_len = 0;
    }
    if (out_fin_only) {
        *out_fin_only = 0;
    }
    if (!map || !out_stream || !out_len || !out_fin_only) {
        return -1;
    }

    for (i = 0; i < QUIC_STREAM_MAX_COUNT; i++) {
        quic_stream_t *stream = &map->streams[i];
        size_t candidate;

        if (!stream->active || !quic_stream_can_transmit(stream)) {
            continue;
        }
        if (!quic_crypto_sendbuf_has_pending(&stream->sendbuf) &&
            stream->sendbuf.len > stream->sendbuf.flight_end) {
            quic_crypto_sendbuf_mark_flight(&stream->sendbuf);
        }
        if (!quic_crypto_sendbuf_has_pending(&stream->sendbuf)) {
            if (stream->fin_requested && !stream->fin_sent) {
                *out_stream = stream;
                *out_fin_only = 1;
                return 1;
            }
            continue;
        }

        candidate = quic_stream_send_candidate_len(map, stream);
        if (candidate == 0) {
            continue;
        }
        *out_stream = stream;
        *out_len = (size_t)candidate;
        return 1;
    }

    return 0;
}

void quic_stream_map_note_stream_send(quic_stream_map_t *map,
                                      quic_stream_t *stream,
                                      uint64_t offset,
                                      size_t len,
                                      int fin) {
    uint64_t end_offset;

    if (!map || !stream) {
        return;
    }

    end_offset = offset + len;
    if (end_offset > stream->send_highest_offset) {
        map->send_connection_highest += end_offset - stream->send_highest_offset;
        stream->send_highest_offset = end_offset;
    }

    if (len > 0) {
        quic_crypto_sendbuf_advance(&stream->sendbuf, len);
    }
    if (fin) {
        stream->fin_sent = 1;
        stream->fin_in_flight = 1;
        stream->send_open = 0;
        stream->send_final_size_known = 1;
        stream->send_final_size = stream->sendbuf.len;
    }
}

void quic_stream_map_restart_flights(quic_stream_map_t *map) {
    size_t i;

    if (!map) {
        return;
    }

    if (map->max_data_in_flight) {
        map->max_data_pending = 1;
    }
    if (map->max_streams_bidi_in_flight) {
        map->max_streams_bidi_pending = 1;
    }
    if (map->max_streams_uni_in_flight) {
        map->max_streams_uni_pending = 1;
    }

    for (i = 0; i < QUIC_STREAM_MAX_COUNT; i++) {
        quic_stream_t *stream = &map->streams[i];

        if (!stream->active) {
            continue;
        }
        quic_crypto_sendbuf_restart_flight(&stream->sendbuf);
        if (stream->fin_in_flight) {
            stream->fin_sent = 0;
        }
        if (stream->stop_sending_in_flight) {
            stream->stop_sending_pending = 1;
        }
        if (stream->reset_in_flight) {
            stream->reset_pending = 1;
        }
        if (stream->max_stream_data_in_flight) {
            stream->max_stream_data_pending = 1;
        }
    }
}
