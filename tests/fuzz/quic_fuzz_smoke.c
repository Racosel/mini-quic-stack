#include "pkt_decode.h"
#include "quic_ack.h"
#include "quic_frame.h"
#include "quic_stream.h"
#include "quic_transport_params.h"
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    const uint8_t *data;
    size_t len;
    const char *name;
} fuzz_seed_t;

static uint32_t fuzz_next(uint32_t *state) {
    *state = (*state * 1664525U) + 1013904223U;
    return *state;
}

static void mutate_bytes(uint8_t *dst, const uint8_t *src, size_t len, uint32_t *state) {
    size_t i;

    memcpy(dst, src, len);
    for (i = 0; i < len; i++) {
        uint32_t r = fuzz_next(state);

        if ((r & 3U) == 0U) {
            dst[i] ^= (uint8_t)(r >> 24);
        }
        if ((r & 0x1fU) == 7U) {
            dst[i] = (uint8_t)r;
        }
    }
}

static void exercise_pkt_decode(const uint8_t *data, size_t len) {
    quic_pkt_header_meta_t meta;

    (void)quic_parse_header_meta(data, len, &meta);
}

static void exercise_frames(const uint8_t *data, size_t len) {
    (void)quic_parse_frames(data, len);
}

static void exercise_transport_params(const uint8_t *data, size_t len) {
    quic_transport_params_t params;
    uint8_t encoded[512];

    quic_transport_params_init(&params);
    if (quic_transport_params_decode(data, len, &params) == 0) {
        (void)quic_transport_params_encode(&params, encoded, sizeof(encoded));
    }
}

static void exercise_ack(const uint8_t *data, size_t len) {
    quic_ack_frame_t ack;
    quic_ack_range_t ranges[QUIC_MAX_ACK_RANGES];
    size_t consumed = 0;
    size_t range_count = 0;
    size_t written = 0;
    uint8_t encoded[256];
    size_t i;

    if (quic_ack_parse_frame(data, len, &ack, &consumed) == 0) {
        (void)quic_ack_encode_frame(&ack, encoded, sizeof(encoded), &written);
    }

    quic_ack_ranges_init(ranges, &range_count);
    for (i = 0; i < len && i < 16; i++) {
        (void)quic_ack_note_received(ranges, &range_count, ((uint64_t)data[i] << 1) | (uint64_t)(i & 1U));
    }
    if (quic_ack_frame_from_ranges(ranges, range_count, &ack) == 0) {
        (void)quic_ack_encode_frame(&ack, encoded, sizeof(encoded), &written);
    }
}

static void exercise_stream_map(const uint8_t *data, size_t len) {
    quic_stream_map_t map;
    char err[128];
    uint8_t readbuf[256];
    size_t used = 0;
    uint64_t stream_id = UINT64_MAX;
    size_t i;

    quic_stream_map_init(&map, 1);
    quic_stream_map_set_local_limits(&map, 64 * 1024, 32 * 1024, 32 * 1024, 32 * 1024, 8, 8);
    quic_stream_map_set_peer_limits(&map, 64 * 1024, 32 * 1024, 32 * 1024, 32 * 1024, 8, 8);

    if (quic_stream_map_open(&map, 1, &stream_id) == 0) {
        size_t write_len = len > 64 ? 64 : len;

        (void)quic_stream_map_write(&map, stream_id, data, write_len, len > 0 ? 1 : 0, err, sizeof(err));
        if (quic_stream_map_has_buffered_send_data(&map)) {
            quic_stream_t *stream = NULL;
            uint64_t offset = 0;
            size_t out_len = 0;
            int fin_only = 0;
            int is_retransmit = 0;

            if (quic_stream_map_prepare_stream_send(&map,
                                                   &stream,
                                                   &offset,
                                                   &out_len,
                                                   &fin_only,
                                                   &is_retransmit) == 0 &&
                stream) {
                quic_stream_map_note_stream_send(&map, stream, offset, out_len, fin_only, is_retransmit);
                quic_stream_map_on_stream_lost(&map, stream->id, offset, out_len);
                quic_stream_map_on_stream_acked(&map, stream->id, offset, out_len);
            }
        }
    }

    for (i = 0; i < len; i += 7) {
        uint64_t offset = len == 0 ? 0 : (uint64_t)(data[i] % 64U);
        size_t chunk = len - i;
        int fin = 0;

        if (chunk > 12) {
            chunk = 12;
        }
        if (chunk == 0) {
            break;
        }
        if (i + chunk >= len) {
            fin = 1;
        }
        (void)quic_stream_map_on_stream(&map, 0, offset, data + i, chunk, fin, err, sizeof(err));
    }

    for (;;) {
        size_t available = 0;
        size_t out_read = 0;
        int fin = 0;
        int exists = 0;

        if (quic_stream_map_peek(&map, 0, &available, &fin, &exists) != 0 || !exists) {
            break;
        }
        if (available == 0 && !fin) {
            break;
        }
        if (available > sizeof(readbuf)) {
            available = sizeof(readbuf);
        }
        if (quic_stream_map_read(&map, 0, readbuf, available == 0 ? sizeof(readbuf) : available, &out_read, &fin, err, sizeof(err)) != 0) {
            break;
        }
        used += out_read;
        if (fin || out_read == 0) {
            break;
        }
    }

    (void)used;
    quic_stream_map_free(&map);
}

static void run_seed(const fuzz_seed_t *seed, uint32_t *state) {
    uint8_t buffer[512];
    size_t i;

    assert(seed);
    assert(seed->len <= sizeof(buffer));

    exercise_pkt_decode(seed->data, seed->len);
    exercise_frames(seed->data, seed->len);
    exercise_transport_params(seed->data, seed->len);
    exercise_ack(seed->data, seed->len);
    exercise_stream_map(seed->data, seed->len);

    for (i = 0; i < 64; i++) {
        mutate_bytes(buffer, seed->data, seed->len, state);
        exercise_pkt_decode(buffer, seed->len);
        exercise_frames(buffer, seed->len);
        exercise_transport_params(buffer, seed->len);
        exercise_ack(buffer, seed->len);
        exercise_stream_map(buffer, seed->len);
    }
}

int main(void) {
    static const uint8_t seed_ack[] = {0x02, 0x00, 0x00, 0x00, 0x00};
    static const uint8_t seed_stream[] = {0x08, 0x00, 'f', 'u', 'z', 'z'};
    static const uint8_t seed_crypto[] = {0x06, 0x00, 0x01, 0xaa};
    static const uint8_t seed_tp[] = {0x01, 0x01, 0x00, 0x0e, 0x01, 0x04};
    static const uint8_t seed_initial[] = {
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
        0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x00, 0x01, 0x00
    };
    static const fuzz_seed_t seeds[] = {
        {seed_ack, sizeof(seed_ack), "ack"},
        {seed_stream, sizeof(seed_stream), "stream"},
        {seed_crypto, sizeof(seed_crypto), "crypto"},
        {seed_tp, sizeof(seed_tp), "transport_params"},
        {seed_initial, sizeof(seed_initial), "initial"}
    };
    uint32_t state = 0x5a17c0deU;
    int saved_stdout = -1;
    int devnull = -1;
    size_t i;

    fflush(stdout);
    saved_stdout = dup(STDOUT_FILENO);
    devnull = open("/dev/null", O_WRONLY);
    if (saved_stdout >= 0 && devnull >= 0) {
        (void)dup2(devnull, STDOUT_FILENO);
    }

    for (i = 0; i < sizeof(seeds) / sizeof(seeds[0]); i++) {
        run_seed(&seeds[i], &state);
    }

    fflush(stdout);
    if (saved_stdout >= 0) {
        (void)dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }
    if (devnull >= 0) {
        close(devnull);
    }

    printf("[PASS] Stage 6 fuzz smoke harness covered packet/frame/tp/ack/stream surfaces across %zu seeds\n",
           sizeof(seeds) / sizeof(seeds[0]));
    return 0;
}
