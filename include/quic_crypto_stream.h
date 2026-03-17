#ifndef QUIC_CRYPTO_STREAM_H
#define QUIC_CRYPTO_STREAM_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    uint8_t *present;
    size_t capacity;
    size_t end_offset;
    size_t next_read_offset;
} quic_crypto_recvbuf_t;

typedef struct {
    uint8_t *data;
    size_t len;
    size_t capacity;
    size_t flight_start;
    size_t flight_end;
    size_t send_offset;
    uint8_t flight_pending;
} quic_crypto_sendbuf_t;

void quic_crypto_recvbuf_init(quic_crypto_recvbuf_t *buf);
void quic_crypto_recvbuf_free(quic_crypto_recvbuf_t *buf);
int quic_crypto_recvbuf_insert(quic_crypto_recvbuf_t *buf, uint64_t offset, const uint8_t *data, size_t len);
size_t quic_crypto_recvbuf_contiguous_len(const quic_crypto_recvbuf_t *buf);
const uint8_t *quic_crypto_recvbuf_read_ptr(const quic_crypto_recvbuf_t *buf);
void quic_crypto_recvbuf_consume(quic_crypto_recvbuf_t *buf, size_t len);

void quic_crypto_sendbuf_init(quic_crypto_sendbuf_t *buf);
void quic_crypto_sendbuf_free(quic_crypto_sendbuf_t *buf);
int quic_crypto_sendbuf_append(quic_crypto_sendbuf_t *buf, const uint8_t *data, size_t len);
void quic_crypto_sendbuf_mark_flight(quic_crypto_sendbuf_t *buf);
int quic_crypto_sendbuf_has_pending(const quic_crypto_sendbuf_t *buf);
size_t quic_crypto_sendbuf_pending_offset(const quic_crypto_sendbuf_t *buf);
size_t quic_crypto_sendbuf_flight_end(const quic_crypto_sendbuf_t *buf);
void quic_crypto_sendbuf_advance(quic_crypto_sendbuf_t *buf, size_t len);
void quic_crypto_sendbuf_restart_flight(quic_crypto_sendbuf_t *buf);

#endif // QUIC_CRYPTO_STREAM_H：头文件保护结束
