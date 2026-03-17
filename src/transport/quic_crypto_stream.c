#include "quic_crypto_stream.h"
#include <stdlib.h>
#include <string.h>

static int quic_crypto_reserve_bytes(uint8_t **ptr,
                                     size_t current_capacity,
                                     size_t required,
                                     size_t *new_capacity) {
    uint8_t *resized;
    size_t next_capacity;

    if (*ptr && current_capacity >= required) {
        *new_capacity = current_capacity;
        return 0;
    }

    next_capacity = (current_capacity == 0) ? 256 : current_capacity;
    while (next_capacity < required) {
        next_capacity *= 2;
    }

    resized = (uint8_t *)realloc(*ptr, next_capacity);
    if (!resized) {
        return -1;
    }

    if (next_capacity > current_capacity) {
        memset(resized + current_capacity, 0, next_capacity - current_capacity);
    }

    *ptr = resized;
    *new_capacity = next_capacity;
    return 0;
}

void quic_crypto_recvbuf_init(quic_crypto_recvbuf_t *buf) {
    if (!buf) {
        return;
    }
    memset(buf, 0, sizeof(*buf));
}

void quic_crypto_recvbuf_free(quic_crypto_recvbuf_t *buf) {
    if (!buf) {
        return;
    }
    free(buf->data);
    free(buf->present);
    memset(buf, 0, sizeof(*buf));
}

int quic_crypto_recvbuf_insert(quic_crypto_recvbuf_t *buf, uint64_t offset, const uint8_t *data, size_t len) {
    size_t required;
    size_t next_capacity;

    if (!buf || (!data && len != 0)) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    if (offset > SIZE_MAX || len > SIZE_MAX - (size_t)offset) {
        return -1;
    }

    required = (size_t)offset + len;
    if (quic_crypto_reserve_bytes(&buf->data,
                                  buf->data ? buf->capacity : 0,
                                  required,
                                  &next_capacity) != 0) {
        return -1;
    }
    if (quic_crypto_reserve_bytes(&buf->present,
                                  buf->present ? buf->capacity : 0,
                                  required,
                                  &next_capacity) != 0) {
        return -1;
    }
    buf->capacity = next_capacity;

    memcpy(buf->data + offset, data, len);
    memset(buf->present + offset, 1, len);
    if (required > buf->end_offset) {
        buf->end_offset = required;
    }
    return 0;
}

size_t quic_crypto_recvbuf_contiguous_len(const quic_crypto_recvbuf_t *buf) {
    size_t cursor;

    if (!buf || !buf->present || buf->next_read_offset >= buf->end_offset) {
        return 0;
    }

    cursor = buf->next_read_offset;
    while (cursor < buf->end_offset && buf->present[cursor] != 0) {
        cursor++;
    }
    return cursor - buf->next_read_offset;
}

const uint8_t *quic_crypto_recvbuf_read_ptr(const quic_crypto_recvbuf_t *buf) {
    if (!buf || !buf->data || buf->next_read_offset >= buf->end_offset) {
        return NULL;
    }
    return buf->data + buf->next_read_offset;
}

void quic_crypto_recvbuf_consume(quic_crypto_recvbuf_t *buf, size_t len) {
    if (!buf) {
        return;
    }
    if (len > buf->end_offset - buf->next_read_offset) {
        len = buf->end_offset - buf->next_read_offset;
    }
    buf->next_read_offset += len;
}

void quic_crypto_sendbuf_init(quic_crypto_sendbuf_t *buf) {
    if (!buf) {
        return;
    }
    memset(buf, 0, sizeof(*buf));
}

void quic_crypto_sendbuf_free(quic_crypto_sendbuf_t *buf) {
    if (!buf) {
        return;
    }
    free(buf->data);
    memset(buf, 0, sizeof(*buf));
}

int quic_crypto_sendbuf_append(quic_crypto_sendbuf_t *buf, const uint8_t *data, size_t len) {
    size_t next_capacity;

    if (!buf || (!data && len != 0)) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    if (len > SIZE_MAX - buf->len) {
        return -1;
    }
    if (quic_crypto_reserve_bytes(&buf->data, buf->capacity, buf->len + len, &next_capacity) != 0) {
        return -1;
    }
    buf->capacity = next_capacity;

    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return 0;
}

void quic_crypto_sendbuf_mark_flight(quic_crypto_sendbuf_t *buf) {
    if (!buf || buf->len <= buf->flight_end) {
        return;
    }

    buf->flight_start = buf->flight_end;
    buf->flight_end = buf->len;
    buf->send_offset = buf->flight_start;
    buf->flight_pending = 1;
}

int quic_crypto_sendbuf_has_pending(const quic_crypto_sendbuf_t *buf) {
    if (!buf || !buf->flight_pending) {
        return 0;
    }
    return buf->send_offset < buf->flight_end;
}

size_t quic_crypto_sendbuf_pending_offset(const quic_crypto_sendbuf_t *buf) {
    return buf ? buf->send_offset : 0;
}

size_t quic_crypto_sendbuf_flight_end(const quic_crypto_sendbuf_t *buf) {
    return buf ? buf->flight_end : 0;
}

void quic_crypto_sendbuf_advance(quic_crypto_sendbuf_t *buf, size_t len) {
    if (!buf) {
        return;
    }
    if (len > buf->flight_end - buf->send_offset) {
        len = buf->flight_end - buf->send_offset;
    }
    buf->send_offset += len;
}

void quic_crypto_sendbuf_restart_flight(quic_crypto_sendbuf_t *buf) {
    if (!buf || !buf->flight_pending) {
        return;
    }
    buf->send_offset = buf->flight_start;
}
