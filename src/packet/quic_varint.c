#include "quic_varint.h"

int quic_decode_varint(const uint8_t *data, size_t max_len, size_t *offset, uint64_t *out_val) {
    if (*offset >= max_len) return -1;

    uint8_t first_byte = data[*offset];
    uint8_t len_prefix = (first_byte & 0xc0) >> 6;
    size_t length = 1 << len_prefix; // 1, 2, 4, or 8 bytes

    if (*offset + length > max_len) return -1;

    uint64_t val = first_byte & 0x3f;
    for (size_t i = 1; i < length; i++) {
        val = (val << 8) + data[*offset + i];
    }

    *out_val = val;
    *offset += length;
    return 0;
}