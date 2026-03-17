#include "quic_varint.h"

int quic_decode_varint(const uint8_t *data, size_t max_len, size_t *offset, uint64_t *out_val) {
    if (*offset >= max_len) return -1;

    uint8_t first_byte = data[*offset];
    uint8_t len_prefix = (first_byte & 0xc0) >> 6;
    size_t length = 1 << len_prefix; // 长度只能是 1、2、4 或 8 字节

    if (*offset + length > max_len) return -1;

    uint64_t val = first_byte & 0x3f;
    for (size_t i = 1; i < length; i++) {
        val = (val << 8) + data[*offset + i];
    }

    *out_val = val;
    *offset += length;
    return 0;
}

size_t quic_varint_size(uint64_t val) {
    if (val <= 63) {
        return 1;
    }
    if (val <= 16383) {
        return 2;
    }
    if (val <= 1073741823ULL) {
        return 4;
    }
    if (val <= 4611686018427387903ULL) {
        return 8;
    }
    return 0;
}

int quic_encode_varint(uint64_t val, uint8_t *out, size_t out_len) {
    size_t len = quic_varint_size(val);
    if (len == 0 || out_len < len) {
        return -1;
    }

    switch (len) {
        case 1:
            out[0] = (uint8_t)val;
            return 1;
        case 2:
            out[0] = 0x40 | (uint8_t)(val >> 8);
            out[1] = (uint8_t)val;
            return 2;
        case 4:
            out[0] = 0x80 | (uint8_t)(val >> 24);
            out[1] = (uint8_t)(val >> 16);
            out[2] = (uint8_t)(val >> 8);
            out[3] = (uint8_t)val;
            return 4;
        case 8:
            out[0] = 0xC0 | (uint8_t)(val >> 56);
            out[1] = (uint8_t)(val >> 48);
            out[2] = (uint8_t)(val >> 40);
            out[3] = (uint8_t)(val >> 32);
            out[4] = (uint8_t)(val >> 24);
            out[5] = (uint8_t)(val >> 16);
            out[6] = (uint8_t)(val >> 8);
            out[7] = (uint8_t)val;
            return 8;
        default:
            return -1;
    }
}
