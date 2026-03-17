#ifndef QUIC_INITIAL_H
#define QUIC_INITIAL_H

#include "pkt_decode.h"
#include "quic_version.h"
#include <stddef.h>
#include <stdint.h>

typedef struct {
    quic_pkt_header_meta_t meta;
    const quic_version_ops_t *version_ops;
    uint64_t token_length;
    const uint8_t *token;
    uint64_t length;
    size_t pn_offset;
} quic_initial_header_t;

int quic_parse_initial_header(const uint8_t *packet, size_t packet_len, quic_initial_header_t *out);

#endif // QUIC_INITIAL_H：头文件保护结束
