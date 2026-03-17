#ifndef QUIC_PACKET_PROTECTION_H
#define QUIC_PACKET_PROTECTION_H

#include "quic_crypto.h"
#include <stddef.h>
#include <stdint.h>

#define QUIC_HP_MASK_LEN 5
#define QUIC_HP_SAMPLE_LEN 16
#define QUIC_AEAD_TAG_LEN 16

size_t quic_packet_number_encode_size(uint64_t full_pn, uint64_t largest_acked);
int quic_encode_packet_number(uint64_t full_pn, size_t pn_len, uint8_t *out, size_t out_len);
uint64_t quic_decode_packet_number(uint64_t largest_pn, uint64_t truncated_pn, size_t pn_nbits);

int quic_packet_protect(
    const quic_crypto_level_ctx_t *ctx,
    uint64_t packet_number,
    const uint8_t *header,
    size_t header_len,
    size_t pn_offset,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *out_packet,
    size_t out_len,
    size_t *out_packet_len
);

int quic_packet_unprotect(
    const quic_crypto_level_ctx_t *ctx,
    uint64_t largest_pn,
    uint8_t *packet,
    size_t packet_len,
    size_t pn_offset,
    uint64_t *packet_number,
    size_t *header_len,
    uint8_t *out_plaintext,
    size_t out_len,
    size_t *out_plaintext_len
);

#endif // QUIC_PACKET_PROTECTION_H：头文件保护结束
