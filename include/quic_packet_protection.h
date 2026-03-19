#ifndef QUIC_PACKET_PROTECTION_H
#define QUIC_PACKET_PROTECTION_H

#include "quic_crypto.h"
#include <stddef.h>
#include <stdint.h>

#define QUIC_HP_MASK_LEN 5
#define QUIC_HP_SAMPLE_LEN 16
#define QUIC_AEAD_TAG_LEN 16

// 功能：根据完整包号与 `largest_acked` 推导最小编码长度。
// 返回值：返回 1、2、3 或 4 字节。
size_t quic_packet_number_encode_size(uint64_t full_pn, uint64_t largest_acked);
// 功能：把完整包号按指定长度编码到输出缓冲区。
// 返回值：0 表示成功；< 0 表示输出缓冲区不足或参数无效。
int quic_encode_packet_number(uint64_t full_pn, size_t pn_len, uint8_t *out, size_t out_len);
// 功能：根据最大已知包号恢复截断后的完整包号。
// 返回值：恢复后的完整包号。
uint64_t quic_decode_packet_number(uint64_t largest_pn, uint64_t truncated_pn, size_t pn_nbits);

// 功能：对报文载荷执行 AEAD 保护并应用头部保护。
// 返回值：0 表示成功；< 0 表示密钥无效、缓冲区不足或加密失败。
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

// 功能：移除头部保护并对报文载荷执行解保护。
// 返回值：0 表示成功；< 0 表示包格式错误、解密失败或输出缓冲区不足。
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
