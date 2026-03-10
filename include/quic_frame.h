#ifndef QUIC_FRAME_H
#define QUIC_FRAME_H

#include <stdint.h>
#include <stddef.h>

#define QUIC_FRAME_PADDING 0x00
#define QUIC_FRAME_PING    0x01
#define QUIC_FRAME_ACK     0x02
#define QUIC_FRAME_CRYPTO  0x06
// STREAM 帧类型范围 0x08 - 0x0F

// 提取的 CRYPTO 帧元数据
typedef struct {
    uint64_t offset;
    uint64_t length;
    const uint8_t *data;
} quic_crypto_frame_t;

// 提取的 STREAM 帧元数据
typedef struct {
    uint64_t stream_id;
    uint64_t offset;
    uint64_t length;
    const uint8_t *data;
    uint8_t fin;
} quic_stream_frame_t;

// 轮询解析一段连续的明文 Payload
int quic_parse_frames(const uint8_t *payload, size_t payload_len);

#endif // QUIC_FRAME_H