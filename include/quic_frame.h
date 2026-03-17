#ifndef QUIC_FRAME_H
#define QUIC_FRAME_H

#include <stdint.h>
#include <stddef.h>

#define QUIC_FRAME_PADDING 0x00
#define QUIC_FRAME_PING    0x01
#define QUIC_FRAME_ACK     0x02
#define QUIC_FRAME_ACK_ECN 0x03
#define QUIC_FRAME_RESET_STREAM 0x04
#define QUIC_FRAME_STOP_SENDING 0x05
#define QUIC_FRAME_CRYPTO  0x06
#define QUIC_FRAME_NEW_TOKEN 0x07
// STREAM 帧类型范围 0x08 - 0x0F
#define QUIC_FRAME_MAX_DATA 0x10
#define QUIC_FRAME_MAX_STREAM_DATA 0x11
#define QUIC_FRAME_MAX_STREAMS_BIDI 0x12
#define QUIC_FRAME_MAX_STREAMS_UNI 0x13
#define QUIC_FRAME_DATA_BLOCKED 0x14
#define QUIC_FRAME_STREAM_DATA_BLOCKED 0x15
#define QUIC_FRAME_STREAMS_BLOCKED_BIDI 0x16
#define QUIC_FRAME_STREAMS_BLOCKED_UNI 0x17
#define QUIC_FRAME_NEW_CONNECTION_ID 0x18
#define QUIC_FRAME_RETIRE_CONNECTION_ID 0x19
#define QUIC_FRAME_PATH_CHALLENGE 0x1a
#define QUIC_FRAME_PATH_RESPONSE 0x1b
#define QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT 0x1c
#define QUIC_FRAME_CONNECTION_CLOSE_APPLICATION 0x1d
#define QUIC_FRAME_HANDSHAKE_DONE 0x1e

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

// 轮询解析一段连续的明文载荷
int quic_parse_frames(const uint8_t *payload, size_t payload_len);

#endif // QUIC_FRAME_H：头文件保护结束
