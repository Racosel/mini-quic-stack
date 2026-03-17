#include "quic_frame.h"
#include "quic_varint.h"
#include <stdio.h>
#include <string.h>

static int quic_skip_varint(const uint8_t *payload, size_t payload_len, size_t *offset) {
    uint64_t ignored;
    return quic_decode_varint(payload, payload_len, offset, &ignored);
}

static int quic_skip_length_prefixed_bytes(const uint8_t *payload, size_t payload_len, size_t *offset) {
    uint64_t length;
    if (quic_decode_varint(payload, payload_len, offset, &length) != 0) {
        return -1;
    }
    if (*offset + length > payload_len) {
        return -1;
    }
    *offset += length;
    return 0;
}

int quic_parse_frames(const uint8_t *payload, size_t payload_len) {
    size_t offset = 0;

    while (offset < payload_len) {
        uint64_t frame_type;
        if (quic_decode_varint(payload, payload_len, &offset, &frame_type) != 0) {
            return -1; // 解析截断
        }

        switch (frame_type) {
            case QUIC_FRAME_PADDING:
                // 连续的 PADDING 可以跳过
                while (offset < payload_len && payload[offset] == 0x00) {
                    offset++;
                }
                printf("[Frame] PADDING parsed.\n");
                break;

            case QUIC_FRAME_PING:
                printf("[Frame] PING parsed.\n");
                break;

            case QUIC_FRAME_ACK:
            case QUIC_FRAME_ACK_ECN: {
                uint64_t largest_acked, ack_delay, ack_range_count, first_ack_range;
                if (quic_decode_varint(payload, payload_len, &offset, &largest_acked) != 0) return -1;
                if (quic_decode_varint(payload, payload_len, &offset, &ack_delay) != 0) return -1;
                if (quic_decode_varint(payload, payload_len, &offset, &ack_range_count) != 0) return -1;
                if (quic_decode_varint(payload, payload_len, &offset, &first_ack_range) != 0) return -1;

                for (uint64_t i = 0; i < ack_range_count; i++) {
                    if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1; // ACK 间隔
                    if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1; // ACK 区间长度
                }

                if (frame_type == QUIC_FRAME_ACK_ECN) {
                    if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1;
                    if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1;
                    if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1;
                }

                printf("[Frame] ACK: largest=%lu, ranges=%lu, ecn=%d\n",
                       largest_acked, ack_range_count, frame_type == QUIC_FRAME_ACK_ECN);
                break;
            }

            case QUIC_FRAME_RESET_STREAM:
                if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1;
                if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1;
                if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1;
                printf("[Frame] RESET_STREAM parsed.\n");
                break;

            case QUIC_FRAME_STOP_SENDING:
                if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1;
                if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1;
                printf("[Frame] STOP_SENDING parsed.\n");
                break;

            case QUIC_FRAME_CRYPTO: {
                quic_crypto_frame_t crypto;
                if (quic_decode_varint(payload, payload_len, &offset, &crypto.offset) != 0) return -1;
                if (quic_decode_varint(payload, payload_len, &offset, &crypto.length) != 0) return -1;
                
                if (offset + crypto.length > payload_len) return -1;
                crypto.data = &payload[offset];
                offset += crypto.length;
                
                printf("[Frame] CRYPTO: offset=%lu, len=%lu\n", crypto.offset, crypto.length);
                break;
            }

            case QUIC_FRAME_NEW_TOKEN:
                if (quic_skip_length_prefixed_bytes(payload, payload_len, &offset) != 0) return -1;
                printf("[Frame] NEW_TOKEN parsed.\n");
                break;

            case QUIC_FRAME_MAX_DATA:
                if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1;
                printf("[Frame] MAX_DATA parsed.\n");
                break;

            case QUIC_FRAME_MAX_STREAM_DATA:
                if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1;
                if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1;
                printf("[Frame] MAX_STREAM_DATA parsed.\n");
                break;

            case QUIC_FRAME_MAX_STREAMS_BIDI:
            case QUIC_FRAME_MAX_STREAMS_UNI:
                if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1;
                printf("[Frame] MAX_STREAMS parsed.\n");
                break;

            case QUIC_FRAME_DATA_BLOCKED:
                if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1;
                printf("[Frame] DATA_BLOCKED parsed.\n");
                break;

            case QUIC_FRAME_STREAM_DATA_BLOCKED:
                if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1;
                if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1;
                printf("[Frame] STREAM_DATA_BLOCKED parsed.\n");
                break;

            case QUIC_FRAME_STREAMS_BLOCKED_BIDI:
            case QUIC_FRAME_STREAMS_BLOCKED_UNI:
                if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1;
                printf("[Frame] STREAMS_BLOCKED parsed.\n");
                break;

            case QUIC_FRAME_NEW_CONNECTION_ID: {
                uint64_t sequence_number, retire_prior_to;
                uint8_t cid_len;
                if (quic_decode_varint(payload, payload_len, &offset, &sequence_number) != 0) return -1;
                if (quic_decode_varint(payload, payload_len, &offset, &retire_prior_to) != 0) return -1;
                if (offset >= payload_len) return -1;
                cid_len = payload[offset++];
                if (cid_len == 0 || cid_len > 20 || offset + cid_len + 16 > payload_len) return -1;
                offset += cid_len + 16;
                printf("[Frame] NEW_CONNECTION_ID: seq=%lu retire_prior_to=%lu\n",
                       sequence_number, retire_prior_to);
                break;
            }

            case QUIC_FRAME_RETIRE_CONNECTION_ID:
                if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1;
                printf("[Frame] RETIRE_CONNECTION_ID parsed.\n");
                break;

            case QUIC_FRAME_PATH_CHALLENGE:
            case QUIC_FRAME_PATH_RESPONSE:
                if (offset + 8 > payload_len) return -1;
                offset += 8;
                printf("[Frame] PATH validation frame parsed.\n");
                break;

            case QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT:
            case QUIC_FRAME_CONNECTION_CLOSE_APPLICATION:
                if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1; // 错误码
                if (frame_type == QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT) {
                    if (quic_skip_varint(payload, payload_len, &offset) != 0) return -1; // 帧类型
                }
                if (quic_skip_length_prefixed_bytes(payload, payload_len, &offset) != 0) return -1;
                printf("[Frame] CONNECTION_CLOSE parsed.\n");
                break;

            case QUIC_FRAME_HANDSHAKE_DONE:
                printf("[Frame] HANDSHAKE_DONE parsed.\n");
                break;

            default:
                if (frame_type >= 0x08 && frame_type <= 0x0F) {
                    quic_stream_frame_t stream = {0};
                    stream.fin = frame_type & 0x01;
                    uint8_t has_len = frame_type & 0x02;
                    uint8_t has_off = frame_type & 0x04;

                    if (quic_decode_varint(payload, payload_len, &offset, &stream.stream_id) != 0) return -1;
                    if (has_off) {
                        if (quic_decode_varint(payload, payload_len, &offset, &stream.offset) != 0) return -1;
                    }
                    if (has_len) {
                        if (quic_decode_varint(payload, payload_len, &offset, &stream.length) != 0) return -1;
                    } else {
                        stream.length = payload_len - offset;
                    }

                    if (offset + stream.length > payload_len) return -1;
                    stream.data = &payload[offset];
                    offset += stream.length;

                    printf("[Frame] STREAM: id=%lu, off=%lu, len=%lu, fin=%d\n", 
                           stream.stream_id, stream.offset, stream.length, stream.fin);
                } else {
                    printf("[Frame] Unknown or unhandled frame type: %lu\n", frame_type);
                    return -1; // 遇到未处理帧，终止解析以防偏移错误
                }
                break;
        }
    }
    return 0;
}
