#include "quic_frame.h"
#include "quic_varint.h"
#include <stdio.h>

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