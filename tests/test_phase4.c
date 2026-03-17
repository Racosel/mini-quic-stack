#include <stdio.h>
#include <assert.h>
#include "quic_varint.h"
#include "quic_frame.h"

void test_varint_decode() {
    uint8_t data[] = {
        0x25,                   // 1 字节编码：37
        0x40, 0x25,             // 2 字节编码：37
        0x9d, 0x7f, 0x3e, 0x7d, // 4 字节编码：494878333
        0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c // 8 字节编码：151288809941952652
    };

    size_t offset = 0;
    uint64_t val;

    quic_decode_varint(data, sizeof(data), &offset, &val);
    assert(val == 37 && offset == 1);

    quic_decode_varint(data, sizeof(data), &offset, &val);
    assert(val == 37 && offset == 3);

    quic_decode_varint(data, sizeof(data), &offset, &val);
    assert(val == 494878333 && offset == 7);

    quic_decode_varint(data, sizeof(data), &offset, &val);
    assert(val == 151288809941952652ULL && offset == 15);

    printf("[PASS] VarInt Decoder\n");
}

void test_frame_parsing() {
    // 模拟解密后的明文载荷
    // 包含：PADDING(0x00)、PADDING(0x00)、CRYPTO(0x06, offset=0, len=4, data="QUIC")、STREAM(0x0a: off=0, len=1, id=4, len=3, data="XYZ")
    uint8_t payload[] = {
        0x00, 0x00, 
        0x06, 0x00, 0x04, 'Q', 'U', 'I', 'C',
        0x0a, 0x04, 0x03, 'X', 'Y', 'Z'  // 0x0a = 00001010（STREAM，has_len=1）
    };

    int ret = quic_parse_frames(payload, sizeof(payload));
    assert(ret == 0);
    printf("[PASS] Frame Parsing Pipeline\n");
}

int main() {
    printf("--- Running Phase 4 Tests ---\n");
    test_varint_decode();
    test_frame_parsing();
    printf("--- All Phase 4 Tests Passed! ---\n");
    return 0;
}
