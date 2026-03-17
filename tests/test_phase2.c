#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "quic_types.h"
#include "quic_version.h"
#include "pkt_decode.h"

void test_version_routing() {
    // 测试 v1 路由
    const quic_version_ops_t *ops_v1 = quic_version_get_ops(QUIC_V1_VERSION);
    assert(ops_v1 != NULL);
    assert(strcmp(ops_v1->hkdf_label_key, "quic key") == 0);
    // 构造 v1 Initial 报文头字节：Form=1、Fixed=1、Type=0（0x00）-> 0xc0
    assert(ops_v1->decode_packet_type(0xc0) == 0); // 内部统一映射的 Initial

    // 测试 v2 路由
    const quic_version_ops_t *ops_v2 = quic_version_get_ops(QUIC_V2_VERSION);
    assert(ops_v2 != NULL);
    assert(strcmp(ops_v2->hkdf_label_key, "quicv2 key") == 0);
    // 构造 v2 Initial 报文头字节：Form=1、Fixed=1、Type=1（0x10）-> 0xd0
    assert(ops_v2->decode_packet_type(0xd0) == 0); // 内部统一映射的 Initial

    // 测试不支持的版本
    const quic_version_ops_t *ops_unknown = quic_version_get_ops(0x12345678);
    assert(ops_unknown == NULL);
    
    printf("[PASS] Version Routing & Type Decoding\n");
}

void test_version_negotiation_gen() {
    quic_pkt_header_meta_t meta;
    memset(&meta, 0, sizeof(meta));
    
    // 模拟收到未知版本的包
    meta.version = 0x99999999; 
    meta.dest_cid.len = 4;
    meta.dest_cid.data[0] = 0xaa; meta.dest_cid.data[1] = 0xbb; meta.dest_cid.data[2] = 0xcc; meta.dest_cid.data[3] = 0xdd;
    meta.src_cid.len = 2;
    meta.src_cid.data[0] = 0x11; meta.src_cid.data[1] = 0x22;

    uint8_t out_buf[128];
    int len = quic_generate_version_negotiation(&meta, out_buf, sizeof(out_buf));
    
    assert(len > 0);
    // 验证生成格式：1(Header) + 4(Version=0) + 1(DCID_Len) + 2(DCID) + 1(SCID_Len) + 4(SCID) + 8(Supported Versions) = 21
    assert(len == 21);
    
    assert((out_buf[0] & 0x80) == 0x80); // 最高位必须为 1
    assert(out_buf[1] == 0 && out_buf[2] == 0 && out_buf[3] == 0 && out_buf[4] == 0); // Version 必须为 0
    assert(out_buf[5] == 2); // DCID_Len 应等于收到报文的 SCID_Len
    assert(out_buf[6] == 0x11 && out_buf[7] == 0x22); // DCID 内容
    assert(out_buf[8] == 4); // SCID_Len 应等于收到报文的 DCID_Len
    assert(out_buf[9] == 0xaa); // SCID 内容起头

    printf("[PASS] Version Negotiation Generation\n");
}

int main() {
    printf("--- Running Phase 2 Tests ---\n");
    test_version_routing();
    test_version_negotiation_gen();
    printf("--- All Phase 2 Tests Passed! ---\n");
    return 0;
}
