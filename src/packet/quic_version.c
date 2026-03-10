#include "quic_version.h"
#include <string.h>
#include <stdio.h>

// ============================================================================
// v1 (RFC 9000) 常量与解析逻辑
// ============================================================================
static const uint8_t v1_salt[] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 
    0xcc, 0xbb, 0x7f, 0x0a
};

static uint8_t v1_decode_packet_type(uint8_t header_byte) {
    // 提取第 4 和 5 位 (0x30)
    uint8_t type = (header_byte & 0x30) >> 4;
    // v1: 0=Initial, 1=0-RTT, 2=Handshake, 3=Retry
    return type; 
}

static const quic_version_ops_t v1_ops = {
    .version_id = QUIC_V1_VERSION,
    .initial_salt = v1_salt,
    .salt_len = sizeof(v1_salt),
    .hkdf_label_key = "quic key",
    .hkdf_label_iv = "quic iv",
    .hkdf_label_hp = "quic hp",
    .decode_packet_type = v1_decode_packet_type
};

// ============================================================================
// v2 (RFC 9369) 常量与解析逻辑
// ============================================================================
static const uint8_t v2_salt[] = {
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 
    0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 
    0xf9, 0xbd, 0x2e, 0xd9
};

static uint8_t v2_decode_packet_type(uint8_t header_byte) {
    uint8_t raw_type = (header_byte & 0x30) >> 4;
    // v2 打乱了标识位，在此统一映射为标准内部状态：0=Initial, 1=0-RTT, 2=Handshake, 3=Retry
    switch (raw_type) {
        case 1: return 0; // Initial
        case 2: return 1; // 0-RTT
        case 3: return 2; // Handshake
        case 0: return 3; // Retry
        default: return 0xFF;
    }
}

static const quic_version_ops_t v2_ops = {
    .version_id = QUIC_V2_VERSION,
    .initial_salt = v2_salt,
    .salt_len = sizeof(v2_salt),
    .hkdf_label_key = "quicv2 key",
    .hkdf_label_iv = "quicv2 iv",
    .hkdf_label_hp = "quicv2 hp",
    .decode_packet_type = v2_decode_packet_type
};

// ============================================================================
// 路由与协商接口
// ============================================================================

const quic_version_ops_t* quic_version_get_ops(uint32_t version) {
    if (version == QUIC_V1_VERSION) {
        printf("[DEBUG] Route to QUIC v1 (RFC 9000) profile.\n");
        return &v1_ops;
    } else if (version == QUIC_V2_VERSION) {
        printf("[DEBUG] Route to QUIC v2 (RFC 9369) profile.\n");
        return &v2_ops;
    }
    printf("[DEBUG] Unsupported version: 0x%08x\n", version);
    return NULL;
}

int quic_generate_version_negotiation(const quic_pkt_header_meta_t *in_meta, uint8_t *out_buf, size_t max_len) {
    // 报文结构: Header(1) + Version(4=0x0) + DCID_Len(1) + DCID + SCID_Len(1) + SCID + Supported_Versions
    // Version Negotiation 包将接收到的 SCID 作为 DCID，接收到的 DCID 作为 SCID
    size_t required_len = 1 + 4 + 1 + in_meta->src_cid.len + 1 + in_meta->dest_cid.len + 8; // 支持 v1 和 v2 (各4字节)
    
    if (max_len < required_len) {
        return -1;
    }

    size_t offset = 0;
    
    // 1. 首字节 (必须设置 Long Header bit，其他位随机，RFC 规范为防特征识别)
    out_buf[offset++] = 0x80; 
    
    // 2. Version 必须为 0x00000000
    out_buf[offset++] = 0x00;
    out_buf[offset++] = 0x00;
    out_buf[offset++] = 0x00;
    out_buf[offset++] = 0x00;

    // 3. DCID (来自收到的包的 SCID)
    out_buf[offset++] = in_meta->src_cid.len;
    memcpy(&out_buf[offset], in_meta->src_cid.data, in_meta->src_cid.len);
    offset += in_meta->src_cid.len;

    // 4. SCID (来自收到的包的 DCID)
    out_buf[offset++] = in_meta->dest_cid.len;
    memcpy(&out_buf[offset], in_meta->dest_cid.data, in_meta->dest_cid.len);
    offset += in_meta->dest_cid.len;

    // 5. 附加上服务器支持的版本列表 (QUIC_V2_VERSION, QUIC_V1_VERSION)
    // 写入 v2
    out_buf[offset++] = (QUIC_V2_VERSION >> 24) & 0xFF;
    out_buf[offset++] = (QUIC_V2_VERSION >> 16) & 0xFF;
    out_buf[offset++] = (QUIC_V2_VERSION >> 8) & 0xFF;
    out_buf[offset++] = QUIC_V2_VERSION & 0xFF;

    // 写入 v1
    out_buf[offset++] = (QUIC_V1_VERSION >> 24) & 0xFF;
    out_buf[offset++] = (QUIC_V1_VERSION >> 16) & 0xFF;
    out_buf[offset++] = (QUIC_V1_VERSION >> 8) & 0xFF;
    out_buf[offset++] = QUIC_V1_VERSION & 0xFF;

    printf("[DEBUG] Generated Version Negotiation Packet, length=%zu\n", offset);
    return offset;
}