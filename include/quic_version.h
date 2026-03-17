#ifndef QUIC_VERSION_H
#define QUIC_VERSION_H

#include "quic_types.h"

// 阶段2：版本多态操作集
typedef struct {
    uint32_t version_id;
    const uint8_t* initial_salt;
    size_t salt_len;
    const char* hkdf_label_key;
    const char* hkdf_label_iv;
    const char* hkdf_label_hp;
    // 动态解析长头部包类型（返回 0=Initial，1=0-RTT，2=Handshake，3=Retry）
    uint8_t (*decode_packet_type)(uint8_t header_byte);
} quic_version_ops_t;

// 根据版本号获取对应的操作集；如果不支持该版本则返回 NULL
const quic_version_ops_t* quic_version_get_ops(uint32_t version);

// 生成版本协商（Version Negotiation）报文
// 返回生成的报文总长度，如果出错返回 -1
int quic_generate_version_negotiation(const quic_pkt_header_meta_t *in_meta, uint8_t *out_buf, size_t max_len);

#endif // QUIC_VERSION_H：头文件保护结束
