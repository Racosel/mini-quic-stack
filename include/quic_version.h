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
    // 将内部逻辑包类型编码回指定版本的长头部类型位
    uint8_t (*encode_packet_type)(uint8_t logical_type);
} quic_version_ops_t;

// 功能：根据版本号获取对应的版本操作集。
// 返回值：非 NULL 表示支持该版本；NULL 表示当前未实现该版本。
const quic_version_ops_t* quic_version_get_ops(uint32_t version);

// 功能：根据入站长头元数据生成 Version Negotiation 报文。
// 返回值：>= 0 表示生成的报文总长度；-1 表示输入非法或输出缓冲区不足。
int quic_generate_version_negotiation(const quic_pkt_header_meta_t *in_meta, uint8_t *out_buf, size_t max_len);

#endif // QUIC_VERSION_H：头文件保护结束
