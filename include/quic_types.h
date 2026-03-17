#ifndef QUIC_TYPES_H
#define QUIC_TYPES_H

#include <stdint.h>
#include <stddef.h>

#define MAX_CID_LEN 20

// QUIC 版本号定义
#define QUIC_V1_VERSION 0x00000001
#define QUIC_V2_VERSION 0x6b3343cf

// 连接 ID 结构
typedef struct {
    uint8_t len;
    uint8_t data[MAX_CID_LEN];
} quic_cid_t;

// 数据包预检提取的元数据
typedef struct {
    uint8_t header_form; // 1 = 长包头，0 = 短包头
    uint8_t fixed_bit;   // 必须为 1
    quic_cid_t dest_cid;
    quic_cid_t src_cid;  // 仅长包头有效
    uint32_t version;    // 仅长包头有效
} quic_pkt_header_meta_t;

#endif // QUIC_TYPES_H：头文件保护结束
