#include "pkt_decode.h"
#include <string.h>



int quic_parse_header_meta(const uint8_t *data, size_t len, quic_pkt_header_meta_t *meta) {
    if (len == 0 || data == NULL || meta == NULL) {
        return -1;
    }

    memset(meta, 0, sizeof(quic_pkt_header_meta_t));

    // 首字节解析
    uint8_t first_byte = data[0];
    meta->header_form = (first_byte & 0x80) >> 7; // 最高位：1=Long, 0=Short
    meta->fixed_bit = (first_byte & 0x40) >> 6;   // 次高位：固定为1

    if (meta->fixed_bit != 1) {
        return -2; // 无效的 QUIC 数据包
    }

    if (meta->header_form == 1) {
        // --- Long Header 解析 ---
        // 结构: Header(1) + Version(4) + DCID_Len(1) + DCID(n) + SCID_Len(1) + SCID(n)
        if (len < 6) return -3;

        // 提取 Version (大端序转换)
        meta->version = ((uint32_t)data[1] << 24) | ((uint32_t)data[2] << 16) |
                        ((uint32_t)data[3] << 8)  | (uint32_t)data[4];

        // 提取 DCID
        meta->dest_cid.len = data[5];
        // 修改此处：将算术结果强制转换为 size_t 消除警告
        if (meta->dest_cid.len > MAX_CID_LEN || len < (size_t)(7 + meta->dest_cid.len)) {
            return -4;
        }
        memcpy(meta->dest_cid.data, &data[6], meta->dest_cid.len);

        // 提取 SCID
        size_t scid_offset = 6 + meta->dest_cid.len;
        meta->src_cid.len = data[scid_offset];
        // 修改此处：强制转换消除警告
        if (meta->src_cid.len > MAX_CID_LEN || len < scid_offset + 1 + (size_t)meta->src_cid.len) {
            return -5;
        }
        memcpy(meta->src_cid.data, &data[scid_offset + 1], meta->src_cid.len);

    } else {
        // --- Short Header 解析 ---
        // 结构: Header(1) + DCID(n)
        // 注意：Short Header 中不包含 DCID 长度字段。长度由本地 Connection 状态决定。
        // 在预检阶段，我们提取最大可能的长度，交由 dispatcher 根据本地已注册的 CID 长度进行匹配。
        if (len < 1) return -6;
        
        size_t available_len = len - 1;
        meta->dest_cid.len = (available_len > MAX_CID_LEN) ? MAX_CID_LEN : available_len;
        memcpy(meta->dest_cid.data, &data[1], meta->dest_cid.len);
        
        // Short header 没有 SCID 和 Version
        meta->src_cid.len = 0;
        meta->version = 0;
    }

    return 0;
}