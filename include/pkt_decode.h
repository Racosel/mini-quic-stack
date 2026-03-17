#ifndef PKT_DECODE_H
#define PKT_DECODE_H

#include "quic_types.h"

// 预解析数据包头部，提取路由所需的基础信息
// 返回值：0 表示成功，< 0 表示数据包格式错误或长度不足
int quic_parse_header_meta(const uint8_t *data, size_t len, quic_pkt_header_meta_t *meta);

#endif // PKT_DECODE_H：头文件保护结束
