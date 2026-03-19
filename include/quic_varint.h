#ifndef QUIC_VARINT_H
#define QUIC_VARINT_H

#include <stdint.h>
#include <stddef.h>

// 功能：从 `data[*offset..max_len)` 中解码一个 QUIC 变长整数。
// 返回值：0 表示成功；-1 表示缓冲区长度不足、编码非法或输出参数无效。
int quic_decode_varint(const uint8_t *data, size_t max_len, size_t *offset, uint64_t *out_val);

// 功能：返回编码 `val` 所需的字节数。
// 返回值：1、2、4 或 8；如果 `val` 超出 QUIC varint 上限则返回 0。
size_t quic_varint_size(uint64_t val);

// 功能：将 `val` 以 QUIC varint 形式写入 `out`。
// 返回值：> 0 表示写入字节数；-1 表示输出缓冲区不足或数值非法。
int quic_encode_varint(uint64_t val, uint8_t *out, size_t out_len);

#endif // QUIC_VARINT_H：头文件保护结束
