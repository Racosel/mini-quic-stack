#ifndef QUIC_VARINT_H
#define QUIC_VARINT_H

#include <stdint.h>
#include <stddef.h>

// 从 data 中解码一个变长整数
// offset：输入时的当前偏移量，解码成功后会自动累加已读取的字节数
// 返回值：0 表示成功，-1 表示缓冲区长度不足
int quic_decode_varint(const uint8_t *data, size_t max_len, size_t *offset, uint64_t *out_val);

// 返回编码 val 所需的字节数；如果 val 超出 QUIC varint 上限则返回 0
size_t quic_varint_size(uint64_t val);

// 将 val 以 QUIC varint 形式写入 out，返回写入字节数；失败返回 -1
int quic_encode_varint(uint64_t val, uint8_t *out, size_t out_len);

#endif // QUIC_VARINT_H：头文件保护结束
