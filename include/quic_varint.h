#ifndef QUIC_VARINT_H
#define QUIC_VARINT_H

#include <stdint.h>
#include <stddef.h>

// 从 data 中解码一个变长整数
// offset: 输入时的当前偏移量，解码成功后会自动累加读取的字节数
// 返回值: 0 表示成功，-1 表示缓冲区长度不足
int quic_decode_varint(const uint8_t *data, size_t max_len, size_t *offset, uint64_t *out_val);

#endif // QUIC_VARINT_H