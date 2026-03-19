#ifndef QUIC_CRYPTO_STREAM_H
#define QUIC_CRYPTO_STREAM_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    uint8_t *present;
    size_t capacity;
    size_t end_offset;
    size_t next_read_offset;
} quic_crypto_recvbuf_t;

typedef struct {
    uint8_t *data;
    size_t len;
    size_t capacity;
    size_t flight_start;
    size_t flight_end;
    size_t send_offset;
    uint8_t flight_pending;
} quic_crypto_sendbuf_t;

// 功能：初始化 CRYPTO 接收缓冲区。
// 返回值：无。
void quic_crypto_recvbuf_init(quic_crypto_recvbuf_t *buf);
// 功能：释放 CRYPTO 接收缓冲区占用的内存。
// 返回值：无。
void quic_crypto_recvbuf_free(quic_crypto_recvbuf_t *buf);
// 功能：把 CRYPTO 数据插入接收缓冲区的指定偏移。
// 返回值：0 表示成功；< 0 表示内存分配失败、参数无效或范围非法。
int quic_crypto_recvbuf_insert(quic_crypto_recvbuf_t *buf, uint64_t offset, const uint8_t *data, size_t len);
// 功能：返回当前从 `next_read_offset` 开始可连续读取的字节数。
// 返回值：可连续读取的字节数。
size_t quic_crypto_recvbuf_contiguous_len(const quic_crypto_recvbuf_t *buf);
// 功能：返回当前连续可读区域的起始指针。
// 返回值：非 NULL 表示可读数据起点；NULL 表示参数无效或没有可读数据。
const uint8_t *quic_crypto_recvbuf_read_ptr(const quic_crypto_recvbuf_t *buf);
// 功能：消费一段已经连续读取完成的 CRYPTO 数据。
// 返回值：无。
void quic_crypto_recvbuf_consume(quic_crypto_recvbuf_t *buf, size_t len);

// 功能：初始化 CRYPTO 发送缓冲区。
// 返回值：无。
void quic_crypto_sendbuf_init(quic_crypto_sendbuf_t *buf);
// 功能：释放 CRYPTO 发送缓冲区占用的内存。
// 返回值：无。
void quic_crypto_sendbuf_free(quic_crypto_sendbuf_t *buf);
// 功能：向 CRYPTO 发送缓冲区追加待发送数据。
// 返回值：0 表示成功；< 0 表示内存分配失败或参数非法。
int quic_crypto_sendbuf_append(quic_crypto_sendbuf_t *buf, const uint8_t *data, size_t len);
// 功能：把当前待发送范围标记为一个新的 flight。
// 返回值：无。
void quic_crypto_sendbuf_mark_flight(quic_crypto_sendbuf_t *buf);
// 功能：判断发送缓冲区是否仍有待发送或待重传数据。
// 返回值：非 0 表示仍有待发送数据；0 表示没有。
int quic_crypto_sendbuf_has_pending(const quic_crypto_sendbuf_t *buf);
// 功能：返回当前待发送 flight 的起始偏移。
// 返回值：待发送偏移。
size_t quic_crypto_sendbuf_pending_offset(const quic_crypto_sendbuf_t *buf);
// 功能：返回当前 flight 的结束偏移。
// 返回值：flight 结束偏移。
size_t quic_crypto_sendbuf_flight_end(const quic_crypto_sendbuf_t *buf);
// 功能：推进已确认/已发送的 flight 偏移。
// 返回值：无。
void quic_crypto_sendbuf_advance(quic_crypto_sendbuf_t *buf, size_t len);
// 功能：在 flight 丢失后重启发送窗口。
// 返回值：无。
void quic_crypto_sendbuf_restart_flight(quic_crypto_sendbuf_t *buf);

#endif // QUIC_CRYPTO_STREAM_H：头文件保护结束
