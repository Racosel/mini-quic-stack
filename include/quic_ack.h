#ifndef QUIC_ACK_H
#define QUIC_ACK_H

#include "quic_recovery.h"
#include <stddef.h>
#include <stdint.h>

#define QUIC_MAX_ACK_RANGES 32

typedef struct {
    uint64_t smallest;
    uint64_t largest;
} quic_ack_range_t;

typedef struct {
    uint8_t has_ecn;
    uint64_t largest_acked;
    uint64_t ack_delay;
    size_t ack_range_count;
    quic_ack_range_t ranges[QUIC_MAX_ACK_RANGES];
    uint64_t ect0_count;
    uint64_t ect1_count;
    uint64_t ecn_ce_count;
} quic_ack_frame_t;

// 功能：从字节串解析 ACK 或 ACK_ECN frame。
// 返回值：0 表示成功；< 0 表示帧格式不合法、长度不足或范围字段异常。
int quic_ack_parse_frame(const uint8_t *frame, size_t frame_len, quic_ack_frame_t *ack, size_t *consumed);
// 功能：把 ACK frame 结构编码为字节串。
// 返回值：0 表示成功；< 0 表示输出缓冲区不足或输入范围非法。
int quic_ack_encode_frame(const quic_ack_frame_t *ack, uint8_t *out, size_t out_len, size_t *written);
// 功能：把 ACK frame 应用到 in-flight 队列，删除已确认包并统计数量。
// 返回值：0 表示成功；< 0 表示 ACK 范围非法或输入参数无效。
int quic_on_ack_frame(quic_in_flight_queue_t *q, const quic_ack_frame_t *ack, size_t *acked_packets);
// 功能：初始化 ACK range 数组。
// 返回值：无。
void quic_ack_ranges_init(quic_ack_range_t *ranges, size_t *range_count);
// 功能：把一个新收到的包号并入 ACK range 集合。
// 返回值：0 表示成功；< 0 表示数组已满或输入参数无效。
int quic_ack_note_received(quic_ack_range_t *ranges, size_t *range_count, uint64_t packet_number);
// 功能：根据 ACK range 集合构造一个可编码的 ACK frame。
// 返回值：0 表示成功；< 0 表示输入 range 集合非法。
int quic_ack_frame_from_ranges(const quic_ack_range_t *ranges, size_t range_count, quic_ack_frame_t *ack);

#endif // QUIC_ACK_H：头文件保护结束
