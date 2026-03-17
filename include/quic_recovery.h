#ifndef QUIC_RECOVERY_H
#define QUIC_RECOVERY_H

#include "quic_types.h"
#include <sys/time.h>

// 记录已发送包的元数据
typedef struct quic_sent_packet {
    uint64_t packet_number;
    struct timeval sent_time;
    size_t sent_bytes;
    int is_ack_eliciting;
    int in_flight;
    // 指向包中包含的需要重传的帧备份（暂留接口）
    struct quic_sent_packet *next;
    struct quic_sent_packet *prev;
} quic_sent_packet_t;

// 飞行队列管理结构
typedef struct {
    quic_sent_packet_t *head;
    quic_sent_packet_t *tail;
    uint64_t bytes_in_flight;
    uint64_t largest_acked_packet;
} quic_in_flight_queue_t;

void quic_queue_init(quic_in_flight_queue_t *q);
void quic_on_packet_sent(quic_in_flight_queue_t *q, uint64_t pn, size_t len, int ack_eliciting);
void quic_on_packet_acked(quic_in_flight_queue_t *q, uint64_t pn);

#endif // QUIC_RECOVERY_H：头文件保护结束
