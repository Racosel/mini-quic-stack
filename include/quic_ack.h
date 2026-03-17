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

int quic_ack_parse_frame(const uint8_t *frame, size_t frame_len, quic_ack_frame_t *ack, size_t *consumed);
int quic_on_ack_frame(quic_in_flight_queue_t *q, const quic_ack_frame_t *ack, size_t *acked_packets);

#endif // QUIC_ACK_H：头文件保护结束
