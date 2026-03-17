#include "quic_recovery.h"
#include <stdlib.h>
#include <string.h>

void quic_queue_init(quic_in_flight_queue_t *q) {
    q->head = q->tail = NULL;
    q->bytes_in_flight = 0;
    q->largest_acked_packet = 0;
}

void quic_queue_clear(quic_in_flight_queue_t *q) {
    quic_sent_packet_t *curr;
    quic_sent_packet_t *next;

    if (!q) {
        return;
    }

    curr = q->head;
    while (curr) {
        next = curr->next;
        free(curr);
        curr = next;
    }

    q->head = NULL;
    q->tail = NULL;
    q->bytes_in_flight = 0;
    q->largest_acked_packet = 0;
}

void quic_on_packet_sent(quic_in_flight_queue_t *q, uint64_t pn, size_t len, int ack_eliciting) {
    quic_sent_packet_t *p = malloc(sizeof(quic_sent_packet_t));
    p->packet_number = pn;
    gettimeofday(&p->sent_time, NULL);
    p->sent_bytes = len;
    p->is_ack_eliciting = ack_eliciting;
    p->in_flight = 1;
    p->next = NULL;

    // 插入队尾
    if (!q->tail) {
        q->head = q->tail = p;
        p->prev = NULL;
    } else {
        q->tail->next = p;
        p->prev = q->tail;
        q->tail = p;
    }

    if (ack_eliciting) {
        q->bytes_in_flight += len;
    }
}

void quic_on_packet_acked(quic_in_flight_queue_t *q, uint64_t pn) {
    quic_sent_packet_t *curr = q->head;
    while (curr) {
        if (curr->packet_number == pn) {
            // 更新统计
            if (curr->is_ack_eliciting) {
                q->bytes_in_flight -= curr->sent_bytes;
            }
            if (pn > q->largest_acked_packet) {
                q->largest_acked_packet = pn;
            }

            // 从链表移除
            if (curr->prev) curr->prev->next = curr->next;
            if (curr->next) curr->next->prev = curr->prev;
            if (curr == q->head) q->head = curr->next;
            if (curr == q->tail) q->tail = curr->prev;

            free(curr);
            return;
        }
        curr = curr->next;
    }
}
