#include "quic_ack.h"
#include "quic_recovery.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    uint64_t time_sent_ms;
    size_t sent_bytes;
    uint8_t in_flight;
    uint8_t app_limited;
    uint8_t flow_control_limited;
} quic_acked_packet_info_t;

static uint64_t quic_recovery_now_ms(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

static void quic_queue_link_tail(quic_in_flight_queue_t *q, quic_sent_packet_t *packet) {
    packet->next = NULL;

    if (!q->tail) {
        q->head = q->tail = packet;
        packet->prev = NULL;
        return;
    }

    q->tail->next = packet;
    packet->prev = q->tail;
    q->tail = packet;
}

static void quic_queue_unlink(quic_in_flight_queue_t *q, quic_sent_packet_t *packet) {
    if (packet->prev) {
        packet->prev->next = packet->next;
    }
    if (packet->next) {
        packet->next->prev = packet->prev;
    }
    if (q->head == packet) {
        q->head = packet->next;
    }
    if (q->tail == packet) {
        q->tail = packet->prev;
    }
}

static void quic_queue_account_remove(quic_in_flight_queue_t *q, const quic_sent_packet_t *packet) {
    if (!q || !packet) {
        return;
    }

    if (packet->in_flight && q->bytes_in_flight >= packet->sent_bytes) {
        q->bytes_in_flight -= packet->sent_bytes;
    }
    if (packet->is_ack_eliciting && q->ack_eliciting_in_flight > 0) {
        q->ack_eliciting_in_flight--;
    }
    if (packet->packet_number > q->largest_acked_packet) {
        q->largest_acked_packet = packet->packet_number;
    }
}

static void quic_queue_remove_packet(quic_in_flight_queue_t *q, quic_sent_packet_t *packet) {
    if (!q || !packet) {
        return;
    }

    quic_queue_account_remove(q, packet);
    quic_queue_unlink(q, packet);
    free(packet);
}

static uint64_t quic_recovery_min(uint64_t a, uint64_t b) {
    return a < b ? a : b;
}

static uint64_t quic_recovery_max(uint64_t a, uint64_t b) {
    return a > b ? a : b;
}

static uint64_t quic_recovery_abs_diff(uint64_t a, uint64_t b) {
    return a > b ? a - b : b - a;
}

static uint64_t quic_recovery_initial_window(uint64_t max_datagram_size) {
    uint64_t datagram = max_datagram_size < 1200 ? 1200 : max_datagram_size;
    uint64_t ten_packets = datagram * 10ULL;
    uint64_t lower_bound = quic_recovery_max(datagram * 2ULL, 14720ULL);

    return ten_packets < lower_bound ? ten_packets : lower_bound;
}

static uint64_t quic_recovery_minimum_window(const quic_recovery_state_t *state) {
    uint64_t datagram = state && state->max_datagram_size >= 1200 ? state->max_datagram_size : 1200ULL;
    return datagram * 2ULL;
}

static int quic_recovery_in_congestion_recovery(const quic_recovery_state_t *state, uint64_t sent_time_ms) {
    return state && state->congestion_recovery_start_time_ms != 0 &&
           sent_time_ms <= state->congestion_recovery_start_time_ms;
}

static uint64_t quic_recovery_pto_base(const quic_recovery_state_t *state) {
    uint64_t granularity = QUIC_RECOVERY_GRANULARITY_MS;
    uint64_t variance = 0;

    if (!state) {
        return QUIC_RECOVERY_INITIAL_RTT_MS + granularity;
    }

    variance = state->rttvar_ms * 4ULL;
    if (variance < granularity) {
        variance = granularity;
    }
    return state->smoothed_rtt_ms + variance;
}

static uint64_t quic_recovery_loss_delay(const quic_recovery_state_t *state) {
    uint64_t basis;
    uint64_t delay;

    if (!state) {
        return QUIC_RECOVERY_GRANULARITY_MS;
    }

    basis = quic_recovery_max(state->latest_rtt_ms, state->smoothed_rtt_ms);
    delay = (basis * QUIC_RECOVERY_TIME_THRESHOLD_NUM + (QUIC_RECOVERY_TIME_THRESHOLD_DEN - 1ULL)) /
            QUIC_RECOVERY_TIME_THRESHOLD_DEN;
    if (delay < QUIC_RECOVERY_GRANULARITY_MS) {
        delay = QUIC_RECOVERY_GRANULARITY_MS;
    }
    return delay;
}

static void quic_recovery_on_congestion_event(quic_recovery_state_t *state, uint64_t now_ms) {
    uint64_t minimum_window;
    uint64_t reduced_window;

    if (!state || quic_recovery_in_congestion_recovery(state, now_ms)) {
        return;
    }

    minimum_window = quic_recovery_minimum_window(state);
    state->congestion_recovery_start_time_ms = now_ms;
    reduced_window = (state->congestion_window * QUIC_RECOVERY_LOSS_REDUCTION_NUM) /
                     QUIC_RECOVERY_LOSS_REDUCTION_DEN;
    if (reduced_window < minimum_window) {
        reduced_window = minimum_window;
    }
    state->ssthresh = reduced_window;
    state->congestion_window = reduced_window;
}

static void quic_recovery_update_rtt(quic_recovery_state_t *state,
                                     uint8_t packet_number_space,
                                     uint64_t latest_rtt_ms,
                                     uint64_t ack_delay_ms,
                                     uint64_t now_ms) {
    uint64_t adjusted_rtt = latest_rtt_ms;

    if (!state) {
        return;
    }

    state->latest_rtt_ms = latest_rtt_ms;
    if (state->first_rtt_sample_ms == 0) {
        state->min_rtt_ms = latest_rtt_ms;
        state->smoothed_rtt_ms = latest_rtt_ms;
        state->rttvar_ms = latest_rtt_ms / 2ULL;
        state->first_rtt_sample_ms = now_ms;
        return;
    }

    if (latest_rtt_ms < state->min_rtt_ms) {
        state->min_rtt_ms = latest_rtt_ms;
    }

    if (packet_number_space == 2 && state->handshake_confirmed) {
        if (ack_delay_ms > state->max_ack_delay_ms) {
            ack_delay_ms = state->max_ack_delay_ms;
        }
        if (latest_rtt_ms >= state->min_rtt_ms + ack_delay_ms) {
            adjusted_rtt = latest_rtt_ms - ack_delay_ms;
        }
    }

    state->rttvar_ms = (3ULL * state->rttvar_ms + quic_recovery_abs_diff(state->smoothed_rtt_ms, adjusted_rtt)) / 4ULL;
    state->smoothed_rtt_ms = (7ULL * state->smoothed_rtt_ms + adjusted_rtt) / 8ULL;
}

static int quic_recovery_ack_contains_packet(uint64_t pn, const quic_ack_frame_t *ack) {
    size_t i;

    if (!ack) {
        return 0;
    }

    for (i = 0; i < ack->ack_range_count; i++) {
        if (pn >= ack->ranges[i].smallest && pn <= ack->ranges[i].largest) {
            return 1;
        }
    }
    return 0;
}

static int quic_recovery_detect_and_remove_lost_packets(quic_recovery_state_t *state,
                                                        quic_in_flight_queue_t *q,
                                                        uint8_t packet_number_space,
                                                        uint64_t now_ms,
                                                        quic_recovery_packet_observer_t on_lost,
                                                        void *observer_ctx,
                                                        size_t *lost_packets) {
    quic_sent_packet_t *curr;
    uint64_t loss_delay;
    uint64_t lost_send_time;
    uint64_t largest_acked;
    uint64_t earliest_pc_candidate = 0;
    uint64_t latest_pc_candidate = 0;
    size_t count = 0;
    int saw_inflight_loss = 0;

    if (!state || !q || packet_number_space >= QUIC_RECOVERY_PACKET_SPACE_COUNT) {
        return -1;
    }

    if (lost_packets) {
        *lost_packets = 0;
    }

    largest_acked = state->largest_acked_packet[packet_number_space];
    if (largest_acked == UINT64_MAX) {
        state->loss_time_ms[packet_number_space] = 0;
        return 0;
    }

    state->loss_time_ms[packet_number_space] = 0;
    loss_delay = quic_recovery_loss_delay(state);
    lost_send_time = now_ms > loss_delay ? now_ms - loss_delay : 0;

    curr = q->head;
    while (curr) {
        quic_sent_packet_t *next = curr->next;
        int lost_by_time = curr->sent_time_ms <= lost_send_time;
        int lost_by_packet = largest_acked >= curr->packet_number + QUIC_RECOVERY_PACKET_THRESHOLD;

        if (curr->packet_number > largest_acked) {
            curr = next;
            continue;
        }

        if (lost_by_time || lost_by_packet) {
            if (curr->in_flight) {
                if (state->bytes_in_flight >= curr->sent_bytes) {
                    state->bytes_in_flight -= curr->sent_bytes;
                } else {
                    state->bytes_in_flight = 0;
                }
                saw_inflight_loss = 1;
                if (state->first_rtt_sample_ms != 0 && curr->sent_time_ms > state->first_rtt_sample_ms) {
                    if (earliest_pc_candidate == 0 || curr->sent_time_ms < earliest_pc_candidate) {
                        earliest_pc_candidate = curr->sent_time_ms;
                    }
                    if (curr->sent_time_ms > latest_pc_candidate) {
                        latest_pc_candidate = curr->sent_time_ms;
                    }
                }
            }
            if (on_lost) {
                on_lost(observer_ctx, curr);
            }
            quic_queue_remove_packet(q, curr);
            count++;
            curr = next;
            continue;
        }

        if (state->loss_time_ms[packet_number_space] == 0) {
            state->loss_time_ms[packet_number_space] = curr->sent_time_ms + loss_delay;
        } else {
            state->loss_time_ms[packet_number_space] =
                quic_recovery_min(state->loss_time_ms[packet_number_space], curr->sent_time_ms + loss_delay);
        }
        curr = next;
    }

    if (saw_inflight_loss) {
        quic_recovery_on_congestion_event(state, now_ms);
    }

    if (earliest_pc_candidate != 0 && latest_pc_candidate != 0) {
        uint64_t persistent_duration = quic_recovery_pto_base(state);

        if (state->handshake_confirmed) {
            persistent_duration += state->max_ack_delay_ms;
        }
        persistent_duration *= QUIC_RECOVERY_PERSISTENT_CONGESTION_THRESHOLD;
        if (latest_pc_candidate >= earliest_pc_candidate + persistent_duration) {
            state->congestion_window = quic_recovery_minimum_window(state);
            state->congestion_recovery_start_time_ms = 0;
        }
    }

    if (lost_packets) {
        *lost_packets = count;
    }
    return 0;
}

void quic_queue_init(quic_in_flight_queue_t *q) {
    if (!q) {
        return;
    }

    q->head = q->tail = NULL;
    q->bytes_in_flight = 0;
    q->largest_acked_packet = 0;
    q->ack_eliciting_in_flight = 0;
}

void quic_queue_clear(quic_in_flight_queue_t *q) {
    quic_sent_packet_t *curr;

    if (!q) {
        return;
    }

    curr = q->head;
    while (curr) {
        quic_sent_packet_t *next = curr->next;
        free(curr);
        curr = next;
    }

    q->head = NULL;
    q->tail = NULL;
    q->bytes_in_flight = 0;
    q->largest_acked_packet = 0;
    q->ack_eliciting_in_flight = 0;
}

void quic_on_packet_sent(quic_in_flight_queue_t *q, uint64_t pn, size_t len, int ack_eliciting) {
    quic_on_packet_sent_ex(q,
                           pn,
                           len,
                           ack_eliciting,
                           ack_eliciting,
                           0,
                           0,
                           0,
                           0,
                           0,
                           quic_recovery_now_ms(),
                           NULL);
}

void quic_on_packet_sent_ex(quic_in_flight_queue_t *q,
                            uint64_t pn,
                            size_t len,
                            int ack_eliciting,
                            int in_flight,
                            int is_crypto_packet,
                            int is_pto_probe,
                            uint8_t packet_number_space,
                            int app_limited,
                            int flow_control_limited,
                            uint64_t now_ms,
                            const quic_sent_packet_meta_t *meta) {
    quic_sent_packet_t *packet;

    if (!q) {
        return;
    }

    packet = (quic_sent_packet_t *)calloc(1, sizeof(*packet));
    if (!packet) {
        return;
    }

    packet->packet_number = pn;
    packet->sent_time_ms = now_ms;
    packet->sent_bytes = len;
    packet->is_ack_eliciting = (uint8_t)(ack_eliciting ? 1 : 0);
    packet->in_flight = (uint8_t)(in_flight ? 1 : 0);
    packet->is_crypto_packet = (uint8_t)(is_crypto_packet ? 1 : 0);
    packet->is_pto_probe = (uint8_t)(is_pto_probe ? 1 : 0);
    packet->packet_number_space = packet_number_space;
    packet->app_limited = (uint8_t)(app_limited ? 1 : 0);
    packet->flow_control_limited = (uint8_t)(flow_control_limited ? 1 : 0);
    if (meta) {
        packet->meta = *meta;
    }

    quic_queue_link_tail(q, packet);
    if (packet->in_flight) {
        q->bytes_in_flight += len;
    }
    if (packet->is_ack_eliciting) {
        q->ack_eliciting_in_flight++;
    }
}

void quic_on_packet_acked(quic_in_flight_queue_t *q, uint64_t pn) {
    quic_sent_packet_t *curr;

    if (!q) {
        return;
    }

    curr = q->head;
    while (curr) {
        if (curr->packet_number == pn) {
            quic_queue_remove_packet(q, curr);
            return;
        }
        curr = curr->next;
    }
}

const quic_sent_packet_t *quic_recovery_oldest_unacked(const quic_in_flight_queue_t *q) {
    return q ? q->head : NULL;
}

void quic_recovery_init(quic_recovery_state_t *state, uint64_t max_datagram_size) {
    size_t i;

    if (!state) {
        return;
    }

    memset(state, 0, sizeof(*state));
    state->smoothed_rtt_ms = QUIC_RECOVERY_INITIAL_RTT_MS;
    state->rttvar_ms = QUIC_RECOVERY_INITIAL_RTT_MS / 2ULL;
    state->max_ack_delay_ms = 25ULL;
    state->max_datagram_size = max_datagram_size < 1200 ? 1200 : max_datagram_size;
    state->congestion_window = quic_recovery_initial_window(state->max_datagram_size);
    state->ssthresh = UINT64_MAX;
    for (i = 0; i < QUIC_RECOVERY_PACKET_SPACE_COUNT; i++) {
        state->largest_acked_packet[i] = UINT64_MAX;
    }
}

void quic_recovery_set_max_ack_delay(quic_recovery_state_t *state, uint64_t max_ack_delay_ms) {
    if (!state) {
        return;
    }
    state->max_ack_delay_ms = max_ack_delay_ms;
}

void quic_recovery_set_handshake_confirmed(quic_recovery_state_t *state, int confirmed) {
    if (!state) {
        return;
    }
    state->handshake_confirmed = (uint8_t)(confirmed ? 1 : 0);
}

void quic_recovery_set_peer_completed_address_validation(quic_recovery_state_t *state, int validated) {
    if (!state) {
        return;
    }
    state->peer_completed_address_validation = (uint8_t)(validated ? 1 : 0);
}

int quic_recovery_can_send(const quic_recovery_state_t *state, size_t sent_bytes) {
    if (!state) {
        return 0;
    }
    return state->bytes_in_flight + sent_bytes <= state->congestion_window;
}

void quic_recovery_on_packet_sent(quic_recovery_state_t *state,
                                  quic_in_flight_queue_t *q,
                                  uint64_t pn,
                                  uint8_t packet_number_space,
                                  size_t sent_bytes,
                                  int ack_eliciting,
                                  int in_flight,
                                  int is_crypto_packet,
                                  int is_pto_probe,
                                  int app_limited,
                                  int flow_control_limited,
                                  uint64_t now_ms,
                                  const quic_sent_packet_meta_t *meta) {
    if (!state || !q || packet_number_space >= QUIC_RECOVERY_PACKET_SPACE_COUNT) {
        return;
    }

    quic_on_packet_sent_ex(q,
                           pn,
                           sent_bytes,
                           ack_eliciting,
                           in_flight,
                           is_crypto_packet,
                           is_pto_probe,
                           packet_number_space,
                           app_limited,
                           flow_control_limited,
                           now_ms,
                           meta);

    if (!in_flight) {
        return;
    }

    state->bytes_in_flight += sent_bytes;
    if (ack_eliciting) {
        state->time_of_last_ack_eliciting_packet_ms[packet_number_space] = now_ms;
    }
}

int quic_recovery_on_ack_received(quic_recovery_state_t *state,
                                  quic_in_flight_queue_t *q,
                                  const void *ack_frame,
                                  uint8_t packet_number_space,
                                  uint64_t ack_delay_ms,
                                  uint64_t now_ms,
                                  quic_recovery_packet_observer_t on_acked,
                                  quic_recovery_packet_observer_t on_lost,
                                  void *observer_ctx,
                                  size_t *acked_packets,
                                  size_t *lost_packets) {
    const quic_ack_frame_t *ack = (const quic_ack_frame_t *)ack_frame;
    quic_acked_packet_info_t *acked = NULL;
    size_t acked_count = 0;
    size_t acked_cap = 0;
    quic_sent_packet_t *curr;
    uint64_t largest_acked_time_ms = 0;
    int largest_acked_ack_eliciting = 0;
    size_t detected_lost = 0;
    int congestion_event = 0;
    size_t i;

    if (!state || !q || !ack || packet_number_space >= QUIC_RECOVERY_PACKET_SPACE_COUNT) {
        return -1;
    }
    if (acked_packets) {
        *acked_packets = 0;
    }
    if (lost_packets) {
        *lost_packets = 0;
    }

    if (state->largest_acked_packet[packet_number_space] == UINT64_MAX) {
        state->largest_acked_packet[packet_number_space] = ack->largest_acked;
    } else {
        state->largest_acked_packet[packet_number_space] =
            quic_recovery_max(state->largest_acked_packet[packet_number_space], ack->largest_acked);
    }

    // 先按 ACK range 从 in-flight 队列中摘除确认包，并把拥塞控制需要的元数据拷贝出来。
    // 后面可能还要基于“本轮是否发生丢包/ECN 拥塞事件”决定能不能增长 cwnd。
    curr = q->head;
    while (curr) {
        quic_sent_packet_t *next = curr->next;

        if (quic_recovery_ack_contains_packet(curr->packet_number, ack)) {
            if (acked_count == acked_cap) {
                size_t next_cap = acked_cap == 0 ? 8 : acked_cap * 2;
                quic_acked_packet_info_t *grown =
                    (quic_acked_packet_info_t *)realloc(acked, next_cap * sizeof(*grown));

                if (!grown) {
                    free(acked);
                    return -1;
                }
                acked = grown;
                acked_cap = next_cap;
            }

            acked[acked_count].time_sent_ms = curr->sent_time_ms;
            acked[acked_count].sent_bytes = curr->sent_bytes;
            acked[acked_count].in_flight = curr->in_flight;
            acked[acked_count].app_limited = curr->app_limited;
            acked[acked_count].flow_control_limited = curr->flow_control_limited;
            acked_count++;

            if (curr->packet_number == ack->largest_acked) {
                largest_acked_time_ms = curr->sent_time_ms;
                largest_acked_ack_eliciting = curr->is_ack_eliciting;
            }

            if (curr->in_flight) {
                if (state->bytes_in_flight >= curr->sent_bytes) {
                    state->bytes_in_flight -= curr->sent_bytes;
                } else {
                    state->bytes_in_flight = 0;
                }
            }
            if (on_acked) {
                on_acked(observer_ctx, curr);
            }
            quic_queue_remove_packet(q, curr);
        }

        curr = next;
    }

    if (acked_count == 0) {
        free(acked);
        return 0;
    }

    if (largest_acked_time_ms != 0 && largest_acked_ack_eliciting && now_ms >= largest_acked_time_ms) {
        quic_recovery_update_rtt(state,
                                 packet_number_space,
                                 now_ms - largest_acked_time_ms,
                                 ack_delay_ms,
                                 now_ms);
    }

    // ECN CE 或显式丢包都会把这一轮 ACK 视为拥塞事件；发生拥塞时本轮不再继续扩张 cwnd。
    if (ack->has_ecn && ack->ecn_ce_count > state->ecn_ce_counters[packet_number_space]) {
        state->ecn_ce_counters[packet_number_space] = ack->ecn_ce_count;
        if (largest_acked_time_ms != 0) {
            quic_recovery_on_congestion_event(state, now_ms);
            congestion_event = 1;
        }
    }

    if (quic_recovery_detect_and_remove_lost_packets(state,
                                                     q,
                                                     packet_number_space,
                                                     now_ms,
                                                     on_lost,
                                                     observer_ctx,
                                                     &detected_lost) != 0) {
        free(acked);
        return -1;
    }
    if (detected_lost > 0) {
        congestion_event = 1;
    }

    for (i = 0; i < acked_count; i++) {
        quic_acked_packet_info_t *packet = &acked[i];

        if (!packet->in_flight) {
            continue;
        }
        if (congestion_event) {
            continue;
        }
        if (packet->app_limited || packet->flow_control_limited) {
            continue;
        }
        if (quic_recovery_in_congestion_recovery(state, packet->time_sent_ms)) {
            continue;
        }
        if (state->congestion_window < state->ssthresh) {
            state->congestion_window += packet->sent_bytes;
        } else if (state->congestion_window > 0) {
            // Reno 拥塞避免阶段按 RFC 9002 的逐字节近似增长，避免每个 ACK 都加一个整包。
            state->congestion_window +=
                (state->max_datagram_size * packet->sent_bytes) / state->congestion_window;
        }
    }

    if (state->peer_completed_address_validation) {
        state->pto_count = 0;
    }

    if (acked_packets) {
        *acked_packets = acked_count;
    }
    if (lost_packets) {
        *lost_packets = detected_lost;
    }
    free(acked);
    return 0;
}

int quic_recovery_get_timer(const quic_recovery_state_t *state,
                            const quic_in_flight_queue_t *const queues[QUIC_RECOVERY_PACKET_SPACE_COUNT],
                            int server_amplification_limited,
                            int has_handshake_keys,
                            uint64_t now_ms,
                            quic_recovery_timer_t *timer) {
    uint64_t earliest_loss_time = 0;
    uint8_t earliest_loss_space = 0;
    uint64_t base_duration;
    uint64_t pto_timeout = UINT64_MAX;
    uint8_t pto_space = 0;
    size_t i;

    if (!state || !queues || !timer) {
        return -1;
    }

    memset(timer, 0, sizeof(*timer));
    timer->mode = QUIC_RECOVERY_TIMER_NONE;

    for (i = 0; i < QUIC_RECOVERY_PACKET_SPACE_COUNT; i++) {
        if (state->loss_time_ms[i] != 0 &&
            (earliest_loss_time == 0 || state->loss_time_ms[i] < earliest_loss_time)) {
            earliest_loss_time = state->loss_time_ms[i];
            earliest_loss_space = (uint8_t)i;
        }
    }

    if (earliest_loss_time != 0) {
        timer->mode = QUIC_RECOVERY_TIMER_LOSS;
        timer->packet_number_space = earliest_loss_space;
        timer->deadline_ms = earliest_loss_time;
        return 1;
    }

    // Anti-amplification 命中时，服务端不能靠 recovery timer 继续探测，只能等更多入站字节解锁。
    if (server_amplification_limited) {
        return 0;
    }

    if (state->bytes_in_flight == 0 && state->peer_completed_address_validation) {
        return 0;
    }

    base_duration = quic_recovery_pto_base(state) << state->pto_count;
    if (state->bytes_in_flight == 0) {
        // 没有在途包时仍保留 PTO：它负责驱动 crypto 数据或探测包重新发出，而不是等待永久静默。
        timer->mode = QUIC_RECOVERY_TIMER_PTO;
        timer->packet_number_space = (uint8_t)(has_handshake_keys ? 1 : 0);
        timer->deadline_ms = now_ms + base_duration;
        return 1;
    }

    for (i = 0; i < QUIC_RECOVERY_PACKET_SPACE_COUNT; i++) {
        uint64_t duration = base_duration;
        uint64_t candidate;

        if (!queues[i] || queues[i]->ack_eliciting_in_flight == 0) {
            continue;
        }
        if (i == 2) {
            if (!state->handshake_confirmed) {
                continue;
            }
            duration += state->max_ack_delay_ms << state->pto_count;
        }

        candidate = state->time_of_last_ack_eliciting_packet_ms[i] + duration;
        if (candidate < pto_timeout) {
            pto_timeout = candidate;
            pto_space = (uint8_t)i;
        }
    }

    if (pto_timeout == UINT64_MAX) {
        return 0;
    }

    timer->mode = QUIC_RECOVERY_TIMER_PTO;
    timer->packet_number_space = pto_space;
    timer->deadline_ms = pto_timeout;
    return 1;
}

int quic_recovery_on_timeout(quic_recovery_state_t *state,
                             quic_in_flight_queue_t *const queues[QUIC_RECOVERY_PACKET_SPACE_COUNT],
                             int server_amplification_limited,
                             int has_handshake_keys,
                             uint64_t now_ms,
                             quic_recovery_packet_observer_t on_lost,
                             void *observer_ctx,
                             quic_recovery_timer_t *timer,
                             size_t *lost_packets) {
    const quic_in_flight_queue_t *lookup[QUIC_RECOVERY_PACKET_SPACE_COUNT];
    size_t i;

    if (!state || !queues || !timer) {
        return -1;
    }
    if (lost_packets) {
        *lost_packets = 0;
    }
    for (i = 0; i < QUIC_RECOVERY_PACKET_SPACE_COUNT; i++) {
        lookup[i] = queues[i];
    }

    if (quic_recovery_get_timer(state,
                                lookup,
                                server_amplification_limited,
                                has_handshake_keys,
                                now_ms,
                                timer) <= 0) {
        timer->mode = QUIC_RECOVERY_TIMER_NONE;
        return 0;
    }
    if (timer->deadline_ms > now_ms) {
        return 0;
    }

    if (timer->mode == QUIC_RECOVERY_TIMER_LOSS) {
        return quic_recovery_detect_and_remove_lost_packets(state,
                                                            queues[timer->packet_number_space],
                                                            timer->packet_number_space,
                                                            now_ms,
                                                            on_lost,
                                                            observer_ctx,
                                                            lost_packets);
    }

    // PTO 本身不直接重传具体包；它只提高探测计数，具体探测内容由上层按空间选择 crypto restart 或 probe。
    state->pto_count++;
    return 0;
}

void quic_recovery_discard_space(quic_recovery_state_t *state,
                                 quic_in_flight_queue_t *q,
                                 uint8_t packet_number_space) {
    if (!state || !q || packet_number_space >= QUIC_RECOVERY_PACKET_SPACE_COUNT) {
        return;
    }

    if (state->bytes_in_flight >= q->bytes_in_flight) {
        state->bytes_in_flight -= q->bytes_in_flight;
    } else {
        state->bytes_in_flight = 0;
    }
    state->time_of_last_ack_eliciting_packet_ms[packet_number_space] = 0;
    state->loss_time_ms[packet_number_space] = 0;
    state->largest_acked_packet[packet_number_space] = UINT64_MAX;
    state->ecn_ce_counters[packet_number_space] = 0;
    state->pto_count = 0;
    quic_queue_clear(q);
}
