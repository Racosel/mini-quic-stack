#ifndef QUIC_RECOVERY_H
#define QUIC_RECOVERY_H

#include "quic_types.h"
#include <stddef.h>
#include <stdint.h>

#define QUIC_RECOVERY_INITIAL_RTT_MS 333ULL
#define QUIC_RECOVERY_GRANULARITY_MS 1ULL
#define QUIC_RECOVERY_PACKET_THRESHOLD 3ULL
#define QUIC_RECOVERY_TIME_THRESHOLD_NUM 9ULL
#define QUIC_RECOVERY_TIME_THRESHOLD_DEN 8ULL
#define QUIC_RECOVERY_LOSS_REDUCTION_NUM 1ULL
#define QUIC_RECOVERY_LOSS_REDUCTION_DEN 2ULL
#define QUIC_RECOVERY_PERSISTENT_CONGESTION_THRESHOLD 3ULL
#define QUIC_RECOVERY_PACKET_SPACE_COUNT 3U

typedef struct {
    uint8_t includes_crypto;
    uint8_t includes_stream;
    uint8_t stream_fin;
    uint8_t includes_ping;
    uint8_t includes_handshake_done;
    uint8_t includes_max_data;
    uint8_t includes_max_streams_bidi;
    uint8_t includes_max_streams_uni;
    uint8_t includes_stop_sending;
    uint8_t includes_reset_stream;
    uint8_t includes_max_stream_data;
    uint64_t stream_id;
    uint64_t control_stream_id;
    uint64_t stream_offset;
    uint64_t stream_length;
} quic_sent_packet_meta_t;

// 记录已发送包的元数据
typedef struct quic_sent_packet {
    uint64_t packet_number;
    uint64_t sent_time_ms;
    size_t sent_bytes;
    uint8_t is_ack_eliciting;
    uint8_t in_flight;
    uint8_t is_crypto_packet;
    uint8_t is_pto_probe;
    uint8_t packet_number_space;
    uint8_t app_limited;
    uint8_t flow_control_limited;
    quic_sent_packet_meta_t meta;
    struct quic_sent_packet *next;
    struct quic_sent_packet *prev;
} quic_sent_packet_t;

// 飞行队列管理结构
typedef struct {
    quic_sent_packet_t *head;
    quic_sent_packet_t *tail;
    uint64_t bytes_in_flight;
    uint64_t largest_acked_packet;
    size_t ack_eliciting_in_flight;
} quic_in_flight_queue_t;

typedef struct {
    uint64_t latest_rtt_ms;
    uint64_t smoothed_rtt_ms;
    uint64_t rttvar_ms;
    uint64_t min_rtt_ms;
    uint64_t first_rtt_sample_ms;
    uint64_t max_ack_delay_ms;
    uint64_t pto_count;
    uint64_t loss_time_ms[QUIC_RECOVERY_PACKET_SPACE_COUNT];
    uint64_t largest_acked_packet[QUIC_RECOVERY_PACKET_SPACE_COUNT];
    uint64_t time_of_last_ack_eliciting_packet_ms[QUIC_RECOVERY_PACKET_SPACE_COUNT];
    uint64_t ecn_ce_counters[QUIC_RECOVERY_PACKET_SPACE_COUNT];
    uint64_t bytes_in_flight;
    uint64_t congestion_window;
    uint64_t ssthresh;
    uint64_t congestion_recovery_start_time_ms;
    uint64_t max_datagram_size;
    uint8_t handshake_confirmed;
    uint8_t peer_completed_address_validation;
} quic_recovery_state_t;

typedef enum {
    QUIC_RECOVERY_TIMER_NONE = 0,
    QUIC_RECOVERY_TIMER_LOSS = 1,
    QUIC_RECOVERY_TIMER_PTO = 2
} quic_recovery_timer_mode_t;

typedef struct {
    quic_recovery_timer_mode_t mode;
    uint8_t packet_number_space;
    uint64_t deadline_ms;
} quic_recovery_timer_t;

typedef void (*quic_recovery_packet_observer_t)(void *ctx, const quic_sent_packet_t *packet);

void quic_queue_init(quic_in_flight_queue_t *q);
void quic_queue_clear(quic_in_flight_queue_t *q);
void quic_on_packet_sent(quic_in_flight_queue_t *q, uint64_t pn, size_t len, int ack_eliciting);
void quic_on_packet_acked(quic_in_flight_queue_t *q, uint64_t pn);
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
                            const quic_sent_packet_meta_t *meta);
const quic_sent_packet_t *quic_recovery_oldest_unacked(const quic_in_flight_queue_t *q);

void quic_recovery_init(quic_recovery_state_t *state, uint64_t max_datagram_size);
void quic_recovery_set_max_ack_delay(quic_recovery_state_t *state, uint64_t max_ack_delay_ms);
void quic_recovery_set_handshake_confirmed(quic_recovery_state_t *state, int confirmed);
void quic_recovery_set_peer_completed_address_validation(quic_recovery_state_t *state, int validated);
int quic_recovery_can_send(const quic_recovery_state_t *state, size_t sent_bytes);
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
                                  const quic_sent_packet_meta_t *meta);
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
                                  size_t *lost_packets);
int quic_recovery_get_timer(const quic_recovery_state_t *state,
                            const quic_in_flight_queue_t *const queues[QUIC_RECOVERY_PACKET_SPACE_COUNT],
                            int server_amplification_limited,
                            int has_handshake_keys,
                            uint64_t now_ms,
                            quic_recovery_timer_t *timer);
int quic_recovery_on_timeout(quic_recovery_state_t *state,
                             quic_in_flight_queue_t *const queues[QUIC_RECOVERY_PACKET_SPACE_COUNT],
                             int server_amplification_limited,
                             int has_handshake_keys,
                             uint64_t now_ms,
                             quic_recovery_packet_observer_t on_lost,
                             void *observer_ctx,
                             quic_recovery_timer_t *timer,
                             size_t *lost_packets);
void quic_recovery_discard_space(quic_recovery_state_t *state,
                                 quic_in_flight_queue_t *q,
                                 uint8_t packet_number_space);

#endif // QUIC_RECOVERY_H：头文件保护结束
