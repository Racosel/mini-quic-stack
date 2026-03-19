#ifndef QUIC_STREAM_H
#define QUIC_STREAM_H

#include "quic_crypto_stream.h"
#include <stddef.h>
#include <stdint.h>

#define QUIC_STREAM_MAX_COUNT 32
#define QUIC_STREAM_MAX_RETRANSMIT_RANGES 32

typedef struct {
    uint64_t start;
    uint64_t end;
} quic_stream_send_range_t;

typedef struct {
    uint8_t active;
    uint8_t local_initiated;
    uint8_t bidirectional;
    uint8_t send_open;
    uint8_t recv_open;
    uint8_t fin_requested;
    uint8_t fin_sent;
    uint8_t fin_in_flight;
    uint8_t fin_received;
    uint8_t stop_sending_pending;
    uint8_t stop_sending_in_flight;
    uint8_t stop_sending_received;
    uint8_t reset_pending;
    uint8_t reset_in_flight;
    uint8_t reset_received;
    uint8_t max_stream_data_pending;
    uint8_t max_stream_data_in_flight;
    uint8_t retired_for_streams_credit;
    uint64_t id;
    uint64_t send_max_data;
    uint64_t send_highest_offset;
    uint64_t send_final_size;
    uint8_t send_final_size_known;
    uint64_t recv_max_data;
    uint64_t recv_window_size;
    uint64_t recv_highest_offset;
    uint64_t recv_consumed_offset;
    uint64_t recv_final_size;
    uint8_t recv_final_size_known;
    uint64_t stop_error_code;
    uint64_t reset_error_code;
    uint64_t max_stream_data_to_send;
    quic_stream_send_range_t retransmit_ranges[QUIC_STREAM_MAX_RETRANSMIT_RANGES];
    size_t retransmit_range_count;
    quic_crypto_sendbuf_t sendbuf;
    quic_crypto_recvbuf_t recvbuf;
} quic_stream_t;

typedef struct {
    quic_stream_t streams[QUIC_STREAM_MAX_COUNT];
    uint8_t is_client;
    uint8_t local_limits_ready;
    uint8_t peer_limits_ready;
    uint64_t next_local_bidi_id;
    uint64_t next_local_uni_id;
    uint64_t local_bidi_local_limit;
    uint64_t local_bidi_remote_limit;
    uint64_t local_uni_limit;
    uint64_t peer_bidi_local_limit;
    uint64_t peer_bidi_remote_limit;
    uint64_t peer_uni_limit;
    uint64_t max_local_bidi_streams;
    uint64_t max_local_uni_streams;
    uint64_t max_remote_bidi_streams;
    uint64_t max_remote_uni_streams;
    uint64_t opened_local_bidi;
    uint64_t opened_local_uni;
    uint64_t opened_remote_bidi;
    uint64_t opened_remote_uni;
    uint64_t send_connection_max_data;
    uint64_t send_connection_highest;
    uint64_t recv_connection_max_data;
    uint64_t recv_connection_window_size;
    uint64_t recv_connection_highest;
    uint64_t recv_connection_consumed;
    uint8_t max_data_pending;
    uint8_t max_data_in_flight;
    uint64_t max_data_to_send;
    uint8_t max_streams_bidi_pending;
    uint8_t max_streams_bidi_in_flight;
    uint8_t max_streams_uni_pending;
    uint8_t max_streams_uni_in_flight;
    uint64_t max_streams_bidi_to_send;
    uint64_t max_streams_uni_to_send;
} quic_stream_map_t;

// 功能：初始化 stream map 和流控状态。
// 返回值：无。
void quic_stream_map_init(quic_stream_map_t *map, int is_client);
// 功能：释放 stream map 持有的所有流和缓冲区资源。
// 返回值：无。
void quic_stream_map_free(quic_stream_map_t *map);

// 功能：设置本端声明的连接/流级流控和 stream 数量限制。
// 返回值：无。
void quic_stream_map_set_local_limits(quic_stream_map_t *map,
                                      uint64_t max_data,
                                      uint64_t bidi_local,
                                      uint64_t bidi_remote,
                                      uint64_t uni,
                                      uint64_t max_streams_bidi,
                                      uint64_t max_streams_uni);
// 功能：设置对端声明的连接/流级流控和 stream 数量限制。
// 返回值：无。
void quic_stream_map_set_peer_limits(quic_stream_map_t *map,
                                     uint64_t max_data,
                                     uint64_t bidi_local,
                                     uint64_t bidi_remote,
                                     uint64_t uni,
                                     uint64_t max_streams_bidi,
                                     uint64_t max_streams_uni);

// 功能：在 stream map 中查找指定 stream。
// 返回值：非 NULL 表示找到；NULL 表示不存在。
quic_stream_t *quic_stream_map_find(quic_stream_map_t *map, uint64_t stream_id);
// 功能：以只读方式在 stream map 中查找指定 stream。
// 返回值：非 NULL 表示找到；NULL 表示不存在。
const quic_stream_t *quic_stream_map_find_const(const quic_stream_map_t *map, uint64_t stream_id);

// 功能：打开一个新的本地 stream。
// 返回值：0 表示成功；< 0 表示 stream 数量限制或状态不允许。
int quic_stream_map_open(quic_stream_map_t *map, int bidirectional, uint64_t *stream_id);
// 功能：向指定 stream 发送缓冲区写入数据，并可附带 FIN。
// 返回值：0 表示成功；< 0 表示流不存在、流控受限或状态不允许。
int quic_stream_map_write(quic_stream_map_t *map,
                          uint64_t stream_id,
                          const uint8_t *data,
                          size_t len,
                          int fin,
                          char *err,
                          size_t err_len);
// 功能：从指定 stream 读取数据。
// 返回值：0 表示成功；< 0 表示流不存在、输出参数无效或状态不允许。
int quic_stream_map_read(quic_stream_map_t *map,
                         uint64_t stream_id,
                         uint8_t *out,
                         size_t out_cap,
                         size_t *out_read,
                         int *out_fin,
                         char *err,
                         size_t err_len);
// 功能：查看指定 stream 的可读字节数和 FIN 状态，但不消费数据。
// 返回值：0 表示成功；< 0 表示流不存在或输出参数无效。
int quic_stream_map_peek(const quic_stream_map_t *map,
                         uint64_t stream_id,
                         size_t *available,
                         int *fin,
                         int *exists);
// 功能：标记需要向对端发送 STOP_SENDING。
// 返回值：0 表示成功；< 0 表示流不存在或状态不允许。
int quic_stream_map_stop_sending(quic_stream_map_t *map,
                                 uint64_t stream_id,
                                 uint64_t error_code,
                                 char *err,
                                 size_t err_len);
// 功能：标记需要向对端发送 RESET_STREAM。
// 返回值：0 表示成功；< 0 表示流不存在或状态不允许。
int quic_stream_map_reset(quic_stream_map_t *map,
                          uint64_t stream_id,
                          uint64_t error_code,
                          char *err,
                          size_t err_len);

// 功能：把收到的 STREAM frame 数据并入接收侧状态机。
// 返回值：0 表示成功；< 0 表示 final size 冲突、流非法或状态不允许。
int quic_stream_map_on_stream(quic_stream_map_t *map,
                              uint64_t stream_id,
                              uint64_t offset,
                              const uint8_t *data,
                              size_t len,
                              int fin,
                              char *err,
                              size_t err_len);
// 功能：处理收到的 RESET_STREAM。
// 返回值：0 表示成功；< 0 表示流非法、final size 冲突或状态不允许。
int quic_stream_map_on_reset_stream(quic_stream_map_t *map,
                                    uint64_t stream_id,
                                    uint64_t error_code,
                                    uint64_t final_size,
                                    char *err,
                                    size_t err_len);
// 功能：处理收到的 STOP_SENDING。
// 返回值：0 表示成功；< 0 表示流非法或状态不允许。
int quic_stream_map_on_stop_sending(quic_stream_map_t *map,
                                    uint64_t stream_id,
                                    uint64_t error_code,
                                    char *err,
                                    size_t err_len);
// 功能：处理收到的 MAX_DATA。
// 返回值：0 表示成功；< 0 表示输入非法。
int quic_stream_map_on_max_data(quic_stream_map_t *map, uint64_t max_data);
// 功能：处理收到的 MAX_STREAM_DATA。
// 返回值：0 表示成功；< 0 表示流非法或输入不合法。
int quic_stream_map_on_max_stream_data(quic_stream_map_t *map,
                                       uint64_t stream_id,
                                       uint64_t max_data,
                                       char *err,
                                       size_t err_len);
// 功能：处理收到的 MAX_STREAMS。
// 返回值：0 表示成功；< 0 表示输入不合法。
int quic_stream_map_on_max_streams(quic_stream_map_t *map, int bidirectional, uint64_t max_streams);

// 功能：判断是否仍有待发送的流控帧或 STREAM 数据。
// 返回值：非 0 表示有；0 表示没有。
int quic_stream_map_has_pending_output(const quic_stream_map_t *map);
// 功能：判断是否仍有缓冲中的发送数据。
// 返回值：非 0 表示有；0 表示没有。
int quic_stream_map_has_buffered_send_data(const quic_stream_map_t *map);
// 功能：判断当前是否处于流控受限状态。
// 返回值：非 0 表示流控受限；0 表示不是。
int quic_stream_map_is_flow_control_limited(const quic_stream_map_t *map);
// 功能：为下一个 STREAM 发送动作选择流、偏移和长度。
// 返回值：0 表示成功；< 0 表示当前没有可发送数据或状态不允许。
int quic_stream_map_prepare_stream_send(quic_stream_map_t *map,
                                        quic_stream_t **out_stream,
                                        uint64_t *out_offset,
                                        size_t *out_len,
                                        int *out_fin_only,
                                        int *out_is_retransmit);
// 功能：在真正发送 STREAM 数据后更新发送侧 flight 记录。
// 返回值：无。
void quic_stream_map_note_stream_send(quic_stream_map_t *map,
                                      quic_stream_t *stream,
                                      uint64_t offset,
                                      size_t len,
                                      int fin,
                                      int is_retransmit);
// 功能：在 STREAM 数据被确认后更新重传与发送状态。
// 返回值：无。
void quic_stream_map_on_stream_acked(quic_stream_map_t *map,
                                     uint64_t stream_id,
                                     uint64_t offset,
                                     size_t len);
// 功能：在 STREAM 数据丢失后把相应范围重新加入重传队列。
// 返回值：无。
void quic_stream_map_on_stream_lost(quic_stream_map_t *map,
                                    uint64_t stream_id,
                                    uint64_t offset,
                                    size_t len);
// 功能：重启当前 stream map 中所有 flight 的发送状态。
// 返回值：无。
void quic_stream_map_restart_flights(quic_stream_map_t *map);

#endif // QUIC_STREAM_H
