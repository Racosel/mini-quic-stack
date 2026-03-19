#ifndef QUIC_API_H
#define QUIC_API_H

#include "quic_tls.h"
#include <stddef.h>
#include <stdint.h>

#define QUIC_API_MAX_EVENTS 128

typedef enum {
    QUIC_API_EVENT_NONE = 0,
    QUIC_API_EVENT_CONNECTION_STARTED = 1,
    QUIC_API_EVENT_HANDSHAKE_COMPLETE = 2,
    QUIC_API_EVENT_STREAM_OPENED = 3,
    QUIC_API_EVENT_STREAM_READABLE = 4,
    QUIC_API_EVENT_STREAM_FIN_RECEIVED = 5,
    QUIC_API_EVENT_PATH_VALIDATED = 6,
    QUIC_API_EVENT_ACTIVE_PATH_CHANGED = 7,
    QUIC_API_EVENT_PING_QUEUED = 8,
    QUIC_API_EVENT_CONNECTION_CLOSE_REQUESTED = 9,
    QUIC_API_EVENT_CONNECTION_STATE_CHANGED = 10,
    QUIC_API_EVENT_CONNECTION_CLOSED = 11
} quic_api_event_type_t;

typedef struct {
    uint64_t sequence;
    uint64_t time_ms;
    quic_api_event_type_t type;
    uint64_t stream_id;
    size_t path_index;
    uint64_t value_u64;
    quic_conn_state_t state;
} quic_api_event_t;

typedef struct {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t bytes_in_flight;
    uint64_t congestion_window;
    uint64_t latest_rtt_ms;
    uint64_t smoothed_rtt_ms;
    uint64_t pto_count;
    uint64_t events_emitted;
    uint64_t events_dropped;
    uint64_t streams_opened_local;
    uint64_t streams_opened_remote;
    uint64_t fin_streams_received;
    uint64_t connections_closed;
    size_t active_streams;
    size_t path_count;
    size_t active_path_index;
} quic_api_metrics_t;

typedef struct {
    quic_role_t role;
    quic_conn_state_t state;
    uint8_t handshake_complete;
    uint8_t application_secrets_ready;
    uint8_t has_pending_output;
    uint8_t close_received;
    uint8_t close_sent;
    uint8_t stateless_reset_detected;
    uint8_t ping_received;
    size_t path_count;
    size_t active_path_index;
    size_t pending_path_index;
} quic_api_conn_info_t;

typedef struct {
    uint8_t present;
    quic_tls_path_state_t state;
    quic_socket_addr_t local;
    quic_socket_addr_t peer;
    uint64_t bytes_received;
    uint64_t bytes_sent_before_validation;
    uint8_t challenge_pending;
    uint8_t challenge_in_flight;
    uint8_t challenge_expected;
    uint8_t response_pending;
    uint8_t response_in_flight;
    uint8_t mtu_validated;
} quic_api_path_info_t;

typedef struct {
    uint8_t exists;
    uint8_t local_initiated;
    uint8_t bidirectional;
    uint8_t send_open;
    uint8_t recv_open;
    uint8_t fin_sent;
    uint8_t fin_received;
    uint8_t reset_received;
    uint8_t stop_sending_received;
    size_t readable_bytes;
    uint64_t send_highest_offset;
    uint64_t recv_highest_offset;
    uint8_t recv_final_size_known;
    uint64_t recv_final_size;
} quic_api_stream_info_t;

typedef struct {
    quic_tls_conn_t tls;
    quic_api_event_t events[QUIC_API_MAX_EVENTS];
    size_t event_head;
    size_t event_count;
    uint64_t next_event_sequence;
    quic_api_metrics_t metrics;
    quic_conn_state_t observed_state;
    size_t observed_active_path_index;
    uint8_t observed_handshake_complete;
    uint8_t observed_path_state[QUIC_TLS_MAX_PATHS];
    uint8_t observed_stream_active[QUIC_STREAM_MAX_COUNT];
    uint8_t observed_stream_readable[QUIC_STREAM_MAX_COUNT];
    uint8_t observed_stream_fin[QUIC_STREAM_MAX_COUNT];
} quic_api_conn_t;

/* 功能：初始化对外 API 连接对象。 */
/* 返回值：无。 */
void quic_api_conn_init(quic_api_conn_t *conn);
/* 功能：释放对外 API 连接对象持有的所有内部资源。 */
/* 返回值：无。 */
void quic_api_conn_free(quic_api_conn_t *conn);
/* 功能：配置连接角色、版本、CID 以及服务端证书/私钥。 */
/* 返回值：0 表示成功；< 0 表示参数无效或 TLS/QUIC 初始化失败。 */
int quic_api_conn_configure(quic_api_conn_t *conn,
                            quic_role_t role,
                            uint32_t version,
                            const quic_cid_t *local_cid,
                            const quic_cid_t *peer_cid,
                            const char *cert_file,
                            const char *key_file);
/* 功能：开启或关闭 Retry 逻辑。 */
/* 返回值：无。 */
void quic_api_conn_enable_retry(quic_api_conn_t *conn, int enabled);
/* 功能：设置本端声明的最大 idle timeout。 */
/* 返回值：无。 */
void quic_api_conn_set_max_idle_timeout(quic_api_conn_t *conn, uint64_t timeout_ms);
/* 功能：设置连接和流的初始流控参数。 */
/* 返回值：无。 */
void quic_api_conn_set_initial_flow_control(quic_api_conn_t *conn,
                                            uint64_t max_data,
                                            uint64_t max_stream_data_bidi_local,
                                            uint64_t max_stream_data_bidi_remote,
                                            uint64_t max_stream_data_uni,
                                            uint64_t max_streams_bidi,
                                            uint64_t max_streams_uni);
/* 功能：设置连接的初始本地/对端 path。 */
/* 返回值：0 表示成功；< 0 表示 path 非法或连接状态不允许。 */
int quic_api_conn_set_initial_path(quic_api_conn_t *conn, const quic_path_addr_t *path);
/* 功能：在服务端连接上配置要发送给客户端的 preferred address。 */
/* 返回值：0 表示成功；< 0 表示参数非法、CID/token 不合法或状态不允许。 */
int quic_api_conn_set_server_preferred_address(quic_api_conn_t *conn,
                                               const quic_socket_addr_t *peer_addr,
                                               const quic_cid_t *cid,
                                               const uint8_t *stateless_reset_token);
/* 功能：读取对端在 transport parameters 中声明的 preferred address。 */
/* 返回值：0 表示成功；< 0 表示当前没有可用的 preferred address 或输出参数无效。 */
int quic_api_conn_get_peer_preferred_address(const quic_api_conn_t *conn,
                                             quic_path_addr_t *path,
                                             quic_cid_t *cid,
                                             uint8_t *stateless_reset_token);
/* 功能：请求开始一次主动迁移或 preferred-address 迁移。 */
/* 返回值：0 表示成功；< 0 表示状态不允许、path 非法或迁移前提未满足。 */
int quic_api_conn_begin_migration(quic_api_conn_t *conn, const quic_path_addr_t *path, int use_preferred_address);
/* 功能：启动连接，客户端会开始发送 Initial。 */
/* 返回值：0 表示成功；< 0 表示连接尚未配置完成或启动失败。 */
int quic_api_conn_start(quic_api_conn_t *conn);
/* 功能：在默认 path 上处理一个入站 datagram。 */
/* 返回值：0 表示成功；< 0 表示解包、状态机或密钥处理失败。 */
int quic_api_conn_handle_datagram(quic_api_conn_t *conn, const uint8_t *packet, size_t packet_len);
/* 功能：在显式指定 path 的前提下处理一个入站 datagram。 */
/* 返回值：0 表示成功；< 0 表示 path 非法、解包失败或状态机拒绝该数据报。 */
int quic_api_conn_handle_datagram_on_path(quic_api_conn_t *conn,
                                          const uint8_t *packet,
                                          size_t packet_len,
                                          const quic_path_addr_t *path);
/* 功能：在默认 path 上构造下一个待发送 datagram。 */
/* 返回值：0 表示成功；`QUIC_TLS_BUILD_BLOCKED` 表示暂时受发送约束阻塞；其他非零表示错误。 */
int quic_api_conn_build_next_datagram(quic_api_conn_t *conn, uint8_t *out, size_t out_len, size_t *written);
/* 功能：构造下一个待发送 datagram，并返回其目标 path。 */
/* 返回值：0 表示成功；`QUIC_TLS_BUILD_BLOCKED` 表示暂时受发送约束阻塞；其他非零表示错误。 */
int quic_api_conn_build_next_datagram_on_path(quic_api_conn_t *conn,
                                              uint8_t *out,
                                              size_t out_len,
                                              size_t *written,
                                              quic_path_addr_t *out_path);
/* 功能：判断连接当前是否仍有待发送数据。 */
/* 返回值：非 0 表示仍有待发送输出；0 表示当前没有。 */
int quic_api_conn_has_pending_output(const quic_api_conn_t *conn);
/* 功能：在给定时间点推进超时处理逻辑。 */
/* 返回值：无。 */
void quic_api_conn_on_timeout(quic_api_conn_t *conn, uint64_t now_ms);
/* 功能：查询下一次需要调用 `quic_api_conn_on_timeout()` 的时间。 */
/* 返回值：绝对时间毫秒值；0 表示当前没有定时器。 */
uint64_t quic_api_conn_next_timeout_ms(const quic_api_conn_t *conn);
/* 功能：读取连接级只读快照。 */
/* 返回值：0 表示成功；< 0 表示输出参数无效。 */
int quic_api_conn_get_info(const quic_api_conn_t *conn, quic_api_conn_info_t *out_info);
/* 功能：读取某条 path 的只读快照。 */
/* 返回值：0 表示成功；< 0 表示 path 索引越界或输出参数无效。 */
int quic_api_conn_get_path_info(const quic_api_conn_t *conn, size_t path_index, quic_api_path_info_t *out_info);
/* 功能：打开一个新的本地 stream。 */
/* 返回值：0 表示成功；< 0 表示流数量限制、状态不允许或参数无效。 */
int quic_api_conn_open_stream(quic_api_conn_t *conn, int bidirectional, uint64_t *stream_id);
/* 功能：向指定 stream 写入数据，并可选择带 FIN。 */
/* 返回值：0 表示成功；< 0 表示流不存在、流控受限或状态不允许。 */
int quic_api_conn_stream_write(quic_api_conn_t *conn,
                               uint64_t stream_id,
                               const uint8_t *data,
                               size_t len,
                               int fin);
/* 功能：从指定 stream 读取数据。 */
/* 返回值：0 表示成功；< 0 表示流不存在、读取参数非法或状态不允许。 */
int quic_api_conn_stream_read(quic_api_conn_t *conn,
                              uint64_t stream_id,
                              uint8_t *out,
                              size_t out_cap,
                              size_t *out_read,
                              int *out_fin);
/* 功能：查看指定 stream 当前可读字节数和 FIN 状态，但不消费数据。 */
/* 返回值：0 表示成功；< 0 表示流不存在或输出参数无效。 */
int quic_api_conn_stream_peek(const quic_api_conn_t *conn,
                              uint64_t stream_id,
                              size_t *available,
                              int *fin,
                              int *exists);
/* 功能：读取指定 stream 的只读快照。 */
/* 返回值：0 表示调用成功；若流不存在则 `out_info->exists` 为 0。 */
int quic_api_conn_get_stream_info(const quic_api_conn_t *conn, uint64_t stream_id, quic_api_stream_info_t *out_info);
/* 功能：向对端发送 STOP_SENDING 请求。 */
/* 返回值：0 表示成功；< 0 表示流不存在或当前状态不允许。 */
int quic_api_conn_stop_sending(quic_api_conn_t *conn, uint64_t stream_id, uint64_t error_code);
/* 功能：向对端发送 RESET_STREAM。 */
/* 返回值：0 表示成功；< 0 表示流不存在或当前状态不允许。 */
int quic_api_conn_reset_stream(quic_api_conn_t *conn, uint64_t stream_id, uint64_t error_code);
/* 功能：排队一个待发送的 PING。 */
/* 返回值：无。 */
void quic_api_conn_queue_ping(quic_api_conn_t *conn);
/* 功能：请求发送 `CONNECTION_CLOSE`。 */
/* 返回值：0 表示成功；< 0 表示当前状态不允许或构包失败。 */
int quic_api_conn_close(quic_api_conn_t *conn, uint64_t transport_error_code);
/* 功能：判断握手是否完成。 */
/* 返回值：非 0 表示已完成握手；0 表示尚未完成。 */
int quic_api_conn_handshake_complete(const quic_api_conn_t *conn);
/* 功能：返回最近一次 API/TLS 层错误信息。 */
/* 返回值：始终返回可读字符串；参数无效时返回兜底错误文本。 */
const char *quic_api_conn_last_error(const quic_api_conn_t *conn);
/* 功能：读取当前 metrics 快照。 */
/* 返回值：0 表示成功；< 0 表示输出参数无效。 */
int quic_api_conn_get_metrics(quic_api_conn_t *conn, quic_api_metrics_t *out_metrics);
/* 功能：从事件队列中弹出一个事件。 */
/* 返回值：0 表示成功取到事件；< 0 表示当前没有事件或参数无效。 */
int quic_api_conn_poll_event(quic_api_conn_t *conn, quic_api_event_t *out_event);
/* 功能：返回事件类型对应的人类可读名称。 */
/* 返回值：始终返回静态字符串。 */
const char *quic_api_event_name(quic_api_event_type_t type);
/* 功能：把一个事件格式化为 qlog 风格 JSON 行。 */
/* 返回值：0 表示成功；< 0 表示输出缓冲区不足或参数无效。 */
int quic_api_event_format_json(const quic_api_event_t *event, char *out, size_t out_cap);
/* 功能：把 metrics 快照格式化为 JSON。 */
/* 返回值：0 表示成功；< 0 表示输出缓冲区不足或参数无效。 */
int quic_api_metrics_format_json(const quic_api_metrics_t *metrics, char *out, size_t out_cap);
/* 功能：返回底层 `quic_tls_conn_t` 指针，供调试或过渡阶段直接查看内部状态。 */
/* 返回值：非 NULL 表示有效底层连接；NULL 表示输入连接无效。 */
const quic_tls_conn_t *quic_api_conn_raw(const quic_api_conn_t *conn);

#endif // QUIC_API_H
