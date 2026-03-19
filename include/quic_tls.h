#ifndef QUIC_TLS_H
#define QUIC_TLS_H

#include "quic_connection.h"
#include "quic_crypto_stream.h"
#include "quic_stream.h"
#include "quic_transport_params.h"
#include <openssl/ssl.h>

#define QUIC_TLS_MAX_TRANSPORT_PARAMS 512
#define QUIC_TLS_MAX_DATAGRAM_SIZE 1400
#define QUIC_TLS_MAX_RETRY_TOKEN 256
#define QUIC_TLS_RETRANSMIT_TIMEOUT_MS 200
#define QUIC_TLS_MAX_PATHS 4
#define QUIC_TLS_MAX_CID_POOL 8
#define QUIC_TLS_MAX_NEW_TOKEN_LEN 256
#define QUIC_TRANSPORT_ERROR_NO_ERROR 0x00
#define QUIC_TLS_BUILD_BLOCKED 1

typedef enum {
    QUIC_ROLE_CLIENT = 0,
    QUIC_ROLE_SERVER = 1
} quic_role_t;

typedef enum {
    QUIC_ADDR_FAMILY_NONE = 0,
    QUIC_ADDR_FAMILY_V4 = 4
} quic_addr_family_t;

typedef struct {
    uint8_t family;
    uint8_t addr[16];
    uint16_t port;
} quic_socket_addr_t;

typedef struct {
    quic_socket_addr_t local;
    quic_socket_addr_t peer;
} quic_path_addr_t;

typedef enum {
    QUIC_TLS_PATH_UNUSED = 0,
    QUIC_TLS_PATH_VALIDATING = 1,
    QUIC_TLS_PATH_VALIDATED = 2,
    QUIC_TLS_PATH_FAILED = 3
} quic_tls_path_state_t;

typedef struct {
    uint8_t active;
    uint8_t received_on_path;
    uint8_t challenge_pending;
    uint8_t challenge_in_flight;
    uint8_t challenge_expected;
    uint8_t response_pending;
    uint8_t response_in_flight;
    uint8_t mtu_probe_required;
    uint8_t mtu_validated;
    uint8_t peer_cid_seq_known;
    uint64_t peer_cid_sequence;
    uint64_t validation_deadline_ms;
    uint64_t bytes_received;
    uint64_t bytes_sent_before_validation;
    uint64_t local_challenge_token;
    uint64_t peer_challenge_token;
    quic_path_addr_t addr;
    quic_tls_path_state_t state;
} quic_tls_path_t;

typedef struct {
    uint8_t active;
    uint8_t issued;
    uint8_t retired;
    uint8_t retire_pending;
    uint8_t acked;
    uint64_t sequence;
    quic_cid_t cid;
    uint8_t stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];
} quic_tls_cid_state_t;

typedef struct {
    uint8_t present;
    quic_socket_addr_t peer_addr;
    quic_cid_t cid;
    uint8_t stateless_reset_token[QUIC_STATELESS_RESET_TOKEN_LEN];
} quic_tls_preferred_address_t;

typedef struct {
    quic_crypto_recvbuf_t recv;
    quic_crypto_sendbuf_t send;
    uint8_t read_secret_ready;
    uint8_t write_secret_ready;
    uint8_t discarded;
    uint8_t ack_pending;
} quic_tls_crypto_level_t;

typedef struct {
    quic_connection_t conn;
    quic_role_t role;
    uint32_t version;
    const quic_version_ops_t *version_ops;
    quic_cid_t local_cid;
    quic_cid_t peer_cid;
    quic_cid_t original_dcid;
    quic_cid_t initial_dcid;
    uint8_t peer_cid_known;
    uint8_t original_dcid_known;
    uint8_t initial_dcid_known;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    quic_tls_crypto_level_t levels[ssl_encryption_application + 1];
    quic_transport_params_t local_transport_params;
    quic_transport_params_t peer_transport_params;
    quic_stream_map_t streams;
    uint8_t local_transport_params_bytes[QUIC_TLS_MAX_TRANSPORT_PARAMS];
    size_t local_transport_params_len;
    uint8_t peer_transport_params_bytes[QUIC_TLS_MAX_TRANSPORT_PARAMS];
    size_t peer_transport_params_len;
    uint8_t transport_params_set;
    uint8_t peer_transport_params_ready;
    uint8_t handshake_complete;
    uint8_t application_secrets_ready;
    uint8_t received_handshake_packet;
    uint8_t received_version_negotiation;
    uint8_t initial_keys_discarded;
    uint8_t handshake_keys_discarded;
    uint8_t retry_required;
    uint8_t retry_processed;
    uint8_t handshake_done_pending;
    uint8_t handshake_done_in_flight;
    uint8_t handshake_done_received;
    uint8_t ping_pending;
    uint8_t ping_in_flight;
    uint8_t ping_received;
    uint8_t close_pending;
    uint8_t close_enter_draining_after_send;
    uint8_t close_received;
    uint8_t close_sent;
    uint8_t peer_address_validated;
    uint8_t peer_disable_active_migration;
    uint8_t ack_eliciting_sent_since_rx;
    uint8_t amplification_blocked;
    uint8_t special_packet_pending;
    uint8_t new_connection_id_pending;
    uint8_t new_connection_id_in_flight;
    uint8_t retire_connection_id_pending;
    uint8_t retire_connection_id_in_flight;
    uint8_t path_control_pending;
    uint8_t path_control_in_flight;
    uint8_t preferred_migration_pending;
    uint8_t new_token_pending;
    uint8_t new_token_in_flight;
    uint8_t stateless_reset_detected;
    uint8_t last_alert_level;
    uint8_t last_alert;
    uint8_t retry_token[QUIC_TLS_MAX_RETRY_TOKEN];
    size_t retry_token_len;
    uint8_t new_token_to_send[QUIC_TLS_MAX_NEW_TOKEN_LEN];
    size_t new_token_to_send_len;
    uint8_t special_packet[QUIC_TLS_MAX_DATAGRAM_SIZE];
    size_t special_packet_len;
    uint8_t close_packet[QUIC_TLS_MAX_DATAGRAM_SIZE];
    size_t close_packet_len;
    uint64_t bytes_received;
    uint64_t bytes_sent;
    uint64_t next_challenge_token;
    uint64_t close_deadline_ms;
    uint64_t idle_deadline_ms;
    uint64_t effective_idle_timeout_ms;
    uint64_t peer_close_error_code;
    uint64_t local_active_connection_id_limit;
    uint64_t peer_active_connection_id_limit;
    uint64_t next_local_cid_sequence;
    uint64_t pending_retire_sequence;
    uint64_t configured_max_idle_timeout_ms;
    uint64_t initial_max_data;
    uint64_t initial_max_stream_data_bidi_local;
    uint64_t initial_max_stream_data_bidi_remote;
    uint64_t initial_max_stream_data_uni;
    uint64_t initial_max_streams_bidi;
    uint64_t initial_max_streams_uni;
    size_t path_count;
    size_t active_path_index;
    size_t tx_path_index;
    size_t local_cid_count;
    size_t peer_cid_count;
    size_t active_local_cid_index;
    size_t active_peer_cid_index;
    size_t rx_path_index;
    size_t pending_issue_cid_index;
    size_t pending_retire_cid_index;
    size_t pending_path_index;
    size_t preferred_migration_path_index;
    quic_tls_path_t paths[QUIC_TLS_MAX_PATHS];
    quic_tls_cid_state_t local_cids[QUIC_TLS_MAX_CID_POOL];
    quic_tls_cid_state_t peer_cids[QUIC_TLS_MAX_CID_POOL];
    quic_tls_preferred_address_t local_preferred_address;
    quic_tls_preferred_address_t peer_preferred_address;
    char error_message[256];
} quic_tls_conn_t;

// 功能：初始化 IPv4 地址结构。
// 返回值：无。
void quic_socket_addr_init_ipv4(quic_socket_addr_t *addr, uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port);
// 功能：比较两个 socket 地址是否完全相同。
// 返回值：非 0 表示相同；0 表示不同。
int quic_socket_addr_equal(const quic_socket_addr_t *lhs, const quic_socket_addr_t *rhs);
// 功能：根据本地/对端 socket 地址初始化一个 path。
// 返回值：无。
void quic_path_addr_init(quic_path_addr_t *path, const quic_socket_addr_t *local, const quic_socket_addr_t *peer);

// 功能：初始化 QUIC+TLS 连接对象。
// 返回值：无。
void quic_tls_conn_init(quic_tls_conn_t *conn);
// 功能：释放 QUIC+TLS 连接对象持有的全部资源。
// 返回值：无。
void quic_tls_conn_free(quic_tls_conn_t *conn);
// 功能：配置 QUIC 连接的角色、版本、CID 和服务端证书/私钥。
// 返回值：0 表示成功；< 0 表示参数无效、TLS 初始化失败或版本不支持。
int quic_tls_conn_configure(
    quic_tls_conn_t *conn,
    quic_role_t role,
    uint32_t version,
    const quic_cid_t *local_cid,
    const quic_cid_t *peer_cid,
    const char *cert_file,
    const char *key_file
);
// 功能：启动客户端握手或把连接推进到可收发状态。
// 返回值：0 表示成功；< 0 表示连接未配置完成或启动失败。
int quic_tls_conn_start(quic_tls_conn_t *conn);
// 功能：在默认 path 上处理一个入站 datagram。
// 返回值：0 表示成功；< 0 表示解包、密钥、状态机或 frame 处理失败。
int quic_tls_conn_handle_datagram(quic_tls_conn_t *conn, const uint8_t *packet, size_t packet_len);
// 功能：在显式 path 上处理一个入站 datagram。
// 返回值：0 表示成功；< 0 表示 path 非法、解包失败或状态机拒绝。
int quic_tls_conn_handle_datagram_on_path(quic_tls_conn_t *conn,
                                          const uint8_t *packet,
                                          size_t packet_len,
                                          const quic_path_addr_t *path);
// 功能：在默认 path 上构造下一个待发送 datagram。
// 返回值：0 表示成功；`QUIC_TLS_BUILD_BLOCKED` 表示暂时不能发；其他非零表示错误。
int quic_tls_conn_build_next_datagram(quic_tls_conn_t *conn, uint8_t *out, size_t out_len, size_t *written);
// 功能：构造下一个待发送 datagram，并返回其发送 path。
// 返回值：0 表示成功；`QUIC_TLS_BUILD_BLOCKED` 表示暂时不能发；其他非零表示错误。
int quic_tls_conn_build_next_datagram_on_path(quic_tls_conn_t *conn,
                                              uint8_t *out,
                                              size_t out_len,
                                              size_t *written,
                                              quic_path_addr_t *out_path);
// 功能：判断连接当前是否仍有待发送输出。
// 返回值：非 0 表示仍有待发送输出；0 表示没有。
int quic_tls_conn_has_pending_output(const quic_tls_conn_t *conn);
// 功能：仅推进 loss timeout 相关逻辑。
// 返回值：无。
void quic_tls_conn_on_loss_timeout(quic_tls_conn_t *conn, uint64_t now_ms);
// 功能：查询当前 loss timeout 的截止时间。
// 返回值：绝对时间毫秒值；0 表示当前没有 loss 定时器。
uint64_t quic_tls_conn_loss_deadline_ms(const quic_tls_conn_t *conn);
// 功能：推进统一超时入口，包括 loss、path validation 和 idle timeout。
// 返回值：无。
void quic_tls_conn_on_timeout(quic_tls_conn_t *conn, uint64_t now_ms);
// 功能：查询下一次统一超时的截止时间。
// 返回值：绝对时间毫秒值；0 表示当前没有定时器。
uint64_t quic_tls_conn_next_timeout_ms(const quic_tls_conn_t *conn);
// 功能：开启或关闭 Retry 逻辑。
// 返回值：无。
void quic_tls_conn_enable_retry(quic_tls_conn_t *conn, int enabled);
// 功能：设置本端声明的最大 idle timeout。
// 返回值：无。
void quic_tls_conn_set_max_idle_timeout(quic_tls_conn_t *conn, uint64_t timeout_ms);
// 功能：设置连接的初始 path。
// 返回值：0 表示成功；< 0 表示 path 非法或状态不允许。
int quic_tls_conn_set_initial_path(quic_tls_conn_t *conn, const quic_path_addr_t *path);
// 功能：请求开始一次主动迁移或 preferred-address 迁移。
// 返回值：0 表示成功；< 0 表示状态不允许、path 非法或迁移前提未满足。
int quic_tls_conn_begin_migration(quic_tls_conn_t *conn, const quic_path_addr_t *path, int use_preferred_address);
// 功能：在服务端连接上配置要通过 transport parameters 通告给客户端的 preferred address。
// 返回值：0 表示成功；< 0 表示参数非法、CID/token 不合法或连接状态不允许。
int quic_tls_conn_set_server_preferred_address(quic_tls_conn_t *conn,
                                               const quic_socket_addr_t *peer_addr,
                                               const quic_cid_t *cid,
                                               const uint8_t *stateless_reset_token);
// 功能：读取对端通过 transport parameters 声明的 preferred address、CID 和 stateless reset token。
// 返回值：0 表示成功；< 0 表示当前没有可用 preferred address、输出参数无效或信息尚未就绪。
int quic_tls_conn_get_peer_preferred_address(const quic_tls_conn_t *conn,
                                             quic_path_addr_t *path,
                                             quic_cid_t *cid,
                                             uint8_t *stateless_reset_token);
// 功能：根据收到的未知连接 datagram 构造一个 stateless reset 响应。
// 返回值：0 表示成功；< 0 表示当前无法发送 stateless reset、输入长度非法或输出缓冲不足。
int quic_tls_conn_build_stateless_reset(const quic_tls_conn_t *conn,
                                        size_t received_datagram_len,
                                        uint8_t *out,
                                        size_t out_len,
                                        size_t *written);
// 功能：设置本端初始连接/流级流控额度，并同步到 transport parameters 与 stream map。
// 返回值：无。
void quic_tls_conn_set_initial_flow_control(quic_tls_conn_t *conn,
                                            uint64_t max_data,
                                            uint64_t max_stream_data_bidi_local,
                                            uint64_t max_stream_data_bidi_remote,
                                            uint64_t max_stream_data_uni,
                                            uint64_t max_streams_bidi,
                                            uint64_t max_streams_uni);
// 功能：打开一个新的本地 stream。
// 返回值：0 表示成功；< 0 表示 stream 数量限制、流控或状态不允许。
int quic_tls_conn_open_stream(quic_tls_conn_t *conn, int bidirectional, uint64_t *stream_id);
// 功能：向指定 stream 写入数据，并可选择带 FIN。
// 返回值：0 表示成功；< 0 表示流不存在、流控受限或状态不允许。
int quic_tls_conn_stream_write(quic_tls_conn_t *conn,
                               uint64_t stream_id,
                               const uint8_t *data,
                               size_t len,
                               int fin);
// 功能：从指定 stream 读取数据。
// 返回值：0 表示成功；< 0 表示流不存在、输出参数无效或状态不允许。
int quic_tls_conn_stream_read(quic_tls_conn_t *conn,
                              uint64_t stream_id,
                              uint8_t *out,
                              size_t out_cap,
                              size_t *out_read,
                              int *out_fin);
// 功能：查看指定 stream 当前可读字节数和 FIN 状态，但不消费数据。
// 返回值：0 表示成功；< 0 表示流不存在或输出参数无效。
int quic_tls_conn_stream_peek(const quic_tls_conn_t *conn,
                              uint64_t stream_id,
                              size_t *available,
                              int *fin,
                              int *exists);
// 功能：向对端发送 STOP_SENDING 请求。
// 返回值：0 表示成功；< 0 表示流不存在或当前状态不允许。
int quic_tls_conn_stop_sending(quic_tls_conn_t *conn, uint64_t stream_id, uint64_t error_code);
// 功能：向对端发送 RESET_STREAM。
// 返回值：0 表示成功；< 0 表示流不存在或当前状态不允许。
int quic_tls_conn_reset_stream(quic_tls_conn_t *conn, uint64_t stream_id, uint64_t error_code);
// 功能：排队一个待发送的 PING。
// 返回值：无。
void quic_tls_conn_queue_ping(quic_tls_conn_t *conn);
// 功能：请求发送 `CONNECTION_CLOSE`。
// 返回值：0 表示成功；< 0 表示状态不允许或构包失败。
int quic_tls_conn_close(quic_tls_conn_t *conn, uint64_t transport_error_code);
// 功能：判断握手是否已经完成。
// 返回值：非 0 表示已完成；0 表示未完成。
int quic_tls_conn_handshake_complete(const quic_tls_conn_t *conn);
// 功能：返回最近一次 TLS/QUIC 层错误文本。
// 返回值：始终返回可读字符串。 
const char *quic_tls_conn_last_error(const quic_tls_conn_t *conn);

#endif // QUIC_TLS_H：头文件保护结束
