#ifndef QUIC_TLS_H
#define QUIC_TLS_H

#include "quic_connection.h"
#include "quic_crypto_stream.h"
#include "quic_transport_params.h"
#include <openssl/ssl.h>

#define QUIC_TLS_MAX_TRANSPORT_PARAMS 512
#define QUIC_TLS_MAX_DATAGRAM_SIZE 1400
#define QUIC_TLS_MAX_RETRY_TOKEN 256
#define QUIC_TLS_RETRANSMIT_TIMEOUT_MS 200

typedef enum {
    QUIC_ROLE_CLIENT = 0,
    QUIC_ROLE_SERVER = 1
} quic_role_t;

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
    uint8_t peer_address_validated;
    uint8_t special_packet_pending;
    uint8_t last_alert_level;
    uint8_t last_alert;
    uint8_t retry_token[QUIC_TLS_MAX_RETRY_TOKEN];
    size_t retry_token_len;
    uint8_t special_packet[QUIC_TLS_MAX_DATAGRAM_SIZE];
    size_t special_packet_len;
    uint64_t bytes_received;
    uint64_t bytes_sent;
    char error_message[256];
} quic_tls_conn_t;

void quic_tls_conn_init(quic_tls_conn_t *conn);
void quic_tls_conn_free(quic_tls_conn_t *conn);
int quic_tls_conn_configure(
    quic_tls_conn_t *conn,
    quic_role_t role,
    uint32_t version,
    const quic_cid_t *local_cid,
    const quic_cid_t *peer_cid,
    const char *cert_file,
    const char *key_file
);
int quic_tls_conn_start(quic_tls_conn_t *conn);
int quic_tls_conn_handle_datagram(quic_tls_conn_t *conn, const uint8_t *packet, size_t packet_len);
int quic_tls_conn_build_next_datagram(quic_tls_conn_t *conn, uint8_t *out, size_t out_len, size_t *written);
int quic_tls_conn_has_pending_output(const quic_tls_conn_t *conn);
void quic_tls_conn_on_loss_timeout(quic_tls_conn_t *conn, uint64_t now_ms);
uint64_t quic_tls_conn_loss_deadline_ms(const quic_tls_conn_t *conn);
void quic_tls_conn_enable_retry(quic_tls_conn_t *conn, int enabled);
void quic_tls_conn_queue_ping(quic_tls_conn_t *conn);
int quic_tls_conn_handshake_complete(const quic_tls_conn_t *conn);
const char *quic_tls_conn_last_error(const quic_tls_conn_t *conn);

#endif // QUIC_TLS_H：头文件保护结束
