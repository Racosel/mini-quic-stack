#include "quic_tls.h"
#include "pkt_decode.h"
#include "quic_crypto.h"
#include "quic_frame.h"
#include "quic_initial.h"
#include "quic_packet_protection.h"
#include "quic_varint.h"
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define QUIC_TLS_CIPHER_AES_128_GCM_SHA256 0x1301
#define QUIC_TLS_MAX_CRYPTO_CHUNK 1000

static const uint8_t quic_tls_alpn[] = { 0x07, 'a', 'i', '-', 'q', 'u', 'i', 'c' };

typedef struct {
    quic_pkt_header_meta_t meta;
    quic_pn_space_id_t space;
    enum ssl_encryption_level_t level;
    size_t pn_offset;
} quic_tls_packet_header_t;

static uint64_t quic_tls_now_ms(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

static int quic_tls_server_alpn_cb(SSL *ssl,
                                   const uint8_t **out,
                                   uint8_t *out_len,
                                   const uint8_t *in,
                                   unsigned int in_len,
                                   void *arg) {
    size_t offset = 0;
    (void)ssl;
    (void)arg;

    while (offset < in_len) {
        uint8_t proto_len = in[offset++];
        if (offset + proto_len > in_len) {
            break;
        }
        if (proto_len == quic_tls_alpn[0] &&
            memcmp(in + offset, quic_tls_alpn + 1, proto_len) == 0) {
            *out = quic_tls_alpn + 1;
            *out_len = proto_len;
            return SSL_TLSEXT_ERR_OK;
        }
        offset += proto_len;
    }

    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static void quic_tls_set_error(quic_tls_conn_t *conn, const char *message) {
    if (!conn || !message) {
        return;
    }
    snprintf(conn->error_message, sizeof(conn->error_message), "%s", message);
}

static int quic_tls_fail(quic_tls_conn_t *conn, const char *message) {
    quic_tls_set_error(conn, message);
    return -1;
}

static int quic_tls_fail_ssl(quic_tls_conn_t *conn, const char *prefix) {
    unsigned long err = ERR_get_error();
    char detail[160];

    if (err != 0) {
        ERR_error_string_n(err, detail, sizeof(detail));
    } else {
        snprintf(detail, sizeof(detail), "unknown ssl error");
    }
    snprintf(conn->error_message, sizeof(conn->error_message), "%s: %s", prefix, detail);
    return -1;
}

static quic_tls_conn_t *quic_tls_from_ssl(SSL *ssl) {
    return (quic_tls_conn_t *)SSL_get_app_data(ssl);
}

static size_t quic_tls_varint_len(uint64_t value) {
    uint8_t scratch[8];
    int rc = quic_encode_varint(value, scratch, sizeof(scratch));
    return rc < 0 ? 0 : (size_t)rc;
}

static quic_pn_space_id_t quic_tls_space_from_level(enum ssl_encryption_level_t level) {
    switch (level) {
        case ssl_encryption_initial:
            return QUIC_PN_SPACE_INITIAL;
        case ssl_encryption_handshake:
            return QUIC_PN_SPACE_HANDSHAKE;
        case ssl_encryption_application:
            return QUIC_PN_SPACE_APPLICATION;
        default:
            return QUIC_PN_SPACE_COUNT;
    }
}

static int quic_tls_is_supported_level(enum ssl_encryption_level_t level) {
    return level == ssl_encryption_initial ||
           level == ssl_encryption_handshake ||
           level == ssl_encryption_application;
}

static int quic_tls_has_live_flight(const quic_tls_conn_t *conn) {
    size_t i;

    if (!conn) {
        return 0;
    }

    if (conn->ping_pending ||
        conn->ping_in_flight ||
        conn->handshake_done_pending ||
        conn->handshake_done_in_flight) {
        return 1;
    }

    for (i = 0; i <= ssl_encryption_application; i++) {
        const quic_crypto_sendbuf_t *send = &conn->levels[i].send;
        if (send->flight_pending && send->flight_end > send->flight_start) {
            return 1;
        }
    }
    return 0;
}

static int quic_tls_level_has_sendable_output(const quic_tls_conn_t *conn, enum ssl_encryption_level_t level) {
    quic_pn_space_id_t space = quic_tls_space_from_level(level);

    if (!conn || space == QUIC_PN_SPACE_COUNT) {
        return 0;
    }
    return quic_crypto_sendbuf_has_pending(&conn->levels[level].send) &&
           conn->conn.spaces[space].tx_keys_ready;
}

static void quic_tls_arm_loss_timer(quic_tls_conn_t *conn) {
    if (!conn) {
        return;
    }
    if (quic_tls_has_live_flight(conn)) {
        quic_conn_arm_timer(&conn->conn,
                            QUIC_CONN_TIMER_LOSS_DETECTION,
                            quic_tls_now_ms() + QUIC_TLS_RETRANSMIT_TIMEOUT_MS);
    } else {
        quic_conn_disarm_timer(&conn->conn, QUIC_CONN_TIMER_LOSS_DETECTION);
    }
}

static int quic_tls_update_peer_transport_params(quic_tls_conn_t *conn) {
    const uint8_t *params = NULL;
    size_t params_len = 0;

    if (!conn || !conn->ssl || conn->peer_transport_params_ready) {
        return 0;
    }

    SSL_get_peer_quic_transport_params(conn->ssl, &params, &params_len);
    if (!params || params_len == 0) {
        return 0;
    }
    if (params_len > sizeof(conn->peer_transport_params_bytes)) {
        return quic_tls_fail(conn, "peer transport params too large");
    }

    memcpy(conn->peer_transport_params_bytes, params, params_len);
    conn->peer_transport_params_len = params_len;
    if (quic_transport_params_decode(conn->peer_transport_params_bytes,
                                     conn->peer_transport_params_len,
                                     &conn->peer_transport_params) != 0) {
        return quic_tls_fail(conn, "failed to decode peer transport params");
    }

    conn->peer_transport_params_ready = 1;
    return 0;
}

static void quic_tls_maybe_discard_keys(quic_tls_conn_t *conn) {
    if (!conn) {
        return;
    }

    if (conn->received_handshake_packet &&
        conn->levels[ssl_encryption_initial].send.send_offset >= conn->levels[ssl_encryption_initial].send.flight_end &&
        !conn->initial_keys_discarded) {
        quic_conn_discard_space(&conn->conn, QUIC_PN_SPACE_INITIAL);
        conn->levels[ssl_encryption_initial].discarded = 1;
        conn->levels[ssl_encryption_initial].read_secret_ready = 0;
        conn->levels[ssl_encryption_initial].write_secret_ready = 0;
        conn->initial_keys_discarded = 1;
    }

    if (conn->handshake_complete &&
        conn->application_secrets_ready &&
        conn->levels[ssl_encryption_handshake].send.send_offset >= conn->levels[ssl_encryption_handshake].send.flight_end &&
        ((conn->role == QUIC_ROLE_CLIENT && (conn->handshake_done_received || conn->ping_received)) ||
         (conn->role == QUIC_ROLE_SERVER && conn->ping_received)) &&
        !conn->handshake_keys_discarded) {
        quic_conn_discard_space(&conn->conn, QUIC_PN_SPACE_HANDSHAKE);
        conn->levels[ssl_encryption_handshake].discarded = 1;
        conn->levels[ssl_encryption_handshake].read_secret_ready = 0;
        conn->levels[ssl_encryption_handshake].write_secret_ready = 0;
        conn->handshake_keys_discarded = 1;
    }
}

static int quic_tls_set_transport_params(quic_tls_conn_t *conn) {
    int encoded_len;

    if (!conn || !conn->ssl || !conn->local_cid.len) {
        return quic_tls_fail(conn, "transport params missing local cid");
    }

    quic_transport_params_init(&conn->local_transport_params);
    conn->local_transport_params.max_udp_payload_size.present = 1;
    conn->local_transport_params.max_udp_payload_size.value = 1200;
    conn->local_transport_params.max_idle_timeout.present = 1;
    conn->local_transport_params.max_idle_timeout.value = 30000;
    conn->local_transport_params.initial_max_data.present = 1;
    conn->local_transport_params.initial_max_data.value = 65536;
    conn->local_transport_params.initial_max_stream_data_bidi_local.present = 1;
    conn->local_transport_params.initial_max_stream_data_bidi_local.value = 16384;
    conn->local_transport_params.initial_max_stream_data_bidi_remote.present = 1;
    conn->local_transport_params.initial_max_stream_data_bidi_remote.value = 16384;
    conn->local_transport_params.initial_max_stream_data_uni.present = 1;
    conn->local_transport_params.initial_max_stream_data_uni.value = 16384;
    conn->local_transport_params.initial_max_streams_bidi.present = 1;
    conn->local_transport_params.initial_max_streams_bidi.value = 4;
    conn->local_transport_params.initial_max_streams_uni.present = 1;
    conn->local_transport_params.initial_max_streams_uni.value = 4;
    conn->local_transport_params.active_connection_id_limit.present = 1;
    conn->local_transport_params.active_connection_id_limit.value = 4;
    conn->local_transport_params.initial_source_connection_id.present = 1;
    conn->local_transport_params.initial_source_connection_id.cid = conn->local_cid;
    if (conn->role == QUIC_ROLE_SERVER) {
        if (!conn->original_dcid_known) {
            return quic_tls_fail(conn, "server original dcid unavailable");
        }
        conn->local_transport_params.original_destination_connection_id.present = 1;
        conn->local_transport_params.original_destination_connection_id.cid = conn->original_dcid;
    }

    encoded_len = quic_transport_params_encode(&conn->local_transport_params,
                                               conn->local_transport_params_bytes,
                                               sizeof(conn->local_transport_params_bytes));
    if (encoded_len < 0) {
        return quic_tls_fail(conn, "failed to encode local transport params");
    }
    conn->local_transport_params_len = (size_t)encoded_len;

    if (SSL_set_quic_transport_params(conn->ssl,
                                      conn->local_transport_params_bytes,
                                      conn->local_transport_params_len) != 1) {
        return quic_tls_fail_ssl(conn, "failed to set local transport params");
    }

    conn->transport_params_set = 1;
    return 0;
}

static int quic_tls_install_initial_keys(quic_tls_conn_t *conn) {
    quic_crypto_context_t initial;

    if (!conn || !conn->version_ops || !conn->original_dcid_known) {
        return quic_tls_fail(conn, "initial key prerequisites missing");
    }
    if (conn->levels[ssl_encryption_initial].read_secret_ready &&
        conn->levels[ssl_encryption_initial].write_secret_ready) {
        return 0;
    }

    if (quic_crypto_setup_initial_keys(&conn->original_dcid, conn->version_ops, &initial) != 0) {
        return quic_tls_fail(conn, "failed to derive initial keys");
    }

    conn->conn.version = conn->version;
    conn->conn.version_ops = conn->version_ops;
    conn->conn.original_dcid = conn->original_dcid;
    conn->conn.state = QUIC_CONN_STATE_HANDSHAKING;

    if (conn->role == QUIC_ROLE_CLIENT) {
        if (quic_conn_install_tx_keys(&conn->conn, QUIC_PN_SPACE_INITIAL, &initial.client_initial) != QUIC_CONN_OK) {
            return quic_tls_fail(conn, "failed to install client initial tx keys");
        }
        if (quic_conn_install_rx_keys(&conn->conn, QUIC_PN_SPACE_INITIAL, &initial.server_initial) != QUIC_CONN_OK) {
            return quic_tls_fail(conn, "failed to install client initial rx keys");
        }
    } else {
        if (quic_conn_install_rx_keys(&conn->conn, QUIC_PN_SPACE_INITIAL, &initial.client_initial) != QUIC_CONN_OK) {
            return quic_tls_fail(conn, "failed to install server initial rx keys");
        }
        if (quic_conn_install_tx_keys(&conn->conn, QUIC_PN_SPACE_INITIAL, &initial.server_initial) != QUIC_CONN_OK) {
            return quic_tls_fail(conn, "failed to install server initial tx keys");
        }
    }

    conn->levels[ssl_encryption_initial].read_secret_ready = 1;
    conn->levels[ssl_encryption_initial].write_secret_ready = 1;
    return 0;
}

static int quic_tls_install_secret(quic_tls_conn_t *conn,
                                   enum ssl_encryption_level_t level,
                                   const SSL_CIPHER *cipher,
                                   const uint8_t *secret,
                                   size_t secret_len,
                                   int is_write) {
    quic_crypto_level_ctx_t packet_keys;
    quic_pn_space_id_t space;
    uint16_t cipher_id;

    if (!conn || !cipher || !secret) {
        return 0;
    }
    if (!quic_tls_is_supported_level(level)) {
        quic_tls_set_error(conn, "0-rtt is not implemented");
        return 0;
    }

    cipher_id = SSL_CIPHER_get_protocol_id(cipher);
    if (cipher_id != QUIC_TLS_CIPHER_AES_128_GCM_SHA256) {
        quic_tls_set_error(conn, "only TLS_AES_128_GCM_SHA256 is supported");
        return 0;
    }
    if (quic_crypto_derive_packet_keys(secret, secret_len, conn->version_ops, &packet_keys) != 0) {
        quic_tls_set_error(conn, "failed to derive packet protection keys");
        return 0;
    }

    space = quic_tls_space_from_level(level);
    if (space == QUIC_PN_SPACE_COUNT) {
        quic_tls_set_error(conn, "invalid encryption level");
        return 0;
    }

    if (is_write) {
        if (quic_conn_install_tx_keys(&conn->conn, space, &packet_keys) != QUIC_CONN_OK) {
            quic_tls_set_error(conn, "failed to install tx keys");
            return 0;
        }
        conn->levels[level].write_secret_ready = 1;
    } else {
        if (quic_conn_install_rx_keys(&conn->conn, space, &packet_keys) != QUIC_CONN_OK) {
            quic_tls_set_error(conn, "failed to install rx keys");
            return 0;
        }
        conn->levels[level].read_secret_ready = 1;
    }

    if (level == ssl_encryption_application &&
        conn->levels[level].read_secret_ready &&
        conn->levels[level].write_secret_ready) {
        conn->application_secrets_ready = 1;
    }

    quic_tls_maybe_discard_keys(conn);
    return 1;
}

static int quic_tls_set_read_secret_cb(SSL *ssl,
                                       enum ssl_encryption_level_t level,
                                       const SSL_CIPHER *cipher,
                                       const uint8_t *secret,
                                       size_t secret_len) {
    return quic_tls_install_secret(quic_tls_from_ssl(ssl), level, cipher, secret, secret_len, 0);
}

static int quic_tls_set_write_secret_cb(SSL *ssl,
                                        enum ssl_encryption_level_t level,
                                        const SSL_CIPHER *cipher,
                                        const uint8_t *secret,
                                        size_t secret_len) {
    return quic_tls_install_secret(quic_tls_from_ssl(ssl), level, cipher, secret, secret_len, 1);
}

static int quic_tls_add_handshake_data_cb(SSL *ssl,
                                          enum ssl_encryption_level_t level,
                                          const uint8_t *data,
                                          size_t len) {
    quic_tls_conn_t *conn = quic_tls_from_ssl(ssl);

    if (!conn || !quic_tls_is_supported_level(level)) {
        return 0;
    }
    if (quic_crypto_sendbuf_append(&conn->levels[level].send, data, len) != 0) {
        quic_tls_set_error(conn, "failed to append handshake data");
        return 0;
    }
    return 1;
}

static int quic_tls_flush_flight_cb(SSL *ssl) {
    quic_tls_conn_t *conn = quic_tls_from_ssl(ssl);
    size_t i;

    if (!conn) {
        return 0;
    }

    for (i = 0; i <= ssl_encryption_application; i++) {
        quic_crypto_sendbuf_mark_flight(&conn->levels[i].send);
    }
    quic_tls_arm_loss_timer(conn);
    return 1;
}

static int quic_tls_send_alert_cb(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert) {
    quic_tls_conn_t *conn = quic_tls_from_ssl(ssl);

    if (!conn) {
        return 0;
    }
    conn->last_alert_level = (uint8_t)level;
    conn->last_alert = alert;
    return 1;
}

static const SSL_QUIC_METHOD quic_tls_quic_method = {
    .set_read_secret = quic_tls_set_read_secret_cb,
    .set_write_secret = quic_tls_set_write_secret_cb,
    .add_handshake_data = quic_tls_add_handshake_data_cb,
    .flush_flight = quic_tls_flush_flight_cb,
    .send_alert = quic_tls_send_alert_cb,
};

static int quic_tls_drive_handshake(quic_tls_conn_t *conn) {
    int ret;

    if (!conn || !conn->ssl) {
        return quic_tls_fail(conn, "tls object unavailable");
    }

    ret = SSL_do_handshake(conn->ssl);
    if (ret == 1) {
        conn->handshake_complete = 1;
        conn->conn.state = QUIC_CONN_STATE_ACTIVE;
        if (conn->role == QUIC_ROLE_SERVER) {
            conn->handshake_done_pending = 1;
        }
        if (quic_tls_update_peer_transport_params(conn) != 0) {
            return -1;
        }
        quic_tls_maybe_discard_keys(conn);
        quic_tls_arm_loss_timer(conn);
        return 0;
    }

    ret = SSL_get_error(conn->ssl, ret);
    if (ret == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE) {
        quic_tls_arm_loss_timer(conn);
        return 0;
    }

    return quic_tls_fail_ssl(conn, "tls handshake failed");
}

static int quic_tls_feed_crypto(quic_tls_conn_t *conn, enum ssl_encryption_level_t level, int *fed_anything) {
    size_t contiguous;
    const uint8_t *ptr;

    if (!conn || !fed_anything) {
        return quic_tls_fail(conn, "invalid crypto feed arguments");
    }

    while ((contiguous = quic_crypto_recvbuf_contiguous_len(&conn->levels[level].recv)) > 0) {
        ptr = quic_crypto_recvbuf_read_ptr(&conn->levels[level].recv);
        if (SSL_provide_quic_data(conn->ssl, level, ptr, contiguous) != 1) {
            return quic_tls_fail_ssl(conn, "failed to provide quic crypto data");
        }
        quic_crypto_recvbuf_consume(&conn->levels[level].recv, contiguous);
        *fed_anything = 1;
    }
    return 0;
}

static int quic_tls_parse_frames(quic_tls_conn_t *conn,
                                 enum ssl_encryption_level_t level,
                                 const uint8_t *plaintext,
                                 size_t plaintext_len,
                                 int *fed_crypto) {
    size_t offset = 0;

    while (offset < plaintext_len) {
        uint64_t frame_type;

        if (quic_decode_varint(plaintext, plaintext_len, &offset, &frame_type) != 0) {
            return quic_tls_fail(conn, "failed to decode frame type");
        }

        switch (frame_type) {
            case QUIC_FRAME_PADDING:
                while (offset < plaintext_len && plaintext[offset] == 0x00) {
                    offset++;
                }
                break;

            case QUIC_FRAME_PING:
                conn->ping_received = 1;
                break;

            case QUIC_FRAME_HANDSHAKE_DONE:
                conn->handshake_done_received = 1;
                break;

            case QUIC_FRAME_CRYPTO: {
                uint64_t crypto_offset;
                uint64_t crypto_len;

                if (quic_decode_varint(plaintext, plaintext_len, &offset, &crypto_offset) != 0 ||
                    quic_decode_varint(plaintext, plaintext_len, &offset, &crypto_len) != 0 ||
                    crypto_len > plaintext_len - offset) {
                    return quic_tls_fail(conn, "invalid crypto frame");
                }

                if (quic_crypto_recvbuf_insert(&conn->levels[level].recv,
                                               crypto_offset,
                                               plaintext + offset,
                                               (size_t)crypto_len) != 0) {
                    return quic_tls_fail(conn, "failed to reassemble crypto data");
                }
                offset += (size_t)crypto_len;
                if (quic_tls_feed_crypto(conn, level, fed_crypto) != 0) {
                    return -1;
                }
                break;
            }

            default:
                return quic_tls_fail(conn, "received unsupported frame during stage 1");
        }
    }

    return 0;
}

static int quic_tls_encode_long_header(uint8_t packet_type,
                                       const quic_cid_t *dcid,
                                       const quic_cid_t *scid,
                                       uint32_t version,
                                       uint64_t length,
                                       int include_token,
                                       size_t pn_len,
                                       uint64_t packet_number,
                                       uint8_t *out,
                                       size_t out_len,
                                       size_t *pn_offset,
                                       size_t *header_len) {
    size_t offset = 0;
    int rc;

    if (!dcid || !scid || !out || !pn_offset || !header_len || pn_len != 4) {
        return -1;
    }

    out[offset++] = (uint8_t)(0xc0 | ((packet_type & 0x03) << 4) | ((pn_len - 1) & 0x03));
    out[offset++] = (uint8_t)(version >> 24);
    out[offset++] = (uint8_t)(version >> 16);
    out[offset++] = (uint8_t)(version >> 8);
    out[offset++] = (uint8_t)version;

    if (offset + 1 + dcid->len + 1 + scid->len > out_len) {
        return -1;
    }
    out[offset++] = dcid->len;
    memcpy(out + offset, dcid->data, dcid->len);
    offset += dcid->len;
    out[offset++] = scid->len;
    memcpy(out + offset, scid->data, scid->len);
    offset += scid->len;

    if (include_token) {
        rc = quic_encode_varint(0, out + offset, out_len - offset);
        if (rc < 0) {
            return -1;
        }
        offset += (size_t)rc;
    }

    rc = quic_encode_varint(length, out + offset, out_len - offset);
    if (rc < 0) {
        return -1;
    }
    offset += (size_t)rc;
    *pn_offset = offset;

    if (quic_encode_packet_number(packet_number, pn_len, out + offset, out_len - offset) != 0) {
        return -1;
    }
    offset += pn_len;
    *header_len = offset;
    return 0;
}

static int quic_tls_encode_short_header(const quic_cid_t *dcid,
                                        size_t pn_len,
                                        uint64_t packet_number,
                                        uint8_t *out,
                                        size_t out_len,
                                        size_t *pn_offset,
                                        size_t *header_len) {
    size_t offset = 0;

    if (!dcid || !out || !pn_offset || !header_len || pn_len != 4) {
        return -1;
    }
    if (1 + dcid->len + pn_len > out_len) {
        return -1;
    }

    out[offset++] = (uint8_t)(0x40 | ((pn_len - 1) & 0x03));
    memcpy(out + offset, dcid->data, dcid->len);
    offset += dcid->len;
    *pn_offset = offset;

    if (quic_encode_packet_number(packet_number, pn_len, out + offset, out_len - offset) != 0) {
        return -1;
    }
    offset += pn_len;
    *header_len = offset;
    return 0;
}

static int quic_tls_parse_handshake_header(const uint8_t *packet, size_t packet_len, size_t *pn_offset) {
    quic_pkt_header_meta_t meta;
    const quic_version_ops_t *ops;
    size_t offset;
    uint64_t ignored_length;

    if (!packet || !pn_offset) {
        return -1;
    }
    if (quic_parse_header_meta(packet, packet_len, &meta) != 0 || meta.header_form != 1) {
        return -1;
    }

    ops = quic_version_get_ops(meta.version);
    if (!ops || ops->decode_packet_type(packet[0]) != 2) {
        return -1;
    }

    offset = 6 + meta.dest_cid.len + 1 + meta.src_cid.len;
    if (quic_decode_varint(packet, packet_len, &offset, &ignored_length) != 0) {
        return -1;
    }
    if (offset + 4 > packet_len) {
        return -1;
    }

    *pn_offset = offset;
    return 0;
}

static int quic_tls_classify_packet(quic_tls_conn_t *conn,
                                    const uint8_t *packet,
                                    size_t packet_len,
                                    quic_tls_packet_header_t *header) {
    const quic_version_ops_t *ops;
    uint8_t packet_type;

    if (!conn || !packet || !header) {
        return quic_tls_fail(conn, "invalid packet classification arguments");
    }
    if (quic_parse_header_meta(packet, packet_len, &header->meta) != 0) {
        return quic_tls_fail(conn, "failed to parse packet header");
    }

    if (header->meta.header_form == 0) {
        if (conn->local_cid.len == 0 ||
            packet_len < (size_t)(1 + conn->local_cid.len + 4 + QUIC_AEAD_TAG_LEN)) {
            return quic_tls_fail(conn, "short header packet is truncated");
        }
        header->space = QUIC_PN_SPACE_APPLICATION;
        header->level = ssl_encryption_application;
        header->pn_offset = 1 + conn->local_cid.len;
        return 0;
    }

    ops = quic_version_get_ops(header->meta.version);
    if (!ops) {
        return quic_tls_fail(conn, "unsupported quic version");
    }
    packet_type = ops->decode_packet_type(packet[0]);
    if (packet_type == 0) {
        quic_initial_header_t initial;
        if (quic_parse_initial_header(packet, packet_len, &initial) != 0) {
            return quic_tls_fail(conn, "failed to parse initial header");
        }
        header->space = QUIC_PN_SPACE_INITIAL;
        header->level = ssl_encryption_initial;
        header->pn_offset = initial.pn_offset;
        return 0;
    }
    if (packet_type == 2) {
        if (quic_tls_parse_handshake_header(packet, packet_len, &header->pn_offset) != 0) {
            return quic_tls_fail(conn, "failed to parse handshake header");
        }
        header->space = QUIC_PN_SPACE_HANDSHAKE;
        header->level = ssl_encryption_handshake;
        return 0;
    }

    return quic_tls_fail(conn, "unsupported packet type for stage 1");
}

static int quic_tls_prepare_plan(quic_tls_conn_t *conn,
                                 quic_pn_space_id_t space,
                                 uint8_t ack_eliciting,
                                 quic_conn_tx_plan_t *plan) {
    int status;

    status = quic_conn_prepare_send(&conn->conn, space, 0, ack_eliciting, plan);
    if (status != QUIC_CONN_OK) {
        snprintf(conn->error_message,
                 sizeof(conn->error_message),
                 "failed to allocate packet number: status=%d space=%d tx_ready=%u next_pn=%lu",
                 status,
                 (int)space,
                 conn->conn.spaces[space].tx_keys_ready,
                 (unsigned long)conn->conn.spaces[space].next_packet_number);
        return -1;
    }
    plan->packet_number_len = 4;
    return 0;
}

static int quic_tls_build_crypto_payload(quic_tls_conn_t *conn,
                                         enum ssl_encryption_level_t level,
                                         uint8_t *plaintext,
                                         size_t plaintext_cap,
                                         size_t *plaintext_len,
                                         size_t *crypto_data_len) {
    quic_crypto_sendbuf_t *send = &conn->levels[level].send;
    size_t available = send->flight_end - send->send_offset;
    size_t chunk = available > QUIC_TLS_MAX_CRYPTO_CHUNK ? QUIC_TLS_MAX_CRYPTO_CHUNK : available;
    int rc;
    size_t frame_header_len;

    if (!plaintext || !plaintext_len || !crypto_data_len || available == 0) {
        return quic_tls_fail(conn, "no crypto data available");
    }

    while (chunk > 0) {
        frame_header_len = 1 + quic_tls_varint_len(send->send_offset) + quic_tls_varint_len(chunk);
        if (frame_header_len + chunk <= plaintext_cap) {
            break;
        }
        chunk--;
    }
    if (chunk == 0) {
        return quic_tls_fail(conn, "crypto frame does not fit into packet");
    }

    plaintext[0] = QUIC_FRAME_CRYPTO;
    *plaintext_len = 1;

    rc = quic_encode_varint(send->send_offset, plaintext + *plaintext_len, plaintext_cap - *plaintext_len);
    if (rc < 0) {
        return quic_tls_fail(conn, "failed to encode crypto offset");
    }
    *plaintext_len += (size_t)rc;

    rc = quic_encode_varint(chunk, plaintext + *plaintext_len, plaintext_cap - *plaintext_len);
    if (rc < 0) {
        return quic_tls_fail(conn, "failed to encode crypto length");
    }
    *plaintext_len += (size_t)rc;

    memcpy(plaintext + *plaintext_len, send->data + send->send_offset, chunk);
    *plaintext_len += chunk;
    *crypto_data_len = chunk;
    return 0;
}

static int quic_tls_build_application_payload(quic_tls_conn_t *conn,
                                              uint8_t *plaintext,
                                              size_t plaintext_cap,
                                              size_t *plaintext_len,
                                              size_t *crypto_data_len,
                                              int *includes_handshake_done,
                                              int *includes_ping) {
    size_t offset = 0;

    if (!conn || !plaintext || !plaintext_len || !crypto_data_len || !includes_handshake_done || !includes_ping) {
        return quic_tls_fail(conn, "invalid application payload arguments");
    }

    *crypto_data_len = 0;
    *includes_handshake_done = 0;
    *includes_ping = 0;

    if (quic_crypto_sendbuf_has_pending(&conn->levels[ssl_encryption_application].send)) {
        if (quic_tls_build_crypto_payload(conn,
                                          ssl_encryption_application,
                                          plaintext,
                                          plaintext_cap,
                                          &offset,
                                          crypto_data_len) != 0) {
            return -1;
        }
    }

    if (conn->handshake_done_pending) {
        if (offset + 1 > plaintext_cap) {
            return quic_tls_fail(conn, "handshake_done does not fit");
        }
        plaintext[offset++] = QUIC_FRAME_HANDSHAKE_DONE;
        *includes_handshake_done = 1;
    }

    if (conn->ping_pending) {
        if (offset + 1 > plaintext_cap) {
            return quic_tls_fail(conn, "ping does not fit");
        }
        plaintext[offset++] = QUIC_FRAME_PING;
        *includes_ping = 1;
    }

    if (offset == 0) {
        return quic_tls_fail(conn, "no application payload queued");
    }

    *plaintext_len = offset;
    return 0;
}

static int quic_tls_build_datagram_for_level(quic_tls_conn_t *conn,
                                             enum ssl_encryption_level_t level,
                                             uint8_t *out,
                                             size_t out_len,
                                             size_t *written) {
    quic_conn_tx_plan_t plan;
    quic_pn_space_id_t space = quic_tls_space_from_level(level);
    uint8_t header[256];
    uint8_t plaintext[QUIC_TLS_MAX_DATAGRAM_SIZE];
    size_t pn_offset;
    size_t header_len;
    size_t plaintext_len = 0;
    size_t packet_len = 0;
    size_t crypto_data_len = 0;
    uint64_t length_field;
    size_t target_total_len = 0;
    quic_crypto_level_ctx_t *tx_ctx;
    int includes_handshake_done = 0;
    int includes_ping = 0;

    if (!conn || !out || !written || space == QUIC_PN_SPACE_COUNT) {
        return quic_tls_fail(conn, "invalid datagram build arguments");
    }

    if (quic_tls_prepare_plan(conn, space, 1, &plan) != 0) {
        return -1;
    }

    if (level == ssl_encryption_application) {
        if (quic_tls_build_application_payload(conn,
                                               plaintext,
                                               sizeof(plaintext),
                                               &plaintext_len,
                                               &crypto_data_len,
                                               &includes_handshake_done,
                                               &includes_ping) != 0) {
            return -1;
        }
        if (quic_tls_encode_short_header(&conn->peer_cid,
                                         plan.packet_number_len,
                                         plan.packet_number,
                                         header,
                                         sizeof(header),
                                         &pn_offset,
                                         &header_len) != 0) {
            return quic_tls_fail(conn, "failed to encode short header");
        }
    } else {
        if (quic_tls_build_crypto_payload(conn,
                                          level,
                                          plaintext,
                                          sizeof(plaintext),
                                          &plaintext_len,
                                          &crypto_data_len) != 0) {
            return -1;
        }

        target_total_len = 0;
        if (level == ssl_encryption_initial && conn->role == QUIC_ROLE_CLIENT && plan.packet_number == 0) {
            target_total_len = 1200;
        }

        for (;;) {
            size_t token_varint_len = 1;
            size_t fixed_header_len = 1 + 4 + 1 + conn->peer_cid.len + 1 + conn->local_cid.len +
                                      (level == ssl_encryption_initial ? token_varint_len : 0) +
                                      quic_tls_varint_len(plan.packet_number_len + plaintext_len + QUIC_AEAD_TAG_LEN) +
                                      plan.packet_number_len;
            size_t total_len = fixed_header_len + plaintext_len + QUIC_AEAD_TAG_LEN;

            if (target_total_len == 0 || total_len >= target_total_len) {
                break;
            }
            if (plaintext_len >= sizeof(plaintext)) {
                return quic_tls_fail(conn, "initial packet padding overflow");
            }
            plaintext[plaintext_len++] = QUIC_FRAME_PADDING;
        }

        length_field = plan.packet_number_len + plaintext_len + QUIC_AEAD_TAG_LEN;
        if (quic_tls_encode_long_header(level == ssl_encryption_initial ? 0 : 2,
                                        &conn->peer_cid,
                                        &conn->local_cid,
                                        conn->version,
                                        length_field,
                                        level == ssl_encryption_initial,
                                        plan.packet_number_len,
                                        plan.packet_number,
                                        header,
                                        sizeof(header),
                                        &pn_offset,
                                        &header_len) != 0) {
            return quic_tls_fail(conn, "failed to encode long header");
        }
    }

    tx_ctx = &conn->conn.spaces[space].tx_crypto;
    if (quic_packet_protect(tx_ctx,
                            plan.packet_number,
                            header,
                            header_len,
                            pn_offset,
                            plaintext,
                            plaintext_len,
                            out,
                            out_len,
                            &packet_len) != 0) {
        return quic_tls_fail(conn, "failed to protect packet");
    }

    if (level == ssl_encryption_application) {
        if (crypto_data_len > 0) {
            quic_crypto_sendbuf_advance(&conn->levels[level].send, crypto_data_len);
        }
        if (includes_handshake_done) {
            conn->handshake_done_pending = 0;
            conn->handshake_done_in_flight = 1;
        }
        if (includes_ping) {
            conn->ping_pending = 0;
            conn->ping_in_flight = 1;
        }
    } else {
        quic_crypto_sendbuf_advance(&conn->levels[level].send, crypto_data_len);
    }

    *written = packet_len;
    quic_tls_arm_loss_timer(conn);
    return 0;
}

void quic_tls_conn_init(quic_tls_conn_t *conn) {
    size_t i;

    if (!conn) {
        return;
    }

    memset(conn, 0, sizeof(*conn));
    quic_conn_init(&conn->conn);
    for (i = 0; i <= ssl_encryption_application; i++) {
        quic_crypto_recvbuf_init(&conn->levels[i].recv);
        quic_crypto_sendbuf_init(&conn->levels[i].send);
    }
    quic_tls_set_error(conn, "ok");
}

void quic_tls_conn_free(quic_tls_conn_t *conn) {
    size_t i;

    if (!conn) {
        return;
    }

    if (conn->ssl) {
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    if (conn->ssl_ctx) {
        SSL_CTX_free(conn->ssl_ctx);
        conn->ssl_ctx = NULL;
    }
    for (i = 0; i <= ssl_encryption_application; i++) {
        quic_crypto_recvbuf_free(&conn->levels[i].recv);
        quic_crypto_sendbuf_free(&conn->levels[i].send);
    }
}

int quic_tls_conn_configure(quic_tls_conn_t *conn,
                            quic_role_t role,
                            uint32_t version,
                            const quic_cid_t *local_cid,
                            const quic_cid_t *peer_cid,
                            const char *cert_file,
                            const char *key_file) {
    if (!conn || !local_cid || !local_cid->len) {
        return quic_tls_fail(conn, "invalid quic tls configuration");
    }

    conn->role = role;
    conn->version = version;
    conn->version_ops = quic_version_get_ops(version);
    if (!conn->version_ops) {
        return quic_tls_fail(conn, "unsupported quic version");
    }
    conn->local_cid = *local_cid;

    if (peer_cid) {
        conn->peer_cid = *peer_cid;
        conn->peer_cid_known = 1;
    }

    conn->ssl_ctx = SSL_CTX_new(TLS_method());
    if (!conn->ssl_ctx) {
        return quic_tls_fail_ssl(conn, "failed to create ssl ctx");
    }
    if (SSL_CTX_set_min_proto_version(conn->ssl_ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(conn->ssl_ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_strict_cipher_list(conn->ssl_ctx, "ALL") != 1) {
        return quic_tls_fail_ssl(conn, "failed to configure tls version or cipher");
    }
    SSL_CTX_set_verify(conn->ssl_ctx, SSL_VERIFY_NONE, NULL);
    if (role == QUIC_ROLE_SERVER) {
        SSL_CTX_set_alpn_select_cb(conn->ssl_ctx, quic_tls_server_alpn_cb, NULL);
    }
    if (role == QUIC_ROLE_SERVER) {
        if (!cert_file || !key_file) {
            return quic_tls_fail(conn, "server certificate or key missing");
        }
        if (SSL_CTX_use_certificate_chain_file(conn->ssl_ctx, cert_file) != 1 ||
            SSL_CTX_use_PrivateKey_file(conn->ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
            return quic_tls_fail_ssl(conn, "failed to load server certificate");
        }
        SSL_CTX_set_num_tickets(conn->ssl_ctx, 0);
    }

    conn->ssl = SSL_new(conn->ssl_ctx);
    if (!conn->ssl) {
        return quic_tls_fail_ssl(conn, "failed to create ssl object");
    }
    if (SSL_set_quic_method(conn->ssl, &quic_tls_quic_method) != 1) {
        return quic_tls_fail_ssl(conn, "failed to install quic method");
    }
    SSL_set_app_data(conn->ssl, conn);
    if (role == QUIC_ROLE_CLIENT &&
        SSL_set_alpn_protos(conn->ssl, quic_tls_alpn, sizeof(quic_tls_alpn)) != 0) {
        return quic_tls_fail_ssl(conn, "failed to configure alpn");
    }

    if (role == QUIC_ROLE_CLIENT) {
        SSL_set_connect_state(conn->ssl);
        if (!peer_cid || !peer_cid->len) {
            return quic_tls_fail(conn, "client original dcid missing");
        }
        conn->original_dcid = *peer_cid;
        conn->original_dcid_known = 1;
        if (quic_tls_install_initial_keys(conn) != 0) {
            return -1;
        }
        if (quic_tls_set_transport_params(conn) != 0) {
            return -1;
        }
    } else {
        SSL_set_accept_state(conn->ssl);
    }

    return 0;
}

int quic_tls_conn_start(quic_tls_conn_t *conn) {
    if (!conn || conn->role != QUIC_ROLE_CLIENT) {
        return quic_tls_fail(conn, "only client may start handshake proactively");
    }
    return quic_tls_drive_handshake(conn);
}

int quic_tls_conn_handle_datagram(quic_tls_conn_t *conn, const uint8_t *packet, size_t packet_len) {
    quic_tls_packet_header_t header;
    uint8_t packet_copy[QUIC_TLS_MAX_DATAGRAM_SIZE];
    uint8_t plaintext[QUIC_TLS_MAX_DATAGRAM_SIZE];
    size_t header_len;
    size_t plaintext_len;
    uint64_t packet_number;
    quic_conn_pn_space_t *space;
    int fed_crypto = 0;

    if (!conn || !packet || packet_len == 0 || packet_len > sizeof(packet_copy)) {
        return quic_tls_fail(conn, "invalid datagram input");
    }

    memcpy(packet_copy, packet, packet_len);
    if (quic_tls_classify_packet(conn, packet_copy, packet_len, &header) != 0) {
        return -1;
    }

    if (header.meta.header_form == 1) {
        if (conn->role == QUIC_ROLE_SERVER && !conn->original_dcid_known && header.space == QUIC_PN_SPACE_INITIAL) {
            conn->original_dcid = header.meta.dest_cid;
            conn->original_dcid_known = 1;
            conn->peer_cid = header.meta.src_cid;
            conn->peer_cid_known = 1;
            if (quic_tls_install_initial_keys(conn) != 0) {
                return -1;
            }
            if (!conn->transport_params_set && quic_tls_set_transport_params(conn) != 0) {
                return -1;
            }
        } else if (conn->role == QUIC_ROLE_CLIENT && header.meta.src_cid.len > 0) {
            conn->peer_cid = header.meta.src_cid;
            conn->peer_cid_known = 1;
        }
    }

    space = &conn->conn.spaces[header.space];
    if (!space->rx_keys_ready) {
        if ((header.space == QUIC_PN_SPACE_INITIAL && conn->initial_keys_discarded) ||
            (header.space == QUIC_PN_SPACE_HANDSHAKE && conn->handshake_keys_discarded) ||
            conn->levels[header.level].discarded) {
            return 0;
        }
        snprintf(conn->error_message,
                 sizeof(conn->error_message),
                 "receive keys unavailable for packet level: role=%d space=%d original_dcid_known=%u peer_cid_known=%u",
                 (int)conn->role,
                 (int)header.space,
                 conn->original_dcid_known,
                 conn->peer_cid_known);
        return -1;
    }

    if (quic_packet_unprotect(&space->rx_crypto,
                              space->largest_received_packet,
                              packet_copy,
                              packet_len,
                              header.pn_offset,
                              &packet_number,
                              &header_len,
                              plaintext,
                              sizeof(plaintext),
                              &plaintext_len) != 0) {
        return quic_tls_fail(conn, "failed to remove packet protection");
    }

    if (packet_number > space->largest_received_packet) {
        space->largest_received_packet = packet_number;
    }
    space->last_received_packet = packet_number;
    conn->conn.last_recv_space = header.space;

    if (quic_tls_parse_frames(conn, header.level, plaintext, plaintext_len, &fed_crypto) != 0) {
        return -1;
    }

    if (header.space == QUIC_PN_SPACE_HANDSHAKE) {
        conn->received_handshake_packet = 1;
    }

    if (fed_crypto) {
        if (!conn->handshake_complete) {
            if (quic_tls_drive_handshake(conn) != 0) {
                return -1;
            }
        } else if (header.level == ssl_encryption_application) {
            if (SSL_process_quic_post_handshake(conn->ssl) != 1) {
                return quic_tls_fail_ssl(conn, "failed to process post-handshake data");
            }
        }
    }

    if (conn->handshake_complete && quic_tls_update_peer_transport_params(conn) != 0) {
        return -1;
    }

    quic_tls_maybe_discard_keys(conn);
    quic_tls_arm_loss_timer(conn);
    return 0;
}

int quic_tls_conn_build_next_datagram(quic_tls_conn_t *conn, uint8_t *out, size_t out_len, size_t *written) {
    if (!conn || !out || !written) {
        return quic_tls_fail(conn, "invalid build_next_datagram arguments");
    }

    if (quic_tls_level_has_sendable_output(conn, ssl_encryption_initial)) {
        return quic_tls_build_datagram_for_level(conn, ssl_encryption_initial, out, out_len, written);
    }
    if (quic_tls_level_has_sendable_output(conn, ssl_encryption_handshake)) {
        return quic_tls_build_datagram_for_level(conn, ssl_encryption_handshake, out, out_len, written);
    }
    if (quic_tls_level_has_sendable_output(conn, ssl_encryption_application) ||
        ((conn->handshake_done_pending || conn->ping_pending) &&
         conn->conn.spaces[QUIC_PN_SPACE_APPLICATION].tx_keys_ready)) {
        return quic_tls_build_datagram_for_level(conn, ssl_encryption_application, out, out_len, written);
    }

    return quic_tls_fail(conn, "no datagram pending");
}

int quic_tls_conn_has_pending_output(const quic_tls_conn_t *conn) {
    if (!conn) {
        return 0;
    }
    return quic_tls_level_has_sendable_output(conn, ssl_encryption_initial) ||
           quic_tls_level_has_sendable_output(conn, ssl_encryption_handshake) ||
           quic_tls_level_has_sendable_output(conn, ssl_encryption_application) ||
           ((conn->handshake_done_pending || conn->ping_pending) &&
            conn->conn.spaces[QUIC_PN_SPACE_APPLICATION].tx_keys_ready);
}

void quic_tls_conn_on_loss_timeout(quic_tls_conn_t *conn, uint64_t now_ms) {
    size_t i;

    if (!conn) {
        return;
    }
    if (quic_conn_on_timer(&conn->conn, QUIC_CONN_TIMER_LOSS_DETECTION, now_ms) != QUIC_CONN_OK) {
        return;
    }

    for (i = 0; i <= ssl_encryption_application; i++) {
        quic_crypto_sendbuf_restart_flight(&conn->levels[i].send);
    }
    if (conn->handshake_done_in_flight) {
        conn->handshake_done_pending = 1;
    }
    if (conn->ping_in_flight) {
        conn->ping_pending = 1;
    }
    quic_tls_arm_loss_timer(conn);
}

uint64_t quic_tls_conn_loss_deadline_ms(const quic_tls_conn_t *conn) {
    if (!conn || !conn->conn.timers[QUIC_CONN_TIMER_LOSS_DETECTION].armed) {
        return 0;
    }
    return conn->conn.timers[QUIC_CONN_TIMER_LOSS_DETECTION].deadline_ms;
}

void quic_tls_conn_queue_ping(quic_tls_conn_t *conn) {
    if (!conn) {
        return;
    }
    conn->ping_pending = 1;
    quic_tls_arm_loss_timer(conn);
}

int quic_tls_conn_handshake_complete(const quic_tls_conn_t *conn) {
    return conn ? conn->handshake_complete : 0;
}

const char *quic_tls_conn_last_error(const quic_tls_conn_t *conn) {
    return conn ? conn->error_message : "invalid quic tls connection";
}
