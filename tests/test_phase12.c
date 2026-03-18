#include "pkt_decode.h"
#include "quic_tls.h"
#include "quic_version.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define TEST_CERT_FILE "tests/certs/server_cert.pem"
#define TEST_KEY_FILE  "tests/certs/server_key.pem"
#define MAX_CAPTURED_PACKETS 32

typedef struct {
    uint8_t bytes[QUIC_TLS_MAX_DATAGRAM_SIZE];
    size_t len;
    quic_pn_space_id_t space;
} captured_packet_t;

static quic_cid_t make_cid(uint8_t seed) {
    quic_cid_t cid;
    size_t i;

    memset(&cid, 0, sizeof(cid));
    cid.len = 8;
    for (i = 0; i < cid.len; i++) {
        cid.data[i] = (uint8_t)(seed + i);
    }
    return cid;
}

static quic_pn_space_id_t classify_packet_space(const uint8_t *packet, size_t len) {
    quic_pkt_header_meta_t meta;
    const quic_version_ops_t *ops;

    assert(quic_parse_header_meta(packet, len, &meta) == 0);
    if (meta.header_form == 0) {
        return QUIC_PN_SPACE_APPLICATION;
    }

    ops = quic_version_get_ops(meta.version);
    assert(ops != NULL);
    switch (ops->decode_packet_type(packet[0])) {
        case 0:
            return QUIC_PN_SPACE_INITIAL;
        case 2:
            return QUIC_PN_SPACE_HANDSHAKE;
        default:
            return QUIC_PN_SPACE_APPLICATION;
    }
}

static size_t capture_pending(quic_tls_conn_t *src, captured_packet_t *captured, size_t cap) {
    size_t count = 0;

    while (quic_tls_conn_has_pending_output(src)) {
        size_t written = 0;
        assert(count < cap);
        assert(quic_tls_conn_build_next_datagram(src, captured[count].bytes, sizeof(captured[count].bytes), &written) == 0);
        captured[count].len = written;
        captured[count].space = classify_packet_space(captured[count].bytes, captured[count].len);
        count++;
    }

    return count;
}

static int flush_pending(quic_tls_conn_t *src, quic_tls_conn_t *dst) {
    int moved = 0;

    while (quic_tls_conn_has_pending_output(src)) {
        uint8_t packet[QUIC_TLS_MAX_DATAGRAM_SIZE];
        size_t written = 0;

        if (quic_tls_conn_build_next_datagram(src, packet, sizeof(packet), &written) != 0) {
            fprintf(stderr, "build_next_datagram failed: %s\n", quic_tls_conn_last_error(src));
            assert(0);
        }
        if (quic_tls_conn_handle_datagram(dst, packet, written) != 0) {
            fprintf(stderr,
                    "handle_datagram failed: packet_space=%d err=%s\n",
                    (int)classify_packet_space(packet, written),
                    quic_tls_conn_last_error(dst));
            assert(0);
        }
        moved = 1;
    }

    return moved;
}

static int flush_pending_with_single_drop(quic_tls_conn_t *src,
                                          quic_tls_conn_t *dst,
                                          quic_pn_space_id_t drop_space,
                                          int *dropped) {
    int moved = 0;

    while (quic_tls_conn_has_pending_output(src)) {
        uint8_t packet[QUIC_TLS_MAX_DATAGRAM_SIZE];
        size_t written = 0;
        quic_pn_space_id_t space;

        if (quic_tls_conn_build_next_datagram(src, packet, sizeof(packet), &written) != 0) {
            fprintf(stderr, "build_next_datagram failed: %s\n", quic_tls_conn_last_error(src));
            assert(0);
        }

        space = classify_packet_space(packet, written);
        if (!*dropped && space == drop_space) {
            *dropped = 1;
            moved = 1;
            continue;
        }

        if (quic_tls_conn_handle_datagram(dst, packet, written) != 0) {
            fprintf(stderr,
                    "handle_datagram failed: packet_space=%d err=%s\n",
                    (int)space,
                    quic_tls_conn_last_error(dst));
            assert(0);
        }
        moved = 1;
    }

    return moved;
}

static int level_sendable(const quic_tls_conn_t *conn, enum ssl_encryption_level_t level, quic_pn_space_id_t space);

static void run_until(quic_tls_conn_t *client,
                      quic_tls_conn_t *server,
                      int (*done)(const quic_tls_conn_t *, const quic_tls_conn_t *)) {
    size_t round = 0;

    while (!done(client, server) && round++ < 512) {
        int progressed = 0;
        progressed |= flush_pending(client, server);
        progressed |= flush_pending(server, client);

        if (!progressed) {
            uint64_t deadline;

            deadline = quic_tls_conn_loss_deadline_ms(client);
            if (deadline != 0) {
                quic_tls_conn_on_loss_timeout(client, deadline);
                progressed = 1;
            }
            deadline = quic_tls_conn_loss_deadline_ms(server);
            if (deadline != 0) {
                quic_tls_conn_on_loss_timeout(server, deadline);
                progressed = 1;
            }
        }

        assert(progressed);
    }

    if (!done(client, server)) {
        fprintf(stderr,
                "run_until stalled: "
                "client hs=%u app=%u init_discarded=%u hs_discarded=%u recv_hs=%u "
                "pending(i=%d h=%d a=%d) hs_send(off=%zu end=%zu) hs_rx_largest=%lu err=%s | "
                "server hs=%u app=%u init_discarded=%u hs_discarded=%u recv_hs=%u "
                "pending(i=%d h=%d a=%d) hs_send(off=%zu end=%zu) hs_rx_largest=%lu err=%s\n",
                client->handshake_complete,
                client->application_secrets_ready,
                client->initial_keys_discarded,
                client->handshake_keys_discarded,
                client->received_handshake_packet,
                level_sendable(client, ssl_encryption_initial, QUIC_PN_SPACE_INITIAL),
                level_sendable(client, ssl_encryption_handshake, QUIC_PN_SPACE_HANDSHAKE),
                level_sendable(client, ssl_encryption_application, QUIC_PN_SPACE_APPLICATION),
                client->levels[ssl_encryption_handshake].send.send_offset,
                client->levels[ssl_encryption_handshake].send.flight_end,
                (unsigned long)client->conn.spaces[QUIC_PN_SPACE_HANDSHAKE].largest_received_packet,
                quic_tls_conn_last_error(client),
                server->handshake_complete,
                server->application_secrets_ready,
                server->initial_keys_discarded,
                server->handshake_keys_discarded,
                server->received_handshake_packet,
                level_sendable(server, ssl_encryption_initial, QUIC_PN_SPACE_INITIAL),
                level_sendable(server, ssl_encryption_handshake, QUIC_PN_SPACE_HANDSHAKE),
                level_sendable(server, ssl_encryption_application, QUIC_PN_SPACE_APPLICATION),
                server->levels[ssl_encryption_handshake].send.send_offset,
                server->levels[ssl_encryption_handshake].send.flight_end,
                (unsigned long)server->conn.spaces[QUIC_PN_SPACE_HANDSHAKE].largest_received_packet,
                quic_tls_conn_last_error(server));
        assert(0);
    }
}

static int handshake_done(const quic_tls_conn_t *client, const quic_tls_conn_t *server) {
    return quic_tls_conn_handshake_complete(client) && quic_tls_conn_handshake_complete(server);
}

static int ping_done(const quic_tls_conn_t *client, const quic_tls_conn_t *server) {
    return client->ping_received && server->ping_received;
}

static int level_sendable(const quic_tls_conn_t *conn, enum ssl_encryption_level_t level, quic_pn_space_id_t space) {
    return quic_crypto_sendbuf_has_pending(&conn->levels[level].send) &&
           conn->conn.spaces[space].tx_keys_ready;
}

static void poison_recvbuf_heap(void) {
    uint8_t *block_a = (uint8_t *)malloc(256);
    uint8_t *block_b = (uint8_t *)malloc(256);

    assert(block_a != NULL);
    assert(block_b != NULL);
    memset(block_a, 0xff, 256);
    memset(block_b, 0xff, 256);
    free(block_b);
    free(block_a);
}

static void test_crypto_recvbuf_gap_tracking(void) {
    quic_crypto_recvbuf_t buf;
    static const uint8_t head[] = { 0x01, 0x02, 0x03, 0x04 };
    static const uint8_t tail[] = { 0xaa, 0xbb, 0xcc, 0xdd };

    poison_recvbuf_heap();

    quic_crypto_recvbuf_init(&buf);
    assert(quic_crypto_recvbuf_insert(&buf, 4, tail, sizeof(tail)) == 0);
    assert(quic_crypto_recvbuf_contiguous_len(&buf) == 0);
    assert(quic_crypto_recvbuf_insert(&buf, 0, head, sizeof(head)) == 0);
    assert(quic_crypto_recvbuf_contiguous_len(&buf) == sizeof(head) + sizeof(tail));
    quic_crypto_recvbuf_free(&buf);
}

static void test_stage1_tls_handshake(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    quic_cid_t client_scid = make_cid(0x10);
    quic_cid_t client_odcid = make_cid(0xa0);
    quic_cid_t server_scid = make_cid(0xb0);
    captured_packet_t server_flight[MAX_CAPTURED_PACKETS];
    size_t server_packet_count;
    size_t i;

    quic_tls_conn_init(&client);
    quic_tls_conn_init(&server);

    if (quic_tls_conn_configure(&client,
                                QUIC_ROLE_CLIENT,
                                QUIC_V1_VERSION,
                                &client_scid,
                                &client_odcid,
                                NULL,
                                NULL) != 0) {
        fprintf(stderr, "client configure failed: %s\n", quic_tls_conn_last_error(&client));
        assert(0);
    }
    if (quic_tls_conn_configure(&server,
                                QUIC_ROLE_SERVER,
                                QUIC_V1_VERSION,
                                &server_scid,
                                NULL,
                                TEST_CERT_FILE,
                                TEST_KEY_FILE) != 0) {
        fprintf(stderr, "server configure failed: %s\n", quic_tls_conn_last_error(&server));
        assert(0);
    }

    if (quic_tls_conn_start(&client) != 0) {
        fprintf(stderr, "client start failed: %s\n", quic_tls_conn_last_error(&client));
        assert(0);
    }
    assert(flush_pending(&client, &server) == 1);

    server_packet_count = capture_pending(&server, server_flight, MAX_CAPTURED_PACKETS);
    assert(server_packet_count >= 2);

    for (i = 0; i < server_packet_count; i++) {
        if (server_flight[i].space == QUIC_PN_SPACE_INITIAL) {
            assert(quic_tls_conn_handle_datagram(&client, server_flight[i].bytes, server_flight[i].len) == 0);
        }
    }
    for (i = server_packet_count; i-- > 0;) {
        if (server_flight[i].space == QUIC_PN_SPACE_HANDSHAKE) {
            assert(quic_tls_conn_handle_datagram(&client, server_flight[i].bytes, server_flight[i].len) == 0);
        }
    }

    run_until(&client, &server, handshake_done);

    assert(client.peer_transport_params_ready);
    assert(server.peer_transport_params_ready);
    assert(client.application_secrets_ready);
    assert(server.application_secrets_ready);
    assert(client.initial_keys_discarded);
    assert(server.initial_keys_discarded);

    quic_tls_conn_queue_ping(&client);
    quic_tls_conn_queue_ping(&server);
    run_until(&client, &server, ping_done);

    assert(client.handshake_done_received);
    assert(client.handshake_keys_discarded);
    assert(server.handshake_keys_discarded);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
}

static void test_stage1_client_ignores_handshake_packets_before_keys(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    quic_cid_t client_scid = make_cid(0x20);
    quic_cid_t client_odcid = make_cid(0xb0);
    quic_cid_t server_scid = make_cid(0xc0);
    captured_packet_t server_flight[MAX_CAPTURED_PACKETS];
    size_t server_packet_count;
    size_t i;
    int saw_handshake = 0;

    quic_tls_conn_init(&client);
    quic_tls_conn_init(&server);

    assert(quic_tls_conn_configure(&client,
                                   QUIC_ROLE_CLIENT,
                                   QUIC_V1_VERSION,
                                   &client_scid,
                                   &client_odcid,
                                   NULL,
                                   NULL) == 0);
    assert(quic_tls_conn_configure(&server,
                                   QUIC_ROLE_SERVER,
                                   QUIC_V1_VERSION,
                                   &server_scid,
                                   NULL,
                                   TEST_CERT_FILE,
                                   TEST_KEY_FILE) == 0);
    assert(quic_tls_conn_start(&client) == 0);
    assert(flush_pending(&client, &server) == 1);

    server_packet_count = capture_pending(&server, server_flight, MAX_CAPTURED_PACKETS);
    assert(server_packet_count >= 2);
    assert(!client.conn.spaces[QUIC_PN_SPACE_HANDSHAKE].rx_keys_ready);

    for (i = 0; i < server_packet_count; i++) {
        if (server_flight[i].space == QUIC_PN_SPACE_HANDSHAKE) {
            assert(quic_tls_conn_handle_datagram(&client, server_flight[i].bytes, server_flight[i].len) == 0);
            saw_handshake = 1;
        }
    }

    assert(saw_handshake);
    assert(!client.received_handshake_packet);
    assert(!client.conn.spaces[QUIC_PN_SPACE_HANDSHAKE].rx_keys_ready);

    for (i = 0; i < server_packet_count; i++) {
        if (server_flight[i].space == QUIC_PN_SPACE_INITIAL) {
            assert(quic_tls_conn_handle_datagram(&client, server_flight[i].bytes, server_flight[i].len) == 0);
        }
    }

    assert(client.conn.spaces[QUIC_PN_SPACE_HANDSHAKE].rx_keys_ready);

    for (i = 0; i < server_packet_count; i++) {
        if (server_flight[i].space == QUIC_PN_SPACE_HANDSHAKE) {
            assert(quic_tls_conn_handle_datagram(&client, server_flight[i].bytes, server_flight[i].len) == 0);
        }
    }

    run_until(&client, &server, handshake_done);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
}

static void test_stage1_application_retransmit(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    quic_cid_t client_scid = make_cid(0x30);
    quic_cid_t client_odcid = make_cid(0xc0);
    quic_cid_t server_scid = make_cid(0xd0);
    int dropped = 0;

    quic_tls_conn_init(&client);
    quic_tls_conn_init(&server);

    assert(quic_tls_conn_configure(&client,
                                   QUIC_ROLE_CLIENT,
                                   QUIC_V1_VERSION,
                                   &client_scid,
                                   &client_odcid,
                                   NULL,
                                   NULL) == 0);
    assert(quic_tls_conn_configure(&server,
                                   QUIC_ROLE_SERVER,
                                   QUIC_V1_VERSION,
                                   &server_scid,
                                   NULL,
                                   TEST_CERT_FILE,
                                   TEST_KEY_FILE) == 0);
    assert(quic_tls_conn_start(&client) == 0);

    run_until(&client, &server, handshake_done);

    quic_tls_conn_queue_ping(&client);
    quic_tls_conn_queue_ping(&server);

    assert(flush_pending(&client, &server) == 1);
    assert(flush_pending_with_single_drop(&server, &client, QUIC_PN_SPACE_APPLICATION, &dropped) == 1);
    assert(dropped == 1);

    run_until(&client, &server, ping_done);
    assert(client.handshake_done_received);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
}

int main(void) {
    test_crypto_recvbuf_gap_tracking();
    test_stage1_tls_handshake();
    test_stage1_client_ignores_handshake_packets_before_keys();
    test_stage1_application_retransmit();
    printf("Phase 12 tests passed.\n");
    return 0;
}
