#include "pkt_decode.h"
#include "quic_crypto.h"
#include "quic_tls.h"
#include "quic_version.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define TEST_CERT_FILE "example/server_cert.pem"
#define TEST_KEY_FILE  "example/server_key.pem"

typedef struct {
    uint8_t bytes[QUIC_TLS_MAX_DATAGRAM_SIZE];
    size_t len;
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

static uint8_t classify_long_packet_type(const uint8_t *packet, size_t len) {
    quic_pkt_header_meta_t meta;
    const quic_version_ops_t *ops;

    assert(quic_parse_header_meta(packet, len, &meta) == 0);
    assert(meta.header_form == 1);
    if (meta.version == 0) {
        return 0xff;
    }
    ops = quic_version_get_ops(meta.version);
    assert(ops != NULL);
    return ops->decode_packet_type(packet[0]);
}

static int flush_pending(quic_tls_conn_t *src, quic_tls_conn_t *dst) {
    int moved = 0;

    while (quic_tls_conn_has_pending_output(src)) {
        uint8_t packet[QUIC_TLS_MAX_DATAGRAM_SIZE];
        size_t written = 0;

        assert(quic_tls_conn_build_next_datagram(src, packet, sizeof(packet), &written) == 0);
        assert(quic_tls_conn_handle_datagram(dst, packet, written) == 0);
        moved = 1;
    }

    return moved;
}

static int capture_one(quic_tls_conn_t *src, captured_packet_t *packet) {
    if (!quic_tls_conn_has_pending_output(src)) {
        return 0;
    }
    assert(quic_tls_conn_build_next_datagram(src, packet->bytes, sizeof(packet->bytes), &packet->len) == 0);
    return 1;
}

static int handshake_done(const quic_tls_conn_t *client, const quic_tls_conn_t *server) {
    return quic_tls_conn_handshake_complete(client) && quic_tls_conn_handshake_complete(server);
}

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

    assert(done(client, server));
}

static void drain_all_pending(quic_tls_conn_t *client, quic_tls_conn_t *server) {
    size_t round = 0;

    while (round++ < 256) {
        int progressed = 0;
        progressed |= flush_pending(client, server);
        progressed |= flush_pending(server, client);
        if (!progressed) {
            break;
        }
    }
}

static void configure_pair(quic_tls_conn_t *client,
                           quic_tls_conn_t *server,
                           quic_cid_t *client_scid,
                           quic_cid_t *client_odcid,
                           quic_cid_t *server_scid) {
    *client_scid = make_cid(0x10);
    *client_odcid = make_cid(0xa0);
    *server_scid = make_cid(0xb0);

    quic_tls_conn_init(client);
    quic_tls_conn_init(server);

    assert(quic_tls_conn_configure(client,
                                   QUIC_ROLE_CLIENT,
                                   QUIC_V1_VERSION,
                                   client_scid,
                                   client_odcid,
                                   NULL,
                                   NULL) == 0);
    assert(quic_tls_conn_configure(server,
                                   QUIC_ROLE_SERVER,
                                   QUIC_V1_VERSION,
                                   server_scid,
                                   NULL,
                                   TEST_CERT_FILE,
                                   TEST_KEY_FILE) == 0);
}

static void test_stage2_ack_generation_clears_inflight(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    quic_cid_t client_scid;
    quic_cid_t client_odcid;
    quic_cid_t server_scid;
    captured_packet_t packet;

    configure_pair(&client, &server, &client_scid, &client_odcid, &server_scid);
    assert(quic_tls_conn_start(&client) == 0);

    run_until(&client, &server, handshake_done);
    drain_all_pending(&client, &server);

    quic_tls_conn_queue_ping(&client);
    assert(capture_one(&client, &packet) == 1);
    assert(client.conn.spaces[QUIC_PN_SPACE_APPLICATION].in_flight.bytes_in_flight > 0);
    assert(quic_tls_conn_handle_datagram(&server, packet.bytes, packet.len) == 0);
    assert(server.levels[ssl_encryption_application].ack_pending == 1);

    assert(capture_one(&server, &packet) == 1);
    assert(quic_tls_conn_handle_datagram(&client, packet.bytes, packet.len) == 0);
    assert(client.conn.spaces[QUIC_PN_SPACE_APPLICATION].in_flight.bytes_in_flight == 0);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 2 ACK generation clears application in-flight packets\n");
}

static void test_stage2_interleaved_initial_ack_uses_original_keys(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    quic_cid_t client_scid;
    quic_cid_t client_odcid;
    quic_cid_t server_scid;
    captured_packet_t packet;

    configure_pair(&client, &server, &client_scid, &client_odcid, &server_scid);
    assert(quic_tls_conn_start(&client) == 0);

    assert(capture_one(&client, &packet) == 1);
    assert(classify_long_packet_type(packet.bytes, packet.len) == 0);
    assert(quic_tls_conn_handle_datagram(&server, packet.bytes, packet.len) == 0);

    assert(capture_one(&server, &packet) == 1);
    assert(classify_long_packet_type(packet.bytes, packet.len) == 0);
    assert(quic_tls_conn_handle_datagram(&client, packet.bytes, packet.len) == 0);

    assert(quic_tls_conn_has_pending_output(&client));
    assert(capture_one(&client, &packet) == 1);
    assert(classify_long_packet_type(packet.bytes, packet.len) == 0);
    assert(packet.bytes[6] == server_scid.data[0]);
    assert(quic_tls_conn_handle_datagram(&server, packet.bytes, packet.len) == 0);

    run_until(&client, &server, handshake_done);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 2 interleaved Initial ACK keeps original Initial keys\n");
}

static void test_stage2_retry_round_trip(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    quic_cid_t client_scid;
    quic_cid_t client_odcid;
    quic_cid_t server_scid;
    captured_packet_t packet;

    configure_pair(&client, &server, &client_scid, &client_odcid, &server_scid);
    quic_tls_conn_enable_retry(&server, 1);
    assert(quic_tls_conn_start(&client) == 0);

    assert(capture_one(&client, &packet) == 1);
    assert(quic_tls_conn_handle_datagram(&server, packet.bytes, packet.len) == 0);
    assert(quic_tls_conn_has_pending_output(&server));

    assert(capture_one(&server, &packet) == 1);
    assert(classify_long_packet_type(packet.bytes, packet.len) == 3);
    assert(quic_tls_conn_handle_datagram(&client, packet.bytes, packet.len) == 0);
    assert(client.retry_processed);
    assert(client.retry_token_len > 0);

    run_until(&client, &server, handshake_done);
    assert(server.peer_address_validated);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 2 Retry path completes a retried handshake\n");
}

static void test_stage2_version_negotiation(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    quic_cid_t client_scid;
    quic_cid_t client_odcid;
    quic_cid_t server_scid;
    captured_packet_t packet;
    uint8_t unsupported_packet[] = {
        0xc0, 0xfa, 0xce, 0xb0, 0x0c,
        0x08, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0x08, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };
    quic_pkt_header_meta_t meta;

    configure_pair(&client, &server, &client_scid, &client_odcid, &server_scid);

    assert(quic_tls_conn_handle_datagram(&server, unsupported_packet, sizeof(unsupported_packet)) == 0);
    assert(quic_tls_conn_has_pending_output(&server));
    assert(capture_one(&server, &packet) == 1);
    assert(quic_parse_header_meta(packet.bytes, packet.len, &meta) == 0);
    assert(meta.version == 0);

    assert(quic_tls_conn_handle_datagram(&client, packet.bytes, packet.len) == 0);
    assert(client.received_version_negotiation);
    assert(client.conn.state == QUIC_CONN_STATE_CLOSED);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 2 Version Negotiation packets are generated and processed\n");
}

static void test_stage2_anti_amplification_limit(void) {
    quic_tls_conn_t server;
    quic_cid_t server_scid = make_cid(0xe0);
    uint8_t unsupported_packet[] = {
        0xc0, 0xfa, 0xce, 0xb0, 0x0c,
        0x08, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0x08, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };
    uint8_t packet[QUIC_TLS_MAX_DATAGRAM_SIZE];
    size_t written = 0;

    quic_tls_conn_init(&server);
    assert(quic_tls_conn_configure(&server,
                                   QUIC_ROLE_SERVER,
                                   QUIC_V1_VERSION,
                                   &server_scid,
                                   NULL,
                                   TEST_CERT_FILE,
                                   TEST_KEY_FILE) == 0);

    assert(quic_tls_conn_handle_datagram(&server, unsupported_packet, sizeof(unsupported_packet)) == 0);
    server.bytes_sent = server.bytes_received * 3;
    assert(quic_tls_conn_build_next_datagram(&server, packet, sizeof(packet), &written) != 0);

    quic_tls_conn_free(&server);
    printf("[PASS] Stage 2 anti-amplification blocks sends beyond 3x budget\n");
}

static void test_stage2_zero_rtt_and_short_header_paths(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    quic_crypto_context_t keys;
    quic_cid_t client_cid = make_cid(0x40);
    quic_cid_t server_cid = make_cid(0x90);
    captured_packet_t packet;

    quic_tls_conn_init(&client);
    quic_tls_conn_init(&server);

    client.role = QUIC_ROLE_CLIENT;
    client.version = QUIC_V1_VERSION;
    client.version_ops = quic_version_get_ops(QUIC_V1_VERSION);
    client.local_cid = client_cid;
    client.peer_cid = server_cid;
    client.peer_cid_known = 1;

    server.role = QUIC_ROLE_SERVER;
    server.version = QUIC_V1_VERSION;
    server.version_ops = quic_version_get_ops(QUIC_V1_VERSION);
    server.local_cid = server_cid;
    server.peer_cid = client_cid;
    server.peer_cid_known = 1;
    server.peer_address_validated = 1;

    assert(quic_crypto_setup_initial_keys(&server_cid, client.version_ops, &keys) == 0);
    assert(quic_conn_install_tx_keys(&client.conn, QUIC_PN_SPACE_APPLICATION, &keys.client_initial) == QUIC_CONN_OK);
    assert(quic_conn_install_rx_keys(&server.conn, QUIC_PN_SPACE_APPLICATION, &keys.client_initial) == QUIC_CONN_OK);
    assert(quic_conn_install_tx_keys(&server.conn, QUIC_PN_SPACE_APPLICATION, &keys.server_initial) == QUIC_CONN_OK);
    assert(quic_conn_install_rx_keys(&client.conn, QUIC_PN_SPACE_APPLICATION, &keys.server_initial) == QUIC_CONN_OK);
    client.levels[ssl_encryption_early_data].write_secret_ready = 1;
    server.levels[ssl_encryption_early_data].read_secret_ready = 1;
    server.levels[ssl_encryption_application].write_secret_ready = 1;
    client.levels[ssl_encryption_application].read_secret_ready = 1;

    quic_tls_conn_queue_ping(&client);
    assert(capture_one(&client, &packet) == 1);
    assert(classify_long_packet_type(packet.bytes, packet.len) == 1);
    assert(quic_tls_conn_handle_datagram(&server, packet.bytes, packet.len) == 0);
    assert(server.ping_received);

    assert(capture_one(&server, &packet) == 1);
    assert((packet.bytes[0] & 0x80) == 0);
    assert(quic_tls_conn_handle_datagram(&client, packet.bytes, packet.len) == 0);
    assert(client.conn.spaces[QUIC_PN_SPACE_APPLICATION].in_flight.bytes_in_flight == 0);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 2 0-RTT long header and short-header ACK paths work\n");
}

int main(void) {
    test_stage2_ack_generation_clears_inflight();
    test_stage2_interleaved_initial_ack_uses_original_keys();
    test_stage2_retry_round_trip();
    test_stage2_version_negotiation();
    test_stage2_anti_amplification_limit();
    test_stage2_zero_rtt_and_short_header_paths();
    printf("Phase 13 tests passed.\n");
    return 0;
}
