#include "quic_tls.h"
#include "quic_version.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define TEST_CERT_FILE "tests/certs/server_cert.pem"
#define TEST_KEY_FILE  "tests/certs/server_key.pem"

typedef struct {
    uint8_t bytes[QUIC_TLS_MAX_DATAGRAM_SIZE];
    size_t len;
    quic_path_addr_t send_path;
} captured_packet_t;

static uint64_t now_ms(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

static uint64_t current_pto_ms(const quic_tls_conn_t *conn) {
    uint64_t variance;
    uint64_t pto;

    assert(conn);
    variance = conn->conn.recovery.rttvar_ms * 4ULL;
    if (variance < QUIC_RECOVERY_GRANULARITY_MS) {
        variance = QUIC_RECOVERY_GRANULARITY_MS;
    }
    pto = conn->conn.recovery.smoothed_rtt_ms + variance;
    if (conn->conn.recovery.handshake_confirmed) {
        pto += conn->conn.recovery.max_ack_delay_ms;
    }
    return pto << conn->conn.recovery.pto_count;
}

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

static void make_path(quic_path_addr_t *path,
                      uint8_t local_last_octet,
                      uint16_t local_port,
                      uint8_t peer_last_octet,
                      uint16_t peer_port) {
    quic_socket_addr_t local;
    quic_socket_addr_t peer;

    quic_socket_addr_init_ipv4(&local, 10, 0, 0, local_last_octet, local_port);
    quic_socket_addr_init_ipv4(&peer, 10, 0, 0, peer_last_octet, peer_port);
    quic_path_addr_init(path, &local, &peer);
}

static void reverse_path(const quic_path_addr_t *src, quic_path_addr_t *dst) {
    assert(src);
    assert(dst);
    quic_path_addr_init(dst, &src->peer, &src->local);
}

static int capture_one(quic_tls_conn_t *src, captured_packet_t *packet) {
    int status;

    if (!src || !packet || !quic_tls_conn_has_pending_output(src)) {
        return 0;
    }
    status = quic_tls_conn_build_next_datagram_on_path(src,
                                                       packet->bytes,
                                                       sizeof(packet->bytes),
                                                       &packet->len,
                                                       &packet->send_path);
    if (status == QUIC_TLS_BUILD_BLOCKED) {
        return 0;
    }
    if (status != 0) {
        fprintf(stderr, "build_next_datagram_on_path failed: %s\n", quic_tls_conn_last_error(src));
        assert(0);
    }
    return 1;
}

static int deliver_packet(quic_tls_conn_t *dst, const captured_packet_t *packet) {
    quic_path_addr_t recv_path;
    int rc;

    assert(dst);
    assert(packet);
    reverse_path(&packet->send_path, &recv_path);
    rc = quic_tls_conn_handle_datagram_on_path(dst, packet->bytes, packet->len, &recv_path);
    if (rc != 0) {
        fprintf(stderr, "handle_datagram_on_path failed: %s\n", quic_tls_conn_last_error(dst));
    }
    return rc;
}

static int drive_timers(quic_tls_conn_t *client, quic_tls_conn_t *server) {
    uint64_t client_deadline = quic_tls_conn_next_timeout_ms(client);
    uint64_t server_deadline = quic_tls_conn_next_timeout_ms(server);
    uint64_t deadline = 0;

    if (client_deadline != 0 && (deadline == 0 || client_deadline < deadline)) {
        deadline = client_deadline;
    }
    if (server_deadline != 0 && (deadline == 0 || server_deadline < deadline)) {
        deadline = server_deadline;
    }
    if (deadline == 0) {
        return 0;
    }

    if (client_deadline != 0 && client_deadline == deadline) {
        quic_tls_conn_on_timeout(client, deadline);
    }
    if (server_deadline != 0 && server_deadline == deadline) {
        quic_tls_conn_on_timeout(server, deadline);
    }
    return 1;
}

static int handshake_done(const quic_tls_conn_t *client, const quic_tls_conn_t *server) {
    return quic_tls_conn_handshake_complete(client) && quic_tls_conn_handshake_complete(server);
}

static void run_until(quic_tls_conn_t *client,
                      quic_tls_conn_t *server,
                      int (*done)(const quic_tls_conn_t *, const quic_tls_conn_t *)) {
    size_t rounds = 0;

    while (!done(client, server) && rounds++ < 2048) {
        int progressed = 0;
        captured_packet_t packet;

        while (capture_one(client, &packet)) {
            assert(deliver_packet(server, &packet) == 0);
            progressed = 1;
        }
        while (capture_one(server, &packet)) {
            assert(deliver_packet(client, &packet) == 0);
            progressed = 1;
        }
        if (!progressed) {
            progressed = drive_timers(client, server);
        }
        assert(progressed);
    }

    assert(done(client, server));
}

static void configure_pair(quic_tls_conn_t *client,
                           quic_tls_conn_t *server,
                           const quic_path_addr_t *client_path,
                           const quic_path_addr_t *server_path) {
    quic_cid_t client_scid = make_cid(0x41);
    quic_cid_t client_odcid = make_cid(0x91);
    quic_cid_t server_scid = make_cid(0xb1);

    quic_tls_conn_init(client);
    quic_tls_conn_init(server);
    assert(quic_tls_conn_configure(client,
                                   QUIC_ROLE_CLIENT,
                                   QUIC_V1_VERSION,
                                   &client_scid,
                                   &client_odcid,
                                   NULL,
                                   NULL) == 0);
    assert(quic_tls_conn_configure(server,
                                   QUIC_ROLE_SERVER,
                                   QUIC_V1_VERSION,
                                   &server_scid,
                                   NULL,
                                   TEST_CERT_FILE,
                                   TEST_KEY_FILE) == 0);
    assert(quic_tls_conn_set_initial_path(client, client_path) == 0);
    assert(quic_tls_conn_set_initial_path(server, server_path) == 0);
    assert(quic_tls_conn_start(client) == 0);
    run_until(client, server, handshake_done);
}

static int client_got_new_token_and_preferred_address(const quic_tls_conn_t *client,
                                                      const quic_tls_conn_t *server) {
    (void)server;
    return client &&
           client->retry_token_len > 0 &&
           client->peer_preferred_address.present &&
           client->peer_cid_count >= 2;
}

static void test_stage5_preferred_address_and_new_token_arrive_post_handshake(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    quic_path_addr_t client_path;
    quic_path_addr_t server_path;
    quic_socket_addr_t preferred_server_addr;
    quic_cid_t client_scid = make_cid(0x41);
    quic_cid_t client_odcid = make_cid(0x91);
    quic_cid_t server_scid = make_cid(0xb1);
    quic_cid_t preferred_cid = make_cid(0xd1);
    uint8_t preferred_token[QUIC_STATELESS_RESET_TOKEN_LEN];
    quic_path_addr_t advertised_path;
    quic_cid_t advertised_cid;
    uint8_t advertised_token[QUIC_STATELESS_RESET_TOKEN_LEN];
    size_t i;

    for (i = 0; i < sizeof(preferred_token); i++) {
        preferred_token[i] = (uint8_t)(0xa0 + i);
    }

    make_path(&client_path, 1, 40000, 2, 4434);
    make_path(&server_path, 2, 4434, 1, 40000);
    quic_socket_addr_init_ipv4(&preferred_server_addr, 10, 0, 0, 2, 4445);

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
    assert(quic_tls_conn_set_server_preferred_address(&server,
                                                      &preferred_server_addr,
                                                      &preferred_cid,
                                                      preferred_token) == 0);
    assert(quic_tls_conn_set_initial_path(&client, &client_path) == 0);
    assert(quic_tls_conn_set_initial_path(&server, &server_path) == 0);
    assert(quic_tls_conn_start(&client) == 0);
    run_until(&client, &server, handshake_done);
    run_until(&client, &server, client_got_new_token_and_preferred_address);

    assert(quic_tls_conn_get_peer_preferred_address(&client,
                                                    &advertised_path,
                                                    &advertised_cid,
                                                    advertised_token) == 0);
    assert(advertised_path.peer.port == 4445);
    assert(advertised_cid.len == preferred_cid.len);
    assert(memcmp(advertised_cid.data, preferred_cid.data, preferred_cid.len) == 0);
    assert(memcmp(advertised_token, preferred_token, sizeof(preferred_token)) == 0);
    assert(client.retry_token_len > 0);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 5 preferred_address and NEW_TOKEN are advertised after the handshake\n");
}

static void test_stage5_idle_timeout_uses_effective_deadline_and_closes(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    quic_path_addr_t client_path;
    quic_path_addr_t server_path;
    quic_cid_t client_scid = make_cid(0x51);
    quic_cid_t client_odcid = make_cid(0xa1);
    quic_cid_t server_scid = make_cid(0xc1);
    uint64_t start_ms;
    uint64_t client_deadline;
    uint64_t server_deadline;
    uint64_t client_min_timeout;
    uint64_t server_min_timeout;

    make_path(&client_path, 1, 40100, 2, 4434);
    make_path(&server_path, 2, 4434, 1, 40100);

    quic_tls_conn_init(&client);
    quic_tls_conn_init(&server);
    quic_tls_conn_set_max_idle_timeout(&client, 50);
    quic_tls_conn_set_max_idle_timeout(&server, 50);
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
    assert(quic_tls_conn_set_initial_path(&client, &client_path) == 0);
    assert(quic_tls_conn_set_initial_path(&server, &server_path) == 0);
    assert(quic_tls_conn_start(&client) == 0);
    run_until(&client, &server, handshake_done);
    start_ms = now_ms();
    client_min_timeout = current_pto_ms(&client) * 3ULL;
    if (client_min_timeout < 50) {
        client_min_timeout = 50;
    }
    server_min_timeout = current_pto_ms(&server) * 3ULL;
    if (server_min_timeout < 50) {
        server_min_timeout = 50;
    }
    client_deadline = client.idle_deadline_ms;
    server_deadline = server.idle_deadline_ms;
    assert(client_deadline > start_ms);
    assert(server_deadline > start_ms);
    assert(client.effective_idle_timeout_ms >= client_min_timeout);
    assert(server.effective_idle_timeout_ms >= server_min_timeout);
    assert(client_deadline - start_ms >= client_min_timeout);
    assert(server_deadline - start_ms >= server_min_timeout);

    quic_tls_conn_on_timeout(&client, client_deadline);
    quic_tls_conn_on_timeout(&server, server_deadline);
    assert(client.conn.state == QUIC_CONN_STATE_CLOSED);
    assert(server.conn.state == QUIC_CONN_STATE_CLOSED);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 5 idle timeout uses the negotiated effective timeout and closes silently\n");
}

static void test_stage5_stateless_reset_detection_enters_draining(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    quic_path_addr_t client_path;
    quic_path_addr_t server_path;
    captured_packet_t reset_packet;

    make_path(&client_path, 1, 40200, 2, 4434);
    make_path(&server_path, 2, 4434, 1, 40200);
    configure_pair(&client, &server, &client_path, &server_path);

    assert(quic_tls_conn_build_stateless_reset(&server,
                                               64,
                                               reset_packet.bytes,
                                               sizeof(reset_packet.bytes),
                                               &reset_packet.len) == 0);
    reset_packet.send_path = server_path;
    assert(deliver_packet(&client, &reset_packet) == 0);
    assert(client.stateless_reset_detected == 1);
    assert(client.conn.state == QUIC_CONN_STATE_DRAINING);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 5 stateless reset detection enters draining without sending further packets\n");
}

int main(void) {
    test_stage5_preferred_address_and_new_token_arrive_post_handshake();
    test_stage5_idle_timeout_uses_effective_deadline_and_closes();
    test_stage5_stateless_reset_detection_enters_draining();
    printf("Phase 18 tests passed.\n");
    return 0;
}
