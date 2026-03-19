#include "quic_tls.h"
#include "quic_version.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define TEST_CERT_FILE "tests/certs/server_cert.pem"
#define TEST_KEY_FILE  "tests/certs/server_key.pem"

typedef struct {
    uint8_t bytes[QUIC_TLS_MAX_DATAGRAM_SIZE];
    size_t len;
    quic_path_addr_t send_path;
} captured_packet_t;

static void dump_conn_state(const char *label, const quic_tls_conn_t *conn);

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

static int step_pair(quic_tls_conn_t *client, quic_tls_conn_t *server) {
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
    return progressed;
}

static int handshake_done(const quic_tls_conn_t *client, const quic_tls_conn_t *server) {
    return quic_tls_conn_handshake_complete(client) && quic_tls_conn_handshake_complete(server);
}

static int preferred_path_validated(const quic_tls_conn_t *client, const quic_tls_conn_t *server) {
    return client &&
           server &&
           client->active_path_index < client->path_count &&
           server->active_path_index < server->path_count &&
           client->paths[client->active_path_index].state == QUIC_TLS_PATH_VALIDATED &&
           client->paths[client->active_path_index].addr.peer.port == 4445 &&
           server->paths[server->active_path_index].state == QUIC_TLS_PATH_VALIDATED;
}

static void run_until(quic_tls_conn_t *client,
                      quic_tls_conn_t *server,
                      int (*done)(const quic_tls_conn_t *, const quic_tls_conn_t *)) {
    size_t rounds = 0;

    while (!done(client, server) && rounds++ < 4096) {
        assert(step_pair(client, server));
    }
    assert(done(client, server));
}

static void run_until_stream_available(quic_tls_conn_t *client,
                                       quic_tls_conn_t *server,
                                       quic_tls_conn_t *reader,
                                       uint64_t stream_id) {
    size_t rounds = 0;

    while (rounds++ < 4096) {
        size_t available = 0;
        int fin = 0;
        int exists = 0;

        if (quic_stream_map_peek(&reader->streams, stream_id, &available, &fin, &exists) == 0 &&
            exists &&
            (available > 0 || fin)) {
            return;
        }
        assert(step_pair(client, server));
    }
    dump_conn_state("client", client);
    dump_conn_state("server", server);
    fprintf(stderr, "stream %" PRIu64 " did not become readable in time\n", stream_id);
    assert(0);
}

static void dump_conn_state(const char *label, const quic_tls_conn_t *conn) {
    size_t i;

    fprintf(stderr,
            "%s state=%d active_path=%zu pending_path=%zu path_count=%zu has_output=%d next_timeout=%llu\n",
            label,
            conn ? (int)conn->conn.state : -1,
            conn ? conn->active_path_index : 0,
            conn ? conn->pending_path_index : 0,
            conn ? conn->path_count : 0,
            quic_tls_conn_has_pending_output(conn),
            (unsigned long long)quic_tls_conn_next_timeout_ms(conn));
    if (!conn) {
        return;
    }
    for (i = 0; i < conn->path_count; i++) {
        const quic_tls_path_t *path = &conn->paths[i];

        fprintf(stderr,
                "  path[%zu] active=%u state=%u challenge_pending=%u challenge_in_flight=%u "
                "challenge_expected=%u response_pending=%u response_in_flight=%u "
                "local_port=%u peer_port=%u\n",
                i,
                path->active,
                path->state,
                path->challenge_pending,
                path->challenge_in_flight,
                path->challenge_expected,
                path->response_pending,
                path->response_in_flight,
                path->addr.local.port,
                path->addr.peer.port);
    }
}

static void configure_pair(quic_tls_conn_t *client,
                           quic_tls_conn_t *server,
                           const quic_path_addr_t *client_path,
                           const quic_path_addr_t *server_path,
                           const quic_socket_addr_t *preferred_server_addr,
                           const quic_cid_t *preferred_cid,
                           const uint8_t *preferred_token) {
    quic_cid_t client_scid = make_cid(0x71);
    quic_cid_t client_odcid = make_cid(0xa1);
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
    assert(quic_tls_conn_set_server_preferred_address(server,
                                                      preferred_server_addr,
                                                      preferred_cid,
                                                      preferred_token) == 0);
    assert(quic_tls_conn_set_initial_path(client, client_path) == 0);
    assert(quic_tls_conn_set_initial_path(server, server_path) == 0);
    assert(quic_tls_conn_start(client) == 0);
    run_until(client, server, handshake_done);
}

static void test_stage5_integrated_preferred_address_transfer_then_stateless_reset(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    quic_path_addr_t client_path;
    quic_path_addr_t server_path;
    quic_socket_addr_t preferred_server_addr;
    quic_path_addr_t preferred_path;
    quic_cid_t preferred_cid = make_cid(0xf1);
    uint8_t preferred_token[QUIC_STATELESS_RESET_TOKEN_LEN];
    uint64_t stream_id = UINT64_MAX;
    static const uint8_t request[] = "integrated migration request";
    static const uint8_t response[] = "integrated migration response";
    uint8_t recvbuf[128];
    size_t recvlen = 0;
    int fin = 0;
    captured_packet_t reset_packet;
    size_t i;

    for (i = 0; i < sizeof(preferred_token); i++) {
        preferred_token[i] = (uint8_t)(0xd0 + i);
    }

    make_path(&client_path, 1, 42000, 2, 4434);
    make_path(&server_path, 2, 4434, 1, 42000);
    quic_socket_addr_init_ipv4(&preferred_server_addr, 10, 0, 0, 2, 4445);

    configure_pair(&client, &server, &client_path, &server_path, &preferred_server_addr, &preferred_cid, preferred_token);
    assert(quic_tls_conn_get_peer_preferred_address(&client, &preferred_path, NULL, NULL) == 0);
    assert(quic_tls_conn_begin_migration(&client, &preferred_path, 1) == 0);
    run_until(&client, &server, preferred_path_validated);

    assert(quic_tls_conn_open_stream(&client, 1, &stream_id) == 0);
    assert(quic_tls_conn_stream_write(&client, stream_id, request, sizeof(request) - 1, 1) == 0);
    run_until_stream_available(&client, &server, &server, stream_id);
    if (quic_tls_conn_stream_read(&server, stream_id, recvbuf, sizeof(recvbuf), &recvlen, &fin) != 0) {
        dump_conn_state("client", &client);
        dump_conn_state("server", &server);
        fprintf(stderr, "server stream_read failed: %s\n", quic_tls_conn_last_error(&server));
        assert(0);
    }
    assert(fin == 1);
    assert(recvlen == sizeof(request) - 1);
    assert(memcmp(recvbuf, request, recvlen) == 0);

    assert(quic_tls_conn_stream_write(&server, stream_id, response, sizeof(response) - 1, 1) == 0);
    memset(recvbuf, 0, sizeof(recvbuf));
    recvlen = 0;
    fin = 0;
    run_until_stream_available(&client, &server, &client, stream_id);
    assert(quic_tls_conn_stream_read(&client, stream_id, recvbuf, sizeof(recvbuf), &recvlen, &fin) == 0);
    assert(fin == 1);
    assert(recvlen == sizeof(response) - 1);
    assert(memcmp(recvbuf, response, recvlen) == 0);
    assert(client.paths[client.active_path_index].addr.peer.port == 4445);

    assert(quic_tls_conn_build_stateless_reset(&server,
                                               80,
                                               reset_packet.bytes,
                                               sizeof(reset_packet.bytes),
                                               &reset_packet.len) == 0);
    reset_packet.send_path.local = preferred_server_addr;
    reset_packet.send_path.peer = client.paths[client.active_path_index].addr.local;
    assert(deliver_packet(&client, &reset_packet) == 0);
    assert(client.stateless_reset_detected == 1);
    assert(client.conn.state == QUIC_CONN_STATE_DRAINING);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 5 integrated migration keeps transfer alive and stateless reset still terminates the connection\n");
}

int main(void) {
    test_stage5_integrated_preferred_address_transfer_then_stateless_reset();
    printf("Phase 20 tests passed.\n");
    return 0;
}
