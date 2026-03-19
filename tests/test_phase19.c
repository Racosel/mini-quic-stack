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
        fprintf(stderr,
                "capture_one blocked role=%d bytes_in_flight=%llu cwnd=%llu pending_path=%zu path_count=%zu\n",
                src->role,
                (unsigned long long)src->conn.recovery.bytes_in_flight,
                (unsigned long long)src->conn.recovery.congestion_window,
                src->pending_path_index,
                src->path_count);
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

static int handshake_done(const quic_tls_conn_t *client, const quic_tls_conn_t *server) {
    return quic_tls_conn_handshake_complete(client) && quic_tls_conn_handshake_complete(server);
}

static void dump_conn_state(const char *label, const quic_tls_conn_t *conn) {
    size_t i;

    fprintf(stderr,
            "%s state=%d active_path=%zu pending_path=%zu path_count=%zu has_output=%d next_timeout=%llu "
            "new_cid=%u retire_cid=%u new_token=%u ping=%u hs_done=%u stream_output=%d "
            "bytes_in_flight=%llu cwnd=%llu app_ack_in_flight=%zu\n",
            label,
            conn ? (int)conn->conn.state : -1,
            conn ? conn->active_path_index : 0,
            conn ? conn->pending_path_index : 0,
            conn ? conn->path_count : 0,
            quic_tls_conn_has_pending_output(conn),
            (unsigned long long)quic_tls_conn_next_timeout_ms(conn),
            conn ? conn->new_connection_id_pending : 0,
            conn ? conn->retire_connection_id_pending : 0,
            conn ? conn->new_token_pending : 0,
            conn ? conn->ping_pending : 0,
            conn ? conn->handshake_done_pending : 0,
            conn ? quic_stream_map_has_pending_output(&conn->streams) : 0,
            conn ? (unsigned long long)conn->conn.recovery.bytes_in_flight : 0ULL,
            conn ? (unsigned long long)conn->conn.recovery.congestion_window : 0ULL,
            conn ? conn->conn.spaces[QUIC_PN_SPACE_APPLICATION].in_flight.ack_eliciting_in_flight : 0U);
    if (!conn) {
        return;
    }
    for (i = 0; i < conn->path_count; i++) {
        const quic_tls_path_t *path = &conn->paths[i];

        fprintf(stderr,
                "  path[%zu] active=%u state=%u challenge_pending=%u challenge_in_flight=%u "
                "response_pending=%u response_in_flight=%u deadline=%llu local_port=%u peer_port=%u\n",
                i,
                path->active,
                path->state,
                path->challenge_pending,
                path->challenge_in_flight,
                path->response_pending,
                path->response_in_flight,
                (unsigned long long)path->validation_deadline_ms,
                path->addr.local.port,
                path->addr.peer.port);
    }
}

static void run_until(quic_tls_conn_t *client,
                      quic_tls_conn_t *server,
                      int (*done)(const quic_tls_conn_t *, const quic_tls_conn_t *)) {
    size_t rounds = 0;

    while (!done(client, server) && rounds++ < 4096) {
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
    if (!done(client, server)) {
        dump_conn_state("client", client);
        dump_conn_state("server", server);
    }
    assert(done(client, server));
}

static void configure_pair(quic_tls_conn_t *client,
                           quic_tls_conn_t *server,
                           const quic_path_addr_t *client_path,
                           const quic_path_addr_t *server_path) {
    quic_cid_t client_scid = make_cid(0x51);
    quic_cid_t client_odcid = make_cid(0xa1);
    quic_cid_t server_scid = make_cid(0xc1);

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

static int client_has_spare_cid(const quic_tls_conn_t *client, const quic_tls_conn_t *server) {
    (void)server;
    return client && client->peer_cid_count >= 2;
}

static int migration_completed(const quic_tls_conn_t *client, const quic_tls_conn_t *server) {
    return client &&
           server &&
           client->active_path_index < client->path_count &&
           server->active_path_index < server->path_count &&
           client->paths[client->active_path_index].state == QUIC_TLS_PATH_VALIDATED &&
           server->paths[server->active_path_index].state == QUIC_TLS_PATH_VALIDATED &&
           client->paths[client->active_path_index].addr.local.port == 41001 &&
           server->paths[server->active_path_index].addr.peer.port == 41001;
}

static void test_stage5_active_migration_validates_new_path(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    quic_path_addr_t client_path;
    quic_path_addr_t server_path;
    quic_path_addr_t migrated_client_path;
    uint64_t stream_id = UINT64_MAX;
    static const uint8_t request[] = "post-migration request payload";
    uint8_t recvbuf[128];
    size_t recvlen = 0;
    int fin = 0;

    make_path(&client_path, 1, 41000, 2, 4434);
    make_path(&server_path, 2, 4434, 1, 41000);
    configure_pair(&client, &server, &client_path, &server_path);
    run_until(&client, &server, client_has_spare_cid);

    make_path(&migrated_client_path, 1, 41001, 2, 4434);
    assert(quic_tls_conn_begin_migration(&client, &migrated_client_path, 0) == 0);
    assert(quic_tls_conn_open_stream(&client, 1, &stream_id) == 0);
    assert(stream_id == 0);
    assert(quic_tls_conn_stream_write(&client, stream_id, request, sizeof(request) - 1, 1) == 0);

    run_until(&client, &server, migration_completed);
    assert(quic_tls_conn_stream_read(&server, stream_id, recvbuf, sizeof(recvbuf), &recvlen, &fin) == 0);
    assert(fin == 1);
    assert(recvlen == sizeof(request) - 1);
    assert(memcmp(recvbuf, request, recvlen) == 0);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 5 active migration validates a new client path and keeps stream transfer alive\n");
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

static void test_stage5_preferred_address_migration_uses_announced_server_address(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    quic_path_addr_t client_path;
    quic_path_addr_t server_path;
    quic_socket_addr_t preferred_server_addr;
    quic_cid_t preferred_cid = make_cid(0xe1);
    uint8_t preferred_token[QUIC_STATELESS_RESET_TOKEN_LEN];
    quic_path_addr_t preferred_path;
    size_t i;

    for (i = 0; i < sizeof(preferred_token); i++) {
        preferred_token[i] = (uint8_t)(0xc0 + i);
    }

    make_path(&client_path, 1, 41100, 2, 4434);
    make_path(&server_path, 2, 4434, 1, 41100);
    quic_socket_addr_init_ipv4(&preferred_server_addr, 10, 0, 0, 2, 4445);

    quic_tls_conn_init(&client);
    quic_tls_conn_init(&server);
    assert(quic_tls_conn_configure(&client,
                                   QUIC_ROLE_CLIENT,
                                   QUIC_V1_VERSION,
                                   &(quic_cid_t){ .len = 8, .data = {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68} },
                                   &(quic_cid_t){ .len = 8, .data = {0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8} },
                                   NULL,
                                   NULL) == 0);
    assert(quic_tls_conn_configure(&server,
                                   QUIC_ROLE_SERVER,
                                   QUIC_V1_VERSION,
                                   &(quic_cid_t){ .len = 8, .data = {0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8} },
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
    assert(quic_tls_conn_get_peer_preferred_address(&client, &preferred_path, NULL, NULL) == 0);
    assert(quic_tls_conn_begin_migration(&client, &preferred_path, 1) == 0);
    assert(client.preferred_migration_pending == 1);
    assert(client.preferred_migration_path_index < client.path_count);
    assert(client.paths[client.preferred_migration_path_index].addr.peer.port == 4445);
    assert(client.paths[client.active_path_index].addr.peer.port == 4434);
    assert(client.retire_connection_id_pending == 0);
    run_until(&client, &server, preferred_path_validated);

    assert(client.paths[client.active_path_index].addr.peer.port == 4445);
    assert(client.preferred_migration_pending == 0);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 5 preferred_address migration switches the client to the announced server address\n");
}

int main(void) {
    test_stage5_active_migration_validates_new_path();
    test_stage5_preferred_address_migration_uses_announced_server_address();
    printf("Phase 19 tests passed.\n");
    return 0;
}
