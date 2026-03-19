#include "quic_api.h"
#include "quic_version.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

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

static int capture_one(quic_api_conn_t *src, captured_packet_t *packet) {
    int status;

    if (!src || !packet || !quic_api_conn_has_pending_output(src)) {
        return 0;
    }
    status = quic_api_conn_build_next_datagram_on_path(src,
                                                       packet->bytes,
                                                       sizeof(packet->bytes),
                                                       &packet->len,
                                                       &packet->send_path);
    if (status == QUIC_TLS_BUILD_BLOCKED) {
        return 0;
    }
    if (status != 0) {
        fprintf(stderr, "build_next_datagram_on_path failed: %s\n", quic_api_conn_last_error(src));
        assert(0);
    }
    return 1;
}

static int deliver_packet(quic_api_conn_t *dst, const captured_packet_t *packet) {
    quic_path_addr_t recv_path;
    int rc;

    reverse_path(&packet->send_path, &recv_path);
    rc = quic_api_conn_handle_datagram_on_path(dst, packet->bytes, packet->len, &recv_path);
    if (rc != 0) {
        fprintf(stderr, "handle_datagram_on_path failed: %s\n", quic_api_conn_last_error(dst));
    }
    return rc;
}

static int drive_timers(quic_api_conn_t *client, quic_api_conn_t *server) {
    uint64_t client_deadline = quic_api_conn_next_timeout_ms(client);
    uint64_t server_deadline = quic_api_conn_next_timeout_ms(server);
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
        quic_api_conn_on_timeout(client, deadline);
    }
    if (server_deadline != 0 && server_deadline == deadline) {
        quic_api_conn_on_timeout(server, deadline);
    }
    return 1;
}

static int step_pair(quic_api_conn_t *client, quic_api_conn_t *server) {
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

static int handshake_done(const quic_api_conn_t *client, const quic_api_conn_t *server) {
    return quic_api_conn_handshake_complete(client) && quic_api_conn_handshake_complete(server);
}

static void run_until(quic_api_conn_t *client,
                      quic_api_conn_t *server,
                      int (*done)(const quic_api_conn_t *, const quic_api_conn_t *)) {
    size_t rounds = 0;

    while (!done(client, server) && rounds++ < 4096) {
        assert(step_pair(client, server));
    }
    assert(done(client, server));
}

static void run_until_stream_available(quic_api_conn_t *client,
                                       quic_api_conn_t *server,
                                       quic_api_conn_t *reader,
                                       uint64_t stream_id) {
    size_t rounds = 0;

    while (rounds++ < 4096) {
        size_t available = 0;
        int fin = 0;
        int exists = 0;

        if (quic_api_conn_stream_peek(reader, stream_id, &available, &fin, &exists) == 0 &&
            exists &&
            (available > 0 || fin)) {
            return;
        }
        assert(step_pair(client, server));
    }
    fprintf(stderr, "stream %llu did not become readable in time\n", (unsigned long long)stream_id);
    assert(0);
}

static void drain_stream(quic_api_conn_t *conn,
                         uint64_t stream_id,
                         uint8_t *storage,
                         size_t storage_cap,
                         size_t *used,
                         int *fin) {
    for (;;) {
        size_t available = 0;
        size_t out_read = 0;
        int exists = 0;
        int local_fin = 0;
        uint8_t scratch[512];
        size_t chunk = sizeof(scratch);

        assert(quic_api_conn_stream_peek(conn, stream_id, &available, &local_fin, &exists) == 0);
        if (!exists || (available == 0 && !local_fin)) {
            break;
        }
        if (available > 0 && available < chunk) {
            chunk = available;
        }
        assert(quic_api_conn_stream_read(conn, stream_id, scratch, chunk, &out_read, &local_fin) == 0);
        assert(*used + out_read <= storage_cap);
        if (out_read > 0) {
            memcpy(storage + *used, scratch, out_read);
            *used += out_read;
        }
        if (local_fin) {
            *fin = 1;
            break;
        }
        if (out_read == 0) {
            break;
        }
    }
}

static void configure_pair(quic_api_conn_t *client,
                           quic_api_conn_t *server,
                           const quic_path_addr_t *client_path,
                           const quic_path_addr_t *server_path) {
    quic_cid_t client_scid = make_cid(0x51);
    quic_cid_t client_odcid = make_cid(0xa1);
    quic_cid_t server_scid = make_cid(0xb1);

    quic_api_conn_init(client);
    quic_api_conn_init(server);
    quic_api_conn_set_initial_flow_control(client, 256 * 1024, 64 * 1024, 64 * 1024, 64 * 1024, 8, 8);
    quic_api_conn_set_initial_flow_control(server, 256 * 1024, 64 * 1024, 64 * 1024, 64 * 1024, 8, 8);

    assert(quic_api_conn_configure(client,
                                   QUIC_ROLE_CLIENT,
                                   QUIC_V1_VERSION,
                                   &client_scid,
                                   &client_odcid,
                                   NULL,
                                   NULL) == 0);
    assert(quic_api_conn_configure(server,
                                   QUIC_ROLE_SERVER,
                                   QUIC_V1_VERSION,
                                   &server_scid,
                                   NULL,
                                   TEST_CERT_FILE,
                                   TEST_KEY_FILE) == 0);
    assert(quic_api_conn_set_initial_path(client, client_path) == 0);
    assert(quic_api_conn_set_initial_path(server, server_path) == 0);
    assert(quic_api_conn_start(client) == 0);
    run_until(client, server, handshake_done);
}

static int close_done(const quic_api_conn_t *client, const quic_api_conn_t *server) {
    quic_api_conn_info_t client_info;
    quic_api_conn_info_t server_info;

    return quic_api_conn_get_info(client, &client_info) == 0 &&
           quic_api_conn_get_info(server, &server_info) == 0 &&
           (client_info.state == QUIC_CONN_STATE_DRAINING || client_info.state == QUIC_CONN_STATE_CLOSED) &&
           (server_info.state == QUIC_CONN_STATE_DRAINING || server_info.state == QUIC_CONN_STATE_CLOSED);
}

static void test_stage6_api_request_response_and_close(void) {
    quic_api_conn_t client;
    quic_api_conn_t server;
    quic_path_addr_t client_path;
    quic_path_addr_t server_path;
    uint64_t stream0 = UINT64_MAX;
    uint64_t stream4 = UINT64_MAX;
    static const uint8_t request0[] = "api-stage6-request-0";
    static const uint8_t request4[] = "api-stage6-request-4";
    static const uint8_t response0[] = "api-stage6-response-0";
    static const uint8_t response4[] = "api-stage6-response-4";
    uint8_t recvbuf[256];
    size_t recvlen = 0;
    int fin = 0;
    quic_api_metrics_t client_metrics;
    quic_api_metrics_t server_metrics;
    quic_api_event_t event;
    int saw_client_handshake = 0;
    int saw_client_open = 0;
    int saw_client_readable = 0;
    int saw_client_fin = 0;
    int saw_client_close_req = 0;
    int saw_server_handshake = 0;
    int saw_server_open = 0;
    int saw_server_readable = 0;
    int saw_server_fin = 0;
    quic_api_stream_info_t stream_info;
    quic_api_conn_info_t client_info;
    quic_api_conn_info_t server_info;

    make_path(&client_path, 1, 44330, 2, 44340);
    make_path(&server_path, 2, 44340, 1, 44330);
    configure_pair(&client, &server, &client_path, &server_path);

    assert(quic_api_conn_open_stream(&client, 1, &stream0) == 0);
    assert(quic_api_conn_open_stream(&client, 1, &stream4) == 0);
    assert(stream0 == 0);
    assert(stream4 == 4);
    assert(quic_api_conn_stream_write(&client, stream0, request0, sizeof(request0) - 1, 1) == 0);
    assert(quic_api_conn_stream_write(&client, stream4, request4, sizeof(request4) - 1, 1) == 0);

    run_until_stream_available(&client, &server, &server, stream0);
    recvlen = 0;
    fin = 0;
    drain_stream(&server, stream0, recvbuf, sizeof(recvbuf), &recvlen, &fin);
    assert(fin == 1);
    assert(recvlen == sizeof(request0) - 1);
    assert(memcmp(recvbuf, request0, recvlen) == 0);

    run_until_stream_available(&client, &server, &server, stream4);
    recvlen = 0;
    fin = 0;
    drain_stream(&server, stream4, recvbuf, sizeof(recvbuf), &recvlen, &fin);
    assert(fin == 1);
    assert(recvlen == sizeof(request4) - 1);
    assert(memcmp(recvbuf, request4, recvlen) == 0);

    assert(quic_api_conn_stream_write(&server, stream0, response0, sizeof(response0) - 1, 1) == 0);
    assert(quic_api_conn_stream_write(&server, stream4, response4, sizeof(response4) - 1, 1) == 0);

    run_until_stream_available(&client, &server, &client, stream0);
    recvlen = 0;
    fin = 0;
    drain_stream(&client, stream0, recvbuf, sizeof(recvbuf), &recvlen, &fin);
    assert(fin == 1);
    assert(recvlen == sizeof(response0) - 1);
    assert(memcmp(recvbuf, response0, recvlen) == 0);

    run_until_stream_available(&client, &server, &client, stream4);
    recvlen = 0;
    fin = 0;
    drain_stream(&client, stream4, recvbuf, sizeof(recvbuf), &recvlen, &fin);
    assert(fin == 1);
    assert(recvlen == sizeof(response4) - 1);
    assert(memcmp(recvbuf, response4, recvlen) == 0);

    assert(quic_api_conn_get_stream_info(&client, stream0, &stream_info) == 0);
    assert(stream_info.exists == 1);
    assert(stream_info.fin_received == 1);
    assert(stream_info.recv_final_size_known == 1);
    assert(stream_info.recv_final_size == sizeof(response0) - 1);

    assert(quic_api_conn_get_stream_info(&server, stream4, &stream_info) == 0);
    assert(stream_info.exists == 1);
    assert(stream_info.fin_received == 1);
    assert(stream_info.recv_final_size_known == 1);
    assert(stream_info.recv_final_size == sizeof(request4) - 1);

    assert(quic_api_conn_close(&client, QUIC_TRANSPORT_ERROR_NO_ERROR) == 0);
    run_until(&client, &server, close_done);

    assert(quic_api_conn_get_info(&client, &client_info) == 0);
    assert(quic_api_conn_get_info(&server, &server_info) == 0);
    assert(client_info.handshake_complete == 1);
    assert(server_info.handshake_complete == 1);
    assert(client_info.path_count >= 1);
    assert(server_info.path_count >= 1);

    assert(quic_api_conn_get_metrics(&client, &client_metrics) == 0);
    assert(quic_api_conn_get_metrics(&server, &server_metrics) == 0);
    assert(client_metrics.bytes_sent > 0);
    assert(client_metrics.bytes_received > 0);
    assert(server_metrics.bytes_sent > 0);
    assert(server_metrics.bytes_received > 0);
    assert(client_metrics.streams_opened_local >= 2);
    assert(server_metrics.streams_opened_remote >= 2);

    while (quic_api_conn_poll_event(&client, &event) == 0) {
        saw_client_handshake |= event.type == QUIC_API_EVENT_HANDSHAKE_COMPLETE;
        saw_client_open |= event.type == QUIC_API_EVENT_STREAM_OPENED;
        saw_client_readable |= event.type == QUIC_API_EVENT_STREAM_READABLE;
        saw_client_fin |= event.type == QUIC_API_EVENT_STREAM_FIN_RECEIVED;
        saw_client_close_req |= event.type == QUIC_API_EVENT_CONNECTION_CLOSE_REQUESTED;
    }
    while (quic_api_conn_poll_event(&server, &event) == 0) {
        saw_server_handshake |= event.type == QUIC_API_EVENT_HANDSHAKE_COMPLETE;
        saw_server_open |= event.type == QUIC_API_EVENT_STREAM_OPENED;
        saw_server_readable |= event.type == QUIC_API_EVENT_STREAM_READABLE;
        saw_server_fin |= event.type == QUIC_API_EVENT_STREAM_FIN_RECEIVED;
    }

    assert(saw_client_handshake);
    assert(saw_client_open);
    assert(saw_client_readable);
    assert(saw_client_fin);
    assert(saw_client_close_req);
    assert(saw_server_handshake);
    assert(saw_server_open);
    assert(saw_server_readable);
    assert(saw_server_fin);

    quic_api_conn_free(&client);
    quic_api_conn_free(&server);
    printf("[PASS] Stage 6 stable application API can drive request/response streams and graceful close\n");
}

int main(void) {
    test_stage6_api_request_response_and_close();
    return 0;
}
