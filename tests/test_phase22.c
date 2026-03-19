#include "pkt_decode.h"
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

static void fill_pattern(uint8_t *out, size_t len, uint8_t seed) {
    size_t i;

    for (i = 0; i < len; i++) {
        out[i] = (uint8_t)(seed + (i * 37U) % 251U);
    }
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

static int step_pair(quic_api_conn_t *client,
                     quic_api_conn_t *server,
                     int drop_first_client_app_packet,
                     int *dropped) {
    int progressed = 0;
    captured_packet_t packet;

    while (capture_one(client, &packet)) {
        if (drop_first_client_app_packet && dropped && !*dropped) {
            quic_pkt_header_meta_t meta;

            if (quic_parse_header_meta(packet.bytes, packet.len, &meta) == 0 && meta.header_form == 0) {
                *dropped = 1;
                progressed = 1;
                continue;
            }
        }
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

static void dump_conn_state(const char *label, const quic_api_conn_t *conn) {
    quic_api_conn_info_t info;
    quic_api_path_info_t path_info;
    quic_api_stream_info_t stream0;
    size_t i;

    if (!label || quic_api_conn_get_info(conn, &info) != 0) {
        return;
    }
    fprintf(stderr,
            "%s state=%d handshake=%u ping_received=%u has_output=%d bytes_sent=%llu bytes_recv=%llu pto=%llu cwnd=%llu bif=%llu\n",
            label,
            (int)info.state,
            info.handshake_complete,
            info.ping_received,
            info.has_pending_output,
            (unsigned long long)conn->metrics.bytes_sent,
            (unsigned long long)conn->metrics.bytes_received,
            (unsigned long long)conn->metrics.pto_count,
            (unsigned long long)conn->metrics.congestion_window,
            (unsigned long long)conn->metrics.bytes_in_flight);
    if (quic_api_conn_get_stream_info(conn, 0, &stream0) == 0 && stream0.exists) {
        fprintf(stderr,
                "  stream0 send_highest=%llu recv_highest=%llu recv_final_known=%u fin_received=%u fin_sent=%u readable=%zu\n",
                (unsigned long long)stream0.send_highest_offset,
                (unsigned long long)stream0.recv_highest_offset,
                stream0.recv_final_size_known,
                stream0.fin_received,
                stream0.fin_sent,
                stream0.readable_bytes);
    }
    for (i = 0; i < info.path_count; i++) {
        if (quic_api_conn_get_path_info(conn, i, &path_info) == 0) {
            fprintf(stderr,
                    "  path[%zu] state=%u local_port=%u peer_port=%u challenge_in_flight=%u response_pending=%u\n",
                    i,
                    path_info.state,
                    path_info.local.port,
                    path_info.peer.port,
                    path_info.challenge_in_flight,
                    path_info.response_pending);
        }
    }
}

static void run_until(quic_api_conn_t *client,
                      quic_api_conn_t *server,
                      int (*done)(const quic_api_conn_t *, const quic_api_conn_t *),
                      int drop_first_client_app_packet,
                      int *dropped) {
    size_t rounds = 0;

    while (!done(client, server) && rounds++ < 4096) {
        assert(step_pair(client, server, drop_first_client_app_packet, dropped));
    }
    if (!done(client, server)) {
        dump_conn_state("client", client);
        dump_conn_state("server", server);
    }
    assert(done(client, server));
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
        uint8_t scratch[2048];
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

static int server_ping_received(const quic_api_conn_t *client, const quic_api_conn_t *server) {
    quic_api_conn_info_t info;

    (void)client;
    return quic_api_conn_get_info(server, &info) == 0 && info.ping_received;
}

static void configure_pair(quic_api_conn_t *client,
                           quic_api_conn_t *server,
                           const quic_path_addr_t *client_path,
                           const quic_path_addr_t *server_path) {
    quic_cid_t client_scid = make_cid(0x61);
    quic_cid_t client_odcid = make_cid(0xa2);
    quic_cid_t server_scid = make_cid(0xb2);

    quic_api_conn_init(client);
    quic_api_conn_init(server);
    quic_api_conn_set_initial_flow_control(client, 512 * 1024, 512 * 1024, 512 * 1024, 512 * 1024, 8, 8);
    quic_api_conn_set_initial_flow_control(server, 512 * 1024, 512 * 1024, 512 * 1024, 512 * 1024, 8, 8);
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
    run_until(client, server, handshake_done, 0, NULL);
}

static void test_stage6_metrics_events_and_parser_stress(void) {
    quic_api_conn_t client;
    quic_api_conn_t server;
    quic_path_addr_t client_path;
    quic_path_addr_t server_path;
    uint8_t payload[16384];
    uint8_t response[] = "stage6-metrics-response";
    uint8_t recvbuf[16384];
    size_t recvlen = 0;
    int fin = 0;
    int dropped = 0;
    uint64_t stream_id = UINT64_MAX;
    quic_api_metrics_t metrics;
    quic_api_event_t event;
    quic_api_conn_info_t info;
    quic_api_path_info_t path_info;
    quic_api_stream_info_t stream_info;
    char json[256];
    char metrics_json[512];
    int saw_handshake_json = 0;
    int saw_ping_json = 0;
    int saw_readable_json = 0;
    uint32_t seed = 0x12345678U;
    size_t len;

    fill_pattern(payload, sizeof(payload), 0x19);
    make_path(&client_path, 1, 44430, 2, 44440);
    make_path(&server_path, 2, 44440, 1, 44430);
    configure_pair(&client, &server, &client_path, &server_path);

    quic_api_conn_queue_ping(&client);
    run_until(&client, &server, server_ping_received, 1, &dropped);
    assert(dropped == 1);

    assert(quic_api_conn_open_stream(&client, 1, &stream_id) == 0);
    assert(stream_id == 0);
    assert(quic_api_conn_stream_write(&client, stream_id, payload, sizeof(payload), 1) == 0);

    recvlen = 0;
    fin = 0;
    for (len = 0; len < 4096 && !fin; len++) {
        assert(step_pair(&client, &server, 0, NULL));
        drain_stream(&server, stream_id, recvbuf, sizeof(recvbuf), &recvlen, &fin);
    }
    assert(fin == 1);
    assert(recvlen == sizeof(payload));
    assert(memcmp(recvbuf, payload, sizeof(payload)) == 0);

    assert(quic_api_conn_stream_write(&server, stream_id, response, sizeof(response) - 1, 1) == 0);
    recvlen = 0;
    fin = 0;
    for (len = 0; len < 4096 && !fin; len++) {
        assert(step_pair(&client, &server, 0, NULL));
        drain_stream(&client, stream_id, recvbuf, sizeof(recvbuf), &recvlen, &fin);
    }
    assert(fin == 1);
    assert(recvlen == sizeof(response) - 1);
    assert(memcmp(recvbuf, response, sizeof(response) - 1) == 0);

    assert(quic_api_conn_get_metrics(&client, &metrics) == 0);
    assert(metrics.bytes_sent > 0);
    assert(metrics.bytes_received > 0);
    assert(metrics.congestion_window > 0);
    assert(metrics.events_emitted > 0);
    assert(quic_api_metrics_format_json(&metrics, metrics_json, sizeof(metrics_json)) == 0);
    assert(strstr(metrics_json, "\"bytes_sent\":") != NULL);
    assert(strstr(metrics_json, "\"congestion_window\":") != NULL);

    assert(quic_api_conn_get_info(&client, &info) == 0);
    assert(info.handshake_complete == 1);
    assert(info.path_count >= 1);
    assert(quic_api_conn_get_path_info(&client, info.active_path_index, &path_info) == 0);
    assert(path_info.present == 1);
    assert(path_info.state == QUIC_TLS_PATH_VALIDATED);
    assert(quic_api_conn_get_stream_info(&server, stream_id, &stream_info) == 0);
    assert(stream_info.exists == 1);
    assert(stream_info.fin_received == 1);
    assert(stream_info.recv_final_size_known == 1);
    assert(stream_info.recv_final_size == sizeof(payload));

    while (quic_api_conn_poll_event(&client, &event) == 0) {
        assert(quic_api_event_format_json(&event, json, sizeof(json)) == 0);
        saw_handshake_json |= strstr(json, "\"event\":\"handshake_complete\"") != NULL;
        saw_ping_json |= strstr(json, "\"event\":\"ping_queued\"") != NULL;
        saw_readable_json |= strstr(json, "\"event\":\"stream_readable\"") != NULL;
    }
    assert(saw_handshake_json);
    assert(saw_ping_json);
    assert(saw_readable_json);

    assert(quic_api_event_format_json(&event, json, 8) == -1);

    for (len = 0; len < 64; len++) {
        uint8_t packet[64];
        quic_pkt_header_meta_t meta;
        size_t i;
        int rc;

        for (i = 0; i < len; i++) {
            seed = seed * 1103515245U + 12345U;
            packet[i] = (uint8_t)((seed >> 16) & 0xff);
        }
        rc = quic_parse_header_meta(packet, len, &meta);
        assert(rc == 0 || rc < 0);
    }

    quic_api_conn_free(&client);
    quic_api_conn_free(&server);
    printf("[PASS] Stage 6 metrics/events export and parser-stress regression work through the stable API\n");
}

int main(void) {
    test_stage6_metrics_events_and_parser_stress();
    return 0;
}
