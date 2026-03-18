#include "pkt_decode.h"
#include "quic_stream.h"
#include "quic_tls.h"
#include "quic_version.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_CERT_FILE "tests/certs/server_cert.pem"
#define TEST_KEY_FILE  "tests/certs/server_key.pem"

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

static void fill_pattern(uint8_t *out, size_t len, uint8_t seed) {
    size_t i;

    for (i = 0; i < len; i++) {
        out[i] = (uint8_t)(seed + (i * 29U) % 251U);
    }
}

static int capture_one(quic_tls_conn_t *src, captured_packet_t *packet) {
    int status;

    if (!src || !packet || !quic_tls_conn_has_pending_output(src)) {
        return 0;
    }

    status = quic_tls_conn_build_next_datagram(src, packet->bytes, sizeof(packet->bytes), &packet->len);
    if (status == QUIC_TLS_BUILD_BLOCKED) {
        return 0;
    }
    if (status != 0) {
        fprintf(stderr, "build_next_datagram failed: %s\n", quic_tls_conn_last_error(src));
        assert(0);
    }
    return 1;
}

static int drive_timers(quic_tls_conn_t *client,
                        quic_tls_conn_t *server,
                        size_t *timeout_count) {
    uint64_t client_deadline = quic_tls_conn_loss_deadline_ms(client);
    uint64_t server_deadline = quic_tls_conn_loss_deadline_ms(server);
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
        quic_tls_conn_on_loss_timeout(client, deadline);
    }
    if (server_deadline != 0 && server_deadline == deadline) {
        quic_tls_conn_on_loss_timeout(server, deadline);
    }
    if (timeout_count) {
        (*timeout_count)++;
    }
    return 1;
}

static int handshake_done(const quic_tls_conn_t *client, const quic_tls_conn_t *server) {
    return quic_tls_conn_handshake_complete(client) && quic_tls_conn_handshake_complete(server);
}

static void run_handshake(quic_tls_conn_t *client, quic_tls_conn_t *server) {
    size_t rounds = 0;

    while (!handshake_done(client, server) && rounds++ < 1024) {
        int progressed = 0;
        captured_packet_t packet;

        while (capture_one(client, &packet)) {
            assert(quic_tls_conn_handle_datagram(server, packet.bytes, packet.len) == 0);
            progressed = 1;
        }
        while (capture_one(server, &packet)) {
            assert(quic_tls_conn_handle_datagram(client, packet.bytes, packet.len) == 0);
            progressed = 1;
        }
        if (!progressed) {
            progressed = drive_timers(client, server, NULL);
        }
        assert(progressed);
    }

    assert(handshake_done(client, server));
}

static void drain_pending_pair(quic_tls_conn_t *client, quic_tls_conn_t *server) {
    size_t rounds = 0;

    while (rounds++ < 1024) {
        int progressed = 0;
        captured_packet_t packet;

        while (capture_one(client, &packet)) {
            assert(quic_tls_conn_handle_datagram(server, packet.bytes, packet.len) == 0);
            progressed = 1;
        }
        while (capture_one(server, &packet)) {
            assert(quic_tls_conn_handle_datagram(client, packet.bytes, packet.len) == 0);
            progressed = 1;
        }
        if (!progressed) {
            break;
        }
    }
}

static void configure_pair(quic_tls_conn_t *client,
                           quic_tls_conn_t *server,
                           uint64_t max_data,
                           uint64_t max_stream_data) {
    quic_cid_t client_scid = make_cid(0x31);
    quic_cid_t client_odcid = make_cid(0x91);
    quic_cid_t server_scid = make_cid(0xb1);

    quic_tls_conn_init(client);
    quic_tls_conn_init(server);
    quic_tls_conn_set_initial_flow_control(client, max_data, max_stream_data, max_stream_data, max_stream_data, 4, 1);
    quic_tls_conn_set_initial_flow_control(server, max_data, max_stream_data, max_stream_data, max_stream_data, 4, 1);

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
    assert(quic_tls_conn_start(client) == 0);
    run_handshake(client, server);
    drain_pending_pair(client, server);
}

static int drain_stream(quic_tls_conn_t *conn,
                        uint64_t stream_id,
                        uint8_t *storage,
                        size_t storage_cap,
                        size_t *used,
                        int *fin,
                        size_t max_chunk) {
    int progressed = 0;

    for (;;) {
        size_t available = 0;
        size_t out_read = 0;
        int exists = 0;
        int local_fin = 0;
        uint8_t scratch[2048];
        size_t chunk = sizeof(scratch);

        if (max_chunk > 0 && max_chunk < chunk) {
            chunk = max_chunk;
        }
        assert(quic_tls_conn_stream_peek(conn, stream_id, &available, &local_fin, &exists) == 0);
        if (!exists || (available == 0 && !local_fin)) {
            break;
        }
        if (chunk > available && available > 0) {
            chunk = available;
        }
        assert(quic_tls_conn_stream_read(conn, stream_id, scratch, chunk, &out_read, &local_fin) == 0);
        assert(*used + out_read <= storage_cap);
        if (out_read > 0) {
            memcpy(storage + *used, scratch, out_read);
            *used += out_read;
            progressed = 1;
        }
        if (local_fin) {
            *fin = 1;
            progressed = 1;
            break;
        }
        if (out_read == 0) {
            break;
        }
    }

    return progressed;
}

static int should_drop_short_header(const captured_packet_t *packet, size_t drop_every, size_t *counter) {
    quic_pkt_header_meta_t meta;

    if (!packet || drop_every == 0 || !counter) {
        return 0;
    }
    if (quic_parse_header_meta(packet->bytes, packet->len, &meta) != 0 || meta.header_form != 0) {
        return 0;
    }

    (*counter)++;
    return (*counter % drop_every) == 0;
}

static void test_stage4_build_blocked_does_not_consume_send_state(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    uint8_t payload[4096];
    captured_packet_t packet;
    uint64_t stream_id = UINT64_MAX;
    const quic_stream_t *stream;
    size_t before_send_offset;
    size_t before_flight_end;
    uint64_t before_send_highest;
    uint64_t before_conn_highest;
    int before_fin_sent;
    int before_fin_in_flight;
    int before_send_open;
    int status;

    fill_pattern(payload, sizeof(payload), 0x11);
    configure_pair(&client, &server, 512 * 1024, 512 * 1024);
    assert(quic_tls_conn_open_stream(&client, 1, &stream_id) == 0);
    assert(quic_tls_conn_stream_write(&client, stream_id, payload, sizeof(payload), 1) == 0);

    stream = quic_stream_map_find_const(&client.streams, stream_id);
    assert(stream);
    before_send_offset = stream->sendbuf.send_offset;
    before_flight_end = stream->sendbuf.flight_end;
    before_send_highest = stream->send_highest_offset;
    before_conn_highest = client.streams.send_connection_highest;
    before_fin_sent = stream->fin_sent;
    before_fin_in_flight = stream->fin_in_flight;
    before_send_open = stream->send_open;

    client.conn.recovery.bytes_in_flight = client.conn.recovery.congestion_window;
    packet.len = sizeof(packet.bytes);
    status = quic_tls_conn_build_next_datagram(&client, packet.bytes, sizeof(packet.bytes), &packet.len);
    assert(status == QUIC_TLS_BUILD_BLOCKED);
    assert(packet.len == 0);
    assert(quic_tls_conn_has_pending_output(&client) == 1);

    stream = quic_stream_map_find_const(&client.streams, stream_id);
    assert(stream);
    assert(stream->sendbuf.send_offset == before_send_offset);
    assert(stream->sendbuf.flight_end == before_flight_end);
    assert(stream->send_highest_offset == before_send_highest);
    assert(client.streams.send_connection_highest == before_conn_highest);
    assert(stream->fin_sent == before_fin_sent);
    assert(stream->fin_in_flight == before_fin_in_flight);
    assert(stream->send_open == before_send_open);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 4 blocked packet builds do not consume STREAM send state before a packet is actually sent\n");
}

static void test_stage4_clean_bulk_transfer_grows_cwnd(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    uint64_t stream_id = UINT64_MAX;
    uint8_t *payload;
    uint8_t *received;
    size_t payload_len = 128 * 1024;
    size_t received_len = 0;
    int received_fin = 0;
    size_t rounds = 0;
    uint64_t initial_cwnd;

    payload = (uint8_t *)malloc(payload_len);
    received = (uint8_t *)malloc(payload_len);
    assert(payload && received);
    fill_pattern(payload, payload_len, 0x44);
    memset(received, 0, payload_len);

    configure_pair(&client, &server, 512 * 1024, 512 * 1024);
    initial_cwnd = client.conn.recovery.congestion_window;
    assert(quic_tls_conn_open_stream(&client, 1, &stream_id) == 0);
    assert(stream_id == 0);
    assert(quic_tls_conn_stream_write(&client, stream_id, payload, payload_len, 1) == 0);

    while ((!received_fin || received_len != payload_len) && rounds++ < 20000) {
        int progressed = 0;
        captured_packet_t packet;

        while (capture_one(&client, &packet)) {
            assert(quic_tls_conn_handle_datagram(&server, packet.bytes, packet.len) == 0);
            progressed = 1;
        }
        progressed |= drain_stream(&server, stream_id, received, payload_len, &received_len, &received_fin, 4096);
        while (capture_one(&server, &packet)) {
            assert(quic_tls_conn_handle_datagram(&client, packet.bytes, packet.len) == 0);
            progressed = 1;
        }
        if (!progressed) {
            progressed = drive_timers(&client, &server, NULL);
        }
        if (!progressed) {
            fprintf(stderr,
                    "clean bulk stalled: round=%lu recv=%lu fin=%d client_pending=%d server_pending=%d client_bif=%lu server_bif=%lu\n",
                    (unsigned long)rounds,
                    (unsigned long)received_len,
                    received_fin,
                    quic_tls_conn_has_pending_output(&client),
                    quic_tls_conn_has_pending_output(&server),
                    (unsigned long)client.conn.recovery.bytes_in_flight,
                    (unsigned long)server.conn.recovery.bytes_in_flight);
        }
        assert(progressed);
    }

    assert(received_fin);
    assert(received_len == payload_len);
    assert(memcmp(payload, received, payload_len) == 0);
    assert(client.conn.recovery.congestion_window > initial_cwnd);

    free(payload);
    free(received);
    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 4 clean bulk transfer grows the congestion window beyond its initial value\n");
}

static void test_stage4_lossy_bulk_transfer_recovers(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    uint64_t stream_id = UINT64_MAX;
    uint8_t *payload;
    uint8_t *received;
    size_t payload_len = 96 * 1024;
    size_t received_len = 0;
    int received_fin = 0;
    size_t rounds = 0;
    size_t timeout_count = 0;
    size_t dropped_client_packets = 0;

    payload = (uint8_t *)malloc(payload_len);
    received = (uint8_t *)malloc(payload_len);
    assert(payload && received);
    fill_pattern(payload, payload_len, 0x67);
    memset(received, 0, payload_len);

    configure_pair(&client, &server, 512 * 1024, 512 * 1024);
    assert(quic_tls_conn_open_stream(&client, 1, &stream_id) == 0);
    assert(quic_tls_conn_stream_write(&client, stream_id, payload, payload_len, 1) == 0);

    while ((!received_fin || received_len != payload_len) && rounds++ < 30000) {
        int progressed = 0;
        captured_packet_t packet;

        while (capture_one(&client, &packet)) {
            if (!should_drop_short_header(&packet, 5, &dropped_client_packets)) {
                assert(quic_tls_conn_handle_datagram(&server, packet.bytes, packet.len) == 0);
            }
            progressed = 1;
        }
        progressed |= drain_stream(&server, stream_id, received, payload_len, &received_len, &received_fin, 4096);
        while (capture_one(&server, &packet)) {
            assert(quic_tls_conn_handle_datagram(&client, packet.bytes, packet.len) == 0);
            progressed = 1;
        }
        if (!progressed) {
            progressed = drive_timers(&client, &server, &timeout_count);
        }
        assert(progressed);
    }

    assert(received_fin);
    assert(received_len == payload_len);
    assert(memcmp(payload, received, payload_len) == 0);
    assert(dropped_client_packets > 0);

    free(payload);
    free(received);
    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 4 lossy bulk transfer recovers after loss detection and still completes\n");
}

static void test_stage4_small_flow_control_window_is_observable(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    uint64_t stream_id = UINT64_MAX;
    uint8_t *payload;
    uint8_t *received;
    size_t payload_len = 16 * 1024;
    size_t received_len = 0;
    int received_fin = 0;
    int saw_flow_limited = 0;
    size_t rounds = 0;

    payload = (uint8_t *)malloc(payload_len);
    received = (uint8_t *)malloc(payload_len);
    assert(payload && received);
    fill_pattern(payload, payload_len, 0x29);
    memset(received, 0, payload_len);

    configure_pair(&client, &server, 4096, 2048);
    assert(quic_tls_conn_open_stream(&client, 1, &stream_id) == 0);
    assert(quic_tls_conn_stream_write(&client, stream_id, payload, payload_len, 1) == 0);

    while ((!received_fin || received_len != payload_len) && rounds++ < 30000) {
        int progressed = 0;
        captured_packet_t packet;

        while (capture_one(&client, &packet)) {
            assert(quic_tls_conn_handle_datagram(&server, packet.bytes, packet.len) == 0);
            progressed = 1;
        }
        if (quic_stream_map_is_flow_control_limited(&client.streams)) {
            saw_flow_limited = 1;
        }
        progressed |= drain_stream(&server, stream_id, received, payload_len, &received_len, &received_fin, 256);
        while (capture_one(&server, &packet)) {
            assert(quic_tls_conn_handle_datagram(&client, packet.bytes, packet.len) == 0);
            progressed = 1;
        }
        if (!progressed) {
            progressed = drive_timers(&client, &server, NULL);
        }
        assert(progressed);
    }

    assert(received_fin);
    assert(received_len == payload_len);
    assert(memcmp(payload, received, payload_len) == 0);
    assert(saw_flow_limited);

    free(payload);
    free(received);
    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 4 small receive windows make the sender enter a flow-control-limited state before completion\n");
}

int main(void) {
    const char *selected = getenv("QUIC_STAGE4_CASE");

    if (!selected || strcmp(selected, "blocked") == 0 || strcmp(selected, "all") == 0) {
        test_stage4_build_blocked_does_not_consume_send_state();
    }
    if (!selected || strcmp(selected, "clean") == 0 || strcmp(selected, "all") == 0) {
        test_stage4_clean_bulk_transfer_grows_cwnd();
    }
    if (!selected || strcmp(selected, "lossy") == 0 || strcmp(selected, "all") == 0) {
        test_stage4_lossy_bulk_transfer_recovers();
    }
    if (!selected || strcmp(selected, "flow") == 0 || strcmp(selected, "all") == 0) {
        test_stage4_small_flow_control_window_is_observable();
    }
    printf("Phase 17 tests passed.\n");
    return 0;
}
