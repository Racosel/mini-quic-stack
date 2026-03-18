#include "quic_tls.h"
#include "quic_version.h"
#include <assert.h>
#include <stdio.h>
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
            fprintf(stderr, "handle_datagram failed: %s\n", quic_tls_conn_last_error(dst));
            assert(0);
        }
        moved = 1;
    }

    return moved;
}

static int capture_one(quic_tls_conn_t *src, captured_packet_t *packet) {
    if (!src || !packet || !quic_tls_conn_has_pending_output(src)) {
        return 0;
    }
    if (quic_tls_conn_build_next_datagram(src, packet->bytes, sizeof(packet->bytes), &packet->len) != 0) {
        fprintf(stderr, "build_next_datagram failed: %s\n", quic_tls_conn_last_error(src));
        assert(0);
    }
    return 1;
}

static void run_for_progress(quic_tls_conn_t *client,
                             quic_tls_conn_t *server,
                             int (*done)(const quic_tls_conn_t *, const quic_tls_conn_t *)) {
    size_t round = 0;

    while (!done(client, server) && round++ < 512) {
        int progressed = 0;
        uint64_t deadline;

        progressed |= flush_pending(client, server);
        progressed |= flush_pending(server, client);
        if (done(client, server)) {
            break;
        }
        if (!progressed) {
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

static int handshake_done(const quic_tls_conn_t *client, const quic_tls_conn_t *server) {
    return quic_tls_conn_handshake_complete(client) && quic_tls_conn_handshake_complete(server);
}

static void configure_pair(quic_tls_conn_t *client,
                           quic_tls_conn_t *server,
                           uint64_t max_data,
                           uint64_t max_stream_data,
                           uint64_t max_streams_bidi) {
    quic_cid_t client_scid = make_cid(0x10);
    quic_cid_t client_odcid = make_cid(0xa0);
    quic_cid_t server_scid = make_cid(0xb0);

    quic_tls_conn_init(client);
    quic_tls_conn_init(server);
    quic_tls_conn_set_initial_flow_control(client, max_data, max_stream_data, max_stream_data, max_stream_data, max_streams_bidi, 1);
    quic_tls_conn_set_initial_flow_control(server, max_data, max_stream_data, max_stream_data, max_stream_data, max_streams_bidi, 1);

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
    run_for_progress(client, server, handshake_done);
}

static int drain_stream(quic_tls_conn_t *conn,
                        uint64_t stream_id,
                        uint8_t *storage,
                        size_t storage_cap,
                        size_t *used,
                        int *fin) {
    size_t available = 0;
    size_t out_read = 0;
    int exists = 0;
    uint8_t scratch[16];
    int progressed = 0;

    assert(quic_tls_conn_stream_peek(conn, stream_id, &available, fin, &exists) == 0);
    if (!exists || (available == 0 && !*fin)) {
        return 0;
    }
    assert(quic_tls_conn_stream_read(conn, stream_id, scratch, sizeof(scratch), &out_read, fin) == 0);
    assert(*used + out_read <= storage_cap);
    if (out_read > 0) {
        memcpy(storage + *used, scratch, out_read);
        *used += out_read;
        progressed = 1;
    }
    if (*fin) {
        progressed = 1;
    }
    return progressed;
}

static void test_stage3_multistream_flow_control(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    uint64_t stream0;
    uint64_t stream4;
    static const uint8_t msg0[] = "abcdefghijklmnopqrstuvwxyz0123456789-stream-zero";
    static const uint8_t msg1[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9876543210-stream-four";
    uint8_t recv0[128];
    uint8_t recv1[128];
    size_t recv0_len = 0;
    size_t recv1_len = 0;
    int recv0_fin = 0;
    int recv1_fin = 0;
    size_t round = 0;

    memset(recv0, 0, sizeof(recv0));
    memset(recv1, 0, sizeof(recv1));
    configure_pair(&client, &server, 64, 32, 4);

    assert(quic_tls_conn_open_stream(&client, 1, &stream0) == 0);
    assert(stream0 == 0);
    assert(quic_tls_conn_open_stream(&client, 1, &stream4) == 0);
    assert(stream4 == 4);
    assert(quic_tls_conn_stream_write(&client, stream0, msg0, sizeof(msg0) - 1, 1) == 0);
    assert(quic_tls_conn_stream_write(&client, stream4, msg1, sizeof(msg1) - 1, 1) == 0);

    while ((!recv0_fin || recv0_len != sizeof(msg0) - 1 || !recv1_fin || recv1_len != sizeof(msg1) - 1) &&
           round++ < 512) {
        int progressed = 0;
        uint64_t deadline;

        progressed |= flush_pending(&client, &server);
        progressed |= drain_stream(&server, stream0, recv0, sizeof(recv0), &recv0_len, &recv0_fin);
        progressed |= drain_stream(&server, stream4, recv1, sizeof(recv1), &recv1_len, &recv1_fin);
        progressed |= flush_pending(&server, &client);

        if (!progressed) {
            deadline = quic_tls_conn_loss_deadline_ms(&client);
            if (deadline != 0) {
                quic_tls_conn_on_loss_timeout(&client, deadline);
                progressed = 1;
            }
            deadline = quic_tls_conn_loss_deadline_ms(&server);
            if (deadline != 0) {
                quic_tls_conn_on_loss_timeout(&server, deadline);
                progressed = 1;
            }
        }

        assert(progressed);
    }

    assert(recv0_fin && recv1_fin);
    assert(recv0_len == sizeof(msg0) - 1);
    assert(recv1_len == sizeof(msg1) - 1);
    assert(memcmp(recv0, msg0, sizeof(msg0) - 1) == 0);
    assert(memcmp(recv1, msg1, sizeof(msg1) - 1) == 0);
    assert(client.streams.send_connection_max_data > 64);
    assert(quic_stream_map_find_const(&client.streams, stream0)->send_max_data > 32);
    assert(quic_stream_map_find_const(&client.streams, stream4)->send_max_data > 32);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 3 multi-stream transfer advances MAX_DATA and MAX_STREAM_DATA credits\n");
}

static void test_stage3_packet_meta_keeps_control_stream_identity(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    uint64_t stream0;
    uint64_t stream4;
    static const uint8_t msg0[] =
        "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static const uint8_t msg4[] = "small-control-trigger";
    static const uint8_t response4[] = "server-stream-4 response payload";
    uint8_t recv0[128];
    uint8_t recv4[64];
    size_t recv0_len = 0;
    size_t recv4_len = 0;
    int recv0_fin = 0;
    int recv4_fin = 0;
    captured_packet_t packet;
    const quic_sent_packet_t *tail;

    memset(recv0, 0, sizeof(recv0));
    memset(recv4, 0, sizeof(recv4));
    configure_pair(&client, &server, 256, 64, 4);

    assert(quic_tls_conn_open_stream(&client, 1, &stream0) == 0);
    assert(quic_tls_conn_open_stream(&client, 1, &stream4) == 0);
    assert(stream0 == 0);
    assert(stream4 == 4);
    assert(quic_tls_conn_stream_write(&client, stream0, msg0, sizeof(msg0) - 1, 1) == 0);
    assert(quic_tls_conn_stream_write(&client, stream4, msg4, sizeof(msg4) - 1, 1) == 0);

    while (flush_pending(&client, &server)) {
    }

    while (recv0_len < 32) {
        assert(drain_stream(&server, stream0, recv0, sizeof(recv0), &recv0_len, &recv0_fin) == 1);
    }
    while (!recv4_fin) {
        assert(drain_stream(&server, stream4, recv4, sizeof(recv4), &recv4_len, &recv4_fin) == 1);
    }
    assert(quic_tls_conn_stream_write(&server, stream4, response4, sizeof(response4) - 1, 1) == 0);

    assert(capture_one(&server, &packet) == 1);
    tail = server.conn.spaces[QUIC_PN_SPACE_APPLICATION].in_flight.tail;
    assert(tail != NULL);
    assert(tail->meta.includes_max_stream_data == 1);
    assert(tail->meta.includes_stream == 1);
    assert(tail->meta.control_stream_id == stream0);
    assert(tail->meta.stream_id == stream4);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 3 packet metadata preserves per-stream control-frame identity when MAX_STREAM_DATA and STREAM share a packet\n");
}

static void test_stage3_stop_sending_prompts_reset(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    uint64_t stream_id;
    static const uint8_t payload[] = "stage3-stop-sending-reset";
    size_t round = 0;

    configure_pair(&client, &server, 128, 64, 4);

    assert(quic_tls_conn_open_stream(&client, 1, &stream_id) == 0);
    assert(quic_tls_conn_stream_write(&client, stream_id, payload, sizeof(payload) - 1, 0) == 0);

    while (quic_stream_map_find_const(&server.streams, stream_id) == NULL && round++ < 64) {
        assert(flush_pending(&client, &server) == 1);
    }
    assert(quic_stream_map_find_const(&server.streams, stream_id) != NULL);

    assert(quic_tls_conn_stop_sending(&server, stream_id, 0x33) == 0);

    round = 0;
    while ((!quic_stream_map_find_const(&server.streams, stream_id)->reset_received) && round++ < 128) {
        int progressed = 0;
        uint64_t deadline;

        progressed |= flush_pending(&server, &client);
        progressed |= flush_pending(&client, &server);
        if (!progressed) {
            deadline = quic_tls_conn_loss_deadline_ms(&client);
            if (deadline != 0) {
                quic_tls_conn_on_loss_timeout(&client, deadline);
                progressed = 1;
            }
            deadline = quic_tls_conn_loss_deadline_ms(&server);
            if (deadline != 0) {
                quic_tls_conn_on_loss_timeout(&server, deadline);
                progressed = 1;
            }
        }
        assert(progressed);
    }

    assert(quic_stream_map_find_const(&server.streams, stream_id)->reset_received);
    assert(quic_stream_map_find_const(&server.streams, stream_id)->reset_error_code == 0x33);
    assert(quic_stream_map_find_const(&client.streams, stream_id)->send_open == 0);
    assert(quic_stream_map_find_const(&client.streams, stream_id)->reset_error_code == 0x33);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 3 STOP_SENDING prompts peer RESET_STREAM\n");
}

static void test_stage3_connection_close_round_trip(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    size_t round = 0;

    configure_pair(&client, &server, 128, 64, 4);

    assert(quic_tls_conn_close(&client, QUIC_TRANSPORT_ERROR_NO_ERROR) == 0);
    assert(client.conn.state == QUIC_CONN_STATE_CLOSING);
    assert(quic_tls_conn_has_pending_output(&client));

    while (!((server.conn.state == QUIC_CONN_STATE_DRAINING || server.conn.state == QUIC_CONN_STATE_CLOSED) &&
             (client.conn.state == QUIC_CONN_STATE_DRAINING || client.conn.state == QUIC_CONN_STATE_CLOSED)) &&
           round++ < 64) {
        int progressed = 0;
        uint64_t deadline;

        progressed |= flush_pending(&client, &server);
        progressed |= flush_pending(&server, &client);
        if (!progressed) {
            deadline = quic_tls_conn_loss_deadline_ms(&client);
            if (deadline != 0) {
                quic_tls_conn_on_loss_timeout(&client, deadline);
                progressed = 1;
            }
            deadline = quic_tls_conn_loss_deadline_ms(&server);
            if (deadline != 0) {
                quic_tls_conn_on_loss_timeout(&server, deadline);
                progressed = 1;
            }
        }
        assert(progressed);
    }

    assert(client.close_received);
    assert(server.close_received);
    assert(server.conn.state == QUIC_CONN_STATE_DRAINING || server.conn.state == QUIC_CONN_STATE_CLOSED);
    assert(client.conn.state == QUIC_CONN_STATE_DRAINING || client.conn.state == QUIC_CONN_STATE_CLOSED);
    assert(!quic_tls_conn_has_pending_output(&client));
    assert(!quic_tls_conn_has_pending_output(&server));

    if (quic_tls_conn_loss_deadline_ms(&client) != 0) {
        quic_tls_conn_on_loss_timeout(&client, quic_tls_conn_loss_deadline_ms(&client));
    }
    if (quic_tls_conn_loss_deadline_ms(&server) != 0) {
        quic_tls_conn_on_loss_timeout(&server, quic_tls_conn_loss_deadline_ms(&server));
    }
    assert(client.conn.state == QUIC_CONN_STATE_CLOSED);
    assert(server.conn.state == QUIC_CONN_STATE_CLOSED);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 3 CONNECTION_CLOSE transitions both peers to draining then closed\n");
}

static void test_stage3_terminal_receive_discards_retransmitted_stream(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    captured_packet_t packet;
    uint64_t stream_id;
    uint8_t received[64];
    size_t received_len = 0;
    size_t round = 0;
    int received_fin = 0;
    static const uint8_t payload[] = "retransmitted-stream-after-finish";

    memset(received, 0, sizeof(received));
    configure_pair(&client, &server, 1024, 1024, 4);
    drain_all_pending(&client, &server);

    assert(quic_tls_conn_open_stream(&client, 1, &stream_id) == 0);
    assert(quic_tls_conn_stream_write(&client, stream_id, payload, sizeof(payload) - 1, 1) == 0);
    assert(capture_one(&client, &packet) == 1);
    assert(quic_tls_conn_handle_datagram(&server, packet.bytes, packet.len) == 0);
    while (!received_fin && round++ < 16) {
        assert(drain_stream(&server, stream_id, received, sizeof(received), &received_len, &received_fin) == 1);
    }
    assert(received_fin);
    assert(received_len == sizeof(payload) - 1);
    assert(memcmp(received, payload, sizeof(payload) - 1) == 0);

    assert(quic_tls_conn_handle_datagram(&server, packet.bytes, packet.len) == 0);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 3 terminal receive state discards retransmitted STREAM frames\n");
}

static void test_stage3_ack_ranges_preserve_stream_gap(void) {
    quic_tls_conn_t client;
    quic_tls_conn_t server;
    captured_packet_t packets[8];
    captured_packet_t ack_packet;
    uint8_t payload[1800];
    uint8_t received[2048];
    uint64_t stream_id;
    size_t received_len = 0;
    size_t round = 0;
    size_t packet_count = 0;
    int received_fin = 0;
    uint64_t deadline;
    size_t i;
    uint64_t inflight_before_ack;

    memset(payload, 0, sizeof(payload));
    memset(received, 0, sizeof(received));
    for (i = 0; i < sizeof(payload); i++) {
        payload[i] = (uint8_t)('a' + (i % 26));
    }

    configure_pair(&client, &server, 4096, 4096, 4);
    drain_all_pending(&client, &server);

    assert(quic_tls_conn_open_stream(&client, 1, &stream_id) == 0);
    assert(quic_tls_conn_stream_write(&client, stream_id, payload, sizeof(payload), 1) == 0);

    while (packet_count < (sizeof(packets) / sizeof(packets[0])) && capture_one(&client, &packets[packet_count]) == 1) {
        packet_count++;
    }
    assert(packet_count >= 2);
    inflight_before_ack = client.conn.spaces[QUIC_PN_SPACE_APPLICATION].in_flight.bytes_in_flight;
    assert(inflight_before_ack > 0);

    assert(quic_tls_conn_handle_datagram(&server, packets[packet_count - 1].bytes, packets[packet_count - 1].len) == 0);
    assert(server.levels[ssl_encryption_application].ack_pending == 1);

    assert(capture_one(&server, &ack_packet) == 1);
    assert(quic_tls_conn_handle_datagram(&client, ack_packet.bytes, ack_packet.len) == 0);
    assert(client.conn.spaces[QUIC_PN_SPACE_APPLICATION].in_flight.bytes_in_flight > 0);
    assert(client.conn.spaces[QUIC_PN_SPACE_APPLICATION].in_flight.bytes_in_flight < inflight_before_ack);

    deadline = quic_tls_conn_loss_deadline_ms(&client);
    assert(deadline != 0);
    quic_tls_conn_on_loss_timeout(&client, deadline);

    while ((!received_fin || received_len != sizeof(payload)) && round++ < 256) {
        int progressed = 0;
        uint64_t timer_deadline;

        progressed |= flush_pending(&client, &server);
        progressed |= drain_stream(&server, stream_id, received, sizeof(received), &received_len, &received_fin);
        progressed |= flush_pending(&server, &client);
        if (!progressed) {
            timer_deadline = quic_tls_conn_loss_deadline_ms(&client);
            if (timer_deadline != 0) {
                quic_tls_conn_on_loss_timeout(&client, timer_deadline);
                progressed = 1;
            }
            timer_deadline = quic_tls_conn_loss_deadline_ms(&server);
            if (timer_deadline != 0) {
                quic_tls_conn_on_loss_timeout(&server, timer_deadline);
                progressed = 1;
            }
        }
        assert(progressed);
    }

    if (!received_fin || received_len != sizeof(payload)) {
        const quic_stream_t *stream = quic_stream_map_find_const(&server.streams, stream_id);

        fprintf(stderr,
                "stage3 gap test incomplete: packet_count=%zu received_len=%zu received_fin=%d recv_highest=%lu recv_final_known=%u recv_final=%lu recv_consumed=%lu\n",
                packet_count,
                received_len,
                received_fin,
                stream ? (unsigned long)stream->recv_highest_offset : 0UL,
                stream ? (unsigned int)stream->recv_final_size_known : 0U,
                stream ? (unsigned long)stream->recv_final_size : 0UL,
                stream ? (unsigned long)stream->recv_consumed_offset : 0UL);
    }
    assert(received_fin);
    assert(received_len == sizeof(payload));
    assert(memcmp(received, payload, sizeof(payload)) == 0);

    quic_tls_conn_free(&client);
    quic_tls_conn_free(&server);
    printf("[PASS] Stage 3 ACK ranges preserve stream gaps and allow retransmission\n");
}

int main(void) {
    test_stage3_multistream_flow_control();
    test_stage3_packet_meta_keeps_control_stream_identity();
    test_stage3_stop_sending_prompts_reset();
    test_stage3_connection_close_round_trip();
    test_stage3_terminal_receive_discards_retransmitted_stream();
    test_stage3_ack_ranges_preserve_stream_gap();
    printf("Phase 14 tests passed.\n");
    return 0;
}
