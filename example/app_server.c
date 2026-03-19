#include "quic_api.h"
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PORT 4434
#define DEFAULT_CERT "tests/certs/server_cert.pem"
#define DEFAULT_KEY  "tests/certs/server_key.pem"

static uint64_t now_ms(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
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

static void sockaddr_in_to_quic_addr(const struct sockaddr_in *src, quic_socket_addr_t *dst) {
    uint32_t ip;

    if (!src || !dst) {
        return;
    }
    ip = ntohl(src->sin_addr.s_addr);
    quic_socket_addr_init_ipv4(dst,
                               (uint8_t)((ip >> 24) & 0xff),
                               (uint8_t)((ip >> 16) & 0xff),
                               (uint8_t)((ip >> 8) & 0xff),
                               (uint8_t)(ip & 0xff),
                               ntohs(src->sin_port));
}

static void quic_addr_to_sockaddr_in(const quic_socket_addr_t *src, struct sockaddr_in *dst) {
    uint32_t ip;

    if (!src || !dst) {
        return;
    }
    memset(dst, 0, sizeof(*dst));
    dst->sin_family = AF_INET;
    dst->sin_port = htons(src->port);
    ip = ((uint32_t)src->addr[0] << 24) |
         ((uint32_t)src->addr[1] << 16) |
         ((uint32_t)src->addr[2] << 8) |
         (uint32_t)src->addr[3];
    dst->sin_addr.s_addr = htonl(ip);
}

static void make_recv_path(const struct sockaddr_in *local_addr,
                           const struct sockaddr_in *peer_addr,
                           quic_path_addr_t *path) {
    quic_socket_addr_t local;
    quic_socket_addr_t peer;

    if (!local_addr || !peer_addr || !path) {
        return;
    }
    sockaddr_in_to_quic_addr(local_addr, &local);
    sockaddr_in_to_quic_addr(peer_addr, &peer);
    quic_path_addr_init(path, &local, &peer);
}

static void drain_events(quic_api_conn_t *conn, FILE *qlog) {
    quic_api_event_t event;
    char json[256];

    if (!conn || !qlog) {
        return;
    }
    while (quic_api_conn_poll_event(conn, &event) == 0) {
        if (quic_api_event_format_json(&event, json, sizeof(json)) == 0) {
            fprintf(qlog, "%s\n", json);
        }
    }
    fflush(qlog);
}

static int send_pending_packets(int fd, quic_api_conn_t *conn) {
    while (quic_api_conn_has_pending_output(conn)) {
        uint8_t packet[QUIC_TLS_MAX_DATAGRAM_SIZE];
        size_t packet_len = 0;
        quic_path_addr_t send_path;
        struct sockaddr_in peer_addr;
        int build_status;

        build_status = quic_api_conn_build_next_datagram_on_path(conn,
                                                                 packet,
                                                                 sizeof(packet),
                                                                 &packet_len,
                                                                 &send_path);
        if (build_status == QUIC_TLS_BUILD_BLOCKED) {
            break;
        }
        if (build_status != 0) {
            fprintf(stderr, "app server build packet failed: %s\n", quic_api_conn_last_error(conn));
            return -1;
        }
        quic_addr_to_sockaddr_in(&send_path.peer, &peer_addr);
        if (sendto(fd,
                   packet,
                   packet_len,
                   0,
                   (const struct sockaddr *)&peer_addr,
                   sizeof(peer_addr)) < 0) {
            perror("app server sendto");
            return -1;
        }
    }

    return 0;
}

static int drain_stream(quic_api_conn_t *conn,
                        uint64_t stream_id,
                        uint8_t *storage,
                        size_t storage_cap,
                        size_t *used,
                        int *fin) {
    int progressed = 0;

    for (;;) {
        size_t available = 0;
        size_t out_read = 0;
        int exists = 0;
        int local_fin = 0;
        uint8_t scratch[512];
        size_t chunk = sizeof(scratch);

        if (quic_api_conn_stream_peek(conn, stream_id, &available, &local_fin, &exists) != 0) {
            return -1;
        }
        if (!exists || (available == 0 && !local_fin)) {
            break;
        }
        if (available > 0 && available < chunk) {
            chunk = available;
        }
        if (quic_api_conn_stream_read(conn, stream_id, scratch, chunk, &out_read, &local_fin) != 0) {
            return -1;
        }
        if (*used + out_read > storage_cap) {
            return -1;
        }
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

static void dump_conn_state(const quic_api_conn_t *conn) {
    quic_api_conn_info_t info;
    quic_api_path_info_t path;
    size_t i;

    if (quic_api_conn_get_info(conn, &info) != 0) {
        return;
    }
    fprintf(stderr,
            "app-server-timeout state=%d handshake=%u active_path=%zu pending_path=%zu has_output=%d\n",
            (int)info.state,
            info.handshake_complete,
            info.active_path_index,
            info.pending_path_index,
            info.has_pending_output);
    for (i = 0; i < info.path_count; i++) {
        if (quic_api_conn_get_path_info(conn, i, &path) != 0) {
            continue;
        }
        fprintf(stderr,
                "  path[%zu] state=%u local_port=%u peer_port=%u challenge_in_flight=%u response_pending=%u\n",
                i,
                path.state,
                path.local.port,
                path.peer.port,
                path.challenge_in_flight,
                path.response_pending);
    }
}

int main(int argc, char **argv) {
    const char *bind_ip = "127.0.0.1";
    const char *cert_file = DEFAULT_CERT;
    const char *key_file = DEFAULT_KEY;
    const char *qlog_path = NULL;
    int port = DEFAULT_PORT;
    int fd = -1;
    struct sockaddr_in local_addr;
    struct sockaddr_in peer_addr;
    struct sockaddr_in recv_local_addr;
    socklen_t peer_len = sizeof(peer_addr);
    quic_path_addr_t recv_path;
    quic_api_conn_t conn;
    quic_cid_t local_cid = make_cid(0xc0);
    static const uint8_t expected0[] = "app-demo-request-0";
    static const uint8_t expected4[] = "app-demo-request-4";
    static const uint8_t response0[] = "app-demo-response-0";
    static const uint8_t response4[] = "app-demo-response-4";
    uint8_t request0[128];
    uint8_t request4[128];
    size_t request0_len = 0;
    size_t request4_len = 0;
    int request0_fin = 0;
    int request4_fin = 0;
    int responded0 = 0;
    int responded4 = 0;
    uint64_t deadline = now_ms() + 15000;
    uint8_t buffer[QUIC_TLS_MAX_DATAGRAM_SIZE];
    ssize_t recv_len;
    FILE *qlog = NULL;
    quic_api_metrics_t metrics;

    if (argc > 1) {
        bind_ip = argv[1];
    }
    if (argc > 2) {
        port = atoi(argv[2]);
    }
    if (argc > 3) {
        cert_file = argv[3];
    }
    if (argc > 4) {
        key_file = argv[4];
    }
    if (argc > 5) {
        qlog_path = argv[5];
    }

    quic_api_conn_init(&conn);
    quic_api_conn_set_initial_flow_control(&conn, 128 * 1024, 64 * 1024, 64 * 1024, 64 * 1024, 8, 8);
    if (quic_api_conn_configure(&conn,
                                QUIC_ROLE_SERVER,
                                QUIC_V1_VERSION,
                                &local_cid,
                                NULL,
                                cert_file,
                                key_file) != 0) {
        fprintf(stderr, "app server configure failed: %s\n", quic_api_conn_last_error(&conn));
        quic_api_conn_free(&conn);
        return 1;
    }

    if (qlog_path) {
        qlog = fopen(qlog_path, "w");
        if (!qlog) {
            perror("app server fopen qlog");
            quic_api_conn_free(&conn);
            return 1;
        }
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("app server socket");
        if (qlog) fclose(qlog);
        quic_api_conn_free(&conn);
        return 1;
    }

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, bind_ip, &local_addr.sin_addr) != 1) {
        fprintf(stderr, "app server invalid bind ip: %s\n", bind_ip);
        close(fd);
        if (qlog) fclose(qlog);
        quic_api_conn_free(&conn);
        return 1;
    }
    if (bind(fd, (struct sockaddr *)&local_addr, sizeof(local_addr)) != 0) {
        perror("app server bind");
        close(fd);
        if (qlog) fclose(qlog);
        quic_api_conn_free(&conn);
        return 1;
    }

    printf("app server listening on %s:%d\n", bind_ip, port);
    fflush(stdout);
    drain_events(&conn, qlog);

    while (now_ms() < deadline) {
        struct pollfd pfd;
        int timeout_ms = 50;
        uint64_t next_deadline = quic_api_conn_next_timeout_ms(&conn);
        uint64_t now = now_ms();
        quic_api_conn_info_t info;

        if (responded0 &&
            responded4 &&
            quic_api_conn_get_info(&conn, &info) == 0 &&
            (info.state == QUIC_CONN_STATE_DRAINING || info.state == QUIC_CONN_STATE_CLOSED)) {
            if (quic_api_conn_get_metrics(&conn, &metrics) == 0) {
                printf("app server complete: responses=2 bytes_sent=%llu bytes_received=%llu cwnd=%llu rtt=%llu\n",
                       (unsigned long long)metrics.bytes_sent,
                       (unsigned long long)metrics.bytes_received,
                       (unsigned long long)metrics.congestion_window,
                       (unsigned long long)metrics.smoothed_rtt_ms);
            } else {
                printf("app server complete: responses=2\n");
            }
            close(fd);
            if (qlog) fclose(qlog);
            quic_api_conn_free(&conn);
            return 0;
        }

        if (quic_api_conn_has_pending_output(&conn)) {
            if (send_pending_packets(fd, &conn) != 0) {
                close(fd);
                if (qlog) fclose(qlog);
                quic_api_conn_free(&conn);
                return 1;
            }
            drain_events(&conn, qlog);
        }

        if (next_deadline != 0 && next_deadline <= now) {
            quic_api_conn_on_timeout(&conn, next_deadline);
            drain_events(&conn, qlog);
            continue;
        }
        if (next_deadline != 0 && next_deadline > now) {
            uint64_t remaining = next_deadline - now;
            if (remaining < (uint64_t)timeout_ms) {
                timeout_ms = (int)remaining;
            }
        }

        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, timeout_ms) < 0) {
            perror("app server poll");
            close(fd);
            if (qlog) fclose(qlog);
            quic_api_conn_free(&conn);
            return 1;
        }

        if ((pfd.revents & POLLIN) != 0) {
            recv_local_addr = local_addr;
            peer_len = sizeof(peer_addr);
            recv_len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&peer_addr, &peer_len);
            if (recv_len < 0) {
                if (errno == EINTR) {
                    continue;
                }
                perror("app server recvfrom");
                close(fd);
                if (qlog) fclose(qlog);
                quic_api_conn_free(&conn);
                return 1;
            }

            make_recv_path(&recv_local_addr, &peer_addr, &recv_path);
            if (quic_api_conn_handle_datagram_on_path(&conn, buffer, (size_t)recv_len, &recv_path) != 0) {
                fprintf(stderr, "app server handle datagram failed: %s\n", quic_api_conn_last_error(&conn));
                close(fd);
                if (qlog) fclose(qlog);
                quic_api_conn_free(&conn);
                return 1;
            }
            drain_events(&conn, qlog);

            if (drain_stream(&conn, 0, request0, sizeof(request0), &request0_len, &request0_fin) < 0 ||
                drain_stream(&conn, 4, request4, sizeof(request4), &request4_len, &request4_fin) < 0) {
                fprintf(stderr, "app server stream read failed: %s\n", quic_api_conn_last_error(&conn));
                close(fd);
                if (qlog) fclose(qlog);
                quic_api_conn_free(&conn);
                return 1;
            }

            if (request0_fin && !responded0) {
                if (request0_len != sizeof(expected0) - 1 ||
                    memcmp(request0, expected0, request0_len) != 0 ||
                    quic_api_conn_stream_write(&conn, 0, response0, sizeof(response0) - 1, 1) != 0) {
                    fprintf(stderr, "app server stream 0 handling failed: %s\n", quic_api_conn_last_error(&conn));
                    close(fd);
                    if (qlog) fclose(qlog);
                    quic_api_conn_free(&conn);
                    return 1;
                }
                responded0 = 1;
                drain_events(&conn, qlog);
            }
            if (request4_fin && !responded4) {
                if (request4_len != sizeof(expected4) - 1 ||
                    memcmp(request4, expected4, request4_len) != 0 ||
                    quic_api_conn_stream_write(&conn, 4, response4, sizeof(response4) - 1, 1) != 0) {
                    fprintf(stderr, "app server stream 4 handling failed: %s\n", quic_api_conn_last_error(&conn));
                    close(fd);
                    if (qlog) fclose(qlog);
                    quic_api_conn_free(&conn);
                    return 1;
                }
                responded4 = 1;
                drain_events(&conn, qlog);
            }
        }
    }

    fprintf(stderr, "app server timeout waiting for app demo\n");
    dump_conn_state(&conn);
    close(fd);
    if (qlog) fclose(qlog);
    quic_api_conn_free(&conn);
    return 1;
}
