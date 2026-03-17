#include "quic_tls.h"
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_SERVER_IP "10.0.0.2"
#define DEFAULT_PORT 4434

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

static int send_pending_packets(int fd, quic_tls_conn_t *conn) {
    while (quic_tls_conn_has_pending_output(conn)) {
        uint8_t packet[QUIC_TLS_MAX_DATAGRAM_SIZE];
        size_t packet_len = 0;

        if (quic_tls_conn_build_next_datagram(conn, packet, sizeof(packet), &packet_len) != 0) {
            fprintf(stderr, "client build packet failed: %s\n", quic_tls_conn_last_error(conn));
            return -1;
        }
        if (send(fd, packet, packet_len, 0) < 0) {
            perror("client send");
            return -1;
        }
    }

    return 0;
}

int main(int argc, char **argv) {
    const char *server_ip = DEFAULT_SERVER_IP;
    int port = DEFAULT_PORT;
    int fd = -1;
    struct sockaddr_in server_addr;
    quic_tls_conn_t conn;
    quic_cid_t client_scid = make_cid(0x10);
    quic_cid_t client_odcid = make_cid(0xa0);
    int ping_enqueued = 0;
    uint64_t deadline = now_ms() + 15000;
    ssize_t recv_len;
    uint8_t buffer[QUIC_TLS_MAX_DATAGRAM_SIZE];

    if (argc > 1) {
        server_ip = argv[1];
    }
    if (argc > 2) {
        port = atoi(argv[2]);
    }

    quic_tls_conn_init(&conn);
    if (quic_tls_conn_configure(&conn,
                                QUIC_ROLE_CLIENT,
                                QUIC_V1_VERSION,
                                &client_scid,
                                &client_odcid,
                                NULL,
                                NULL) != 0) {
        fprintf(stderr, "client configure failed: %s\n", quic_tls_conn_last_error(&conn));
        quic_tls_conn_free(&conn);
        return 1;
    }
    if (quic_tls_conn_start(&conn) != 0) {
        fprintf(stderr, "client start failed: %s\n", quic_tls_conn_last_error(&conn));
        quic_tls_conn_free(&conn);
        return 1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("client socket");
        quic_tls_conn_free(&conn);
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) != 1) {
        fprintf(stderr, "client invalid server ip: %s\n", server_ip);
        close(fd);
        quic_tls_conn_free(&conn);
        return 1;
    }
    if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        perror("client connect");
        close(fd);
        quic_tls_conn_free(&conn);
        return 1;
    }

    while (now_ms() < deadline) {
        struct pollfd pfd;
        int timeout_ms = 50;
        uint64_t loss_deadline = quic_tls_conn_loss_deadline_ms(&conn);
        uint64_t now = now_ms();

        if (quic_tls_conn_has_pending_output(&conn)) {
            if (send_pending_packets(fd, &conn) != 0) {
                close(fd);
                quic_tls_conn_free(&conn);
                return 1;
            }
        }

        if (loss_deadline != 0 && loss_deadline <= now) {
            quic_tls_conn_on_loss_timeout(&conn, loss_deadline);
            continue;
        }
        if (loss_deadline != 0 && loss_deadline > now) {
            uint64_t remaining = loss_deadline - now;
            if (remaining < (uint64_t)timeout_ms) {
                timeout_ms = (int)remaining;
            }
        }

        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, timeout_ms) < 0) {
            perror("client poll");
            close(fd);
            quic_tls_conn_free(&conn);
            return 1;
        }

        if ((pfd.revents & POLLIN) != 0) {
            recv_len = recv(fd, buffer, sizeof(buffer), 0);
            if (recv_len < 0) {
                if (errno == EINTR) {
                    continue;
                }
                perror("client recv");
                close(fd);
                quic_tls_conn_free(&conn);
                return 1;
            }
            if (quic_tls_conn_handle_datagram(&conn, buffer, (size_t)recv_len) != 0) {
                fprintf(stderr, "client handle datagram failed: %s\n", quic_tls_conn_last_error(&conn));
                close(fd);
                quic_tls_conn_free(&conn);
                return 1;
            }
            if (quic_tls_conn_handshake_complete(&conn) && !ping_enqueued) {
                quic_tls_conn_queue_ping(&conn);
                ping_enqueued = 1;
                if (send_pending_packets(fd, &conn) != 0) {
                    close(fd);
                    quic_tls_conn_free(&conn);
                    return 1;
                }
            }
        }

        if (conn.handshake_complete &&
            conn.ping_received &&
            ping_enqueued &&
            !conn.ping_pending &&
            !quic_tls_conn_has_pending_output(&conn)) {
            printf("client handshake complete and received encrypted ping\n");
            close(fd);
            quic_tls_conn_free(&conn);
            return 0;
        }
    }

    fprintf(stderr, "client timeout waiting for QUIC handshake\n");
    close(fd);
    quic_tls_conn_free(&conn);
    return 1;
}
