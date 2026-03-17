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

#define DEFAULT_PORT 4434
#define DEFAULT_CERT "example/server_cert.pem"
#define DEFAULT_KEY  "example/server_key.pem"

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

static int send_pending_packets(int fd,
                                quic_tls_conn_t *conn,
                                const struct sockaddr_in *peer_addr,
                                socklen_t peer_len) {
    while (quic_tls_conn_has_pending_output(conn)) {
        uint8_t packet[QUIC_TLS_MAX_DATAGRAM_SIZE];
        size_t packet_len = 0;

        if (quic_tls_conn_build_next_datagram(conn, packet, sizeof(packet), &packet_len) != 0) {
            fprintf(stderr, "server build packet failed: %s\n", quic_tls_conn_last_error(conn));
            return -1;
        }
        if (sendto(fd, packet, packet_len, 0, (const struct sockaddr *)peer_addr, peer_len) < 0) {
            perror("server sendto");
            return -1;
        }
    }

    return 0;
}

int main(int argc, char **argv) {
    const char *bind_ip = "10.0.0.2";
    const char *cert_file = DEFAULT_CERT;
    const char *key_file = DEFAULT_KEY;
    int port = DEFAULT_PORT;
    int fd = -1;
    struct sockaddr_in local_addr;
    struct sockaddr_in peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    quic_tls_conn_t conn;
    quic_cid_t local_cid = make_cid(0xb0);
    int peer_known = 0;
    int ping_enqueued = 0;
    uint64_t deadline = now_ms() + 15000;
    ssize_t recv_len;
    uint8_t buffer[QUIC_TLS_MAX_DATAGRAM_SIZE];

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

    quic_tls_conn_init(&conn);
    if (quic_tls_conn_configure(&conn,
                                QUIC_ROLE_SERVER,
                                QUIC_V1_VERSION,
                                &local_cid,
                                NULL,
                                cert_file,
                                key_file) != 0) {
        fprintf(stderr, "server configure failed: %s\n", quic_tls_conn_last_error(&conn));
        quic_tls_conn_free(&conn);
        return 1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("server socket");
        quic_tls_conn_free(&conn);
        return 1;
    }

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, bind_ip, &local_addr.sin_addr) != 1) {
        fprintf(stderr, "server invalid bind ip: %s\n", bind_ip);
        close(fd);
        quic_tls_conn_free(&conn);
        return 1;
    }
    if (bind(fd, (struct sockaddr *)&local_addr, sizeof(local_addr)) != 0) {
        perror("server bind");
        close(fd);
        quic_tls_conn_free(&conn);
        return 1;
    }

    printf("server listening on %s:%d\n", bind_ip, port);
    fflush(stdout);

    while (now_ms() < deadline) {
        struct pollfd pfd;
        int timeout_ms = 50;
        uint64_t loss_deadline = quic_tls_conn_loss_deadline_ms(&conn);
        uint64_t now = now_ms();

        if (peer_known && quic_tls_conn_has_pending_output(&conn)) {
            if (send_pending_packets(fd, &conn, &peer_addr, peer_len) != 0) {
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
            perror("server poll");
            close(fd);
            quic_tls_conn_free(&conn);
            return 1;
        }

        if ((pfd.revents & POLLIN) != 0) {
            recv_len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&peer_addr, &peer_len);
            if (recv_len < 0) {
                if (errno == EINTR) {
                    continue;
                }
                perror("server recvfrom");
                close(fd);
                quic_tls_conn_free(&conn);
                return 1;
            }
            peer_known = 1;
            if (quic_tls_conn_handle_datagram(&conn, buffer, (size_t)recv_len) != 0) {
                fprintf(stderr, "server handle datagram failed: %s\n", quic_tls_conn_last_error(&conn));
                close(fd);
                quic_tls_conn_free(&conn);
                return 1;
            }
            if (quic_tls_conn_handshake_complete(&conn) && !ping_enqueued) {
                quic_tls_conn_queue_ping(&conn);
                ping_enqueued = 1;
            }
        }

        if (conn.handshake_complete && conn.ping_received) {
            printf("server handshake complete and received encrypted ping\n");
            close(fd);
            quic_tls_conn_free(&conn);
            return 0;
        }
    }

    fprintf(stderr, "server timeout waiting for QUIC handshake\n");
    close(fd);
    quic_tls_conn_free(&conn);
    return 1;
}
