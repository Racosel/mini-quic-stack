#include "quic_tls.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/sha.h>
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

static const uint8_t server_completion_signal[] = "APP_COMPLETE";
static const uint8_t server_completion_ack[] = "APP_COMPLETE_ACK";

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} byte_buffer_t;

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

static void byte_buffer_init(byte_buffer_t *buf) {
    if (!buf) {
        return;
    }
    memset(buf, 0, sizeof(*buf));
}

static void byte_buffer_free(byte_buffer_t *buf) {
    if (!buf) {
        return;
    }
    free(buf->data);
    memset(buf, 0, sizeof(*buf));
}

static int byte_buffer_reserve(byte_buffer_t *buf, size_t needed) {
    uint8_t *resized;
    size_t next_cap;

    if (!buf) {
        return -1;
    }
    if (needed <= buf->cap) {
        return 0;
    }

    next_cap = buf->cap == 0 ? 1024 : buf->cap;
    while (next_cap < needed) {
        next_cap *= 2;
    }
    resized = (uint8_t *)realloc(buf->data, next_cap);
    if (!resized) {
        return -1;
    }

    buf->data = resized;
    buf->cap = next_cap;
    return 0;
}

static int byte_buffer_append(byte_buffer_t *buf, const uint8_t *data, size_t len) {
    if (!buf || (!data && len != 0) || len > SIZE_MAX - buf->len) {
        return -1;
    }
    if (byte_buffer_reserve(buf, buf->len + len) != 0) {
        return -1;
    }
    if (len > 0) {
        memcpy(buf->data + buf->len, data, len);
        buf->len += len;
    }
    return 0;
}

static int load_file(const char *path, byte_buffer_t *out) {
    FILE *fp;
    uint8_t scratch[4096];
    size_t nread;

    if (!path || !out) {
        return -1;
    }
    fp = fopen(path, "rb");
    if (!fp) {
        perror("server fopen send file");
        return -1;
    }

    while ((nread = fread(scratch, 1, sizeof(scratch), fp)) > 0) {
        if (byte_buffer_append(out, scratch, nread) != 0) {
            fclose(fp);
            return -1;
        }
    }
    if (ferror(fp)) {
        perror("server fread send file");
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

static int write_file(const char *path, const byte_buffer_t *buf) {
    FILE *fp;

    if (!path || !buf) {
        return -1;
    }
    unlink(path);
    fp = fopen(path, "wb");
    if (!fp) {
        perror("server fopen receive file");
        return -1;
    }
    if (buf->len > 0 && fwrite(buf->data, 1, buf->len, fp) != buf->len) {
        perror("server fwrite receive file");
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static void sha256_hex(const uint8_t *data, size_t len, char out[65]) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    size_t i;

    SHA256(data, len, digest);
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(out + (i * 2), 3, "%02x", digest[i]);
    }
    out[64] = '\0';
}

static int send_pending_packets(int fd,
                                quic_tls_conn_t *conn,
                                const struct sockaddr_in *peer_addr,
                                socklen_t peer_len) {
    while (quic_tls_conn_has_pending_output(conn)) {
        uint8_t packet[QUIC_TLS_MAX_DATAGRAM_SIZE];
        size_t packet_len = 0;
        int build_status;

        build_status = quic_tls_conn_build_next_datagram(conn, packet, sizeof(packet), &packet_len);
        if (build_status == QUIC_TLS_BUILD_BLOCKED) {
            // RFC 9000/9002: anti-amplification only blocks sends temporarily.
            break;
        }
        if (build_status != 0) {
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

static int drain_stream(quic_tls_conn_t *conn, uint64_t stream_id, byte_buffer_t *storage, int *fin) {
    int progressed = 0;

    if (!conn || !storage || !fin) {
        return -1;
    }

    for (;;) {
        size_t available = 0;
        size_t out_read = 0;
        int exists = 0;
        uint8_t scratch[1024];
        int local_fin = 0;

        if (quic_tls_conn_stream_peek(conn, stream_id, &available, &local_fin, &exists) != 0) {
            return -1;
        }
        if (!exists || (available == 0 && !local_fin)) {
            break;
        }
        if (quic_tls_conn_stream_read(conn, stream_id, scratch, sizeof(scratch), &out_read, &local_fin) != 0) {
            return -1;
        }
        if (out_read > 0 && byte_buffer_append(storage, scratch, out_read) != 0) {
            return -1;
        }
        if (out_read > 0 || local_fin) {
            progressed = 1;
        }
        if (local_fin) {
            *fin = 1;
            break;
        }
        if (out_read == 0) {
            break;
        }
    }

    return progressed;
}

static int server_app_data_complete(const quic_tls_conn_t *conn,
                                    int responded0,
                                    int responded4,
                                    int request0_fin,
                                    int request4_fin,
                                    int ping_enqueued) {
    return conn &&
           conn->handshake_complete &&
           conn->ping_received &&
           responded0 &&
           responded4 &&
           request0_fin &&
           request4_fin &&
           ping_enqueued &&
           !conn->ping_pending;
}

static int server_close_complete(const quic_tls_conn_t *conn) {
    return conn &&
           (conn->conn.state == QUIC_CONN_STATE_DRAINING ||
            conn->conn.state == QUIC_CONN_STATE_CLOSED);
}

int main(int argc, char **argv) {
    const char *bind_ip = "10.0.0.2";
    const char *cert_file = DEFAULT_CERT;
    const char *key_file = DEFAULT_KEY;
    const char *receive_file = NULL;
    const char *send_file = NULL;
    int file_mode = 0;
    int port = DEFAULT_PORT;
    int fd = -1;
    struct sockaddr_in local_addr;
    struct sockaddr_in peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    quic_tls_conn_t conn;
    quic_cid_t local_cid = make_cid(0xb0);
    byte_buffer_t request0;
    byte_buffer_t request4;
    byte_buffer_t request8;
    byte_buffer_t send_payload;
    int peer_known = 0;
    int app_started = 0;
    int ping_enqueued = 0;
    int responded0 = 0;
    int responded4 = 0;
    int completion_acked = 0;
    int received_file_written = 0;
    static const uint8_t expected0[] = "client-stream-0 request payload";
    static const uint8_t expected4[] = "client-stream-4 request payload";
    static const uint8_t response0[] = "server-stream-0 response payload";
    static const uint8_t response4[] = "server-stream-4 response payload";
    static const uint8_t download_request[] = "DOWNLOAD_FILE";
    int request0_fin = 0;
    int request4_fin = 0;
    int request8_fin = 0;
    uint64_t deadline = now_ms() + 15000;
    ssize_t recv_len;
    uint8_t buffer[QUIC_TLS_MAX_DATAGRAM_SIZE];

    byte_buffer_init(&request0);
    byte_buffer_init(&request4);
    byte_buffer_init(&request8);
    byte_buffer_init(&send_payload);

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
        receive_file = argv[5];
    }
    if (argc > 6) {
        send_file = argv[6];
    }
    if ((receive_file && !send_file) || (!receive_file && send_file)) {
        fprintf(stderr, "server requires both receive and send file paths\n");
        return 1;
    }
    file_mode = (receive_file && send_file) ? 1 : 0;
    if (file_mode && load_file(send_file, &send_payload) != 0) {
        byte_buffer_free(&request0);
        byte_buffer_free(&request4);
        byte_buffer_free(&request8);
        byte_buffer_free(&send_payload);
        return 1;
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
        byte_buffer_free(&request0);
        byte_buffer_free(&request4);
        byte_buffer_free(&request8);
        byte_buffer_free(&send_payload);
        return 1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("server socket");
        quic_tls_conn_free(&conn);
        byte_buffer_free(&request0);
        byte_buffer_free(&request4);
        byte_buffer_free(&request8);
        byte_buffer_free(&send_payload);
        return 1;
    }

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, bind_ip, &local_addr.sin_addr) != 1) {
        fprintf(stderr, "server invalid bind ip: %s\n", bind_ip);
        close(fd);
        quic_tls_conn_free(&conn);
        byte_buffer_free(&request0);
        byte_buffer_free(&request4);
        byte_buffer_free(&request8);
        byte_buffer_free(&send_payload);
        return 1;
    }
    if (bind(fd, (struct sockaddr *)&local_addr, sizeof(local_addr)) != 0) {
        perror("server bind");
        close(fd);
        quic_tls_conn_free(&conn);
        byte_buffer_free(&request0);
        byte_buffer_free(&request4);
        byte_buffer_free(&request8);
        byte_buffer_free(&send_payload);
        return 1;
    }

    printf("server listening on %s:%d\n", bind_ip, port);
    fflush(stdout);

    while (now_ms() < deadline) {
        struct pollfd pfd;
        int timeout_ms = 50;
        uint64_t loss_deadline = quic_tls_conn_loss_deadline_ms(&conn);
        uint64_t now = now_ms();

        if (server_app_data_complete(&conn,
                                     responded0,
                                     responded4,
                                     request0_fin,
                                     request4_fin,
                                     ping_enqueued) &&
            completion_acked &&
            server_close_complete(&conn)) {
            if (file_mode) {
                printf("server handshake complete, received %lu upload bytes, sent %lu download bytes, and received encrypted ping\n",
                       (unsigned long)request0.len,
                       (unsigned long)send_payload.len);
            } else {
                printf("server handshake complete, exchanged two bidirectional streams, and received encrypted ping\n");
            }
            close(fd);
            quic_tls_conn_free(&conn);
            byte_buffer_free(&request0);
            byte_buffer_free(&request4);
            byte_buffer_free(&request8);
            byte_buffer_free(&send_payload);
            return 0;
        }

        if (peer_known && quic_tls_conn_has_pending_output(&conn)) {
            if (send_pending_packets(fd, &conn, &peer_addr, peer_len) != 0) {
                close(fd);
                quic_tls_conn_free(&conn);
                byte_buffer_free(&request0);
                byte_buffer_free(&request4);
                byte_buffer_free(&request8);
                byte_buffer_free(&send_payload);
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
            byte_buffer_free(&request0);
            byte_buffer_free(&request4);
            byte_buffer_free(&request8);
            byte_buffer_free(&send_payload);
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
                byte_buffer_free(&request0);
                byte_buffer_free(&request4);
                byte_buffer_free(&request8);
                byte_buffer_free(&send_payload);
                return 1;
            }
            peer_known = 1;
            if (quic_tls_conn_handle_datagram(&conn, buffer, (size_t)recv_len) != 0) {
                fprintf(stderr, "server handle datagram failed: %s\n", quic_tls_conn_last_error(&conn));
                close(fd);
                quic_tls_conn_free(&conn);
                byte_buffer_free(&request0);
                byte_buffer_free(&request4);
                byte_buffer_free(&request8);
                byte_buffer_free(&send_payload);
                return 1;
            }
            if (quic_tls_conn_handshake_complete(&conn) && !ping_enqueued) {
                quic_tls_conn_queue_ping(&conn);
                ping_enqueued = 1;
                app_started = 1;
            }
            if (app_started) {
                if (drain_stream(&conn, 0, &request0, &request0_fin) < 0 ||
                    drain_stream(&conn, 4, &request4, &request4_fin) < 0 ||
                    drain_stream(&conn, 8, &request8, &request8_fin) < 0) {
                    fprintf(stderr, "server stream read failed: %s\n", quic_tls_conn_last_error(&conn));
                    close(fd);
                    quic_tls_conn_free(&conn);
                    byte_buffer_free(&request0);
                    byte_buffer_free(&request4);
                    byte_buffer_free(&request8);
                    byte_buffer_free(&send_payload);
                    return 1;
                }
                if (request0_fin && !responded0) {
                    if (file_mode) {
                        char upload_hash[65];
                        char ack_message[160];

                        if (!received_file_written && write_file(receive_file, &request0) != 0) {
                            close(fd);
                            quic_tls_conn_free(&conn);
                            byte_buffer_free(&request0);
                            byte_buffer_free(&request4);
                            byte_buffer_free(&request8);
                            byte_buffer_free(&send_payload);
                            return 1;
                        }
                        received_file_written = 1;
                        sha256_hex(request0.data, request0.len, upload_hash);
                        snprintf(ack_message,
                                 sizeof(ack_message),
                                 "UPLOAD_OK size=%lu sha256=%s",
                                 (unsigned long)request0.len,
                                 upload_hash);
                        if (quic_tls_conn_stream_write(&conn,
                                                       0,
                                                       (const uint8_t *)ack_message,
                                                       strlen(ack_message),
                                                       1) != 0) {
                            fprintf(stderr, "server upload ack write failed: %s\n", quic_tls_conn_last_error(&conn));
                            close(fd);
                            quic_tls_conn_free(&conn);
                            byte_buffer_free(&request0);
                            byte_buffer_free(&request4);
                            byte_buffer_free(&request8);
                            byte_buffer_free(&send_payload);
                            return 1;
                        }
                    } else if (request0.len == sizeof(expected0) - 1 &&
                               memcmp(request0.data, expected0, sizeof(expected0) - 1) == 0) {
                        if (quic_tls_conn_stream_write(&conn, 0, response0, sizeof(response0) - 1, 1) != 0) {
                            fprintf(stderr, "server stream 0 write failed: %s\n", quic_tls_conn_last_error(&conn));
                            close(fd);
                            quic_tls_conn_free(&conn);
                            byte_buffer_free(&request0);
                            byte_buffer_free(&request4);
                            byte_buffer_free(&request8);
                            byte_buffer_free(&send_payload);
                            return 1;
                        }
                    } else {
                        fprintf(stderr, "server stream 0 payload mismatch\n");
                        close(fd);
                        quic_tls_conn_free(&conn);
                        byte_buffer_free(&request0);
                        byte_buffer_free(&request4);
                        byte_buffer_free(&request8);
                        byte_buffer_free(&send_payload);
                        return 1;
                    }
                    responded0 = 1;
                }
                if (request4_fin && !responded4) {
                    if (file_mode) {
                        if (request4.len != sizeof(download_request) - 1 ||
                            memcmp(request4.data, download_request, sizeof(download_request) - 1) != 0) {
                            fprintf(stderr, "server download request mismatch\n");
                            close(fd);
                            quic_tls_conn_free(&conn);
                            byte_buffer_free(&request0);
                            byte_buffer_free(&request4);
                            byte_buffer_free(&request8);
                            byte_buffer_free(&send_payload);
                            return 1;
                        }
                        if (quic_tls_conn_stream_write(&conn,
                                                       4,
                                                       send_payload.data,
                                                       send_payload.len,
                                                       1) != 0) {
                            fprintf(stderr, "server file stream write failed: %s\n", quic_tls_conn_last_error(&conn));
                            close(fd);
                            quic_tls_conn_free(&conn);
                            byte_buffer_free(&request0);
                            byte_buffer_free(&request4);
                            byte_buffer_free(&request8);
                            byte_buffer_free(&send_payload);
                            return 1;
                        }
                    } else if (request4.len == sizeof(expected4) - 1 &&
                               memcmp(request4.data, expected4, sizeof(expected4) - 1) == 0) {
                        if (quic_tls_conn_stream_write(&conn, 4, response4, sizeof(response4) - 1, 1) != 0) {
                            fprintf(stderr, "server stream 4 write failed: %s\n", quic_tls_conn_last_error(&conn));
                            close(fd);
                            quic_tls_conn_free(&conn);
                            byte_buffer_free(&request0);
                            byte_buffer_free(&request4);
                            byte_buffer_free(&request8);
                            byte_buffer_free(&send_payload);
                            return 1;
                        }
                    } else {
                        fprintf(stderr, "server stream 4 payload mismatch\n");
                        close(fd);
                        quic_tls_conn_free(&conn);
                        byte_buffer_free(&request0);
                        byte_buffer_free(&request4);
                        byte_buffer_free(&request8);
                        byte_buffer_free(&send_payload);
                        return 1;
                    }
                    responded4 = 1;
                }
                if (request8_fin && !completion_acked) {
                    if (!server_app_data_complete(&conn,
                                                  responded0,
                                                  responded4,
                                                  request0_fin,
                                                  request4_fin,
                                                  ping_enqueued)) {
                        fprintf(stderr, "server completion signal arrived before data exchange finished\n");
                        close(fd);
                        quic_tls_conn_free(&conn);
                        byte_buffer_free(&request0);
                        byte_buffer_free(&request4);
                        byte_buffer_free(&request8);
                        byte_buffer_free(&send_payload);
                        return 1;
                    }
                    if (request8.len != sizeof(server_completion_signal) - 1 ||
                        memcmp(request8.data, server_completion_signal, sizeof(server_completion_signal) - 1) != 0) {
                        fprintf(stderr, "server completion signal mismatch\n");
                        close(fd);
                        quic_tls_conn_free(&conn);
                        byte_buffer_free(&request0);
                        byte_buffer_free(&request4);
                        byte_buffer_free(&request8);
                        byte_buffer_free(&send_payload);
                        return 1;
                    }
                    if (quic_tls_conn_stream_write(&conn,
                                                   8,
                                                   server_completion_ack,
                                                   sizeof(server_completion_ack) - 1,
                                                   1) != 0) {
                        fprintf(stderr, "server completion ack write failed: %s\n", quic_tls_conn_last_error(&conn));
                        close(fd);
                        quic_tls_conn_free(&conn);
                        byte_buffer_free(&request0);
                        byte_buffer_free(&request4);
                        byte_buffer_free(&request8);
                        byte_buffer_free(&send_payload);
                        return 1;
                    }
                    completion_acked = 1;
                }
            }
            if (peer_known && quic_tls_conn_has_pending_output(&conn)) {
                if (send_pending_packets(fd, &conn, &peer_addr, peer_len) != 0) {
                    close(fd);
                    quic_tls_conn_free(&conn);
                    byte_buffer_free(&request0);
                    byte_buffer_free(&request4);
                    byte_buffer_free(&request8);
                    byte_buffer_free(&send_payload);
                    return 1;
                }
            }
        }

    }

    fprintf(stderr, "server timeout waiting for QUIC stream exchange\n");
    close(fd);
    quic_tls_conn_free(&conn);
    byte_buffer_free(&request0);
    byte_buffer_free(&request4);
    byte_buffer_free(&request8);
    byte_buffer_free(&send_payload);
    return 1;
}
