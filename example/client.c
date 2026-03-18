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

#define DEFAULT_SERVER_IP "10.0.0.2"
#define DEFAULT_PORT 4434

static const uint8_t client_completion_signal[] = "APP_COMPLETE";
static const uint8_t client_completion_ack[] = "APP_COMPLETE_ACK";

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
        perror("client fopen upload");
        return -1;
    }

    while ((nread = fread(scratch, 1, sizeof(scratch), fp)) > 0) {
        if (byte_buffer_append(out, scratch, nread) != 0) {
            fclose(fp);
            return -1;
        }
    }
    if (ferror(fp)) {
        perror("client fread upload");
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
        perror("client fopen download");
        return -1;
    }
    if (buf->len > 0 && fwrite(buf->data, 1, buf->len, fp) != buf->len) {
        perror("client fwrite download");
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

static int send_pending_packets(int fd, quic_tls_conn_t *conn) {
    while (quic_tls_conn_has_pending_output(conn)) {
        uint8_t packet[QUIC_TLS_MAX_DATAGRAM_SIZE];
        size_t packet_len = 0;
        int build_status;

        build_status = quic_tls_conn_build_next_datagram(conn, packet, sizeof(packet), &packet_len);
        if (build_status == QUIC_TLS_BUILD_BLOCKED) {
            break;
        }
        if (build_status != 0) {
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

static int client_app_data_complete(const quic_tls_conn_t *conn,
                                    int file_mode,
                                    const byte_buffer_t *response0,
                                    const byte_buffer_t *response1,
                                    int response0_fin,
                                    int response1_fin,
                                    int app_started,
                                    int ping_enqueued,
                                    int download_written,
                                    const char *expected_ack,
                                    const uint8_t *expected0,
                                    size_t expected0_len,
                                    const uint8_t *expected1,
                                    size_t expected1_len) {
    if (!conn || !response0 || !response1) {
        return 0;
    }
    if (!conn->handshake_complete ||
        !conn->ping_received ||
        !app_started ||
        !ping_enqueued ||
        conn->ping_pending ||
        !response0_fin ||
        !response1_fin) {
        return 0;
    }

    if (file_mode) {
        return download_written &&
               response0->len == strlen(expected_ack) &&
               memcmp(response0->data, expected_ack, response0->len) == 0;
    }

    return response0->len == expected0_len &&
           response1->len == expected1_len &&
           memcmp(response0->data, expected0, expected0_len) == 0 &&
           memcmp(response1->data, expected1, expected1_len) == 0;
}

static int client_close_complete(const quic_tls_conn_t *conn) {
    return conn &&
           (conn->conn.state == QUIC_CONN_STATE_DRAINING ||
            conn->conn.state == QUIC_CONN_STATE_CLOSED);
}

int main(int argc, char **argv) {
    const char *server_ip = DEFAULT_SERVER_IP;
    int port = DEFAULT_PORT;
    const char *upload_file = NULL;
    const char *download_file = NULL;
    int file_mode = 0;
    int fd = -1;
    struct sockaddr_in server_addr;
    quic_tls_conn_t conn;
    quic_cid_t client_scid = make_cid(0x10);
    quic_cid_t client_odcid = make_cid(0xa0);
    byte_buffer_t upload_payload;
    byte_buffer_t response0;
    byte_buffer_t response1;
    byte_buffer_t response8;
    int app_started = 0;
    int ping_enqueued = 0;
    int download_written = 0;
    int completion_sent = 0;
    int close_started = 0;
    uint64_t stream0 = UINT64_MAX;
    uint64_t stream4 = UINT64_MAX;
    uint64_t stream8 = UINT64_MAX;
    static const uint8_t request0[] = "client-stream-0 request payload";
    static const uint8_t request1[] = "client-stream-4 request payload";
    static const uint8_t expected0[] = "server-stream-0 response payload";
    static const uint8_t expected1[] = "server-stream-4 response payload";
    static const uint8_t download_request[] = "DOWNLOAD_FILE";
    int response0_fin = 0;
    int response1_fin = 0;
    int response8_fin = 0;
    uint64_t deadline = now_ms() + 15000;
    ssize_t recv_len;
    uint8_t buffer[QUIC_TLS_MAX_DATAGRAM_SIZE];
    char upload_hash[65];
    char expected_ack[160];

    byte_buffer_init(&upload_payload);
    byte_buffer_init(&response0);
    byte_buffer_init(&response1);
    byte_buffer_init(&response8);
    memset(upload_hash, 0, sizeof(upload_hash));
    memset(expected_ack, 0, sizeof(expected_ack));

    if (argc > 1) {
        server_ip = argv[1];
    }
    if (argc > 2) {
        port = atoi(argv[2]);
    }
    if (argc > 3) {
        upload_file = argv[3];
    }
    if (argc > 4) {
        download_file = argv[4];
    }
    if ((upload_file && !download_file) || (!upload_file && download_file)) {
        fprintf(stderr, "client requires both upload and download file paths\n");
        return 1;
    }
    file_mode = (upload_file && download_file) ? 1 : 0;

    if (file_mode) {
        if (load_file(upload_file, &upload_payload) != 0) {
            byte_buffer_free(&upload_payload);
            return 1;
        }
        sha256_hex(upload_payload.data, upload_payload.len, upload_hash);
        snprintf(expected_ack,
                 sizeof(expected_ack),
                 "UPLOAD_OK size=%lu sha256=%s",
                 (unsigned long)upload_payload.len,
                 upload_hash);
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
        byte_buffer_free(&upload_payload);
        byte_buffer_free(&response0);
        byte_buffer_free(&response1);
        byte_buffer_free(&response8);
        return 1;
    }
    if (quic_tls_conn_start(&conn) != 0) {
        fprintf(stderr, "client start failed: %s\n", quic_tls_conn_last_error(&conn));
        quic_tls_conn_free(&conn);
        byte_buffer_free(&upload_payload);
        byte_buffer_free(&response0);
        byte_buffer_free(&response1);
        byte_buffer_free(&response8);
        return 1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("client socket");
        quic_tls_conn_free(&conn);
        byte_buffer_free(&upload_payload);
        byte_buffer_free(&response0);
        byte_buffer_free(&response1);
        byte_buffer_free(&response8);
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) != 1) {
        fprintf(stderr, "client invalid server ip: %s\n", server_ip);
        close(fd);
        quic_tls_conn_free(&conn);
        byte_buffer_free(&upload_payload);
        byte_buffer_free(&response0);
        byte_buffer_free(&response1);
        byte_buffer_free(&response8);
        return 1;
    }
    if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        perror("client connect");
        close(fd);
        quic_tls_conn_free(&conn);
        byte_buffer_free(&upload_payload);
        byte_buffer_free(&response0);
        byte_buffer_free(&response1);
        byte_buffer_free(&response8);
        return 1;
    }

    while (now_ms() < deadline) {
        struct pollfd pfd;
        int timeout_ms = 50;
        uint64_t loss_deadline = quic_tls_conn_loss_deadline_ms(&conn);
        uint64_t now = now_ms();

        if (close_started && client_close_complete(&conn)) {
            if (file_mode) {
                printf("client handshake complete, uploaded %lu bytes, downloaded %lu bytes, and received encrypted ping\n",
                       (unsigned long)upload_payload.len,
                       (unsigned long)response1.len);
            } else {
                printf("client handshake complete, exchanged two bidirectional streams, and received encrypted ping\n");
            }
            close(fd);
            quic_tls_conn_free(&conn);
            byte_buffer_free(&upload_payload);
            byte_buffer_free(&response0);
            byte_buffer_free(&response1);
            byte_buffer_free(&response8);
            return 0;
        }

        if (quic_tls_conn_has_pending_output(&conn)) {
            if (send_pending_packets(fd, &conn) != 0) {
                close(fd);
                quic_tls_conn_free(&conn);
                byte_buffer_free(&upload_payload);
                byte_buffer_free(&response0);
                byte_buffer_free(&response1);
                byte_buffer_free(&response8);
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
            byte_buffer_free(&upload_payload);
            byte_buffer_free(&response0);
            byte_buffer_free(&response1);
            byte_buffer_free(&response8);
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
                byte_buffer_free(&upload_payload);
                byte_buffer_free(&response0);
                byte_buffer_free(&response1);
                byte_buffer_free(&response8);
                return 1;
            }
            if (quic_tls_conn_handle_datagram(&conn, buffer, (size_t)recv_len) != 0) {
                fprintf(stderr, "client handle datagram failed: %s\n", quic_tls_conn_last_error(&conn));
                close(fd);
                quic_tls_conn_free(&conn);
                byte_buffer_free(&upload_payload);
                byte_buffer_free(&response0);
                byte_buffer_free(&response1);
                byte_buffer_free(&response8);
                return 1;
            }
            if (quic_tls_conn_handshake_complete(&conn) && !app_started) {
                const uint8_t *stream0_payload = file_mode ? upload_payload.data : request0;
                size_t stream0_len = file_mode ? upload_payload.len : (sizeof(request0) - 1);
                const uint8_t *stream4_payload = file_mode ? download_request : request1;
                size_t stream4_len = file_mode ? (sizeof(download_request) - 1) : (sizeof(request1) - 1);

                quic_tls_conn_queue_ping(&conn);
                ping_enqueued = 1;
                if (quic_tls_conn_open_stream(&conn, 1, &stream0) != 0 ||
                    quic_tls_conn_open_stream(&conn, 1, &stream4) != 0 ||
                    quic_tls_conn_stream_write(&conn, stream0, stream0_payload, stream0_len, 1) != 0 ||
                    quic_tls_conn_stream_write(&conn, stream4, stream4_payload, stream4_len, 1) != 0) {
                    fprintf(stderr, "client stream setup failed: %s\n", quic_tls_conn_last_error(&conn));
                    close(fd);
                    quic_tls_conn_free(&conn);
                    byte_buffer_free(&upload_payload);
                    byte_buffer_free(&response0);
                    byte_buffer_free(&response1);
                    byte_buffer_free(&response8);
                    return 1;
                }
                app_started = 1;
                if (send_pending_packets(fd, &conn) != 0) {
                    close(fd);
                    quic_tls_conn_free(&conn);
                    byte_buffer_free(&upload_payload);
                    byte_buffer_free(&response0);
                    byte_buffer_free(&response1);
                    byte_buffer_free(&response8);
                    return 1;
                }
            }

            if (app_started) {
                if (drain_stream(&conn, stream0, &response0, &response0_fin) < 0 ||
                    drain_stream(&conn, stream4, &response1, &response1_fin) < 0 ||
                    (stream8 != UINT64_MAX && drain_stream(&conn, stream8, &response8, &response8_fin) < 0)) {
                    fprintf(stderr, "client stream read failed: %s\n", quic_tls_conn_last_error(&conn));
                    close(fd);
                    quic_tls_conn_free(&conn);
                    byte_buffer_free(&upload_payload);
                    byte_buffer_free(&response0);
                    byte_buffer_free(&response1);
                    byte_buffer_free(&response8);
                    return 1;
                }
            }
        }

        if (file_mode && response1_fin && !download_written) {
            if (write_file(download_file, &response1) != 0) {
                close(fd);
                quic_tls_conn_free(&conn);
                byte_buffer_free(&upload_payload);
                byte_buffer_free(&response0);
                byte_buffer_free(&response1);
                byte_buffer_free(&response8);
                return 1;
            }
            download_written = 1;
        }

        if (!completion_sent &&
            client_app_data_complete(&conn,
                                     file_mode,
                                     &response0,
                                     &response1,
                                     response0_fin,
                                     response1_fin,
                                     app_started,
                                     ping_enqueued,
                                     download_written,
                                     expected_ack,
                                     expected0,
                                     sizeof(expected0) - 1,
                                     expected1,
                                     sizeof(expected1) - 1)) {
            if (quic_tls_conn_open_stream(&conn, 1, &stream8) != 0 ||
                quic_tls_conn_stream_write(&conn,
                                           stream8,
                                           client_completion_signal,
                                           sizeof(client_completion_signal) - 1,
                                           1) != 0) {
                fprintf(stderr, "client completion signal failed: %s\n", quic_tls_conn_last_error(&conn));
                close(fd);
                quic_tls_conn_free(&conn);
                byte_buffer_free(&upload_payload);
                byte_buffer_free(&response0);
                byte_buffer_free(&response1);
                byte_buffer_free(&response8);
                return 1;
            }
            completion_sent = 1;
            if (send_pending_packets(fd, &conn) != 0) {
                close(fd);
                quic_tls_conn_free(&conn);
                byte_buffer_free(&upload_payload);
                byte_buffer_free(&response0);
                byte_buffer_free(&response1);
                byte_buffer_free(&response8);
                return 1;
            }
        }

        if (completion_sent && response8_fin && !close_started) {
            if (response8.len != sizeof(client_completion_ack) - 1 ||
                memcmp(response8.data, client_completion_ack, sizeof(client_completion_ack) - 1) != 0) {
                fprintf(stderr, "client completion ack mismatch\n");
                close(fd);
                quic_tls_conn_free(&conn);
                byte_buffer_free(&upload_payload);
                byte_buffer_free(&response0);
                byte_buffer_free(&response1);
                byte_buffer_free(&response8);
                return 1;
            }
            if (quic_tls_conn_close(&conn, QUIC_TRANSPORT_ERROR_NO_ERROR) != 0) {
                fprintf(stderr, "client connection close failed: %s\n", quic_tls_conn_last_error(&conn));
                close(fd);
                quic_tls_conn_free(&conn);
                byte_buffer_free(&upload_payload);
                byte_buffer_free(&response0);
                byte_buffer_free(&response1);
                byte_buffer_free(&response8);
                return 1;
            }
            close_started = 1;
            if (send_pending_packets(fd, &conn) != 0) {
                close(fd);
                quic_tls_conn_free(&conn);
                byte_buffer_free(&upload_payload);
                byte_buffer_free(&response0);
                byte_buffer_free(&response1);
                byte_buffer_free(&response8);
                return 1;
            }
        }
    }

    fprintf(stderr, "client timeout waiting for QUIC stream exchange\n");
    close(fd);
    quic_tls_conn_free(&conn);
    byte_buffer_free(&upload_payload);
    byte_buffer_free(&response0);
    byte_buffer_free(&response1);
    byte_buffer_free(&response8);
    return 1;
}
