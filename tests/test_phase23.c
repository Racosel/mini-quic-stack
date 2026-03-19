#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CLIENT_QLOG "tests/data/stage6-demo/client.qlog"
#define SERVER_QLOG "tests/data/stage6-demo/server.qlog"

static int file_contains(const char *path, const char *needle) {
    FILE *fp;
    char buffer[8192];
    size_t nread;

    if (!path || !needle) {
        return 0;
    }
    fp = fopen(path, "rb");
    if (!fp) {
        return 0;
    }
    nread = fread(buffer, 1, sizeof(buffer) - 1, fp);
    fclose(fp);
    buffer[nread] = '\0';
    return strstr(buffer, needle) != NULL;
}

static void test_stage6_loopback_app_demo_with_qlog(void) {
    char command[2048];
    int rc;

    rc = system("mkdir -p tests/data/stage6-demo && rm -f " CLIENT_QLOG " " SERVER_QLOG);
    assert(rc == 0);

    snprintf(command,
             sizeof(command),
             "tmp_srv=/tmp/ai_quic_stage6_server.log; "
             "tmp_cli=/tmp/ai_quic_stage6_client.log; "
             "./tests/bin/quic_app_server 127.0.0.1 4456 tests/certs/server_cert.pem tests/certs/server_key.pem " SERVER_QLOG " > \"$tmp_srv\" 2>&1 & "
             "srv=$!; "
             "sleep 1; "
             "./tests/bin/quic_app_client 127.0.0.1 4456 " CLIENT_QLOG " > \"$tmp_cli\" 2>&1; "
             "cli_rc=$?; "
             "wait $srv; "
             "srv_rc=$?; "
             "cat \"$tmp_cli\"; "
             "cat \"$tmp_srv\"; "
             "test \"$cli_rc\" -eq 0 -a \"$srv_rc\" -eq 0");
    rc = system(command);
    assert(rc == 0);

    assert(file_contains(CLIENT_QLOG, "\"event\":\"handshake_complete\""));
    assert(file_contains(CLIENT_QLOG, "\"event\":\"connection_close_requested\""));
    assert(file_contains(SERVER_QLOG, "\"event\":\"handshake_complete\""));
    assert(file_contains(SERVER_QLOG, "\"event\":\"stream_readable\""));

    printf("[PASS] Stage 6 app demo binaries complete a loopback exchange and emit qlog-style events\n");
}

int main(void) {
    test_stage6_loopback_app_demo_with_qlog();
    return 0;
}
