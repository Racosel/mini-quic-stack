CC = gcc
LD = gcc
CFLAGS = -Wall -Wextra -g -O0
INCLUDES = -I./include -I./boringssl/include
BORINGSSL_LIBS = boringssl/build/libssl.a boringssl/build/libcrypto.a
LDFLAGS = $(BORINGSSL_LIBS) -lpthread -ldl -lstdc++

SRC_PACKET = src/packet/pkt_decode.c
SRC_TRANSPORT = src/transport/udp_io.c
SRC_VERSION = src/packet/quic_version.c
SRC_CRYPTO = src/crypto/quic_crypto.c
SRC_FRAME = src/packet/quic_varint.c src/frame/frame_decode.c
SRC_TP = src/packet/quic_transport_params.c src/packet/quic_varint.c
SRC_RETRY = src/packet/quic_retry.c
SRC_PACKET_PROTECTION = src/packet/quic_packet_protection.c
SRC_ACK = src/recovery/quic_ack.c src/recovery/loss_detector.c src/packet/quic_varint.c
SRC_INITIAL = src/packet/quic_initial.c src/packet/quic_varint.c src/packet/pkt_decode.c src/packet/quic_version.c
SRC_CONN = src/transport/quic_connection.c src/recovery/quic_ack.c src/recovery/loss_detector.c src/packet/quic_varint.c src/packet/quic_initial.c src/packet/quic_packet_protection.c src/packet/quic_version.c src/packet/pkt_decode.c src/crypto/quic_crypto.c
SRC_CRYPTO_STREAM = src/transport/quic_crypto_stream.c
SRC_TLS = src/tls/quic_tls.c $(SRC_CRYPTO_STREAM) $(SRC_CONN) src/packet/quic_transport_params.c src/packet/quic_retry.c

SRC_TEST_PHASE1 = tests/test_phase1.c
SRC_TEST_PHASE2 = tests/test_phase2.c
SRC_TEST_PHASE3 = tests/test_phase3.c
SRC_TEST_PHASE4 = tests/test_phase4.c
SRC_TEST_PHASE6 = tests/test_phase6.c
SRC_TEST_PHASE7 = tests/test_phase7.c
SRC_TEST_PHASE8 = tests/test_phase8.c
SRC_TEST_PHASE9 = tests/test_phase9.c
SRC_TEST_PHASE10 = tests/test_phase10.c
SRC_TEST_PHASE11 = tests/test_phase11.c
SRC_TEST_PHASE12 = tests/test_phase12.c
SRC_TEST_PHASE13 = tests/test_phase13.c

BIN_TEST_PHASE1 = test_phase1_bin
BIN_TEST_PHASE2 = test_phase2_bin
BIN_TEST_PHASE3 = test_phase3_bin
BIN_TEST_PHASE4 = test_phase4_bin
BIN_TEST_PHASE6 = test_phase6_bin
BIN_TEST_PHASE7 = test_phase7_bin
BIN_TEST_PHASE8 = test_phase8_bin
BIN_TEST_PHASE9 = test_phase9_bin
BIN_TEST_PHASE10 = test_phase10_bin
BIN_TEST_PHASE11 = test_phase11_bin
BIN_TEST_PHASE12 = test_phase12_bin
BIN_TEST_PHASE13 = test_phase13_bin
BIN_EXAMPLE_SERVER = example/quic_server
BIN_EXAMPLE_CLIENT = example/quic_client
EXAMPLE_CERT = example/server_cert.pem
EXAMPLE_KEY = example/server_key.pem
BIN_TESTS = $(BIN_TEST_PHASE1) $(BIN_TEST_PHASE2) $(BIN_TEST_PHASE3) $(BIN_TEST_PHASE4) $(BIN_TEST_PHASE6) $(BIN_TEST_PHASE7) $(BIN_TEST_PHASE8) $(BIN_TEST_PHASE9) $(BIN_TEST_PHASE10) $(BIN_TEST_PHASE11) $(BIN_TEST_PHASE12) $(BIN_TEST_PHASE13)


.PHONY: all test1 test2 test3 test4 test6 test7 test8 test9 test10 test11 test12 test13 example-certs quic-server quic-client quic-demo topo-auto clean net

all: $(BIN_TEST_PHASE1) $(BIN_TEST_PHASE2) $(BIN_TEST_PHASE3) $(BIN_TEST_PHASE4) $(BIN_TEST_PHASE6) $(BIN_TEST_PHASE7) $(BIN_TEST_PHASE8) $(BIN_TEST_PHASE9) $(BIN_TEST_PHASE10) $(BIN_TEST_PHASE11) $(BIN_TEST_PHASE12) $(BIN_TEST_PHASE13) $(BIN_EXAMPLE_SERVER) $(BIN_EXAMPLE_CLIENT)

$(BORINGSSL_LIBS):
	cmake -S boringssl -B boringssl/build
	cmake --build boringssl/build --target ssl crypto -j4


# ==========================================
# 阶段 1 / 阶段 2 规则
# ==========================================
$(BIN_TEST_PHASE1): $(SRC_TEST_PHASE1) $(SRC_PACKET) $(SRC_TRANSPORT)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test1: $(BIN_TEST_PHASE1)
	./$(BIN_TEST_PHASE1)

$(BIN_TEST_PHASE2): $(SRC_TEST_PHASE2) $(SRC_PACKET) $(SRC_VERSION)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test2: $(BIN_TEST_PHASE2)
	./$(BIN_TEST_PHASE2)

# ==========================================
# 阶段 3 规则（OpenSSL 加密）
# ==========================================
$(BIN_TEST_PHASE3): $(SRC_TEST_PHASE3) $(SRC_PACKET) $(SRC_VERSION) $(SRC_CRYPTO)
	$(LD) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS)

test3: $(BIN_TEST_PHASE3)
	./$(BIN_TEST_PHASE3)

# ==========================================
# 阶段 4 规则（帧解析）
# ==========================================
$(BIN_TEST_PHASE4): $(SRC_TEST_PHASE4) $(SRC_FRAME)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test4: $(BIN_TEST_PHASE4)
	@echo "--- 执行阶段 4 测试（帧解析） ---"
	./$(BIN_TEST_PHASE4)

$(BIN_TEST_PHASE6): $(SRC_TEST_PHASE6) $(SRC_FRAME)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test6: $(BIN_TEST_PHASE6)
	./$(BIN_TEST_PHASE6)

$(BIN_TEST_PHASE7): $(SRC_TEST_PHASE7) $(SRC_TP) $(SRC_RETRY)
	$(LD) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS)

test7: $(BIN_TEST_PHASE7)
	./$(BIN_TEST_PHASE7)

$(BIN_TEST_PHASE8): $(SRC_TEST_PHASE8) $(SRC_CRYPTO) $(SRC_VERSION) $(SRC_PACKET_PROTECTION)
	$(LD) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS)

test8: $(BIN_TEST_PHASE8)
	./$(BIN_TEST_PHASE8)

$(BIN_TEST_PHASE9): $(SRC_TEST_PHASE9) $(SRC_ACK)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test9: $(BIN_TEST_PHASE9)
	./$(BIN_TEST_PHASE9)

$(BIN_TEST_PHASE10): $(SRC_TEST_PHASE10) $(SRC_CONN)
	$(LD) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS)

test10: $(BIN_TEST_PHASE10)
	./$(BIN_TEST_PHASE10)

$(BIN_TEST_PHASE11): $(SRC_TEST_PHASE11) $(SRC_CONN)
	$(LD) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS)

test11: $(BIN_TEST_PHASE11)
	./$(BIN_TEST_PHASE11)

$(BIN_TEST_PHASE12): $(SRC_TEST_PHASE12) $(SRC_TLS) $(BORINGSSL_LIBS)
	$(LD) $(CFLAGS) $(INCLUDES) $(SRC_TEST_PHASE12) $(SRC_TLS) -o $@ $(LDFLAGS)

test12: $(BIN_TEST_PHASE12) example-certs
	./$(BIN_TEST_PHASE12)

$(BIN_TEST_PHASE13): $(SRC_TEST_PHASE13) $(SRC_TLS) $(BORINGSSL_LIBS)
	$(LD) $(CFLAGS) $(INCLUDES) $(SRC_TEST_PHASE13) $(SRC_TLS) -o $@ $(LDFLAGS)

test13: $(BIN_TEST_PHASE13) example-certs
	./$(BIN_TEST_PHASE13)

SRC_RECOVERY = src/recovery/loss_detector.c
SRC_TEST_PHASE5_1 = tests/test_phase5_1.c
BIN_TEST_PHASE5_1 = test_phase5_1_bin

all: $(BIN_TEST_PHASE5_1)

$(BIN_TEST_PHASE5_1): $(SRC_TEST_PHASE5_1) $(SRC_RECOVERY)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test5_1: $(BIN_TEST_PHASE5_1)
	./$(BIN_TEST_PHASE5_1)

BIN_TESTS += $(BIN_TEST_PHASE5_1)

example-certs: $(EXAMPLE_CERT) $(EXAMPLE_KEY)

$(EXAMPLE_CERT) $(EXAMPLE_KEY):
	mkdir -p example
	if [ ! -f $(EXAMPLE_CERT) ] || [ ! -f $(EXAMPLE_KEY) ]; then openssl req -x509 -newkey rsa:2048 -nodes -keyout $(EXAMPLE_KEY) -out $(EXAMPLE_CERT) -subj "/CN=AI-QUIC Test Server" -days 1 > /dev/null 2>&1; fi

$(BIN_EXAMPLE_SERVER): example/server.c $(SRC_TLS) $(BORINGSSL_LIBS)
	$(LD) $(CFLAGS) $(INCLUDES) example/server.c $(SRC_TLS) -o $@ $(LDFLAGS)

$(BIN_EXAMPLE_CLIENT): example/client.c $(SRC_TLS) $(BORINGSSL_LIBS)
	$(LD) $(CFLAGS) $(INCLUDES) example/client.c $(SRC_TLS) -o $@ $(LDFLAGS)

quic-server: $(BIN_EXAMPLE_SERVER) example-certs

quic-client: $(BIN_EXAMPLE_CLIENT)

quic-demo: $(BIN_EXAMPLE_SERVER) $(BIN_EXAMPLE_CLIENT) example-certs

topo-auto: quic-demo
	sudo python3 topo.py --auto

# ==========================================
# 网络与清理
# ==========================================
net:
	sudo python3 topo.py

clean:
	rm -f $(BIN_TESTS) $(BIN_EXAMPLE_SERVER) $(BIN_EXAMPLE_CLIENT) *.o
	sudo mn -c > /dev/null 2>&1
	-sudo fuser -k 6653/tcp > /dev/null 2>&1
	-sudo fuser -k 4434/udp > /dev/null 2>&1 || true
