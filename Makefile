CC = gcc
LD = gcc
CFLAGS = -Wall -Wextra -g -O0
INCLUDES = -I./include -I./boringssl/include
BORINGSSL_LIBS = boringssl/build/libssl.a boringssl/build/libcrypto.a
LDFLAGS = $(BORINGSSL_LIBS) -lpthread -ldl -lstdc++
TEST_REPEAT ?= 5
TESTS_DIR = tests
TEST_BIN_DIR = $(TESTS_DIR)/bin
TEST_CERT_DIR = $(TESTS_DIR)/certs
TEST_DATA_DIR = $(TESTS_DIR)/data
TEST_TRANSFER_DIR = $(TEST_DATA_DIR)/topo-transfer

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
SRC_STREAM = src/transport/quic_stream.c
SRC_TLS = src/tls/quic_tls.c $(SRC_CRYPTO_STREAM) $(SRC_STREAM) $(SRC_CONN) src/packet/quic_transport_params.c src/packet/quic_retry.c

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
SRC_TEST_PHASE14 = tests/test_phase14.c
SRC_TEST_PHASE15 = tests/test_phase15.c
SRC_TEST_PHASE16 = tests/test_phase16.c
SRC_TEST_PHASE17 = tests/test_phase17.c
SRC_TEST_PHASE18 = tests/test_phase18.c
SRC_TEST_PHASE19 = tests/test_phase19.c
SRC_TEST_PHASE20 = tests/test_phase20.c

BIN_TEST_PHASE1 = $(TEST_BIN_DIR)/test_phase1_bin
BIN_TEST_PHASE2 = $(TEST_BIN_DIR)/test_phase2_bin
BIN_TEST_PHASE3 = $(TEST_BIN_DIR)/test_phase3_bin
BIN_TEST_PHASE4 = $(TEST_BIN_DIR)/test_phase4_bin
BIN_TEST_PHASE6 = $(TEST_BIN_DIR)/test_phase6_bin
BIN_TEST_PHASE7 = $(TEST_BIN_DIR)/test_phase7_bin
BIN_TEST_PHASE8 = $(TEST_BIN_DIR)/test_phase8_bin
BIN_TEST_PHASE9 = $(TEST_BIN_DIR)/test_phase9_bin
BIN_TEST_PHASE10 = $(TEST_BIN_DIR)/test_phase10_bin
BIN_TEST_PHASE11 = $(TEST_BIN_DIR)/test_phase11_bin
BIN_TEST_PHASE12 = $(TEST_BIN_DIR)/test_phase12_bin
BIN_TEST_PHASE13 = $(TEST_BIN_DIR)/test_phase13_bin
BIN_TEST_PHASE14 = $(TEST_BIN_DIR)/test_phase14_bin
BIN_TEST_PHASE15 = $(TEST_BIN_DIR)/test_phase15_bin
BIN_TEST_PHASE16 = $(TEST_BIN_DIR)/test_phase16_bin
BIN_TEST_PHASE17 = $(TEST_BIN_DIR)/test_phase17_bin
BIN_TEST_PHASE18 = $(TEST_BIN_DIR)/test_phase18_bin
BIN_TEST_PHASE19 = $(TEST_BIN_DIR)/test_phase19_bin
BIN_TEST_PHASE20 = $(TEST_BIN_DIR)/test_phase20_bin
BIN_EXAMPLE_SERVER = $(TEST_BIN_DIR)/quic_server
BIN_EXAMPLE_CLIENT = $(TEST_BIN_DIR)/quic_client
TEST_CERT = $(TEST_CERT_DIR)/server_cert.pem
TEST_KEY = $(TEST_CERT_DIR)/server_key.pem
BIN_TESTS = $(BIN_TEST_PHASE1) $(BIN_TEST_PHASE2) $(BIN_TEST_PHASE3) $(BIN_TEST_PHASE4) $(BIN_TEST_PHASE6) $(BIN_TEST_PHASE7) $(BIN_TEST_PHASE8) $(BIN_TEST_PHASE9) $(BIN_TEST_PHASE10) $(BIN_TEST_PHASE11) $(BIN_TEST_PHASE12) $(BIN_TEST_PHASE13) $(BIN_TEST_PHASE14) $(BIN_TEST_PHASE15) $(BIN_TEST_PHASE16) $(BIN_TEST_PHASE17) $(BIN_TEST_PHASE18) $(BIN_TEST_PHASE19) $(BIN_TEST_PHASE20)


.PHONY: all test1 test2 test3 test4 test5_1 test6 test7 test8 test9 test10 test11 test12 test13 test14 test15 test16 test17 test18 test19 test20 example-certs quic-server quic-client quic-demo topo-auto topo-auto-file topo-stage4-clean topo-stage4-lossy topo-stage5-preferred clean net

all: $(BIN_TEST_PHASE1) $(BIN_TEST_PHASE2) $(BIN_TEST_PHASE3) $(BIN_TEST_PHASE4) $(BIN_TEST_PHASE6) $(BIN_TEST_PHASE7) $(BIN_TEST_PHASE8) $(BIN_TEST_PHASE9) $(BIN_TEST_PHASE10) $(BIN_TEST_PHASE11) $(BIN_TEST_PHASE12) $(BIN_TEST_PHASE13) $(BIN_TEST_PHASE14) $(BIN_TEST_PHASE15) $(BIN_TEST_PHASE16) $(BIN_TEST_PHASE17) $(BIN_TEST_PHASE18) $(BIN_TEST_PHASE19) $(BIN_TEST_PHASE20) $(BIN_EXAMPLE_SERVER) $(BIN_EXAMPLE_CLIENT)

$(BORINGSSL_LIBS):
	cmake -S boringssl -B boringssl/build
	cmake --build boringssl/build --target ssl crypto -j4

define RUN_REPEATED
	@set -e; i=1; while [ $$i -le $(TEST_REPEAT) ]; do \
		echo "[run $$i/$(TEST_REPEAT)] $(1)"; \
		$(2); \
		i=$$((i + 1)); \
	done
endef


# ==========================================
# 阶段 1 / 阶段 2 规则
# ==========================================
$(BIN_TEST_PHASE1): $(SRC_TEST_PHASE1) $(SRC_PACKET) $(SRC_TRANSPORT)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test1: $(BIN_TEST_PHASE1)
	$(call RUN_REPEATED,test1,./$(BIN_TEST_PHASE1))

$(BIN_TEST_PHASE2): $(SRC_TEST_PHASE2) $(SRC_PACKET) $(SRC_VERSION)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test2: $(BIN_TEST_PHASE2)
	$(call RUN_REPEATED,test2,./$(BIN_TEST_PHASE2))

# ==========================================
# 阶段 3 规则（OpenSSL 加密）
# ==========================================
$(BIN_TEST_PHASE3): $(SRC_TEST_PHASE3) $(SRC_PACKET) $(SRC_VERSION) $(SRC_CRYPTO)
	mkdir -p $(@D)
	$(LD) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS)

test3: $(BIN_TEST_PHASE3)
	$(call RUN_REPEATED,test3,./$(BIN_TEST_PHASE3))

# ==========================================
# 阶段 4 规则（帧解析）
# ==========================================
$(BIN_TEST_PHASE4): $(SRC_TEST_PHASE4) $(SRC_FRAME)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test4: $(BIN_TEST_PHASE4)
	$(call RUN_REPEATED,test4,./$(BIN_TEST_PHASE4))

$(BIN_TEST_PHASE6): $(SRC_TEST_PHASE6) $(SRC_FRAME)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test6: $(BIN_TEST_PHASE6)
	$(call RUN_REPEATED,test6,./$(BIN_TEST_PHASE6))

$(BIN_TEST_PHASE7): $(SRC_TEST_PHASE7) $(SRC_TP) $(SRC_RETRY)
	mkdir -p $(@D)
	$(LD) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS)

test7: $(BIN_TEST_PHASE7)
	$(call RUN_REPEATED,test7,./$(BIN_TEST_PHASE7))

$(BIN_TEST_PHASE8): $(SRC_TEST_PHASE8) $(SRC_CRYPTO) $(SRC_VERSION) $(SRC_PACKET_PROTECTION)
	mkdir -p $(@D)
	$(LD) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS)

test8: $(BIN_TEST_PHASE8)
	$(call RUN_REPEATED,test8,./$(BIN_TEST_PHASE8))

$(BIN_TEST_PHASE9): $(SRC_TEST_PHASE9) $(SRC_ACK)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test9: $(BIN_TEST_PHASE9)
	$(call RUN_REPEATED,test9,./$(BIN_TEST_PHASE9))

$(BIN_TEST_PHASE10): $(SRC_TEST_PHASE10) $(SRC_CONN)
	mkdir -p $(@D)
	$(LD) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS)

test10: $(BIN_TEST_PHASE10)
	$(call RUN_REPEATED,test10,./$(BIN_TEST_PHASE10))

$(BIN_TEST_PHASE11): $(SRC_TEST_PHASE11) $(SRC_CONN)
	mkdir -p $(@D)
	$(LD) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS)

test11: $(BIN_TEST_PHASE11)
	$(call RUN_REPEATED,test11,./$(BIN_TEST_PHASE11))

$(BIN_TEST_PHASE12): $(SRC_TEST_PHASE12) $(SRC_TLS) $(BORINGSSL_LIBS)
	mkdir -p $(@D)
	$(LD) $(CFLAGS) $(INCLUDES) $(SRC_TEST_PHASE12) $(SRC_TLS) -o $@ $(LDFLAGS)

test12: $(BIN_TEST_PHASE12) example-certs
	$(call RUN_REPEATED,test12,./$(BIN_TEST_PHASE12))

$(BIN_TEST_PHASE13): $(SRC_TEST_PHASE13) $(SRC_TLS) $(BORINGSSL_LIBS)
	mkdir -p $(@D)
	$(LD) $(CFLAGS) $(INCLUDES) $(SRC_TEST_PHASE13) $(SRC_TLS) -o $@ $(LDFLAGS)

test13: $(BIN_TEST_PHASE13) example-certs
	$(call RUN_REPEATED,test13,./$(BIN_TEST_PHASE13))

$(BIN_TEST_PHASE14): $(SRC_TEST_PHASE14) $(SRC_TLS) $(BORINGSSL_LIBS)
	mkdir -p $(@D)
	$(LD) $(CFLAGS) $(INCLUDES) $(SRC_TEST_PHASE14) $(SRC_TLS) -o $@ $(LDFLAGS)

test14: $(BIN_TEST_PHASE14) example-certs
	$(call RUN_REPEATED,test14,./$(BIN_TEST_PHASE14))

$(BIN_TEST_PHASE15): $(SRC_TEST_PHASE15) $(SRC_ACK)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_TEST_PHASE15) $(SRC_ACK) -o $@

test15: $(BIN_TEST_PHASE15)
	$(call RUN_REPEATED,test15,./$(BIN_TEST_PHASE15))

$(BIN_TEST_PHASE16): $(SRC_TEST_PHASE16) $(SRC_ACK)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC_TEST_PHASE16) $(SRC_ACK) -o $@

test16: $(BIN_TEST_PHASE16)
	$(call RUN_REPEATED,test16,./$(BIN_TEST_PHASE16))

$(BIN_TEST_PHASE17): $(SRC_TEST_PHASE17) $(SRC_TLS) $(BORINGSSL_LIBS)
	mkdir -p $(@D)
	$(LD) $(CFLAGS) $(INCLUDES) $(SRC_TEST_PHASE17) $(SRC_TLS) -o $@ $(LDFLAGS)

test17: $(BIN_TEST_PHASE17) example-certs
	$(call RUN_REPEATED,test17,./$(BIN_TEST_PHASE17))

$(BIN_TEST_PHASE18): $(SRC_TEST_PHASE18) $(SRC_TLS) $(BORINGSSL_LIBS)
	mkdir -p $(@D)
	$(LD) $(CFLAGS) $(INCLUDES) $(SRC_TEST_PHASE18) $(SRC_TLS) -o $@ $(LDFLAGS)

test18: $(BIN_TEST_PHASE18) example-certs
	$(call RUN_REPEATED,test18,./$(BIN_TEST_PHASE18))

$(BIN_TEST_PHASE19): $(SRC_TEST_PHASE19) $(SRC_TLS) $(BORINGSSL_LIBS)
	mkdir -p $(@D)
	$(LD) $(CFLAGS) $(INCLUDES) $(SRC_TEST_PHASE19) $(SRC_TLS) -o $@ $(LDFLAGS)

test19: $(BIN_TEST_PHASE19) example-certs
	$(call RUN_REPEATED,test19,./$(BIN_TEST_PHASE19))

$(BIN_TEST_PHASE20): $(SRC_TEST_PHASE20) $(SRC_TLS) $(BORINGSSL_LIBS)
	mkdir -p $(@D)
	$(LD) $(CFLAGS) $(INCLUDES) $(SRC_TEST_PHASE20) $(SRC_TLS) -o $@ $(LDFLAGS)

test20: $(BIN_TEST_PHASE20) example-certs
	$(call RUN_REPEATED,test20,./$(BIN_TEST_PHASE20))

SRC_RECOVERY = src/recovery/loss_detector.c
SRC_TEST_PHASE5_1 = tests/test_phase5_1.c
BIN_TEST_PHASE5_1 = $(TEST_BIN_DIR)/test_phase5_1_bin

all: $(BIN_TEST_PHASE5_1)

$(BIN_TEST_PHASE5_1): $(SRC_TEST_PHASE5_1) $(SRC_RECOVERY)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test5_1: $(BIN_TEST_PHASE5_1)
	$(call RUN_REPEATED,test5_1,./$(BIN_TEST_PHASE5_1))

BIN_TESTS += $(BIN_TEST_PHASE5_1)

example-certs: $(TEST_CERT) $(TEST_KEY)

$(TEST_CERT) $(TEST_KEY):
	mkdir -p $(TEST_CERT_DIR)
	if [ ! -f $(TEST_CERT) ] || [ ! -f $(TEST_KEY) ]; then openssl req -x509 -newkey rsa:2048 -nodes -keyout $(TEST_KEY) -out $(TEST_CERT) -subj "/CN=AI-QUIC Test Server" -days 1 > /dev/null 2>&1; fi

$(BIN_EXAMPLE_SERVER): example/server.c $(SRC_TLS) $(BORINGSSL_LIBS)
	mkdir -p $(@D)
	$(LD) $(CFLAGS) $(INCLUDES) example/server.c $(SRC_TLS) -o $@ $(LDFLAGS)

$(BIN_EXAMPLE_CLIENT): example/client.c $(SRC_TLS) $(BORINGSSL_LIBS)
	mkdir -p $(@D)
	$(LD) $(CFLAGS) $(INCLUDES) example/client.c $(SRC_TLS) -o $@ $(LDFLAGS)

quic-server: $(BIN_EXAMPLE_SERVER) example-certs

quic-client: $(BIN_EXAMPLE_CLIENT)

quic-demo: $(BIN_EXAMPLE_SERVER) $(BIN_EXAMPLE_CLIENT) example-certs

topo-auto: quic-demo
	sudo python3 topo.py --auto --rounds $(TEST_REPEAT)

topo-auto-file: quic-demo
	sudo python3 topo.py --auto-file --rounds $(TEST_REPEAT)

topo-stage4-clean: quic-demo
	sudo python3 topo.py --auto-file --profile clean-bdp --rounds $(TEST_REPEAT)

topo-stage4-lossy: quic-demo
	sudo python3 topo.py --auto-file --profile lossy-recovery --rounds $(TEST_REPEAT)

topo-stage5-preferred: quic-demo
	sudo python3 topo.py --auto-file --profile preferred-address --rounds $(TEST_REPEAT)

# ==========================================
# 网络与清理
# ==========================================
net:
	sudo python3 topo.py

clean:
	rm -rf $(TEST_BIN_DIR) $(TEST_CERT_DIR) $(TEST_DATA_DIR) __pycache__ $(TESTS_DIR)/__pycache__
	rm -rf example/topo-transfer
	rm -f test_phase*_bin example/quic_server example/quic_client example/server_cert.pem example/server_key.pem *.o
	sudo mn -c > /dev/null 2>&1
	-sudo fuser -k 6653/tcp > /dev/null 2>&1
	-sudo fuser -k 4434/udp > /dev/null 2>&1 || true
