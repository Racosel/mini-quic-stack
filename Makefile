CC = gcc
CFLAGS = -Wall -Wextra -g -O0
INCLUDES = -I./include
LDFLAGS = -lcrypto

SRC_PACKET = src/packet/pkt_decode.c
SRC_TRANSPORT = src/transport/udp_io.c
SRC_VERSION = src/packet/quic_version.c
SRC_CRYPTO = src/crypto/quic_crypto.c
SRC_FRAME = src/packet/quic_varint.c src/frame/frame_decode.c

SRC_TEST_PHASE1 = tests/test_phase1.c
SRC_TEST_PHASE2 = tests/test_phase2.c
SRC_TEST_PHASE3 = tests/test_phase3.c
SRC_TEST_PHASE4 = tests/test_phase4.c

BIN_TEST_PHASE1 = test_phase1_bin
BIN_TEST_PHASE2 = test_phase2_bin
BIN_TEST_PHASE3 = test_phase3_bin
BIN_TEST_PHASE4 = test_phase4_bin
BIN_TESTS = $(BIN_TEST_PHASE1) $(BIN_TEST_PHASE2) $(BIN_TEST_PHASE3) $(BIN_TEST_PHASE4)


.PHONY: all test1 test2 test3 test4 clean net

all: $(BIN_TEST_PHASE1) $(BIN_TEST_PHASE2) $(BIN_TEST_PHASE3) $(BIN_TEST_PHASE4)


# ==========================================
# Phase 1 / Phase 2 Rules
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
# Phase 3 Rules (OpenSSL Crypto)
# ==========================================
$(BIN_TEST_PHASE3): $(SRC_TEST_PHASE3) $(SRC_PACKET) $(SRC_VERSION) $(SRC_CRYPTO)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS)

test3: $(BIN_TEST_PHASE3)
	./$(BIN_TEST_PHASE3)

# ==========================================
# Phase 4 Rules (Frame Parsing)
# ==========================================
$(BIN_TEST_PHASE4): $(SRC_TEST_PHASE4) $(SRC_FRAME)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test4: $(BIN_TEST_PHASE4)
	@echo "--- Executing Phase 4 Tests (Frame Parsing) ---"
	./$(BIN_TEST_PHASE4)

SRC_RECOVERY = src/recovery/loss_detector.c
SRC_TEST_PHASE5_1 = tests/test_phase5_1.c
BIN_TEST_PHASE5_1 = test_phase5_1_bin

all: $(BIN_TEST_PHASE5_1)

$(BIN_TEST_PHASE5_1): $(SRC_TEST_PHASE5_1) $(SRC_RECOVERY)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test5_1: $(BIN_TEST_PHASE5_1)
	./$(BIN_TEST_PHASE5_1)

BIN_TESTS += $(BIN_TEST_PHASE5_1)

# ==========================================
# Network & Clean
# ==========================================
net:
	sudo python3 topo.py

clean:
	rm -f $(BIN_TESTS) *.o
	sudo mn -c > /dev/null 2>&1
	-sudo fuser -k 6653/tcp > /dev/null 2>&1
	-sudo fuser -k 4434/udp > /dev/null 2>&1 || true