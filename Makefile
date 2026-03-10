CC = gcc
CFLAGS = -Wall -Wextra -g -O0
INCLUDES = -I./include
LDFLAGS = -lcrypto

SRC_PACKET = src/packet/pkt_decode.c
SRC_TRANSPORT = src/transport/udp_io.c
SRC_VERSION = src/packet/quic_version.c
SRC_CRYPTO = src/crypto/quic_crypto.c

SRC_TEST_PHASE1 = tests/test_phase1.c
SRC_TEST_PHASE2 = tests/test_phase2.c
SRC_TEST_PHASE3 = tests/test_phase3.c

BIN_TEST_PHASE1 = test_phase1_bin
BIN_TEST_PHASE2 = test_phase2_bin
BIN_TEST_PHASE3 = test_phase3_bin

.PHONY: all test1 test2 test3 clean net

all: $(BIN_TEST_PHASE1) $(BIN_TEST_PHASE2) $(BIN_TEST_PHASE3)

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
# Network & Clean
# ==========================================
net:
	sudo python3 quic_testnet.py

clean:
	rm -f $(BIN_TEST_PHASE1) $(BIN_TEST_PHASE2) $(BIN_TEST_PHASE3) *.o
	sudo mn -c > /dev/null 2>&1
	-sudo fuser -k 6653/tcp > /dev/null 2>&1
	-sudo fuser -k 4434/udp > /dev/null 2>&1 || true