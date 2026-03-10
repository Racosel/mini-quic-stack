CC = gcc
CFLAGS = -Wall -Wextra -g -O0
INCLUDES = -I./include

# 源文件定义
SRC_PACKET = src/packet/pkt_decode.c
SRC_TRANSPORT = src/transport/udp_io.c
SRC_VERSION = src/packet/quic_version.c

# 测试文件定义
SRC_TEST_PHASE1 = tests/test_phase1.c
SRC_TEST_PHASE2 = tests/test_phase2.c

# 二进制文件定义
BIN_TEST_PHASE1 = test_phase1_bin
BIN_TEST_PHASE2 = test_phase2_bin

.PHONY: all test1 test2 clean net

all: $(BIN_TEST_PHASE1) $(BIN_TEST_PHASE2)

# ==========================================
# Phase 1 规则
# ==========================================
$(BIN_TEST_PHASE1): $(SRC_TEST_PHASE1) $(SRC_PACKET) $(SRC_TRANSPORT)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test1: $(BIN_TEST_PHASE1)
	@echo "--- Executing Phase 1 Comprehensive Tests ---"
	./$(BIN_TEST_PHASE1)

# ==========================================
# Phase 2 规则 (新增)
# ==========================================
$(BIN_TEST_PHASE2): $(SRC_TEST_PHASE2) $(SRC_PACKET) $(SRC_VERSION)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

test2: $(BIN_TEST_PHASE2)
	@echo "--- Executing Phase 2 Tests (Version Routing & Negotiation) ---"
	./$(BIN_TEST_PHASE2)

# ==========================================
# 网络环境与清理
# ==========================================
net:
	sudo python3 quic_testnet.py

clean:
	@echo "--- Cleaning Build Artifacts ---"
	rm -f $(BIN_TEST_PHASE1) $(BIN_TEST_PHASE2) *.o
	@echo "--- Resetting Mininet and Ports ---"
	sudo mn -c > /dev/null 2>&1
	-sudo fuser -k 6653/tcp > /dev/null 2>&1
	-sudo fuser -k 4434/udp > /dev/null 2>&1 || true