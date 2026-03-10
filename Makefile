CC = gcc
CFLAGS = -Wall -Wextra -g -O0
INCLUDES = -I./include

SRC_PACKET = src/packet/pkt_decode.c
SRC_TRANSPORT = src/transport/udp_io.c
SRC_TEST_PHASE1 = tests/test_phase1.c

BIN_TEST_PHASE1 = test_phase1_bin

.PHONY: all test1 clean net

all: $(BIN_TEST_PHASE1)

# 编译并链接 Phase 1 所有依赖
$(BIN_TEST_PHASE1): $(SRC_TEST_PHASE1) $(SRC_PACKET) $(SRC_TRANSPORT)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

# 一键运行阶段1测试
test1: $(BIN_TEST_PHASE1)
	@echo "--- Executing Phase 1 Comprehensive Tests ---"
	./$(BIN_TEST_PHASE1)

net:
	sudo python3 quic_testnet.py

clean:
	@echo "--- Cleaning Build Artifacts ---"
	rm -f $(BIN_TEST_PHASE1) *.o
	@echo "--- Resetting Mininet and Ports ---"
	sudo mn -c > /dev/null 2>&1
	-sudo fuser -k 6653/tcp > /dev/null 2>&1
	-sudo fuser -k 4434/udp > /dev/null 2>&1 || true