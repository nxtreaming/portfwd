CC ?= $(CROSS_COMPILE)gcc
PREFIX ?= /usr/local
CFLAGS += -Wall -Wextra
# CFLAGS += -g

# Build directory
BUILD_DIR = build

NO_EPOLL_O =
ifeq ($(shell uname), Linux)
#LDFLAGS += -levent
LDFLAGS_PTHREAD = -lpthread
else
NO_EPOLL_O = $(BUILD_DIR)/no-epoll.o
LDFLAGS_PTHREAD = -lpthread
endif

all: $(BUILD_DIR) tcpfwd udpfwd kcptcp-client kcptcp-server

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)/3rd/kcp
	mkdir -p $(BUILD_DIR)/3rd/chacha20poly1305

FWD_OBJS = $(BUILD_DIR)/tcpfwd.o $(BUILD_DIR)/common.o $(BUILD_DIR)/fwd_util.o $(BUILD_DIR)/conn_pool.o $(NO_EPOLL_O)

tcpfwd: $(FWD_OBJS)
	$(CC) $(CFLAGS) -o tcpfwd $(FWD_OBJS) $(LDFLAGS) $(LDFLAGS_PTHREAD)

# udpfwd is single-threaded and does not need pthread
udpfwd: $(BUILD_DIR)/udpfwd.o $(BUILD_DIR)/common.o $(BUILD_DIR)/fwd_util.o $(BUILD_DIR)/conn_pool.o $(NO_EPOLL_O)
	$(CC) $(CFLAGS) -o udpfwd $(BUILD_DIR)/udpfwd.o $(BUILD_DIR)/common.o $(BUILD_DIR)/fwd_util.o $(BUILD_DIR)/conn_pool.o $(NO_EPOLL_O) $(LDFLAGS)

# High-performance version with optimizations disabled (single-threaded, no pthread)
udpfwd-fast: $(BUILD_DIR)/udpfwd-fast.o $(BUILD_DIR)/common.o $(BUILD_DIR)/fwd_util.o $(BUILD_DIR)/conn_pool.o $(NO_EPOLL_O)
	$(CC) $(CFLAGS) -o udpfwd-fast $(BUILD_DIR)/udpfwd-fast.o $(BUILD_DIR)/common.o $(BUILD_DIR)/fwd_util.o $(BUILD_DIR)/conn_pool.o $(NO_EPOLL_O) $(LDFLAGS)

$(BUILD_DIR)/udpfwd-fast.o: udpfwd.c
	$(CC) $(CFLAGS) -DDISABLE_ADAPTIVE_BATCHING -DDISABLE_RATE_LIMITING -DDISABLE_PACKET_VALIDATION -c -o $@ $<

# Ultra-fast version with minimal locking (single-threaded, no pthread)
udpfwd-ultra: $(BUILD_DIR)/udpfwd-ultra.o $(BUILD_DIR)/common.o $(BUILD_DIR)/fwd_util.o $(BUILD_DIR)/conn_pool.o $(NO_EPOLL_O)
	$(CC) $(CFLAGS) -o udpfwd-ultra $(BUILD_DIR)/udpfwd-ultra.o $(BUILD_DIR)/common.o $(BUILD_DIR)/fwd_util.o $(BUILD_DIR)/conn_pool.o $(NO_EPOLL_O) $(LDFLAGS)

$(BUILD_DIR)/udpfwd-ultra.o: udpfwd.c
	$(CC) $(CFLAGS) -DDISABLE_ADAPTIVE_BATCHING -DDISABLE_RATE_LIMITING -DDISABLE_PACKET_VALIDATION -DDISABLE_FINE_GRAINED_LOCKS -DDISABLE_LRU_LOCKS -DDISABLE_BACKPRESSURE_QUEUE -c -o $@ $<

# KCP-based TCP-over-UDP binaries with AEAD support
KCPOBJS = $(BUILD_DIR)/kcp_common.o $(BUILD_DIR)/3rd/kcp/ikcp.o
AEADOBJS = $(BUILD_DIR)/anti_replay.o $(BUILD_DIR)/secure_random.o $(BUILD_DIR)/outer_obfs.o $(BUILD_DIR)/3rd/chacha20poly1305/chacha20poly1305.o
KCPTCPOBJS = $(BUILD_DIR)/kcptcp_common.o

kcptcp-client: $(BUILD_DIR)/kcptcp_client.o $(KCPTCPOBJS) $(KCPOBJS) $(AEADOBJS) $(BUILD_DIR)/common.o $(BUILD_DIR)/conn_pool.o $(BUILD_DIR)/fwd_util.o $(NO_EPOLL_O)
	$(CC) $(CFLAGS) -o kcptcp-client $(BUILD_DIR)/kcptcp_client.o $(KCPTCPOBJS) $(KCPOBJS) $(AEADOBJS) $(BUILD_DIR)/common.o $(BUILD_DIR)/conn_pool.o $(BUILD_DIR)/fwd_util.o $(NO_EPOLL_O) $(LDFLAGS) $(LDFLAGS_PTHREAD)

kcptcp-server: $(BUILD_DIR)/kcptcp_server.o $(BUILD_DIR)/kcptcp_common.o $(BUILD_DIR)/kcp_map.o $(KCPOBJS) $(AEADOBJS) $(BUILD_DIR)/common.o $(BUILD_DIR)/conn_pool.o $(BUILD_DIR)/fwd_util.o $(NO_EPOLL_O)
	$(CC) $(CFLAGS) -o kcptcp-server $(BUILD_DIR)/kcptcp_server.o $(BUILD_DIR)/kcptcp_common.o $(BUILD_DIR)/kcp_map.o $(KCPOBJS) $(AEADOBJS) $(BUILD_DIR)/common.o $(BUILD_DIR)/conn_pool.o $(BUILD_DIR)/fwd_util.o $(NO_EPOLL_O) $(LDFLAGS) $(LDFLAGS_PTHREAD)

# Convenience aliases: allow underscored targets too
.PHONY: kcptcp_client kcptcp_server
kcptcp_client: kcptcp-client
	@:
kcptcp_server: kcptcp-server
	@:

# Object file compilation rules
$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/tcpfwd.o: tcpfwd.c common.h proxy_conn.h
$(BUILD_DIR)/udpfwd.o: udpfwd.c common.h proxy_conn.h
$(BUILD_DIR)/common.o: common.c common.h
$(BUILD_DIR)/no-epoll.o: no-epoll.c no-epoll.h
$(BUILD_DIR)/kcptcp_client.o: kcptcp_client.c common.h proxy_conn.h kcptcp_common.h
$(BUILD_DIR)/kcptcp_server.o: kcptcp_server.c common.h proxy_conn.h kcptcp_common.h
$(BUILD_DIR)/kcptcp_common.o: kcptcp_common.c kcptcp_common.h proxy_conn.h common.h
$(BUILD_DIR)/kcp_common.o: kcp_common.c kcp_common.h proxy_conn.h common.h
$(BUILD_DIR)/kcp_map.o: kcp_map.c kcp_map.h proxy_conn.h common.h

# AEAD and vendor chacha20poly1305
$(BUILD_DIR)/aead_protocol.o: aead_protocol.c aead_protocol.h proxy_conn.h kcptcp_common.h aead.h
$(BUILD_DIR)/anti_replay.o: anti_replay.c anti_replay.h
$(BUILD_DIR)/aead.o: aead.c aead.h 3rd/chacha20poly1305/chacha20poly1305.h
$(BUILD_DIR)/secure_random.o: secure_random.c secure_random.h
$(BUILD_DIR)/3rd/chacha20poly1305/chacha20poly1305.o: 3rd/chacha20poly1305/chacha20poly1305.c 3rd/chacha20poly1305/chacha20poly1305.h

# Placeholder KCP vendor objects
$(BUILD_DIR)/3rd/kcp/ikcp.o: 3rd/kcp/ikcp.c 3rd/kcp/ikcp.h

install: all
	mkdir -p $(PREFIX)/bin
	cp -vf tcpfwd udpfwd kcptcp-client kcptcp-server $(PREFIX)/bin/

clean:
	rm -f tcpfwd udpfwd kcptcp-client kcptcp-server
	rm -rf $(BUILD_DIR)
	rm -f 3rd/kcp/*.o 3rd/chacha20poly1305/*.o

