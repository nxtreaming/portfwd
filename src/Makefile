CC ?= $(CROSS_COMPILE)gcc
PREFIX ?= /usr/local
CFLAGS += -Wall -Wextra
# CFLAGS += -g

NO_EPOLL_O = 
ifeq ($(shell uname), Linux)
#LDFLAGS += -levent
else
NO_EPOLL_O = no-epoll.o
endif

all: tcpfwd udpfwd kcptcp-client kcptcp-server

tcpfwd: tcpfwd.o common.o $(NO_EPOLL_O)
	$(CC) $(CFLAGS) -o tcpfwd tcpfwd.o common.o $(NO_EPOLL_O) $(LDFLAGS)

udpfwd: udpfwd.o common.o $(NO_EPOLL_O)
	$(CC) $(CFLAGS) -o udpfwd udpfwd.o common.o $(NO_EPOLL_O) $(LDFLAGS)

# KCP-based TCP-over-UDP binaries with AEAD support
KCPOBJS = kcp_common.o 3rd/kcp/ikcp.o
AEADOBJS = aead_protocol.o aead.o 3rd/chacha20poly1305/chacha20poly1305.o
KCPTCPOBJS = kcptcp_common.o

kcptcp-client: kcptcp_client.o $(KCPTCPOBJS) $(KCPOBJS) $(AEADOBJS) common.o $(NO_EPOLL_O)
	$(CC) $(CFLAGS) -o kcptcp-client kcptcp_client.o $(KCPTCPOBJS) $(KCPOBJS) $(AEADOBJS) common.o $(NO_EPOLL_O) $(LDFLAGS)

kcptcp-server: kcptcp_server.o kcptcp_common.o kcp_map.o $(KCPOBJS) $(AEADOBJS) common.o $(NO_EPOLL_O)
	$(CC) $(CFLAGS) -o kcptcp-server kcptcp_server.o kcptcp_common.o kcp_map.o $(KCPOBJS) $(AEADOBJS) common.o $(NO_EPOLL_O) $(LDFLAGS)

# Convenience aliases: allow underscored targets too
.PHONY: kcptcp_client kcptcp_server
kcptcp_client: kcptcp-client
	@:
kcptcp_server: kcptcp-server
	@:

tcpfwd.o: tcpfwd.c common.h proxy_conn.h
udpfwd.o: udpfwd.c common.h proxy_conn.h
common.o: common.c common.h
no-epoll.o: no-epoll.c no-epoll.h
kcptcp_client.o: kcptcp_client.c common.h proxy_conn.h kcptcp_common.h
kcptcp_server.o: kcptcp_server.c common.h proxy_conn.h kcptcp_common.h
kctags:
	@:
kcptcp_common.o: kcptcp_common.c kcptcp_common.h proxy_conn.h common.h
kcp_common.o: kcp_common.c kcp_common.h proxy_conn.h common.h
kcp_map.o: kcp_map.c kcp_map.h proxy_conn.h common.h

# AEAD and vendor chacha20poly1305
aead_protocol.o: aead_protocol.c aead_protocol.h proxy_conn.h kcptcp_common.h aead.h
	$(CC) $(CFLAGS) -c -o aead_protocol.o aead_protocol.c

aead.o: aead.c aead.h 3rd/chacha20poly1305/chacha20poly1305.h
	$(CC) $(CFLAGS) -c -o aead.o aead.c
3rd/chacha20poly1305/chacha20poly1305.o: 3rd/chacha20poly1305/chacha20poly1305.c 3rd/chacha20poly1305/chacha20poly1305.h
	$(CC) $(CFLAGS) -c -o 3rd/chacha20poly1305/chacha20poly1305.o 3rd/chacha20poly1305/chacha20poly1305.c

# Placeholder KCP vendor objects
3rd/kcp/ikcp.o: 3rd/kcp/ikcp.c 3rd/kcp/ikcp.h
	$(CC) $(CFLAGS) -c -o 3rd/kcp/ikcp.o 3rd/kcp/ikcp.c

install: all
	mkdir -p $(PREFIX)/bin
	cp -vf tcpfwd udpfwd kcptcp-client kcptcp-server $(PREFIX)/bin/

clean:
	rm -f tcpfwd udpfwd kcptcp-client kcptcp-server *.o

