CC ?= $(CROSS_COMPILE)gcc
CFLAGS += -Wall -Wextra -I.. -I../3rd/chacha20poly1305

# Reuse project objects for AEAD
AEADOBJS = ../3rd/chacha20poly1305/chacha20poly1305.o

all: test_handshake test_stealth_handshake test_outer_obfs_handshake test_outer_obfs_kcp tcp_echo it_kcp test_timestamp_burst

# Build unit tests as standalone binaries
# Note: run from this directory: make -C tests

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<



test_handshake: test_handshake.o ../3rd/chacha20poly1305/chacha20poly1305.o
	$(CC) $(CFLAGS) -o $@ test_handshake.o ../3rd/chacha20poly1305/chacha20poly1305.o

test_stealth_handshake: test_stealth_handshake.o ../kcptcp_common.o ../3rd/chacha20poly1305/chacha20poly1305.o ../secure_random.o
	$(CC) $(CFLAGS) -o $@ test_stealth_handshake.o ../kcptcp_common.o ../3rd/chacha20poly1305/chacha20poly1305.o ../secure_random.o

test_outer_obfs_handshake: test_outer_obfs_handshake.o ../outer_obfs.o ../kcptcp_common.o ../3rd/chacha20poly1305/chacha20poly1305.o ../secure_random.o
	$(CC) $(CFLAGS) -o $@ test_outer_obfs_handshake.o ../outer_obfs.o ../kcptcp_common.o ../3rd/chacha20poly1305/chacha20poly1305.o ../secure_random.o

test_outer_obfs_kcp: test_outer_obfs_kcp.o ../outer_obfs.o ../3rd/chacha20poly1305/chacha20poly1305.o ../secure_random.o
	$(CC) $(CFLAGS) -o $@ test_outer_obfs_kcp.o ../outer_obfs.o ../3rd/chacha20poly1305/chacha20poly1305.o ../secure_random.o

tcp_echo: tcp_echo.o
	$(CC) $(CFLAGS) -o $@ tcp_echo.o

it_kcp: it_kcp.o
	$(CC) $(CFLAGS) -o $@ it_kcp.o

test_timestamp_burst: test_timestamp_burst.o
	$(CC) $(CFLAGS) -o $@ test_timestamp_burst.o

clean:
	rm -f test_aead test_replay test_handshake test_stealth_handshake tcp_echo it_kcp test_timestamp_burst *.o
