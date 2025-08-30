CC ?= $(CROSS_COMPILE)gcc
CFLAGS += -Wall -Wextra -I.. -I../3rd/chacha20poly1305

# Reuse project objects for AEAD
AEADOBJS = ../aead.o ../anti_replay.o ../3rd/chacha20poly1305/chacha20poly1305.o

all: test_aead test_replay test_handshake tcp_echo it_kcp

# Build unit tests as standalone binaries
# Note: run from this directory: make -C tests

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

test_aead: test_aead.o $(AEADOBJS)
	$(CC) $(CFLAGS) -o $@ test_aead.o $(AEADOBJS)

test_replay: test_replay.o
	$(CC) $(CFLAGS) -o $@ test_replay.o

test_handshake: test_handshake.o ../3rd/chacha20poly1305/chacha20poly1305.o
	$(CC) $(CFLAGS) -o $@ test_handshake.o ../3rd/chacha20poly1305/chacha20poly1305.o

tcp_echo: tcp_echo.o
	$(CC) $(CFLAGS) -o $@ tcp_echo.o

it_kcp: it_kcp.o
	$(CC) $(CFLAGS) -o $@ it_kcp.o

clean:
	rm -f test_aead test_replay test_handshake tcp_echo it_kcp *.o
