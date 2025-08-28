CC ?= $(CROSS_COMPILE)gcc
CFLAGS += -Wall -Wextra -I.. -I../3rd/chacha20poly1305

# Reuse project objects for AEAD
AEADOBJS = ../aead.o ../3rd/chacha20poly1305/chacha20poly1305.o

all: test_aead test_replay

# Build unit tests as standalone binaries
# Note: run from this directory: make -C tests

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

test_aead: test_aead.o $(AEADOBJS)
	$(CC) $(CFLAGS) -o $@ test_aead.o $(AEADOBJS)

test_replay: test_replay.o
	$(CC) $(CFLAGS) -o $@ test_replay.o

clean:
	rm -f test_aead test_replay *.o
