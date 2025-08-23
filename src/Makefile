CC ?= $(CROSS_COMPILE)gcc
PREFIX ?= /usr/local
CFLAGS += -Wall -Wextra
# CFLAGS += -g

ifeq ($(shell uname), Linux)
#LDFLAGS += -levent
else
HEADERS += no-epoll.h
endif

all: tcpfwd udpfwd

tcpfwd: tcpfwd.o common.o
	$(CC) $(CFLAGS) -o tcpfwd tcpfwd.o common.o $(LDFLAGS)

udpfwd: udpfwd.o common.o
	$(CC) $(CFLAGS) -o udpfwd udpfwd.o common.o $(LDFLAGS)

tcpfwd.o: tcpfwd.c common.h no-epoll.h
udpfwd.o: udpfwd.c common.h no-epoll.h
common.o: common.c common.h no-epoll.h

install: all
	mkdir -p $(PREFIX)/bin
	cp -vf tcpfwd udpfwd $(PREFIX)/bin/

clean:
	rm -f tcpfwd udpfwd *.o

