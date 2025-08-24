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

all: tcpfwd udpfwd

tcpfwd: tcpfwd.o common.o $(NO_EPOLL_O)
	$(CC) $(CFLAGS) -o tcpfwd tcpfwd.o common.o $(NO_EPOLL_O) $(LDFLAGS)

udpfwd: udpfwd.o common.o $(NO_EPOLL_O)
	$(CC) $(CFLAGS) -o udpfwd udpfwd.o common.o $(NO_EPOLL_O) $(LDFLAGS)

tcpfwd.o: tcpfwd.c common.h proxy_conn.h
udpfwd.o: udpfwd.c common.h proxy_conn.h
common.o: common.c common.h
no-epoll.o: no-epoll.c no-epoll.h

install: all
	mkdir -p $(PREFIX)/bin
	cp -vf tcpfwd udpfwd $(PREFIX)/bin/

clean:
	rm -f tcpfwd udpfwd *.o

