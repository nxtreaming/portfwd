#ifndef __PORTFWD_COMMON_H__
#define __PORTFWD_COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>

#ifdef __linux__
#include <sys/epoll.h>
#else
#include "no-epoll.h"
#endif

/* A sockaddr_in6 can hold both IPv4 and IPv6 addresses. */
union sockaddr_inx {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

extern const char *g_pidfile;
extern volatile sig_atomic_t g_terminate;

void on_signal(int sig);
void cleanup_pidfile(void);
void write_pidfile(const char *path);
int do_daemonize(void);

void setup_signal_handlers(void);
void set_nonblock(int fd);
void *addr_of_sockaddr(const union sockaddr_inx *addr);
const unsigned short *port_of_sockaddr(const union sockaddr_inx *addr);
size_t sizeof_sockaddr(const union sockaddr_inx *addr);
bool is_sockaddr_inx_equal(const union sockaddr_inx *a, const union sockaddr_inx *b);
int get_sockaddr_inx_pair(const char *pair, union sockaddr_inx *sa, bool is_udp);
void epoll_close_comp(int epfd);

#endif /* __PORTFWD_COMMON_H__ */
