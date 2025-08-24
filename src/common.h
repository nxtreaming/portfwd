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
#include <syslog.h>

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

struct app_state {
    const char *pidfile;
    int pidfile_fd;
    volatile sig_atomic_t terminate;
    bool daemonized;
};

extern struct app_state g_state;

void on_signal(int sig);
void cleanup_pidfile(void);
int write_pidfile(const char *path);
int do_daemonize(void);

void setup_signal_handlers(void);
void set_nonblock(int fd);
void *addr_of_sockaddr(const union sockaddr_inx *addr);
const unsigned short *port_of_sockaddr(const union sockaddr_inx *addr);
size_t sizeof_sockaddr(const union sockaddr_inx *addr);
bool is_sockaddr_inx_equal(const union sockaddr_inx *a, const union sockaddr_inx *b);
int get_sockaddr_inx_pair(const char *pair, union sockaddr_inx *sa, bool is_udp);
void epoll_close_comp(int epfd);
static inline int ep_add_or_mod(int epfd, int sock, struct epoll_event *ev)
{
    /* First, try to modify an existing file descriptor. */
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, sock, ev) == 0) {
        return 0; /* Success */
    }

    /* If the descriptor was not found, try to add it. */
    if (errno == ENOENT) {
        return epoll_ctl(epfd, EPOLL_CTL_ADD, sock, ev);
    }

    /* Any other error is a failure. */
    return -1;
}

/* Standardized logging macros */
#define LOG_MSG(level, fmt, ...) do { \
    if (g_state.daemonized) \
        syslog(level, fmt, ##__VA_ARGS__); \
    else \
        fprintf(stderr, fmt "\n", ##__VA_ARGS__); \
} while(0)

#define P_LOG_ERR(fmt, ...) LOG_MSG(LOG_ERR, "ERROR: " fmt, ##__VA_ARGS__)
#define P_LOG_WARN(fmt, ...) LOG_MSG(LOG_WARNING, "WARN: " fmt, ##__VA_ARGS__)
#define P_LOG_INFO(fmt, ...) LOG_MSG(LOG_INFO, fmt, ##__VA_ARGS__)

#endif /* __PORTFWD_COMMON_H__ */
