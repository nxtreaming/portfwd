#ifndef __NO_EPOLL_H
#define __NO_EPOLL_H

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/select.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>

typedef union epoll_data {
    void *ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

struct epoll_event {
    uint32_t events; /* epoll events */
    epoll_data_t data; /* user data variable */
};


#define EPOLLIN       0x001
#define EPOLLOUT      0x004
#define EPOLLERR      0x008
#define EPOLLHUP      0x010
#define EPOLLRDHUP    0x2000
/* Edge-triggered flag is accepted but ignored in this select()-based shim */
#define EPOLLET       0x80000000u

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

struct pseudo_epoll_handle {
    struct pollfd *pfds;              /* dynamic array of pollfd */
    struct epoll_event *evs;          /* parallel epoll_event (stores .data) */
    size_t len;                        /* number of active fds */
    size_t cap;                        /* capacity of arrays */
};

static struct pseudo_epoll_handle **pseudo_epolls = NULL;
static size_t pseudo_epolls_cap = 0;

static int epoll_create(int size)
{
    (void)size;
    size_t i;
    /* Find a free slot */
    for (i = 0; i < pseudo_epolls_cap; i++) {
        if (pseudo_epolls[i] == NULL) {
            struct pseudo_epoll_handle *eh = (struct pseudo_epoll_handle *)calloc(1, sizeof(*eh));
            if (!eh) return -ENOMEM;
            eh->cap = 16;
            eh->pfds = (struct pollfd *)calloc(eh->cap, sizeof(struct pollfd));
            eh->evs = (struct epoll_event *)calloc(eh->cap, sizeof(struct epoll_event));
            if (!eh->pfds || !eh->evs) {
                free(eh->pfds); free(eh->evs); free(eh);
                return -ENOMEM;
            }
            pseudo_epolls[i] = eh;
            return (int)i;
        }
    }
    /* Need to grow registry */
    size_t old_cap = pseudo_epolls_cap;
    size_t new_cap = old_cap ? (old_cap + 8) : 8;
    void *np = realloc(pseudo_epolls, new_cap * sizeof(*pseudo_epolls));
    if (!np) return -ENOMEM;
    pseudo_epolls = (struct pseudo_epoll_handle **)np;
    for (i = old_cap; i < new_cap; i++) pseudo_epolls[i] = NULL;
    pseudo_epolls_cap = new_cap;
    /* Allocate first new slot */
    struct pseudo_epoll_handle *eh = (struct pseudo_epoll_handle *)calloc(1, sizeof(*eh));
    if (!eh) return -ENOMEM;
    eh->cap = 16;
    eh->pfds = (struct pollfd *)calloc(eh->cap, sizeof(struct pollfd));
    eh->evs = (struct epoll_event *)calloc(eh->cap, sizeof(struct epoll_event));
    if (!eh->pfds || !eh->evs) { free(eh->pfds); free(eh->evs); free(eh); return -ENOMEM; }
    pseudo_epolls[old_cap] = eh;
    return (int)old_cap;
}

static int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    if (epfd < 0 || (size_t)epfd >= pseudo_epolls_cap || !pseudo_epolls[epfd])
        return -EINVAL;
    struct pseudo_epoll_handle *eh = pseudo_epolls[epfd];

    /* find existing index */
    size_t idx;
    for (idx = 0; idx < eh->len; idx++) {
        if (eh->pfds[idx].fd == fd) break;
    }

    switch (op) {
    case EPOLL_CTL_ADD:
    case EPOLL_CTL_MOD: {
        /* Allow commonly used flags; unsupported ones are ignored here */
        if (!event) return -EINVAL;
        short pev = 0;
        if (event->events & EPOLLIN) pev |= POLLIN;
        if (event->events & EPOLLOUT) pev |= POLLOUT;

        if (idx == eh->len) {
            /* append */
            if (eh->len == eh->cap) {
                size_t ncap = eh->cap * 2;
                struct pollfd *npfds = (struct pollfd *)realloc(eh->pfds, ncap * sizeof(*npfds));
                struct epoll_event *nevs = (struct epoll_event *)realloc(eh->evs, ncap * sizeof(*nevs));
                if (!npfds || !nevs) {
                    /* realloc failure: free any successful allocation and preserve original */
                    if (npfds != eh->pfds) free(npfds);
                    if (nevs != eh->evs) free(nevs);
                    return -ENOMEM;
                }
                eh->pfds = npfds; eh->evs = nevs; eh->cap = ncap;
            }
            eh->pfds[eh->len].fd = fd;
            eh->pfds[eh->len].events = pev;
            eh->pfds[eh->len].revents = 0;
            eh->evs[eh->len] = *event; /* stores .data; events will be recomputed on wait */
            eh->len++;
        } else {
            eh->pfds[idx].events = pev;
            eh->evs[idx] = *event;
        }
        break;
    }
    case EPOLL_CTL_DEL: {
        if (idx == eh->len) return 0; /* not found */
        size_t last = eh->len - 1;
        if (idx != last) {
            eh->pfds[idx] = eh->pfds[last];
            eh->evs[idx] = eh->evs[last];
        }
        eh->len--;
        break;
    }
    default:
        fprintf(stderr, "*** Unsupported operation: %d\n", op);
        abort();
    }

    return 0;
}

static int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    if (epfd < 0 || (size_t)epfd >= pseudo_epolls_cap || !pseudo_epolls[epfd])
        return -EINVAL;
    struct pseudo_epoll_handle *eh = pseudo_epolls[epfd];

    int nfds = poll(eh->pfds, (nfds_t)eh->len, timeout);
    if (nfds <= 0) return nfds;

    int out = 0;
    for (size_t i = 0; i < eh->len && out < maxevents; i++) {
        if (eh->pfds[i].revents) {
            uint32_t evs = 0;
            if (eh->pfds[i].revents & (POLLIN | POLLHUP)) evs |= EPOLLIN; /* readable or hup */
            if (eh->pfds[i].revents & POLLOUT) evs |= EPOLLOUT;
            if (eh->pfds[i].revents & POLLERR) evs |= EPOLLERR;
            if (eh->pfds[i].revents & POLLHUP) evs |= EPOLLHUP;
            events[out] = eh->evs[i];
            events[out].events = evs;
            out++;
        }
    }
    return out;
}

#endif /* __NO_EPOLL_H */
