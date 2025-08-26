#ifndef __NO_EPOLL_H
#define __NO_EPOLL_H

#include <stdint.h>

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
#define EPOLLET       0x80000000u

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

int epoll_create(int size);
int epoll_close(int epfd);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

#endif /* __NO_EPOLL_H */
