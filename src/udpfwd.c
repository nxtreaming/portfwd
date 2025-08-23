#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <syslog.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#include "common.h"

#ifdef __linux__
    #include <sys/epoll.h>
    #include <sys/uio.h>
#else
    #define ERESTART 700
    #include "no-epoll.h"
#endif

typedef int bool;
#define true 1
#define false 0

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Tunables */
#ifndef UDP_PROXY_SOCKBUF_CAP
#define UDP_PROXY_SOCKBUF_CAP   (256 * 1024)
#endif
#ifdef __linux__
#ifndef UDP_PROXY_BATCH_SZ
#define UDP_PROXY_BATCH_SZ 16
#endif
#ifndef UDP_PROXY_DGRAM_CAP
#define UDP_PROXY_DGRAM_CAP 65536
#endif
#endif

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

#include <stddef.h>

#define container_of(ptr, type, member) ({          \
    const typeof(((type *)0)->member) * __mptr = (ptr); \
    (type *)((char *)__mptr - offsetof(type, member)); })

#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

struct list_head {
    struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
    struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
    list->next = list;
    list->prev = list;
}

static inline void __list_add(struct list_head *new,
                  struct list_head *prev,
                  struct list_head *next)
{
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
    __list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
    __list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
    next->prev = prev;
    prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    entry->next = LIST_POISON1;
    entry->prev = LIST_POISON2;
}

static inline int list_empty(const struct list_head *head)
{
    return head->next == head;
}

#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
    list_entry((ptr)->next, type, member)

#define list_next_entry(pos, member) \
    list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_for_each_entry(pos, head, member)              \
    for (pos = list_entry((head)->next, typeof(*pos), member);  \
         /*prefetch(pos->member.next),*/ &pos->member != (head);    \
         pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)          \
    for (pos = list_first_entry(head, typeof(*pos), member),    \
        n = list_next_entry(pos, member);           \
         &pos->member != (head);                    \
         pos = n, n = list_next_entry(n, member))

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

struct config {
    struct sockaddr_inx src_addr;
    struct sockaddr_inx dst_addr;
    const char *pidfile;
    unsigned proxy_conn_timeo;
    bool daemonize;
    bool v6only;
    bool reuseaddr;
};

#ifndef UDP_PROXY_MAX_CONNS
#define UDP_PROXY_MAX_CONNS   8192
#endif
#define CONN_TBL_HASH_SIZE  (1 << 8)
static struct list_head conn_tbl_hbase[CONN_TBL_HASH_SIZE];
static unsigned conn_tbl_len;

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/* Forward declarations */
static void proxy_conn_walk_continue(const struct config *cfg, unsigned walk_max, int epfd);
static bool proxy_conn_evict_one(int epfd);

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static void set_sock_buffers(int sockfd)
{
    int sz = UDP_PROXY_SOCKBUF_CAP;
    (void)setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    (void)setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
}

static bool is_sockaddr_inx_equal(struct sockaddr_inx *sa1, struct sockaddr_inx *sa2)
{
    if (sa1->sa.sa_family != sa2->sa.sa_family)
        return false;

    if (sa1->sa.sa_family == AF_INET) {
        if (sa1->in.sin_addr.s_addr != sa2->in.sin_addr.s_addr)
            return false;
        if (sa1->in.sin_port != sa2->in.sin_port)
            return false;
        return true;
    } else if (sa1->sa.sa_family == AF_INET6) {
        if (memcmp(&sa1->in6.sin6_addr, &sa2->in6.sin6_addr, sizeof(sa2->in6.sin6_addr)))
            return false;
        if (sa1->in6.sin6_port != sa2->in6.sin6_port)
            return false;
        return true;
    }

    return true;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/**
 * Connection tracking information to indicate
 *  a proxy session.
 */
struct proxy_conn {
    struct list_head list;
    time_t last_active;
    struct sockaddr_inx cli_addr;  /* <-- key */
    int svr_sock;
    struct list_head lru;          /* LRU linkage: oldest at head, newest at tail */
};

static unsigned int proxy_conn_hash(struct sockaddr_inx *sa)
{
    unsigned int hash = 0;

    if (sa->sa.sa_family == AF_INET) {
        hash = ntohl(sa->in.sin_addr.s_addr) + ntohs(sa->in.sin_port);
    } else if (sa->sa.sa_family == AF_INET6) {
        int i;
        for (i = 0; i < 4; i++)
            hash += ((uint32_t *)&sa->in6.sin6_addr)[i];
        hash += ntohs(sa->in6.sin6_port);
    }

    return hash;
}

/* Global LRU list for O(1) oldest selection */
static LIST_HEAD(g_lru_list);

static inline void touch_proxy_conn(struct proxy_conn *conn)
{
    /* Move to MRU (tail) and refresh timestamp */
    conn->last_active = time(NULL);
    list_del(&conn->lru);
    list_add_tail(&conn->lru, &g_lru_list);
}

static struct proxy_conn *proxy_conn_get_or_create(
        const struct config *cfg, struct sockaddr_inx *cli_addr, int epfd)
{
    struct list_head *chain = &conn_tbl_hbase[
        proxy_conn_hash(cli_addr) & (CONN_TBL_HASH_SIZE - 1)];
    struct proxy_conn *conn;
    int svr_sock = -1;
    struct epoll_event ev;
    char s_addr[50] = "";

    list_for_each_entry (conn, chain, list) {
        if (is_sockaddr_inx_equal(cli_addr, &conn->cli_addr)) {
            touch_proxy_conn(conn);
            return conn;
        }
    }

    /* Enforce connection cap before creating a new one */
    if (conn_tbl_len >= UDP_PROXY_MAX_CONNS) {
        /* First, aggressively recycle timeouts */
        proxy_conn_walk_continue(cfg, conn_tbl_len, epfd);
        if (conn_tbl_len >= UDP_PROXY_MAX_CONNS) {
            if (!proxy_conn_evict_one(epfd)) {
                inet_ntop(cli_addr->sa.sa_family, addr_of_sockaddr(cli_addr),
                          s_addr, sizeof(s_addr));
                syslog(LOG_WARNING, "Conn table full (%u). Drop %s:%d",
                       conn_tbl_len, s_addr, ntohs(port_of_sockaddr(cli_addr)));
                goto err;
            }
        }
    }

    /* ------------------------------------------ */
    /* Establish the server-side connection */
    if ((svr_sock = socket(cfg->dst_addr.sa.sa_family, SOCK_DGRAM, 0)) < 0) {
        syslog(LOG_ERR, "*** socket(svr_sock): %s", strerror(errno));
        goto err;
    }
    /* Connect to real server. */
    if (connect(svr_sock, (struct sockaddr *)&cfg->dst_addr,
            sizeof_sockaddr(&cfg->dst_addr)) != 0) {
        /* Error occurs, drop the session. */
        syslog(LOG_WARNING, "Connection failed: %s", strerror(errno));
        goto err;
    }
    set_nonblock(svr_sock);
    set_sock_buffers(svr_sock);

    /* Allocate session data for the connection */
    if ((conn = malloc(sizeof(*conn))) == NULL) {
        syslog(LOG_ERR, "*** malloc(conn): %s", strerror(errno));
        goto err;
    }
    memset(conn, 0x0, sizeof(*conn));
    conn->svr_sock = svr_sock;
    conn->cli_addr = *cli_addr;
    INIT_LIST_HEAD(&conn->lru);

    ev.data.ptr = conn;
    ev.events = EPOLLIN;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, conn->svr_sock, &ev) < 0) {
        syslog(LOG_ERR, "epoll_ctl(ADD, svr_sock): %s", strerror(errno));
        goto err;
    }
    /* ------------------------------------------ */

    list_add_tail(&conn->list, chain);
    list_add_tail(&conn->lru, &g_lru_list);
    conn_tbl_len++;

    inet_ntop(cli_addr->sa.sa_family, addr_of_sockaddr(cli_addr),
            s_addr, sizeof(s_addr));
    syslog(LOG_INFO, "New connection %s:%d [%u]",
            s_addr, ntohs(port_of_sockaddr(cli_addr)), conn_tbl_len);

    conn->last_active = time(NULL);
    return conn;

err:
    if (svr_sock >= 0)
        close(svr_sock);
    if (conn)
        free(conn);
    return NULL;
}

/**
 * Close both sockets of the connection and remove it
 * from the current ready list.
 */
static void release_proxy_conn(struct proxy_conn *conn, int epfd)
{
    list_del(&conn->list);
    conn_tbl_len--;
    /* remove from LRU as well */
    list_del(&conn->lru);
    if (epoll_ctl(epfd, EPOLL_CTL_DEL, conn->svr_sock, NULL) < 0 && errno != EBADF) {
        syslog(LOG_DEBUG, "epoll_ctl(DEL, svr_sock): %s", strerror(errno));
    }
    close(conn->svr_sock);
    free(conn);
}

static void proxy_conn_walk_continue(const struct config *cfg, unsigned walk_max, int epfd)
{
    unsigned walked = 0;
    time_t now = time(NULL);
    while (walked < walk_max && !list_empty(&g_lru_list)) {
        struct proxy_conn *oldest = list_first_entry(&g_lru_list, struct proxy_conn, lru);
        if ((unsigned)(now - oldest->last_active) <= cfg->proxy_conn_timeo)
            break; /* oldest not expired -> none later are expired */
        {
            struct sockaddr_inx addr = oldest->cli_addr;
            char s_addr[50] = "";
            release_proxy_conn(oldest, epfd);
            inet_ntop(addr.sa.sa_family, addr_of_sockaddr(&addr), s_addr, sizeof(s_addr));
            syslog(LOG_INFO, "Recycled %s:%d [%u]",
                   s_addr, ntohs(port_of_sockaddr(&addr)), conn_tbl_len);
        }
        walked++;
    }
}

/* Evict the least recently active connection (LRU-ish across all buckets). */
static bool proxy_conn_evict_one(int epfd)
{
    if (list_empty(&g_lru_list))
        return false;
    {
        struct proxy_conn *oldest = list_first_entry(&g_lru_list, struct proxy_conn, lru);
        struct sockaddr_inx addr = oldest->cli_addr;
        char s_addr[50] = "";
        release_proxy_conn(oldest, epfd);
        inet_ntop(addr.sa.sa_family, addr_of_sockaddr(&addr), s_addr, sizeof(s_addr));
        syslog(LOG_WARNING, "Evicted LRU %s:%d [%u]",
               s_addr, ntohs(port_of_sockaddr(&addr)), conn_tbl_len);
    }
    return true;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static void show_help(int argc, char *argv[])
{
    (void)argc; /* unused */
    printf("Userspace UDP proxy.\n");
    printf("Usage:\n");
    printf("  %s <local_ip:local_port> <dest_ip:dest_port> [options]\n", argv[0]);
    printf("Examples:\n");
    printf("  %s 0.0.0.0:10000 10.0.0.1:20000\n", argv[0]);
    printf("  %s [::]:10000 [2001:db8::1]:20000\n", argv[0]);
    printf("Options:\n");
    printf("  -t <seconds>     proxy session timeout (default: %u)\n", 60);
    printf("  -d               run in background\n");
    printf("  -o               IPv6 listener accepts IPv6 only (sets IPV6_V6ONLY)\n");
    printf("  -r               set SO_REUSEADDR before binding local port\n");
    printf("  -p <pidfile>     write PID to file\n");
}

int main(int argc, char *argv[])
{
    int opt, b_true = 1, lsn_sock, epfd, i;
    struct config cfg;
    struct epoll_event ev, events[1024];
    char buffer[1024 * 64], s_addr1[50] = "", s_addr2[50] = "";
    time_t last_check;

    memset(&cfg, 0, sizeof(cfg));
    cfg.proxy_conn_timeo = 60; /* default */
#ifdef __linux__
    /* Batching resources (allocated at runtime) */
    struct mmsghdr *c_msgs = NULL;          /* client -> server */
    struct iovec   *c_iov = NULL;
    struct sockaddr_storage *c_addrs = NULL;
    char          (*c_bufs)[UDP_PROXY_DGRAM_CAP] = NULL;
#endif

    while ((opt = getopt(argc, argv, "t:dhorp:")) != -1) {
        switch (opt) {
        case 't':
            cfg.proxy_conn_timeo = strtoul(optarg, NULL, 10);
            break;
        case 'd':
            cfg.daemonize = true;
            break;
        case 'h':
            show_help(argc, argv);
            exit(0);
            break;
        case 'o':
            cfg.v6only = true;
            break;
        case 'r':
            cfg.reuseaddr = true;
            break;
        case 'p':
            cfg.pidfile = optarg;
            break;
        case '?':
            exit(1);
        }
    }

    if (optind > argc - 2) {
        show_help(argc, argv);
        exit(1);
    }

    /* Resolve source address */
    if (get_sockaddr_inx_pair(argv[optind], &cfg.src_addr, true) < 0) {
        fprintf(stderr, "*** Invalid source address '%s'.\n", argv[optind]);
        exit(1);
    }
    optind++;

    /* Resolve destination addresse */
    if (get_sockaddr_inx_pair(argv[optind], &cfg.dst_addr, true) < 0) {
        fprintf(stderr, "*** Invalid destination address '%s'.\n", argv[optind]);
        exit(1);
    }
    optind++;

    openlog("udpfwd", LOG_PERROR|LOG_NDELAY, LOG_USER);

    lsn_sock = socket(cfg.src_addr.sa.sa_family, SOCK_DGRAM, 0);
    if (lsn_sock < 0) {
        fprintf(stderr, "*** socket(): %s.\n", strerror(errno));
        exit(1);
    }
    if (cfg.reuseaddr)
        setsockopt(lsn_sock, SOL_SOCKET, SO_REUSEADDR, &b_true, sizeof(b_true));
    if (cfg.src_addr.sa.sa_family == AF_INET6 && cfg.v6only)
        setsockopt(lsn_sock, IPPROTO_IPV6, IPV6_V6ONLY, &b_true, sizeof(b_true));
    if (bind(lsn_sock, (struct sockaddr *)&cfg.src_addr,
            sizeof_sockaddr(&cfg.src_addr)) < 0) {
        fprintf(stderr, "*** bind(): %s.\n", strerror(errno));
        exit(1);
    }
    set_nonblock(lsn_sock);
    set_sock_buffers(lsn_sock);

    inet_ntop(cfg.src_addr.sa.sa_family, addr_of_sockaddr(&cfg.src_addr),
            s_addr1, sizeof(s_addr1));
    inet_ntop(cfg.dst_addr.sa.sa_family, addr_of_sockaddr(&cfg.dst_addr),
            s_addr2, sizeof(s_addr2));
    syslog(LOG_INFO, "UDP proxy [%s]:%d -> [%s]:%d",
            s_addr1, ntohs(port_of_sockaddr(&cfg.src_addr)),
            s_addr2, ntohs(port_of_sockaddr(&cfg.dst_addr)));

    /* Create epoll table. */
    if ((epfd = epoll_create(2048)) < 0) {
        syslog(LOG_ERR, "epoll_create(): %s", strerror(errno));
        exit(1);
    }

    if (cfg.daemonize)
        do_daemonize();
    if (cfg.pidfile)
        write_pidfile(cfg.pidfile);

    setup_signal_handlers();

    /* Initialize the connection table */
    for (i = 0; i < CONN_TBL_HASH_SIZE; i++)
        INIT_LIST_HEAD(&conn_tbl_hbase[i]);
    conn_tbl_len = 0;

    last_check = time(NULL);

    /* Optional Linux batching init */
#ifdef __linux__
    c_msgs = calloc(UDP_PROXY_BATCH_SZ, sizeof(*c_msgs));
    c_iov = calloc(UDP_PROXY_BATCH_SZ, sizeof(*c_iov));
    c_addrs = calloc(UDP_PROXY_BATCH_SZ, sizeof(*c_addrs));
    c_bufs = calloc(UDP_PROXY_BATCH_SZ, sizeof(*c_bufs));
    if (!c_msgs || !c_iov || !c_addrs || !c_bufs) {
        free(c_msgs); free(c_iov); free(c_addrs); free(c_bufs);
        c_msgs = NULL; c_iov = NULL; c_addrs = NULL; c_bufs = NULL;
    } else {
        for (i = 0; i < UDP_PROXY_BATCH_SZ; i++) {
            memset(&c_addrs[i], 0, sizeof(c_addrs[i]));
            c_iov[i].iov_base = c_bufs[i];
            c_iov[i].iov_len = UDP_PROXY_DGRAM_CAP;
            c_msgs[i].msg_hdr.msg_iov = &c_iov[i];
            c_msgs[i].msg_hdr.msg_iovlen = 1;
            c_msgs[i].msg_hdr.msg_name = &c_addrs[i];
            c_msgs[i].msg_hdr.msg_namelen = sizeof(c_addrs[i]);
        }
    }
#endif

    /* epoll loop */
    ev.data.ptr = NULL;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, lsn_sock, &ev) < 0) {
        syslog(LOG_ERR, "epoll_ctl(ADD, listener): %s", strerror(errno));
        exit(1);
    }

    for (;;) {
        int nfds;
        time_t current_ts = time(NULL);

        /* Timeout check and recycle */
        if ((unsigned)(current_ts - last_check) >= 2) {
            proxy_conn_walk_continue(&cfg, 200, epfd);
            last_check = current_ts;
        }

        nfds = epoll_wait(epfd, events, countof(events), 1000 * 2);
        if (nfds == 0)
            continue;
        if (nfds < 0) {
            if (errno == EINTR || errno == ERESTART)
                continue;
            syslog(LOG_ERR, "*** epoll_wait(): %s", strerror(errno));
            exit(1);
        }

        if (g_terminate)
            break;

        for (i = 0; i < nfds; i++) {
            struct epoll_event *evp = &events[i];
            struct proxy_conn *conn;
            int r;

            if (evp->data.ptr == NULL) {
                /* Data from client */
                if (evp->events & (EPOLLERR | EPOLLHUP)) {
                    syslog(LOG_WARNING, "listener: EPOLLERR/HUP");
                    continue;
                }
                struct sockaddr_inx cli_addr;
                socklen_t cli_alen = sizeof(cli_addr);
#ifdef __linux__
                if (c_msgs) {
                    int j, n = recvmmsg(lsn_sock, c_msgs, UDP_PROXY_BATCH_SZ, 0, NULL);
                    if (n < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                            continue;
                        syslog(LOG_WARNING, "recvmmsg(): %s", strerror(errno));
                        continue;
                    }
                    for (j = 0; j < n; j++) {
                        struct sockaddr_inx *sa = (struct sockaddr_inx *)c_msgs[j].msg_hdr.msg_name;
                        ssize_t len = c_msgs[j].msg_len;
                        if (!(conn = proxy_conn_get_or_create(&cfg, sa, epfd)))
                            continue;
                        touch_proxy_conn(conn);
                        {
                            ssize_t wr = send(conn->svr_sock, c_bufs[j], len, 0);
                            if (wr < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                                syslog(LOG_WARNING, "send(server): %s", strerror(errno));
                            }
                        }
                    }
                    continue;
                }
#endif
                r = recvfrom(lsn_sock, buffer, sizeof(buffer), 0,
                        (struct sockaddr *)&cli_addr, &cli_alen);
                if (r < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                        continue; /* transient, try later */
                    syslog(LOG_WARNING, "recvfrom(): %s", strerror(errno));
                    continue; /* drop this datagram and move on */
                }
                if (!(conn = proxy_conn_get_or_create(&cfg, &cli_addr, epfd)))
                    continue;
                /* refresh activity */
                touch_proxy_conn(conn);
                {
                    ssize_t wr = send(conn->svr_sock, buffer, r, 0);
                    if (wr < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                        syslog(LOG_WARNING, "send(server): %s", strerror(errno));
                    }
                }
            } else {
                /* Data from server */
                conn = (struct proxy_conn *)evp->data.ptr;
                if (evp->events & (EPOLLERR | EPOLLHUP)) {
                    /* fatal on this flow: release session */
                    release_proxy_conn(conn, epfd);
                    continue;
                }
                for (;;) {
                    r = recv(conn->svr_sock, buffer, sizeof(buffer), 0);
                    if (r < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                            break; /* drained */
                        syslog(LOG_WARNING, "recv(server): %s", strerror(errno));
                        /* fatal error on server socket: close session */
                        release_proxy_conn(conn, epfd);
                        break;
                    }
                    /* r >= 0: forward even zero-length datagrams */
                    touch_proxy_conn(conn);
                    {
                        ssize_t wr = sendto(lsn_sock, buffer, r, 0, (struct sockaddr *)&conn->cli_addr,
                                sizeof_sockaddr(&conn->cli_addr));
                        if (wr < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                            syslog(LOG_WARNING, "sendto(client): %s", strerror(errno));
                        }
                    }
                    if (r == 0)
                        break;
                }
            }
        }
    }

    close(lsn_sock);
    epoll_close_comp(epfd);

    return 0;
}
