#define _GNU_SOURCE 1

#include "common.h"
#include "list.h"
#include "proxy_conn.h"

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
#include <stdbool.h>

#ifdef __linux__
#include <sys/epoll.h>
#include <sys/uio.h>
#else
#define ERESTART 700
#include "no-epoll.h"
#endif

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Constants and Tunables */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))
#define MAX_EVENTS 1024

/* Socket buffer size */
#ifndef UDP_PROXY_SOCKBUF_CAP
#define UDP_PROXY_SOCKBUF_CAP (256 * 1024)
#endif

/* Linux-specific batching parameters */
#ifdef __linux__
#ifndef UDP_PROXY_BATCH_SZ
#define UDP_PROXY_BATCH_SZ 16
#endif
#ifndef UDP_PROXY_DGRAM_CAP
/* Max safe UDP payload size: 65535 - 8 (UDP header) - 20 (IPv4 header) */
#define UDP_PROXY_DGRAM_CAP 65507
#endif
#endif

/* Hash function constants */
#define FNV_PRIME_32 16777619
#define FNV_OFFSET_BASIS_32 2166136261U

/* Connection pool size */
#ifndef UDP_PROXY_MAX_CONNS
#define UDP_PROXY_MAX_CONNS 4096
#endif

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Data Structures */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

struct config {
    union sockaddr_inx src_addr;
    union sockaddr_inx dst_addr;
    const char *pidfile;
    unsigned proxy_conn_timeo;
    unsigned conn_tbl_hash_size;
    bool daemonize;
    bool v6only;
    bool reuse_addr;
    bool reuse_port;
};

struct conn_pool {
    struct proxy_conn *connections;
    struct proxy_conn *freelist;
    int capacity;
    int used_count;
};

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Global Variables */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/* Connection hash table */
static struct list_head *conn_tbl_hbase;
static unsigned g_conn_tbl_hash_size;
static unsigned conn_tbl_len;

/* Connection pool */
static struct conn_pool g_conn_pool;

/* Runtime tunables (overridable via CLI) */
static int g_sockbuf_cap_runtime = UDP_PROXY_SOCKBUF_CAP;
static int g_conn_pool_capacity = UDP_PROXY_MAX_CONNS;
#ifdef __linux__
static int g_batch_sz_runtime = UDP_PROXY_BATCH_SZ;
#endif

/* Global LRU list for O(1) oldest selection */
static LIST_HEAD(g_lru_list);

/* Cached current timestamp (monotonic seconds on Linux) for hot paths */
static time_t g_now_ts;

/* Function pointer to compute bucket index from a 32-bit hash */
static unsigned int (*bucket_index_fun)(const union sockaddr_inx *);

/* Stats: batch overflow immediate-sends (client->server) */
static uint64_t g_stat_c2s_batch_socket_overflow;
static uint64_t g_stat_c2s_batch_entry_overflow;

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Utility Functions */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/* Simple monotonic-seconds helper (Linux) with portable fallback */
static inline time_t monotonic_seconds(void) {
#ifdef __linux__
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (time_t)ts.tv_sec;
    /* Fallback if clock_gettime fails */
#endif
    return time(NULL);
}

static int safe_close(int fd) {
    if (fd < 0)
        return 0;
    for (;;) {
        if (close(fd) == 0)
            return 0;
        if (errno == EINTR)
            continue;
        return -1;
    }
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Function Declarations */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/* Hash functions */
static uint32_t hash_addr(const union sockaddr_inx *a);

/* Connection management */
static struct proxy_conn *alloc_proxy_conn(void);
static void release_proxy_conn_to_pool(struct proxy_conn *conn);
static void proxy_conn_walk_continue(const struct config *cfg,
                                     unsigned walk_max, int epfd);
static bool proxy_conn_evict_one(int epfd);

/* Data handling */
static void handle_server_data(struct proxy_conn *conn, int lsn_sock, int epfd);
#ifdef __linux__
static void handle_client_data(const struct config *cfg, int lsn_sock, int epfd,
                               struct mmsghdr *c_msgs, struct mmsghdr *s_msgs,
                               struct iovec *s_iovs,
                               char (*c_bufs)[UDP_PROXY_DGRAM_CAP]);
#else
static void handle_client_data(const struct config *cfg, int lsn_sock,
                               int epfd);
#endif

/* Linux batching support */
#ifdef __linux__
static void init_batching_resources(struct mmsghdr **c_msgs,
                                    struct iovec **c_iov,
                                    struct sockaddr_storage **c_addrs,
                                    char (**c_bufs)[UDP_PROXY_DGRAM_CAP],
                                    struct mmsghdr **s_msgs,
                                    struct iovec **s_iovs);

static void destroy_batching_resources(struct mmsghdr *c_msgs,
                                       struct iovec *c_iov,
                                       struct sockaddr_storage *c_addrs,
                                       char (*c_bufs)[UDP_PROXY_DGRAM_CAP],
                                       struct mmsghdr *s_msgs,
                                       struct iovec *s_iovs);
#endif

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Connection Pool Management */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static int init_conn_pool(void) {
    g_conn_pool.capacity =
        (g_conn_pool_capacity > 0) ? g_conn_pool_capacity : UDP_PROXY_MAX_CONNS;
    g_conn_pool.connections =
        malloc(sizeof(struct proxy_conn) * (size_t)g_conn_pool.capacity);
    if (!g_conn_pool.connections) {
        P_LOG_ERR("Failed to allocate connection pool");
        return -1;
    }

    g_conn_pool.freelist = NULL;
    for (int i = 0; i < g_conn_pool.capacity; i++) {
        struct proxy_conn *conn = &g_conn_pool.connections[i];
        conn->next = g_conn_pool.freelist;
        g_conn_pool.freelist = conn;
    }
    g_conn_pool.used_count = 0;
    P_LOG_INFO("Connection pool initialized with %d connections",
               g_conn_pool.capacity);
    return 0;
}

/* Small helper to check if an unsigned value is a power of two */
static inline bool is_power_of_two(unsigned v) {
    return v && ((v & (v - 1)) == 0);
}

/* Bucket index strategies (selected once at init) */
static unsigned int proxy_conn_hash_bitwise(const union sockaddr_inx *sa) {
    uint32_t h = hash_addr(sa);
    return h & (g_conn_tbl_hash_size - 1);
}

static unsigned int proxy_conn_hash_mod(const union sockaddr_inx *sa) {
    uint32_t h = hash_addr(sa);
    return h % g_conn_tbl_hash_size;
}

static void destroy_conn_pool(void) {
    if (g_conn_pool.connections) {
        free(g_conn_pool.connections);
        g_conn_pool.connections = NULL;
        P_LOG_INFO("Connection pool destroyed.");
    }
}

static struct proxy_conn *alloc_proxy_conn(void) {
    if (!g_conn_pool.freelist) {
        P_LOG_WARN("Connection pool exhausted!");
        return NULL;
    }
    struct proxy_conn *conn = g_conn_pool.freelist;
    g_conn_pool.freelist = conn->next;
    g_conn_pool.used_count++;
    assert(g_conn_pool.used_count <= g_conn_pool.capacity);
    memset(conn, 0, sizeof(*conn));
    return conn;
}

static void release_proxy_conn_to_pool(struct proxy_conn *conn) {
    conn->next = g_conn_pool.freelist;
    g_conn_pool.freelist = conn;
    assert(g_conn_pool.used_count > 0);
    g_conn_pool.used_count--;
}

static void set_sock_buffers(int sockfd) {
    int sz = g_sockbuf_cap_runtime;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)) < 0) {
        P_LOG_WARN("setsockopt(SO_RCVBUF): %s", strerror(errno));
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)) < 0) {
        P_LOG_WARN("setsockopt(SO_SNDBUF): %s", strerror(errno));
    }
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Hash Functions */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static uint32_t fnv1a_32_hash(const void *data, size_t len) {
    uint32_t hash = FNV_OFFSET_BASIS_32;
    const unsigned char *p = (const unsigned char *)data;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint32_t)p[i];
        hash *= FNV_PRIME_32;
    }
    return hash;
}

static uint32_t hash_addr(const union sockaddr_inx *a) {
    if (a->sa.sa_family == AF_INET) {
        struct {
            uint32_t addr;
            uint16_t port;
        } k;
        memset(&k, 0, sizeof(k));
        k.addr = a->sin.sin_addr.s_addr;
        k.port = a->sin.sin_port;
        return fnv1a_32_hash(&k, sizeof(k));
    } else if (a->sa.sa_family == AF_INET6) {
        struct {
            struct in6_addr addr;
            uint16_t port;
            uint32_t scope;
        } k;
        memset(&k, 0, sizeof(k));
        k.addr = a->sin6.sin6_addr;
        k.port = a->sin6.sin6_port;
        k.scope = a->sin6.sin6_scope_id;
        return fnv1a_32_hash(&k, sizeof(k));
    }
    return 0;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Connection Management */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static inline void touch_proxy_conn(struct proxy_conn *conn) {
    /* Move to MRU (tail) and refresh timestamp */
    time_t snap = g_now_ts;
    conn->last_active = snap ? snap : monotonic_seconds();
    list_del(&conn->lru);
    list_add_tail(&conn->lru, &g_lru_list);
}

static struct proxy_conn *
proxy_conn_get_or_create(const struct config *cfg,
                         const union sockaddr_inx *cli_addr, int epfd) {
    struct list_head *chain = &conn_tbl_hbase[bucket_index_fun(cli_addr)];
    struct proxy_conn *conn = NULL;
    int svr_sock = -1;
    struct epoll_event ev;
    char s_addr[50] = "";

    list_for_each_entry(conn, chain, list) {
        if (is_sockaddr_inx_equal(cli_addr, &conn->cli_addr)) {
            touch_proxy_conn(conn);
            return conn;
        }
    }

    /* Enforce connection capacity */
    if (conn_tbl_len >= (unsigned)g_conn_pool.capacity) {
        /* First, try to recycle any timed-out connections */
        proxy_conn_walk_continue(cfg, conn_tbl_len, epfd);

        /* If still full, try to evict the oldest connection */
        if (conn_tbl_len >= (unsigned)g_conn_pool.capacity) {
            proxy_conn_evict_one(epfd);
        }

        /* If still full after all attempts, drop the new connection */
        if (conn_tbl_len >= (unsigned)g_conn_pool.capacity) {
            inet_ntop(cli_addr->sa.sa_family, addr_of_sockaddr(cli_addr),
                      s_addr, sizeof(s_addr));
            P_LOG_WARN("Conn table full (%u), dropping %s:%d", conn_tbl_len,
                       s_addr, ntohs(*port_of_sockaddr(cli_addr)));
            goto err;
        }
    }

    /* High-water one-time warning at ~90% capacity */
    static bool warned_high_water = false;
    if (!warned_high_water && g_conn_pool.capacity > 0 &&
        conn_tbl_len >= (unsigned)((g_conn_pool.capacity * 9) / 10)) {
        P_LOG_WARN(
            "UDP conn table high-water: %u/%d (~%d%%). Consider raising -C or "
            "reducing -t.",
            conn_tbl_len, g_conn_pool.capacity,
            (int)((conn_tbl_len * 100) / (unsigned)g_conn_pool.capacity));
        warned_high_water = true;
    }

    /* ------------------------------------------ */
    /* Establish the server-side connection */
    if ((svr_sock = socket(cfg->dst_addr.sa.sa_family, SOCK_DGRAM, 0)) < 0) {
        P_LOG_ERR("socket(svr_sock): %s", strerror(errno));
        goto err;
    }
    /* Connect to real server. */
    if (connect(svr_sock, (struct sockaddr *)&cfg->dst_addr,
                sizeof_sockaddr(&cfg->dst_addr)) != 0) {
        /* Error occurs, drop the session. */
        P_LOG_WARN("Connection failed: %s", strerror(errno));
        goto err;
    }
    set_nonblock(svr_sock);
    set_sock_buffers(svr_sock);

    /* Allocate session data for the connection */
    if ((conn = alloc_proxy_conn()) == NULL) {
        P_LOG_ERR("malloc(conn): %s", strerror(errno));
        goto err;
    }
    conn->svr_sock = svr_sock;
    conn->cli_addr = *cli_addr;
    INIT_LIST_HEAD(&conn->lru);

    ev.data.ptr = conn;
    ev.events = EPOLLIN;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, conn->svr_sock, &ev) < 0) {
        P_LOG_ERR("epoll_ctl(ADD, svr_sock): %s", strerror(errno));
        goto err;
    }
    /* ------------------------------------------ */

    list_add_tail(&conn->list, chain);
    list_add_tail(&conn->lru, &g_lru_list);
    conn_tbl_len++;

    inet_ntop(cli_addr->sa.sa_family, addr_of_sockaddr(cli_addr), s_addr,
              sizeof(s_addr));
    P_LOG_INFO("New UDP session for [%s]:%d, total %u", s_addr,
               ntohs(*port_of_sockaddr(cli_addr)), conn_tbl_len);

    conn->last_active = monotonic_seconds();
    return conn;

err:
    if (svr_sock >= 0) {
        if (safe_close(svr_sock) < 0) {
            P_LOG_WARN("close(svr_sock=%d): %s", svr_sock, strerror(errno));
        }
    }
    if (conn)
        release_proxy_conn_to_pool(conn);
    return NULL;
}

/**
 * @brief Releases a proxy connection.
 *
 * This function removes the connection from the hash table and LRU list,
 * deregisters its socket from epoll, closes the server-side socket, and
 * returns the connection object to the memory pool.
 */
static void release_proxy_conn(struct proxy_conn *conn, int epfd) {
    list_del(&conn->list);
    conn_tbl_len--;
    /* remove from LRU as well */
    list_del(&conn->lru);
    if (epoll_ctl(epfd, EPOLL_CTL_DEL, conn->svr_sock, NULL) < 0 &&
        errno != EBADF && errno != ENOENT) {
        P_LOG_WARN("epoll_ctl(DEL, svr_sock=%d): %s", conn->svr_sock,
                   strerror(errno));
    }
    if (safe_close(conn->svr_sock) < 0) {
        P_LOG_WARN("close(svr_sock=%d): %s", conn->svr_sock, strerror(errno));
    }
    release_proxy_conn_to_pool(conn);
}

static void proxy_conn_walk_continue(const struct config *cfg,
                                     unsigned walk_max, int epfd) {
    unsigned walked = 0;
    time_t now = g_now_ts ? g_now_ts : monotonic_seconds();

    if (list_empty(&g_lru_list))
        return;

    while (walked < walk_max && !list_empty(&g_lru_list)) {
        struct proxy_conn *oldest = list_first_entry(&g_lru_list, struct proxy_conn, lru);
        {
            long diff = (long)(now - oldest->last_active);
            if (diff < 0)
                diff = 0;
            if ((unsigned)diff <= cfg->proxy_conn_timeo)
                break; /* oldest not expired -> none later are expired */
        }
        {
            union sockaddr_inx addr = oldest->cli_addr;
            char s_addr[50] = "";
            release_proxy_conn(oldest, epfd);
            inet_ntop(addr.sa.sa_family, addr_of_sockaddr(&addr), s_addr,
                      sizeof(s_addr));
            P_LOG_INFO("Recycled %s:%d [%u]", s_addr,
                       ntohs(*port_of_sockaddr(&addr)), conn_tbl_len);
        }
        walked++;
    }
}



/* Evict the least recently active connection (LRU-ish across all buckets) */
static bool proxy_conn_evict_one(int epfd) {
    if (list_empty(&g_lru_list))
        return false;
    {
        struct proxy_conn *oldest =
            list_first_entry(&g_lru_list, struct proxy_conn, lru);
        union sockaddr_inx addr = oldest->cli_addr;
        char s_addr[50] = "";
        release_proxy_conn(oldest, epfd);
        inet_ntop(addr.sa.sa_family, addr_of_sockaddr(&addr), s_addr,
                  sizeof(s_addr));
        P_LOG_WARN("Evicted LRU %s:%d [%u]", s_addr,
                   ntohs(*port_of_sockaddr(&addr)), conn_tbl_len);
    }
    return true;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Data Handling Functions */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

#ifdef __linux__
static void handle_client_data(const struct config *cfg, int lsn_sock, int epfd,
                               struct mmsghdr *c_msgs, struct mmsghdr *s_msgs,
                               struct iovec *s_iovs,
                               char (*c_bufs)[UDP_PROXY_DGRAM_CAP])
#else
static void handle_client_data(const struct config *cfg, int lsn_sock, int epfd)
#endif
{
    struct proxy_conn *conn;

#ifdef __linux__
    if (c_msgs && s_msgs) {
        /* Drain multiple batches per epoll wake to reduce syscalls */
        int iterations = 0;
        const int max_iterations = 64; /* fairness cap per tick */
        const int ncap =
            g_batch_sz_runtime > 0 ? g_batch_sz_runtime : UDP_PROXY_BATCH_SZ;
        for (; iterations < max_iterations; iterations++) {
            /* Ensure namelen is reset before each recvmmsg call */
            for (int i = 0; i < ncap; i++) {
                c_msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
            }

            int n = recvmmsg(lsn_sock, c_msgs, ncap, 0, NULL);
            if (n <= 0) {
                if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                    errno != EINTR)
                    P_LOG_WARN("recvmmsg(): %s", strerror(errno));
                break; /* no more to read now */
            }

            struct send_batch {
                int sock;
                int msg_indices[UDP_PROXY_BATCH_SZ];
                int count;
            } batches[UDP_PROXY_BATCH_SZ];
            int num_batches = 0;

            for (int i = 0; i < n; i++) {
                union sockaddr_inx *sa =
                    (union sockaddr_inx *)c_msgs[i].msg_hdr.msg_name;
                if (!(conn = proxy_conn_get_or_create(cfg, sa, epfd)))
                    continue;
                touch_proxy_conn(conn);

                int batch_idx = -1;
                for (int k = 0; k < num_batches; k++) {
                    if (batches[k].sock == conn->svr_sock) {
                        batch_idx = k;
                        break;
                    }
                }
                if (batch_idx == -1) {
                    if (num_batches >= UDP_PROXY_BATCH_SZ) {
                        g_stat_c2s_batch_socket_overflow++;
                        ssize_t wr = send(conn->svr_sock, c_bufs[i], c_msgs[i].msg_len, 0);
                        if (wr < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                            P_LOG_WARN("send(server, overflow): %s", strerror(errno));
                        }
                        continue;
                    }
                    batch_idx = num_batches++;
                    batches[batch_idx].sock = conn->svr_sock;
                    batches[batch_idx].count = 0;
                }
                if (batches[batch_idx].count >= UDP_PROXY_BATCH_SZ) {
                    g_stat_c2s_batch_entry_overflow++;
                    ssize_t wr = send(conn->svr_sock, c_bufs[i], c_msgs[i].msg_len, 0);
                    if (wr < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                        P_LOG_WARN("send(server, batch_full): %s", strerror(errno));
                    }
                } else {
                    batches[batch_idx].msg_indices[batches[batch_idx].count++] = i;
                }
            }

            for (int i = 0; i < num_batches; i++) {
                struct send_batch *b = &batches[i];
                for (int k = 0; k < b->count; k++) {
                    int msg_idx = b->msg_indices[k];
                    s_iovs[k].iov_base = c_bufs[msg_idx];
                    s_iovs[k].iov_len = c_msgs[msg_idx].msg_len;
                    /* s_msgs already configured in init loop */
                }

                /* Retry on partial send to avoid dropping remaining packets */
                int remaining = b->count;
                if (remaining > g_batch_sz_runtime)
                    remaining = g_batch_sz_runtime;
                struct mmsghdr *msgp = s_msgs;
                do {
                    int sent = sendmmsg(b->sock, msgp, remaining, 0);
                    if (sent < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK ||
                            errno == EINTR) {
                            /* Transient backpressure; give up remaining for now
                             */
                            break;
                        }
                        P_LOG_WARN("sendmmsg(server): %s", strerror(errno));
                        break;
                    }
                    if (sent == 0) {
                        /* Avoid tight loop if nothing progressed */
                        break;
                    }
                    remaining -= sent;
                    msgp += sent;
                } while (remaining > 0);
            }

            /* If we read fewer than the batch, likely drained; stop early */
            if (n < ncap)
                break;
        }
        return;
    }
#endif

    char buffer[UDP_PROXY_DGRAM_CAP];
    union sockaddr_inx cli_addr;
    socklen_t cli_alen = sizeof(cli_addr);

    int r = recvfrom(lsn_sock, buffer, sizeof(buffer), 0,
                     (struct sockaddr *)&cli_addr, &cli_alen);
    if (r < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            P_LOG_WARN("recvfrom(): %s", strerror(errno));
        return; /* drop this datagram and move on */
    }

    if (!(conn = proxy_conn_get_or_create(cfg, &cli_addr, epfd)))
        return;

    /* refresh activity */
    touch_proxy_conn(conn);

    ssize_t wr = send(conn->svr_sock, buffer, r, 0);
    if (wr < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        P_LOG_WARN("send(server): %s", strerror(errno));
    }
}

static void handle_server_data(struct proxy_conn *conn, int lsn_sock,
                               int epfd) {
#ifdef __linux__
    /* Use recvmmsg() to batch receive from server and sendmmsg() to client */
    struct mmsghdr msgs[UDP_PROXY_BATCH_SZ];
    struct iovec iovs[UDP_PROXY_BATCH_SZ];
    static char bufs[UDP_PROXY_BATCH_SZ][UDP_PROXY_DGRAM_CAP];

    int iterations = 0;
    const int max_iterations = 64; /* fairness cap per event */
    const int ncap =
        g_batch_sz_runtime > 0 ? g_batch_sz_runtime : UDP_PROXY_BATCH_SZ;

    for (; iterations < max_iterations; iterations++) {
        memset(msgs, 0, sizeof(msgs));
        for (int i = 0; i < ncap; i++) {
            iovs[i].iov_base = bufs[i];
            iovs[i].iov_len = UDP_PROXY_DGRAM_CAP;
            msgs[i].msg_hdr.msg_iov = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            /* For recvmmsg on connected UDP, msg_name must be NULL */
            msgs[i].msg_hdr.msg_name = NULL;
            msgs[i].msg_hdr.msg_namelen = 0;
        }

        int n = recvmmsg(conn->svr_sock, msgs, ncap, 0, NULL);
        if (n <= 0) {
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    break; /* drained */
                }
                P_LOG_WARN("recvmmsg(server): %s", strerror(errno));
                /* fatal error on server socket: close session */
                release_proxy_conn(conn, epfd);
            }
            return;
        }

        /* Prepare destination (original client) for each message */
        for (int i = 0; i < n; i++) {
            msgs[i].msg_hdr.msg_name = &conn->cli_addr;
            msgs[i].msg_hdr.msg_namelen =
                (socklen_t)sizeof_sockaddr(&conn->cli_addr);
            /* Ensure iov_len matches actual datagram size */
            iovs[i].iov_len = msgs[i].msg_len;
            touch_proxy_conn(conn);
        }

        /* Send out the batch to client, retry on partial */
        int remaining = n;
        struct mmsghdr *msgp = msgs;
        do {
            int sent = sendmmsg(lsn_sock, msgp, remaining, 0);
            if (sent < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    /* leave remaining for later */
                    break;
                }
                P_LOG_WARN("sendmmsg(client): %s", strerror(errno));
                break;
            }
            if (sent == 0) {
                /* Avoid tight loop if nothing progressed */
                break;
            }
            remaining -= sent;
            msgp += sent;
        } while (remaining > 0);
    }
    return;
#else
    char buffer[UDP_PROXY_DGRAM_CAP];
    int r;

    for (;;) {
        r = recv(conn->svr_sock, buffer, sizeof(buffer), 0);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                break; /* drained */
            P_LOG_WARN("recv(server): %s", strerror(errno));
            /* fatal error on server socket: close session */
            release_proxy_conn(conn, epfd);
            break;
        }

        /* r >= 0: forward even zero-length datagrams */
        touch_proxy_conn(conn);

        ssize_t wr =
            sendto(lsn_sock, buffer, r, 0, (struct sockaddr *)&conn->cli_addr,
                   sizeof_sockaddr(&conn->cli_addr));
        if (wr < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
            errno != EINTR) {
            P_LOG_WARN("sendto(client): %s", strerror(errno));
        }

        if (r < (int)sizeof(buffer)) {
            break; /* Drained */
        }
    }
#endif
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Linux Batching Support */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

#ifdef __linux__
static void init_batching_resources(struct mmsghdr **c_msgs,
                                    struct iovec **c_iov,
                                    struct sockaddr_storage **c_addrs,
                                    char (**c_bufs)[UDP_PROXY_DGRAM_CAP],
                                    struct mmsghdr **s_msgs,
                                    struct iovec **s_iovs) {
    int ncap = g_batch_sz_runtime > 0 ? g_batch_sz_runtime : UDP_PROXY_BATCH_SZ;
    *c_msgs = calloc(ncap, sizeof(**c_msgs));
    *c_iov = calloc(ncap, sizeof(**c_iov));
    *c_addrs = calloc(ncap, sizeof(**c_addrs));
    *c_bufs = calloc(ncap, sizeof(**c_bufs));
    *s_msgs = calloc(ncap, sizeof(**s_msgs));
    *s_iovs = calloc(ncap, sizeof(**s_iovs));

    if (!*c_msgs || !*c_iov || !*c_addrs || !*c_bufs || !*s_msgs || !*s_iovs) {
        P_LOG_WARN("Failed to allocate UDP batching buffers; proceeding "
                   "without batching.");
        free(*c_msgs);
        free(*c_iov);
        free(*c_addrs);
        free(*c_bufs);
        free(*s_msgs);
        free(*s_iovs);

        *c_msgs = NULL;
        *c_iov = NULL;
        *c_addrs = NULL;
        *c_bufs = NULL;
        *s_msgs = NULL;
        *s_iovs = NULL;
        return;
    }

    for (int i = 0; i < ncap; i++) {
        (*c_iov)[i].iov_base = (*c_bufs)[i];
        (*c_iov)[i].iov_len = UDP_PROXY_DGRAM_CAP;
        (*c_msgs)[i].msg_hdr.msg_iov = &(*c_iov)[i];
        (*c_msgs)[i].msg_hdr.msg_iovlen = 1;
        (*c_msgs)[i].msg_hdr.msg_name = &(*c_addrs)[i];
        (*c_msgs)[i].msg_hdr.msg_namelen = sizeof((*c_addrs)[i]);

        (*s_msgs)[i].msg_hdr.msg_iov = &(*s_iovs)[i];
        (*s_msgs)[i].msg_hdr.msg_iovlen = 1;
    }
}

static void destroy_batching_resources(struct mmsghdr *c_msgs,
                                       struct iovec *c_iov,
                                       struct sockaddr_storage *c_addrs,
                                       char (*c_bufs)[UDP_PROXY_DGRAM_CAP],
                                       struct mmsghdr *s_msgs,
                                       struct iovec *s_iovs) {
    free(c_msgs);
    free(c_iov);
    free(c_addrs);
    free(c_bufs);
    free(s_msgs);
    free(s_iovs);
}
#endif

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Help and Main Function */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static void show_help(const char *prog) {
    P_LOG_INFO("Userspace UDP proxy.");
    P_LOG_INFO("Usage:");
    P_LOG_INFO("  %s <local_ip:local_port> <dest_ip:dest_port> [options]",
               prog);
    P_LOG_INFO("Examples:");
    P_LOG_INFO("  %s 0.0.0.0:10000 10.0.0.1:20000", prog);
    P_LOG_INFO("  %s [::]:10000 [2001:db8::1]:20000", prog);
    P_LOG_INFO("Options:");
    P_LOG_INFO("  -t <seconds>     proxy session timeout (default: %u)", 60);
    P_LOG_INFO("  -d               run in background");
    P_LOG_INFO("  -o               IPv6 listener accepts IPv6 only (sets "
               "IPV6_V6ONLY)");
    P_LOG_INFO("  -r, --reuse-addr set SO_REUSEADDR before binding local port");
    P_LOG_INFO("  -R, --reuse-port set SO_REUSEPORT before binding local port");
    P_LOG_INFO(
        "  -S <bytes>       SO_RCVBUF/SO_SNDBUF for sockets (default: %d)",
        UDP_PROXY_SOCKBUF_CAP);
    P_LOG_INFO("  -C <max_conns>   maximum tracked UDP sessions (default: %d)",
               UDP_PROXY_MAX_CONNS);
    P_LOG_INFO("  -B <batch>       Linux recvmmsg/sendmmsg batch size (1..%d, "
               "default: %d)",
               UDP_PROXY_BATCH_SZ, UDP_PROXY_BATCH_SZ);
    P_LOG_INFO("  -H <size>        hash table size (default: 4093)");
    P_LOG_INFO("  -p <pidfile>     write PID to file");
}

int main(int argc, char *argv[]) {
    /* Local variables */
    int opt, b_true = 1, lsn_sock = -1, epfd = -1, i, rc = 0;
    struct config cfg;
    struct epoll_event ev, events[MAX_EVENTS];
    char s_addr1[50] = "", s_addr2[50] = "";
    time_t last_check;

    /* Initialize configuration with defaults */
    memset(&cfg, 0, sizeof(cfg));
    cfg.proxy_conn_timeo = 60;     /* default timeout */
    cfg.conn_tbl_hash_size = 4093; /* default hash table size */

#ifdef __linux__
    /* Linux batching resources (allocated at runtime) */
    struct mmsghdr *c_msgs = NULL;              /* client -> server messages */
    struct iovec *c_iov = NULL;                 /* client I/O vectors */
    struct sockaddr_storage *c_addrs = NULL;    /* client addresses */
    char (*c_bufs)[UDP_PROXY_DGRAM_CAP] = NULL; /* client buffers */
    struct mmsghdr *s_msgs = NULL;              /* server messages */
    struct iovec *s_iovs = NULL;                /* server I/O vectors */
#endif

    /* Parse command line arguments */
    while ((opt = getopt(argc, argv, "t:dhorp:H:RS:C:B:")) != -1) {
        switch (opt) {
        case 't': {
            char *end = NULL;
            unsigned long v = strtoul(optarg, &end, 10);
            if (end == optarg || *end != '\0') {
                P_LOG_WARN("invalid -t value '%s', keeping default %u", optarg,
                           cfg.proxy_conn_timeo);
            } else {
                if (v == 0)
                    v = 1;
                if (v > 86400UL)
                    v = 86400UL;
                cfg.proxy_conn_timeo = (unsigned)v;
            }
            break;
        }
        case 'd':
            cfg.daemonize = true;
            break;
        case 'h':
            show_help(argv[0]);
            rc = 0;
            goto cleanup;
        case 'o':
            cfg.v6only = true;
            break;
        case 'r':
            cfg.reuse_addr = true;
            break;
        case 'R':
            cfg.reuse_port = true;
            break;
        case 'S': {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v <= 0) {
                P_LOG_WARN("invalid -S value '%s', keeping default %d", optarg,
                           g_sockbuf_cap_runtime);
            } else {
                if (v < 4096)
                    v = 4096;
                if (v > (8 << 20))
                    v = (8 << 20);
                g_sockbuf_cap_runtime = (int)v;
            }
            break;
        }
        case 'C': {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v <= 0) {
                P_LOG_WARN("invalid -C value '%s', keeping default %d", optarg,
                           g_conn_pool_capacity);
            } else {
                if (v < 64)
                    v = 64;
                if (v > (1 << 20))
                    v = (1 << 20);
                g_conn_pool_capacity = (int)v;
            }
            break;
        }
        case 'B': {
#ifdef __linux__
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0') {
                P_LOG_WARN("invalid -B value '%s', keeping default %d", optarg,
                           g_batch_sz_runtime);
            } else {
                if (v < 1)
                    v = 1;
                if (v > UDP_PROXY_BATCH_SZ)
                    v = UDP_PROXY_BATCH_SZ;
                g_batch_sz_runtime = (int)v;
            }
#else
            P_LOG_WARN("-B has no effect on non-Linux builds");
#endif
            break;
        }
        case 'p':
            cfg.pidfile = optarg;
            break;
        case 'H': {
            char *end = NULL;
            unsigned long v = strtoul(optarg, &end, 10);
            if (end == optarg || *end != '\0') {
                P_LOG_WARN("invalid -H value '%s', keeping default %u", optarg,
                           cfg.conn_tbl_hash_size);
            } else {
                if (v == 0)
                    v = 4093UL;
                if (v < 64UL)
                    v = 64UL;
                if (v > (1UL << 20))
                    v = (1UL << 20);
                cfg.conn_tbl_hash_size = (unsigned)v;
            }
            break;
        }
        default:
            show_help(argv[0]);
            rc = 1;
            goto cleanup;
        }
    }

    if (optind > argc - 2) {
        show_help(argv[0]);
        rc = 1;
        goto cleanup;
    }

    /* Resolve source address */
    if (get_sockaddr_inx_pair(argv[optind], &cfg.src_addr, true) < 0) {
        P_LOG_ERR("Invalid source address '%s'.", argv[optind]);
        rc = 1;
        goto cleanup;
    }
    optind++;

    /* Resolve destination addresse */
    if (get_sockaddr_inx_pair(argv[optind], &cfg.dst_addr, true) < 0) {
        P_LOG_ERR("Invalid destination address '%s'.", argv[optind]);
        rc = 1;
        goto cleanup;
    }
    optind++;

    /* Initialize logging */
    openlog("udpfwd", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    /* Initialize connection pool */
    if (init_conn_pool() != 0) {
        rc = 1;
        goto cleanup;
    }

    /* Create listening socket */
    lsn_sock = socket(cfg.src_addr.sa.sa_family, SOCK_DGRAM, 0);
    if (lsn_sock < 0) {
        P_LOG_ERR("socket(): %s.", strerror(errno));
        rc = 1;
        goto cleanup;
    }

    /* Configure socket options */
    if (cfg.reuse_addr) {
        if (setsockopt(lsn_sock, SOL_SOCKET, SO_REUSEADDR, &b_true,
                       sizeof(b_true)) < 0)
            P_LOG_WARN(
                "setsockopt(SO_REUSEADDR): %s (continuing without reuseaddr)",
                strerror(errno));
    }
#ifdef SO_REUSEPORT
    if (cfg.reuse_port) {
        if (setsockopt(lsn_sock, SOL_SOCKET, SO_REUSEPORT, &b_true,
                       sizeof(b_true)) < 0) {
            P_LOG_WARN(
                "setsockopt(SO_REUSEPORT): %s (continuing without reuseport)",
                strerror(errno));
        }
    }
#endif
    if (cfg.src_addr.sa.sa_family == AF_INET6 && cfg.v6only)
        (void)setsockopt(lsn_sock, IPPROTO_IPV6, IPV6_V6ONLY, &b_true,
                         sizeof(b_true));
    if (bind(lsn_sock, (struct sockaddr *)&cfg.src_addr,
             sizeof_sockaddr(&cfg.src_addr)) < 0) {
        P_LOG_ERR("bind(): %s.", strerror(errno));
        rc = 1;
        goto cleanup;
    }
    set_nonblock(lsn_sock);
    set_sock_buffers(lsn_sock);

    inet_ntop(cfg.src_addr.sa.sa_family, addr_of_sockaddr(&cfg.src_addr),
              s_addr1, sizeof(s_addr1));
    inet_ntop(cfg.dst_addr.sa.sa_family, addr_of_sockaddr(&cfg.dst_addr),
              s_addr2, sizeof(s_addr2));
    P_LOG_INFO("Listening on [%s]:%d, proxying to [%s]:%d", s_addr1,
               ntohs(*port_of_sockaddr(&cfg.src_addr)), s_addr2,
               ntohs(*port_of_sockaddr(&cfg.dst_addr)));

    /* Create epoll table. */
    /* Prefer epoll_create1 with CLOEXEC when available */
#ifdef __linux__
#ifdef EPOLL_CLOEXEC
    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0 && (errno == ENOSYS || errno == EINVAL))
        epfd = epoll_create(2048);
#else
    epfd = epoll_create(2048);
#endif
#else
    epfd = epoll_create(2048);
#endif
    if (epfd < 0) {
        P_LOG_ERR("epoll_create(): %s", strerror(errno));
        rc = 1;
        goto cleanup;
    }

    if (cfg.daemonize && do_daemonize() != 0) {
        rc = 1;
        goto cleanup;
    }
    if (cfg.pidfile) {
        if (write_pidfile(cfg.pidfile) < 0) {
            rc = 1;
            goto cleanup;
        }
    }

    setup_signal_handlers();

    /* Initialize the connection table */
    g_conn_tbl_hash_size = cfg.conn_tbl_hash_size;
    /*
     * Respect the configured hash size (e.g., a prime like 4093 to reduce
     * collisions). Only clamp to sane bounds; do NOT round to power-of-two
     * here.
     */
    if (g_conn_tbl_hash_size < 64)
        g_conn_tbl_hash_size = 64;
    if (g_conn_tbl_hash_size > (1u << 20))
        g_conn_tbl_hash_size = (1u << 20);

    /* Select bucket indexing strategy once to avoid per-call checks */
    bucket_index_fun =
        is_power_of_two(g_conn_tbl_hash_size)
            ? proxy_conn_hash_bitwise /* fast path for 2^k sizes */
            : proxy_conn_hash_mod;    /* general path for arbitrary sizes (e.g.,
                                         primes) */
    assert(bucket_index_fun != NULL);

    conn_tbl_hbase = malloc(sizeof(struct list_head) * g_conn_tbl_hash_size);
    if (!conn_tbl_hbase) {
        P_LOG_ERR("Failed to allocate connection hash table");
        rc = 1;
        goto cleanup;
    }
    for (i = 0; (unsigned)i < g_conn_tbl_hash_size; i++)
        INIT_LIST_HEAD(&conn_tbl_hbase[i]);
    conn_tbl_len = 0;

    last_check = monotonic_seconds();

    /* Optional Linux batching init */
#ifdef __linux__
    init_batching_resources(&c_msgs, &c_iov, &c_addrs, &c_bufs, &s_msgs,
                            &s_iovs);
#endif

    /* epoll loop */
    ev.data.ptr = NULL;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
#ifdef EPOLLEXCLUSIVE
    ev.events |= EPOLLEXCLUSIVE;
#endif
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, lsn_sock, &ev) < 0) {
        P_LOG_ERR("epoll_ctl(ADD, listener): %s", strerror(errno));
        rc = 1;
        goto cleanup;
    }

    /* Main event loop */
    for (;;) {
        int nfds;
        time_t current_ts = monotonic_seconds();

        /* Periodic timeout check and connection recycling */
        if ((long)(current_ts - last_check) >= 2) {
            proxy_conn_walk_continue(&cfg, 200, epfd);
            last_check = current_ts;
        }

        /* Cache current timestamp for hot paths */
        g_now_ts = current_ts;

        /* Wait for events */
        nfds = epoll_wait(epfd, events, countof(events), 1000 * 2);
        if (nfds == 0)
            continue;
        if (nfds < 0) {
            if (errno == EINTR || errno == ERESTART)
                continue;
            P_LOG_ERR("epoll_wait(): %s", strerror(errno));
            rc = 1;
            goto cleanup;
        }

        if (g_state.terminate)
            break;

        /* Process events */
        for (i = 0; i < nfds; i++) {
            struct epoll_event *evp = &events[i];
            struct proxy_conn *conn;

            if (evp->data.ptr == NULL) {
                /* Data from client */
                if (evp->events & (EPOLLERR | EPOLLHUP)) {
                    P_LOG_ERR("listener: EPOLLERR/HUP");
                    rc = 1;
                    goto cleanup;
                }
#ifdef __linux__
                handle_client_data(&cfg, lsn_sock, epfd, c_msgs, s_msgs, s_iovs,
                                   c_bufs);
#else
                handle_client_data(&cfg, lsn_sock, epfd);
#endif
            } else {
                /* Data from server */
                conn = (struct proxy_conn *)evp->data.ptr;
                if (evp->events & (EPOLLERR | EPOLLHUP)) {
                    /* fatal on this flow: release session */
                    release_proxy_conn(conn, epfd);
                    continue;
                }
                handle_server_data(conn, lsn_sock, epfd);
            }
        }
    }

cleanup:
    /* Cleanup resources */
    if (lsn_sock >= 0) {
        if (safe_close(lsn_sock) < 0) {
            P_LOG_WARN("close(lsn_sock=%d): %s", lsn_sock, strerror(errno));
        }
    }
    epoll_close_comp(epfd);
    free(conn_tbl_hbase);
    destroy_conn_pool();
#ifdef __linux__
    destroy_batching_resources(c_msgs, c_iov, c_addrs, c_bufs, s_msgs, s_iovs);
#endif

    /* Print statistics if any batch overflows occurred */
    if (g_stat_c2s_batch_socket_overflow || g_stat_c2s_batch_entry_overflow) {
        P_LOG_INFO("c2s batch overflows: sockets=%" PRIu64 ", entries=%" PRIu64,
                   g_stat_c2s_batch_socket_overflow,
                   g_stat_c2s_batch_entry_overflow);
    }
    closelog();

    return rc;
}
