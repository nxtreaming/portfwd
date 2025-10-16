/* udpfwd.c - High-performance UDP port forwarding proxy with connection tracking */

#define _GNU_SOURCE 1
#define UDPFWD_ONLY 1  /* Enable lightweight UDP-only proxy_conn structure */

#include "common.h"
#include "conn_pool.h"
#include "fwd_util.h"
#include "proxy_conn.h"
#include "list.h"

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
#include <stdint.h>

#ifdef __linux__
#include <sys/epoll.h>
#include <sys/uio.h>
#else
#define ERESTART 700
#include "no-epoll.h"
#endif

#define KEEPALIVE_LOG_INTERVAL_SEC 60
#define DEFAULT_CONN_TIMEOUT_SEC 300
#define DEFAULT_HASH_TABLE_SIZE 128

#define FNV_PRIME_32 0x01000193
#define FNV_OFFSET_32 0x811c9dc5
#define GOLDEN_RATIO_32 0x9e3779b9

#define HIGH_WATER_MARK_PERCENT 95
#define MAX_EVICTION_ATTEMPTS 5
#define TIME_GAP_WARNING_THRESHOLD_SEC 120

/* Compiler optimization hints */
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))
#define MAX_EVENTS 1024
#define EPOLL_WAIT_TIMEOUT_MS 500
#define CLIENT_MAX_ITERATIONS 64
#define SERVER_MAX_ITERATIONS 64
#define MAINT_INTERVAL_SEC 2
#define MAX_EXPIRE_PER_SWEEP 64
#define MAX_SCAN_PER_SWEEP 128
#ifndef UDP_PROXY_SOCKBUF_CAP
#define UDP_PROXY_SOCKBUF_CAP (1024 * 1024)
#endif

#define UDP_BACKLOG_FLUSH_LIMIT 16

#ifdef __linux__
#ifndef UDP_PROXY_BATCH_SZ
#define UDP_PROXY_BATCH_SZ 32
#endif

#ifndef UDP_PROXY_DGRAM_CAP
/* Max safe UDP payload size: 1500 - 8 (UDP header) - 20 (IPv4 header) */
#define UDP_PROXY_DGRAM_CAP 1472
#endif

#if (UDP_PROXY_DGRAM_CAP <= 0) || (UDP_PROXY_DGRAM_CAP > 1472)
#error "UDP_PROXY_DGRAM_CAP must be between 1 and 1472."
#endif
#endif

#ifndef UDP_PROXY_MAX_CONNS
#define UDP_PROXY_MAX_CONNS 64
#endif

static struct list_head *conn_tbl_hbase;
static unsigned g_conn_tbl_hash_size;
static unsigned conn_tbl_len;
static struct conn_pool g_conn_pool;
static int g_sockbuf_cap_runtime = UDP_PROXY_SOCKBUF_CAP;
static int g_conn_pool_capacity = UDP_PROXY_MAX_CONNS;
#ifdef __linux__
static int g_batch_sz_runtime = UDP_PROXY_BATCH_SZ;
#endif
static LIST_HEAD(g_lru_list);
static time_t g_now_ts;
static unsigned int (*bucket_index_fun)(const union sockaddr_inx *);
static struct {
    uint64_t packets_processed;
    uint64_t bytes_processed;
    uint64_t hash_collisions;
} g_stats = {0};
static struct fwd_config g_cfg;

static void proxy_conn_walk_continue(int epfd);
static bool proxy_conn_evict_one(int epfd);
static void handle_server_data(struct proxy_conn *conn, int lsn_sock, int epfd);
#ifdef __linux__
static void handle_client_data(int listen_sock, int epfd, struct mmsghdr *c_msgs,
                               char (*c_bufs)[UDP_PROXY_DGRAM_CAP]);
#else
static void handle_client_data(int listen_sock, int epfd);
#endif
static void proxy_conn_put(struct proxy_conn *conn, int epfd);

static inline time_t monotonic_seconds(void) {
#ifdef __linux__
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (time_t)ts.tv_sec;
#endif
    return time(NULL);
}

static inline time_t cached_now_seconds(void) {
    if (g_now_ts == 0)
        g_now_ts = monotonic_seconds();
    return g_now_ts;
}

static int safe_close(int fd) {
    if (fd < 0)
        return 0;
    while (close(fd) != 0) {
        if (errno != EINTR)
            return -1;
    }
    return 0;
}

static inline bool is_wouldblock(int e) {
    return likely(e == EAGAIN) || e == EWOULDBLOCK;
}

static inline bool is_temporary_errno(int e) {
    return likely(e == EINTR) || is_wouldblock(e);
}

static inline size_t align_up(size_t n, size_t align) {
    return (n + (align - 1)) & ~(align - 1);
}

static inline void log_if_unexpected_errno(const char *what) {
    int e = errno;
    if (!is_temporary_errno(e))
        P_LOG_WARN("%s: %s", what, strerror(e));
}

static inline bool udp_backlog_empty(const struct proxy_conn *conn) {
    return conn->udp_backlog.dlen == 0;
}

static void udp_backlog_clear(struct proxy_conn *conn) {
    conn->udp_backlog.rpos = conn->udp_backlog.dlen = 0;
}

static int update_server_epoll_interest(struct proxy_conn *conn, int epfd, bool want_write) {
    if (!conn || conn->svr_sock < 0)
        return -1;
    if (conn->udp_send_blocked == want_write)
        return 0;

    struct epoll_event ev = {
        .data.ptr = conn,
        .events = EPOLLIN | EPOLLERR | EPOLLHUP | (want_write ? EPOLLOUT : 0),
    };

    if (epoll_ctl(epfd, EPOLL_CTL_MOD, conn->svr_sock, &ev) < 0) {
        P_LOG_WARN("epoll_ctl(MOD, svr_sock=%d): %s", conn->svr_sock, strerror(errno));
        return -1;
    }
    conn->udp_send_blocked = want_write;
    return 0;
}

static bool udp_backlog_reserve(struct proxy_conn *conn, size_t additional) {
    if (!conn)
        return false;

    size_t in_queue = conn->udp_backlog.dlen - conn->udp_backlog.rpos;
    if (conn->udp_backlog.rpos > 0) {
        if (in_queue > 0)
            memmove(conn->udp_backlog.data, conn->udp_backlog.data + conn->udp_backlog.rpos, in_queue);
        conn->udp_backlog.dlen = in_queue;
        conn->udp_backlog.rpos = 0;
    }

    size_t required = conn->udp_backlog.dlen + additional;
    if (required == 0 || conn->udp_backlog.capacity >= required)
        return true;

    size_t new_cap = conn->udp_backlog.capacity ? conn->udp_backlog.capacity : align_up(required, 256);
    while (new_cap < required) {
        if (new_cap >= SIZE_MAX / 2) {
            new_cap = required;
            break;
        }
        new_cap *= 2;
    }

    char *np = (char *)realloc(conn->udp_backlog.data, new_cap);
    if (!np)
        return false;
    conn->udp_backlog.data = np;
    conn->udp_backlog.capacity = new_cap;
    return true;
}

static bool udp_queue_datagram(struct proxy_conn *conn, int epfd, const char *buf, size_t len) {
    if (!conn || !buf || len == 0)
        return false;

    if (len > UINT16_MAX) {
        P_LOG_WARN("Dropping oversized UDP datagram (%zu bytes)", len);
        return false;
    }

    size_t need = sizeof(uint16_t) + len;
    if (!udp_backlog_reserve(conn, need)) {
        P_LOG_WARN("Failed to allocate UDP backlog buffer (%zu bytes)", need);
        return false;
    }

    uint16_t pkt_len = (uint16_t)len;
    memcpy(conn->udp_backlog.data + conn->udp_backlog.dlen, &pkt_len, sizeof(pkt_len));
    conn->udp_backlog.dlen += sizeof(pkt_len);
    memcpy(conn->udp_backlog.data + conn->udp_backlog.dlen, buf, len);
    conn->udp_backlog.dlen += len;

    update_server_epoll_interest(conn, epfd, true);
    return true;
}

static bool udp_flush_backlog(struct proxy_conn *conn, int epfd) {
    if (!conn || conn->svr_sock < 0)
        return true;

    if (udp_backlog_empty(conn))
        return true;

    int sent_packets = 0;

    while (conn->udp_backlog.dlen - conn->udp_backlog.rpos >= sizeof(uint16_t) &&
           sent_packets < UDP_BACKLOG_FLUSH_LIMIT) {
        uint16_t pkt_len;
        memcpy(&pkt_len, conn->udp_backlog.data + conn->udp_backlog.rpos, sizeof(pkt_len));

        if (conn->udp_backlog.dlen - conn->udp_backlog.rpos < sizeof(uint16_t) + pkt_len) {
            /* Corrupted backlog entry; drop remaining data. */
            P_LOG_WARN("Corrupted UDP backlog entry (len=%u, available=%zu)", pkt_len,
                       conn->udp_backlog.dlen - conn->udp_backlog.rpos);
            udp_backlog_clear(conn);
            update_server_epoll_interest(conn, epfd, false);
            return true;
        }

        const char *payload = conn->udp_backlog.data + conn->udp_backlog.rpos + sizeof(uint16_t);
        ssize_t wr = send(conn->svr_sock, payload, pkt_len, 0);
        if (wr < 0) {
            if (errno == EINTR)
                continue;
            if (is_wouldblock(errno)) {
                update_server_epoll_interest(conn, epfd, true);
                return false;
            }
            P_LOG_WARN("send(server backlog) failed: %s", strerror(errno));
            conn->udp_backlog.rpos += sizeof(uint16_t) + pkt_len;
            sent_packets++;
            continue;
        }

        if ((size_t)wr != pkt_len) {
            P_LOG_WARN("Partial UDP datagram send: expected %u, sent %zd", pkt_len, wr);
            conn->udp_backlog.rpos += sizeof(uint16_t) + pkt_len;
        } else {
            conn->udp_backlog.rpos += sizeof(uint16_t) + pkt_len;
            sent_packets++;
        }
    }

    if (conn->udp_backlog.rpos >= conn->udp_backlog.dlen) {
        udp_backlog_clear(conn);
    }

    if (udp_backlog_empty(conn)) {
        update_server_epoll_interest(conn, epfd, false);
        return true;
    }

    update_server_epoll_interest(conn, epfd, true);
    return false;
}

static inline bool validate_packet(const char *data, size_t len, const union sockaddr_inx *src) {
    (void)data;
    (void)src;
    /* Basic sanity check: packet must be non-empty and within MTU limits */
    return (len > 0 && len <= UDP_PROXY_DGRAM_CAP);
}

static inline bool is_power_of_two(unsigned v) {
    return v && ((v & (v - 1)) == 0);
}

static inline void proxy_conn_hold(struct proxy_conn *conn) {
    conn->ref_count++;
}

static struct proxy_conn *init_proxy_conn(struct proxy_conn *conn) {
    if (!conn) {
        return NULL;
    }

    /* Zero out the memory and set default values */
    memset(conn, 0, sizeof(*conn));
    conn->ref_count = 1;
    conn->svr_sock = -1;
    /* Initialize other fields as needed */

    return conn;
}

static inline uint32_t hash_addr(const union sockaddr_inx *sa) {
    uint32_t hash = 0;

    if (sa->sa.sa_family != AF_INET && sa->sa.sa_family != AF_INET6) {
        P_LOG_WARN("Unsupported address family: %d", sa->sa.sa_family);
        return 0;
    }

    if (sa->sa.sa_family == AF_INET) {
        /* Use FNV-1a hash for better distribution */
        const uint32_t FNV_PRIME = FNV_PRIME_32;
        const uint32_t FNV_OFFSET = FNV_OFFSET_32;

        hash = FNV_OFFSET;
        const uint8_t *bytes = (const uint8_t *)&sa->sin.sin_addr.s_addr;
        for (int i = 0; i < 4; i++) {
            hash ^= bytes[i];
            hash *= FNV_PRIME;
        }

        /* Mix in port for better distribution */
        uint16_t port = sa->sin.sin_port;
        hash ^= port;
        hash *= FNV_PRIME;
    } else if (sa->sa.sa_family == AF_INET6) {
        /* For IPv6, use a more sophisticated hash */
        const uint32_t *words = (const uint32_t *)&sa->sin6.sin6_addr;
        hash = words[0] ^ words[1] ^ words[2] ^ words[3];

        /* Mix in port */
        hash ^= sa->sin6.sin6_port;
        hash = hash * GOLDEN_RATIO_32; /* Golden ratio hash */
    }

    return hash;
}

static inline unsigned int proxy_conn_hash_bitwise(const union sockaddr_inx *sa) {
    uint32_t h = hash_addr(sa);
    return h & (g_conn_tbl_hash_size - 1);
}

static inline unsigned int proxy_conn_hash_mod(const union sockaddr_inx *sa) {
    uint32_t h = hash_addr(sa);
    return h % g_conn_tbl_hash_size;
}

static inline void format_client_addr(const union sockaddr_inx *addr, char *buf, size_t bufsize) {
    if (!addr || !buf || bufsize == 0)
        return;
    inet_ntop(addr->sa.sa_family, addr_of_sockaddr(addr), buf, bufsize);
}

static inline void touch_proxy_conn(struct proxy_conn *conn) {
    if (g_cfg.proxy_conn_timeo == 0)
        return;

    time_t now = cached_now_seconds();
    time_t old_active = conn->last_active;
    conn->last_active = now;

    if (old_active != now && (now - old_active) > TIME_GAP_WARNING_THRESHOLD_SEC) {
        char s_addr[INET6_ADDRSTRLEN];
        format_client_addr(&conn->cli_addr, s_addr, sizeof(s_addr));
        P_LOG_WARN("Large time gap for %s:%d: gap=%ld sec (last_active=%ld, now=%ld). "
                   "System may have been suspended or heavily loaded.",
                   s_addr, ntohs(*port_of_sockaddr(&conn->cli_addr)),
                   (long)(now - old_active), old_active, now);
    }
}

static struct proxy_conn *proxy_conn_get_or_create(const union sockaddr_inx *cli_addr, int epfd) {
    struct list_head *chain = &conn_tbl_hbase[bucket_index_fun(cli_addr)];
    struct proxy_conn *conn = NULL;
    int svr_sock = -1;
    struct epoll_event ev;
    char s_addr[INET6_ADDRSTRLEN] = "";

    list_for_each_entry(conn, chain, list) {
        if (is_sockaddr_inx_equal(cli_addr, &conn->cli_addr)) {
            proxy_conn_hold(conn);
            touch_proxy_conn(conn);
            return conn;
        }
    }

    bool reserved_slot = false;
    int eviction_attempts = 0;
    
    for (;;) {
        unsigned current_conn_count = conn_tbl_len;
        if (current_conn_count >= (unsigned)g_conn_pool.capacity) {
            if (eviction_attempts >= MAX_EVICTION_ATTEMPTS) {
                format_client_addr(cli_addr, s_addr, sizeof(s_addr));
                P_LOG_WARN("Conn table full after %d eviction attempts, dropping %s:%d",
                           eviction_attempts, s_addr, ntohs(*port_of_sockaddr(cli_addr)));
                goto err;
            }
            eviction_attempts++;
            
            if (!proxy_conn_evict_one(epfd)) {
                format_client_addr(cli_addr, s_addr, sizeof(s_addr));
                P_LOG_WARN("Conn table full but LRU empty, dropping %s:%d",
                           s_addr, ntohs(*port_of_sockaddr(cli_addr)));
                goto err;
            }
            continue;
        }
        if (conn_tbl_len == current_conn_count) {
            conn_tbl_len = current_conn_count + 1;
            reserved_slot = true;
            break;
        }
    }

    static bool warned_high_water = false;
    if (!warned_high_water && g_conn_pool.capacity > 0 &&
        conn_tbl_len >= (unsigned)((g_conn_pool.capacity * HIGH_WATER_MARK_PERCENT) / 100)) {
        P_LOG_WARN("UDP conn table high-water: %u/%u (~%d%%). Consider raising -C or reducing -t.",
                   conn_tbl_len, (unsigned)g_conn_pool.capacity,
                   (int)((conn_tbl_len * 100) / (unsigned)g_conn_pool.capacity));
        warned_high_water = true;
    }
    if ((svr_sock = socket(g_cfg.dst_addr.sa.sa_family, SOCK_DGRAM, 0)) < 0) {
        P_LOG_ERR("socket(svr_sock): %s", strerror(errno));
        goto err;
    }
    if (connect(svr_sock, (struct sockaddr *)&g_cfg.dst_addr, sizeof_sockaddr(&g_cfg.dst_addr)) != 0) {
        P_LOG_WARN("Connection failed: %s", strerror(errno));
        goto err;
    }
    set_nonblock(svr_sock);

    if (!(conn = init_proxy_conn(conn_pool_alloc(&g_conn_pool)))) {
        P_LOG_ERR("conn_pool_alloc: failed");
        goto err_unlock;
    }
    conn->svr_sock = svr_sock;
    conn->cli_addr = *cli_addr;
    INIT_LIST_HEAD(&conn->lru);

    ev.data.ptr = conn;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, conn->svr_sock, &ev) < 0) {
        P_LOG_ERR("epoll_ctl(ADD, svr_sock): %s", strerror(errno));
        goto err_unlock;
    }

    list_add_tail(&conn->list, chain);
    list_add_tail(&conn->lru, &g_lru_list);

    format_client_addr(cli_addr, s_addr, sizeof(s_addr));
    P_LOG_INFO("New UDP session [%s]:%d, total %u", s_addr,
               ntohs(*port_of_sockaddr(cli_addr)), conn_tbl_len);

    conn->last_active = cached_now_seconds();
    proxy_conn_hold(conn);
    return conn;

err_unlock:
    if (conn) {
        conn_pool_release(&g_conn_pool, conn);
        conn = NULL;
    }
    if (svr_sock >= 0)
        safe_close(svr_sock);
err:
    if (reserved_slot)
        conn_tbl_len--;
    return NULL;
}

static void release_proxy_conn(struct proxy_conn *conn, int epfd) {
    if (!conn)
        return;

    list_del(&conn->list);
    conn_tbl_len--;

    if (!list_empty(&conn->lru))
        list_del(&conn->lru);

    if (conn->svr_sock >= 0) {
        if (epoll_ctl(epfd, EPOLL_CTL_DEL, conn->svr_sock, NULL) < 0 && 
            errno != EBADF && errno != ENOENT)
            P_LOG_WARN("epoll_ctl(DEL, svr_sock=%d): %s", conn->svr_sock, strerror(errno));
        safe_close(conn->svr_sock);
        conn->svr_sock = -1;
    }

    if (conn->udp_backlog.data) {
        free(conn->udp_backlog.data);
        conn->udp_backlog.data = NULL;
    }
    conn->udp_backlog.capacity = 0;
    conn->udp_backlog.dlen = 0;
    conn->udp_backlog.rpos = 0;
    conn->udp_send_blocked = false;

    conn_pool_release(&g_conn_pool, conn);
}

static void proxy_conn_put(struct proxy_conn *conn, int epfd) {
    if (--conn->ref_count == 0)
        release_proxy_conn(conn, epfd);
}

static void proxy_conn_walk_continue(int epfd) {
    if (list_empty(&g_lru_list))
        return;

    time_t now = cached_now_seconds();
    LIST_HEAD(reap_list);
    struct proxy_conn *conn, *tmp;
    size_t reaped = 0, scanned = 0;
    list_for_each_entry_safe(conn, tmp, &g_lru_list, lru) {
        if (g_shutdown_requested)
            return;
        
        if (++scanned >= MAX_SCAN_PER_SWEEP)
            break;
        
        long diff = (long)(now - conn->last_active);
        if (diff < 0)
            diff = 0;
        
        if (g_cfg.proxy_conn_timeo != 0 && (unsigned)diff > g_cfg.proxy_conn_timeo) {
            if (unlikely(conn->ref_count != 1))
                continue;
            list_move_tail(&conn->lru, &reap_list);
            if (++reaped >= MAX_EXPIRE_PER_SWEEP)
                break;
        } else {
            break;
        }
    }

    list_for_each_entry_safe(conn, tmp, &reap_list, lru) {
        char s_addr[INET6_ADDRSTRLEN];
        const char *conn_type = "";
        if (conn->client_packets == 0 && conn->server_packets > 0)
            conn_type = " [SERVER-ONLY]";
        else if (conn->client_packets > 0 && conn->server_packets == 0)
            conn_type = " [CLIENT-ONLY]";
        else if (conn->client_packets > 0 && conn->server_packets > 0)
            conn_type = " [BIDIRECTIONAL]";
        
        format_client_addr(&conn->cli_addr, s_addr, sizeof(s_addr));
        P_LOG_INFO("Recycling %s:%d%s - last_active=%ld, now=%ld, idle=%ld sec, timeout=%u sec, "
                   "client_pkts=%lu, server_pkts=%lu. Client must send new data to re-establish.",
                   s_addr, ntohs(*port_of_sockaddr(&conn->cli_addr)), conn_type,
                   conn->last_active, now, (long)(now - conn->last_active), g_cfg.proxy_conn_timeo,
                   conn->client_packets, conn->server_packets);
        proxy_conn_put(conn, epfd);
    }
}

static bool proxy_conn_evict_one(int epfd) {
    if (list_empty(&g_lru_list))
        return false;

    struct proxy_conn *oldest = list_first_entry(&g_lru_list, struct proxy_conn, lru);
    union sockaddr_inx addr = oldest->cli_addr;
    char s_addr[INET6_ADDRSTRLEN];

    proxy_conn_hold(oldest);
    proxy_conn_put(oldest, epfd);
    format_client_addr(&addr, s_addr, sizeof(s_addr));
    P_LOG_WARN("Evicted LRU %s:%d [%u]", s_addr, ntohs(*port_of_sockaddr(&addr)), conn_tbl_len);
    return true;
}

#ifdef __linux__
static void handle_client_data(int lsn_sock, int epfd, struct mmsghdr *c_msgs,
                               char (*c_bufs)[UDP_PROXY_DGRAM_CAP]) {
#else
static void handle_client_data(int lsn_sock, int epfd) {
#endif
    struct proxy_conn *conn;

#ifdef __linux__
    if (c_msgs && c_bufs) {
        int iterations = 0;
        const int max_iterations = CLIENT_MAX_ITERATIONS;
        const int ncap = g_batch_sz_runtime > 0 ? g_batch_sz_runtime : UDP_PROXY_BATCH_SZ;

        for (; iterations < max_iterations; iterations++) {
            for (int i = 0; i < ncap; i++) {
                c_msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
            }

            int n = recvmmsg(lsn_sock, c_msgs, ncap, 0, NULL);
            if (n <= 0) {
                if (n < 0)
                    log_if_unexpected_errno("recvmmsg()");
                break;
            }

            g_now_ts = monotonic_seconds();

            for (int i = 0; i < n; i++) {
                union sockaddr_inx *sa = (union sockaddr_inx *)c_msgs[i].msg_hdr.msg_name;
                size_t packet_len = c_msgs[i].msg_len;

                if (unlikely(!validate_packet(c_bufs[i], packet_len, sa))) {
                    continue;
                }

                conn = proxy_conn_get_or_create(sa, epfd);
                if (!conn)
                    continue;

                conn->client_packets++;
                touch_proxy_conn(conn);

                if (!udp_flush_backlog(conn, epfd)) {
                    if (!udp_queue_datagram(conn, epfd, c_bufs[i], packet_len))
                        P_LOG_WARN("Dropping UDP datagram (%zu bytes) due to backlog overflow", packet_len);
                    proxy_conn_put(conn, epfd);
                    continue;
                }

                ssize_t wr;
                do {
                    wr = send(conn->svr_sock, c_bufs[i], packet_len, 0);
                } while (wr < 0 && errno == EINTR);

                if (wr < 0) {
                    if (is_wouldblock(errno)) {
                        if (!udp_queue_datagram(conn, epfd, c_bufs[i], packet_len))
                            P_LOG_WARN("Dropping UDP datagram (%zu bytes) due to backlog allocation failure", packet_len);
                    } else {
                        log_if_unexpected_errno("send(server)");
                    }
                } else {
                    g_stats.bytes_processed += (size_t)wr;
                }
                proxy_conn_put(conn, epfd);
            }

            g_stats.packets_processed += n;

            if (n < ncap)
                break;
        }

        return;
    }
#endif

    char buffer[UDP_PROXY_DGRAM_CAP];
    union sockaddr_inx cli_addr;
    socklen_t cli_alen = sizeof(cli_addr);

    int r = recvfrom(lsn_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&cli_addr, &cli_alen);
    if (r < 0) {
        if (errno)
            log_if_unexpected_errno("recvfrom()");
        return;
    }

    g_now_ts = monotonic_seconds();

    if (!validate_packet(buffer, (size_t)r, &cli_addr))
        return;

    conn = proxy_conn_get_or_create(&cli_addr, epfd);
    if (!conn)
        return;

    conn->client_packets++;
    touch_proxy_conn(conn);

    if (!udp_flush_backlog(conn, epfd)) {
        if (!udp_queue_datagram(conn, epfd, buffer, (size_t)r))
            P_LOG_WARN("Dropping UDP datagram (%d bytes) due to backlog overflow", r);
        proxy_conn_put(conn, epfd);
        return;
    }

    ssize_t wr;
    do {
        wr = send(conn->svr_sock, buffer, r, 0);
    } while (wr < 0 && errno == EINTR);
    if (wr < 0) {
        if (is_wouldblock(errno)) {
            if (!udp_queue_datagram(conn, epfd, buffer, (size_t)r))
                P_LOG_WARN("Dropping UDP datagram (%d bytes) due to backlog allocation failure", r);
        } else {
            log_if_unexpected_errno("send(server)");
        }
    } else {
        g_stats.bytes_processed += (size_t)wr;
    }

    proxy_conn_put(conn, epfd);
}

static void handle_server_data(struct proxy_conn *conn, int lsn_sock, int epfd) {
#ifdef __linux__
    static __thread struct mmsghdr tls_msgs[UDP_PROXY_BATCH_SZ];
    static __thread struct iovec tls_iovs[UDP_PROXY_BATCH_SZ];
    static __thread char tls_bufs[UDP_PROXY_BATCH_SZ][UDP_PROXY_DGRAM_CAP];
    static __thread bool tls_inited;
    struct mmsghdr *msgs = tls_msgs;
    struct iovec *iovs = tls_iovs;
    char (*bufs)[UDP_PROXY_DGRAM_CAP] = tls_bufs;
    char s_addr[INET6_ADDRSTRLEN];

    if (!tls_inited) {
        for (int i = 0; i < UDP_PROXY_BATCH_SZ; i++) {
            iovs[i].iov_base = bufs[i];
            iovs[i].iov_len = UDP_PROXY_DGRAM_CAP;
            msgs[i].msg_hdr.msg_iov = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_name = NULL;
            msgs[i].msg_hdr.msg_namelen = 0;
            msgs[i].msg_hdr.msg_control = NULL;
            msgs[i].msg_hdr.msg_controllen = 0;
            msgs[i].msg_hdr.msg_flags = 0;
        }
        tls_inited = true;
    }

    const int max_iterations = SERVER_MAX_ITERATIONS;
    const int ncap = g_batch_sz_runtime > 0 ? g_batch_sz_runtime : UDP_PROXY_BATCH_SZ;

    for (int iterations = 0; iterations < max_iterations; iterations++) {
        for (int i = 0; i < ncap; i++) {
            iovs[i].iov_len = UDP_PROXY_DGRAM_CAP;
            msgs[i].msg_hdr.msg_name = NULL;
            msgs[i].msg_hdr.msg_namelen = 0;
        }

        int n = recvmmsg(conn->svr_sock, msgs, ncap, 0, NULL);
        if (n <= 0) {
            if (n < 0) {
                if (is_temporary_errno(errno)) {
                    break; /* drained */
                }
                log_if_unexpected_errno("recvmmsg(server)");
                /* fatal error on server socket: close session */
                proxy_conn_put(conn, epfd);
            }
            return;
        }

        g_now_ts = monotonic_seconds();
        conn->server_packets += n;
        touch_proxy_conn(conn);

        for (int i = 0; i < n; i++) {
            msgs[i].msg_hdr.msg_name = &conn->cli_addr;
            msgs[i].msg_hdr.msg_namelen = (socklen_t)sizeof_sockaddr(&conn->cli_addr);
            iovs[i].iov_len = msgs[i].msg_len;
        }
        int remaining = n;
        struct mmsghdr *msgp = msgs;
        int total_sent = 0;
        do {
            int sent = sendmmsg(lsn_sock, msgp, remaining, 0);
            if (sent < 0) {
                if (is_temporary_errno(errno))
                    break;
                format_client_addr(&conn->cli_addr, s_addr, sizeof(s_addr));
                P_LOG_WARN("sendmmsg(client) FAILED for %s:%d: %s, sent=%d/%d, remaining=%d",
                           s_addr, ntohs(*port_of_sockaddr(&conn->cli_addr)),
                           strerror(errno), total_sent, n, remaining);
                break;
            }
            if (sent == 0) {
                format_client_addr(&conn->cli_addr, s_addr, sizeof(s_addr));
                P_LOG_WARN("sendmmsg(client) sent 0 packets for %s:%d, sent=%d/%d, remaining=%d",
                           s_addr, ntohs(*port_of_sockaddr(&conn->cli_addr)),
                           total_sent, n, remaining);
                break;
            }
            total_sent += sent;
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
            if (is_temporary_errno(errno))
                break;
            log_if_unexpected_errno("recv(server)");
            proxy_conn_put(conn, epfd);
            break;
        }

        g_now_ts = monotonic_seconds();
        conn->server_packets++;
        touch_proxy_conn(conn);

        ssize_t wr = sendto(lsn_sock, buffer, r, 0, (struct sockaddr *)&conn->cli_addr,
                            sizeof_sockaddr(&conn->cli_addr));
        if (wr < 0) {
            char s_addr[INET6_ADDRSTRLEN];
            format_client_addr(&conn->cli_addr, s_addr, sizeof(s_addr));
            P_LOG_WARN("sendto(client) FAILED for %s:%d: %s, packet_size=%d",
                       s_addr, ntohs(*port_of_sockaddr(&conn->cli_addr)),
                       strerror(errno), r);
        }

        if (r < (int)sizeof(buffer))
            break;
    }
#endif
}

#ifdef __linux__
static void init_batching_resources(struct mmsghdr **c_msgs, struct iovec **c_iov,
                                    struct sockaddr_storage **c_addrs,
                                    char (**c_bufs)[UDP_PROXY_DGRAM_CAP]) {
    const int ncap = g_batch_sz_runtime > 0 ? g_batch_sz_runtime : UDP_PROXY_BATCH_SZ;

    size_t size_c_msgs = (size_t)ncap * sizeof(**c_msgs);
    size_t size_c_iov  = (size_t)ncap * sizeof(**c_iov);
    size_t size_c_addrs= (size_t)ncap * sizeof(**c_addrs);
    size_t size_c_bufs = (size_t)ncap * sizeof(**c_bufs);
    size_t total = size_c_msgs + size_c_iov + size_c_addrs + size_c_bufs;

    void *block = aligned_alloc(64, align_up(total, 64));
    if (!block) {
        P_LOG_WARN("Failed to allocate UDP batching buffers; proceeding without batching.");
        *c_msgs = *c_iov = NULL;
        *c_addrs = NULL;
        *c_bufs = NULL;
        return;
    }

    char *p = (char *)block;
    *c_msgs = (struct mmsghdr *)p;
    p += size_c_msgs;
    *c_iov  = (struct iovec *)p;
    p += size_c_iov;
    *c_addrs= (struct sockaddr_storage *)p;
    p += size_c_addrs;
    *c_bufs = (char (*)[UDP_PROXY_DGRAM_CAP])p;

    for (int i = 0; i < ncap; i++) {
        (*c_iov)[i].iov_base = (*c_bufs)[i];
        (*c_iov)[i].iov_len = UDP_PROXY_DGRAM_CAP;
        (*c_msgs)[i].msg_hdr.msg_iov = &(*c_iov)[i];
        (*c_msgs)[i].msg_hdr.msg_iovlen = 1;
        (*c_msgs)[i].msg_hdr.msg_name = &(*c_addrs)[i];
        (*c_msgs)[i].msg_hdr.msg_namelen = sizeof((*c_addrs)[i]);
    }
}

static void destroy_batching_resources(struct mmsghdr *c_msgs, struct iovec *c_iov,
                                       struct sockaddr_storage *c_addrs,
                                       char (*c_bufs)[UDP_PROXY_DGRAM_CAP]) {
    (void)c_iov; (void)c_addrs; (void)c_bufs;
    free(c_msgs);
}
#endif

static void show_help(const char *prog) {
    P_LOG_INFO("Userspace UDP proxy.");
    P_LOG_INFO("Usage:");
    P_LOG_INFO("  %s <local_ip:local_port> <dest_ip:dest_port> [options]", prog);
    P_LOG_INFO("Examples:");
    P_LOG_INFO("  %s 0.0.0.0:10000 10.0.0.1:20000", prog);
    P_LOG_INFO("  %s [::]:10000 [2001:db8::1]:20000", prog);
    P_LOG_INFO("Options:");
    P_LOG_INFO("  -t <seconds>     proxy session timeout (default: %u)", DEFAULT_CONN_TIMEOUT_SEC);
    P_LOG_INFO("  -S <bytes>       SO_RCVBUF/SO_SNDBUF for sockets (default: %d)",
               UDP_PROXY_SOCKBUF_CAP);
    P_LOG_INFO("  -C <max_conns>   maximum tracked UDP sessions (default: %d)",
               UDP_PROXY_MAX_CONNS);
    P_LOG_INFO("  -B <batch>       Linux recvmmsg/sendmmsg batch size (1..%d, "
               "default: %d)",
               UDP_PROXY_BATCH_SZ, UDP_PROXY_BATCH_SZ);
    P_LOG_INFO("  -H <size>        hash table size (default: %d, recommend >= "
               "max_conns)",
               DEFAULT_HASH_TABLE_SIZE);
    P_LOG_INFO("Common options: -d (daemon), -r (reuse_addr), -R (reuse_port), "
               "-6 (v6only), -p <pidfile>, -i <max_per_ip>");
}

int main(int argc, char *argv[]) {
    int rc = 1;
    int listen_sock = -1, epfd = -1, i;
    time_t last_check = 0;
    struct epoll_event ev, events[MAX_EVENTS];
    uintptr_t magic_listener = EV_MAGIC_LISTENER;

#ifdef __linux__
    struct mmsghdr *c_msgs = NULL;
    struct iovec *c_iov = NULL;
    struct sockaddr_storage *c_addrs = NULL;
    char (*c_bufs)[UDP_PROXY_DGRAM_CAP] = {0};
#endif

    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.proxy_conn_timeo = DEFAULT_CONN_TIMEOUT_SEC;
    g_cfg.conn_tbl_hash_size = DEFAULT_HASH_TABLE_SIZE;

    int opt;
    while ((opt = getopt(argc, argv, "hdvRr6p:i:t:S:C:B:H:")) != -1) {
        switch (opt) {
        case 't': {
            char *end = NULL;
            unsigned long v = strtoul(optarg, &end, 10);
            if (end == optarg || *end != '\0')
                P_LOG_WARN("invalid -t value '%s', keeping default %u", optarg, g_cfg.proxy_conn_timeo);
            else {
                if (v > 86400UL)
                    v = 86400UL;
                g_cfg.proxy_conn_timeo = (unsigned)v;
            }
            break;
        }
        case 'd':
            g_cfg.daemonize = true;
            break;
        case 'v':
            /* verbose, placeholder */
            break;
        case 'R':
            g_cfg.reuse_port = true;
            break;
        case 'r':
            g_cfg.reuse_addr = true;
            break;
        case '6':
            g_cfg.v6only = true;
            break;
        case 'p':
            g_cfg.pidfile = optarg;
            break;
        case 'i': {
            char *end = NULL;
            unsigned long v = strtoul(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v == 0)
                P_LOG_WARN("invalid -i value '%s', keeping default %u", optarg, g_cfg.max_per_ip_connections);
            else
                g_cfg.max_per_ip_connections = (unsigned)v;
            break;
        }
        case 'S': {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v <= 0)
                P_LOG_WARN("invalid -S value '%s', keeping default %d", optarg, g_sockbuf_cap_runtime);
            else {
                if (v < 4096) v = 4096;
                if (v > (8 << 20)) v = (8 << 20);
                g_sockbuf_cap_runtime = (int)v;
            }
            break;
        }
        case 'C': {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v <= 0)
                P_LOG_WARN("invalid -C value '%s', keeping default %d", optarg, g_conn_pool_capacity);
            else {
                if (v < 64) v = 64;
                if (v > (1 << 20)) v = (1 << 20);
                g_conn_pool_capacity = (int)v;
            }
            break;
        }
        case 'B': {
#ifdef __linux__
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0')
                P_LOG_WARN("invalid -B value '%s', keeping default %d", optarg, g_batch_sz_runtime);
            else {
                if (v < 1) v = 1;
                if (v > UDP_PROXY_BATCH_SZ) v = UDP_PROXY_BATCH_SZ;
                g_batch_sz_runtime = (int)v;
            }
#else
            P_LOG_WARN("-B has no effect on non-Linux builds");
#endif
            break;
        }
        case 'H': {
            char *end = NULL;
            unsigned long v = strtoul(optarg, &end, 10);
            if (end == optarg || *end != '\0')
                P_LOG_WARN("invalid -H value '%s', keeping default %u", optarg, g_cfg.conn_tbl_hash_size);
            else {
                if (v == 0) v = 4093UL;
                if (v < 64UL) v = 64UL;
                if (v > (1UL << 20)) v = (1UL << 20);
                g_cfg.conn_tbl_hash_size = (unsigned)v;
            }
            break;
        }
        default:
            show_help(argv[0]);
            return 1;
        }
    }

    if (optind > argc - 2) {
        show_help(argv[0]);
        return 1;
    }

    if (get_sockaddr_inx(argv[optind], &g_cfg.listen_addr, true) != 0)
        return 1;
    if (get_sockaddr_inx(argv[optind + 1], &g_cfg.dst_addr, false) != 0)
        return 1;

    openlog("udpfwd", LOG_PID | LOG_PERROR, LOG_DAEMON);

    if (g_cfg.daemonize) {
        if (do_daemonize() != 0)
            return 1;
        
        char log_path[256];
        unsigned short listen_port = ntohs(*port_of_sockaddr(&g_cfg.listen_addr));
        snprintf(log_path, sizeof(log_path), "/var/log/udpfwd_%u.log", listen_port);
        
        g_state.log_file = fopen(log_path, "a");
        if (!g_state.log_file)
            syslog(LOG_WARNING, "Failed to open log file %s: %s, using syslog", log_path, strerror(errno));
        else
            P_LOG_INFO("UDP forwarder started, logging to %s", log_path);
    }

    if (g_cfg.pidfile) {
        if (create_pid_file(g_cfg.pidfile) != 0)
            return 1;
    }

    if (conn_pool_init(&g_conn_pool, g_conn_pool_capacity, sizeof(struct proxy_conn)) < 0) {
        P_LOG_ERR("conn_pool_init: failed");
        goto cleanup;
    }

    if (init_signals() != 0) {
        P_LOG_ERR("setup_shutdown_signals: failed");
        rc = 1;
        goto cleanup;
    }

    listen_sock = socket(g_cfg.listen_addr.sa.sa_family, SOCK_DGRAM, 0);
    if (listen_sock < 0) {
        P_LOG_ERR("socket(): %s", strerror(errno));
        goto cleanup;
    }

    if (g_cfg.reuse_addr) {
        int on = 1;
        if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
            P_LOG_WARN("setsockopt(SO_REUSEADDR): %s", strerror(errno));
    }

#ifdef SO_REUSEPORT
    if (g_cfg.reuse_port) {
        int on = 1;
        if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0)
            P_LOG_WARN("setsockopt(SO_REUSEPORT): %s", strerror(errno));
    }
#endif

    if (g_cfg.listen_addr.sa.sa_family == AF_INET6 && g_cfg.v6only) {
        int on = 1;
        (void)setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
    }

    if (bind(listen_sock, &g_cfg.listen_addr.sa, sizeof_sockaddr(&g_cfg.listen_addr)) < 0) {
        P_LOG_ERR("bind(): %s", strerror(errno));
        goto cleanup;
    }

    set_nonblock(listen_sock);
    if (g_sockbuf_cap_runtime > 0) {
        if (setsockopt(listen_sock, SOL_SOCKET, SO_RCVBUF, &g_sockbuf_cap_runtime,
                       sizeof(g_sockbuf_cap_runtime)) < 0)
            P_LOG_WARN("setsockopt(SO_RCVBUF): %s", strerror(errno));
        if (setsockopt(listen_sock, SOL_SOCKET, SO_SNDBUF, &g_sockbuf_cap_runtime,
                       sizeof(g_sockbuf_cap_runtime)) < 0)
            P_LOG_WARN("setsockopt(SO_SNDBUF): %s", strerror(errno));
    }

#ifdef EPOLL_CLOEXEC
    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0 && (errno == ENOSYS || errno == EINVAL))
        epfd = epoll_create(1);
#else
    epfd = epoll_create(1);
#endif
    if (epfd < 0) {
        P_LOG_ERR("epoll_create(): %s", strerror(errno));
        goto cleanup;
    }

    g_conn_tbl_hash_size = g_cfg.conn_tbl_hash_size;
    if (g_conn_tbl_hash_size < 64) g_conn_tbl_hash_size = 64;
    if (g_conn_tbl_hash_size > (1u << 20)) g_conn_tbl_hash_size = (1u << 20);

    bucket_index_fun = is_power_of_two(g_conn_tbl_hash_size) ? proxy_conn_hash_bitwise : proxy_conn_hash_mod;

    conn_tbl_hbase = malloc(sizeof(struct list_head) * g_conn_tbl_hash_size);
    if (!conn_tbl_hbase) {
        P_LOG_ERR("malloc(conn_tbl_hbase): failed");
        goto cleanup;
    }
    for (i = 0; (unsigned)i < g_conn_tbl_hash_size; i++) {
        INIT_LIST_HEAD(&conn_tbl_hbase[i]);
    }

    conn_tbl_len = 0;
    last_check = monotonic_seconds();

#ifdef __linux__
    init_batching_resources(&c_msgs, &c_iov, &c_addrs, &c_bufs);
#endif
    ev.data.ptr = &magic_listener;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
#ifdef EPOLLEXCLUSIVE
    ev.events |= EPOLLEXCLUSIVE;
#endif
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_sock, &ev) < 0) {
        P_LOG_ERR("epoll_ctl(ADD, listener): %s", strerror(errno));
        rc = 1;
        goto cleanup;
    }

    static time_t last_keepalive_log = 0;
    static uint64_t last_packets_count = 0;
    static uint64_t last_bytes_count = 0;

    for (;;) {
        time_t current_ts = monotonic_seconds();

        if (g_cfg.proxy_conn_timeo != 0 && (long)(current_ts - last_check) >= MAINT_INTERVAL_SEC) {
            g_now_ts = current_ts;
            proxy_conn_walk_continue(epfd);
            last_check = current_ts;
            if (g_shutdown_requested)
                break;
        }

        if (last_keepalive_log == 0) {
            last_keepalive_log = current_ts;
            last_packets_count = g_stats.packets_processed;
            last_bytes_count = g_stats.bytes_processed;
        }
        if (current_ts < last_keepalive_log) {
            P_LOG_WARN("Time went backwards (current=%ld, last=%ld). Resetting keep-alive timer.",
                       (long)current_ts, (long)last_keepalive_log);
            last_keepalive_log = current_ts;
        }
        if ((long)(current_ts - last_keepalive_log) >= KEEPALIVE_LOG_INTERVAL_SEC) {
            uint64_t packets_delta = g_stats.packets_processed - last_packets_count;
            uint64_t bytes_delta = g_stats.bytes_processed - last_bytes_count;
            time_t interval = current_ts - last_keepalive_log;
            
            P_LOG_INFO("[Keep-Alive] Active sessions: %u/%u, "
                       "Packets: %" PRIu64 " (%.1f pps), "
                       "Bytes: %" PRIu64 " (%.2f KB/s)",
                       conn_tbl_len, 
                       (unsigned)g_conn_pool.capacity,
                       packets_delta,
                       interval > 0 ? (double)packets_delta / interval : 0.0,
                       bytes_delta,
                       interval > 0 ? (double)bytes_delta / interval / 1024.0 : 0.0);
            
            last_keepalive_log = current_ts;
            last_packets_count = g_stats.packets_processed;
            last_bytes_count = g_stats.bytes_processed;
        }

        if (g_shutdown_requested)
            break;

        int nfds = epoll_wait(epfd, events, countof(events), EPOLL_WAIT_TIMEOUT_MS);
        current_ts = monotonic_seconds();
        g_now_ts = current_ts;
        
        if (g_shutdown_requested)
            break;

        if (nfds == 0)
            continue;
        if (nfds < 0) {
            if (errno == EINTR || errno == ERESTART)
                continue;
            P_LOG_ERR("epoll_wait(): %s", strerror(errno));
            rc = 1;
            goto cleanup;
        }

        for (i = 0; i < nfds; i++) {
            struct epoll_event *evp = &events[i];
            struct proxy_conn *conn;

            if (evp->data.ptr == &magic_listener) {
                if (evp->events & (EPOLLERR | EPOLLHUP)) {
                    P_LOG_ERR("listener: EPOLLERR/HUP");
                    rc = 1;
                    goto cleanup;
                }
#ifdef __linux__
                handle_client_data(listen_sock, epfd, c_msgs, c_bufs);
#else
                handle_client_data(listen_sock, epfd);
#endif
            } else {
                conn = evp->data.ptr;
                
                if (conn->ref_count <= 0) {
                    char s_addr[INET6_ADDRSTRLEN] = "unknown";
                    if (conn->svr_sock >= 0)
                        format_client_addr(&conn->cli_addr, s_addr, sizeof(s_addr));
                    P_LOG_INFO("Server data arrived for recycled connection %s (ref_count=%d). "
                               "Discarding. Client must send new data to re-establish.", s_addr, conn->ref_count);
                    continue;
                }
                
                if (evp->events & (EPOLLERR | EPOLLHUP)) {
                    proxy_conn_put(conn, epfd);
                    continue;
                }

                if (evp->events & EPOLLOUT)
                    udp_flush_backlog(conn, epfd);

                if (evp->events & EPOLLIN)
                    handle_server_data(conn, listen_sock, epfd);
            }
        }
    }

cleanup:
    if (listen_sock >= 0)
        safe_close(listen_sock);
    epoll_close_comp(epfd);

    free(conn_tbl_hbase);
    conn_tbl_hbase = NULL;
    conn_pool_destroy(&g_conn_pool);
#ifdef __linux__
    destroy_batching_resources(c_msgs, c_iov, c_addrs, c_bufs);
#endif

    P_LOG_INFO("Performance statistics:");
    P_LOG_INFO("  Total packets processed: %" PRIu64, g_stats.packets_processed);
    P_LOG_INFO("  Total bytes processed: %" PRIu64, g_stats.bytes_processed);
    P_LOG_INFO("  Hash collisions: %" PRIu64 " (avg probe: %.2f)", g_stats.hash_collisions,
               g_stats.packets_processed > 0 ? (double)g_stats.hash_collisions / g_stats.packets_processed : 0.0);

    if (g_stats.packets_processed > 0 && g_stats.hash_collisions > g_stats.packets_processed / 2)
        P_LOG_WARN("High hash collision rate detected (%.1f%%), consider adjusting hash table size",
                   (double)g_stats.hash_collisions * 100.0 / g_stats.packets_processed);
    if (g_stats.packets_processed > 0)
        P_LOG_INFO("  Estimated throughput: %.0f packets/sec",
                   (double)g_stats.packets_processed / (time(NULL) - last_check + 1));
    
    if (g_state.log_file) {
        fclose(g_state.log_file);
        g_state.log_file = NULL;
    }
    closelog();

    return rc;
}
