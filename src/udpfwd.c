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
#include <limits.h>

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
#define MAX_EVENTS 256
#define EPOLL_WAIT_TIMEOUT_MS 500
#define CLIENT_MAX_ITERATIONS 128
#define SERVER_MAX_ITERATIONS 128
#define MAINT_INTERVAL_SEC 2
#define MAX_EXPIRE_PER_SWEEP 64
#define MAX_SCAN_PER_SWEEP 128
#ifndef UDP_PROXY_SOCKBUF_CAP
#define UDP_PROXY_SOCKBUF_CAP (1024 * 1024)
#endif

#ifdef __linux__
#ifndef UDP_PROXY_BATCH_SZ
#define UDP_PROXY_BATCH_SZ 16
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
    uint64_t connections_created;
    uint64_t connections_evicted;
    uint64_t connections_expired;
    uint64_t packets_dropped;  /* Packets dropped due to send failures */
    uint64_t send_errors;      /* Additional send error tracking */
    uint64_t recv_errors;      /* Receive error tracking */
    time_t start_time;         /* Process start time for metrics */
    uint64_t last_stats_time;  /* Last time stats were printed */
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

static inline ssize_t udp_send_retry(int sock, const void *buf, size_t len) {
    if (sock < 0) {
        P_LOG_WARN("udp_send_retry: invalid socket descriptor %d", sock);
        return -1;
    }
    
    if (!buf || len == 0) {
        P_LOG_WARN("udp_send_retry: invalid buffer parameters");
        return -1;
    }
    
    ssize_t wr;
    int retry_count = 0;
    const int max_retries = 3;
    
    do {
        wr = send(sock, buf, len, 0);
        if (wr < 0 && errno == EINTR) {
            retry_count++;
            if (retry_count >= max_retries) {
                P_LOG_WARN("udp_send_retry: too many interrupts (%d), giving up", max_retries);
                break;
            }
        }
    } while (wr < 0 && errno == EINTR);
    
    return wr;
}

static inline void set_socket_buffers(int sock, int bufsize) {
    if (sock < 0) {
        P_LOG_WARN("set_socket_buffers: invalid socket descriptor %d", sock);
        return;
    }
    
    if (bufsize <= 0) {
        P_LOG_WARN("set_socket_buffers: invalid buffer size %d", bufsize);
        return;
    }
    
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) < 0)
        P_LOG_WARN("setsockopt(SO_RCVBUF, fd=%d, size=%d): %s", sock, bufsize, strerror(errno));
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0)
        P_LOG_WARN("setsockopt(SO_SNDBUF, fd=%d, size=%d): %s", sock, bufsize, strerror(errno));
}

static bool parse_ulong_opt(const char *optarg, const char *opt_name,
                           unsigned long *out, unsigned long min, unsigned long max,
                           unsigned long default_val) {
    if (!optarg || !opt_name || !out) {
        P_LOG_WARN("Invalid parameters passed to parse_ulong_opt");
        return false;
    }
    
    /* Check for empty string */
    if (*optarg == '\0') {
        P_LOG_WARN("Empty %s value, keeping default %lu", opt_name, default_val);
        return false;
    }
    
    char *end = NULL;
    errno = 0; /* Clear errno to detect overflow */
    unsigned long v = strtoul(optarg, &end, 10);
    
    /* Check for conversion errors */
    if (end == optarg || *end != '\0') {
        P_LOG_WARN("Invalid %s value '%s' (not a number), keeping default %lu", 
                   opt_name, optarg, default_val);
        return false;
    }
    
    /* Check for overflow/underflow */
    if (errno == ERANGE) {
        P_LOG_WARN("%s value '%s' out of range, keeping default %lu", 
                   opt_name, optarg, default_val);
        return false;
    }
    
    /* Apply bounds checking */
    if (v < min) {
        P_LOG_WARN("%s value %lu below minimum %lu, using minimum", 
                   opt_name, v, min);
        v = min;
    }
    if (v > max) {
        P_LOG_WARN("%s value %lu above maximum %lu, using maximum", 
                   opt_name, v, max);
        v = max;
    }
    
    *out = v;
    return true;
}

static bool parse_long_opt(const char *optarg, const char *opt_name,
                          long *out, long min, long max,
                          long default_val) {
    if (!optarg || !opt_name || !out) {
        P_LOG_WARN("Invalid parameters passed to parse_long_opt");
        return false;
    }
    
    /* Check for empty string */
    if (*optarg == '\0') {
        P_LOG_WARN("Empty %s value, keeping default %ld", opt_name, default_val);
        return false;
    }
    
    char *end = NULL;
    errno = 0; /* Clear errno to detect overflow */
    long v = strtol(optarg, &end, 10);
    
    /* Check for conversion errors */
    if (end == optarg || *end != '\0') {
        P_LOG_WARN("Invalid %s value '%s' (not a number), keeping default %ld", 
                   opt_name, optarg, default_val);
        return false;
    }
    
    /* Check for overflow/underflow */
    if (errno == ERANGE) {
        P_LOG_WARN("%s value '%s' out of range, keeping default %ld", 
                   opt_name, optarg, default_val);
        return false;
    }
    
    /* Additional validation for positive-only parameters */
    if (min > 0 && v <= 0) {
        P_LOG_WARN("%s value %ld must be positive, keeping default %ld", 
                   opt_name, v, default_val);
        return false;
    }
    
    /* Apply bounds checking */
    if (v < min) {
        P_LOG_WARN("%s value %ld below minimum %ld, using minimum", 
                   opt_name, v, min);
        v = min;
    }
    if (v > max) {
        P_LOG_WARN("%s value %ld above maximum %ld, using maximum", 
                   opt_name, v, max);
        v = max;
    }
    
    *out = v;
    return true;
}

static void print_keepalive_status(time_t *last_log, uint64_t *last_pkts, uint64_t *last_bytes, time_t now) {
    if (!last_log || !last_pkts || !last_bytes) {
        P_LOG_WARN("print_keepalive_status: NULL parameters");
        return;
    }
    
    if (*last_log == 0) {
        *last_log = now;
        *last_pkts = g_stats.packets_processed;
        *last_bytes = g_stats.bytes_processed;
        return;
    }

    /* Handle time going backwards */
    if (now < *last_log) {
        P_LOG_DEBUG("Time went backwards (%ld -> %ld), resetting keepalive timer", *last_log, now);
        *last_log = now;
        return;
    }

    if ((long)(now - *last_log) >= KEEPALIVE_LOG_INTERVAL_SEC) {
        uint64_t packets_delta = g_stats.packets_processed - *last_pkts;
        uint64_t bytes_delta = g_stats.bytes_processed - *last_bytes;
        time_t interval = now - *last_log;

        double pps = interval > 0 ? (double)packets_delta / interval : 0.0;
        double kbps = interval > 0 ? (double)bytes_delta / interval / 1024.0 : 0.0;
        
        /* Calculate memory usage efficiency */
        double conn_efficiency = g_conn_pool.capacity > 0 ? 
            (double)conn_tbl_len * 100.0 / g_conn_pool.capacity : 0.0;
        
        P_LOG_INFO("[Keep-Alive] Status Update:");
        P_LOG_INFO("  Runtime: %ld sec, Active sessions: %u/%u (%.1f%% used)",
                   interval, conn_tbl_len, (unsigned)g_conn_pool.capacity, conn_efficiency);
        P_LOG_INFO("  Packets: %" PRIu64 " (%.1f pps), Bytes: %" PRIu64 " (%.2f KB/s)",
                   packets_delta, pps, bytes_delta, kbps);
        
        /* Health indicators */
        if (pps > 1000) {
            P_LOG_INFO("  Status: HEALTHY (high throughput)");
        } else if (pps > 100) {
            P_LOG_INFO("  Status: NORMAL (moderate throughput)");
        } else {
            P_LOG_INFO("  Status: IDLE (low throughput)");
        }

        *last_log = now;
        *last_pkts = g_stats.packets_processed;
        *last_bytes = g_stats.bytes_processed;
    }
}

static inline time_t monotonic_seconds(void) {
#ifdef __linux__
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (time_t)ts.tv_sec;
#endif
    return time(NULL);
}

static void print_statistics(time_t start_time) {
    time_t runtime = monotonic_seconds() - start_time;
    
    P_LOG_INFO("=== UDP Forwarder Performance Statistics ===");
    P_LOG_INFO("Runtime: %ld seconds", runtime);
    P_LOG_INFO("  Total packets processed: %" PRIu64, g_stats.packets_processed);
    P_LOG_INFO("  Total bytes processed: %" PRIu64 " (%.2f MB)",
               g_stats.bytes_processed, (double)g_stats.bytes_processed / (1024.0 * 1024.0));
    P_LOG_INFO("  Connections created: %" PRIu64, g_stats.connections_created);
    P_LOG_INFO("  Connections expired: %" PRIu64, g_stats.connections_expired);
    P_LOG_INFO("  Connections evicted: %" PRIu64, g_stats.connections_evicted);
    P_LOG_INFO("  Packets dropped: %" PRIu64, g_stats.packets_dropped);
    P_LOG_INFO("  Send errors: %" PRIu64, g_stats.send_errors);
    P_LOG_INFO("  Receive errors: %" PRIu64, g_stats.recv_errors);
    P_LOG_INFO("  Hash collisions: %" PRIu64 " (avg probe: %.2f)", g_stats.hash_collisions,
               g_stats.packets_processed > 0 ? (double)g_stats.hash_collisions / g_stats.packets_processed : 0.0);
    P_LOG_INFO("  Active connections: %u/%u", conn_tbl_len, (unsigned)g_conn_pool.capacity);
    P_LOG_INFO("  Hash table size: %u buckets", g_conn_tbl_hash_size);

    /* Performance warnings and recommendations */
    if (g_stats.packets_processed > 0) {
        double collision_rate = (double)g_stats.hash_collisions * 100.0 / g_stats.packets_processed;
        if (collision_rate > 50.0) {
            P_LOG_WARN("High hash collision rate detected (%.1f%%). Consider increasing hash table size (-H).",
                       collision_rate);
        }
        
        double drop_rate = (double)g_stats.packets_dropped * 100.0 / g_stats.packets_processed;
        if (drop_rate > 1.0) {
            P_LOG_WARN("High packet drop rate detected (%.1f%%). Network may be congested or buffers insufficient.",
                       drop_rate);
        }
        
        double error_rate = (double)(g_stats.send_errors + g_stats.recv_errors) * 100.0 / g_stats.packets_processed;
        if (error_rate > 0.1) {
            P_LOG_WARN("High error rate detected (%.1f%%). Check system resources and network stability.",
                       error_rate);
        }
    }
    
    if (g_stats.packets_dropped > 0) {
        P_LOG_WARN("Packets dropped (%" PRIu64 ") due to send failures. Check network connectivity and buffer sizes.",
                   g_stats.packets_dropped);
    }
    
    if (g_stats.send_errors > 0 || g_stats.recv_errors > 0) {
        P_LOG_WARN("Network errors detected - Send: %" PRIu64 ", Receive: %" PRIu64 ". Consider network diagnostics.",
                   g_stats.send_errors, g_stats.recv_errors);
    }

    /* Throughput calculations */
    if (g_stats.packets_processed > 0 && runtime > 0) {
        double pps = (double)g_stats.packets_processed / runtime;
        double kbps = (double)g_stats.bytes_processed / runtime / 1024.0;
        
        P_LOG_INFO("  Average throughput: %.0f packets/sec, %.2f KB/sec", pps, kbps);
        
        /* Performance classification */
        if (pps > 10000) {
            P_LOG_INFO("  Performance: EXCELLENT (>10K pps)");
        } else if (pps > 5000) {
            P_LOG_INFO("  Performance: GOOD (>5K pps)");
        } else if (pps > 1000) {
            P_LOG_INFO("  Performance: FAIR (>1K pps)");
        } else {
            P_LOG_INFO("  Performance: POOR (<1K pps) - consider optimization");
        }
        
        /* Calculate success rate */
        double success_rate = (double)(g_stats.packets_processed - g_stats.packets_dropped) * 100.0 / g_stats.packets_processed;
        P_LOG_INFO("  Success rate: %.2f%% (%" PRIu64 "/%" PRIu64 ")",
                   success_rate, g_stats.packets_processed - g_stats.packets_dropped, g_stats.packets_processed);
    }
    
    P_LOG_INFO("=== End Statistics ===");
}

static inline time_t cached_now_seconds(void) {
    if (g_now_ts == 0)
        g_now_ts = monotonic_seconds();
    return g_now_ts;
}

static int safe_close(int fd) {
    if (fd < 0) {
        P_LOG_DEBUG("safe_close: invalid file descriptor %d", fd);
        return 0;
    }
    
    int retry_count = 0;
    const int max_retries = 3;
    
    while (close(fd) != 0) {
        if (errno != EINTR) {
            P_LOG_WARN("safe_close(fd=%d): %s", fd, strerror(errno));
            return -1;
        }
        
        retry_count++;
        if (retry_count >= max_retries) {
            P_LOG_WARN("safe_close: too many interrupts (%d) for fd=%d, giving up", max_retries, fd);
            return -1;
        }
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
    if (!is_temporary_errno(e)) {
        P_LOG_WARN("%s: %s", what, strerror(e));
        
        /* Track error statistics */
        if (strstr(what, "send") || strstr(what, "sendmmsg")) {
            g_stats.send_errors++;
        } else if (strstr(what, "recv") || strstr(what, "recvmmsg")) {
            g_stats.recv_errors++;
        }
    }
}

static inline bool validate_packet(const char *data, size_t len, const union sockaddr_inx *src) {
    /* Validate input parameters */
    if (!data || !src) {
        P_LOG_WARN("validate_packet: NULL data or src pointer");
        return false;
    }
    
    /* Basic sanity check: packet must be non-empty and within MTU limits */
    if (len == 0) {
        P_LOG_DEBUG("validate_packet: empty packet discarded");
        return false;
    }
    
    if (len > UDP_PROXY_DGRAM_CAP) {
        P_LOG_WARN("validate_packet: oversized packet (%zu bytes) discarded", len);
        return false;
    }
    
    /* Validate address family */
    if (src->sa.sa_family != AF_INET && src->sa.sa_family != AF_INET6) {
        P_LOG_WARN("validate_packet: unsupported address family %d", src->sa.sa_family);
        return false;
    }
    
    return true;
}

static inline bool is_power_of_two(unsigned v) {
    return v && ((v & (v - 1)) == 0);
}

static inline void proxy_conn_hold(struct proxy_conn *conn) {
    if (!conn) {
        P_LOG_WARN("proxy_conn_hold: NULL connection pointer");
        return;
    }
    if (conn->ref_count == UINT_MAX) {
        P_LOG_WARN("proxy_conn_hold: reference count overflow detected");
        return;
    }
    conn->ref_count++;
}

static struct proxy_conn *init_proxy_conn(struct proxy_conn *conn) {
    if (!conn) {
        P_LOG_WARN("init_proxy_conn: NULL connection pointer");
        return NULL;
    }

    memset(conn, 0, sizeof(*conn));
    conn->ref_count = 1;
    conn->svr_sock = -1;
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

    /* Handle time going backwards (system clock adjustment) */
    if (now < old_active) {
        conn->last_active = now;
        return;
    }

    conn->last_active = now;

    if (old_active != now && (now - old_active) > TIME_GAP_WARNING_THRESHOLD_SEC) {
        char s_addr[INET6_ADDRSTRLEN];
        format_client_addr(&conn->cli_addr, s_addr, sizeof(s_addr));
        P_LOG_WARN("Large time gap for %s:%d: gap=%ld sec. System may have been suspended.",
                   s_addr, ntohs(*port_of_sockaddr(&conn->cli_addr)),
                   (long)(now - old_active));
    }
}

static struct proxy_conn *proxy_conn_get_or_create(const union sockaddr_inx *cli_addr, int epfd) {
    if (!cli_addr) {
        P_LOG_WARN("proxy_conn_get_or_create: NULL client address");
        return NULL;
    }
    
    if (epfd < 0) {
        P_LOG_WARN("proxy_conn_get_or_create: invalid epoll fd %d", epfd);
        return NULL;
    }
    
    struct list_head *chain = &conn_tbl_hbase[bucket_index_fun(cli_addr)];
    struct proxy_conn *conn = NULL;
    int svr_sock = -1;
    struct epoll_event ev;
    char s_addr[INET6_ADDRSTRLEN] = "";

    /* Track hash collisions for performance monitoring */
    int chain_len = 0;
    list_for_each_entry(conn, chain, list) {
        chain_len++;
        if (is_sockaddr_inx_equal(cli_addr, &conn->cli_addr)) {
            if (chain_len > 1)
                g_stats.hash_collisions += (chain_len - 1);
            touch_proxy_conn(conn);
            /* Move to end of LRU list (most recently used) */
            if (!list_empty(&conn->lru)) {
                list_del(&conn->lru);
                list_add_tail(&conn->lru, &g_lru_list);
            }
            return conn;
        }
    }

    /* Track collisions for new connection insertion */
    if (chain_len > 0)
        g_stats.hash_collisions += chain_len;

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

    /* Create server socket with proper error handling */
    svr_sock = socket(g_cfg.dst_addr.sa.sa_family, SOCK_DGRAM, 0);
    if (svr_sock < 0) {
        P_LOG_ERR("socket(svr_sock): %s", strerror(errno));
        goto err;
    }

    /* Always set socket buffer sizes for connection socket (same as listen socket) */
    set_socket_buffers(svr_sock, g_sockbuf_cap_runtime);

    if (connect(svr_sock, (struct sockaddr *)&g_cfg.dst_addr, sizeof_sockaddr(&g_cfg.dst_addr)) != 0) {
        P_LOG_WARN("Connection failed: %s", strerror(errno));
        goto err;
    }
    set_nonblock(svr_sock);

    /* Initialize connection structure */
    conn = init_proxy_conn(conn_pool_alloc(&g_conn_pool));
    if (!conn) {
        P_LOG_ERR("conn_pool_alloc: failed");
        goto err_unlock;
    }
    
    conn->svr_sock = svr_sock;
    conn->cli_addr = *cli_addr;
    conn->last_active = cached_now_seconds();
    
    /* Initialize LRU list head - required for list_empty() checks */
    INIT_LIST_HEAD(&conn->lru);

    /* Add to epoll */
    ev.data.ptr = conn;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, conn->svr_sock, &ev) < 0) {
        P_LOG_ERR("epoll_ctl(ADD, svr_sock): %s", strerror(errno));
        goto err_unlock;
    }

    /* Add to hash table and LRU */
    list_add_tail(&conn->list, chain);
    list_add_tail(&conn->lru, &g_lru_list);

    format_client_addr(cli_addr, s_addr, sizeof(s_addr));
    P_LOG_INFO("New UDP session [%s]:%d, total %u", s_addr,
               ntohs(*port_of_sockaddr(cli_addr)), conn_tbl_len);

    g_stats.connections_created++;
    /* ref_count is already 1 from init_proxy_conn */
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

    conn_pool_release(&g_conn_pool, conn);
}

static void proxy_conn_put(struct proxy_conn *conn, int epfd) {
    if (!conn) {
        P_LOG_WARN("proxy_conn_put: NULL connection pointer");
        return;
    }
    
    if (conn->ref_count == 0) {
        P_LOG_WARN("proxy_conn_put: reference count already zero");
        return;
    }
    
    if (--conn->ref_count == 0) {
        release_proxy_conn(conn, epfd);
    }
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

        /* Handle time going backwards - reset last_active to current time */
        if (now < conn->last_active) {
            conn->last_active = now;
            continue;
        }

        unsigned long diff = (unsigned long)(now - conn->last_active);

        if (g_cfg.proxy_conn_timeo != 0 && diff > g_cfg.proxy_conn_timeo) {
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
        g_stats.connections_expired++;
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
    g_stats.connections_evicted++;
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

                proxy_conn_hold(conn);  /* Hold reference for this operation */
                conn->client_packets++;
                touch_proxy_conn(conn);

                /* Direct send, no backlog buffering */
                ssize_t wr = udp_send_retry(conn->svr_sock, c_bufs[i], packet_len);
                if (wr < 0) {
                    g_stats.packets_dropped++;
                    if (!is_wouldblock(errno))
                        log_if_unexpected_errno("send(server)");
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

    proxy_conn_hold(conn);  /* Hold reference for this operation */
    conn->client_packets++;
    touch_proxy_conn(conn);

    /* Direct send, no backlog buffering */
    ssize_t wr = udp_send_retry(conn->svr_sock, buffer, r);
    if (wr < 0) {
        g_stats.packets_dropped++;
        if (!is_wouldblock(errno))
            log_if_unexpected_errno("send(server)");
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
    
    /* Validate batch size */
    if (ncap <= 0 || ncap > UDP_PROXY_BATCH_SZ) {
        P_LOG_WARN("init_batching_resources: invalid batch size %d, using default %d", 
                   ncap, UDP_PROXY_BATCH_SZ);
        ncap = UDP_PROXY_BATCH_SZ;
    }

    size_t size_c_msgs = (size_t)ncap * sizeof(**c_msgs);
    size_t size_c_iov  = (size_t)ncap * sizeof(**c_iov);
    size_t size_c_addrs= (size_t)ncap * sizeof(**c_addrs);
    size_t size_c_bufs = (size_t)ncap * sizeof(**c_bufs);
    size_t total = size_c_msgs + size_c_iov + size_c_addrs + size_c_bufs;
    
    /* Check for potential overflow */
    if (total < size_c_msgs || total < size_c_iov || total < size_c_addrs || total < size_c_bufs) {
        P_LOG_ERR("init_batching_resources: size calculation overflow");
        goto fail;
    }

    void *block = aligned_alloc(64, align_up(total, 64));
    if (!block) {
        P_LOG_WARN("Failed to allocate UDP batching buffers (%zu bytes); proceeding without batching.", total);
        goto fail;
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
        /* Initialize control fields to prevent uninitialized memory */
        (*c_msgs)[i].msg_hdr.msg_control = NULL;
        (*c_msgs)[i].msg_hdr.msg_controllen = 0;
        (*c_msgs)[i].msg_hdr.msg_flags = 0;
    }
    
    P_LOG_DEBUG("UDP batching resources initialized: batch_size=%d, total_allocated=%zu bytes", 
                ncap, total);
    return;
    
fail:
    *c_msgs = NULL;
    *c_iov = NULL;
    *c_addrs = NULL;
    *c_bufs = NULL;
}

static void destroy_batching_resources(struct mmsghdr *c_msgs, struct iovec *c_iov,
                                       struct sockaddr_storage *c_addrs,
                                       char (*c_bufs)[UDP_PROXY_DGRAM_CAP]) {
    (void)c_iov; (void)c_addrs; (void)c_bufs;
    
    if (c_msgs) {
        P_LOG_DEBUG("Destroying UDP batching resources");
        free(c_msgs);
    } else {
        P_LOG_DEBUG("UDP batching resources already NULL, nothing to destroy");
    }
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
    P_LOG_INFO("  -S <bytes>       SO_RCVBUF/SO_SNDBUF for sockets (default: %d = 1MB)",
               UDP_PROXY_SOCKBUF_CAP);
    P_LOG_INFO("  -C <max_conns>   maximum tracked UDP sessions (default: %d)",
               UDP_PROXY_MAX_CONNS);
    P_LOG_INFO("  -B <batch>       Linux recvmmsg/sendmmsg batch size (1..32, "
               "default: %d)",
               UDP_PROXY_BATCH_SZ);
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
    bool resources_initialized = false;

#ifdef __linux__
    struct mmsghdr *c_msgs = NULL;
    struct iovec *c_iov = NULL;
    struct sockaddr_storage *c_addrs = NULL;
    char (*c_bufs)[UDP_PROXY_DGRAM_CAP] = {0};
#endif

    /* Initialize statistics */
    g_stats.start_time = monotonic_seconds();
    g_stats.last_stats_time = g_stats.start_time;

    /* Initialize configuration with defaults */
    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.proxy_conn_timeo = DEFAULT_CONN_TIMEOUT_SEC;
    g_cfg.conn_tbl_hash_size = DEFAULT_HASH_TABLE_SIZE;

    P_LOG_INFO("UDP Forwarder starting up...");

    /* Parse command line arguments */
    int opt;
    while ((opt = getopt(argc, argv, "hdvRr6p:i:t:S:C:B:H:")) != -1) {
        switch (opt) {
        case 't': {
            unsigned long v;
            if (parse_ulong_opt(optarg, "-t", &v, 0, 86400UL, g_cfg.proxy_conn_timeo))
                g_cfg.proxy_conn_timeo = (unsigned)v;
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
            unsigned long v;
            if (parse_ulong_opt(optarg, "-i", &v, 1, ULONG_MAX, g_cfg.max_per_ip_connections))
                g_cfg.max_per_ip_connections = (unsigned)v;
            break;
        }
        case 'S': {
            long v;
            if (parse_long_opt(optarg, "-S", &v, 4096, 8 << 20, g_sockbuf_cap_runtime))
                g_sockbuf_cap_runtime = (int)v;
            break;
        }
        case 'C': {
            long v;
            if (parse_long_opt(optarg, "-C", &v, 64, 1 << 20, g_conn_pool_capacity))
                g_conn_pool_capacity = (int)v;
            break;
        }
        case 'B': {
#ifdef __linux__
            long v;
            if (parse_long_opt(optarg, "-B", &v, 1, UDP_PROXY_BATCH_SZ, g_batch_sz_runtime))
                g_batch_sz_runtime = (int)v;
#else
            P_LOG_WARN("-B has no effect on non-Linux builds");
#endif
            break;
        }
        case 'H': {
            unsigned long v;
            if (parse_ulong_opt(optarg, "-H", &v, 64, 1UL << 20, g_cfg.conn_tbl_hash_size)) {
                g_cfg.conn_tbl_hash_size = (v == 0) ? 4093 : (unsigned)v;
            }
            break;
        }
        default:
            show_help(argv[0]);
            return 1;
        }
    }

    /* Validate arguments */
    if (optind > argc - 2) {
        P_LOG_ERR("Missing required arguments");
        show_help(argv[0]);
        return 1;
    }

    /* Parse addresses */
    if (get_sockaddr_inx(argv[optind], &g_cfg.listen_addr, true) != 0) {
        P_LOG_ERR("Failed to parse listen address: %s", argv[optind]);
        return 1;
    }
    if (get_sockaddr_inx(argv[optind + 1], &g_cfg.dst_addr, false) != 0) {
        P_LOG_ERR("Failed to parse destination address: %s", argv[optind + 1]);
        return 1;
    }

    /* Initialize logging */
    openlog("udpfwd", LOG_PID | LOG_PERROR, LOG_DAEMON);

    /* Daemonize if requested */
    if (g_cfg.daemonize) {
        if (do_daemonize() != 0) {
            P_LOG_ERR("Failed to daemonize");
            return 1;
        }

        char log_path[256];
        unsigned short listen_port = ntohs(*port_of_sockaddr(&g_cfg.listen_addr));
        snprintf(log_path, sizeof(log_path), "/var/log/udpfwd_%u.log", listen_port);

        g_state.log_file = fopen(log_path, "a");
        if (!g_state.log_file)
            syslog(LOG_WARNING, "Failed to open log file %s: %s, using syslog", log_path, strerror(errno));
        else
            P_LOG_INFO("UDP forwarder started, logging to %s", log_path);
    }

    /* Create PID file if requested */
    if (g_cfg.pidfile) {
        if (create_pid_file(g_cfg.pidfile) != 0) {
            P_LOG_ERR("Failed to create PID file: %s", g_cfg.pidfile);
            goto cleanup;
        }
    }

    /* Initialize connection pool */
    if (conn_pool_init(&g_conn_pool, g_conn_pool_capacity, sizeof(struct proxy_conn)) < 0) {
        P_LOG_ERR("conn_pool_init: failed");
        goto cleanup;
    }
    resources_initialized = true;

    /* Setup signal handlers */
    if (init_signals() != 0) {
        P_LOG_ERR("setup_shutdown_signals: failed");
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
    /* Always set socket buffer sizes to optimized default (1MB) */
    set_socket_buffers(listen_sock, g_sockbuf_cap_runtime);

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

        print_keepalive_status(&last_keepalive_log, &last_packets_count, &last_bytes_count, current_ts);

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

                /* Safety check: connection should have ref_count >= 1 */
                if (unlikely(conn->ref_count < 1)) {
                    char s_addr[INET6_ADDRSTRLEN] = "unknown";
                    if (conn->svr_sock >= 0)
                        format_client_addr(&conn->cli_addr, s_addr, sizeof(s_addr));
                    P_LOG_WARN("Event for connection with invalid ref_count=%d (%s). Skipping.",
                               conn->ref_count, s_addr);
                    continue;
                }

                if (evp->events & (EPOLLERR | EPOLLHUP)) {
                    proxy_conn_hold(conn);
                    proxy_conn_put(conn, epfd);
                    continue;
                }

                /* Process server data */
                if (evp->events & EPOLLIN)
                    handle_server_data(conn, listen_sock, epfd);
            }
        }
    }

cleanup:
    P_LOG_INFO("UDP Forwarder shutting down...");
    
    /* Print final statistics before cleanup */
    if (resources_initialized) {
        print_statistics(g_stats.start_time);
    }
    
    /* Close listening socket */
    if (listen_sock >= 0) {
        P_LOG_DEBUG("Closing listening socket (fd=%d)", listen_sock);
        safe_close(listen_sock);
        listen_sock = -1;
    }
    
    /* Close epoll instance */
    if (epfd >= 0) {
        P_LOG_DEBUG("Closing epoll instance (fd=%d)", epfd);
        epoll_close_comp(epfd);
        epfd = -1;
    }

    /* Clean up hash table */
    if (conn_tbl_hbase) {
        P_LOG_DEBUG("Cleaning up connection hash table");
        free(conn_tbl_hbase);
        conn_tbl_hbase = NULL;
    }
    
    /* Clean up connection pool */
    if (resources_initialized) {
        P_LOG_DEBUG("Destroying connection pool");
        conn_pool_destroy(&g_conn_pool);
    }
    
#ifdef __linux__
    /* Clean up batching resources */
    destroy_batching_resources(c_msgs, c_iov, c_addrs, c_bufs);
    c_msgs = NULL;
    c_iov = NULL;
    c_addrs = NULL;
    c_bufs = NULL;
#endif

    /* Clean up logging */
    if (g_state.log_file) {
        P_LOG_DEBUG("Closing log file");
        fclose(g_state.log_file);
        g_state.log_file = NULL;
    }
    
    /* Clean up PID file */
    if (g_cfg.pidfile) {
        cleanup_pidfile();
    }
    
    closelog();
    
    P_LOG_INFO("UDP Forwarder shutdown complete");
    return rc;
}
