/**
 * @file tcpfwd.c
 * @brief High-performance TCP port forwarding proxy with connection pooling
 *
 * This implementation provides:
 * - Thread-safe connection pooling with dynamic expansion
 * - Connection rate limiting per IP and total
 * - Zero-copy forwarding using Linux splice() when available
 * - Robust error handling and graceful shutdown
 * - Dynamic epoll event array sizing for optimal performance
 * - Comprehensive security checks for transparent proxy mode
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <syslog.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#include "common.h"
#include "list.h"
#include "proxy_conn.h"
#include "fwd_util.h"

#ifdef __linux__
#include <netinet/tcp.h>
#include <linux/netfilter_ipv4.h>
#endif

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Constants and Tunables */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Buffer size tunables for throughput */
#ifndef TCP_PROXY_USERBUF_CAP
#define TCP_PROXY_USERBUF_CAP (64 * 1024)
#endif
#ifndef TCP_PROXY_SOCKBUF_CAP
#define TCP_PROXY_SOCKBUF_CAP (256 * 1024)
#endif

/* Backpressure watermark: when opposite TX backlog exceeds this, limit further
 * reads */
#ifndef TCP_PROXY_BACKPRESSURE_WM
#define TCP_PROXY_BACKPRESSURE_WM (TCP_PROXY_USERBUF_CAP * 3 / 4)
#endif

/* TCP Keepalive defaults (Linux specific tunables guarded at runtime) */
#ifndef TCP_PROXY_KEEPALIVE_IDLE
#define TCP_PROXY_KEEPALIVE_IDLE 60
#endif
#ifndef TCP_PROXY_KEEPALIVE_INTVL
#define TCP_PROXY_KEEPALIVE_INTVL 10
#endif
#ifndef TCP_PROXY_KEEPALIVE_CNT
#define TCP_PROXY_KEEPALIVE_CNT 6
#endif

/* Memory pool for connection objects (default) */
#define TCP_PROXY_CONN_POOL_SIZE 4096

/* Epoll event batch size - start small and grow as needed */
#define EPOLL_EVENTS_MIN 64
#define EPOLL_EVENTS_MAX 2048
#define EPOLL_EVENTS_DEFAULT 512

/* Connection limiting constants */
#define MAX_CONSECUTIVE_ACCEPT_ERRORS 10
#define ACCEPT_ERROR_RESET_INTERVAL 60 /* seconds */
#define ACCEPT_ERROR_DELAY_US 100000   /* 100ms in microseconds */
#define MAX_TOTAL_CONNECTIONS_LIMIT 1000000
#define MAX_PER_IP_CONNECTIONS_LIMIT 10000

/* Buffer management constants */
#define BUFFER_COMPACT_THRESHOLD_RATIO                                         \
    4                            /* Compact when waste > 1/4 of capacity */
#define EPOLL_EXPAND_THRESHOLD 3 /* Expand after 3 consecutive full batches */
#define EPOLL_SHRINK_THRESHOLD                                                 \
    10 /* Shrink after 10 consecutive small batches */
#define EPOLL_SHRINK_USAGE_RATIO 4 /* Shrink when usage < 1/4 of capacity */

/* Network validation constants */
#define MIN_PORT_OFFSET -65535
#define MAX_PORT_OFFSET 65535
#define LISTEN_BACKLOG 128

/* Magic numbers for epoll event identification */
#define EV_MAGIC_LISTENER 0xdeadbeefU
#define EV_MAGIC_CLIENT 0xfeedfaceU
#define EV_MAGIC_SERVER 0xbaadcafeU

/* IPv4 address validation constants */
#define IPV4_ADDR_CLASS_A_PRIVATE 0x0A000000U /* 10.0.0.0/8 */
#define IPV4_ADDR_CLASS_A_PRIVATE_MASK 0xFF000000U
#define IPV4_ADDR_CLASS_B_PRIVATE 0xAC100000U /* 172.16.0.0/12 */
#define IPV4_ADDR_CLASS_B_PRIVATE_MASK 0xFFF00000U
#define IPV4_ADDR_CLASS_C_PRIVATE 0xC0A80000U /* 192.168.0.0/16 */
#define IPV4_ADDR_CLASS_C_PRIVATE_MASK 0xFFFF0000U
#define IPV4_ADDR_LOOPBACK 0x7F000000U /* 127.0.0.0/8 */
#define IPV4_ADDR_LOOPBACK_MASK 0xFF000000U
#define IPV4_ADDR_MULTICAST 0xE0000000U /* 224.0.0.0/4 */
#define IPV4_ADDR_MULTICAST_MASK 0xF0000000U
#define IPV4_ADDR_RESERVED 0xF0000000U /* 240.0.0.0/4 */
#define IPV4_ADDR_RESERVED_MASK 0xF0000000U

/* Buffer and I/O constants */
#define SPLICE_CHUNK_SIZE 65536
#define MIN_VALID_POINTER 4096
#define SOCKET_OPTION_RETRY_COUNT 3

/* Statistics and monitoring constants */
#define STATS_REPORT_INTERVAL_SEC 300 /* Report stats every 5 minutes */
#define HEALTH_CHECK_SOCKET_PATH "/tmp/tcpfwd.health"
#define STATS_BUFFER_SIZE 4096

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Data Structures */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/**
 * @brief Configuration structure for the TCP forwarder
 *
 * Contains all runtime configuration including addresses, limits,
 * and behavioral flags.
 */


/**
 * @brief Connection limiting structures for DoS protection
 *
 * Implements a simple hash table to track connections per IP address
 * and enforce both per-IP and total connection limits.
 */
#define CONN_LIMIT_HASH_SIZE 1024

struct conn_limit_entry {
    union sockaddr_inx addr; /**< Client IP address */
    int count;               /**< Current connection count for this IP */
    time_t first_seen;       /**< First connection timestamp */
    time_t last_seen;        /**< Last connection timestamp */
};

struct conn_limiter {
    struct conn_limit_entry
        entries[CONN_LIMIT_HASH_SIZE]; /**< Hash table entries */
    int total_connections;             /**< Current total active connections */
    int max_total;                     /**< Maximum total connections allowed */
    int max_per_ip;                    /**< Maximum connections per IP */
    pthread_mutex_t lock;              /**< Thread safety mutex */
};

/**
 * @brief Comprehensive statistics structure for monitoring and debugging
 *
 * Tracks various metrics including connection counts, data transfer volumes,
 * error rates, and performance indicators. All counters are atomic for
 * thread-safe access from multiple contexts.
 */
struct proxy_stats {
    /* Connection statistics */
    volatile uint64_t total_accepted; /**< Total connections accepted */
    volatile uint64_t
        total_connected;            /**< Total successful server connections */
    volatile uint64_t total_failed; /**< Total failed connections */
    volatile uint64_t current_active;  /**< Currently active connections */
    volatile uint64_t peak_concurrent; /**< Peak concurrent connections */

    /* Traffic statistics */
    volatile uint64_t bytes_received;  /**< Total bytes received from clients */
    volatile uint64_t bytes_sent;      /**< Total bytes sent to clients */
    volatile uint64_t bytes_forwarded; /**< Total bytes forwarded to servers */
    volatile uint64_t
        splice_operations; /**< Number of splice operations performed */
    volatile uint64_t
        buffer_operations; /**< Number of buffer copy operations */

    /* Performance statistics */
    volatile uint64_t epoll_iterations; /**< Total epoll_wait() calls */
    volatile uint64_t
        epoll_events_processed; /**< Total epoll events processed */
    volatile uint32_t
        epoll_array_expansions; /**< Times epoll array was expanded */
    volatile uint32_t epoll_array_shrinks; /**< Times epoll array was shrunk */

    /* Error statistics */
    volatile uint64_t accept_errors;   /**< Accept errors encountered */
    volatile uint64_t connect_errors;  /**< Server connection errors */
    volatile uint64_t forward_errors;  /**< Data forwarding errors */
    volatile uint64_t resource_errors; /**< Resource allocation errors */
    volatile uint64_t
        limit_rejections; /**< Connections rejected due to limits */

    /* Timing information */
    time_t start_time;        /**< Process start time */
    time_t last_stats_report; /**< Last statistics report time */

    /* Thread safety */
    pthread_mutex_t lock; /**< Mutex for non-atomic operations */
};


/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Global Variables */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/* Global state protected by mutex where needed */
static struct conn_pool g_conn_pool;
static struct conn_limiter g_conn_limiter;
static struct proxy_stats g_stats;

/* Runtime tunables (overridable via CLI) - these are read-only after
 * initialization */
static int g_conn_pool_capacity = TCP_PROXY_CONN_POOL_SIZE;
static int g_userbuf_cap_runtime = TCP_PROXY_USERBUF_CAP;
static int g_sockbuf_cap_runtime = TCP_PROXY_SOCKBUF_CAP;
static int g_ka_idle = TCP_PROXY_KEEPALIVE_IDLE;
static int g_ka_intvl = TCP_PROXY_KEEPALIVE_INTVL;
static int g_ka_cnt = TCP_PROXY_KEEPALIVE_CNT;
static int g_backpressure_wm = TCP_PROXY_BACKPRESSURE_WM;


/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Function Declarations */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static int handle_forwarding(struct proxy_conn *conn, int efd, int epfd,
                             struct epoll_event *ev);

/* Statistics functions */
static int init_stats(void);
static void destroy_stats(void);
static void update_connection_stats(bool connected, bool failed);
static void update_traffic_stats(uint64_t bytes_in, uint64_t bytes_out);
static void report_stats_if_needed(void);
static void print_stats_summary(void);

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Utility Functions */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static int set_sock_buffers(int sockfd) {
    int sz = g_sockbuf_cap_runtime;
    int ret = 0;
    int saved_errno;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)) < 0) {
        saved_errno = errno;
        P_LOG_WARN("setsockopt(SO_RCVBUF=%d) on fd %d failed: %s", sz, sockfd,
                   strerror(saved_errno));
        /* Non-fatal error - continue with default buffer size */
        ret = -1;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)) < 0) {
        saved_errno = errno;
        P_LOG_WARN("setsockopt(SO_SNDBUF=%d) on fd %d failed: %s", sz, sockfd,
                   strerror(saved_errno));
        /* Non-fatal error - continue with default buffer size */
        ret = -1;
    }

    /* Verify actual buffer sizes if setting succeeded */
    if (ret == 0) {
        int actual_rcv = 0, actual_snd = 0;
        socklen_t optlen = sizeof(actual_rcv);

        if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &actual_rcv, &optlen) ==
                0 &&
            getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &actual_snd, &optlen) ==
                0) {
            if (actual_rcv < sz || actual_snd < sz) {
                P_LOG_INFO(
                    "Socket buffer sizes: requested=%d, actual rcv=%d snd=%d",
                    sz, actual_rcv, actual_snd);
            }
        }
    }

    return ret;
}

static int set_keepalive(int sockfd) {
    int on = 1;
    int ret = 0;
    int saved_errno;

    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0) {
        saved_errno = errno;
        P_LOG_WARN("setsockopt(SO_KEEPALIVE) on fd %d failed: %s", sockfd,
                   strerror(saved_errno));
        /* Keepalive failure is not fatal, but we should return error */
        return -1;
    }

#ifdef __linux__
    /* Linux-specific TCP keepalive parameters */
    int idle = g_ka_idle;
    int intvl = g_ka_intvl;
    int cnt = g_ka_cnt;

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) <
        0) {
        saved_errno = errno;
        P_LOG_WARN("setsockopt(TCP_KEEPIDLE=%d) on fd %d failed: %s", idle,
                   sockfd, strerror(saved_errno));
        ret = -1;
    }
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl)) <
        0) {
        saved_errno = errno;
        P_LOG_WARN("setsockopt(TCP_KEEPINTVL=%d) on fd %d failed: %s", intvl,
                   sockfd, strerror(saved_errno));
        ret = -1;
    }
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt)) < 0) {
        saved_errno = errno;
        P_LOG_WARN("setsockopt(TCP_KEEPCNT=%d) on fd %d failed: %s", cnt,
                   sockfd, strerror(saved_errno));
        ret = -1;
    }

    if (ret == 0) {
        P_LOG_INFO("TCP keepalive configured: idle=%ds, interval=%ds, count=%d",
                   idle, intvl, cnt);
    }
#else
    P_LOG_INFO(
        "Basic TCP keepalive enabled (platform-specific tuning not available)");
#endif
    return ret;
}

static int set_tcp_nodelay(int sockfd) {
    int on = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0) {
        P_LOG_WARN("setsockopt(TCP_NODELAY) on fd %d: %s", sockfd,
                   strerror(errno));
        return -1;
    }
    return 0;
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

/* Handle accept errors with proper recovery strategy */
static int handle_accept_errors(int listen_sock) {
    static int consecutive_errors = 0;
    static time_t last_error_time = 0;
    time_t now = time(NULL);

    (void)listen_sock; /* Suppress unused parameter warning */

    /* Reset error count if enough time has passed */
    if (now - last_error_time > ACCEPT_ERROR_RESET_INTERVAL) {
        consecutive_errors = 0;
    }

    /* Handle different error types */
    switch (errno) {
    case EAGAIN:
#if EAGAIN != EWOULDBLOCK
    case EWOULDBLOCK:
#endif
        /* Normal case - no more connections to accept */
        consecutive_errors = 0;
        return 0;

    case EMFILE:
    case ENFILE:
        /* File descriptor limit reached */
        P_LOG_ERR("File descriptor limit reached: %s", strerror(errno));
        consecutive_errors++;
        last_error_time = now;
        return -1;

    case ENOBUFS:
    case ENOMEM:
        /* System resource exhaustion */
        P_LOG_ERR("System resource exhaustion: %s", strerror(errno));
        consecutive_errors++;
        last_error_time = now;
        return -1;

    case ECONNABORTED:
    case EPROTO:
        /* Connection aborted by client - not fatal */
        P_LOG_WARN("Connection aborted: %s", strerror(errno));
        return 0;

    default:
        /* Other errors */
        consecutive_errors++;
        last_error_time = now;
        P_LOG_ERR("accept() error: %s", strerror(errno));
        break;
    }

    /* Check if we have too many consecutive errors */
    if (consecutive_errors > MAX_CONSECUTIVE_ACCEPT_ERRORS) {
        P_LOG_ERR("Too many consecutive accept errors (%d), stopping",
                  consecutive_errors);
        return -2; /* Fatal error */
    }

    P_LOG_WARN("Accept error %d of %d: %s", consecutive_errors,
               MAX_CONSECUTIVE_ACCEPT_ERRORS, strerror(errno));

    /* Brief delay to avoid CPU spinning */
    if (consecutive_errors > 3) {
        usleep(ACCEPT_ERROR_DELAY_US);
    }

    return -1;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Statistics Functions */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/* Initialize statistics system */
static int init_stats(void) {
    memset(&g_stats, 0, sizeof(g_stats));

    if (pthread_mutex_init(&g_stats.lock, NULL) != 0) {
        P_LOG_ERR("Failed to initialize statistics mutex");
        return -1;
    }

    g_stats.start_time = time(NULL);
    g_stats.last_stats_report = g_stats.start_time;

    P_LOG_INFO("Statistics system initialized");
    return 0;
}

/* Destroy statistics system */
static void destroy_stats(void) {
    pthread_mutex_destroy(&g_stats.lock);
    memset(&g_stats, 0, sizeof(g_stats));
}

/* Update connection-related statistics */
static void update_connection_stats(bool connected, bool failed) {
    if (connected) {
        __sync_fetch_and_add(&g_stats.total_connected, 1);
        uint64_t current = __sync_fetch_and_add(&g_stats.current_active, 1) + 1;

        /* Update peak concurrent connections */
        uint64_t peak = g_stats.peak_concurrent;
        while (current > peak && !__sync_bool_compare_and_swap(
                                     &g_stats.peak_concurrent, peak, current)) {
            peak = g_stats.peak_concurrent;
        }
    }

    if (failed) {
        __sync_fetch_and_add(&g_stats.total_failed, 1);
    }
}

/* Update traffic statistics */
static void update_traffic_stats(uint64_t bytes_in, uint64_t bytes_out) {
    if (bytes_in > 0) {
        __sync_fetch_and_add(&g_stats.bytes_received, bytes_in);
    }
    if (bytes_out > 0) {
        __sync_fetch_and_add(&g_stats.bytes_sent, bytes_out);
    }
}

/* Report statistics if interval has passed */
static void report_stats_if_needed(void) {
    time_t now = time(NULL);
    if (now - g_stats.last_stats_report >= STATS_REPORT_INTERVAL_SEC) {
        print_stats_summary();
        g_stats.last_stats_report = now;
    }
}

/* Print comprehensive statistics summary */
static void print_stats_summary(void) {
    time_t now = time(NULL);
    time_t uptime = now - g_stats.start_time;

    P_LOG_INFO("=== TCP Forwarder Statistics ===");
    P_LOG_INFO("Uptime: %ld seconds (%ld hours)", uptime, uptime / 3600);
    P_LOG_INFO("Connections: accepted=%lu, connected=%lu, failed=%lu, "
               "active=%lu, peak=%lu",
               g_stats.total_accepted, g_stats.total_connected,
               g_stats.total_failed, g_stats.current_active,
               g_stats.peak_concurrent);
    P_LOG_INFO(
        "Traffic: received=%lu bytes, sent=%lu bytes, forwarded=%lu bytes",
        g_stats.bytes_received, g_stats.bytes_sent, g_stats.bytes_forwarded);
    P_LOG_INFO("Operations: splice=%lu, buffer=%lu, epoll_iterations=%lu",
               g_stats.splice_operations, g_stats.buffer_operations,
               g_stats.epoll_iterations);
    P_LOG_INFO("Errors: accept=%lu, connect=%lu, forward=%lu, resource=%lu, "
               "limits=%lu",
               g_stats.accept_errors, g_stats.connect_errors,
               g_stats.forward_errors, g_stats.resource_errors,
               g_stats.limit_rejections);
    P_LOG_INFO("Pool: used=%zu, capacity=%zu, high_water=%zu",
               g_conn_pool.used_count, g_conn_pool.capacity,
               g_conn_pool.high_water_mark);
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Connection Limiting Functions */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/* Simple hash function for IP addresses */
static uint32_t addr_hash(const union sockaddr_inx *addr) {
    if (addr->sa.sa_family == AF_INET) {
        return ntohl(addr->sin.sin_addr.s_addr) % CONN_LIMIT_HASH_SIZE;
    } else if (addr->sa.sa_family == AF_INET6) {
        const uint32_t *p = (const uint32_t *)&addr->sin6.sin6_addr;
        return (ntohl(p[0]) ^ ntohl(p[1]) ^ ntohl(p[2]) ^ ntohl(p[3])) %
               CONN_LIMIT_HASH_SIZE;
    }
    return 0;
}

/* Initialize connection limiter */
static int init_conn_limiter(int max_total, int max_per_ip) {
    memset(&g_conn_limiter, 0, sizeof(g_conn_limiter));

    if (pthread_mutex_init(&g_conn_limiter.lock, NULL) != 0) {
        P_LOG_ERR("Failed to initialize connection limiter mutex");
        return -1;
    }

    g_conn_limiter.max_total = max_total;
    g_conn_limiter.max_per_ip = max_per_ip;
    g_conn_limiter.total_connections = 0;

    P_LOG_INFO("Connection limiter initialized: max_total=%d, max_per_ip=%d",
               max_total, max_per_ip);
    return 0;
}

/* Destroy connection limiter */
static void destroy_conn_limiter(void) {
    pthread_mutex_destroy(&g_conn_limiter.lock);
    memset(&g_conn_limiter, 0, sizeof(g_conn_limiter));
}

/* Check if connection is allowed */
static bool check_connection_limit(const union sockaddr_inx *addr) {
    if (g_conn_limiter.max_total <= 0 && g_conn_limiter.max_per_ip <= 0) {
        return true; /* No limits configured */
    }

    pthread_mutex_lock(&g_conn_limiter.lock);

    /* Check total connection limit */
    if (g_conn_limiter.max_total > 0 &&
        g_conn_limiter.total_connections >= g_conn_limiter.max_total) {
        pthread_mutex_unlock(&g_conn_limiter.lock);
        P_LOG_WARN("Total connection limit reached (%d)",
                   g_conn_limiter.max_total);
        return false;
    }

    /* Check per-IP limit if configured */
    if (g_conn_limiter.max_per_ip > 0) {
        uint32_t hash = addr_hash(addr);
        struct conn_limit_entry *entry = &g_conn_limiter.entries[hash];
        time_t now = time(NULL);

        /* Check if this is the same IP or a hash collision */
        if (entry->count > 0) {
            if (is_sockaddr_inx_equal(&entry->addr, addr)) {
                /* Same IP */
                if (entry->count >= g_conn_limiter.max_per_ip) {
                    pthread_mutex_unlock(&g_conn_limiter.lock);
                    P_LOG_WARN("Per-IP connection limit reached for %s (%d "
                               "connections)",
                               sockaddr_to_string(addr), entry->count);
                    return false;
                }
                entry->count++;
                entry->last_seen = now;
            } else {
                /* Hash collision - allow but log warning */
                P_LOG_WARN("Hash collision in connection limiter for %s",
                           sockaddr_to_string(addr));
            }
        } else {
            /* New entry */
            entry->addr = *addr;
            entry->count = 1;
            entry->first_seen = now;
            entry->last_seen = now;
        }
    }

    g_conn_limiter.total_connections++;
    pthread_mutex_unlock(&g_conn_limiter.lock);

    return true;
}

/* Release connection from limiter */
static void release_connection_limit(const union sockaddr_inx *addr) {
    if (g_conn_limiter.max_total <= 0 && g_conn_limiter.max_per_ip <= 0) {
        return; /* No limits configured */
    }

    pthread_mutex_lock(&g_conn_limiter.lock);

    if (g_conn_limiter.total_connections > 0) {
        g_conn_limiter.total_connections--;
    }

    /* Update per-IP count if configured */
    if (g_conn_limiter.max_per_ip > 0) {
        uint32_t hash = addr_hash(addr);
        struct conn_limit_entry *entry = &g_conn_limiter.entries[hash];

        if (entry->count > 0 && is_sockaddr_inx_equal(&entry->addr, addr)) {
            entry->count--;
            if (entry->count == 0) {
                memset(entry, 0, sizeof(*entry));
            }
        }
    }

    pthread_mutex_unlock(&g_conn_limiter.lock);
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Connection Management */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static void init_proxy_conn(struct proxy_conn *conn) {
    memset(conn, 0, sizeof(*conn));
    conn->cli_sock = -1;
    conn->svr_sock = -1;
#ifdef __linux__
    conn->c2s_pipe[0] = -1;
    conn->c2s_pipe[1] = -1;
    conn->s2c_pipe[0] = -1;
    conn->s2c_pipe[1] = -1;
#endif
    conn->magic_client = EV_MAGIC_CLIENT;
    conn->magic_server = EV_MAGIC_SERVER;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Connection Management */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static void release_proxy_conn(struct proxy_conn *conn,
                               struct epoll_event *events, int *nfds,
                               int epfd) {
    int i;

    if (!conn) {
        P_LOG_WARN("Attempted to release NULL connection");
        return;
    }

    /*
     * Clear any pending epoll events for this connection's file descriptors.
     * This prevents use-after-free bugs where the event loop might process
     * an event for a connection that has already been released.
     */
    if (events && nfds) {
        for (i = 0; i < *nfds; i++) {
            struct epoll_event *ev = &events[i];
            if (ev->data.ptr == &conn->magic_client ||
                ev->data.ptr == &conn->magic_server) {
                ev->data.ptr = NULL;
            }
        }
    }

    /* Remove from epoll first to prevent new events */
    if (epfd >= 0) {
        if (conn->cli_sock >= 0) {
            if (epoll_ctl(epfd, EPOLL_CTL_DEL, conn->cli_sock, NULL) < 0 &&
                errno != ENOENT) {
                P_LOG_WARN("epoll_ctl(DEL, cli_sock=%d): %s", conn->cli_sock,
                           strerror(errno));
            }
        }
        if (conn->svr_sock >= 0) {
            if (epoll_ctl(epfd, EPOLL_CTL_DEL, conn->svr_sock, NULL) < 0 &&
                errno != ENOENT) {
                P_LOG_WARN("epoll_ctl(DEL, svr_sock=%d): %s", conn->svr_sock,
                           strerror(errno));
            }
        }
    }

#ifdef __linux__
    /* Clean up splice pipes safely */
    if (conn->use_splice) {
        if (conn->c2s_pipe[0] >= 0) {
            if (safe_close(conn->c2s_pipe[0]) < 0) {
                P_LOG_WARN("close(c2s_pipe[0]=%d): %s", conn->c2s_pipe[0],
                           strerror(errno));
            }
            conn->c2s_pipe[0] = -1;
        }
        if (conn->c2s_pipe[1] >= 0) {
            if (safe_close(conn->c2s_pipe[1]) < 0) {
                P_LOG_WARN("close(c2s_pipe[1]=%d): %s", conn->c2s_pipe[1],
                           strerror(errno));
            }
            conn->c2s_pipe[1] = -1;
        }
        if (conn->s2c_pipe[0] >= 0) {
            if (safe_close(conn->s2c_pipe[0]) < 0) {
                P_LOG_WARN("close(s2c_pipe[0]=%d): %s", conn->s2c_pipe[0],
                           strerror(errno));
            }
            conn->s2c_pipe[0] = -1;
        }
        if (conn->s2c_pipe[1] >= 0) {
            if (safe_close(conn->s2c_pipe[1]) < 0) {
                P_LOG_WARN("close(s2c_pipe[1]=%d): %s", conn->s2c_pipe[1],
                           strerror(errno));
            }
            conn->s2c_pipe[1] = -1;
        }
        conn->c2s_pending = 0;
        conn->s2c_pending = 0;
        conn->use_splice = false;
    }
#endif

    /* Close sockets safely */
    if (conn->cli_sock >= 0) {
        if (safe_close(conn->cli_sock) < 0) {
            P_LOG_WARN("close(cli_sock=%d): %s", conn->cli_sock,
                       strerror(errno));
        }
        conn->cli_sock = -1;
    }
    if (conn->svr_sock >= 0) {
        if (safe_close(conn->svr_sock) < 0) {
            P_LOG_WARN("close(svr_sock=%d): %s", conn->svr_sock,
                       strerror(errno));
        }
        conn->svr_sock = -1;
    }

    /* Free user buffers to avoid leaks */
    if (conn->request.data) {
        free(conn->request.data);
        conn->request.data = NULL;
        conn->request.capacity = 0;
        conn->request.dlen = conn->request.rpos = 0;
    }
    if (conn->response.data) {
        free(conn->response.data);
        conn->response.data = NULL;
        conn->response.capacity = 0;
        conn->response.dlen = conn->response.rpos = 0;
    }

    /* Release connection from limiter */
    release_connection_limit(&conn->cli_addr);

    /* Update connection statistics */
    __sync_fetch_and_sub(&g_stats.current_active, 1);

    /* Return connection to the generic pool */
    conn_pool_release(&g_conn_pool, conn);
}

/**
 * @brief Updates epoll event registrations for a connection based on its state.
 *
 * Sets EPOLLIN/EPOLLOUT flags for client and server sockets according to the
 * current state (e.g., connecting, forwarding) and buffer status to ensure
 * correct I/O notifications.
 */
static void set_conn_epoll_fds(struct proxy_conn *conn, int epfd) {
    struct epoll_event ev_cli, ev_svr;

    ev_cli.events = 0;
    ev_cli.data.ptr = &conn->magic_client;

    ev_svr.events = 0;
    ev_svr.data.ptr = &conn->magic_server;

    if (conn->use_splice) {
        /* With per-direction pipes, always read on both; write only where
         * there's pending data to flush. */
        ev_cli.events |= EPOLLIN;
        ev_svr.events |= EPOLLIN;
        if (conn->c2s_pending > 0)
            ev_svr.events |= EPOLLOUT; /* flush to server */
        if (conn->s2c_pending > 0)
            ev_cli.events |= EPOLLOUT; /* flush to client */
    } else {
        switch (conn->state) {
        case S_SERVER_CONNECTING:
            /* Wait for the server connection to establish. */
            if (conn->request.dlen < conn->request.capacity &&
                conn->request.dlen < (size_t)g_backpressure_wm)
                ev_cli.events |= EPOLLIN; /* for detecting client close */
            ev_svr.events |= EPOLLOUT;
            break;
        case S_FORWARDING:
            /* Enable reads only when below backpressure watermark */
            if (conn->request.dlen < conn->request.capacity &&
                conn->request.dlen < (size_t)g_backpressure_wm)
                ev_cli.events |= EPOLLIN;
            if (conn->response.dlen > 0)
                ev_cli.events |= EPOLLOUT;
            if (conn->response.dlen < conn->response.capacity &&
                conn->response.dlen < (size_t)g_backpressure_wm)
                ev_svr.events |= EPOLLIN;
            if (conn->request.dlen > 0)
                ev_svr.events |= EPOLLOUT;
            break;
        default:
            break;
        }
    }

    ev_cli.events |= EPOLLRDHUP | EPOLLHUP | EPOLLERR | EPOLLET;
    ev_svr.events |= EPOLLRDHUP | EPOLLHUP | EPOLLERR | EPOLLET;

    ep_add_or_mod(epfd, conn->cli_sock, &ev_cli);
    ep_add_or_mod(epfd, conn->svr_sock, &ev_svr);
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Event Handling Functions */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static int handle_new_connection(int listen_sock, int epfd,
                                  struct fwd_config *cfg) {
    for (;;) {
        union sockaddr_inx cli_addr;
        socklen_t cli_alen = sizeof(cli_addr);
        int cli_sock;

#ifdef __linux__
        cli_sock = accept4(listen_sock, &cli_addr.sa, &cli_alen,
                           SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cli_sock < 0 && (errno == ENOSYS || errno == EINVAL)) {
            cli_sock = accept(listen_sock, &cli_addr.sa, &cli_alen);
            if (cli_sock >= 0) {
                set_nonblock(cli_sock);
                set_cloexec(cli_sock);
            }
        }
#else
        cli_sock = accept(listen_sock, &cli_addr.sa, &cli_alen);
        if (cli_sock >= 0) {
            set_nonblock(cli_sock);
            set_cloexec(cli_sock);
        }
#endif

        if (cli_sock < 0) {
            int rc = handle_accept_errors(listen_sock);
            if (rc == -2)
                return -1; /* Fatal error */
            return 0;      /* Non-fatal, continue event loop */
        }

        __sync_fetch_and_add(&g_stats.total_accepted, 1);

        struct proxy_conn *conn = NULL;

        if (!check_connection_limit(&cli_addr)) {
            P_LOG_WARN("Connection from %s rejected due to limits",
                       sockaddr_to_string(&cli_addr));
            __sync_fetch_and_add(&g_stats.limit_rejections, 1);
            close(cli_sock);
            continue;
        }

        if (!(conn = conn_pool_alloc(&g_conn_pool))) {
            P_LOG_ERR("conn_pool_alloc(): %s", strerror(errno));
            release_connection_limit(&cli_addr);
            close(cli_sock);
            continue;
        }

        conn->cli_sock = cli_sock;
        set_sock_buffers(conn->cli_sock);
        set_keepalive(conn->cli_sock);
        set_tcp_nodelay(conn->cli_sock);
        conn->cli_addr = cli_addr;
        conn->svr_addr = cfg->dst_addr;

#ifdef __linux__
        if (cfg->base_addr_mode) {
            union sockaddr_inx orig_dst;
            socklen_t addrlen = sizeof(orig_dst);
            if (getsockopt(cli_sock, SOL_IP, SO_ORIGINAL_DST, &orig_dst, &addrlen) < 0) {
                P_LOG_ERR("getsockopt(SO_ORIGINAL_DST) from %s failed: %s",
                          sockaddr_to_string(&cli_addr), strerror(errno));
                release_proxy_conn(conn, NULL, NULL, -1);
                continue;
            }
            conn->svr_addr = orig_dst;
        }
#endif

        if ((conn->svr_sock = socket(conn->svr_addr.sa.sa_family, SOCK_STREAM, 0)) < 0) {
            P_LOG_ERR("socket(svr_sock): %s", strerror(errno));
            release_proxy_conn(conn, NULL, NULL, -1);
            continue;
        }
        set_nonblock(conn->svr_sock);
        set_sock_buffers(conn->svr_sock);
        set_keepalive(conn->svr_sock);
        set_tcp_nodelay(conn->svr_sock);

        if (connect(conn->svr_sock, &conn->svr_addr.sa, sizeof_sockaddr(&conn->svr_addr)) < 0) {
            if (errno != EINPROGRESS) {
                P_LOG_WARN("connect() to %s from %s failed: %s",
                           sockaddr_to_string(&conn->svr_addr),
                           sockaddr_to_string(&cli_addr), strerror(errno));
                release_proxy_conn(conn, NULL, NULL, -1);
                continue;
            }
            conn->state = S_SERVER_CONNECTING;
        } else {
            conn->state = S_FORWARDING;
        }

        set_conn_epoll_fds(conn, epfd);
    }
    return 0;
}

static int proxy_loop(int epfd, int listen_sock, struct fwd_config *cfg) {
    struct epoll_event *events = NULL;
    int events_size = EPOLL_EVENTS_DEFAULT;
    int consecutive_full_batches = 0;
    int consecutive_small_batches = 0;

    /* Allocate initial event array */
    events = malloc(sizeof(struct epoll_event) * events_size);
    if (!events) {
        P_LOG_ERR("Failed to allocate epoll events array");
        return 1;
    }

    while (!g_shutdown_requested) {
        int nfds = epoll_wait(epfd, events, events_size, 1000);
        if (nfds < 0) {
            if (errno == EINTR)
                continue;
            P_LOG_ERR("epoll_wait(): %s", strerror(errno));
            free(events);
            return 1;
        }

        /* Update epoll statistics */
        __sync_fetch_and_add(&g_stats.epoll_iterations, 1);
        __sync_fetch_and_add(&g_stats.epoll_events_processed, nfds);

        /* Report statistics periodically */
        report_stats_if_needed();

        /* Dynamic adjustment of event array size */
        if (nfds == events_size) {
            /* Array was full - consider expanding */
            consecutive_full_batches++;
            consecutive_small_batches = 0;

            if (consecutive_full_batches >= EPOLL_EXPAND_THRESHOLD &&
                events_size < EPOLL_EVENTS_MAX) {
                int new_size = events_size * 2;
                if (new_size > EPOLL_EVENTS_MAX) {
                    new_size = EPOLL_EVENTS_MAX;
                }

                struct epoll_event *new_events =
                    realloc(events, sizeof(struct epoll_event) * new_size);
                if (new_events) {
                    events = new_events;
                    events_size = new_size;
                    consecutive_full_batches = 0;
                    __sync_fetch_and_add(&g_stats.epoll_array_expansions, 1);
                    P_LOG_INFO("Expanded epoll events array to %d",
                               events_size);
                }
            }
        } else if (nfds < events_size / EPOLL_SHRINK_USAGE_RATIO) {
            /* Array usage is low - consider shrinking */
            consecutive_small_batches++;
            consecutive_full_batches = 0;

            if (consecutive_small_batches >= EPOLL_SHRINK_THRESHOLD &&
                events_size > EPOLL_EVENTS_MIN) {
                int new_size = events_size / 2;
                if (new_size < EPOLL_EVENTS_MIN) {
                    new_size = EPOLL_EVENTS_MIN;
                }

                struct epoll_event *new_events =
                    realloc(events, sizeof(struct epoll_event) * new_size);
                if (new_events) {
                    events = new_events;
                    events_size = new_size;
                    consecutive_small_batches = 0;
                    __sync_fetch_and_add(&g_stats.epoll_array_shrinks, 1);
                    P_LOG_INFO("Shrunk epoll events array to %d", events_size);
                }
            }
        } else {
            /* Reset counters for moderate usage */
            consecutive_full_batches = 0;
            consecutive_small_batches = 0;
        }

        for (int i = 0; i < nfds; i++) {
            struct epoll_event *ev = &events[i];
            struct proxy_conn *conn = NULL;

            /* Skip events that have been cleared by release_proxy_conn */
            if (ev->data.ptr == NULL) {
                continue;
            }

            if (*(const uint32_t *)ev->data.ptr == EV_MAGIC_LISTENER) {
                /* Listener socket */
                if (handle_new_connection(listen_sock, epfd, cfg) < 0) {
                    P_LOG_ERR("Fatal error in accept handling, terminating");
                    return 1;
                }
                continue;
            } else {
                /* Client or server socket - validate magic numbers and
                 * connection state */
                uint32_t *magic = ev->data.ptr;
                int efd = -1;

                /* Additional safety check for pointer validity */
                if ((uintptr_t)magic < MIN_VALID_POINTER) {
                    P_LOG_WARN("Invalid pointer in epoll event: %p",
                               (void *)magic);
                    continue;
                }

                if (*magic == EV_MAGIC_CLIENT) {
                    conn = container_of(magic, struct proxy_conn, magic_client);
                    efd = conn->cli_sock;

                    /* Enhanced validation for client socket */
                    if (efd < 0) {
                        P_LOG_WARN(
                            "Event for closed client socket (fd=%d, state=%d)",
                            efd, conn->state);
                        continue;
                    }
                    if (conn->state == S_CLOSING) {
                        P_LOG_DEBUG(
                            "Event for closing client connection (fd=%d)", efd);
                        continue;
                    }
                    if (conn->magic_server != EV_MAGIC_SERVER) {
                        P_LOG_ERR("Corrupted connection object detected "
                                  "(client side)");
                        continue;
                    }
                } else if (*magic == EV_MAGIC_SERVER) {
                    conn = container_of(magic, struct proxy_conn, magic_server);
                    efd = conn->svr_sock;

                    /* Enhanced validation for server socket */
                    if (efd < 0) {
                        P_LOG_WARN(
                            "Event for closed server socket (fd=%d, state=%d)",
                            efd, conn->state);
                        continue;
                    }
                    if (conn->state == S_CLOSING) {
                        P_LOG_DEBUG(
                            "Event for closing server connection (fd=%d)", efd);
                        continue;
                    }
                    if (conn->magic_client != EV_MAGIC_CLIENT) {
                        P_LOG_ERR("Corrupted connection object detected "
                                  "(server side)");
                        continue;
                    }
                } else {
                    P_LOG_WARN("Invalid magic number in epoll event: 0x%x",
                               *magic);
                    continue;
                }

                switch (conn->state) {
                case S_FORWARDING:
                    handle_forwarding(conn, efd, epfd, ev);
                    break;
                case S_SERVER_CONNECTING:
                    handle_server_connecting(conn, efd, epfd, ev);
                    break;
                default:
                    conn->state = S_CLOSING;
                    break;
                }
            }

            if (conn) {
                if (conn->state == S_CLOSING) {
                    release_proxy_conn(conn, events, &nfds, epfd);
                } else {
                    set_conn_epoll_fds(conn, epfd);
                }
            }
        }
    }

    free(events);
    return 0;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Help and Main Function */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options] <listen_addr> <remote_addr>\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d, --daemonize        Run in the background\n");
    fprintf(stderr, "  -b, --base-addr-mode   Enable transparent proxy mode (Linux only)\n");
    fprintf(stderr, "  -r, --reuse-addr         Enable SO_REUSEADDR\n");
    fprintf(stderr, "  -p, --reuse-port         Enable SO_REUSEPORT\n");
    fprintf(stderr, "  -P, --pidfile <path>     Path to PID file\n");
    fprintf(stderr, "  -6, --v6only             Enable IPV6_V6ONLY\n");
    fprintf(stderr, "  -i, --max-per-ip <n>     Set max connections per IP\n");
    fprintf(stderr, "  -h, --help               Show this help message\n");
}

int main(int argc, char *argv[]) {
    int rc = 1;
    struct fwd_config fwd_config;
    int listen_sock = -1, epfd = -1;
    uint32_t magic_listener = EV_MAGIC_LISTENER;
    int opt;

    /* Initialize configuration with defaults */
    init_fwd_config(&fwd_config);

    /* Parse common arguments first */
    int optind_ret = parse_common_args(argc, argv, &fwd_config);
    if (optind_ret < 0) {
        usage(argv[0]);
        return 1;
    }
    optind = optind_ret;

    /* Parse tcpfwd-specific arguments */
    while ((opt = getopt(argc, argv, "bC:U:S:I:N:K:M:h")) != -1) {
        switch (opt) {
        case 'b':
            fwd_config.base_addr_mode = true;
            break;
        case 'C': {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v <= 0) {
                P_LOG_WARN("invalid -C value '%s', keeping default %d", optarg,
                           g_conn_pool_capacity);
            } else {
                if (v < 64) v = 64;
                if (v > (1 << 20)) v = (1 << 20);
                g_conn_pool_capacity = (int)v;
            }
            break;
        }
        case 'U': {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v <= 0) {
                P_LOG_WARN("invalid -U value '%s', keeping default %d", optarg,
                           g_userbuf_cap_runtime);
            } else {
                if (v < 4096) v = 4096;
                if (v > (8 << 20)) v = (8 << 20);
                g_userbuf_cap_runtime = (int)v;
            }
            break;
        }
        case 'S': {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v <= 0) {
                P_LOG_WARN("invalid -S value '%s', keeping default %d", optarg,
                           g_sockbuf_cap_runtime);
            } else {
                if (v < 4096) v = 4096;
                if (v > (8 << 20)) v = (8 << 20);
                g_sockbuf_cap_runtime = (int)v;
            }
            break;
        }
        case 'I': {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v <= 0) {
                P_LOG_WARN("invalid -I value '%s', keeping default %d", optarg,
                           g_ka_idle);
            } else {
                if (v < 10) v = 10;
                if (v > 86400) v = 86400;
                g_ka_idle = (int)v;
            }
            break;
        }
        case 'N': {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v <= 0) {
                P_LOG_WARN("invalid -N value '%s', keeping default %d", optarg,
                           g_ka_intvl);
            } else {
                if (v < 5) v = 5;
                if (v > 3600) v = 3600;
                g_ka_intvl = (int)v;
            }
            break;
        }
        case 'K': {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v <= 0) {
                P_LOG_WARN("invalid -K value '%s', keeping default %d", optarg,
                           g_ka_cnt);
            } else {
                if (v < 1) v = 1;
                if (v > 100) v = 100;
                g_ka_cnt = (int)v;
            }
            break;
        }
        case 'M': {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v < 0) {
                P_LOG_WARN("invalid -M value '%s', keeping default %d", optarg,
                           fwd_config.max_total_connections);
            } else {
                if (v > MAX_TOTAL_CONNECTIONS_LIMIT) v = MAX_TOTAL_CONNECTIONS_LIMIT;
                fwd_config.max_total_connections = (int)v;
            }
            break;
        }
        case 'h':
            usage(argv[0]);
            return 0;
        case '?':
            return 1;
        default:
            return 1;
        }
    }

    if (optind + 2 != argc) {
        usage(argv[0]);
        return 1;
    }

    if (get_sockaddr_inx_pair(argv[optind], &fwd_config.src_addr, false) != 0) {
        P_LOG_ERR("Invalid src_addr: %s", argv[optind]);
        return 1;
    }
    if (get_sockaddr_inx_pair(argv[optind + 1], &fwd_config.dst_addr, false) != 0) {
        P_LOG_ERR("Invalid dst_addr: %s", argv[optind + 1]);
        return 1;
    }

    openlog("tcpfwd", LOG_PID | LOG_PERROR, LOG_DAEMON);

    if (fwd_config.daemonize) {
        if (do_daemonize() != 0) return 1;
    }

    if (fwd_config.pidfile) {
        if (create_pid_file(fwd_config.pidfile) != 0) return 1;
    }

    g_backpressure_wm = (g_userbuf_cap_runtime * 3) / 4;

    if (init_stats() != 0) goto cleanup;

    g_conn_pool_capacity = (g_conn_pool_capacity > 0) ? g_conn_pool_capacity : TCP_PROXY_CONN_POOL_SIZE;
    if (conn_pool_init(&g_conn_pool, (size_t)g_conn_pool_capacity, sizeof(struct proxy_conn)) < 0) {
        P_LOG_ERR("Failed to initialize connection pool");
        goto cleanup;
    }

    if (init_conn_limiter(fwd_config.max_total_connections, fwd_config.max_per_ip) != 0) {
        goto cleanup;
    }

    if (setup_shutdown_signals() != 0) {
        P_LOG_ERR("Failed to setup signal handlers");
        goto cleanup;
    }

    listen_sock = socket(fwd_config.src_addr.sa.sa_family, SOCK_STREAM, 0);
    if (listen_sock < 0) {
        P_LOG_ERR("socket(): %s", strerror(errno));
        goto cleanup;
    }

    if (fwd_config.reuse_addr) {
        int on = 1;
        if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            P_LOG_WARN("setsockopt(SO_REUSEADDR): %s", strerror(errno));
        }
    }

#ifdef SO_REUSEPORT
    if (fwd_config.reuse_port) {
        int on = 1;
        if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
            P_LOG_WARN("setsockopt(SO_REUSEPORT): %s", strerror(errno));
        }
    }
#endif

    if (fwd_config.src_addr.sa.sa_family == AF_INET6 && fwd_config.v6only) {
        int on = 1;
        (void)setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
    }

    if (bind(listen_sock, &fwd_config.src_addr.sa, sizeof_sockaddr(&fwd_config.src_addr)) < 0) {
        P_LOG_ERR("bind(): %s", strerror(errno));
        goto cleanup;
    }

    if (listen(listen_sock, LISTEN_BACKLOG) < 0) {
        P_LOG_ERR("listen(): %s", strerror(errno));
        goto cleanup;
    }

    set_nonblock(listen_sock);

#ifdef EPOLL_CLOEXEC
    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0 && (errno == ENOSYS || errno == EINVAL)) epfd = epoll_create(1);
#else
    epfd = epoll_create(1);
#endif
    if (epfd < 0) {
        P_LOG_ERR("epoll_create(): %s", strerror(errno));
        goto cleanup;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
#ifdef EPOLLEXCLUSIVE
    ev.events |= EPOLLEXCLUSIVE;
#endif
    ev.data.ptr = &magic_listener;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_sock, &ev) < 0) {
        P_LOG_ERR("epoll_ctl(ADD, listener): %s", strerror(errno));
        goto cleanup;
    }

    P_LOG_INFO("TCP forwarding started: %s -> %s",
               sockaddr_to_string(&fwd_config.src_addr),
               sockaddr_to_string(&fwd_config.dst_addr));
    if (fwd_config.max_total_connections > 0) {
        P_LOG_INFO("Connection limits: total=%d, per-IP=%d",
                   fwd_config.max_total_connections, fwd_config.max_per_ip);
    }
    P_LOG_INFO("Connection pool size: %d, buffer size: %d bytes",
               g_conn_pool_capacity, g_userbuf_cap_runtime);

    rc = proxy_loop(epfd, listen_sock, &fwd_config);

cleanup:
    /* Print final statistics before cleanup */
    print_stats_summary();

    /* Cleanup resources */
    if (listen_sock >= 0) {
        if (close(listen_sock) < 0) {
            P_LOG_WARN("close(listen_sock=%d): %s", listen_sock,
                       strerror(errno));
        }
    }
    if (epfd >= 0) {
        epoll_close_comp(epfd);
    }
    conn_pool_destroy(&g_conn_pool);
    destroy_conn_limiter();
    destroy_stats();
    closelog();

    return rc;
}
