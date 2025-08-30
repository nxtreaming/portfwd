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

/* Backpressure watermark: when opposite TX backlog exceeds this, limit further reads */
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
#define ACCEPT_ERROR_RESET_INTERVAL 60  /* seconds */
#define ACCEPT_ERROR_DELAY_US 100000    /* 100ms in microseconds */
#define MAX_TOTAL_CONNECTIONS_LIMIT 1000000
#define MAX_PER_IP_CONNECTIONS_LIMIT 10000

/* Buffer management constants */
#define BUFFER_COMPACT_THRESHOLD_RATIO 4  /* Compact when waste > 1/4 of capacity */
#define EPOLL_EXPAND_THRESHOLD 3          /* Expand after 3 consecutive full batches */
#define EPOLL_SHRINK_THRESHOLD 10         /* Shrink after 10 consecutive small batches */
#define EPOLL_SHRINK_USAGE_RATIO 4        /* Shrink when usage < 1/4 of capacity */

/* Network validation constants */
#define MIN_PORT_OFFSET -65535
#define MAX_PORT_OFFSET 65535
#define LISTEN_BACKLOG 128

/* Magic numbers for epoll event identification */
#define EV_MAGIC_LISTENER 0xdeadbeefU
#define EV_MAGIC_CLIENT 0xfeedfaceU
#define EV_MAGIC_SERVER 0xbaadcafeU

/* IPv4 address validation constants */
#define IPV4_ADDR_CLASS_A_PRIVATE    0x0A000000U  /* 10.0.0.0/8 */
#define IPV4_ADDR_CLASS_A_PRIVATE_MASK 0xFF000000U
#define IPV4_ADDR_CLASS_B_PRIVATE    0xAC100000U  /* 172.16.0.0/12 */
#define IPV4_ADDR_CLASS_B_PRIVATE_MASK 0xFFF00000U
#define IPV4_ADDR_CLASS_C_PRIVATE    0xC0A80000U  /* 192.168.0.0/16 */
#define IPV4_ADDR_CLASS_C_PRIVATE_MASK 0xFFFF0000U
#define IPV4_ADDR_LOOPBACK           0x7F000000U  /* 127.0.0.0/8 */
#define IPV4_ADDR_LOOPBACK_MASK      0xFF000000U
#define IPV4_ADDR_MULTICAST          0xE0000000U  /* 224.0.0.0/4 */
#define IPV4_ADDR_MULTICAST_MASK     0xF0000000U
#define IPV4_ADDR_RESERVED           0xF0000000U  /* 240.0.0.0/4 */
#define IPV4_ADDR_RESERVED_MASK      0xF0000000U

/* Buffer and I/O constants */
#define SPLICE_CHUNK_SIZE 65536
#define MIN_VALID_POINTER 4096
#define SOCKET_OPTION_RETRY_COUNT 3

/* Statistics and monitoring constants */
#define STATS_REPORT_INTERVAL_SEC 300  /* Report stats every 5 minutes */
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

struct config {
    union sockaddr_inx src_addr;
    union sockaddr_inx dst_addr;
    const char *pidfile;
    bool daemonize;
    bool base_addr_mode;
    bool reuse_addr;
    bool reuse_port;
    bool v6only;
    int max_connections;
    int max_per_ip;
};

/**
 * @brief Connection limiting structures for DoS protection
 *
 * Implements a simple hash table to track connections per IP address
 * and enforce both per-IP and total connection limits.
 */
#define CONN_LIMIT_HASH_SIZE 1024

struct conn_limit_entry {
    union sockaddr_inx addr;    /**< Client IP address */
    int count;                  /**< Current connection count for this IP */
    time_t first_seen;          /**< First connection timestamp */
    time_t last_seen;           /**< Last connection timestamp */
};

struct conn_limiter {
    struct conn_limit_entry entries[CONN_LIMIT_HASH_SIZE];  /**< Hash table entries */
    int total_connections;      /**< Current total active connections */
    int max_total;              /**< Maximum total connections allowed */
    int max_per_ip;             /**< Maximum connections per IP */
    pthread_mutex_t lock;       /**< Thread safety mutex */
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
    volatile uint64_t total_accepted;       /**< Total connections accepted */
    volatile uint64_t total_connected;      /**< Total successful server connections */
    volatile uint64_t total_failed;         /**< Total failed connections */
    volatile uint64_t current_active;       /**< Currently active connections */
    volatile uint64_t peak_concurrent;      /**< Peak concurrent connections */

    /* Traffic statistics */
    volatile uint64_t bytes_received;       /**< Total bytes received from clients */
    volatile uint64_t bytes_sent;           /**< Total bytes sent to clients */
    volatile uint64_t bytes_forwarded;      /**< Total bytes forwarded to servers */
    volatile uint64_t splice_operations;    /**< Number of splice operations performed */
    volatile uint64_t buffer_operations;    /**< Number of buffer copy operations */

    /* Performance statistics */
    volatile uint64_t epoll_iterations;     /**< Total epoll_wait() calls */
    volatile uint64_t epoll_events_processed; /**< Total epoll events processed */
    volatile uint32_t epoll_array_expansions;  /**< Times epoll array was expanded */
    volatile uint32_t epoll_array_shrinks;     /**< Times epoll array was shrunk */

    /* Error statistics */
    volatile uint64_t accept_errors;        /**< Accept errors encountered */
    volatile uint64_t connect_errors;       /**< Server connection errors */
    volatile uint64_t forward_errors;       /**< Data forwarding errors */
    volatile uint64_t resource_errors;      /**< Resource allocation errors */
    volatile uint64_t limit_rejections;     /**< Connections rejected due to limits */

    /* Timing information */
    time_t start_time;                      /**< Process start time */
    time_t last_stats_report;              /**< Last statistics report time */

    /* Thread safety */
    pthread_mutex_t lock;                   /**< Mutex for non-atomic operations */
};

/**
 * @brief Thread-safe connection pool with mutex protection
 *
 * Pre-allocates connection objects to avoid malloc/free overhead
 * during high-frequency connection establishment. Provides thread-safe
 * allocation and deallocation with optional blocking when pool is exhausted.
 */
struct conn_pool {
    struct proxy_conn *connections;  /**< Pre-allocated connection array */
    struct proxy_conn *freelist;     /**< Linked list of available connections */
    int capacity;                    /**< Total pool capacity */
    int used_count;                  /**< Currently allocated connections */
    int high_water_mark;             /**< Peak usage for monitoring */
    pthread_mutex_t lock;            /**< Thread safety mutex */
    pthread_cond_t available;        /**< Condition variable for blocking allocation */
};

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Global Variables */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/* Global state protected by mutex where needed */
static struct conn_pool g_conn_pool;
static struct conn_limiter g_conn_limiter;
static struct proxy_stats g_stats;

/* Runtime tunables (overridable via CLI) - these are read-only after initialization */
static int g_conn_pool_capacity = TCP_PROXY_CONN_POOL_SIZE;
static int g_userbuf_cap_runtime = TCP_PROXY_USERBUF_CAP;
static int g_sockbuf_cap_runtime = TCP_PROXY_SOCKBUF_CAP;
static int g_ka_idle = TCP_PROXY_KEEPALIVE_IDLE;
static int g_ka_intvl = TCP_PROXY_KEEPALIVE_INTVL;
static int g_ka_cnt = TCP_PROXY_KEEPALIVE_CNT;
static int g_backpressure_wm = TCP_PROXY_BACKPRESSURE_WM;

/* Signal-safe flag for graceful shutdown */
static volatile sig_atomic_t g_shutdown_requested = 0;

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Signal Handling */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/* Signal-safe shutdown handler */
static void handle_shutdown_signal(int sig) {
    (void)sig; /* Unused parameter */
    g_shutdown_requested = 1;
}

/* Setup signal handlers for graceful shutdown */
static int setup_shutdown_signals(void) {
    struct sigaction sa;

    /* Block signals during handler execution */
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaddset(&sa.sa_mask, SIGQUIT);

    sa.sa_handler = handle_shutdown_signal;
    sa.sa_flags = SA_RESTART; /* Restart interrupted system calls */

    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        P_LOG_ERR("sigaction(SIGTERM): %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        P_LOG_ERR("sigaction(SIGINT): %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGQUIT, &sa, NULL) < 0) {
        P_LOG_ERR("sigaction(SIGQUIT): %s", strerror(errno));
        return -1;
    }

    /* Ignore SIGPIPE - we handle EPIPE explicitly */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        P_LOG_ERR("sigaction(SIGPIPE): %s", strerror(errno));
        return -1;
    }

    return 0;
}

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
        P_LOG_WARN("setsockopt(SO_RCVBUF=%d) on fd %d failed: %s",
                   sz, sockfd, strerror(saved_errno));
        /* Non-fatal error - continue with default buffer size */
        ret = -1;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)) < 0) {
        saved_errno = errno;
        P_LOG_WARN("setsockopt(SO_SNDBUF=%d) on fd %d failed: %s",
                   sz, sockfd, strerror(saved_errno));
        /* Non-fatal error - continue with default buffer size */
        ret = -1;
    }

    /* Verify actual buffer sizes if setting succeeded */
    if (ret == 0) {
        int actual_rcv = 0, actual_snd = 0;
        socklen_t optlen = sizeof(actual_rcv);

        if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &actual_rcv, &optlen) == 0 &&
            getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &actual_snd, &optlen) == 0) {
            if (actual_rcv < sz || actual_snd < sz) {
                P_LOG_INFO("Socket buffer sizes: requested=%d, actual rcv=%d snd=%d",
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
        P_LOG_WARN("setsockopt(SO_KEEPALIVE) on fd %d failed: %s", sockfd, strerror(saved_errno));
        /* Keepalive failure is not fatal, but we should return error */
        return -1;
    }

#ifdef __linux__
    /* Linux-specific TCP keepalive parameters */
    int idle = g_ka_idle;
    int intvl = g_ka_intvl;
    int cnt = g_ka_cnt;

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) < 0) {
        saved_errno = errno;
        P_LOG_WARN("setsockopt(TCP_KEEPIDLE=%d) on fd %d failed: %s",
                   idle, sockfd, strerror(saved_errno));
        ret = -1;
    }
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl)) < 0) {
        saved_errno = errno;
        P_LOG_WARN("setsockopt(TCP_KEEPINTVL=%d) on fd %d failed: %s",
                   intvl, sockfd, strerror(saved_errno));
        ret = -1;
    }
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt)) < 0) {
        saved_errno = errno;
        P_LOG_WARN("setsockopt(TCP_KEEPCNT=%d) on fd %d failed: %s",
                   cnt, sockfd, strerror(saved_errno));
        ret = -1;
    }

    if (ret == 0) {
        P_LOG_INFO("TCP keepalive configured: idle=%ds, interval=%ds, count=%d",
                   idle, intvl, cnt);
    }
#else
    P_LOG_INFO("Basic TCP keepalive enabled (platform-specific tuning not available)");
#endif
    return ret;
}

static int set_tcp_nodelay(int sockfd) {
    int on = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0) {
        P_LOG_WARN("setsockopt(TCP_NODELAY) on fd %d: %s", sockfd, strerror(errno));
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
        P_LOG_ERR("Too many consecutive accept errors (%d), stopping", consecutive_errors);
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
        while (current > peak && !__sync_bool_compare_and_swap(&g_stats.peak_concurrent, peak, current)) {
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
    P_LOG_INFO("Connections: accepted=%lu, connected=%lu, failed=%lu, active=%lu, peak=%lu",
               g_stats.total_accepted, g_stats.total_connected, g_stats.total_failed,
               g_stats.current_active, g_stats.peak_concurrent);
    P_LOG_INFO("Traffic: received=%lu bytes, sent=%lu bytes, forwarded=%lu bytes",
               g_stats.bytes_received, g_stats.bytes_sent, g_stats.bytes_forwarded);
    P_LOG_INFO("Operations: splice=%lu, buffer=%lu, epoll_iterations=%lu",
               g_stats.splice_operations, g_stats.buffer_operations, g_stats.epoll_iterations);
    P_LOG_INFO("Errors: accept=%lu, connect=%lu, forward=%lu, resource=%lu, limits=%lu",
               g_stats.accept_errors, g_stats.connect_errors, g_stats.forward_errors,
               g_stats.resource_errors, g_stats.limit_rejections);
    P_LOG_INFO("Pool: used=%d, capacity=%d, high_water=%d",
               g_conn_pool.used_count, g_conn_pool.capacity, g_conn_pool.high_water_mark);
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
        return (ntohl(p[0]) ^ ntohl(p[1]) ^ ntohl(p[2]) ^ ntohl(p[3])) % CONN_LIMIT_HASH_SIZE;
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
        P_LOG_WARN("Total connection limit reached (%d)", g_conn_limiter.max_total);
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
                    P_LOG_WARN("Per-IP connection limit reached for %s (%d connections)",
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
/* Connection Pool Management */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static int init_conn_pool(void) {
    g_conn_pool.capacity = (g_conn_pool_capacity > 0)
                               ? g_conn_pool_capacity
                               : TCP_PROXY_CONN_POOL_SIZE;
    g_conn_pool.connections =
        malloc(sizeof(struct proxy_conn) * (size_t)g_conn_pool.capacity);
    if (!g_conn_pool.connections) {
        P_LOG_ERR("Failed to allocate connection pool");
        return -1;
    }

    /* Initialize mutex and condition variable */
    if (pthread_mutex_init(&g_conn_pool.lock, NULL) != 0) {
        P_LOG_ERR("Failed to initialize connection pool mutex");
        free(g_conn_pool.connections);
        g_conn_pool.connections = NULL;
        return -1;
    }
    if (pthread_cond_init(&g_conn_pool.available, NULL) != 0) {
        P_LOG_ERR("Failed to initialize connection pool condition variable");
        pthread_mutex_destroy(&g_conn_pool.lock);
        free(g_conn_pool.connections);
        g_conn_pool.connections = NULL;
        return -1;
    }

    g_conn_pool.freelist = NULL;
    for (int i = 0; i < g_conn_pool.capacity; i++) {
        struct proxy_conn *conn = &g_conn_pool.connections[i];
        conn->next = g_conn_pool.freelist;
        g_conn_pool.freelist = conn;
    }
    g_conn_pool.used_count = 0;
    g_conn_pool.high_water_mark = 0;
    P_LOG_INFO("Connection pool initialized with %d connections",
               g_conn_pool.capacity);
    return 0;
}

static void destroy_conn_pool(void) {
    if (g_conn_pool.connections) {
        pthread_mutex_destroy(&g_conn_pool.lock);
        pthread_cond_destroy(&g_conn_pool.available);
        free(g_conn_pool.connections);
        g_conn_pool.connections = NULL;
        g_conn_pool.freelist = NULL;
        g_conn_pool.capacity = 0;
        g_conn_pool.used_count = 0;
        g_conn_pool.high_water_mark = 0;
        P_LOG_INFO("Connection pool destroyed");
    }
}

static inline struct proxy_conn *alloc_proxy_conn(void) {
    struct proxy_conn *conn;

    pthread_mutex_lock(&g_conn_pool.lock);

    if (!g_conn_pool.freelist) {
        pthread_mutex_unlock(&g_conn_pool.lock);
        P_LOG_WARN("Connection pool exhausted!");
        return NULL;
    }

    conn = g_conn_pool.freelist;
    g_conn_pool.freelist = conn->next;
    g_conn_pool.used_count++;

    if (g_conn_pool.used_count > g_conn_pool.high_water_mark) {
        g_conn_pool.high_water_mark = g_conn_pool.used_count;
    }

    pthread_mutex_unlock(&g_conn_pool.lock);

    memset(conn, 0x0, sizeof(*conn));

    conn->cli_sock = -1;
    conn->svr_sock = -1;
#ifdef __linux__
    conn->c2s_pipe[0] = -1;
    conn->c2s_pipe[1] = -1;
    conn->s2c_pipe[0] = -1;
    conn->s2c_pipe[1] = -1;
    conn->c2s_pending = 0;
    conn->s2c_pending = 0;
    conn->use_splice = false;
#endif
    conn->magic_client = EV_MAGIC_CLIENT;
    conn->magic_server = EV_MAGIC_SERVER;

    return conn;
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

    /* Return connection to pool with thread safety */
    pthread_mutex_lock(&g_conn_pool.lock);
    conn->next = g_conn_pool.freelist;
    g_conn_pool.freelist = conn;
    g_conn_pool.used_count--;
    pthread_cond_signal(&g_conn_pool.available);
    pthread_mutex_unlock(&g_conn_pool.lock);
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
/* Proxy Connection Creation and Management */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static struct proxy_conn *
create_proxy_conn(struct config *cfg, int cli_sock,
                  const union sockaddr_inx *cli_addr) {
    struct proxy_conn *conn = NULL;
    char s_addr1[50] = "", s_addr2[50] = "";

    /* Check connection limits first */
    if (!check_connection_limit(cli_addr)) {
        P_LOG_WARN("Connection from %s rejected due to limits",
                   sockaddr_to_string(cli_addr));
        __sync_fetch_and_add(&g_stats.limit_rejections, 1);
        close(cli_sock);
        return NULL;
    }

    /* Client calls in, allocate session data for it. */
    if (!(conn = alloc_proxy_conn())) {
        P_LOG_ERR("alloc_proxy_conn(): %s", strerror(errno));
        /* Release the connection limit since we're failing */
        release_connection_limit(cli_addr);
        close(cli_sock);
        return NULL;
    }
    conn->cli_sock = cli_sock;
    set_nonblock(conn->cli_sock);
    set_sock_buffers(conn->cli_sock);
    set_keepalive(conn->cli_sock);
    set_tcp_nodelay(conn->cli_sock);

    conn->cli_addr = *cli_addr;

    /* Calculate address of the real server */
    conn->svr_addr = cfg->dst_addr;
#ifdef __linux__
    if (cfg->base_addr_mode) {
        /*
         * WARNING: This mode implements a highly specific address translation
         * scheme for transparent proxying (e.g., using TPROXY in iptables).
         * It relies on getsockopt(SO_ORIGINAL_DST) to find the original
         * destination address before redirection.
         *
         * It then performs direct integer arithmetic on the destination IP
         * address based on the difference between the original destination port
         * and the listener port.
         *
         * This is NOT a general-purpose load balancing or NAT mechanism.
         *
         * It is designed for scenarios where a contiguous block of IP addresses
         * is mapped 1:1 to a contiguous block of ports. For example, if the
         * base destination is 192.168.1.0 and a connection to port 8100 is
         * redirected to the listener on port 8080, the port offset of 20 will
         * be added to the base IP, resulting in a destination of 192.168.1.20.
         *
         * Use this feature with extreme caution and only if you have a network
         * environment specifically configured for this behavior.
         */
        union sockaddr_inx loc_addr, orig_dst;
        socklen_t loc_alen = sizeof(loc_addr), orig_alen = sizeof(orig_dst);
        int port_offset = 0;
        uint32_t base, *addr_pos = NULL; /* big-endian data */
        int64_t sum;

        memset(&loc_addr, 0x0, sizeof(loc_addr));
        memset(&orig_dst, 0x0, sizeof(orig_dst));
        if (getsockname(conn->cli_sock, (struct sockaddr *)&loc_addr,
                        &loc_alen)) {
            P_LOG_ERR("getsockname() failed: %s", strerror(errno));
            goto err;
        }

        /* Validate local address length */
        if (loc_alen < sizeof(struct sockaddr_in) ||
            (loc_addr.sa.sa_family == AF_INET6 && loc_alen < sizeof(struct sockaddr_in6))) {
            P_LOG_ERR("Invalid local address length: %u", loc_alen);
            goto err;
        }

        if (getsockopt(conn->cli_sock, SOL_IP, SO_ORIGINAL_DST, &orig_dst,
                       &orig_alen)) {
            int saved_errno = errno;
            P_LOG_ERR("getsockopt(SO_ORIGINAL_DST) failed: %s", strerror(saved_errno));

            /* Provide more specific error information */
            if (saved_errno == ENOPROTOOPT) {
                P_LOG_ERR("SO_ORIGINAL_DST not supported - ensure iptables REDIRECT/DNAT is used");
            } else if (saved_errno == ENOENT) {
                P_LOG_ERR("No original destination found - connection may not be redirected");
            }
            goto err;
        }

        /* Validate original destination address length */
        if (orig_alen < sizeof(struct sockaddr_in) ||
            (orig_dst.sa.sa_family == AF_INET6 && orig_alen < sizeof(struct sockaddr_in6))) {
            P_LOG_ERR("Invalid original destination address length: %u", orig_alen);
            goto err;
        }

        if (conn->svr_addr.sa.sa_family == AF_INET) {
            addr_pos = (uint32_t *)&conn->svr_addr.sin.sin_addr;
        } else if (conn->svr_addr.sa.sa_family == AF_INET6) {
            addr_pos = (uint32_t *)&conn->svr_addr.sin6.sin6_addr.s6_addr32[3];
        } else {
            P_LOG_ERR("Unsupported address family %d in base_addr_mode",
                      conn->svr_addr.sa.sa_family);
            goto err;
        }

        /* Validate original destination and local address families match */
        if (orig_dst.sa.sa_family != loc_addr.sa.sa_family) {
            P_LOG_ERR("Address family mismatch: orig_dst=%d, local=%d",
                      orig_dst.sa.sa_family, loc_addr.sa.sa_family);
            goto err;
        }

        port_offset = (int)(ntohs(*port_of_sockaddr(&orig_dst)) -
                            ntohs(*port_of_sockaddr(&loc_addr)));

        /* Validate port offset is reasonable */
        if (port_offset < MIN_PORT_OFFSET || port_offset > MAX_PORT_OFFSET) {
            P_LOG_ERR("Port offset too large: %d", port_offset);
            goto err;
        }

        base = ntohl(*addr_pos);

        /* Check for overflow/underflow with proper bounds checking */
        if (port_offset > 0) {
            if (base > UINT32_MAX - (uint32_t)port_offset) {
                P_LOG_ERR("Address calculation would overflow: base=%u, offset=%d",
                          base, port_offset);
                goto err;
            }
        } else if (port_offset < 0) {
            if (base < (uint32_t)(-port_offset)) {
                P_LOG_ERR("Address calculation would underflow: base=%u, offset=%d",
                          base, port_offset);
                goto err;
            }
        }

        sum = (int64_t)base + (int64_t)port_offset;

        /* Additional safety check */
        if (sum < 0 || sum > UINT32_MAX) {
            P_LOG_ERR("base address adjustment overflows: base=%u, off=%d, result=%ld",
                      base, port_offset, sum);
            goto err;
        }

        uint32_t new_addr = (uint32_t)sum;

        /* Enhanced validation of the resulting address */
        if (conn->svr_addr.sa.sa_family == AF_INET) {
            /* Check if it's a valid unicast address */
            if ((new_addr & IPV4_ADDR_LOOPBACK_MASK) == IPV4_ADDR_LOOPBACK ||
                (new_addr & IPV4_ADDR_MULTICAST_MASK) == IPV4_ADDR_MULTICAST ||
                (new_addr & IPV4_ADDR_RESERVED_MASK) == IPV4_ADDR_RESERVED ||
                new_addr == 0) {  /* 0.0.0.0 - invalid */
                P_LOG_ERR("Calculated address is invalid or reserved: %u.%u.%u.%u",
                          (new_addr >> 24) & 0xFF, (new_addr >> 16) & 0xFF,
                          (new_addr >> 8) & 0xFF, new_addr & 0xFF);
                goto err;
            }

            /* Additional security checks for private address ranges */
            bool is_private = ((new_addr & IPV4_ADDR_CLASS_A_PRIVATE_MASK) == IPV4_ADDR_CLASS_A_PRIVATE) ||
                             ((new_addr & IPV4_ADDR_CLASS_B_PRIVATE_MASK) == IPV4_ADDR_CLASS_B_PRIVATE) ||
                             ((new_addr & IPV4_ADDR_CLASS_C_PRIVATE_MASK) == IPV4_ADDR_CLASS_C_PRIVATE);

            if (!is_private) {
                P_LOG_WARN("Calculated address %u.%u.%u.%u is not in private range - potential security risk",
                          (new_addr >> 24) & 0xFF, (new_addr >> 16) & 0xFF,
                          (new_addr >> 8) & 0xFF, new_addr & 0xFF);

                /* In production, you might want to reject non-private addresses */
                /* Uncomment the following lines for stricter security: */
                /* P_LOG_ERR("Non-private addresses not allowed in base_addr_mode"); */
                /* goto err; */
            }

            P_LOG_INFO("Base address calculation: offset=%d, result=%u.%u.%u.%u",
                      port_offset,
                      (new_addr >> 24) & 0xFF, (new_addr >> 16) & 0xFF,
                      (new_addr >> 8) & 0xFF, new_addr & 0xFF);
        }

        *addr_pos = htonl(new_addr);
    }
#endif

    inet_ntop(conn->cli_addr.sa.sa_family, addr_of_sockaddr(&conn->cli_addr),
              s_addr1, sizeof(s_addr1));
    inet_ntop(conn->svr_addr.sa.sa_family, addr_of_sockaddr(&conn->svr_addr),
              s_addr2, sizeof(s_addr2));
    P_LOG_INFO("New connection [%s]:%d -> [%s]:%d", s_addr1,
               ntohs(*port_of_sockaddr(&conn->cli_addr)), s_addr2,
               ntohs(*port_of_sockaddr(&conn->svr_addr)));

    /* Initiate the connection to server right now. */
    if ((conn->svr_sock = socket(conn->svr_addr.sa.sa_family, SOCK_STREAM, 0)) <
        0) {
        P_LOG_ERR("socket(svr_sock): %s", strerror(errno));
        goto err;
    }
    set_nonblock(conn->svr_sock);
    set_sock_buffers(conn->svr_sock);
    set_keepalive(conn->svr_sock);
    set_tcp_nodelay(conn->svr_sock);

    /* Allocate per-connection user buffers with proper error handling */
    conn->request.data = (char *)malloc((size_t)g_userbuf_cap_runtime);
    if (!conn->request.data) {
        P_LOG_ERR("malloc(request buffer) failed: %s", strerror(errno));
        goto err;
    }
    conn->response.data = (char *)malloc((size_t)g_userbuf_cap_runtime);
    if (!conn->response.data) {
        P_LOG_ERR("malloc(response buffer) failed: %s", strerror(errno));
        /* Clean up already allocated request buffer */
        free(conn->request.data);
        conn->request.data = NULL;
        conn->request.capacity = 0;
        goto err;
    }
    conn->request.capacity = (size_t)g_userbuf_cap_runtime;
    conn->request.dlen = 0;
    conn->request.rpos = 0;
    conn->response.capacity = (size_t)g_userbuf_cap_runtime;
    conn->response.dlen = 0;
    conn->response.rpos = 0;

    if (connect(conn->svr_sock, (struct sockaddr *)&conn->svr_addr,
                sizeof_sockaddr(&conn->svr_addr)) == 0) {
        /* Connected, ready for data forwarding immediately. */
        conn->state = S_FORWARDING;
        /* Set up splice (Linux) with proper error handling */
#ifdef __linux__
        if (!conn->use_splice) {
            int p1[2] = {-1, -1}, p2[2] = {-1, -1};
            bool p1_created = false, p2_created = false;

            if (pipe2(p1, O_NONBLOCK | O_CLOEXEC) == 0) {
                p1_created = true;
                if (pipe2(p2, O_NONBLOCK | O_CLOEXEC) == 0) {
                    p2_created = true;
                    conn->c2s_pipe[0] = p1[0];
                    conn->c2s_pipe[1] = p1[1];
                    conn->s2c_pipe[0] = p2[0];
                    conn->s2c_pipe[1] = p2[1];
                    conn->use_splice = true;
                    P_LOG_INFO("Splice pipes created successfully for connection");
                } else {
                    P_LOG_WARN("Failed to create s2c pipe for splice: %s", strerror(errno));
                }
            } else {
                P_LOG_WARN("Failed to create c2s pipe for splice: %s", strerror(errno));
            }

            /* Clean up on partial failure - ensure no file descriptor leaks */
            if (!conn->use_splice) {
                if (p1_created) {
                    if (safe_close(p1[0]) < 0) {
                        P_LOG_WARN("Failed to close p1[0]: %s", strerror(errno));
                    }
                    if (safe_close(p1[1]) < 0) {
                        P_LOG_WARN("Failed to close p1[1]: %s", strerror(errno));
                    }
                }
                if (p2_created) {
                    if (safe_close(p2[0]) < 0) {
                        P_LOG_WARN("Failed to close p2[0]: %s", strerror(errno));
                    }
                    if (safe_close(p2[1]) < 0) {
                        P_LOG_WARN("Failed to close p2[1]: %s", strerror(errno));
                    }
                }
                P_LOG_INFO("Falling back to user-space buffering due to splice setup failure");
            }
        }
#endif
        return conn;
    } else if (errno == EINPROGRESS) {
        /* OK, poll for the connection to complete or fail */
        conn->state = S_SERVER_CONNECTING;
        /* Prepare splice early (Linux) with proper error handling */
#ifdef __linux__
        if (!conn->use_splice) {
            int p1[2] = {-1, -1}, p2[2] = {-1, -1};
            bool p1_created = false, p2_created = false;

            if (pipe2(p1, O_NONBLOCK | O_CLOEXEC) == 0) {
                p1_created = true;
                if (pipe2(p2, O_NONBLOCK | O_CLOEXEC) == 0) {
                    p2_created = true;
                    conn->c2s_pipe[0] = p1[0];
                    conn->c2s_pipe[1] = p1[1];
                    conn->s2c_pipe[0] = p2[0];
                    conn->s2c_pipe[1] = p2[1];
                    conn->use_splice = true;
                    P_LOG_INFO("Splice pipes prepared for async connection");
                } else {
                    P_LOG_WARN("Failed to create s2c pipe for splice: %s", strerror(errno));
                }
            } else {
                P_LOG_WARN("Failed to create c2s pipe for splice: %s", strerror(errno));
            }

            /* Clean up on partial failure - ensure no file descriptor leaks */
            if (!conn->use_splice) {
                if (p1_created) {
                    if (safe_close(p1[0]) < 0) {
                        P_LOG_WARN("Failed to close p1[0] during cleanup: %s", strerror(errno));
                    }
                    if (safe_close(p1[1]) < 0) {
                        P_LOG_WARN("Failed to close p1[1] during cleanup: %s", strerror(errno));
                    }
                }
                if (p2_created) {
                    if (safe_close(p2[0]) < 0) {
                        P_LOG_WARN("Failed to close p2[0] during cleanup: %s", strerror(errno));
                    }
                    if (safe_close(p2[1]) < 0) {
                        P_LOG_WARN("Failed to close p2[1] during cleanup: %s", strerror(errno));
                    }
                }
                P_LOG_INFO("Splice setup failed, will use user-space buffering");
            }
        }
#endif
        return conn;
    } else {
        /* Error occurs, drop the session. */
        P_LOG_WARN("Connection to [%s]:%d failed: %s", s_addr2,
                   ntohs(*port_of_sockaddr(&conn->svr_addr)), strerror(errno));
        goto err;
    }

err:
    /* On error, the connection is released here. The caller doesn't need to do
     * anything. */
    if (conn)
        release_proxy_conn(conn, NULL, 0, -1);
    return NULL;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Connection State Handlers */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static int handle_server_connecting(struct proxy_conn *conn, int efd, int epfd,
                                    struct epoll_event *ev) {
    char s_addr[50] = "";

    if (efd == conn->svr_sock) {
        /* The connection has established or failed. */
        int err = 0;
        socklen_t errlen = sizeof(err);

        if (getsockopt(conn->svr_sock, SOL_SOCKET, SO_ERROR, &err, &errlen) <
                0 ||
            err) {
            inet_ntop(conn->svr_addr.sa.sa_family,
                      addr_of_sockaddr(&conn->svr_addr), s_addr,
                      sizeof(s_addr));
            P_LOG_WARN("Connection to [%s]:%d failed: %s", s_addr,
                       ntohs(*port_of_sockaddr(&conn->svr_addr)),
                       strerror(err ? err : errno));
            conn->state = S_CLOSING;
            return 0;
        }

        /* Connected, start forwarding immediately using this event. */
        conn->state = S_FORWARDING;
        /* If we buffered any client data while waiting for the server,
         * disable splice so it gets flushed through the user buffer first. */
        if (conn->request.dlen > conn->request.rpos)
            conn->use_splice = false;
        return handle_forwarding(conn, efd, epfd, ev);
    } else {
        /* Received data early before server connection is OK */
        struct buffer_info *rxb = &conn->request;
        int rc;

        for (;;) {
            rc = recv(efd, rxb->data + rxb->dlen, rxb->capacity - rxb->dlen, 0);
            if (rc == 0) {
                inet_ntop(conn->cli_addr.sa.sa_family,
                          addr_of_sockaddr(&conn->cli_addr), s_addr,
                          sizeof(s_addr));
                P_LOG_INFO("Connection [%s]:%d closed during server handshake",
                           s_addr, ntohs(*port_of_sockaddr(&conn->cli_addr)));
                conn->state = S_CLOSING;
                return 0;
            } else if (rc < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    break; /* drained for now */
                inet_ntop(conn->cli_addr.sa.sa_family,
                          addr_of_sockaddr(&conn->cli_addr), s_addr,
                          sizeof(s_addr));
                P_LOG_INFO(
                    "Connection [%s]:%d error during server handshake: %s",
                    s_addr, ntohs(*port_of_sockaddr(&conn->cli_addr)),
                    strerror(errno));
                conn->state = S_CLOSING;
                return 0;
            }
            rxb->dlen += rc;
            if (rxb->dlen >= rxb->capacity)
                break; /* buffer full */
        }
        return -EAGAIN;
    }
}

#ifdef __linux__
static int handle_forwarding_splice(struct proxy_conn *conn,
                                    struct epoll_event *ev) {
    int src_fd, dst_fd;
    int *pipe_fds;
    size_t *pending;
    ssize_t n_in, n_out;

    if (ev->data.ptr == &conn->magic_client) {
        /* client -> server */
        src_fd = conn->cli_sock;
        dst_fd = conn->svr_sock;
        pipe_fds = conn->c2s_pipe;
        pending = &conn->c2s_pending;
    } else {
        /* server -> client */
        src_fd = conn->svr_sock;
        dst_fd = conn->cli_sock;
        pipe_fds = conn->s2c_pipe;
        pending = &conn->s2c_pending;
    }

    while (1) {
        size_t to_write = *pending;

        if (to_write == 0) {
            /* Pipe is empty, read from source */
            n_in = splice(src_fd, NULL, pipe_fds[1], NULL, SPLICE_CHUNK_SIZE,
                          SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            if (n_in == 0) {
                if (src_fd == conn->cli_sock)
                    conn->cli_in_eof = true;
                else
                    conn->svr_in_eof = true;
                break; /* EOF */
            }
            if (n_in < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    break; /* Drained */
                P_LOG_ERR("splice(in) from fd %d failed: %s", src_fd,
                          strerror(errno));
                conn->state = S_CLOSING;
                return 0;
            }
            to_write = (size_t)n_in;
        }

        /* Write to destination */
        n_out = splice(pipe_fds[0], NULL, dst_fd, NULL, to_write,
                       SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (n_out < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Can't write, so data is now pending */
                *pending = to_write;
                break;
            }
            P_LOG_ERR("splice(out) to fd %d failed: %s", dst_fd,
                      strerror(errno));
            conn->state = S_CLOSING;
            return 0;
        }

        if ((size_t)n_out < to_write) {
            /* Partial write, update pending and yield to EPOLLOUT */
            *pending = to_write - (size_t)n_out;
            break;
        }

        /* Full write */
        *pending = 0;

        /* Update splice statistics */
        __sync_fetch_and_add(&g_stats.splice_operations, 1);
        __sync_fetch_and_add(&g_stats.bytes_forwarded, n_out);
    }

    return -EAGAIN;
}
#endif

static int handle_forwarding(struct proxy_conn *conn, int efd, int epfd,
                             struct epoll_event *ev) {
    char s_addr[50] = "";

    (void)efd;
    (void)epfd;

#ifdef __linux__
    if (conn->use_splice) {
        int io_state = handle_forwarding_splice(conn, ev);
        if (conn->cli_in_eof && !conn->cli2svr_shutdown) {
            shutdown(conn->svr_sock, SHUT_WR);
            conn->cli2svr_shutdown = true;
        }
        if (conn->svr_in_eof && !conn->svr2cli_shutdown) {
            shutdown(conn->cli_sock, SHUT_WR);
            conn->svr2cli_shutdown = true;
        }
        if (conn->cli_in_eof && conn->svr_in_eof) {
            conn->state = S_CLOSING;
        }
        return io_state;
    }
#endif

    if (ev->events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
        goto err;
    }

    if (ev->events & EPOLLIN) {
        int sock = (ev->data.ptr == &conn->magic_client) ? conn->cli_sock
                                                         : conn->svr_sock;
        struct buffer_info *buf = (ev->data.ptr == &conn->magic_client)
                                      ? &conn->request
                                      : &conn->response;
        ssize_t rc;
        /* Compact buffer if needed - only when we have significant waste */
        if (buf->dlen == buf->capacity && buf->rpos > buf->capacity / BUFFER_COMPACT_THRESHOLD_RATIO) {
            size_t unread = buf->dlen - buf->rpos;
            if (unread > 0) {
                memmove(buf->data, buf->data + buf->rpos, unread);
            }
            buf->dlen = unread;
            buf->rpos = 0;
        }
        while (buf->dlen < buf->capacity) {
            rc =
                recv(sock, buf->data + buf->dlen, buf->capacity - buf->dlen, 0);
            if (rc == 0) {
                if (sock == conn->cli_sock)
                    conn->cli_in_eof = true;
                else
                    conn->svr_in_eof = true;
                break;
            }
            if (rc < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    goto err;
                break;
            }
            buf->dlen += rc;

            /* Update traffic statistics */
            if (sock == conn->cli_sock) {
                update_traffic_stats(rc, 0);  /* Bytes received from client */
            } else {
                update_traffic_stats(0, rc);  /* Bytes received from server */
            }
        }
    }

    if (ev->events & EPOLLOUT) {
        int sock = (ev->data.ptr == &conn->magic_client) ? conn->cli_sock
                                                         : conn->svr_sock;
        struct buffer_info *buf = (ev->data.ptr == &conn->magic_client)
                                      ? &conn->response
                                      : &conn->request;
        ssize_t rc;
        if (buf->dlen > buf->rpos) {
            rc = send(sock, buf->data + buf->rpos, buf->dlen - buf->rpos, 0);
            if (rc < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    goto err;
            } else {
                buf->rpos += rc;

                /* Update forwarded bytes statistics */
                __sync_fetch_and_add(&g_stats.bytes_forwarded, rc);
                __sync_fetch_and_add(&g_stats.buffer_operations, 1);
            }
        }
        if (buf->rpos >= buf->dlen) {
            buf->rpos = 0;
            buf->dlen = 0; // Compact buffer
        }
    }

    if (conn->cli_in_eof && !conn->cli2svr_shutdown &&
        conn->request.rpos >= conn->request.dlen) {
        shutdown(conn->svr_sock, SHUT_WR);
        conn->cli2svr_shutdown = true;
    }
    if (conn->svr_in_eof && !conn->svr2cli_shutdown &&
        conn->response.rpos >= conn->response.dlen) {
        shutdown(conn->cli_sock, SHUT_WR);
        conn->svr2cli_shutdown = true;
    }

    if (conn->cli_in_eof && conn->svr_in_eof &&
        conn->request.rpos >= conn->request.dlen &&
        conn->response.rpos >= conn->response.dlen) {
        conn->state = S_CLOSING;
    }

    return 0;

err:
    inet_ntop(conn->cli_addr.sa.sa_family, addr_of_sockaddr(&conn->cli_addr),
              s_addr, sizeof(s_addr));
    P_LOG_INFO("Connection [%s]:%d closed", s_addr,
               ntohs(*port_of_sockaddr(&conn->cli_addr)));
    conn->state = S_CLOSING;
    return 0;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Event Handling Functions */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static int handle_new_connection(int listen_sock, int epfd,
                                 struct config *cfg) {
    for (;;) {
        union sockaddr_inx cli_addr;
        socklen_t cli_alen = sizeof(cli_addr);
        int cli_sock;
#ifdef __linux__
        cli_sock = accept4(listen_sock, (struct sockaddr *)&cli_addr, &cli_alen,
                           SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cli_sock < 0 && (errno == ENOSYS || errno == EINVAL)) {
            /* Fallback if accept4 not supported */
            cli_sock = accept(listen_sock, (struct sockaddr *)&cli_addr, &cli_alen);
            if (cli_sock >= 0) {
                set_nonblock(cli_sock);
                fcntl(cli_sock, F_SETFD, FD_CLOEXEC);
            }
        }
#else
        cli_sock = accept(listen_sock, (struct sockaddr *)&cli_addr, &cli_alen);
        if (cli_sock >= 0) {
            set_nonblock(cli_sock);
            fcntl(cli_sock, F_SETFD, FD_CLOEXEC);
        }
#endif
        if (cli_sock < 0) {
            int error_result = handle_accept_errors(listen_sock);
            if (error_result == 0) {
                /* Normal case - no more connections */
                break;
            } else if (error_result == -2) {
                /* Fatal error - stop accepting */
                return -1;
            }
            /* Temporary error - continue trying */
            continue;
        }

        /* Update accept statistics */
        __sync_fetch_and_add(&g_stats.total_accepted, 1);

        struct proxy_conn *conn = create_proxy_conn(cfg, cli_sock, &cli_addr);
        if (conn) {
            set_conn_epoll_fds(conn, epfd);
            update_connection_stats(true, false);  /* Successfully connected */
        } else {
            update_connection_stats(false, true);  /* Failed to create connection */
        }
        /* Note: create_proxy_conn handles socket closure on failure */
    }
    return 0;
}

static int proxy_loop(int epfd, int listen_sock, struct config *cfg) {
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

    while (!g_state.terminate && !g_shutdown_requested) {
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

            if (consecutive_full_batches >= EPOLL_EXPAND_THRESHOLD && events_size < EPOLL_EVENTS_MAX) {
                int new_size = events_size * 2;
                if (new_size > EPOLL_EVENTS_MAX) {
                    new_size = EPOLL_EVENTS_MAX;
                }

                struct epoll_event *new_events = realloc(events,
                    sizeof(struct epoll_event) * new_size);
                if (new_events) {
                    events = new_events;
                    events_size = new_size;
                    consecutive_full_batches = 0;
                    __sync_fetch_and_add(&g_stats.epoll_array_expansions, 1);
                    P_LOG_INFO("Expanded epoll events array to %d", events_size);
                }
            }
        } else if (nfds < events_size / EPOLL_SHRINK_USAGE_RATIO) {
            /* Array usage is low - consider shrinking */
            consecutive_small_batches++;
            consecutive_full_batches = 0;

            if (consecutive_small_batches >= EPOLL_SHRINK_THRESHOLD && events_size > EPOLL_EVENTS_MIN) {
                int new_size = events_size / 2;
                if (new_size < EPOLL_EVENTS_MIN) {
                    new_size = EPOLL_EVENTS_MIN;
                }

                struct epoll_event *new_events = realloc(events,
                    sizeof(struct epoll_event) * new_size);
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
                /* Client or server socket - validate magic numbers and connection state */
                uint32_t *magic = ev->data.ptr;
                int efd = -1;

                /* Additional safety check for pointer validity */
                if ((uintptr_t)magic < MIN_VALID_POINTER) {
                    P_LOG_WARN("Invalid pointer in epoll event: %p", (void*)magic);
                    continue;
                }

                if (*magic == EV_MAGIC_CLIENT) {
                    conn = container_of(magic, struct proxy_conn, magic_client);
                    efd = conn->cli_sock;

                    /* Enhanced validation for client socket */
                    if (efd < 0) {
                        P_LOG_WARN("Event for closed client socket (fd=%d, state=%d)",
                                   efd, conn->state);
                        continue;
                    }
                    if (conn->state == S_CLOSING) {
                        P_LOG_DEBUG("Event for closing client connection (fd=%d)", efd);
                        continue;
                    }
                    if (conn->magic_server != EV_MAGIC_SERVER) {
                        P_LOG_ERR("Corrupted connection object detected (client side)");
                        continue;
                    }
                } else if (*magic == EV_MAGIC_SERVER) {
                    conn = container_of(magic, struct proxy_conn, magic_server);
                    efd = conn->svr_sock;

                    /* Enhanced validation for server socket */
                    if (efd < 0) {
                        P_LOG_WARN("Event for closed server socket (fd=%d, state=%d)",
                                   efd, conn->state);
                        continue;
                    }
                    if (conn->state == S_CLOSING) {
                        P_LOG_DEBUG("Event for closing server connection (fd=%d)", efd);
                        continue;
                    }
                    if (conn->magic_client != EV_MAGIC_CLIENT) {
                        P_LOG_ERR("Corrupted connection object detected (server side)");
                        continue;
                    }
                } else {
                    P_LOG_WARN("Invalid magic number in epoll event: 0x%x", *magic);
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

static void show_help(const char *prog) {
    P_LOG_INFO("Usage: %s [options] <src_addr> <dst_addr>", prog);
    P_LOG_INFO("  <src_addr>, <dst_addr>    -- IPv4/IPv6 address with port, "
               "e.g. 127.0.0.1:8080, [::1]:8080");
    P_LOG_INFO("  -d, --daemonize           -- detach and run in background");
    P_LOG_INFO("  -p, --pidfile <path>      -- create PID file at <path>");
    P_LOG_INFO("  -b, --base-addr-mode      -- use src_addr as base for "
               "dst_addr (for load balancing)");
    P_LOG_INFO(
        "  -r, --reuse-addr          -- set SO_REUSEADDR on listener socket");
    P_LOG_INFO(
        "  -R, --reuse-port          -- set SO_REUSEPORT on listener socket");
    P_LOG_INFO(
        "  -6, --v6only              -- set IPV6_V6ONLY on listener socket");
    P_LOG_INFO(
        "  -C <pool_size>            -- connection pool size (default: %d)",
        TCP_PROXY_CONN_POOL_SIZE);
    P_LOG_INFO("  -U <userbuf_bytes>        -- per-direction user buffer size "
               "(default: %d)",
               TCP_PROXY_USERBUF_CAP);
    P_LOG_INFO(
        "  -S <sockbuf_bytes>        -- SO_RCVBUF/SO_SNDBUF size (default: %d)",
        TCP_PROXY_SOCKBUF_CAP);
    P_LOG_INFO("  -I <ka_idle>              -- TCP keepalive idle seconds "
               "(default: %d)",
               TCP_PROXY_KEEPALIVE_IDLE);
    P_LOG_INFO("  -N <ka_intvl>             -- TCP keepalive interval seconds "
               "(default: %d)",
               TCP_PROXY_KEEPALIVE_INTVL);
    P_LOG_INFO("  -K <ka_cnt>               -- TCP keepalive probe count "
               "(default: %d)",
               TCP_PROXY_KEEPALIVE_CNT);
    P_LOG_INFO("  -M <max_conn>             -- maximum total connections "
               "(default: unlimited)");
    P_LOG_INFO("  -P <max_per_ip>           -- maximum connections per IP "
               "(default: unlimited)");
    P_LOG_INFO("  -h, --help                -- show this help");
}

int main(int argc, char *argv[]) {
    /* Local variables */
    int rc = 1;
    struct config cfg;
    int listen_sock = -1, epfd = -1;
    uint32_t magic_listener = EV_MAGIC_LISTENER;

    /* Initialize configuration with defaults */
    memset(&cfg, 0, sizeof(cfg));
    cfg.reuse_addr = true;
    cfg.max_connections = 0;  /* 0 = no limit */
    cfg.max_per_ip = 0;       /* 0 = no limit */

    /* Parse command line arguments */
    int opt;
    while ((opt = getopt(argc, argv, "dp:brR6hC:U:S:I:N:K:M:P:")) != -1) {
        switch (opt) {
        case 'd':
            cfg.daemonize = true;
            break;
        case 'p':
            cfg.pidfile = optarg;
            break;
        case 'b':
            cfg.base_addr_mode = true;
            break;
        case 'r':
            cfg.reuse_addr = true;
            break;
        case 'R':
            cfg.reuse_port = true;
            break;
        case '6':
            cfg.v6only = true;
            break;
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
        case 'U': {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v <= 0) {
                P_LOG_WARN("invalid -U value '%s', keeping default %d", optarg,
                           g_userbuf_cap_runtime);
            } else {
                if (v < 4096)
                    v = 4096; /* min 4KB */
                if (v > (8 << 20))
                    v = (8 << 20); /* max 8MB */
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
                if (v < 4096)
                    v = 4096;
                if (v > (8 << 20))
                    v = (8 << 20);
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
                if (v < 10)
                    v = 10;
                if (v > 86400)
                    v = 86400;
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
                if (v < 5)
                    v = 5;
                if (v > 3600)
                    v = 3600;
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
                if (v < 1)
                    v = 1;
                if (v > 100)
                    v = 100;
                g_ka_cnt = (int)v;
            }
            break;
        }
        case 'M': {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v < 0) {
                P_LOG_WARN("invalid -M value '%s', keeping default %d", optarg,
                           cfg.max_connections);
            } else {
                if (v > MAX_TOTAL_CONNECTIONS_LIMIT)
                    v = MAX_TOTAL_CONNECTIONS_LIMIT;
                cfg.max_connections = (int)v;
            }
            break;
        }
        case 'P': {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v < 0) {
                P_LOG_WARN("invalid -P value '%s', keeping default %d", optarg,
                           cfg.max_per_ip);
            } else {
                if (v > MAX_PER_IP_CONNECTIONS_LIMIT)
                    v = MAX_PER_IP_CONNECTIONS_LIMIT;
                cfg.max_per_ip = (int)v;
            }
            break;
        }
        case 'h':
            show_help(argv[0]);
            return 0;
        case '?':
            return 1;
        default:
            break;
        }
    }

    if (optind + 2 != argc) {
        show_help(argv[0]);
        return 1;
    }

    if (get_sockaddr_inx_pair(argv[optind], &cfg.src_addr, false) != 0) {
        P_LOG_ERR("Invalid src_addr: %s", argv[optind]);
        return 1;
    }
    if (get_sockaddr_inx_pair(argv[optind + 1], &cfg.dst_addr, false) != 0) {
        P_LOG_ERR("Invalid dst_addr: %s", argv[optind + 1]);
        return 1;
    }

    /* Initialize logging */
    openlog("tcpfwd", LOG_PID | LOG_PERROR, LOG_DAEMON);

    /* Recompute backpressure WM if userbuf changed */
    g_backpressure_wm = (g_userbuf_cap_runtime * 3) / 4;

    /* Initialize statistics system */
    if (init_stats() != 0) {
        closelog();
        return 1;
    }

    /* Initialize connection pool */
    if (init_conn_pool() != 0) {
        destroy_stats();
        closelog();
        return 1;
    }

    /* Initialize connection limiter */
    if (init_conn_limiter(cfg.max_connections, cfg.max_per_ip) != 0) {
        destroy_conn_pool();
        destroy_stats();
        closelog();
        return 1;
    }

    /* Daemonize if requested */
    if (cfg.daemonize && do_daemonize() != 0)
        goto cleanup;

    /* Write PID file if specified */
    if (cfg.pidfile) {
        if (write_pidfile(cfg.pidfile) < 0) {
            rc = 1;
            goto cleanup;
        }
    }

    /* Set up signal handlers */
    if (setup_shutdown_signals() != 0) {
        P_LOG_ERR("Failed to setup signal handlers");
        rc = 1;
        goto cleanup;
    }
    setup_signal_handlers();

    /* Create listening socket */
    listen_sock = socket(cfg.src_addr.sa.sa_family, SOCK_STREAM, 0);
    if (listen_sock < 0) {
        P_LOG_ERR("socket(): %s", strerror(errno));
        goto cleanup;
    }

    /* Configure socket options */

    if (cfg.reuse_addr) {
        int on = 1;
        if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) <
            0) {
            P_LOG_WARN(
                "setsockopt(SO_REUSEADDR): %s (continuing without reuseaddr)",
                strerror(errno));
        }
    }

#ifdef SO_REUSEPORT
    if (cfg.reuse_port) {
        int on = 1;
        if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) <
            0) {
            P_LOG_WARN(
                "setsockopt(SO_REUSEPORT): %s (continuing without reuseport)",
                strerror(errno));
        }
    }
#endif

    if (cfg.src_addr.sa.sa_family == AF_INET6 && cfg.v6only) {
        int on = 1;
        (void)setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &on,
                         sizeof(on));
    }

    if (bind(listen_sock, &cfg.src_addr.sa, sizeof_sockaddr(&cfg.src_addr)) <
        0) {
        P_LOG_ERR("bind(): %s", strerror(errno));
        goto cleanup;
    }

    /* Start listening */
    if (listen(listen_sock, LISTEN_BACKLOG) < 0) {
        P_LOG_ERR("listen(): %s", strerror(errno));
        goto cleanup;
    }

    set_nonblock(listen_sock);

    /* Create epoll instance */
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

    /* Add listening socket to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN;
#ifdef EPOLLEXCLUSIVE
    /* Reduce thundering herd with multiple processes listening on the same socket */
    ev.events |= EPOLLEXCLUSIVE;
#endif
    ev.data.ptr = &magic_listener;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_sock, &ev) < 0) {
        P_LOG_ERR("epoll_ctl(ADD, listener): %s", strerror(errno));
        goto cleanup;
    }

    P_LOG_INFO("TCP forwarding started: %s -> %s",
               sockaddr_to_string(&cfg.src_addr),
               sockaddr_to_string(&cfg.dst_addr));
    if (cfg.max_connections > 0) {
        P_LOG_INFO("Connection limits: total=%d, per-IP=%d",
                   cfg.max_connections, cfg.max_per_ip);
    }
    P_LOG_INFO("Connection pool size: %d, buffer size: %d bytes",
               g_conn_pool_capacity, g_userbuf_cap_runtime);

    /* Run main event loop */
    rc = proxy_loop(epfd, listen_sock, &cfg);

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
    destroy_conn_pool();
    destroy_conn_limiter();
    destroy_stats();
    closelog();

    return rc;
}
