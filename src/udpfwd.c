/**
 * @file udpfwd.c
 * @brief High-performance UDP port forwarding proxy with connection tracking
 *
 * This implementation provides:
 * - Thread-safe connection pooling and hash table management
 * - Adaptive batch processing for optimal throughput
 * - Rate limiting and DoS protection
 * - Zero-copy forwarding using recvmmsg/sendmmsg on Linux
 * - Fine-grained locking for scalability
 * - Comprehensive security validation
 */

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
#include <pthread.h>
#include <stdatomic.h>

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

/* Performance and security constants */
#define DEFAULT_CONN_TIMEOUT_SEC 60
#define DEFAULT_HASH_TABLE_SIZE 65537  /* Larger prime number for better distribution */
#define MIN_BATCH_SIZE 64              /* Increased from 4 for better performance */
#define MAX_BATCH_SIZE UDP_PROXY_BATCH_SZ
#define BATCH_ADJUST_INTERVAL_SEC 30   /* Reduced frequency from 5 to 30 seconds */
#define RATE_LIMIT_WINDOW_SEC 1

/* Hash function constants */
#define FNV_PRIME_32 0x01000193
#define FNV_OFFSET_32 0x811c9dc5
#define GOLDEN_RATIO_32 0x9e3779b9

/* Adaptive batch sizing thresholds - less aggressive */
#define BATCH_HIGH_UTILIZATION_RATIO 0.9  /* Increased from 0.8 */
#define BATCH_LOW_UTILIZATION_RATIO 0.1   /* Decreased from 0.3 */
#define BATCH_INCREASE_FACTOR 1.2         /* Reduced from 1.5 */
#define BATCH_DECREASE_FACTOR 0.8         /* Reduced from 0.67 */

#define BATCH_HASH_SIZE 4096

/* Performance optimization flags */
#ifndef DISABLE_ADAPTIVE_BATCHING
#define ENABLE_ADAPTIVE_BATCHING 1
#else
#define ENABLE_ADAPTIVE_BATCHING 0
#endif

#ifndef DISABLE_RATE_LIMITING
#define ENABLE_RATE_LIMITING 1
#else
#define ENABLE_RATE_LIMITING 0
#endif

#ifndef DISABLE_PACKET_VALIDATION
#define ENABLE_PACKET_VALIDATION 1
#else
#define ENABLE_PACKET_VALIDATION 0
#endif

#ifndef DISABLE_FINE_GRAINED_LOCKS
#define ENABLE_FINE_GRAINED_LOCKS 1
#else
#define ENABLE_FINE_GRAINED_LOCKS 0
#endif

#ifndef DISABLE_LRU_LOCKS
#define ENABLE_LRU_LOCKS 1
#else
#define ENABLE_LRU_LOCKS 0
#endif

#ifndef DISABLE_BACKPRESSURE_QUEUE
#define ENABLE_BACKPRESSURE_QUEUE 0  /* Disabled by default for better performance */
#else
#define ENABLE_BACKPRESSURE_QUEUE 0
#endif

/* Batch processing limits - decouple max batches from per-batch message limit */
#define MAX_CONCURRENT_BATCHES 1024  /* Maximum number of concurrent server sockets in one batch cycle */

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))
#define MAX_EVENTS 1024

/* Socket buffer size */
#ifndef UDP_PROXY_SOCKBUF_CAP
#define UDP_PROXY_SOCKBUF_CAP (2 * 1024 * 1024)  /* Increased from 256KB to 2MB for better throughput */
#endif

/* Linux-specific batching parameters */
#ifdef __linux__
#ifndef UDP_PROXY_BATCH_SZ
#define UDP_PROXY_BATCH_SZ 512  /* Increased from 16 for much better performance */
#endif
#ifndef UDP_PROXY_DGRAM_CAP
/* Max safe UDP payload size: 65535 - 8 (UDP header) - 20 (IPv4 header) */
#define UDP_PROXY_DGRAM_CAP 65507
#endif
#endif



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
    /* Security limits */
    unsigned max_connections_per_ip;
    unsigned max_packets_per_second;
    unsigned max_bytes_per_second;
    size_t max_packet_size;
    size_t min_packet_size;
};

/**
 * @brief Rate limiting structure for DoS protection
 */
#define RATE_LIMIT_HASH_SIZE 1024
struct rate_limit_entry {
    union sockaddr_inx addr;
    uint64_t packet_count;
    uint64_t byte_count;
    time_t window_start;
    unsigned connection_count;
};

struct rate_limiter {
    struct rate_limit_entry entries[RATE_LIMIT_HASH_SIZE];
    pthread_mutex_t lock;
    unsigned max_pps;
    unsigned max_bps;
    unsigned max_per_ip;
};

/**
 * @brief Thread-safe connection pool for UDP proxy connections
 *
 * Provides atomic allocation and deallocation of connection objects
 * with mutex protection for thread safety.
 */
struct conn_pool {
    struct proxy_conn *connections;  /**< Pre-allocated connection array */
    struct proxy_conn *freelist;     /**< Linked list of available connections */
    int capacity;                    /**< Total pool capacity */
    atomic_int used_count;           /**< Currently allocated connections (atomic) */
    int high_water_mark;             /**< Peak usage for monitoring */
    pthread_mutex_t lock;            /**< Thread safety mutex */
    pthread_cond_t available;        /**< Condition variable for blocking allocation */
};

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Global Variables */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/* Connection hash table - protected by fine-grained locks */
static struct list_head *conn_tbl_hbase;
static unsigned g_conn_tbl_hash_size;
static atomic_uint conn_tbl_len;                /**< Atomic connection count */

/* Hash table bucket locks for fine-grained locking */
static pthread_spinlock_t *conn_tbl_locks;

/* Connection pool */
static struct conn_pool g_conn_pool;

/* Runtime tunables (overridable via CLI) - read-only after initialization */
static int g_sockbuf_cap_runtime = UDP_PROXY_SOCKBUF_CAP;
static int g_conn_pool_capacity = UDP_PROXY_MAX_CONNS;
#ifdef __linux__
static int g_batch_sz_runtime = UDP_PROXY_BATCH_SZ;

/* Dynamic batch sizing */
struct adaptive_batch {
    int current_size;
    int min_size;
    int max_size;
    _Atomic uint64_t total_packets;
    _Atomic uint64_t total_batches;
    time_t last_adjust;
    pthread_mutex_t lock;
};

static struct adaptive_batch g_adaptive_batch = {
    .current_size = UDP_PROXY_BATCH_SZ,  /* Start with full batch size */
    .min_size = MIN_BATCH_SIZE,
    .max_size = MAX_BATCH_SIZE,
    .total_packets = 0,
    .total_batches = 0,
    .last_adjust = 0,
    .lock = PTHREAD_MUTEX_INITIALIZER
};
#endif

/* Global LRU list for O(1) oldest selection - protected by mutex */
static LIST_HEAD(g_lru_list);
static pthread_mutex_t g_lru_lock = PTHREAD_MUTEX_INITIALIZER;

/* Segmented LRU update state to avoid O(N) scans */
static struct {
    unsigned next_bucket;           /* Next bucket to scan in segmented update */
    time_t last_segment_update;     /* Last time we did a segment update */
    unsigned buckets_per_segment;   /* How many buckets to process per segment */
} g_lru_segment_state = {0, 0, 64};

/* Cached current timestamp (monotonic seconds on Linux) for hot paths */
static atomic_long g_now_ts;                    /**< Atomic timestamp cache */

/* Function pointer to compute bucket index from a 32-bit hash */
static unsigned int (*bucket_index_fun)(const union sockaddr_inx *);

/* Stats: batch overflow immediate-sends (client->server) - atomic counters */
static _Atomic uint64_t g_stat_c2s_batch_socket_overflow;
static _Atomic uint64_t g_stat_c2s_batch_entry_overflow;

/* Additional performance statistics */
static _Atomic uint64_t g_stat_hash_collisions;
static _Atomic uint64_t g_stat_lru_immediate_updates;
static _Atomic uint64_t g_stat_lru_deferred_updates;

/* Signal-safe shutdown flag */
static volatile sig_atomic_t g_shutdown_requested = 0;

/* Global rate limiter for security */
static struct rate_limiter g_rate_limiter;

#if ENABLE_BACKPRESSURE_QUEUE
/* Simple backpressure queue for handling EAGAIN */
#define BACKPRESSURE_QUEUE_SIZE 1024
struct backpressure_entry {
    int sock;
    char data[UDP_PROXY_DGRAM_CAP];
    size_t len;
    union sockaddr_inx dest_addr;
    socklen_t dest_len;
};

struct backpressure_queue {
    struct backpressure_entry entries[BACKPRESSURE_QUEUE_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t lock;
};

static struct backpressure_queue g_backpressure_queue;
#endif /* ENABLE_BACKPRESSURE_QUEUE */

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
/* Rate Limiting and Security Functions */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/* Simple hash function for IP addresses */
static uint32_t addr_hash_for_rate_limit(const union sockaddr_inx *addr) {
    if (addr->sa.sa_family == AF_INET) {
        return ntohl(addr->sin.sin_addr.s_addr) % RATE_LIMIT_HASH_SIZE;
    } else if (addr->sa.sa_family == AF_INET6) {
        const uint32_t *p = (const uint32_t *)&addr->sin6.sin6_addr;
        return (ntohl(p[0]) ^ ntohl(p[1]) ^ ntohl(p[2]) ^ ntohl(p[3])) % RATE_LIMIT_HASH_SIZE;
    }
    return 0;
}

/* Initialize rate limiter */
static int init_rate_limiter(unsigned max_pps, unsigned max_bps, unsigned max_per_ip) {
    memset(&g_rate_limiter, 0, sizeof(g_rate_limiter));

    if (pthread_mutex_init(&g_rate_limiter.lock, NULL) != 0) {
        P_LOG_ERR("Failed to initialize rate limiter mutex");
        return -1;
    }

    g_rate_limiter.max_pps = max_pps;
    g_rate_limiter.max_bps = max_bps;
    g_rate_limiter.max_per_ip = max_per_ip;

    P_LOG_INFO("Rate limiter initialized: max_pps=%u, max_bps=%u, max_per_ip=%u",
               max_pps, max_bps, max_per_ip);
    return 0;
}

/* Destroy rate limiter */
static void destroy_rate_limiter(void) {
    pthread_mutex_destroy(&g_rate_limiter.lock);
    memset(&g_rate_limiter, 0, sizeof(g_rate_limiter));
}

/* Check if packet is allowed by rate limiter */
static bool check_rate_limit(const union sockaddr_inx *addr, size_t packet_size) {
#if !ENABLE_RATE_LIMITING
    (void)addr;
    (void)packet_size;
    return true; /* Rate limiting disabled at compile time */
#else
    if (g_rate_limiter.max_pps == 0 && g_rate_limiter.max_bps == 0 &&
        g_rate_limiter.max_per_ip == 0) {
        return true; /* No limits configured */
    }

    pthread_mutex_lock(&g_rate_limiter.lock);

    uint32_t hash = addr_hash_for_rate_limit(addr);
    struct rate_limit_entry *entry = &g_rate_limiter.entries[hash];
    /* Use cached timestamp to avoid frequent time() syscalls */
    time_t now = atomic_load(&g_now_ts);
    if (now == 0) {
        now = time(NULL);
    }

    /* Check if this is the same IP or a hash collision */
    if (entry->packet_count > 0 && !is_sockaddr_inx_equal(&entry->addr, addr)) {
        /* Hash collision - reset entry for new IP */
        memset(entry, 0, sizeof(*entry));
    }

    /* Initialize or reset time window */
    if (entry->packet_count == 0 || now - entry->window_start >= 1) {
        entry->addr = *addr;
        entry->packet_count = 1;
        entry->byte_count = packet_size;
        entry->window_start = now;
        pthread_mutex_unlock(&g_rate_limiter.lock);
        return true;
    }

    /* Check packet rate limit */
    if (g_rate_limiter.max_pps > 0 && entry->packet_count >= g_rate_limiter.max_pps) {
        pthread_mutex_unlock(&g_rate_limiter.lock);
        P_LOG_WARN("Packet rate limit exceeded for %s (%lu pps)",
                   sockaddr_to_string(addr), entry->packet_count);
        return false;
    }

    /* Check byte rate limit */
    if (g_rate_limiter.max_bps > 0 && entry->byte_count + packet_size > g_rate_limiter.max_bps) {
        pthread_mutex_unlock(&g_rate_limiter.lock);
        P_LOG_WARN("Byte rate limit exceeded for %s (%lu bps)",
                   sockaddr_to_string(addr), entry->byte_count);
        return false;
    }

    /* Check per-IP connection limit */
    if (g_rate_limiter.max_per_ip > 0 && entry->connection_count >= g_rate_limiter.max_per_ip) {
        pthread_mutex_unlock(&g_rate_limiter.lock);
        P_LOG_WARN("Per-IP connection limit exceeded for %s (%u connections)",
                   sockaddr_to_string(addr), entry->connection_count);
        return false;
    }

    /* Update counters */
    entry->packet_count++;
    entry->byte_count += packet_size;

    pthread_mutex_unlock(&g_rate_limiter.lock);
    return true;
#endif
}

/* Validate packet size and content */
static bool validate_packet(const char *data, size_t len, const union sockaddr_inx *src) {
#if !ENABLE_PACKET_VALIDATION
    (void)data;
    (void)len;
    (void)src;
    return true; /* Packet validation disabled at compile time */
#else
    /* Check packet size limits */
    if (len < 1 || len > UDP_PROXY_DGRAM_CAP) {
        P_LOG_WARN("Invalid packet size %zu from %s (min=1, max=%d)",
                   len, sockaddr_to_string(src), UDP_PROXY_DGRAM_CAP);
        return false;
    }

    /* Additional validation can be added here:
     * - Check for suspicious patterns
     * - Validate protocol headers
     * - Check for amplification attack patterns
     */

    (void)data; /* Suppress unused parameter warning for now */
    return true;
#endif
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Backpressure Queue Management */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

#if ENABLE_BACKPRESSURE_QUEUE
/* Initialize backpressure queue */
static int init_backpressure_queue(void) {
    memset(&g_backpressure_queue, 0, sizeof(g_backpressure_queue));
    if (pthread_mutex_init(&g_backpressure_queue.lock, NULL) != 0) {
        P_LOG_ERR("Failed to initialize backpressure queue mutex");
        return -1;
    }
    return 0;
}

/* Destroy backpressure queue */
static void destroy_backpressure_queue(void) {
    pthread_mutex_destroy(&g_backpressure_queue.lock);
    memset(&g_backpressure_queue, 0, sizeof(g_backpressure_queue));
}

/* Add entry to backpressure queue */
static bool enqueue_backpressure(int sock, const char *data, size_t len,
                                 const union sockaddr_inx *dest_addr, socklen_t dest_len) {
    pthread_mutex_lock(&g_backpressure_queue.lock);

    if (g_backpressure_queue.count >= BACKPRESSURE_QUEUE_SIZE) {
        pthread_mutex_unlock(&g_backpressure_queue.lock);
        return false; /* Queue full */
    }

    struct backpressure_entry *entry = &g_backpressure_queue.entries[g_backpressure_queue.tail];
    entry->sock = sock;
    memcpy(entry->data, data, len);
    entry->len = len;
    if (dest_addr) {
        entry->dest_addr = *dest_addr;
        entry->dest_len = dest_len;
    } else {
        entry->dest_len = 0;
    }

    g_backpressure_queue.tail = (g_backpressure_queue.tail + 1) % BACKPRESSURE_QUEUE_SIZE;
    g_backpressure_queue.count++;

    pthread_mutex_unlock(&g_backpressure_queue.lock);
    return true;
}

/* Process backpressure queue */
static void process_backpressure_queue(void) {
    pthread_mutex_lock(&g_backpressure_queue.lock);

    while (g_backpressure_queue.count > 0) {
        struct backpressure_entry *entry = &g_backpressure_queue.entries[g_backpressure_queue.head];

        ssize_t sent;
        if (entry->dest_len > 0) {
            /* UDP sendto */
            sent = sendto(entry->sock, entry->data, entry->len, 0,
                         (struct sockaddr *)&entry->dest_addr, entry->dest_len);
        } else {
            /* Connected UDP send */
            sent = send(entry->sock, entry->data, entry->len, 0);
        }

        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Still blocked, stop processing */
                break;
            }
            /* Other error, drop this packet and continue */
        }

        /* Move to next entry */
        g_backpressure_queue.head = (g_backpressure_queue.head + 1) % BACKPRESSURE_QUEUE_SIZE;
        g_backpressure_queue.count--;
    }

    pthread_mutex_unlock(&g_backpressure_queue.lock);
}
#endif /* ENABLE_BACKPRESSURE_QUEUE */

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Performance Optimization Functions */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

#ifdef __linux__
/* Adjust batch size based on recent performance */
static void adjust_batch_size(void) {
    pthread_mutex_lock(&g_adaptive_batch.lock);

    time_t now = time(NULL);
    if (now - g_adaptive_batch.last_adjust < BATCH_ADJUST_INTERVAL_SEC) {
        /* Don't adjust too frequently */
        pthread_mutex_unlock(&g_adaptive_batch.lock);
        return;
    }

    uint64_t packets = atomic_load(&g_adaptive_batch.total_packets);
    uint64_t batches = atomic_load(&g_adaptive_batch.total_batches);

    if (batches > 0) {
        double avg_batch_size = (double)packets / batches;

        if (avg_batch_size > g_adaptive_batch.current_size * BATCH_HIGH_UTILIZATION_RATIO) {
            /* High utilization - increase batch size */
            if (g_adaptive_batch.current_size < g_adaptive_batch.max_size) {
                g_adaptive_batch.current_size =
                    (int)(g_adaptive_batch.current_size * BATCH_INCREASE_FACTOR);
                if (g_adaptive_batch.current_size > g_adaptive_batch.max_size) {
                    g_adaptive_batch.current_size = g_adaptive_batch.max_size;
                }
                P_LOG_INFO("Increased batch size to %d (avg=%.1f)",
                           g_adaptive_batch.current_size, avg_batch_size);
            }
        } else if (avg_batch_size < g_adaptive_batch.current_size * BATCH_LOW_UTILIZATION_RATIO) {
            /* Low utilization - decrease batch size */
            if (g_adaptive_batch.current_size > g_adaptive_batch.min_size) {
                g_adaptive_batch.current_size =
                    (int)(g_adaptive_batch.current_size * BATCH_DECREASE_FACTOR);
                if (g_adaptive_batch.current_size < g_adaptive_batch.min_size) {
                    g_adaptive_batch.current_size = g_adaptive_batch.min_size;
                }
                P_LOG_INFO("Decreased batch size to %d (avg=%.1f)",
                           g_adaptive_batch.current_size, avg_batch_size);
            }
        }
    }

    /* Reset counters */
    atomic_store(&g_adaptive_batch.total_packets, 0);
    atomic_store(&g_adaptive_batch.total_batches, 0);
    g_adaptive_batch.last_adjust = now;

    pthread_mutex_unlock(&g_adaptive_batch.lock);
}

/* Get current optimal batch size */
static int get_optimal_batch_size(void) {
#if ENABLE_ADAPTIVE_BATCHING
    return g_adaptive_batch.current_size;
#else
    return UDP_PROXY_BATCH_SZ; /* Use fixed batch size for maximum performance */
#endif
}

/* Record batch statistics */
static void record_batch_stats(int packets_in_batch) {
#if ENABLE_ADAPTIVE_BATCHING
    atomic_fetch_add(&g_adaptive_batch.total_packets, packets_in_batch);
    atomic_fetch_add(&g_adaptive_batch.total_batches, 1);
#else
    (void)packets_in_batch; /* Suppress unused parameter warning */
#endif
}
#endif

/* Improved hash function with better distribution */
static uint32_t improved_hash_addr(const union sockaddr_inx *sa) {
    uint32_t hash = 0;

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
    atomic_store(&g_conn_pool.used_count, 0);
    g_conn_pool.high_water_mark = 0;
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
        pthread_mutex_destroy(&g_conn_pool.lock);
        pthread_cond_destroy(&g_conn_pool.available);
        free(g_conn_pool.connections);
        g_conn_pool.connections = NULL;
        g_conn_pool.freelist = NULL;
        g_conn_pool.capacity = 0;
        atomic_store(&g_conn_pool.used_count, 0);
        g_conn_pool.high_water_mark = 0;
        P_LOG_INFO("Connection pool destroyed.");
    }
}

static struct proxy_conn *alloc_proxy_conn(void) {
    struct proxy_conn *conn;

    pthread_mutex_lock(&g_conn_pool.lock);

    if (!g_conn_pool.freelist) {
        pthread_mutex_unlock(&g_conn_pool.lock);
        P_LOG_WARN("Connection pool exhausted!");
        return NULL;
    }

    conn = g_conn_pool.freelist;
    g_conn_pool.freelist = conn->next;

    int used = atomic_fetch_add(&g_conn_pool.used_count, 1) + 1;
    if (used > g_conn_pool.high_water_mark) {
        g_conn_pool.high_water_mark = used;
    }

    pthread_mutex_unlock(&g_conn_pool.lock);

    assert(used <= g_conn_pool.capacity);
    memset(conn, 0, sizeof(*conn));
    return conn;
}

static void release_proxy_conn_to_pool(struct proxy_conn *conn) {
    if (!conn) {
        P_LOG_WARN("Attempted to release NULL connection");
        return;
    }

    pthread_mutex_lock(&g_conn_pool.lock);

    conn->next = g_conn_pool.freelist;
    g_conn_pool.freelist = conn;

    int used = atomic_fetch_sub(&g_conn_pool.used_count, 1) - 1;
    assert(used >= 0);

    pthread_cond_signal(&g_conn_pool.available);
    pthread_mutex_unlock(&g_conn_pool.lock);
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



static uint32_t hash_addr(const union sockaddr_inx *a) {
    /* Use the improved hash function for better distribution */
    return improved_hash_addr(a);
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Connection Management */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static inline void touch_proxy_conn(struct proxy_conn *conn) {
    /* Update timestamp */
    time_t snap = atomic_load(&g_now_ts);
    time_t new_time = snap ? snap : monotonic_seconds();
    conn->last_active = new_time;

    /* Try immediate LRU update with trylock to avoid blocking hot path */
#if ENABLE_LRU_LOCKS
    static __thread time_t last_lru_attempt = 0;

    /* Throttle LRU updates per connection - at most once every 5 seconds */
    if (new_time - last_lru_attempt >= 5) {
        if (pthread_mutex_trylock(&g_lru_lock) == 0) {
            /* Successfully got lock - do immediate LRU update */
            if (!conn->needs_lru_update) {
                list_del(&conn->lru);
                list_add_tail(&conn->lru, &g_lru_list);
                atomic_fetch_add(&g_stat_lru_immediate_updates, 1);
            }
            pthread_mutex_unlock(&g_lru_lock);
            last_lru_attempt = new_time;
        } else {
            /* Lock contention - mark for batch update */
            conn->needs_lru_update = true;
            atomic_fetch_add(&g_stat_lru_deferred_updates, 1);
        }
    } else {
        /* Throttled - mark for batch update */
        conn->needs_lru_update = true;
    }
#else
    conn->needs_lru_update = true;
#endif
}

/* Segmented LRU update to avoid O(N) scans - process only a subset of buckets each time */
static void segmented_update_lru(void) {
#if ENABLE_LRU_LOCKS
    time_t now = time(NULL);

    /* Only update segments every 1 second to reduce overhead */
    if (now - g_lru_segment_state.last_segment_update < 1) {
        return;
    }
    g_lru_segment_state.last_segment_update = now;

    /* Adjust buckets per segment based on total hash table size */
    if (g_lru_segment_state.buckets_per_segment == 0) {
        g_lru_segment_state.buckets_per_segment = (g_conn_tbl_hash_size / 32) + 1;
        if (g_lru_segment_state.buckets_per_segment > 256) {
            g_lru_segment_state.buckets_per_segment = 256;
        }
    }

    pthread_mutex_lock(&g_lru_lock);

    /* Process only a segment of buckets to spread the work over time */
    unsigned start_bucket = g_lru_segment_state.next_bucket;
    unsigned end_bucket = start_bucket + g_lru_segment_state.buckets_per_segment;
    if (end_bucket > g_conn_tbl_hash_size) {
        end_bucket = g_conn_tbl_hash_size;
    }

    for (unsigned i = start_bucket; i < end_bucket; i++) {
        struct proxy_conn *conn, *tmp;
#if ENABLE_FINE_GRAINED_LOCKS
        pthread_spin_lock(&conn_tbl_locks[i]);
#endif
        list_for_each_entry_safe(conn, tmp, &conn_tbl_hbase[i], list) {
            if (conn->needs_lru_update) {
                list_del(&conn->lru);
                list_add_tail(&conn->lru, &g_lru_list);
                conn->needs_lru_update = false;
            }
        }
#if ENABLE_FINE_GRAINED_LOCKS
        pthread_spin_unlock(&conn_tbl_locks[i]);
#endif
    }

    /* Update next segment start position */
    g_lru_segment_state.next_bucket = end_bucket;
    if (g_lru_segment_state.next_bucket >= g_conn_tbl_hash_size) {
        g_lru_segment_state.next_bucket = 0; /* Wrap around */
    }

    pthread_mutex_unlock(&g_lru_lock);
#endif
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

    /* Check rate limits before creating new connection */
    if (!check_rate_limit(cli_addr, 0)) {
        /* Rate limit exceeded - drop the connection request */
        return NULL;
    }

    /* Enforce connection capacity - use atomic load for thread safety */
    unsigned current_conn_count = atomic_load(&conn_tbl_len);
    if (current_conn_count >= (unsigned)g_conn_pool.capacity) {
        /* First, try to recycle any timed-out connections */
        proxy_conn_walk_continue(cfg, current_conn_count, epfd);

        /* Reload count after cleanup */
        current_conn_count = atomic_load(&conn_tbl_len);
        if (current_conn_count >= (unsigned)g_conn_pool.capacity) {
            proxy_conn_evict_one(epfd);
        }

        /* Final check after eviction */
        current_conn_count = atomic_load(&conn_tbl_len);
        if (current_conn_count >= (unsigned)g_conn_pool.capacity) {
            inet_ntop(cli_addr->sa.sa_family, addr_of_sockaddr(cli_addr),
                      s_addr, sizeof(s_addr));
            P_LOG_WARN("Conn table full (%u), dropping %s:%d", current_conn_count,
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

    /* Add to hash table with bucket lock */
    unsigned bucket = bucket_index_fun(cli_addr);
#if ENABLE_FINE_GRAINED_LOCKS
    pthread_spin_lock(&conn_tbl_locks[bucket]);
#endif
    list_add_tail(&conn->list, chain);
#if ENABLE_FINE_GRAINED_LOCKS
    pthread_spin_unlock(&conn_tbl_locks[bucket]);
#endif

    /* Add to LRU list with global lock */
#if ENABLE_LRU_LOCKS
    pthread_mutex_lock(&g_lru_lock);
#endif
    list_add_tail(&conn->lru, &g_lru_list);
#if ENABLE_LRU_LOCKS
    pthread_mutex_unlock(&g_lru_lock);
#endif

    /* Update connection count atomically */
    unsigned new_count = atomic_fetch_add(&conn_tbl_len, 1) + 1;

    /* Log new connections at DEBUG level to reduce overhead in high-connection scenarios */
    /* Only log every 100th connection to avoid spam */
    static _Atomic unsigned log_counter = 0;
    unsigned current_count = atomic_fetch_add(&log_counter, 1);
    if ((current_count % 100) == 0) {
        inet_ntop(cli_addr->sa.sa_family, addr_of_sockaddr(cli_addr), s_addr,
                  sizeof(s_addr));
        P_LOG_INFO("New UDP session [%s]:%d, total %u (logging every 100th)", s_addr,
                   ntohs(*port_of_sockaddr(cli_addr)), new_count);
    }

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
    if (!conn) {
        P_LOG_WARN("Attempted to release NULL connection");
        return;
    }

    /* Get bucket index for fine-grained locking */
    unsigned bucket = bucket_index_fun(&conn->cli_addr);

    /* Remove from hash table with bucket lock */
#if ENABLE_FINE_GRAINED_LOCKS
    pthread_spin_lock(&conn_tbl_locks[bucket]);
#endif
    list_del(&conn->list);
#if ENABLE_FINE_GRAINED_LOCKS
    pthread_spin_unlock(&conn_tbl_locks[bucket]);
#endif

    /* Update global connection count atomically */
    atomic_fetch_sub(&conn_tbl_len, 1);

    /* Remove from LRU list with global LRU lock */
#if ENABLE_LRU_LOCKS
    pthread_mutex_lock(&g_lru_lock);
#endif
    list_del(&conn->lru);
#if ENABLE_LRU_LOCKS
    pthread_mutex_unlock(&g_lru_lock);
#endif

    /* Remove from epoll and close socket */
    if (conn->svr_sock >= 0) {
        if (epoll_ctl(epfd, EPOLL_CTL_DEL, conn->svr_sock, NULL) < 0 &&
            errno != EBADF && errno != ENOENT) {
            P_LOG_WARN("epoll_ctl(DEL, svr_sock=%d): %s", conn->svr_sock,
                       strerror(errno));
        }
        if (safe_close(conn->svr_sock) < 0) {
            P_LOG_WARN("close(svr_sock=%d): %s", conn->svr_sock, strerror(errno));
        }
        conn->svr_sock = -1;
    }

    release_proxy_conn_to_pool(conn);
}

static void proxy_conn_walk_continue(const struct config *cfg,
                                     unsigned walk_max, int epfd) {
    unsigned walked = 0;
    time_t now = atomic_load(&g_now_ts);
    if (now == 0) {
        now = monotonic_seconds();
    }

    pthread_mutex_lock(&g_lru_lock);
    if (list_empty(&g_lru_list)) {
        pthread_mutex_unlock(&g_lru_lock);
        return;
    }

    while (walked < walk_max && !list_empty(&g_lru_list)) {
        struct proxy_conn *oldest = list_first_entry(&g_lru_list, struct proxy_conn, lru);

        long diff = (long)(now - oldest->last_active);
        if (diff < 0)
            diff = 0;
        if ((unsigned)diff <= cfg->proxy_conn_timeo) {
            break; /* oldest not expired -> none later are expired */
        }

        /* Save address info before releasing */
        union sockaddr_inx addr = oldest->cli_addr;
        char s_addr[50] = "";

        /* Unlock before calling release_proxy_conn to avoid deadlock */
        pthread_mutex_unlock(&g_lru_lock);

        release_proxy_conn(oldest, epfd);
        inet_ntop(addr.sa.sa_family, addr_of_sockaddr(&addr), s_addr,
                  sizeof(s_addr));
        P_LOG_INFO("Recycled %s:%d [%u]", s_addr,
                   ntohs(*port_of_sockaddr(&addr)), atomic_load(&conn_tbl_len));

        walked++;

        /* Re-acquire lock for next iteration */
        pthread_mutex_lock(&g_lru_lock);
    }
    pthread_mutex_unlock(&g_lru_lock);
}

/* Evict the least recently active connection (LRU-ish across all buckets) */
static bool proxy_conn_evict_one(int epfd) {
    pthread_mutex_lock(&g_lru_lock);
    if (list_empty(&g_lru_list)) {
        pthread_mutex_unlock(&g_lru_lock);
        return false;
    }

    struct proxy_conn *oldest = list_first_entry(&g_lru_list, struct proxy_conn, lru);
    union sockaddr_inx addr = oldest->cli_addr;
    char s_addr[50] = "";

    /* Unlock before calling release_proxy_conn to avoid deadlock */
    pthread_mutex_unlock(&g_lru_lock);

    release_proxy_conn(oldest, epfd);
    inet_ntop(addr.sa.sa_family, addr_of_sockaddr(&addr), s_addr,
              sizeof(s_addr));
    P_LOG_WARN("Evicted LRU %s:%d [%u]", s_addr,
               ntohs(*port_of_sockaddr(&addr)), atomic_load(&conn_tbl_len));

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
            } batches[MAX_CONCURRENT_BATCHES];
            int num_batches = 0;

            /* Hash table for O(1) batch lookup instead of O(n) linear scan */
            int batch_hash[BATCH_HASH_SIZE];
            memset(batch_hash, -1, sizeof(batch_hash));

            for (int i = 0; i < n; i++) {
                union sockaddr_inx *sa =
                    (union sockaddr_inx *)c_msgs[i].msg_hdr.msg_name;

                /* Validate packet size and rate limits */
                size_t packet_len = c_msgs[i].msg_len;
                if (!validate_packet(c_bufs[i], packet_len, sa)) {
                    continue; /* Drop invalid packet */
                }
                if (!check_rate_limit(sa, packet_len)) {
                    continue; /* Drop rate-limited packet */
                }

                if (!(conn = proxy_conn_get_or_create(cfg, sa, epfd)))
                    continue;
                touch_proxy_conn(conn);

                /* O(1) batch lookup using hash table with linear probing for collision resolution */
                int hash_key = conn->svr_sock % BATCH_HASH_SIZE;
                int batch_idx = batch_hash[hash_key];
                int probe_count = 0;

                /* Linear probing to handle hash collisions */
                while (batch_idx != -1 && batches[batch_idx].sock != conn->svr_sock &&
                       probe_count < BATCH_HASH_SIZE) {
                    hash_key = (hash_key + 1) % BATCH_HASH_SIZE;
                    batch_idx = batch_hash[hash_key];
                    probe_count++;
                }

                /* Track hash collision statistics */
                if (probe_count > 0) {
                    atomic_fetch_add(&g_stat_hash_collisions, probe_count);
                }

                /* If we found a matching socket or an empty slot */
                if (batch_idx == -1) {
                    /* Check if we can create a new batch */
                    if (num_batches >= MAX_CONCURRENT_BATCHES) {
                        atomic_fetch_add(&g_stat_c2s_batch_socket_overflow, 1);
                        ssize_t wr = send(conn->svr_sock, c_bufs[i], c_msgs[i].msg_len, 0);
                        if (wr < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                            P_LOG_WARN("send(server, overflow): %s", strerror(errno));
                        }
                        continue;
                    }
                    batch_idx = num_batches++;
                    batches[batch_idx].sock = conn->svr_sock;
                    batches[batch_idx].count = 0;
                    /* Update hash table for O(1) future lookups */
                    batch_hash[hash_key] = batch_idx;
                }
                if (batches[batch_idx].count >= get_optimal_batch_size()) {
                    atomic_fetch_add(&g_stat_c2s_batch_entry_overflow, 1);
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
                            /* Socket buffer full - rely on kernel buffering, don't queue in userspace */
                            /* This is more efficient than copying data to userspace queues */
                            atomic_fetch_add(&g_stat_c2s_batch_socket_overflow, remaining);
                            break;
                        }
                        P_LOG_WARN("sendmmsg(server) failed: %s, attempted=%d, remaining=%d",
                                   strerror(errno), remaining, remaining);
                        break;
                    }
                    if (sent == 0) {
                        /* Avoid tight loop if nothing progressed */
                        P_LOG_WARN("sendmmsg(server) sent 0 packets, remaining=%d", remaining);
                        break;
                    }
                    if (sent < remaining) {
                        /* Partial send - log for debugging */
                        P_LOG_INFO("sendmmsg(server) partial: sent=%d, remaining=%d",
                                   sent, remaining);
                    }
                    remaining -= sent;
                    msgp += sent;
                } while (remaining > 0);
            }

            /* Record batch statistics for adaptive sizing */
            record_batch_stats(n);

            /* If we read fewer than the batch, likely drained; stop early */
            if (n < ncap)
                break;
        }

        /* Periodically adjust batch size based on performance */
#if ENABLE_ADAPTIVE_BATCHING
        static time_t last_adjust_check = 0;
        time_t now = time(NULL);
        if (now - last_adjust_check >= BATCH_ADJUST_INTERVAL_SEC) {
            adjust_batch_size();
            last_adjust_check = now;
        }
#endif

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

    /* Validate packet and check rate limits */
    if (!validate_packet(buffer, (size_t)r, &cli_addr)) {
        return; /* Drop invalid packet */
    }
    if (!check_rate_limit(&cli_addr, (size_t)r)) {
        return; /* Drop rate-limited packet */
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
    /* Use thread-local storage to avoid static buffer race conditions */
    static __thread char tls_bufs[UDP_PROXY_BATCH_SZ][UDP_PROXY_DGRAM_CAP];
    char (*bufs)[UDP_PROXY_DGRAM_CAP] = tls_bufs;

    int iterations = 0;
    const int max_iterations = 64; /* fairness cap per event */
    const int ncap =
        g_batch_sz_runtime > 0 ? g_batch_sz_runtime : UDP_PROXY_BATCH_SZ;

    for (; iterations < max_iterations; iterations++) {
        /* Only initialize what we need instead of expensive full memset */
        for (int i = 0; i < ncap; i++) {
            iovs[i].iov_base = bufs[i];
            iovs[i].iov_len = UDP_PROXY_DGRAM_CAP;
            msgs[i].msg_hdr.msg_iov = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            /* For recvmmsg on connected UDP, msg_name must be NULL */
            msgs[i].msg_hdr.msg_name = NULL;
            msgs[i].msg_hdr.msg_namelen = 0;
            msgs[i].msg_hdr.msg_control = NULL;
            msgs[i].msg_hdr.msg_controllen = 0;
            msgs[i].msg_hdr.msg_flags = 0;
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
                P_LOG_WARN("sendmmsg(client) failed: %s, attempted=%d, remaining=%d",
                           strerror(errno), remaining, remaining);
                break;
            }
            if (sent == 0) {
                /* Avoid tight loop if nothing progressed */
                P_LOG_WARN("sendmmsg(client) sent 0 packets, remaining=%d", remaining);
                break;
            }
            if (sent < remaining) {
                /* Partial send - log for debugging */
                P_LOG_INFO("sendmmsg(client) partial: sent=%d, remaining=%d",
                           sent, remaining);
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
    P_LOG_INFO("  -H <size>        hash table size (default: %d, recommend >= max_conns)",
               DEFAULT_HASH_TABLE_SIZE);
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
    cfg.proxy_conn_timeo = DEFAULT_CONN_TIMEOUT_SEC;
    cfg.conn_tbl_hash_size = DEFAULT_HASH_TABLE_SIZE;
    /* Security defaults - 0 means no limit */
    cfg.max_connections_per_ip = 0;
    cfg.max_packets_per_second = 0;
    cfg.max_bytes_per_second = 0;
    cfg.max_packet_size = UDP_PROXY_DGRAM_CAP;
    cfg.min_packet_size = 1;

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

    /* Initialize rate limiter */
    if (init_rate_limiter(cfg.max_packets_per_second, cfg.max_bytes_per_second,
                          cfg.max_connections_per_ip) != 0) {
        destroy_conn_pool();
        rc = 1;
        goto cleanup;
    }

    /* Initialize backpressure queue */
#if ENABLE_BACKPRESSURE_QUEUE
    if (init_backpressure_queue() != 0) {
        destroy_rate_limiter();
        destroy_conn_pool();
        rc = 1;
        goto cleanup;
    }
#endif

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

    for (i = 0; (unsigned)i < g_conn_tbl_hash_size; i++) {
        INIT_LIST_HEAD(&conn_tbl_hbase[i]);
    }

#if ENABLE_FINE_GRAINED_LOCKS
    /* Allocate fine-grained locks for hash table buckets */
    conn_tbl_locks = malloc(sizeof(pthread_spinlock_t) * g_conn_tbl_hash_size);
    if (!conn_tbl_locks) {
        P_LOG_ERR("Failed to allocate connection hash table locks");
        free(conn_tbl_hbase);
        conn_tbl_hbase = NULL;
        rc = 1;
        goto cleanup;
    }

    for (i = 0; (unsigned)i < g_conn_tbl_hash_size; i++) {
        if (pthread_spin_init(&conn_tbl_locks[i], PTHREAD_PROCESS_PRIVATE) != 0) {
            P_LOG_ERR("Failed to initialize hash table lock %d", i);
            /* Clean up already initialized locks */
            for (int j = 0; j < i; j++) {
                pthread_spin_destroy(&conn_tbl_locks[j]);
            }
            free((void *)conn_tbl_locks);
            free(conn_tbl_hbase);
            conn_tbl_hbase = NULL;
            conn_tbl_locks = NULL;
            rc = 1;
            goto cleanup;
        }
    }
#endif
    atomic_store(&conn_tbl_len, 0);

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
            /* Segmented LRU update to reduce per-packet overhead */
            segmented_update_lru();
            /* Process any queued backpressure packets */
#if ENABLE_BACKPRESSURE_QUEUE
            process_backpressure_queue();
#endif
            last_check = current_ts;
        }

        /* Cache current timestamp for hot paths - atomic update */
        atomic_store(&g_now_ts, current_ts);

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

    /* Destroy hash table locks */
#if ENABLE_FINE_GRAINED_LOCKS
    if (conn_tbl_locks) {
        for (unsigned i = 0; i < g_conn_tbl_hash_size; i++) {
            pthread_spin_destroy(&conn_tbl_locks[i]);
        }
        free((void *)conn_tbl_locks);
        conn_tbl_locks = NULL;
    }
#endif

    free(conn_tbl_hbase);
    conn_tbl_hbase = NULL;
    destroy_conn_pool();
    destroy_rate_limiter();
#if ENABLE_BACKPRESSURE_QUEUE
    destroy_backpressure_queue();
#endif
#ifdef __linux__
    destroy_batching_resources(c_msgs, c_iov, c_addrs, c_bufs, s_msgs, s_iovs);
#endif

    /* Print performance statistics */
    uint64_t socket_overflows = atomic_load(&g_stat_c2s_batch_socket_overflow);
    uint64_t entry_overflows = atomic_load(&g_stat_c2s_batch_entry_overflow);
    uint64_t hash_collisions = atomic_load(&g_stat_hash_collisions);
    uint64_t lru_immediate = atomic_load(&g_stat_lru_immediate_updates);
    uint64_t lru_deferred = atomic_load(&g_stat_lru_deferred_updates);

    P_LOG_INFO("Performance statistics:");
    P_LOG_INFO("  Batch overflows: sockets=%" PRIu64 ", entries=%" PRIu64,
               socket_overflows, entry_overflows);
    P_LOG_INFO("  Hash collisions: %" PRIu64, hash_collisions);
    P_LOG_INFO("  LRU updates: immediate=%" PRIu64 ", deferred=%" PRIu64,
               lru_immediate, lru_deferred);

    if (socket_overflows > 0) {
        P_LOG_WARN("Consider increasing -B (batch size) or -C (max connections) if overflows are high");
    }
    if (hash_collisions > socket_overflows * 10) {
        P_LOG_WARN("High hash collision rate detected, consider adjusting hash table size");
    }
    closelog();

    return rc;
}
