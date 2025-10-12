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
#include "conn_pool.h"
#include "fwd_util.h"
#include "proxy_conn.h"
#include "list.h"

/* ============ DEBUG FLAGS (can be enabled via -DDEBUG_HANG=1) ============ */
#ifndef DEBUG_HANG
#define DEBUG_HANG 0  /* Set to 1 to enable hang debugging, or use -DDEBUG_HANG=1 */
#endif
/* ========================================================================= */

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

/* Performance and security constants */
#define DEFAULT_CONN_TIMEOUT_SEC 300
#define DEFAULT_HASH_TABLE_SIZE 4096  /* Power-of-two for fast bitwise indexing; sized ~ max conns */
#define MIN_BATCH_SIZE 64             /* Increased from 4 for better performance */
#define MAX_BATCH_SIZE UDP_PROXY_BATCH_SZ
#define BATCH_ADJUST_INTERVAL_SEC 30 /* Reduced frequency from 5 to 30 seconds */
#define RATE_LIMIT_WINDOW_SEC 1

/* Hash function constants */
#define FNV_PRIME_32 0x01000193
#define FNV_OFFSET_32 0x811c9dc5
#define GOLDEN_RATIO_32 0x9e3779b9

/* Adaptive batch sizing thresholds - less aggressive */
#define BATCH_HIGH_UTILIZATION_RATIO 0.9 /* Increased from 0.8 */
#define BATCH_LOW_UTILIZATION_RATIO 0.1  /* Decreased from 0.3 */


/* Performance optimization flags */
#ifndef DISABLE_ADAPTIVE_BATCHING
#define ENABLE_ADAPTIVE_BATCHING 1
#else
#define ENABLE_ADAPTIVE_BATCHING 0
#endif

/* Rate limiting compile-time switch
 * Default: disabled for maximum performance.
 * You can enable with -DENABLE_RATE_LIMITING=1 or force disable with -DDISABLE_RATE_LIMITING.
 */
#ifdef DISABLE_RATE_LIMITING
#  undef ENABLE_RATE_LIMITING
#  define ENABLE_RATE_LIMITING 0
#else
#  ifndef ENABLE_RATE_LIMITING
#    define ENABLE_RATE_LIMITING 0
#  endif
#endif

/* Stats atomics control: default off (0) to reduce overhead in single-threaded mode */
#ifndef ENABLE_STATS_ATOMICS
#define ENABLE_STATS_ATOMICS 1
#endif

/* Compiler optimization hints */
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* Prefetch hints for better cache utilization */
#define PREFETCH_READ(addr) __builtin_prefetch((addr), 0, 3)
#define PREFETCH_WRITE(addr) __builtin_prefetch((addr), 1, 3)

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
/* Disabled by default for better performance */
#define ENABLE_BACKPRESSURE_QUEUE 0
#else
#define ENABLE_BACKPRESSURE_QUEUE 0
#endif

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))
#define MAX_EVENTS 1024
/* Event loop timeout (ms) */
#define EPOLL_WAIT_TIMEOUT_MS 2000
/* Fairness caps to avoid starving other fds per wake */
#define CLIENT_MAX_ITERATIONS 64
#define SERVER_MAX_ITERATIONS 64
/* Maintenance tick interval (seconds) */
#define MAINT_INTERVAL_SEC 2
/* Socket buffer size */
#ifndef UDP_PROXY_SOCKBUF_CAP
/* Increased from 256KB to 1024KB for better throughput */
#define UDP_PROXY_SOCKBUF_CAP (1024 * 1024)
#endif

/* Linux-specific batching parameters */
#ifdef __linux__
#ifndef UDP_PROXY_BATCH_SZ
/* Increased from 16 for much better performance */
#define UDP_PROXY_BATCH_SZ 64
#endif

#ifndef UDP_PROXY_DGRAM_CAP
/* Max safe UDP payload size: 1500 - 8 (UDP header) - 20 (IPv4 header) */
#define UDP_PROXY_DGRAM_CAP 1472 /* 1500 MTU - 20 IPv4 - 8 UDP */
#endif

/* Compile-time validation of UDP_PROXY_DGRAM_CAP */
#if (UDP_PROXY_DGRAM_CAP <= 0) || (UDP_PROXY_DGRAM_CAP > 1472)
#error "UDP_PROXY_DGRAM_CAP must be between 1 and 1472."
#endif

#endif

/* Connection pool size */
#ifndef UDP_PROXY_MAX_CONNS
#define UDP_PROXY_MAX_CONNS 2048
#endif

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
    pthread_mutex_t bucket_locks[RATE_LIMIT_HASH_SIZE];
    unsigned max_pps;
    unsigned max_bps;
    unsigned max_per_ip;
};

/* Connection hash table - protected by fine-grained locks */
static struct list_head *conn_tbl_hbase;
static unsigned g_conn_tbl_hash_size;
static atomic_uint conn_tbl_len; /**< Atomic connection count */

#if ENABLE_FINE_GRAINED_LOCKS
/* Hash table bucket locks for fine-grained locking */
static pthread_spinlock_t *conn_tbl_locks;
#endif

/* Connection pool */
static struct conn_pool g_conn_pool;

/* Runtime tunables (overridable via CLI) - read-only after initialization */
static int g_sockbuf_cap_runtime = UDP_PROXY_SOCKBUF_CAP;
static int g_conn_pool_capacity = UDP_PROXY_MAX_CONNS;
#ifdef __linux__
static int g_batch_sz_runtime = UDP_PROXY_BATCH_SZ;

#if ENABLE_ADAPTIVE_BATCHING
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
    .current_size = UDP_PROXY_BATCH_SZ, /* Start with full batch size */
    .min_size = MIN_BATCH_SIZE,
    .max_size = MAX_BATCH_SIZE,
    .total_packets = 0,
    .total_batches = 0,
    .last_adjust = 0,
    .lock = PTHREAD_MUTEX_INITIALIZER
};
#endif /* ENABLE_ADAPTIVE_BATCHING */
#endif

/* Global LRU list for O(1) oldest selection - protected by mutex */
static LIST_HEAD(g_lru_list);
static pthread_mutex_t g_lru_lock = PTHREAD_MUTEX_INITIALIZER;

/* Cached current timestamp (monotonic seconds on Linux) for hot paths */
static atomic_long g_now_ts; /**< Atomic timestamp cache */

/* Function pointer to compute bucket index from a 32-bit hash */
static unsigned int (*bucket_index_fun)(const union sockaddr_inx *);

/* Additional performance statistics */
static _Atomic uint64_t g_stat_hash_collisions;
static _Atomic uint64_t g_stat_lru_immediate_updates;

/* Per-thread statistics to reduce atomic contention */
#define MAX_THREAD_STATS 64
struct thread_stats {
    uint64_t packets_processed;
    uint64_t bytes_processed;
    uint64_t hash_collisions;
    uint64_t lru_updates;
    char padding[64 - 4 * sizeof(uint64_t)]; /* Cache line padding */
};
static __thread struct thread_stats tls_stats = {0};
static struct thread_stats g_thread_stats[MAX_THREAD_STATS] __attribute__((aligned(64)));

/* Global config */
static struct fwd_config g_cfg;

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

/* Hash functions */
static uint32_t hash_addr(const union sockaddr_inx *sa);

/* Connection management */
static void proxy_conn_walk_continue(int epfd);
static bool proxy_conn_evict_one(int epfd);

/* Data handling */
static void handle_server_data(struct proxy_conn *conn, int lsn_sock, int epfd);
#ifdef __linux__
static void handle_client_data(int listen_sock, int epfd, struct mmsghdr *c_msgs,
                               char (*c_bufs)[UDP_PROXY_DGRAM_CAP]);
#else
static void handle_client_data(int listen_sock, int epfd);
#endif

static void proxy_conn_put(struct proxy_conn *conn, int epfd);

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

/* Load cached time with monotonic fallback for hot paths */
static inline time_t cached_now_seconds(void) {
    time_t now = atomic_load(&g_now_ts);
    if (now == 0) {
        now = monotonic_seconds();
        atomic_store(&g_now_ts, now);
#if DEBUG_HANG
        P_LOG_INFO("[HANG_DEBUG] g_now_ts initialized to %ld", now);
#endif
    }
    return now;
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
 
/* Returns true if errno indicates a transient, non-fatal condition. */
static inline bool is_wouldblock(int e) {
    return likely(e == EAGAIN) || e == EWOULDBLOCK;
}

static inline bool is_temporary_errno(int e) {
    return likely(e == EINTR) || is_wouldblock(e);
}

/* Align up to a given power-of-two alignment (e.g., 64). */
static inline size_t align_up(size_t n, size_t align) {
    return (n + (align - 1)) & ~(align - 1);
}

/* Log helper for unexpected (non-transient) errno after a failed syscall */
static inline void log_if_unexpected_errno(const char *what) {
    int e = errno;
    if (!is_temporary_errno(e)) {
        P_LOG_WARN("%s: %s", what, strerror(e));
    }
}

/* Linux batching support */
#ifdef __linux__
static void init_batching_resources(struct mmsghdr **c_msgs, struct iovec **c_iov,
                                    struct sockaddr_storage **c_addrs,
                                    char (**c_bufs)[UDP_PROXY_DGRAM_CAP]);
#endif

#if ENABLE_RATE_LIMITING
/* Simple hash function for IP addresses */
static inline uint32_t addr_hash_for_rate_limit(const union sockaddr_inx *addr) {
    if (addr->sa.sa_family != AF_INET && addr->sa.sa_family != AF_INET6) {
        P_LOG_WARN("Unsupported address family: %d", addr->sa.sa_family);
        return 0;
    }
    if (addr->sa.sa_family == AF_INET) {
        return ntohl(addr->sin.sin_addr.s_addr) % RATE_LIMIT_HASH_SIZE;
    } else if (addr->sa.sa_family == AF_INET6) {
        const uint32_t *p = (const uint32_t *)&addr->sin6.sin6_addr;
        return (ntohl(p[0]) ^ ntohl(p[1]) ^ ntohl(p[2]) ^ ntohl(p[3])) % RATE_LIMIT_HASH_SIZE;
    }
    return 0;
}
#endif

/* Initialize rate limiter */
static int init_rate_limiter(unsigned max_per_ip, unsigned max_pps, unsigned max_bps) {
    memset(&g_rate_limiter, 0, sizeof(g_rate_limiter));
    for (unsigned i = 0; i < RATE_LIMIT_HASH_SIZE; ++i) {
        if (pthread_mutex_init(&g_rate_limiter.bucket_locks[i], NULL) != 0) {
            P_LOG_ERR("Failed to initialize rate limiter bucket mutex %u", i);
            /* Roll back already initialized locks */
            for (unsigned j = 0; j < i; ++j) {
                pthread_mutex_destroy(&g_rate_limiter.bucket_locks[j]);
            }
            return -1;
        }
    }
    g_rate_limiter.max_per_ip = max_per_ip;
    g_rate_limiter.max_pps = max_pps;
    g_rate_limiter.max_bps = max_bps;
    return 0;
}

/* Update connection_count in rate limiter for a given client address */
static inline void rate_limiter_inc_conn(const union sockaddr_inx *addr) {
#if ENABLE_RATE_LIMITING
    uint32_t hash = addr_hash_for_rate_limit(addr);
    pthread_mutex_t *lock = &g_rate_limiter.bucket_locks[hash];
    pthread_mutex_lock(lock);
    struct rate_limit_entry *entry = &g_rate_limiter.entries[hash];
    if (entry->packet_count > 0 && !is_sockaddr_inx_equal(&entry->addr, addr)) {
        memset(entry, 0, sizeof(*entry));
    }
    if (entry->packet_count == 0) {
        entry->addr = *addr;
        entry->window_start = cached_now_seconds();
    }
    entry->connection_count++;
    pthread_mutex_unlock(lock);
#else
    (void)addr;
#endif
}

static inline void rate_limiter_dec_conn(const union sockaddr_inx *addr) {
#if ENABLE_RATE_LIMITING
    uint32_t hash = addr_hash_for_rate_limit(addr);
    pthread_mutex_t *lock = &g_rate_limiter.bucket_locks[hash];
    pthread_mutex_lock(lock);
    struct rate_limit_entry *entry = &g_rate_limiter.entries[hash];
    if (entry->packet_count > 0 && is_sockaddr_inx_equal(&entry->addr, addr)) {
        if (entry->connection_count > 0) entry->connection_count--;
    }
    pthread_mutex_unlock(lock);
#else
    (void)addr;
#endif
}

/* Destroy rate limiter */
static void destroy_rate_limiter(void) {
    for (unsigned i = 0; i < RATE_LIMIT_HASH_SIZE; ++i) {
        pthread_mutex_destroy(&g_rate_limiter.bucket_locks[i]);
    }
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

    uint32_t hash = addr_hash_for_rate_limit(addr);
    pthread_mutex_t *lock = &g_rate_limiter.bucket_locks[hash];
    pthread_mutex_lock(lock);

    struct rate_limit_entry *entry = &g_rate_limiter.entries[hash];
    /* Use cached timestamp to avoid frequent time() syscalls */
    time_t now = cached_now_seconds();

    /* Check if this is the same IP or a hash collision */
    if (entry->packet_count > 0 && !is_sockaddr_inx_equal(&entry->addr, addr)) {
        /* Hash collision - reset entry for new IP */
        memset(entry, 0, sizeof(*entry));
    }

    /* Initialize or reset time window */
    if (entry->packet_count == 0 || now - entry->window_start >= RATE_LIMIT_WINDOW_SEC) {
        entry->addr = *addr;
        entry->packet_count = 1;
        entry->byte_count = packet_size;
        entry->window_start = now;
        pthread_mutex_unlock(lock);
        return true;
    }

    /* Check packet rate limit */
    if (g_rate_limiter.max_pps > 0 && entry->packet_count >= g_rate_limiter.max_pps) {
        pthread_mutex_unlock(lock);
        P_LOG_WARN("Packet rate limit exceeded for %s (%lu pps)", sockaddr_to_string(addr),
                   entry->packet_count);
        return false;
    }

    /* Check byte rate limit */
    if (g_rate_limiter.max_bps > 0 && entry->byte_count + packet_size > g_rate_limiter.max_bps) {
        pthread_mutex_unlock(lock);
        P_LOG_WARN("Byte rate limit exceeded for %s (%lu bps)", sockaddr_to_string(addr),
                   entry->byte_count);
        return false;
    }

    /* Check per-IP connection limit */
    if (g_rate_limiter.max_per_ip > 0 && entry->connection_count >= g_rate_limiter.max_per_ip) {
        pthread_mutex_unlock(lock);
        P_LOG_WARN("Per-IP connection limit exceeded for %s (%u connections)",
                   sockaddr_to_string(addr), entry->connection_count);
        return false;
    }

    /* Update counters */
    entry->packet_count++;
    entry->byte_count += packet_size;

    pthread_mutex_unlock(lock);
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
        P_LOG_WARN("Invalid packet size %zu from %s (min=1, max=%d)", len, sockaddr_to_string(src),
                   UDP_PROXY_DGRAM_CAP);
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
            if (is_wouldblock(errno)) {
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

#ifdef __linux__
#if ENABLE_ADAPTIVE_BATCHING
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
                unsigned long new_size = (unsigned long)g_adaptive_batch.current_size * 12 / 10; /* BATCH_INCREASE_FACTOR 1.2 */
                if (new_size > (unsigned long)g_adaptive_batch.max_size) {
                    new_size = g_adaptive_batch.max_size;
                }
                g_adaptive_batch.current_size = (int)new_size;
                P_LOG_INFO("Increased batch size to %d (avg=%.1f)", g_adaptive_batch.current_size,
                           avg_batch_size);
            }
        } else if (avg_batch_size < g_adaptive_batch.current_size * BATCH_LOW_UTILIZATION_RATIO) {
            /* Low utilization - decrease batch size */
            if (g_adaptive_batch.current_size > g_adaptive_batch.min_size) {
                unsigned long new_size = (unsigned long)g_adaptive_batch.current_size * 8 / 10; /* BATCH_DECREASE_FACTOR 0.8 */
                if (new_size < (unsigned long)g_adaptive_batch.min_size) {
                    new_size = g_adaptive_batch.min_size;
                }
                g_adaptive_batch.current_size = (int)new_size;
                P_LOG_INFO("Decreased batch size to %d (avg=%.1f)", g_adaptive_batch.current_size,
                           avg_batch_size);
            }
        }
    }

    /* Reset counters */
    #if ENABLE_STATS_ATOMICS
    atomic_store(&g_adaptive_batch.total_packets, 0);
    atomic_store(&g_adaptive_batch.total_batches, 0);
    #else
    g_adaptive_batch.total_packets = 0;
    g_adaptive_batch.total_batches = 0;
    #endif
    g_adaptive_batch.last_adjust = now;

    pthread_mutex_unlock(&g_adaptive_batch.lock);
}
#endif /* ENABLE_ADAPTIVE_BATCHING */

/* Record batch statistics */
static void record_batch_stats(int packets_in_batch) {
#if ENABLE_ADAPTIVE_BATCHING
    #if ENABLE_STATS_ATOMICS
    atomic_fetch_add(&g_adaptive_batch.total_packets, packets_in_batch);
    atomic_fetch_add(&g_adaptive_batch.total_batches, 1);
    #else
    g_adaptive_batch.total_packets += packets_in_batch;
    g_adaptive_batch.total_batches += 1;
    #endif
#else
    (void)packets_in_batch; /* Suppress unused parameter warning */
#endif
}
#endif

/* Improved hash function with better distribution */
static inline uint32_t improved_hash_addr(const union sockaddr_inx *sa) {
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

/* Small helper to check if an unsigned value is a power of two */
static inline bool is_power_of_two(unsigned v) {
    return v && ((v & (v - 1)) == 0);
}

/**
 * @brief Initializes a newly allocated proxy connection.
 * @param conn A pointer to the connection object from the pool.
 * @return The initialized connection object, or NULL on failure.
 */
static inline void proxy_conn_hold(struct proxy_conn *conn) {
    atomic_fetch_add_explicit(&conn->ref_count, 1, memory_order_relaxed);
}

static struct proxy_conn *init_proxy_conn(struct proxy_conn *conn) {
    if (!conn) {
        return NULL;
    }

    /* Zero out the memory and set default values */
    memset(conn, 0, sizeof(*conn));
    atomic_init(&conn->ref_count, 1);
    conn->svr_sock = -1;
    /* Initialize other fields as needed */

    return conn;
}

/* Bucket index strategies (selected once at init) */
static inline unsigned int proxy_conn_hash_bitwise(const union sockaddr_inx *sa) {
    uint32_t h = hash_addr(sa);
    return h & (g_conn_tbl_hash_size - 1);
}

static inline unsigned int proxy_conn_hash_mod(const union sockaddr_inx *sa) {
    uint32_t h = hash_addr(sa);
    return h % g_conn_tbl_hash_size;
}

static inline uint32_t hash_addr(const union sockaddr_inx *a) {
    /* Use the improved hash function for better distribution */
    return improved_hash_addr(a);
}

static inline void touch_proxy_conn(struct proxy_conn *conn) {
    /* Keep the LRU ordering in sync with the timestamp that drives expiration */
    time_t now = cached_now_seconds();
    time_t old_active = conn->last_active;
    
    if (conn->last_active == now)
        return;

    conn->last_active = now;
    
#if DEBUG_HANG
    /* Log significant time gaps to detect timestamp issues */
    if (now - old_active > 60) {
        char s_addr[INET6_ADDRSTRLEN];
        inet_ntop(conn->cli_addr.sa.sa_family, addr_of_sockaddr(&conn->cli_addr),
                  s_addr, sizeof(s_addr));
        P_LOG_INFO("[HANG_DEBUG] Connection %s:%d last_active jumped: %ld -> %ld (gap: %ld sec)",
                   s_addr, ntohs(*port_of_sockaddr(&conn->cli_addr)),
                   old_active, now, now - old_active);
    }
#endif
#if ENABLE_LRU_LOCKS
    pthread_mutex_lock(&g_lru_lock);
    /* Connections are linked into g_lru_list once established; guard for safety */
    if (!list_empty(&conn->lru)) {
        list_move_tail(&conn->lru, &g_lru_list);
    }
    pthread_mutex_unlock(&g_lru_lock);
    atomic_fetch_add_explicit(&g_stat_lru_immediate_updates, 1, memory_order_relaxed);
#endif
}

static struct proxy_conn *proxy_conn_get_or_create(const union sockaddr_inx *cli_addr, int epfd) {
    struct list_head *chain = &conn_tbl_hbase[bucket_index_fun(cli_addr)];
    struct proxy_conn *conn = NULL;
    int svr_sock = -1;
    struct epoll_event ev;
    char s_addr[INET6_ADDRSTRLEN] = "";

    list_for_each_entry(conn, chain, list) {
        /* Prefetch next connection for better cache utilization */
        if (conn->list.next != chain) {
            struct proxy_conn *next = list_entry(conn->list.next, struct proxy_conn, list);
            PREFETCH_READ(&next->cli_addr);
        }
        if (is_sockaddr_inx_equal(cli_addr, &conn->cli_addr)) {
            proxy_conn_hold(conn);
            touch_proxy_conn(conn);
            return conn;
        }
    }

    /* Check rate limits before creating new connection */
    if (unlikely(!check_rate_limit(cli_addr, 0))) {
        /* Rate limit exceeded - drop the connection request */
        return NULL;
    }

    /* Reserve a connection slot atomically to avoid races under contention */
    bool reserved_slot = false;
    unsigned current_conn_count;
    int eviction_attempts = 0;
    const int MAX_EVICTION_ATTEMPTS = 3; /* Prevent infinite recursion */
    
    for (;;) {
        current_conn_count = atomic_load(&conn_tbl_len);
        if (current_conn_count >= (unsigned)g_conn_pool.capacity) {
            /* Prevent excessive eviction attempts */
            if (eviction_attempts >= MAX_EVICTION_ATTEMPTS) {
                inet_ntop(cli_addr->sa.sa_family, addr_of_sockaddr(cli_addr), s_addr, sizeof(s_addr));
                P_LOG_WARN("Conn table full after %d eviction attempts, dropping %s:%d",
                           eviction_attempts, s_addr, ntohs(*port_of_sockaddr(cli_addr)));
                goto err;
            }
            eviction_attempts++;
            
            /* Try to make room first */
            proxy_conn_walk_continue(epfd);
            current_conn_count = atomic_load(&conn_tbl_len);
            if (current_conn_count >= (unsigned)g_conn_pool.capacity) {
                proxy_conn_evict_one(epfd);
            }
            /* Re-check after eviction */
            current_conn_count = atomic_load(&conn_tbl_len);
            if (current_conn_count >= (unsigned)g_conn_pool.capacity) {
                /* Loop to attempt reservation after cleanup */
                continue;
            }
        }
        unsigned expected = current_conn_count;
        if (atomic_compare_exchange_weak_explicit(&conn_tbl_len, &expected, current_conn_count + 1, memory_order_acq_rel, memory_order_acquire)) {
            reserved_slot = true;
            break; /* reserved successfully */
        }
        /* CAS failed due to concurrent change; retry */
    }

    /* High-water one-time warning at ~90% capacity */
    static bool warned_high_water = false;
    if (!warned_high_water && g_conn_pool.capacity > 0 &&
        atomic_load(&conn_tbl_len) >= (unsigned)((g_conn_pool.capacity * 9) / 10)) {
        P_LOG_WARN("UDP conn table high-water: %u/%u (~%d%%). Consider raising -C or reducing -t.",
                   atomic_load(&conn_tbl_len), (unsigned)g_conn_pool.capacity,
                   (int)((atomic_load(&conn_tbl_len) * 100) / (unsigned)g_conn_pool.capacity));
        warned_high_water = true;
    }

    /* ------------------------------------------ */
    /* Establish the server-side connection */
    if ((svr_sock = socket(g_cfg.dst_addr.sa.sa_family, SOCK_DGRAM, 0)) < 0) {
        P_LOG_ERR("socket(svr_sock): %s", strerror(errno));
        goto err;
    }
    /* Connect to real server. */
    if (connect(svr_sock, (struct sockaddr *)&g_cfg.dst_addr, sizeof_sockaddr(&g_cfg.dst_addr)) !=
        0) {
        /* Error occurs, drop the session. */
        P_LOG_WARN("Connection failed: %s", strerror(errno));
        goto err;
    }
    set_nonblock(svr_sock);

    /* Allocate session data for the connection */
    if (!(conn = init_proxy_conn(conn_pool_alloc(&g_conn_pool)))) {
        P_LOG_ERR("conn_pool_alloc: failed");
        goto err_unlock;
    }
    conn->svr_sock = svr_sock;
    conn->cli_addr = *cli_addr;
    INIT_LIST_HEAD(&conn->lru);

    ev.data.ptr = conn;
    ev.events = EPOLLIN;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, conn->svr_sock, &ev) < 0) {
        P_LOG_ERR("epoll_ctl(ADD, svr_sock): %s", strerror(errno));
        /* conn_pool_release will be handled by the cleanup path */
        goto err_unlock;
    }
    /* ------------------------------------------ */

    /* Add to hash table with bucket lock */
#if ENABLE_FINE_GRAINED_LOCKS
    unsigned bucket = bucket_index_fun(cli_addr);
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

    /* Update per-IP connection count for rate limiting */
    rate_limiter_inc_conn(cli_addr);

    /* We already reserved the connection count via CAS earlier; read it for logging */
    unsigned new_count = atomic_load(&conn_tbl_len);

    /* Log new connections at DEBUG level to reduce overhead in high-connection
     * scenarios */
    /* Only log every 100th connection to avoid spam */
    static _Atomic unsigned log_counter = 0;
    unsigned current_count = atomic_fetch_add(&log_counter, 1);
    if ((current_count % 100) == 0) {
        inet_ntop(cli_addr->sa.sa_family, addr_of_sockaddr(cli_addr), s_addr, sizeof(s_addr));
        P_LOG_INFO("New UDP session [%s]:%d, total %u (logging every 100th)", s_addr,
                   ntohs(*port_of_sockaddr(cli_addr)), new_count);
    }

    conn->last_active = cached_now_seconds();
    
    /* Hold reference for caller (consistent with existing connection path) */
    proxy_conn_hold(conn);
    
    return conn;

err_unlock:
    /* Centralized cleanup for new connection failures */
    if (conn) {
        conn_pool_release(&g_conn_pool, conn);
        conn = NULL; /* Avoid double-free */
    }
    if (svr_sock >= 0) {
        if (safe_close(svr_sock) < 0) {
            P_LOG_WARN("close(svr_sock=%d): %s", svr_sock, strerror(errno));
        }
    }
err:
    /* Roll back reserved connection slot on failure */
    if (reserved_slot) {
        atomic_fetch_sub_explicit(&conn_tbl_len, 1, memory_order_acq_rel);
    }
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

    /* Remove from hash table with bucket lock */
#if ENABLE_FINE_GRAINED_LOCKS
    unsigned bucket = bucket_index_fun(&conn->cli_addr);
    pthread_spin_lock(&conn_tbl_locks[bucket]);
#endif
    list_del(&conn->list);
#if ENABLE_FINE_GRAINED_LOCKS
    pthread_spin_unlock(&conn_tbl_locks[bucket]);
#endif

    /* Update per-IP connection count for rate limiting */
    rate_limiter_dec_conn(&conn->cli_addr);

    /* Update global connection count atomically */
    atomic_fetch_sub_explicit(&conn_tbl_len, 1, memory_order_acq_rel);

    /* Remove from LRU list with global LRU lock */
#if ENABLE_LRU_LOCKS
    pthread_mutex_lock(&g_lru_lock);
#endif
    /* Check if the entry is actually in a list before deleting */
    if (!list_empty(&conn->lru)) {
        list_del(&conn->lru);
    }
#if ENABLE_LRU_LOCKS
    pthread_mutex_unlock(&g_lru_lock);
#endif

    /* Remove from epoll and close socket */
    if (conn->svr_sock >= 0) {
        if (epoll_ctl(epfd, EPOLL_CTL_DEL, conn->svr_sock, NULL) < 0 && errno != EBADF &&
            errno != ENOENT) {
            P_LOG_WARN("epoll_ctl(DEL, svr_sock=%d): %s", conn->svr_sock, strerror(errno));
        }
        if (safe_close(conn->svr_sock) < 0) {
            P_LOG_WARN("close(svr_sock=%d): %s", conn->svr_sock, strerror(errno));
        }
        conn->svr_sock = -1;
    }

    conn_pool_release(&g_conn_pool, conn);
}

static void proxy_conn_put(struct proxy_conn *conn, int epfd) {
    if (atomic_fetch_sub_explicit(&conn->ref_count, 1, memory_order_acq_rel) == 1) {
        release_proxy_conn(conn, epfd);
    }
}

static void proxy_conn_walk_continue(int epfd) {
    time_t now = cached_now_seconds();

    pthread_mutex_lock(&g_lru_lock);
    if (list_empty(&g_lru_list)) {
        pthread_mutex_unlock(&g_lru_lock);
        return;
    }

    LIST_HEAD(reap_list);
    struct proxy_conn *conn, *tmp;

    /* Collect all expired connections into a temporary reap_list */
    list_for_each_entry_safe(conn, tmp, &g_lru_list, lru) {
        long diff = (long)(now - conn->last_active);

        if (diff < 0)
            diff = 0;
        if (g_cfg.proxy_conn_timeo != 0 && (unsigned)diff > g_cfg.proxy_conn_timeo) {
#if DEBUG_HANG
            char s_addr[INET6_ADDRSTRLEN] = "";
            inet_ntop(conn->cli_addr.sa.sa_family, addr_of_sockaddr(&conn->cli_addr),
                      s_addr, sizeof(s_addr));
            P_LOG_INFO("[HANG_DEBUG] Recycling %s:%d - last_active=%ld, now=%ld, diff=%ld, timeout=%u",
                       s_addr, ntohs(*port_of_sockaddr(&conn->cli_addr)),
                       conn->last_active, now, diff, g_cfg.proxy_conn_timeo);
#endif
            proxy_conn_put(conn, epfd);
        } else {
            /* List is ordered, so we can stop at the first non-expired conn */
            break;
        }
    }

    /* Now that we're done touching the global list, we can unlock it */
    pthread_mutex_unlock(&g_lru_lock);

    /* Reap the collected connections without holding the global LRU lock */
    list_for_each_entry_safe(conn, tmp, &reap_list, lru) {
        char s_addr[INET6_ADDRSTRLEN] = "";
        union sockaddr_inx addr = conn->cli_addr;

        proxy_conn_put(conn, epfd);
        inet_ntop(addr.sa.sa_family, addr_of_sockaddr(&addr), s_addr, sizeof(s_addr));
        P_LOG_INFO("Recycled %s:%d [%u]", s_addr, ntohs(*port_of_sockaddr(&addr)),
                   atomic_load(&conn_tbl_len));
    }
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
    char s_addr[INET6_ADDRSTRLEN] = "";

    /* CRITICAL: Hold reference before unlocking to prevent use-after-free */
    proxy_conn_hold(oldest);

    /* Unlock before calling release_proxy_conn to avoid deadlock */
    pthread_mutex_unlock(&g_lru_lock);

    /* Release the temporary hold (connection will be freed if ref_count reaches 0) */
    proxy_conn_put(oldest, epfd);
    inet_ntop(addr.sa.sa_family, addr_of_sockaddr(&addr), s_addr, sizeof(s_addr));
    P_LOG_WARN("Evicted LRU %s:%d [%u]", s_addr, ntohs(*port_of_sockaddr(&addr)),
               atomic_load(&conn_tbl_len));

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

            atomic_store(&g_now_ts, monotonic_seconds());

            for (int i = 0; i < n; i++) {
                union sockaddr_inx *sa = (union sockaddr_inx *)c_msgs[i].msg_hdr.msg_name;
                size_t packet_len = c_msgs[i].msg_len;

                if (unlikely(!validate_packet(c_bufs[i], packet_len, sa)))
                    continue;
                if (unlikely(!check_rate_limit(sa, packet_len)))
                    continue;

                conn = proxy_conn_get_or_create(sa, epfd);
                if (!conn)
                    continue;

                touch_proxy_conn(conn);

                ssize_t wr = send(conn->svr_sock, c_bufs[i], packet_len, 0);
                if (wr < 0) {
                    log_if_unexpected_errno("send(server)");
                } else {
                    tls_stats.bytes_processed += (size_t)wr;
                }
                proxy_conn_put(conn, epfd);
            }

            record_batch_stats(n);
            tls_stats.packets_processed += n;

            if (n < ncap)
                break;
        }

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

    int r = recvfrom(lsn_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&cli_addr, &cli_alen);
    if (r < 0) {
        if (errno)
            log_if_unexpected_errno("recvfrom()");
        return;
    }

    atomic_store(&g_now_ts, monotonic_seconds());

    if (!validate_packet(buffer, (size_t)r, &cli_addr))
        return;
    if (!check_rate_limit(&cli_addr, (size_t)r))
        return;

    conn = proxy_conn_get_or_create(&cli_addr, epfd);
    if (!conn)
        return;

    touch_proxy_conn(conn);

    ssize_t wr = send(conn->svr_sock, buffer, r, 0);
    if (wr < 0)
        log_if_unexpected_errno("send(server)");
    else
        tls_stats.bytes_processed += (size_t)wr;

    proxy_conn_put(conn, epfd);
}

static void handle_server_data(struct proxy_conn *conn, int lsn_sock, int epfd) {
#ifdef __linux__
    /* Use recvmmsg() to batch receive from server and sendmmsg() to client */
    static __thread struct mmsghdr tls_msgs[UDP_PROXY_BATCH_SZ];
    static __thread struct iovec tls_iovs[UDP_PROXY_BATCH_SZ];
    /* Use thread-local storage to avoid static buffer race conditions */
    static __thread char tls_bufs[UDP_PROXY_BATCH_SZ][UDP_PROXY_DGRAM_CAP];
    static __thread bool tls_inited;
    struct mmsghdr *msgs = tls_msgs;
    struct iovec *iovs = tls_iovs;
    char (*bufs)[UDP_PROXY_DGRAM_CAP] = tls_bufs;

    /* One-time initialization of constant mmsghdr fields */
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

    int iterations = 0;
    const int max_iterations = SERVER_MAX_ITERATIONS; /* fairness cap per event */
    const int ncap = g_batch_sz_runtime > 0 ? g_batch_sz_runtime : UDP_PROXY_BATCH_SZ;

    for (; iterations < max_iterations; iterations++) {
        /* Reset per-call mutable fields */
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

        atomic_store(&g_now_ts, monotonic_seconds());

        /* Prepare destination (original client) for each message */
        /* All packets are for the same connection, so touch it only once per batch. */
        touch_proxy_conn(conn);

        for (int i = 0; i < n; i++) {
            msgs[i].msg_hdr.msg_name = &conn->cli_addr;
            msgs[i].msg_hdr.msg_namelen = (socklen_t)sizeof_sockaddr(&conn->cli_addr);
            /* Ensure iov_len matches actual datagram size */
            iovs[i].iov_len = msgs[i].msg_len;
        }

        /* Send out the batch to client, retry on partial */
        int remaining = n;
        struct mmsghdr *msgp = msgs;
        do {
            int sent = sendmmsg(lsn_sock, msgp, remaining, 0);
            if (sent < 0) {
                if (is_temporary_errno(errno)) {
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
                P_LOG_INFO("sendmmsg(client) partial: sent=%d, remaining=%d", sent, remaining);
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
            if (is_temporary_errno(errno))
                break; /* drained */
            log_if_unexpected_errno("recv(server)");
            /* fatal error on server socket: close session */
            proxy_conn_put(conn, epfd);
            break;
        }

        /* r >= 0: forward even zero-length datagrams */
        atomic_store(&g_now_ts, monotonic_seconds());
        touch_proxy_conn(conn);

        ssize_t wr = sendto(lsn_sock, buffer, r, 0, (struct sockaddr *)&conn->cli_addr,
                            sizeof_sockaddr(&conn->cli_addr));
        if (wr < 0)
            log_if_unexpected_errno("sendto(client)");

        if (r < (int)sizeof(buffer)) {
            break; /* Drained */
        }
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
        *c_msgs = NULL;
        *c_iov = NULL;
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

    /* Initialize mmsghdr/iovec structures */
    for (int i = 0; i < ncap; i++) {
        (*c_iov)[i].iov_base = (*c_bufs)[i];
        (*c_iov)[i].iov_len = UDP_PROXY_DGRAM_CAP;
        (*c_msgs)[i].msg_hdr.msg_iov = &(*c_iov)[i];
        (*c_msgs)[i].msg_hdr.msg_iovlen = 1;
        (*c_msgs)[i].msg_hdr.msg_name = &(*c_addrs)[i];
        (*c_msgs)[i].msg_hdr.msg_namelen = sizeof((*c_addrs)[i]);
    }

    /* Store the base pointer for single-free at destroy time by stashing it in c_msgs[-1].msg_hdr.msg_iov */
    /* We can't portably store it there; instead, rely on contiguous block: free(c_msgs) frees all */
}

static void destroy_batching_resources(struct mmsghdr *c_msgs, struct iovec *c_iov,
                                       struct sockaddr_storage *c_addrs,
                                       char (*c_bufs)[UDP_PROXY_DGRAM_CAP]) {
    /* Single block allocation: freeing c_msgs frees all the contiguous arrays */
    (void)c_iov;
    (void)c_addrs;
    (void)c_bufs;
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
            if (end == optarg || *end != '\0') {
                P_LOG_WARN("invalid -t value '%s', keeping default %u", optarg,
                           g_cfg.proxy_conn_timeo);
            } else {
                /* A value of 0 means infinite timeout */
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
            if (end == optarg || *end != '\0' || v == 0) {
                P_LOG_WARN("invalid -i value '%s', keeping default %u", optarg,
                           g_cfg.max_per_ip_connections);
            } else {
                g_cfg.max_per_ip_connections = (unsigned)v;
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
                P_LOG_WARN("invalid -B value '%s', keeping default %d", optarg, g_batch_sz_runtime);
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
        case 'H': {
            char *end = NULL;
            unsigned long v = strtoul(optarg, &end, 10);
            if (end == optarg || *end != '\0') {
                P_LOG_WARN("invalid -H value '%s', keeping default %u", optarg,
                           g_cfg.conn_tbl_hash_size);
            } else {
                if (v == 0)
                    v = 4093UL;
                if (v < 64UL)
                    v = 64UL;
                if (v > (1UL << 20))
                    v = (1UL << 20);
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
        
        /* Open log file in daemon mode: /var/log/udpfwd_${port}.log */
        char log_path[256];
        unsigned short listen_port = ntohs(*port_of_sockaddr(&g_cfg.listen_addr));
        snprintf(log_path, sizeof(log_path), "/var/log/udpfwd_%u.log", listen_port);
        
        g_state.log_file = fopen(log_path, "a");
        if (!g_state.log_file) {
            /* Fall back to syslog if log file cannot be opened */
            syslog(LOG_WARNING, "Failed to open log file %s: %s, using syslog", 
                   log_path, strerror(errno));
        } else {
            /* Log startup message */
            P_LOG_INFO("UDP forwarder started, logging to %s", log_path);
        }
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
        if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            P_LOG_WARN("setsockopt(SO_REUSEADDR): %s", strerror(errno));
        }
    }

#ifdef SO_REUSEPORT
    if (g_cfg.reuse_port) {
        int on = 1;
        if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
            P_LOG_WARN("setsockopt(SO_REUSEPORT): %s", strerror(errno));
        }
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
                       sizeof(g_sockbuf_cap_runtime)) < 0) {
            P_LOG_WARN("setsockopt(SO_RCVBUF): %s", strerror(errno));
        }
        if (setsockopt(listen_sock, SOL_SOCKET, SO_SNDBUF, &g_sockbuf_cap_runtime,
                       sizeof(g_sockbuf_cap_runtime)) < 0) {
            P_LOG_WARN("setsockopt(SO_SNDBUF): %s", strerror(errno));
        }
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
    if (g_conn_tbl_hash_size < 64)
        g_conn_tbl_hash_size = 64;
    if (g_conn_tbl_hash_size > (1u << 20))
        g_conn_tbl_hash_size = (1u << 20);

    bucket_index_fun =
        is_power_of_two(g_conn_tbl_hash_size) ? proxy_conn_hash_bitwise : proxy_conn_hash_mod;
    assert(bucket_index_fun != NULL);

    conn_tbl_hbase = malloc(sizeof(struct list_head) * g_conn_tbl_hash_size);
    if (!conn_tbl_hbase) {
        P_LOG_ERR("malloc(conn_tbl_hbase): failed");
        goto cleanup;
    }
    for (i = 0; (unsigned)i < g_conn_tbl_hash_size; i++) {
        INIT_LIST_HEAD(&conn_tbl_hbase[i]);
    }

#if ENABLE_FINE_GRAINED_LOCKS
    conn_tbl_locks = malloc(sizeof(pthread_spinlock_t) * g_conn_tbl_hash_size);
    if (!conn_tbl_locks) {
        P_LOG_ERR("malloc(conn_tbl_locks): failed");
        goto cleanup;
    }
    for (i = 0; (unsigned)i < g_conn_tbl_hash_size; i++) {
        if (pthread_spin_init(&conn_tbl_locks[i], PTHREAD_PROCESS_PRIVATE) != 0) {
            P_LOG_ERR("pthread_spin_init(lock %d): failed", i);
            /* Clean up already initialized spinlocks */
            for (int j = 0; j < i; j++) {
                pthread_spin_destroy(&conn_tbl_locks[j]);
            }
            rc = 1;
            goto cleanup;
        }
    }
#endif
    atomic_store(&conn_tbl_len, 0);

    last_check = monotonic_seconds();

    /* Optional Linux batching init */
#ifdef __linux__
    init_batching_resources(&c_msgs, &c_iov, &c_addrs, &c_bufs);
#endif

    if (init_rate_limiter(g_cfg.max_per_ip_connections, 0, 0) != 0) {
        P_LOG_ERR("Failed to initialize rate limiter");
        rc = 1;
        goto cleanup;
    }

    /* epoll loop */
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

    /* Main event loop */
    for (;;) {
        int nfds;
        time_t current_ts = monotonic_seconds();

        /* Refresh cached timestamp immediately so maintenance passes see the
         * up-to-date wall clock. */
        atomic_store(&g_now_ts, current_ts);
        time_t pre_wait_ts = current_ts;

        /* Periodic timeout check and connection recycling */
        if ((long)(current_ts - last_check) >= MAINT_INTERVAL_SEC) {
            proxy_conn_walk_continue(epfd);
            /* Process any queued backpressure packets */
#if ENABLE_BACKPRESSURE_QUEUE
            process_backpressure_queue();
#endif
            last_check = current_ts;
            
            /* Check shutdown flag after maintenance tasks */
            if (g_shutdown_requested)
                break;
        }

        /* Check shutdown flag before blocking */
        if (g_shutdown_requested)
            break;

        /* Wait for events */
        nfds = epoll_wait(epfd, events, countof(events), EPOLL_WAIT_TIMEOUT_MS);
    
        /* Update cached timestamp only if time has advanced since pre-wait.
         * This avoids redundant atomic stores when epoll_wait returns immediately
         * (high PPS scenario), improving performance while maintaining correctness. */
        current_ts = monotonic_seconds();
        if (current_ts != pre_wait_ts) {
            atomic_store(&g_now_ts, current_ts);
#if DEBUG_HANG
            if (current_ts - pre_wait_ts > 5) {
                P_LOG_INFO("[HANG_DEBUG] Main loop: g_now_ts updated %ld -> %ld (epoll blocked %ld sec)",
                           pre_wait_ts, current_ts, current_ts - pre_wait_ts);
            }
#endif
        }
        
        /* Check shutdown flag after epoll_wait (handles timeout and EINTR cases) */
        if (g_shutdown_requested)
            break;

        if (nfds == 0)
            continue; /* Timeout, loop back to check shutdown flag */
        if (nfds < 0) {
            if (errno == EINTR || errno == ERESTART)
                continue; /* Interrupted, loop back to check shutdown flag */
            P_LOG_ERR("epoll_wait(): %s", strerror(errno));
            rc = 1;
            goto cleanup;
        }

        /* Process events */
        for (i = 0; i < nfds; i++) {
            struct epoll_event *evp = &events[i];
            struct proxy_conn *conn;

            if (evp->data.ptr == &magic_listener) {
                /* Data from client */
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
                /* Data from server */
                conn = evp->data.ptr;
                if (evp->events & (EPOLLERR | EPOLLHUP)) {
                    /* fatal on this flow: release session */
                    proxy_conn_put(conn, epfd);
                    continue;
                }
                handle_server_data(conn, listen_sock, epfd);
            }
        }
    }

cleanup:
    /* Cleanup resources */
    if (listen_sock >= 0) {
        if (safe_close(listen_sock) < 0) {
            P_LOG_WARN("close(listen_sock=%d): %s", listen_sock, strerror(errno));
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
    conn_pool_destroy(&g_conn_pool);
    destroy_rate_limiter();
#if ENABLE_BACKPRESSURE_QUEUE
    destroy_backpressure_queue();
#endif
#ifdef __linux__
    destroy_batching_resources(c_msgs, c_iov, c_addrs, c_bufs);
#endif

    /* Aggregate thread-local statistics */
    uint64_t total_packets = 0, total_bytes = 0, total_hash_collisions = 0;
    for (int i = 0; i < MAX_THREAD_STATS; i++) {
        total_packets += g_thread_stats[i].packets_processed;
        total_bytes += g_thread_stats[i].bytes_processed;
        total_hash_collisions += g_thread_stats[i].hash_collisions;
    }

    /* Print performance statistics */
    uint64_t hash_collisions = atomic_load(&g_stat_hash_collisions) + total_hash_collisions;
    uint64_t lru_immediate = atomic_load(&g_stat_lru_immediate_updates);

    P_LOG_INFO("Performance statistics:");
    P_LOG_INFO("  Total packets processed: %" PRIu64, total_packets);
    P_LOG_INFO("  Total bytes processed: %" PRIu64, total_bytes);
    P_LOG_INFO("  Hash collisions: %" PRIu64 " (avg probe: %.2f)", hash_collisions,
               total_packets > 0 ? (double)hash_collisions / total_packets : 0.0);
    P_LOG_INFO("  LRU updates: %" PRIu64, lru_immediate);

    if (total_packets > 0 && hash_collisions > total_packets / 2) {
        P_LOG_WARN("High hash collision rate detected (%.1f%%), consider adjusting hash "
                   "table size or connection distribution",
                   (double)hash_collisions * 100.0 / total_packets);
    }
    if (total_packets > 0) {
        double throughput_pps = (double)total_packets / (time(NULL) - last_check + 1);
        P_LOG_INFO("  Estimated throughput: %.0f packets/sec", throughput_pps);
    }
    
    /* Close log file if opened */
    if (g_state.log_file) {
        fclose(g_state.log_file);
        g_state.log_file = NULL;
    }
    
    closelog();

    return rc;
}
