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
#include <sched.h> /* For sched_getcpu() */

#ifdef __linux__
#include <sys/epoll.h>
#include <sys/uio.h>
#else
#define ERESTART 700
#include "no-epoll.h"
#endif

/* Performance and security constants */
#define DEFAULT_CONN_TIMEOUT_SEC 300
#define DEFAULT_HASH_TABLE_SIZE 65537 /* Larger prime number for better distribution */
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
/* Disabled by default for better performance */
#define ENABLE_BACKPRESSURE_QUEUE 0
#else
#define ENABLE_BACKPRESSURE_QUEUE 0
#endif

/* Batch processing limits - decouple max batches from per-batch message limit
 */
/* Maximum number of concurrent server sockets in one batch cycle */
#define MAX_CONCURRENT_BATCHES 1024

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))
#define MAX_EVENTS 1024

/* Socket buffer size */
#ifndef UDP_PROXY_SOCKBUF_CAP
/* Increased from 256KB to 2MB for better throughput */
#define UDP_PROXY_SOCKBUF_CAP (2 * 1024 * 1024)
#endif

/* Linux-specific batching parameters */
#ifdef __linux__
#ifndef UDP_PROXY_BATCH_SZ
/* Increased from 16 for much better performance */
#define UDP_PROXY_BATCH_SZ 512
#endif
#ifndef UDP_PROXY_DGRAM_CAP
/* Max safe UDP payload size: 65535 - 8 (UDP header) - 20 (IPv4 header) */
#define UDP_PROXY_DGRAM_CAP 65507
#endif

/* Compile-time validation of UDP_PROXY_DGRAM_CAP */
#if (UDP_PROXY_DGRAM_CAP <= 0) || (UDP_PROXY_DGRAM_CAP > 65507)
#error "UDP_PROXY_DGRAM_CAP must be between 1 and 65507."
#endif

#endif

/* Connection pool size */
#ifndef UDP_PROXY_MAX_CONNS
#define UDP_PROXY_MAX_CONNS 4096
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
    pthread_mutex_t lock;
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
    .lock = PTHREAD_MUTEX_INITIALIZER};
#endif /* ENABLE_ADAPTIVE_BATCHING */
#endif

/* Segmented LRU cache to reduce lock contention */
#define NUM_LRU_SEGMENTS 256 /* Power of 2 for fast modulo */
struct lru_cache {
    struct list_head list;
    pthread_mutex_t lock;
};
static struct lru_cache *g_lru_caches;

#if ENABLE_LRU_LOCKS
/* Segmented LRU update state to avoid O(N) scans */
static struct {
    unsigned next_bucket;         /* Next bucket to scan in segmented update */
    time_t last_segment_update;   /* Last time we did a segment update */
    unsigned buckets_per_segment; /* How many buckets to process per segment */
} g_lru_segment_state = {0, 0, 64};
#endif

/* Cached current timestamp (monotonic seconds on Linux) for hot paths */
static atomic_long g_now_ts; /**< Atomic timestamp cache */

/* Function pointer to compute bucket index from a 32-bit hash */
static unsigned int (*bucket_index_fun)(const union sockaddr_inx *);

/* Per-CPU statistics to avoid cache line contention */
struct per_cpu_stats {
    uint64_t c2s_batch_socket_overflow;
    uint64_t c2s_batch_entry_overflow;
    uint64_t hash_collisions;
    uint64_t lru_immediate_updates;
    uint64_t lru_deferred_updates;
} __attribute__((__aligned__(64))); /* Align to cache line size */

static struct per_cpu_stats *g_per_cpu_stats;

/* Global config */
static struct fwd_config g_cfg;

/* Per-CPU rate limiters for security */
static struct rate_limiter *g_rate_limiters;
static int g_num_cpus;

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
static uint32_t hash_addr(const union sockaddr_inx *a);

/* Connection management */
static void proxy_conn_walk_continue(int epfd);
static bool proxy_conn_evict_one(int epfd);

/* Data handling */
static void handle_server_data(struct proxy_conn *conn, int lsn_sock, int epfd);
#ifdef __linux__
static void handle_client_data(int listen_sock, int epfd, struct mmsghdr *c_msgs,
                               struct mmsghdr *s_msgs, struct iovec *s_iovs,
                               char (*c_bufs)[UDP_PROXY_DGRAM_CAP]);
#else
static void handle_client_data(int listen_sock, int epfd);
#endif

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

/* Linux batching support */
#ifdef __linux__
static void init_batching_resources(struct mmsghdr **c_msgs, struct iovec **c_iov,
                                    struct sockaddr_storage **c_addrs,
                                    char (**c_bufs)[UDP_PROXY_DGRAM_CAP], struct mmsghdr **s_msgs,
                                    struct iovec **s_iovs);
#endif

#if ENABLE_RATE_LIMITING
/* Simple hash function for IP addresses */
static uint32_t addr_hash_for_rate_limit(const union sockaddr_inx *addr) {
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
    g_num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (g_num_cpus <= 0) {
        g_num_cpus = 1;
    }

    g_rate_limiters = calloc(g_num_cpus, sizeof(struct rate_limiter));
    if (!g_rate_limiters) {
        P_LOG_ERR("Failed to allocate memory for per-CPU rate limiters");
        return -1;
    }

    for (int i = 0; i < g_num_cpus; i++) {
        if (pthread_mutex_init(&g_rate_limiters[i].lock, NULL) != 0) {
            P_LOG_ERR("Failed to initialize rate limiter mutex for CPU %d", i);
            /* Cleanup previously initialized mutexes */
            for (int j = 0; j < i; j++) {
                pthread_mutex_destroy(&g_rate_limiters[j].lock);
            }
            free(g_rate_limiters);
            g_rate_limiters = NULL;
            return -1;
        }
        g_rate_limiters[i].max_per_ip = max_per_ip;
        g_rate_limiters[i].max_pps = max_pps;
        g_rate_limiters[i].max_bps = max_bps;
    }

    P_LOG_INFO("Initialized %d per-CPU rate limiters.", g_num_cpus);
    return 0;
}

/* Destroy rate limiter */
static void destroy_rate_limiter(void) {
    if (g_rate_limiters) {
        for (int i = 0; i < g_num_cpus; i++) {
            pthread_mutex_destroy(&g_rate_limiters[i].lock);
        }
        free(g_rate_limiters);
        g_rate_limiters = NULL;
    }
}

/* Check if packet is allowed by rate limiter */
static bool check_rate_limit(const union sockaddr_inx *addr, size_t packet_size) {
#if !ENABLE_RATE_LIMITING
    (void)addr;
    (void)packet_size;
    return true; /* Rate limiting disabled at compile time */
#else
    if (!g_rate_limiters) {
        return true; /* Not initialized, allow all */
    }

    int cpu = sched_getcpu();
    if (cpu < 0) {
        cpu = 0; /* Fallback in case of error */
    }
    struct rate_limiter *limiter = &g_rate_limiters[cpu % g_num_cpus];

    if (limiter->max_pps == 0 && limiter->max_bps == 0 && limiter->max_per_ip == 0) {
        return true; /* No limits configured for this CPU's limiter */
    }

    pthread_mutex_lock(&limiter->lock);

    uint32_t hash = addr_hash_for_rate_limit(addr);
    struct rate_limit_entry *entry = &limiter->entries[hash];
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
        pthread_mutex_unlock(&limiter->lock);
        return true;
    }

    /* Check packet rate limit */
    if (limiter->max_pps > 0 && entry->packet_count >= limiter->max_pps) {
        pthread_mutex_unlock(&limiter->lock);
        P_LOG_WARN("Packet rate limit exceeded for %s (%lu pps)", sockaddr_to_string(addr),
                   entry->packet_count);
        return false;
    }

    /* Check byte rate limit */
    if (limiter->max_bps > 0 && entry->byte_count + packet_size > limiter->max_bps) {
        pthread_mutex_unlock(&limiter->lock);
        P_LOG_WARN("Byte rate limit exceeded for %s (%lu bps)", sockaddr_to_string(addr),
                   entry->byte_count);
        return false;
    }

    /* Check per-IP connection limit */
    if (limiter->max_per_ip > 0 && entry->connection_count >= limiter->max_per_ip) {
        pthread_mutex_unlock(&limiter->lock);
        P_LOG_WARN("Per-IP connection limit exceeded for %s (%u connections)",
                   sockaddr_to_string(addr), entry->connection_count);
        return false;
    }

    /* Update counters */
    entry->packet_count++;
    entry->byte_count += packet_size;

    pthread_mutex_unlock(&limiter->lock);
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
    atomic_store(&g_adaptive_batch.total_packets, 0);
    atomic_store(&g_adaptive_batch.total_batches, 0);
    g_adaptive_batch.last_adjust = now;

    pthread_mutex_unlock(&g_adaptive_batch.lock);
}
#endif /* ENABLE_ADAPTIVE_BATCHING */

/* Get current optimal batch size */
static int get_optimal_batch_size(void) {
#if ENABLE_ADAPTIVE_BATCHING
    return g_adaptive_batch.current_size;
#else
    return UDP_PROXY_BATCH_SZ; /* Use fixed batch size for maximum performance
                                */
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

static void proxy_conn_put(struct proxy_conn *conn, int epfd);

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
static unsigned int proxy_conn_hash_bitwise(const union sockaddr_inx *sa) {
    uint32_t h = hash_addr(sa);
    return h & (g_conn_tbl_hash_size - 1);
}

static unsigned int proxy_conn_hash_mod(const union sockaddr_inx *sa) {
    uint32_t h = hash_addr(sa);
    return h % g_conn_tbl_hash_size;
}

static uint32_t hash_addr(const union sockaddr_inx *a) {
    /* Use the improved hash function for better distribution */
    return improved_hash_addr(a);
}

/* Selects the appropriate LRU segment for a given connection */
static inline struct lru_cache *get_lru_cache_for_conn(const struct proxy_conn *conn) {
    uint32_t hash = hash_addr(&conn->cli_addr);
    return &g_lru_caches[hash & (NUM_LRU_SEGMENTS - 1)];
}

/* Aggregate stats from all per-CPU counters */
static void aggregate_stats(struct per_cpu_stats *total) {
    memset(total, 0, sizeof(*total));
    for (int i = 0; i < g_num_cpus; i++) {
        total->c2s_batch_socket_overflow += g_per_cpu_stats[i].c2s_batch_socket_overflow;
        total->c2s_batch_entry_overflow += g_per_cpu_stats[i].c2s_batch_entry_overflow;
        total->hash_collisions += g_per_cpu_stats[i].hash_collisions;
        total->lru_immediate_updates += g_per_cpu_stats[i].lru_immediate_updates;
        total->lru_deferred_updates += g_per_cpu_stats[i].lru_deferred_updates;
    }
}

static void print_final_stats(void) {
    P_LOG_INFO("Shutting down...");
    if (g_per_cpu_stats) {
        struct per_cpu_stats total_stats;
        aggregate_stats(&total_stats);

        P_LOG_INFO("Final Stats:");
        P_LOG_INFO("  Batch Socket Overflows: %lu", (unsigned long)total_stats.c2s_batch_socket_overflow);
        P_LOG_INFO("  Batch Entry Overflows:  %lu", (unsigned long)total_stats.c2s_batch_entry_overflow);
        P_LOG_INFO("  Hash Collisions:        %lu", (unsigned long)total_stats.hash_collisions);
        P_LOG_INFO("  LRU Immediate Updates:  %lu", (unsigned long)total_stats.lru_immediate_updates);
        P_LOG_INFO("  LRU Deferred Updates:   %lu", (unsigned long)total_stats.lru_deferred_updates);
    }
}

static inline void touch_proxy_conn(struct proxy_conn *conn) {
    /* Update timestamp */
    time_t snap = atomic_load(&g_now_ts);
    time_t new_time = snap ? snap : monotonic_seconds();
    conn->last_active = new_time;

    /* Try immediate LRU update with trylock to avoid blocking hot path */
#if ENABLE_LRU_LOCKS
    struct lru_cache *cache = get_lru_cache_for_conn(conn);
    if (pthread_mutex_trylock(&cache->lock) == 0) {
        /* Successfully got lock - do immediate LRU update */
        list_move_tail(&conn->lru, &cache->list);
        pthread_mutex_unlock(&cache->lock);
        g_per_cpu_stats[sched_getcpu()].lru_immediate_updates++;
    } else {
        /* Lock contention - mark for batch update */
        conn->needs_lru_update = true;
        g_per_cpu_stats[sched_getcpu()].lru_deferred_updates++;
    }
#else
    conn->needs_lru_update = true;
#endif
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

    /* Update global connection count atomically */
    atomic_fetch_sub_explicit(&conn_tbl_len, 1, memory_order_acq_rel);

    /* Remove from LRU list with segmented lock */
#if ENABLE_LRU_LOCKS
    struct lru_cache *cache = get_lru_cache_for_conn(conn);
    pthread_mutex_lock(&cache->lock);
    /* Check if the entry is actually in a list before deleting */
    if (!list_empty(&conn->lru)) {
        list_del(&conn->lru);
    }
    pthread_mutex_unlock(&cache->lock);
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

static void proxy_conn_walk_continue(int epfd) {
    time_t now = atomic_load(&g_now_ts);
    if (now == 0) {
        now = monotonic_seconds();
    }

    LIST_HEAD(reap_list);
    struct proxy_conn *conn, *tmp;

    /* Iterate over all LRU segments */
    for (int i = 0; i < NUM_LRU_SEGMENTS; i++) {
        struct lru_cache *cache = &g_lru_caches[i];

        pthread_mutex_lock(&cache->lock);
        if (list_empty(&cache->list)) {
            pthread_mutex_unlock(&cache->lock);
            continue;
        }

        /* Collect all expired connections from this segment into a temporary reap_list */
        list_for_each_entry_safe(conn, tmp, &cache->list, lru) {
            long diff = (long)(now - conn->last_active);
            if (diff < 0) diff = 0;

            if (g_cfg.proxy_conn_timeo != 0 && (unsigned)diff > g_cfg.proxy_conn_timeo) {
                /* Move from LRU to our local reap list */
                list_move_tail(&conn->lru, &reap_list);
            } else {
                /* List is ordered, so we can stop at the first non-expired conn */
                break;
            }
        }
        pthread_mutex_unlock(&cache->lock);
    }

    /* Reap the collected connections without holding any LRU locks */
    if (!list_empty(&reap_list)) {
        list_for_each_entry_safe(conn, tmp, &reap_list, lru) {
            char s_addr[INET6_ADDRSTRLEN] = "";
            union sockaddr_inx addr = conn->cli_addr;

            proxy_conn_put(conn, epfd);
            inet_ntop(addr.sa.sa_family, addr_of_sockaddr(&addr), s_addr, sizeof(s_addr));
            P_LOG_INFO("Recycled %s:%d [%u]", s_addr, ntohs(*port_of_sockaddr(&addr)),
                       atomic_load(&conn_tbl_len));
        }
    }
}

/* Evict the least recently active connection from a randomly chosen segment */
static bool proxy_conn_evict_one(int epfd) {
    /* Choose a random segment to start search, to distribute eviction load */
    int start_idx = rand() % NUM_LRU_SEGMENTS;
    struct proxy_conn *oldest = NULL;

    for (int i = 0; i < NUM_LRU_SEGMENTS; i++) {
        int idx = (start_idx + i) % NUM_LRU_SEGMENTS;
        struct lru_cache *cache = &g_lru_caches[idx];

        pthread_mutex_lock(&cache->lock);
        if (!list_empty(&cache->list)) {
            oldest = list_first_entry(&cache->list, struct proxy_conn, lru);
            /* Move to a temporary list to release lock quickly */
            list_del_init(&oldest->lru);
            pthread_mutex_unlock(&cache->lock);
            break; /* Found a victim */
        }
        pthread_mutex_unlock(&cache->lock);
    }

    if (oldest) {
        union sockaddr_inx addr = oldest->cli_addr;
        char s_addr[INET6_ADDRSTRLEN] = "";

        proxy_conn_put(oldest, epfd);
        inet_ntop(addr.sa.sa_family, addr_of_sockaddr(&addr), s_addr, sizeof(s_addr));
        P_LOG_WARN("Evicted LRU %s:%d [%u]", s_addr, ntohs(*port_of_sockaddr(&addr)),
                   atomic_load(&conn_tbl_len));
        return true;
    }

    return false; /* No connections to evict */
}

/* A simple integer hash function for file descriptors */
static inline uint32_t hash_fd(int fd) {
    uint32_t key = fd;
    key = ~key + (key << 15); // key = (key << 15) - key - 1;
    key = key ^ (key >> 12);
    key = key + (key << 2);
    key = key ^ (key >> 4);
    key = key * 2057; // key = (key + (key << 3)) + (key << 11);
    key = key ^ (key >> 16);
    return key;
}

#ifdef __linux__
static void handle_client_data(int lsn_sock, int epfd, struct mmsghdr *c_msgs,
                               struct mmsghdr *s_msgs, struct iovec *s_iovs,
                               char (*c_bufs)[UDP_PROXY_DGRAM_CAP]) {
#else
static void handle_client_data(int lsn_sock, int epfd) {
#endif
    struct proxy_conn *conn;

#ifdef __linux__
    if (c_msgs && s_msgs) {
        /* Drain multiple batches per epoll wake to reduce syscalls */
        int iterations = 0;
        const int max_iterations = 64; /* fairness cap per tick */
        const int ncap = g_batch_sz_runtime > 0 ? g_batch_sz_runtime : UDP_PROXY_BATCH_SZ;
        for (; iterations < max_iterations; iterations++) {
            /* Ensure namelen is reset before each recvmmsg call */
            for (int i = 0; i < ncap; i++) {
                c_msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
            }

            int n = recvmmsg(lsn_sock, c_msgs, ncap, 0, NULL);
            if (n <= 0) {
                if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
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
                union sockaddr_inx *sa = (union sockaddr_inx *)c_msgs[i].msg_hdr.msg_name;

                /* Validate packet size and rate limits */
                size_t packet_len = c_msgs[i].msg_len;
                if (!validate_packet(c_bufs[i], packet_len, sa)) {
                    continue; /* Drop invalid packet */
                }
                if (!check_rate_limit(sa, packet_len)) {
                    continue; /* Drop rate-limited packet */
                }

                if (!(conn = proxy_conn_get_or_create(sa, epfd)))
                    continue;
                touch_proxy_conn(conn);

                /* O(1) batch lookup using hash table with linear probing for
                 * collision resolution */
                int hash_key = hash_fd(conn->svr_sock) % BATCH_HASH_SIZE;
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
                    g_per_cpu_stats[sched_getcpu()].hash_collisions += probe_count;
                }

                /* If we found a matching socket or an empty slot */
                if (batch_idx == -1) {
                    /* Check if we can create a new batch */
                    if (num_batches >= MAX_CONCURRENT_BATCHES) {
                        g_per_cpu_stats[sched_getcpu()].c2s_batch_socket_overflow++;
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
                    g_per_cpu_stats[sched_getcpu()].c2s_batch_entry_overflow++;

                    /* Batch is full, flush it now to make space */
                    struct send_batch *b = &batches[batch_idx];
                    for (int k = 0; k < b->count; k++) {
                        int msg_idx = b->msg_indices[k];
                        s_iovs[k].iov_base = c_bufs[msg_idx];
                        s_iovs[k].iov_len = c_msgs[msg_idx].msg_len;
                    }
                    if (sendmmsg(b->sock, s_msgs, b->count, 0) < 0) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                            P_LOG_WARN("sendmmsg(server, batch_full): %s", strerror(errno));
                        }
                    }

                    /* Reset batch and add current packet */
                    b->count = 0;
                    batches[batch_idx].msg_indices[batches[batch_idx].count++] = i;

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
                        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                            /* Socket buffer full - rely on kernel buffering,
                             * don't queue in userspace */
                            /* This is more efficient than copying data to
                             * userspace queues */
                            g_per_cpu_stats[sched_getcpu()].c2s_batch_socket_overflow++;
                            break;
                        }
                        P_LOG_WARN("sendmmsg(server) failed: %s, attempted=%d, "
                                   "remaining=%d",
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
                        P_LOG_INFO("sendmmsg(server) partial: sent=%d, remaining=%d", sent, remaining);
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

    int r = recvfrom(lsn_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&cli_addr, &cli_alen);
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

    if (!(conn = proxy_conn_get_or_create(&cli_addr, epfd)))
        return;

    /* refresh activity */
    touch_proxy_conn(conn);

    ssize_t wr = send(conn->svr_sock, buffer, r, 0);
    if (wr < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        P_LOG_WARN("send(server): %s", strerror(errno));
    }
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
    const int max_iterations = 64; /* fairness cap per event */
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
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    break; /* drained */
                }
                P_LOG_WARN("recvmmsg(server): %s", strerror(errno));
                /* fatal error on server socket: close session */
                proxy_conn_put(conn, epfd);
            }
            return;
        }

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
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                break; /* drained */
            P_LOG_WARN("recv(server): %s", strerror(errno));
            /* fatal error on server socket: close session */
            proxy_conn_put(conn, epfd);
            break;
        }

        /* r >= 0: forward even zero-length datagrams */
        touch_proxy_conn(conn);

        ssize_t wr = sendto(lsn_sock, buffer, r, 0, (struct sockaddr *)&conn->cli_addr,
                            sizeof_sockaddr(&conn->cli_addr));
        if (wr < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            P_LOG_WARN("sendto(client): %s", strerror(errno));
        }

        if (r < (int)sizeof(buffer)) {
            break; /* Drained */
        }
    }
#endif
}

#ifdef __linux__
static void init_batching_resources(struct mmsghdr **c_msgs, struct iovec **c_iov,
                                    struct sockaddr_storage **c_addrs,
                                    char (**c_bufs)[UDP_PROXY_DGRAM_CAP], struct mmsghdr **s_msgs,
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

static void destroy_batching_resources(struct mmsghdr *c_msgs, struct iovec *c_iov,
                                       struct sockaddr_storage *c_addrs,
                                       char (*c_bufs)[UDP_PROXY_DGRAM_CAP], struct mmsghdr *s_msgs,
                                       struct iovec *s_iovs) {
    free(c_msgs);
    free(c_iov);
    free(c_addrs);
    free(c_bufs);
    free(s_msgs);
    free(s_iovs);
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
    struct mmsghdr *c_msgs = NULL, *s_msgs = NULL;
    struct iovec *c_iov = NULL, *s_iovs = NULL;
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
    }

    if (g_cfg.pidfile) {
        if (create_pid_file(g_cfg.pidfile) != 0)
            return 1;
    }

    /* Initialize Per-CPU Stats */
    g_per_cpu_stats = calloc(g_num_cpus, sizeof(struct per_cpu_stats));
    if (!g_per_cpu_stats) {
        P_LOG_ERR("Failed to allocate per-CPU stats");
        goto cleanup;
    }

    /* Initialize LRU caches */
    g_lru_caches = calloc(NUM_LRU_SEGMENTS, sizeof(struct lru_cache));
    if (!g_lru_caches) {
        P_LOG_ERR("Failed to allocate LRU caches");
        goto cleanup;
    }
    for (i = 0; i < NUM_LRU_SEGMENTS; i++) {
        INIT_LIST_HEAD(&g_lru_caches[i].list);
        if (pthread_mutex_init(&g_lru_caches[i].lock, NULL) != 0) {
            P_LOG_ERR("Failed to initialize LRU cache lock %d", i);
            goto cleanup;
        }
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
            free(conn_tbl_locks);
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
    init_batching_resources(&c_msgs, &c_iov, &c_addrs, &c_bufs, &s_msgs, &s_iovs);
#endif

    if (init_rate_limiter(g_cfg.max_per_ip_connections, 0, 0) != 0) {
        P_LOG_ERR("Failed to initialize rate limiter");
        rc = 1;
        goto cleanup;
    }
    atexit(destroy_rate_limiter);

    /* Main event loop */
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

        /* Periodic timeout check and connection recycling */
        if ((long)(current_ts - last_check) >= 2) {
            proxy_conn_walk_continue(epfd);
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

        if (g_shutdown_requested)
            break;

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
                handle_client_data(listen_sock, epfd, c_msgs, s_msgs, s_iovs, c_bufs);
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
#if ENABLE_BACKPRESSURE_QUEUE
    destroy_backpressure_queue();
#endif
#ifdef __linux__
    destroy_batching_resources(c_msgs, c_iov, c_addrs, c_bufs, s_msgs, s_iovs);
#endif

    print_final_stats();

    closelog();

    return rc;
}
