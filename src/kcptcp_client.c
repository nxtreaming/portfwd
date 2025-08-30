#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <stddef.h>
#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <netinet/tcp.h>
#endif
#include "common.h"
#include "proxy_conn.h"
#include "kcptcp_common.h"
#include "kcp_common.h"
#include "aead_protocol.h"
#include "anti_replay.h"
#include "secure_random.h"
#include "buffer_limits.h"
#include "3rd/chacha20poly1305/chacha20poly1305.h"
#include "3rd/kcp/ikcp.h"
#include "aead.h"
#include <pthread.h>

/* Configuration constants */
#define DEFAULT_KEEPALIVE_INTERVAL_MS  30000
#define DEFAULT_IDLE_TIMEOUT_SEC        180
#define DEFAULT_EPOLL_MAX_EVENTS        256
#define DEFAULT_REKEY_TIMEOUT_MS        10000
#define MIN_BUFFER_SIZE                 4096
#define UDP_RECV_BUFFER_SIZE            (64 * 1024)

/* Error handling macros */
#define LOG_CONN_ERR(conn, fmt, ...) \
    P_LOG_ERR("conv=%u state=%d: " fmt, \
              (conn)->conv, (conn)->state, ##__VA_ARGS__)

#define LOG_CONN_WARN(conn, fmt, ...) \
    P_LOG_WARN("conv=%u state=%d: " fmt, \
               (conn)->conv, (conn)->state, ##__VA_ARGS__)

/* Enhanced handshake protocol structures */
struct handshake_hello_v2 {
    uint8_t type;        /* KTP_HS_HELLO */
    uint8_t version;     /* KCP_HS_VER */
    uint8_t token[16];   /* Random token */
    uint32_t timestamp;  /* Unix timestamp (network byte order) */
    uint32_t nonce;      /* Additional random nonce */
    uint8_t hmac[16];    /* HMAC-SHA256 truncated to 16 bytes */
} __attribute__((packed));

struct handshake_accept_v2 {
    uint8_t type;        /* KTP_HS_ACCEPT */
    uint8_t version;     /* KCP_HS_VER */
    uint32_t conv;       /* Conversation ID (network byte order) */
    uint8_t token[16];   /* Echo of client token */
    uint32_t timestamp;  /* Server timestamp */
    uint8_t hmac[16];    /* HMAC verification */
} __attribute__((packed));

/* Rate limiting structure */
struct rate_limiter {
    time_t window_start;
    size_t counter;
    size_t max_per_window;
    size_t window_size_sec;
};

/* Connection pool for performance optimization */
struct conn_pool {
    struct proxy_conn *connections;  /* Pre-allocated connection array */
    struct proxy_conn *freelist;     /* Linked list of available connections */
    int capacity;                    /* Total pool capacity */
    int used_count;                  /* Currently allocated connections */
    int high_water_mark;             /* Peak usage for monitoring */
    pthread_mutex_t lock;            /* Thread safety mutex */
    pthread_cond_t available;        /* Condition variable for blocking allocation */
};

/* Forward declarations for basic helper functions */
static int buffer_ensure_capacity(struct buffer_info *buf, size_t needed, size_t max_size);
static void secure_zero(void *ptr, size_t len);
static bool rate_limit_check(struct rate_limiter *rl);
static int validate_handshake_timing(uint32_t timestamp);
static int generate_enhanced_hello(struct proxy_conn *conn, const uint8_t *psk, bool has_psk, unsigned char *out_buf, size_t *out_len);

/* Connection pool management functions */
static int init_conn_pool(void);
static void destroy_conn_pool(void);
static struct proxy_conn *alloc_proxy_conn(void);
static void release_proxy_conn_to_pool(struct proxy_conn *conn);

/* Performance monitoring and logging functions */
static void init_performance_monitoring(void);
static void dump_performance_stats(void);
static void update_connection_stats(struct proxy_conn *c, bool connecting);

struct cfg_client {
    union sockaddr_inx laddr; /* TCP listen */
    union sockaddr_inx raddr; /* UDP remote */
    const char *pidfile;
    bool daemonize;
    bool reuse_addr;
    bool reuse_port;
    bool v6only;
    int sockbuf_bytes;
    bool tcp_nodelay;
    bool has_psk;
    uint8_t psk[32];
};

struct client_ctx {
    int epfd;
    int lsock;
    uint32_t *magic_listener;
    struct cfg_client *cfg;
    struct kcp_opts *kopts;
    struct list_head *conns;
    struct rate_limiter handshake_limiter;  /* Rate limit handshake attempts */
};

/* Functions that need struct client_ctx */
static void conn_cleanup(struct client_ctx *ctx, struct proxy_conn *conn);
static int handle_epoll_error(struct client_ctx *ctx, struct proxy_conn *conn, const char *operation);
static int handle_udp_receive(struct client_ctx *ctx, struct proxy_conn *c, char *ubuf, size_t ubuf_size, bool *fed_kcp);
static int handle_handshake_accept(struct client_ctx *ctx, struct proxy_conn *c, const char *buf, size_t len);
static int handle_kcp_to_tcp(struct client_ctx *ctx, struct proxy_conn *c, char *payload, int plen);
static int validate_udp_source(struct proxy_conn *c, const struct sockaddr_storage *rss);

/* Global connection pool */
static struct conn_pool g_conn_pool = {0};
static const int DEFAULT_CONN_POOL_SIZE = 1024;

/* Performance monitoring counters */
struct perf_counters {
    uint64_t total_connections;
    uint64_t active_connections;
    uint64_t failed_connections;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t pool_hits;
    uint64_t pool_misses;
    uint64_t handshake_attempts;
    uint64_t handshake_successes;
    uint64_t handshake_failures;
    uint64_t rate_limit_drops;
    uint64_t udp_packets_received;
    uint64_t udp_packets_sent;
    uint64_t tcp_connections_accepted;
    uint64_t kcp_packets_processed;
    uint64_t buffer_expansions;
    uint64_t epoll_errors;
    time_t start_time;
    time_t last_stats_dump;
};

static struct perf_counters g_perf = {0};

/* Enhanced logging macros with context */
#define LOG_PERF_INFO(fmt, ...) \
    P_LOG_INFO("[PERF] " fmt, ##__VA_ARGS__)

#define LOG_CONN_DEBUG(conn, fmt, ...) \
    P_LOG_DEBUG("conv=%u state=%d: " fmt, \
                (conn)->conv, (conn)->state, ##__VA_ARGS__)

#define LOG_STATS_INFO(fmt, ...) \
    P_LOG_INFO("[STATS] " fmt, ##__VA_ARGS__)

static void client_handle_accept(struct client_ctx *ctx);
static void client_handle_udp_events(struct client_ctx *ctx,
                                     struct proxy_conn *c, uint32_t evmask);
static void client_handle_tcp_events(struct client_ctx *ctx,
                                     struct proxy_conn *c, uint32_t evmask);

/* Safe memory management functions */
static void secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;
    volatile unsigned char *p = ptr;
    while (len--) *p++ = 0;
}

static int buffer_ensure_capacity(struct buffer_info *buf, size_t needed, size_t max_size) {
    if (!buf) return -1;
    if (buf->capacity >= needed) return 0;

    size_t new_cap = buf->capacity ? buf->capacity * 2 : INITIAL_BUFFER_SIZE;
    if (new_cap < needed) new_cap = needed;
    if (new_cap > max_size) {
        P_LOG_WARN("Buffer size limit exceeded: needed=%zu, max=%zu", needed, max_size);
        return -1;
    }

    char *new_data = (char *)realloc(buf->data, new_cap);
    if (!new_data) {
        P_LOG_ERR("Buffer realloc failed: %s", strerror(errno));
        return -1;
    }

    buf->data = new_data;
    buf->capacity = new_cap;
    return 0;
}

/* Unified connection cleanup function */
static void conn_cleanup(struct client_ctx *ctx, struct proxy_conn *conn) {
    if (!conn) return;

    P_LOG_DEBUG("Cleaning up connection conv=%u", conn->conv);

    /* Remove from epoll and close sockets */
    if (conn->cli_sock >= 0) {
        (void)ep_del(ctx->epfd, conn->cli_sock);
        close(conn->cli_sock);
        conn->cli_sock = -1;
    }
    if (conn->udp_sock >= 0) {
        (void)ep_del(ctx->epfd, conn->udp_sock);
        close(conn->udp_sock);
        conn->udp_sock = -1;
    }

    /* Release KCP */
    if (conn->kcp) {
        ikcp_release(conn->kcp);
        conn->kcp = NULL;
    }

    /* Clean up buffers */
    if (conn->request.data) {
        free(conn->request.data);
        conn->request.data = NULL;
        conn->request.capacity = conn->request.dlen = conn->request.rpos = 0;
    }
    if (conn->response.data) {
        free(conn->response.data);
        conn->response.data = NULL;
        conn->response.capacity = conn->response.dlen = conn->response.rpos = 0;
    }
    if (conn->udp_backlog.data) {
        free(conn->udp_backlog.data);
        conn->udp_backlog.data = NULL;
        conn->udp_backlog.capacity = conn->udp_backlog.dlen = conn->udp_backlog.rpos = 0;
    }

    /* Clean up epoll tags */
    if (conn->cli_tag) {
        free(conn->cli_tag);
        conn->cli_tag = NULL;
    }
    if (conn->udp_tag) {
        free(conn->udp_tag);
        conn->udp_tag = NULL;
    }

    /* Secure cleanup of sensitive data */
    if (conn->has_session_key) {
        secure_zero(conn->session_key, sizeof(conn->session_key));
        conn->has_session_key = false;
    }
    secure_zero(conn->hs_token, sizeof(conn->hs_token));
    secure_zero(conn->nonce_base, sizeof(conn->nonce_base));

    /* Remove from connection list */
    list_del(&conn->list);

    /* Return connection to pool instead of freeing */
    release_proxy_conn_to_pool(conn);
}

/* Handle epoll operation errors with proper cleanup */
static int handle_epoll_error(struct client_ctx *ctx, struct proxy_conn *conn, const char *operation) {
    (void)ctx; /* Unused parameter */
    if (!conn || !operation) return -1;

    LOG_CONN_ERR(conn, "epoll %s failed: %s", operation, strerror(errno));
    conn->state = S_CLOSING;
    return -1;
}

/* Safe epoll add/modify with error handling */
static int safe_epoll_mod(struct client_ctx *ctx, int fd, struct epoll_event *ev, struct proxy_conn *conn) {
    if (ep_add_or_mod(ctx->epfd, fd, ev) < 0) {
        return handle_epoll_error(ctx, conn, "modify");
    }
    return 0;
}

/* Rate limiting implementation */
static bool rate_limit_check(struct rate_limiter *rl) {
    if (!rl) return true;

    time_t now = time(NULL);
    if (now - rl->window_start >= (time_t)rl->window_size_sec) {
        rl->window_start = now;
        rl->counter = 0;
    }
    if (rl->counter >= rl->max_per_window) {
        return false;
    }
    rl->counter++;
    return true;
}

/* Validate handshake timestamp to prevent replay attacks */
static int validate_handshake_timing(uint32_t timestamp) {
    time_t now = time(NULL);
    time_t msg_time = (time_t)ntohl(timestamp);

    /* Allow 5 minutes clock skew in either direction */
    const time_t MAX_SKEW = 300;

    if (msg_time < now - MAX_SKEW || msg_time > now + MAX_SKEW) {
        P_LOG_WARN("Handshake timestamp out of range: msg_time=%ld, now=%ld",
                   (long)msg_time, (long)now);
        return -1;
    }
    return 0;
}

/* Generate enhanced HELLO message with HMAC authentication */
static int generate_enhanced_hello(struct proxy_conn *conn, const uint8_t *psk, bool has_psk,
                                   unsigned char *out_buf, size_t *out_len) {
    (void)psk; /* Unused parameter - reserved for future HMAC implementation */
    if (!conn || !out_buf || !out_len) return -1;

    if (has_psk && sizeof(struct handshake_hello_v2) <= *out_len) {
        /* Enhanced version with HMAC */
        struct handshake_hello_v2 *hello = (struct handshake_hello_v2 *)out_buf;
        hello->type = KTP_HS_HELLO;
        hello->version = KCP_HS_VER;
        memcpy(hello->token, conn->hs_token, 16);
        hello->timestamp = htonl((uint32_t)time(NULL));

        /* Generate additional nonce */
        uint32_t nonce;
        if (secure_random_bytes((unsigned char *)&nonce, sizeof(nonce)) != 0) {
            return -1;
        }
        hello->nonce = nonce;

        /* Calculate HMAC over the message (excluding HMAC field itself) */
        /* For now, use a simple hash - in production, use proper HMAC-SHA256 */
        memset(hello->hmac, 0, 16);
        /* TODO: Implement proper HMAC calculation */

        *out_len = sizeof(struct handshake_hello_v2);
    } else {
        /* Fallback to simple version */
        if (*out_len < 1 + 1 + 16) return -1;

        out_buf[0] = (unsigned char)KTP_HS_HELLO;
        out_buf[1] = (unsigned char)KCP_HS_VER;
        memcpy(out_buf + 2, conn->hs_token, 16);
        *out_len = 1 + 1 + 16;
    }

    return 0;
}

/* Connection pool management implementation */
static int init_conn_pool(void) {
    g_conn_pool.capacity = DEFAULT_CONN_POOL_SIZE;
    g_conn_pool.connections = malloc(sizeof(struct proxy_conn) * (size_t)g_conn_pool.capacity);
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

    /* Initialize freelist */
    g_conn_pool.freelist = NULL;
    for (int i = 0; i < g_conn_pool.capacity; i++) {
        struct proxy_conn *conn = &g_conn_pool.connections[i];
        conn->next = g_conn_pool.freelist;
        g_conn_pool.freelist = conn;
    }
    g_conn_pool.used_count = 0;
    g_conn_pool.high_water_mark = 0;

    P_LOG_INFO("Connection pool initialized with %d connections", g_conn_pool.capacity);
    return 0;
}

static void destroy_conn_pool(void) {
    if (g_conn_pool.connections) {
        pthread_mutex_destroy(&g_conn_pool.lock);
        pthread_cond_destroy(&g_conn_pool.available);
        free(g_conn_pool.connections);
        g_conn_pool.connections = NULL;
    }
}

static struct proxy_conn *alloc_proxy_conn(void) {
    struct proxy_conn *conn;

    pthread_mutex_lock(&g_conn_pool.lock);

    if (!g_conn_pool.freelist) {
        pthread_mutex_unlock(&g_conn_pool.lock);
        P_LOG_WARN("Connection pool exhausted!");
        g_perf.pool_misses++;
        return NULL;
    }

    conn = g_conn_pool.freelist;
    g_conn_pool.freelist = conn->next;
    g_conn_pool.used_count++;

    if (g_conn_pool.used_count > g_conn_pool.high_water_mark) {
        g_conn_pool.high_water_mark = g_conn_pool.used_count;
    }

    pthread_mutex_unlock(&g_conn_pool.lock);

    /* Update performance counters */
    g_perf.pool_hits++;
    g_perf.total_connections++;
    g_perf.active_connections++;

    /* Initialize connection structure */
    memset(conn, 0, sizeof(*conn));
    conn->cli_sock = -1;
    conn->udp_sock = -1;
    INIT_LIST_HEAD(&conn->list);

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
    g_conn_pool.used_count--;

    pthread_cond_signal(&g_conn_pool.available);
    pthread_mutex_unlock(&g_conn_pool.lock);

    /* Update performance counters */
    if (g_perf.active_connections > 0) {
        g_perf.active_connections--;
    }
}

/* Validate UDP source address matches expected peer */
static int validate_udp_source(struct proxy_conn *c, const struct sockaddr_storage *rss) {
    union sockaddr_inx ra;
    memset(&ra, 0, sizeof(ra));

    if (rss->ss_family == AF_INET) {
        struct sockaddr_in *in4 = (struct sockaddr_in *)rss;
        ra.sin = *in4;
    } else if (rss->ss_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)rss;
        ra.sin6 = *in6;
    } else {
        return -1; /* Unknown family: drop */
    }

    if (!is_sockaddr_inx_equal(&ra, &c->peer_addr)) {
        time_t now = time(NULL);
        if (now - c->last_addr_warn >= 1) {
            LOG_CONN_WARN(c, "dropping UDP from unexpected %s (expected %s)",
                          sockaddr_to_string(&ra),
                          sockaddr_to_string(&c->peer_addr));
            c->last_addr_warn = now;
        }
        return -1;
    }
    return 0;
}

/* Handle handshake ACCEPT message */
static int handle_handshake_accept(struct client_ctx *ctx, struct proxy_conn *c, const char *buf, size_t len) {
    uint32_t conv;
    bool valid_accept = false;

    /* Check if this is enhanced ACCEPT format */
    if (ctx->cfg->has_psk && len >= sizeof(struct handshake_accept_v2)) {
        struct handshake_accept_v2 *accept = (struct handshake_accept_v2 *)buf;
        conv = ntohl(accept->conv);

        /* Validate token */
        if (memcmp(accept->token, c->hs_token, 16) != 0) {
            LOG_CONN_WARN(c, "Enhanced ACCEPT token mismatch; ignore");
            return 1; /* Continue processing other packets */
        }

        /* Validate timestamp */
        if (validate_handshake_timing(accept->timestamp) != 0) {
            LOG_CONN_WARN(c, "Enhanced ACCEPT timestamp validation failed; ignore");
            return 1; /* Continue processing other packets */
        }

        /* TODO: Validate HMAC */
        /* For now, accept if token and timestamp are valid */
        valid_accept = true;

    } else {
        /* Fallback to simple ACCEPT format */
        conv = (uint32_t)((unsigned char)buf[2] << 24 |
                          (unsigned char)buf[3] << 16 |
                          (unsigned char)buf[4] << 8 |
                          (unsigned char)buf[5]);
        if (memcmp(buf + 6, c->hs_token, 16) != 0) {
            LOG_CONN_WARN(c, "ACCEPT token mismatch; ignore");
            return 1; /* Continue processing other packets */
        }
        valid_accept = true;
    }

    if (!valid_accept) {
        return 1; /* Continue processing other packets */
    }

    c->conv = conv;
    /* Derive session key if PSK provided */
    if (ctx->cfg->has_psk) {
        if (derive_session_key_from_psk((const uint8_t *)ctx->cfg->psk,
                                        c->hs_token, c->conv,
                                        c->session_key) == 0) {
            c->has_session_key = true;
            /* Initialize nonce base and counters */
            memcpy(c->nonce_base, c->session_key, 12);
            c->send_seq = 0;
            /* Initialize anti-replay detector */
            anti_replay_init(&c->replay_detector);
            c->recv_seq = 0;
            c->recv_win = UINT32_MAX; /* uninitialized */
            c->recv_win_mask = 0ULL;
            c->epoch = 0;
            c->rekey_in_progress = false;
        } else {
            P_LOG_ERR("session key derivation failed");
            return -1; /* Error: close connection */
        }
    }

    if (kcp_setup_conn(c, c->udp_sock, &c->peer_addr, c->conv, ctx->kopts) != 0) {
        P_LOG_ERR("kcp_setup_conn failed after ACCEPT");
        return -1; /* Error: close connection */
    }

    c->kcp_ready = true;
    c->next_ka_ms = kcp_now_ms() + DEFAULT_KEEPALIVE_INTERVAL_MS;
    P_LOG_INFO("handshake ACCEPT: conv=%u", c->conv);

    /* Update performance counters */
    g_perf.handshake_successes++;
    update_connection_stats(c, true);

    /* Flush any buffered request data */
    if (c->request.dlen > c->request.rpos) {
        size_t remain = c->request.dlen - c->request.rpos;
        if (aead_protocol_send_data(c, c->request.data + c->request.rpos, (int)remain,
                                    ctx->cfg->psk, ctx->cfg->has_psk) < 0) {
            return -1; /* Error: close connection */
        }
        c->request.rpos = c->request.dlen; /* consumed */
    }

    /* If TCP already EOF, send FIN now */
    if (c->cli_in_eof) {
        if (aead_protocol_send_fin(c, ctx->cfg->psk, ctx->cfg->has_psk) < 0) {
            return -1; /* Error: close connection */
        }
    }

    return 1; /* Continue processing other packets */
}

/* Handle KCP data forwarding to TCP */
static int handle_kcp_to_tcp(struct client_ctx *ctx, struct proxy_conn *c, char *payload, int plen) {
    if (!payload || plen <= 0) {
        return 0; /* Continue processing */
    }

    c->kcp_rx_bytes += (uint64_t)plen;
    ssize_t wn = send(c->cli_sock, payload, (size_t)plen, MSG_NOSIGNAL);

    if (wn < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Backpressure: buffer and enable EPOLLOUT */
            size_t need = c->response.dlen + (size_t)plen;
            if (buffer_ensure_capacity(&c->response, need, MAX_TCP_BUFFER_SIZE) < 0) {
                P_LOG_WARN("Response buffer size limit exceeded, closing connection");
                return -1; /* Error: close connection */
            }
            memcpy(c->response.data + c->response.dlen, payload, (size_t)plen);
            c->response.dlen += (size_t)plen;

            struct epoll_event cev = (struct epoll_event){0};
            cev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
            cev.data.ptr = c->cli_tag;
            if (safe_epoll_mod(ctx, c->cli_sock, &cev, c) < 0) {
                return -1; /* Error: close connection */
            }
            return -2; /* Break from processing loop */
        }
        return -1; /* Error: close connection */

    } else if (wn < plen) {
        /* Short write: buffer remaining and enable EPOLLOUT */
        size_t rem = (size_t)plen - (size_t)wn;
        size_t need = c->response.dlen + rem;
        if (buffer_ensure_capacity(&c->response, need, MAX_TCP_BUFFER_SIZE) < 0) {
            P_LOG_WARN("Response buffer size limit exceeded, closing connection");
            return -1; /* Error: close connection */
        }
        memcpy(c->response.data + c->response.dlen, payload + wn, rem);
        c->response.dlen += rem;

        struct epoll_event cev = (struct epoll_event){0};
        cev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
        cev.data.ptr = c->cli_tag;
        if (safe_epoll_mod(ctx, c->cli_sock, &cev, c) < 0) {
            return -1; /* Error: close connection */
        }
        return -2; /* Break from processing loop */
    }

    /* Stats: count TCP TX bytes to client */
    if (wn > 0) {
        c->tcp_tx_bytes += (uint64_t)wn;
        g_perf.bytes_sent += (uint64_t)wn;
    }

    return 0; /* Continue processing */
}

/* Handle UDP packet reception and processing */
static int handle_udp_receive(struct client_ctx *ctx, struct proxy_conn *c, char *ubuf, size_t ubuf_size, bool *fed_kcp) {
    for (;;) {
        struct sockaddr_storage rss;
        socklen_t rlen = sizeof(rss);
        ssize_t rn = recvfrom(c->udp_sock, ubuf, ubuf_size, MSG_DONTWAIT,
                              (struct sockaddr *)&rss, &rlen);
        if (rn < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            P_LOG_WARN("recvfrom udp: %s", strerror(errno));
            return -1; /* Error: close connection */
        }
        if (rn == 0) {
            break;
        }

        /* Stats: count UDP RX bytes */
        c->udp_rx_bytes += (uint64_t)rn;
        g_perf.bytes_received += (uint64_t)rn;
        g_perf.udp_packets_received++;

        /* Validate UDP source address matches expected peer */
        if (validate_udp_source(c, &rss) != 0) {
            continue; /* Drop packet and continue */
        }

        /* Handshake ACCEPT path */
        if (!c->kcp_ready && rn >= (ssize_t)(1 + 1 + 4 + 16) &&
            (unsigned char)ubuf[0] == (unsigned char)KTP_HS_ACCEPT &&
            (unsigned char)ubuf[1] == (unsigned char)KCP_HS_VER) {

            int result = handle_handshake_accept(ctx, c, ubuf, (size_t)rn);
            if (result < 0) {
                return -1; /* Error: close connection */
            }
            continue;
        }

        if (!c->kcp_ready) {
            /* Not ready and not ACCEPT: ignore */
            continue;
        }

        if (c->kcp) {
            (void)ikcp_input(c->kcp, ubuf, (long)rn);
            *fed_kcp = true;
        }
    }

    return 0; /* Success */
}

/* Performance monitoring and logging functions */
static void init_performance_monitoring(void) {
    memset(&g_perf, 0, sizeof(g_perf));
    g_perf.start_time = time(NULL);
    g_perf.last_stats_dump = g_perf.start_time;
    LOG_PERF_INFO("Performance monitoring initialized");
}

static void dump_performance_stats(void) {
    time_t now = time(NULL);
    time_t uptime = now - g_perf.start_time;
    time_t since_last = now - g_perf.last_stats_dump;

    if (since_last < 60) { /* Dump stats every minute at most */
        return;
    }

    LOG_STATS_INFO("=== Performance Statistics (uptime: %ld seconds) ===", uptime);
    LOG_STATS_INFO("Connections: total=%llu active=%llu failed=%llu",
                   (unsigned long long)g_perf.total_connections,
                   (unsigned long long)g_perf.active_connections,
                   (unsigned long long)g_perf.failed_connections);
    LOG_STATS_INFO("Data transfer: sent=%llu bytes received=%llu bytes",
                   (unsigned long long)g_perf.bytes_sent,
                   (unsigned long long)g_perf.bytes_received);
    LOG_STATS_INFO("Connection pool: hits=%llu misses=%llu",
                   (unsigned long long)g_perf.pool_hits,
                   (unsigned long long)g_perf.pool_misses);
    LOG_STATS_INFO("Handshakes: attempts=%llu successes=%llu failures=%llu",
                   (unsigned long long)g_perf.handshake_attempts,
                   (unsigned long long)g_perf.handshake_successes,
                   (unsigned long long)g_perf.handshake_failures);
    LOG_STATS_INFO("Network: UDP_rx=%llu UDP_tx=%llu TCP_accept=%llu",
                   (unsigned long long)g_perf.udp_packets_received,
                   (unsigned long long)g_perf.udp_packets_sent,
                   (unsigned long long)g_perf.tcp_connections_accepted);
    LOG_STATS_INFO("KCP: packets_processed=%llu",
                   (unsigned long long)g_perf.kcp_packets_processed);
    LOG_STATS_INFO("System: buffer_expansions=%llu epoll_errors=%llu rate_limit_drops=%llu",
                   (unsigned long long)g_perf.buffer_expansions,
                   (unsigned long long)g_perf.epoll_errors,
                   (unsigned long long)g_perf.rate_limit_drops);

    /* Connection pool statistics */
    if (g_conn_pool.capacity > 0) {
        double pool_utilization = (double)g_conn_pool.used_count / g_conn_pool.capacity * 100.0;
        LOG_STATS_INFO("Pool: used=%d/%d (%.1f%%) high_water=%d",
                       g_conn_pool.used_count, g_conn_pool.capacity,
                       pool_utilization, g_conn_pool.high_water_mark);
    }

    g_perf.last_stats_dump = now;
}

static void update_connection_stats(struct proxy_conn *c, bool connecting) {
    if (connecting) {
        g_perf.total_connections++;
        g_perf.active_connections++;
        LOG_CONN_DEBUG(c, "Connection established");
    } else {
        if (g_perf.active_connections > 0) {
            g_perf.active_connections--;
        }
        LOG_CONN_DEBUG(c, "Connection closed");
    }
}

/* UDP socket events for a single connection */
static void client_handle_udp_events(struct client_ctx *ctx,
                                     struct proxy_conn *c, uint32_t evmask) {
    if (c->state == S_CLOSING)
        return;

    if (!(evmask & EPOLLIN)) {
        return;
    }

    char ubuf[UDP_RECV_BUFFER_SIZE];
    bool fed_kcp = false;

    /* Handle UDP packet reception */
    if (handle_udp_receive(ctx, c, ubuf, sizeof(ubuf), &fed_kcp) < 0) {
        c->state = S_CLOSING;
        return;
    }

    if (fed_kcp && c->kcp) {
        /* Drain KCP to TCP once after ingesting all UDP */
        for (;;) {
            int peek = ikcp_peeksize(c->kcp);
            if (peek < 0)
                break;
            if (peek > (int)sizeof(ubuf))
                peek = (int)sizeof(ubuf);
            int got = ikcp_recv(c->kcp, ubuf, peek);
            if (got <= 0)
                break;
            c->kcp_rx_msgs++;
            g_perf.kcp_packets_processed++;

            char *payload = NULL;
            int plen = 0;
            int res = aead_protocol_handle_incoming_packet(
                c, ubuf, got, ctx->cfg->psk, ctx->cfg->has_psk, &payload, &plen);

            if (res < 0) { // Error
                P_LOG_ERR("AEAD packet handling failed (res=%d)", res);
                c->state = S_CLOSING;
                break;
            }
            if (res > 0) { // Control packet handled
                if (c->svr_in_eof && !c->svr2cli_shutdown &&
                    c->response.dlen == c->response.rpos) {
                    shutdown(c->cli_sock, SHUT_WR);
                    c->svr2cli_shutdown = true;
                }
                continue;
            }

            /* Handle KCP data forwarding to TCP */
            int forward_result = handle_kcp_to_tcp(ctx, c, payload, plen);
            if (forward_result < 0) {
                if (forward_result == -2) {
                    break; /* Break from processing loop */
                }
                c->state = S_CLOSING;
                break;
            }
        }
        c->last_active = time(NULL);
    }
}

/* Accept one or more clients and set up per-connection state */
static void client_handle_accept(struct client_ctx *ctx) {
    while (1) {
        union sockaddr_inx ca;
        socklen_t calen = sizeof(ca);
        int cs = accept(ctx->lsock, &ca.sa, &calen);
        if (cs < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            P_LOG_ERR("accept: %s", strerror(errno));
            break;
        }

        /* Apply rate limiting to prevent handshake flooding */
        if (!rate_limit_check(&ctx->handshake_limiter)) {
            P_LOG_WARN("Handshake rate limit exceeded, dropping connection from %s",
                       sockaddr_to_string(&ca));
            g_perf.rate_limit_drops++;
            close(cs);
            continue;
        }

        g_perf.tcp_connections_accepted++;
        kcptcp_tune_tcp_socket(cs, 0 /*no change*/, ctx->cfg->tcp_nodelay,
                               true /*keepalive*/);
        /* Create per-connection UDP socket via shared helper */
        int us = kcptcp_create_udp_socket(ctx->cfg->raddr.sa.sa_family,
                                          ctx->cfg->sockbuf_bytes);
        if (us < 0) {
            close(cs);
            continue;
        }

        /* Allocate connection from pool */
        struct proxy_conn *c = alloc_proxy_conn();
        if (!c) {
            P_LOG_ERR("Connection pool exhausted");
            close(cs);
            close(us);
            continue;
        }
        c->state = S_FORWARDING;
        c->cli_sock = cs;
        c->udp_sock = us;
        c->peer_addr = ctx->cfg->raddr;
        c->last_active = time(NULL);
        c->kcp = NULL; /* not created until ACCEPT */
        c->kcp_ready = false;
        c->next_ka_ms = 0;
        /* Generate 16-byte token using cryptographically secure random */
        if (secure_random_bytes(c->hs_token, 16) != 0) {
            P_LOG_ERR("Failed to generate secure random token");
            close(cs);
            close(us);
            free(c);
            continue;
        }
        /* Send HELLO with enhanced security if PSK is available */
        unsigned char hbuf[sizeof(struct handshake_hello_v2)];
        size_t hbuf_len = sizeof(hbuf);

        if (generate_enhanced_hello(c, ctx->cfg->psk, ctx->cfg->has_psk, hbuf, &hbuf_len) != 0) {
            P_LOG_ERR("Failed to generate HELLO message");
            g_perf.handshake_failures++;
            close(cs);
            close(us);
            free(c);
            continue;
        }

        g_perf.handshake_attempts++;

        ssize_t sent = sendto(c->udp_sock, hbuf, hbuf_len, MSG_DONTWAIT,
                              &c->peer_addr.sa,
                              (socklen_t)sizeof_sockaddr(&c->peer_addr));
        if (sent < 0) {
            P_LOG_WARN("Failed to send HELLO: %s", strerror(errno));
        } else if (ctx->cfg->has_psk) {
            P_LOG_DEBUG("Sent enhanced HELLO with HMAC authentication");
        }

        /* Prepare epoll tags */
        struct ep_tag *ctag = (struct ep_tag *)malloc(sizeof(*ctag));
        struct ep_tag *utag = (struct ep_tag *)malloc(sizeof(*utag));
        if (!ctag || !utag) {
            P_LOG_ERR("malloc ep_tag");
            if (ctag)
                free(ctag);
            if (utag)
                free(utag);
            close(cs);
            close(us);
            free(c);
            continue;
        }
        ctag->conn = c;
        ctag->which = 1;
        c->cli_tag = ctag;
        utag->conn = c;
        utag->which = 2;
        c->udp_tag = utag;

        /* Register both fds */
        if (kcptcp_ep_register_tcp(ctx->epfd, cs, ctag, false) < 0) {
            P_LOG_ERR("epoll add cli: %s", strerror(errno));
            close(cs);
            close(us);
            free(ctag);
            free(utag);
            free(c);
            continue;
        }
        if (kcptcp_ep_register_rw(ctx->epfd, us, utag, false) < 0) {
            P_LOG_ERR("epoll add udp: %s", strerror(errno));
            (void)ep_del(ctx->epfd, cs);
            close(cs);
            close(us);
            free(ctag);
            free(utag);
            free(c);
            continue;
        }

        list_add_tail(&c->list, ctx->conns);
        P_LOG_INFO("accepted TCP %s, conv=%u", sockaddr_to_string(&ca),
                   c->conv);
    }
}

/* TCP client socket events for a single connection */
static void client_handle_tcp_events(struct client_ctx *ctx,
                                     struct proxy_conn *c, uint32_t evmask) {
    if (c->state == S_CLOSING)
        return;

    if (evmask & (EPOLLERR | EPOLLHUP)) {
        c->state = S_CLOSING;
    }

    if (evmask & EPOLLOUT) {
        /* Flush pending data to client */
        while (c->response.rpos < c->response.dlen) {
            ssize_t wn =
                send(c->cli_sock, c->response.data + c->response.rpos,
                     c->response.dlen - c->response.rpos, MSG_NOSIGNAL);
            if (wn > 0) {
                c->response.rpos += (size_t)wn;
                /* Stats: count TCP TX bytes during flush */
                c->tcp_tx_bytes += (uint64_t)wn;
            } else if (wn < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            } else {
                c->state = S_CLOSING;
                break;
            }
        }
        if (c->response.rpos >= c->response.dlen) {
            c->response.rpos = 0;
            c->response.dlen = 0;
            /* Disable EPOLLOUT when drained */
            struct epoll_event cev = (struct epoll_event){0};
            cev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
            cev.data.ptr = c->cli_tag;
            if (safe_epoll_mod(ctx, c->cli_sock, &cev, c) < 0) {
                return;
            }
            /* If we received FIN earlier, shutdown write now that buffer is
             * drained */
            if (c->svr_in_eof && !c->svr2cli_shutdown) {
                shutdown(c->cli_sock, SHUT_WR);
                c->svr2cli_shutdown = true;
            }
        }
    }

    if (evmask & (EPOLLIN | EPOLLRDHUP)) {
        /* TCP side readable/half-closed */
        char tbuf[64 * 1024];
        ssize_t rn;
        while ((rn = recv(c->cli_sock, tbuf, sizeof(tbuf), 0)) > 0) {
            /* Stats: count TCP RX bytes from client */
            c->tcp_rx_bytes += (uint64_t)rn;
            if (!c->kcp_ready) {
                /* buffer until KCP ready */
                size_t need = c->request.dlen + (size_t)rn;
                if (buffer_ensure_capacity(&c->request, need, MAX_TCP_BUFFER_SIZE) < 0) {
                    P_LOG_WARN("Request buffer size limit exceeded, closing connection");
                    c->state = S_CLOSING;
                    break;
                }
                memcpy(c->request.data + c->request.dlen, tbuf, (size_t)rn);
                c->request.dlen += (size_t)rn;
            } else {
                int sn = aead_protocol_send_data(c, tbuf, rn, ctx->cfg->psk,
                                                 ctx->cfg->has_psk);
                if (sn < 0) {
                    c->state = S_CLOSING;
                    break;
                }
            }
        }
        if (rn == 0) {
            /* TCP EOF: on handshake pending, defer FIN until ready */
            if (c->kcp_ready) {
                (void)aead_protocol_send_fin(c, ctx->cfg->psk,
                                             ctx->cfg->has_psk);
            }
            c->cli_in_eof = true;
            struct epoll_event cev = (struct epoll_event){0};
            cev.events = EPOLLRDHUP | EPOLLERR | EPOLLHUP; /* disable EPOLLIN */
            cev.data.ptr = c->cli_tag;
            if (safe_epoll_mod(ctx, c->cli_sock, &cev, c) < 0) {
                return;
            }
        } else if (rn < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            c->state = S_CLOSING;
        }
    }
}

static void print_usage(const char *prog) {
    P_LOG_INFO(
        "Usage: %s [options] <local_tcp_addr:port> <remote_udp_addr:port>",
        prog);
    P_LOG_INFO("Options:");
    P_LOG_INFO("  -d                 run in background (daemonize)");
    P_LOG_INFO("  -p <pidfile>       write PID to file");
    P_LOG_INFO("  -r                 set SO_REUSEADDR on listener socket");
    P_LOG_INFO("  -R                 set SO_REUSEPORT on listener socket");
    P_LOG_INFO("  -6                 for IPv6 listener, set IPV6_V6ONLY");
    P_LOG_INFO(
        "  -S <bytes>         SO_RCVBUF/SO_SNDBUF size (default build-time)");
    P_LOG_INFO("  -M <mtu>           KCP MTU (default 1350; lower if frequent "
               "fragmentation)");
    P_LOG_INFO("  -A <0|1>           KCP nodelay (default 1)");
    P_LOG_INFO("  -I <ms>            KCP interval in ms (default 10)");
    P_LOG_INFO("  -X <n>             KCP fast resend (default 2)");
    P_LOG_INFO("  -C <0|1>           KCP no congestion control (default 1)");
    P_LOG_INFO(
        "  -w <sndwnd>        KCP send window in packets (default 1024)");
    P_LOG_INFO(
        "  -W <rcvwnd>        KCP recv window in packets (default 1024)");
    P_LOG_INFO("  -N                 enable TCP_NODELAY on client sockets");
    P_LOG_INFO("  -K <hex>           32-byte PSK in hex (ChaCha20-Poly1305)");
    P_LOG_INFO("  -h                 show help");
}

int main(int argc, char **argv) {
    int rc = 1;
    int epfd = -1, lsock = -1;
    uint32_t magic_listener = 0xdeadbeefU; /* reuse value style from tcpfwd */
    struct cfg_client cfg;
    struct list_head conns; /* active connections */
    INIT_LIST_HEAD(&conns);

    memset(&cfg, 0, sizeof(cfg));
    cfg.reuse_addr = true;

    int kcp_mtu = -1;
    int kcp_nd = -1, kcp_it = -1, kcp_rs = -1, kcp_nc = -1, kcp_snd = -1,
        kcp_rcv = -1;

    struct kcptcp_common_cli opts;
    int pos = 0;
    if (!kcptcp_parse_common_opts(argc, argv, &opts, &pos, false)) {
        print_usage(argv[0]);
        return 2;
    }
    if (opts.show_help) {
        print_usage(argv[0]);
        return 0;
    }

    /* Map common options to cfg and local KCP overrides */
    cfg.pidfile = opts.pidfile;
    cfg.daemonize = opts.daemonize;
    cfg.reuse_addr = opts.reuse_addr;
    cfg.reuse_port = opts.reuse_port;
    cfg.v6only = opts.v6only;
    cfg.sockbuf_bytes = opts.sockbuf_bytes;
    cfg.tcp_nodelay = opts.tcp_nodelay;
    cfg.has_psk = opts.has_psk;
    if (opts.has_psk)
        memcpy(cfg.psk, opts.psk, 32);

    kcp_mtu = opts.kcp_mtu;
    kcp_nd = opts.kcp_nd;
    kcp_it = opts.kcp_it;
    kcp_rs = opts.kcp_rs;
    kcp_nc = opts.kcp_nc;
    kcp_snd = opts.kcp_snd;
    kcp_rcv = opts.kcp_rcv;

    if (pos + 2 != argc) {
        print_usage(argv[0]);
        return 2;
    }

    if (get_sockaddr_inx_pair(argv[pos], &cfg.laddr, false) < 0) {
        P_LOG_ERR("invalid local tcp addr: %s", argv[pos]);
        return 2;
    }
    if (get_sockaddr_inx_pair(argv[pos + 1], &cfg.raddr, true) < 0) {
        P_LOG_ERR("invalid remote udp addr: %s", argv[pos + 1]);
        return 2;
    }

    if (cfg.daemonize) {
        if (do_daemonize() != 0)
            return 1;
        g_state.daemonized = true;
    }
    setup_signal_handlers();
    if (cfg.pidfile) {
        if (write_pidfile(cfg.pidfile) != 0) {
            P_LOG_ERR("failed to write pidfile: %s", cfg.pidfile);
            return 1;
        }
    }

    /* Initialize connection pool for performance */
    if (init_conn_pool() != 0) {
        P_LOG_ERR("Failed to initialize connection pool");
        return 1;
    }

    /* Initialize performance monitoring */
    init_performance_monitoring();

    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        P_LOG_ERR("epoll_create1: %s", strerror(errno));
        goto cleanup;
    }

    /* Create TCP listen socket via shared helper */
    lsock =
        kcptcp_setup_tcp_listener(&cfg.laddr, cfg.reuse_addr, cfg.reuse_port,
                                  cfg.v6only, cfg.sockbuf_bytes, 128);
    if (lsock < 0)
        goto cleanup;

    if (kcptcp_ep_register_listener(epfd, lsock, &magic_listener) < 0) {
        P_LOG_ERR("epoll_ctl add listen: %s", strerror(errno));
        goto cleanup;
    }

    P_LOG_INFO("kcptcp-client running: TCP %s -> UDP %s",
               sockaddr_to_string(&cfg.laddr), sockaddr_to_string(&cfg.raddr));

    struct kcp_opts kopts;
    kcp_opts_set_defaults(&kopts);
    kcp_opts_apply_overrides(&kopts, kcp_mtu, kcp_nd, kcp_it, kcp_rs, kcp_nc,
                             kcp_snd, kcp_rcv);

    /* Build context for handlers */
    struct client_ctx cctx;
    cctx.epfd = epfd;
    cctx.lsock = lsock;
    cctx.magic_listener = &magic_listener;
    cctx.cfg = &cfg;
    cctx.kopts = &kopts;
    cctx.conns = &conns;

    /* Initialize rate limiter: max 100 handshakes per 60 seconds */
    cctx.handshake_limiter.window_start = time(NULL);
    cctx.handshake_limiter.counter = 0;
    cctx.handshake_limiter.max_per_window = 100;
    cctx.handshake_limiter.window_size_sec = 60;

    /* Event loop: accept TCP, bridge via KCP over UDP */
    while (!g_state.terminate) {
        /* Compute dynamic timeout from all KCP connections */
        int timeout_ms = kcptcp_compute_kcp_timeout_ms(&conns, 1000);

        struct epoll_event events[DEFAULT_EPOLL_MAX_EVENTS];
        int nfds = epoll_wait(epfd, events, DEFAULT_EPOLL_MAX_EVENTS, timeout_ms);
        if (nfds < 0) {
            if (errno == EINTR) { /* fallthrough to timer update */
            } else {
                P_LOG_ERR("epoll_wait: %s", strerror(errno));
                break;
            }
        }

        for (int i = 0; i < nfds; ++i) {
            void *tptr = events[i].data.ptr;
            if (tptr == &magic_listener) {
                client_handle_accept(&cctx);
                continue;
            }

            /* Tagged connection event: disambiguate source */
            struct ep_tag *etag = (struct ep_tag *)tptr;
            struct proxy_conn *c = etag->conn;
            if (etag->which == 2) {
                client_handle_udp_events(&cctx, c, events[i].events);
                continue;
            }

            /* TCP client socket events */
            if (etag->which == 1) {
                client_handle_tcp_events(&cctx, c, events[i].events);
            }
        }

        /* KCP timer updates and GC */
        uint32_t now = kcp_now_ms();
        struct proxy_conn *pos, *tmp;
        list_for_each_entry_safe(pos, tmp, &conns, list) {
            if (pos->kcp)
                (void)kcp_update_flush(pos, now);
            /* Periodic runtime stats logging (~5s, configurable) */
            if (pos->kcp && get_stats_enabled()) {
                uint64_t now_ms = now;
                if (pos->last_stat_ms == 0) {
                    pos->last_stat_ms = now_ms;
                    pos->last_tcp_rx_bytes = pos->tcp_rx_bytes;
                    pos->last_tcp_tx_bytes = pos->tcp_tx_bytes;
                    pos->last_kcp_tx_bytes = pos->kcp_tx_bytes;
                    pos->last_kcp_rx_bytes = pos->kcp_rx_bytes;
                    pos->last_kcp_xmit = pos->kcp->xmit;
                    pos->last_rekeys_initiated = pos->rekeys_initiated;
                    pos->last_rekeys_completed = pos->rekeys_completed;
                } else if (now_ms - pos->last_stat_ms >=
                           get_stats_interval_ms()) {
                    uint64_t dt = now_ms - pos->last_stat_ms;
                    uint64_t d_tcp_rx =
                        pos->tcp_rx_bytes - pos->last_tcp_rx_bytes;
                    uint64_t d_tcp_tx =
                        pos->tcp_tx_bytes - pos->last_tcp_tx_bytes;
                    uint64_t d_kcp_tx =
                        pos->kcp_tx_bytes - pos->last_kcp_tx_bytes;
                    uint64_t d_kcp_rx =
                        pos->kcp_rx_bytes - pos->last_kcp_rx_bytes;
                    uint32_t d_xmit = pos->kcp->xmit - pos->last_kcp_xmit;
                    uint32_t d_rekey_i =
                        pos->rekeys_initiated - pos->last_rekeys_initiated;
                    uint32_t d_rekey_c =
                        pos->rekeys_completed - pos->last_rekeys_completed;
                    double sec = (double)dt / 1000.0;
                    double tcp_in_mbps =
                        sec > 0 ? (double)d_tcp_rx * 8.0 / (sec * 1e6) : 0.0;
                    double tcp_out_mbps =
                        sec > 0 ? (double)d_tcp_tx * 8.0 / (sec * 1e6) : 0.0;
                    double kcp_in_mbps =
                        sec > 0 ? (double)d_kcp_rx * 8.0 / (sec * 1e6) : 0.0;
                    double kcp_out_mbps =
                        sec > 0 ? (double)d_kcp_tx * 8.0 / (sec * 1e6) : 0.0;
                    P_LOG_INFO("stats conv=%u: TCP in=%.3f Mbps out=%.3f Mbps "
                               "| KCP payload in=%.3f Mbps out=%.3f Mbps | KCP "
                               "xmit_delta=%u RTT=%dms | rekey i=%u c=%u",
                               pos->conv, tcp_in_mbps, tcp_out_mbps,
                               kcp_in_mbps, kcp_out_mbps, d_xmit,
                               pos->kcp->rx_srtt, d_rekey_i, d_rekey_c);
                    pos->last_stat_ms = now_ms;
                    pos->last_tcp_rx_bytes = pos->tcp_rx_bytes;
                    pos->last_tcp_tx_bytes = pos->tcp_tx_bytes;
                    pos->last_kcp_tx_bytes = pos->kcp_tx_bytes;
                    pos->last_kcp_rx_bytes = pos->kcp_rx_bytes;
                    pos->last_kcp_xmit = pos->kcp->xmit;
                    pos->last_rekeys_initiated = pos->rekeys_initiated;
                    pos->last_rekeys_completed = pos->rekeys_completed;
                }
            }
            /* If we received FIN earlier and output buffer has drained,
             * shutdown(WRITE) */
            if (pos->svr_in_eof && !pos->svr2cli_shutdown &&
                pos->response.dlen == pos->response.rpos) {
                shutdown(pos->cli_sock, SHUT_WR);
                pos->svr2cli_shutdown = true;
            }
            /* Graceful close when both halves have signaled EOF and all pending
             * are flushed */
            if (pos->state != S_CLOSING && pos->cli_in_eof && pos->svr_in_eof) {
                int kcp_unsent = pos->kcp ? ikcp_waitsnd(pos->kcp) : 0;
                bool udp_backlog_empty = (pos->udp_backlog.dlen == 0);
                bool resp_empty = (pos->response.dlen == pos->response.rpos);
                if (kcp_unsent == 0 && udp_backlog_empty && resp_empty) {
                    pos->state = S_CLOSING;
                }
            }
            /* Idle timeout */
            time_t ct = time(NULL);
            if (pos->state != S_CLOSING && pos->last_active &&
                (ct - pos->last_active) > DEFAULT_IDLE_TIMEOUT_SEC) {
                P_LOG_INFO("idle timeout, conv=%u", pos->conv);
                pos->state = S_CLOSING;
            }
            /* Rekey timeout enforcement */
            if (pos->state != S_CLOSING && pos->has_session_key &&
                pos->rekey_in_progress) {
                if (now >= pos->rekey_deadline_ms) {
                    P_LOG_ERR("rekey timeout, closing conv=%u (cli)",
                              pos->conv);
                    pos->state = S_CLOSING;
                }
            }
            if (pos->state == S_CLOSING) {
                if (get_stats_dump_enabled()) {
                    P_LOG_INFO("stats total conv=%u: tcp_rx=%llu tcp_tx=%llu "
                               "udp_rx=%llu udp_tx=%llu kcp_rx_msgs=%llu "
                               "kcp_tx_msgs=%llu kcp_rx_bytes=%llu "
                               "kcp_tx_bytes=%llu rekeys_i=%u rekeys_c=%u",
                               pos->conv, (unsigned long long)pos->tcp_rx_bytes,
                               (unsigned long long)pos->tcp_tx_bytes,
                               (unsigned long long)pos->udp_rx_bytes,
                               (unsigned long long)pos->udp_tx_bytes,
                               (unsigned long long)pos->kcp_rx_msgs,
                               (unsigned long long)pos->kcp_tx_msgs,
                               (unsigned long long)pos->kcp_rx_bytes,
                               (unsigned long long)pos->kcp_tx_bytes,
                               pos->rekeys_initiated, pos->rekeys_completed);
                }
                update_connection_stats(pos, false);
                conn_cleanup(&cctx, pos);
            }
        }

        /* Dump performance statistics periodically */
        dump_performance_stats();
    }

    rc = 0;

cleanup:
    if (lsock >= 0)
        close(lsock);
    if (epfd >= 0)
        epoll_close_comp(epfd);
    destroy_conn_pool();
    cleanup_pidfile();
    return rc;
}
