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
#include "outer_obfs.h"
#include "kcp_common.h"
#include "aead_protocol.h"
#include "anti_replay.h"
#include "secure_random.h"
#include "buffer_limits.h"
#include "3rd/chacha20poly1305/chacha20poly1305.h"
#include "3rd/kcp/ikcp.h"
#include "aead.h"
#include "fwd_util.h"
#include <pthread.h>

/* Configuration constants */
#define DEFAULT_KEEPALIVE_INTERVAL_MS 30000
#define DEFAULT_IDLE_TIMEOUT_SEC 180
#define DEFAULT_EPOLL_MAX_EVENTS 256
#define DEFAULT_REKEY_TIMEOUT_MS 10000
#define MIN_BUFFER_SIZE 4096
#define UDP_RECV_BUFFER_SIZE (64 * 1024)

/* Error handling macros */
#define LOG_CONN_ERR(conn, fmt, ...)                                                               \
    P_LOG_ERR("conv=%u state=%d: " fmt, (conn)->conv, (conn)->state, ##__VA_ARGS__)

#define LOG_CONN_WARN(conn, fmt, ...)                                                              \
    P_LOG_WARN("conv=%u state=%d: " fmt, (conn)->conv, (conn)->state, ##__VA_ARGS__)

#define LOG_CONN_DEBUG(conn, fmt, ...)                                                             \
    P_LOG_DEBUG("conv=%u state=%d: " fmt, (conn)->conv, (conn)->state, ##__VA_ARGS__)

/* Rate limiting structure */
struct rate_limiter {
    time_t window_start;
    size_t counter;
    size_t max_per_window;
    size_t window_size_sec;
};

/* Forward declarations for basic helper functions */
static void secure_zero(void *ptr, size_t len);
static bool rate_limit_check(struct rate_limiter *rl);
static int generate_stealth_handshake(struct proxy_conn *conn, const uint8_t *psk, bool has_psk,
                                      const uint8_t *initial_data, size_t initial_data_len,
                                      unsigned char *out_buf, size_t *out_len);

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
    uint32_t agg_min_ms;
    uint32_t agg_max_ms;
    uint32_t agg_max_bytes;
    int agg_profile_mode; /* 0=off, 1=auto, 2=list */
    uint16_t noagg_ports[64];
    int noagg_count;
};

struct client_ctx {
    int epfd;
    int lsock;
    uint32_t *magic_listener;
    struct cfg_client *cfg;
    struct kcp_opts *kopts;
    struct list_head *conns;
    struct rate_limiter handshake_limiter; /* Rate limit handshake attempts */
};

/* Functions that need struct client_ctx */
static void conn_cleanup(struct client_ctx *ctx, struct proxy_conn *conn);
static int handle_epoll_error(struct client_ctx *ctx, struct proxy_conn *conn,
                              const char *operation);
static int handle_udp_receive(struct client_ctx *ctx, struct proxy_conn *c, char *ubuf,
                              size_t ubuf_size, bool *fed_kcp);
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
#define LOG_PERF_INFO(fmt, ...) P_LOG_INFO("[PERF] " fmt, ##__VA_ARGS__)

#define LOG_CONN_DEBUG(conn, fmt, ...)                                                             \
    P_LOG_DEBUG("conv=%u state=%d: " fmt, (conn)->conv, (conn)->state, ##__VA_ARGS__)

#define LOG_STATS_INFO(fmt, ...) P_LOG_INFO("[STATS] " fmt, ##__VA_ARGS__)

static void client_handle_accept(struct client_ctx *ctx);
static void client_handle_udp_events(struct client_ctx *ctx, struct proxy_conn *c, uint32_t evmask);
static void client_handle_tcp_events(struct client_ctx *ctx, struct proxy_conn *c, uint32_t evmask);

/* Compute per-port aggregation profile. Returns effective min/max ms and max
 * bytes. Heuristics:
 *  - SSH-like (22, 2222): no aggregation, low embed cap (e.g., 256-512)
 *  - Web-like (80, 8080, 443, 8443): modest aggregation window (30-100ms),
 * larger embed
 *  - RDP/VNC (3389, 5900): very small aggregation (0-20ms), moderate embed
 *  - Default: use cfg values
 */
static void compute_agg_profile(const struct cfg_client *cfg, uint16_t listen_port,
                                uint32_t *out_min_ms, uint32_t *out_max_ms,
                                uint32_t *out_max_bytes) {
    uint32_t min_ms = cfg->agg_min_ms;
    uint32_t max_ms = cfg->agg_max_ms;
    uint32_t max_bytes = cfg->agg_max_bytes;

    /* If profile OFF: use baseline and return */
    if (cfg->agg_profile_mode == 0) {
        if (out_min_ms)
            *out_min_ms = min_ms;
        if (out_max_ms)
            *out_max_ms = max_ms;
        if (out_max_bytes)
            *out_max_bytes = max_bytes;
        return;
    }

    /* If profile LIST: if port listed, disable aggregation (no wait) */
    if (cfg->agg_profile_mode == 2) {
        for (int i = 0; i < cfg->noagg_count; ++i) {
            if (cfg->noagg_ports[i] == listen_port) {
                min_ms = 0;
                max_ms = 0;
                if (max_bytes > 512)
                    max_bytes = 512;
                if (out_min_ms)
                    *out_min_ms = min_ms;
                if (out_max_ms)
                    *out_max_ms = max_ms;
                if (out_max_bytes)
                    *out_max_bytes = max_bytes;
                return;
            }
        }
        /* Not listed: fall through to auto heuristics */
    }

    switch (listen_port) {
    case 22:
    case 2222:
        min_ms = 0;
        max_ms = 0;
        if (max_bytes > 512)
            max_bytes = 512;
        break;
    case 80:
    case 8080:
    case 443:
    case 8443:
        if (min_ms < 30)
            min_ms = 30;
        if (max_ms < 100)
            max_ms = 100;
        if (max_bytes < 1200) {
            /* keep user's smaller cap */
        } else {
            max_bytes = 1200;
        }
        break;
    case 3389: /* RDP */
    case 5900: /* VNC */
        if (max_ms > 20)
            max_ms = 20;
        if (min_ms > max_ms)
            min_ms = max_ms;
        if (max_bytes > 768)
            max_bytes = 768;
        break;
    default:
        break;
    }
    if (out_min_ms)
        *out_min_ms = min_ms;
    if (out_max_ms)
        *out_max_ms = max_ms;
    if (out_max_bytes)
        *out_max_bytes = max_bytes;
}

/* Parse CSV of port numbers into array */
static int parse_ports_csv(const char *csv, uint16_t *arr, int max, int *outn) {
    if (!csv || !arr || max <= 0 || !outn)
        return -1;
    int n = 0;
    const char *p = csv;
    while (*p) {
        while (*p == ',' || *p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        char *end = NULL;
        long v = strtol(p, &end, 10);
        if (end == p)
            break;
        if (v >= 0 && v <= 65535) {
            if (n < max) {
                arr[n++] = (uint16_t)v;
            }
        }
        p = (*end == ',') ? end + 1 : end;
    }
    *outn = n;
    return 0;
}

/* Safe memory management functions */
static void secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0)
        return;
    volatile unsigned char *p = ptr;
    while (len--)
        *p++ = 0;
}

/* Unified connection cleanup function */
static void conn_cleanup(struct client_ctx *ctx, struct proxy_conn *conn) {
    if (!conn)
        return;

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
    conn_pool_release(&g_conn_pool, conn);
}

/* Handle epoll operation errors with proper cleanup */
static int handle_epoll_error(struct client_ctx *ctx, struct proxy_conn *conn,
                              const char *operation) {
    (void)ctx; /* Unused parameter */
    if (!conn || !operation)
        return -1;

    LOG_CONN_ERR(conn, "epoll %s failed: %s", operation, strerror(errno));
    conn->state = S_CLOSING;
    return -1;
}

/* Safe epoll add/modify with error handling */
static int safe_epoll_mod(struct client_ctx *ctx, int fd, struct epoll_event *ev,
                          struct proxy_conn *conn) {
    if (ep_add_or_mod(ctx->epfd, fd, ev) < 0) {
        return handle_epoll_error(ctx, conn, "modify");
    }
    return 0;
}

/* Rate limiting implementation */
static bool rate_limit_check(struct rate_limiter *rl) {
    if (!rl)
        return true;

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

/* Generate stealth handshake first packet */
static int generate_stealth_handshake(struct proxy_conn *conn, const uint8_t *psk, bool has_psk,
                                      const uint8_t *initial_data, size_t initial_data_len,
                                      unsigned char *out_buf, size_t *out_len) {
    if (!conn || !out_buf || !out_len)
        return -1;

    /* Only support PSK version now */
    if (!has_psk || !psk) {
        P_LOG_ERR("PSK is required for stealth handshake");
        return -1;
    }

    /* Create stealth handshake packet with embedded payload */
    if (stealth_handshake_create_first_packet(psk, conn->hs_token, initial_data, initial_data_len,
                                              out_buf, out_len) != 0) {
        P_LOG_ERR("Failed to create stealth handshake packet");
        return -1;
    }

    return 0;
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
                          sockaddr_to_string(&ra), sockaddr_to_string(&c->peer_addr));
            c->last_addr_warn = now;
        }
        return -1;
    }
    return 0;
}

/* Handle stealth handshake response */
static int handle_stealth_handshake_response(struct client_ctx *ctx, struct proxy_conn *c,
                                             const char *buf, size_t len) {
    /* Only support PSK stealth handshake */
    if (!ctx->cfg->has_psk) {
        LOG_CONN_ERR(c, "PSK is required for stealth handshake");
        return -1; /* Error: close connection */
    }

    /* Try to parse as stealth handshake response */
    struct stealth_handshake_response response;
    if (stealth_handshake_parse_response(ctx->cfg->psk, (const uint8_t *)buf, len, &response) !=
        0) {
        LOG_CONN_DEBUG(c, "Failed to parse stealth handshake response; ignore");
        return 1; /* Continue processing other packets */
    }

    /* Validate token */
    if (memcmp(response.token, c->hs_token, 16) != 0) {
        LOG_CONN_DEBUG(c, "Stealth response token mismatch; ignore");
        return 1; /* Continue processing other packets */
    }

    c->conv = ntohl(response.conv);
    /* Derive session key if PSK provided */
    if (derive_session_key_from_psk((const uint8_t *)ctx->cfg->psk, c->hs_token, c->conv,
                                    c->session_key) != 0) {
        P_LOG_ERR("session key derivation failed");
        return -1; /* Error: close connection */
    }
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

    /* pass PSK to proxy_conn for outer obfs */
    c->cfg_has_psk = ctx->cfg->has_psk;
    if (c->cfg_has_psk) memcpy(c->cfg_psk, ctx->cfg->psk, 32);
    if (kcp_setup_conn(c, c->udp_sock, &c->peer_addr, c->conv, ctx->kopts) != 0) {
        P_LOG_ERR("kcp_setup_conn failed after ACCEPT");
        return -1; /* Error: close connection */
    }

    c->kcp_ready = true;
    c->next_ka_ms = kcp_now_ms() + DEFAULT_KEEPALIVE_INTERVAL_MS;
    P_LOG_INFO("stealth handshake established: conv=%u", c->conv);

    /* Update performance counters */
    g_perf.handshake_successes++;
    update_connection_stats(c, true);

    /* Flush any buffered request data */
    if (c->request.dlen > c->request.rpos) {
        if (!c->has_session_key) {
            LOG_CONN_ERR(c, "Missing session key before flushing buffered data");
            return -1; /* Safety guard: should never happen */
        }
        size_t remain = c->request.dlen - c->request.rpos;
        if (aead_protocol_send_data(c, c->request.data + c->request.rpos, (int)remain,
                                    ctx->cfg->psk, ctx->cfg->has_psk) < 0) {
            return -1; /* Error: close connection */
        }
        c->request.rpos = c->request.dlen; /* consumed */
    }

    /* If TCP already EOF, send FIN now */
    if (c->cli_in_eof) {
        if (!c->has_session_key) {
            LOG_CONN_ERR(c, "Missing session key before sending FIN");
            return -1; /* Safety guard */
        }
        if (aead_protocol_send_fin(c, ctx->cfg->psk, ctx->cfg->has_psk) < 0) {
            return -1; /* Error: close connection */
        }
    }

    return 0; /* signal: handled handshake */
}

/* Handle KCP data forwarding to TCP */
static int handle_kcp_to_tcp(struct client_ctx *ctx, struct proxy_conn *c, char *payload,
                             int plen) {
    if (!payload || plen <= 0) {
        return 0; /* Continue processing */
    }

    c->kcp_rx_bytes += (uint64_t)plen;
    ssize_t wn = send(c->cli_sock, payload, (size_t)plen, MSG_NOSIGNAL);

    if (wn < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Backpressure: buffer and enable EPOLLOUT */
            size_t need = c->response.dlen + (size_t)plen;
            if (ensure_buffer_capacity(&c->response, need, MAX_TCP_BUFFER_SIZE) < 0) {
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
        if (ensure_buffer_capacity(&c->response, need, MAX_TCP_BUFFER_SIZE) < 0) {
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
static int handle_udp_receive(struct client_ctx *ctx, struct proxy_conn *c, char *ubuf,
                              size_t ubuf_size, bool *fed_kcp) {
    for (;;) {
        struct sockaddr_storage rss;
        socklen_t rlen = sizeof(rss);
        ssize_t rn =
            recvfrom(c->udp_sock, ubuf, ubuf_size, MSG_DONTWAIT, (struct sockaddr *)&rss, &rlen);
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

        /* Outer unwrap: all incoming UDP packets are obfuscated with PSK */
        uint8_t inner[2048];
        size_t ilen = sizeof(inner);
        if (outer_unwrap(ctx->cfg->psk, (const uint8_t *)ubuf, (size_t)rn, inner, &ilen) != 0) {
            /* Drop silently: could be noise/spoof */
            continue;
        }

        /* Stealth handshake response path */
        if (!c->kcp_ready) {
            int result = handle_stealth_handshake_response(ctx, c, (const char *)inner, ilen);
            if (result < 0) {
                return -1; /* Error: close connection */
            } else if (result == 0) {
                /* Successfully processed stealth handshake response */
                continue;
            }
            /* If result == 1, it's not a handshake response; fall through to KCP */
        }

        if (!c->kcp_ready) {
            /* Not ready and not a valid handshake response: ignore */
            continue;
        }

        if (c->kcp) {
            (void)ikcp_input(c->kcp, (const char *)inner, (long)ilen);
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

    if (since_last < 60) {
        /* Dump stats every minute at most */
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
    LOG_STATS_INFO("Connection pool: hits=%llu misses=%llu", (unsigned long long)g_perf.pool_hits,
                   (unsigned long long)g_perf.pool_misses);
    LOG_STATS_INFO("Handshakes: attempts=%llu successes=%llu failures=%llu",
                   (unsigned long long)g_perf.handshake_attempts,
                   (unsigned long long)g_perf.handshake_successes,
                   (unsigned long long)g_perf.handshake_failures);
    LOG_STATS_INFO("Network: UDP_rx=%llu UDP_tx=%llu TCP_accept=%llu",
                   (unsigned long long)g_perf.udp_packets_received,
                   (unsigned long long)g_perf.udp_packets_sent,
                   (unsigned long long)g_perf.tcp_connections_accepted);
    LOG_STATS_INFO("KCP: packets_processed=%llu", (unsigned long long)g_perf.kcp_packets_processed);
    LOG_STATS_INFO("System: buffer_expansions=%llu epoll_errors=%llu "
                   "rate_limit_drops=%llu",
                   (unsigned long long)g_perf.buffer_expansions,
                   (unsigned long long)g_perf.epoll_errors,
                   (unsigned long long)g_perf.rate_limit_drops);

    /* Connection pool statistics */
    if (g_conn_pool.capacity > 0) {
        double pool_utilization = (double)g_conn_pool.used_count / g_conn_pool.capacity * 100.0;
        LOG_STATS_INFO("Pool: used=%zu/%zu (%.1f%%) high_water=%zu", g_conn_pool.used_count,
                       g_conn_pool.capacity, pool_utilization, g_conn_pool.high_water_mark);
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
static void client_handle_udp_events(struct client_ctx *ctx, struct proxy_conn *c,
                                     uint32_t evmask) {
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
            int res = aead_protocol_handle_incoming_packet(c, ubuf, got, ctx->cfg->psk,
                                                           ctx->cfg->has_psk, &payload, &plen);

            if (res < 0) {
                // Error
                P_LOG_ERR("AEAD packet handling failed (res=%d)", res);
                c->state = S_CLOSING;
                break;
            }
            if (res > 0) {
                // Control packet handled
                if (c->svr_in_eof && !c->svr2cli_shutdown && c->response.dlen == c->response.rpos) {
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
        kcptcp_tune_tcp_socket(cs, 0 /*no change*/, ctx->cfg->tcp_nodelay, true /*keepalive*/);
        /* Create per-connection UDP socket via shared helper */
        int us = kcptcp_create_udp_socket(ctx->cfg->raddr.sa.sa_family, ctx->cfg->sockbuf_bytes);
        if (us < 0) {
            close(cs);
            continue;
        }

        /* Allocate connection from pool */
        struct proxy_conn *c = (struct proxy_conn *)conn_pool_alloc(&g_conn_pool);
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
            conn_pool_release(&g_conn_pool, c);
            continue;
        }
        /* Determine effective aggregation profile for this listen port */
        uint16_t lport = 0;
        if (ctx->cfg->laddr.sa.sa_family == AF_INET) {
            lport = ntohs(ctx->cfg->laddr.sin.sin_port);
        } else if (ctx->cfg->laddr.sa.sa_family == AF_INET6) {
            lport = ntohs(ctx->cfg->laddr.sin6.sin6_port);
        }
        uint32_t eff_min_ms = ctx->cfg->agg_min_ms;
        uint32_t eff_max_ms = ctx->cfg->agg_max_ms;
        uint32_t eff_max_bytes = ctx->cfg->agg_max_bytes;
        compute_agg_profile(ctx->cfg, lport, &eff_min_ms, &eff_max_ms, &eff_max_bytes);
        /* Cap by MTU-derived embed capacity to avoid fragmentation */
        uint32_t mtu_cap = kcptcp_stealth_embed_cap_from_mtu(ctx->kopts ? ctx->kopts->mtu : 1350);
        if (eff_max_bytes > mtu_cap)
            eff_max_bytes = mtu_cap;
        c->hs_agg_max_bytes_eff = eff_max_bytes;

        /* Pre-drain any immediately available TCP bytes into buffer */
        bool drop_conn = false;
        {
            char tbuf[1024];
            for (;;) {
                ssize_t rn = recv(cs, tbuf, sizeof(tbuf), MSG_DONTWAIT);
                if (rn > 0) {
                    c->tcp_rx_bytes += (uint64_t)rn; /* Stats: TCP RX */
                    size_t need = c->request.dlen + (size_t)rn;
                    if (ensure_buffer_capacity(&c->request, need, MAX_TCP_BUFFER_SIZE) < 0) {
                        P_LOG_WARN("Request buffer size limit exceeded, "
                                   "closing connection");
                        close(cs);
                        close(us);
                        conn_pool_release(&g_conn_pool, c);
                        drop_conn = true;
                        break;
                    }
                    memcpy(c->request.data + c->request.dlen, tbuf, (size_t)rn);
                    c->request.dlen += (size_t)rn;
                    if (c->request.dlen >= eff_max_bytes)
                        break;
                } else {
                    break;
                }
            }
        }
        if (drop_conn) {
            continue;
        }

        /* Schedule stealth handshake send with small randomized aggregation
         * window */
        uint32_t jitter = rand_between(eff_min_ms, eff_max_ms);
        c->hs_scheduled = true;
        c->hs_send_at_ms = kcp_now_ms() + jitter;

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
            conn_pool_release(&g_conn_pool, c);
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
            conn_pool_release(&g_conn_pool, c);
            continue;
        }
        if (kcptcp_ep_register_rw(ctx->epfd, us, utag, false) < 0) {
            P_LOG_ERR("epoll add udp: %s", strerror(errno));
            (void)ep_del(ctx->epfd, cs);
            close(cs);
            close(us);
            free(ctag);
            free(utag);
            conn_pool_release(&g_conn_pool, c);
            continue;
        }

        list_add_tail(&c->list, ctx->conns);
        P_LOG_INFO("accepted TCP %s, conv=%u", sockaddr_to_string(&ca), c->conv);
    }
}

/* TCP client socket events for a single connection */
static void client_handle_tcp_events(struct client_ctx *ctx, struct proxy_conn *c,
                                     uint32_t evmask) {
    if (c->state == S_CLOSING)
        return;

    if (evmask & (EPOLLERR | EPOLLHUP)) {
        c->state = S_CLOSING;
    }

    if (evmask & EPOLLOUT) {
        /* Flush pending data to client */
        while (c->response.rpos < c->response.dlen) {
            ssize_t wn = send(c->cli_sock, c->response.data + c->response.rpos,
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
                if (ensure_buffer_capacity(&c->request, need, MAX_TCP_BUFFER_SIZE) < 0) {
                    P_LOG_WARN("Request buffer size limit exceeded, closing "
                               "connection");
                    c->state = S_CLOSING;
                    break;
                }
                memcpy(c->request.data + c->request.dlen, tbuf, (size_t)rn);
                c->request.dlen += (size_t)rn;
            } else {
                int sn = aead_protocol_send_data(c, tbuf, rn, ctx->cfg->psk, ctx->cfg->has_psk);
                if (sn < 0) {
                    c->state = S_CLOSING;
                    break;
                }
            }
        }
        if (rn == 0) {
            /* TCP EOF: on handshake pending, defer FIN until ready */
            if (c->kcp_ready) {
                (void)aead_protocol_send_fin(c, ctx->cfg->psk, ctx->cfg->has_psk);
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
    P_LOG_INFO("Usage: %s [options] <local_tcp_addr:port> <remote_udp_addr:port>", prog);
    P_LOG_INFO("Options:");
    P_LOG_INFO("  -d                 run in background (daemonize)");
    P_LOG_INFO("  -p <pidfile>       write PID to file");
    P_LOG_INFO("  -r                 set SO_REUSEADDR on listener socket");
    P_LOG_INFO("  -R                 set SO_REUSEPORT on listener socket");
    P_LOG_INFO("  -6                 for IPv6 listener, set IPV6_V6ONLY");
    P_LOG_INFO("  -S <bytes>         SO_RCVBUF/SO_SNDBUF size (default build-time)");
    P_LOG_INFO("  -M <mtu>           KCP MTU (default 1350; lower if frequent "
               "fragmentation)");
    P_LOG_INFO("  -A <0|1>           KCP nodelay (default 1)");
    P_LOG_INFO("  -I <ms>            KCP interval in ms (default 10)");
    P_LOG_INFO("  -X <n>             KCP fast resend (default 2)");
    P_LOG_INFO("  -C <0|1>           KCP no congestion control (default 1)");
    P_LOG_INFO("  -w <sndwnd>        KCP send window in packets (default 1024)");
    P_LOG_INFO("  -W <rcvwnd>        KCP recv window in packets (default 1024)");
    P_LOG_INFO("  -N                 enable TCP_NODELAY on client sockets");
    P_LOG_INFO("  -K <hex>           32-byte PSK in hex (ChaCha20-Poly1305) "
               "[REQUIRED]");
    P_LOG_INFO("  -g <min-max>       aggregate first TCP bytes for min-max ms "
               "before sending first UDP packet");
    P_LOG_INFO("  -G <bytes>         max bytes to embed into first UDP packet "
               "(default 1024)");
    P_LOG_INFO("  -P off|auto|csv:<ports> per-port aggregation profile (client)\n"
               "                         off: disable per-port heuristics\n"
               "                         auto: enable built-in profiles\n"
               "                         csv: comma-separated ports with no "
               "aggregation");
    P_LOG_INFO("  -h                 show help");
    P_LOG_INFO(" ");
    P_LOG_INFO("Note: PSK (-K) is required for secure handshake authentication.");
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
    int kcp_nd = -1, kcp_it = -1, kcp_rs = -1, kcp_nc = -1, kcp_snd = -1, kcp_rcv = -1;

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
    cfg.agg_min_ms = opts.hs_agg_min_ms;
    cfg.agg_max_ms = opts.hs_agg_max_ms;
    cfg.agg_max_bytes = opts.hs_agg_max_bytes;
    /* Per-port profiling mode */
    cfg.agg_profile_mode = 1; /* default auto */
    cfg.noagg_count = 0;
    if (opts.hs_profile) {
        if (strcmp(opts.hs_profile, "off") == 0) {
            cfg.agg_profile_mode = 0;
        } else if (strcmp(opts.hs_profile, "auto") == 0) {
            cfg.agg_profile_mode = 1;
        } else if (strncmp(opts.hs_profile, "csv:", 4) == 0) {
            cfg.agg_profile_mode = 2;
            (void)parse_ports_csv(opts.hs_profile + 4, cfg.noagg_ports,
                                  (int)(sizeof(cfg.noagg_ports) / sizeof(cfg.noagg_ports[0])),
                                  &cfg.noagg_count);
        } else {
            /* Treat as CSV directly */
            cfg.agg_profile_mode = 2;
            (void)parse_ports_csv(opts.hs_profile, cfg.noagg_ports,
                                  (int)(sizeof(cfg.noagg_ports) / sizeof(cfg.noagg_ports[0])),
                                  &cfg.noagg_count);
        }
    }

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

    /* PSK is now required for all connections */
    if (!cfg.has_psk) {
        P_LOG_ERR("PSK (-K option) is required for secure handshake");
        return 2;
    }

    if (cfg.daemonize) {
        if (cfg.daemonize && do_daemonize() != 0)
            return 1;
        g_state.daemonized = true;
    }
    if (init_signals() != 0) {
        return 1;
    }
    if (cfg.pidfile) {
        if (create_pid_file(cfg.pidfile) != 0) {
            P_LOG_ERR("failed to write pidfile: %s", cfg.pidfile);
            return 1;
        }
    }

    /* Initialize connection pool for performance */
    if (conn_pool_init(&g_conn_pool, DEFAULT_CONN_POOL_SIZE, sizeof(struct proxy_conn)) != 0) {
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
    lsock = kcptcp_setup_tcp_listener(&cfg.laddr, cfg.reuse_addr, cfg.reuse_port, cfg.v6only,
                                      cfg.sockbuf_bytes, 128);
    if (lsock < 0)
        goto cleanup;

    if (kcptcp_ep_register_listener(epfd, lsock, &magic_listener) < 0) {
        P_LOG_ERR("epoll_ctl add listen: %s", strerror(errno));
        goto cleanup;
    }

    P_LOG_INFO("kcptcp-client running: TCP %s -> UDP %s", sockaddr_to_string(&cfg.laddr),
               sockaddr_to_string(&cfg.raddr));

    struct kcp_opts kopts;
    kcp_opts_set_defaults(&kopts);
    kcp_opts_apply_overrides(&kopts, kcp_mtu, kcp_nd, kcp_it, kcp_rs, kcp_nc, kcp_snd, kcp_rcv);

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
    while (!g_shutdown_requested) {
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
            /* Send scheduled stealth handshake if due */
            if (!pos->kcp_ready && pos->hs_scheduled) {
                if ((int32_t)(now - pos->hs_send_at_ms) >= 0) {
                    unsigned char hbuf[1500];
                    size_t hlen = sizeof(hbuf);
                    size_t avail = (pos->request.dlen > pos->request.rpos)
                                       ? (pos->request.dlen - pos->request.rpos)
                                       : 0;
                    size_t embed = avail;
                    if (embed > pos->hs_agg_max_bytes_eff)
                        embed = pos->hs_agg_max_bytes_eff;
                    const uint8_t *idata =
                        (embed > 0) ? (const uint8_t *)(pos->request.data + pos->request.rpos)
                                    : NULL;
                    if (generate_stealth_handshake(pos, cctx.cfg->psk, cctx.cfg->has_psk, idata,
                                                   embed, hbuf, &hlen) == 0) {
                        /* Outer obfuscation for handshake packet too */
                        {
                            uint8_t obuf[1600];
                            size_t olen = sizeof(obuf);
                            const uint8_t *key = cctx.cfg->psk; /* PSK for outer layer */
                            if (outer_wrap(key, hbuf, hlen, obuf, &olen, 31) == 0) {
                                ssize_t sent = sendto(pos->udp_sock, obuf, olen, MSG_DONTWAIT,
                                                       &pos->peer_addr.sa,
                                                       (socklen_t)sizeof_sockaddr(&pos->peer_addr));
                                if (sent >= 0) {
                                    g_perf.handshake_attempts++;
                                    P_LOG_DEBUG("Sent stealth handshake packet (%zu bytes)", olen);
                                    pos->hs_scheduled = false;
                                    pos->request.rpos += embed;
                                } else {
                                    P_LOG_WARN("Failed to send stealth handshake: %s", strerror(errno));
                                    pos->hs_send_at_ms = now + 5;
                                }
                            } else {
                                ssize_t sent =
                                    sendto(pos->udp_sock, hbuf, hlen, MSG_DONTWAIT, &pos->peer_addr.sa,
                                           (socklen_t)sizeof_sockaddr(&pos->peer_addr));
                                if (sent >= 0) {
                                    g_perf.handshake_attempts++;
                                    P_LOG_DEBUG("Sent stealth handshake packet (%zu bytes)", hlen);
                                    pos->hs_scheduled = false;
                                    pos->request.rpos += embed;
                                } else {
                                    P_LOG_WARN("Failed to send stealth handshake: %s", strerror(errno));
                                    pos->hs_send_at_ms = now + 5;
                                }
                            }
                        }
                        if (sent >= 0) {
                            g_perf.handshake_attempts++;
                            P_LOG_DEBUG("Sent stealth handshake packet (%zu bytes)", hlen);
                            pos->hs_scheduled = false;
                            pos->request.rpos += embed; /* mark embedded data consumed */
                        } else {
                            P_LOG_WARN("Failed to send stealth handshake: %s", strerror(errno));
                            /* Try again shortly */
                            pos->hs_send_at_ms = now + 5;
                        }
                    } else {
                        P_LOG_ERR("Failed to generate stealth handshake packet");
                        g_perf.handshake_failures++;
                        pos->state = S_CLOSING;
                    }
                }
            }
            if (pos->kcp)
                (void)kcp_update_flush(pos, now);
            kcptcp_maybe_log_stats(pos, now);
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
            if (pos->state != S_CLOSING && pos->has_session_key && pos->rekey_in_progress) {
                if (now >= pos->rekey_deadline_ms) {
                    P_LOG_ERR("rekey timeout, closing conv=%u (cli)", pos->conv);
                    pos->state = S_CLOSING;
                }
            }
            if (pos->state == S_CLOSING) {
                kcptcp_log_total_stats(pos);
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
    conn_pool_destroy(&g_conn_pool);
    cleanup_pidfile();
    return rc;
}
