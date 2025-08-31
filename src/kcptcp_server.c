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
#include "fwd_util.h"
#include "kcp_common.h"
#include "kcptcp_common.h"
#include "kcp_map.h"
#include "aead_protocol.h"
#include "aead.h"
#include "anti_replay.h"
#include "secure_random.h"
#include "buffer_limits.h"
#include "3rd/chacha20poly1305/chacha20poly1305.h"
#include "3rd/kcp/ikcp.h"
#include "fwd_util.h"
#include <pthread.h>

/* Configuration constants */
#define DEFAULT_MAX_CONNECTIONS 10000
#define DEFAULT_MAX_CONNECTIONS_PER_IP 10
#define DEFAULT_RATE_LIMIT_PER_SEC 100
#define DEFAULT_EPOLL_MAX_EVENTS 512
#define DEFAULT_IDLE_TIMEOUT_SEC 180
#define DEFAULT_HANDSHAKE_TIMEOUT_SEC 30
#define UDP_RECV_BUFFER_SIZE (64 * 1024)
#define RATE_WINDOW_SEC 1
#define MAX_REQUESTS_PER_WINDOW 10
#define HASH_TABLE_SIZE 1024
#define MAX_CONV_GENERATION_ATTEMPTS 100

/* Security structures */
struct rate_limiter_entry {
    union sockaddr_inx addr;
    time_t last_time;
    size_t count;
};

struct rate_limiter {
    struct rate_limiter_entry entries[HASH_TABLE_SIZE];
    size_t num_entries;
    pthread_mutex_t lock;
};

struct cfg_server {
    union sockaddr_inx laddr; /* UDP listen address */
    union sockaddr_inx taddr; /* TCP target address */
    bool reuse_addr;
    bool reuse_port;
    bool v6only;
    int sockbuf_bytes;
    bool tcp_nodelay;
    bool has_psk;
    uint8_t psk[32];
    uint32_t hs_rsp_jitter_min_ms;
    uint32_t hs_rsp_jitter_max_ms;
    bool daemonize;
    const char *pidfile;
};

/* Thread-safe KCP map wrapper */
struct kcp_map_safe {
    struct kcp_map map;
    pthread_rwlock_t lock;
};

struct conn_pool g_conn_pool;
static const size_t DEFAULT_CONN_POOL_SIZE = 2048;

/* Global security objects */
static struct rate_limiter g_rate_limiter = {0};
static struct conn_limiter g_conn_limiter = {0};

/* Forward declarations */
static void conn_cleanup_server(struct proxy_conn *conn, int epfd, struct kcp_map_safe *cmap);

/* Thread-safe KCP map operations */
static int kcp_map_safe_init(struct kcp_map_safe *cmap, size_t nbuckets);
static void kcp_map_safe_free(struct kcp_map_safe *cmap);
static struct proxy_conn *kcp_map_safe_get(struct kcp_map_safe *cmap, uint32_t conv);
static int kcp_map_safe_put(struct kcp_map_safe *cmap, uint32_t conv, struct proxy_conn *c);
static void kcp_map_safe_del(struct kcp_map_safe *cmap, uint32_t conv);
static uint32_t generate_secure_conv(void);
static bool rate_limit_check_addr(const union sockaddr_inx *addr);
static bool conn_limit_check(const union sockaddr_inx *addr);
static void conn_limit_release(const union sockaddr_inx *addr);
static size_t addr_hash(const union sockaddr_inx *addr);
static int safe_epoll_mod_server(int epfd, int fd, struct epoll_event *ev, struct proxy_conn *conn);
static uint32_t derive_conv_from_psk_token(const uint8_t psk[32], const uint8_t token[16]);

/* Enhanced error handling */
#define LOG_CONN_ERR(conn, fmt, ...)                                                               \
    P_LOG_ERR("conv=%u state=%d: " fmt, (conn)->conv, (conn)->state, ##__VA_ARGS__)

/* Enhanced error handling functions */

#define LOG_CONN_WARN(conn, fmt, ...)                                                              \
    P_LOG_WARN("conv=%u state=%d: " fmt, (conn)->conv, (conn)->state, ##__VA_ARGS__)

#define LOG_CONN_INFO(conn, fmt, ...)                                                              \
    P_LOG_INFO("conv=%u state=%d: " fmt, (conn)->conv, (conn)->state, ##__VA_ARGS__)

static void remove_pid_file(const char *pidfile) {
    if (pidfile) {
        if (unlink(pidfile) != 0) {
            P_LOG_WARN("Failed to remove pidfile '%s': %s", pidfile, strerror(errno));
        }
    }
}

static void print_usage(const char *prog) {
    printf("Usage: %s [options] <listen-addr> <target-addr>\n", prog);
    printf("Options:\n");
    printf("  -h, --help                 Show this help message\n");
    printf("  -K, --psk <key>            Pre-shared key for AEAD encryption (required)\n");
    printf("  --pidfile <path>           Path to PID file\n");
    printf("  --daemonize                Run as a daemon\n");
    printf("  --reuse-addr               Enable SO_REUSEADDR\n");
    printf("  --reuse-port               Enable SO_REUSEPORT\n");
    printf("  --v6only                   Enable IPV6_V6ONLY\n");
    printf("  --sockbuf <bytes>          Set socket buffer size (SO_SNDBUF/SO_RCVBUF)\n");
    printf("  --tcp-nodelay              Enable TCP_NODELAY on target connection\n");
    printf("  --hs-jitter-min <ms>       Min handshake response jitter (default: 0)\n");
    printf("  --hs-jitter-max <ms>       Max handshake response jitter (default: 0)\n");
    printf("KCP Options:\n");
    printf("  --kcp-mtu <mtu>            Set KCP MTU (default: 1400)\n");
    printf("  --kcp-nodelay <0|1>        Set KCP nodelay mode\n");
    printf("  --kcp-interval <ms>        Set KCP interval\n");
    printf("  --kcp-resend <0|1|2>       Set KCP resend mode\n");
    printf("  --kcp-nc <0|1>             Set KCP congestion control\n");
    printf("  --kcp-sndwnd <wnd>         Set KCP send window size\n");
    printf("  --kcp-rcvwnd <wnd>         Set KCP receive window size\n");
}

/* Safe epoll add/modify wrapper for server */
static int safe_epoll_mod_server(int epfd, int fd, struct epoll_event *ev,
                                 struct proxy_conn *conn) {
    if (ep_add_or_mod(epfd, fd, ev) < 0) {
        if (conn) {
            LOG_CONN_ERR(conn, "epoll modify failed: %s", strerror(errno));
            conn->state = S_CLOSING;
        }
        return -1;
    }
    return 0;
}

/* Optionally derive a deterministic conv from PSK + client token. */
static uint32_t derive_conv_from_psk_token(const uint8_t psk[32], const uint8_t token[16]) {
    if (!psk || !token)
        return 0;
    uint8_t out_key[32];
    hchacha20(psk, token, out_key);
    /* Fold first 4 bytes into 32-bit conv. Avoid 0. */
    uint32_t v = (uint32_t)out_key[0] | ((uint32_t)out_key[1] << 8) | ((uint32_t)out_key[2] << 16) |
                 ((uint32_t)out_key[3] << 24);
    if (v == 0)
        v = 1; /* avoid 0 */
    return v;
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
static void conn_cleanup_server(struct proxy_conn *conn, int epfd, struct kcp_map_safe *cmap) {
    if (!conn)
        return;

    P_LOG_DEBUG("Cleaning up server connection conv=%u", conn->conv);

    /* Remove from epoll and close socket */
    if (conn->svr_sock >= 0 && epfd >= 0) {
        (void)ep_del(epfd, conn->svr_sock);
        close(conn->svr_sock);
        conn->svr_sock = -1;
    }

    /* Remove from KCP map */
    if (cmap && conn->conv != 0) {
        kcp_map_safe_del(cmap, conn->conv);
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

    /* Secure cleanup of sensitive data */
    if (conn->has_session_key) {
        secure_zero(conn->session_key, sizeof(conn->session_key));
        secure_zero(conn->nonce_base, sizeof(conn->nonce_base));
        conn->has_session_key = false;
    }
    secure_zero(conn->hs_token, sizeof(conn->hs_token));

    /* Release connection limit for this address */
    conn_limit_release(&conn->peer_addr);

    /* Return connection to pool */
    conn_pool_release(&g_conn_pool, conn);
}

/* Address hashing function for rate limiting and connection limiting */
static size_t addr_hash(const union sockaddr_inx *addr) {
    if (!addr)
        return 0;

    if (addr->sa.sa_family == AF_INET) {
        return (size_t)addr->sin.sin_addr.s_addr;
    } else if (addr->sa.sa_family == AF_INET6) {
        const uint32_t *p = (const uint32_t *)&addr->sin6.sin6_addr;
        return (size_t)(p[0] ^ p[1] ^ p[2] ^ p[3]);
    }
    return 0;
}

/* Rate limiting implementation */
static bool rate_limit_check_addr(const union sockaddr_inx *addr) {
    if (!addr)
        return false;

    pthread_mutex_lock(&g_rate_limiter.lock);

    time_t now = time(NULL);
    size_t hash = addr_hash(addr) % HASH_TABLE_SIZE;
    struct rate_limiter_entry *entry = &g_rate_limiter.entries[hash];

    /* Check if this is a new address or hash collision */
    if (!is_sockaddr_inx_equal(&entry->addr, addr)) {
        /* New address or collision, reset entry */
        entry->addr = *addr;
        entry->last_time = now;
        entry->count = 1;
        pthread_mutex_unlock(&g_rate_limiter.lock);
        return true;
    }

    /* Check time window */
    if (now - entry->last_time > RATE_WINDOW_SEC) {
        entry->last_time = now;
        entry->count = 1;
        pthread_mutex_unlock(&g_rate_limiter.lock);
        return true;
    }

    /* Check rate limit */
    if (entry->count >= MAX_REQUESTS_PER_WINDOW) {
        pthread_mutex_unlock(&g_rate_limiter.lock);
        P_LOG_WARN("Rate limit exceeded for %s", sockaddr_to_string(addr));
        return false;
    }

    entry->count++;
    pthread_mutex_unlock(&g_rate_limiter.lock);
    return true;
}

/* Connection limiting implementation */
static bool conn_limit_check(const union sockaddr_inx *addr) {
    if (!addr)
        return false;

    pthread_mutex_lock(&g_conn_limiter.lock);

    if (g_conn_limiter.total_connections >= DEFAULT_MAX_CONNECTIONS) {
        pthread_mutex_unlock(&g_conn_limiter.lock);
        P_LOG_WARN("Total connection limit exceeded");
        return false;
    }

    /* Check per-IP connection limit */
    size_t hash = addr_hash(addr) % HASH_TABLE_SIZE;
    struct conn_limit_entry *entry = &g_conn_limiter.entries[hash];

    if (!is_sockaddr_inx_equal(&entry->addr, addr)) {
        /* New address */
        entry->addr = *addr;
        entry->count = 1;
    } else {
        if (entry->count >= DEFAULT_MAX_CONNECTIONS_PER_IP) {
            pthread_mutex_unlock(&g_conn_limiter.lock);
            P_LOG_WARN("Per-IP connection limit exceeded for %s", sockaddr_to_string(addr));
            return false;
        }
        entry->count++;
    }

    g_conn_limiter.total_connections++;
    pthread_mutex_unlock(&g_conn_limiter.lock);
    return true;
}

static void conn_limit_release(const union sockaddr_inx *addr) {
    if (!addr)
        return;

    pthread_mutex_lock(&g_conn_limiter.lock);

    size_t hash = addr_hash(addr) % HASH_TABLE_SIZE;
    struct conn_limit_entry *entry = &g_conn_limiter.entries[hash];

    if (is_sockaddr_inx_equal(&entry->addr, addr) && entry->count > 0) {
        entry->count--;
    }

    if (g_conn_limiter.total_connections > 0) {
        g_conn_limiter.total_connections--;
    }

    pthread_mutex_unlock(&g_conn_limiter.lock);
}

/* Secure conv ID generation */
static uint32_t generate_secure_conv(void) {
    static pthread_mutex_t conv_lock = PTHREAD_MUTEX_INITIALIZER;
    static uint32_t counter = 0;

    pthread_mutex_lock(&conv_lock);

    uint32_t random_part;
    if (secure_random_bytes((unsigned char *)&random_part, sizeof(random_part)) != 0) {
        /* Fail closed: return 0 to signal failure upstream */
        pthread_mutex_unlock(&conv_lock);
        return 0;
    }

    /* Combine random part with counter to ensure uniqueness */
    uint32_t conv = (random_part & 0xFFFF0000) | (++counter & 0x0000FFFF);

    pthread_mutex_unlock(&conv_lock);
    return conv;
}

static int kcp_map_safe_init(struct kcp_map_safe *cmap, size_t nbuckets) {
    if (!cmap)
        return -1;

    if (kcp_map_init(&cmap->map, nbuckets) != 0) {
        return -1;
    }

    if (pthread_rwlock_init(&cmap->lock, NULL) != 0) {
        kcp_map_free(&cmap->map);
        return -1;
    }

    return 0;
}

static void kcp_map_safe_free(struct kcp_map_safe *cmap) {
    if (!cmap)
        return;

    pthread_rwlock_wrlock(&cmap->lock);
    kcp_map_free(&cmap->map);
    pthread_rwlock_unlock(&cmap->lock);
    pthread_rwlock_destroy(&cmap->lock);
}

static struct proxy_conn *kcp_map_safe_get(struct kcp_map_safe *cmap, uint32_t conv) {
    if (!cmap)
        return NULL;

    pthread_rwlock_rdlock(&cmap->lock);
    struct proxy_conn *conn = kcp_map_get(&cmap->map, conv);
    pthread_rwlock_unlock(&cmap->lock);

    return conn;
}

static int kcp_map_safe_put(struct kcp_map_safe *cmap, uint32_t conv, struct proxy_conn *c) {
    if (!cmap)
        return -1;

    pthread_rwlock_wrlock(&cmap->lock);
    int result = kcp_map_put(&cmap->map, conv, c);
    pthread_rwlock_unlock(&cmap->lock);

    return result;
}

static void kcp_map_safe_del(struct kcp_map_safe *cmap, uint32_t conv) {
    if (!cmap)
        return;

    pthread_rwlock_wrlock(&cmap->lock);
    kcp_map_del(&cmap->map, conv);
    pthread_rwlock_unlock(&cmap->lock);
}

static int handle_system_error(const char *operation, int error_code) {
    if (!operation)
        return -1;

    switch (error_code) {
    case EAGAIN:
#if EAGAIN != EWOULDBLOCK
    case EWOULDBLOCK:
#endif
        /* Non-blocking operation would block - not really an error */
        return 0;
    case EINTR:
        /* Interrupted by signal - can retry */
        P_LOG_DEBUG("Operation %s interrupted by signal", operation);
        return 1;
    case ENOMEM:
    case ENOBUFS:
        P_LOG_ERR("Memory/buffer exhaustion in %s: %s", operation, strerror(error_code));
        return -1;
    case ECONNRESET:
    case EPIPE:
        P_LOG_INFO("Connection closed during %s: %s", operation, strerror(error_code));
        return -1;
    default:
        P_LOG_ERR("System error in %s: %s", operation, strerror(error_code));
        return -1;
    }
}

int main(int argc, char **argv) {
    int rc = 1;
    int epfd = -1, usock = -1;
    uint32_t magic_listener = 0xcafef00dU;
    struct cfg_server cfg;
    struct kcp_map_safe cmap;

    /* Initialize security components */
    if (pthread_mutex_init(&g_rate_limiter.lock, NULL) != 0) {
        P_LOG_ERR("Failed to initialize rate limiter mutex");
        return 1;
    }
    if (pthread_mutex_init(&g_conn_limiter.lock, NULL) != 0) {
        P_LOG_ERR("Failed to initialize connection limiter mutex");
        pthread_mutex_destroy(&g_rate_limiter.lock);
        return 1;
    }
    struct list_head conns;
    INIT_LIST_HEAD(&conns);

    memset(&cmap, 0, sizeof(cmap));
    memset(&cfg, 0, sizeof(cfg));
    cfg.reuse_addr = true;

    int kcp_mtu = -1;
    int kcp_nd = -1, kcp_it = -1, kcp_rs = -1, kcp_nc = -1, kcp_snd = -1, kcp_rcv = -1;

    struct kcptcp_common_cli opts;
    int pos = 0;
    if (!kcptcp_parse_common_opts(argc, argv, &opts, &pos, true)) {
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
    cfg.hs_rsp_jitter_min_ms = opts.hs_rsp_jitter_min_ms;
    cfg.hs_rsp_jitter_max_ms = opts.hs_rsp_jitter_max_ms;

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

    if (get_sockaddr_inx_pair(argv[pos], &cfg.laddr, true) < 0) {
        P_LOG_ERR("invalid local udp addr: %s", argv[pos]);
        return 2;
    }
    if (get_sockaddr_inx_pair(argv[pos + 1], &cfg.taddr, false) < 0) {
        P_LOG_ERR("invalid target tcp addr: %s", argv[pos + 1]);
        return 2;
    }

    /* PSK is now required for all connections */
    if (!cfg.has_psk) {
        P_LOG_ERR("PSK (-K option) is required for secure handshake");
        return 2;
    }

    if (cfg.daemonize) {
        if (do_daemonize() != 0)
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

    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        P_LOG_ERR("epoll_create1: %s", strerror(errno));
        goto cleanup;
    }

    /* Create UDP listen socket via shared helper */
    usock = kcptcp_setup_udp_listener(&cfg.laddr, cfg.reuse_addr, cfg.reuse_port, cfg.v6only,
                                      cfg.sockbuf_bytes);
    if (usock < 0)
        goto cleanup;

    if (kcptcp_ep_register_listener(epfd, usock, &magic_listener) < 0) {
        P_LOG_ERR("epoll_ctl add udp: %s", strerror(errno));
        goto cleanup;
    }

    if (kcp_map_safe_init(&cmap, HASH_TABLE_SIZE) != 0) {
        P_LOG_ERR("kcp_map_safe_init failed");
        goto cleanup;
    }

    /* Initialize connection pool */
    if (conn_pool_init(&g_conn_pool, DEFAULT_CONN_POOL_SIZE, sizeof(struct proxy_conn)) != 0) {
        P_LOG_ERR("Failed to initialize connection pool");
        goto cleanup;
    }

    P_LOG_INFO("kcptcp-server running: UDP %s -> TCP %s", sockaddr_to_string(&cfg.laddr),
               sockaddr_to_string(&cfg.taddr));

    struct kcp_opts kopts;
    kcp_opts_set_defaults(&kopts);
    kcp_opts_apply_overrides(&kopts, kcp_mtu, kcp_nd, kcp_it, kcp_rs, kcp_nc, kcp_snd, kcp_rcv);

    while (!g_shutdown_requested) {
        /* Compute timeout from all KCP sessions */
        int timeout_ms = kcptcp_compute_kcp_timeout_ms(&conns, 1000);

        struct epoll_event events[DEFAULT_EPOLL_MAX_EVENTS];
        int nfds = epoll_wait(epfd, events, DEFAULT_EPOLL_MAX_EVENTS, timeout_ms);
        if (nfds < 0) {
            if (errno == EINTR) {
                /* continue to timer */
            } else {
                P_LOG_ERR("epoll_wait: %s", strerror(errno));
                break;
            }
        }

        for (int i = 0; i < nfds; ++i) {
            void *tag = events[i].data.ptr;
            if (tag == &magic_listener) {
                /* UDP packet(s) */
                for (;;) {
                    char buf[UDP_RECV_BUFFER_SIZE];
                    struct sockaddr_storage rss;
                    socklen_t ralen = sizeof(rss);
                    ssize_t rn = recvfrom(usock, buf, sizeof(buf), MSG_DONTWAIT,
                                          (struct sockaddr *)&rss, &ralen);
                    if (rn < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;
                        P_LOG_ERR("recvfrom: %s", strerror(errno));
                        break;
                    }
                    if (rn == 0)
                        break;
                    /* Build union sockaddr_inx from rss */
                    union sockaddr_inx ra;
                    memset(&ra, 0, sizeof(ra));
                    if (rss.ss_family == AF_INET) {
                        ra.sin = *(struct sockaddr_in *)&rss;
                    } else if (rss.ss_family == AF_INET6) {
                        ra.sin6 = *(struct sockaddr_in6 *)&rss;
                    } else {
                        P_LOG_WARN("drop UDP from unknown family=%d", (int)rss.ss_family);
                        continue;
                    }
                    /* Try stealth handshake first: attempt to decrypt any
                     * packet from unknown source */
                    if (rn >= 28) { /* Minimum size for encrypted packet */
                        /* Only support PSK stealth handshake */
                        if (!cfg.has_psk || !cfg.psk) {
                            P_LOG_WARN("PSK is required for stealth handshake, "
                                       "dropping packet from %s",
                                       sockaddr_to_string(&ra));
                            continue;
                        }

                        /* Try to parse as stealth handshake */
                        struct stealth_handshake_payload payload;
                        uint8_t extracted_data[1024];
                        size_t extracted_data_len = sizeof(extracted_data);

                        if (stealth_handshake_parse_first_packet(
                                cfg.psk, (const uint8_t *)buf, (size_t)rn, &payload, extracted_data,
                                &extracted_data_len) == 0) {
                            /* Successfully parsed stealth handshake! */

                            /* Apply rate limiting */
                            if (!rate_limit_check_addr(&ra)) {
                                continue;
                            }

                            /* Apply connection limiting */
                            if (!conn_limit_check(&ra)) {
                                continue;
                            }
                            /* Create TCP to target via shared helper */
                            int ts = kcptcp_create_tcp_socket(cfg.taddr.sa.sa_family,
                                                              cfg.sockbuf_bytes, cfg.tcp_nodelay);
                            if (ts < 0) {
                                continue;
                            }
                            int yes = 1;
                            (void)setsockopt(ts, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));

                            int cr =
                                connect(ts, &cfg.taddr.sa, (socklen_t)sizeof_sockaddr(&cfg.taddr));
                            if (cr < 0 && errno != EINPROGRESS) {
                                P_LOG_ERR("connect: %s", strerror(errno));
                                close(ts);
                                continue;
                            }

                            struct proxy_conn *nc = conn_pool_alloc(&g_conn_pool);
                            if (!nc) {
                                P_LOG_ERR("Connection pool exhausted");
                                close(ts);
                                continue;
                            }
                            nc->state = S_SERVER_CONNECTING;
                            nc->svr_sock = ts;
                            nc->udp_sock = usock;
                            nc->peer_addr = ra;
                            /* Extract token from stealth handshake payload */
                            memcpy(nc->hs_token, payload.token, 16);
                            nc->last_active = time(NULL);
                            /* Prefer deterministic conv from PSK+token if
                             * available; fallback to secure random */
                            uint32_t conv_try = 0;
                            if (cfg.has_psk && kcptcp_deterministic_conv_enabled()) {
                                conv_try = derive_conv_from_psk_token(cfg.psk, nc->hs_token);
                                if (conv_try != 0 && kcp_map_safe_get(&cmap, conv_try) != NULL) {
                                    /* Collision: reset to 0 to trigger random
                                     * generation */
                                    conv_try = 0;
                                }
                            }
                            if (conv_try == 0) {
                                int attempts = 0;
                                do {
                                    conv_try = generate_secure_conv();
                                    attempts++;
                                    if (attempts > MAX_CONV_GENERATION_ATTEMPTS) {
                                        P_LOG_ERR("Failed to generate unique "
                                                  "conv after 100 attempts");
                                        close(ts);
                                        conn_limit_release(&ra);
                                        conn_pool_release(&g_conn_pool, nc);
                                        continue;
                                    }
                                } while (conv_try == 0 ||
                                         kcp_map_safe_get(&cmap, conv_try) != NULL);
                            }
                            nc->conv = conv_try;

                            /* Derive session key if PSK provided */
                            if (cfg.has_psk && kcptcp_deterministic_conv_enabled()) {
                                if (derive_session_key_from_psk((const uint8_t *)cfg.psk,
                                                                nc->hs_token, nc->conv,
                                                                nc->session_key) == 0) {
                                    nc->has_session_key = true;
                                    /* Initialize AEAD nonce base and counters
                                     */
                                    memcpy(nc->nonce_base, nc->session_key, 12);
                                    nc->send_seq = 0;
                                    /* Initialize anti-replay detector */
                                    anti_replay_init(&nc->replay_detector);
                                    nc->recv_seq = 0;
                                    nc->recv_win = UINT32_MAX; /* uninitialized */
                                    nc->recv_win_mask = 0ULL;
                                    nc->epoch = 0;
                                    nc->rekey_in_progress = false;
                                } else {
                                    P_LOG_ERR("session key derivation failed");
                                    close(ts);
                                    conn_pool_release(&g_conn_pool, nc);
                                    continue;
                                }
                            }

                            if (kcp_setup_conn(nc, usock, &ra, nc->conv, &kopts) != 0) {
                                P_LOG_ERR("kcp_setup_conn failed");
                                close(ts);
                                kcp_map_safe_del(&cmap, nc->conv);
                                conn_pool_release(&g_conn_pool, nc);
                                continue;
                            }

                            /* Register TCP server socket */
                            if (kcptcp_ep_register_tcp(epfd, ts, nc, true) < 0) {
                                int err = errno;
                                P_LOG_ERR("epoll add tcp failed: %s", strerror(err));
                                /* Use unified cleanup function */
                                conn_cleanup_server(nc, -1, &cmap); /* Don't remove from epoll since
                                                                       registration failed */
                                if (handle_system_error("epoll_register_tcp", err) < 0) {
                                    /* Critical error, might need to exit */
                                    P_LOG_ERR("Critical epoll error, continuing with "
                                              "degraded service");
                                }
                                continue;
                            }
                            list_add_tail(&nc->list, &conns);
                            (void)kcp_map_safe_put(&cmap, nc->conv, nc);

                            /* Send stealth handshake response */
                            unsigned char response_buf[1024];
                            size_t response_len = sizeof(response_buf);

                            if (stealth_handshake_create_response(cfg.psk, nc->conv, nc->hs_token,
                                                                  response_buf,
                                                                  &response_len) != 0) {
                                P_LOG_ERR("Failed to create stealth handshake "
                                          "response");
                                close(nc->svr_sock);
                                conn_limit_release(&ra);
                                conn_pool_release(&g_conn_pool, nc);
                                continue;
                            }

                            /* Apply small response jitter to look like normal
                             * traffic */
                            uint32_t jitter =
                                rand_between(cfg.hs_rsp_jitter_min_ms, cfg.hs_rsp_jitter_max_ms);
                            if (jitter == 0) {
                                (void)sendto(usock, response_buf, response_len, MSG_DONTWAIT,
                                             &nc->peer_addr.sa,
                                             (socklen_t)sizeof_sockaddr(&nc->peer_addr));
                                P_LOG_INFO("sent stealth handshake response "
                                           "conv=%u for %s (%zu bytes)",
                                           nc->conv, sockaddr_to_string(&ra), response_len);
                            } else {
                                if (response_len <= sizeof(nc->hs_resp_buf)) {
                                    memcpy(nc->hs_resp_buf, response_buf, response_len);
                                    nc->hs_resp_len = response_len;
                                    nc->hs_resp_send_at_ms = kcp_now_ms() + jitter;
                                    nc->hs_resp_pending = true;
                                    P_LOG_DEBUG("queued handshake response "
                                                "conv=%u with %u ms jitter",
                                                nc->conv, jitter);
                                } else {
                                    P_LOG_WARN("handshake response too large to "
                                               "buffer; sending immediately");
                                    (void)sendto(usock, response_buf, response_len, MSG_DONTWAIT,
                                                 &nc->peer_addr.sa,
                                                 (socklen_t)sizeof_sockaddr(&nc->peer_addr));
                                }
                            }

                            /* Forward any extracted initial payload to target
                             * TCP */
                            if (extracted_data_len > 0) {
                                P_LOG_DEBUG("Extracted %zu bytes of initial "
                                            "data from stealth handshake",
                                            extracted_data_len);
                                /* Buffer initial data to be sent once connect
                                 * completes */
                                size_t need = nc->request.dlen + extracted_data_len;
                                if (ensure_buffer_capacity(&nc->request, need,
                                                           MAX_TCP_BUFFER_SIZE) == 0) {
                                    memcpy(nc->request.data + nc->request.dlen, extracted_data,
                                           extracted_data_len);
                                    nc->request.dlen += extracted_data_len;
                                } else {
                                    P_LOG_WARN("Initial data buffer exceeds "
                                               "limit/alloc fails; dropping "
                                               "extracted data");
                                }
                                /* Ensure EPOLLOUT is enabled so data flushes
                                 * when connect finishes */
                                if (kcptcp_ep_register_tcp(epfd, nc->svr_sock, nc, true) < 0) {
                                    LOG_CONN_WARN(nc, "Failed to enable TCP write "
                                                      "events for initial data");
                                }
                            }

                            continue;
                        } else {
                            /* Not a stealth handshake packet, continue to
                             * regular KCP processing */
                        }
                    }

                    /* Otherwise expect KCP packet for existing conv */
                    if (rn < 24) {
                        P_LOG_WARN("drop non-handshake short UDP pkt len=%zd", rn);
                        continue;
                    }
                    uint32_t conv = ikcp_getconv(buf);
                    struct proxy_conn *c = kcp_map_safe_get(&cmap, conv);
                    if (!c) {
                        P_LOG_WARN("drop UDP for unknown conv=%u from %s", conv,
                                   sockaddr_to_string(&ra));
                        continue;
                    }
                    if (!is_sockaddr_inx_equal(&ra, &c->peer_addr)) {
                        P_LOG_WARN("drop UDP conv=%u from unexpected %s (expected %s)", conv,
                                   sockaddr_to_string(&ra), sockaddr_to_string(&c->peer_addr));
                        continue;
                    }
                    /* Feed KCP */
                    c->udp_rx_bytes += (uint64_t)rn; /* Stats: UDP RX */
                    if (c->kcp) {
                        (void)ikcp_input(c->kcp, buf, (long)rn);
                    } else {
                        P_LOG_WARN("drop UDP for conv=%u with no KCP", conv);
                        continue;
                    }
                    /* Drain to TCP (KCP -> target TCP) */
                    for (;;) {
                        int peek = ikcp_peeksize(c->kcp);
                        if (peek < 0)
                            break;
                        if (peek > (int)sizeof(buf))
                            peek = (int)sizeof(buf);
                        int got = ikcp_recv(c->kcp, buf, peek);
                        if (got <= 0)
                            break;
                        c->kcp_rx_msgs++; /* Stats: KCP RX message */
                        char *payload = NULL;
                        int plen = 0;
                        int res = aead_protocol_handle_incoming_packet(
                            c, buf, got, cfg.psk, cfg.has_psk, &payload, &plen);

                        if (res < 0) { // Error
                            c->state = S_CLOSING;
                            break;
                        }
                        if (res > 0) { // Control packet handled
                            if (c->svr_in_eof && !c->svr2cli_shutdown &&
                                c->response.dlen == c->response.rpos && c->svr_sock > 0) {
                                shutdown(c->svr_sock, SHUT_WR);
                                c->svr2cli_shutdown = true;
                            }
                            continue;
                        }

                        if (!payload || plen <= 0) {
                            continue;
                        }

                        c->kcp_rx_bytes += (uint64_t)plen; /* Stats: accumulate
                                                   KCP RX payload bytes */
                        /* If TCP connect not completed, buffer instead of
                         * sending */
                        if (c->state != S_FORWARDING) {
                            size_t need = c->request.dlen + (size_t)plen;
                            if (ensure_buffer_capacity(&c->request, need, MAX_TCP_BUFFER_SIZE) !=
                                0) {
                                P_LOG_WARN("Request buffer size limit "
                                           "exceeded, closing connection");
                                c->state = S_CLOSING;
                                break;
                            }
                            memcpy(c->request.data + c->request.dlen, payload, (size_t)plen);
                            c->request.dlen += (size_t)plen;
                            if (kcptcp_ep_register_tcp(epfd, c->svr_sock, c, true) < 0) {
                                LOG_CONN_WARN(c, "Failed to re-register TCP "
                                                 "socket for write");
                            }
                            break;
                        }
                        ssize_t wn = send(c->svr_sock, payload, (size_t)plen, MSG_NOSIGNAL);
                        if (wn < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                            /* Would block: buffer all and enable EPOLLOUT */
                            size_t rem = (size_t)plen;
                            size_t need = c->request.dlen + rem;
                            if (ensure_buffer_capacity(&c->request, need, MAX_TCP_BUFFER_SIZE) !=
                                0) {
                                P_LOG_WARN("Buffer size limit exceeded for "
                                           "connection, closing");
                                c->state = S_CLOSING;
                                break;
                            }
                            memcpy(c->request.data + c->request.dlen, payload, rem);
                            c->request.dlen += rem;
                            if (kcptcp_ep_register_tcp(epfd, c->svr_sock, c, true) < 0) {
                                LOG_CONN_WARN(c, "Failed to re-register TCP "
                                                 "socket for write");
                            }
                            break;
                        } else if (wn < 0) {
                            c->state = S_CLOSING;
                            break;
                        } else if (wn < plen) {
                            /* Short write: buffer remaining and enable EPOLLOUT
                             */
                            size_t rem = (size_t)plen - (size_t)wn;
                            size_t need = c->request.dlen + rem;
                            if (ensure_buffer_capacity(&c->request, need, MAX_TCP_BUFFER_SIZE) !=
                                0) {
                                P_LOG_WARN("Buffer size limit exceeded for "
                                           "connection, closing");
                                c->state = S_CLOSING;
                                break;
                            }
                            memcpy(c->request.data + c->request.dlen, payload + wn, rem);
                            c->request.dlen += rem;
                            if (wn > 0)
                                c->tcp_tx_bytes += (uint64_t)wn; /* Stats: TCP TX */
                            if (kcptcp_ep_register_tcp(epfd, c->svr_sock, c, true) < 0) {
                                LOG_CONN_WARN(c, "Failed to re-register TCP "
                                                 "socket for write");
                            }
                            break;
                        }
                        if (wn > 0)
                            c->tcp_tx_bytes += (uint64_t)wn; /* Stats: TCP TX */
                        c->last_active = time(NULL);
                    }
                    continue;
                }

                /* TCP events for an existing connection */
                if (!tag) {
                    P_LOG_WARN("epoll event with NULL tag");
                    continue;
                }
                struct proxy_conn *c = (struct proxy_conn *)tag;
                if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                    c->state = S_CLOSING;
                }
                if ((events[i].events & EPOLLOUT) && c->state == S_SERVER_CONNECTING) {
                    int err = 0;
                    socklen_t elen = sizeof(err);
                    if (getsockopt(c->svr_sock, SOL_SOCKET, SO_ERROR, &err, &elen) == 0 &&
                        err == 0) {
                        c->state = S_FORWARDING;
                    } else {
                        c->state = S_CLOSING;
                    }
                }
                if ((events[i].events & EPOLLOUT) && c->state == S_FORWARDING) {
                    /* Flush pending request data to target TCP */
                    while (c->request.rpos < c->request.dlen) {
                        ssize_t wn = send(c->svr_sock, c->request.data + c->request.rpos,
                                          c->request.dlen - c->request.rpos, MSG_NOSIGNAL);
                        if (wn > 0) {
                            c->request.rpos += (size_t)wn;
                            c->tcp_tx_bytes += (uint64_t)wn; /* Stats: TCP TX */
                        } else if (wn < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                            break;
                        } else {
                            c->state = S_CLOSING;
                            break;
                        }
                    }
                    if (c->request.rpos >= c->request.dlen) {
                        c->request.rpos = 0;
                        c->request.dlen = 0;
                        if (kcptcp_ep_register_tcp(epfd, c->svr_sock, c, false) < 0) {
                            LOG_CONN_WARN(c, "Failed to disable TCP socket write events");
                        }
                        /* If we got FIN from peer earlier, perform shutdown
                         * write now */
                        if (c->cli_in_eof && !c->cli2svr_shutdown && c->svr_sock > 0) {
                            shutdown(c->svr_sock, SHUT_WR);
                            c->cli2svr_shutdown = true;
                        }
                    }
                }
                if (events[i].events & EPOLLIN) {
                    char sbuf[UDP_RECV_BUFFER_SIZE];
                    ssize_t rn;
                    while ((rn = recv(c->svr_sock, sbuf, sizeof(sbuf), 0)) > 0) {
                        c->tcp_rx_bytes += (uint64_t)rn; /* Stats: TCP RX */
                        if (aead_protocol_send_data(c, sbuf, rn, cfg.psk, cfg.has_psk) < 0) {
                            c->state = S_CLOSING;
                            break;
                        }
                    }
                    if (rn == 0) {
                        /* TCP target sent EOF: send FIN/EFIN over KCP, stop
                         * further reads, allow pending KCP to flush */
                        if (aead_protocol_send_fin(c, cfg.psk, cfg.has_psk) < 0) {
                            c->state = S_CLOSING;
                        }
                        c->svr_in_eof = true;
                        struct epoll_event tev2 = (struct epoll_event){0};
                        tev2.events =
                            EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP; /* disable EPOLLIN */
                        tev2.data.ptr = c;
                        (void)safe_epoll_mod_server(epfd, c->svr_sock, &tev2, c);
                    } else if (rn < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        c->state = S_CLOSING;
                    }
                }
            }
        }

        /* Timers and cleanup */
        uint32_t now = kcp_now_ms();

        struct proxy_conn *conn, *tmp;
        list_for_each_entry_safe(conn, tmp, &conns, list) {
            /* Send delayed handshake responses if due */
            if (conn->hs_resp_pending) {
                if ((int32_t)(now - conn->hs_resp_send_at_ms) >= 0) {
                    (void)sendto(usock, conn->hs_resp_buf, conn->hs_resp_len, MSG_DONTWAIT,
                                 &conn->peer_addr.sa, (socklen_t)sizeof_sockaddr(&conn->peer_addr));
                    conn->hs_resp_pending = false;
                    P_LOG_INFO("sent delayed handshake response conv=%u (%zu bytes)", conn->conv,
                               conn->hs_resp_len);
                }
            }
            (void)kcp_update_flush(conn, now);
            /* If server TCP got EOF, wait until all buffered client->server
             * data is flushed before closing */
            if (conn->svr_in_eof && conn->state != S_CLOSING) {
                bool tcp_buf_empty = (conn->request.dlen == conn->request.rpos);
                int kcp_unsent = conn->kcp ? ikcp_waitsnd(conn->kcp) : 0;
                bool udp_backlog_empty = (conn->udp_backlog.dlen == 0);
                if (tcp_buf_empty && kcp_unsent == 0 && udp_backlog_empty) {
                    conn->state = S_CLOSING;
                }
            }
            /* Idle timeout (e.g., 180s) */
            time_t ct = time(NULL);
            const time_t IDLE_TO = 180;
            if (conn->state != S_CLOSING && conn->last_active &&
                (ct - conn->last_active) > IDLE_TO) {
                P_LOG_INFO("idle timeout, conv=%u", conn->conv);
                conn->state = S_CLOSING;
            }
            /* Rekey timeout enforcement */
            if (conn->state != S_CLOSING && conn->has_session_key && conn->rekey_in_progress) {
                if (now >= conn->rekey_deadline_ms) {
                    P_LOG_ERR("rekey timeout, closing conv=%u (svr)", conn->conv);
                    conn->state = S_CLOSING;
                }
            }
            kcptcp_maybe_log_stats(conn, now);
            if (conn->state == S_CLOSING) {
                kcptcp_log_total_stats(conn);
                conn_cleanup_server(conn, epfd, &cmap);
            }
        }
    }

    rc = 0;

cleanup:
    if (usock >= 0)
        close(usock);
    if (epfd >= 0)
        epoll_close_comp(epfd);
    kcp_map_safe_free(&cmap);
    if (cfg.pidfile)
        remove_pid_file(cfg.pidfile);

    conn_pool_destroy(&g_conn_pool);

    P_LOG_INFO("kcptcp-server shut down");

    return rc;
}
