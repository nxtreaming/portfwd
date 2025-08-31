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
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
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
#include "conn_pool.h"
#include "fwd_util.h"

#ifdef __linux__
#include <sys/sendfile.h>
#include <netinet/tcp.h>
#include <linux/netfilter_ipv4.h>
#endif

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Constants and Tunables */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

#define TCP_PROXY_USERBUF_CAP (64 * 1024)
#define TCP_PROXY_SOCKBUF_CAP (256 * 1024)
#define TCP_PROXY_BACKPRESSURE_WM (TCP_PROXY_USERBUF_CAP * 3 / 4)

#define TCP_PROXY_KEEPALIVE_IDLE 60
#define TCP_PROXY_KEEPALIVE_INTVL 10
#define TCP_PROXY_KEEPALIVE_CNT 6

#define TCP_PROXY_CONN_POOL_SIZE 4096

#define EPOLL_EVENTS_MIN 64
#define EPOLL_EVENTS_MAX 2048
#define EPOLL_EVENTS_DEFAULT 512

#define MAX_CONSECUTIVE_ACCEPT_ERRORS 10
#define ACCEPT_ERROR_RESET_INTERVAL 60
#define ACCEPT_ERROR_DELAY_US 100000

#define LISTEN_BACKLOG 128

#define EV_MAGIC_LISTENER 0xdeadbeefU
#define EV_MAGIC_CLIENT 0xfeedfaceU
#define EV_MAGIC_SERVER 0xbaadcafeU

#define MIN_VALID_POINTER 4096

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Global Variables */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static struct fwd_config g_cfg;
static struct conn_pool g_conn_pool;
static struct conn_limiter g_conn_limiter;
static struct proxy_stats g_stats;

static int g_sockbuf_cap_runtime = TCP_PROXY_SOCKBUF_CAP;
static int g_ka_idle = TCP_PROXY_KEEPALIVE_IDLE;
static int g_ka_intvl = TCP_PROXY_KEEPALIVE_INTVL;
static int g_ka_cnt = TCP_PROXY_KEEPALIVE_CNT;
static int g_backpressure_wm = TCP_PROXY_BACKPRESSURE_WM;

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Function Declarations */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/* Core event handling */
static void proxy_loop(int listen_sock, int epfd, const struct fwd_config *cfg);
static int handle_new_connection(int listen_sock, int epfd, const struct fwd_config *cfg);
static void handle_server_connecting(struct proxy_conn *conn, int efd, int epfd, struct epoll_event *ev);
static int handle_forwarding(struct proxy_conn *conn, int efd, int epfd, struct epoll_event *ev);

/* Connection management */
static void release_proxy_conn(struct proxy_conn *conn, struct epoll_event *events, int *nfds, int epfd);
static void check_idle_connections(const struct fwd_config *cfg);

/* Socket and epoll utilities */
static int create_listen_socket(const union sockaddr_inx *addr, const struct fwd_config *cfg);
static void set_conn_epoll_fds(struct proxy_conn *conn, int epfd);
static int set_sock_buffers(int sockfd);
static int set_keepalive(int sockfd);
static int set_tcp_nodelay(int sockfd);
static int safe_close(int fd);

/* Statistics and connection limiting */
static int init_stats(void);
static void destroy_stats(void);
static void print_stats_summary(void);
static void report_stats_if_needed(void);
static int init_conn_limiter(int max_total, int max_per_ip);
static void destroy_conn_limiter(void);
static bool check_connection_limit(const union sockaddr_inx *addr);
static void release_connection_limit(const union sockaddr_inx *addr);

/* Command-line parsing and main function */
static void usage(const char *prog);
static int parse_opts(int argc, char **argv, struct fwd_config *cfg);

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

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Connection Limiting */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/* Initialize connection limiter */
static int init_conn_limiter(uint32_t max_total, uint32_t max_per_ip) {
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

static void release_proxy_conn(struct proxy_conn *conn, struct epoll_event *events, int *nfds, int epfd) {
    if (!conn) return;

    if (events && nfds) {
        for (int i = 0; i < *nfds; i++) {
            struct epoll_event *ev = &events[i];
            uintptr_t ptr = (uintptr_t)ev->data.ptr;
            if (ptr != EV_MAGIC_LISTENER && (struct proxy_conn *)(ptr & ~0xFU) == conn) {
                ev->data.ptr = NULL; // Invalidate event
            }
        }
    }

    if (conn->cli_sock >= 0) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, conn->cli_sock, NULL);
        safe_close(conn->cli_sock);
        conn->cli_sock = -1;
    }
    if (conn->svr_sock >= 0) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, conn->svr_sock, NULL);
        safe_close(conn->svr_sock);
        conn->svr_sock = -1;
    }

    free(conn->request.data);
    free(conn->response.data);

    release_connection_limit(&conn->cli_addr);
    __sync_fetch_and_sub(&g_stats.current_active, 1);
    conn_pool_release(&g_conn_pool, conn);
}

static void check_idle_connections(const struct fwd_config *cfg) {
    if (cfg->idle_timeout <= 0) {
        return;
    }

    time_t now = time(NULL);
    size_t checked = 0;
    size_t closed = 0;

    /*
     * The conn_pool does not maintain a separate list of active connections.
     * We must iterate through the entire contiguous memory block and check
     * the state of each connection object to see if it's currently in use.
     */
    for (size_t i = 0; i < g_conn_pool.capacity; ++i) {
        struct proxy_conn *conn = (struct proxy_conn *)((char *)g_conn_pool.pool_mem + i * g_conn_pool.item_size);

        /*
         * A connection is active if its state is S_FORWARDING. We don't want to
         * close connections that are still in the process of connecting.
         * We also check the magic number to be extra sure this is a valid conn.
         */
        if (conn->state == S_FORWARDING && conn->magic_client == EV_MAGIC_CLIENT) {
            checked++;
            if (now - conn->last_active > cfg->idle_timeout) {
                P_LOG_INFO("Closing idle connection (cli_sock=%d, svr_sock=%d) after %ld seconds.",
                           conn->cli_sock, conn->svr_sock, (long)(now - conn->last_active));
                conn->state = S_CLOSING; /* Mark for cleanup in the main loop */
                closed++;
            }
        }
    }

    if (closed > 0) {
        P_LOG_DEBUG("Closed %zu idle connections (checked %zu active).", closed, checked);
    }
}

static void set_conn_epoll_fds(struct proxy_conn *conn, int epfd) {
    struct epoll_event ev;
    uint32_t cli_events = 0;
    uint32_t srv_events = 0;

    if (conn->state != S_FORWARDING) return;

    // Read from client if server buffer has space
    if (conn->response.dlen < g_backpressure_wm) cli_events |= EPOLLIN;
    // Write to client if we have data for it
    if (conn->response.dlen > 0) srv_events |= EPOLLOUT;

    // Read from server if client buffer has space
    if (conn->request.dlen < g_backpressure_wm) srv_events |= EPOLLIN;
    // Write to server if we have data for it
    if (conn->request.dlen > 0) cli_events |= EPOLLOUT;

    ev.events = cli_events | EPOLLET | EPOLLRDHUP;
    ev.data.ptr = (void *)conn->magic_client;
    epoll_ctl(epfd, EPOLL_CTL_MOD, conn->cli_sock, &ev);

    ev.events = srv_events | EPOLLET | EPOLLRDHUP;
    ev.data.ptr = (void *)conn->magic_server;
    epoll_ctl(epfd, EPOLL_CTL_MOD, conn->svr_sock, &ev);
}

static int do_forward(struct proxy_conn *conn, int src_fd, int dst_fd, struct buffer_info *buf) {
    ssize_t n;
    if (buf->dlen > 0) {
        n = write(dst_fd, buf->data + buf->rpos, buf->dlen);
        if (n > 0) {
            buf->rpos += n;
            if (buf->rpos == buf->dlen) {
                buf->rpos = buf->dlen = 0;
            }
            update_traffic_stats(0, n);
            conn->last_active = time(NULL);
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            P_LOG_WARN("write error: %s", strerror(errno));
            return -1;
        }
    }

    if (buf->dlen < buf->capacity) {
        n = read(src_fd, buf->data + buf->dlen, buf->capacity - buf->dlen);
        if (n > 0) {
            buf->dlen += n;
            update_traffic_stats(n, 0);
            conn->last_active = time(NULL);
        } else if (n == 0) {
            return -1; /* EOF */
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            P_LOG_WARN("read error: %s", strerror(errno));
            return -1;
        }
    }
    return 0;
}

static int handle_forwarding(struct proxy_conn *conn, int efd, int epfd, struct epoll_event *ev) {
    (void)efd;
    uintptr_t magic = (uintptr_t)ev->data.ptr;

    if (ev->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
        return -1; // Signal to close connection
    }

    if (magic == conn->magic_client) { // Event on client socket
        if (ev->events & EPOLLIN) {
            if (do_forward(conn, conn->cli_sock, conn->svr_sock, &conn->request) < 0) return -1;
        }
        if (ev->events & EPOLLOUT) {
            if (do_forward(conn, conn->svr_sock, conn->cli_sock, &conn->response) < 0) return -1;
        }
    } else if (magic == conn->magic_server) { // Event on server socket
        if (ev->events & EPOLLIN) {
            if (do_forward(conn, conn->svr_sock, conn->cli_sock, &conn->response) < 0) return -1;
        }
        if (ev->events & EPOLLOUT) {
            if (do_forward(conn, conn->cli_sock, conn->svr_sock, &conn->request) < 0) return -1;
        }
    }

    set_conn_epoll_fds(conn, epfd);
    return 0;
}

static void handle_server_connecting(struct proxy_conn *conn, int efd, int epfd, struct epoll_event *ev) {
    (void)efd;
    int err = 0;
    socklen_t len = sizeof(err);

    if ((ev->events & (EPOLLERR | EPOLLHUP)) || (getsockopt(conn->svr_sock, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0)) {
        P_LOG_WARN("Server connection failed: %s", strerror(err == 0 ? ETIMEDOUT : err));
        __sync_fetch_and_add(&g_stats.connect_errors, 1);
        release_proxy_conn(conn, NULL, NULL, epfd);
        return;
    }

    P_LOG_INFO("Server connection established for client %s", sockaddr_to_string(&conn->cli_addr));
    conn->state = S_FORWARDING;
    update_connection_stats(true, false);

    struct epoll_event cli_ev, srv_ev;
    cli_ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    cli_ev.data.ptr = (void *)conn->magic_client;
    epoll_ctl(epfd, EPOLL_CTL_ADD, conn->cli_sock, &cli_ev);

    srv_ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    srv_ev.data.ptr = (void *)conn->magic_server;
    epoll_ctl(epfd, EPOLL_CTL_MOD, conn->svr_sock, &srv_ev);
}

static void proxy_loop(int listen_sock, int epfd, const struct fwd_config *cfg) {
    int num_events;
    struct epoll_event *events = calloc(EPOLL_EVENTS_DEFAULT, sizeof(struct epoll_event));
    time_t last_idle_check = time(NULL);

    while (1) {
        report_stats_if_needed();
        num_events = epoll_wait(epfd, events, EPOLL_EVENTS_DEFAULT, 1000);

        if (num_events < 0) {
            if (errno == EINTR) continue;
            P_LOG_ERR("epoll_wait(): %s", strerror(errno));
            break;
        }

        for (int i = 0; i < num_events; ++i) {
            struct epoll_event *ev = &events[i];
            uintptr_t ptr = (uintptr_t)ev->data.ptr;

            if (ptr == EV_MAGIC_LISTENER) {
                if (handle_new_connection(listen_sock, epfd, cfg) < 0) {
                    P_LOG_CRIT("Accept loop failed, shutting down.");
                    goto end_loop;
                }
            } else if (ptr >= MIN_VALID_POINTER) {
                struct proxy_conn *conn = (struct proxy_conn *)(ptr & ~0xFU);
                if (conn->state == S_SERVER_CONNECTING) {
                    handle_server_connecting(conn, i, epfd, ev);
                } else if (conn->state == S_FORWARDING) {
                    if (handle_forwarding(conn, i, epfd, ev) < 0) {
                        release_proxy_conn(conn, events, &num_events, epfd);
                    }
                }
            }
        }

        if (cfg->idle_timeout > 0 && time(NULL) - last_idle_check > cfg->idle_timeout) {
            check_idle_connections(cfg);
            last_idle_check = time(NULL);
        }
    }

end_loop:
    free(events);
}

static int handle_new_connection(int listen_sock, int epfd, const struct fwd_config *cfg) {
    static int consecutive_errors = 0;
    static time_t last_error_time = 0;

    for (;;) {
        union sockaddr_inx cli_addr;
        socklen_t cli_alen = sizeof(cli_addr);
        int cli_sock = accept4(listen_sock, &cli_addr.sa, &cli_alen, SOCK_NONBLOCK | SOCK_CLOEXEC);

        if (cli_sock < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            P_LOG_ERR("accept4(): %s", strerror(errno));
            time_t now = time(NULL);
            if (now - last_error_time > ACCEPT_ERROR_RESET_INTERVAL) consecutive_errors = 0;
            last_error_time = now;
            if (++consecutive_errors > MAX_CONSECUTIVE_ACCEPT_ERRORS) return -1;
            usleep(ACCEPT_ERROR_DELAY_US);
            continue;
        }

        consecutive_errors = 0;

        if (!check_connection_limit(&cli_addr)) {
            P_LOG_WARN("Connection from %s rejected due to limits", sockaddr_to_string(&cli_addr));
            __sync_fetch_and_add(&g_stats.limit_rejections, 1);
            close(cli_sock);
            continue;
        }

        struct proxy_conn *conn = conn_pool_alloc(&g_conn_pool);
        if (!conn) {
            P_LOG_ERR("conn_pool_alloc() failed");
            release_connection_limit(&cli_addr);
            close(cli_sock);
            continue;
        }

        memset(conn, 0, sizeof(*conn));
        conn->cli_sock = cli_sock;
        conn->svr_sock = -1;
        conn->magic_client = (uintptr_t)conn | EV_MAGIC_CLIENT;
        conn->magic_server = (uintptr_t)conn | EV_MAGIC_SERVER;
        conn->last_active = time(NULL);
        memcpy(&conn->cli_addr, &cli_addr, sizeof(cli_addr));

        set_sock_buffers(conn->cli_sock);
        set_keepalive(conn->cli_sock);
        set_tcp_nodelay(conn->cli_sock);

        union sockaddr_inx *dst_addr = (union sockaddr_inx *)&cfg->dst_addr;
#ifdef __linux__
        if (cfg->transparent_proxy) {
            socklen_t len = sizeof(conn->srv_addr);
            if (getsockopt(conn->cli_sock, SOL_IP, SO_ORIGINAL_DST, &conn->srv_addr, &len) == 0) {
                dst_addr = &conn->srv_addr;
            } else {
                P_LOG_WARN("getsockopt(SO_ORIGINAL_DST) failed: %s", strerror(errno));
            }
        }
#endif

        conn->svr_sock = socket(dst_addr->sa.sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (conn->svr_sock < 0) {
            P_LOG_ERR("socket(svr_sock): %s", strerror(errno));
            release_proxy_conn(conn, NULL, NULL, epfd);
            continue;
        }

        set_sock_buffers(conn->svr_sock);

        if (connect(conn->svr_sock, &dst_addr->sa, sizeof_sockaddr(dst_addr)) == 0) {
            conn->state = S_FORWARDING;
            update_connection_stats(true, false);
            struct epoll_event cli_ev, srv_ev;
            cli_ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
            cli_ev.data.ptr = (void *)conn->magic_client;
            epoll_ctl(epfd, EPOLL_CTL_ADD, conn->cli_sock, &cli_ev);
            srv_ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
            srv_ev.data.ptr = (void *)conn->magic_server;
            epoll_ctl(epfd, EPOLL_CTL_ADD, conn->svr_sock, &srv_ev);
        } else if (errno == EINPROGRESS) {
            conn->state = S_SERVER_CONNECTING;
            struct epoll_event ev = { .events = EPOLLOUT | EPOLLIN | EPOLLET, .data.ptr = (void*)conn };
            if (epoll_ctl(epfd, EPOLL_CTL_ADD, conn->svr_sock, &ev) < 0) {
                P_LOG_ERR("epoll_ctl(ADD, svr_sock): %s", strerror(errno));
                release_proxy_conn(conn, NULL, NULL, epfd);
                continue;
            }
        } else {
            P_LOG_ERR("connect() to %s: %s", sockaddr_to_string(dst_addr), strerror(errno));
            __sync_fetch_and_add(&g_stats.connect_errors, 1);
            release_proxy_conn(conn, NULL, NULL, epfd);
            continue;
        }
        __sync_fetch_and_add(&g_stats.total_accepted, 1);
        uint64_t current = __sync_fetch_and_add(&g_stats.current_active, 1) + 1;
        if (current > g_stats.peak_concurrent) g_stats.peak_concurrent = current;
    }

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* Main and Command Line Parsing */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options] <listen_addr> <listen_port> <dest_addr> <dest_port>\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d, --daemonize                Daemonize the process\n");
    fprintf(stderr, "  -p, --pidfile <path>           PID file path\n");
    fprintf(stderr, "  -u, --user <user>              Drop privileges to this user\n");
    fprintf(stderr, "  -t, --transparent              Enable transparent proxy mode (Linux only)\n");
    fprintf(stderr, "  -z, --zero-copy                Enable zero-copy (splice) forwarding (Linux only)\n");
    fprintf(stderr, "  -c, --max-conns <num>          Maximum total connections\n");
    fprintf(stderr, "  -i, --max-per-ip <num>         Maximum connections per source IP\n");
    fprintf(stderr, "  -k, --keepalive-idle <sec>     Keepalive idle time (seconds)\n");
    fprintf(stderr, "  -K, --keepalive-interval <sec> Keepalive interval (seconds)\n");
    fprintf(stderr, "  -C, --keepalive-count <num>    Keepalive probe count\n");
    fprintf(stderr, "  -b, --sock-buffer <size>       Socket buffer size (bytes)\n");
    fprintf(stderr, "  -h, --help                     Show this help message\n");
}

static int parse_opts(int argc, char **argv, struct fwd_config *cfg) {
    int opt;
    const char *prog = argv[0];

    static const struct option long_opts[] = {
        {"daemonize", no_argument, 0, 'd'},
        {"pidfile", required_argument, 0, 'p'},
        {"user", required_argument, 0, 'u'},
        {"transparent", no_argument, 0, 't'},
        {"zero-copy", no_argument, 0, 'z'},
        {"max-conns", required_argument, 0, 'c'},
        {"max-per-ip", required_argument, 0, 'i'},
        {"keepalive-idle", required_argument, 0, 'k'},
        {"keepalive-interval", required_argument, 0, 'K'},
        {"keepalive-count", required_argument, 0, 'C'},
        {"sock-buffer", required_argument, 0, 'b'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "dp:u:tzc:i:k:K:C:b:h", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'd': cfg->daemonize = true; break;
            case 'p': cfg->pidfile = optarg; break;
            case 'u': cfg->username = optarg; break;
            case 't': cfg->transparent_proxy = true; break;
            case 'z': cfg->use_splice = true; break;
            case 'c': cfg->max_total_connections = atoi(optarg); break;
            case 'i': cfg->max_per_ip_connections = atoi(optarg); break;
            case 'k': cfg->ka_idle = atoi(optarg); break;
            case 'K': cfg->ka_intvl = atoi(optarg); break;
            case 'C': cfg->ka_cnt = atoi(optarg); break;
            case 'b': cfg->sockbuf_size = atoi(optarg); break;
            case 'h': usage(prog); return 1;
            default: usage(prog); return 1;
        }
    }

    if (argc - optind < 4) {
        usage(prog);
        return 1;
    }

    if (resolve_address(&cfg->listen_addr, argv[optind], argv[optind + 1]) != 0) return 1;
    if (resolve_address(&cfg->dst_addr, argv[optind + 2], argv[optind + 3]) != 0) return 1;

    return 0;
}


static int create_listen_socket(const union sockaddr_inx *addr, const struct fwd_config *cfg) {
    int sock = -1;
    int on = 1;

    if ((sock = socket(addr->sa.sa_family, SOCK_STREAM, 0)) < 0) {
        P_LOG_ERR("socket(listen_sock): %s", strerror(errno));
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        P_LOG_WARN("setsockopt(SO_REUSEADDR): %s", strerror(errno));
    }

#ifdef __linux__
    if (cfg->transparent_proxy) {
        if (setsockopt(sock, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) < 0) {
            P_LOG_ERR("setsockopt(IP_TRANSPARENT): %s. This requires CAP_NET_ADMIN.", strerror(errno));
            close(sock);
            return -1;
        }
    }
#endif

    if (bind(sock, &addr->sa, sizeof_sockaddr(addr)) < 0) {
        P_LOG_ERR("bind() to %s: %s", sockaddr_to_string(addr), strerror(errno));
        close(sock);
        return -1;
    }

    if (listen(sock, LISTEN_BACKLOG) < 0) {
        P_LOG_ERR("listen(): %s", strerror(errno));
        close(sock);
        return -1;
    }

    set_nonblock(sock);
    set_cloexec(sock);

    P_LOG_INFO("Listening on %s", sockaddr_to_string(addr));
    return sock;
}

int main(int argc, char **argv) {
    int listen_sock = -1;
    int epfd = -1;
    int rc = 0;

    init_fwd_config(&g_cfg);

    if (parse_opts(argc, argv, &g_cfg) != 0) {
        return 1;
    }

    g_sockbuf_cap_runtime = g_cfg.sockbuf_size;
    g_ka_idle = g_cfg.ka_idle;
    g_ka_intvl = g_cfg.ka_intvl;
    g_ka_cnt = g_cfg.ka_cnt;
    g_backpressure_wm = g_cfg.backpressure_wm;

    if (g_cfg.daemonize) {
        do_daemonize();
    }

    init_signals();

    if (g_cfg.pidfile) {
        cleanup_pidfile();
    }

    if (init_stats() != 0) {
        rc = 1;
        goto cleanup;
    }

    if (init_conn_limiter(g_cfg.max_total_connections, g_cfg.max_per_ip_connections) != 0) {
        rc = 1;
        goto cleanup;
    }

    if (conn_pool_init(&g_conn_pool, g_cfg.max_total_connections > 0 ? g_cfg.max_total_connections : TCP_PROXY_CONN_POOL_SIZE, sizeof(struct proxy_conn)) != 0) {
        rc = 1;
        goto cleanup;
    }

    if ((listen_sock = create_listen_socket(&g_cfg.listen_addr, &g_cfg)) < 0) {
        rc = 1;
        goto cleanup;
    }

#ifdef EPOLL_CLOEXEC
    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0 && (errno == ENOSYS || errno == EINVAL)) epfd = epoll_create(1);
#else
    epfd = epoll_create(1);
#endif
    if (epfd < 0) {
        P_LOG_ERR("epoll_create(): %s", strerror(errno));
        rc = 1;
        goto cleanup;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = (void *)EV_MAGIC_LISTENER;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_sock, &ev) < 0) {
        P_LOG_ERR("epoll_ctl(ADD, listen_sock): %s", strerror(errno));
        rc = 1;
        goto cleanup;
    }

    if (g_cfg.username) {
        if (drop_privileges(g_cfg.username) != 0) {
            rc = 1;
            goto cleanup;
        }
    }

    proxy_loop(listen_sock, epfd, &g_cfg);

cleanup:
    P_LOG_INFO("Shutting down...");
    print_stats_summary();

    if (listen_sock >= 0) close(listen_sock);
    if (epfd >= 0) close(epfd);
    if (g_cfg.pidfile) remove_pidfile(g_cfg.pidfile);

    conn_pool_destroy(&g_conn_pool);
    destroy_conn_limiter();
    destroy_stats();

    return rc;
}
