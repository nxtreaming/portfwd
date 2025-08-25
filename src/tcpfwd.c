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

#include "common.h"
#include "list.h"
#include "proxy_conn.h"

#ifdef __linux__
#include <netinet/tcp.h>
#include <linux/netfilter_ipv4.h>
#endif

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Tunables for throughput */
#ifndef TCP_PROXY_USERBUF_CAP
#define TCP_PROXY_USERBUF_CAP   (64 * 1024)
#endif
#ifndef TCP_PROXY_SOCKBUF_CAP
#define TCP_PROXY_SOCKBUF_CAP   (256 * 1024)
#endif

/* Backpressure watermark: when opposite TX backlog exceeds this, limit further reads */
#ifndef TCP_PROXY_BACKPRESSURE_WM
#define TCP_PROXY_BACKPRESSURE_WM   (TCP_PROXY_USERBUF_CAP * 3 / 4)
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

/* Memory pool for connection objects */
#define TCP_PROXY_CONN_POOL_SIZE 4096

#define EV_MAGIC_LISTENER 0xdeadbeef
#define EV_MAGIC_CLIENT   0xfeedface
#define EV_MAGIC_SERVER   0xbaadcafe

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

struct config {
    union sockaddr_inx src_addr;
    union sockaddr_inx dst_addr;
    const char *pidfile;
    bool daemonize;
    bool base_addr_mode;
    bool reuse_addr;
    bool reuse_port;
    bool v6only;
};

struct conn_pool {
    struct proxy_conn *connections;
    struct proxy_conn *freelist;
    int capacity;
    int used_count;
};

static struct conn_pool g_conn_pool;

static void set_sock_buffers(int sockfd)
{
    int sz = TCP_PROXY_SOCKBUF_CAP;
    (void)setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    (void)setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
}

static void set_keepalive(int sockfd)
{
    int on = 1;
    (void)setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
#ifdef __linux__
    int idle = TCP_PROXY_KEEPALIVE_IDLE;
    int intvl = TCP_PROXY_KEEPALIVE_INTVL;
    int cnt = TCP_PROXY_KEEPALIVE_CNT;
    (void)setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    (void)setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    (void)setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif
}

static void set_tcp_nodelay(int sockfd)
{
    int on = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0) {
        P_LOG_WARN("setsockopt(TCP_NODELAY): %s", strerror(errno));
    }
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

static int init_conn_pool(void)
{
    g_conn_pool.capacity = TCP_PROXY_CONN_POOL_SIZE;
    g_conn_pool.connections = malloc(sizeof(struct proxy_conn) * g_conn_pool.capacity);
    if (!g_conn_pool.connections) {
        P_LOG_ERR("Failed to allocate connection pool");
        return -1;
    }

    g_conn_pool.freelist = NULL;
    for (int i = 0; i < g_conn_pool.capacity; i++) {
        struct proxy_conn *conn = &g_conn_pool.connections[i];
        conn->next = g_conn_pool.freelist;
        g_conn_pool.freelist = conn;
    }
    g_conn_pool.used_count = 0;
    P_LOG_INFO("Connection pool initialized with %d connections", g_conn_pool.capacity);
    return 0;
}

static void destroy_conn_pool(void)
{
    if (g_conn_pool.connections) {
        free(g_conn_pool.connections);
        g_conn_pool.connections = NULL;
        g_conn_pool.freelist = NULL;
        g_conn_pool.capacity = 0;
        g_conn_pool.used_count = 0;
        P_LOG_INFO("Connection pool destroyed");
    }
}

static inline struct proxy_conn *alloc_proxy_conn(void)
{
    struct proxy_conn *conn;

    if (!g_conn_pool.freelist) {
        P_LOG_WARN("Connection pool exhausted!");
        return NULL;
    }

    conn = g_conn_pool.freelist;
    g_conn_pool.freelist = conn->next;
    g_conn_pool.used_count++;

    memset(conn, 0x0, sizeof(*conn));

    conn->cli_sock = -1;
    conn->svr_sock = -1;
#ifdef __linux__
    conn->splice_pipe[0] = -1;
    conn->splice_pipe[1] = -1;
    conn->use_splice = false;
#endif
    conn->magic_client = EV_MAGIC_CLIENT;
    conn->magic_server = EV_MAGIC_SERVER;

    return conn;
}

static void release_proxy_conn(struct proxy_conn *conn, struct epoll_event *events,
        int *nfds, int epfd)
{
    int i;

    /*
     * Clear any pending epoll events for this connection's file descriptors.
     * This prevents use-after-free bugs where the event loop might process
     * an event for a connection that has already been released.
     */
    for (i = 0; i < *nfds; i++) {
        struct epoll_event *ev = &events[i];
        if (ev->data.ptr == &conn->magic_client ||
            ev->data.ptr == &conn->magic_server) {
            ev->data.ptr = NULL;
        }
    }

    if (epfd >= 0) {
        if (conn->cli_sock >= 0) {
            if (epoll_ctl(epfd, EPOLL_CTL_DEL, conn->cli_sock, NULL) < 0) {
                P_LOG_WARN("epoll_ctl(DEL, cli_sock=%d): %s", conn->cli_sock, strerror(errno));
            }
        }
        if (conn->svr_sock >= 0) {
            if (epoll_ctl(epfd, EPOLL_CTL_DEL, conn->svr_sock, NULL) < 0) {
                P_LOG_WARN("epoll_ctl(DEL, svr_sock=%d): %s", conn->svr_sock, strerror(errno));
            }
        }
    }

#ifdef __linux__
    if (conn->use_splice) {
        if (close(conn->splice_pipe[0]) < 0) {
            P_LOG_WARN("close(splice_pipe[0]=%d): %s", conn->splice_pipe[0], strerror(errno));
        }
        if (close(conn->splice_pipe[1]) < 0) {
            P_LOG_WARN("close(splice_pipe[1]=%d): %s", conn->splice_pipe[1], strerror(errno));
        }
    }
#endif
    if (conn->cli_sock >= 0) {
        if (close(conn->cli_sock) < 0) {
            P_LOG_WARN("close(cli_sock=%d): %s", conn->cli_sock, strerror(errno));
        }
    }
    if (conn->svr_sock != -1) {
        if (close(conn->svr_sock) < 0) {
            P_LOG_WARN("close(svr_sock=%d): %s", conn->svr_sock, strerror(errno));
        }
    }

    /* Free user buffers to avoid leaks, since alloc_proxy_conn() zeroes pointers */
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

    conn->next = g_conn_pool.freelist;
    g_conn_pool.freelist = conn;
    g_conn_pool.used_count--;
}

/**
 * @brief Updates epoll event registrations for a connection based on its state.
 *
 * Sets EPOLLIN/EPOLLOUT flags for client and server sockets according to the
 * current state (e.g., connecting, forwarding) and buffer status to ensure
 * correct I/O notifications.
 */
static void set_conn_epoll_fds(struct proxy_conn *conn, int epfd)
{
    struct epoll_event ev_cli, ev_svr;

    ev_cli.events = 0;
    ev_cli.data.ptr = &conn->magic_client;

    ev_svr.events = 0;
    ev_svr.data.ptr = &conn->magic_server;

    if (conn->use_splice) {
        /* With splice, we don't maintain user buffers; rely on kernel pipe.
         * Enable both IN and OUT on both ends to guarantee progress. */
        ev_cli.events |= EPOLLIN | EPOLLOUT;
        ev_svr.events |= EPOLLIN | EPOLLOUT;
    } else {
        switch(conn->state) {
        case S_SERVER_CONNECTING:
            /* Wait for the server connection to establish. */
            if (conn->request.dlen < conn->request.capacity)
                ev_cli.events |= EPOLLIN; /* for detecting client close */
            ev_svr.events |= EPOLLOUT;
            break;
        case S_FORWARDING:
            if (conn->request.dlen < conn->request.capacity)
                ev_cli.events |= EPOLLIN;
            if (conn->response.dlen > 0)
                ev_cli.events |= EPOLLOUT;
            if (conn->response.dlen < conn->response.capacity)
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

static struct proxy_conn *create_proxy_conn(struct config *cfg, int cli_sock, const union sockaddr_inx *cli_addr)
{
    struct proxy_conn *conn = NULL;
    char s_addr1[50] = "", s_addr2[50] = "";

    /* Client calls in, allocate session data for it. */
    if (!(conn = alloc_proxy_conn())) {
        P_LOG_ERR("alloc_proxy_conn(): %s", strerror(errno));
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
         * It then performs direct integer arithmetic on the destination IP address
         * based on the difference between the original destination port and the
         * listener port.
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
        if (getsockname(conn->cli_sock, (struct sockaddr *)&loc_addr, &loc_alen)) {
            P_LOG_ERR("getsockname(): %s.", strerror(errno));
            goto err;
        }
        if (getsockopt(conn->cli_sock, SOL_IP, SO_ORIGINAL_DST, &orig_dst, &orig_alen)) {
            P_LOG_ERR("getsockopt(SO_ORIGINAL_DST): %s.", strerror(errno));
            goto err;
        }

        if (conn->svr_addr.sa.sa_family == AF_INET) {
            addr_pos = (uint32_t *)&conn->svr_addr.sin.sin_addr;
        } else {
            addr_pos = (uint32_t *)&conn->svr_addr.sin6.sin6_addr.s6_addr32[3];
        }
        port_offset = (int)(ntohs(*port_of_sockaddr(&orig_dst)) - ntohs(*port_of_sockaddr(&loc_addr)));

        base = ntohl(*addr_pos);
        sum = (int64_t)base + (int64_t)(int32_t)port_offset;
        if (sum < 0 || sum > UINT32_MAX) {
            P_LOG_ERR("base address adjustment overflows: base=%u, off=%d", base, port_offset);
            goto err;
        }

        *addr_pos = htonl((uint32_t)sum);
    }
#endif

    inet_ntop(conn->cli_addr.sa.sa_family, addr_of_sockaddr(&conn->cli_addr),
            s_addr1, sizeof(s_addr1));
    inet_ntop(conn->svr_addr.sa.sa_family, addr_of_sockaddr(&conn->svr_addr),
            s_addr2, sizeof(s_addr2));
    P_LOG_INFO("New connection [%s]:%d -> [%s]:%d",
            s_addr1, ntohs(*port_of_sockaddr(&conn->cli_addr)),
            s_addr2, ntohs(*port_of_sockaddr(&conn->svr_addr)));

    /* Initiate the connection to server right now. */
    if ((conn->svr_sock = socket(conn->svr_addr.sa.sa_family, SOCK_STREAM, 0)) < 0) {
        P_LOG_ERR("socket(svr_sock): %s", strerror(errno));
        goto err;
    }
    set_nonblock(conn->svr_sock);
    set_sock_buffers(conn->svr_sock);
    set_keepalive(conn->svr_sock);
    set_tcp_nodelay(conn->svr_sock);

    /* Allocate per-connection user buffers */
    conn->request.data = (char *)malloc(TCP_PROXY_USERBUF_CAP);
    conn->response.data = (char *)malloc(TCP_PROXY_USERBUF_CAP);
    if (!conn->request.data || !conn->response.data) {
        P_LOG_ERR("malloc(user buffers) failed");
        goto err;
    }
    conn->request.capacity = TCP_PROXY_USERBUF_CAP;
    conn->request.dlen = 0;
    conn->request.rpos = 0;
    conn->response.capacity = TCP_PROXY_USERBUF_CAP;
    conn->response.dlen = 0;
    conn->response.rpos = 0;

    if (connect(conn->svr_sock, (struct sockaddr *)&conn->svr_addr,
            sizeof_sockaddr(&conn->svr_addr)) == 0) {
        /* Connected, prepare for data forwarding. */
        conn->state = S_SERVER_CONNECTED;
        /* Set up splice (Linux) */
#ifdef __linux__
        if (!conn->use_splice) {
            int pfds[2];
            if (pipe2(pfds, O_NONBLOCK | O_CLOEXEC) == 0) {
                conn->splice_pipe[0] = pfds[0];
                conn->splice_pipe[1] = pfds[1];
                conn->use_splice = true;
            }
        }
#endif
        return conn;
    } else if (errno == EINPROGRESS) {
        /* OK, poll for the connection to complete or fail */
        conn->state = S_SERVER_CONNECTING;
        /* Prepare splice early (Linux) */
#ifdef __linux__
        if (!conn->use_splice) {
            int pfds[2];
            if (pipe2(pfds, O_NONBLOCK | O_CLOEXEC) == 0) {
                conn->splice_pipe[0] = pfds[0];
                conn->splice_pipe[1] = pfds[1];
                conn->use_splice = true;
            }
        }
#endif
        return conn;
    } else {
        /* Error occurs, drop the session. */
        P_LOG_WARN("Connection to [%s]:%d failed: %s",
                s_addr2, ntohs(*port_of_sockaddr(&conn->svr_addr)),
                strerror(errno));
        goto err;
    }

err:
    /* On error, the connection is released here. The caller doesn't need to do anything. */
    if (conn)
        release_proxy_conn(conn, NULL, 0, -1);
    return NULL;
}

static int handle_server_connecting(struct proxy_conn *conn, int efd)
{
    char s_addr[50] = "";

    if (efd == conn->svr_sock) {
        /* The connection has established or failed. */
        int err = 0;
        socklen_t errlen = sizeof(err);

        if (getsockopt(conn->svr_sock, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err) {
            inet_ntop(conn->svr_addr.sa.sa_family, addr_of_sockaddr(&conn->svr_addr),
                    s_addr, sizeof(s_addr));
            P_LOG_WARN("Connection to [%s]:%d failed: %s",
                    s_addr, ntohs(*port_of_sockaddr(&conn->svr_addr)),
                    strerror(err ? err : errno));
            conn->state = S_CLOSING;
            return 0;
        }

        /* Connected, preparing for data forwarding. */
        conn->state = S_SERVER_CONNECTED;
        return 0;
    } else {
        /* Received data early before server connection is OK */
        struct buffer_info *rxb = &conn->request;
        int rc;

        for (;;) {
            rc = recv(efd , rxb->data + rxb->dlen,
                    rxb->capacity - rxb->dlen, 0);
            if (rc == 0) {
                inet_ntop(conn->cli_addr.sa.sa_family, addr_of_sockaddr(&conn->cli_addr),
                        s_addr, sizeof(s_addr));
                P_LOG_INFO("Connection [%s]:%d closed during server handshake",
                        s_addr, ntohs(*port_of_sockaddr(&conn->cli_addr)));
                conn->state = S_CLOSING;
                return 0;
            } else if (rc < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    break; /* drained for now */
                inet_ntop(conn->cli_addr.sa.sa_family, addr_of_sockaddr(&conn->cli_addr),
                        s_addr, sizeof(s_addr));
                P_LOG_INFO("Connection [%s]:%d error during server handshake: %s",
                        s_addr, ntohs(*port_of_sockaddr(&conn->cli_addr)), strerror(errno));
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

static int handle_server_connected(struct proxy_conn *conn, int efd)
{
    (void)efd; /* unused */
    conn->state = S_FORWARDING;
    return -EAGAIN;
}

#ifdef __linux__
static int handle_forwarding_splice(struct proxy_conn *conn, struct epoll_event *ev)
{
    int src_fd, dst_fd;
    int *pipe_fds;
    ssize_t n_in, n_out;

    pipe_fds = conn->splice_pipe;

    if (ev->data.ptr == &conn->magic_client) { /* client -> server */
        src_fd = conn->cli_sock;
        dst_fd = conn->svr_sock;
    } else { /* server -> client */
        src_fd = conn->svr_sock;
        dst_fd = conn->cli_sock;
    }

    while (1) {
        size_t to_write = conn->splice_pending;

        if (to_write == 0) {
            /* Pipe is empty, read from source */
            n_in = splice(src_fd, NULL, pipe_fds[1], NULL, 65536, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            if (n_in == 0) {
                if (src_fd == conn->cli_sock) conn->cli_in_eof = true;
                else conn->svr_in_eof = true;
                break; /* EOF */
            }
            if (n_in < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break; /* Drained */
                P_LOG_ERR("splice(in) from fd %d failed: %s", src_fd, strerror(errno));
                conn->state = S_CLOSING;
                return 0;
            }
            to_write = n_in;
        }

        /* Write to destination */
        n_out = splice(pipe_fds[0], NULL, dst_fd, NULL, to_write, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (n_out < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Can't write, so data is now pending */
                conn->splice_pending = to_write;
                break;
            }
            P_LOG_ERR("splice(out) to fd %d failed: %s", dst_fd, strerror(errno));
            conn->state = S_CLOSING;
            return 0;
        }

        if ((size_t)n_out < to_write) {
            /* Partial write, update pending and try again */
            conn->splice_pending = to_write - n_out;
            continue;
        }

        /* Full write */
        conn->splice_pending = 0;
    }

    return -EAGAIN;
}
#endif

static int handle_forwarding(struct proxy_conn *conn, int efd, int epfd,
        struct epoll_event *ev)
{
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
            return 0;
        }
        return io_state;
    }
#endif


    if (ev->events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
        goto err;
    }

    if (ev->events & EPOLLIN) {
        int can_read = (ev->data.ptr == &conn->magic_client) ?
                       (conn->request.dlen - conn->request.rpos < TCP_PROXY_BACKPRESSURE_WM) :
                       (conn->response.dlen - conn->response.rpos < TCP_PROXY_BACKPRESSURE_WM);

        if (can_read) {
            struct buffer_info *read_buf = (ev->data.ptr == &conn->magic_client) ? &conn->request : &conn->response;
            int read_sock = (ev->data.ptr == &conn->magic_client) ? conn->cli_sock : conn->svr_sock;
            ssize_t rc;

            for (;;) {
                rc = recv(read_sock, read_buf->data + read_buf->dlen, read_buf->capacity - read_buf->dlen, 0);
                if (rc == 0) {
                    if (read_sock == conn->cli_sock) conn->cli_in_eof = true;
                    else conn->svr_in_eof = true;
                    break;
                }
                if (rc < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    goto err;
                }
                read_buf->dlen += rc;
                if (read_buf->dlen >= read_buf->capacity) break;
            }
        }
    }

    if (ev->events & EPOLLOUT) {
        struct buffer_info *write_buf = (ev->data.ptr == &conn->magic_client) ? &conn->response : &conn->request;
        int write_sock = (ev->data.ptr == &conn->magic_client) ? conn->cli_sock : conn->svr_sock;
        ssize_t rc;

        if (write_buf->dlen > write_buf->rpos) {
            rc = send(write_sock, write_buf->data + write_buf->rpos, write_buf->dlen - write_buf->rpos, 0);
            if (rc > 0) {
                write_buf->rpos += rc;
            } else if (rc < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                goto err;
            }
            if (write_buf->rpos >= write_buf->dlen) {
                write_buf->rpos = write_buf->dlen = 0;
            }
        }
    }

    if (conn->cli_in_eof && !conn->cli2svr_shutdown && conn->request.rpos >= conn->request.dlen) {
        shutdown(conn->svr_sock, SHUT_WR);
        conn->cli2svr_shutdown = true;
    }
    if (conn->svr_in_eof && !conn->svr2cli_shutdown && conn->response.rpos >= conn->response.dlen) {
        shutdown(conn->cli_sock, SHUT_WR);
        conn->svr2cli_shutdown = true;
    }

    if (conn->cli_in_eof && conn->svr_in_eof &&
        conn->request.rpos >= conn->request.dlen &&
        conn->response.rpos >= conn->response.dlen) {
        conn->state = S_CLOSING;
        return 0;
    }

    return -EAGAIN;

err:
    inet_ntop(conn->cli_addr.sa.sa_family, addr_of_sockaddr(&conn->cli_addr), s_addr, sizeof(s_addr));
    P_LOG_INFO("Connection [%s]:%d closed", s_addr, ntohs(*port_of_sockaddr(&conn->cli_addr)));
    conn->state = S_CLOSING;
    return 0;
}

static void handle_new_connection(int listen_sock, int epfd, struct config *cfg)
{
    for (;;) {
        union sockaddr_inx cli_addr;
        socklen_t cli_alen = sizeof(cli_addr);
        int cli_sock;
#ifdef __linux__
        cli_sock = accept4(listen_sock, (struct sockaddr *)&cli_addr, &cli_alen, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cli_sock < 0 && (errno == ENOSYS || errno == EINVAL)) {
            /* Fallback if accept4 not supported */
            cli_sock = accept(listen_sock, (struct sockaddr *)&cli_addr, &cli_alen);
        }
#else
        cli_sock = accept(listen_sock, (struct sockaddr *)&cli_addr, &cli_alen);
#endif
        if (cli_sock < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Processed all incoming connections. */
                break;
            }
            P_LOG_ERR("accept(): %s", strerror(errno));
            break;
        }

        struct proxy_conn *conn = create_proxy_conn(cfg, cli_sock, &cli_addr);
        if (conn) {
            set_conn_epoll_fds(conn, epfd);
        } else {
            close(cli_sock);
        }
    }
}

static int proxy_loop(int epfd, int listen_sock, struct config *cfg)
{
    struct epoll_event events[512];

    while (!g_state.terminate) {
        int nfds = epoll_wait(epfd, events, countof(events), 1000);
        if (nfds < 0) {
            if (errno == EINTR)
                continue;
            P_LOG_ERR("epoll_wait(): %s", strerror(errno));
            return 1;
        }

        for (int i = 0; i < nfds; i++) {
            struct epoll_event *ev = &events[i];
            struct proxy_conn *conn = NULL;
            int io_state = 0;

            /* Skip events that have been cleared by release_proxy_conn */
            if (ev->data.ptr == NULL) {
                continue;
            }

            if (*(int *)ev->data.ptr == (int)EV_MAGIC_LISTENER) { /* Listener socket */
                handle_new_connection(listen_sock, epfd, cfg);
                continue;
            } else { /* Client or server socket */
                int *magic = (int *)ev->data.ptr;
                int efd = -1;
                if (*magic == (int)EV_MAGIC_CLIENT) {
                    conn = container_of(magic, struct proxy_conn, magic_client);
                    efd = conn->cli_sock;
                } else if (*magic == (int)EV_MAGIC_SERVER) {
                    conn = container_of(magic, struct proxy_conn, magic_server);
                    efd = conn->svr_sock;
                } else {
                    continue; /* Should not happen */
                }

                while (conn->state != S_CLOSING && io_state == 0) {
                    switch (conn->state) {
                    case S_FORWARDING:
                        io_state = handle_forwarding(conn, efd, epfd, ev);
                        break;
                    case S_SERVER_CONNECTING:
                        io_state = handle_server_connecting(conn, efd);
                        break;
                    case S_SERVER_CONNECTED:
                        io_state = handle_server_connected(conn, efd);
                        break;
                    default:
                        conn->state = S_CLOSING;
                        break;
                    }
                }
            }

            if (conn) {
                if (conn->state == S_CLOSING)
                    release_proxy_conn(conn, events, &nfds, epfd);
                else if (io_state == -EAGAIN)
                    set_conn_epoll_fds(conn, epfd);
            }
        }
    }
    return 0;
}

static void show_help(const char *prog)
{
    P_LOG_INFO("Usage: %s [options] <src_addr> <dst_addr>", prog);
    P_LOG_INFO("  <src_addr>, <dst_addr>    -- IPv4/IPv6 address with port, e.g. 127.0.0.1:8080, [::1]:8080");
    P_LOG_INFO("  -d, --daemonize           -- detach and run in background");
    P_LOG_INFO("  -p, --pidfile <path>      -- create PID file at <path>");
    P_LOG_INFO("  -b, --base-addr-mode      -- use src_addr as base for dst_addr (for load balancing)");
    P_LOG_INFO("  -r, --reuse-addr          -- set SO_REUSEADDR on listener socket");
    P_LOG_INFO("  -R, --reuse-port          -- set SO_REUSEPORT on listener socket");
    P_LOG_INFO("  -6, --v6only              -- set IPV6_V6ONLY on listener socket");
    P_LOG_INFO("  -h, --help                -- show this help");
}

int main(int argc, char *argv[])
{
    int rc = 1;
    struct config cfg;
    int listen_sock = -1, epfd = -1;
    int magic_listener = EV_MAGIC_LISTENER;

    memset(&cfg, 0, sizeof(cfg));

    int opt;
    while ((opt = getopt(argc, argv, "dp:brR6h")) != -1) {
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

    openlog("tcpfwd", LOG_PID | LOG_PERROR, LOG_DAEMON);

    if (init_conn_pool() != 0) {
        closelog();
        return 1;
    }

    if (cfg.daemonize && do_daemonize() != 0)
        goto cleanup;

    if (cfg.pidfile) {
        if (write_pidfile(cfg.pidfile) < 0) {
            rc = 1;
            goto cleanup;
        }
    }

    setup_signal_handlers();

    listen_sock = socket(cfg.src_addr.sa.sa_family, SOCK_STREAM, 0);
    if (listen_sock < 0) {
        P_LOG_ERR("socket(): %s", strerror(errno));
        goto cleanup;
    }

    if (cfg.reuse_addr) {
        int on = 1;
        if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            P_LOG_ERR("setsockopt(SO_REUSEADDR): %s", strerror(errno));
            goto cleanup;
        }
    }

#ifdef SO_REUSEPORT
    if (cfg.reuse_port) {
        int on = 1;
        if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
            P_LOG_ERR("setsockopt(SO_REUSEPORT): %s", strerror(errno));
            goto cleanup;
        }
    }
#endif

    if (cfg.src_addr.sa.sa_family == AF_INET6 && cfg.v6only) {
        int on = 1;
        (void)setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
    }

    if (bind(listen_sock, &cfg.src_addr.sa, sizeof_sockaddr(&cfg.src_addr)) < 0) {
        P_LOG_ERR("bind(): %s", strerror(errno));
        goto cleanup;
    }

    if (listen(listen_sock, 128) < 0) {
        P_LOG_ERR("listen(): %s", strerror(errno));
        goto cleanup;
    }

    set_nonblock(listen_sock);

    epfd = epoll_create(1);
    if (epfd < 0) {
        P_LOG_ERR("epoll_create(): %s", strerror(errno));
        goto cleanup;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = &magic_listener;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_sock, &ev) < 0) {
        P_LOG_ERR("epoll_ctl(ADD, listener): %s", strerror(errno));
        goto cleanup;
    }

    P_LOG_INFO("TCP forwarding started.");

    rc = proxy_loop(epfd, listen_sock, &cfg);

cleanup:
    if (listen_sock >= 0) {
        if (close(listen_sock) < 0) {
            P_LOG_WARN("close(listen_sock=%d): %s", listen_sock, strerror(errno));
        }
    }
    if (epfd >= 0) {
        epoll_close_comp(epfd);
    }
    destroy_conn_pool();
    closelog();

    return rc;
}
