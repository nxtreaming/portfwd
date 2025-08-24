#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "common.h"

#ifdef __linux__
#include <netinet/tcp.h> /* for TCP_KEEPIDLE, etc. */
#include <linux/netfilter_ipv4.h> /* for SO_ORIGINAL_DST */
#endif

#include <syslog.h>
#include <stddef.h>

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Tunables for throughput */
#ifndef TCP_PROXY_USERBUF_CAP
#define TCP_PROXY_USERBUF_CAP   (64 * 1024)   /* per-direction userspace buffer */
#endif
#ifndef TCP_PROXY_SOCKBUF_CAP
#define TCP_PROXY_SOCKBUF_CAP   (256 * 1024)  /* desired kernel socket buffer */
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

#define container_of(ptr, type, member) ({          \
    const typeof(((type *)0)->member) * __mptr = (ptr); \
    (type *)((char *)__mptr - offsetof(type, member)); })

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

struct config {
    union sockaddr_inx src_addr;
    union sockaddr_inx dst_addr;
    const char *pidfile;
    bool daemonize;
    bool base_addr_mode;
    bool reuse_addr;
    bool v6only;
};

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

/* Status indicators of proxy sessions */
enum conn_state {
    S_INVALID,
    S_SERVER_CONNECTING,
    S_SERVER_CONNECTED,
    S_FORWARDING,
    S_CLOSING,
};

enum ev_magic {
    EV_MAGIC_LISTENER = 0x1010,
    EV_MAGIC_CLIENT   = 0x2020,
    EV_MAGIC_SERVER   = 0x3030,
};

struct buffer_info {
    char data[TCP_PROXY_USERBUF_CAP];
    unsigned rpos;
    unsigned dlen;
};

/**
 * Connection tracking information to indicate
 *  a proxy session.
 */
struct proxy_conn {
    int cli_sock;
    int svr_sock;

    /**
     * The two fields are used when an epoll event occurs,
     * to know on which socket fd it is triggered client
     * or server.
     * ev.data.ptr = &ct.magic_client;
     */
    int magic_client;
    int magic_server;
    unsigned short state;

    /* Remember the session addresses */
    union sockaddr_inx cli_addr;
    union sockaddr_inx svr_addr;

    /* Buffers for both direction */
    struct buffer_info request;
    struct buffer_info response;

    /* Half-close tracking */
    bool cli_in_eof;            /* received EOF from client (client->server) */
    bool svr_in_eof;            /* received EOF from server (server->client) */
    bool cli2svr_shutdown;      /* propagated FIN to server (shutdown server write) */
    bool svr2cli_shutdown;      /* propagated FIN to client (shutdown client write) */
};

static inline struct proxy_conn *alloc_proxy_conn(void)
{
    struct proxy_conn *conn;

    if (!(conn = malloc(sizeof(*conn))))
        return NULL;
    memset(conn, 0x0, sizeof(*conn));

    conn->cli_sock = -1;
    conn->svr_sock = -1;
    conn->magic_client = EV_MAGIC_CLIENT;
    conn->magic_server = EV_MAGIC_SERVER;
    conn->state = S_INVALID;

    conn->cli_in_eof = false;
    conn->svr_in_eof = false;
    conn->cli2svr_shutdown = false;
    conn->svr2cli_shutdown = false;

    return conn;
}

/**
 * Close both sockets of the connection and remove it
 *  from the current ready list.
 */
static int ep_add_or_mod(int epfd, int fd, struct epoll_event *ev)
{
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, fd, ev) == 0)
        return 0;
    if (errno == ENOENT)
        return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, ev);
    return -1;
}

static void release_proxy_conn(struct proxy_conn *conn,
        struct epoll_event *pending_evs, int pending_fds, int epfd)
{
    int i;

    /**
     * Clear possible fd events that might belong to current
     *  connection. The event must be cleared or an invalid
     *  pointer might be accessed.
     */
    for (i = 0; i < pending_fds; i++) {
        struct epoll_event *ev = &pending_evs[i];
        if (ev->data.ptr == &conn->magic_client ||
            ev->data.ptr == &conn->magic_server) {
            ev->data.ptr = NULL;
        }
    }

    if (epfd >= 0) {
        if (conn->cli_sock >= 0)
            epoll_ctl(epfd, EPOLL_CTL_DEL, conn->cli_sock, NULL);
        if (conn->svr_sock >= 0)
            epoll_ctl(epfd, EPOLL_CTL_DEL, conn->svr_sock, NULL);
    }

    if (conn->cli_sock >= 0)
        close(conn->cli_sock);
    if (conn->svr_sock >= 0)
        close(conn->svr_sock);

    free(conn);
}


/**
 * Add or activate the epoll fds according to the status of
 *  'conn'. Different conn->state and buffer status will
 *  affect the polling behaviors.
 */
static void set_conn_epoll_fds(struct proxy_conn *conn, int epfd)
{
    struct epoll_event ev_cli, ev_svr;

    ev_cli.events = 0;
    ev_cli.data.ptr = &conn->magic_client;

    ev_svr.events = 0;
    ev_svr.data.ptr = &conn->magic_server;

    switch(conn->state) {
        case S_FORWARDING:
            /* Connection established, data forwarding in progress. */
            if (!conn->cli_in_eof && conn->request.dlen < sizeof(conn->request.data))
                ev_cli.events |= EPOLLIN;
            if (!conn->svr_in_eof && conn->response.dlen < sizeof(conn->response.data))
                ev_svr.events |= EPOLLIN;
            if (conn->request.rpos < conn->request.dlen)
                ev_svr.events |= EPOLLOUT;
            if (conn->response.rpos < conn->response.dlen)
                ev_cli.events |= EPOLLOUT;
            /* Edge-triggered for data sockets */
            ev_cli.events |= EPOLLRDHUP | EPOLLHUP | EPOLLERR | EPOLLET;
            ev_svr.events |= EPOLLRDHUP | EPOLLHUP | EPOLLERR | EPOLLET;
            break;
        case S_SERVER_CONNECTING:
            /* Wait for the server connection to establish. */
            if (conn->request.dlen < sizeof(conn->request.data))
                ev_cli.events |= EPOLLIN; /* for detecting client close */
            ev_svr.events |= EPOLLOUT;
            ev_cli.events |= EPOLLRDHUP | EPOLLHUP | EPOLLERR | EPOLLET;
            ev_svr.events |= EPOLLRDHUP | EPOLLHUP | EPOLLERR | EPOLLET;
            break;
    }

    /* Reset epoll status */
    if (ep_add_or_mod(epfd, conn->cli_sock, &ev_cli) < 0) {
        P_LOG_WARN("epoll_ctl(MOD/ADD, cli): %s", strerror(errno));
        conn->state = S_CLOSING;
        return;
    }
    if (ep_add_or_mod(epfd, conn->svr_sock, &ev_svr) < 0) {
        P_LOG_WARN("epoll_ctl(MOD/ADD, svr): %s", strerror(errno));
        conn->state = S_CLOSING;
        return;
    }
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

    if (connect(conn->svr_sock, (struct sockaddr *)&conn->svr_addr,
            sizeof_sockaddr(&conn->svr_addr)) == 0) {
        /* Connected, prepare for data forwarding. */
        conn->state = S_SERVER_CONNECTED;
        return conn;
    } else if (errno == EINPROGRESS) {
        /* OK, poll for the connection to complete or fail */
        conn->state = S_SERVER_CONNECTING;
        return conn;
    } else {
        /* Error occurs, drop the session. */
        P_LOG_WARN("Connection to [%s]:%d failed: %s",
                s_addr2, ntohs(*port_of_sockaddr(&conn->svr_addr)),
                strerror(errno));
        goto err;
    }

err:
    /**
     * 'conn' has only been used among this function,
     * so don't need the caller to release anything
     */
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
                    sizeof(rxb->data) - rxb->dlen, 0);
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
            if (rxb->dlen >= sizeof(rxb->data))
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

static int handle_forwarding(struct proxy_conn *conn, int efd, int epfd,
        struct epoll_event *ev)
{
    struct buffer_info *rxb, *txb;
    int noefd, rc;
    char s_addr[50] = "";

    (void)epfd; /* unused */

    if (efd == conn->cli_sock) {
        rxb = &conn->request;
        txb = &conn->response;
        noefd = conn->svr_sock;
    } else {
        rxb = &conn->response;
        txb = &conn->request;
        noefd = conn->cli_sock;
    }

    /* Fast-path: detect remote hangups/errors early */
    if (ev->events & (EPOLLRDHUP | EPOLLHUP)) {
        if (efd == conn->cli_sock)
            conn->cli_in_eof = true;
        else
            conn->svr_in_eof = true;
    }
    if (ev->events & EPOLLERR) {
        goto err;
    }

    if ((ev->events & EPOLLIN)) {
        /* Backpressure: if opposite TX backlog is large, skip reading now */
        if ((txb->dlen - txb->rpos) >= TCP_PROXY_BACKPRESSURE_WM)
            goto skip_read;
        for (;;) {
            rc = recv(efd , rxb->data + rxb->dlen,
                    sizeof(rxb->data) - rxb->dlen, 0);
            if (rc == 0) {
                /* Peer performed a half-close (FIN). Mark EOF for this direction. */
                if (efd == conn->cli_sock)
                    conn->cli_in_eof = true;
                else
                    conn->svr_in_eof = true;
                break;
            } else if (rc < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    /* fully drained for now */
                    break;
                }
                goto err;
            }
            rxb->dlen += rc;
            if (rxb->dlen >= sizeof(rxb->data))
                break; /* buffer full */
        }
        /* After reading, try to flush to peer as much as possible */
        while (rxb->rpos < rxb->dlen) {
            rc = send(noefd, rxb->data + rxb->rpos, rxb->dlen - rxb->rpos, 0);
            if (rc > 0) {
                rxb->rpos += rc;
            } else if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break; /* can't write now */
            } else if (rc == 0) {
                break; /* no progress */
            } else {
                goto err;
            }
        }
        if (rxb->rpos >= rxb->dlen)
            rxb->rpos = rxb->dlen = 0;
    }
skip_read:

    if (ev->events & EPOLLOUT) {
        while (txb->rpos < txb->dlen) {
            rc = send(efd, txb->data + txb->rpos, txb->dlen - txb->rpos, 0);
            if (rc > 0) {
                txb->rpos += rc;
            } else if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            } else if (rc == 0) {
                break;
            } else {
                goto err;
            }
        }
        if (txb->rpos >= txb->dlen)
            txb->rpos = txb->dlen = 0;
    }

    /* If a half-close happened earlier and its corresponding buffer drained, propagate FIN */
    if (conn->cli_in_eof && !conn->cli2svr_shutdown && conn->request.rpos >= conn->request.dlen) {
        shutdown(conn->svr_sock, SHUT_WR);
        conn->cli2svr_shutdown = true;
    }
    if (conn->svr_in_eof && !conn->svr2cli_shutdown && conn->response.rpos >= conn->response.dlen) {
        shutdown(conn->cli_sock, SHUT_WR);
        conn->svr2cli_shutdown = true;
    }

    /* If both sides have sent EOF and buffers are drained, we can close */
    if (conn->cli_in_eof && conn->svr_in_eof &&
        conn->request.rpos >= conn->request.dlen &&
        conn->response.rpos >= conn->response.dlen) {
        inet_ntop(conn->cli_addr.sa.sa_family, addr_of_sockaddr(&conn->cli_addr), s_addr, sizeof(s_addr));
        P_LOG_INFO("Connection [%s]:%d closed (both directions finished)",
               s_addr, ntohs(*port_of_sockaddr(&conn->cli_addr)));
        conn->state = S_CLOSING;
        return 0;
    }

    /* I/O not ready or waiting for further events (including FIN propagation). */
    return -EAGAIN;

err:
    inet_ntop(conn->cli_addr.sa.sa_family, addr_of_sockaddr(&conn->cli_addr), s_addr, sizeof(s_addr));
    P_LOG_INFO("Connection [%s]:%d closed", s_addr, ntohs(*port_of_sockaddr(&conn->cli_addr)));
    conn->state = S_CLOSING;
    return 0;
}

static int proxy_loop(int epfd, int listen_sock, struct config *cfg)
{
    struct epoll_event events[512];

    while (!g_terminate) {
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

            if (*(int *)ev->data.ptr == EV_MAGIC_LISTENER) { /* Listener socket */
                for (;;) {
                    union sockaddr_inx cli_addr;
                    socklen_t cli_alen = sizeof(cli_addr);
                    int cli_sock = accept(listen_sock, (struct sockaddr *)&cli_addr, &cli_alen);
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
                continue;
            } else { /* Client or server socket */
                int *magic = (int *)ev->data.ptr;
                int efd = -1;
                if (*magic == EV_MAGIC_CLIENT) {
                    conn = container_of(magic, struct proxy_conn, magic_client);
                    efd = conn->cli_sock;
                } else if (*magic == EV_MAGIC_SERVER) {
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
                    release_proxy_conn(conn, events, nfds, epfd);
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
    P_LOG_INFO("  -6, --v6only              -- set IPV6_V6ONLY on listener socket");
    P_LOG_INFO("  -h, --help                -- show this help");
}

int main(int argc, char *argv[])
{
    int i;
    int rc = 1;
    struct config cfg;
    int listen_sock = -1, epfd = -1;
    int magic_listener = EV_MAGIC_LISTENER;

    memset(&cfg, 0, sizeof(cfg));

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--daemonize") == 0) {
            cfg.daemonize = true;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--pidfile") == 0) {
            if (i + 1 >= argc) {
                P_LOG_ERR("-p/--pidfile requires an argument.");
                return 1;
            }
            cfg.pidfile = argv[++i];
        } else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--base-addr-mode") == 0) {
            cfg.base_addr_mode = true;
        } else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--reuse-addr") == 0) {
            cfg.reuse_addr = true;
        } else if (strcmp(argv[i], "-6") == 0 || strcmp(argv[i], "--v6only") == 0) {
            cfg.v6only = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            show_help(argv[0]);
            return 0;
        } else if (argv[i][0] == '-') {
            P_LOG_ERR("Unknown option: %s", argv[i]);
            return 1;
        } else {
            break;
        }
    }

    if (i + 2 != argc) {
        show_help(argv[0]);
        return 1;
    }

    if (get_sockaddr_inx_pair(argv[i], &cfg.src_addr, false) != 0) {
        P_LOG_ERR("Invalid src_addr: %s", argv[i]);
        return 1;
    }
    if (get_sockaddr_inx_pair(argv[i + 1], &cfg.dst_addr, false) != 0) {
        P_LOG_ERR("Invalid dst_addr: %s", argv[i + 1]);
        return 1;
    }

    openlog(argv[0], LOG_PID | LOG_NDELAY, LOG_DAEMON);

    if (cfg.daemonize && do_daemonize() != 0)
        goto cleanup;

    if (cfg.pidfile) {
        g_pidfile = cfg.pidfile;
        write_pidfile(g_pidfile);
    }

    setup_signal_handlers();

    listen_sock = socket(cfg.src_addr.sa.sa_family, SOCK_STREAM, 0);
    if (listen_sock < 0) {
        P_LOG_ERR("socket(): %s", strerror(errno));
        goto cleanup;
    }

    if (cfg.reuse_addr) {
        int on = 1;
        (void)setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    }

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

    P_LOG_INFO("TCP forwarding stopped.");

cleanup:
    if (listen_sock >= 0)
        close(listen_sock);
    if (epfd >= 0)
        epoll_close_comp(epfd);
    closelog();

    return rc;
}
