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
#include "common.h"
#include "proxy_conn.h"
#include "kcp_common.h"
#include "3rd/kcp/ikcp.h"

static void print_usage(const char *prog) {
    P_LOG_INFO("Usage: %s [options] <local_tcp_addr:port> <remote_udp_addr:port>", prog);
    P_LOG_INFO("Options (subset; KCP tunables to be added):");
    P_LOG_INFO("  -d                 run in background (daemonize)");
    P_LOG_INFO("  -p <pidfile>       write PID to file");
    P_LOG_INFO("  -r                 set SO_REUSEADDR on listener socket");
    P_LOG_INFO("  -R                 set SO_REUSEPORT on listener socket");
    P_LOG_INFO("  -6                 for IPv6 listener, set IPV6_V6ONLY");
    P_LOG_INFO("  -S <bytes>         SO_RCVBUF/SO_SNDBUF size (default build-time)");
    P_LOG_INFO("  -h                 show help");
}

struct cfg_client {
    union sockaddr_inx laddr; /* TCP listen */
    union sockaddr_inx raddr; /* UDP remote */
    const char *pidfile;
    bool daemonize;
    bool reuse_addr;
    bool reuse_port;
    bool v6only;
    int sockbuf_bytes;
};

static void set_sock_buffers_sz(int sockfd, int bytes) {
    if (bytes <= 0) return;
    (void)setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes));
    (void)setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
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

    int opt;
    while ((opt = getopt(argc, argv, "dp:rR6S:h")) != -1) {
        switch (opt) {
        case 'd':
            cfg.daemonize = true;
            break;
        case 'p':
            cfg.pidfile = optarg;
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
        case 'S': {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v <= 0) {
                P_LOG_WARN("invalid -S value '%s'", optarg);
            } else {
                if (v < 4096) v = 4096;
                if (v > (8<<20)) v = (8<<20);
                cfg.sockbuf_bytes = (int)v;
            }
            break;
        }
        case 'h': default:
            print_usage(argv[0]);
            return (opt == 'h') ? 0 : 2;
        }
    }

    if (optind + 2 != argc) {
        print_usage(argv[0]);
        return 2;
    }

    if (get_sockaddr_inx_pair(argv[optind], &cfg.laddr, false) < 0) {
        P_LOG_ERR("invalid local tcp addr: %s", argv[optind]);
        return 2;
    }
    if (get_sockaddr_inx_pair(argv[optind+1], &cfg.raddr, true) < 0) {
        P_LOG_ERR("invalid remote udp addr: %s", argv[optind+1]);
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

    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        P_LOG_ERR("epoll_create1: %s", strerror(errno));
        goto cleanup;
    }

    /* Create TCP listen socket */
    lsock = socket(cfg.laddr.sa.sa_family, SOCK_STREAM, 0);
    if (lsock < 0) {
        P_LOG_ERR("socket(listen): %s", strerror(errno));
        goto cleanup;
    }
    if (cfg.reuse_addr) {
        int on = 1;
        (void)setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    }
#ifdef SO_REUSEPORT
    if (cfg.reuse_port) {
        int on = 1;
        (void)setsockopt(lsock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
    }
#endif
#ifdef IPV6_V6ONLY
    if (cfg.v6only && cfg.laddr.sa.sa_family == AF_INET6) {
        int on = 1;
        (void)setsockopt(lsock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
    }
#endif
    set_nonblock(lsock);
    set_sock_buffers_sz(lsock, cfg.sockbuf_bytes);
    if (bind(lsock, &cfg.laddr.sa, (socklen_t)sizeof_sockaddr(&cfg.laddr)) < 0) {
        P_LOG_ERR("bind(listen): %s", strerror(errno));
        goto cleanup;
    }
    if (listen(lsock, 128) < 0) {
        P_LOG_ERR("listen: %s", strerror(errno));
        goto cleanup;
    }

    struct epoll_event ev = {0};
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP; /* level-trigger for listener */
    ev.data.ptr = &magic_listener; /* mark listener */
    if (ep_add_or_mod(epfd, lsock, &ev) < 0) {
        P_LOG_ERR("epoll_ctl add listen: %s", strerror(errno));
        goto cleanup;
    }

    P_LOG_INFO("kcptcp-client running: TCP %s -> UDP %s",
               sockaddr_to_string(&cfg.laddr), sockaddr_to_string(&cfg.raddr));

    struct kcp_opts kopts;
    kcp_opts_set_defaults(&kopts);

    /* Event loop: accept TCP, bridge via KCP over UDP */
    while (!g_state.terminate) {
        /* Compute dynamic timeout from all KCP connections */
        int timeout_ms = 1000;
        uint32_t now = kcp_now_ms();
        struct proxy_conn *pc_it;
        list_for_each_entry(pc_it, &conns, list) {
            uint32_t due = ikcp_check(pc_it->kcp, now);
            int t = (int)((due > now) ? (due - now) : 0);
            if (t < timeout_ms) timeout_ms = t;
        }

        struct epoll_event events[128];
        int nfds = epoll_wait(epfd, events, 128, timeout_ms);
        if (nfds < 0) {
            if (errno == EINTR) { /* fallthrough to timer update */ }
            else { P_LOG_ERR("epoll_wait: %s", strerror(errno)); break; }
        }

        for (int i = 0; i < nfds; ++i) {
            void *tag = events[i].data.ptr;
            if (tag == &magic_listener) {
                /* Accept one or more clients */
                while (1) {
                    union sockaddr_inx ca;
                    socklen_t calen = sizeof(ca);
                    int cs = accept(lsock, &ca.sa, &calen);
                    if (cs < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;
                        P_LOG_ERR("accept: %s", strerror(errno));
                        break;
                    }
                    set_nonblock(cs);
                    /* Create per-connection UDP socket */
                    int us = socket(cfg.raddr.sa.sa_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                    if (us < 0) {
                        P_LOG_ERR("socket(udp): %s", strerror(errno));
                        close(cs);
                        continue;
                    }
                    set_sock_buffers_sz(us, cfg.sockbuf_bytes);

                    /* Allocate connection */
                    struct proxy_conn *c = (struct proxy_conn*)calloc(1, sizeof(*c));
                    if (!c) {
                        P_LOG_ERR("calloc conn");
                        close(cs);
                        close(us);
                        continue;
                    }
                    INIT_LIST_HEAD(&c->list);
                    c->state = S_FORWARDING;
                    c->cli_sock = cs;
                    c->udp_sock = us;
                    c->peer_addr = cfg.raddr;
                    c->last_active = time(NULL);
                    /* Choose conv: lower 31 bits random-ish */
                    c->conv = (uint32_t)(((uint64_t)now << 16) ^ (uintptr_t)c ^ (uint32_t)cs);

                    if (kcp_setup_conn(c, us, &cfg.raddr, c->conv, &kopts) != 0) {
                        P_LOG_ERR("kcp_setup_conn failed");
                        close(cs);
                        close(us);
                        free(c);
                        continue;
                    }

                    /* Register both fds */
                    struct epoll_event cev = {0};
                    cev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
                    cev.data.ptr = c; /* tag with connection */
                    if (ep_add_or_mod(epfd, cs, &cev) < 0) {
                        P_LOG_ERR("epoll add cli: %s", strerror(errno));
                        ikcp_release(c->kcp);
                        close(cs);
                        close(us);
                        free(c);
                        continue;
                    }
                    struct epoll_event uev = {0};
                    uev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
                    uev.data.ptr = c; /* same tag */
                    if (ep_add_or_mod(epfd, us, &uev) < 0) {
                        P_LOG_ERR("epoll add udp: %s", strerror(errno));
                        (void)ep_del(epfd, cs);
                        ikcp_release(c->kcp);
                        close(cs);
                        close(us);
                        free(c);
                        continue;
                    }

                    list_add_tail(&c->list, &conns);
                    P_LOG_INFO("accepted TCP %s, conv=%u", sockaddr_to_string(&ca), c->conv);
                }
                continue;
            }

            /* Connection event: figure out which fd by probing readable */
            struct proxy_conn *c = (struct proxy_conn*)tag;
            int goterr = (events[i].events & (EPOLLERR | EPOLLHUP)) != 0;
            if (goterr) {
                c->state = S_CLOSING;
            }

            /* Try UDP first */
            if (events[i].events & EPOLLIN) {
                /* We don't know if this event is from UDP or TCP since we reuse ptr; try nonblocking recvfrom */
                char ubuf[64 * 1024];
                struct sockaddr_storage rss;
                socklen_t rlen = sizeof(rss);
                ssize_t rn = recvfrom(c->udp_sock, ubuf, sizeof(ubuf), MSG_DONTWAIT, (struct sockaddr*)&rss, &rlen);
                if (rn > 0) {
                    (void)ikcp_input(c->kcp, ubuf, (long)rn);
                    /* Drain KCP to TCP */
                    for (;;) {
                        int peek = ikcp_peeksize(c->kcp);
                        if (peek < 0)
                            break;
                        if (peek > (int)sizeof(ubuf))
                            peek = (int)sizeof(ubuf);
                        int got = ikcp_recv(c->kcp, ubuf, peek);
                        if (got <= 0)
                            break;
                        ssize_t wn = send(c->cli_sock, ubuf, (size_t)got, MSG_NOSIGNAL);
                        if (wn < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                /* Backpressure: buffer and enable EPOLLOUT */
                                size_t need = (size_t)got;
                                size_t freecap = (c->response.capacity > c->response.dlen) ? (c->response.capacity - c->response.dlen) : 0;
                                if (freecap < need) {
                                    size_t ncap = c->response.capacity ? c->response.capacity * 2 : (size_t)65536;
                                    if (ncap < c->response.dlen + need) ncap = c->response.dlen + need;
                                    char *np = (char*)realloc(c->response.data, ncap);
                                    if (!np) { c->state = S_CLOSING; break; }
                                    c->response.data = np;
                                    c->response.capacity = ncap;
                                }
                                memcpy(c->response.data + c->response.dlen, ubuf, (size_t)got);
                                c->response.dlen += (size_t)got;
                                struct epoll_event cev = (struct epoll_event){0};
                                cev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
                                cev.data.ptr = c;
                                (void)ep_add_or_mod(epfd, c->cli_sock, &cev);
                                break;
                            }
                            c->state = S_CLOSING;
                            break;
                        } else if (wn < got) {
                            /* Short write: buffer remaining and enable EPOLLOUT */
                            size_t rem = (size_t)got - (size_t)wn;
                            size_t freecap = (c->response.capacity > c->response.dlen) ? (c->response.capacity - c->response.dlen) : 0;
                            if (freecap < rem) {
                                size_t ncap = c->response.capacity ? c->response.capacity * 2 : (size_t)65536;
                                if (ncap < c->response.dlen + rem) ncap = c->response.dlen + rem;
                                char *np = (char*)realloc(c->response.data, ncap);
                                if (!np) { c->state = S_CLOSING; break; }
                                c->response.data = np;
                                c->response.capacity = ncap;
                            }
                            memcpy(c->response.data + c->response.dlen, ubuf + wn, rem);
                            c->response.dlen += rem;
                            struct epoll_event cev = (struct epoll_event){0};
                            cev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
                            cev.data.ptr = c;
                            (void)ep_add_or_mod(epfd, c->cli_sock, &cev);
                            break;
                        }
                    }
                    c->last_active = time(NULL);
                }
            }

            if (events[i].events & EPOLLOUT) {
                /* Flush pending data to client */
                while (c->response.rpos < c->response.dlen) {
                    ssize_t wn = send(c->cli_sock,
                                      c->response.data + c->response.rpos,
                                      c->response.dlen - c->response.rpos,
                                      MSG_NOSIGNAL);
                    if (wn > 0) {
                        c->response.rpos += (size_t)wn;
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
                    cev.data.ptr = c;
                    (void)ep_add_or_mod(epfd, c->cli_sock, &cev);
                }
            }

            if (events[i].events & (EPOLLIN | EPOLLRDHUP)) {
                /* TCP side readable/half-closed */
                char tbuf[64 * 1024];
                ssize_t rn;
                while ((rn = recv(c->cli_sock, tbuf, sizeof(tbuf), 0)) > 0) {
                    int sn = ikcp_send(c->kcp, tbuf, (int)rn);
                    if (sn < 0) {
                        c->state = S_CLOSING;
                        break;
                    }
                    c->last_active = time(NULL);
                }
                if (rn == 0) {
                    /* EOF */
                    c->svr2cli_shutdown = true;
                } else if (rn < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    c->state = S_CLOSING;
                }
            }
        }

        /* KCP timer updates and GC */
        now = kcp_now_ms();
        struct proxy_conn *pos, *tmp;
        list_for_each_entry_safe(pos, tmp, &conns, list) {
            (void)kcp_update_flush(pos, now);
            if (pos->state == S_CLOSING) {
                (void)ep_del(epfd, pos->cli_sock);
                (void)ep_del(epfd, pos->udp_sock);
                if (pos->kcp) ikcp_release(pos->kcp);
                close(pos->cli_sock);
                close(pos->udp_sock);
                list_del(&pos->list);
                free(pos);
            }
        }
    }

    rc = 0;

cleanup:
    if (lsock >= 0) close(lsock);
    if (epfd >= 0) epoll_close_comp(epfd);
    cleanup_pidfile();
    return rc;
}
