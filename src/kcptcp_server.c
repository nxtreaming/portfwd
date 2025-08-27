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
#include "kcp_map.h"
#include "3rd/kcp/ikcp.h"

static void print_usage(const char *prog) {
    P_LOG_INFO("Usage: %s [options] <local_udp_addr:port> <target_tcp_addr:port>", prog);
    P_LOG_INFO("Options (subset; KCP tunables to be added):");
    P_LOG_INFO("  -d                 run in background (daemonize)");
    P_LOG_INFO("  -p <pidfile>       write PID to file");
    P_LOG_INFO("  -r                 set SO_REUSEADDR on listener socket");
    P_LOG_INFO("  -R                 set SO_REUSEPORT on listener socket");
    P_LOG_INFO("  -6                 for IPv6 listener, set IPV6_V6ONLY");
    P_LOG_INFO("  -S <bytes>         SO_RCVBUF/SO_SNDBUF size (default build-time)");
    P_LOG_INFO("  -h                 show help");
}

struct cfg_server {
    union sockaddr_inx laddr; /* UDP listen */
    union sockaddr_inx taddr; /* TCP target */
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
    int epfd = -1, usock = -1;
    uint32_t magic_listener = 0xcafef00dU;
    struct cfg_server cfg;
    struct kcp_map cmap;
    struct list_head conns;
    INIT_LIST_HEAD(&conns);

    memset(&cmap, 0, sizeof(cmap));
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
        case 'h':
        default:
            print_usage(argv[0]);
            return (opt == 'h') ? 0 : 2;
        }
    }

    if (optind + 2 != argc) {
        print_usage(argv[0]);
        return 2;
    }

    if (get_sockaddr_inx_pair(argv[optind], &cfg.laddr, true) < 0) {
        P_LOG_ERR("invalid local udp addr: %s", argv[optind]);
        return 2;
    }
    if (get_sockaddr_inx_pair(argv[optind+1], &cfg.taddr, false) < 0) {
        P_LOG_ERR("invalid target tcp addr: %s", argv[optind+1]);
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

    /* Create UDP listen socket */
    usock = socket(cfg.laddr.sa.sa_family, SOCK_DGRAM, 0);
    if (usock < 0) {
        P_LOG_ERR("socket(udp): %s", strerror(errno));
        goto cleanup;
    }
    if (cfg.reuse_addr) {
        int on = 1;
        (void)setsockopt(usock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    }
#ifdef SO_REUSEPORT
    if (cfg.reuse_port) {
        int on = 1; 
        (void)setsockopt(usock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
    }
#endif
#ifdef IPV6_V6ONLY
    if (cfg.v6only && cfg.laddr.sa.sa_family == AF_INET6) {
        int on = 1;
        (void)setsockopt(usock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
    }
#endif
    set_nonblock(usock);
    set_sock_buffers_sz(usock, cfg.sockbuf_bytes);
    if (bind(usock, &cfg.laddr.sa, (socklen_t)sizeof_sockaddr(&cfg.laddr)) < 0) {
        P_LOG_ERR("bind(udp): %s", strerror(errno));
        goto cleanup;
    }

    struct epoll_event ev = {0};
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    ev.data.ptr = &magic_listener; /* tag udp listener */
    if (ep_add_or_mod(epfd, usock, &ev) < 0) {
        P_LOG_ERR("epoll_ctl add udp: %s", strerror(errno));
        goto cleanup;
    }

    if (kcp_map_init(&cmap, 1024) != 0) {
        P_LOG_ERR("kcp_map_init failed");
        goto cleanup;
    }

    P_LOG_INFO("kcptcp-server running: UDP %s -> TCP %s",
               sockaddr_to_string(&cfg.laddr), sockaddr_to_string(&cfg.taddr));

    struct kcp_opts kopts;
    kcp_opts_set_defaults(&kopts);

    while (!g_state.terminate) {
        /* Compute timeout from all KCP sessions */
        int timeout_ms = 1000;
        uint32_t now = kcp_now_ms();
        struct proxy_conn *pc;
        list_for_each_entry(pc, &conns, list) {
            uint32_t due = ikcp_check(pc->kcp, now);
            int t = (int)((due > now) ? (due - now) : 0);
            if (t < timeout_ms)
                timeout_ms = t;
        }

        struct epoll_event events[128];
        int nfds = epoll_wait(epfd, events, 128, timeout_ms);
        if (nfds < 0) {
            if (errno == EINTR) {
                /* continue to timer */
            }
            else {
                P_LOG_ERR("epoll_wait: %s", strerror(errno));
                break;
            }
        }

        for (int i = 0; i < nfds; ++i) {
            void *tag = events[i].data.ptr;
            if (tag == &magic_listener) {
                /* UDP packet(s) */
                for (;;) {
                    char buf[64 * 1024];
                    struct sockaddr_storage rss;
                    socklen_t ralen = sizeof(rss);
                    ssize_t rn = recvfrom(usock, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr*)&rss, &ralen);
                    if (rn < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;
                        P_LOG_ERR("recvfrom: %s", strerror(errno));
                        break;
                    }
                    if (rn == 0)
                        break;
                    /* Basic sanity: KCP header is 24 bytes */
                    if (rn < 24) {
                        P_LOG_WARN("drop short UDP pkt len=%zd", rn);
                        continue;
                    }
                    /* Build union sockaddr_inx from rss */
                    union sockaddr_inx ra;
                    memset(&ra, 0, sizeof(ra));
                    if (rss.ss_family == AF_INET) {
                        ra.sin = *(struct sockaddr_in*)&rss;
                    } else if (rss.ss_family == AF_INET6) {
                        ra.sin6 = *(struct sockaddr_in6*)&rss;
                    } else {
                        P_LOG_WARN("drop UDP from unknown family=%d", (int)rss.ss_family);
                        continue;
                    }
                    /* Extract conv and route */
                    uint32_t conv = ikcp_getconv(buf);
                    struct proxy_conn *c = kcp_map_get(&cmap, conv);
                    if (c && !is_sockaddr_inx_equal(&ra, &c->peer_addr)) {
                        P_LOG_WARN("drop UDP conv=%u from unexpected %s (expected %s)",
                                   conv, sockaddr_to_string(&ra), sockaddr_to_string(&c->peer_addr));
                        continue;
                    }
                    if (!c) {
                        /* New connection: create TCP to target */
                        int ts = socket(cfg.taddr.sa.sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
                        if (ts < 0) {
                            P_LOG_ERR("socket(tcp): %s", strerror(errno));
                            continue;
                        }
                        (void)set_sock_buffers_sz(ts, cfg.sockbuf_bytes);
                        /* Enable TCP keepalive */
                        int yes = 1;
                        (void)setsockopt(ts, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
                        int cr = connect(ts, &cfg.taddr.sa, (socklen_t)sizeof_sockaddr(&cfg.taddr));
                        if (cr < 0 && errno != EINPROGRESS) {
                            P_LOG_ERR("connect: %s", strerror(errno));
                            close(ts);
                            continue;
                        }

                        c = (struct proxy_conn*)calloc(1, sizeof(*c));
                        if (!c) {
                            P_LOG_ERR("calloc conn");
                            close(ts);
                            continue;
                        }
                        INIT_LIST_HEAD(&c->list);
                        c->state = S_SERVER_CONNECTING;
                        c->svr_sock = ts;
                        c->udp_sock = usock; /* shared */
                        c->peer_addr = ra;   /* client udp addr */
                        c->conv = conv;
                        c->last_active = time(NULL);
                        c->next_ka_ms = now + 30000; /* schedule first heartbeat in 30s */

                        if (kcp_setup_conn(c, usock, &ra, conv, &kopts) != 0) {
                            P_LOG_ERR("kcp_setup_conn failed");
                            close(ts);
                            free(c);
                            continue;
                        }

                        /* Register TCP server socket */
                        struct epoll_event tev = {0};
                        tev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
                        tev.data.ptr = c;
                        if (ep_add_or_mod(epfd, ts, &tev) < 0) {
                            P_LOG_ERR("epoll add tcp: %s", strerror(errno));
                            ikcp_release(c->kcp);
                            close(ts);
                            free(c);
                            continue;
                        }

                        list_add_tail(&c->list, &conns);
                        (void)kcp_map_put(&cmap, conv, c);
                        P_LOG_INFO("new conv=%u from %s", conv, sockaddr_to_string(&ra));
                    }

                    /* Feed KCP */
                    (void)ikcp_input(c->kcp, buf, (long)rn);
                    /* Drain to TCP */
                    for (;;) {
                        int peek = ikcp_peeksize(c->kcp);
                        if (peek < 0)
                            break;
                        if (peek > (int)sizeof(buf))
                            peek = (int)sizeof(buf);
                        int got = ikcp_recv(c->kcp, buf, peek);
                        if (got <= 0)
                            break;
                        /* If TCP connect not completed, buffer instead of sending */
                        if (c->state != S_FORWARDING) {
                            size_t need = (size_t)got;
                            size_t freecap = (c->request.capacity > c->request.dlen) ? (c->request.capacity - c->request.dlen) : 0;
                            if (freecap < need) {
                                size_t ncap = c->request.capacity ? c->request.capacity * 2 : (size_t)65536;
                                if (ncap < c->request.dlen + need) ncap = c->request.dlen + need;
                                char *np = (char*)realloc(c->request.data, ncap);
                                if (!np) { c->state = S_CLOSING; break; }
                                c->request.data = np;
                                c->request.capacity = ncap;
                            }
                            memcpy(c->request.data + c->request.dlen, buf, (size_t)got);
                            c->request.dlen += (size_t)got;
                            /* Ensure EPOLLOUT is enabled to both complete connect and flush later */
                            struct epoll_event tev2 = (struct epoll_event){0};
                            tev2.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
                            tev2.data.ptr = c;
                            (void)ep_add_or_mod(epfd, c->svr_sock, &tev2);
                            break;
                        }
                        ssize_t wn = send(c->svr_sock, buf, (size_t)got, MSG_NOSIGNAL);
                        if (wn < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                /* Backpressure: buffer and enable EPOLLOUT */
                                size_t need = (size_t)got;
                                size_t freecap = (c->request.capacity > c->request.dlen) ? (c->request.capacity - c->request.dlen) : 0;
                                if (freecap < need) {
                                    size_t ncap = c->request.capacity ? c->request.capacity * 2 : (size_t)65536;
                                    if (ncap < c->request.dlen + need) ncap = c->request.dlen + need;
                                    char *np = (char*)realloc(c->request.data, ncap);
                                    if (!np) { c->state = S_CLOSING; break; }
                                    c->request.data = np;
                                    c->request.capacity = ncap;
                                }
                                memcpy(c->request.data + c->request.dlen, buf, (size_t)got);
                                c->request.dlen += (size_t)got;
                                struct epoll_event tev2 = (struct epoll_event){0};
                                tev2.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
                                tev2.data.ptr = c;
                                (void)ep_add_or_mod(epfd, c->svr_sock, &tev2);
                                break;
                            }
                            c->state = S_CLOSING;
                            break;
                        } else if (wn < got) {
                            /* Short write: buffer remaining and enable EPOLLOUT */
                            size_t rem = (size_t)got - (size_t)wn;
                            size_t freecap = (c->request.capacity > c->request.dlen) ? (c->request.capacity - c->request.dlen) : 0;
                            if (freecap < rem) {
                                size_t ncap = c->request.capacity ? c->request.capacity * 2 : (size_t)65536;
                                if (ncap < c->request.dlen + rem) ncap = c->request.dlen + rem;
                                char *np = (char*)realloc(c->request.data, ncap);
                                if (!np) { c->state = S_CLOSING; break; }
                                c->request.data = np;
                                c->request.capacity = ncap;
                            }
                            memcpy(c->request.data + c->request.dlen, buf + wn, rem);
                            c->request.dlen += rem;
                            struct epoll_event tev2 = (struct epoll_event){0};
                            tev2.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
                            tev2.data.ptr = c;
                            (void)ep_add_or_mod(epfd, c->svr_sock, &tev2);
                            break;
                        }
                    }
                    c->last_active = time(NULL);
                }
                continue;
            }

            /* TCP events for an existing connection */
            struct proxy_conn *c = (struct proxy_conn*)tag;
            if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                c->state = S_CLOSING;
            }
            if ((events[i].events & EPOLLOUT) && c->state == S_SERVER_CONNECTING) {
                int err = 0;
                socklen_t elen = sizeof(err);
                if (getsockopt(c->svr_sock, SOL_SOCKET, SO_ERROR, &err, &elen) == 0 && err == 0) {
                    c->state = S_FORWARDING;
                } else {
                    c->state = S_CLOSING;
                }
            }
            if ((events[i].events & EPOLLOUT) && c->state == S_FORWARDING) {
                /* Flush pending request data to target TCP */
                while (c->request.rpos < c->request.dlen) {
                    ssize_t wn = send(c->svr_sock,
                                      c->request.data + c->request.rpos,
                                      c->request.dlen - c->request.rpos,
                                      MSG_NOSIGNAL);
                    if (wn > 0) {
                        c->request.rpos += (size_t)wn;
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
                    struct epoll_event tev2 = (struct epoll_event){0};
                    tev2.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
                    tev2.data.ptr = c;
                    (void)ep_add_or_mod(epfd, c->svr_sock, &tev2);
                }
            }
            if (events[i].events & EPOLLIN) {
                char sbuf[64 * 1024];
                ssize_t rn;
                while ((rn = recv(c->svr_sock, sbuf, sizeof(sbuf), 0)) > 0) {
                    int sn = ikcp_send(c->kcp, sbuf, (int)rn);
                    if (sn < 0) {
                        c->state = S_CLOSING;
                        break;
                    }
                    c->last_active = time(NULL);
                }
                if (rn == 0) {
                    c->state = S_CLOSING;
                } else if (rn < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    c->state = S_CLOSING;
                }
            }
        }

        /* Timers and cleanup */
        now = kcp_now_ms();
        struct proxy_conn *pos, *tmp;
        list_for_each_entry_safe(pos, tmp, &conns, list) {
            (void)kcp_update_flush(pos, now);
            /* Heartbeat over KCP every 30s to keep NAT/paths warm */
            if (pos->state != S_CLOSING && pos->kcp && pos->next_ka_ms && (int32_t)(now - pos->next_ka_ms) >= 0) {
                static const char ka = 0;
                (void)ikcp_send(pos->kcp, &ka, 1);
                pos->next_ka_ms = now + 30000;
            }
            /* Idle timeout (e.g., 180s) */
            time_t ct = time(NULL);
            const time_t IDLE_TO = 180;
            if (pos->state != S_CLOSING && pos->last_active && (ct - pos->last_active) > IDLE_TO) {
                P_LOG_INFO("idle timeout, conv=%u", pos->conv);
                pos->state = S_CLOSING;
            }
            if (pos->state == S_CLOSING) {
                (void)ep_del(epfd, pos->svr_sock);
                kcp_map_del(&cmap, pos->conv);
                if (pos->kcp) ikcp_release(pos->kcp);
                close(pos->svr_sock);
                if (pos->request.data) free(pos->request.data);
                if (pos->response.data) free(pos->response.data);
                list_del(&pos->list);
                free(pos);
            }
        }
    }

    rc = 0;

cleanup:
    if (usock >= 0) close(usock);
    if (epfd >= 0) epoll_close_comp(epfd);
    kcp_map_free(&cmap);
    cleanup_pidfile();
    return rc;
}
