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
#include "kcp_common.h"
#include "kcptcp_common.h"
#include "kcp_map.h"
#include "aead_protocol.h"
#include "aead.h"
#include "anti_replay.h"
#include "buffer_limits.h"
#include "3rd/chacha20poly1305/chacha20poly1305.h"
#include "3rd/kcp/ikcp.h"

static void print_usage(const char *prog) {
    P_LOG_INFO(
        "Usage: %s [options] <local_udp_addr:port> <target_tcp_addr:port>",
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
    P_LOG_INFO(
        "  -N                 enable TCP_NODELAY on outbound TCP to target");
    P_LOG_INFO("  -K <hex>           32-byte PSK in hex (ChaCha20-Poly1305)");
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
    bool tcp_nodelay;
    bool has_psk;
    uint8_t psk[32];
};

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

    int kcp_mtu = -1;
    int kcp_nd = -1, kcp_it = -1, kcp_rs = -1, kcp_nc = -1, kcp_snd = -1,
        kcp_rcv = -1;

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

    /* Create UDP listen socket via shared helper */
    usock =
        kcptcp_setup_udp_listener(&cfg.laddr, cfg.reuse_addr, cfg.reuse_port,
                                  cfg.v6only, cfg.sockbuf_bytes);
    if (usock < 0)
        goto cleanup;

    if (kcptcp_ep_register_listener(epfd, usock, &magic_listener) < 0) {
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
    kcp_opts_apply_overrides(&kopts, kcp_mtu, kcp_nd, kcp_it, kcp_rs, kcp_nc,
                             kcp_snd, kcp_rcv);

    while (!g_state.terminate) {
        /* Compute timeout from all KCP sessions */
        int timeout_ms = kcptcp_compute_kcp_timeout_ms(&conns, 1000);

        struct epoll_event events[128];
        int nfds = epoll_wait(epfd, events, 128, timeout_ms);
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
                    char buf[64 * 1024];
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
                        P_LOG_WARN("drop UDP from unknown family=%d",
                                   (int)rss.ss_family);
                        continue;
                    }
                    /* Handshake first: if this is HELLO, allocate conv and
                     * respond */
                    if (rn >= 2 &&
                        (unsigned char)buf[0] == (unsigned char)KTP_HS_HELLO &&
                        (unsigned char)buf[1] == (unsigned char)KCP_HS_VER) {
                        if (rn < 2 + 16) {
                            P_LOG_WARN("HELLO too short len=%zd", rn);
                            continue;
                        }
                        /* Create TCP to target via shared helper */
                        int ts = kcptcp_create_tcp_socket(
                            cfg.taddr.sa.sa_family, cfg.sockbuf_bytes,
                            cfg.tcp_nodelay);
                        if (ts < 0) {
                            continue;
                        }
                        int yes = 1;
                        (void)setsockopt(ts, SOL_SOCKET, SO_KEEPALIVE, &yes,
                                         sizeof(yes));

                        int cr =
                            connect(ts, &cfg.taddr.sa,
                                    (socklen_t)sizeof_sockaddr(&cfg.taddr));
                        if (cr < 0 && errno != EINPROGRESS) {
                            P_LOG_ERR("connect: %s", strerror(errno));
                            close(ts);
                            continue;
                        }

                        struct proxy_conn *nc =
                            (struct proxy_conn *)calloc(1, sizeof(*nc));
                        if (!nc) {
                            P_LOG_ERR("calloc conn");
                            close(ts);
                            continue;
                        }
                        INIT_LIST_HEAD(&nc->list);
                        nc->state = S_SERVER_CONNECTING;
                        nc->svr_sock = ts;
                        nc->udp_sock = usock;
                        nc->peer_addr = ra;
                        memcpy(nc->hs_token, buf + 2, 16);
                        nc->last_active = time(NULL);
                        /* Allocate unique conv */
                        static uint32_t next_conv = 1u;
                        uint32_t conv_try;
                        do {
                            conv_try = next_conv++;
                        } while (kcp_map_get(&cmap, conv_try) != NULL);
                        nc->conv = conv_try;

                        /* Derive session key if PSK provided */
                        if (cfg.has_psk) {
                            if (derive_session_key_from_psk(
                                    (const uint8_t *)cfg.psk, nc->hs_token,
                                    nc->conv, nc->session_key) == 0) {
                                nc->has_session_key = true;
                                /* Initialize AEAD nonce base and counters */
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
                                if (nc->request.data)
                                    free(nc->request.data);
                                if (nc->response.data)
                                    free(nc->response.data);
                                if (nc->udp_backlog.data)
                                    free(nc->udp_backlog.data);
                                free(nc);
                                continue;
                            }
                        }

                        if (kcp_setup_conn(nc, usock, &ra, nc->conv, &kopts) !=
                            0) {
                            P_LOG_ERR("kcp_setup_conn failed");
                            close(ts);
                            if (nc->request.data)
                                free(nc->request.data);
                            if (nc->response.data)
                                free(nc->response.data);
                            if (nc->udp_backlog.data)
                                free(nc->udp_backlog.data);
                            kcp_map_del(&cmap, nc->conv);
                            free(nc);
                            continue;
                        }

                        /* Register TCP server socket */
                        if (kcptcp_ep_register_tcp(epfd, ts, nc, true) < 0) {
                            P_LOG_ERR("epoll add tcp: %s", strerror(errno));
                            if (nc->kcp)
                                ikcp_release(nc->kcp);
                            close(ts);
                            if (nc->request.data)
                                free(nc->request.data);
                            if (nc->response.data)
                                free(nc->response.data);
                            if (nc->udp_backlog.data)
                                free(nc->udp_backlog.data);
                            kcp_map_del(&cmap, nc->conv);
                            free(nc);
                            continue;
                        }
                        list_add_tail(&nc->list, &conns);
                        (void)kcp_map_put(&cmap, nc->conv, nc);

                        /* Send ACCEPT: [type=ACCEPT][ver][conv(4)][token(16)]
                         */
                        unsigned char abuf[1 + 1 + 4 + 16];
                        abuf[0] = (unsigned char)KTP_HS_ACCEPT;
                        abuf[1] = (unsigned char)KCP_HS_VER;
                        abuf[2] = (unsigned char)((nc->conv >> 24) & 0xff);
                        abuf[3] = (unsigned char)((nc->conv >> 16) & 0xff);
                        abuf[4] = (unsigned char)((nc->conv >> 8) & 0xff);
                        abuf[5] = (unsigned char)(nc->conv & 0xff);
                        memcpy(abuf + 6, nc->hs_token, 16);
                        (void)sendto(
                            usock, abuf, sizeof(abuf), MSG_DONTWAIT,
                            &nc->peer_addr.sa,
                            (socklen_t)sizeof_sockaddr(&nc->peer_addr));
                        P_LOG_INFO("accept conv=%u for %s", nc->conv,
                                   sockaddr_to_string(&ra));
                        continue;
                    }

                    /* Otherwise expect KCP packet for existing conv */
                    if (rn < 24) {
                        P_LOG_WARN("drop non-handshake short UDP pkt len=%zd",
                                   rn);
                        continue;
                    }
                    uint32_t conv = ikcp_getconv(buf);
                    struct proxy_conn *c = kcp_map_get(&cmap, conv);
                    if (!c) {
                        P_LOG_WARN("drop UDP for unknown conv=%u from %s", conv,
                                   sockaddr_to_string(&ra));
                        continue;
                    }
                    if (!is_sockaddr_inx_equal(&ra, &c->peer_addr)) {
                        P_LOG_WARN(
                            "drop UDP conv=%u from unexpected %s (expected %s)",
                            conv, sockaddr_to_string(&ra),
                            sockaddr_to_string(&c->peer_addr));
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
                                c->response.dlen == c->response.rpos &&
                                c->svr_sock > 0) {
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
                            size_t need = (size_t)plen;
                            size_t freecap =
                                (c->request.capacity > c->request.dlen)
                                    ? (c->request.capacity - c->request.dlen)
                                    : 0;
                            if (freecap < need) {
                                size_t ncap = c->request.capacity
                                                  ? c->request.capacity * 2
                                                  : INITIAL_BUFFER_SIZE;
                                if (ncap < c->request.dlen + need)
                                    ncap = c->request.dlen + need;
                                if (!buffer_size_check(c->request.capacity,
                                                       ncap,
                                                       MAX_TCP_BUFFER_SIZE)) {
                                    P_LOG_WARN("Request buffer size limit "
                                               "exceeded, closing connection");
                                    c->state = S_CLOSING;
                                    break;
                                }
                                char *np =
                                    (char *)realloc(c->request.data, ncap);
                                if (!np) {
                                    if (c->request.data)
                                        free(c->request.data);
                                    c->request.data = NULL;
                                    c->request.capacity = 0;
                                    c->request.dlen = 0;
                                    c->request.rpos = 0;
                                    c->state = S_CLOSING;
                                    break;
                                }
                                c->request.data = np;
                                c->request.capacity = ncap;
                            }
                            memcpy(c->request.data + c->request.dlen, payload,
                                   (size_t)plen);
                            c->request.dlen += (size_t)plen;
                            (void)kcptcp_ep_register_tcp(epfd, c->svr_sock, c,
                                                         true);
                            break;
                        }
                        ssize_t wn = send(c->svr_sock, payload, (size_t)plen,
                                          MSG_NOSIGNAL);
                        if (wn < 0 &&
                            (errno == EAGAIN || errno == EWOULDBLOCK)) {
                            /* Would block: buffer all and enable EPOLLOUT */
                            size_t rem = (size_t)plen;
                            size_t freecap =
                                (c->request.capacity > c->request.dlen)
                                    ? (c->request.capacity - c->request.dlen)
                                    : 0;
                            if (freecap < rem) {
                                size_t ncap = c->request.capacity
                                                  ? c->request.capacity * 2
                                                  : INITIAL_BUFFER_SIZE;
                                if (ncap < c->request.dlen + rem)
                                    ncap = c->request.dlen + rem;

                                /* Check buffer size limit before realloc */
                                if (!buffer_size_check(c->request.capacity,
                                                       ncap,
                                                       MAX_TCP_BUFFER_SIZE)) {
                                    P_LOG_WARN("Buffer size limit exceeded for "
                                               "connection, closing");
                                    c->state = S_CLOSING;
                                    break;
                                }

                                char *np =
                                    (char *)realloc(c->request.data, ncap);
                                if (!np) {
                                    if (c->request.data)
                                        free(c->request.data);
                                    c->request.data = NULL;
                                    c->request.capacity = 0;
                                    c->request.dlen = 0;
                                    c->request.rpos = 0;
                                    c->state = S_CLOSING;
                                    break;
                                }
                                c->request.data = np;
                                c->request.capacity = ncap;
                            }
                            memcpy(c->request.data + c->request.dlen, payload,
                                   rem);
                            c->request.dlen += rem;
                            (void)kcptcp_ep_register_tcp(epfd, c->svr_sock, c,
                                                         true);
                            break;
                        } else if (wn < 0) {
                            c->state = S_CLOSING;
                            break;
                        } else if (wn < plen) {
                            /* Short write: buffer remaining and enable EPOLLOUT
                             */
                            size_t rem = (size_t)plen - (size_t)wn;
                            size_t freecap =
                                (c->request.capacity > c->request.dlen)
                                    ? (c->request.capacity - c->request.dlen)
                                    : 0;
                            if (freecap < rem) {
                                size_t ncap = c->request.capacity
                                                  ? c->request.capacity * 2
                                                  : INITIAL_BUFFER_SIZE;
                                if (ncap < c->request.dlen + rem)
                                    ncap = c->request.dlen + rem;
                                
                                /* Check buffer size limit before realloc */
                                if (!buffer_size_check(c->request.capacity,
                                                       ncap,
                                                       MAX_TCP_BUFFER_SIZE)) {
                                    P_LOG_WARN("Buffer size limit exceeded for "
                                               "connection, closing");
                                    c->state = S_CLOSING;
                                    break;
                                }
                                
                                char *np =
                                    (char *)realloc(c->request.data, ncap);
                                if (!np) {
                                    if (c->request.data)
                                        free(c->request.data);
                                    c->request.data = NULL;
                                    c->request.capacity = 0;
                                    c->request.dlen = 0;
                                    c->request.rpos = 0;
                                    c->state = S_CLOSING;
                                    break;
                                }
                                c->request.data = np;
                                c->request.capacity = ncap;
                            }
                            memcpy(c->request.data + c->request.dlen,
                                   payload + wn, rem);
                            c->request.dlen += rem;
                            if (wn > 0)
                                c->tcp_tx_bytes +=
                                    (uint64_t)wn; /* Stats: TCP TX */
                            (void)kcptcp_ep_register_tcp(epfd, c->svr_sock, c,
                                                         true);
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
                if ((events[i].events & EPOLLOUT) &&
                    c->state == S_SERVER_CONNECTING) {
                    int err = 0;
                    socklen_t elen = sizeof(err);
                    if (getsockopt(c->svr_sock, SOL_SOCKET, SO_ERROR, &err,
                                   &elen) == 0 &&
                        err == 0) {
                        c->state = S_FORWARDING;
                    } else {
                        c->state = S_CLOSING;
                    }
                }
                if ((events[i].events & EPOLLOUT) && c->state == S_FORWARDING) {
                    /* Flush pending request data to target TCP */
                    while (c->request.rpos < c->request.dlen) {
                        ssize_t wn = send(
                            c->svr_sock, c->request.data + c->request.rpos,
                            c->request.dlen - c->request.rpos, MSG_NOSIGNAL);
                        if (wn > 0) {
                            c->request.rpos += (size_t)wn;
                            c->tcp_tx_bytes += (uint64_t)wn; /* Stats: TCP TX */
                        } else if (wn < 0 &&
                                   (errno == EAGAIN || errno == EWOULDBLOCK)) {
                            break;
                        } else {
                            c->state = S_CLOSING;
                            break;
                        }
                    }
                    if (c->request.rpos >= c->request.dlen) {
                        c->request.rpos = 0;
                        c->request.dlen = 0;
                        (void)kcptcp_ep_register_tcp(epfd, c->svr_sock, c,
                                                     false);
                        /* If we got FIN from peer earlier, perform shutdown
                         * write now */
                        if (c->cli_in_eof && !c->cli2svr_shutdown &&
                            c->svr_sock > 0) {
                            shutdown(c->svr_sock, SHUT_WR);
                            c->cli2svr_shutdown = true;
                        }
                    }
                }
                if (events[i].events & EPOLLIN) {
                    char sbuf[64 * 1024];
                    ssize_t rn;
                    while ((rn = recv(c->svr_sock, sbuf, sizeof(sbuf), 0)) >
                           0) {
                        c->tcp_rx_bytes += (uint64_t)rn; /* Stats: TCP RX */
                        if (aead_protocol_send_data(c, sbuf, rn, cfg.psk,
                                                    cfg.has_psk) < 0) {
                            c->state = S_CLOSING;
                            break;
                        }
                    }
                    if (rn == 0) {
                        /* TCP target sent EOF: send FIN/EFIN over KCP, stop
                         * further reads, allow pending KCP to flush */
                        if (aead_protocol_send_fin(c, cfg.psk, cfg.has_psk) <
                            0) {
                            c->state = S_CLOSING;
                        }
                        c->svr_in_eof = true;
                        struct epoll_event tev2 = (struct epoll_event){0};
                        tev2.events = EPOLLOUT | EPOLLRDHUP | EPOLLERR |
                                      EPOLLHUP; /* disable EPOLLIN */
                        tev2.data.ptr = c;
                        (void)ep_add_or_mod(epfd, c->svr_sock, &tev2);
                    } else if (rn < 0 && errno != EAGAIN &&
                               errno != EWOULDBLOCK) {
                        c->state = S_CLOSING;
                    }
                }
            }

        }

        /* Timers and cleanup */
        uint32_t now = kcp_now_ms();

        struct proxy_conn *pos, *tmp;
        list_for_each_entry_safe(pos, tmp, &conns, list) {
            (void)kcp_update_flush(pos, now);
            /* If server TCP got EOF, wait until all buffered client->server
             * data is flushed before closing */
            if (pos->svr_in_eof && pos->state != S_CLOSING) {
                bool tcp_buf_empty = (pos->request.dlen == pos->request.rpos);
                int kcp_unsent = pos->kcp ? ikcp_waitsnd(pos->kcp) : 0;
                bool udp_backlog_empty = (pos->udp_backlog.dlen == 0);
                if (tcp_buf_empty && kcp_unsent == 0 && udp_backlog_empty) {
                    pos->state = S_CLOSING;
                }
            }
            /* Idle timeout (e.g., 180s) */
            time_t ct = time(NULL);
            const time_t IDLE_TO = 180;
            if (pos->state != S_CLOSING && pos->last_active &&
                (ct - pos->last_active) > IDLE_TO) {
                P_LOG_INFO("idle timeout, conv=%u", pos->conv);
                pos->state = S_CLOSING;
            }
            /* Rekey timeout enforcement */
            if (pos->state != S_CLOSING && pos->has_session_key &&
                pos->rekey_in_progress) {
                if (now >= pos->rekey_deadline_ms) {
                    P_LOG_ERR("rekey timeout, closing conv=%u (svr)",
                              pos->conv);
                    pos->state = S_CLOSING;
                }
            }
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
                } else if (now_ms - pos->last_stat_ms >= get_stats_interval_ms()) {
                    uint64_t dt = now_ms - pos->last_stat_ms;
                    uint64_t d_tcp_rx = pos->tcp_rx_bytes - pos->last_tcp_rx_bytes;
                    uint64_t d_tcp_tx = pos->tcp_tx_bytes - pos->last_tcp_tx_bytes;
                    uint64_t d_kcp_tx = pos->kcp_tx_bytes - pos->last_kcp_tx_bytes;
                    uint64_t d_kcp_rx = pos->kcp_rx_bytes - pos->last_kcp_rx_bytes;
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
                    P_LOG_INFO(
                        "stats conv=%u: TCP in=%.3f Mbps out=%.3f Mbps | "
                        "KCP payload in=%.3f Mbps out=%.3f Mbps | KCP "
                        "xmit_delta=%u RTT=%dms | rekey i=%u c=%u",
                        pos->conv, tcp_in_mbps, tcp_out_mbps, kcp_in_mbps,
                        kcp_out_mbps, d_xmit, pos->kcp->rx_srtt, d_rekey_i,
                        d_rekey_c);
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
            if (pos->state == S_CLOSING) {
                if (get_stats_dump_enabled()) {
                    P_LOG_INFO(
                        "stats total conv=%u: tcp_rx=%llu tcp_tx=%llu "
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
                (void)ep_del(epfd, pos->svr_sock);
                kcp_map_del(&cmap, pos->conv);
                if (pos->kcp)
                    ikcp_release(pos->kcp);
                close(pos->svr_sock);
                if (pos->request.data)
                    free(pos->request.data);
                if (pos->response.data)
                    free(pos->response.data);
                if (pos->udp_backlog.data)
                    free(pos->udp_backlog.data);
                list_del(&pos->list);
                free(pos);
            }
        }
    }

    rc = 0;

cleanup:
    if (usock >= 0)
        close(usock);
    if (epfd >= 0)
        epoll_close_comp(epfd);
    kcp_map_free(&cmap);
    cleanup_pidfile();
    return rc;
}
