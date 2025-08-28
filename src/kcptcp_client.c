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
};

static void client_handle_accept(struct client_ctx *ctx);
static void client_handle_udp_events(struct client_ctx *ctx,
                                     struct proxy_conn *c,
                                     uint32_t evmask);
static void client_handle_tcp_events(struct client_ctx *ctx,
                                     struct proxy_conn *c,
                                     uint32_t evmask);

/* UDP socket events for a single connection */
static void client_handle_udp_events(struct client_ctx *ctx,
                                     struct proxy_conn *c,
                                     uint32_t evmask) {
    if (!(evmask & EPOLLIN)) {
        return;
    }
    char ubuf[64 * 1024];
    bool fed_kcp = false;
    for (;;) {
        struct sockaddr_storage rss;
        socklen_t rlen = sizeof(rss);
        ssize_t rn = recvfrom(c->udp_sock, ubuf, sizeof(ubuf), MSG_DONTWAIT,
                              (struct sockaddr *)&rss, &rlen);
        if (rn < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            P_LOG_WARN("recvfrom udp: %s", strerror(errno));
            break;
        }
        if (rn == 0) {
            break;
        }
        /* Stats: count UDP RX bytes */
        c->udp_rx_bytes += (uint64_t)rn;
        /* Validate UDP source address matches expected peer */
        union sockaddr_inx ra;
        memset(&ra, 0, sizeof(ra));
        if (rss.ss_family == AF_INET) {
            struct sockaddr_in *in4 = (struct sockaddr_in *)&rss;
            ra.sin = *in4;
        } else if (rss.ss_family == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&rss;
            ra.sin6 = *in6;
        } else {
            continue; /* Unknown family: drop */
        }
        if (!is_sockaddr_inx_equal(&ra, &c->peer_addr)) {
            P_LOG_WARN("dropping UDP from unexpected %s (expected %s)",
                       sockaddr_to_string(&ra),
                       sockaddr_to_string(&c->peer_addr));
            continue;
        }
        /* Handshake ACCEPT path */
        if (!c->kcp_ready && rn >= (ssize_t)(1 + 1 + 4 + 16) &&
            (unsigned char)ubuf[0] == (unsigned char)KTP_HS_ACCEPT &&
            (unsigned char)ubuf[1] == (unsigned char)KCP_HS_VER) {
            uint32_t conv = (uint32_t)((unsigned char)ubuf[2] << 24 |
                                       (unsigned char)ubuf[3] << 16 |
                                       (unsigned char)ubuf[4] << 8 |
                                       (unsigned char)ubuf[5]);
            if (memcmp(ubuf + 6, c->hs_token, 16) != 0) {
                P_LOG_WARN("ACCEPT token mismatch; ignore");
                continue;
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
                    c->state = S_CLOSING;
                    break;
                }
            }
            if (kcp_setup_conn(c, c->udp_sock, &c->peer_addr, c->conv,
                               ctx->kopts) != 0) {
                P_LOG_ERR("kcp_setup_conn failed after ACCEPT");
                c->state = S_CLOSING;
                break;
            }
            c->kcp_ready = true;
            c->next_ka_ms = kcp_now_ms() + 30000;
            P_LOG_INFO("handshake ACCEPT: conv=%u", c->conv);
            /* Flush any buffered request data */
            if (c->request.dlen > c->request.rpos) {
                size_t remain = c->request.dlen - c->request.rpos;
                if (aead_protocol_send_data(c, c->request.data + c->request.rpos, (int)remain, ctx->cfg->psk, ctx->cfg->has_psk) < 0) {
                    c->state = S_CLOSING;
                    break;
                }
                c->request.rpos = c->request.dlen; /* consumed */
            }
            /* If TCP already EOF, send FIN now */
            if (c->cli_in_eof) {
                if (aead_protocol_send_fin(c, ctx->cfg->psk, ctx->cfg->has_psk) < 0) {
                    c->state = S_CLOSING;
                    break;
                }
            }
            continue;
        }
        if (!c->kcp_ready) {
            /* Not ready and not ACCEPT: ignore */
            continue;
        }
        (void)ikcp_input(c->kcp, ubuf, (long)rn);
        fed_kcp = true;
    }
    if (fed_kcp) {
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

            char *payload = NULL;
            int plen = 0;
            int res = aead_protocol_handle_incoming_packet(c, ubuf, got, ctx->cfg->psk, ctx->cfg->has_psk, &payload, &plen);

            if (res < 0) { // Error
                c->state = S_CLOSING;
                break;
            }
            if (res > 0) { // Control packet handled
                if (c->svr_in_eof && !c->svr2cli_shutdown && c->response.dlen == c->response.rpos) {
                    shutdown(c->cli_sock, SHUT_WR);
                    c->svr2cli_shutdown = true;
                }
                continue;
            }

            if (!payload || plen <= 0) {
                continue;
            }

            c->kcp_rx_bytes += (uint64_t)plen;
            ssize_t wn = send(c->cli_sock, payload, (size_t)plen, MSG_NOSIGNAL);
            if (wn < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    /* Backpressure: buffer and enable EPOLLOUT */
                    size_t need = (size_t)plen;
                    size_t freecap = (c->response.capacity > c->response.dlen)
                                         ? (c->response.capacity -
                                            c->response.dlen)
                                         : 0;
                    if (freecap < need) {
                        size_t ncap = c->response.capacity
                                          ? c->response.capacity * 2
                                          : INITIAL_BUFFER_SIZE;
                        if (ncap < c->response.dlen + need)
                            ncap = c->response.dlen + need;
                        if (!buffer_size_check(c->response.capacity, ncap, MAX_TCP_BUFFER_SIZE)) {
                            P_LOG_WARN("Response buffer size limit exceeded, closing connection");
                            c->state = S_CLOSING;
                            break;
                        }
                        char *np = (char *)realloc(c->response.data, ncap);
                        if (!np) {
                            c->state = S_CLOSING;
                            break;
                        }
                        c->response.data = np;
                        c->response.capacity = ncap;
                    }
                    memcpy(c->response.data + c->response.dlen, payload,
                           (size_t)plen);
                    c->response.dlen += (size_t)plen;
                    struct epoll_event cev = (struct epoll_event){0};
                    cev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR |
                                 EPOLLHUP;
                    cev.data.ptr = c->cli_tag;
                    (void)ep_add_or_mod(ctx->epfd, c->cli_sock, &cev);
                    break;
                }
                c->state = S_CLOSING;
                break;
            } else if (wn < plen) {
                /* Short write: buffer remaining and enable EPOLLOUT */
                size_t rem = (size_t)plen - (size_t)wn;
                size_t freecap = (c->response.capacity > c->response.dlen)
                                     ? (c->response.capacity -
                                        c->response.dlen)
                                     : 0;
                if (freecap < rem) {
                    size_t ncap = c->response.capacity
                                      ? c->response.capacity * 2
                                      : INITIAL_BUFFER_SIZE;
                    if (ncap < c->response.dlen + rem)
                        ncap = c->response.dlen + rem;
                    if (!buffer_size_check(c->response.capacity, ncap, MAX_TCP_BUFFER_SIZE)) {
                        P_LOG_WARN("Response buffer size limit exceeded, closing connection");
                        c->state = S_CLOSING;
                        break;
                    }
                    char *np = (char *)realloc(c->response.data, ncap);
                    if (!np) {
                        c->state = S_CLOSING;
                        break;
                    }
                    c->response.data = np;
                    c->response.capacity = ncap;
                }
                memcpy(c->response.data + c->response.dlen, payload + wn, rem);
                c->response.dlen += rem;
                struct epoll_event cev = (struct epoll_event){0};
                cev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR |
                             EPOLLHUP;
                cev.data.ptr = c->cli_tag;
                (void)ep_add_or_mod(ctx->epfd, c->cli_sock, &cev);
                break;
            }
            /* Stats: count TCP TX bytes to client */
            if (wn > 0)
                c->tcp_tx_bytes += (uint64_t)wn;
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
        kcptcp_tune_tcp_socket(cs, 0 /*no change*/, ctx->cfg->tcp_nodelay,
                               true /*keepalive*/);
        /* Create per-connection UDP socket via shared helper */
        int us = kcptcp_create_udp_socket(ctx->cfg->raddr.sa.sa_family,
                                          ctx->cfg->sockbuf_bytes);
        if (us < 0) {
            close(cs);
            continue;
        }


        /* Allocate connection */
        struct proxy_conn *c = (struct proxy_conn *)calloc(1, sizeof(*c));
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
        c->peer_addr = ctx->cfg->raddr;
        c->last_active = time(NULL);
        c->kcp = NULL; /* not created until ACCEPT */
        c->kcp_ready = false;
        c->next_ka_ms = 0;
        /* Generate 16-byte token using cryptographically secure random */
        if (secure_random_bytes(c->hs_token, 16) != 0) {
            P_LOG_ERR("Failed to generate secure random token");
            c->state = S_CLOSING;
            break;
        }
        /* Send HELLO: [type][ver][token(16)] */
        unsigned char hbuf[1 + 1 + 16];
        hbuf[0] = (unsigned char)KTP_HS_HELLO;
        hbuf[1] = (unsigned char)KCP_HS_VER;
        memcpy(hbuf + 2, c->hs_token, 16);
        (void)sendto(c->udp_sock, hbuf, sizeof(hbuf), MSG_DONTWAIT,
                     &c->peer_addr.sa,
                     (socklen_t)sizeof_sockaddr(&c->peer_addr));

        /* Prepare epoll tags */
        struct ep_tag *ctag = (struct ep_tag *)malloc(sizeof(*ctag));
        struct ep_tag *utag = (struct ep_tag *)malloc(sizeof(*utag));
        if (!ctag || !utag) {
            P_LOG_ERR("malloc ep_tag");
            if (ctag)
                free(ctag);
            if (utag)
                free(utag);
            if (c->kcp)
                ikcp_release(c->kcp);
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
            if (c->kcp)
                ikcp_release(c->kcp);
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
            if (c->kcp)
                ikcp_release(c->kcp);
            close(cs);
            close(us);
            free(ctag);
            free(utag);
            free(c);
            continue;
        }

        list_add_tail(&c->list, ctx->conns);
        P_LOG_INFO("accepted TCP %s, conv=%u",
                   sockaddr_to_string(&ca), c->conv);
    }
}

/* TCP client socket events for a single connection */
static void client_handle_tcp_events(struct client_ctx *ctx,
                                     struct proxy_conn *c,
                                     uint32_t evmask) {
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
            (void)ep_add_or_mod(ctx->epfd, c->cli_sock, &cev);
            /* If we received FIN earlier, shutdown write now that buffer is drained */
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
                size_t need = (size_t)rn;
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
                    if (!buffer_size_check(c->request.capacity, ncap, MAX_TCP_BUFFER_SIZE)) {
                        P_LOG_WARN("Request buffer size limit exceeded, closing connection");
                        c->state = S_CLOSING;
                        break;
                    }
                    char *np = (char *)realloc(c->request.data, ncap);
                    if (!np) {
                        c->state = S_CLOSING;
                        break;
                    }
                    c->request.data = np;
                    c->request.capacity = ncap;
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
            (void)ep_add_or_mod(ctx->epfd, c->cli_sock, &cev);
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
    if (opts.has_psk) memcpy(cfg.psk, opts.psk, 32);

    kcp_mtu = opts.kcp_mtu;
    kcp_nd = opts.kcp_nd; kcp_it = opts.kcp_it; kcp_rs = opts.kcp_rs;
    kcp_nc = opts.kcp_nc; kcp_snd = opts.kcp_snd; kcp_rcv = opts.kcp_rcv;

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

    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        P_LOG_ERR("epoll_create1: %s", strerror(errno));
        goto cleanup;
    }

    /* Create TCP listen socket via shared helper */
    lsock = kcptcp_setup_tcp_listener(&cfg.laddr, cfg.reuse_addr,
                                      cfg.reuse_port, cfg.v6only,
                                      cfg.sockbuf_bytes, 128);
    if (lsock < 0) goto cleanup;

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

    /* Event loop: accept TCP, bridge via KCP over UDP */
    while (!g_state.terminate) {
        /* Compute dynamic timeout from all KCP connections */
        int timeout_ms = kcptcp_compute_kcp_timeout_ms(&conns, 1000);

        struct epoll_event events[128];
        int nfds = epoll_wait(epfd, events, 128, timeout_ms);
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
                (void)ep_del(epfd, pos->cli_sock);
                (void)ep_del(epfd, pos->udp_sock);
                if (pos->kcp)
                    ikcp_release(pos->kcp);
                close(pos->cli_sock);
                close(pos->udp_sock);
                if (pos->request.data)
                    free(pos->request.data);
                if (pos->response.data)
                    free(pos->response.data);
                if (pos->udp_backlog.data)
                    free(pos->udp_backlog.data);
                if (pos->cli_tag)
                    free(pos->cli_tag);
                if (pos->udp_tag)
                    free(pos->udp_tag);
                list_del(&pos->list);
                free(pos);
            }
        }
    }

    rc = 0;

cleanup:
    if (lsock >= 0)
        close(lsock);
    if (epfd >= 0)
        epoll_close_comp(epfd);
    cleanup_pidfile();
    return rc;
}
