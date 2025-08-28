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
#include "aead.h"
#include "3rd/chacha20poly1305/chacha20poly1305.h"
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
    P_LOG_INFO("  -M <mtu>           KCP MTU (default 1350; lower if frequent fragmentation)");
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
    bool has_psk;
    uint8_t psk[32];
};

static void set_sock_buffers_sz(int sockfd, int bytes) {
    if (bytes <= 0) return;
    (void)setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes));
    (void)setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
}

static int hex2nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool parse_psk_hex32(const char *hex, uint8_t out[32]) {
    size_t n = strlen(hex);
    if (n != 64) return false;
    for (size_t i = 0; i < 32; ++i) {
        int hi = hex2nibble(hex[2*i]);
        int lo = hex2nibble(hex[2*i+1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
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

    int kcp_mtu = -1;
    int opt;
    while ((opt = getopt(argc, argv, "dp:rR6S:M:K:h")) != -1) {
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
        case 'M': {
            char *end = NULL;
            long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v <= 0) {
                P_LOG_WARN("invalid -M value '%s'", optarg);
            } else {
                if (v < 576) v = 576;
                if (v > 1500) v = 1500;
                kcp_mtu = (int)v;
            }
            break;
        }
        case 'K': {
            uint8_t key[32];
            if (!parse_psk_hex32(optarg, key)) {
                P_LOG_ERR("invalid -K PSK (expect 64 hex chars)");
                return 2;
            }
            memcpy(cfg.psk, key, 32);
            cfg.has_psk = true;
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
    if (kcp_mtu > 0) {
        kopts.mtu = kcp_mtu;
    }

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
                    /* Handshake first: if this is HELLO, allocate conv and respond */
                    if (rn >= 2 && (unsigned char)buf[0] == (unsigned char)KTP_HS_HELLO && (unsigned char)buf[1] == (unsigned char)KCP_HS_VER) {
                        if (rn < 2 + 16) {
                            P_LOG_WARN("HELLO too short len=%zd", rn);
                            continue;
                        }
                        /* Create TCP to target */
                        int ts = socket(cfg.taddr.sa.sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
                        if (ts < 0) { P_LOG_ERR("socket(tcp): %s", strerror(errno)); continue; }
                        (void)set_sock_buffers_sz(ts, cfg.sockbuf_bytes);
                        int yes = 1; (void)setsockopt(ts, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
                        int cr = connect(ts, &cfg.taddr.sa, (socklen_t)sizeof_sockaddr(&cfg.taddr));
                        if (cr < 0 && errno != EINPROGRESS) { P_LOG_ERR("connect: %s", strerror(errno)); close(ts); continue; }

                        struct proxy_conn *nc = (struct proxy_conn*)calloc(1, sizeof(*nc));
                        if (!nc) { P_LOG_ERR("calloc conn"); close(ts); continue; }
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
                            if (derive_session_key_from_psk((const uint8_t*)cfg.psk, nc->hs_token, nc->conv, nc->session_key) == 0) {
                                nc->has_session_key = true;
                                /* Initialize AEAD nonce base and counters */
                                memcpy(nc->nonce_base, nc->session_key, 12);
                                nc->send_seq = 0;
                                nc->recv_seq = 0;
                            } else {
                                P_LOG_ERR("session key derivation failed");
                                close(ts);
                                free(nc);
                                continue;
                            }
                        }

                        if (kcp_setup_conn(nc, usock, &ra, nc->conv, &kopts) != 0) {
                            P_LOG_ERR("kcp_setup_conn failed");
                            close(ts);
                            free(nc);
                            continue;
                        }

                        /* Register TCP server socket */
                        struct epoll_event tev = (struct epoll_event){0};
                        tev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
                        tev.data.ptr = nc;
                        if (ep_add_or_mod(epfd, ts, &tev) < 0) {
                            P_LOG_ERR("epoll add tcp: %s", strerror(errno));
                            ikcp_release(nc->kcp);
                            close(ts);
                            free(nc);
                            continue;
                        }
                        list_add_tail(&nc->list, &conns);
                        (void)kcp_map_put(&cmap, nc->conv, nc);

                        /* Send ACCEPT: [type=ACCEPT][ver][conv(4)][token(16)] */
                        unsigned char abuf[1 + 1 + 4 + 16];
                        abuf[0] = (unsigned char)KTP_HS_ACCEPT;
                        abuf[1] = (unsigned char)KCP_HS_VER;
                        abuf[2] = (unsigned char)((nc->conv >> 24) & 0xff);
                        abuf[3] = (unsigned char)((nc->conv >> 16) & 0xff);
                        abuf[4] = (unsigned char)((nc->conv >> 8) & 0xff);
                        abuf[5] = (unsigned char)(nc->conv & 0xff);
                        memcpy(abuf + 6, nc->hs_token, 16);
                        (void)sendto(usock, abuf, sizeof(abuf), MSG_DONTWAIT, &nc->peer_addr.sa, (socklen_t)sizeof_sockaddr(&nc->peer_addr));
                        P_LOG_INFO("accept conv=%u for %s", nc->conv, sockaddr_to_string(&ra));
                        continue;
                    }

                    /* Otherwise expect KCP packet for existing conv */
                    if (rn < 24) {
                        P_LOG_WARN("drop non-handshake short UDP pkt len=%zd", rn);
                        continue;
                    }
                    uint32_t conv = ikcp_getconv(buf);
                    struct proxy_conn *c = kcp_map_get(&cmap, conv);
                    if (!c) {
                        P_LOG_WARN("drop UDP for unknown conv=%u from %s", conv, sockaddr_to_string(&ra));
                        continue;
                    }
                    if (!is_sockaddr_inx_equal(&ra, &c->peer_addr)) {
                        P_LOG_WARN("drop UDP conv=%u from unexpected %s (expected %s)", conv, sockaddr_to_string(&ra), sockaddr_to_string(&c->peer_addr));
                        continue;
                    }
                    /* Feed KCP */
                    (void)ikcp_input(c->kcp, buf, (long)rn);
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
                        if (got < 1) continue;
                        unsigned char t = (unsigned char)buf[0];
                        if (t == KTP_EFIN && c->has_session_key) {
                            if (got < (int)(1 + 4 + 16)) continue;
                            uint32_t seq = (uint32_t)((uint8_t)buf[1] | ((uint8_t)buf[2] << 8) | ((uint8_t)buf[3] << 16) | ((uint8_t)buf[4] << 24));
                            uint8_t nonce[12]; memcpy(nonce, c->nonce_base, 12);
                            nonce[8]=(uint8_t)seq; nonce[9]=(uint8_t)(seq>>8); nonce[10]=(uint8_t)(seq>>16); nonce[11]=(uint8_t)(seq>>24);
                            uint8_t ad[5]; ad[0]=(uint8_t)KTP_EFIN; ad[1]=(uint8_t)seq; ad[2]=(uint8_t)(seq>>8); ad[3]=(uint8_t)(seq>>16); ad[4]=(uint8_t)(seq>>24);
                            if (chacha20poly1305_open(c->session_key, nonce, ad, sizeof(ad), NULL, 0, (const uint8_t*)(buf + 1 + 4), (uint8_t*)buf) != 0) {
                                P_LOG_ERR("EFIN tag verify failed (svr)");
                                c->state = S_CLOSING; break;
                            }
                            /* treat as FIN */
                            c->cli_in_eof = true;
                            if (!c->cli2svr_shutdown && c->request.rpos == c->request.dlen) {
                                shutdown(c->svr_sock, SHUT_WR);
                                c->cli2svr_shutdown = true;
                            }
                            continue;
                        }
                        if (t == KTP_FIN) {
                            /* Peer indicates no more client->server data; schedule shutdown(WRITE) after request buffer drains */
                            c->cli_in_eof = true;
                            if (!c->cli2svr_shutdown && c->request.rpos == c->request.dlen) {
                                shutdown(c->svr_sock, SHUT_WR);
                                c->cli2svr_shutdown = true;
                            }
                            continue;
                        }
                        /* Data payload (plain or encrypted) */
                        char *payload = NULL;
                        int plen = 0;
                        if (t == KTP_EDATA && c->has_session_key) {
                            if (got < (int)(1 + 4 + 16)) continue;
                            uint32_t seq = (uint32_t)((uint8_t)buf[1] | ((uint8_t)buf[2] << 8) | ((uint8_t)buf[3] << 16) | ((uint8_t)buf[4] << 24));
                            uint8_t nonce[12]; memcpy(nonce, c->nonce_base, 12);
                            nonce[8]=(uint8_t)seq; nonce[9]=(uint8_t)(seq>>8); nonce[10]=(uint8_t)(seq>>16); nonce[11]=(uint8_t)(seq>>24);
                            uint8_t ad[5]; ad[0]=(uint8_t)KTP_EDATA; ad[1]=(uint8_t)seq; ad[2]=(uint8_t)(seq>>8); ad[3]=(uint8_t)(seq>>16); ad[4]=(uint8_t)(seq>>24);
                            int ctlen = got - (int)(1 + 4 + 16);
                            if (ctlen < 0) continue;
                            if (chacha20poly1305_open(c->session_key, nonce, ad, sizeof(ad), (const uint8_t*)(buf + 1 + 4), (size_t)ctlen, (const uint8_t*)(buf + 1 + 4 + ctlen), (uint8_t*)buf) != 0) {
                                P_LOG_ERR("EDATA tag verify failed (svr)");
                                c->state = S_CLOSING; break;
                            }
                            payload = buf; plen = ctlen;
                        } else {
                            payload = buf + 1; plen = got - 1;
                        }
                        /* If TCP connect not completed, buffer instead of sending */
                        if (c->state != S_FORWARDING) {
                            size_t need = (size_t)plen;
                            size_t freecap = (c->request.capacity > c->request.dlen) ? (c->request.capacity - c->request.dlen) : 0;
                            if (freecap < need) {
                                size_t ncap = c->request.capacity ? c->request.capacity * 2 : (size_t)65536;
                                if (ncap < c->request.dlen + need) ncap = c->request.dlen + need;
                                char *np = (char*)realloc(c->request.data, ncap);
                                if (!np) { c->state = S_CLOSING; break; }
                                c->request.data = np;
                                c->request.capacity = ncap;
                            }
                            memcpy(c->request.data + c->request.dlen, payload, (size_t)plen);
                            c->request.dlen += (size_t)plen;
                            /* Ensure EPOLLOUT is enabled to both complete connect and flush later */
                            struct epoll_event tev2 = (struct epoll_event){0};
                            tev2.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
                            tev2.data.ptr = c;
                            (void)ep_add_or_mod(epfd, c->svr_sock, &tev2);
                            break;
                        }
                        ssize_t wn = send(c->svr_sock, payload, (size_t)plen, MSG_NOSIGNAL);
                        if (wn < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                /* Backpressure: buffer and enable EPOLLOUT */
                                size_t need = (size_t)plen;
                                size_t freecap = (c->request.capacity > c->request.dlen) ? (c->request.capacity - c->request.dlen) : 0;
                                if (freecap < need) {
                                    size_t ncap = c->request.capacity ? c->request.capacity * 2 : (size_t)65536;
                                    if (ncap < c->request.dlen + need) ncap = c->request.dlen + need;
                                    char *np = (char*)realloc(c->request.data, ncap);
                                    if (!np) { c->state = S_CLOSING; break; }
                                    c->request.data = np;
                                    c->request.capacity = ncap;
                                }
                                memcpy(c->request.data + c->request.dlen, payload, (size_t)plen);
                                c->request.dlen += (size_t)plen;
                                struct epoll_event tev2 = (struct epoll_event){0};
                                tev2.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
                                tev2.data.ptr = c;
                                (void)ep_add_or_mod(epfd, c->svr_sock, &tev2);
                                break;
                            }
                            c->state = S_CLOSING;
                            break;
                        } else if (wn < plen) {
                            /* Short write: buffer remaining and enable EPOLLOUT */
                            size_t rem = (size_t)plen - (size_t)wn;
                            size_t freecap = (c->request.capacity > c->request.dlen) ? (c->request.capacity - c->request.dlen) : 0;
                            if (freecap < rem) {
                                size_t ncap = c->request.capacity ? c->request.capacity * 2 : (size_t)65536;
                                if (ncap < c->request.dlen + rem) ncap = c->request.dlen + rem;
                                char *np = (char*)realloc(c->request.data, ncap);
                                if (!np) { c->state = S_CLOSING; break; }
                                c->request.data = np;
                                c->request.capacity = ncap;
                            }
                            memcpy(c->request.data + c->request.dlen, payload + wn, rem);
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
                    /* If we got FIN from peer earlier, perform shutdown write now */
                    if (c->cli_in_eof && !c->cli2svr_shutdown) {
                        shutdown(c->svr_sock, SHUT_WR);
                        c->cli2svr_shutdown = true;
                    }
                }
            }
            if (events[i].events & EPOLLIN) {
                char sbuf[64 * 1024];
                ssize_t rn;
                while ((rn = recv(c->svr_sock, sbuf, sizeof(sbuf), 0)) > 0) {
                    /* Wrap as DATA (encrypt if session key) */
                    int sn = 0;
                    if (c->has_session_key) {
                        unsigned char hdrbuf[1 + 4 + sizeof(sbuf) + 16];
                        uint8_t nonce[12]; memcpy(nonce, c->nonce_base, 12);
                        uint32_t seq = c->send_seq++;
                        nonce[8]=(uint8_t)seq; nonce[9]=(uint8_t)(seq>>8); nonce[10]=(uint8_t)(seq>>16); nonce[11]=(uint8_t)(seq>>24);
                        uint8_t ad[5]; ad[0]=(uint8_t)KTP_EDATA; ad[1]=(uint8_t)seq; ad[2]=(uint8_t)(seq>>8); ad[3]=(uint8_t)(seq>>16); ad[4]=(uint8_t)(seq>>24);
                        hdrbuf[0] = (unsigned char)KTP_EDATA;
                        hdrbuf[1] = ad[1]; hdrbuf[2] = ad[2]; hdrbuf[3] = ad[3]; hdrbuf[4] = ad[4];
                        chacha20poly1305_seal(c->session_key, nonce, ad, sizeof(ad), (const uint8_t*)sbuf, (size_t)rn, hdrbuf + 1 + 4, hdrbuf + 1 + 4 + rn);
                        sn = ikcp_send(c->kcp, (const char*)hdrbuf, (int)(1 + 4 + rn + 16));
                    } else {
                        unsigned char hdrbuf[1 + sizeof(sbuf)];
                        hdrbuf[0] = (unsigned char)KTP_DATA;
                        memcpy(hdrbuf + 1, sbuf, (size_t)rn);
                        sn = ikcp_send(c->kcp, (const char*)hdrbuf, (int)(rn + 1));
                    }
                    if (sn < 0) {
                        c->state = S_CLOSING;
                        break;
                    }
                    c->last_active = time(NULL);
                }
                if (rn == 0) {
                    /* TCP target sent EOF: send FIN/EFIN over KCP, stop further reads, allow pending KCP to flush */
                    if (c->has_session_key) {
                        uint8_t nonce[12]; memcpy(nonce, c->nonce_base, 12);
                        uint32_t seq = c->send_seq++;
                        nonce[8]=(uint8_t)seq; nonce[9]=(uint8_t)(seq>>8); nonce[10]=(uint8_t)(seq>>16); nonce[11]=(uint8_t)(seq>>24);
                        uint8_t ad[5]; ad[0]=(uint8_t)KTP_EFIN; ad[1]=(uint8_t)seq; ad[2]=(uint8_t)(seq>>8); ad[3]=(uint8_t)(seq>>16); ad[4]=(uint8_t)(seq>>24);
                        unsigned char pkt[1 + 4 + 16];
                        pkt[0] = (unsigned char)KTP_EFIN;
                        pkt[1] = ad[1]; pkt[2] = ad[2]; pkt[3] = ad[3]; pkt[4] = ad[4];
                        uint8_t tag[16];
                        chacha20poly1305_seal(c->session_key, nonce, ad, sizeof(ad), NULL, 0, NULL, tag);
                        memcpy(pkt + 1 + 4, tag, 16);
                        (void)ikcp_send(c->kcp, (const char*)pkt, (int)sizeof(pkt));
                    } else {
                        unsigned char fin = (unsigned char)KTP_FIN;
                        (void)ikcp_send(c->kcp, (const char*)&fin, 1);
                    }
                    c->svr_in_eof = true;
                    struct epoll_event tev2 = (struct epoll_event){0};
                    tev2.events = EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP; /* disable EPOLLIN */
                    tev2.data.ptr = c;
                    (void)ep_add_or_mod(epfd, c->svr_sock, &tev2);
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
            /* If server TCP got EOF, wait until all buffered client->server data is flushed before closing */
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
                if (pos->udp_backlog.data) free(pos->udp_backlog.data);
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
