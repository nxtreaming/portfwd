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
#include "kcp_map.h"
#include "aead.h"
#include "3rd/chacha20poly1305/chacha20poly1305.h"
#include "3rd/kcp/ikcp.h"

/* Allow overriding stats logging interval via environment variable PFWD_STATS_INTERVAL_MS */
static inline uint32_t get_stats_interval_ms(void) {
    static uint32_t cached = 0; /* 0 => uninitialized */
    if (cached == 0) {
        const char *s = getenv("PFWD_STATS_INTERVAL_MS");
        long v = s ? strtol(s, NULL, 10) : 0;
        if (v <= 0) v = 5000; /* default 5s */
        if (v < 100) v = 100; /* clamp to sane minimum */
        if (v > 600000) v = 600000; /* clamp to 10 minutes */
        cached = (uint32_t)v;
    }
    return cached;
}

/* Dump final totals at connection close if PFWD_STATS_DUMP is set to non-zero */
static inline bool get_stats_dump_enabled(void) {
    const char *s = getenv("PFWD_STATS_DUMP");
    if (!s) return false;
    return !(s[0] == '0');
}

/* Enable/disable stats via PFWD_STATS_ENABLE (set to "0" to disable) */
static inline bool get_stats_enabled(void) {
    const char *s = getenv("PFWD_STATS_ENABLE");
    if (!s) return true; /* default enabled */
    /* treat any leading '0' as false */
    return !(s[0] == '0');
}

/* Anti-replay helpers (sliding window, 64 entries) */
static inline int32_t seq_diff_u32(uint32_t a, uint32_t b) { return (int32_t)(a - b); }
static inline bool aead_replay_check_and_update(uint32_t seq, uint32_t *p_win, uint64_t *p_mask) {
    uint32_t win = *p_win;
    uint64_t mask = *p_mask;
    if (win == UINT32_MAX) { /* uninitialized */
        *p_win = seq;
        *p_mask = 1ULL; /* mark bit0 */
        return true;
    }
    int32_t d = seq_diff_u32(seq, win);
    if (d > 0) {
        uint32_t shift = (d >= 64) ? 64u : (uint32_t)d;
        mask = (shift >= 64) ? 0ULL : (mask << shift);
        mask |= 1ULL;
        win = seq;
        *p_win = win; *p_mask = mask; return true;
    }
    int32_t behind = -d;
    if (behind >= 64) return false;
    uint64_t bit = 1ULL << behind;
    if (mask & bit) return false; /* replay */
    mask |= bit; *p_win = win; *p_mask = mask; return true;
}

/* Guard against send_seq wraparound; returns false on wrap */
static inline bool aead_next_send_seq(struct proxy_conn *c, uint32_t *out_seq) {
    if (c->send_seq == UINT32_MAX) return false;
    *out_seq = c->send_seq++;
    return true;
}

static void print_usage(const char *prog) {
    P_LOG_INFO("Usage: %s [options] <local_udp_addr:port> <target_tcp_addr:port>", prog);
    P_LOG_INFO("Options:");
    P_LOG_INFO("  -d                 run in background (daemonize)");
    P_LOG_INFO("  -p <pidfile>       write PID to file");
    P_LOG_INFO("  -r                 set SO_REUSEADDR on listener socket");
    P_LOG_INFO("  -R                 set SO_REUSEPORT on listener socket");
    P_LOG_INFO("  -6                 for IPv6 listener, set IPV6_V6ONLY");
    P_LOG_INFO("  -S <bytes>         SO_RCVBUF/SO_SNDBUF size (default build-time)");
    P_LOG_INFO("  -M <mtu>           KCP MTU (default 1350; lower if frequent fragmentation)");
    P_LOG_INFO("  -A <0|1>           KCP nodelay (default 1)");
    P_LOG_INFO("  -I <ms>            KCP interval in ms (default 10)");
    P_LOG_INFO("  -X <n>             KCP fast resend (default 2)");
    P_LOG_INFO("  -C <0|1>           KCP no congestion control (default 1)");
    P_LOG_INFO("  -w <sndwnd>        KCP send window in packets (default 1024)");
    P_LOG_INFO("  -W <rcvwnd>        KCP recv window in packets (default 1024)");
    P_LOG_INFO("  -N                 enable TCP_NODELAY on outbound TCP to target");
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
    int kcp_nd = -1, kcp_it = -1, kcp_rs = -1, kcp_nc = -1, kcp_snd = -1, kcp_rcv = -1;
    int opt;
    while ((opt = getopt(argc, argv, "dp:rR6S:M:A:I:X:C:w:W:NK:h")) != -1) {
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
        case 'A': {
            if (strcmp(optarg, "0") == 0) kcp_nd = 0;
            else if (strcmp(optarg, "1") == 0) kcp_nd = 1;
            else P_LOG_WARN("invalid -A value '%s' (expect 0|1)", optarg);
            break;
        }
        case 'I': {
            char *end = NULL; long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v <= 0) P_LOG_WARN("invalid -I value '%s'", optarg);
            else kcp_it = (int)v;
            break;
        }
        case 'X': {
            char *end = NULL; long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v < 0) P_LOG_WARN("invalid -X value '%s'", optarg);
            else kcp_rs = (int)v;
            break;
        }
        case 'C': {
            if (strcmp(optarg, "0") == 0) kcp_nc = 0;
            else if (strcmp(optarg, "1") == 0) kcp_nc = 1;
            else P_LOG_WARN("invalid -C value '%s' (expect 0|1)", optarg);
            break;
        }
        case 'w': {
            char *end = NULL; long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v <= 0) P_LOG_WARN("invalid -w value '%s'", optarg);
            else kcp_snd = (int)v;
            break;
        }
        case 'W': {
            char *end = NULL; long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v <= 0) P_LOG_WARN("invalid -W value '%s'", optarg);
            else kcp_rcv = (int)v;
            break;
        }
        case 'N':
            cfg.tcp_nodelay = true;
            break;
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
    if (kcp_nd >= 0) kopts.nodelay = kcp_nd;
    if (kcp_it >= 0) kopts.interval_ms = kcp_it;
    if (kcp_rs >= 0) kopts.resend = kcp_rs;
    if (kcp_nc >= 0) kopts.nc = kcp_nc;
    if (kcp_snd >= 0) kopts.sndwnd = kcp_snd;
    if (kcp_rcv >= 0) kopts.rcvwnd = kcp_rcv;

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
                        if (cfg.tcp_nodelay) { int one = 1; (void)setsockopt(ts, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }
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
                                nc->recv_win = UINT32_MAX; /* uninitialized */
                                nc->recv_win_mask = 0ULL;
                                nc->epoch = 0;
                                nc->rekey_in_progress = false;
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
                    c->udp_rx_bytes += (uint64_t)rn; /* Stats: UDP RX */
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
                        c->kcp_rx_msgs++; /* Stats: KCP RX message */
                        if (got < 1) continue;
                        unsigned char t = (unsigned char)buf[0];
                        /* Rekey control handling */
                        if (t == KTP_REKEY_INIT && c->has_session_key) {
                            if (got < (int)(1 + 4 + 16)) continue;
                            uint32_t seq = (uint32_t)((uint8_t)buf[1] | ((uint8_t)buf[2] << 8) | ((uint8_t)buf[3] << 16) | ((uint8_t)buf[4] << 24));
                            /* Tentative anti-replay */
                            uint32_t win_tmp = c->recv_win; uint64_t mask_tmp = c->recv_win_mask;
                            if (!aead_replay_check_and_update(seq, &win_tmp, &mask_tmp)) {
                                P_LOG_WARN("drop replay/old REKEY_INIT seq=%u (svr)", seq);
                                continue;
                            }
                            uint8_t nonce[12]; memcpy(nonce, c->nonce_base, 12);
                            nonce[8]=(uint8_t)seq; nonce[9]=(uint8_t)(seq>>8); nonce[10]=(uint8_t)(seq>>16); nonce[11]=(uint8_t)(seq>>24);
                            uint8_t ad[5]; ad[0]=(uint8_t)KTP_REKEY_INIT; ad[1]=(uint8_t)seq; ad[2]=(uint8_t)(seq>>8); ad[3]=(uint8_t)(seq>>16); ad[4]=(uint8_t)(seq>>24);
                            if (chacha20poly1305_open(c->session_key, nonce, ad, sizeof(ad), NULL, 0, (const uint8_t*)(buf + 1 + 4), (uint8_t*)buf) != 0) {
                                P_LOG_ERR("REKEY_INIT tag verify failed (svr)");
                                c->state = S_CLOSING; break;
                            }
                            /* Commit anti-replay */
                            c->recv_win = win_tmp; c->recv_win_mask = mask_tmp;
                            P_LOG_INFO("recv REKEY_INIT conv=%u seq=%u (svr)", c->conv, seq);
                            if (!cfg.has_psk) { c->state = S_CLOSING; break; }
                            /* Prepare next key if not already */
                            if (!c->rekey_in_progress) {
                                c->next_epoch = c->epoch + 1;
                                if (derive_session_key_epoch((const uint8_t*)cfg.psk, c->hs_token, c->conv, c->next_epoch, c->next_session_key) != 0) { c->state = S_CLOSING; break; }
                                memcpy(c->next_nonce_base, c->next_session_key, 12);
                                c->rekey_in_progress = true;
                            }
                            /* Send REKEY_ACK sealed with NEXT key, seq=0 (next epoch namespace) */
                            {
                                unsigned char pkt[1 + 4 + 16];
                                pkt[0] = (unsigned char)KTP_REKEY_ACK;
                                pkt[1] = 0; pkt[2] = 0; pkt[3] = 0; pkt[4] = 0;
                                uint8_t nonce2[12]; memcpy(nonce2, c->next_nonce_base, 12);
                                uint8_t ad2[5]; ad2[0]=(uint8_t)KTP_REKEY_ACK; ad2[1]=0; ad2[2]=0; ad2[3]=0; ad2[4]=0;
                                uint8_t tag[16];
                                chacha20poly1305_seal(c->next_session_key, nonce2, ad2, sizeof(ad2), NULL, 0, NULL, tag);
                                memcpy(pkt + 1 + 4, tag, 16);
                                (void)ikcp_send(c->kcp, (const char*)pkt, (int)sizeof(pkt));
                                c->kcp_tx_msgs++; /* Stats: control msg via KCP */
                            }
                            /* Switch to next epoch immediately */
                            memcpy(c->session_key, c->next_session_key, 32);
                            memcpy(c->nonce_base, c->next_nonce_base, 12);
                            c->epoch = c->next_epoch;
                            c->send_seq = 0;
                            c->recv_win = UINT32_MAX; c->recv_win_mask = 0ULL;
                            c->rekey_in_progress = false;
                            c->rekeys_completed++; /* Stats: rekey completed */
                            P_LOG_INFO("epoch switch conv=%u -> epoch=%u (svr)", c->conv, c->epoch);
                            continue;
                        }
                        if (t == KTP_REKEY_ACK && c->has_session_key && c->rekey_in_progress) {
                            if (got < (int)(1 + 4 + 16)) continue;
                            uint32_t seq = (uint32_t)((uint8_t)buf[1] | ((uint8_t)buf[2] << 8) | ((uint8_t)buf[3] << 16) | ((uint8_t)buf[4] << 24));
                            if (seq != 0) { P_LOG_ERR("REKEY_ACK seq!=0 (svr)"); c->state = S_CLOSING; break; }
                            uint8_t nonce2[12]; memcpy(nonce2, c->next_nonce_base, 12);
                            uint8_t ad2[5]; ad2[0]=(uint8_t)KTP_REKEY_ACK; ad2[1]=0; ad2[2]=0; ad2[3]=0; ad2[4]=0;
                            if (chacha20poly1305_open(c->next_session_key, nonce2, ad2, sizeof(ad2), NULL, 0, (const uint8_t*)(buf + 1 + 4), (uint8_t*)buf) != 0) {
                                P_LOG_ERR("REKEY_ACK tag verify failed (svr)");
                                c->state = S_CLOSING; break;
                            }
                            P_LOG_INFO("recv REKEY_ACK conv=%u (svr)", c->conv);
                            /* Switch epoch */
                            memcpy(c->session_key, c->next_session_key, 32);
                            memcpy(c->nonce_base, c->next_nonce_base, 12);
                            c->epoch = c->next_epoch;
                            c->send_seq = 0;
                            c->recv_win = UINT32_MAX; c->recv_win_mask = 0ULL;
                            c->rekey_in_progress = false;
                            c->rekeys_completed++; /* Stats: rekey completed */
                            P_LOG_INFO("epoch switch conv=%u -> epoch=%u (svr)", c->conv, c->epoch);
                            continue;
                        }
                        if (c->has_session_key && (t == KTP_DATA || t == KTP_FIN)) {
                            P_LOG_ERR("plaintext pkt type in encrypted session (svr)");
                            c->state = S_CLOSING; break;
                        }
                        if (t == KTP_EFIN && c->has_session_key) {
                            if (got < (int)(1 + 4 + 16)) continue;
                            uint32_t seq = (uint32_t)((uint8_t)buf[1] | ((uint8_t)buf[2] << 8) | ((uint8_t)buf[3] << 16) | ((uint8_t)buf[4] << 24));
                            /* Anti-replay window check (tentative) */
                            uint32_t win_tmp = c->recv_win; uint64_t mask_tmp = c->recv_win_mask;
                            if (!aead_replay_check_and_update(seq, &win_tmp, &mask_tmp)) {
                                P_LOG_WARN("drop replay/old EFIN seq=%u (svr)", seq);
                                continue;
                            }
                            uint8_t nonce[12]; memcpy(nonce, c->nonce_base, 12);
                            nonce[8]=(uint8_t)seq; nonce[9]=(uint8_t)(seq>>8); nonce[10]=(uint8_t)(seq>>16); nonce[11]=(uint8_t)(seq>>24);
                            uint8_t ad[5]; ad[0]=(uint8_t)KTP_EFIN; ad[1]=(uint8_t)seq; ad[2]=(uint8_t)(seq>>8); ad[3]=(uint8_t)(seq>>16); ad[4]=(uint8_t)(seq>>24);
                            if (chacha20poly1305_open(c->session_key, nonce, ad, sizeof(ad), NULL, 0, (const uint8_t*)(buf + 1 + 4), (uint8_t*)buf) != 0) {
                                P_LOG_ERR("EFIN tag verify failed (svr)");
                                c->state = S_CLOSING; break;
                            }
                            /* Commit anti-replay window advance */
                            c->recv_win = win_tmp; c->recv_win_mask = mask_tmp;
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
                            /* Anti-replay window check (tentative) */
                            uint32_t win_tmp = c->recv_win; uint64_t mask_tmp = c->recv_win_mask;
                            if (!aead_replay_check_and_update(seq, &win_tmp, &mask_tmp)) {
                                P_LOG_WARN("drop replay/old EDATA seq=%u (svr)", seq);
                                continue;
                            }
                            uint8_t nonce[12]; memcpy(nonce, c->nonce_base, 12);
                            nonce[8]=(uint8_t)seq; nonce[9]=(uint8_t)(seq>>8); nonce[10]=(uint8_t)(seq>>16); nonce[11]=(uint8_t)(seq>>24);
                            uint8_t ad[5]; ad[0]=(uint8_t)KTP_EDATA; ad[1]=(uint8_t)seq; ad[2]=(uint8_t)(seq>>8); ad[3]=(uint8_t)(seq>>16); ad[4]=(uint8_t)(seq>>24);
                            int ctlen = got - (int)(1 + 4 + 16);
                            if (ctlen < 0) continue;
                            if (chacha20poly1305_open(c->session_key, nonce, ad, sizeof(ad), (const uint8_t*)(buf + 1 + 4), (size_t)ctlen, (const uint8_t*)(buf + 1 + 4 + ctlen), (uint8_t*)buf) != 0) {
                                P_LOG_ERR("EDATA tag verify failed (svr)");
                                c->state = S_CLOSING; break;
                            }
                            /* Commit anti-replay window advance */
                            c->recv_win = win_tmp; c->recv_win_mask = mask_tmp;
                            payload = buf; plen = ctlen;
                        } else {
                            payload = buf + 1; plen = got - 1;
                        }
                        if (plen > 0) c->kcp_rx_bytes += (uint64_t)plen; /* Stats: accumulate KCP RX payload bytes */
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
                            if (wn > 0) c->tcp_tx_bytes += (uint64_t)wn; /* Stats: TCP TX */
                            struct epoll_event tev2 = (struct epoll_event){0};
                            tev2.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
                            tev2.data.ptr = c;
                            (void)ep_add_or_mod(epfd, c->svr_sock, &tev2);
                            break;
                        }
                        if (wn > 0) c->tcp_tx_bytes += (uint64_t)wn; /* Stats: TCP TX */
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
                    c->tcp_rx_bytes += (uint64_t)rn; /* Stats: TCP RX */
                    /* Wrap as DATA (encrypt if session key) */
                    int sn = 0;
                    if (c->has_session_key) {
                        unsigned char hdrbuf[1 + 4 + sizeof(sbuf) + 16];
                        /* Rekey trigger before sending encrypted data */
                        if (c->has_session_key && cfg.has_psk && !c->rekey_in_progress && c->send_seq >= REKEY_SEQ_THRESHOLD) {
                            c->next_epoch = c->epoch + 1;
                            if (derive_session_key_epoch((const uint8_t*)cfg.psk, c->hs_token, c->conv, c->next_epoch, c->next_session_key) != 0) { c->state = S_CLOSING; break; }
                            memcpy(c->next_nonce_base, c->next_session_key, 12);
                            c->rekey_in_progress = true;
                            c->rekey_deadline_ms = kcp_now_ms() + REKEY_TIMEOUT_MS;
                            P_LOG_INFO("rekey trigger conv=%u epoch=%u->%u send_seq=%u deadline=%" PRIu64 " (svr)", c->conv, c->epoch, c->next_epoch, c->send_seq, c->rekey_deadline_ms);
                            /* Send REKEY_INIT under current key */
                            uint8_t nonceI[12]; memcpy(nonceI, c->nonce_base, 12);
                            uint32_t seqI; if (!aead_next_send_seq(c, &seqI)) { P_LOG_ERR("send_seq wraparound guard hit, closing conv=%u (svr)", c->conv); c->state = S_CLOSING; break; }
                            nonceI[8]=(uint8_t)seqI; nonceI[9]=(uint8_t)(seqI>>8); nonceI[10]=(uint8_t)(seqI>>16); nonceI[11]=(uint8_t)(seqI>>24);
                            uint8_t adI[5]; adI[0]=(uint8_t)KTP_REKEY_INIT; adI[1]=(uint8_t)seqI; adI[2]=(uint8_t)(seqI>>8); adI[3]=(uint8_t)(seqI>>16); adI[4]=(uint8_t)(seqI>>24);
                            unsigned char pktI[1 + 4 + 16];
                            pktI[0] = (unsigned char)KTP_REKEY_INIT;
                            pktI[1] = adI[1]; pktI[2] = adI[2]; pktI[3] = adI[3]; pktI[4] = adI[4];
                            uint8_t tagI[16]; chacha20poly1305_seal(c->session_key, nonceI, adI, sizeof(adI), NULL, 0, NULL, tagI);
                            memcpy(pktI + 1 + 4, tagI, 16);
                            (void)ikcp_send(c->kcp, (const char*)pktI, (int)sizeof(pktI));
                            c->kcp_tx_msgs++; /* Stats: control msg via KCP */
                            c->rekeys_initiated++; /* Stats: rekey initiated */
                        }
                        uint8_t nonce[12]; memcpy(nonce, c->nonce_base, 12);
                        uint32_t seq; if (!aead_next_send_seq(c, &seq)) { P_LOG_ERR("send_seq wraparound guard hit, closing conv=%u (svr)", c->conv); c->state = S_CLOSING; break; }
                        nonce[8]=(uint8_t)seq; nonce[9]=(uint8_t)(seq>>8); nonce[10]=(uint8_t)(seq>>16); nonce[11]=(uint8_t)(seq>>24);
                        uint8_t ad[5]; ad[0]=(uint8_t)KTP_EDATA; ad[1]=(uint8_t)seq; ad[2]=(uint8_t)(seq>>8); ad[3]=(uint8_t)(seq>>16); ad[4]=(uint8_t)(seq>>24);
                        hdrbuf[0] = (unsigned char)KTP_EDATA;
                        hdrbuf[1] = ad[1]; hdrbuf[2] = ad[2]; hdrbuf[3] = ad[3]; hdrbuf[4] = ad[4];
                        chacha20poly1305_seal(c->session_key, nonce, ad, sizeof(ad), (const uint8_t*)sbuf, (size_t)rn, hdrbuf + 1 + 4, hdrbuf + 1 + 4 + rn);
                        sn = ikcp_send(c->kcp, (const char*)hdrbuf, (int)(1 + 4 + rn + 16));
                        if (sn >= 0) { c->kcp_tx_msgs++; c->kcp_tx_bytes += (uint64_t)rn; }
                    } else {
                        unsigned char hdrbuf[1 + sizeof(sbuf)];
                        hdrbuf[0] = (unsigned char)KTP_DATA;
                        memcpy(hdrbuf + 1, sbuf, (size_t)rn);
                        sn = ikcp_send(c->kcp, (const char*)hdrbuf, (int)(rn + 1));
                        if (sn >= 0) { c->kcp_tx_msgs++; c->kcp_tx_bytes += (uint64_t)rn; }
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
                        /* Rekey trigger before sending encrypted FIN */
                        if (c->has_session_key && cfg.has_psk && !c->rekey_in_progress && c->send_seq >= REKEY_SEQ_THRESHOLD) {
                            c->next_epoch = c->epoch + 1;
                            if (derive_session_key_epoch((const uint8_t*)cfg.psk, c->hs_token, c->conv, c->next_epoch, c->next_session_key) != 0) { c->state = S_CLOSING; break; }
                            memcpy(c->next_nonce_base, c->next_session_key, 12);
                            c->rekey_in_progress = true;
                            c->rekey_deadline_ms = kcp_now_ms() + REKEY_TIMEOUT_MS;
                            P_LOG_INFO("rekey trigger (EFIN) conv=%u epoch=%u->%u send_seq=%u deadline=%" PRIu64 " (svr)", c->conv, c->epoch, c->next_epoch, c->send_seq, c->rekey_deadline_ms);
                            /* Send REKEY_INIT under current key */
                            uint8_t nonceI[12]; memcpy(nonceI, c->nonce_base, 12);
                            uint32_t seqI; if (!aead_next_send_seq(c, &seqI)) { P_LOG_ERR("send_seq wraparound guard hit, closing conv=%u (svr)", c->conv); c->state = S_CLOSING; break; }
                            nonceI[8]=(uint8_t)seqI; nonceI[9]=(uint8_t)(seqI>>8); nonceI[10]=(uint8_t)(seqI>>16); nonceI[11]=(uint8_t)(seqI>>24);
                            uint8_t adI[5]; adI[0]=(uint8_t)KTP_REKEY_INIT; adI[1]=(uint8_t)seqI; adI[2]=(uint8_t)(seqI>>8); adI[3]=(uint8_t)(seqI>>16); adI[4]=(uint8_t)(seqI>>24);
                            unsigned char pktI[1 + 4 + 16];
                            pktI[0] = (unsigned char)KTP_REKEY_INIT;
                            pktI[1] = adI[1]; pktI[2] = adI[2]; pktI[3] = adI[3]; pktI[4] = adI[4];
                            uint8_t tagI[16]; chacha20poly1305_seal(c->session_key, nonceI, adI, sizeof(adI), NULL, 0, NULL, tagI);
                            memcpy(pktI + 1 + 4, tagI, 16);
                            (void)ikcp_send(c->kcp, (const char*)pktI, (int)sizeof(pktI));
                            c->kcp_tx_msgs++;
                            c->rekeys_initiated++;
                        }
                        uint8_t nonce[12]; memcpy(nonce, c->nonce_base, 12);
                        uint32_t seq; if (!aead_next_send_seq(c, &seq)) { P_LOG_ERR("send_seq wraparound guard hit, closing conv=%u (svr)", c->conv); c->state = S_CLOSING; }
                        nonce[8]=(uint8_t)seq; nonce[9]=(uint8_t)(seq>>8); nonce[10]=(uint8_t)(seq>>16); nonce[11]=(uint8_t)(seq>>24);
                        uint8_t ad[5]; ad[0]=(uint8_t)KTP_EFIN; ad[1]=(uint8_t)seq; ad[2]=(uint8_t)(seq>>8); ad[3]=(uint8_t)(seq>>16); ad[4]=(uint8_t)(seq>>24);
                        unsigned char pkt[1 + 4 + 16];
                        pkt[0] = (unsigned char)KTP_EFIN;
                        pkt[1] = ad[1]; pkt[2] = ad[2]; pkt[3] = ad[3]; pkt[4] = ad[4];
                        uint8_t tag[16];
                        chacha20poly1305_seal(c->session_key, nonce, ad, sizeof(ad), NULL, 0, NULL, tag);
                        memcpy(pkt + 1 + 4, tag, 16);
                        (void)ikcp_send(c->kcp, (const char*)pkt, (int)sizeof(pkt));
                        c->kcp_tx_msgs++; /* Stats: FIN ctrl */
                    } else {
                        unsigned char fin = (unsigned char)KTP_FIN;
                        (void)ikcp_send(c->kcp, (const char*)&fin, 1);
                        c->kcp_tx_msgs++; /* Stats: FIN ctrl */
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
            /* Rekey timeout enforcement */
            if (pos->state != S_CLOSING && pos->has_session_key && pos->rekey_in_progress) {
                if (now >= pos->rekey_deadline_ms) {
                    P_LOG_ERR("rekey timeout, closing conv=%u (svr)", pos->conv);
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
                    uint32_t d_rekey_i = pos->rekeys_initiated - pos->last_rekeys_initiated;
                    uint32_t d_rekey_c = pos->rekeys_completed - pos->last_rekeys_completed;
                    double sec = (double)dt / 1000.0;
                    double tcp_in_mbps = sec > 0 ? (double)d_tcp_rx * 8.0 / (sec * 1e6) : 0.0;
                    double tcp_out_mbps = sec > 0 ? (double)d_tcp_tx * 8.0 / (sec * 1e6) : 0.0;
                    double kcp_in_mbps = sec > 0 ? (double)d_kcp_rx * 8.0 / (sec * 1e6) : 0.0;
                    double kcp_out_mbps = sec > 0 ? (double)d_kcp_tx * 8.0 / (sec * 1e6) : 0.0;
                    P_LOG_INFO("stats conv=%u: TCP in=%.3f Mbps out=%.3f Mbps | KCP payload in=%.3f Mbps out=%.3f Mbps | KCP xmit_delta=%u RTT=%dms | rekey i=%u c=%u",
                               pos->conv,
                               tcp_in_mbps, tcp_out_mbps,
                               kcp_in_mbps, kcp_out_mbps,
                               d_xmit, pos->kcp->rx_srtt,
                               d_rekey_i, d_rekey_c);
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
                    P_LOG_INFO("stats total conv=%u: tcp_rx=%llu tcp_tx=%llu udp_rx=%llu udp_tx=%llu kcp_rx_msgs=%llu kcp_tx_msgs=%llu kcp_rx_bytes=%llu kcp_tx_bytes=%llu rekeys_i=%u rekeys_c=%u",
                               pos->conv,
                               (unsigned long long)pos->tcp_rx_bytes,
                               (unsigned long long)pos->tcp_tx_bytes,
                               (unsigned long long)pos->udp_rx_bytes,
                               (unsigned long long)pos->udp_tx_bytes,
                               (unsigned long long)pos->kcp_rx_msgs,
                               (unsigned long long)pos->kcp_tx_msgs,
                               (unsigned long long)pos->kcp_rx_bytes,
                               (unsigned long long)pos->kcp_tx_bytes,
                               pos->rekeys_initiated,
                               pos->rekeys_completed);
                }
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
