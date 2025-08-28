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
#include "aead.h"
#include "3rd/chacha20poly1305/chacha20poly1305.h"
#include "3rd/kcp/ikcp.h"

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
        /* seq ahead of window; advance */
        uint32_t shift = (d >= 64) ? 64u : (uint32_t)d;
        mask = (shift >= 64) ? 0ULL : (mask << shift);
        mask |= 1ULL; /* mark newest */
        win = seq;
        *p_win = win; *p_mask = mask; return true;
    }
    /* seq <= win */
    int32_t behind = -d; /* how far behind win */
    if (behind >= 64) {
        /* too old */
        return false;
    }
    uint64_t bit = 1ULL << behind;
    if (mask & bit) {
        /* replay */
        return false;
    }
    mask |= bit;
    *p_win = win; *p_mask = mask; return true;
}

/* Guard against send_seq wraparound; returns false on wrap */
static inline bool aead_next_send_seq(struct proxy_conn *c, uint32_t *out_seq) {
    if (c->send_seq == UINT32_MAX) return false;
    *out_seq = c->send_seq++;
    return true;
}

static void print_usage(const char *prog) {
    P_LOG_INFO("Usage: %s [options] <local_tcp_addr:port> <remote_udp_addr:port>", prog);
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

struct cfg_client {
    union sockaddr_inx laddr; /* TCP listen */
    union sockaddr_inx raddr; /* UDP remote */
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
    int epfd = -1, lsock = -1;
    uint32_t magic_listener = 0xdeadbeefU; /* reuse value style from tcpfwd */
    struct cfg_client cfg;
    struct list_head conns; /* active connections */
    INIT_LIST_HEAD(&conns);

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
    if (kcp_mtu > 0) {
        kopts.mtu = kcp_mtu;
    }

    /* Event loop: accept TCP, bridge via KCP over UDP */
    while (!g_state.terminate) {
        /* Compute dynamic timeout from all KCP connections */
        int timeout_ms = 1000;
        uint32_t now = kcp_now_ms();
        struct proxy_conn *pc_it;
        list_for_each_entry(pc_it, &conns, list) {
            if (pc_it->kcp) {
                uint32_t due = ikcp_check(pc_it->kcp, now);
                int t = (int)((due > now) ? (due - now) : 0);
                if (t < timeout_ms) timeout_ms = t;
            }
        }

        struct epoll_event events[128];
        int nfds = epoll_wait(epfd, events, 128, timeout_ms);
        if (nfds < 0) {
            if (errno == EINTR) { /* fallthrough to timer update */ }
            else { P_LOG_ERR("epoll_wait: %s", strerror(errno)); break; }
        }

        for (int i = 0; i < nfds; ++i) {
            void *tptr = events[i].data.ptr;
            if (tptr == &magic_listener) {
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
                    /* Enable TCP keepalive */
                    int yes = 1;
                    (void)setsockopt(cs, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
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
                    c->kcp = NULL; /* not created until ACCEPT */
                    c->kcp_ready = false;
                    c->next_ka_ms = 0;
                    /* Generate 16-byte token */
                    for (int i = 0; i < 16; ++i) c->hs_token[i] = (unsigned char)(rand() & 0xFF);
                    /* Send HELLO: [type][ver][token(16)] */
                    unsigned char hbuf[1 + 1 + 16];
                    hbuf[0] = (unsigned char)KTP_HS_HELLO;
                    hbuf[1] = (unsigned char)KCP_HS_VER;
                    memcpy(hbuf + 2, c->hs_token, 16);
                    (void)sendto(c->udp_sock, hbuf, sizeof(hbuf), MSG_DONTWAIT, &c->peer_addr.sa, (socklen_t)sizeof_sockaddr(&c->peer_addr));

                    /* Prepare epoll tags */
                    struct ep_tag *ctag = (struct ep_tag*)malloc(sizeof(*ctag));
                    struct ep_tag *utag = (struct ep_tag*)malloc(sizeof(*utag));
                    if (!ctag || !utag) {
                        P_LOG_ERR("malloc ep_tag");
                        if (ctag) free(ctag);
                        if (utag) free(utag);
                        ikcp_release(c->kcp);
                        close(cs);
                        close(us);
                        free(c);
                        continue;
                    }
                    ctag->conn = c; ctag->which = 1; c->cli_tag = ctag;
                    utag->conn = c; utag->which = 2; c->udp_tag = utag;

                    /* Register both fds */
                    struct epoll_event cev = {0};
                    cev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
                    cev.data.ptr = ctag; /* client TCP tag */
                    if (ep_add_or_mod(epfd, cs, &cev) < 0) {
                        P_LOG_ERR("epoll add cli: %s", strerror(errno));
                        ikcp_release(c->kcp);
                        close(cs);
                        close(us);
                        free(ctag);
                        free(utag);
                        free(c);
                        continue;
                    }
                    struct epoll_event uev = {0};
                    uev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
                    uev.data.ptr = utag; /* UDP tag */
                    if (ep_add_or_mod(epfd, us, &uev) < 0) {
                        P_LOG_ERR("epoll add udp: %s", strerror(errno));
                        (void)ep_del(epfd, cs);
                        ikcp_release(c->kcp);
                        close(cs);
                        close(us);
                        free(ctag);
                        free(utag);
                        free(c);
                        continue;
                    }

                    list_add_tail(&c->list, &conns);
                    P_LOG_INFO("accepted TCP %s, conv=%u", sockaddr_to_string(&ca), c->conv);
                }
                continue;
            }

            /* Tagged connection event: disambiguate source */
            struct ep_tag *etag = (struct ep_tag*)tptr;
            struct proxy_conn *c = etag->conn;
            if (etag->which == 2) {
                /* UDP socket events */
                if (!(events[i].events & EPOLLIN)) {
                    continue;
                }
                char ubuf[64 * 1024];
                bool fed_kcp = false;
                for (;;) {
                    struct sockaddr_storage rss;
                    socklen_t rlen = sizeof(rss);
                    ssize_t rn = recvfrom(c->udp_sock, ubuf, sizeof(ubuf), MSG_DONTWAIT, (struct sockaddr*)&rss, &rlen);
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
                    /* Validate UDP source address matches expected peer */
                    union sockaddr_inx ra;
                    memset(&ra, 0, sizeof(ra));
                    if (rss.ss_family == AF_INET) {
                        struct sockaddr_in *in4 = (struct sockaddr_in*)&rss;
                        ra.sin = *in4;
                    } else if (rss.ss_family == AF_INET6) {
                        struct sockaddr_in6 *in6 = (struct sockaddr_in6*)&rss;
                        ra.sin6 = *in6;
                    } else {
                        continue; /* Unknown family: drop */
                    }
                    if (!is_sockaddr_inx_equal(&ra, &c->peer_addr)) {
                        P_LOG_WARN("dropping UDP from unexpected %s (expected %s)",
                                   sockaddr_to_string(&ra), sockaddr_to_string(&c->peer_addr));
                        continue;
                    }
                    /* Handshake ACCEPT path */
                    if (!c->kcp_ready && rn >= (ssize_t)(1 + 1 + 4 + 16) &&
                        (unsigned char)ubuf[0] == (unsigned char)KTP_HS_ACCEPT &&
                        (unsigned char)ubuf[1] == (unsigned char)KCP_HS_VER) {
                        uint32_t conv = (uint32_t)((unsigned char)ubuf[2] << 24 | (unsigned char)ubuf[3] << 16 |
                                                    (unsigned char)ubuf[4] << 8 | (unsigned char)ubuf[5]);
                        if (memcmp(ubuf + 6, c->hs_token, 16) != 0) {
                            P_LOG_WARN("ACCEPT token mismatch; ignore");
                            continue;
                        }
                        c->conv = conv;
                        /* Derive session key if PSK provided */
                        if (cfg.has_psk) {
                            if (derive_session_key_from_psk((const uint8_t*)cfg.psk, c->hs_token, c->conv, c->session_key) == 0) {
                                c->has_session_key = true;
                                /* Initialize nonce base and counters */
                                memcpy(c->nonce_base, c->session_key, 12);
                                c->send_seq = 0;
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
                        if (kcp_setup_conn(c, c->udp_sock, &c->peer_addr, c->conv, &kopts) != 0) {
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
                            size_t off = c->request.rpos;
                            while (remain > 0) {
                                size_t chunk = remain;
                                if (chunk > sizeof(ubuf) - 1) chunk = sizeof(ubuf) - 1;
                                unsigned char *db = (unsigned char*)ubuf;
                                /* Rekey trigger before sending data */
                                if (cfg.has_psk && c->has_session_key && !c->rekey_in_progress && c->send_seq >= REKEY_SEQ_THRESHOLD) {
                                    c->next_epoch = c->epoch + 1;
                                    if (derive_session_key_epoch((const uint8_t*)cfg.psk, c->hs_token, c->conv, c->next_epoch, c->next_session_key) != 0) { c->state = S_CLOSING; break; }
                                    memcpy(c->next_nonce_base, c->next_session_key, 12);
                                    c->rekey_in_progress = true;
                                    c->rekey_deadline_ms = kcp_now_ms() + REKEY_TIMEOUT_MS;
                                    /* Send REKEY_INIT under current key */
                                    uint8_t nonceI[12]; memcpy(nonceI, c->nonce_base, 12);
                                    uint32_t seqI; if (!aead_next_send_seq(c, &seqI)) { c->state = S_CLOSING; break; }
                                    nonceI[8]=(uint8_t)seqI; nonceI[9]=(uint8_t)(seqI>>8); nonceI[10]=(uint8_t)(seqI>>16); nonceI[11]=(uint8_t)(seqI>>24);
                                    uint8_t adI[5]; adI[0]=(uint8_t)KTP_REKEY_INIT; adI[1]=(uint8_t)seqI; adI[2]=(uint8_t)(seqI>>8); adI[3]=(uint8_t)(seqI>>16); adI[4]=(uint8_t)(seqI>>24);
                                    unsigned char pktI[1 + 4 + 16];
                                    pktI[0] = (unsigned char)KTP_REKEY_INIT;
                                    pktI[1] = adI[1]; pktI[2] = adI[2]; pktI[3] = adI[3]; pktI[4] = adI[4];
                                    uint8_t tagI[16]; chacha20poly1305_seal(c->session_key, nonceI, adI, sizeof(adI), NULL, 0, NULL, tagI);
                                    memcpy(pktI + 1 + 4, tagI, 16);
                                    (void)ikcp_send(c->kcp, (const char*)pktI, (int)sizeof(pktI));
                                }
                                if (c->has_session_key) {
                            /* Rekey trigger before sending data */
                            if (cfg.has_psk && !c->rekey_in_progress && c->send_seq >= REKEY_SEQ_THRESHOLD) {
                                c->next_epoch = c->epoch + 1;
                                if (derive_session_key_epoch((const uint8_t*)cfg.psk, c->hs_token, c->conv, c->next_epoch, c->next_session_key) != 0) { c->state = S_CLOSING; break; }
                                memcpy(c->next_nonce_base, c->next_session_key, 12);
                                c->rekey_in_progress = true;
                                c->rekey_deadline_ms = kcp_now_ms() + REKEY_TIMEOUT_MS;
                                /* Send REKEY_INIT under current key */
                                uint8_t nonceI[12]; memcpy(nonceI, c->nonce_base, 12);
                                uint32_t seqI; if (!aead_next_send_seq(c, &seqI)) { c->state = S_CLOSING; break; }
                                nonceI[8]=(uint8_t)seqI; nonceI[9]=(uint8_t)(seqI>>8); nonceI[10]=(uint8_t)(seqI>>16); nonceI[11]=(uint8_t)(seqI>>24);
                                uint8_t adI[5]; adI[0]=(uint8_t)KTP_REKEY_INIT; adI[1]=(uint8_t)seqI; adI[2]=(uint8_t)(seqI>>8); adI[3]=(uint8_t)(seqI>>16); adI[4]=(uint8_t)(seqI>>24);
                                unsigned char pktI[1 + 4 + 16];
                                pktI[0] = (unsigned char)KTP_REKEY_INIT;
                                pktI[1] = adI[1]; pktI[2] = adI[2]; pktI[3] = adI[3]; pktI[4] = adI[4];
                                uint8_t tagI[16]; chacha20poly1305_seal(c->session_key, nonceI, adI, sizeof(adI), NULL, 0, NULL, tagI);
                                memcpy(pktI + 1 + 4, tagI, 16);
                                (void)ikcp_send(c->kcp, (const char*)pktI, (int)sizeof(pktI));
                            }
                                    /* [type][seq(4)][ct][tag(16)] */
                                    uint8_t nonce[12]; memcpy(nonce, c->nonce_base, 12);
                                    uint32_t seq; if (!aead_next_send_seq(c, &seq)) { c->state = S_CLOSING; break; }
                                    nonce[8] = (uint8_t)(seq);
                                    nonce[9] = (uint8_t)(seq >> 8);
                                    nonce[10]= (uint8_t)(seq >> 16);
                                    nonce[11]= (uint8_t)(seq >> 24);
                                    uint8_t ad[5]; ad[0]=(uint8_t)KTP_EDATA; ad[1]=(uint8_t)seq; ad[2]=(uint8_t)(seq>>8); ad[3]=(uint8_t)(seq>>16); ad[4]=(uint8_t)(seq>>24);
                                    db[0] = (unsigned char)KTP_EDATA;
                                    db[1] = ad[1]; db[2] = ad[2]; db[3] = ad[3]; db[4] = ad[4];
                                    chacha20poly1305_seal(c->session_key, nonce, ad, sizeof(ad),
                                                         (const uint8_t*)(c->request.data + off), chunk,
                                                         db + 1 + 4, db + 1 + 4 + chunk);
                                    int sn = ikcp_send(c->kcp, (const char*)db, (int)(1 + 4 + chunk + 16));
                                    if (sn < 0) { c->state = S_CLOSING; break; }
                                } else {
                                    db[0] = (unsigned char)KTP_DATA;
                                    memcpy(db + 1, c->request.data + off, chunk);
                                    int sn = ikcp_send(c->kcp, (const char*)db, (int)(chunk + 1));
                                    if (sn < 0) { c->state = S_CLOSING; break; }
                                }
                                off += chunk; remain -= chunk;
                            }
                            c->request.rpos = c->request.dlen; /* consumed */
                        }
                        /* If TCP already EOF, send FIN now */
                        if (c->cli_in_eof) {
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
                        if (got < 1) continue;
                        unsigned char t = (unsigned char)ubuf[0];
                        /* Rekey control handling */
                        if (t == KTP_REKEY_INIT && c->has_session_key) {
                            if (got < (int)(1 + 4 + 16)) continue;
                            uint32_t seq = (uint32_t)((uint8_t)ubuf[1] | ((uint8_t)ubuf[2] << 8) | ((uint8_t)ubuf[3] << 16) | ((uint8_t)ubuf[4] << 24));
                            /* Tentative anti-replay */
                            uint32_t win_tmp = c->recv_win; uint64_t mask_tmp = c->recv_win_mask;
                            if (!aead_replay_check_and_update(seq, &win_tmp, &mask_tmp)) {
                                P_LOG_WARN("drop replay/old REKEY_INIT seq=%u (cli)", seq);
                                continue;
                            }
                            uint8_t nonce[12]; memcpy(nonce, c->nonce_base, 12);
                            nonce[8]=(uint8_t)seq; nonce[9]=(uint8_t)(seq>>8); nonce[10]=(uint8_t)(seq>>16); nonce[11]=(uint8_t)(seq>>24);
                            uint8_t ad[5]; ad[0]=(uint8_t)KTP_REKEY_INIT; ad[1]=(uint8_t)seq; ad[2]=(uint8_t)(seq>>8); ad[3]=(uint8_t)(seq>>16); ad[4]=(uint8_t)(seq>>24);
                            if (chacha20poly1305_open(c->session_key, nonce, ad, sizeof(ad), NULL, 0, (const uint8_t*)(ubuf + 1 + 4), (uint8_t*)ubuf) != 0) {
                                P_LOG_ERR("REKEY_INIT tag verify failed (cli)");
                                c->state = S_CLOSING; break;
                            }
                            /* Commit anti-replay */
                            c->recv_win = win_tmp; c->recv_win_mask = mask_tmp;
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
                                /* seq 0 -> nonce low bytes all zero */
                                uint8_t ad2[5]; ad2[0]=(uint8_t)KTP_REKEY_ACK; ad2[1]=0; ad2[2]=0; ad2[3]=0; ad2[4]=0;
                                uint8_t tag[16];
                                chacha20poly1305_seal(c->next_session_key, nonce2, ad2, sizeof(ad2), NULL, 0, NULL, tag);
                                memcpy(pkt + 1 + 4, tag, 16);
                                (void)ikcp_send(c->kcp, (const char*)pkt, (int)sizeof(pkt));
                            }
                            /* Switch to next epoch immediately */
                            memcpy(c->session_key, c->next_session_key, 32);
                            memcpy(c->nonce_base, c->next_nonce_base, 12);
                            c->epoch = c->next_epoch;
                            c->send_seq = 0;
                            c->recv_win = UINT32_MAX; c->recv_win_mask = 0ULL;
                            c->rekey_in_progress = false;
                            continue;
                        }
                        if (t == KTP_REKEY_ACK && c->has_session_key && c->rekey_in_progress) {
                            if (got < (int)(1 + 4 + 16)) continue;
                            /* verify with next key, seq must be 0 */
                            uint32_t seq = (uint32_t)((uint8_t)ubuf[1] | ((uint8_t)ubuf[2] << 8) | ((uint8_t)ubuf[3] << 16) | ((uint8_t)ubuf[4] << 24));
                            if (seq != 0) { P_LOG_ERR("REKEY_ACK seq!=0 (cli)"); c->state = S_CLOSING; break; }
                            uint8_t nonce2[12]; memcpy(nonce2, c->next_nonce_base, 12);
                            uint8_t ad2[5]; ad2[0]=(uint8_t)KTP_REKEY_ACK; ad2[1]=0; ad2[2]=0; ad2[3]=0; ad2[4]=0;
                            if (chacha20poly1305_open(c->next_session_key, nonce2, ad2, sizeof(ad2), NULL, 0, (const uint8_t*)(ubuf + 1 + 4), (uint8_t*)ubuf) != 0) {
                                P_LOG_ERR("REKEY_ACK tag verify failed (cli)");
                                c->state = S_CLOSING; break;
                            }
                            /* Switch epoch */
                            memcpy(c->session_key, c->next_session_key, 32);
                            memcpy(c->nonce_base, c->next_nonce_base, 12);
                            c->epoch = c->next_epoch;
                            c->send_seq = 0;
                            c->recv_win = UINT32_MAX; c->recv_win_mask = 0ULL;
                            c->rekey_in_progress = false;
                            continue;
                        }
                        if (c->has_session_key && (t == KTP_DATA || t == KTP_FIN)) {
                            /* Encrypted session must not receive plaintext types */
                            P_LOG_ERR("plaintext pkt type in encrypted session (cli)");
                            c->state = S_CLOSING; break;
                        }
                        if (t == KTP_EFIN && c->has_session_key) {
                            if (got < (int)(1 + 4 + 16)) continue;
                            uint32_t seq = (uint32_t)( (uint8_t)ubuf[1] | ((uint8_t)ubuf[2] << 8) | ((uint8_t)ubuf[3] << 16) | ((uint8_t)ubuf[4] << 24) );
                            /* Anti-replay window check (tentative) */
                            uint32_t win_tmp = c->recv_win; uint64_t mask_tmp = c->recv_win_mask;
                            if (!aead_replay_check_and_update(seq, &win_tmp, &mask_tmp)) {
                                P_LOG_WARN("drop replay/old EFIN seq=%u (cli)", seq);
                                continue;
                            }
                            uint8_t nonce[12]; memcpy(nonce, c->nonce_base, 12);
                            nonce[8]=(uint8_t)seq; nonce[9]=(uint8_t)(seq>>8); nonce[10]=(uint8_t)(seq>>16); nonce[11]=(uint8_t)(seq>>24);
                            uint8_t ad[5]; ad[0]=(uint8_t)KTP_EFIN; ad[1]=(uint8_t)seq; ad[2]=(uint8_t)(seq>>8); ad[3]=(uint8_t)(seq>>16); ad[4]=(uint8_t)(seq>>24);
                            if (chacha20poly1305_open(c->session_key, nonce, ad, sizeof(ad), NULL, 0, (const uint8_t*)(ubuf + 1 + 4), (uint8_t*)ubuf) != 0) {
                                P_LOG_ERR("EFIN tag verify failed");
                                c->state = S_CLOSING; break;
                            }
                            /* Commit anti-replay window advance */
                            c->recv_win = win_tmp; c->recv_win_mask = mask_tmp;
                            /* treat as FIN */
                            c->svr_in_eof = true;
                            if (!c->svr2cli_shutdown && c->response.dlen == c->response.rpos) {
                                shutdown(c->cli_sock, SHUT_WR);
                                c->svr2cli_shutdown = true;
                            }
                            continue;
                        }
                        if (t == KTP_FIN) {
                            /* Peer half-closing server->client: record and possibly shutdown write after drain */
                            c->svr_in_eof = true;
                            /* Try to shutdown write if nothing pending */
                            if (!c->svr2cli_shutdown && c->response.dlen == c->response.rpos) {
                                shutdown(c->cli_sock, SHUT_WR);
                                c->svr2cli_shutdown = true;
                            }
                            continue;
                        }
                        /* Data (plain or encrypted) */
                        char *payload = NULL;
                        int plen = 0;
                        if (t == KTP_EDATA && c->has_session_key) {
                            if (got < (int)(1 + 4 + 16)) continue;
                            uint32_t seq = (uint32_t)( (uint8_t)ubuf[1] | ((uint8_t)ubuf[2] << 8) | ((uint8_t)ubuf[3] << 16) | ((uint8_t)ubuf[4] << 24) );
                            /* Anti-replay window check (tentative) */
                            uint32_t win_tmp = c->recv_win; uint64_t mask_tmp = c->recv_win_mask;
                            if (!aead_replay_check_and_update(seq, &win_tmp, &mask_tmp)) {
                                P_LOG_WARN("drop replay/old EDATA seq=%u (cli)", seq);
                                continue;
                            }
                            uint8_t nonce[12]; memcpy(nonce, c->nonce_base, 12);
                            nonce[8]=(uint8_t)seq; nonce[9]=(uint8_t)(seq>>8); nonce[10]=(uint8_t)(seq>>16); nonce[11]=(uint8_t)(seq>>24);
                            uint8_t ad[5]; ad[0]=(uint8_t)KTP_EDATA; ad[1]=(uint8_t)seq; ad[2]=(uint8_t)(seq>>8); ad[3]=(uint8_t)(seq>>16); ad[4]=(uint8_t)(seq>>24);
                            int ctlen = got - (int)(1 + 4 + 16);
                            if (ctlen < 0) continue;
                            if (chacha20poly1305_open(c->session_key, nonce, ad, sizeof(ad), (const uint8_t*)(ubuf + 1 + 4), (size_t)ctlen, (const uint8_t*)(ubuf + 1 + 4 + ctlen), (uint8_t*)ubuf) != 0) {
                                P_LOG_ERR("EDATA tag verify failed");
                                c->state = S_CLOSING; break;
                            }
                            /* Commit anti-replay window advance */
                            c->recv_win = win_tmp; c->recv_win_mask = mask_tmp;
                            payload = ubuf; plen = ctlen;
                        } else {
                            payload = ubuf + 1; plen = got - 1;
                        }
                        ssize_t wn = send(c->cli_sock, payload, (size_t)plen, MSG_NOSIGNAL);
                        if (wn < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                /* Backpressure: buffer and enable EPOLLOUT */
                                size_t need = (size_t)plen;
                                size_t freecap = (c->response.capacity > c->response.dlen) ? (c->response.capacity - c->response.dlen) : 0;
                                if (freecap < need) {
                                    size_t ncap = c->response.capacity ? c->response.capacity * 2 : (size_t)65536;
                                    if (ncap < c->response.dlen + need) ncap = c->response.dlen + need;
                                    char *np = (char*)realloc(c->response.data, ncap);
                                    if (!np) { c->state = S_CLOSING; break; }
                                    c->response.data = np;
                                    c->response.capacity = ncap;
                                }
                                memcpy(c->response.data + c->response.dlen, payload, (size_t)plen);
                                c->response.dlen += (size_t)plen;
                                struct epoll_event cev = (struct epoll_event){0};
                                cev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
                                cev.data.ptr = c->cli_tag;
                                (void)ep_add_or_mod(epfd, c->cli_sock, &cev);
                                break;
                            }
                            c->state = S_CLOSING;
                            break;
                        } else if (wn < plen) {
                            /* Short write: buffer remaining and enable EPOLLOUT */
                            size_t rem = (size_t)plen - (size_t)wn;
                            size_t freecap = (c->response.capacity > c->response.dlen) ? (c->response.capacity - c->response.dlen) : 0;
                            if (freecap < rem) {
                                size_t ncap = c->response.capacity ? c->response.capacity * 2 : (size_t)65536;
                                if (ncap < c->response.dlen + rem) ncap = c->response.dlen + rem;
                                char *np = (char*)realloc(c->response.data, ncap);
                                if (!np) { c->state = S_CLOSING; break; }
                                c->response.data = np;
                                c->response.capacity = ncap;
                            }
                            memcpy(c->response.data + c->response.dlen, payload + wn, rem);
                            c->response.dlen += rem;
                            struct epoll_event cev = (struct epoll_event){0};
                            cev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
                            cev.data.ptr = c->cli_tag;
                            (void)ep_add_or_mod(epfd, c->cli_sock, &cev);
                            break;
                        }
                    }
                    c->last_active = time(NULL);
                }
                continue;
            }

            /* TCP client socket events */
            if (etag->which == 1 && (events[i].events & (EPOLLERR | EPOLLHUP))) {
                c->state = S_CLOSING;
            }

            if (etag->which == 1 && (events[i].events & EPOLLOUT)) {
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
                    cev.data.ptr = c->cli_tag;
                    (void)ep_add_or_mod(epfd, c->cli_sock, &cev);
                    /* If we received FIN earlier, shutdown write now that buffer is drained */
                    if (c->svr_in_eof && !c->svr2cli_shutdown) {
                        shutdown(c->cli_sock, SHUT_WR);
                        c->svr2cli_shutdown = true;
                    }
                }
            }

            if (etag->which == 1 && (events[i].events & (EPOLLIN | EPOLLRDHUP))) {
                /* TCP side readable/half-closed */
                char tbuf[64 * 1024];
                ssize_t rn;
                while ((rn = recv(c->cli_sock, tbuf, sizeof(tbuf), 0)) > 0) {
                    if (!c->kcp_ready) {
                        /* buffer until KCP ready */
                        size_t need = (size_t)rn;
                        size_t freecap = (c->request.capacity > c->request.dlen) ? (c->request.capacity - c->request.dlen) : 0;
                        if (freecap < need) {
                            size_t ncap = c->request.capacity ? c->request.capacity * 2 : (size_t)65536;
                            if (ncap < c->request.dlen + need) ncap = c->request.dlen + need;
                            char *np = (char*)realloc(c->request.data, ncap);
                            if (!np) { c->state = S_CLOSING; break; }
                            c->request.data = np;
                            c->request.capacity = ncap;
                        }
                        memcpy(c->request.data + c->request.dlen, tbuf, (size_t)rn);
                        c->request.dlen += (size_t)rn;
                    } else {
                        if (c->has_session_key) {
                            unsigned char hdrbuf[1 + 4 + sizeof(tbuf) + 16];
                            uint8_t nonce[12]; memcpy(nonce, c->nonce_base, 12);
                            uint32_t seq; if (!aead_next_send_seq(c, &seq)) { c->state = S_CLOSING; break; }
                            nonce[8]=(uint8_t)seq; nonce[9]=(uint8_t)(seq>>8); nonce[10]=(uint8_t)(seq>>16); nonce[11]=(uint8_t)(seq>>24);
                            uint8_t ad[5]; ad[0]=(uint8_t)KTP_EDATA; ad[1]=(uint8_t)seq; ad[2]=(uint8_t)(seq>>8); ad[3]=(uint8_t)(seq>>16); ad[4]=(uint8_t)(seq>>24);
                            hdrbuf[0] = (unsigned char)KTP_EDATA;
                            hdrbuf[1] = ad[1]; hdrbuf[2] = ad[2]; hdrbuf[3] = ad[3]; hdrbuf[4] = ad[4];
                            chacha20poly1305_seal(c->session_key, nonce, ad, sizeof(ad), (const uint8_t*)tbuf, (size_t)rn, hdrbuf + 1 + 4, hdrbuf + 1 + 4 + rn);
                            int sn = ikcp_send(c->kcp, (const char*)hdrbuf, (int)(1 + 4 + rn + 16));
                            if (sn < 0) { c->state = S_CLOSING; break; }
                        } else {
                            /* Wrap as DATA with 1-byte header */
                            unsigned char hdrbuf[1 + sizeof(tbuf)];
                            hdrbuf[0] = (unsigned char)KTP_DATA;
                            memcpy(hdrbuf + 1, tbuf, (size_t)rn);
                            int sn = ikcp_send(c->kcp, (const char*)hdrbuf, (int)(rn + 1));
                            if (sn < 0) { c->state = S_CLOSING; break; }
                        }
                    }
                }
                if (rn == 0) {
                    /* TCP EOF: on handshake pending, defer FIN until ready */
                    if (c->kcp_ready) {
                        if (c->has_session_key) {
                            uint8_t nonce[12]; memcpy(nonce, c->nonce_base, 12);
                            uint32_t seq; if (!aead_next_send_seq(c, &seq)) { c->state = S_CLOSING; }
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
                    }
                    c->cli_in_eof = true;
                    struct epoll_event cev = (struct epoll_event){0};
                    cev.events = EPOLLRDHUP | EPOLLERR | EPOLLHUP; /* disable EPOLLIN */
                    cev.data.ptr = c->cli_tag;
                    (void)ep_add_or_mod(epfd, c->cli_sock, &cev);
                } else if (rn < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    c->state = S_CLOSING;
                }
            }
        }

        /* KCP timer updates and GC */
        now = kcp_now_ms();
        struct proxy_conn *pos, *tmp;
        list_for_each_entry_safe(pos, tmp, &conns, list) {
            if (pos->kcp) (void)kcp_update_flush(pos, now);
            /* If we received FIN earlier and output buffer has drained, shutdown(WRITE) */
            if (pos->svr_in_eof && !pos->svr2cli_shutdown && pos->response.dlen == pos->response.rpos) {
                shutdown(pos->cli_sock, SHUT_WR);
                pos->svr2cli_shutdown = true;
            }
            /* Graceful close when both halves have signaled EOF and all pending are flushed */
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
            if (pos->state != S_CLOSING && pos->last_active && (ct - pos->last_active) > IDLE_TO) {
                P_LOG_INFO("idle timeout, conv=%u", pos->conv);
                pos->state = S_CLOSING;
            }
            if (pos->state == S_CLOSING) {
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
    if (lsock >= 0) close(lsock);
    if (epfd >= 0) epoll_close_comp(epfd);
    cleanup_pidfile();
    return rc;
}
