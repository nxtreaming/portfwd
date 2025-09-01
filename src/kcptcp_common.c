#include "kcptcp_common.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <netinet/tcp.h>
#endif
#include "common.h"
#include "3rd/kcp/ikcp.h"
#include "3rd/chacha20poly1305/chacha20poly1305.h"
#include "secure_random.h"
#include "buffer_limits.h"

/* ---------------- Env-controlled stats helpers ---------------- */
uint32_t get_stats_interval_ms(void) {
    static uint32_t cached = 0; /* 0 => uninitialized */
    if (cached == 0) {
        const char *s = getenv("PFWD_STATS_INTERVAL_MS");
        long v = s ? strtol(s, NULL, 10) : 0;
        if (v <= 0)
            v = 5000; /* default 5s */
        if (v < 100)
            v = 100; /* clamp */
        if (v > 600000)
            v = 600000; /* 10 minutes */
        cached = (uint32_t)v;
    }
    return cached;
}

bool get_stats_dump_enabled(void) {
    const char *s = getenv("PFWD_STATS_DUMP");
    if (!s)
        return false;
    return !(s[0] == '0');
}

bool get_stats_enabled(void) {
    const char *s = getenv("PFWD_STATS_ENABLE");
    if (!s)
        return true; /* default enabled */
    return !(s[0] == '0');
}

/* Deterministic conv toggle */
bool kcptcp_deterministic_conv_enabled(void) {
    const char *s = getenv("PFWD_DETERMINISTIC_CONV");
    if (!s)
        return true; /* default enabled */
    return !(s[0] == '0' || s[0] == 'n' || s[0] == 'N' || s[0] == 'f' || s[0] == 'F');
}

/* ---------------- Socket helpers ---------------- */
void set_sock_buffers_sz(int sockfd, int bytes) {
    if (bytes <= 0)
        return;
    (void)setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes));
    (void)setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
}

void kcptcp_tune_tcp_socket(int fd, int sockbuf_bytes, bool tcp_nodelay, bool keepalive) {
    if (fd < 0)
        return;
    set_nonblock(fd);
    set_sock_buffers_sz(fd, sockbuf_bytes);
    if (keepalive) {
        int yes = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
    }
#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    if (tcp_nodelay) {
        int one = 1;
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
#else
    (void)tcp_nodelay;
#endif
}

void kcp_opts_apply_overrides(struct kcp_opts *o, int mtu, int nd, int it, int rs, int nc, int snd,
                              int rcv) {
    if (mtu > 0)
        o->mtu = mtu;
    if (nd >= 0)
        o->nodelay = nd;
    if (it >= 0)
        o->interval_ms = it;
    if (rs >= 0)
        o->resend = rs;
    if (nc >= 0)
        o->nc = nc;
    if (snd >= 0)
        o->sndwnd = snd;
    if (rcv >= 0)
        o->rcvwnd = rcv;
}

int kcptcp_compute_kcp_timeout_ms(struct list_head *conns, int default_ms) {
    int timeout_ms = default_ms;
    uint32_t now = kcp_now_ms();
    struct proxy_conn *pc;
    list_for_each_entry(pc, conns, list) {
        if (!pc->kcp)
            continue;
        uint32_t due = ikcp_check(pc->kcp, now);
        int t = (int)((due > now) ? (due - now) : 0);
        if (t < timeout_ms)
            timeout_ms = t;
    }
    return timeout_ms;
}

int kcptcp_ep_register(int epfd, int fd, void *ptr, uint32_t base_events, uint32_t extra_events) {
    struct epoll_event ev = (struct epoll_event){0};
    ev.events = base_events | extra_events;
    ev.data.ptr = ptr;
    return ep_add_or_mod(epfd, fd, &ev);
}

uint32_t rand_between(uint32_t min, uint32_t max) {
    if (max <= min)
        return min;
    uint32_t r = 0;
    if (secure_random_bytes((unsigned char *)&r, sizeof(r)) != 0) {
        r = (uint32_t)time(NULL);
    }
    uint32_t span = max - min + 1u;
    return min + (r % span);
}

/* ---------------- PSK parsing ---------------- */
static int hex2nibble(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

bool parse_psk_hex32(const char *hex, uint8_t out[32]) {
    size_t n = strlen(hex);
    if (n != 64)
        return false;
    for (size_t i = 0; i < 32; ++i) {
        int hi = hex2nibble(hex[2 * i]);
        int lo = hex2nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/* ---------------- Session key derivation ---------------- */
int derive_session_key_from_psk(const uint8_t *psk, const uint8_t token[16], uint32_t conv,
                                uint8_t out_key[32]) {
    if (!psk || !token || !out_key) return -1;
    /* AAD = token(16) || conv(4, network byte order) */
    uint8_t aad[20];
    memcpy(aad, token, 16);
    uint32_t cbe = htonl(conv);
    memcpy(aad + 16, &cbe, 4);

    /* Two domain-separated nonces to stretch 16B tag -> 32B key */
    uint8_t nonce1[12] = { 'P','F','W','D','K','D','F',0,0,0,0,1 };
    uint8_t nonce2[12] = { 'P','F','W','D','K','D','F',0,0,0,0,2 };

    uint8_t tag1[16];
    uint8_t tag2[16];

    /* AEAD with AAD-only (plaintext len 0) to produce tags */
    if (chacha20poly1305_seal(psk, nonce1, aad, sizeof(aad), NULL, 0, NULL, tag1), 0) {
        /* chacha20poly1305_seal has no return; assume success */
    }
    if (chacha20poly1305_seal(psk, nonce2, aad, sizeof(aad), NULL, 0, NULL, tag2), 0) {
    }

    memcpy(out_key, tag1, 16);
    memcpy(out_key + 16, tag2, 16);
    return 0;
}

/* ---------------- AEAD anti-replay helpers ---------------- */
static inline int32_t seq_diff_u32(uint32_t a, uint32_t b) {
    return (int32_t)(a - b);
}

bool aead_replay_check_and_update(uint32_t seq, uint32_t *p_win, uint64_t *p_mask) {
    uint32_t win = *p_win;
    uint64_t mask = *p_mask;
    if (win == UINT32_MAX) {
        *p_win = seq;
        *p_mask = 1ULL;
        return true;
    }
    int32_t d = seq_diff_u32(seq, win);
    if (d > 0) {
        uint32_t shift = (d >= 64) ? 64u : (uint32_t)d;
        mask = (shift >= 64) ? 0ULL : (mask << shift);
        mask |= 1ULL;
        win = seq;
        *p_win = win;
        *p_mask = mask;
        return true;
    }
    int32_t behind = -d;
    if (behind >= 64)
        return false;
    uint64_t bit = 1ULL << behind;
    if (mask & bit)
        return false;
    mask |= bit;
    *p_win = win;
    *p_mask = mask;
    return true;
}

bool aead_next_send_seq(struct proxy_conn *c, uint32_t *out_seq) {
    if (c->send_seq == UINT32_MAX)
        return false;
    *out_seq = c->send_seq++;
    return true;
}

/* ---------------- Socket setup helpers ---------------- */
int kcptcp_setup_tcp_listener(const union sockaddr_inx *addr, bool reuse_addr, bool reuse_port,
                              bool v6only, int sockbuf_bytes, int backlog) {
    int fd = socket(addr->sa.sa_family, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    if (reuse_addr) {
        int on = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    }
#ifdef SO_REUSEPORT
    if (reuse_port) {
        int on = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
    }
#endif
#ifdef IPV6_V6ONLY
    if (v6only && addr->sa.sa_family == AF_INET6) {
        int on = 1;
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
    }
#endif
    set_nonblock(fd);
    set_sock_buffers_sz(fd, sockbuf_bytes);
    if (bind(fd, &addr->sa, (socklen_t)sizeof_sockaddr(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, backlog) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int kcptcp_setup_udp_listener(const union sockaddr_inx *addr, bool reuse_addr, bool reuse_port,
                              bool v6only, int sockbuf_bytes) {
    int fd = socket(addr->sa.sa_family, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    if (reuse_addr) {
        int on = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    }
#ifdef SO_REUSEPORT
    if (reuse_port) {
        int on = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
    }
#endif
#ifdef IPV6_V6ONLY
    if (v6only && addr->sa.sa_family == AF_INET6) {
        int on = 1;
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
    }
#endif
    set_nonblock(fd);
    set_sock_buffers_sz(fd, sockbuf_bytes);
    if (bind(fd, &addr->sa, (socklen_t)sizeof_sockaddr(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int kcptcp_create_udp_socket(int family, int sockbuf_bytes) {
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    set_nonblock(fd);
    set_sock_buffers_sz(fd, sockbuf_bytes);
    return fd;
}

int kcptcp_create_tcp_socket(int family, int sockbuf_bytes, bool tcp_nodelay) {
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    kcptcp_tune_tcp_socket(fd, sockbuf_bytes, tcp_nodelay, false);
    return fd;
}

/* ---------------- Common CLI parsing ---------------- */
int kcptcp_parse_common_opts(int argc, char **argv, struct kcptcp_common_cli *out, int *pos_start,
                             bool is_server) {
    (void)is_server;
    if (!out)
        return 0;
    memset(out, 0, sizeof(*out));
    out->reuse_addr = false;
    out->reuse_port = false;
    out->v6only = false;
    out->sockbuf_bytes = 0;
    out->tcp_nodelay = false;
    out->has_psk = false;
    out->kcp_mtu = 0;
    out->kcp_nd = -1;
    out->kcp_it = -1;
    out->kcp_rs = -1;
    out->kcp_nc = -1;
    out->kcp_snd = -1;
    out->kcp_rcv = -1;
    out->hs_agg_min_ms = 20;
    out->hs_agg_max_ms = 80;
    out->hs_agg_max_bytes = 1024;
    out->hs_rsp_jitter_min_ms = 5;
    out->hs_rsp_jitter_max_ms = 20;
    out->hs_profile = NULL;
    out->show_help = false;

    optind = 1;
    int opt;
    while ((opt = getopt(argc, argv, "dp:rR6b:NK:M:n:I:X:C:w:W:g:G:j:P:h")) != -1) {
        switch (opt) {
        case 'd':
            out->daemonize = true;
            break;
        case 'p':
            out->pidfile = optarg;
            break;
        case 'r':
            out->reuse_addr = true;
            break;
        case 'R':
            out->reuse_port = true;
            break;
        case '6':
            out->v6only = true;
            break;
        case 'b': {
            long v = strtol(optarg, NULL, 10);
            if (v < 0)
                return 0;
            out->sockbuf_bytes = (int)v;
            break;
        }
        case 'N':
            out->tcp_nodelay = true;
            break;
        case 'K': {
            if (!parse_psk_hex32(optarg, out->psk)) {
                return 0;
            }
            out->has_psk = true;
            break;
        }
        case 'M': {
            long v = strtol(optarg, NULL, 10);
            if (v <= 0)
                return 0;
            out->kcp_mtu = (int)v;
            break;
        }
        case 'n': {
            long v = strtol(optarg, NULL, 10);
            if (v < 0)
                return 0;
            out->kcp_nd = (int)v;
            break;
        }
        case 'I': {
            long v = strtol(optarg, NULL, 10);
            if (v < 0)
                return 0;
            out->kcp_it = (int)v;
            break;
        }
        case 'X': {
            long v = strtol(optarg, NULL, 10);
            if (v < 0)
                return 0;
            out->kcp_rs = (int)v;
            break;
        }
        case 'C': {
            long v = strtol(optarg, NULL, 10);
            if (v < 0)
                return 0;
            out->kcp_nc = (int)v;
            break;
        }
        case 'w': {
            long v = strtol(optarg, NULL, 10);
            if (v < 0)
                return 0;
            out->kcp_snd = (int)v;
            break;
        }
        case 'W': {
            long v = strtol(optarg, NULL, 10);
            if (v < 0)
                return 0;
            out->kcp_rcv = (int)v;
            break;
        }
        case 'g': {
            char *sep = strchr(optarg, '-');
            if (!sep)
                sep = strchr(optarg, ':');
            long vmin = 0, vmax = 0;
            if (sep) {
                *sep = '\0';
                vmin = strtol(optarg, NULL, 10);
                vmax = strtol(sep + 1, NULL, 10);
                *sep = '-';
            } else {
                vmax = strtol(optarg, NULL, 10);
                vmin = 0;
            }
            if (vmin < 0 || vmax < 0) {
                return 0;
            }
            out->hs_agg_min_ms = (uint32_t)vmin;
            out->hs_agg_max_ms = (uint32_t)vmax;
            break;
        }
        case 'G': {
            long v = strtol(optarg, NULL, 10);
            if (v < 0)
                return 0;
            if (v > 4096)
                v = 4096;
            out->hs_agg_max_bytes = (uint32_t)v;
            break;
        }
        case 'j': {
            char *sep = strchr(optarg, '-');
            if (!sep)
                sep = strchr(optarg, ':');
            long vmin = 0, vmax = 0;
            if (sep) {
                *sep = '\0';
                vmin = strtol(optarg, NULL, 10);
                vmax = strtol(sep + 1, NULL, 10);
                *sep = '-';
            } else {
                vmax = strtol(optarg, NULL, 10);
                vmin = 0;
            }
            if (vmin < 0 || vmax < 0) {
                return 0;
            }
            out->hs_rsp_jitter_min_ms = (uint32_t)vmin;
            out->hs_rsp_jitter_max_ms = (uint32_t)vmax;
            break;
        }
        case 'P':
            out->hs_profile = optarg;
            break;
        case 'h':
            out->show_help = true;
            break;
        default:
            return 0;
        }
    }
    if (pos_start)
        *pos_start = optind;
    return 1;
}

/* ---------------- Stats helpers (shared) ---------------- */
void kcptcp_maybe_log_stats(struct proxy_conn *c, uint64_t now_ms) {
    if (!c || !c->kcp)
        return;
    if (!get_stats_enabled())
        return;
    if (c->last_stat_ms == 0) {
        c->last_stat_ms = now_ms;
        c->last_tcp_rx_bytes = c->tcp_rx_bytes;
        c->last_tcp_tx_bytes = c->tcp_tx_bytes;
        c->last_kcp_tx_bytes = c->kcp_tx_bytes;
        c->last_kcp_rx_bytes = c->kcp_rx_bytes;
        c->last_kcp_xmit = c->kcp->xmit;
        c->last_rekeys_initiated = c->rekeys_initiated;
        c->last_rekeys_completed = c->rekeys_completed;
        return;
    }
    if (now_ms - c->last_stat_ms < get_stats_interval_ms())
        return;
    uint64_t dt = now_ms - c->last_stat_ms;
    uint64_t d_tcp_rx = c->tcp_rx_bytes - c->last_tcp_rx_bytes;
    uint64_t d_tcp_tx = c->tcp_tx_bytes - c->last_tcp_tx_bytes;
    uint64_t d_kcp_tx = c->kcp_tx_bytes - c->last_kcp_tx_bytes;
    uint64_t d_kcp_rx = c->kcp_rx_bytes - c->last_kcp_rx_bytes;
    uint32_t d_xmit = c->kcp->xmit - c->last_kcp_xmit;
    uint32_t d_rekey_i = c->rekeys_initiated - c->last_rekeys_initiated;
    uint32_t d_rekey_c = c->rekeys_completed - c->last_rekeys_completed;
    double sec = (double)dt / 1000.0;
    double tcp_in_mbps = sec > 0 ? (double)d_tcp_rx * 8.0 / (sec * 1e6) : 0.0;
    double tcp_out_mbps = sec > 0 ? (double)d_tcp_tx * 8.0 / (sec * 1e6) : 0.0;
    double kcp_in_mbps = sec > 0 ? (double)d_kcp_rx * 8.0 / (sec * 1e6) : 0.0;
    double kcp_out_mbps = sec > 0 ? (double)d_kcp_tx * 8.0 / (sec * 1e6) : 0.0;
    P_LOG_INFO("stats conv=%u: TCP in=%.3f Mbps out=%.3f Mbps | KCP payload in=%.3f "
               "Mbps out=%.3f Mbps | KCP xmit_delta=%u RTT=%dms | rekey i=%u c=%u",
               c->conv, tcp_in_mbps, tcp_out_mbps, kcp_in_mbps, kcp_out_mbps, d_xmit,
               c->kcp->rx_srtt, d_rekey_i, d_rekey_c);
    c->last_stat_ms = now_ms;
    c->last_tcp_rx_bytes = c->tcp_rx_bytes;
    c->last_tcp_tx_bytes = c->tcp_tx_bytes;
    c->last_kcp_tx_bytes = c->kcp_tx_bytes;
    c->last_kcp_rx_bytes = c->kcp_rx_bytes;
    c->last_kcp_xmit = c->kcp->xmit;
    c->last_rekeys_initiated = c->rekeys_initiated;
    c->last_rekeys_completed = c->rekeys_completed;
}

void kcptcp_log_total_stats(struct proxy_conn *c) {
    if (!c)
        return;
    if (!get_stats_dump_enabled())
        return;
    P_LOG_INFO("stats total conv=%u: tcp_rx=%llu tcp_tx=%llu udp_rx=%llu udp_tx=%llu "
               "kcp_rx_msgs=%llu kcp_tx_msgs=%llu kcp_rx_bytes=%llu kcp_tx_bytes=%llu "
               "rekeys_i=%u rekeys_c=%u",
               c->conv, (unsigned long long)c->tcp_rx_bytes, (unsigned long long)c->tcp_tx_bytes,
               (unsigned long long)c->udp_rx_bytes, (unsigned long long)c->udp_tx_bytes,
               (unsigned long long)c->kcp_rx_msgs, (unsigned long long)c->kcp_tx_msgs,
               (unsigned long long)c->kcp_rx_bytes, (unsigned long long)c->kcp_tx_bytes,
               c->rekeys_initiated, c->rekeys_completed);
}

/* ---------------- Shared buffer helper ---------------- */
int ensure_buffer_capacity(struct buffer_info *buf, size_t needed, size_t max_size) {
    if (!buf)
        return -1;
    if (buf->capacity >= needed)
        return 0;
    size_t new_cap = buf->capacity ? buf->capacity * 2 : INITIAL_BUFFER_SIZE;
    if (new_cap < needed)
        new_cap = needed;
    if (new_cap > max_size)
        return -1;
    char *np = (char *)realloc(buf->data, new_cap);
    if (!np)
        return -1;
    buf->data = np;
    buf->capacity = new_cap;
    return 0;
}

/* ---------------- Stealth Handshake Implementation ---------------- */
int stealth_handshake_create_first_packet(const uint8_t *psk, const uint8_t *token,
                                          const uint8_t *initial_data, size_t initial_data_len,
                                          uint8_t *out_packet, size_t *out_packet_len) {
    if (!psk || !token || !out_packet || !out_packet_len)
        return -1;
    struct stealth_handshake_payload payload;
    payload.magic = htonl(STEALTH_HANDSHAKE_MAGIC);
    payload.timestamp = htonl((uint32_t)time(NULL));
    memcpy(payload.token, token, 16);
    if (secure_random_bytes((uint8_t *)&payload.nonce, sizeof(payload.nonce)) != 0)
        return -1;
    if (secure_random_bytes(payload.reserved, sizeof(payload.reserved)) != 0)
        return -1;

    uint8_t pad_rnd = 0;
    if (secure_random_bytes(&pad_rnd, 1) != 0)
        return -1;
    size_t padding_size = (size_t)(pad_rnd % 16); /* 0..15 to reduce overhead */
    size_t total_size = sizeof(payload) + initial_data_len + padding_size;
    if (total_size + 28 > *out_packet_len)
        return -1; /* +12 nonce +16 tag */

    uint8_t *plaintext = (uint8_t *)malloc(total_size);
    if (!plaintext)
        return -1;
    memcpy(plaintext, &payload, sizeof(payload));
    if (initial_data && initial_data_len > 0)
        memcpy(plaintext + sizeof(payload), initial_data, initial_data_len);
    if (secure_random_bytes(plaintext + sizeof(payload) + initial_data_len, padding_size) != 0) {
        free(plaintext);
        return -1;
    }

    uint8_t nonce[12];
    if (secure_random_bytes(nonce, sizeof(nonce)) != 0) {
        free(plaintext);
        return -1;
    }
    uint8_t tag[16];
    chacha20poly1305_seal(psk, nonce, NULL, 0, plaintext, total_size, out_packet + 12, tag);
    memcpy(out_packet, nonce, 12);
    memcpy(out_packet + 12 + total_size, tag, 16);
    *out_packet_len = 12 + total_size + 16;
    free(plaintext);
    return 0;
}

int stealth_handshake_parse_first_packet(const uint8_t *psk, const uint8_t *packet,
                                         size_t packet_len,
                                         struct stealth_handshake_payload *payload,
                                         uint8_t *out_data, size_t *out_data_len) {
    if (!psk || !packet || !payload || packet_len < 28)
        return -1;
    const uint8_t *nonce = packet;
    const uint8_t *ciphertext = packet + 12;
    size_t ciphertext_len = packet_len - 28;
    const uint8_t *tag = packet + 12 + ciphertext_len;

    uint8_t *plaintext = (uint8_t *)malloc(ciphertext_len);
    if (!plaintext)
        return -1;
    if (chacha20poly1305_open(psk, nonce, NULL, 0, ciphertext, ciphertext_len, tag, plaintext) !=
        0) {
        free(plaintext);
        return -1;
    }
    if (ciphertext_len < sizeof(struct stealth_handshake_payload)) {
        free(plaintext);
        return -1;
    }
    memcpy(payload, plaintext, sizeof(struct stealth_handshake_payload));
    if (ntohl(payload->magic) != STEALTH_HANDSHAKE_MAGIC) {
        free(plaintext);
        return -1;
    }
    time_t now = time(NULL);
    time_t msg_time = (time_t)ntohl(payload->timestamp);
    if (msg_time < now - 300 || msg_time > now + 300) {
        free(plaintext);
        return -1;
    }

    size_t remaining = ciphertext_len - sizeof(struct stealth_handshake_payload);
    if (out_data && out_data_len && remaining > 0) {
        size_t copy = remaining < *out_data_len ? remaining : *out_data_len;
        memcpy(out_data, plaintext + sizeof(struct stealth_handshake_payload), copy);
        *out_data_len = copy;
    } else if (out_data_len) {
        *out_data_len = 0;
    }
    free(plaintext);
    return 0;
}

int stealth_handshake_create_response(const uint8_t *psk, uint32_t conv, const uint8_t *token,
                                      uint8_t *out_packet, size_t *out_packet_len) {
    if (!psk || !token || !out_packet || !out_packet_len)
        return -1;
    struct stealth_handshake_response response;
    response.magic = htonl(STEALTH_RESPONSE_MAGIC);
    response.conv = htonl(conv);
    memcpy(response.token, token, 16);
    response.timestamp = htonl((uint32_t)time(NULL));
    if (secure_random_bytes(response.reserved, sizeof(response.reserved)) != 0)
        return -1;

    uint8_t pad_rnd = 0;
    if (secure_random_bytes(&pad_rnd, 1) != 0)
        return -1;
    size_t padding_size = (size_t)(pad_rnd % 16);
    size_t total_size = sizeof(response) + padding_size;
    if (total_size + 28 > *out_packet_len)
        return -1;

    uint8_t *plaintext = (uint8_t *)malloc(total_size);
    if (!plaintext)
        return -1;
    memcpy(plaintext, &response, sizeof(response));
    if (secure_random_bytes(plaintext + sizeof(response), padding_size) != 0) {
        free(plaintext);
        return -1;
    }

    uint8_t nonce[12];
    if (secure_random_bytes(nonce, sizeof(nonce)) != 0) {
        free(plaintext);
        return -1;
    }
    uint8_t tag[16];
    chacha20poly1305_seal(psk, nonce, NULL, 0, plaintext, total_size, out_packet + 12, tag);
    memcpy(out_packet, nonce, 12);
    memcpy(out_packet + 12 + total_size, tag, 16);
    *out_packet_len = 12 + total_size + 16;
    free(plaintext);
    return 0;
}

int stealth_handshake_parse_response(const uint8_t *psk, const uint8_t *packet, size_t packet_len,
                                     struct stealth_handshake_response *response) {
    if (!psk || !packet || !response || packet_len < 28)
        return -1;
    const uint8_t *nonce = packet;
    const uint8_t *ciphertext = packet + 12;
    size_t ciphertext_len = packet_len - 28;
    const uint8_t *tag = packet + 12 + ciphertext_len;

    uint8_t *plaintext = (uint8_t *)malloc(ciphertext_len);
    if (!plaintext)
        return -1;
    if (chacha20poly1305_open(psk, nonce, NULL, 0, ciphertext, ciphertext_len, tag, plaintext) !=
        0) {
        free(plaintext);
        return -1;
    }
    if (ciphertext_len < sizeof(struct stealth_handshake_response)) {
        free(plaintext);
        return -1;
    }

    memcpy(response, plaintext, sizeof(struct stealth_handshake_response));
    if (ntohl(response->magic) != STEALTH_RESPONSE_MAGIC) {
        free(plaintext);
        return -1;
    }
    time_t now = time(NULL);
    time_t msg_time = (time_t)ntohl(response->timestamp);
    if (msg_time < now - 300 || msg_time > now + 300) {
        free(plaintext);
        return -1;
    }
    free(plaintext);
    return 0;
}

/* ---------------- MTU-aware embed cap ---------------- */
uint32_t kcptcp_stealth_embed_cap_from_mtu(int mtu) {
    if (mtu <= 0)
        mtu = 1350;
    size_t min_padding = 0; /* new outer padding range 0..15 */
    size_t overhead = 12 + 16 + STEALTH_HANDSHAKE_PAYLOAD_SIZE + min_padding;
    if ((size_t)mtu <= overhead)
        return 0;
    size_t cap = (size_t)mtu - overhead;
    if (cap > 4096)
        cap = 4096;
    return (uint32_t)cap;
}
