#include "kcptcp_common.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <netinet/tcp.h>
#endif
#include "common.h"
#include "3rd/kcp/ikcp.h"

/* Env-controlled stats helpers */
uint32_t get_stats_interval_ms(void) {
    static uint32_t cached = 0; /* 0 => uninitialized */
    if (cached == 0) {
        const char *s = getenv("PFWD_STATS_INTERVAL_MS");
        long v = s ? strtol(s, NULL, 10) : 0;
        if (v <= 0) v = 5000; /* default 5s */
        if (v < 100) v = 100; /* clamp */
        if (v > 600000) v = 600000; /* 10 minutes */
        cached = (uint32_t)v;
    }
    return cached;
}

void kcptcp_tune_tcp_socket(int fd, int sockbuf_bytes, bool tcp_nodelay,
                            bool keepalive) {
    if (fd < 0) return;
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

void kcp_opts_apply_overrides(struct kcp_opts *o, int mtu, int nd, int it,
                              int rs, int nc, int snd, int rcv) {
    if (mtu > 0) o->mtu = mtu;
    if (nd >= 0) o->nodelay = nd;
    if (it >= 0) o->interval_ms = it;
    if (rs >= 0) o->resend = rs;
    if (nc >= 0) o->nc = nc;
    if (snd >= 0) o->sndwnd = snd;
    if (rcv >= 0) o->rcvwnd = rcv;
}

int kcptcp_compute_kcp_timeout_ms(struct list_head *conns, int default_ms) {
    int timeout_ms = default_ms;
    uint32_t now = kcp_now_ms();
    struct proxy_conn *pc;
    list_for_each_entry(pc, conns, list) {
        if (!pc->kcp) continue;
        uint32_t due = ikcp_check(pc->kcp, now);
        int t = (int)((due > now) ? (due - now) : 0);
        if (t < timeout_ms) timeout_ms = t;
    }
    return timeout_ms;
}

int kcptcp_ep_register(int epfd, int fd, void *ptr,
                       uint32_t base_events, uint32_t extra_events) {
    struct epoll_event ev = {0};
    ev.events = base_events | extra_events;
    ev.data.ptr = ptr;
    return ep_add_or_mod(epfd, fd, &ev);
}

bool get_stats_dump_enabled(void) {
    const char *s = getenv("PFWD_STATS_DUMP");
    if (!s) return false;
    return !(s[0] == '0');
}

bool get_stats_enabled(void) {
    const char *s = getenv("PFWD_STATS_ENABLE");
    if (!s) return true; /* default enabled */
    return !(s[0] == '0');
}

void set_sock_buffers_sz(int sockfd, int bytes) {
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

bool parse_psk_hex32(const char *hex, uint8_t out[32]) {
    size_t n = strlen(hex);
    if (n != 64) return false;
    for (size_t i = 0; i < 32; ++i) {
        int hi = hex2nibble(hex[2 * i]);
        int lo = hex2nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/* Anti-replay helpers (sliding window, 64 entries) */
static inline int32_t seq_diff_u32(uint32_t a, uint32_t b) {
    return (int32_t)(a - b);
}

bool aead_replay_check_and_update(uint32_t seq, uint32_t *p_win,
                                  uint64_t *p_mask) {
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
    if (behind >= 64) return false;
    uint64_t bit = 1ULL << behind;
    if (mask & bit) return false; /* replay */
    mask |= bit;
    *p_win = win;
    *p_mask = mask;
    return true;
}

bool aead_next_send_seq(struct proxy_conn *c, uint32_t *out_seq) {
    if (c->send_seq == UINT32_MAX) return false;
    *out_seq = c->send_seq++;
    return true;
}

/* Socket setup helpers */
int kcptcp_setup_tcp_listener(const union sockaddr_inx *addr,
                              bool reuse_addr,
                              bool reuse_port,
                              bool v6only,
                              int sockbuf_bytes,
                              int backlog) {
    int fd = -1;
    fd = socket(addr->sa.sa_family, SOCK_STREAM, 0);
    if (fd < 0) {
        P_LOG_ERR("socket(listen): %s", strerror(errno));
        return -1;
    }
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
    if (bind(fd, &((const union sockaddr_inx *)addr)->sa,
             (socklen_t)sizeof_sockaddr(addr)) < 0) {
        P_LOG_ERR("bind(listen): %s", strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, backlog) < 0) {
        P_LOG_ERR("listen: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int kcptcp_setup_udp_listener(const union sockaddr_inx *addr,
                              bool reuse_addr,
                              bool reuse_port,
                              bool v6only,
                              int sockbuf_bytes) {
    int fd = -1;
    fd = socket(addr->sa.sa_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        P_LOG_ERR("socket(udp): %s", strerror(errno));
        return -1;
    }
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
    if (bind(fd, &((const union sockaddr_inx *)addr)->sa,
             (socklen_t)sizeof_sockaddr(addr)) < 0) {
        P_LOG_ERR("bind(udp): %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int kcptcp_create_udp_socket(int family, int sockbuf_bytes) {
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) {
        P_LOG_ERR("socket(udp): %s", strerror(errno));
        return -1;
    }
    set_nonblock(fd);
    set_sock_buffers_sz(fd, sockbuf_bytes);
    return fd;
}

int kcptcp_create_tcp_socket(int family, int sockbuf_bytes, bool tcp_nodelay) {
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) {
        P_LOG_ERR("socket(tcp): %s", strerror(errno));
        return -1;
    }
    set_nonblock(fd);
    set_sock_buffers_sz(fd, sockbuf_bytes);
#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    if (tcp_nodelay) {
        int one = 1;
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
#else
    (void)tcp_nodelay;
#endif
    return fd;
}
