#ifndef PORTFWD_KCPTCP_COMMON_H
#define PORTFWD_KCPTCP_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include "proxy_conn.h"
#include "common.h"
#include "kcp_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Env-controlled stats helpers */
uint32_t get_stats_interval_ms(void);
bool get_stats_dump_enabled(void);
bool get_stats_enabled(void);

/* Socket buffer sizing (no-op if bytes <= 0) */
void set_sock_buffers_sz(int sockfd, int bytes);

/* PSK parsing */
bool parse_psk_hex32(const char *hex, uint8_t out[32]);

/* AEAD sequence window helpers (shared by client/server) */
bool aead_replay_check_and_update(uint32_t seq, uint32_t *p_win,
                                  uint64_t *p_mask);
bool aead_next_send_seq(struct proxy_conn *c, uint32_t *out_seq);

/* Socket setup helpers */
int kcptcp_setup_tcp_listener(const union sockaddr_inx *addr,
                              bool reuse_addr,
                              bool reuse_port,
                              bool v6only,
                              int sockbuf_bytes,
                              int backlog);

int kcptcp_setup_udp_listener(const union sockaddr_inx *addr,
                              bool reuse_addr,
                              bool reuse_port,
                              bool v6only,
                              int sockbuf_bytes);

/* Create non-bound UDP socket (non-blocking, buffer size applied) */
int kcptcp_create_udp_socket(int family, int sockbuf_bytes);

/* Create non-blocking TCP socket (unconnected), apply buffers and optional TCP_NODELAY */
int kcptcp_create_tcp_socket(int family, int sockbuf_bytes, bool tcp_nodelay);

/* Tune an existing TCP socket: non-blocking, buffers, TCP_NODELAY, KEEPALIVE */
void kcptcp_tune_tcp_socket(int fd, int sockbuf_bytes, bool tcp_nodelay,
                            bool keepalive);

/* Apply optional overrides to kcp_opts if values are >= 0; mtu > 0 */
void kcp_opts_apply_overrides(struct kcp_opts *o, int mtu, int nd, int it,
                              int rs, int nc, int snd, int rcv);

/* Compute epoll timeout from KCP timers across connections */
int kcptcp_compute_kcp_timeout_ms(struct list_head *conns, int default_ms);

/* ---------------- Common CLI parsing (shared) ---------------- */
struct kcptcp_common_cli {
    /* generic */
    const char *pidfile;
    bool daemonize;
    bool reuse_addr;
    bool reuse_port;
    bool v6only;
    int  sockbuf_bytes;
    bool tcp_nodelay;
    bool has_psk;
    uint8_t psk[32];
    /* KCP overrides (use -1 if not set; mtu>0) */
    int kcp_mtu;
    int kcp_nd, kcp_it, kcp_rs, kcp_nc, kcp_snd, kcp_rcv;
    /* flow */
    bool show_help;
};

/* Parse shared options. Returns 1 on success, 0 on parse error. Sets optind via getopt.
   pos_start (optional) receives first non-option argv index.
   is_server reserved for future divergence. */
int kcptcp_parse_common_opts(int argc, char **argv,
                             struct kcptcp_common_cli *out,
                             int *pos_start,
                             bool is_server);

/* ---------------- Epoll helpers (shared) ---------------- */
/* Generic register or modify */
int kcptcp_ep_register(int epfd, int fd, void *ptr,
                       uint32_t base_events, uint32_t extra_events);
/* Listener: EPOLLIN|EPOLLERR|EPOLLHUP */
static inline int kcptcp_ep_register_listener(int epfd, int fd, void *tag) {
    return kcptcp_ep_register(epfd, fd, tag,
                              EPOLLIN | EPOLLERR | EPOLLHUP, 0);
}
/* RW for connections, toggling EPOLLOUT */
static inline int kcptcp_ep_register_rw(int epfd, int fd, void *ptr,
                                        bool want_write) {
    uint32_t extra = want_write ? EPOLLOUT : 0;
    return kcptcp_ep_register(epfd, fd, ptr,
                              EPOLLIN | EPOLLERR | EPOLLHUP, extra);
}

/* TCP connection: include EPOLLRDHUP and optional EPOLLOUT */
static inline int kcptcp_ep_register_tcp(int epfd, int fd, void *ptr,
                                         bool want_write) {
    uint32_t extra = want_write ? EPOLLOUT : 0;
    return kcptcp_ep_register(epfd, fd, ptr,
                              EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP,
                              extra);
}

#ifdef __cplusplus
}
#endif

#endif /* PORTFWD_KCPTCP_COMMON_H */
