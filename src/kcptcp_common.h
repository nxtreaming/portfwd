#ifndef PORTFWD_KCPTCP_COMMON_H
#define PORTFWD_KCPTCP_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include "proxy_conn.h"
#include "common.h"
#include "kcp_common.h"

/* Minimal control markers over KCP (no inner AEAD) */
#define FIN_MARKER ((unsigned char)0xF1)

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------- Stealth Handshake Protocol ---------------- */
/*
 * Stealth handshake protocol inspired by Shadowsocks:
 * - No obvious handshake phase
 * - First packet looks like encrypted data
 * - Server attempts to decrypt and identify new connections
 * - Handshake info embedded in first data packet
 */

/* Stealth handshake payload (encrypted within first packet) */
struct stealth_handshake_payload {
    uint32_t magic;      /* Magic number for validation */
    uint32_t timestamp;  /* Unix timestamp (network byte order) */
    uint8_t token[16];   /* Random token for session identification */
    uint32_t nonce;      /* Additional random nonce */
    uint8_t reserved[8]; /* Reserved for future use, filled with random data */
} __attribute__((packed));

/* Stealth handshake response (encrypted) */
struct stealth_handshake_response {
    uint32_t magic;      /* Magic number echo */
    uint32_t conv;       /* Conversation ID (network byte order) */
    uint8_t token[16];   /* Echo of client token */
    uint32_t timestamp;  /* Server timestamp */
    uint8_t reserved[8]; /* Reserved, filled with random data */
} __attribute__((packed));

/* Magic numbers for stealth handshake */
#define STEALTH_HANDSHAKE_MAGIC 0x12345678
#define STEALTH_RESPONSE_MAGIC 0x87654321

/* Buffer sizes */
#define STEALTH_HANDSHAKE_PAYLOAD_SIZE sizeof(struct stealth_handshake_payload)
#define STEALTH_HANDSHAKE_RESPONSE_SIZE sizeof(struct stealth_handshake_response)

/* Minimum size for stealth handshake packet (payload + some padding) */
#define STEALTH_HANDSHAKE_MIN_SIZE (STEALTH_HANDSHAKE_PAYLOAD_SIZE + 16)

/* Stealth handshake helper functions */
int stealth_handshake_create_first_packet(const uint8_t *psk, const uint8_t *token,
                                          const uint8_t *initial_data, size_t initial_data_len,
                                          uint8_t *out_packet, size_t *out_packet_len);

int stealth_handshake_parse_first_packet(const uint8_t *psk, const uint8_t *packet,
                                         size_t packet_len,
                                         struct stealth_handshake_payload *payload,
                                         uint8_t *out_data, size_t *out_data_len);

int stealth_handshake_create_response(const uint8_t *psk, uint32_t conv, const uint8_t *token,
                                      uint8_t *out_packet, size_t *out_packet_len);

int stealth_handshake_parse_response(const uint8_t *psk, const uint8_t *packet, size_t packet_len,
                                     struct stealth_handshake_response *response);


/* Session key derivation from PSK + token + conv */
int derive_session_key_from_psk(const uint8_t *psk, const uint8_t token[16], uint32_t conv,
                                uint8_t out_key[32]);

/* Env-controlled stats helpers */
uint32_t get_stats_interval_ms(void);
bool get_stats_dump_enabled(void);
bool get_stats_enabled(void);
/* Per-connection periodic stats logging using last_* snapshots inside
 * proxy_conn. */
void kcptcp_maybe_log_stats(struct proxy_conn *c, uint64_t now_ms);
/* One-shot dump of totals for a connection when closing */
void kcptcp_log_total_stats(struct proxy_conn *c);
/* Env toggle: deterministic conv derivation (default: enabled). */
bool kcptcp_deterministic_conv_enabled(void);

/* Socket buffer sizing (no-op if bytes <= 0) */
void set_sock_buffers_sz(int sockfd, int bytes);

/* PSK parsing */
bool parse_psk_hex32(const char *hex, uint8_t out[32]);

/* Shared buffer growth helper (returns 0 on success, -1 on error/limit) */
int ensure_buffer_capacity(struct buffer_info *buf, size_t needed, size_t max_size);

/* Compute safe embed cap for stealth first-packet based on MTU */
uint32_t kcptcp_stealth_embed_cap_from_mtu(int mtu);

/* AEAD sequence window helpers (shared by client/server) */
bool aead_replay_check_and_update(uint32_t seq, uint32_t *p_win, uint64_t *p_mask);
bool aead_next_send_seq(struct proxy_conn *c, uint32_t *out_seq);

/* Socket setup helpers */
int kcptcp_setup_tcp_listener(const union sockaddr_inx *addr, bool reuse_addr, bool reuse_port,
                              bool v6only, int sockbuf_bytes, int backlog);

int kcptcp_setup_udp_listener(const union sockaddr_inx *addr, bool reuse_addr, bool reuse_port,
                              bool v6only, int sockbuf_bytes);

/* Create non-bound UDP socket (non-blocking, buffer size applied) */
int kcptcp_create_udp_socket(int family, int sockbuf_bytes);

/* Create non-blocking TCP socket (unconnected), apply buffers and optional
 * TCP_NODELAY */
int kcptcp_create_tcp_socket(int family, int sockbuf_bytes, bool tcp_nodelay);

/* Tune an existing TCP socket: non-blocking, buffers, TCP_NODELAY, KEEPALIVE */
void kcptcp_tune_tcp_socket(int fd, int sockbuf_bytes, bool tcp_nodelay, bool keepalive);

/* Apply optional overrides to kcp_opts if values are >= 0; mtu > 0 */
void kcp_opts_apply_overrides(struct kcp_opts *o, int mtu, int nd, int it, int rs, int nc, int snd,
                              int rcv);

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
    int sockbuf_bytes;
    bool tcp_nodelay;
    bool has_psk;
    uint8_t psk[32];
    /* Stealth handshake tuning */
    uint32_t hs_agg_min_ms;        /* client: min wait to aggregate first TCP */
    uint32_t hs_agg_max_ms;        /* client: max wait to aggregate first TCP */
    uint32_t hs_agg_max_bytes;     /* client: max bytes to embed into first packet */
    uint32_t hs_rsp_jitter_min_ms; /* server: min jitter before response */
    uint32_t hs_rsp_jitter_max_ms; /* server: max jitter before response */
    /* Profile selector (client): "off", "auto", or "csv:22,2222" */
    const char *hs_profile;
    /* KCP overrides (use -1 if not set; mtu>0) */
    int kcp_mtu;
    int kcp_nd, kcp_it, kcp_rs, kcp_nc, kcp_snd, kcp_rcv;
    /* flow */
    bool show_help;
};

/* Parse shared options. Returns 1 on success, 0 on parse error. Sets optind via
   getopt. pos_start (optional) receives first non-option argv index. is_server
   reserved for future divergence. */
int kcptcp_parse_common_opts(int argc, char **argv, struct kcptcp_common_cli *out, int *pos_start,
                             bool is_server);

/* Secure-random helper: return integer in [min, max]. If max<=min, returns min.
 */
uint32_t rand_between(uint32_t min, uint32_t max);

/* ---------------- Epoll helpers (shared) ---------------- */
/* Generic register or modify */
int kcptcp_ep_register(int epfd, int fd, void *ptr, uint32_t base_events, uint32_t extra_events);
/* Listener: EPOLLIN|EPOLLERR|EPOLLHUP */
static inline int kcptcp_ep_register_listener(int epfd, int fd, void *tag) {
    return kcptcp_ep_register(epfd, fd, tag, EPOLLIN | EPOLLERR | EPOLLHUP, 0);
}
/* RW for connections, toggling EPOLLOUT */
static inline int kcptcp_ep_register_rw(int epfd, int fd, void *ptr, bool want_write) {
    uint32_t extra = want_write ? EPOLLOUT : 0;
    return kcptcp_ep_register(epfd, fd, ptr, EPOLLIN | EPOLLERR | EPOLLHUP, extra);
}

/* TCP connection: include EPOLLRDHUP and optional EPOLLOUT */
static inline int kcptcp_ep_register_tcp(int epfd, int fd, void *ptr, bool want_write) {
    uint32_t extra = want_write ? EPOLLOUT : 0;
    return kcptcp_ep_register(epfd, fd, ptr, EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP, extra);
}

#ifdef __cplusplus
}
#endif

#endif /* PORTFWD_KCPTCP_COMMON_H */
