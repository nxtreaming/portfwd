#ifndef __PORTFWD_PROXY_CONN_H__
#define __PORTFWD_PROXY_CONN_H__

#include "list.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include "common.h" /* for union sockaddr_inx */

/* Forward declaration to avoid forcing ikcp.h inclusion here */
struct IKCPCB;

/* Shared buffer structure */
struct buffer_info {
    char *data;
    size_t dlen; /* Data length */
    size_t rpos; /* Read position */
    size_t capacity;
};

enum proxy_state {
    S_INITIAL = 0,
    S_CONNECTING,
    S_SERVER_CONNECTING,
    S_FORWARDING,
    S_CLOSING,
};

struct proxy_conn {
    /* Common fields */
    enum proxy_state state;
    struct list_head list; /* For linking into different lists */
    struct proxy_conn *next; /* For freelist in conn_pool */

    /* TCP specific fields */
    int cli_sock;
    int svr_sock;
    union sockaddr_inx svr_addr;
    struct buffer_info request;  /* client -> server */
    struct buffer_info response; /* server -> client */

    uint32_t magic_client;
    uint32_t magic_server;

    bool use_splice;
    size_t splice_pending;
    int splice_pipe[2];
    bool cli_in_eof;
    bool svr_in_eof;
    bool cli2svr_shutdown;
    bool svr2cli_shutdown;

    /* UDP specific fields */
    union sockaddr_inx cli_addr;
    int svr_fd;
    time_t last_active;
    struct list_head lru;          /* LRU linkage: oldest at head, newest at tail */

    /* KCP tunneling fields (used by kcptcp-* binaries) */
    struct IKCPCB *kcp;            /* KCP control block */
    uint32_t conv;                 /* KCP conversation ID */
    int udp_sock;                  /* UDP socket for KCP transport (per-conn or shared) */
    union sockaddr_inx peer_addr;  /* Remote UDP peer */
    bool use_kcp;                  /* Marks connection as using KCP path */
    bool kcp_tx_pending;           /* Pending KCP flush due to EAGAIN/backpressure */
    struct buffer_info udp_backlog;/* Pending UDP datagram to retry sendto() */
    /* Handshake */
    unsigned char hs_token[16];    /* 128-bit token echoed by server in ACCEPT */
    bool kcp_ready;                /* becomes true after ACCEPT and ikcp_create */

    /* Epoll tagging (client side): distinguish TCP vs UDP events */
    struct ep_tag *cli_tag;        /* tag for client TCP fd */
    struct ep_tag *udp_tag;        /* tag for per-conn UDP fd */

    /* Keepalive scheduling */
    uint32_t next_ka_ms;           /* next time to send heartbeat over KCP */

    /* AEAD session key (Phase 2): derived from PSK + token + conv */
    bool has_session_key;
    uint8_t session_key[32];
    uint8_t nonce_base[12];   /* 12-byte base; per-direction seq fills low 4 bytes */
    uint32_t send_seq;        /* increment per outbound KCP packet carrying DATA/FIN */
    uint32_t recv_seq;        /* legacy counter; not used for anti-replay window */
    /* Anti-replay sliding window (Phase 3):
     *  - recv_win tracks the highest validated sequence number received so far
     *  - recv_win_mask is a 64-bit bitmap of recently seen sequences in the range [recv_win-63, recv_win]
     */
    uint32_t recv_win;        /* highest accepted seq */
    uint64_t recv_win_mask;   /* bit i set means (recv_win - i) was seen */
};

/* Epoll event tag to disambiguate fd source */
struct ep_tag {
    struct proxy_conn *conn;
    int which; /* 1 = TCP client socket, 2 = UDP socket, 3 = TCP server socket (if needed) */
};

#endif /* __PORTFWD_PROXY_CONN_H__ */
