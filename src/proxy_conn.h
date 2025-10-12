#ifndef __PORTFWD_PROXY_CONN_H__
#define __PORTFWD_PROXY_CONN_H__

#define EV_MAGIC_LISTENER ((uintptr_t)0xdeadbeefdeadbeef)
#define EV_MAGIC_CLIENT ((uintptr_t)0xcafebabecafebabe)
#define EV_MAGIC_SERVER ((uintptr_t)0xfeedfacefeedface)

#include "list.h"
#include "anti_replay.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include <stdatomic.h>
#include "common.h"


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
    atomic_uint ref_count;   /* Atomic reference counter */
    enum proxy_state state;
    struct list_head list;   /* For linking into different lists */
    struct proxy_conn *next; /* For freelist in conn_pool */

    /* TCP specific fields */
    int cli_sock;
    int svr_sock;
    union sockaddr_inx svr_addr;
    struct buffer_info request;  /* client -> server */
    struct buffer_info response; /* server -> client */

    uintptr_t magic_client;
    uintptr_t magic_server;

    bool use_splice;
    /* Per-direction splice pipes and pending lengths */
    int c2s_pipe[2]; /* [0]=read end, [1]=write end */
    int s2c_pipe[2];
    size_t c2s_pending;
    size_t s2c_pending;
    bool cli_in_eof;
    bool svr_in_eof;
    bool cli2svr_shutdown;
    bool svr2cli_shutdown;

    /* UDP specific fields */
    union sockaddr_inx cli_addr;
    int svr_fd;
    time_t last_active;
    time_t last_addr_warn; /* Last time we warned about unexpected UDP source */
    struct list_head lru;  /* LRU linkage: oldest at head, newest at tail */
    
    /* Statistics (always enabled for diagnostics) */
    unsigned long client_packets;  /* Packets received from client */
    unsigned long server_packets;  /* Packets received from server */

    /* KCP tunneling fields (used by kcptcp-* binaries) */
    struct IKCPCB *kcp; /* KCP control block */
    uint32_t conv;
    uint32_t next_conv;
    struct anti_replay_detector replay_detector;
    int udp_sock;                   /* UDP socket for KCP transport (per-conn or shared) */
    union sockaddr_inx peer_addr;   /* Remote UDP peer */
    bool use_kcp;                   /* Marks connection as using KCP path */
    bool kcp_tx_pending;            /* Pending KCP flush due to EAGAIN/backpressure */
    struct buffer_info udp_backlog; /* Pending UDP datagram to retry sendto() */
    /* Configured PSK (for outer obfuscation) */
    bool cfg_has_psk;
    uint8_t cfg_psk[32];
    /* Handshake */
    unsigned char hs_token[16]; /* 128-bit token echoed by server in ACCEPT */
    bool kcp_ready;             /* becomes true after ACCEPT and ikcp_create */
    /* Delayed handshake scheduling (client) */
    bool hs_scheduled;
    uint32_t hs_send_at_ms;
    /* Delayed handshake response (server) */
    uint32_t hs_deadline_ms;    /* client: handshake must complete by this time */

    bool hs_resp_pending;
    uint32_t hs_resp_send_at_ms;
    size_t hs_resp_len;
    unsigned char hs_resp_buf[1536];
    uint32_t hs_agg_max_bytes_eff; /* effective per-connection embed cap */

    /* Epoll tagging (client side): distinguish TCP vs UDP events */
    struct ep_tag *cli_tag; /* tag for client TCP fd */
    struct ep_tag *udp_tag; /* tag for per-conn UDP fd */

    /* Keepalive scheduling */
    uint32_t next_ka_ms; /* next time to send heartbeat over KCP */

    /* AEAD session key (Phase 2): derived from PSK + token + conv */
    bool has_session_key;
    uint8_t session_key[32];
    uint8_t nonce_base[12]; /* 12-byte base; per-direction seq fills low 4 bytes */
    uint32_t send_seq;      /* increment per outbound KCP packet carrying DATA/FIN */
    uint32_t recv_seq;      /* legacy counter; not used for anti-replay window */
    /* Anti-replay sliding window (Phase 3):
     *  - recv_win tracks the highest validated sequence number received so far
     *  - recv_win_mask is a 64-bit bitmap of recently seen sequences in the
     * range [recv_win-63, recv_win]
     */
    uint32_t recv_win;      /* highest accepted seq */
    uint64_t recv_win_mask; /* bit i set means (recv_win - i) was seen */

    /* Rekeying state (Phase 3.5): key epochs and next-key staging */
    uint32_t epoch;               /* current key epoch; starts at 0 when session key derived */
    bool rekey_in_progress;       /* set after sending/receiving REKEY_INIT until
                                     switch */
    uint8_t next_session_key[32]; /* derived via derive_session_key_epoch(psk,
                                     token, conv, epoch+1) */
    uint8_t next_nonce_base[12];  /* base for next epoch; usually first 12 bytes
                                     of next_session_key */
    uint32_t next_epoch;          /* typically epoch+1 */
    uint64_t rekey_deadline_ms;   /* absolute deadline (kcp_now_ms) to
                                     receive/switch, else close */

    /* Runtime statistics (Phase 4): throughput, RTT snapshots, counters */
    uint64_t tcp_rx_bytes;     /* bytes read from TCP (ingress from client or to
                                  server) */
    uint64_t tcp_tx_bytes;     /* bytes written to TCP (egress to client or to server) */
    uint64_t udp_rx_bytes;     /* bytes received from UDP peer */
    uint64_t udp_tx_bytes;     /* bytes sent over UDP to peer */
    uint64_t kcp_tx_msgs;      /* number of ikcp_send() messages we attempted */
    uint64_t kcp_rx_msgs;      /* number of messages drained via ikcp_recv() */
    uint64_t kcp_tx_bytes;     /* application payload bytes passed into KCP */
    uint64_t kcp_rx_bytes;     /* application payload bytes received from KCP */
    uint32_t rekeys_initiated; /* count of REKEY_INIT we triggered */
    uint32_t rekeys_completed; /* count of successful epoch switches */
    uint64_t last_stat_ms;     /* last time we printed stats */
    /* Last-snapshot deltas for periodic logging */
    uint64_t last_tcp_rx_bytes;
    uint64_t last_tcp_tx_bytes;
    uint64_t last_kcp_tx_bytes;
    uint64_t last_kcp_rx_bytes;
    uint32_t last_kcp_xmit; /* snapshot of kcp->xmit for retrans/xmit deltas */
    uint32_t last_rekeys_initiated;
    uint32_t last_rekeys_completed;
};

/* Epoll event tag to disambiguate fd source */
struct ep_tag {
    struct proxy_conn *conn;
    int which; /* 1 = TCP client socket, 2 = UDP socket, 3 = TCP server socket
                  (if needed) */
};

#endif /* __PORTFWD_PROXY_CONN_H__ */
