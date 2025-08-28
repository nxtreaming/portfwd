#ifndef PORTFWD_KCP_COMMON_H
#define PORTFWD_KCP_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "proxy_conn.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declare without including ikcp.h to avoid vendor dependency at this stage */
struct IKCPCB;

struct kcp_opts {
    int nodelay;      /* 0/1 */
    int interval_ms;  /* 10..100 */
    int resend;       /* fast resend count */
    int nc;           /* 0/1: disable cc */
    int mtu;          /* e.g., 1400 */
    int sndwnd;       /* packets */
    int rcvwnd;       /* packets */
};

/* Reasonable defaults matching our discussion */
static inline void kcp_opts_set_defaults(struct kcp_opts *o) {
    o->nodelay = 1;
    o->interval_ms = 10;
    o->resend = 2;
    o->nc = 1;
    o->mtu = 1350; /* Safer default to avoid IP fragmentation on common paths */
    o->sndwnd = 1024;
    o->rcvwnd = 1024;
}

/* Monotonic-ish milliseconds for driving KCP timers */
uint32_t kcp_now_ms(void);

/* Setup KCP on a proxy_conn (stub until ikcp is linked) */
int kcp_setup_conn(struct proxy_conn *c, int udp_fd, const union sockaddr_inx *peer,
                   uint32_t conv, const struct kcp_opts *opts);

/* Drive timer update/flush (stub until ikcp is linked) */
int kcp_update_flush(struct proxy_conn *c, uint32_t now_ms);

/* KCP tunneled packet types (1-byte header before payload) */
enum kcp_tun_type {
    KTP_DATA = 0x00,
    KTP_FIN  = 0x01,
    KTP_KA   = 0x02,
    /* Encrypted variants (ChaCha20-Poly1305) */
    KTP_EDATA = 0x20, /* [type][seq(4)][ciphertext][tag(16)] */
    KTP_EFIN  = 0x21, /* [type][seq(4)][tag(16)] */
    /* Rekey control (sent inside KCP stream, AEAD-authenticated) */
    KTP_REKEY_INIT = 0x22, /* [type][seq(4)][tag(16)] sealed with CURRENT key */
    KTP_REKEY_ACK  = 0x23, /* [type][seq(4)==0][tag(16)] sealed with NEXT key */
    /* Handshake control (outer, non-KCP) */
    KTP_HS_HELLO  = 0x10,
    KTP_HS_ACCEPT = 0x11,
    KTP_HS_REJECT = 0x12,
    KTP_HS_RESUME = 0x13
};

/* Rekey policy defaults */
#define REKEY_SEQ_THRESHOLD 0xFFF00000u /* start rekey before wraparound */
#define REKEY_TIMEOUT_MS    5000u       /* wait for ACK before fail-closed */

#define KCP_HS_VER 0x01

#ifdef __cplusplus
}
#endif

#endif /* PORTFWD_KCP_COMMON_H */
