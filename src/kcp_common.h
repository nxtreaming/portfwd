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

#ifdef __cplusplus
}
#endif

#endif /* PORTFWD_KCP_COMMON_H */
