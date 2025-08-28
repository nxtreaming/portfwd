#include "kcp_common.h"
#include "common.h"
#include "3rd/kcp/ikcp.h"
#include <time.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#if defined(_WIN32)
#include <windows.h>
#endif

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif

/* Output callback: sendto over UDP with simple backlog handling on EAGAIN */
static int kcp_output_cb(const char *buf, int len, struct IKCPCB *kcp, void *user) {
    (void)kcp;
    struct proxy_conn *pc = (struct proxy_conn*)user;
    if (!pc) return -1;
    /* Try to send current datagram */
    ssize_t n = sendto(pc->udp_sock, buf, (size_t)len, MSG_DONTWAIT,
                       &pc->peer_addr.sa, (socklen_t)sizeof_sockaddr(&pc->peer_addr));
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Kernel TX queue full: store one-packet backlog and retry on next update */
            if (pc->udp_backlog.dlen == 0) {
                size_t need = (size_t)len;
                size_t cap = pc->udp_backlog.capacity;
                if (cap < need) {
                    size_t ncap = cap ? (cap * 2) : (size_t)2048;
                    if (ncap < need) ncap = need;
                    char *np = (char*)realloc(pc->udp_backlog.data, ncap);
                    if (!np) {
                        return 0; /* drop; KCP will retransmit later */
                    }
                    pc->udp_backlog.data = np;
                    pc->udp_backlog.capacity = ncap;
                }
                memcpy(pc->udp_backlog.data, buf, need);
                pc->udp_backlog.dlen = need;
                pc->udp_backlog.rpos = 0;
                pc->kcp_tx_pending = true;
            }
            return 0; /* report success to KCP; we'll flush shortly */
        }
        return -1;
    }
    if (n > 0) {
        pc->udp_tx_bytes += (uint64_t)n;
    }
    return (int)n;
}

uint32_t kcp_now_ms(void) {
#if defined(_WIN32)
# if defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0600)
    /* Windows Vista+ */
    return (uint32_t)GetTickCount64();
# else
    /* Older Windows: 32-bit tick (wraps ~49 days) */
    return (uint32_t)GetTickCount();
# endif
#else
# ifdef CLOCK_MONOTONIC
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
    }
# endif
    return (uint32_t)(time(NULL) * 1000u);
#endif
}

int kcp_setup_conn(struct proxy_conn *c, int udp_fd, const union sockaddr_inx *peer,
                   uint32_t conv, const struct kcp_opts *opts) {
    if (!c || !peer || !opts) return -1;
    c->udp_sock = udp_fd;
    c->peer_addr = *peer;
    c->conv = conv;
    c->use_kcp = true;
    c->kcp_tx_pending = false;

    /* Create KCP control block */
    c->kcp = ikcp_create(conv, c);
    if (!c->kcp) {
        P_LOG_ERR("ikcp_create failed");
        return -1;
    }

    /* Use official API to set output callback */
    ikcp_setoutput(c->kcp, kcp_output_cb);

    /* Apply options */
    ikcp_nodelay(c->kcp, opts->nodelay, opts->interval_ms, opts->resend, opts->nc);
    ikcp_setmtu(c->kcp, opts->mtu);
    ikcp_wndsize(c->kcp, opts->sndwnd, opts->rcvwnd);

    return 0;
}

int kcp_update_flush(struct proxy_conn *c, uint32_t now_ms) {
    if (!c || !c->kcp) return -1;
    /* If we have a pending UDP datagram due to previous EAGAIN, try to flush it first */
    if (c->udp_backlog.dlen > 0) {
        ssize_t n = sendto(c->udp_sock,
                           c->udp_backlog.data + c->udp_backlog.rpos,
                           c->udp_backlog.dlen - c->udp_backlog.rpos,
                           MSG_DONTWAIT,
                           &c->peer_addr.sa,
                           (socklen_t)sizeof_sockaddr(&c->peer_addr));
        if (n > 0) {
            c->udp_backlog.rpos += (size_t)n;
            c->udp_tx_bytes += (uint64_t)n;
            if (c->udp_backlog.rpos >= c->udp_backlog.dlen) {
                c->udp_backlog.rpos = 0;
                c->udp_backlog.dlen = 0;
                c->kcp_tx_pending = false;
            }
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            /* Hard error: drop this backlog packet */
            c->udp_backlog.rpos = 0;
            c->udp_backlog.dlen = 0;
            c->kcp_tx_pending = false;
        }
    }
    ikcp_update(c->kcp, now_ms);
    return 0;
}
