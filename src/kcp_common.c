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

/* Output callback: sendto over UDP */
static int kcp_output_cb(const char *buf, int len, struct IKCPCB *kcp, void *user) {
    (void)kcp;
    struct proxy_conn *pc = (struct proxy_conn*)user;
    if (!pc) return -1;
    ssize_t n = sendto(pc->udp_sock, buf, (size_t)len, MSG_DONTWAIT,
                       &pc->peer_addr.sa, (socklen_t)sizeof_sockaddr(&pc->peer_addr));
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; /* will flush later */
        return -1;
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
    ikcp_update(c->kcp, now_ms);
    return 0;
}
