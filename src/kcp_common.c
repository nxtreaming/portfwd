#include "kcp_common.h"
#include "common.h"
#include <time.h>
#include <string.h>

uint32_t kcp_now_ms(void) {
#if defined(_WIN32)
    /* Fallback: use CLOCK_MONOTONIC-like via GetTickCount if desired; for now use time() */
    return (uint32_t)(time(NULL) * 1000u);
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
    /* IKCPCB not created yet (vendor not linked). Leave c->kcp = NULL for now. */
    (void)opts; /* will be applied when ikcp is wired */
    return 0;
}

int kcp_update_flush(struct proxy_conn *c, uint32_t now_ms) {
    (void)now_ms;
    if (!c) return -1;
    /* Stub: when ikcp is linked, call ikcp_update(c->kcp, now_ms) */
    return 0;
}
