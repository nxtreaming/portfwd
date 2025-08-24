#ifndef __PORTFWD_PROXY_CONN_H__
#define __PORTFWD_PROXY_CONN_H__

#include "list.h"

/* Common structure for a proxy connection */

enum proxy_state {
    S_INITIAL = 0,
    S_CONNECTING, /* TCP only */
    S_FORWARDING,
    S_CLOSING,
};

struct proxy_conn {
    /* For TCP */
    int cli_sock;
    int svr_sock;
    int pipe_fds[2];
    bool use_splice;
    bool cli_in_eof;
    bool svr_in_eof;
    bool cli2svr_shutdown;
    bool svr2cli_shutdown;

    /* For UDP */
    union sockaddr_inx cli_addr;
    int svr_fd;
    time_t last_active;
    struct proxy_conn *next_in_pool;

    /* Common fields */
    enum proxy_state state;
    struct list_head list; /* For linking into different lists */
};

#endif /* __PORTFWD_PROXY_CONN_H__ */
