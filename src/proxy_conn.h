#ifndef __PORTFWD_PROXY_CONN_H__
#define __PORTFWD_PROXY_CONN_H__

#include "list.h"
#include <stdint.h>

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
};

#endif /* __PORTFWD_PROXY_CONN_H__ */
