#ifndef PORTFWD_KCP_MAP_H
#define PORTFWD_KCP_MAP_H

#include <stdint.h>
#include <stddef.h>
#include "proxy_conn.h"
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Minimal conv -> proxy_conn* mapping for kcptcp-server. */

struct kcp_map_entry {
    struct list_head node;
    uint32_t conv;
    struct proxy_conn *conn;
};

struct kcp_map_bucket {
    struct list_head head;
};

struct kcp_map {
    size_t nbuckets;
    struct kcp_map_bucket *buckets;
};

int kcp_map_init(struct kcp_map *m, size_t nbuckets);
void kcp_map_free(struct kcp_map *m);

struct proxy_conn *kcp_map_get(struct kcp_map *m, uint32_t conv);
int kcp_map_put(struct kcp_map *m, uint32_t conv, struct proxy_conn *c);
void kcp_map_del(struct kcp_map *m, uint32_t conv);

#ifdef __cplusplus
}
#endif

#endif /* PORTFWD_KCP_MAP_H */
