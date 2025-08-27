#include "kcp_map.h"
#include <stdlib.h>
#include <string.h>

static inline size_t kcp_hash(uint32_t conv, size_t nbuckets) {
    /* simple 32-bit mix then mask */
    conv ^= conv >> 16;
    conv *= 0x7feb352dU;
    conv ^= conv >> 15;
    conv *= 0x846ca68bU;
    conv ^= conv >> 16;
    return (size_t)(conv % (nbuckets ? nbuckets : 1));
}

int kcp_map_init(struct kcp_map *m, size_t nbuckets) {
    if (!m || nbuckets == 0) return -1;
    m->nbuckets = nbuckets;
    m->buckets = (struct kcp_map_bucket*)calloc(nbuckets, sizeof(*m->buckets));
    if (!m->buckets) return -1;
    for (size_t i = 0; i < nbuckets; ++i) {
        INIT_LIST_HEAD(&m->buckets[i].head);
    }
    return 0;
}

void kcp_map_free(struct kcp_map *m) {
    if (!m || !m->buckets) return;
    for (size_t i = 0; i < m->nbuckets; ++i) {
        struct list_head *head = &m->buckets[i].head;
        while (!list_empty(head)) {
            struct kcp_map_entry *e = list_first_entry(head, struct kcp_map_entry, node);
            list_del(&e->node);
            free(e);
        }
    }
    free(m->buckets);
    m->buckets = NULL;
    m->nbuckets = 0;
}

struct proxy_conn *kcp_map_get(struct kcp_map *m, uint32_t conv) {
    if (!m || !m->buckets) return NULL;
    size_t idx = kcp_hash(conv, m->nbuckets);
    struct list_head *head = &m->buckets[idx].head;
    struct kcp_map_entry *e;
    list_for_each_entry(e, head, node) {
        if (e->conv == conv) return e->conn;
    }
    return NULL;
}

int kcp_map_put(struct kcp_map *m, uint32_t conv, struct proxy_conn *c) {
    if (!m || !m->buckets) return -1;
    size_t idx = kcp_hash(conv, m->nbuckets);
    struct list_head *head = &m->buckets[idx].head;
    struct kcp_map_entry *e;
    list_for_each_entry(e, head, node) {
        if (e->conv == conv) {
            e->conn = c;
            return 0;
        }
    }
    e = (struct kcp_map_entry*)calloc(1, sizeof(*e));
    if (!e) return -1;
    e->conv = conv;
    e->conn = c;
    list_add(&e->node, head); /* insert at head */
    return 0;
}

void kcp_map_del(struct kcp_map *m, uint32_t conv) {
    if (!m || !m->buckets) return;
    size_t idx = kcp_hash(conv, m->nbuckets);
    struct list_head *head = &m->buckets[idx].head;
    struct kcp_map_entry *e, *tmp;
    list_for_each_entry_safe(e, tmp, head, node) {
        if (e->conv == conv) {
            list_del(&e->node);
            free(e);
            return;
        }
    }
}
