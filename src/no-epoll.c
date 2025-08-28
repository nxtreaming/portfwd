#include "no-epoll.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

/* Hash table for O(1) fd -> index mapping */
#define HT_INITIAL_CAPACITY 16

struct ht_entry {
    int fd;
    size_t index;
    struct ht_entry *next;
};

struct ht {
    struct ht_entry **buckets;
    size_t capacity;
    size_t size;
};

struct pseudo_epoll_handle {
    struct pollfd *pfds;     /* dynamic array of pollfd */
    struct epoll_event *evs; /* parallel epoll_event (stores .data) */
    size_t len;              /* number of active fds */
    size_t cap;              /* capacity of arrays */
    struct ht *fd_map;       /* hash table for fd -> index in pfds */
};

static struct pseudo_epoll_handle **pseudo_epolls = NULL;
static size_t pseudo_epolls_cap = 0;

static int ht_insert(struct ht *ht, int fd, size_t index);
static int ht_remove(struct ht *ht, int fd);
static struct ht_entry *ht_find(struct ht *ht, int fd);

static void ht_destroy(struct ht *ht) {
    if (!ht)
        return;
    for (size_t i = 0; i < ht->capacity; i++) {
        struct ht_entry *entry = ht->buckets[i];
        while (entry) {
            struct ht_entry *next = entry->next;
            free(entry);
            entry = next;
        }
    }
    free(ht->buckets);
    free(ht);
}

static void cleanup_pseudo_epolls(void) {
    if (pseudo_epolls) {
        for (size_t i = 0; i < pseudo_epolls_cap; i++) {
            if (pseudo_epolls[i]) {
                free(pseudo_epolls[i]->pfds);
                free(pseudo_epolls[i]->evs);
                ht_destroy(pseudo_epolls[i]->fd_map);
                free(pseudo_epolls[i]);
            }
        }
        free(pseudo_epolls);
        pseudo_epolls = NULL;
        pseudo_epolls_cap = 0;
    }
}

int epoll_create(int size) {
    if (pseudo_epolls == NULL) {
        atexit(cleanup_pseudo_epolls);
    }
    (void)size;
    size_t i;
    /* Find a free slot */
    for (i = 0; i < pseudo_epolls_cap; i++) {
        if (pseudo_epolls[i] == NULL) {
            struct pseudo_epoll_handle *eh =
                (struct pseudo_epoll_handle *)calloc(1, sizeof(*eh));
            if (!eh) {
                errno = ENOMEM;
                return -1;
            }
            eh->cap = 16;
            eh->pfds = (struct pollfd *)calloc(eh->cap, sizeof(struct pollfd));
            eh->evs = (struct epoll_event *)calloc(eh->cap,
                                                   sizeof(struct epoll_event));
            eh->fd_map = (struct ht *)calloc(1, sizeof(struct ht));
            if (!eh->pfds || !eh->evs || !eh->fd_map) {
                free(eh->pfds);
                free(eh->evs);
                ht_destroy(eh->fd_map);
                free(eh);
                errno = ENOMEM;
                return -1;
            }
            eh->fd_map->capacity = HT_INITIAL_CAPACITY;
            eh->fd_map->buckets = (struct ht_entry **)calloc(
                eh->fd_map->capacity, sizeof(struct ht_entry *));
            if (!eh->fd_map->buckets) {
                free(eh->pfds);
                free(eh->evs);
                ht_destroy(eh->fd_map);
                free(eh);
                errno = ENOMEM;
                return -1;
            }
            pseudo_epolls[i] = eh;
            return (int)i;
        }
    }
    /* Need to grow registry */
    size_t old_cap = pseudo_epolls_cap;
    size_t new_cap = old_cap ? (old_cap + 8) : 8;
    void *np = realloc(pseudo_epolls, new_cap * sizeof(*pseudo_epolls));
    if (!np) {
        errno = ENOMEM;
        return -1;
    }
    pseudo_epolls = (struct pseudo_epoll_handle **)np;
    for (i = old_cap; i < new_cap; i++)
        pseudo_epolls[i] = NULL;
    pseudo_epolls_cap = new_cap;
    /* Allocate first new slot */
    struct pseudo_epoll_handle *eh =
        (struct pseudo_epoll_handle *)calloc(1, sizeof(*eh));
    if (!eh) {
        errno = ENOMEM;
        return -1;
    }
    eh->cap = 16;
    eh->pfds = (struct pollfd *)calloc(eh->cap, sizeof(struct pollfd));
    eh->evs = (struct epoll_event *)calloc(eh->cap, sizeof(struct epoll_event));
    eh->fd_map = (struct ht *)calloc(1, sizeof(struct ht));
    if (!eh->pfds || !eh->evs || !eh->fd_map) {
        free(eh->pfds);
        free(eh->evs);
        ht_destroy(eh->fd_map);
        free(eh);
        errno = ENOMEM;
        return -1;
    }
    eh->fd_map->capacity = HT_INITIAL_CAPACITY;
    eh->fd_map->buckets = (struct ht_entry **)calloc(eh->fd_map->capacity,
                                                     sizeof(struct ht_entry *));
    if (!eh->fd_map->buckets) {
        free(eh->pfds);
        free(eh->evs);
        ht_destroy(eh->fd_map);
        free(eh);
        errno = ENOMEM;
        return -1;
    }
    pseudo_epolls[old_cap] = eh;
    return (int)old_cap;
}

int epoll_close(int epfd) {
    if (epfd < 0 || (size_t)epfd >= pseudo_epolls_cap || !pseudo_epolls[epfd]) {
        errno = EINVAL;
        return -1;
    }

    struct pseudo_epoll_handle *eh = pseudo_epolls[epfd];
    free(eh->pfds);
    free(eh->evs);
    ht_destroy(eh->fd_map);
    free(eh);
    pseudo_epolls[epfd] = NULL;
    return 0;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    if (epfd < 0 || (size_t)epfd >= pseudo_epolls_cap || !pseudo_epolls[epfd]) {
        errno = EINVAL;
        return -1;
    }
    struct pseudo_epoll_handle *eh = pseudo_epolls[epfd];
    struct ht_entry *entry = ht_find(eh->fd_map, fd);

    switch (op) {
    case EPOLL_CTL_ADD:
    case EPOLL_CTL_MOD: {
        if (!event) {
            errno = EINVAL;
            return -1;
        }

        short pev = 0;
        if (event->events & EPOLLIN)
            pev |= POLLIN;
        if (event->events & EPOLLOUT)
            pev |= POLLOUT;

        if (op == EPOLL_CTL_ADD && entry) {
            errno = EEXIST;
            return -1;
        }
        if (op == EPOLL_CTL_MOD && !entry) {
            errno = ENOENT;
            return -1;
        }

        if (!entry) { /* ADD */
            if (eh->len == eh->cap) {
                size_t ncap = eh->cap * 2;
                struct pollfd *npfds =
                    (struct pollfd *)realloc(eh->pfds, ncap * sizeof(*npfds));
                struct epoll_event *nevs = (struct epoll_event *)realloc(
                    eh->evs, ncap * sizeof(*nevs));
                if (!npfds || !nevs) {
                    if (npfds != eh->pfds)
                        free(npfds);
                    if (nevs != eh->evs)
                        free(nevs);
                    errno = ENOMEM;
                    return -1;
                }
                eh->pfds = npfds;
                eh->evs = nevs;
                eh->cap = ncap;
            }
            size_t new_idx = eh->len;
            eh->pfds[new_idx].fd = fd;
            eh->pfds[new_idx].events = pev;
            eh->pfds[new_idx].revents = 0;
            eh->evs[new_idx] = *event;
            if (ht_insert(eh->fd_map, fd, new_idx) != 0) {
                return -1;
            }
            eh->len++;
        } else { /* MOD */
            eh->pfds[entry->index].events = pev;
            eh->evs[entry->index] = *event;
        }
        break;
    }
    case EPOLL_CTL_DEL: {
        if (!entry) {
            return 0; /* not found, success */
        }
        size_t idx_to_del = entry->index;
        ht_remove(eh->fd_map, fd);

        size_t last_idx = eh->len - 1;
        if (idx_to_del != last_idx) {
            /* Move last element to the deleted slot */
            eh->pfds[idx_to_del] = eh->pfds[last_idx];
            eh->evs[idx_to_del] = eh->evs[last_idx];
            /* Update hash map for the moved element */
            int moved_fd = eh->pfds[idx_to_del].fd;
            ht_remove(eh->fd_map, moved_fd);
            ht_insert(eh->fd_map, moved_fd, idx_to_del);
        }
        eh->len--;
        break;
    }
    default:
        errno = EINVAL;
        return -1;
    }

    return 0;
}

static int ht_resize(struct ht *ht) {
    size_t old_capacity = ht->capacity;
    struct ht_entry **old_buckets = ht->buckets;

    ht->capacity *= 2;
    ht->buckets =
        (struct ht_entry **)calloc(ht->capacity, sizeof(struct ht_entry *));
    if (!ht->buckets) {
        ht->capacity = old_capacity;
        ht->buckets = old_buckets;
        errno = ENOMEM;
        return -1;
    }
    ht->size = 0;

    for (size_t i = 0; i < old_capacity; i++) {
        struct ht_entry *entry = old_buckets[i];
        while (entry) {
            ht_insert(ht, entry->fd, entry->index);
            struct ht_entry *next = entry->next;
            free(entry);
            entry = next;
        }
    }
    free(old_buckets);
    return 0;
}

static int ht_insert(struct ht *ht, int fd, size_t index) {
    if (ht->size >= ht->capacity / 2) { // Rehash when 50% full
        if (ht_resize(ht) != 0)
            return -1;
    }

    unsigned long hash = (unsigned long)fd;
    size_t bucket_index = hash % ht->capacity;
    struct ht_entry *new_entry =
        (struct ht_entry *)malloc(sizeof(struct ht_entry));
    if (!new_entry) {
        errno = ENOMEM;
        return -1;
    }

    new_entry->fd = fd;
    new_entry->index = index;
    new_entry->next = ht->buckets[bucket_index];
    ht->buckets[bucket_index] = new_entry;
    ht->size++;
    return 0;
}

static struct ht_entry *ht_find(struct ht *ht, int fd) {
    unsigned long hash = (unsigned long)fd;
    size_t bucket_index = hash % ht->capacity;
    struct ht_entry *entry = ht->buckets[bucket_index];
    while (entry) {
        if (entry->fd == fd) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

static int ht_remove(struct ht *ht, int fd) {
    unsigned long hash = (unsigned long)fd;
    size_t bucket_index = hash % ht->capacity;
    struct ht_entry *entry = ht->buckets[bucket_index];
    struct ht_entry *prev = NULL;

    while (entry) {
        if (entry->fd == fd) {
            if (prev) {
                prev->next = entry->next;
            } else {
                ht->buckets[bucket_index] = entry->next;
            }
            free(entry);
            ht->size--;
            return 0;
        }
        prev = entry;
        entry = entry->next;
    }
    return -1; /* Not found */
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents,
               int timeout) {
    if (epfd < 0 || (size_t)epfd >= pseudo_epolls_cap || !pseudo_epolls[epfd]) {
        errno = EINVAL;
        return -1;
    }
    struct pseudo_epoll_handle *eh = pseudo_epolls[epfd];

    int nfds = poll(eh->pfds, (nfds_t)eh->len, timeout);
    if (nfds <= 0)
        return nfds;

    int out = 0;
    for (size_t i = 0; i < eh->len && out < maxevents; i++) {
        if (eh->pfds[i].revents) {
            uint32_t evs = 0;
            if (eh->pfds[i].revents & POLLIN)
                evs |= EPOLLIN;
            if (eh->pfds[i].revents & POLLOUT)
                evs |= EPOLLOUT;
            if (eh->pfds[i].revents & POLLERR)
                evs |= EPOLLERR;
#ifdef POLLRDHUP
            if (eh->pfds[i].revents & POLLRDHUP)
                evs |= EPOLLRDHUP;
#endif
            if (eh->pfds[i].revents & POLLHUP)
                evs |= EPOLLHUP;
            events[out] = eh->evs[i];
            events[out].events = evs;
            out++;
        }
    }
    return out;
}
