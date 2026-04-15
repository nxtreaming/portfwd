#include "conn_pool.h"
#include "common.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#ifdef CONN_POOL_NO_MUTEX
#define POOL_LOCK(p)   ((void)(p))
#define POOL_UNLOCK(p) ((void)(p))
#else
#define POOL_LOCK(p)   pthread_mutex_lock(&(p)->lock)
#define POOL_UNLOCK(p) pthread_mutex_unlock(&(p)->lock)
#endif

/* Validate that the item pointer belongs to this pool and is properly aligned */
static int is_valid_pool_item(const struct conn_pool *pool, const void *item) {
    if (!pool || !item || !pool->pool_mem || pool->item_size == 0 || pool->capacity == 0)
        return 0;
    uintptr_t addr = (uintptr_t)item;
    uintptr_t start = (uintptr_t)pool->pool_mem;
    uintptr_t end = start + pool->capacity * pool->item_size;
    if (addr < start || addr >= end)
        return 0;
    if (((addr - start) % pool->item_size) != 0)
        return 0;
    return 1;
}

int conn_pool_init(struct conn_pool *pool, size_t capacity, size_t item_size) {
    if (!pool || capacity == 0 || item_size == 0) {
        errno = EINVAL;
        return -1; /* Invalid arguments */
    }

    memset(pool, 0, sizeof(*pool));
    pool->capacity = capacity;
    pool->item_size = item_size;

    /* Allocate the main memory block for all objects */
    pool->pool_mem = malloc(capacity * item_size);
    if (!pool->pool_mem) {
        P_LOG_ERR("Failed to allocate memory for object pool: %s", strerror(errno));
        errno = ENOMEM;
        return -1;
    }

    /* Allocate the freelist array */
    pool->freelist = malloc(capacity * sizeof(void *));
    if (!pool->freelist) {
        P_LOG_ERR("Failed to allocate memory for freelist: %s", strerror(errno));
        free(pool->pool_mem);
        pool->pool_mem = NULL;
        errno = ENOMEM;
        return -1;
    }

    /* Populate the freelist with pointers to each object in the pool */
    for (size_t i = 0; i < capacity; i++) {
        pool->freelist[i] = (char *)pool->pool_mem + (i * item_size);
    }

    pool->used_count = 0;
    pool->high_water_mark = 0;

#ifndef CONN_POOL_NO_MUTEX
    if (pthread_mutex_init(&pool->lock, NULL) != 0) {
        P_LOG_ERR("Failed to initialize connection pool mutex: %s", strerror(errno));
        free(pool->pool_mem);
        free(pool->freelist);
        errno = EBUSY;
        return -1;
    }
#endif

    return 0;
}

void conn_pool_destroy(struct conn_pool *pool) {
    if (!pool) {
        return;
    }
#ifndef CONN_POOL_NO_MUTEX
    pthread_mutex_destroy(&pool->lock);
#endif
    free(pool->pool_mem);
    free(pool->freelist);
    memset(pool, 0, sizeof(*pool));
}

void *conn_pool_alloc(struct conn_pool *pool) {
    if (!pool) {
        errno = EINVAL;
        return NULL;
    }

    POOL_LOCK(pool);

    if (pool->used_count >= pool->capacity) {
        POOL_UNLOCK(pool);
        errno = ENOSPC; /* Pool is full */
        return NULL;
    }

    /* Get an item from the top of the freelist stack */
    void *item = pool->freelist[pool->used_count];
    pool->used_count++;

    if (pool->used_count > pool->high_water_mark) {
        pool->high_water_mark = pool->used_count;
    }

    POOL_UNLOCK(pool);

    return item;
}

void conn_pool_release(struct conn_pool *pool, void *item) {
    if (!pool || !item) {
        P_LOG_WARN("Invalid pool or item in conn_pool_release");
        errno = EINVAL;
        return;
    }

    /* Validate that item is from this pool */
    if (!is_valid_pool_item(pool, item)) {
        P_LOG_ERR("Attempt to release item not from this pool");
        errno = EFAULT;
        return;
    }

    POOL_LOCK(pool);

    if (pool->used_count == 0) {
        /* Underflow detected: nothing to release */
        P_LOG_WARN("Pool underflow in release");
        POOL_UNLOCK(pool);
        errno = EOVERFLOW;
        return;
    }

    /* Clear the memory before returning to freelist to avoid data leakage */
    memset(item, 0, pool->item_size);

    /* Add the released item back to the top of the freelist stack */
    pool->used_count--;
    pool->freelist[pool->used_count] = item;

    POOL_UNLOCK(pool);
}
