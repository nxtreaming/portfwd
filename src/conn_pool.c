#include "conn_pool.h"
#include "common.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int conn_pool_init(struct conn_pool *pool, size_t capacity, size_t item_size) {
    if (!pool || capacity == 0 || item_size == 0) {
        return -1; /* Invalid arguments */
    }

    memset(pool, 0, sizeof(*pool));
    pool->capacity = capacity;
    pool->item_size = item_size;

    /* Allocate the main memory block for all objects */
    pool->pool_mem = malloc(capacity * item_size);
    if (!pool->pool_mem) {
        P_LOG_ERR("Failed to allocate memory for object pool: %s", strerror(errno));
        return -1;
    }

    /* Allocate the freelist array */
    pool->freelist = malloc(capacity * sizeof(void *));
    if (!pool->freelist) {
        P_LOG_ERR("Failed to allocate memory for freelist: %s", strerror(errno));
        free(pool->pool_mem);
        pool->pool_mem = NULL;
        return -1;
    }

    /* Populate the freelist with pointers to each object in the pool */
    for (size_t i = 0; i < capacity; i++) {
        pool->freelist[i] = (char *)pool->pool_mem + (i * item_size);
    }

    pool->used_count = 0;
    pool->high_water_mark = 0;

    if (pthread_mutex_init(&pool->lock, NULL) != 0) {
        P_LOG_ERR("Failed to initialize connection pool mutex: %s", strerror(errno));
        free(pool->pool_mem);
        free(pool->freelist);
        return -1;
    }

    return 0;
}

void conn_pool_destroy(struct conn_pool *pool) {
    if (!pool) {
        return;
    }
    pthread_mutex_destroy(&pool->lock);
    free(pool->pool_mem);
    free(pool->freelist);
    memset(pool, 0, sizeof(*pool));
}

void *conn_pool_alloc(struct conn_pool *pool) {
    if (!pool) {
        return NULL;
    }

    pthread_mutex_lock(&pool->lock);

    if (pool->used_count >= pool->capacity) {
        pthread_mutex_unlock(&pool->lock);
        return NULL; /* Pool is full */
    }

    /* Get an item from the top of the freelist stack */
    void *item = pool->freelist[pool->used_count];
    pool->used_count++;

    if (pool->used_count > pool->high_water_mark) {
        pool->high_water_mark = pool->used_count;
    }

    pthread_mutex_unlock(&pool->lock);

    return item;
}

void conn_pool_release(struct conn_pool *pool, void *item) {
    if (!pool || !item) {
        return;
    }

    pthread_mutex_lock(&pool->lock);

    if (pool->used_count == 0) {
        /* Should not happen in normal operation */
        pthread_mutex_unlock(&pool->lock);
        return;
    }

    /* Add the released item back to the top of the freelist stack */
    pool->used_count--;
    pool->freelist[pool->used_count] = item;

    pthread_mutex_unlock(&pool->lock);
}
