#ifndef __PORTFWD_CONN_POOL_H__
#define __PORTFWD_CONN_POOL_H__

#include <stddef.h>
#include <pthread.h>

/**
 * @brief A generic fixed-size object pool.
 *
 * This structure manages a pre-allocated pool of fixed-size memory blocks.
 * It is thread-safe through a mutex lock.
 */
struct conn_pool {
    void *pool_mem;         /**< Pointer to the contiguous block of memory for all objects. */
    void **freelist;        /**< A stack-based freelist to manage available objects. */
    size_t capacity;        /**< Total number of objects the pool can hold. */
    size_t item_size;       /**< Size of a single object in the pool. */
    size_t used_count;      /**< Number of objects currently in use. */
    size_t high_water_mark; /**< Peak number of used objects for monitoring. */
    pthread_mutex_t lock;   /**< Mutex for thread-safe operations. */
};

/**
 * @brief Initializes a connection pool.
 *
 * @param pool The connection pool to initialize.
 * @param capacity The maximum number of items in the pool.
 * @param item_size The size of each item.
 * @return 0 on success, -1 on failure (e.g., memory allocation failed).
 */
int conn_pool_init(struct conn_pool *pool, size_t capacity, size_t item_size);

/**
 * @brief Destroys a connection pool and frees its resources.
 *
 * @param pool The connection pool to destroy.
 */
void conn_pool_destroy(struct conn_pool *pool);

/**
 * @brief Allocates an item from the connection pool.
 *
 * This function is thread-safe.
 * @param pool The connection pool.
 * @return A pointer to an item, or NULL if the pool is full.
 */
void *conn_pool_alloc(struct conn_pool *pool);

/**
 * @brief Releases an item back to the connection pool.
 *
 * This function is thread-safe.
 * @param pool The connection pool.
 * @param item A pointer to the item to release.
 */
void conn_pool_release(struct conn_pool *pool, void *item);

#endif /* __PORTFWD_CONN_POOL_H__ */
