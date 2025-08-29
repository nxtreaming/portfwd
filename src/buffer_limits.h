#ifndef PORTFWD_BUFFER_LIMITS_H
#define PORTFWD_BUFFER_LIMITS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum buffer sizes to prevent memory exhaustion attacks */
#define MAX_TCP_BUFFER_SIZE (16 * 1024 * 1024) /* 16MB per connection */
#define MAX_UDP_BACKLOG_SIZE (1 * 1024 * 1024) /* 1MB UDP backlog */
#define INITIAL_BUFFER_SIZE (64 * 1024)        /* 64KB initial size */

/**
 * Check if a buffer size increase is within limits
 * @param current_size Current buffer size
 * @param requested_size Requested new size
 * @param max_size Maximum allowed size
 * @return 1 if allowed, 0 if would exceed limits
 */
static inline int buffer_size_check(size_t current_size, size_t requested_size,
                                    size_t max_size) {
    (void)current_size; /* unused for now */
    return (requested_size <= max_size) ? 1 : 0;
}

#ifdef __cplusplus
}
#endif

#endif /* PORTFWD_BUFFER_LIMITS_H */
