#ifndef PORTFWD_SECURE_RANDOM_H
#define PORTFWD_SECURE_RANDOM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generate cryptographically secure random bytes.
 * Uses platform-specific secure random sources.
 * 
 * @param buf Buffer to fill with random bytes
 * @param len Number of bytes to generate
 * @return 0 on success, -1 on failure
 */
int secure_random_bytes(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PORTFWD_SECURE_RANDOM_H */
