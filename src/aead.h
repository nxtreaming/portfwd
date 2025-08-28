#ifndef PORTFWD_AEAD_H
#define PORTFWD_AEAD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Derive a per-connection session key from PSK and client token + conv.
 * out_key[32] receives the session key. Returns 0 on success, -1 otherwise.
 */
int derive_session_key_from_psk(const uint8_t psk[32], const uint8_t token16[16], uint32_t conv, uint8_t out_key[32]);

#ifdef __cplusplus
}
#endif

#endif /* PORTFWD_AEAD_H */
