#ifndef OUTER_OBFS_H
#define OUTER_OBFS_H

#include <stddef.h>
#include <stdint.h>

/*
 * Outer obfuscation wrapper: unify wire shape for all UDP packets.
 * Packet format (wire):
 *   [12-byte random nonce] [ciphertext(inner || padding)] [16-byte tag]
 * AAD is empty (NULL, 0) to match existing handshake usage.
 */

/* Max additional padding to add after inner payload (0..pad_max bytes). */
int outer_wrap(const uint8_t psk[32], const uint8_t *inner, size_t inner_len,
               uint8_t *out_buf, size_t *out_len, size_t pad_max);

/* Unwrap outer packet. On success, copies inner payload to out_buf. */
int outer_unwrap(const uint8_t psk[32], const uint8_t *packet, size_t packet_len,
                 uint8_t *out_buf, size_t *out_len);

#endif /* OUTER_OBFS_H */

