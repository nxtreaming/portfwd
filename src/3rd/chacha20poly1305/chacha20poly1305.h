/*
 * Compact public-domain ChaCha20-Poly1305 (IETF) implementation
 * - Based on public-domain/CC0 works by Andrew Moon (floodyberry) and others
 * - Single-header interface for AEAD encrypt/decrypt and HChaCha20
 */
#ifndef PORTFWD_CHACHA20_POLY1305_H
#define PORTFWD_CHACHA20_POLY1305_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HChaCha20: derive 32-byte subkey from 32-byte key and 16-byte nonce */
void hchacha20(const uint8_t key[32], const uint8_t nonce16[16], uint8_t out_subkey[32]);

/* AEAD: ChaCha20-Poly1305 (IETF) with 96-bit nonce */
/* out must have space for inlen bytes; tag is 16 bytes */
void chacha20poly1305_seal(
    const uint8_t key[32],
    const uint8_t nonce12[12],
    const uint8_t *ad, size_t adlen,
    const uint8_t *in, size_t inlen,
    uint8_t *out, /* ciphertext */
    uint8_t tag[16]
);

/* returns 0 on success, -1 on authentication failure */
int chacha20poly1305_open(
    const uint8_t key[32],
    const uint8_t nonce12[12],
    const uint8_t *ad, size_t adlen,
    const uint8_t *in, size_t inlen,
    const uint8_t tag[16],
    uint8_t *out /* plaintext */
);

#ifdef __cplusplus
}
#endif

#endif /* PORTFWD_CHACHA20_POLY1305_H */
