#include "aead.h"
#include <string.h>
#include "3rd/chacha20poly1305/chacha20poly1305.h"

int derive_session_key_from_psk(const uint8_t psk[32],
                                const uint8_t token16[16], uint32_t conv,
                                uint8_t out_key[32]) {
    if (!psk || !token16 || !out_key)
        return -1;
    /* Build 16-byte nonce: token16[0..15] XOR conv (little-endian) into last 4
     * bytes */
    uint8_t nonce16[16];
    memcpy(nonce16, token16, 16);
    nonce16[12] ^= (uint8_t)(conv & 0xFF);
    nonce16[13] ^= (uint8_t)((conv >> 8) & 0xFF);
    nonce16[14] ^= (uint8_t)((conv >> 16) & 0xFF);
    nonce16[15] ^= (uint8_t)((conv >> 24) & 0xFF);
    /* Use HChaCha20 to derive subkey */
    hchacha20(psk, nonce16, out_key);
    return 0;
}

int derive_session_key_epoch(const uint8_t psk[32], const uint8_t token16[16],
                             uint32_t conv, uint32_t epoch,
                             uint8_t out_key[32]) {
    if (!psk || !token16 || !out_key)
        return -1;
    /* Build 16-byte nonce mixing token, conv, and epoch deterministically */
    uint8_t nonce16[16];
    memcpy(nonce16, token16, 16);
    /* Mix conv into last 4 bytes (little-endian XOR), same as base derivation
     */
    nonce16[12] ^= (uint8_t)(conv & 0xFF);
    nonce16[13] ^= (uint8_t)((conv >> 8) & 0xFF);
    nonce16[14] ^= (uint8_t)((conv >> 16) & 0xFF);
    nonce16[15] ^= (uint8_t)((conv >> 24) & 0xFF);
    /* Mix epoch into first 4 bytes to create per-epoch separation */
    nonce16[0] ^= (uint8_t)(epoch & 0xFF);
    nonce16[1] ^= (uint8_t)((epoch >> 8) & 0xFF);
    nonce16[2] ^= (uint8_t)((epoch >> 16) & 0xFF);
    nonce16[3] ^= (uint8_t)((epoch >> 24) & 0xFF);
    hchacha20(psk, nonce16, out_key);
    return 0;
}
