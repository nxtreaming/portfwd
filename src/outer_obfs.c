#include "outer_obfs.h"
#include <string.h>
#include <stdlib.h>
#include "secure_random.h"
#include "3rd/chacha20poly1305/chacha20poly1305.h"

int outer_wrap(const uint8_t psk[32], const uint8_t *inner, size_t inner_len,
               uint8_t *out_buf, size_t *out_len, size_t pad_max) {
    if (!psk || !inner || !out_buf || !out_len) return -1;
    size_t max_out = *out_len;

    /* Decide padding length: 0..pad_max */
    uint8_t rnd = 0;
    size_t pad = 0;
    if (pad_max > 0) {
        if (secure_random_bytes(&rnd, 1) != 0) return -1;
        pad = (size_t)(rnd % (pad_max + 1));
    }
    size_t total = inner_len + pad;

    if (12 + total + 16 > max_out) return -1;

    uint8_t *plaintext = (uint8_t *)malloc(total);
    if (!plaintext) return -1;
    memcpy(plaintext, inner, inner_len);
    if (pad) {
        if (secure_random_bytes(plaintext + inner_len, pad) != 0) {
            free(plaintext);
            return -1;
        }
    }

    uint8_t nonce[12];
    if (secure_random_bytes(nonce, sizeof(nonce)) != 0) {
        free(plaintext);
        return -1;
    }
    uint8_t tag[16];

    chacha20poly1305_seal(psk, nonce, NULL, 0, plaintext, total, out_buf + 12, tag);
    memcpy(out_buf, nonce, 12);
    memcpy(out_buf + 12 + total, tag, 16);
    *out_len = 12 + total + 16;

    free(plaintext);
    return 0;
}

int outer_unwrap(const uint8_t psk[32], const uint8_t *packet, size_t packet_len,
                 uint8_t *out_buf, size_t *out_len) {
    if (!psk || !packet || !out_buf || !out_len) return -1;
    if (packet_len < 12 + 16) return -1;

    const uint8_t *nonce = packet;
    const uint8_t *ciphertext = packet + 12;
    size_t ciphertext_len = packet_len - 28; /* minus nonce(12) and tag(16) */
    const uint8_t *tag = packet + 12 + ciphertext_len;

    uint8_t *plaintext = (uint8_t *)malloc(ciphertext_len);
    if (!plaintext) return -1;

    if (chacha20poly1305_open(psk, nonce, NULL, 0, ciphertext, ciphertext_len, tag, plaintext) != 0) {
        free(plaintext);
        return -1;
    }

    /* Caller provides buffer; truncate if too small */
    size_t copy = (ciphertext_len < *out_len) ? ciphertext_len : *out_len;
    memcpy(out_buf, plaintext, copy);
    *out_len = copy;

    free(plaintext);
    return 0;
}

