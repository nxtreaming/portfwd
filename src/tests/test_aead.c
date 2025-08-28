#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "../aead.h"

static void hexdump(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; ++i) printf("%02x", b[i]);
}

int main(void) {
    /* Fixed test vectors (not secret) */
    const uint8_t psk[32] = {
        0x00,1,2,3,4,5,6,7, 8,9,10,11,12,13,14,15,
        16,17,18,19,20,21,22,23, 24,25,26,27,28,29,30,31
    };
    const uint8_t token[32] = {
        0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x11,0x22,
        0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00,
        0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
        0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0,0x01
    };
    uint32_t conv = 0x12345678;

    uint8_t k0[32], k1[32], k0_bis[32];
    if (derive_session_key_epoch(psk, token, conv, 0, k0) != 0) {
        fprintf(stderr, "derive_session_key_epoch epoch0 failed\n");
        return 1;
    }
    if (derive_session_key_epoch(psk, token, conv, 1, k1) != 0) {
        fprintf(stderr, "derive_session_key_epoch epoch1 failed\n");
        return 1;
    }
    if (derive_session_key_epoch(psk, token, conv, 0, k0_bis) != 0) {
        fprintf(stderr, "derive_session_key_epoch epoch0 (bis) failed\n");
        return 1;
    }

    int ok_same = (memcmp(k0, k0_bis, 32) == 0);
    int ok_diff = (memcmp(k0, k1, 32) != 0);

    printf("k0="); hexdump(k0, 32); printf("\n");
    printf("k1="); hexdump(k1, 32); printf("\n");
    printf("k0_bis="); hexdump(k0_bis, 32); printf("\n");

    if (!ok_same) {
        fprintf(stderr, "FAIL: epoch 0 derivations not deterministic\n");
        return 2;
    }
    if (!ok_diff) {
        fprintf(stderr, "FAIL: epoch 0 and 1 keys should differ\n");
        return 3;
    }

    printf("OK: key derivation deterministic and epoch-separated\n");
    return 0;
}
