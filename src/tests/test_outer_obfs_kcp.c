#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "../outer_obfs.h"

static void fill_psk(uint8_t psk[32]) {
    for (int i = 0; i < 32; ++i)
        psk[i] = (uint8_t)(0xC3 ^ (i * 13 + 1));
}

/*
 * Build a minimal KCP-like datagram in memory:
 * We only care that the first 4 bytes carry conv and are preserved across
 * outer wrap/unwrap. We don't run KCP, just shape-check.
 */
static size_t build_fake_kcp(uint8_t *buf, size_t cap, uint32_t conv, const uint8_t *payload,
                             size_t plen) {
    if (cap < 24 + plen)
        return 0; /* minimal header (24) + payload */
    /* KCP header fields (little-endian in reference implementation, but we only memcpy/compare) */
    memcpy(buf + 0, &conv, 4);
    buf[4] = 0x81; /* cmd (dummy) */
    buf[5] = 0x00; /* frg */
    buf[6] = 0x20;
    buf[7] = 0x20; /* wnd (dummy) */
    uint32_t ts = 0x01020304;
    uint32_t sn = 0x05060708;
    uint32_t una = 0x090A0B0C;
    uint32_t len = (uint32_t)plen;
    memcpy(buf + 8, &ts, 4);
    memcpy(buf + 12, &sn, 4);
    memcpy(buf + 16, &una, 4);
    memcpy(buf + 20, &len, 4);
    memcpy(buf + 24, payload, plen);
    return 24 + plen;
}

int main(void) {
    uint8_t psk[32];
    fill_psk(psk);

    uint8_t inner[1500];
    uint8_t payload[100];
    for (int i = 0; i < (int)sizeof(payload); ++i)
        payload[i] = (uint8_t)i;
    uint32_t conv = 0x11223344;

    size_t inner_len = build_fake_kcp(inner, sizeof(inner), conv, payload, sizeof(payload));
    if (inner_len == 0) {
        fprintf(stderr, "failed to build fake kcp datagram\n");
        return 1;
    }

    uint8_t wire[2000];
    size_t wire_len = sizeof(wire);
    if (outer_wrap(psk, inner, inner_len, wire, &wire_len, 31) != 0) {
        fprintf(stderr, "outer_wrap failed\n");
        return 1;
    }

    uint8_t unwrapped[1500];
    size_t unwrapped_len = sizeof(unwrapped);
    if (outer_unwrap(psk, wire, wire_len, unwrapped, &unwrapped_len) != 0) {
        fprintf(stderr, "outer_unwrap failed\n");
        return 1;
    }

    if (unwrapped_len != inner_len || memcmp(unwrapped, inner, inner_len) != 0) {
        fprintf(stderr, "mismatch after wrap/unwrap (len=%zu/%zu)\n", inner_len, unwrapped_len);
        return 1;
    }

    uint32_t conv2 = 0;
    memcpy(&conv2, unwrapped, 4);
    if (conv2 != conv) {
        fprintf(stderr, "conv mismatch after unwrap: %08x vs %08x\n", conv, conv2);
        return 1;
    }

    printf("OK: outer obfs preserves KCP-shaped datagram; conv=%08x len=%zu\n", conv2,
           unwrapped_len);
    return 0;
}
