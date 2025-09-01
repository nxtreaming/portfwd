#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

#include "../outer_obfs.h"
#include "../kcptcp_common.h"

static void fill_psk(uint8_t psk[32]) {
    for (int i = 0; i < 32; ++i)
        psk[i] = (uint8_t)(i * 7 + 3);
}

int main(void) {
    uint8_t psk[32];
    fill_psk(psk);

    /* Prepare a fake inner payload (stealth handshake first-packet) */
    uint8_t token[16];
    memset(token, 0xA5, sizeof(token));

    const char *init = "GET / HTTP/1.1\r\n\r\n";
    const uint8_t *init_data = (const uint8_t *)init;
    size_t init_len = strlen(init);

    uint8_t pkt[1600];
    size_t pkt_len = sizeof(pkt);
    if (stealth_handshake_create_first_packet(psk, token, init_data, init_len, pkt, &pkt_len) !=
        0) {
        fprintf(stderr, "Failed to create stealth handshake packet\n");
        return 1;
    }

    /* Outer wrap */
    uint8_t wire[2000];
    size_t wire_len = sizeof(wire);
    if (outer_wrap(psk, pkt, pkt_len, wire, &wire_len, 31) != 0) {
        fprintf(stderr, "outer_wrap failed\n");
        return 1;
    }

    /* Outer unwrap */
    uint8_t inner[1600];
    size_t inner_len = sizeof(inner);
    if (outer_unwrap(psk, wire, wire_len, inner, &inner_len) != 0) {
        fprintf(stderr, "outer_unwrap failed\n");
        return 1;
    }

    if (inner_len != pkt_len || memcmp(inner, pkt, pkt_len) != 0) {
        fprintf(stderr, "mismatch after wrap/unwrap (len=%zu/%zu)\n", pkt_len, inner_len);
        return 1;
    }

    /* Parse back the handshake to ensure it remains valid */
    struct stealth_handshake_payload payload;
    uint8_t extracted[1024];
    size_t extracted_len = sizeof(extracted);
    if (stealth_handshake_parse_first_packet(psk, inner, inner_len, &payload, extracted,
                                             &extracted_len) != 0) {
        fprintf(stderr, "parse_first_packet failed after outer wrap\n");
        return 1;
    }

    printf("OK: outer wrap/unwrap keeps handshake valid; extracted_len=%zu\n", extracted_len);
    return 0;
}
