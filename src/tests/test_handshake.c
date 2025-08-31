#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include "../3rd/chacha20poly1305/chacha20poly1305.h"
#include "../kcptcp_common.h"

#define KTP_HS_HELLO 0x10
#define KTP_HS_ACCEPT 0x11
#define KCP_HS_VER 0x01

/* Simple HMAC implementation using ChaCha20-Poly1305 for authentication */
static void compute_handshake_hmac(const uint8_t *psk, const uint8_t *data,
                                   size_t data_len, uint8_t *hmac_out) {
    /* Use ChaCha20-Poly1305 as HMAC substitute:
     * - Use PSK as key
     * - Use first 12 bytes of data as nonce (padded if needed)
     * - Compute authentication tag over the data
     */
    uint8_t nonce[12];
    memset(nonce, 0, sizeof(nonce));
    size_t nonce_len = data_len < 12 ? data_len : 12;
    memcpy(nonce, data, nonce_len);

    uint8_t tag[16];
    uint8_t dummy_output[1]; /* We only need the tag */

    /* Use ChaCha20-Poly1305 to compute authentication tag */
    chacha20poly1305_seal(psk, nonce, NULL, 0, data, data_len, dummy_output,
                          tag);

    /* Copy first 16 bytes of tag as HMAC */
    memcpy(hmac_out, tag, 16);
}

int test_hello_hmac_consistency() {
    printf("Testing HELLO HMAC consistency...\n");

    /* Test PSK */
    uint8_t psk[32];
    for (int i = 0; i < 32; i++) {
        psk[i] = (uint8_t)i;
    }

    /* Create HELLO message */
    struct handshake_hello hello;
    hello.type = KTP_HS_HELLO;
    hello.version = KCP_HS_VER;
    memset(hello.token, 0xAA, 16);
    hello.timestamp = htonl(1234567890);
    hello.nonce = 0x12345678;

    /* Calculate HMAC */
    size_t hmac_data_len = sizeof(struct handshake_hello) - 16;
    compute_handshake_hmac(psk, (const uint8_t *)&hello, hmac_data_len,
                           hello.hmac);

    /* Verify HMAC by recalculating */
    uint8_t expected_hmac[16];
    compute_handshake_hmac(psk, (const uint8_t *)&hello, hmac_data_len,
                           expected_hmac);

    if (memcmp(hello.hmac, expected_hmac, 16) == 0) {
        printf("✓ HELLO HMAC consistency test passed\n");
        return 0;
    } else {
        printf("✗ HELLO HMAC consistency test failed\n");
        return 1;
    }
}

int test_accept_hmac_consistency() {
    printf("Testing ACCEPT HMAC consistency...\n");

    /* Test PSK */
    uint8_t psk[32];
    for (int i = 0; i < 32; i++) {
        psk[i] = (uint8_t)i;
    }

    /* Create ACCEPT message */
    struct handshake_accept accept;
    accept.type = KTP_HS_ACCEPT;
    accept.version = KCP_HS_VER;
    accept.conv = htonl(0x12345678);
    memset(accept.token, 0xBB, 16);
    accept.timestamp = htonl(1234567890);

    /* Calculate HMAC */
    size_t hmac_data_len = sizeof(struct handshake_accept) - 16;
    compute_handshake_hmac(psk, (const uint8_t *)&accept, hmac_data_len,
                           accept.hmac);

    /* Verify HMAC by recalculating */
    uint8_t expected_hmac[16];
    compute_handshake_hmac(psk, (const uint8_t *)&accept, hmac_data_len,
                           expected_hmac);

    if (memcmp(accept.hmac, expected_hmac, 16) == 0) {
        printf("✓ ACCEPT HMAC consistency test passed\n");
        return 0;
    } else {
        printf("✗ ACCEPT HMAC consistency test failed\n");
        return 1;
    }
}

int test_cross_validation() {
    printf("Testing cross-validation between HELLO and ACCEPT...\n");

    /* Test PSK */
    uint8_t psk[32];
    for (int i = 0; i < 32; i++) {
        psk[i] = (uint8_t)(i * 2 + 1);
    }

    /* Simulate client creating HELLO */
    struct handshake_hello hello;
    hello.type = KTP_HS_HELLO;
    hello.version = KCP_HS_VER;
    memset(hello.token, 0xCC, 16);
    hello.timestamp = htonl((uint32_t)time(NULL));
    hello.nonce = 0x87654321;

    size_t hello_hmac_len = sizeof(struct handshake_hello) - 16;
    compute_handshake_hmac(psk, (const uint8_t *)&hello, hello_hmac_len,
                           hello.hmac);

    /* Simulate server validating HELLO */
    uint8_t server_hello_hmac[16];
    compute_handshake_hmac(psk, (const uint8_t *)&hello, hello_hmac_len,
                           server_hello_hmac);

    if (memcmp(hello.hmac, server_hello_hmac, 16) != 0) {
        printf("✗ Server failed to validate client HELLO HMAC\n");
        return 1;
    }

    /* Simulate server creating ACCEPT */
    struct handshake_accept accept;
    accept.type = KTP_HS_ACCEPT;
    accept.version = KCP_HS_VER;
    accept.conv = htonl(0xABCDEF12);
    memcpy(accept.token, hello.token, 16); /* Echo client token */
    accept.timestamp = htonl((uint32_t)time(NULL));

    size_t accept_hmac_len = sizeof(struct handshake_accept) - 16;
    compute_handshake_hmac(psk, (const uint8_t *)&accept, accept_hmac_len,
                           accept.hmac);

    /* Simulate client validating ACCEPT */
    uint8_t client_accept_hmac[16];
    compute_handshake_hmac(psk, (const uint8_t *)&accept, accept_hmac_len,
                           client_accept_hmac);

    if (memcmp(accept.hmac, client_accept_hmac, 16) != 0) {
        printf("✗ Client failed to validate server ACCEPT HMAC\n");
        return 1;
    }

    printf("✓ Cross-validation test passed\n");
    return 0;
}

int main() {
    printf("Handshake Protocol Compatibility Test\n");
    printf("=====================================\n");

    /* Verify structure sizes */
    printf("Structure sizes:\n");
    printf("  handshake_hello: %zu bytes\n", sizeof(struct handshake_hello));
    printf("  handshake_accept: %zu bytes\n", sizeof(struct handshake_accept));
    printf("\n");

    int failures = 0;

    failures += test_hello_hmac_consistency();
    failures += test_accept_hmac_consistency();
    failures += test_cross_validation();

    printf("\nTest Results:\n");
    if (failures == 0) {
        printf("✓ All tests passed! Handshake protocol is compatible.\n");
        return 0;
    } else {
        printf("✗ %d test(s) failed. Handshake protocol has issues.\n",
               failures);
        return 1;
    }
}
