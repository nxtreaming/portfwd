#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>

/* Include the stealth handshake functions */
#include "src/kcptcp_common.h"

int main() {
    printf("Simple Stealth Handshake Test\n");
    printf("=============================\n");

    /* Test PSK */
    uint8_t psk[32];
    for (int i = 0; i < 32; i++) {
        psk[i] = (uint8_t)i;
    }

    /* Test token */
    uint8_t token[16];
    memset(token, 0xAA, 16);

    /* Create stealth handshake packet */
    uint8_t packet[1024];
    size_t packet_len = sizeof(packet);

    printf("Creating stealth handshake packet...\n");
    if (stealth_handshake_create_first_packet(psk, token, NULL, 0, packet, &packet_len) != 0) {
        printf("✗ Failed to create stealth handshake packet\n");
        return 1;
    }

    printf("✓ Created stealth handshake packet: %zu bytes\n", packet_len);

    /* Parse the packet back */
    struct stealth_handshake_payload payload;
    uint8_t extracted_data[1024];
    size_t extracted_data_len = sizeof(extracted_data);

    printf("Parsing stealth handshake packet...\n");
    if (stealth_handshake_parse_first_packet(psk, packet, packet_len, &payload, extracted_data,
                                             &extracted_data_len) != 0) {
        printf("✗ Failed to parse stealth handshake packet\n");
        return 1;
    }

    printf("✓ Successfully parsed stealth handshake packet\n");

    /* Validate payload */
    if (ntohl(payload.magic) != STEALTH_HANDSHAKE_MAGIC) {
        printf("✗ Invalid magic number: expected 0x%08x, got 0x%08x\n", STEALTH_HANDSHAKE_MAGIC,
               ntohl(payload.magic));
        return 1;
    }

    if (memcmp(payload.token, token, 16) != 0) {
        printf("✗ Token mismatch\n");
        return 1;
    }

    printf("✓ Magic number and token validated\n");

    /* Test response creation */
    uint32_t conv = 0x12345678;
    uint8_t response_packet[1024];
    size_t response_len = sizeof(response_packet);

    printf("Creating stealth handshake response...\n");
    if (stealth_handshake_create_response(psk, conv, token, response_packet, &response_len) != 0) {
        printf("✗ Failed to create stealth handshake response\n");
        return 1;
    }

    printf("✓ Created stealth handshake response: %zu bytes\n", response_len);

    /* Parse the response */
    struct stealth_handshake_response response;
    printf("Parsing stealth handshake response...\n");
    if (stealth_handshake_parse_response(psk, response_packet, response_len, &response) != 0) {
        printf("✗ Failed to parse stealth handshake response\n");
        return 1;
    }

    printf("✓ Successfully parsed stealth handshake response\n");

    /* Validate response */
    if (ntohl(response.magic) != STEALTH_RESPONSE_MAGIC) {
        printf("✗ Invalid response magic: expected 0x%08x, got 0x%08x\n", STEALTH_RESPONSE_MAGIC,
               ntohl(response.magic));
        return 1;
    }

    if (ntohl(response.conv) != conv) {
        printf("✗ Conversation ID mismatch: expected 0x%08x, got 0x%08x\n", conv,
               ntohl(response.conv));
        return 1;
    }

    if (memcmp(response.token, token, 16) != 0) {
        printf("✗ Response token mismatch\n");
        return 1;
    }

    printf("✓ Response magic, conv, and token validated\n");

    printf("\n🎉 All stealth handshake tests passed!\n");
    printf("The stealth handshake protocol is working correctly.\n");

    return 0;
}
