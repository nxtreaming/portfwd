#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include "../kcptcp_common.h"

int test_stealth_handshake_basic() {
    printf("Testing basic stealth handshake...\n");

    /* Test PSK */
    uint8_t psk[32];
    for (int i = 0; i < 32; i++) {
        psk[i] = (uint8_t)i;
    }

    /* Test token */
    uint8_t token[16];
    memset(token, 0xAA, 16);

    /* Test initial data */
    const char *initial_data = "Hello, World!";
    size_t initial_data_len = strlen(initial_data);

    /* Create stealth handshake packet */
    uint8_t packet[1024];
    size_t packet_len = sizeof(packet);

    if (stealth_handshake_create_first_packet(
            psk, token, (const uint8_t *)initial_data, initial_data_len, packet,
            &packet_len) != 0) {
        printf("✗ Failed to create stealth handshake packet\n");
        return 1;
    }

    printf("  Created stealth handshake packet: %zu bytes\n", packet_len);

    /* Parse the packet back */
    struct stealth_handshake_payload payload;
    uint8_t extracted_data[1024];
    size_t extracted_data_len = sizeof(extracted_data);

    if (stealth_handshake_parse_first_packet(psk, packet, packet_len, &payload,
                                             extracted_data,
                                             &extracted_data_len) != 0) {
        printf("✗ Failed to parse stealth handshake packet\n");
        return 1;
    }

    /* Validate payload */
    if (ntohl(payload.magic) != STEALTH_HANDSHAKE_MAGIC) {
        printf("✗ Invalid magic number in payload\n");
        return 1;
    }

    if (memcmp(payload.token, token, 16) != 0) {
        printf("✗ Token mismatch in payload\n");
        return 1;
    }

    /* Validate extracted data */
    if (extracted_data_len != initial_data_len) {
        printf("✗ Extracted data length mismatch: expected %zu, got %zu\n",
               initial_data_len, extracted_data_len);
        return 1;
    }

    if (memcmp(extracted_data, initial_data, initial_data_len) != 0) {
        printf("✗ Extracted data content mismatch\n");
        return 1;
    }

    printf("✓ Basic stealth handshake test passed\n");
    return 0;
}

int test_stealth_handshake_response() {
    printf("Testing stealth handshake response...\n");

    /* Test PSK */
    uint8_t psk[32];
    for (int i = 0; i < 32; i++) {
        psk[i] = (uint8_t)(i * 2 + 1);
    }

    /* Test parameters */
    uint32_t conv = 0x12345678;
    uint8_t token[16];
    memset(token, 0xBB, 16);

    /* Create response */
    uint8_t response_packet[1024];
    size_t response_len = sizeof(response_packet);

    if (stealth_handshake_create_response(psk, conv, token, response_packet,
                                          &response_len) != 0) {
        printf("✗ Failed to create stealth handshake response\n");
        return 1;
    }

    printf("  Created stealth handshake response: %zu bytes\n", response_len);

    /* Parse the response back */
    struct stealth_handshake_response response;
    if (stealth_handshake_parse_response(psk, response_packet, response_len,
                                         &response) != 0) {
        printf("✗ Failed to parse stealth handshake response\n");
        return 1;
    }

    /* Validate response */
    if (ntohl(response.magic) != STEALTH_RESPONSE_MAGIC) {
        printf("✗ Invalid magic number in response\n");
        return 1;
    }

    if (ntohl(response.conv) != conv) {
        printf("✗ Conversation ID mismatch: expected 0x%08x, got 0x%08x\n",
               conv, ntohl(response.conv));
        return 1;
    }

    if (memcmp(response.token, token, 16) != 0) {
        printf("✗ Token mismatch in response\n");
        return 1;
    }

    printf("✓ Stealth handshake response test passed\n");
    return 0;
}

int test_stealth_handshake_full_flow() {
    printf("Testing full stealth handshake flow...\n");

    /* Test PSK */
    uint8_t psk[32];
    for (int i = 0; i < 32; i++) {
        psk[i] = (uint8_t)(i ^ 0x55);
    }

    /* Client creates handshake */
    uint8_t client_token[16];
    memset(client_token, 0xCC, 16);

    const char *initial_request = "GET / HTTP/1.1\r\n\r\n";
    size_t request_len = strlen(initial_request);

    uint8_t client_packet[1024];
    size_t client_packet_len = sizeof(client_packet);

    if (stealth_handshake_create_first_packet(
            psk, client_token, (const uint8_t *)initial_request, request_len,
            client_packet, &client_packet_len) != 0) {
        printf("✗ Client failed to create stealth handshake\n");
        return 1;
    }

    /* Server parses handshake */
    struct stealth_handshake_payload server_payload;
    uint8_t server_extracted[1024];
    size_t server_extracted_len = sizeof(server_extracted);

    if (stealth_handshake_parse_first_packet(
            psk, client_packet, client_packet_len, &server_payload,
            server_extracted, &server_extracted_len) != 0) {
        printf("✗ Server failed to parse stealth handshake\n");
        return 1;
    }

    /* Server creates response */
    uint32_t server_conv = 0xABCDEF12;
    uint8_t server_response[1024];
    size_t server_response_len = sizeof(server_response);

    if (stealth_handshake_create_response(psk, server_conv,
                                          server_payload.token, server_response,
                                          &server_response_len) != 0) {
        printf("✗ Server failed to create response\n");
        return 1;
    }

    /* Client parses response */
    struct stealth_handshake_response client_response;
    if (stealth_handshake_parse_response(
            psk, server_response, server_response_len, &client_response) != 0) {
        printf("✗ Client failed to parse server response\n");
        return 1;
    }

    /* Validate full flow */
    if (memcmp(client_response.token, client_token, 16) != 0) {
        printf("✗ Token echo mismatch in full flow\n");
        return 1;
    }

    if (ntohl(client_response.conv) != server_conv) {
        printf("✗ Conversation ID mismatch in full flow\n");
        return 1;
    }

    if (server_extracted_len != request_len ||
        memcmp(server_extracted, initial_request, request_len) != 0) {
        printf("✗ Initial request data mismatch in full flow\n");
        return 1;
    }

    printf("✓ Full stealth handshake flow test passed\n");
    return 0;
}

int test_stealth_handshake_wrong_psk() {
    printf("Testing stealth handshake with wrong PSK...\n");

    /* Correct PSK */
    uint8_t correct_psk[32];
    for (int i = 0; i < 32; i++) {
        correct_psk[i] = (uint8_t)i;
    }

    /* Wrong PSK */
    uint8_t wrong_psk[32];
    for (int i = 0; i < 32; i++) {
        wrong_psk[i] = (uint8_t)(i + 1);
    }

    uint8_t token[16];
    memset(token, 0xDD, 16);

    /* Create packet with correct PSK */
    uint8_t packet[1024];
    size_t packet_len = sizeof(packet);

    if (stealth_handshake_create_first_packet(correct_psk, token, NULL, 0,
                                              packet, &packet_len) != 0) {
        printf("✗ Failed to create packet with correct PSK\n");
        return 1;
    }

    /* Try to parse with wrong PSK - should fail */
    struct stealth_handshake_payload payload;
    uint8_t extracted_data[1024];
    size_t extracted_data_len = sizeof(extracted_data);

    if (stealth_handshake_parse_first_packet(wrong_psk, packet, packet_len,
                                             &payload, extracted_data,
                                             &extracted_data_len) == 0) {
        printf("✗ Parsing with wrong PSK should have failed but succeeded\n");
        return 1;
    }

    printf("✓ Wrong PSK correctly rejected\n");
    return 0;
}

int main() {
    printf("Stealth Handshake Protocol Test\n");
    printf("===============================\n");

    int failures = 0;

    failures += test_stealth_handshake_basic();
    failures += test_stealth_handshake_response();
    failures += test_stealth_handshake_full_flow();
    failures += test_stealth_handshake_wrong_psk();

    printf("\nTest Results:\n");
    if (failures == 0) {
        printf("✓ All stealth handshake tests passed! Protocol is working "
               "correctly.\n");
        return 0;
    } else {
        printf("✗ %d test(s) failed. Stealth handshake protocol has issues.\n",
               failures);
        return 1;
    }
}
