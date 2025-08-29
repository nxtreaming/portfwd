#ifndef AEAD_PROTOCOL_H
#define AEAD_PROTOCOL_H

#include "proxy_conn.h"

// Forward declaration
struct proxy_conn;

/**
 * @brief Handles an incoming KCP packet that may be a control message or data.
 *
 * This function inspects the packet type and dispatches to the appropriate
 * handler for AEAD control messages (rekeying) or data decryption.
 *
 * @param c The connection context.
 * @param data The received KCP payload.
 * @param len The length of the payload.
 * @param psk The pre-shared key for key derivation.
 * @param has_psk Whether a PSK is configured.
 * @param out_payload Pointer to be updated with the start of the decrypted
 * payload.
 * @param out_plen Pointer to be updated with the length of the decrypted
 * payload.
 * @return int 0 on success (data packet processed), 1 if it was a handled
 * control packet, -1 on error (e.g., tag verification failed, which should lead
 * to connection closure).
 */
int aead_protocol_handle_incoming_packet(struct proxy_conn *c, char *data,
                                         int len, const uint8_t *psk,
                                         bool has_psk, char **out_payload,
                                         int *out_plen);

/**
 * @brief Encrypts and sends application data over KCP.
 *
 * Handles AEAD wrapping (if enabled) and potential rekeying triggers before
 * sending.
 *
 * @param c The connection context.
 * @param data The plaintext data to send.
 * @param len The length of the data.
 * @param psk The pre-shared key for key derivation.
 * @param has_psk Whether a PSK is configured.
 * @return int 0 on success, -1 on failure.
 */
int aead_protocol_send_data(struct proxy_conn *c, const char *data, int len,
                            const uint8_t *psk, bool has_psk);

/**
 * @brief Sends a FIN message, encrypted if AEAD is enabled.
 *
 * @param c The connection context.
 * @param psk The pre-shared key for key derivation.
 * @param has_psk Whether a PSK is configured.
 * @return int 0 on success, -1 on failure.
 */
int aead_protocol_send_fin(struct proxy_conn *c, const uint8_t *psk,
                           bool has_psk);

#endif // AEAD_PROTOCOL_H
