#ifndef PORTFWD_AEAD_H
#define PORTFWD_AEAD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Derive a per-connection session key from PSK and client token + conv.
 * out_key[32] receives the session key. Returns 0 on success, -1 otherwise.
 */
int derive_session_key_from_psk(const uint8_t psk[32], const uint8_t token16[16], uint32_t conv,
                                uint8_t out_key[32]);

struct proxy_conn;

void aead_gen_control_packet(unsigned char type, uint32_t seq, const uint8_t *key,
                             const uint8_t *nonce_base, uint8_t *ad, uint8_t *out_pkt);
int aead_verify_packet(struct proxy_conn *c, uint8_t *data, int len, uint32_t *out_seq);
int aead_verify_ack_packet(struct proxy_conn *c, uint8_t *data, int len);
void aead_seal_packet(struct proxy_conn *c, uint32_t seq, const uint8_t *payload, size_t plen,
                      uint8_t *out_pkt);
void aead_epoch_switch(struct proxy_conn *c);

/* Derive a session key with an explicit epoch for rekeying.
 * This must be deterministic for both peers given PSK, token, conv, and epoch.
 * out_key[32] receives the session key. Returns 0 on success, -1 otherwise.
 */
int derive_session_key_epoch(const uint8_t psk[32], const uint8_t token16[16], uint32_t conv,
                             uint32_t epoch, uint8_t out_key[32]);

#ifdef __cplusplus
}
#endif

#endif /* PORTFWD_AEAD_H */
