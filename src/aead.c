#include "aead.h"
#include <string.h>
#include "3rd/chacha20poly1305/chacha20poly1305.h"
#include "proxy_conn.h"
#include "common.h"
#include "kcptcp_common.h"
#include "anti_replay.h"

int derive_session_key_from_psk(const uint8_t psk[32],
                                const uint8_t token16[16], uint32_t conv,
                                uint8_t out_key[32]) {
    if (!psk || !token16 || !out_key)
        return -1;
    uint8_t nonce16[16];
    memcpy(nonce16, token16, 16);
    nonce16[12] ^= (uint8_t)(conv & 0xFF);
    nonce16[13] ^= (uint8_t)((conv >> 8) & 0xFF);
    nonce16[14] ^= (uint8_t)((conv >> 16) & 0xFF);
    nonce16[15] ^= (uint8_t)((conv >> 24) & 0xFF);
    hchacha20(psk, nonce16, out_key);
    return 0;
}

int derive_session_key_epoch(const uint8_t psk[32], const uint8_t token16[16],
                             uint32_t conv, uint32_t epoch,
                             uint8_t out_key[32]) {
    if (!psk || !token16 || !out_key)
        return -1;
    uint8_t nonce16[16];
    memcpy(nonce16, token16, 16);
    nonce16[12] ^= (uint8_t)(conv & 0xFF);
    nonce16[13] ^= (uint8_t)((conv >> 8) & 0xFF);
    nonce16[14] ^= (uint8_t)((conv >> 16) & 0xFF);
    nonce16[15] ^= (uint8_t)((conv >> 24) & 0xFF);
    nonce16[0] ^= (uint8_t)(epoch & 0xFF);
    nonce16[1] ^= (uint8_t)((epoch >> 8) & 0xFF);
    nonce16[2] ^= (uint8_t)((epoch >> 16) & 0xFF);
    nonce16[3] ^= (uint8_t)((epoch >> 24) & 0xFF);
    hchacha20(psk, nonce16, out_key);
    return 0;
}

void aead_gen_control_packet(unsigned char type, uint32_t seq,
                             const uint8_t *key, const uint8_t *nonce_base,
                             uint8_t *ad, uint8_t *out_pkt) {
    out_pkt[0] = type;
    out_pkt[1] = (uint8_t)seq;
    out_pkt[2] = (uint8_t)(seq >> 8);
    out_pkt[3] = (uint8_t)(seq >> 16);
    out_pkt[4] = (uint8_t)(seq >> 24);
    ad[0] = type;
    ad[1] = (uint8_t)seq;
    ad[2] = (uint8_t)(seq >> 8);
    ad[3] = (uint8_t)(seq >> 16);
    ad[4] = (uint8_t)(seq >> 24);

    uint8_t nonce[12];
    memcpy(nonce, nonce_base, 12);
    nonce[8] = (uint8_t)seq;
    nonce[9] = (uint8_t)(seq >> 8);
    nonce[10] = (uint8_t)(seq >> 16);
    nonce[11] = (uint8_t)(seq >> 24);

    chacha20poly1305_seal(key, nonce, ad, 5, NULL, 0, NULL, out_pkt + 5);
}

int aead_verify_packet(struct proxy_conn *c, uint8_t *data, int len,
                       uint32_t *out_seq) {
    if (len < 1 + 4 + 16)
        return -1;

    uint32_t seq = (uint32_t)data[1] | ((uint32_t)data[2] << 8) |
                   ((uint32_t)data[3] << 16) | ((uint32_t)data[4] << 24);
    *out_seq = seq;

    if (!anti_replay_check_and_update(&c->replay_detector, seq)) {
        return -1;
    }

    uint8_t ad[5];
    ad[0] = data[0];
    ad[1] = data[1];
    ad[2] = data[2];
    ad[3] = data[3];
    ad[4] = data[4];

    uint8_t nonce[12];
    memcpy(nonce, c->nonce_base, 12);
    nonce[8] = (uint8_t)seq;
    nonce[9] = (uint8_t)(seq >> 8);
    nonce[10] = (uint8_t)(seq >> 16);
    nonce[11] = (uint8_t)(seq >> 24);

    int plen = len - (1 + 4 + 16);
    uint8_t *payload = (plen > 0) ? data + 1 + 4 : NULL;

    if (chacha20poly1305_open(c->session_key, nonce, ad, 5, payload, plen,
                              data + 1 + 4 + plen, data) != 0) {
        return -1;
    }
    return plen;
}

int aead_verify_ack_packet(struct proxy_conn *c, uint8_t *data, int len) {
    if (len < 1 + 4 + 16)
        return -1;

    uint32_t seq = (uint32_t)data[1] | ((uint32_t)data[2] << 8) |
                   ((uint32_t)data[3] << 16) | ((uint32_t)data[4] << 24);

    uint8_t ad[5];
    ad[0] = data[0];
    ad[1] = data[1];
    ad[2] = data[2];
    ad[3] = data[3];
    ad[4] = data[4];

    uint8_t nonce[12];
    memcpy(nonce, c->next_nonce_base, 12);
    nonce[8] = (uint8_t)seq;
    nonce[9] = (uint8_t)(seq >> 8);
    nonce[10] = (uint8_t)(seq >> 16);
    nonce[11] = (uint8_t)(seq >> 24);

    if (chacha20poly1305_open(c->next_session_key, nonce, ad, 5, NULL, 0,
                              data + 5, data) != 0) {
        return -1;
    }
    return 0;
}

void aead_epoch_switch(struct proxy_conn *c) {
    memcpy(c->session_key, c->next_session_key, 32);
    memcpy(c->nonce_base, c->next_nonce_base, 12);
    c->epoch = c->next_epoch;
    c->rekey_in_progress = false;
}

void aead_seal_packet(struct proxy_conn *c, uint32_t seq,
                      const uint8_t *payload, size_t plen, uint8_t *out_pkt) {
    out_pkt[0] = KTP_EDATA;
    out_pkt[1] = (uint8_t)seq;
    out_pkt[2] = (uint8_t)(seq >> 8);
    out_pkt[3] = (uint8_t)(seq >> 16);
    out_pkt[4] = (uint8_t)(seq >> 24);

    uint8_t ad[5];
    ad[0] = KTP_EDATA;
    ad[1] = (uint8_t)seq;
    ad[2] = (uint8_t)(seq >> 8);
    ad[3] = (uint8_t)(seq >> 16);
    ad[4] = (uint8_t)(seq >> 24);

    uint8_t nonce[12];
    memcpy(nonce, c->nonce_base, 12);
    nonce[8] = (uint8_t)seq;
    nonce[9] = (uint8_t)(seq >> 8);
    nonce[10] = (uint8_t)(seq >> 16);
    nonce[11] = (uint8_t)(seq >> 24);

    chacha20poly1305_seal(c->session_key, nonce, ad, 5, payload, plen,
                          out_pkt + 1 + 4, out_pkt + 1 + 4 + plen);
}
