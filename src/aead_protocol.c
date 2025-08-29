#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <syslog.h>

#include "common.h"
#include "proxy_conn.h"
#include "kcp_common.h"
#include "kcptcp_common.h"
#include "aead.h"
#include "3rd/chacha20poly1305/chacha20poly1305.h"
#include "3rd/kcp/ikcp.h"
#include "aead_protocol.h"

static int send_rekey_init(struct proxy_conn *c, const uint8_t *psk);

static int trigger_rekey_if_needed(struct proxy_conn *c, const uint8_t *psk) {
    if (!c->has_session_key || !psk || c->rekey_in_progress ||
        c->send_seq < REKEY_SEQ_THRESHOLD) {
        return 0;
    }
    return send_rekey_init(c, psk);
}

static int send_rekey_init(struct proxy_conn *c, const uint8_t *psk) {
    c->next_epoch = c->epoch + 1;
    if (derive_session_key_epoch(psk, c->hs_token, c->conv, c->next_epoch,
                                 c->next_session_key) != 0) {
        return -1;
    }
    memcpy(c->next_nonce_base, c->next_session_key, 12);
    c->rekey_in_progress = true;
    c->rekey_deadline_ms = kcp_now_ms() + REKEY_TIMEOUT_MS;

    uint32_t seq;
    if (!aead_next_send_seq(c, &seq)) {
        P_LOG_ERR("send_seq wraparound guard hit, closing conv=%u", c->conv);
        return -1;
    }

    uint8_t ad[5];
    unsigned char pkt[1 + 4 + 16];
    aead_gen_control_packet(KTP_REKEY_INIT, seq, c->session_key, c->nonce_base,
                            ad, pkt);

    if (ikcp_send(c->kcp, (const char *)pkt, sizeof(pkt)) < 0) {
        return -1;
    }
    c->rekeys_initiated++;
    return 0;
}

int aead_protocol_handle_incoming_packet(struct proxy_conn *c, char *data,
                                         int len, const uint8_t *psk,
                                         bool has_psk, char **out_payload,
                                         int *out_plen) {
    if (len < 1)
        return 0;
    unsigned char t = (unsigned char)data[0];

    *out_payload = NULL;
    *out_plen = 0;

    if (has_psk && (t == KTP_DATA || t == KTP_FIN)) {
        P_LOG_ERR("Plaintext packet type %d in encrypted session conv=%u",
                  (int)t, c->conv);
        return -1;
    }

    if (!has_psk) {
        if (t == KTP_DATA) {
            *out_payload = data + 1;
            *out_plen = len - 1;
        } else if (t == KTP_FIN) {
            c->svr_in_eof = true;
            return 1; // Handled control packet
        }
        return 0;
    }

    // From here, has_psk is true
    uint32_t seq;
    int verified = aead_verify_packet(c, (uint8_t *)data, len, &seq);
    if (verified < 0) {
        P_LOG_WARN("Packet verification failed for type %d, len %d", (int)t,
                   len);
        return (t == KTP_EDATA) ? 0 : -1; // Drop data, close on control failure
    }

    switch (t) {
    case KTP_EDATA:
        *out_payload = data;
        *out_plen = verified;
        return 0; // Data packet

    case KTP_EFIN:
        c->svr_in_eof = true;
        return 1; // Handled control packet

    case KTP_REKEY_INIT: {
        if (!c->rekey_in_progress) {
            c->next_epoch = c->epoch + 1;
            if (derive_session_key_epoch(psk, c->hs_token, c->conv,
                                         c->next_epoch,
                                         c->next_session_key) != 0) {
                return -1;
            }
            memcpy(c->next_nonce_base, c->next_session_key, 12);
            c->rekey_in_progress = true;
        }

        unsigned char ack_pkt[1 + 4 + 16];
        uint8_t ack_ad[5];
        aead_gen_control_packet(KTP_REKEY_ACK, seq, c->next_session_key,
                                c->next_nonce_base, ack_ad, ack_pkt);
        ikcp_send(c->kcp, (const char *)ack_pkt, sizeof(ack_pkt));

        // Switch to next epoch immediately
        aead_epoch_switch(c);
        c->rekeys_completed++;
        P_LOG_INFO("epoch switch conv=%u -> epoch=%u", c->conv, c->epoch);
        return 1;
    }

    case KTP_REKEY_ACK: {
        if (!c->rekey_in_progress)
            return 1; // Ignore spurious ACK
        int verified_ack = aead_verify_ack_packet(c, (uint8_t *)data, len);
        if (verified_ack < 0) {
            P_LOG_ERR("REKEY_ACK tag verify failed");
            return -1;
        }
        aead_epoch_switch(c);
        c->rekeys_completed++;
        P_LOG_INFO("epoch switch conv=%u -> epoch=%u", c->conv, c->epoch);
        return 1;
    }

    default:
        P_LOG_WARN("Unhandled packet type %d in AEAD mode", (int)t);
        break;
    }
    return 0;
}

int aead_protocol_send_data(struct proxy_conn *c, const char *data, int len,
                            const uint8_t *psk, bool has_psk) {
    if (!has_psk) {
        char *buf = (char *)malloc(len + 1);
        if (!buf)
            return -1;
        buf[0] = (unsigned char)KTP_DATA;
        memcpy(buf + 1, data, len);
        int ret = ikcp_send(c->kcp, buf, len + 1);
        free(buf);
        return ret;
    }

    if (trigger_rekey_if_needed(c, psk) != 0) {
        return -1;
    }

    size_t pkt_len = 1 + 4 + len + 16;
    char *buf = (char *)malloc(pkt_len);
    if (!buf)
        return -1;

    uint32_t seq;
    if (!aead_next_send_seq(c, &seq)) {
        free(buf);
        return -1;
    }

    aead_seal_packet(c, seq, (const uint8_t *)data, len, (uint8_t *)buf);

    int ret = ikcp_send(c->kcp, buf, pkt_len);
    if (ret >= 0) {
        c->kcp_tx_msgs++;
        c->kcp_tx_bytes += (uint64_t)len;
    }
    free(buf);
    return ret;
}

int aead_protocol_send_fin(struct proxy_conn *c, const uint8_t *psk,
                           bool has_psk) {
    if (!has_psk) {
        unsigned char fin = (unsigned char)KTP_FIN;
        return ikcp_send(c->kcp, (const char *)&fin, 1);
    }

    if (trigger_rekey_if_needed(c, psk) != 0) {
        return -1;
    }

    uint32_t seq;
    if (!aead_next_send_seq(c, &seq)) {
        return -1;
    }

    uint8_t pkt[1 + 4 + 16];
    uint8_t ad[5];
    aead_gen_control_packet(KTP_EFIN, seq, c->session_key, c->nonce_base, ad,
                            pkt);

    int ret = ikcp_send(c->kcp, (const char *)pkt, sizeof(pkt));
    if (ret >= 0) {
        c->kcp_tx_msgs++;
    }
    return ret;
}
