#include "kcptcp_common.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h> /* getopt */
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <netinet/tcp.h>
#endif
#include "common.h"
#include "3rd/kcp/ikcp.h"
#include "3rd/chacha20poly1305/chacha20poly1305.h"
#include "secure_random.h"

/* Env-controlled stats helpers */
uint32_t get_stats_interval_ms(void) {
    static uint32_t cached = 0; /* 0 => uninitialized */
    if (cached == 0) {
        const char *s = getenv("PFWD_STATS_INTERVAL_MS");
        long v = s ? strtol(s, NULL, 10) : 0;
        if (v <= 0)
            v = 5000; /* default 5s */
        if (v < 100)
            v = 100; /* clamp */
        if (v > 600000)
            v = 600000; /* 10 minutes */
        cached = (uint32_t)v;
    }
    return cached;
}

void kcptcp_tune_tcp_socket(int fd, int sockbuf_bytes, bool tcp_nodelay,
                            bool keepalive) {
    if (fd < 0)
        return;
    set_nonblock(fd);
    set_sock_buffers_sz(fd, sockbuf_bytes);
    if (keepalive) {
        int yes = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
    }
#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    if (tcp_nodelay) {
        int one = 1;
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
#else
    (void)tcp_nodelay;
#endif
}

void kcp_opts_apply_overrides(struct kcp_opts *o, int mtu, int nd, int it,
                              int rs, int nc, int snd, int rcv) {
    if (mtu > 0)
        o->mtu = mtu;
    if (nd >= 0)
        o->nodelay = nd;
    if (it >= 0)
        o->interval_ms = it;
    if (rs >= 0)
        o->resend = rs;
    if (nc >= 0)
        o->nc = nc;
    if (snd >= 0)
        o->sndwnd = snd;
    if (rcv >= 0)
        o->rcvwnd = rcv;
}

int kcptcp_compute_kcp_timeout_ms(struct list_head *conns, int default_ms) {
    int timeout_ms = default_ms;
    uint32_t now = kcp_now_ms();
    struct proxy_conn *pc;
    list_for_each_entry(pc, conns, list) {
        if (!pc->kcp)
            continue;
        uint32_t due = ikcp_check(pc->kcp, now);
        int t = (int)((due > now) ? (due - now) : 0);
        if (t < timeout_ms)
            timeout_ms = t;
    }
    return timeout_ms;
}

int kcptcp_ep_register(int epfd, int fd, void *ptr, uint32_t base_events,
                       uint32_t extra_events) {
    struct epoll_event ev = {0};
    ev.events = base_events | extra_events;
    ev.data.ptr = ptr;
    return ep_add_or_mod(epfd, fd, &ev);
}

bool get_stats_dump_enabled(void) {
    const char *s = getenv("PFWD_STATS_DUMP");
    if (!s)
        return false;
    return !(s[0] == '0');
}

bool get_stats_enabled(void) {
    const char *s = getenv("PFWD_STATS_ENABLE");
    if (!s)
        return true; /* default enabled */
    return !(s[0] == '0');
}

void set_sock_buffers_sz(int sockfd, int bytes) {
    if (bytes <= 0)
        return;
    (void)setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes));
    (void)setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
}

static int hex2nibble(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

bool parse_psk_hex32(const char *hex, uint8_t out[32]) {
    size_t n = strlen(hex);
    if (n != 64)
        return false;
    for (size_t i = 0; i < 32; ++i) {
        int hi = hex2nibble(hex[2 * i]);
        int lo = hex2nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/* Anti-replay helpers (sliding window, 64 entries) */
static inline int32_t seq_diff_u32(uint32_t a, uint32_t b) {
    return (int32_t)(a - b);
}

bool aead_replay_check_and_update(uint32_t seq, uint32_t *p_win,
                                  uint64_t *p_mask) {
    uint32_t win = *p_win;
    uint64_t mask = *p_mask;
    if (win == UINT32_MAX) {
        *p_win = seq;
        *p_mask = 1ULL;
        return true;
    }
    int32_t d = seq_diff_u32(seq, win);
    if (d > 0) {
        uint32_t shift = (d >= 64) ? 64u : (uint32_t)d;
        mask = (shift >= 64) ? 0ULL : (mask << shift);
        mask |= 1ULL;
        win = seq;
        *p_win = win;
        *p_mask = mask;
        return true;
    }
    int32_t behind = -d;
    if (behind >= 64)
        return false;
    uint64_t bit = 1ULL << behind;
    if (mask & bit)
        return false; /* replay */
    mask |= bit;
    *p_win = win;
    *p_mask = mask;
    return true;
}

bool aead_next_send_seq(struct proxy_conn *c, uint32_t *out_seq) {
    if (c->send_seq == UINT32_MAX)
        return false;
    *out_seq = c->send_seq++;
    return true;
}

/* Socket setup helpers */
int kcptcp_setup_tcp_listener(const union sockaddr_inx *addr, bool reuse_addr,
                              bool reuse_port, bool v6only, int sockbuf_bytes,
                              int backlog) {
    int fd = -1;
    fd = socket(addr->sa.sa_family, SOCK_STREAM, 0);
    if (fd < 0) {
        P_LOG_ERR("socket(listen): %s", strerror(errno));
        return -1;
    }
    if (reuse_addr) {
        int on = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    }
#ifdef SO_REUSEPORT
    if (reuse_port) {
        int on = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
    }
#endif
#ifdef IPV6_V6ONLY
    if (v6only && addr->sa.sa_family == AF_INET6) {
        int on = 1;
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
    }
#endif
    set_nonblock(fd);
    set_sock_buffers_sz(fd, sockbuf_bytes);
    if (bind(fd, &((const union sockaddr_inx *)addr)->sa,
             (socklen_t)sizeof_sockaddr(addr)) < 0) {
        P_LOG_ERR("bind(listen): %s", strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, backlog) < 0) {
        P_LOG_ERR("listen: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int kcptcp_setup_udp_listener(const union sockaddr_inx *addr, bool reuse_addr,
                              bool reuse_port, bool v6only, int sockbuf_bytes) {
    int fd = -1;
    fd = socket(addr->sa.sa_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        P_LOG_ERR("socket(udp): %s", strerror(errno));
        return -1;
    }
    if (reuse_addr) {
        int on = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    }
#ifdef SO_REUSEPORT
    if (reuse_port) {
        int on = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
    }
#endif
#ifdef IPV6_V6ONLY
    if (v6only && addr->sa.sa_family == AF_INET6) {
        int on = 1;
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
    }
#endif
    set_nonblock(fd);
    set_sock_buffers_sz(fd, sockbuf_bytes);
    if (bind(fd, &((const union sockaddr_inx *)addr)->sa,
             (socklen_t)sizeof_sockaddr(addr)) < 0) {
        P_LOG_ERR("bind(udp): %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int kcptcp_create_udp_socket(int family, int sockbuf_bytes) {
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) {
        P_LOG_ERR("socket(udp): %s", strerror(errno));
        return -1;
    }
    set_nonblock(fd);
    set_sock_buffers_sz(fd, sockbuf_bytes);
    return fd;
}

int kcptcp_create_tcp_socket(int family, int sockbuf_bytes, bool tcp_nodelay) {
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) {
        P_LOG_ERR("socket(tcp): %s", strerror(errno));
        return -1;
    }
    set_nonblock(fd);
    set_sock_buffers_sz(fd, sockbuf_bytes);
#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    if (tcp_nodelay) {
        int one = 1;
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
#else
    (void)tcp_nodelay;
#endif
    return fd;
}

/* ---------------- Common CLI parsing (shared) ---------------- */
int kcptcp_parse_common_opts(int argc, char **argv,
                             struct kcptcp_common_cli *out, int *pos_start,
                             bool is_server) {
    (void)is_server; /* currently unused, reserved for divergence */
    if (!out)
        return 0;
    memset(out, 0, sizeof(*out));
    out->reuse_addr = false;
    out->reuse_port = false;
    out->v6only = false;
    out->sockbuf_bytes = 0;
    out->tcp_nodelay = false;
    out->has_psk = false;
    out->kcp_mtu = 0; /* only apply if >0 */
    out->kcp_nd = -1; /* apply if >=0 */
    out->kcp_it = -1;
    out->kcp_rs = -1;
    out->kcp_nc = -1;
    out->kcp_snd = -1;
    out->kcp_rcv = -1;
    out->show_help = false;

    /* reset getopt state */
    optind = 1;

    int opt;
    /* Options:
       -d (daemonize)
       -p <pidfile>
       -r (SO_REUSEADDR)
       -R (SO_REUSEPORT)
       -6 (IPV6_V6ONLY)
       -b <bytes> (socket buffers)
       -N (TCP_NODELAY)
       -K <hex32> (PSK)
       -M <mtu> (KCP mtu)
       -n <0|1> (KCP nodelay)
       -I <ms> (KCP interval)
       -X <n> (KCP fast resend)
       -C <0|1> (KCP no congestion)
       -w <sndwnd>
       -W <rcvwnd>
       -h (help)
    */
    while ((opt = getopt(argc, argv, "dp:rR6b:NK:M:n:I:X:C:w:W:h")) != -1) {
        switch (opt) {
        case 'd':
            out->daemonize = true;
            break;
        case 'p':
            out->pidfile = optarg;
            break;
        case 'r':
            out->reuse_addr = true;
            break;
        case 'R':
            out->reuse_port = true;
            break;
        case '6':
            out->v6only = true;
            break;
        case 'b': {
            long v = strtol(optarg, NULL, 10);
            if (v < 0)
                return 0;
            out->sockbuf_bytes = (int)v;
            break;
        }
        case 'N':
            out->tcp_nodelay = true;
            break;
        case 'K': {
            if (!parse_psk_hex32(optarg, out->psk))
                return 0;
            out->has_psk = true;
            break;
        }
        case 'M': {
            long v = strtol(optarg, NULL, 10);
            if (v <= 0)
                return 0;
            out->kcp_mtu = (int)v;
            break;
        }
        case 'n': {
            long v = strtol(optarg, NULL, 10);
            if (v < 0)
                return 0;
            out->kcp_nd = (int)v;
            break;
        }
        case 'I': {
            long v = strtol(optarg, NULL, 10);
            if (v < 0)
                return 0;
            out->kcp_it = (int)v;
            break;
        }
        case 'X': {
            long v = strtol(optarg, NULL, 10);
            if (v < 0)
                return 0;
            out->kcp_rs = (int)v;
            break;
        }
        case 'C': {
            long v = strtol(optarg, NULL, 10);
            if (v < 0)
                return 0;
            out->kcp_nc = (int)v;
            break;
        }
        case 'w': {
            long v = strtol(optarg, NULL, 10);
            if (v < 0)
                return 0;
            out->kcp_snd = (int)v;
            break;
        }
        case 'W': {
            long v = strtol(optarg, NULL, 10);
            if (v < 0)
                return 0;
            out->kcp_rcv = (int)v;
            break;
        }
        case 'h':
            out->show_help = true;
            break;
        default:
            return 0;
        }
    }
    if (pos_start)
        *pos_start = optind;
    return 1;
}

/* ---------------- Stealth Handshake Implementation ---------------- */

/* Create first packet with embedded stealth handshake */
int stealth_handshake_create_first_packet(const uint8_t *psk, const uint8_t *token,
                                          const uint8_t *initial_data, size_t initial_data_len,
                                          uint8_t *out_packet, size_t *out_packet_len) {
    if (!psk || !token || !out_packet || !out_packet_len) {
        return -1;
    }

    /* Create handshake payload */
    struct stealth_handshake_payload payload;
    payload.magic = htonl(STEALTH_HANDSHAKE_MAGIC);
    payload.timestamp = htonl((uint32_t)time(NULL));
    memcpy(payload.token, token, 16);

    /* Generate random nonce */
    if (secure_random_bytes((uint8_t *)&payload.nonce, sizeof(payload.nonce)) != 0) {
        return -1;
    }

    /* Fill reserved field with random data */
    if (secure_random_bytes(payload.reserved, sizeof(payload.reserved)) != 0) {
        return -1;
    }

    /* Calculate total packet size: payload + initial_data + some random padding */
    size_t padding_size = 16 + (rand() % 32); /* 16-47 bytes random padding */
    size_t total_size = sizeof(payload) + initial_data_len + padding_size;

    if (total_size > *out_packet_len) {
        return -1; /* Buffer too small */
    }

    /* Create plaintext: payload + initial_data + padding */
    uint8_t *plaintext = malloc(total_size);
    if (!plaintext) {
        return -1;
    }

    memcpy(plaintext, &payload, sizeof(payload));
    if (initial_data && initial_data_len > 0) {
        memcpy(plaintext + sizeof(payload), initial_data, initial_data_len);
    }

    /* Fill padding with random data */
    if (secure_random_bytes(plaintext + sizeof(payload) + initial_data_len, padding_size) != 0) {
        free(plaintext);
        return -1;
    }

    /* Generate random nonce for encryption */
    uint8_t nonce[12];
    if (secure_random_bytes(nonce, sizeof(nonce)) != 0) {
        free(plaintext);
        return -1;
    }

    /* Encrypt the entire packet using ChaCha20-Poly1305 */
    uint8_t tag[16];
    chacha20poly1305_seal(psk, nonce, NULL, 0, plaintext, total_size, out_packet + 12, tag);

    /* Prepend nonce to the packet */
    memcpy(out_packet, nonce, 12);
    memcpy(out_packet + 12 + total_size, tag, 16);

    *out_packet_len = 12 + total_size + 16; /* nonce + ciphertext + tag */

    free(plaintext);
    return 0;
}

/* Parse first packet and extract stealth handshake payload */
int stealth_handshake_parse_first_packet(const uint8_t *psk, const uint8_t *packet, size_t packet_len,
                                        struct stealth_handshake_payload *payload,
                                        uint8_t *out_data, size_t *out_data_len) {
    if (!psk || !packet || !payload || packet_len < 28) { /* 12 nonce + 16 tag minimum */
        return -1;
    }

    /* Extract nonce and tag */
    const uint8_t *nonce = packet;
    const uint8_t *ciphertext = packet + 12;
    size_t ciphertext_len = packet_len - 28; /* Total - nonce - tag */
    const uint8_t *tag = packet + 12 + ciphertext_len;

    /* Decrypt the packet */
    uint8_t *plaintext = malloc(ciphertext_len);
    if (!plaintext) {
        return -1;
    }

    if (chacha20poly1305_open(psk, nonce, NULL, 0, ciphertext, ciphertext_len, tag, plaintext) != 0) {
        free(plaintext);
        return -1; /* Decryption failed - not a valid stealth handshake */
    }

    /* Check if we have enough data for the payload */
    if (ciphertext_len < sizeof(struct stealth_handshake_payload)) {
        free(plaintext);
        return -1;
    }

    /* Extract and validate payload */
    memcpy(payload, plaintext, sizeof(struct stealth_handshake_payload));

    /* Validate magic number */
    if (ntohl(payload->magic) != STEALTH_HANDSHAKE_MAGIC) {
        free(plaintext);
        return -1; /* Not a stealth handshake packet */
    }

    /* Validate timestamp (allow 5 minutes skew) */
    time_t now = time(NULL);
    time_t msg_time = (time_t)ntohl(payload->timestamp);
    if (msg_time < now - 300 || msg_time > now + 300) {
        free(plaintext);
        return -1; /* Timestamp out of range */
    }

    /* Extract any additional data after the payload */
    size_t remaining_len = ciphertext_len - sizeof(struct stealth_handshake_payload);
    if (out_data && out_data_len && remaining_len > 0) {
        size_t copy_len = remaining_len < *out_data_len ? remaining_len : *out_data_len;
        memcpy(out_data, plaintext + sizeof(struct stealth_handshake_payload), copy_len);
        *out_data_len = copy_len;
    } else if (out_data_len) {
        *out_data_len = 0;
    }

    free(plaintext);
    return 0;
}

/* Create stealth handshake response */
int stealth_handshake_create_response(const uint8_t *psk, uint32_t conv, const uint8_t *token,
                                     uint8_t *out_packet, size_t *out_packet_len) {
    if (!psk || !token || !out_packet || !out_packet_len) {
        return -1;
    }

    /* Create response payload */
    struct stealth_handshake_response response;
    response.magic = htonl(STEALTH_RESPONSE_MAGIC);
    response.conv = htonl(conv);
    memcpy(response.token, token, 16);
    response.timestamp = htonl((uint32_t)time(NULL));

    /* Fill reserved field with random data */
    if (secure_random_bytes(response.reserved, sizeof(response.reserved)) != 0) {
        return -1;
    }

    /* Add some random padding to make it look like normal data */
    size_t padding_size = 8 + (rand() % 24); /* 8-31 bytes random padding */
    size_t total_size = sizeof(response) + padding_size;

    if (total_size + 28 > *out_packet_len) { /* +28 for nonce and tag */
        return -1; /* Buffer too small */
    }

    /* Create plaintext: response + padding */
    uint8_t *plaintext = malloc(total_size);
    if (!plaintext) {
        return -1;
    }

    memcpy(plaintext, &response, sizeof(response));
    if (secure_random_bytes(plaintext + sizeof(response), padding_size) != 0) {
        free(plaintext);
        return -1;
    }

    /* Generate random nonce for encryption */
    uint8_t nonce[12];
    if (secure_random_bytes(nonce, sizeof(nonce)) != 0) {
        free(plaintext);
        return -1;
    }

    /* Encrypt the response */
    uint8_t tag[16];
    chacha20poly1305_seal(psk, nonce, NULL, 0, plaintext, total_size, out_packet + 12, tag);

    /* Prepend nonce and append tag */
    memcpy(out_packet, nonce, 12);
    memcpy(out_packet + 12 + total_size, tag, 16);

    *out_packet_len = 12 + total_size + 16; /* nonce + ciphertext + tag */

    free(plaintext);
    return 0;
}

/* Parse stealth handshake response */
int stealth_handshake_parse_response(const uint8_t *psk, const uint8_t *packet, size_t packet_len,
                                    struct stealth_handshake_response *response) {
    if (!psk || !packet || !response || packet_len < 28) { /* 12 nonce + 16 tag minimum */
        return -1;
    }

    /* Extract nonce and tag */
    const uint8_t *nonce = packet;
    const uint8_t *ciphertext = packet + 12;
    size_t ciphertext_len = packet_len - 28; /* Total - nonce - tag */
    const uint8_t *tag = packet + 12 + ciphertext_len;

    /* Decrypt the packet */
    uint8_t *plaintext = malloc(ciphertext_len);
    if (!plaintext) {
        return -1;
    }

    if (chacha20poly1305_open(psk, nonce, NULL, 0, ciphertext, ciphertext_len, tag, plaintext) != 0) {
        free(plaintext);
        return -1; /* Decryption failed */
    }

    /* Check if we have enough data for the response */
    if (ciphertext_len < sizeof(struct stealth_handshake_response)) {
        free(plaintext);
        return -1;
    }

    /* Extract and validate response */
    memcpy(response, plaintext, sizeof(struct stealth_handshake_response));

    /* Validate magic number */
    if (ntohl(response->magic) != STEALTH_RESPONSE_MAGIC) {
        free(plaintext);
        return -1; /* Not a stealth handshake response */
    }

    /* Validate timestamp (allow 5 minutes skew) */
    time_t now = time(NULL);
    time_t msg_time = (time_t)ntohl(response->timestamp);
    if (msg_time < now - 300 || msg_time > now + 300) {
        free(plaintext);
        return -1; /* Timestamp out of range */
    }

    free(plaintext);
    return 0;
}
