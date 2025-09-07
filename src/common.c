#include "common.h"
#include <syslog.h>
#include <assert.h>
#include <sys/file.h>
#include <stdarg.h>
struct app_state g_state = {.daemonized = false};

/* Simple sanitizer: mask long hex-like sequences (potential keys) */
static void sanitize_message(char *dst, size_t dst_sz, const char *src) {
    if (!dst || dst_sz == 0) return;
    size_t di = 0;
    for (size_t i = 0; src && src[i] && di + 1 < dst_sz; ) {
        /* Detect sequences of >= 32 hex chars (likely sensitive) */
        size_t j = i;
        size_t hex_run = 0;
        while (src[j]) {
            char c = src[j];
            bool is_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!is_hex) break;
            hex_run++; j++;
        }
        if (hex_run >= 32) {
            const char *mask = "[REDACTED_HEX]";
            for (size_t k = 0; mask[k] && di + 1 < dst_sz; ++k) dst[di++] = mask[k];
            i += hex_run;
            continue;
        }
        dst[di++] = src[i++];
    }
    dst[di] = '\0';
}

void log_msg(int level, const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    char s_buf[1200];
    sanitize_message(s_buf, sizeof(s_buf), buf);

    if (g_state.daemonized) {
        syslog(level, "%s", s_buf);
    } else {
        fprintf(stderr, "%s\n", s_buf);
    }
}


void set_nonblock(int sockfd) {
    int flags;

    /* Set O_NONBLOCK */
    flags = fcntl(sockfd, F_GETFL, 0);
    if (flags >= 0) {
        if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
            P_LOG_WARN("fcntl(F_SETFL, O_NONBLOCK): %s", strerror(errno));
        }
    } else {
        P_LOG_WARN("fcntl(F_GETFL): %s", strerror(errno));
    }

    /* Set FD_CLOEXEC */
    flags = fcntl(sockfd, F_GETFD, 0);
    if (flags >= 0) {
        if (fcntl(sockfd, F_SETFD, flags | FD_CLOEXEC) < 0) {
            P_LOG_WARN("fcntl(F_SETFD, FD_CLOEXEC): %s", strerror(errno));
        }
    } else {
        P_LOG_WARN("fcntl(F_GETFD): %s", strerror(errno));
    }
}

void *addr_of_sockaddr(const union sockaddr_inx *addr) {
    assert(addr->sa.sa_family == AF_INET || addr->sa.sa_family == AF_INET6);
    if (addr->sa.sa_family == AF_INET6)
        return (void *)&addr->sin6.sin6_addr;
    return (void *)&addr->sin.sin_addr;
}

const unsigned short *port_of_sockaddr(const union sockaddr_inx *addr) {
    if (addr->sa.sa_family == AF_INET)
        return &addr->sin.sin_port;
    else
        return &addr->sin6.sin6_port;
}

size_t sizeof_sockaddr(const union sockaddr_inx *addr) {
    if (addr->sa.sa_family == AF_INET6)
        return sizeof(struct sockaddr_in6);
    return sizeof(struct sockaddr_in);
}

bool is_sockaddr_inx_equal(const union sockaddr_inx *a, const union sockaddr_inx *b) {
    if (a->sa.sa_family != b->sa.sa_family)
        return false;
    if (*port_of_sockaddr(a) != *port_of_sockaddr(b))
        return false;
    if (a->sa.sa_family == AF_INET) {
        return a->sin.sin_addr.s_addr == b->sin.sin_addr.s_addr;
    } else if (a->sa.sa_family == AF_INET6) {
        return a->sin6.sin6_scope_id == b->sin6.sin6_scope_id &&
               memcmp(&a->sin6.sin6_addr, &b->sin6.sin6_addr, sizeof(struct in6_addr)) == 0;
    }
    return false;
}

int get_sockaddr_inx_pair(const char *pair, union sockaddr_inx *sa, bool is_udp) {
    char s_addr[256];
    char *host = NULL, *port = NULL;
    struct addrinfo hints, *result = NULL;
    int rc;

    strncpy(s_addr, pair, sizeof(s_addr) - 1);
    s_addr[sizeof(s_addr) - 1] = '\0';

    char *last_colon = strrchr(s_addr, ':');
    char *bracket = strchr(s_addr, ']');

    if (s_addr[0] == '[' && bracket != NULL && bracket < last_colon) {
        /* IPv6 format: [host]:port */
        host = s_addr + 1;
        *bracket = '\0';
        port = last_colon + 1;
    } else if (last_colon != NULL && (bracket == NULL || last_colon > bracket)) {
        /* IPv4 or hostname format: host:port */
        host = s_addr;
        *last_colon = '\0';
        port = last_colon + 1;
        if (host == port - 1) { /* Bare port format: :port */
            host = NULL;
        }
    } else {
        /* No port found, treat the whole string as a port */
        host = NULL;
        port = s_addr;
    }

    if (port && *port) {
        char *end;
        long p = strtol(port, &end, 10);
        if (end == port || *end != '\0' || p < 1 || p > 65535) {
            P_LOG_ERR("Invalid port number '%s'. Must be between 1 and 65535.", port);
            return -EINVAL;
        }
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    /* Allow both numeric addresses and hostnames.
     * If host is NULL, use AI_PASSIVE for wildcard bind. */
    hints.ai_socktype = is_udp ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = 0;
    if (!host) {
        hints.ai_flags |= AI_PASSIVE;
    }

    rc = getaddrinfo(host, port, &hints, &result);
    if (rc != 0) {
        P_LOG_ERR("getaddrinfo(%s:%s): %s", host ? host : "<any>", port, gai_strerror(rc));
        return -EHOSTUNREACH;
    }

    memcpy(sa, result->ai_addr, result->ai_addrlen);
    freeaddrinfo(result);
    return 0;
}

void epoll_close_comp(int epfd) {
    if (epfd >= 0)
        close(epfd);
}

const char *sockaddr_to_string(const union sockaddr_inx *addr) {
    static char buf[128];
    if (!addr)
        return "(null)";
    void *a = addr_of_sockaddr(addr);
    unsigned short port = ntohs(*port_of_sockaddr(addr));
    char ip[96];
    ip[0] = '\0';
    if (addr->sa.sa_family == AF_INET6) {
        if (inet_ntop(AF_INET6, a, ip, sizeof(ip)) == NULL) {
            snprintf(ip, sizeof(ip), "?");
        }
        snprintf(buf, sizeof(buf), "[%s]:%hu", ip, port);
    } else if (addr->sa.sa_family == AF_INET) {
        if (inet_ntop(AF_INET, a, ip, sizeof(ip)) == NULL) {
            snprintf(ip, sizeof(ip), "?");
        }
        snprintf(buf, sizeof(buf), "%s:%hu", ip, port);
    } else {
        snprintf(buf, sizeof(buf), "(af=%d)", addr->sa.sa_family);
    }
    return buf;
}

int ep_del(int epfd, int sock) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    return epoll_ctl(epfd, EPOLL_CTL_DEL, sock, &ev);
}
