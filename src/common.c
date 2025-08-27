#include "common.h"
#include <syslog.h>
#include <assert.h>
#include <sys/file.h>

struct app_state g_state = {
    .pidfile = NULL,
    .pidfile_fd = -1,
    .terminate = 0,
    .daemonized = false
};

void on_signal(int sig) {
    (void)sig;
    g_state.terminate = 1;
}

void cleanup_pidfile(void) {
    if (g_state.pidfile_fd >= 0) {
        if (close(g_state.pidfile_fd) < 0) {
            P_LOG_WARN("close(pidfile): %s", strerror(errno));
        }
        g_state.pidfile_fd = -1;
    }
    if (g_state.pidfile) {
        unlink(g_state.pidfile);
    }
}

int write_pidfile(const char *filepath) {
    char buf[32];
    ssize_t wlen;
    pid_t pid = getpid();

    g_state.pidfile = filepath;

    g_state.pidfile_fd = open(filepath, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (g_state.pidfile_fd < 0) {
        if (errno != EEXIST) {
            P_LOG_ERR("open(%s) exclusively: %s", filepath, strerror(errno));
            return -1;
        }
        /* File exists, try to open and lock it */
        g_state.pidfile_fd = open(filepath, O_WRONLY, 0644);
        if (g_state.pidfile_fd < 0) {
            P_LOG_ERR("open(%s) for locking: %s", filepath, strerror(errno));
            return -1;
        }
    }

    int flags = fcntl(g_state.pidfile_fd, F_GETFD, 0);
    if (flags != -1) {
        fcntl(g_state.pidfile_fd, F_SETFD, flags | FD_CLOEXEC);
    }

    if (flock(g_state.pidfile_fd, LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK) {
            P_LOG_ERR("pidfile %s exists and is locked, another instance running?", filepath);
        } else {
            P_LOG_ERR("flock(%s): %s", filepath, strerror(errno));
        }
        close(g_state.pidfile_fd);
        g_state.pidfile_fd = -1;
        return -1;
    }

    if (ftruncate(g_state.pidfile_fd, 0) < 0) {
        P_LOG_ERR("ftruncate(%s): %s", filepath, strerror(errno));
        close(g_state.pidfile_fd);
        g_state.pidfile_fd = -1;
        return -1;
    }

    int len = snprintf(buf, sizeof(buf), "%d\n", (int)pid);
    if (len < 0 || len >= (int)sizeof(buf)) {
        P_LOG_ERR("snprintf(pid) failed.");
        close(g_state.pidfile_fd);
        g_state.pidfile_fd = -1;
        return -1;
    }
    wlen = write(g_state.pidfile_fd, buf, (size_t)len);
    if (wlen != len) {
        P_LOG_ERR("write(%s): %s", filepath, strerror(errno));
        close(g_state.pidfile_fd);
        g_state.pidfile_fd = -1;
        return -1;
    }

    atexit(cleanup_pidfile);
    return 0;
}

int do_daemonize(void) {
    int rc;

    if ((rc = fork()) < 0) {
        P_LOG_ERR("fork() error: %s.", strerror(errno));
        return rc;
    } else if (rc > 0) {
        /* In parent process */
        exit(0);
    } else {
        /* In child process */
        int fd;
        setsid();
        fd = open("/dev/null", O_RDONLY);
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2) {
            if (close(fd) < 0) {
                P_LOG_WARN("close(/dev/null): %s", strerror(errno));
            }
        }
        chdir("/");
        g_state.daemonized = true;
    }
    return 0;
}

void setup_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
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

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags |= AI_NUMERICHOST;
    hints.ai_socktype = is_udp ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = 0;
    if (!host) {
        hints.ai_flags = AI_PASSIVE;
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
    if (!addr) return "(null)";
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
