#include "common.h"
#include <syslog.h>
#include <assert.h>
#include <sys/file.h>

const char *g_pidfile = NULL;
static int g_pidfile_fd = -1;
volatile sig_atomic_t g_terminate = 0;
bool g_daemonized = false;

void on_signal(int sig)
{
    (void)sig;
    g_terminate = 1;
}

void cleanup_pidfile(void)
{
    if (g_pidfile_fd >= 0) {
        close(g_pidfile_fd);
        g_pidfile_fd = -1;
    }
    if (g_pidfile) {
        unlink(g_pidfile);
    }
}

void write_pidfile(const char *filepath)
{
    char buf[32];
    ssize_t wlen;
    pid_t pid = getpid();

    g_pidfile_fd = open(filepath, O_WRONLY | O_CREAT, 0644);
    if (g_pidfile_fd < 0) {
        P_LOG_ERR("open(%s): %s", filepath, strerror(errno));
        exit(1);
    }

    if (flock(g_pidfile_fd, LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK) {
            P_LOG_ERR("pidfile %s exists and is locked, another instance running?", filepath);
        } else {
            P_LOG_ERR("flock(%s): %s", filepath, strerror(errno));
        }
        close(g_pidfile_fd);
        exit(1);
    }

    if (ftruncate(g_pidfile_fd, 0) < 0) {
        P_LOG_ERR("ftruncate(%s): %s", filepath, strerror(errno));
        close(g_pidfile_fd);
        exit(1);
    }

    int len = snprintf(buf, sizeof(buf), "%d\n", (int)pid);
    if (len < 0 || len >= (int)sizeof(buf)) {
        P_LOG_ERR("snprintf(pid) failed.");
        close(g_pidfile_fd);
        exit(1);
    }
    wlen = write(g_pidfile_fd, buf, (size_t)len);
    if (wlen != len) {
        int saved = errno;
        P_LOG_ERR("write(%s): %s", filepath, strerror(saved));
        close(g_pidfile_fd);
        exit(1);
    }

    atexit(cleanup_pidfile);
}

int do_daemonize(void)
{
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
        if (fd > 2)
            close(fd);
        chdir("/");
        g_daemonized = true;
    }
    return 0;
}

void setup_signal_handlers(void)
{
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

void set_nonblock(int sockfd)
{
    int flags;

    /* Set O_NONBLOCK */
    flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        P_LOG_WARN("fcntl(F_GETFL): %s", strerror(errno));
        /* continue and try to set CLOEXEC anyway */
    } else {
        if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
            P_LOG_WARN("fcntl(F_SETFL,O_NONBLOCK): %s", strerror(errno));
        }
    }

    /* Set FD_CLOEXEC */
    flags = fcntl(sockfd, F_GETFD, 0);
    if (flags < 0) {
        P_LOG_WARN("fcntl(F_GETFD): %s", strerror(errno));
        return;
    }
    if (fcntl(sockfd, F_SETFD, flags | FD_CLOEXEC) < 0) {
        P_LOG_WARN("fcntl(F_SETFD,FD_CLOEXEC): %s", strerror(errno));
    }
}

void *addr_of_sockaddr(const union sockaddr_inx *addr)
{
    assert(addr->sa.sa_family == AF_INET || addr->sa.sa_family == AF_INET6);
    if (addr->sa.sa_family == AF_INET6)
        return (void *)&addr->sin6.sin6_addr;
    return (void *)&addr->sin.sin_addr;
}

const unsigned short *port_of_sockaddr(const union sockaddr_inx *addr)
{
    if (addr->sa.sa_family == AF_INET)
        return &addr->sin.sin_port;
    else
        return &addr->sin6.sin6_port;
}

size_t sizeof_sockaddr(const union sockaddr_inx *addr)
{
    if (addr->sa.sa_family == AF_INET6)
        return sizeof(struct sockaddr_in6);
    return sizeof(struct sockaddr_in);
}

bool is_sockaddr_inx_equal(const union sockaddr_inx *a, const union sockaddr_inx *b)
{
    if (a->sa.sa_family != b->sa.sa_family)
        return false;
    if (*port_of_sockaddr(a) != *port_of_sockaddr(b))
        return false;
    if (a->sa.sa_family == AF_INET) {
        return a->sin.sin_addr.s_addr == b->sin.sin_addr.s_addr;
    } else if (a->sa.sa_family == AF_INET6) {
        return memcmp(&a->sin6.sin6_addr, &b->sin6.sin6_addr, sizeof(struct in6_addr)) == 0;
    }
    return false;
}

int get_sockaddr_inx_pair(const char *pair, union sockaddr_inx *sa, bool is_udp)
{
    char s_addr[256];
    char *host = NULL, *port = NULL;
    struct addrinfo hints, *result = NULL;
    int rc;

    strncpy(s_addr, pair, sizeof(s_addr) - 1);
    s_addr[sizeof(s_addr) - 1] = '\0';

    if (s_addr[0] == '[') {
        /* IPv6 address literal */
        host = s_addr + 1;
        port = strchr(host, ']');
        if (!port) {
            return -EINVAL; /* Unmatched '[' */
        }
        *port = '\0'; /* Terminate host */
        port++; /* Move to char after ']' */
        if (*port != ':' && *port != '\0') {
            return -EINVAL; /* Must be ':' or end of string */
        }
        if (*port == ':') {
            port++;
        }
    } else {
        /* IPv4, hostname, or bare port */
        port = strrchr(s_addr, ':');
        if (port) {
            host = s_addr;
            *port = '\0';
            port++;
            if (host == port -1) { /* Bare port, e.g. ":8080" */
                host = NULL;
            }
        }
    }

    if (!port) {
        port = s_addr;
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
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

void epoll_close_comp(int epfd)
{
#ifdef __linux__
    close(epfd);
#else
    epoll_close(epfd);
#endif
}
