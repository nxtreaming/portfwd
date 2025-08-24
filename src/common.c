#include "common.h"
#include <syslog.h>
#include <assert.h>

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
        LOG_ERR("open(%s): %s", filepath, strerror(errno));
        exit(1);
    }

    if (flock(g_pidfile_fd, LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK) {
            LOG_ERR("pidfile %s exists and is locked, another instance running?", filepath);
        } else {
            LOG_ERR("flock(%s): %s", filepath, strerror(errno));
        }
        close(g_pidfile_fd);
        exit(1);
    }

    if (ftruncate(g_pidfile_fd, 0) < 0) {
        LOG_ERR("ftruncate(%s): %s", filepath, strerror(errno));
        close(g_pidfile_fd);
        exit(1);
    }

    int len = snprintf(buf, sizeof(buf), "%d\n", (int)pid);
    if (len < 0 || len >= (int)sizeof(buf)) {
        LOG_ERR("snprintf(pid) failed.");
        close(g_pidfile_fd);
        exit(1);
    }
    wlen = write(g_pidfile_fd, buf, (size_t)len);
    if (wlen != len) {
        int saved = errno;
        LOG_ERR("write(%s): %s", filepath, strerror(saved));
        close(g_pidfile_fd);
        exit(1);
    }

    atexit(cleanup_pidfile);
}

int do_daemonize(void)
{
    int rc;

    if ((rc = fork()) < 0) {
        LOG_ERR("fork() error: %s.", strerror(errno));
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
        chdir("/tmp");
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
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        LOG_WARN("fcntl(F_GETFL): %s", strerror(errno));
        return;
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOG_WARN("fcntl(F_SETFL,O_NONBLOCK): %s", strerror(errno));
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
    char host[256], s_port[32];
    const char *port_str;
    long port;

    memset(host, 0, sizeof(host));

    if (pair[0] == '[') { /* [ip6]:port */
        const char *end = strchr(pair + 1, ']');
        if (!end || *(end + 1) != ':' || *(end + 2) == '\0')
            return -EINVAL;
        size_t len = end - (pair + 1);
        if (len >= sizeof(host) - 1)
            return -EINVAL;
        memcpy(host, pair + 1, len);
        host[len] = '\0';
        port_str = end + 2;
    } else { /* ip4:port or just ip4 */
        port_str = strrchr(pair, ':');
        if (port_str) {
            size_t len = port_str - pair;
            if (len >= sizeof(host) - 1)
                return -EINVAL;
            memcpy(host, pair, len);
            host[len] = '\0';
            port_str++;
        } else {
            port_str = pair;
            if (snprintf(host, sizeof(host), "0.0.0.0") >= (int)sizeof(host))
                return -EINVAL;
        }
    }

    if (host[0] == '\0') {
        if (snprintf(host, sizeof(host), "0.0.0.0") >= (int)sizeof(host))
            return -EINVAL;
    }

    char *endptr;
    errno = 0;
    port = strtol(port_str, &endptr, 10);
    if (errno != 0 || *endptr != '\0' || port < 0 || port > 65535) {
        return -EINVAL;
    }
    if (snprintf(s_port, sizeof(s_port), "%ld", port) >= (int)sizeof(s_port))
        return -EINVAL;

    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = is_udp ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;

    int rc = getaddrinfo(host, s_port, &hints, &result);
    if (rc != 0) {
        LOG_ERR("getaddrinfo(%s:%s): %s", host, s_port, gai_strerror(rc));
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
