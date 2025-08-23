#include "common.h"
#include <syslog.h>
#include <assert.h>

const char *g_pidfile = NULL;
static bool g_pidfile_created = false;
volatile sig_atomic_t g_terminate = 0;

void on_signal(int sig)
{
    (void)sig;
    g_terminate = 1;
}

void cleanup_pidfile(void)
{
    if (g_pidfile_created && g_pidfile) {
        unlink(g_pidfile);
        g_pidfile_created = false;
    }
}

void write_pidfile(const char *filepath)
{
    int fd;
    char buf[32];
    ssize_t wlen;
    pid_t pid = getpid();

    /* Try exclusive create to avoid races */
    fd = open(filepath, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0 && errno == EEXIST) {
        /* Check if existing PID is stale */
        int rfd = open(filepath, O_RDONLY);
        if (rfd >= 0) {
            char rbuf[64];
            ssize_t r = read(rfd, rbuf, sizeof(rbuf) - 1);
            close(rfd);
            if (r > 0) {
                char *endp = NULL;
                long oldpid;
                rbuf[r] = '\0';
                errno = 0;
                oldpid = strtol(rbuf, &endp, 10);
                if (errno == 0 && endp != rbuf && oldpid > 0) {
                    if (kill((pid_t)oldpid, 0) == 0) {
                        fprintf(stderr, "*** pidfile %s exists, process %ld appears running.\n", filepath, oldpid);
                        exit(1);
                    }
                }
            }
        }
        /* Stale or unreadable: try to remove and recreate */
        if (unlink(filepath) == 0)
            fd = open(filepath, O_WRONLY | O_CREAT | O_EXCL, 0644);
    }

    if (fd < 0) {
        fprintf(stderr, "*** open(%s): %s\n", filepath, strerror(errno));
        exit(1);
    }

    int len = snprintf(buf, sizeof(buf), "%d\n", (int)pid);
    if (len < 0 || len >= (int)sizeof(buf)) {
        close(fd);
        fprintf(stderr, "*** snprintf(pid) failed.\n");
        exit(1);
    }
    wlen = write(fd, buf, (size_t)len);
    if (wlen != len) {
        int saved = errno;
        close(fd);
        fprintf(stderr, "*** write(%s): %s\n", filepath, strerror(saved));
        exit(1);
    }
    (void)fsync(fd);
    close(fd);

    atexit(cleanup_pidfile);
    g_pidfile_created = true;
}

int do_daemonize(void)
{
    int rc;

    if ((rc = fork()) < 0) {
        fprintf(stderr, "*** fork() error: %s.\n", strerror(errno));
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
        syslog(LOG_WARNING, "fcntl(F_GETFL): %s", strerror(errno));
        return;
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        syslog(LOG_WARNING, "fcntl(F_SETFL,O_NONBLOCK): %s", strerror(errno));
    }
}

void *addr_of_sockaddr(const union sockaddr_inx *addr)
{
    assert(addr->sa.sa_family == AF_INET || addr->sa.sa_family == AF_INET6);
    if (addr->sa.sa_family == AF_INET6)
        return (void *)&addr->sin6.sin6_addr;
    return (void *)&addr->sin.sin_addr;
}

unsigned short port_of_sockaddr(const union sockaddr_inx *addr)
{
    assert(addr->sa.sa_family == AF_INET || addr->sa.sa_family == AF_INET6);
    if (addr->sa.sa_family == AF_INET6)
        return addr->sin6.sin6_port;
    return addr->sin.sin_port;
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
        if (len >= sizeof(host))
            return -EINVAL;
        memcpy(host, pair + 1, len);
        host[len] = '\0';
        port_str = end + 2;
    } else { /* ip4:port or just ip4 */
        port_str = strrchr(pair, ':');
        if (port_str) {
            size_t len = port_str - pair;
            if (len >= sizeof(host))
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
        syslog(LOG_ERR, "getaddrinfo(%s:%s): %s", host, s_port, gai_strerror(rc));
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
