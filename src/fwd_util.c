#include "fwd_util.h"
#include "common.h"
#include <getopt.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>

// Global signal-safe flag for graceful shutdown
volatile sig_atomic_t g_shutdown_requested = 0;

static int g_pidfile_fd = -1;
static const char *g_pidfile_path = NULL;

/* Signal-safe shutdown handler */
static void handle_shutdown_signal(int sig) {
    (void)sig; /* Unused parameter */
    g_shutdown_requested = 1;
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

/* Setup signal handlers for graceful shutdown */
int init_signals(void) {
    struct sigaction sa;

    /* Block signals during handler execution */
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaddset(&sa.sa_mask, SIGQUIT);

    sa.sa_handler = handle_shutdown_signal;
    sa.sa_flags = SA_RESTART; /* Restart interrupted system calls */

    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        P_LOG_ERR("sigaction(SIGTERM): %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        P_LOG_ERR("sigaction(SIGINT): %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGQUIT, &sa, NULL) < 0) {
        P_LOG_ERR("sigaction(SIGQUIT): %s", strerror(errno));
        return -1;
    }

    /* Ignore SIGPIPE - we handle EPIPE explicitly */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        P_LOG_ERR("sigaction(SIGPIPE): %s", strerror(errno));
        return -1;
    }

    return 0;
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */
/* PID File Management */
/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

void cleanup_pidfile(void) {
    if (g_pidfile_fd >= 0) {
        if (close(g_pidfile_fd) < 0) {
            P_LOG_WARN("close(pidfile): %s", strerror(errno));
        }
        g_pidfile_fd = -1;
    }
    if (g_pidfile_path) {
        unlink(g_pidfile_path);
    }
}

int create_pid_file(const char *filepath) {
    char buf[32];
    ssize_t wlen;
    pid_t pid = getpid();

    g_pidfile_path = filepath;

    g_pidfile_fd = open(filepath, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (g_pidfile_fd < 0) {
        if (errno != EEXIST) {
            P_LOG_ERR("open(%s) exclusively: %s", filepath, strerror(errno));
            return -1;
        }
        /* File exists, try to open and lock it */
        g_pidfile_fd = open(filepath, O_WRONLY, 0644);
        if (g_pidfile_fd < 0) {
            P_LOG_ERR("open(%s) for locking: %s", filepath, strerror(errno));
            return -1;
        }
    }

    int flags = fcntl(g_pidfile_fd, F_GETFD, 0);
    if (flags != -1) {
        fcntl(g_pidfile_fd, F_SETFD, flags | FD_CLOEXEC);
    }

    if (flock(g_pidfile_fd, LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK) {
            P_LOG_ERR("pidfile %s exists and is locked, another instance running?", filepath);
        } else {
            P_LOG_ERR("flock(%s): %s", filepath, strerror(errno));
        }
        close(g_pidfile_fd);
        g_pidfile_fd = -1;
        return -1;
    }

    if (ftruncate(g_pidfile_fd, 0) < 0) {
        P_LOG_ERR("ftruncate(%s): %s", filepath, strerror(errno));
        close(g_pidfile_fd);
        g_pidfile_fd = -1;
        return -1;
    }

    int len = snprintf(buf, sizeof(buf), "%d\n", (int)pid);
    if (len < 0 || len >= (int)sizeof(buf)) {
        P_LOG_ERR("snprintf(pid) failed.");
        close(g_pidfile_fd);
        g_pidfile_fd = -1;
        return -1;
    }
    wlen = write(g_pidfile_fd, buf, (size_t)len);
    if (wlen != len) {
        P_LOG_ERR("write(%s): %s", filepath, strerror(errno));
        close(g_pidfile_fd);
        g_pidfile_fd = -1;
        return -1;
    }

    atexit(cleanup_pidfile);
    return 0;
}

void init_fwd_config(struct fwd_config *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->max_total_connections = -1; // Default: no limit
    cfg->max_per_ip_connections = 0; // Default: no limit
}

int parse_common_args(int argc, char **argv, struct fwd_config *cfg) {
    int opt;

    // Reset getopt's internal state.
    optind = 1;

    // A colon after an option character indicates it takes an argument.
    while ((opt = getopt(argc, argv, "drR6P:i:")) != -1) {
        switch (opt) {
        case 'd':
            cfg->daemonize = true;
            break;
        case 'r':
            cfg->reuse_addr = 1;
            break;
        case 'R':
            cfg->reuse_port = 1;
            break;
        case '6':
            cfg->v6only = 1;
            break;
        case 'P':
            cfg->pidfile = optarg;
            break;
        case 'i':
            cfg->max_per_ip_connections = (unsigned int)atoi(optarg);
            break;
        case '?':
            // getopt() prints an error message to stderr.
            return -1;
        default:
            // Should not happen.
            return -1;
        }
    }

    return optind;
}

void set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags != -1) {
        fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
}

void drop_privileges(const char *username) {
    struct passwd *pw = getpwnam(username);
    if (pw == NULL) {
        P_LOG_ERR("getpwnam(\"%s\"): %s. User not found?", username, strerror(errno));
        exit(1);
    }
    if (initgroups(username, pw->pw_gid) != 0) {
        P_LOG_ERR("initgroups() failed: %s", strerror(errno));
        exit(1);
    }
    if (setgid(pw->pw_gid) != 0) {
        P_LOG_ERR("setgid() failed: %s", strerror(errno));
        exit(1);
    }
    if (setuid(pw->pw_uid) != 0) {
        P_LOG_ERR("setuid() failed: %s", strerror(errno));
        exit(1);
    }
    P_LOG_INFO("Dropped privileges to user '%s'", username);
}

int get_sockaddr_inx(const char *str, union sockaddr_inx *addr, bool is_source) {
    char *host, *port_str;
    char *dup = strdup(str);
    if (!dup) {
        P_LOG_ERR("strdup failed");
        return -1;
    }

    if (*dup == '[') {
        host = dup + 1;
        char *end = strchr(host, ']');
        if (!end) {
            P_LOG_ERR("Invalid IPv6 address format: missing ']'");
            free(dup);
            return -1;
        }
        *end = '\0';
        port_str = end + 1;
        if (*port_str != ':') {
            P_LOG_ERR("Invalid IPv6 address format: missing ':' after ']' ");
            free(dup);
            return -1;
        }
        port_str++;
    } else {
        host = dup;
        port_str = strrchr(dup, ':');
        if (!port_str) {
            if (is_source) {
                P_LOG_ERR("Source address requires a port.");
                free(dup);
                return -1;
            }
            port_str = "0"; // Destination port can be 0
        } else {
            *port_str = '\0';
            port_str++;
        }
    }

    if (port_str && *port_str) {
        char *end;
        long p = strtol(port_str, &end, 10);
        if (end == port_str || *end != '\0' || p < 1 || p > 65535) {
            P_LOG_ERR("Invalid port number '%s'. Must be between 1 and 65535.", port_str);
            free(dup);
            return -1;
        }
    }

    if (strlen(host) == 0) {
        if (is_source) {
            host = "0.0.0.0";
        } else {
            P_LOG_ERR("Destination address requires a host.");
            free(dup);
            return -1;
        }
    }

    int rc = resolve_address(addr, host, port_str);
    free(dup);
    return rc;
}

int resolve_address(union sockaddr_inx *addr, const char *host, const char *port_str) {
    struct addrinfo hints, *res;
    int status;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP socket

    if ((status = getaddrinfo(host, port_str, &hints, &res)) != 0) {
        P_LOG_ERR("getaddrinfo for %s:%s: %s", host, port_str, gai_strerror(status));
        return -1;
    }

    // Copy the first result's address info
    memcpy(addr, res->ai_addr, res->ai_addrlen);

    freeaddrinfo(res); // Free the linked list

    return 0;
}
