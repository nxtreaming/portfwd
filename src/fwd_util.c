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

// For logging before daemonization or when syslog is not used
#define P_LOG_ERR(fmt, ...) fprintf(stderr, "ERROR: " fmt "\n", ##__VA_ARGS__)
#define P_LOG_WARN(fmt, ...) fprintf(stderr, "WARN: " fmt "\n", ##__VA_ARGS__)
#define P_LOG_INFO(fmt, ...) fprintf(stderr, "INFO: " fmt "\n", ##__VA_ARGS__)

// Global signal-safe flag for graceful shutdown
volatile sig_atomic_t g_shutdown_requested = 0;

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
int setup_shutdown_signals(void) {
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

static int g_pidfile_fd = -1;
static const char *g_pidfile_path = NULL;

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
            P_LOG_ERR(
                "pidfile %s exists and is locked, another instance running?",
                filepath);
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
    cfg->max_per_ip = 0; // Default: no limit
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
            cfg->reuse_addr = true;
            break;
        case 'R':
            cfg->reuse_port = true;
            break;
        case '6':
            cfg->v6only = true;
            break;
        case 'P':
            cfg->pidfile = optarg;
            break;
        case 'i':
            cfg->max_per_ip = (unsigned int)atoi(optarg);
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

