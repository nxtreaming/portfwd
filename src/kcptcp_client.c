#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <stddef.h>
#include "common.h"
#include "proxy_conn.h"

static void print_usage(const char *prog) {
    P_LOG_INFO("Usage: %s [options] <local_tcp_addr:port> <remote_udp_addr:port>", prog);
    P_LOG_INFO("");
    P_LOG_INFO("Options (subset; KCP tunables to be added):");
    P_LOG_INFO("  -d                 run in background (daemonize)");
    P_LOG_INFO("  -p <pidfile>       write PID to file");
    P_LOG_INFO("  -r                 set SO_REUSEADDR on listener socket");
    P_LOG_INFO("  -R                 set SO_REUSEPORT on listener socket");
    P_LOG_INFO("  -6                 for IPv6 listener, set IPV6_V6ONLY");
    P_LOG_INFO("  -S <bytes>         SO_RCVBUF/SO_SNDBUF size (default build-time)");
    P_LOG_INFO("  -h                 show help");
}

struct cfg_client {
    union sockaddr_inx laddr; /* TCP listen */
    union sockaddr_inx raddr; /* UDP remote */
    const char *pidfile;
    bool daemonize;
    bool reuse_addr;
    bool reuse_port;
    bool v6only;
    int sockbuf_bytes;
};

static void set_sock_buffers_sz(int sockfd, int bytes)
{
    if (bytes <= 0) return;
    (void)setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes));
    (void)setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
}

int main(int argc, char **argv) {
    int rc = 1;
    int epfd = -1, lsock = -1;
    uint32_t magic_listener = 0xdeadbeefU; /* reuse value style from tcpfwd */
    struct cfg_client cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.reuse_addr = true;

    int opt;
    while ((opt = getopt(argc, argv, "dp:rR6S:h")) != -1) {
        switch (opt) {
        case 'd': cfg.daemonize = true; break;
        case 'p': cfg.pidfile = optarg; break;
        case 'r': cfg.reuse_addr = true; break;
        case 'R': cfg.reuse_port = true; break;
        case '6': cfg.v6only = true; break;
        case 'S': {
            char *end = NULL; long v = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0' || v <= 0) {
                P_LOG_WARN("invalid -S value '%s'", optarg);
            } else {
                if (v < 4096) v = 4096; if (v > (8<<20)) v = (8<<20);
                cfg.sockbuf_bytes = (int)v;
            }
            break;
        }
        case 'h': default:
            print_usage(argv[0]);
            return (opt == 'h') ? 0 : 2;
        }
    }

    if (optind + 2 != argc) {
        print_usage(argv[0]);
        return 2;
    }

    if (get_sockaddr_inx_pair(argv[optind], &cfg.laddr, false) < 0) {
        P_LOG_ERR("invalid local tcp addr: %s", argv[optind]);
        return 2;
    }
    if (get_sockaddr_inx_pair(argv[optind+1], &cfg.raddr, true) < 0) {
        P_LOG_ERR("invalid remote udp addr: %s", argv[optind+1]);
        return 2;
    }

    if (cfg.daemonize) {
        if (do_daemonize() != 0) return 1;
        g_state.daemonized = true;
    }
    setup_signal_handlers();
    if (cfg.pidfile) {
        if (write_pidfile(cfg.pidfile) != 0) {
            P_LOG_ERR("failed to write pidfile: %s", cfg.pidfile);
            return 1;
        }
    }

    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) { P_LOG_ERR("epoll_create1: %s", strerror(errno)); goto cleanup; }

    /* Create TCP listen socket */
    lsock = socket(cfg.laddr.sa.sa_family, SOCK_STREAM, 0);
    if (lsock < 0) { P_LOG_ERR("socket(listen): %s", strerror(errno)); goto cleanup; }
    if (cfg.reuse_addr) {
        int on = 1; (void)setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    }
#ifdef SO_REUSEPORT
    if (cfg.reuse_port) {
        int on = 1; (void)setsockopt(lsock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
    }
#endif
#ifdef IPV6_V6ONLY
    if (cfg.v6only && cfg.laddr.sa.sa_family == AF_INET6) {
        int on = 1; (void)setsockopt(lsock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
    }
#endif
    set_nonblock(lsock);
    set_sock_buffers_sz(lsock, cfg.sockbuf_bytes);
    if (bind(lsock, &cfg.laddr.sa, (socklen_t)sizeof_sockaddr(&cfg.laddr)) < 0) {
        P_LOG_ERR("bind(listen): %s", strerror(errno)); goto cleanup;
    }
    if (listen(lsock, 128) < 0) { P_LOG_ERR("listen: %s", strerror(errno)); goto cleanup; }

    struct epoll_event ev = {0};
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP; /* level-trigger for listener */
    ev.data.ptr = &magic_listener;
    if (ep_add_or_mod(epfd, lsock, &ev) < 0) { P_LOG_ERR("epoll_ctl add listen: %s", strerror(errno)); goto cleanup; }

    P_LOG_INFO("kcptcp-client initialized (listener ready). KCP data path pending implementation.");

    /* Minimal loop: keep process alive until terminated, no accept yet. */
    while (!g_state.terminate) {
        struct epoll_event events[64];
        int nfds = epoll_wait(epfd, events, 64, 1000);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            P_LOG_ERR("epoll_wait: %s", strerror(errno));
            break;
        }
    }

    rc = 0;

cleanup:
    if (lsock >= 0) close(lsock);
    if (epfd >= 0) epoll_close_comp(epfd);
    cleanup_pidfile();
    return rc;
}
