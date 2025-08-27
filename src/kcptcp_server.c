#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "common.h"
#include "proxy_conn.h"

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options] <local_udp_addr:port> <target_tcp_addr:port>\n"
        "\n"
        "Options (subset; KCP tunables to be added):\n"
        "  -d                 run in background (daemonize)\n"
        "  -p <pidfile>       write PID to file\n"
        "  -r                 set SO_REUSEADDR on listener socket\n"
        "  -R                 set SO_REUSEPORT on listener socket\n"
        "  -6                 for IPv6 listener, set IPV6_V6ONLY\n"
        "  -S <bytes>         SO_RCVBUF/SO_SNDBUF size (default build-time)\n"
        "  -h                 show help\n",
        prog);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 2;
    }

    // Placeholder: not implemented yet.
    fprintf(stderr, "kcptcp-server: feature scaffolding present; implementation pending.\n");
    (void)argv; (void)argc;
    return 64; // EX_USAGE-like
}
