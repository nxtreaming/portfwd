#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sig(int s) {
    (void)s;
    g_stop = 1;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <bind_ip> <port>\n", argv[0]);
        return 2;
    }
    const char *ip = argv[1];
    int port = atoi(argv[2]);

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) {
        perror("socket");
        return 1;
    }
    int on = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "bad ip\n");
        return 2;
    }

    if (bind(ls, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(ls, 64) < 0) {
        perror("listen");
        return 1;
    }

    fprintf(stderr, "tcp_echo listening on %s:%d\n", ip, port);

    while (!g_stop) {
        int cs = accept(ls, NULL, NULL);
        if (cs < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            break;
        }
        for (;;) {
            char buf[65536];
            ssize_t rn = recv(cs, buf, sizeof(buf), 0);
            if (rn == 0)
                break;
            if (rn < 0) {
                if (errno == EINTR)
                    continue;
                perror("recv");
                break;
            }
            ssize_t off = 0;
            while (off < rn) {
                ssize_t wn = send(cs, buf + off, (size_t)(rn - off), 0);
                if (wn < 0) {
                    if (errno == EINTR)
                        continue;
                    perror("send");
                    break;
                }
                off += wn;
            }
        }
        close(cs);
    }
    close(ls);
    return 0;
}
