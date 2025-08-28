#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sig(int s){ (void)s; g_stop = 1; }

// forward declarations for functions used before definition
static void msleep(int ms);
static void die(const char* fmt, ...);

struct child_proc {
    pid_t pid;
    int   fd;   /* read end of combined stdout/stderr */
};

static struct child_proc spawn_capture(char* const argv[]) {
    int pipefd[2];
    if (pipe(pipefd) < 0) die("pipe: %s", strerror(errno));
    pid_t pid = fork();
    if (pid < 0) die("fork: %s", strerror(errno));
    if (pid == 0) {
        // child: redirect stdout/stderr to pipe write end
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execvp(argv[0], argv);
        fprintf(stderr, "exec %s failed: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    // parent
    close(pipefd[1]);
    struct child_proc cp = { pid, pipefd[0] };
    return cp;
}

static void read_all_fd(int fd, char** out_buf, size_t* out_len) {
    const size_t step = 4096;
    size_t cap = step, len = 0;
    char* buf = (char*)malloc(cap);
    if (!buf) die("oom");
    for (;;) {
        if (len + step > cap) { cap *= 2; buf = (char*)realloc(buf, cap); if (!buf) die("oom"); }
        ssize_t rn = read(fd, buf + len, step);
        if (rn < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (rn == 0) break;
        len += (size_t)rn;
    }
    *out_buf = buf; *out_len = len;
}

static void msleep(int ms){ struct timespec ts={ ms/1000, (ms%1000)*1000000L }; nanosleep(&ts, NULL); }

static void die(const char* fmt, ...) {
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr); exit(1);
}

static pid_t spawn(char* const argv[]) {
    pid_t pid = fork();
    if (pid < 0) die("fork failed: %s", strerror(errno));
    if (pid == 0) {
        // child
        execvp(argv[0], argv);
        fprintf(stderr, "exec %s failed: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    return pid;
}

static int connect_tcp(const char* ip, int port){
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) die("socket: %s", strerror(errno));
    struct sockaddr_in a; memset(&a,0,sizeof(a)); a.sin_family=AF_INET; a.sin_port=htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) die("inet_pton failed for %s", ip);
    int tries = 100;
    while (tries-- && !g_stop) {
        if (connect(s, (struct sockaddr*)&a, sizeof(a)) == 0) return s;
        msleep(50);
    }
    die("connect to %s:%d failed: %s", ip, port, strerror(errno));
    return -1;
}

static void fill_pattern(unsigned char* b, size_t n, unsigned seed){
    for (size_t i=0;i<n;i++) b[i] = (unsigned char)((i*1315423911u + seed) & 0xff);
}

int main(int argc, char** argv){
    const char* psk = getenv("IT_PSK");
    if (!psk) psk = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; // 64 hex (32 bytes)

    // Args: [mode] [send_mb] [pause_ms] [pause_at_mb]
    // mode: normal | timeout
    const char* mode = (argc >= 2) ? argv[1] : "normal";
    bool mode_timeout = (strcmp(mode, "timeout") == 0);
    size_t send_mb = (argc >= 3) ? (size_t)strtoul(argv[2], NULL, 10) : 8;
    int pause_ms = (argc >= 4) ? (int)strtol(argv[3], NULL, 10) : 5000; // > REKEY_TIMEOUT_MS
    size_t pause_at_mb = (argc >= 5) ? (size_t)strtoul(argv[4], NULL, 10) : (send_mb/2 ? send_mb/2 : 1);

    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);

    // Launch tcp_echo 127.0.0.1:2323
    char* echo_argv[] = { (char*)"./tcp_echo", (char*)"127.0.0.1", (char*)"2323", NULL };
    pid_t pid_echo = spawn(echo_argv);
    fprintf(stderr, "[it] started tcp_echo pid=%d\n", (int)pid_echo);
    msleep(150);

    // Launch kcptcp-server: 0.0.0.0:4000 -> 127.0.0.1:2323 with -K (capture logs)
    char* srv_argv[] = { (char*)"../kcptcp-server", (char*)"0.0.0.0:4000", (char*)"127.0.0.1:2323", (char*)"-K", (char*)psk, NULL };
    struct child_proc srv = spawn_capture(srv_argv);
    pid_t pid_srv = srv.pid;
    fprintf(stderr, "[it] started kcptcp-server pid=%d\n", (int)pid_srv);
    msleep(200);

    // Launch kcptcp-client: 127.0.0.1:2023 -> 127.0.0.1:4000 with -K (capture logs)
    char* cli_argv[] = { (char*)"../kcptcp-client", (char*)"127.0.0.1:2023", (char*)"127.0.0.1:4000", (char*)"-K", (char*)psk, NULL };
    struct child_proc cli = spawn_capture(cli_argv);
    pid_t pid_cli = cli.pid;
    fprintf(stderr, "[it] started kcptcp-client pid=%d\n", (int)pid_cli);

    // Connect to client TCP listen and send data
    int s = connect_tcp("127.0.0.1", 2023);

    const size_t total = send_mb * 1024 * 1024;
    const size_t chunk = 64 * 1024;
    const size_t pause_at = pause_at_mb * 1024 * 1024;
    unsigned char* buf = (unsigned char*)malloc(chunk);
    unsigned char* rcv = (unsigned char*)malloc(chunk);
    if (!buf || !rcv) die("oom");

    size_t sent = 0, recvd = 0; unsigned seed = 0xC0FFEEu;
    bool did_pause = false; bool timeout_observed = false;
    fprintf(stderr, "[it] mode=%s send=%zuMB pause_ms=%d at=%zuMB\n", mode_timeout?"timeout":"normal", send_mb, pause_ms, pause_at_mb);

    while (sent < total && !g_stop) {
        size_t n = (total - sent) < chunk ? (total - sent) : chunk;
        fill_pattern(buf, n, seed);

        // Inject pause around rekey window to induce timeout
        if (mode_timeout && !did_pause && sent >= pause_at) {
            fprintf(stderr, "[it] SIGSTOP server for %d ms to induce timeout...\n", pause_ms);
            kill(pid_srv, SIGSTOP);
            msleep(pause_ms);
            kill(pid_srv, SIGCONT);
            did_pause = true;
        }

        size_t off = 0;
        while (off < n) {
            ssize_t wn = send(s, buf + off, n - off, 0);
            if (wn == 0) { if (mode_timeout) { timeout_observed = true; goto out; } die("send returned 0"); }
            if (wn < 0) {
                if (errno == EINTR) continue;
                if (mode_timeout) { fprintf(stderr, "[it] send error after pause (expected): %s\n", strerror(errno)); timeout_observed = true; goto out; }
                die("send: %s", strerror(errno));
            }
            off += (size_t)wn;
        }
        sent += n;

        // read back echo for this chunk
        size_t roff = 0;
        while (roff < n) {
            ssize_t rn = recv(s, rcv + roff, n - roff, 0);
            if (rn == 0) { if (mode_timeout) { fprintf(stderr, "[it] peer closed (expected in timeout mode)\n"); timeout_observed = true; goto out; } die("peer closed early at %zu/%zu", recvd, total); }
            if (rn < 0) {
                if (errno == EINTR) continue;
                if (mode_timeout) { fprintf(stderr, "[it] recv error after pause (expected): %s\n", strerror(errno)); timeout_observed = true; goto out; }
                die("recv: %s", strerror(errno));
            }
            roff += (size_t)rn;
        }
        if (memcmp(buf, rcv, n) != 0) die("mismatch in echo data");
        recvd += n;
    }

out:
    // Read logs from children (do not close read fds before reading)
    char *cli_log = NULL, *srv_log = NULL; size_t cli_len = 0, srv_len = 0;
    // Wait a moment to flush
    msleep(200);
    // Reap children after kill below to ensure logs complete

    if (mode_timeout) {
        if (!timeout_observed) die("expected timeout was NOT observed");
        // Check logs for rekey timeout message (client or server)
        read_all_fd(cli.fd, &cli_log, &cli_len);
        read_all_fd(srv.fd, &srv_log, &srv_len);
        const char* needle = "rekey timeout, closing";
        bool has_cli = contains(cli_log, cli_len, needle);
        bool has_svr = contains(srv_log, srv_len, needle);
        if (!has_cli && !has_svr) die("missing timeout log in client/server output");
        fprintf(stderr, "[it] timeout observed successfully.\n");
    } else {
        if (recvd != total) die("incomplete transfer: %zu/%zu", recvd, total);
        // Check logs for rekey lifecycle: trigger, recv REKEY_ACK, epoch switch
        read_all_fd(cli.fd, &cli_log, &cli_len);
        read_all_fd(srv.fd, &srv_log, &srv_len);
        bool ok = true;
        if (!contains(cli_log, cli_len, "rekey trigger")) ok = false;
        if (!contains(cli_log, cli_len, "recv REKEY_ACK")) ok = false;
        if (!contains(cli_log, cli_len, "epoch switch")) ok = false;
        if (!contains(srv_log, srv_len, "recv REKEY_INIT")) ok = false;
        if (!contains(srv_log, srv_len, "epoch switch")) ok = false;
        if (!ok) die("missing expected rekey logs (trigger/ACK/epoch) in client/server output");
        fprintf(stderr, "[it] completed echo %zu/%zu bytes OK and rekey logs verified\n", recvd, total);
    }

    // Cleanup
    close(s);
    close(cli.fd); close(srv.fd);
    kill(pid_cli, SIGTERM);
    kill(pid_srv, SIGTERM);
    kill(pid_echo, SIGTERM);
    int st; while (waitpid(-1, &st, 0) > 0) {}
    free(buf); free(rcv);
    free(cli_log); free(srv_log);
    fprintf(stderr, "[it] done.\n");
    return 0;
}
