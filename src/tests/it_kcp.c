#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <ctype.h>
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

struct totals {
    unsigned conv;
    unsigned long long tcp_rx, tcp_tx;
    unsigned long long udp_rx, udp_tx;
    unsigned long long kcp_rx_msgs, kcp_tx_msgs;
    unsigned long long kcp_rx_bytes, kcp_tx_bytes;
    unsigned rekeys_i, rekeys_c;
};

/* Try to parse a totals line starting at ptr. Returns true on success. */
static bool parse_totals_line(const char* ptr, struct totals* out) {
    return sscanf(ptr,
                  "stats total conv=%u: tcp_rx=%llu tcp_tx=%llu udp_rx=%llu udp_tx=%llu kcp_rx_msgs=%llu kcp_tx_msgs=%llu kcp_rx_bytes=%llu kcp_tx_bytes=%llu rekeys_i=%u rekeys_c=%u",
                  &out->conv,
                  &out->tcp_rx, &out->tcp_tx,
                  &out->udp_rx, &out->udp_tx,
                  &out->kcp_rx_msgs, &out->kcp_tx_msgs,
                  &out->kcp_rx_bytes, &out->kcp_tx_bytes,
                  &out->rekeys_i, &out->rekeys_c) == 11;
}

/* Scan buffer for the last totals line; if found, parse into out and return true */
static bool find_last_totals(const char* buf, size_t len, struct totals* out) {
    const char* key = "stats total conv=";
    size_t klen = strlen(key);
    const char* last = NULL;
    for (size_t i = 0; i + klen < len; ++i) {
        if (memcmp(buf + i, key, klen) == 0) last = buf + i;
    }
    if (!last) return false;
    return parse_totals_line(last, out);
}

/* Find maximum floating value after key, tolerant to following text like " Mbps" */
static double find_max_double(const char* buf, size_t len, const char* key) {
    if (!buf || !key) return 0.0;
    size_t klen = strlen(key);
    if (klen == 0 || len < klen) return 0.0;
    double maxv = 0.0;
    size_t i = 0;
    char tmp[64];
    while (i + klen < len) {
        if (memcmp(buf + i, key, klen) == 0) {
            size_t j = i + klen;
            // copy up to next non-number char window
            size_t t = 0;
            // allow optional sign, digits, dot
            while (j < len && t + 1 < sizeof(tmp)) {
                char c = buf[j];
                if ((c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+') {
                    tmp[t++] = c; j++;
                } else {
                    break;
                }
            }
            tmp[t] = '\0';
            if (t > 0) {
                double v = strtod(tmp, NULL);
                if (v > maxv) maxv = v;
            }
            i = j;
        } else {
            i++;
        }
    }
    return maxv;
}

/* Find the maximum numeric value appearing after a given key pattern, e.g., key="rekey i=" */
static unsigned find_max_counter(const char* buf, size_t len, const char* key) {
    if (!buf || !key) return 0u;
    size_t klen = strlen(key);
    if (klen == 0 || len < klen) return 0u;
    unsigned maxv = 0u;
    size_t i = 0;
    while (i + klen <= len) {
        if (memcmp(buf + i, key, klen) == 0) {
            size_t j = i + klen;
            // parse unsigned integer digits
            unsigned v = 0u; bool any = false;
            while (j < len && isdigit((unsigned char)buf[j])) { any = true; v = v*10u + (unsigned)(buf[j]-'0'); j++; }
            if (any && v > maxv) maxv = v;
            i = j;
        } else {
            i++;
        }
    }
    return maxv;
}

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

/* Return true if needle appears as a contiguous substring within the first len bytes of buf */
static bool contains(const char* buf, size_t len, const char* needle) {
    if (!buf || !needle) return false;
    size_t nlen = strlen(needle);
    if (nlen == 0) return true;
    if (len < nlen) return false;
    const size_t last = len - nlen;
    for (size_t i = 0; i <= last; ++i) {
        if (memcmp(buf + i, needle, nlen) == 0) return true;
    }
    return false;
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

    // Make stats logs more responsive for tests and ensure enabled
    setenv("PFWD_STATS_INTERVAL_MS", "1000", 1); // 1s interval
    setenv("PFWD_STATS_ENABLE", "1", 1);
    setenv("PFWD_STATS_DUMP", "1", 1);

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
        // Ensure at least one periodic stats log line is emitted by either side
        bool has_stats_cli = contains(cli_log, cli_len, "stats conv=");
        bool has_stats_srv = contains(srv_log, srv_len, "stats conv=");
        if (!has_stats_cli && !has_stats_srv) ok = false;
        // Ensure at least one final totals line is emitted by either side
        bool has_total_cli = contains(cli_log, cli_len, "stats total conv=");
        bool has_total_srv = contains(srv_log, srv_len, "stats total conv=");
        if (!has_total_cli && !has_total_srv) ok = false;
        // Validate throughput counters (expect some positive traffic)
        double tcp_in = find_max_double(cli_log, cli_len, "TCP in=");
        if (tcp_in <= 0.0) tcp_in = find_max_double(srv_log, srv_len, "TCP in=");
        double kcp_out = find_max_double(cli_log, cli_len, "KCP payload out=");
        if (kcp_out <= 0.0) kcp_out = find_max_double(srv_log, srv_len, "KCP payload out=");
        if (tcp_in <= 0.0 && kcp_out <= 0.0) ok = false;
        // Validate core counters from totals
        struct totals t = {0}; bool have_totals = false;
        if (find_last_totals(cli_log, cli_len, &t)) have_totals = true;
        else if (find_last_totals(srv_log, srv_len, &t)) have_totals = true;
        if (!have_totals) ok = false;
        if (have_totals) {
            if (t.tcp_rx == 0ull || t.tcp_tx == 0ull) ok = false;
            if (t.udp_rx == 0ull || t.udp_tx == 0ull) ok = false;
            if (t.kcp_rx_bytes == 0ull || t.kcp_tx_bytes == 0ull) ok = false;
            if (t.kcp_rx_msgs == 0ull || t.kcp_tx_msgs == 0ull) ok = false;
            if (t.rekeys_i == 0u || t.rekeys_c == 0u) ok = false;
        }
        // Verify rekey counter deltas observed in stats logs (expect >=1 initiated and completed)
        unsigned i_max = find_max_counter(cli_log, cli_len, "rekey i=");
        if (i_max == 0u) {
            unsigned i_max_srv = find_max_counter(srv_log, srv_len, "rekey i=");
            i_max = i_max_srv;
        }
        unsigned c_max = find_max_counter(cli_log, cli_len, "rekey c=");
        if (c_max == 0u) {
            unsigned c_max_srv = find_max_counter(srv_log, srv_len, "rekey c=");
            c_max = c_max_srv;
        }
        if (i_max == 0u || c_max == 0u) ok = false;
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
