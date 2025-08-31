#ifndef FWD_UTIL_H
#define FWD_UTIL_H

#include "common.h"
#include "proxy_conn.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "conn_pool.h"

#include <signal.h>

/**
 * @brief Holds configuration options common to all forwarders.
 */
struct fwd_config {
    union sockaddr_inx listen_addr;
    union sockaddr_inx dst_addr;
    const char *pidfile;
    const char *username;
    bool daemonize;
    bool transparent_proxy;
    bool use_splice; /* zero-copy */

    /* Connection limits */
    int max_total_connections;
    int max_per_ip_connections;

    /* Keepalive settings */
    int ka_idle;
    int ka_intvl;
    int ka_cnt;

    /* Buffer sizes */
    int sockbuf_size;
    int backpressure_wm;

    /* Timeouts */
    int idle_timeout;
};

struct proxy_stats {
    pthread_mutex_t lock;
    time_t start_time;
    time_t last_stats_report;
    uint64_t total_connected;
    uint64_t total_failed;
    uint64_t total_accepted;
    uint64_t current_active;
    uint64_t peak_concurrent;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t limit_rejections;
    uint64_t connect_errors;
};

#define CONN_LIMIT_HASH_SIZE 256

struct conn_limit_entry {
    union sockaddr_inx addr;
    uint32_t count;
    time_t first_seen;
    time_t last_seen;
};

struct conn_limiter {
    pthread_mutex_t lock;
    struct conn_limit_entry entries[CONN_LIMIT_HASH_SIZE];
    int total_connections;
    int max_total;
    int max_per_ip;
};

// Global signal-safe flag for graceful shutdown
extern volatile sig_atomic_t g_shutdown_requested;

// Setup signal handlers for graceful shutdown
int setup_shutdown_signals(void);

// PID file management
int create_pid_file(const char *path);
void cleanup_pidfile(void);
int do_daemonize(void);
void init_signals(void);
void drop_privileges(const char *username);

/**
 * @brief Parses common command-line arguments and populates the config.
 *
 * @param argc Argument count from main().
 * @param argv Argument vector from main().
 * @param cfg  The fwd_config struct to populate.
 * @return The updated optind value on success, -1 on error.
 */
void init_fwd_config(struct fwd_config *cfg);
int parse_common_args(int argc, char **argv, struct fwd_config *cfg);

#endif // FWD_UTIL_H
