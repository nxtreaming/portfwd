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
    union sockaddr_inx src_addr;
    union sockaddr_inx dst_addr;
    const char *pidfile;
    bool daemonize;
    bool reuse_addr;
    bool reuse_port;
    bool v6only;
    unsigned int max_per_ip; /* Max connections per source IP */
};

// Global signal-safe flag for graceful shutdown
extern volatile sig_atomic_t g_shutdown_requested;

// Setup signal handlers for graceful shutdown
int setup_shutdown_signals(void);

// PID file management
int create_pid_file(const char *path);
void cleanup_pidfile(void);
int do_daemonize(void);

/**
 * @brief Parses common command-line arguments and populates the config.
 *
 * @param argc Argument count from main().
 * @param argv Argument vector from main().
 * @param cfg  The fwd_config struct to populate.
 * @return The updated optind value on success, -1 on error.
 */
int parse_common_args(int argc, char **argv, struct fwd_config *cfg);

#endif // FWD_UTIL_H
