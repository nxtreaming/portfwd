portfwd
=======

User-space TCP/UDP port forwarding services

## Summary
 This project contains two applications: tcpfwd, udpfwd, which are for TCP and UDP port forwarding literally.
 Written in pure C.
 
## Usage

### tcpfwd (TCP forwarder)

    tcpfwd [options] <local_addr:local_port> <dest_addr:dest_port>

    Options:
      -d                 run in background (daemonize)
      -p <pidfile>       write PID to file
      -b                 base-addr mode (Linux TPROXY/original-dst based address math; expert use only)
      -r                 set SO_REUSEADDR on listener socket
      -R                 set SO_REUSEPORT on listener socket
      -6                 for IPv6 listener, set IPV6_V6ONLY
      -h                 show help

### udpfwd (UDP forwarder)

    udpfwd <local_addr:local_port> <dest_addr:dest_port> [options]

    Options:
      -t <seconds>       proxy session timeout (default: 60)
      -d                 run in background (daemonize)
      -o                 for IPv6 listener, set IPV6_V6ONLY
      -r                 set SO_REUSEADDR before binding listener
      -R                 set SO_REUSEPORT before binding listener
      -H <size>          hash table size for UDP connection tracking (default: 4093)
      -p <pidfile>       write PID to file
      -h                 show help

### kcptcp-client (TCP over KCP/UDP client)

    kcptcp-client [options] <local_tcp_addr:port> <remote_udp_addr:port>

    Options:
      -d                 run in background (daemonize)
      -p <pidfile>       write PID to file
      -r                 set SO_REUSEADDR on listener socket
      -R                 set SO_REUSEPORT on listener socket
      -6                 for IPv6 listener, set IPV6_V6ONLY
      -S <bytes>         SO_RCVBUF/SO_SNDBUF size (default build-time)
      -M <mtu>           KCP MTU (default 1350; tune to avoid IP fragmentation)
      -K <hex>           32-byte PSK in hex (ChaCha20-Poly1305); enables encryption
      -h                 show help

  Notes:
  - Listens on a local TCP address and forwards streams over UDP using KCP.
  - AEAD encryption is enabled only when `-K` is provided on both client and server.

### kcptcp-server (KCP/UDP to TCP server)

    kcptcp-server [options] <local_udp_addr:port> <target_tcp_addr:port>

    Options:
      -d                 run in background (daemonize)
      -p <pidfile>       write PID to file
      -r                 set SO_REUSEADDR on listener socket
      -R                 set SO_REUSEPORT on listener socket
      -6                 for IPv6 listener, set IPV6_V6ONLY
      -S <bytes>         SO_RCVBUF/SO_SNDBUF size (default build-time)
      -M <mtu>           KCP MTU (default 1350; tune to avoid IP fragmentation)
      -K <hex>           32-byte PSK in hex (ChaCha20-Poly1305); enables encryption
      -h                 show help

  Notes:
  - Listens on a UDP address, accepts KCP sessions, and bridges to a target TCP service.
  - AEAD requires the same `-K` PSK as the client for handshakes to succeed.

## Examples

##### Map local TCP port 1022 to 192.168.1.77:22

    tcpfwd 0.0.0.0:1022 192.168.1.77:22     # allow access from all hosts
    tcpfwd 127.0.0.1:1022 192.168.1.77:22   # only allow localhost
    tcpfwd [::]:1022 192.168.1.77:22        # allow access to port 1022 via both IPv4 and IPv6

##### Map local UDP port 53 to 8.8.8.8:53

    udpfwd 0.0.0.0:53 8.8.8.8:53
    udpfwd [::]:53 8.8.8.8:53

##### IPv4-IPv6 transforming

    udpfwd [::]:1701 localhost:1701         # add IPv6 support for a local L2TP service
    tcpfwd 0.0.0.0:80 [2001:db8:3::2]:80    # enable IPv4 access for an IPv6-only web service

##### KCP TCP tunneling (encrypted)

Server (on host with SSH at 127.0.0.1:22):

```sh
kcptcp-server 0.0.0.0:4000 127.0.0.1:22 -K 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Client (on your local machine):

```sh
kcptcp-client 127.0.0.1:2022 server.example.com:4000 -K 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
ssh -p 2022 localhost
```

Notes:

- The `-K` PSK must be the same 32-byte value (64 hex chars) on both sides.
- If you observe IP fragmentation, try `-M 1200` on both client and server.
- Without `-K`, traffic is not encrypted; use `-K` to enable ChaCha20-Poly1305.

## Signals, PID files, and graceful shutdown

Both `tcpfwd` and `udpfwd` support optional PID files via `-p <pidfile>`. The PID file is created exclusively, checks for stale PIDs, and is automatically removed on clean exit. The following signals trigger graceful shutdown and PID cleanup:

- SIGINT, SIGTERM, SIGHUP, SIGQUIT

On receipt, the main loop exits cleanly; registered `atexit` handlers remove the PID file.

## Management Script

A startup script `portfwd-control.sh` is provided in the `src/` directory to manage the daemon. This script handles PID file management, including cleaning up stale PID files to ensure the service can restart reliably after a crash.

### Usage

First, configure the `ARGS` variable inside the script to match your desired forwarding rule.

```sh
cd src/

# Make the script executable
chmod +x portfwd-control.sh

# Start the daemon
./portfwd-control.sh start

# Check the status
./portfwd-control.sh status

# Stop the daemon
./portfwd-control.sh stop

# Restart the daemon
./portfwd-control.sh restart
```

## Epoll behavior and error handling

- Data sockets use edge-triggered epoll (EPOLLET) for high performance.
- Robust events are registered and handled uniformly: `EPOLLRDHUP | EPOLLHUP | EPOLLERR`.
- Listener sockets are level-triggered and also watch `EPOLLERR | EPOLLHUP` to avoid spurious accepts.

## Portability: no-epoll fallback

On non-Linux platforms where epoll is unavailable, the project uses a lightweight compatibility layer in `src/no-epoll.h`:

- Implements the epoll API on top of `poll()` for portability.
- Dynamically allocates handles and file descriptor arrays (no FD_SETSIZE cap, no fixed handle count).
- Supports common flags: `EPOLLIN`, `EPOLLOUT`, `EPOLLERR`, `EPOLLHUP`, `EPOLLRDHUP`. `EPOLLET` is accepted but edge-triggered semantics are not emulated.
- `epoll_event.data` is preserved across `epoll_ctl()`/`epoll_wait()`.

Limitations:

- Behavior is level-triggered; do not rely on edge-triggered wakeups when built with the fallback.
- Performance may differ from native epoll; consider libevent/libuv for advanced cross-platform needs.

## UDP performance tunables (build-time)

The UDP forwarder (`udpfwd`) supports kernel/userspace buffer and batching tunables. Set via CFLAGS at build time:

- UDP_PROXY_SOCKBUF_CAP: kernel SO_RCVBUF/SO_SNDBUF size (default 262144)
- UDP_PROXY_BATCH_SZ: Linux-only `recvmmsg()` batch size (default 16)
- UDP_PROXY_DGRAM_CAP: per-datagram buffer capacity (default 65536)
- UDP_PROXY_MAX_CONNS: maximum tracked UDP connections (default 8192)

Example:

```sh
make -C src CFLAGS='-DUDP_PROXY_SOCKBUF_CAP=524288 -DUDP_PROXY_BATCH_SZ=32 -DUDP_PROXY_DGRAM_CAP=131072'
```

Notes:

- Batching auto-enables on Linux when resources allocate; otherwise falls back to single `recvfrom()`.
- Server->client path drains reads until EAGAIN to reduce wakeups.

## UDP connection tracking and eviction

- `udpfwd` tracks client endpoints in a hash table with idle timeout (`-t <seconds>`, default shown in `-h`).
- When the table reaches `UDP_PROXY_MAX_CONNS`, it first recycles timed-out entries, then evicts the least recently active (LRU) connection.
- Increase the cap via `CFLAGS` or reduce `-t` to make recycling more aggressive.

## TCP performance tunables

`tcpfwd` increases throughput via larger userspace buffers and kernel socket buffers, plus backpressure gating and TCP keepalive.

- TCP_PROXY_USERBUF_CAP: per-direction userspace buffer (default 65536)
- TCP_PROXY_SOCKBUF_CAP: kernel SO_RCVBUF/SO_SNDBUF (default 262144)
- TCP_PROXY_BACKPRESSURE_WM: read gating watermark (default 3/4 of user buffer)
- TCP keepalive defaults (Linux):
  - TCP_PROXY_KEEPALIVE_IDLE (60s)
  - TCP_PROXY_KEEPALIVE_INTVL (10s)
  - TCP_PROXY_KEEPALIVE_CNT (6)

### Linux zero-copy acceleration (splice)

On Linux, `tcpfwd` opportunistically uses `splice()` with a non-blocking pipe to reduce copies and syscalls on the hot path. This is automatic when available, with graceful fallback to userspace buffering. No runtime flag is required.

## KCP + AEAD Overview

- Transport: KCP over UDP (for `kcptcp-client`/`kcptcp-server`).
- AEAD: ChaCha20-Poly1305.
- Each session derives a per-epoch 32-byte key and a 12-byte nonce base.
- Nonces are 96-bit: top 96 bits from nonce base, low 32 bits from `send_seq`.

## AEAD Rekeying

Rekeying prevents nonce reuse by switching to a new epoch (key/nonce base) before the 32-bit sequence number can wrap.

- Preconditions:
  - PSK must be configured on both sides; a successful handshake establishes the initial session key.
- Trigger:
  - When `send_seq >= REKEY_SEQ_THRESHOLD` and no rekey is in progress, the sender initiates rekeying.
- Protocol:
  - REKEY_INIT: sent by the initiator under the current epoch key; associated data includes type and the sender’s current `send_seq`.
  - REKEY_ACK: sent by the peer under the next epoch key with `seq=0` (in the next epoch namespace).
- Epoch switch (both sides):
  - After sending REKEY_ACK (responder) or receiving valid REKEY_ACK (initiator):
    - `next_session_key` → `session_key`
    - `next_nonce_base` → `nonce_base`
    - `epoch++`
    - `send_seq = 0`
    - Reset anti-replay window
- Timeout:
  - If `rekey_in_progress` and `now >= rekey_deadline_ms` (elapsed ≥ `REKEY_TIMEOUT_MS`), close the connection to avoid stalling and potential nonce exhaustion.
- Wraparound guard:
  - If `send_seq == UINT32_MAX`, close the connection to prevent nonce reuse.
- Anti-replay:
  - 64-bit sliding window on receiver; drops too-old or duplicate sequences.

### Logging (selected)

- Rekey trigger (before encrypted data/FIN): `rekey trigger conv=<id> epoch=<cur>-><next> send_seq=<n> deadline=<ms>`
- Received REKEY_INIT: `recv REKEY_INIT conv=<id> seq=<n>`
- Received REKEY_ACK: `recv REKEY_ACK conv=<id>`
- Epoch switch: `epoch switch conv=<id> -> epoch=<n>`
- Wraparound guard: `send_seq wraparound guard hit, closing conv=<id>`
- Timeout: `rekey timeout, closing conv=<id>`

## Tests

Standalone unit tests live in `src/tests/` (they do not affect the main build):

- `test_aead`: verifies deterministic per-epoch key derivation and that different epochs yield different keys.
- `test_replay`: verifies the anti-replay sliding window (accept, replay, too-old, window advance, near-wrap).

Build example:

```sh
# build main objects first (e.g., aead.o) from src/
make -C src

# then build tests
make -C src/tests
```

Run:

```sh
src/tests/test_aead
src/tests/test_replay
```

### Integration test: kcptcp tunnel + AEAD rekeying

`src/tests/it_kcp` is a small C harness that launches `tcp_echo` (TCP echo on 127.0.0.1:2323), `kcptcp-server`, and `kcptcp-client`, then sends data through the tunnel to validate normal operation and rekey lifecycle. It asserts log lines like `rekey trigger`, `recv REKEY_INIT/ACK`, `epoch switch`, and in timeout mode `rekey timeout, closing`.

Usage (run after building `src` and `src/tests`):

```sh
# Normal rekey path, send 16MB (adjust as needed)
IT_PSK=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
src/tests/it_kcp normal 16

# Timeout scenario: send 16MB, pause server 5000ms at ~8MB to induce rekey timeout
IT_PSK=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
src/tests/it_kcp timeout 16 5000 8
```

Parameters:

- `mode`: `normal` | `timeout`
- `send_mb`: total data to send (MB)
- `pause_ms` (timeout mode): SIGSTOP duration for server; set > `REKEY_TIMEOUT_MS`
- `pause_at_mb` (timeout mode): point to inject the pause

Notes:

- Set `IT_PSK` to a 64-hex (32-byte) key; default is built-in if unset.
- Uses POSIX `fork/exec` and signals (`SIGSTOP`/`SIGCONT`); run on Linux/WSL/MSYS2/MinGW.

## Build

```sh
 make -C src
```

Override tunables with `CFLAGS` as shown in the examples above.

Notes:

- On Linux, native epoll is used. On other platforms, `no-epoll.h` is included automatically by the source as a shim.
