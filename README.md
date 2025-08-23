portfwd
=======

User-space TCP/UDP port forwarding services

## Summary
 This project contains two applications: tcpfwd, udpfwd, which are for TCP and UDP port forwarding literally.
 Written in pure C.
 
## Usage ##

    tcpfwd|udpfwd <local_addr:local_port> <dest_addr:dest_port> [-d] [-o]
     
    Options:
      -d              run in background
      -o              accept IPv6 connections only for IPv6 listener
      -p <pidfile>    write PID to file

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

## Signals, PID files, and graceful shutdown

Both `tcpfwd` and `udpfwd` support optional PID files via `-p <pidfile>`. The PID file is created exclusively, checks for stale PIDs, and is automatically removed on clean exit. The following signals trigger graceful shutdown and PID cleanup:

- SIGINT, SIGTERM, SIGHUP, SIGQUIT

On receipt, the main loop exits cleanly; registered `atexit` handlers remove the PID file.

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

## Build

```sh
make -C src
```

Override tunables with `CFLAGS` as shown in the examples above.

Notes:

- On Linux, native epoll is used. On other platforms, `no-epoll.h` is included automatically by the source as a shim.
