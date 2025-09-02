# portfwd

User-space TCP/UDP port forwarding services

## Summary

This project contains four applications: tcpfwd, udpfwd, kcptcp_client and kcptcp_server, providing TCP and UDP port forwarding.
Written in pure C.

## Usage

### tcpfwd

    tcpfwd [options] <local_addr:local_port> <dest_addr:dest_port>

    Options:
      -d                 run in background (daemonize)
      -p <pidfile>       write PID to file
      -b                 base-addr mode (Linux TPROXY/original-dst based address math; expert use only)
      -r                 set SO_REUSEADDR on listener socket
      -R                 set SO_REUSEPORT on listener socket
      -6                 for IPv6 listener, set IPV6_V6ONLY
      -h                 show help

### udpfwd

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

### kcptcp-client

    kcptcp-client [options] <local_tcp_addr:port> <remote_udp_addr:port>

    Options:
      -d                 run in background (daemonize)
      -p <pidfile>       write PID to file
      -r                 set SO_REUSEADDR on listener socket
      -R                 set SO_REUSEPORT on listener socket
      -6                 for IPv6 listener, set IPV6_V6ONLY
      -S <bytes>         SO_RCVBUF/SO_SNDBUF size (default build-time)
      -M <mtu>           KCP MTU (default 1350; tune to avoid IP fragmentation)
      -A <0|1>           KCP nodelay (default 1)
      -I <ms>            KCP interval in ms (default 10)
      -X <n>             KCP fast resend (default 2)
      -C <0|1>           KCP no congestion control (default 1)
      -w <sndwnd>        KCP send window in packets (default 1024)
      -W <rcvwnd>        KCP recv window in packets (default 1024)
      -N                 enable TCP_NODELAY on client sockets
      -K <hex>           32-byte PSK in hex (REQUIRED; outer obfuscation + stealth handshake)
      -g <min-max>       aggregate first TCP bytes for min-max ms before first UDP (default 20-80)
      -G <bytes>         max bytes to embed in first UDP packet (default 1024)
      -P off|auto|csv:<ports> per-port aggregation profile
                           off: disable per-port heuristics
                           auto: built-in profiles (SSH/web/RDP/VNC)
                           csv: comma-separated ports with no aggregation
      -h                 show help

Notes:

- Listens on a local TCP address and forwards streams over UDP using KCP.
- PSK `-K` is required. Outer obfuscation (ChaCha20-Poly1305) and stealth handshake are always enabled with the PSK; after handshake, a per-session key is used for the outer layer.
- Stealth handshake: the first UDP packet looks like encrypted data and can embed the first TCP bytes.
- Aggregation (`-g/-G/-P`) adds a small randomized delay to gather initial TCP bytes to mimic normal traffic.
  - Effective embed cap is MTU-aware: the actual first-packet embed size is bounded by a budget computed from the KCP MTU to avoid fragmentation (i.e., `embed <= min(-G, MTU budget)`).
  - If no early TCP bytes arrive within the aggregation window, the client still sends a stealth packet with random padding.

### kcptcp-server

    kcptcp-server [options] <local_udp_addr:port> <target_tcp_addr:port>

    Options:
      -d                 run in background (daemonize)
      -p <pidfile>       write PID to file
      -r                 set SO_REUSEADDR on listener socket
      -R                 set SO_REUSEPORT on listener socket
      -6                 for IPv6 listener, set IPV6_V6ONLY
      -S <bytes>         SO_RCVBUF/SO_SNDBUF size (default build-time)
      -M <mtu>           KCP MTU (default 1350; tune to avoid IP fragmentation)
      -A <0|1>           KCP nodelay (default 1)
      -I <ms>            KCP interval in ms (default 10)
      -X <n>             KCP fast resend (default 2)
      -C <0|1>           KCP no congestion control (default 1)
      -w <sndwnd>        KCP send window in packets (default 1024)
      -W <rcvwnd>        KCP recv window in packets (default 1024)
      -N                 enable TCP_NODELAY on outbound TCP to target
      -K <hex>           32-byte PSK in hex (REQUIRED; outer obfuscation + stealth handshake)
      -j <min-max>       jitter response to first packet by min-max ms (stealth)
      -h                 show help

Notes:

- Listens on a UDP address, accepts KCP sessions, and bridges to a target TCP service.
- PSK must match the client; stealth handshake response can be jittered with `-j` to mimic normal traffic timing.
- Default jitter window is 5–20ms. Set `-j 0-0` to disable jitter.

## Examples

### Map local TCP port 1022 to 192.168.1.77:22

    tcpfwd 0.0.0.0:1022 192.168.1.77:22     # allow access from all hosts
    tcpfwd 127.0.0.1:1022 192.168.1.77:22   # only allow localhost
    tcpfwd [::]:1022 192.168.1.77:22        # allow access to port 1022 via both IPv4 and IPv6

### Map local UDP port 53 to 8.8.8.8:53

    udpfwd 0.0.0.0:53 8.8.8.8:53
    udpfwd [::]:53 8.8.8.8:53

### IPv4-IPv6 transforming

    udpfwd [::]:1701 localhost:1701         # add IPv6 support for a local L2TP service
    tcpfwd 0.0.0.0:80 [2001:db8:3::2]:80    # enable IPv4 access for an IPv6-only web service

### KCP TCP tunneling (encrypted)

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

- The `-K` PSK must be the same 32-byte value (64 hex chars) on both sides; it is now required.
- If you observe IP fragmentation, try `-M 1200` on both client and server.
- Client-side stealth tunables:
  - `-g 30-100 -G 1200` for web-like ports (80/443) to gather HTTP/TLS client hello.
  - `-P off` to disable per-port heuristics and always use `-g/-G` as provided.
  - `-P csv:22,2222` to disable aggregation on specific ports (e.g., SSH).
- Server-side stealth jitter:
  - `-j 5-25` to add small jitter before sending handshake response.

#### Deterministic conv (optional)

By default the server derives the KCP conversation ID (conv) from the PSK and the client token during the stealth handshake. This binds the session identity to the key material and reduces metadata randomness.

- Disable via env var on the server:

```sh
PFWD_DETERMINISTIC_CONV=0 kcptcp-server ...
```

When disabled, the server uses secure random conv IDs with a uniqueness check.

#### Stealth handshake notes

- Client aggregates early TCP bytes (if any) for a short window and embeds up to the MTU-aware cap into the first UDP packet.
- The first UDP packet always looks like encrypted payload (no plaintext headers). If there is nothing to embed, random padding is used.
- Server can jitter the handshake response (`-j`) to avoid an immediate request/response signature.
- Per-port client profiles (`-P`) can turn aggregation off for interactive ports (e.g., `-P csv:22,2222`) or use built-in heuristics (`-P auto`).

### MTU budget for first‑packet embed

- Formula (application payload embedded into the first UDP packet):
  - `embed_budget ≈ KCP_MTU - (nonce 12 + tag 16 + payload 36 + padding)`
  - Payload is the stealth handshake header (36 bytes); padding is random 16–47 bytes.
  - Therefore: `embed_budget ∈ [KCP_MTU - 111, KCP_MTU - 80]`
- Typical ranges (bytes):
  - KCP_MTU=1200 → 1089–1120
  - KCP_MTU=1350 → 1239–1270 (default build)
  - KCP_MTU=1480 → 1369–1400
- The client takes `min(-G, MTU budget)` when embedding early TCP bytes to avoid fragmentation.

### Wire-level overhead, FIN, and MTU budgeting

- Wire shape (outer obfuscation): every UDP datagram on the wire is
  `[nonce 12B | ciphertext(inner) | tag 16B]`. This is a fixed 28-byte overhead per packet.
- KCP segment header is ~24 bytes inside the ciphertext. Application payload is carried in the KCP segment body.
- FIN signaling: there is no inner protocol anymore. A half-close is indicated by a 1-byte marker inside the KCP payload: `0xF1` (aka `FIN_MARKER`).
- Effective KCP MTU: the project configures KCP to use `effective_mtu = configured_mtu - 28` so that the wire-level UDP payload remains within the configured MTU after adding the outer obfuscation. This avoids IP fragmentation on typical paths.
- Stealth handshake padding and response padding are both in the range `0..15` bytes to keep overhead low while preserving length variation.
- First-packet embed budgeting: the client computes a budget from the effective MTU so that the first UDP packet (handshake + optional embedded TCP bytes + padding + outer 28B) does not exceed the MTU.

Implications:
- For large payloads, the fixed 28B overhead is amortized. For small packets, consider tuning KCP aggregation and MTU to improve payload ratio.
- If you still observe fragmentation, reduce `-M` on both client and server (e.g., `-M 1200`).


### Generate a secure PSK

Use a cryptographically secure random 32-byte key (64 hex characters).

Linux/macOS:

```sh
openssl rand -hex 32
# or
head -c 32 /dev/urandom | xxd -p -c 64
# or
python3 - << 'PY'
import secrets; print(secrets.token_hex(32))
PY
```

Windows PowerShell:

```powershell
[Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLower()
# compatible form:
$b = New-Object byte[] 32; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); ($b | ForEach-Object { $_.ToString('x2') }) -join ''
```

Validate: ensure exactly 64 hex chars (regex `^[0-9a-fA-F]{64}$`).

Use with CLI:

```sh
kcptcp-server 0.0.0.0:4000 127.0.0.1:22 -K <64-hex-psk>
kcptcp-client 127.0.0.1:2022 server:4000     -K <64-hex-psk>
```

Store securely:

```sh
echo "<64-hex-psk>" > psk.txt && chmod 600 psk.txt
kcptcp-server ... -K "$(cat psk.txt)"
kcptcp-client ... -K "$(cat psk.txt)"
```

Rotate periodically: generate a new PSK and restart client/server with the same new value; existing sessions continue until closed.

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

## KCP + Outer Obfuscation Overview

- Transport: KCP over UDP (for `kcptcp-client`/`kcptcp-server`).
- Outer layer: ChaCha20-Poly1305 obfuscation on the entire KCP datagram.
- Each session derives a 32-byte session key after handshake (PSK is used only before handshake).

## Session key & wire behavior

- PSK is used only to authenticate and encrypt the stealth handshake and the very first messages.
- After handshake, a per-session key is used for the outer layer; there is no inner protocol.
- All UDP datagrams on the wire share the same obfuscated shape: `[nonce 12B | ciphertext | tag 16B]`.
- To avoid fragmentation, KCP MTU is configured as `effective_mtu = configured_mtu - 28`.
- FIN is a single byte (0xF1) carried inside KCP payload.


## Tests

Standalone unit tests live in `src/tests/` (they do not affect the main build):

- `test_handshake`: validates stealth handshake pack/unpack and token/conv checks.
- `test_outer_obfs_handshake`: validates outer obfuscation for handshake packets.
- `test_outer_obfs_kcp`: validates outer obfuscation for KCP-shaped datagrams.

Build example:

```sh
make -C src
make -C src/tests
```

Run:

```sh
src/tests/test_handshake
src/tests/test_outer_obfs_handshake
src/tests/test_outer_obfs_kcp
```

### Integration test: kcptcp tunnel

`src/tests/it_kcp` is a small C harness that launches `tcp_echo` (TCP echo on 127.0.0.1:2323), `kcptcp-server`, and `kcptcp-client`, then sends data through the tunnel to validate normal operation (connectivity, throughput baseline, FIN half‑close).

Usage (run after building `src` and `src/tests`):

```sh
src/tests/it_kcp
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
