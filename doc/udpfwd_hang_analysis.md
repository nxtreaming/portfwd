# udpfwd hang analysis

## Summary
While reviewing `src/udpfwd.c` to diagnose the long-running hang that appears after the proxy has been forwarding traffic for several minutes, I noticed that the cached timestamp (`g_now_ts`) used to drive connection expiration is updated in the wrong place. The main event loop writes the current monotonic time into `g_now_ts` **before** it goes to sleep in `epoll_wait()`. Functions that mark a connection as active, such as `touch_proxy_conn()`, read that cached value and store it in `conn->last_active`. As a result, every datagram handled during one pass through the event loop receives the timestamp that was recorded *before* the call to `epoll_wait()`.

If the loop then blocks in `epoll_wait()` for a long period (for example because only a trickle of traffic arrives), the cached time lags behind the real time by the entire sleep duration. When the maintenance pass runs, `proxy_conn_walk_continue()` compares the fresh current time with the stale `conn->last_active`, computes a large idle duration, and tears the mapping down even though the flow is still active. Once the mapping disappears, datagrams sent by the client no longer find an existing `proxy_conn`, the forwarding socket is recreated, and the remote peer sees traffic coming from a different 5-tuple. That looks like the proxy has frozen until the application-level protocol restarts.

### Key locations
- The cached timestamp is recorded before blocking in `epoll_wait()`.【F:src/udpfwd.c†L1692-L1716】
- `touch_proxy_conn()` copies that cached timestamp into `conn->last_active` for every packet we forward, so it inherits the stale value.【F:src/udpfwd.c†L775-L788】
- The LRU reaper uses `cached_now_seconds()` (which simply returns `g_now_ts`) to decide which connections are idle and should be dropped.【F:src/udpfwd.c†L1025-L1066】

Because the timestamp cache is only refreshed *before* the blocking wait, the timeout calculation can drift by multiple seconds (or even minutes if the loop keeps processing other fds) and eventually exceeds the configured timeout. At that point the proxy releases otherwise healthy sessions, and UDP forwarding appears to hang from the user's perspective.

## Suggested direction
Move the `atomic_store(&g_now_ts, current_ts);` call so that it runs **after** `epoll_wait()` returns with events, or refresh the cached time again immediately before calling `touch_proxy_conn()`. That way the activity timestamps track the real arrival time of packets and the timeout walker no longer evicts live flows.
