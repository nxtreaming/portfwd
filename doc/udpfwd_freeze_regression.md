# UDP forwarding freeze/hang regression analysis

## Executive summary
- **Root cause commit:** `4418a784aee92bcc260e5d619ed8d1d669ddf784` ("Fix UDP LRU updates to prevent stale evictions").
- **Change volume:** 376 lines touched in `src/udpfwd.c` plus struct churn in `src/proxy_conn.h`, replacing the previously stable LRU maintenance design with a synchronous one we authored.【89a383†L1-L8】
- **Primary change:** Replaced the deferred LRU maintenance loop with synchronous per-packet locking inside `touch_proxy_conn()`.
- **Impact:** Under load the hot path now grabs the global `g_lru_lock` for every datagram, creating severe contention, starving worker threads, and producing the reported multi-second freezes until traffic subsides.

## Stable baseline (`6458690db6c61f05cbe4c94de75bc1c30be7dcda`)
At the last known-good revision the UDP fast path simply marked connections for later LRU maintenance and avoided taking locks while packets were flowing. The periodic maintenance sweep moved any "touched" sessions to the tail of the shared list in manageable segments.【cd8f13†L1-L58】【796039†L24-L63】

```c
static inline void touch_proxy_conn(struct proxy_conn *conn) {
    time_t snap = atomic_load(&g_now_ts);
    time_t new_time = snap ? snap : monotonic_seconds();
    conn->last_active = new_time;
#if ENABLE_LRU_LOCKS
    conn->needs_lru_update = true;
#endif
}
```

```c
static void segmented_update_lru(void) {
#if ENABLE_LRU_LOCKS
    ...
    pthread_mutex_lock(&g_lru_lock);
    list_add_tail(&conn->lru, &g_lru_list);
    conn->needs_lru_update = false;
    pthread_mutex_unlock(&g_lru_lock);
    ...
#endif
}
```

Those helpers ensured that the main loop could defer LRU list manipulation and only acquire `g_lru_lock` tens of times per maintenance interval, even if the forwarder handled thousands of packets per second.

## Regression introduced in `4418a784`
Commit `4418a784` deletes `segmented_update_lru()`, removes the `needs_lru_update` flag from `struct proxy_conn`, and rewires `touch_proxy_conn()` so the hot path takes the LRU mutex on every packet.【cf6d70†L1-L1】【e53733†L1-L1】【91856b†L1-L60】 The current code performs the following steps for each datagram:

1. Read the cached time.
2. Update `last_active`.
3. Acquire `g_lru_lock`.
4. Move the node to the tail of `g_lru_list`.
5. Release the lock.

```c
static inline void touch_proxy_conn(struct proxy_conn *conn) {
    time_t now = cached_now_seconds();
    if (conn->last_active == now)
        return;

    conn->last_active = now;
#if ENABLE_LRU_LOCKS
    pthread_mutex_lock(&g_lru_lock);
    if (!list_empty(&conn->lru)) {
        list_move_tail(&conn->lru, &g_lru_list);
    }
    pthread_mutex_unlock(&g_lru_lock);
    atomic_fetch_add_explicit(&g_stat_lru_immediate_updates, 1, memory_order_relaxed);
#endif
}
```

The main loop still executes maintenance every two seconds but no longer performs any batched LRU work—`segmented_update_lru()` and its call site were both removed—so all ordering updates now happen inside the packet handlers themselves.【91856b†L1-L60】【748d72†L95-L123】【e58550†L1-L64】

### Change audit
- `struct proxy_conn` dropped the `needs_lru_update` flag, eliminating the deferred-update marker used by the maintenance sweep.【cf6d70†L1-L1】【e53733†L1-L1】
- `touch_proxy_conn()` switched from "mark for later" to "lock and relink now" semantics, placing `pthread_mutex_lock(&g_lru_lock)` directly in the hot path.【cd8f13†L17-L33】【91856b†L39-L58】
- The periodic `segmented_update_lru()` function and its invocation inside the two-second maintenance window were excised, removing the batching mechanism entirely.【cd8f13†L21-L58】【796039†L28-L36】【748d72†L95-L123】

## Why this causes freeze/hang symptoms
- `touch_proxy_conn()` runs for every inbound and outbound datagram. Under realistic workloads (10k+ packets/sec) it therefore performs thousands of mutex operations per second on the single global `g_lru_lock`.
- Multiple worker threads enter `handle_client_data()` and `handle_server_data()` concurrently. Each call to `touch_proxy_conn()` serializes behind the mutex, creating a lock convoy where all threads spin waiting for the same lock.
- While threads wait, packet processing stalls, sockets fill, and dependent applications observe the forwarder as "frozen". Once traffic subsides enough for the mutex to become available, the backlog drains and service appears to "recover"—matching the observed tens-of-seconds hang windows.
- Disabling timeouts (`-t 0`) bypasses the problematic block because the new guard returns early, confirming the lock contention as the failure mode rather than stale timestamps.【91856b†L39-L54】

## Subsequent commits
Later commits add debugging, tweak timestamp caching, and adjust maintenance logging, but none of them restore deferred LRU processing. As a result the lock contention introduced in `4418a784` persists all the way to HEAD.

## Recommendation
- Revert or reintroduce the segmented LRU updater so that connection touches simply mark state and the global `g_lru_lock` is only taken during periodic maintenance.
- If immediate updates are required, replace the single global mutex with a lock-free or sharded design to avoid serializing every packet.

Either approach must be validated under realistic packet rates to ensure the UDP forwarder no longer freezes under load.
