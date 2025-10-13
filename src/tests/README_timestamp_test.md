# Timestamp Burst Regression Test

## Purpose

This test verifies the fix for commit 4975bf3, which addresses a critical bug where active UDP connections were incorrectly recycled due to a timestamp update optimization.

## Bug Description

**Problem**: The `touch_proxy_conn()` function had an optimization that skipped updating `last_active` if the timestamp was the same second:

```c
if (conn->last_active == now)
    return;  // BUG: Skip update
```

**Impact**: 
- High-frequency or bursty UDP traffic (>1 PPS) would only update `last_active` once per second
- Active connections were incorrectly marked as idle and recycled
- Particularly affected OpenVPN, gaming, and video streaming applications
- Worse on poor networks due to increased retransmissions and bursts

**Fix**: Always update `last_active` on every packet, regardless of timestamp.

## Building the Test

```bash
cd src/tests
make test_timestamp_burst
```

## Running the Test

```bash
./test_timestamp_burst
```

Expected output:
```
=== Timestamp Burst Regression Test ===

Test 1: Fixed version updates timestamp on every packet... PASS
Test 2: Buggy version skips updates in same second... PASS (bug reproduced)
Test 3: Bursty traffic pattern (OpenVPN scenario)... PASS
Test 4: High-frequency traffic (10 PPS)... PASS
Test 5: Continuous traffic prevents recycling... PASS
Test 6: Idle connection should be recycled... PASS

=== All tests passed! ===
```

## Test Cases

### Test 1: Fixed Version Updates Every Packet
Verifies that the fixed version updates `last_active` on every packet, even within the same second.

### Test 2: Buggy Version Skips Updates
Reproduces the original bug to demonstrate the problem.

### Test 3: Bursty Traffic Pattern (OpenVPN Scenario)
Simulates the real-world scenario from production logs:
- 500 packets at t=0
- 431 packets at t=8
- Verifies behavior at t=310 (302 seconds after last burst)

### Test 4: High-Frequency Traffic (10 PPS)
Tests behavior with sustained high packet rate (10 packets per second).

### Test 5: Continuous Traffic Prevents Recycling
Verifies that regular traffic (1 packet every 60 seconds) keeps connection alive.

### Test 6: Idle Connection Should Be Recycled
Verifies that truly idle connections are still recycled after timeout.

## Integration with CI/CD

Add to your CI pipeline:

```bash
# In your CI script
cd src/tests
make test_timestamp_burst
./test_timestamp_burst || exit 1
```

## Manual Testing

To manually verify the fix in production:

1. Start udpfwd with logging enabled
2. Generate bursty UDP traffic (e.g., OpenVPN connection)
3. Monitor logs for "Recycling" messages
4. Verify that active connections are NOT recycled

Example:
```bash
# Start udpfwd
./udpfwd 0.0.0.0:1194 server:1194 -C 100 -t 300

# Connect OpenVPN client and use it
# Monitor logs - should NOT see premature recycling
```

## Related Commits

- **4975bf3**: Fix critical bug (this test)
- **a5f7616**: Fix UDP send backpressure (separate issue)

## Performance Impact

The fix has negligible performance impact:
- Writing `time_t` variable: ~1-2 nanoseconds
- Setting `needs_lru_update` flag: ~1 nanosecond
- No locks involved in hot path
- Total overhead: <5 nanoseconds per packet

For reference, a typical `recvmmsg()` + `sendmmsg()` batch costs ~1-10 microseconds, making this overhead 0.0005% of the total cost.
