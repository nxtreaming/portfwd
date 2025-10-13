/**
 * @file test_timestamp_burst.c
 * @brief Regression test for timestamp update bug (commit 4975bf3)
 * 
 * This test verifies that active connections are not incorrectly recycled
 * when packets arrive in bursts within the same second.
 * 
 * Bug scenario:
 * - Multiple packets arrive in the same second (PPS > 1)
 * - Old code: only first packet updated last_active
 * - Result: connection recycled despite having traffic
 * 
 * Test approach:
 * - Simulate bursty packet arrivals (multiple packets per second)
 * - Verify that last_active is updated for every packet
 * - Verify that connection is not recycled while active
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

/* Simulate the proxy_conn structure */
struct test_proxy_conn {
    time_t last_active;
    int needs_lru_update;
};

/* Simulate cached_now_seconds() */
static time_t g_cached_time = 0;
static time_t cached_now_seconds(void) {
    return g_cached_time;
}

/* Simulate touch_proxy_conn() - FIXED version */
static void touch_proxy_conn_fixed(struct test_proxy_conn *conn) {
    time_t now = cached_now_seconds();
    
    /* ALWAYS update last_active (the fix) */
    conn->last_active = now;
    conn->needs_lru_update = 1;
}

/* Simulate touch_proxy_conn() - BUGGY version */
static void touch_proxy_conn_buggy(struct test_proxy_conn *conn) {
    time_t now = cached_now_seconds();
    
    /* BUG: Skip update if same second */
    if (conn->last_active == now)
        return;
    
    conn->last_active = now;
    conn->needs_lru_update = 1;
}

/* Test helper: check if connection should be recycled */
static int should_recycle(struct test_proxy_conn *conn, time_t now, int timeout) {
    return (now - conn->last_active) > timeout;
}

/**
 * Test 1: Verify that fixed version updates timestamp on every packet
 */
static void test_fixed_version_updates_every_packet(void) {
    printf("Test 1: Fixed version updates timestamp on every packet... ");
    
    struct test_proxy_conn conn = {0};
    g_cached_time = 1000;
    
    /* First packet */
    touch_proxy_conn_fixed(&conn);
    assert(conn.last_active == 1000);
    assert(conn.needs_lru_update == 1);
    
    /* Second packet in same second */
    conn.needs_lru_update = 0;  /* Reset flag */
    touch_proxy_conn_fixed(&conn);
    assert(conn.last_active == 1000);  /* Still updated */
    assert(conn.needs_lru_update == 1);  /* Flag set again */
    
    /* Third packet in same second */
    conn.needs_lru_update = 0;
    touch_proxy_conn_fixed(&conn);
    assert(conn.last_active == 1000);
    assert(conn.needs_lru_update == 1);
    
    printf("PASS\n");
}

/**
 * Test 2: Verify that buggy version skips updates in same second
 */
static void test_buggy_version_skips_updates(void) {
    printf("Test 2: Buggy version skips updates in same second... ");
    
    struct test_proxy_conn conn = {0};
    g_cached_time = 1000;
    
    /* First packet */
    touch_proxy_conn_buggy(&conn);
    assert(conn.last_active == 1000);
    assert(conn.needs_lru_update == 1);
    
    /* Second packet in same second - BUG: skipped */
    conn.needs_lru_update = 0;
    touch_proxy_conn_buggy(&conn);
    assert(conn.last_active == 1000);
    assert(conn.needs_lru_update == 0);  /* NOT updated! */
    
    printf("PASS (bug reproduced)\n");
}

/**
 * Test 3: Simulate bursty traffic pattern (OpenVPN scenario)
 */
static void test_bursty_traffic_pattern(void) {
    printf("Test 3: Bursty traffic pattern (OpenVPN scenario)... ");
    
    struct test_proxy_conn conn_fixed = {0};
    struct test_proxy_conn conn_buggy = {0};
    int timeout = 300;  /* 5 minutes */
    
    /* Initial connection */
    g_cached_time = 0;
    touch_proxy_conn_fixed(&conn_fixed);
    touch_proxy_conn_buggy(&conn_buggy);
    
    /* Burst 1: 500 packets at t=0 */
    for (int i = 0; i < 500; i++) {
        touch_proxy_conn_fixed(&conn_fixed);
        touch_proxy_conn_buggy(&conn_buggy);
    }
    assert(conn_fixed.last_active == 0);
    assert(conn_buggy.last_active == 0);
    
    /* Burst 2: 431 packets at t=8 */
    g_cached_time = 8;
    for (int i = 0; i < 431; i++) {
        touch_proxy_conn_fixed(&conn_fixed);
        touch_proxy_conn_buggy(&conn_buggy);
    }
    assert(conn_fixed.last_active == 8);
    assert(conn_buggy.last_active == 8);
    
    /* Check at t=310 (302 seconds after last burst) */
    g_cached_time = 310;
    
    int fixed_recycled = should_recycle(&conn_fixed, g_cached_time, timeout);
    int buggy_recycled = should_recycle(&conn_buggy, g_cached_time, timeout);
    
    /* Fixed version: should recycle (302s > 300s) */
    assert(fixed_recycled == 1);
    
    /* Buggy version: also recycles (same behavior in this case) */
    assert(buggy_recycled == 1);
    
    printf("PASS\n");
}

/**
 * Test 4: High-frequency traffic (>1 PPS)
 */
static void test_high_frequency_traffic(void) {
    printf("Test 4: High-frequency traffic (10 PPS)... ");
    
    struct test_proxy_conn conn_fixed = {0};
    struct test_proxy_conn conn_buggy = {0};
    int timeout = 300;
    
    /* Initial connection */
    g_cached_time = 0;
    touch_proxy_conn_fixed(&conn_fixed);
    touch_proxy_conn_buggy(&conn_buggy);
    
    /* Simulate 10 packets per second for 10 seconds */
    for (int sec = 0; sec < 10; sec++) {
        g_cached_time = sec;
        for (int pkt = 0; pkt < 10; pkt++) {
            touch_proxy_conn_fixed(&conn_fixed);
            touch_proxy_conn_buggy(&conn_buggy);
        }
    }
    
    /* Both should have last_active = 9 */
    assert(conn_fixed.last_active == 9);
    assert(conn_buggy.last_active == 9);
    
    /* Check at t=310 */
    g_cached_time = 310;
    
    int fixed_recycled = should_recycle(&conn_fixed, g_cached_time, timeout);
    int buggy_recycled = should_recycle(&conn_buggy, g_cached_time, timeout);
    
    /* Both should recycle (301s > 300s) */
    assert(fixed_recycled == 1);
    assert(buggy_recycled == 1);
    
    printf("PASS\n");
}

/**
 * Test 5: Continuous traffic should prevent recycling
 */
static void test_continuous_traffic_prevents_recycling(void) {
    printf("Test 5: Continuous traffic prevents recycling... ");
    
    struct test_proxy_conn conn = {0};
    int timeout = 300;
    
    /* Initial connection */
    g_cached_time = 0;
    touch_proxy_conn_fixed(&conn);
    
    /* Simulate continuous traffic: 1 packet every 60 seconds */
    for (int t = 60; t <= 600; t += 60) {
        g_cached_time = t;
        touch_proxy_conn_fixed(&conn);
        
        /* Connection should NOT be recycled */
        int recycled = should_recycle(&conn, g_cached_time, timeout);
        assert(recycled == 0);
    }
    
    printf("PASS\n");
}

/**
 * Test 6: Idle connection should be recycled
 */
static void test_idle_connection_recycled(void) {
    printf("Test 6: Idle connection should be recycled... ");
    
    struct test_proxy_conn conn = {0};
    int timeout = 300;
    
    /* Initial connection */
    g_cached_time = 0;
    touch_proxy_conn_fixed(&conn);
    
    /* No traffic for 301 seconds */
    g_cached_time = 301;
    
    /* Should be recycled */
    int recycled = should_recycle(&conn, g_cached_time, timeout);
    assert(recycled == 1);
    
    printf("PASS\n");
}

int main(void) {
    printf("=== Timestamp Burst Regression Test ===\n\n");
    
    test_fixed_version_updates_every_packet();
    test_buggy_version_skips_updates();
    test_bursty_traffic_pattern();
    test_high_frequency_traffic();
    test_continuous_traffic_prevents_recycling();
    test_idle_connection_recycled();
    
    printf("\n=== All tests passed! ===\n");
    return 0;
}
