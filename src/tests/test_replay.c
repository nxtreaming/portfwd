#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

/* Minimal copy of seq diff and replay window logic for testing */
static inline int32_t seq_diff_u32(uint32_t a, uint32_t b) {
    return (int32_t)(a - b);
}

static inline bool aead_replay_check_and_update(uint32_t seq, uint32_t *p_win, uint64_t *p_mask) {
    uint32_t win = *p_win;
    uint64_t mask = *p_mask;
    if (win == UINT32_MAX) { /* uninitialized */
        *p_win = seq;
        *p_mask = 1ULL; /* mark bit0 */
        return true;
    }
    int32_t d = seq_diff_u32(seq, win);
    if (d > 0) {
        /* seq ahead of window; advance */
        uint32_t shift = (d >= 64) ? 64u : (uint32_t)d;
        mask = (shift >= 64) ? 0ULL : (mask << shift);
        mask |= 1ULL; /* mark newest */
        win = seq;
        *p_win = win; *p_mask = mask; return true;
    }
    /* seq <= win */
    int32_t behind = -d; /* how far behind win */
    if (behind >= 64) {
        /* too old */
        return false;
    }
    uint64_t bit = 1ULL << behind;
    if (mask & bit) {
        /* replay */
        return false;
    }
    mask |= bit;
    *p_win = win; *p_mask = mask; return true;
}

static int expect_true(bool v, const char *msg) {
    if (!v) { fprintf(stderr, "FAIL: %s\n", msg); return 1; }
    return 0;
}
static int expect_false(bool v, const char *msg) {
    if (v) { fprintf(stderr, "FAIL: %s\n", msg); return 1; }
    return 0;
}

int main(void) {
    int fails = 0;
    uint32_t win = UINT32_MAX; /* uninit */
    uint64_t mask = 0;

    /* First packet initializes */
    fails += expect_true(aead_replay_check_and_update(1000, &win, &mask), "init accept 1000");

    /* Replay same seq -> reject */
    fails += expect_false(aead_replay_check_and_update(1000, &win, &mask), "reject replay 1000");

    /* In-window older but unseen seq -> accept */
    fails += expect_true(aead_replay_check_and_update(999, &win, &mask), "accept 999 in-window");
    /* Replay 999 -> reject */
    fails += expect_false(aead_replay_check_and_update(999, &win, &mask), "reject replay 999");

    /* Too old (beyond 64) -> reject */
    fails += expect_false(aead_replay_check_and_update(1000 - 64, &win, &mask), "reject too old 1000-64");

    /* Advance window forward by large gap -> accept and reset mask appropriately */
    fails += expect_true(aead_replay_check_and_update(2000, &win, &mask), "advance to 2000");
    /* Now in-window older (1999) unseen -> accept */
    fails += expect_true(aead_replay_check_and_update(1999, &win, &mask), "accept 1999 after advance");

    /* Wraparound behavior: accept high values then low wrap to small increases should be considered older (depending on signed diff) */
    win = UINT32_MAX; mask = 0; /* reset */
    fails += expect_true(aead_replay_check_and_update(0xFFFFFFF0u, &win, &mask), "accept near-max");
    /* small forward (wrap) should be ahead (positive diff) because of 2's complement diff */
    fails += expect_true(aead_replay_check_and_update(0xFFFFFFF1u, &win, &mask), "accept +1 near wrap");
    /* big forward past wrap */
    fails += expect_true(aead_replay_check_and_update(5u, &win, &mask), "accept wrap to 5");

    if (fails) {
        fprintf(stderr, "Replay window tests failed: %d\n", fails);
        return 1;
    }
    printf("OK: replay window basic behavior verified\n");
    return 0;
}
