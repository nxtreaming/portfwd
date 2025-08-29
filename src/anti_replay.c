#include "anti_replay.h"

void anti_replay_init(struct anti_replay_detector *d) {
    d->bitmap = 0;
    d->last_seq = 0;
}

bool anti_replay_check_and_update(struct anti_replay_detector *d,
                                  uint32_t seq) {
    if (seq > d->last_seq) {
        uint32_t diff = seq - d->last_seq;
        if (diff < ANTI_REPLAY_WINDOW_SIZE) {
            d->bitmap <<= diff;
            d->bitmap |= 1;
        } else {
            d->bitmap = 1;
        }
        d->last_seq = seq;
        return true;
    }

    uint32_t diff = d->last_seq - seq;
    if (diff >= ANTI_REPLAY_WINDOW_SIZE) {
        return false; // Too old
    }

    if ((d->bitmap >> diff) & 1) {
        return false; // Replay
    }

    d->bitmap |= (1ULL << diff);
    return true;
}
