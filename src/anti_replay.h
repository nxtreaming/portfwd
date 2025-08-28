#ifndef __PORTFWD_ANTI_REPLAY_H__
#define __PORTFWD_ANTI_REPLAY_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ANTI_REPLAY_WINDOW_SIZE 64

struct anti_replay_detector {
    uint64_t bitmap;
    uint32_t last_seq;
};

void anti_replay_init(struct anti_replay_detector *d);
bool anti_replay_check_and_update(struct anti_replay_detector *d, uint32_t seq);

#ifdef __cplusplus
}
#endif

#endif /* __PORTFWD_ANTI_REPLAY_H__ */
