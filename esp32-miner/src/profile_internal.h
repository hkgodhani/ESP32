#pragma once
#include <stdint.h>
#include <stdbool.h>

#define PROFILE_SAMPLE_MASK 0x3FF

static inline uint32_t get_cycle_count(void)
{
    uint32_t cyc;
    __asm__ volatile("rsr %0, ccount" : "=a"(cyc));
    return cyc;
}

typedef enum {
    HW_FILL_BLOCK_UPPER,
    HW_START1,
    HW_FILL_UPPER,
    HW_WAIT1,
    HW_CONTINUE,
    HW_FILL_DOUBLE,
    HW_WAIT2,
    HW_LOAD1,
    HW_WAIT3,
    HW_START2,
    HW_WAIT4,
    HW_LOAD2,
    HW_READ_DIGEST,
    HW_TARGET_CHECK,
    HW_FILL_BLOCK_LOWER,
    HW_STAGE_COUNT
} hw_stage_t;

extern const char * const hw_stage_names[HW_STAGE_COUNT];

typedef enum {
    SW_NONCE_UPDATE,
    SW_SHA_COMPUTE,
    SW_TARGET_CHECK,
    SW_STAGE_COUNT
} sw_stage_t;

extern const char * const sw_stage_names[SW_STAGE_COUNT];

typedef struct {
    uint64_t total;
    uint32_t cnt;
    uint32_t min;
    uint32_t max;
} stage_acc_t;

typedef struct {
    stage_acc_t stages[HW_STAGE_COUNT];
    uint64_t hash_total;
    uint32_t hash_cnt;
} hw_profile_t;

typedef struct {
    stage_acc_t stages[SW_STAGE_COUNT];
    uint64_t hash_total;
    uint32_t hash_cnt;
} sw_profile_t;

typedef struct {
    uint32_t jobs_recv;
    uint32_t jobs_switch_hw;
    uint32_t jobs_switch_sw;
    uint32_t shares_found;
    uint32_t shares_submit;
    uint32_t shares_accept;
    uint32_t shares_reject;
    uint32_t mutex_cont;
    double best_diff;
    uint64_t batch_nonces;
    uint32_t batch_cnt;
} event_ctrs_t;

typedef struct {
    uint64_t total;
    uint32_t cnt;
    uint32_t min;
    uint32_t max;
} js_latency_t;

extern uint32_t profile_self_overhead;
extern uint32_t profile_hw_start_times[HW_STAGE_COUNT];
extern uint32_t profile_sw_start_times[SW_STAGE_COUNT];
extern uint32_t profile_hw_hash_start;
extern uint32_t profile_sw_hash_start;
extern hw_profile_t profile_hw;
extern sw_profile_t profile_sw;
extern event_ctrs_t profile_ev;
extern js_latency_t profile_js;
extern uint32_t profile_js_time;
