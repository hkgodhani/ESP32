#pragma once
#include <stdint.h>
#include <stdbool.h>

#define PROFILE_SAMPLE_MASK 0x3FF

#include "profile_internal.h"

#ifdef PROFILE_ENABLED

void profile_init(void);
void profile_measure_overhead(void);

void profile_job_recv(void);
void profile_job_switch_hw(void);
void profile_job_switch_sw(void);
void profile_share_found(void);
void profile_share_submit(void);
void profile_share_accept(void);
void profile_share_reject(void);
void profile_mutex_cont(void);
void profile_best_diff(double d);
void profile_batch(uint32_t n);

void profile_report_hw(const char *tag, uint64_t total_h, uint32_t sec, uint32_t self_cyc);
void profile_report_sw(const char *tag, uint64_t total_h, uint32_t sec, uint32_t self_cyc);

void profile_set_sha(const char *name);

static inline bool profile_check(uint32_t nonce)
{
    return (nonce & PROFILE_SAMPLE_MASK) == 0;
}

static inline void profile_hw_start(int stage)
{
    profile_hw_start_times[stage] = get_cycle_count();
}

static inline void profile_hw_end(int stage)
{
    uint32_t _d = get_cycle_count() - profile_hw_start_times[stage];
    if (_d >= profile_self_overhead) _d -= profile_self_overhead;
    stage_acc_t *a = &profile_hw.stages[stage];
    a->total += _d;
    a->cnt++;
    if (_d < a->min) a->min = _d;
    if (_d > a->max) a->max = _d;
}

static inline void profile_sw_start(int stage)
{
    profile_sw_start_times[stage] = get_cycle_count();
}

static inline void profile_sw_end(int stage)
{
    uint32_t _d = get_cycle_count() - profile_sw_start_times[stage];
    if (_d >= profile_self_overhead) _d -= profile_self_overhead;
    stage_acc_t *a = &profile_sw.stages[stage];
    a->total += _d;
    a->cnt++;
    if (_d < a->min) a->min = _d;
    if (_d > a->max) a->max = _d;
}

static inline void profile_hw_hash_begin(void)
{
    profile_hw_hash_start = get_cycle_count();
}

static inline void profile_hw_hash_end(void)
{
    uint32_t _d = get_cycle_count() - profile_hw_hash_start;
    if (_d >= profile_self_overhead) _d -= profile_self_overhead;
    profile_hw.hash_total += _d;
    profile_hw.hash_cnt++;
}

static inline void profile_sw_hash_begin(void)
{
    profile_sw_hash_start = get_cycle_count();
}

static inline void profile_sw_hash_end(void)
{
    uint32_t _d = get_cycle_count() - profile_sw_hash_start;
    if (_d >= profile_self_overhead) _d -= profile_self_overhead;
    profile_sw.hash_total += _d;
    profile_sw.hash_cnt++;
}

static inline void profile_js_start(void)
{
    profile_js_time = get_cycle_count();
}

static inline void profile_js_end(void)
{
    uint32_t _d = get_cycle_count() - profile_js_time;
    if (_d >= profile_self_overhead) _d -= profile_self_overhead;
    profile_js.total += _d;
    profile_js.cnt++;
    if (_d < profile_js.min) profile_js.min = _d;
    if (_d > profile_js.max) profile_js.max = _d;
}

#else

#define profile_init()                         ((void)0)
#define profile_measure_overhead()             ((void)0)
#define profile_check(nonce)                   ((void)(nonce), false)
#define profile_hw_start(s)                    ((void)(s))
#define profile_hw_end(s)                      ((void)(s))
#define profile_sw_start(s)                    ((void)(s))
#define profile_sw_end(s)                      ((void)(s))
#define profile_hw_hash_begin()                ((void)0)
#define profile_hw_hash_end()                  ((void)0)
#define profile_sw_hash_begin()                ((void)0)
#define profile_sw_hash_end()                  ((void)0)
#define profile_job_recv()                     ((void)0)
#define profile_job_switch_hw()                ((void)0)
#define profile_job_switch_sw()                ((void)0)
#define profile_share_found()                  ((void)0)
#define profile_share_submit()                 ((void)0)
#define profile_share_accept()                 ((void)0)
#define profile_share_reject()                 ((void)0)
#define profile_mutex_cont()                   ((void)0)
#define profile_best_diff(d)                   ((void)(d))
#define profile_batch(n)                       ((void)(n))
#define profile_js_start()                     ((void)0)
#define profile_js_end()                       ((void)0)
#define profile_report_hw(t,h,s,o)             ((void)(t),(void)(h),(void)(s),(void)(o))
#define profile_report_sw(t,h,s,o)             ((void)(t),(void)(h),(void)(s),(void)(o))
#define profile_set_sha(n)                     ((void)(n))

#endif
