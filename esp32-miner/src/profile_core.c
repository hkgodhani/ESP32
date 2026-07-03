#include "profile.h"
#include <string.h>
#include "esp_log.h"

static const char *TAG_P = "PROFILE";

uint32_t profile_self_overhead;
uint32_t profile_hw_start_times[HW_STAGE_COUNT];
uint32_t profile_sw_start_times[SW_STAGE_COUNT];
uint32_t profile_hw_hash_start;
uint32_t profile_sw_hash_start;
hw_profile_t profile_hw;
sw_profile_t profile_sw;
event_ctrs_t profile_ev;
js_latency_t profile_js;
uint32_t profile_js_time;
static const char *s_sha_name;

const char * const hw_stage_names[HW_STAGE_COUNT] = {
    "fill_block_up", "start1", "fill_upper", "wait1",
    "continue", "fill_double", "wait2",
    "load1", "wait3",
    "start2", "wait4",
    "load2", "read_digest", "target_check",
    "fill_block_lo"
};

const char * const sw_stage_names[SW_STAGE_COUNT] = {
    "nonce_update", "sha_compute", "target_check"
};

void profile_init(void)
{
    memset(&profile_hw, 0, sizeof(profile_hw));
    memset(&profile_sw, 0, sizeof(profile_sw));
    memset(&profile_ev, 0, sizeof(profile_ev));
    memset(&profile_js, 0, sizeof(profile_js));
    for (int i = 0; i < HW_STAGE_COUNT; i++) {
        profile_hw.stages[i].min = 0xFFFFFFFF;
    }
    for (int i = 0; i < SW_STAGE_COUNT; i++) {
        profile_sw.stages[i].min = 0xFFFFFFFF;
    }
    profile_js.min = 0xFFFFFFFF;
    s_sha_name = "none";
}

void profile_measure_overhead(void)
{
    uint32_t trials = 10000;
    uint32_t start = get_cycle_count();
    uint32_t sum = 0;
    for (uint32_t i = 0; i < trials; i++) {
        uint32_t a = get_cycle_count();
        uint32_t b = get_cycle_count();
        sum += (b - a);
    }
    uint32_t end = get_cycle_count();
    uint32_t total = end - start;
    profile_self_overhead = sum / trials;
    ESP_LOGI(TAG_P, "Overhead: %lu cycles/call  total=%lu for %lu trials",
             (unsigned long)profile_self_overhead, (unsigned long)total, (unsigned long)trials);
}

void profile_job_recv(void) { profile_ev.jobs_recv++; }
void profile_job_switch_hw(void) { profile_ev.jobs_switch_hw++; }
void profile_job_switch_sw(void) { profile_ev.jobs_switch_sw++; }
void profile_share_found(void) { profile_ev.shares_found++; }
void profile_share_submit(void) { profile_ev.shares_submit++; }
void profile_share_accept(void) { profile_ev.shares_accept++; }
void profile_share_reject(void) { profile_ev.shares_reject++; }
void profile_mutex_cont(void) { profile_ev.mutex_cont++; }

void profile_best_diff(double d)
{
    if (d > profile_ev.best_diff) profile_ev.best_diff = d;
}

void profile_batch(uint32_t n)
{
    profile_ev.batch_nonces += n;
    profile_ev.batch_cnt++;
}

void profile_set_sha(const char *name)
{
    s_sha_name = name;
}

static void report_stages(const char *tag, const stage_acc_t *stages, int count, const char * const *names,
                          uint64_t hash_total, uint32_t hash_cnt, uint64_t total_h, uint32_t sec,
                          uint32_t self_cyc, const char *kind)
{
    ESP_LOGI(tag, "===== PROFILE_%s [v1] mask=0x%x cpu=240MHz sha=%s =====",
             kind, PROFILE_SAMPLE_MASK, s_sha_name ? s_sha_name : "?");
    uint64_t total_stage = 0;
    for (int i = 0; i < count; i++) {
        const stage_acc_t *a = &stages[i];
        if (a->cnt == 0) continue;
        uint32_t avg = (uint32_t)(a->total / a->cnt);
        total_stage += a->total;
    }
    ESP_LOGI(tag, "sampled=%lu interval_H=%llu interval_sec=%u cyc/hash=%lu probe_ovr=%lu",
             (unsigned long)hash_cnt,
             (unsigned long long)total_h,
             (unsigned)sec,
             (unsigned long)(hash_cnt > 0 ? (uint32_t)(total_stage / hash_cnt) : 0),
             (unsigned long)(hash_cnt > 0 && total_stage > 0
                ? (uint32_t)((hash_total - total_stage) / hash_cnt) : 0));
    ESP_LOGI(tag, "Stage               avg[cyc]     min     max   lifetime    share");

    for (int i = 0; i < count; i++) {
        const stage_acc_t *a = &stages[i];
        if (a->cnt == 0) continue;
        uint32_t avg = (uint32_t)(a->total / a->cnt);
        double pct = total_stage > 0 ? (100.0 * a->total / total_stage) : 0;
        ESP_LOGI(tag, "%-20s %9lu %7lu %7lu %12llu %6.1f%%",
                 names[i],
                 (unsigned long)avg,
                 (unsigned long)a->min,
                 (unsigned long)a->max,
                 (unsigned long long)a->total,
                 pct);
    }

    uint64_t wait_total = 0;
    uint64_t reg_total = 0;
    uint64_t digest_total = 0;
    uint64_t ctrl_total = 0;

    if (count == HW_STAGE_COUNT) {
        wait_total = stages[HW_WAIT1].total + stages[HW_WAIT2].total
                   + stages[HW_WAIT3].total + stages[HW_WAIT4].total;
        reg_total = stages[HW_FILL_BLOCK_UPPER].total + stages[HW_FILL_BLOCK_LOWER].total
                  + stages[HW_FILL_UPPER].total + stages[HW_FILL_DOUBLE].total;
        digest_total = stages[HW_READ_DIGEST].total + stages[HW_TARGET_CHECK].total;
        ctrl_total = stages[HW_START1].total + stages[HW_CONTINUE].total
                   + stages[HW_LOAD1].total + stages[HW_START2].total + stages[HW_LOAD2].total;
    } else {
        reg_total = stages[SW_NONCE_UPDATE].total + stages[SW_SHA_COMPUTE].total;
        digest_total = stages[SW_TARGET_CHECK].total;
    }

    if (total_stage > 0) {
        ESP_LOGI(tag, "===== CRITICAL PATH =====");
        if (wait_total > 0)  ESP_LOGI(tag, "SHA wait          %7llu cyc (%5.1f%%)",
                                      (unsigned long long)wait_total, 100.0 * wait_total / total_stage);
        if (reg_total > 0)   ESP_LOGI(tag, "Register writes   %7llu cyc (%5.1f%%)",
                                      (unsigned long long)reg_total, 100.0 * reg_total / total_stage);
        if (digest_total > 0) ESP_LOGI(tag, "Digest read+check %7llu cyc (%5.1f%%)",
                                       (unsigned long long)digest_total, 100.0 * digest_total / total_stage);
        if (ctrl_total > 0)  ESP_LOGI(tag, "Control           %7llu cyc (%5.1f%%)",
                                      (unsigned long long)ctrl_total, 100.0 * ctrl_total / total_stage);
    }

    if (sec > 0) {
        double hz = (double)total_h / sec;
        double cyc_per_hash = (double)total_stage / (hash_cnt ? hash_cnt : 1);
        double sha_busy = wait_total > 0 ? 100.0 * (wait_total) / total_stage : 0;
        double cpu_active = total_stage > 0
            ? 100.0 * (total_stage - wait_total) / total_stage : 0;
        ESP_LOGI(tag, "===== PIPELINE UTIL ===== %llu H/s  %.0f cyc/hash",
                 (unsigned long long)hz, cyc_per_hash);
        ESP_LOGI(tag, "CPU active=%.0f%% SHA busy=%.0f%%",
                 cpu_active, sha_busy);
    }

    ESP_LOGI(tag, "===== EVENTS =====");
    ESP_LOGI(tag, "jobs=%u switch=%u shares=%u submit=%u accept=%u reject=%u",
             (unsigned)profile_ev.jobs_recv,
             (unsigned)(profile_ev.jobs_switch_hw + profile_ev.jobs_switch_sw),
             (unsigned)profile_ev.shares_found,
             (unsigned)profile_ev.shares_submit,
             (unsigned)profile_ev.shares_accept,
             (unsigned)profile_ev.shares_reject);
    ESP_LOGI(tag, "mutex_cont=%u best_diff=%.2e batch_avg=%lu",
             (unsigned)profile_ev.mutex_cont,
             profile_ev.best_diff,
             (unsigned long)(profile_ev.batch_cnt > 0 ? (uint32_t)(profile_ev.batch_nonces / profile_ev.batch_cnt) : 0));

    if (profile_js.cnt > 0) {
        uint32_t js_avg = (uint32_t)(profile_js.total / profile_js.cnt);
        ESP_LOGI(tag, "===== JOB SWITCH LATENCY =====");
        ESP_LOGI(tag, "avg=%lu min=%lu max=%lu cnt=%u",
                 (unsigned long)js_avg, (unsigned long)profile_js.min,
                 (unsigned long)profile_js.max, (unsigned)profile_js.cnt);
    }
}

void profile_report_hw(const char *tag, uint64_t total_h, uint32_t sec, uint32_t self_cyc)
{
    report_stages(tag, profile_hw.stages, HW_STAGE_COUNT, hw_stage_names,
                  profile_hw.hash_total, profile_hw.hash_cnt, total_h, sec, self_cyc, "HW");
}

void profile_report_sw(const char *tag, uint64_t total_h, uint32_t sec, uint32_t self_cyc)
{
    report_stages(tag, profile_sw.stages, SW_STAGE_COUNT, sw_stage_names,
                  profile_sw.hash_total, profile_sw.hash_cnt, total_h, sec, self_cyc, "SW");
}
