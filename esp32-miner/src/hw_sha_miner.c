#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_task_wdt.h"

#include "hal/sha_ll.h"
#include "sha/sha_parallel_engine.h"
#include "soc/dport_reg.h"
#include "soc/hwcrypto_reg.h"
#include "soc/dport_access.h"

#include "miner.h"
#include "nerdSHA256plus.h"
#include "profile.h"

extern void write_u32_le(uint8_t *out, uint32_t value);
extern void reverse_copy(uint8_t *dst, const uint8_t *src, size_t len);
extern void bytes_to_hex(const uint8_t *data, size_t len, char *out, size_t out_max);
extern bool target_less_or_equal(const uint8_t a[32], const uint8_t b[32]);
extern void target_to_hex(const uint8_t target[32], char *out, size_t out_max);
extern void double_sha256(const uint8_t *data, size_t len, uint8_t *output);
extern bool submit_share(miner_context_t *miner, const stratum_job_t *job, const uint8_t *extranonce2, uint32_t nonce);
extern void build_extranonce2(const stratum_job_t *job, uint64_t counter, uint8_t *out, size_t out_len);
extern bool build_coinbase(const stratum_job_t *job, const uint8_t *extranonce2, size_t extranonce2_len, uint8_t *coinbase, size_t *coinbase_len);
extern bool merkle_root_from_job(const stratum_job_t *job, const uint8_t *coinbase_hash, uint8_t out[32]);
extern void prepare_sha_buffer(stratum_job_t *job, const uint8_t merkle_root[32], uint32_t start_nonce);

static const char *TAG_HW = "FB_HW";

#define HW_WORK_CHUNK 16384u
#define HW_NONCE_MASK 0xFFFFC000

__attribute__((optimize("O3")))
static inline void sha_wait_idle(void)
{
    while (DPORT_REG_READ(SHA_256_BUSY_REG)) {}
}

__attribute__((optimize("O3")))
static inline void sha_fill_block_lower(const void *input)
{
    const uint32_t *src = (const uint32_t *)input;
    uint32_t *dst = (uint32_t *)(SHA_TEXT_BASE);
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
    dst[4] = src[4];
    dst[5] = src[5];
    dst[6] = src[6];
    dst[7] = src[7];
}

__attribute__((optimize("O3")))
static inline void sha_fill_block_upper(const void *input)
{
    const uint32_t *src = (const uint32_t *)input;
    uint32_t *dst = (uint32_t *)(SHA_TEXT_BASE);
    dst[8] = src[8];
    dst[9] = src[9];
    dst[10] = src[10];
    dst[11] = src[11];
    dst[12] = src[12];
    dst[13] = src[13];
    dst[14] = src[14];
    dst[15] = src[15];
}

__attribute__((optimize("O3")))
static inline void sha_fill_block(const void *input)
{
    sha_fill_block_lower(input);
    sha_fill_block_upper(input);
}

__attribute__((optimize("O3")))
static inline void sha_fill_upper(const void *upper, uint32_t nonce)
{
    const uint32_t *src = (const uint32_t *)upper;
    uint32_t *dst = (uint32_t *)(SHA_TEXT_BASE);
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = __builtin_bswap32(nonce);
    dst[4] = 0x80000000;
    dst[5] = 0x00000000;
    dst[6] = 0x00000000;
    dst[7] = 0x00000000;
    dst[8] = 0x00000000;
    dst[9] = 0x00000000;
    dst[10] = 0x00000000;
    dst[11] = 0x00000000;
    dst[12] = 0x00000000;
    dst[13] = 0x00000000;
    dst[14] = 0x00000000;
    dst[15] = 0x00000280;
}

__attribute__((optimize("O3")))
static inline void sha_fill_double(void)
{
    uint32_t *dst = (uint32_t *)(SHA_TEXT_BASE);
    dst[8] = 0x80000000;
    dst[9] = 0x00000000;
    dst[10] = 0x00000000;
    dst[11] = 0x00000000;
    dst[12] = 0x00000000;
    dst[13] = 0x00000000;
    dst[14] = 0x00000000;
    dst[15] = 0x00000100;
}

__attribute__((optimize("O3")))
static inline bool sha_read_digest_swap(uint8_t hash[32])
{
    DPORT_INTERRUPT_DISABLE();
    uint32_t fin = DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 7 * 4);
    if ((fin & 0xFFFF) != 0)
    {
        DPORT_INTERRUPT_RESTORE();
        return false;
    }
    ((uint32_t *)hash)[7] = __builtin_bswap32(fin);
    ((uint32_t *)hash)[0] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 0 * 4));
    ((uint32_t *)hash)[1] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 1 * 4));
    ((uint32_t *)hash)[2] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 2 * 4));
    ((uint32_t *)hash)[3] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 3 * 4));
    ((uint32_t *)hash)[4] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 4 * 4));
    ((uint32_t *)hash)[5] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 5 * 4));
    ((uint32_t *)hash)[6] = __builtin_bswap32(DPORT_SEQUENCE_REG_READ(SHA_TEXT_BASE + 6 * 4));
    DPORT_INTERRUPT_RESTORE();
    return true;
}

void miner_hw_task(void *arg)
{
    miner_context_t *miner = (miner_context_t *)arg;

    uint8_t hash[32];
    uint8_t coinbase[MAX_COINBASE_SIZE];
    uint8_t coinbase_hash[32];
    uint8_t merkle_root[32];
    uint8_t extranonce2[16];
    stratum_job_t job;
    uint64_t last_job_seq = 0;
    int64_t last_log = esp_timer_get_time();
    uint64_t hash_count_snapshot = 0;
    uint32_t nonce_start = 0;

    ESP_LOGI(TAG_HW, "Hardware mining task started on core %d", xPortGetCoreID());

    while (1)
    {
        bool have_job = false;
        if (xSemaphoreTake(miner->job_mutex, pdMS_TO_TICKS(1000)) == pdTRUE)
        {
            have_job = miner->current_job.job_available;
            if (have_job)
            {
                job = miner->current_job;
                if (job.extranonce1_len == 0 || job.extranonce2_size == 0)
                {
                    xSemaphoreGive(miner->job_mutex);
                    vTaskDelay(pdMS_TO_TICKS(100));
                    continue;
                }
                if (job.job_seq != last_job_seq)
                {
                    last_job_seq = job.job_seq;
                    nonce_start = 0;
                }

                uint32_t claimed = miner->current_job.next_nonce;
                miner->current_job.next_nonce += HW_WORK_CHUNK;
                if (miner->current_job.next_nonce < claimed)
                {
                    miner->current_job.next_nonce = 0;
                    miner->current_job.extranonce2_counter++;
                }

                size_t extranonce2_len = job.extranonce2_size;
                if (extranonce2_len > sizeof(extranonce2))
                    extranonce2_len = sizeof(extranonce2);

                build_extranonce2(&job, miner->current_job.extranonce2_counter, extranonce2, extranonce2_len);
                miner->current_job.extranonce2_counter++;

                xSemaphoreGive(miner->job_mutex);

                nonce_start = claimed;

                size_t coinbase_len = 0;
                if (!build_coinbase(&job, extranonce2, extranonce2_len, coinbase, &coinbase_len))
                {
                    vTaskDelay(pdMS_TO_TICKS(10));
                    continue;
                }

                double_sha256(coinbase, coinbase_len, coinbase_hash);
                merkle_root_from_job(&job, coinbase_hash, merkle_root);
                prepare_sha_buffer(&job, merkle_root, nonce_start);

                esp_sha_lock_engine(SHA2_256);

                sha_fill_block(job.sha_buffer);

                for (uint32_t i = 0; i < HW_WORK_CHUNK; i++)
                {
                    uint32_t nonce = nonce_start + i;
                    bool prof = profile_check(nonce);

                    if (xSemaphoreTake(miner->job_mutex, 0) == pdTRUE)
                    {
                        bool still_valid = miner->current_job.job_available &&
                                          miner->current_job.job_seq == last_job_seq;
                        xSemaphoreGive(miner->job_mutex);
                        if (!still_valid)
                            break;
                    }

                    if (prof) { profile_hw_hash_begin(); profile_hw_start(HW_START1); }
                    sha_ll_start_block(SHA2_256);
                    if (prof) { profile_hw_end(HW_START1); profile_hw_start(HW_FILL_UPPER); }

                    sha_fill_upper(job.sha_buffer + 64, nonce);
                    if (prof) { profile_hw_end(HW_FILL_UPPER); profile_hw_start(HW_WAIT1); }

                    sha_wait_idle();
                    if (prof) { profile_hw_end(HW_WAIT1); profile_hw_start(HW_CONTINUE); }

                    sha_ll_continue_block(SHA2_256);
                    if (prof) { profile_hw_end(HW_CONTINUE); profile_hw_start(HW_FILL_DOUBLE); }

                    sha_fill_double();
                    if (prof) { profile_hw_end(HW_FILL_DOUBLE); profile_hw_start(HW_WAIT2); }

                    sha_wait_idle();
                    if (prof) { profile_hw_end(HW_WAIT2); profile_hw_start(HW_LOAD1); }

                    sha_ll_load(SHA2_256);
                    if (prof) { profile_hw_end(HW_LOAD1); profile_hw_start(HW_WAIT3); }

                    sha_wait_idle();
                    if (prof) { profile_hw_end(HW_WAIT3); profile_hw_start(HW_START2); }

                    sha_ll_start_block(SHA2_256);
                    if (prof) { profile_hw_end(HW_START2); profile_hw_start(HW_FILL_BLOCK_UPPER); }

                    sha_fill_block_upper(job.sha_buffer);
                    if (prof) { profile_hw_end(HW_FILL_BLOCK_UPPER); profile_hw_start(HW_WAIT4); }

                    sha_wait_idle();
                    if (prof) { profile_hw_end(HW_WAIT4); profile_hw_start(HW_LOAD2); }

                    sha_ll_load(SHA2_256);
                    if (prof) { profile_hw_end(HW_LOAD2); profile_hw_start(HW_READ_DIGEST); }

                    bool digest_ok = sha_read_digest_swap(hash);
                    if (prof) { profile_hw_end(HW_READ_DIGEST); }
                    if (digest_ok)
                    {
                        if (prof) profile_hw_start(HW_TARGET_CHECK);
                        bool share_ok = target_less_or_equal(hash, job.share_target);
                        bool block_ok = target_less_or_equal(hash, job.block_target);
                        if (prof) profile_hw_end(HW_TARGET_CHECK);

                        if (share_ok)
                        {
                            if (submit_share(miner, &job, extranonce2, nonce))
                            {
                                __atomic_add_fetch(&miner->share_count, 1, __ATOMIC_RELAXED);
                                profile_share_submit();
                                profile_share_accept();
                            }
                            else
                            {
                                profile_share_reject();
                            }
                        }
                        if (block_ok)
                        {
                            char hash_hex[65];
                            target_to_hex(hash, hash_hex, sizeof(hash_hex));
                            ESP_LOGW(TAG_HW, "BLOCK CANDIDATE on core %d nonce=%08x hash=%s",
                                     xPortGetCoreID(), nonce, hash_hex);
                        }
                    }

                    if (prof) { profile_hw_start(HW_FILL_BLOCK_LOWER); }
                    sha_fill_block_lower(job.sha_buffer);
                    if (prof) { profile_hw_end(HW_FILL_BLOCK_LOWER); profile_hw_hash_end(); }

                    __atomic_add_fetch(&miner->hash_count, 1, __ATOMIC_RELAXED);
                }

                esp_sha_unlock_engine(SHA2_256);
            }
            else
            {
                xSemaphoreGive(miner->job_mutex);
            }
        }

        int64_t now = esp_timer_get_time();
        if (now - last_log > 30000000)
        {
            uint64_t total_hashes = __atomic_load_n(&miner->hash_count, __ATOMIC_RELAXED);
            uint64_t hashes_30s = total_hashes - hash_count_snapshot;
            hash_count_snapshot = total_hashes;
            ESP_LOGI(TAG_HW, "Core%d[HW]: total=%llu rate=%llu H/s",
                     xPortGetCoreID(),
                     (unsigned long long)total_hashes,
                     (unsigned long long)(hashes_30s / 30));
            last_log = now;
            profile_report_hw(TAG_HW, hashes_30s, 30, 0);
        }

        if (!have_job)
            vTaskDelay(pdMS_TO_TICKS(500));
    }
}
