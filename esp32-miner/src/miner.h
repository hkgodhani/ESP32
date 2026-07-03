#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#define MAX_MERKLE_BRANCHES 16
#define MAX_COINBASE_SIZE 1024
#define MAX_JSON_LINE 4096

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    size_t datalen;
} sha256_ctx_t;

typedef struct {
    uint8_t job_id[64];
    size_t job_id_len;
    uint8_t prev_block_hash[32];
    uint8_t coinb1[MAX_COINBASE_SIZE];
    size_t coinb1_len;
    uint8_t coinb2[MAX_COINBASE_SIZE];
    size_t coinb2_len;
    uint8_t merkle_branch[MAX_MERKLE_BRANCHES][32];
    size_t merkle_branch_count;
    uint32_t version;
    uint32_t nbits;
    uint32_t ntime;
    uint8_t block_target[32];
    uint8_t share_target[32];
    uint8_t extranonce1[16];
    size_t extranonce1_len;
    uint32_t extranonce2_size;
    uint32_t next_nonce;
    uint64_t extranonce2_counter;
    uint64_t job_seq;
    bool job_available;

    uint8_t sha_buffer[128];
    uint32_t midstate[8];
    uint32_t bake[15];
} stratum_job_t;

typedef struct {
    int sock;
    char recv_buf[MAX_JSON_LINE];
    int recv_len;
    stratum_job_t current_job;
    uint32_t share_count;
    uint64_t hash_count;
    double difficulty;
    SemaphoreHandle_t job_mutex;
    SemaphoreHandle_t sock_mutex;
    TaskHandle_t mining_task_core0;
    TaskHandle_t mining_task_core1;
    int64_t start_time;
    uint8_t diff1_target[32];
} miner_context_t;
