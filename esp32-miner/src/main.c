#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"

#include "esp_system.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_tls.h"
#include "esp_task_wdt.h"

#include "driver/gpio.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"

#include "cJSON.h"
#include "nerdSHA256plus.h"
#include "miner.h"
#include "hw_sha_miner.h"
#include "profile.h"

static const char *TAG = "FB_MINER";

#define WIFI_SSID "Hkgodhani1"
#define WIFI_PASSWORD "hkgodhani"

#ifndef CONFIG_STRATUM_POOL
#define CONFIG_STRATUM_POOL "stratum+tcp://stratum.slushpool.com:3333"
#endif
#ifndef CONFIG_WORKER_NAME
#define CONFIG_WORKER_NAME "esp32_worker_01"
#endif
#ifndef CONFIG_FB_WALLET
#define CONFIG_FB_WALLET "hkx.test"
#endif
#ifndef CONFIG_STRATUM_PASSWORD
#define CONFIG_STRATUM_PASSWORD "x"
#endif

static char s_stratum_host[128] = "stratum.slushpool.com";
static int s_stratum_port = 3333;
static char s_stratum_user[192] = CONFIG_FB_WALLET "." CONFIG_WORKER_NAME;
static char s_stratum_pass[64] = CONFIG_STRATUM_PASSWORD;

#define STRATUM_HOST (s_stratum_host)
#define STRATUM_PORT (s_stratum_port)
#define STRATUM_USER (s_stratum_user)
#define STRATUM_PASS (s_stratum_pass)

#define LED_PIN 2

#define WORK_CHUNK_NONCES 10000u
#define MAX_MERKLE_BRANCHES 16
#define MAX_COINBASE_SIZE 1024
#define MAX_JSON_LINE 4096

#define SHA256_K0  0x428a2f98u
#define SHA256_K1  0x71374491u
#define SHA256_K2  0xb5c0fbcfu
#define SHA256_K3  0xe9b5dba5u
#define SHA256_K4  0x3956c25bu
#define SHA256_K5  0x59f111f1u
#define SHA256_K6  0x923f82a4u
#define SHA256_K7  0xab1c5ed5u
#define SHA256_K8  0xd807aa98u
#define SHA256_K9  0x12835b01u
#define SHA256_K10 0x243185beu
#define SHA256_K11 0x550c7dc3u
#define SHA256_K12 0x72be5d74u
#define SHA256_K13 0x80deb1feu
#define SHA256_K14 0x9bdc06a7u
#define SHA256_K15 0xc19bf174u
#define SHA256_K16 0xe49b69c1u
#define SHA256_K17 0xefbe4786u
#define SHA256_K18 0x0fc19dc6u
#define SHA256_K19 0x240ca1ccu
#define SHA256_K20 0x2de92c6fu
#define SHA256_K21 0x4a7484aau
#define SHA256_K22 0x5cb0a9dcu
#define SHA256_K23 0x76f988dau
#define SHA256_K24 0x983e5152u
#define SHA256_K25 0xa831c66du
#define SHA256_K26 0xb00327c8u
#define SHA256_K27 0xbf597fc7u
#define SHA256_K28 0xc6e00bf3u
#define SHA256_K29 0xd5a79147u
#define SHA256_K30 0x06ca6351u
#define SHA256_K31 0x14292967u
#define SHA256_K32 0x27b70a85u
#define SHA256_K33 0x2e1b2138u
#define SHA256_K34 0x4d2c6dfcu
#define SHA256_K35 0x53380d13u
#define SHA256_K36 0x650a7354u
#define SHA256_K37 0x766a0abbu
#define SHA256_K38 0x81c2c92eu
#define SHA256_K39 0x92722c85u
#define SHA256_K40 0xa2bfe8a1u
#define SHA256_K41 0xa81a664bu
#define SHA256_K42 0xc24b8b70u
#define SHA256_K43 0xc76c51a3u
#define SHA256_K44 0xd192e819u
#define SHA256_K45 0xd6990624u
#define SHA256_K46 0xf40e3585u
#define SHA256_K47 0x106aa070u
#define SHA256_K48 0x19a4c116u
#define SHA256_K49 0x1e376c08u
#define SHA256_K50 0x2748774cu
#define SHA256_K51 0x34b0bcb5u
#define SHA256_K52 0x391c0cb3u
#define SHA256_K53 0x4ed8aa4au
#define SHA256_K54 0x5b9cca4fu
#define SHA256_K55 0x682e6ff3u
#define SHA256_K56 0x748f82eeu
#define SHA256_K57 0x78a5636fu
#define SHA256_K58 0x84c87814u
#define SHA256_K59 0x8cc70208u
#define SHA256_K60 0x90befffau
#define SHA256_K61 0xa4506cebu
#define SHA256_K62 0xbef9a3f7u
#define SHA256_K63 0xc67178f2u

static const uint32_t SHA256_K[64] = {
    SHA256_K0, SHA256_K1, SHA256_K2, SHA256_K3,
    SHA256_K4, SHA256_K5, SHA256_K6, SHA256_K7,
    SHA256_K8, SHA256_K9, SHA256_K10, SHA256_K11,
    SHA256_K12, SHA256_K13, SHA256_K14, SHA256_K15,
    SHA256_K16, SHA256_K17, SHA256_K18, SHA256_K19,
    SHA256_K20, SHA256_K21, SHA256_K22, SHA256_K23,
    SHA256_K24, SHA256_K25, SHA256_K26, SHA256_K27,
    SHA256_K28, SHA256_K29, SHA256_K30, SHA256_K31,
    SHA256_K32, SHA256_K33, SHA256_K34, SHA256_K35,
    SHA256_K36, SHA256_K37, SHA256_K38, SHA256_K39,
    SHA256_K40, SHA256_K41, SHA256_K42, SHA256_K43,
    SHA256_K44, SHA256_K45, SHA256_K46, SHA256_K47,
    SHA256_K48, SHA256_K49, SHA256_K50, SHA256_K51,
    SHA256_K52, SHA256_K53, SHA256_K54, SHA256_K55,
    SHA256_K56, SHA256_K57, SHA256_K58, SHA256_K59,
    SHA256_K60, SHA256_K61, SHA256_K62, SHA256_K63
};



static miner_context_t g_miner = {0};
static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

static void configure_stratum_settings(void) {
    const char *pool = CONFIG_STRATUM_POOL;
    const char *host = pool;
    const char *scheme = strstr(pool, "://");
    if (scheme) {
        host = scheme + 3;
    }

    const char *colon = strrchr(host, ':');
    if (colon && colon > host) {
        size_t host_len = (size_t)(colon - host);
        if (host_len >= sizeof(s_stratum_host)) {
            host_len = sizeof(s_stratum_host) - 1u;
        }
        memcpy(s_stratum_host, host, host_len);
        s_stratum_host[host_len] = '\0';
        s_stratum_port = atoi(colon + 1);
        if (s_stratum_port <= 0) {
            s_stratum_port = 3333;
        }
    } else {
        strncpy(s_stratum_host, host, sizeof(s_stratum_host) - 1u);
        s_stratum_host[sizeof(s_stratum_host) - 1u] = '\0';
        s_stratum_port = 3333;
    }

    s_stratum_user[sizeof(s_stratum_user) - 1u] = '\0';
    s_stratum_pass[sizeof(s_stratum_pass) - 1u] = '\0';
}

static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint32_t ch32(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static inline uint32_t maj32(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline uint32_t ep0(uint32_t x) { return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22); }
static inline uint32_t ep1(uint32_t x) { return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25); }
static inline uint32_t sig0(uint32_t x) { return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3); }
static inline uint32_t sig1(uint32_t x) { return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10); }

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[64]) {
    uint32_t m[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (int i = 0; i < 16; i++) {
        m[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + ep1(e) + ch32(e, f, g) + SHA256_K[i] + m[i];
        uint32_t t2 = ep0(a) + maj32(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t *hash) {
    size_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) {
            ctx->data[i++] = 0x00;
        }
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) {
            ctx->data[i++] = 0x00;
        }
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += (uint64_t)ctx->datalen * 8u;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; i++) {
        hash[i]      = (uint8_t)((ctx->state[0] >> (24 - i * 8)) & 0xffu);
        hash[i + 4]  = (uint8_t)((ctx->state[1] >> (24 - i * 8)) & 0xffu);
        hash[i + 8]  = (uint8_t)((ctx->state[2] >> (24 - i * 8)) & 0xffu);
        hash[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i * 8)) & 0xffu);
        hash[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i * 8)) & 0xffu);
        hash[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i * 8)) & 0xffu);
        hash[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i * 8)) & 0xffu);
        hash[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i * 8)) & 0xffu);
    }
}

static void sha256_full(const uint8_t *data, size_t len, uint8_t *output) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, output);
}

void double_sha256(const uint8_t *data, size_t len, uint8_t *output) {
    uint8_t first[32];
    sha256_full(data, len, first);
    sha256_full(first, sizeof(first), output);
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t out_max, size_t *out_len) {
    size_t len = strlen(hex);
    if ((len & 1u) != 0u) {
        return false;
    }

    size_t bytes = len / 2u;
    if (bytes > out_max) {
        return false;
    }

    for (size_t i = 0; i < bytes; i++) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    if (out_len) {
        *out_len = bytes;
    }
    return true;
}

static bool hex_to_bytes_reversed(const char *hex, uint8_t *out, size_t out_max, size_t *out_len) {
    uint8_t tmp[128];
    size_t len = 0;

    if (!hex_to_bytes(hex, tmp, sizeof(tmp), &len)) {
        return false;
    }
    if (len > out_max) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        out[i] = tmp[len - 1u - i];
    }
    if (out_len) {
        *out_len = len;
    }
    return true;
}

void bytes_to_hex(const uint8_t *data, size_t len, char *out, size_t out_max) {
    static const char hex[] = "0123456789abcdef";
    if (out_max < (len * 2u + 1u)) {
        if (out_max > 0u) {
            out[0] = '\0';
        }
        return;
    }

    for (size_t i = 0; i < len; i++) {
        out[i * 2u] = hex[(data[i] >> 4) & 0x0fu];
        out[i * 2u + 1u] = hex[data[i] & 0x0fu];
    }
    out[len * 2u] = '\0';
}

void write_u32_le(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value & 0xffu);
    out[1] = (uint8_t)((value >> 8) & 0xffu);
    out[2] = (uint8_t)((value >> 16) & 0xffu);
    out[3] = (uint8_t)((value >> 24) & 0xffu);
}

void reverse_copy(uint8_t *dst, const uint8_t *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dst[i] = src[len - 1u - i];
    }
}

static void compact_to_target(uint32_t compact, uint8_t target[32]) {
    memset(target, 0, 32);

    uint32_t exponent = compact >> 24;
    uint32_t mantissa = compact & 0x007fffffu;

    if (mantissa == 0u) {
        return;
    }

    if (exponent <= 3u) {
        uint32_t value = mantissa >> (8u * (3u - exponent));
        for (uint32_t i = 0; i < exponent; i++) {
            target[32u - exponent + i] = (uint8_t)((value >> (8u * (exponent - 1u - i))) & 0xffu);
        }
        return;
    }

    uint32_t offset = 32u - exponent;
    if (offset > 31u) {
        return;
    }

    target[offset] = (uint8_t)((mantissa >> 16) & 0xffu);
    if (offset + 1u < 32u) target[offset + 1u] = (uint8_t)((mantissa >> 8) & 0xffu);
    if (offset + 2u < 32u) target[offset + 2u] = (uint8_t)(mantissa & 0xffu);
}

static void target_div_u64(const uint8_t in[32], uint64_t divisor, uint8_t out[32]) {
    uint64_t rem = 0;
    if (divisor == 0u) {
        memset(out, 0xff, 32);
        return;
    }

    for (size_t i = 0; i < 32; i++) {
        uint64_t cur = (rem << 8) | in[i];
        out[i] = (uint8_t)(cur / divisor);
        rem = cur % divisor;
    }
}

static void target_mul10(uint8_t value[32]) {
    uint16_t carry = 0;
    for (int i = 31; i >= 0; i--) {
        uint16_t cur = (uint16_t)value[i] * 10u + carry;
        value[i] = (uint8_t)(cur & 0xffu);
        carry = (uint16_t)(cur >> 8);
    }
}

bool target_less_or_equal(const uint8_t a[32], const uint8_t b[32]) {
    for (size_t i = 0; i < 32; i++) {
        if (a[i] < b[i]) return true;
        if (a[i] > b[i]) return false;
    }
    return true;
}

void target_to_hex(const uint8_t target[32], char *out, size_t out_max) {
    bytes_to_hex(target, 32, out, out_max);
}

static bool parse_u32_value(cJSON *item, uint32_t *out) {
    if (cJSON_IsNumber(item)) {
        *out = (uint32_t)item->valuedouble;
        return true;
    }
    if (cJSON_IsString(item) && item->valuestring) {
        char *end = NULL;
        unsigned long v = strtoul(item->valuestring, &end, 16);
        if (end == item->valuestring || *end != '\0') {
            return false;
        }
        *out = (uint32_t)v;
        return true;
    }
    return false;
}

static void update_share_target(miner_context_t *miner) {
    uint8_t scaled_target[32];
    memcpy(scaled_target, miner->diff1_target, sizeof(scaled_target));

    for (int i = 0; i < 6; i++) {
        target_mul10(scaled_target);
    }

    uint64_t diff_scaled = (uint64_t)(miner->difficulty * 1000000.0 + 0.5);
    if (diff_scaled == 0u) {
        diff_scaled = 1u;
    }

    target_div_u64(scaled_target, diff_scaled, miner->current_job.share_target);
}

void build_extranonce2(const stratum_job_t *job, uint64_t counter, uint8_t *out, size_t out_len) {
    memset(out, 0, out_len);
    for (size_t i = 0; i < out_len; i++) {
        size_t shift = (out_len - 1u - i) * 8u;
        if (shift >= 64u) {
            out[i] = 0;
        } else {
            out[i] = (uint8_t)((counter >> shift) & 0xffu);
        }
    }
    (void)job;
}

bool build_coinbase(const stratum_job_t *job, const uint8_t *extranonce2, size_t extranonce2_len, uint8_t *coinbase, size_t *coinbase_len) {
    size_t total = job->coinb1_len + job->extranonce1_len + extranonce2_len + job->coinb2_len;
    if (total > MAX_COINBASE_SIZE) {
        return false;
    }

    size_t pos = 0;
    memcpy(coinbase + pos, job->coinb1, job->coinb1_len);
    pos += job->coinb1_len;
    memcpy(coinbase + pos, job->extranonce1, job->extranonce1_len);
    pos += job->extranonce1_len;
    memcpy(coinbase + pos, extranonce2, extranonce2_len);
    pos += extranonce2_len;
    memcpy(coinbase + pos, job->coinb2, job->coinb2_len);
    pos += job->coinb2_len;

    *coinbase_len = pos;
    return true;
}

bool submit_share(miner_context_t *miner, const stratum_job_t *job, const uint8_t *extranonce2, uint32_t nonce) {
    char extranonce2_hex[64];
    char nonce_hex[16];
    char ntime_hex[16];
    char msg[512];

    bytes_to_hex(extranonce2, job->extranonce2_size, extranonce2_hex, sizeof(extranonce2_hex));
    bytes_to_hex((const uint8_t *)&nonce, 4, nonce_hex, sizeof(nonce_hex));
    bytes_to_hex((const uint8_t *)&job->ntime, 4, ntime_hex, sizeof(ntime_hex));

    snprintf(msg, sizeof(msg),
             "{\"id\":4,\"method\":\"mining.submit\",\"params\":[\"%s\",\"%.*s\",\"%s\",\"%s\",\"%s\"]}\n",
             STRATUM_USER,
             (int)job->job_id_len,
             job->job_id,
             extranonce2_hex,
             ntime_hex,
             nonce_hex);

    if (xSemaphoreTake(miner->sock_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return false;
    }

    int len = (int)strlen(msg);
    int sent = lwip_send(miner->sock, msg, len, 0);
    xSemaphoreGive(miner->sock_mutex);

    if (sent != len) {
        ESP_LOGE(TAG, "Failed to submit share");
        return false;
    }

    return true;
}

static bool parse_notify(miner_context_t *miner, cJSON *params) {
    if (!cJSON_IsArray(params) || cJSON_GetArraySize(params) < 9) {
        return false;
    }

    cJSON *job_id = cJSON_GetArrayItem(params, 0);
    cJSON *prevhash = cJSON_GetArrayItem(params, 1);
    cJSON *coinb1 = cJSON_GetArrayItem(params, 2);
    cJSON *coinb2 = cJSON_GetArrayItem(params, 3);
    cJSON *merkle = cJSON_GetArrayItem(params, 4);
    cJSON *version = cJSON_GetArrayItem(params, 5);
    cJSON *nbits = cJSON_GetArrayItem(params, 6);
    cJSON *ntime = cJSON_GetArrayItem(params, 7);
    cJSON *clean_jobs = cJSON_GetArrayItem(params, 8);

    if (!cJSON_IsString(job_id) || !cJSON_IsString(prevhash) || !cJSON_IsString(coinb1) || !cJSON_IsString(coinb2) || !cJSON_IsArray(merkle)) {
        return false;
    }

    if (xSemaphoreTake(miner->job_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return false;
    }

    stratum_job_t *job = &miner->current_job;
    uint8_t prev_extranonce1[sizeof(job->extranonce1)];
    size_t prev_extranonce1_len = job->extranonce1_len;
    uint32_t prev_extranonce2_size = job->extranonce2_size;
    uint8_t prev_share_target[32];

    memcpy(prev_extranonce1, job->extranonce1, sizeof(prev_extranonce1));
    memcpy(prev_share_target, job->share_target, sizeof(prev_share_target));

    memset(job, 0, sizeof(*job));

    if (!hex_to_bytes(prevhash->valuestring, job->prev_block_hash, sizeof(job->prev_block_hash), NULL) ||
        !hex_to_bytes(coinb1->valuestring, job->coinb1, sizeof(job->coinb1), &job->coinb1_len) ||
        !hex_to_bytes(coinb2->valuestring, job->coinb2, sizeof(job->coinb2), &job->coinb2_len) ||
        !parse_u32_value(version, &job->version) ||
        !parse_u32_value(nbits, &job->nbits) ||
        !parse_u32_value(ntime, &job->ntime)) {
        xSemaphoreGive(miner->job_mutex);
        return false;
    }

    size_t job_id_len = strlen(job_id->valuestring);
    if (job_id_len >= sizeof(job->job_id)) {
        job_id_len = sizeof(job->job_id) - 1u;
    }
    memcpy(job->job_id, job_id->valuestring, job_id_len);
    job->job_id_len = job_id_len;

    job->merkle_branch_count = 0;
    int branch_count = cJSON_GetArraySize(merkle);
    for (int i = 0; i < branch_count && job->merkle_branch_count < MAX_MERKLE_BRANCHES; i++) {
        cJSON *branch = cJSON_GetArrayItem(merkle, i);
        if (cJSON_IsString(branch) && branch->valuestring) {
            size_t branch_len = 0;
            if (hex_to_bytes_reversed(branch->valuestring, job->merkle_branch[job->merkle_branch_count], 32, &branch_len) && branch_len == 32) {
                job->merkle_branch_count++;
            }
        }
    }

    if (cJSON_IsTrue(clean_jobs)) {
        job->next_nonce = 0;
        job->extranonce2_counter = 0;
    }

    job->extranonce1_len = prev_extranonce1_len;
    memcpy(job->extranonce1, prev_extranonce1, job->extranonce1_len);
    job->extranonce2_size = prev_extranonce2_size;
    job->job_seq = miner->current_job.job_seq + 1u;
    job->job_available = true;

    compact_to_target(job->nbits, job->block_target);
    memcpy(job->share_target, prev_share_target, sizeof(job->share_target));

    miner->current_job.job_seq = job->job_seq;
    miner->current_job.job_available = true;
    xSemaphoreGive(miner->job_mutex);

    char block_target_hex[65];
    char share_target_hex[65];
    target_to_hex(job->block_target, block_target_hex, sizeof(block_target_hex));
    target_to_hex(job->share_target, share_target_hex, sizeof(share_target_hex));
    ESP_LOGI(TAG, "Mining notify: job=%.*s branches=%d target=%s share=%s",
             (int)job->job_id_len, job->job_id, branch_count, block_target_hex, share_target_hex);

    return true;
}

static bool parse_subscribe_result(miner_context_t *miner, cJSON *result) {
    if (!cJSON_IsArray(result) || cJSON_GetArraySize(result) < 3) {
        return false;
    }

    cJSON *extranonce1 = cJSON_GetArrayItem(result, 1);
    cJSON *extranonce2_size = cJSON_GetArrayItem(result, 2);
    uint32_t parsed_extranonce2_size = 0;
    uint8_t parsed_extranonce1[sizeof(miner->current_job.extranonce1)];
    size_t parsed_extranonce1_len = 0;

    if (!cJSON_IsString(extranonce1) || !parse_u32_value(extranonce2_size, &parsed_extranonce2_size)) {
        return false;
    }

    if (parsed_extranonce2_size > sizeof(parsed_extranonce1)) {
        parsed_extranonce2_size = sizeof(parsed_extranonce1);
    }

    if (!hex_to_bytes(extranonce1->valuestring, parsed_extranonce1, sizeof(parsed_extranonce1), &parsed_extranonce1_len)) {
        return false;
    }

    if (xSemaphoreTake(miner->job_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return false;
    }

    miner->current_job.extranonce2_size = parsed_extranonce2_size;
    miner->current_job.extranonce1_len = parsed_extranonce1_len;
    memcpy(miner->current_job.extranonce1, parsed_extranonce1, parsed_extranonce1_len);
    xSemaphoreGive(miner->job_mutex);

    ESP_LOGI(TAG, "Subscribed: extranonce1_len=%u extranonce2_size=%u",
             (unsigned)miner->current_job.extranonce1_len,
             (unsigned)miner->current_job.extranonce2_size);
    return true;
}

static void stratum_handle_response(miner_context_t *miner, const char *resp) {
    cJSON *root = cJSON_Parse(resp);
    if (!root) {
        ESP_LOGW(TAG, "Bad JSON from pool: %s", resp);
        return;
    }

    cJSON *method = cJSON_GetObjectItem(root, "method");
    cJSON *params = cJSON_GetObjectItem(root, "params");
    cJSON *result = cJSON_GetObjectItem(root, "result");
    cJSON *error = cJSON_GetObjectItem(root, "error");

    if (cJSON_IsObject(error) && !cJSON_IsNull(error)) {
        char *err_str = cJSON_PrintUnformatted(error);
        ESP_LOGW(TAG, "Pool error: %s", err_str ? err_str : "<alloc failed>");
        if (err_str) {
            free(err_str);
        }
    }

    if (cJSON_IsString(method) && method->valuestring) {
        if (strcmp(method->valuestring, "mining.notify") == 0) {
            (void)parse_notify(miner, params);
        } else if (strcmp(method->valuestring, "mining.set_difficulty") == 0) {
            if (cJSON_IsArray(params) && cJSON_GetArraySize(params) > 0) {
                cJSON *diff = cJSON_GetArrayItem(params, 0);
                if (cJSON_IsNumber(diff)) {
                    if (xSemaphoreTake(miner->job_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
                        cJSON_Delete(root);
                        return;
                    }
                    miner->difficulty = diff->valuedouble;
                    update_share_target(miner);
                    char share_target_hex[65];
                    target_to_hex(miner->current_job.share_target, share_target_hex, sizeof(share_target_hex));
                    xSemaphoreGive(miner->job_mutex);
                    ESP_LOGI(TAG, "Difficulty set to %.4f share_target=%s", miner->difficulty, share_target_hex);
                }
            }
        }
    } else if (cJSON_IsNumber(cJSON_GetObjectItem(root, "id"))) {
        cJSON *id = cJSON_GetObjectItem(root, "id");
        if (id->valueint == 1) {
            (void)parse_subscribe_result(miner, result);
        } else if (id->valueint == 2) {
            ESP_LOGI(TAG, "Authorize result: %s", cJSON_IsTrue(result) ? "OK" : "FAIL");
        } else if (id->valueint == 4) {
            if (cJSON_IsTrue(result)) {
                __atomic_add_fetch(&miner->share_count, 1u, __ATOMIC_RELAXED);
                ESP_LOGI(TAG, "Share accepted, total=%u", miner->share_count);
            } else {
                ESP_LOGW(TAG, "Share rejected");
            }
        }
    }

    cJSON_Delete(root);
}

static int stratum_send(miner_context_t *miner, const char *msg) {
    if (miner->sock < 0) {
        return -1;
    }

    if (xSemaphoreTake(miner->sock_mutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return -1;
    }

    int len = (int)strlen(msg);
    int sent = lwip_send(miner->sock, msg, len, 0);
    xSemaphoreGive(miner->sock_mutex);

    if (sent != len) {
        ESP_LOGE(TAG, "Failed to send stratum message");
        return -1;
    }
    return 0;
}

static int stratum_recv_line(miner_context_t *miner, char *buf, int max_len) {
    int pos = 0;
    while (pos < max_len - 1) {
        int ret = lwip_recv(miner->sock, buf + pos, 1, 0);
        if (ret <= 0) {
            return -1;
        }
        if (buf[pos] == '\n') {
            buf[pos] = '\0';
            if (pos > 0 && buf[pos - 1] == '\r') {
                buf[pos - 1] = '\0';
            }
            return pos;
        }
        pos++;
    }
    buf[max_len - 1] = '\0';
    return -1;
}

static int stratum_connect(miner_context_t *miner) {
    int retry_count = 0;

    while (retry_count < 10) {
        int sock = lwip_socket(PF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            ESP_LOGE(TAG, "Failed to create socket");
            vTaskDelay(pdMS_TO_TICKS(1000));
            retry_count++;
            continue;
        }

        struct hostent *he = gethostbyname(STRATUM_HOST);
        if (!he) {
            ESP_LOGW(TAG, "Failed to resolve hostname (attempt %d)", retry_count + 1);
            lwip_close(sock);
            vTaskDelay(pdMS_TO_TICKS(2000));
            retry_count++;
            continue;
        }

        struct sockaddr_in server = {0};
        server.sin_family = AF_INET;
        server.sin_addr = *((struct in_addr *)he->h_addr);
        server.sin_port = htons(STRATUM_PORT);

        ESP_LOGI(TAG, "Connecting to %s (%s):%d...", STRATUM_HOST, inet_ntoa(server.sin_addr), STRATUM_PORT);

        if (lwip_connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
            ESP_LOGW(TAG, "Failed to connect to stratum (attempt %d)", retry_count + 1);
            lwip_close(sock);
            vTaskDelay(pdMS_TO_TICKS(2000));
            retry_count++;
            continue;
        }

        ESP_LOGI(TAG, "Connected to stratum pool %s:%d", STRATUM_HOST, STRATUM_PORT);
        miner->sock = sock;
        return 0;
    }

    ESP_LOGE(TAG, "Failed to connect after 10 attempts");
    return -1;
}

bool merkle_root_from_job(const stratum_job_t *job, const uint8_t *coinbase_hash, uint8_t out[32]) {
    uint8_t hash[32];
    memcpy(out, coinbase_hash, 32);

    for (size_t i = 0; i < job->merkle_branch_count; i++) {
        uint8_t buffer[64];
        memcpy(buffer, out, 32);
        memcpy(buffer + 32, job->merkle_branch[i], 32);
        double_sha256(buffer, sizeof(buffer), hash);
        memcpy(out, hash, 32);
    }
    return true;
}

void prepare_sha_buffer(stratum_job_t *job, const uint8_t merkle_root[32], uint32_t start_nonce) {
    write_u32_le(&job->sha_buffer[0], job->version);
    reverse_copy(&job->sha_buffer[4], job->prev_block_hash, 32);
    reverse_copy(&job->sha_buffer[36], merkle_root, 32);
    write_u32_le(&job->sha_buffer[68], job->ntime);
    write_u32_le(&job->sha_buffer[72], job->nbits);
    write_u32_le(&job->sha_buffer[76], start_nonce);

    job->sha_buffer[80] = 0x80;
    memset(&job->sha_buffer[81], 0, 45);
    job->sha_buffer[126] = 0x02;
    job->sha_buffer[127] = 0x80;

    nerd_mids(job->midstate, job->sha_buffer);
    nerd_sha256_bake(job->midstate, job->sha_buffer + 64, job->bake);
}

static void mining_task(void *arg) {
    miner_context_t *miner = (miner_context_t *)arg;
    uint8_t hash[32];
    uint8_t coinbase[MAX_COINBASE_SIZE];
    uint8_t coinbase_hash[32];
    uint8_t merkle_root[32];
    uint8_t extranonce2[16];
    stratum_job_t job;
    uint64_t last_job_seq = 0;
    uint32_t nonce = 0;
    int64_t last_log = esp_timer_get_time();
    uint64_t hash_count_snapshot = 0;

    ESP_LOGI(TAG, "Mining task started on core %d", xPortGetCoreID());

    while (1) {
        bool have_job = false;
        if (xSemaphoreTake(miner->job_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
            have_job = miner->current_job.job_available;
            if (have_job) {
                job = miner->current_job;
                if (job.extranonce1_len == 0u || job.extranonce2_size == 0u) {
                    xSemaphoreGive(miner->job_mutex);
                    vTaskDelay(pdMS_TO_TICKS(100));
                    continue;
                }
                if (job.job_seq != last_job_seq) {
                    last_job_seq = job.job_seq;
                    nonce = 0;
                }

                uint32_t claimed = miner->current_job.next_nonce;
                miner->current_job.next_nonce += WORK_CHUNK_NONCES;
                if (miner->current_job.next_nonce < claimed) {
                    miner->current_job.next_nonce = 0;
                    miner->current_job.extranonce2_counter++;
                }

                size_t extranonce2_len = job.extranonce2_size;
                if (extranonce2_len > sizeof(extranonce2)) {
                    extranonce2_len = sizeof(extranonce2);
                }

                build_extranonce2(&job, miner->current_job.extranonce2_counter, extranonce2, extranonce2_len);
                miner->current_job.extranonce2_counter++;

                xSemaphoreGive(miner->job_mutex);

                nonce = claimed;

                size_t coinbase_len = 0;
                if (!build_coinbase(&job, extranonce2, extranonce2_len, coinbase, &coinbase_len)) {
                    vTaskDelay(pdMS_TO_TICKS(10));
                    continue;
                }

                double_sha256(coinbase, coinbase_len, coinbase_hash);
                merkle_root_from_job(&job, coinbase_hash, merkle_root);

                prepare_sha_buffer(&job, merkle_root, nonce);

                for (uint32_t i = 0; i < WORK_CHUNK_NONCES; i++, nonce++) {
                    bool prof = profile_check(nonce);

                    if (xSemaphoreTake(miner->job_mutex, 0) == pdTRUE) {
                        bool still_valid = miner->current_job.job_available && miner->current_job.job_seq == last_job_seq;
                        xSemaphoreGive(miner->job_mutex);
                        if (!still_valid) {
                            break;
                        }
                    }

                    if (prof) { profile_sw_start(SW_NONCE_UPDATE); profile_sw_hash_begin(); }
                    ((uint32_t *)(job.sha_buffer + 76))[0] = nonce;
                    if (prof) { profile_sw_end(SW_NONCE_UPDATE); profile_sw_start(SW_SHA_COMPUTE); }

                    bool sha_ok = nerd_sha256d_baked(job.midstate, job.sha_buffer + 64, job.bake, hash);
                    if (prof) { profile_sw_end(SW_SHA_COMPUTE); profile_sw_start(SW_TARGET_CHECK); }

                    if (sha_ok) {
                        bool share_ok = target_less_or_equal(hash, job.share_target);
                        bool block_ok = target_less_or_equal(hash, job.block_target);
                        if (prof) { profile_sw_end(SW_TARGET_CHECK); profile_sw_hash_end(); }

                        if (share_ok) {
                            if (submit_share(miner, &job, extranonce2, nonce)) {
                                __atomic_add_fetch(&miner->share_count, 1u, __ATOMIC_RELAXED);
                                profile_share_submit();
                            }
                        }
                        if (block_ok) {
                            char hash_hex[65];
                            target_to_hex(hash, hash_hex, sizeof(hash_hex));
                            ESP_LOGW(TAG, "BLOCK CANDIDATE on core %d nonce=%08x hash=%s", xPortGetCoreID(), nonce, hash_hex);
                        }
                    } else {
                        if (prof) { profile_sw_end(SW_TARGET_CHECK); profile_sw_hash_end(); }
                    }

                    __atomic_add_fetch(&miner->hash_count, 1u, __ATOMIC_RELAXED);
                }
            } else {
                xSemaphoreGive(miner->job_mutex);
            }
        }

        int64_t now = esp_timer_get_time();
        if (now - last_log > 30000000) {
            uint64_t total_hashes = __atomic_load_n(&miner->hash_count, __ATOMIC_RELAXED);
            uint64_t hashes_30s = total_hashes - hash_count_snapshot;
            hash_count_snapshot = total_hashes;
            ESP_LOGI(TAG, "Core%d: total=%llu rate=%llu H/s nonce=%08x",
                     xPortGetCoreID(),
                     (unsigned long long)total_hashes,
                     (unsigned long long)(hashes_30s / 30u),
                     nonce);
            last_log = now;
            profile_report_sw(TAG, hashes_30s, 30, 0);
        }

        if (!have_job) {
            vTaskDelay(pdMS_TO_TICKS(500));
        }
    }
}

static void stratum_task(void *arg) {
    miner_context_t *miner = (miner_context_t *)arg;
    char line[MAX_JSON_LINE];

    while (1) {
        if (stratum_connect(miner) < 0) {
            vTaskDelay(pdMS_TO_TICKS(3000));
            continue;
        }

        char subscribe_msg[256];
        snprintf(subscribe_msg, sizeof(subscribe_msg),
                 "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"esp32/1.0\"]}\n");
        if (stratum_send(miner, subscribe_msg) < 0) {
            lwip_close(miner->sock);
            miner->sock = -1;
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        char authorize_msg[512];
        snprintf(authorize_msg, sizeof(authorize_msg),
                 "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\"]}\n",
                 STRATUM_USER, STRATUM_PASS);
        if (stratum_send(miner, authorize_msg) < 0) {
            lwip_close(miner->sock);
            miner->sock = -1;
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        while (stratum_recv_line(miner, line, sizeof(line)) >= 0) {
            stratum_handle_response(miner, line);
        }

        ESP_LOGW(TAG, "Stratum disconnected");
        if (miner->sock >= 0) {
            lwip_close(miner->sock);
        }
        miner->sock = -1;

        if (xSemaphoreTake(miner->job_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
            miner->current_job.job_available = false;
            xSemaphoreGive(miner->job_mutex);
        }

        vTaskDelay(pdMS_TO_TICKS(3000));
    }
}

static void WiFi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    (void)arg;
    (void)event_data;

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
        ESP_LOGI(TAG, "Retrying WiFi connection...");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        char ip_str[16];
        esp_ip4addr_ntoa(&event->ip_info.ip, ip_str, sizeof(ip_str));
        ESP_LOGI(TAG, "WiFi connected! IP: %s", ip_str);
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
        gpio_set_level(LED_PIN, 1);
    }
}

static void WiFi_init(void) {
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &WiFi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &WiFi_event_handler, NULL));

    wifi_config_t wifi_config = {0};
    strcpy((char *)wifi_config.sta.ssid, WIFI_SSID);
    strcpy((char *)wifi_config.sta.password, WIFI_PASSWORD);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "WiFi init complete, connecting to %s...", WIFI_SSID);
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
    ESP_LOGI(TAG, "WiFi connected!");
}

static void LED_init(void) {
    gpio_reset_pin(LED_PIN);
    gpio_set_direction(LED_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(LED_PIN, 0);
}

static void prepare_default_targets(miner_context_t *miner) {
    compact_to_target(0x1d00ffffu, miner->diff1_target);
    memcpy(miner->current_job.share_target, miner->diff1_target, sizeof(miner->diff1_target));
}

void app_main(void) {
    configure_stratum_settings();

    ESP_LOGI(TAG, "===========================================");
    ESP_LOGI(TAG, "Fractal Bitcoin (FB) ESP32 Miner");
    ESP_LOGI(TAG, "===========================================");
    ESP_LOGI(TAG, "Chip: ESP32-D0WD-V3 (Dual Core)");
    ESP_LOGI(TAG, "Framework: ESP-IDF 6.0");
    ESP_LOGI(TAG, "CPU Frequency: 240 MHz");
    ESP_LOGI(TAG, "Target: Fractal Bitcoin (Testing with Slushpool)");
    ESP_LOGI(TAG, "Pool: %s:%d", STRATUM_HOST, STRATUM_PORT);
    ESP_LOGI(TAG, "Worker: %s", STRATUM_USER);
    ESP_LOGI(TAG, "===========================================");

    profile_init();
    profile_set_sha("SHA256_LL");
    profile_measure_overhead();

    LED_init();
    gpio_set_level(LED_PIN, 1);
    vTaskDelay(pdMS_TO_TICKS(100));
    gpio_set_level(LED_PIN, 0);

    ESP_ERROR_CHECK(nvs_flash_init());
    esp_task_wdt_deinit();

    WiFi_init();

    memset(&g_miner, 0, sizeof(g_miner));
    g_miner.sock = -1;
    g_miner.difficulty = 1.0;
    g_miner.job_mutex = xSemaphoreCreateMutex();
    g_miner.sock_mutex = xSemaphoreCreateMutex();
    g_miner.start_time = esp_timer_get_time();
    g_miner.current_job.job_available = false;
    prepare_default_targets(&g_miner);

    if (!g_miner.job_mutex || !g_miner.sock_mutex) {
        ESP_LOGE(TAG, "Failed to create mutexes");
        return;
    }

    xTaskCreatePinnedToCore(&stratum_task, "stratum", 12288, &g_miner, 5, NULL, 1);
    vTaskDelay(pdMS_TO_TICKS(500));
    xTaskCreatePinnedToCore(&mining_task, "mining0", 12288, &g_miner, 3, NULL, 0);
    xTaskCreatePinnedToCore(&miner_hw_task, "mining1", 12288, &g_miner, 3, NULL, 1);

    ESP_LOGI(TAG, "===========================================");
    ESP_LOGI(TAG, "Mining started!");
    ESP_LOGI(TAG, "===========================================");

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
