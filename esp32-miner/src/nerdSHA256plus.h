#ifndef nerdSHA256plus_H_
#define nerdSHA256plus_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

void nerd_mids(uint32_t* digest, const uint8_t* dataIn);

void nerd_sha256_bake(const uint32_t* digest, const uint8_t* dataIn, uint32_t* bake);

bool nerd_sha256d_baked(const uint32_t* digest, const uint8_t* dataIn, const uint32_t* bake, uint8_t* doubleHash);

double diff_from_target(void *target);

bool isSha256Valid(const void* sha256);

#endif
