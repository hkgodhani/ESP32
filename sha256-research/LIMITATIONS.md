# Limitations — Research Phase 1 (v1.0.0)

This document explicitly states the scope boundaries of this research. These limitations prevent overgeneralization of the conclusions.

## Algorithmic Scope

1. **Standard SHA-256 only**: This study investigates the SHA-256 algorithm as defined by FIPS 180-4. Variants (SHA-512, SHA-3, BLAKE, etc.) are not analyzed.

2. **Bitcoin proof-of-work construction**: The specific construction SHA-256d (double SHA-256 applied to an 80-byte block header) is used. Conclusions may not apply to other uses of SHA-256.

3. **Single-SHA analysis**: The first SHA-256 application (header → 32-byte digest) is analyzed in full. The second SHA-256 (hash of the 32-byte result) is not analyzed; its input is fully nonce-dependent, so 100% of its operations are likely nonce-dependent.

## Input Variation Scope

4. **Nonce-only variation**: Only the 32-bit nonce field varies. All other fields (version, prev_block, merkle_root, timestamp, nbits) are fixed. If extranonce, timestamp, or merkle root changes, the precomputation boundary shifts.

5. **Synthetic block header**: Experiments use a minimal block header with zeroed prev_block and merkle_root. Real Bitcoin headers produce the same mathematical dependency structure, but the specific bit patterns differ.

6. **Single-bit influence detection**: Influence is classified binarily (invariant vs. nonce-dependent) by comparing nonce=0 against nonce=1 (a single-bit flip). The degree of influence (number of bits that change) is not quantified.

## Optimization Class Scope

7. **Exact precomputation only**: This study examines exact precomputation — caching results that are mathematically identical across nonces. Nonexact methods (probabilistic computation, approximation, statistical shortcuts) are not considered.

8. **Algorithm-level analysis only**: The precomputation boundary applies to the SHA-256 algorithm itself. Hardware-specific optimizations (assembly implementations, SIMD, GPU, ASIC circuit techniques) operate at different levels and are not bounded by this analysis.

9. **Dependency-based optimizations only**: The study investigates optimizations that exploit input-to-output dependency. Other classes (memory layout, instruction scheduling, parallel execution) may achieve gains independently of the algorithmic boundary.

## Platform Scope

10. **ESP32-specific findings**: Hardware constraints (DPORT contention, SHA_LOAD direction, mandatory TEXT_BASE writes) are specific to the ESP32 SHA accelerator. They do not generalize to other platforms.

11. **No power/energy analysis**: Trade-offs between computation, power consumption, and energy efficiency are not analyzed.
