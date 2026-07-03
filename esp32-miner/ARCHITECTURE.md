# ESP32 FB Miner — Architecture

## Overview

Dual-core ESP32 Bitcoin miner using hardware SHA-256 accelerator (Core 1) and software SHA-256 (Core 0). Targets ~276 kH/s combined.

## System Components

```
app_main()
├── WiFi_init()           — Connect to AP
├── stratum_task (Core 1) — Stratum protocol handler
├── mining_task (Core 0)  — Software SHA-256 mining loop
└── miner_hw_task (Core 1) — Hardware SHA-256 mining loop
```

## Core 0: Software Mining (mining_task)

Runs `nerdSHA256plus` — optimized SHA-256 with midstate precomputation and baked message schedule.

Per-nonce:
1. Nonce update (write nonce to sha_buffer)
2. SHA compute (nerd_sha256d_baked)
3. Target check (16-bit early reject)

## Core 1: Hardware Mining (miner_hw_task)

Runs ESP32 SHA-256 accelerator via direct register access.

Per-nonce:
1. START block 1 — SHA engine processes first 64 bytes
2. FILL_UPPER — Write block 2 data (tail + nonce + padding)
3. CONTINUE — Process block 2
4. FILL_DOUBLE — Write double-hash padding
5. START — Process double-hash
6. FILL_BLOCK_UPPER — Write block 1 upper half for next iteration
7. LOAD — Transfer hash from engine to TEXT_BASE
8. READ_DIGEST — Read and check hash

## Data Flow

```
Stratum Pool
    ↓
stratum_task → job data → miner_context_t (shared via mutex)
    ↓
prepare_sha_buffer() → sha_buffer[128] (block header)
    ↓
Core 0: nerd_sha256d_baked(midstate, tail, bake, hash)
Core 1: sha_ll_start/continue/load → TEXT_BASE → read_digest
```

## Key Files

| File | Purpose |
|------|---------|
| `main.c` | WiFi, stratum, SW mining task, app_main |
| `hw_sha_miner.c` | HW SHA mining loop |
| `nerdSHA256plus.c` | Optimized SW SHA-256 with midstate/bake |
| `profile.h` | Inline profiler API |
| `profile_internal.h` | Stage enums, extern variables |
| `profile_core.c` | Profiler state, report formatting |
| `miner.h` | Shared types (stratum_job_t, miner_context_t) |

## Hardware SHA Pipeline

```
sha_fill_block_lower (124 cyc, [0:7]=block1)
    ↓
START (17 cyc) — engine reads TEXT_BASE, begins block 1
    ↓
sha_fill_upper (135 cyc, [0:15]=block2+nonce+padding)
    ↓
WAIT1 (60 cyc) — engine finishes block 1
    ↓
CONTINUE (14 cyc) — engine reads TEXT_BASE, begins block 2
    ↓
sha_fill_double (54 cyc, [8:15]=double padding)
    ↓
WAIT2 (56 cyc) — engine finishes block 2
    ↓
LOAD1 (13 cyc) — intermediate hash → TEXT_BASE[0:7]
    ↓
WAIT3 (56 cyc) — engine loads hash
    ↓
START2 (13 cyc) — engine reads TEXT_BASE, begins double SHA
    ↓
sha_fill_block_upper (134 cyc, [8:15]=block1 upper for next iter)
    ↓
WAIT4 (60 cyc) — engine finishes double SHA
    ↓
LOAD2 (14 cyc) — final hash → TEXT_BASE[0:7]
    ↓
READ_DIGEST (60 cyc) — read hash, early reject on H0 top 16 bits
    ↓
sha_fill_block_lower (134 cyc, [0:7]=block1 lower for next iter)
    ↓
TARGET_CHECK (17 cyc) — compare against share/block target
```

Total pipeline: ~826 cyc/hash
