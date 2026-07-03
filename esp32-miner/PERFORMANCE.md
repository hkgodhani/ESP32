# ESP32 FB Miner — Performance Report

## Hardware

| Item | Value |
|------|-------|
| Chip | ESP32-D0WD-V3 (rev v3.1) |
| CPU | 240 MHz, dual-core Xtensa LX6 |
| Flash | 2MB (detected), DIO mode |
| Framework | ESP-IDF 6.0.1 |
| SHA | Hardware accelerator (SHA256_LL) |

## Combined Hashrate

| Core | Method | Hashrate |
|------|--------|----------|
| Core 0 | SW SHA (nerdSHA256plus) | ~138 kH/s |
| Core 1 | HW SHA (SHA accelerator) | ~138 kH/s |
| **Combined** | | **~276 kH/s** |

## Hardware SHA Pipeline (826 cyc/hash)

| Stage | Avg Cycles | % of Total |
|-------|-----------|------------|
| fill_block_up | 134 | 16.2% |
| start1 | 17 | 2.1% |
| fill_upper | 135 | 16.4% |
| wait1 | 60 | 7.3% |
| continue | 14 | 1.7% |
| fill_double | 54 | 6.5% |
| wait2 | 56 | 6.8% |
| load1 | 13 | 1.6% |
| wait3 | 56 | 6.8% |
| start2 | 13 | 1.6% |
| wait4 | 60 | 7.3% |
| load2 | 14 | 1.7% |
| read_digest | 60 | 7.3% |
| fill_block_lo | 134 | 16.2% |
| **Total** | **826** | **100%** |

## Critical Path Breakdown

| Category | Cycles | % |
|----------|--------|---|
| Register writes | 457 | 55.3% |
| SHA wait | 232 | 28.1% |
| Digest read+check | 60 | 7.3% |
| Control | 77 | 9.3% |

## Register Write Audit

| Fill Function | Stores | Constant | Variable | Cycles | cyc/store |
|-------------|--------|----------|----------|--------|-----------|
| fill_block (upper+lower) | 16 | 16 | 0 | 268 | 16.8 |
| fill_upper | 16 | 15 | 1 | 135 | 8.4 |
| fill_double | 8 | 8 | 0 | 54 | 6.8 |
| **Total** | **40** | **39 (97.5%)** | **1 (2.5%)** | **457** | **11.4** |

## Software SHA Pipeline (3422 cyc/hash)

| Stage | Avg Cycles | % of Total |
|-------|-----------|------------|
| nonce_update | 44 | 1.3% |
| sha_compute | 3418 | 98.2% |
| target_check | 17 | 0.5% |
| **Total** | **3479** | **100%** |

## Profiler Configuration

- Sampling: 1:1024 (every 1024th nonce)
- Clock: Cycle-accurate via RSR(CCOUNT)
- Self-overhead: 1 cycle/call (measured, 10k trials)
- Mask: 0x3FF
