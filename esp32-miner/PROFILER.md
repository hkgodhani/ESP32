# ESP32 FB Miner — Profiler

## Design

Cycle-accurate profiler using the ESP32's CCOUNT register (cycle counter, one per core).

### Sampling

- 1:1024 sample rate (`nonce & 0x3FF == 0`)
- Only sampled nonces incur profiling overhead
- Overhead: ~40-60 cycles per sampled hash (1 cycle for CCOUNT read, rest for accumulator update)

### Measurement

```c
// Hot path (inline, zero-overhead when disabled)
static inline void profile_hw_start(int stage) {
    profile_hw_start_times[stage] = get_cycle_count();
}

static inline void profile_hw_end(int stage) {
    uint32_t _d = get_cycle_count() - profile_hw_start_times[stage];
    if (_d >= profile_self_overhead) _d -= profile_self_overhead;
    stage_acc_t *a = &profile_hw.stages[stage];
    a->total += _d;
    a->cnt++;
}
```

### Stages (HW)

| Enum | Name | Description |
|------|------|-------------|
| HW_FILL_BLOCK_UPPER | fill_block_up | Write TEXT_BASE[8:15] with block 1 data |
| HW_START1 | start1 | Trigger SHA-256 start |
| HW_FILL_UPPER | fill_upper | Write TEXT_BASE[0:15] with block 2 + nonce + padding |
| HW_WAIT1 | wait1 | Poll SHA_BUSY after block 1 |
| HW_CONTINUE | continue | Trigger SHA-256 continue |
| HW_FILL_DOUBLE | fill_double | Write TEXT_BASE[8:15] with double padding |
| HW_WAIT2 | wait2 | Poll SHA_BUSY after block 2 |
| HW_LOAD1 | load1 | Trigger SHA_LOAD (intermediate hash) |
| HW_WAIT3 | wait3 | Poll SHA_BUSY after load |
| HW_START2 | start2 | Trigger SHA-256 start for double |
| HW_WAIT4 | wait4 | Poll SHA_BUSY after double |
| HW_LOAD2 | load2 | Trigger SHA_LOAD (final hash) |
| HW_READ_DIGEST | read_digest | Read hash from TEXT_BASE via DPORT |
| HW_TARGET_CHECK | target_check | Compare hash against targets |
| HW_FILL_BLOCK_LOWER | fill_block_lo | Write TEXT_BASE[0:7] with block 1 lower |

### Stages (SW)

| Enum | Name | Description |
|------|------|-------------|
| SW_NONCE_UPDATE | nonce_update | Write nonce to sha_buffer |
| SW_SHA_COMPUTE | sha_compute | Execute nerd_sha256d_baked |
| SW_TARGET_CHECK | target_check | Compare hash against targets |

### Report

```
===== PROFILE_HW [v1] mask=0x3ff cpu=240MHz sha=SHA256_LL =====
sampled=10784 interval_H=4160083 interval_sec=30 cyc/hash=822 probe_ovr=1025

Stage               avg[cyc]     min     max   lifetime    share
fill_block_up              134     134    1847      1446774   16.3%
...
```

### Validation

- Self-overhead measured via 10k back-to-back CCOUNT reads
- `probe_ovr` tracks (hash_total - sum(stages)) for measurement noise
- Typical probe_ovr: 1025 cyc (includes target_check on rare valid hashes)
