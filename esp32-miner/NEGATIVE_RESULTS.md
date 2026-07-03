# ESP32 FB Miner — Negative Results

Documented experiments that did not produce improvement. Prevents revisiting dead ends.

## NR-001: Pipeline Overlap

| Field | Value |
|-------|-------|
| **Hypothesis** | Writing SHA_TEXT_BASE while the SHA engine is busy will hide register write latency behind engine processing time |
| **Method** | Reordered mining loop: fill_upper immediately after START1 (before WAIT1), fill_double immediately after CONTINUE (before WAIT2), fill_block_upper after START2 (before WAIT4) |
| **Result** | No improvement. Pipeline remained at ~826 cyc/hash (was ~811). WAIT stages showed same cycle counts. |
| **Conclusion** | DPORT bus contention between CPU writes to TEXT_BASE and SHA engine DPORT accesses inflates engine busy time, negating any overlap gain. The SHA engine's busy time increased by exactly the amount of overlapping CPU writes. |
| **Evidence** | Profiler showed WAIT1=60, WAIT2=56, WAIT4=60 — unchanged from serial pipeline |

## NR-002: Midstate Injection (v4)

| Field | Value |
|-------|-------|
| **Hypothesis** | Pre-computed midstate (8 words) can be restored into the SHA engine via SHA_LOAD, avoiding the need to rewrite Block 1 (16 words) every iteration |
| **Method** | Write midstate to TEXT_BASE[0:7], call SHA_LOAD to inject into engine, then process only Block 2 |
| **Result** | Does not work. SHA_LOAD copies FROM internal state TO TEXT_BASE, not the other way around. |
| **Conclusion** | ESP32 hardware has no writable state registers. Midstate injection is architecturally impossible on the original ESP32. SparkMiner independently confirmed this. |
| **Evidence** | TEXT_BASE retention test: after SHA_LOAD, TEXT_BASE[0:7] contains the hash result (overwritten), proving LOAD is a one-way transfer. SparkMiner miner.cpp line 684: "v4 midstate injection does NOT work on ESP32" |

## NR-003: Register Caching (Xtensa)

| Field | Value |
|-------|-------|
| **Hypothesis** | Caching frequently-used values in Xtensa registers will reduce memory access and improve hashrate |
| **Method** | Attempt to keep constant words (padding, zeros) in registers across iterations |
| **Result** | Not achievable due to Xtensa register pressure constraints (16 general-purpose registers, many occupied by loop state) |
| **Conclusion** | SparkMiner independently confirmed: "Register caching was attempted but not achievable due to Xtensa constraints." |
| **Evidence** | SparkMiner sha256_pipelined_v3.cpp comment |

## NR-004: SparkMiner Comparison

| Field | Value |
|-------|-------|
| **Hypothesis** | SparkMiner may have undiscovered optimizations that improve upon our miner |
| **Method** | Full analysis of SparkMiner repository: sha256_ll.cpp, sha256_pipelined*.cpp, sha256_asm.h, miner_sha256.cpp, sha256_hw.cpp |
| **Result** | Same hardware limitations confirmed. Assembly pipeline (v3) uses same approach as our C code. Midstate injection (v4) confirmed non-functional on ESP32. |
| **Conclusion** | Independent validation of our findings. SparkMiner faces identical hardware constraints. Their assembly implementation provides ~10-15% ceiling vs. our C code. |
| **Evidence** | Detailed comparison in SparkMiner analysis report |
