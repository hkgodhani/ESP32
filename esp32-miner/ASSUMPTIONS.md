# ESP32 FB Miner — Assumptions

Every assumption documented with status: `Untested`, `Confirmed`, or `False`.

## Hardware SHA

| ID | Assumption | Status | Evidence |
|----|-----------|--------|----------|
| A-001 | Changing only the nonce changes only W3 of Block 2 | **Confirmed** | Store audit: 39/40 stores constant, only nonce word changes |
| A-002 | SHA_TEXT_BASE persists unmodified during engine processing | **Confirmed** | TEXT_BASE retention test: data preserved during START busy and after WAIT |
| A-003 | SHA_LOAD overwrites TEXT_BASE[0:7], preserves [8:15] | **Confirmed** | TEXT_BASE retention test: lo=OVERWRITTEN, hi=PRESERVED |
| A-004 | The SHA engine reads TEXT_BASE at trigger time, not during processing | **Confirmed** | TEXT_BASE retention test: Writes to TEXT_BASE during engine busy don't corrupt computation |
| A-005 | Writing to TEXT_BASE while engine is busy causes DPORT contention | **Confirmed** | Pipeline overlap test: WAIT1/WAIT2/WAIT4 didn't decrease when writes overlapped |
| A-006 | Midstate can be injected back into the SHA engine via SHA_LOAD | **False** | SHA_LOAD is one-way (internal → TEXT_BASE), not injectable |
| A-007 | Pipeline overlap can hide register writes behind SHA engine busy time | **False** | DPORT contention inflates engine busy time, negating overlap gains |
| A-008 | Assembly fill functions will be significantly faster than C | **Untested** | Not yet benchmarked; estimated 10-15% improvement |

## Software SHA

| ID | Assumption | Status | Evidence |
|----|-----------|--------|----------|
| A-009 | nerdSHA256plus computes correct SHA-256 for all inputs | **Confirmed** | NIST + Bitcoin test vectors pass |
| A-010 | The baked message schedule optimization produces correct SHA-256 results | **Confirmed** | Bitcoin block hashes verified |
| A-011 | 16-bit early reject is safe (no false positives for valid blocks) | **Confirmed** | Valid blocks have H0 top 16 bits = 0; rejects have non-zero |

## Architecture

| ID | Assumption | Status | Evidence |
|----|-----------|--------|----------|
| A-012 | Dual-core mining doubles single-core hashrate | **Confirmed** | Both cores achieve ~138 kH/s independently |
| A-013 | Mutex contention between cores is negligible | **Confirmed** | Profiler shows near-zero mutex_cont events |
| A-014 | The stratum protocol is the bottleneck for job switching | **Confirmed** | Job switch latency measured but not performance-critical |
