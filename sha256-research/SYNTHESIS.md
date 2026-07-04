# SHA-256 Under Bitcoin Nonce Variation: An Experimental Study

```
Research Phase: 1
Release: v1.0.0
Status: Stable
Date: 2026-07-04
```

## Abstract

This study investigates how information propagates through the SHA-256 algorithm under Bitcoin mining conditions where only the 32-bit nonce varies. Using cycle-accurate profiling on an ESP32 and a pure-Python SHA-256 tracing framework, we quantify the spread of nonce influence through the message schedule, compression function, and individual algorithmic operations. The result is a reproducible, evidence-based map of the SHA-256 precomputation boundary for Bitcoin block headers.

---

## 1. Introduction

Bitcoin mining applies SHA-256d to an 80-byte block header where only the 4-byte nonce field varies across iterations (ignoring infrequent changes to timestamp, extranonce, and merkle root). This restricted variation raises a natural question: what portions of SHA-256's computation produce identical results across nonces and could therefore be precomputed?

The standard Bitcoin mining optimization — **midstate computation** — exploits one such invariant region: the first 64 bytes of the block header (Block 0 of the SHA-256 padded message) produce an identical intermediate hash for all nonces. This optimization is universal and well-documented.

However, the question of whether **additional invariant regions exist beyond the midstate** has remained speculative. This study provides an experimental answer by systematically tracing nonce influence through every stage of SHA-256.

### Research questions

| ID | Question |
|----|----------|
| RQ-001 | Which message schedule words change when only the nonce changes? |
| RQ-002 | How does nonce influence propagate through the 64 compression rounds? |
| RQ-003 | Which algorithmic operations produce identical results across nonces? |
| RQ-004 | What is the maximum SHA-256 computation that can be precomputed exactly? |

---

## 2. Methodology

### 2.1 Tools

Two complementary tools were developed:

**ESP32 cycle-accurate profiler** (`esp32-miner/src/profile.h`): Measures hardware SHA-256 pipeline timing at 1:1024 sampling resolution using inline RSR(CCOUNT) reads. Validated against real Bitcoin mining at ~276 kH/s.

**Python SHA-256 tracing framework** (`sha256-research/tools/sha256_trace.py`): Pure-Python implementation exposing message schedule (W[0..63]), round-by-round compression state (a-h after each round), and operation-level intermediate values. Verified against NIST FIPS 180-4 test vectors and Python hashlib reference.

### 2.2 Influence detection

For each research question, influence is measured by comparing the computation for a base nonce (0x00000000) against a flipped-bit nonce (0x00000001). Any difference in output values (word-level, variable-level, or operation-level) is classified as "nonce-dependent."

### 2.3 Block header model

A synthetic Bitcoin block header is used with all fields fixed except the nonce:

```
version=1, prev_block=0x00*32, merkle_root=0x00*32,
time=0x4DAB5D0A, bits=0x1D00FFFF, nonce=varying
```

Real Bitcoin headers have the same mathematical structure; only the bit patterns differ. The influence propagation behavior is a property of the SHA-256 algorithm, not the specific header values.

---

## 3. RQ-001 — Message Schedule Influence

### 3.1 Method

For each of the 32 nonce bits, flip that bit and recompute the full 128-word message schedule (2 blocks × 64 words). Any word that differs from the base nonce is marked as "dependent" on that bit.

### 3.2 Results

| Region | Words | Invariant | Nonce-dependent |
|--------|-------|-----------|-----------------|
| Block 0 (W0-W63) | 64 | 64 (100%) | 0 (0%) |
| Block 1 input (W0-W15) | 16 | 15 (93.75%) | 1 — W3 (nonce word) |
| Block 1 generated (W16-W63) | 48 | 2 — W16, W17 | 46 — W18-W63 |
| **Total** | **128** | **81 (63.3%)** | **47 (36.7%)** |

### 3.3 Key findings

1. Block 0's entire message schedule is invariant. This is expected — the nonce resides at bytes 76-79 of the 80-byte header, which falls in Block 1.
2. Nonce influence first appears at **W18** of Block 1 via the dependency chain: W18 = S1(W16) + W11 + S0(W3) + W2, where W3 (the nonce) enters through the S0 rotation.
3. Once introduced at W18, influence spreads to all 46 subsequent generated words through the avalanche effect.

---

## 4. RQ-002 — Compression Round Influence

### 4.1 Method

Extending RQ-001's message schedule analysis, trace the 8 state variables (a,b,c,d,e,f,g,h) through all 64 compression rounds for each nonce. Record which variables differ from the base case after each round.

### 4.2 Results

| Round (Block 1) | Vars Influenced | Event |
|-----------------|-----------------|-------|
| 0-2 | 0 | Invariant state from Block 0 output |
| **3** | **2 (a, e)** | W3 (nonce) enters via temp1 |
| **4** | **4** | Influence spreads via S0/S1/MAJ/CH |
| **5** | **6** | Continued spread |
| **6+** | **8** | Full avalanche achieved |
| 7-63 | 8 | All subsequent rounds fully influenced |

### 4.3 Key findings

1. **Full avalanche by Round 6**: Within 3 rounds of the nonce entering the compression state, all 8 variables are nonce-dependent.
2. **Rounds 0-2 are invariant**: 3 of 64 rounds (4.7%) produce identical results across nonces. These are the only compression rounds that could benefit from precomputation.
3. **90.6% of compression operates on fully influenced state**: Rounds 7-63 (58 rounds) have all 8 variables nonce-dependent.

---

## 5. RQ-003 — Operation-Level Invariance

### 5.1 Method

For each of the 8 operations per compression round (S1, ch, temp1, S0, maj, temp2, e_new, a_new), determine whether all inputs are invariant. If any input is nonce-dependent, the operation's output is classified as nonce-dependent.

### 5.2 Results

| Block | Total Ops | Invariant | % |
|-------|-----------|-----------|---|
| Block 0 (64 rounds × 8 ops) | 512 | 512 | 100.0% |
| Block 1 (64 rounds × 8 ops) | 512 | 29 | 5.7% |
| **Total** | **1024** | **541** | **52.8%** |

The 29 invariant operations in Block 1 are:
- **Rounds 0-2**: 24 ops (all 8 types) — complete rounds with invariant inputs
- **Round 3**: 5 ops (S1, ch, S0, maj, temp2) — only the nonce word W[3] changes

### 5.3 Key finding

52.8% of SHA-256 compression operations appear invariant under nonce variation. However, this figure is misleading because it excludes the message schedule expansion (see RQ-004).

---

## 6. RQ-004 — Formal Precomputation Boundary

### 6.1 Method

Implemented a caching SHA-256 prototype (`precompute_boundary.py`) that precomputes:
- Block 0 fully (standard midstate)
- Block 1 state after Round 2 of compression
- Block 1 Round 3 invariant intermediates (S1, ch, S0, maj, temp2)

For each nonce, reconstruct the message schedule and run only Rounds 3-63 of compression from the cached state. Verify every digest against standard SHA-256.

### 6.2 Results

**Correctness**: 100/100 nonces verified against reference SHA-256. The precomputation boundary is proven correct.

**Net computation analysis**:

| Component | Ops | Description |
|-----------|-----|-------------|
| Compression cached (Block 0) | +512 | Standard midstate |
| Compression cached (Block 1, new) | +29 | R0-R2 state + R3 intermediates |
| Schedule expansion recomputed | -230 | W18-W63 depend on W3 |
| **Net savings** | **-201** | **NEGATIVE** |

### 6.3 Why the schedule expansion cost dominates

RQ-001 found that 81/128 schedule words are invariant. However, the 46 "dependent" words include W18-W63, which must be recomputed for every nonce because their dependency chain traces back to W[3]:

```
W18 = S1(W16) + W11 + S0(W3) + W2   ← W3 enters via S0(W3)
W19 = S1(W17) + W12 + S0(W4) + W3   ← W3 enters via W3 itself
...
```

Each of the 46 words requires approximately 5 operations (rotations, XORs, additions). The 230 operations required to recompute the schedule outweigh the 29 compression operations saved.

### 6.4 Conclusion

**Within the standard SHA-256 algorithm used by Bitcoin, and within the classes of exact precomputation and dependency-based optimizations investigated in this work, we found no algorithm-level optimization beyond the standard Bitcoin midstate optimization that yields a net reduction in total computation.**

---

## 7. Discussion

### 7.1 The precomputation boundary

The four research questions together establish a **computational boundary**:

> For Bitcoin block headers varying only in the nonce, exact precomputation beyond the standard midstate optimization rapidly encounters a dependency boundary where message schedule recomputation dominates any savings from invariant compression operations.

This boundary is a property of SHA-256's design — specifically, the message schedule expansion function `W[t] = S1(W[t-2]) + W[t-7] + S0(W[t-15]) + W[t-16]` — which introduces nonce dependence into the schedule approximately 3 steps after it enters the input words.

### 7.2 Why the intuition about "hidden optimization" fails

The intuitive argument is appealing: "97.5% of register writes are constant; surely there must be a way to eliminate them." Our experiments show why this intuition fails:

1. **Constant register values ≠ invariant computation**: Even though the data values written to registers are constant across nonces, the computation that produces those values depends on nonce-influenced state. You can't skip the computation without changing the result.

2. **Schedule expansion dominates**: The 64-word message schedule expansion turns a single word difference (W[3]) into 46 word differences within 3 expansion steps. This rapid diffusion means the schedule must be fully recomputed.

3. **The hardware is the bottleneck, not the algorithm**: On the ESP32, 55.6% of SHA-256 pipeline cycles are spent on register writes. But these writes are mandatory because the hardware requires TEXT_BASE to be fully rewritten each iteration. This is a hardware limitation, not an algorithmic one.

### 7.3 Relationship to the ESP32 hardware findings

The ESP32 hardware SHA accelerator adds another layer of constraints:
- **Pipeline overlap fails**: DPORT bus contention between CPU writes to TEXT_BASE and SHA engine reads inflates busy time
- **Midstate injection fails**: SHA_LOAD is one-way (internal → TEXT_BASE), not injectable
- **40 stores per hash are mandatory**: TEXT_BASE must be fully rewritten each iteration

These hardware constraints are independent of the algorithmic findings in this study. They represent a separate bound on achievable performance.

---

## 8. Threats to Validity

1. **Synthetic block header**: All experiments used a minimal block header with zeroed prev_block and merkle_root. Real Bitcoin headers have different bit patterns, but the mathematical structure of SHA-256 ensures the influence propagation behavior is identical.
2. **Single-bit detection**: Influence was detected by comparing nonce=0 against nonce=1 (a single-bit flip). This detects whether any influence exists but does not quantify the degree of influence (number of bits changed).
3. **Algorithm-level analysis only**: The precomputation boundary applies to the SHA-256 algorithm itself. Hardware-specific optimizations (assembly implementations, SIMD, parallel execution) operate at a different level and are not bounded by this analysis.
4. **No double-SHA analysis**: The second SHA-256 (hash of the 32-byte result) was not analyzed. Its input is fully nonce-dependent, so 100% of its operations are likely nonce-dependent.

---

## 9. Conclusions

### 9.1 What was found

1. **81/128 (63.3%) of schedule words are invariant** under nonce variation, but the 46 nonce-dependent words include all generated words W18-W63, which must be recomputed per nonce.

2. **3/64 (4.7%) of compression rounds are invariant** in Block 1, but the compression state reaches full avalanche by Round 6.

3. **541/1024 (52.8%) of compression operations are invariant** overall, but 512 of these are in Block 0 (already captured by midstate). Only 29 are in Block 1.

4. **The precomputation boundary is negative**: The 29 compression operations saved are outweighed by the ~230 schedule expansion operations that must be recomputed.

### 9.2 What was bounded

> **Within the standard SHA-256 algorithm used by Bitcoin, and within the classes of exact precomputation and dependency-based optimizations investigated in this work, we found no algorithm-level optimization beyond the standard Bitcoin midstate optimization that yields a net reduction in total computation.**

### 9.3 What remains open

- **Hardware-specific optimizations**: Assembly implementations of SHA-256 on specific architectures may still yield gains through better instruction scheduling, register allocation, or memory access patterns.
- **Mathematical structure**: The observation that nonce influence propagates through specific dependency chains (W3 → S0(W3) → W18 → ...) may have theoretical implications for SHA-256 analysis.
- **Alternative algorithmic approaches**: This study examined exact precomputation. Nonexact methods (e.g., probabilistic computation, approximation) are not considered.

---

## 10. Future Work

### 10.1 Structural questions

The natural next research questions are structural rather than optimization-driven:

- **RQ-005**: "How quickly does information diffuse across SHA-256 rounds?" — Quantify the avalanche effect as a function of round number, measuring output bit entropy as a function of input bit flips.
- **RQ-006**: "Which input bits dominate specific output bits?" — Construct an input-output bit dependency matrix for SHA-256 under Bitcoin mining conditions.
- **RQ-007**: "How does the SHA-256 message schedule evolution compare to that of other hash functions?" — Comparative analysis of diffusion properties across SHA family members.

### 10.2 Engineering follow-ups

The ESP32 production miner is frozen at v1.0. Future engineering work should be evaluated against the precomputation boundary established here:

| Optimization | Expected gain | Viable? |
|-------------|--------------|---------|
| Xtensa assembly for fill functions | 5-15% | Yes — hardware-specific |
| Unrolled zero writes | ~20 cycles/hash | Yes — ESP32-specific |
| Algorithm-level precomputation | ~0% | No — bounded by this study |

---

## Appendix A: Tooling

All tools and experiments are available at:
- **Production miner**: `https://github.com/hkgodhani/ESP32/tree/main/esp32-miner`
- **Research platform**: `https://github.com/hkgodhani/ESP32/tree/main/sha256-research`

### Core tools

| Tool | Purpose |
|------|---------|
| `tools/sha256_trace.py` | Pure Python SHA-256 with message schedule and compression tracing |
| `analysis/message_schedule/nonce_influence.py` | Nonce Influence Matrix (word-level and compression-level) |
| `analysis/compute_dependency.py` | Operation-level dependency analysis |
| `experiments/RQ-004/precompute_boundary.py` | Precomputation boundary prototype and verifier |

### Experiment data

| Dataset | Contents |
|---------|----------|
| `analysis/message_schedule/output/nonce_influence.csv` | 32×128 matrix (nonce bits × schedule words) |
| `analysis/message_schedule/output/nonce_influence.json` | Machine-readable influence data |
| `analysis/message_schedule/output/compression_influence.csv` | 32×8192 matrix (nonce bits × round×state_var) |

---

## Appendix B: Reproducibility

```bash
# Clone repository
git clone https://github.com/hkgodhani/ESP32.git
cd ESP32/sha256-research

# Install dependencies
pip install matplotlib numpy  # optional, for visualizations

# Run SHA-256 self-tests
python tools/sha256_trace.py

# Generate Nonce Influence Matrix
python analysis/message_schedule/nonce_influence.py --output-dir output

# Trace compression influence
python analysis/message_schedule/nonce_influence.py --compress --output-dir output

# Compute operation dependency
python analysis/compute_dependency.py --json --output-dir output

# Verify precomputation boundary
python experiments/RQ-004/precompute_boundary.py --test-nonces 100

# Expected output:
#   NIST: ALL PASS
#   Double SHA: ALL PASS
#   81/128 invariant schedule words (63.3%)
#   Full avalanche by Round 6
#   541/1024 invariant compression ops (52.8%)
#   Precomputation: 100/100 nonces verified
#   Net savings: -201 ops (NEGATIVE)
```
