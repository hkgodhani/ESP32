# RQ-003: Which operations are mathematically identical across all nonce values?

## Metadata

- **ID**: RQ-003
- **Status**: Complete
- **Hypothesis**: Operations whose inputs are entirely invariant (both state variables and schedule words) will produce identical outputs regardless of nonce. These operations can be precomputed.
- **Tools**: `analysis/compute_dependency.py`
- **Output**: `analysis/compute_dependency.py --json --output-dir ./output`

---

## Method

For each of the 8 operations per round across 64 rounds × 2 blocks:

1. Determine whether each operation's **input** (state variables + schedule word) differs between nonce=0 and nonce=1.
2. If ALL inputs to an operation are invariant, the operation's output is classified as **INVARIANT** (I).
3. If ANY input is nonce-dependent, the output is classified as **NONCE-DEPENDENT** (D).
4. The 8 operations per round: S1, ch, temp1, S0, maj, temp2, e_new, a_new.

This is a **static dependency analysis** — it traces influence mathematically, not by running all 2^32 nonces.

---

## Results

### Overall

| Category | Operations | % |
|----------|-----------|---|
| **Invariant operations** | **541/1024** | **52.8%** |
| Nonce-dependent operations | 483/1024 | 47.2% |

### By Block

| Block | Invariant | % |
|-------|-----------|---|
| Block 0 (all 64 rounds) | 512/512 | **100.0%** |
| Block 1 (64 rounds) | 29/512 | **5.7%** |

### By Round (Block 1)

| Round | W[t] Status | Invariant Ops | Detail |
|-------|-------------|---------------|--------|
| R0-R2 | W0-W2 input (invariant) | **8/8** | All operations: no nonce influence yet |
| R3 | W3 = **nonce** (influenced) | **5/8** | S1, ch, S0, maj, temp2 invariant. temp1/e_new/a_new influenced |
| R4-R63 | W4-W63 (various) | **0/8** | State fully nonce-influenced; all ops produce nonce-dependent output |

### The Invariant Operations in Block 1 (29 total)

**Rounds 0-2** (24 operations, all 8 types):

| Op | Inputs | Why Invariant |
|----|--------|---------------|
| S1 | rr(e,6) ^ rr(e,11) ^ rr(e,25) | e is from invariant Block 0 output |
| ch | (e & f) ^ ((~e) & g) | e, f, g are from invariant Block 0 output |
| temp1 | h + S1 + ch + K + W[t] | h, S1, ch are invariant; W0-W2 are merkle tail/timestamp/nbits |
| S0 | rr(a,2) ^ rr(a,13) ^ rr(a,22) | a is from invariant Block 0 output |
| maj | (a & b) ^ (a & c) ^ (b & c) | a, b, c are from invariant Block 0 output |
| temp2 | S0 + maj | Both are invariant |
| e_new | d + temp1 | Both are invariant |
| a_new | temp1 + temp2 | Both are invariant |

**Round 3** (5 operations):

| Op | Inputs | Why Invariant |
|----|--------|---------------|
| S1 | rr(e,6) ^ rr(e,11) ^ rr(e,25) | e is still from invariant Round 2 state |
| ch | (e & f) ^ ((~e) & g) | e, f, g are still invariant |
| S0 | rr(a,2) ^ rr(a,13) ^ rr(a,22) | a is still invariant (a updated last round was from Round 0's e_new, which was invariant) |
| maj | (a & b) ^ (a & c) ^ (b & c) | a, b, c are still invariant |
| temp2 | S0 + maj | Both are invariant |

**Round 3** (3 influenced operations):

| Op | Inputs | Why Influenced |
|----|--------|----------------|
| temp1 | h + S1 + ch + K + W[3] | **W[3] is the nonce** — the only nonce-dependent input at this round |
| e_new | d + temp1 | temp1 is influenced by nonce |
| a_new | temp1 + temp2 | temp1 is influenced by nonce |

---

## Discussion

### Key Finding 1: 52.8% of all SHA-256 operations are invariant

Block 0 contains 100% of the operations for the first SHA-256 block (512 ops), and a further 29 ops in Block 1. This means more than half of the computation produces an identical result for every nonce.

### Key Finding 2: Only 1 word (W3 in Round 3 of Block 1) directly introduces nonce influence

At Round 3 of Block 1, the only nonce-dependent input is schedule word W[3]. All state variables (a-h) are still from the invariant Block 0 output. This means:

```
temp1 = h + S1(e) + ch(e,f,g) + K[3] + W[3]
       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^   ^^^^
       invariant inputs                  NONCE
```

The nonce enters ONLY through W[3]. Everything else at this stage is invariant.

### Key Finding 3: After R3, state is forever influenced

Once temp1 and a/e are updated with nonce-dependent values at R3, all subsequent rounds (R4-R63) have fully nonce-influenced state. The compaction shift (h=g, g=f, f=e, ..., a=temp1+temp2) propagates the nonce influence through all 8 variables within 3 rounds, as confirmed by RQ-002.

### Key Finding 4: 5/8 operations at R3 are still invariant

Even though the nonce enters at R3, S1, ch, S0, maj, and temp2 are still invariant. This is because:
- S1 depends only on `e`, which hasn't been updated yet (it's still from Round 2)
- ch depends on `e, f, g`, which are all still invariant
- S0 depends only on `a`, which is still invariant
- maj depends on `a, b, c`, which are all still invariant
- temp2 = S0 + maj, both invariant

This means **S1, ch, S0, maj, and temp2 at Round 3** produce identical outputs for all nonces, even though temp1 (which uses W[3]) produces a different output.

---

## Implications for Optimization

### What can be precomputed

1. **Block 0 entirely**: All 64 rounds × 8 operations = 512 operations (50% of total). This is what midstate computation does.

2. **Block 1 Rounds 0-2**: All 24 operations (2.3% of total). The first 3 rounds of Block 1's compression produce identical results regardless of nonce.

3. **Block 1 Round 3, 5 operations**: S1, ch, S0, maj, temp2 (0.5% of total). These depend only on invariant state.

**Total precomputable operations**: 541/1024 = 52.8%

### What CANNOT be precomputed

- Block 1 Rounds 4-63: 480 operations (46.9%). Once the nonce enters through temp1 at R3, the state is nonce-dependent forever.
- Block 1 Round 3, 3 operations: temp1, e_new, a_new (0.3%). These directly use W[3] (the nonce).

### Practical Savings

In terms of SHA-256 hardware/computation:
- **Block 0**: Already fully cached via midstate (standard optimization)
- **Block 1 R0-R2**: 3/64 = 4.7% of Block 1 compression saved
- **Block 1 R3, S1/ch/S0/maj/temp2**: 5 ops out of 512 = 1% of Block 1 - negligible

**Net new savings beyond midstate**: ~4.7% of Block 1 compression, or roughly 2.3% of total SHA-256 computation.

---

## Limitations

1. **Static analysis only**: This traces influence deterministically by comparing nonce=0 vs nonce=1. A single bit flip captures whether an output can change, but doesn't measure how much it changes.
2. **No double-SHA analysis**: The second SHA-256 (hash of the 32-byte result) is not analyzed. Its input is fully nonce-dependent, so 100% of its operations are likely nonce-dependent.
3. **Assumes Block 0 is invariant**: This is true for a fixed job where only the nonce varies. If extranonce2 or timestamp changes, Block 0 becomes nonce-dependent.

---

## Future Work

1. **RQ-004**: "Which invariant operations can be safely precomputed and reused without changing the final SHA-256 output?" — This would implement a prototype SHA-256 that caches the invariant operations and measures actual cycle savings.
2. **Quantify bit-level influence**: Instead of binary invariant/dependent, measure what percentage of bits change in each operation's output.
3. **Double-SHA analysis**: Extend the dependency analysis to the second SHA-256.

---

## Reproducibility

```bash
python analysis/compute_dependency.py

Expected:
  Block 0: 512/512 invariant (100.0%)
  Block 1: 29/512 invariant (5.7%)
  Overall: 541/1024 invariant (52.8%)
```
