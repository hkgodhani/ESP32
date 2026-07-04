# RQ-002: How does nonce influence propagate through the 64 compression rounds?

## Metadata

- **ID**: RQ-002
- **Status**: Complete
- **Hypothesis**: Nonce influence enters the compression state at round 3 of Block 1 (when W3 is first used), and spreads to all 8 state variables within a few rounds due to the avalanche effect
- **Tools**: `tools/sha256_trace.py` (`sha256_compress_trace`), `analysis/message_schedule/nonce_influence.py` (`--compress`)
- **Datasets**: `analysis/message_schedule/output/compression_influence.csv`, `analysis/message_schedule/output/compression_influence.json`

---

## Method

1. Build on RQ-001's message schedule analysis by extending the Nonce Influence Matrix tool.
2. For each nonce bit flip, compute the full SHA-256 compression function using `sha256_compress_trace()`, which records the 8 state variables (a,b,c,d,e,f,g,h) after each of the 64 rounds.
3. Compare the state at each round against the base nonce (0x00000000).
4. Track how many state variables differ at each round.
5. The output is a round-by-round influence matrix showing the spread of nonce influence.

---

## Results

### Propagation Timeline

| Round (Block 1) | Absolute | Vars Influenced | W[t] Used | Event |
|-----------------|----------|-----------------|-----------|-------|
| 0-2 | 64-66 | 0 | W0-W2 (invariant) | State unchanged from Block 0 |
| **3** | **67** | **2 (a, e)** | **W3 (nonce)** | **Nonce enters state** |
| 4 | 68 | 4 | W4 (padding) | Influence spreads via S0/S1/MAJ/CH |
| 5 | 69 | 6 | W5 (zero) | Further spread |
| **6** | **70** | **8** | **W6 (zero)** | **Full avalanche achieved** |
| 7-63 | 71-127 | 8 | W7-W63 | All subsequent rounds fully influenced |

### Key Finding 1: Nonce enters at R3

The nonce word W3 is first used in the compression function at round 3 of Block 1. At this point:
- `temp1 = h + S1(e) + ch(e,f,g) + K[3] + W[3]`
- The nonce difference in W[3] propagates into `a` (via `temp1 + temp2`) and `e` (via `d + temp1`)
- Variables `b, c, d, f, g, h` are simply shifted (b=a_prev, c=b_prev, etc.) and remain unchanged from the base nonce

**Result**: Exactly 2 of 8 state variables differ at R3.

### Key Finding 2: Full avalanche by R6

Within just 3 rounds (R4, R5, R6), the nonce influence spreads to all 8 state variables:

- **R4**: The influenced `a` and `e` from R3 now participate in S0/maj (affecting temp2) and S1/ch (affecting temp1). This spreads influence to 4 variables.
- **R5**: Continued spread through the non-linear functions reaches 6 variables.
- **R6**: All 8 variables are fully nonce-dependent.

### Key Finding 3: 90.6% of compression is fully influenced

For the remaining 58 rounds (R7-R63), all 8 state variables are nonce-dependent. This means:

```
Rounds with non-zero influence: 61/64 (95.3%)
Rounds with full influence:     58/64 (90.6%)
Rounds with zero influence:     3/64  (4.7%)
```

---

## Discussion

### Implication: Rounds 0-2 are invariant

Rounds 0-2 of Block 1 use W0, W1, W2 which are all invariant (they contain the merkle tail, timestamp, and nbits). These 3 rounds of compression produce identical results regardless of nonce.

**However**, the initial state for Block 1's compression is the final state from Block 0, which IS nonce-dependent in practice (because Block 0's initial state includes the merkle root, which depends on the coinbase which changes with extranonce2).

**For a fixed job** (where only the nonce varies), Block 0 is indeed invariant, so rounds 0-2 of Block 1 are also invariant.

### Implication: No useful precomputation beyond midstate

Since nonce influence spreads to all 8 variables by R6, and the nonce enters at R3, only 3 rounds (R0-R2) of Block 1's compression are invariant. This is only 3/64 = 4.7% of the compression function.

Combined with RQ-001's finding that 63.3% of message schedule words are invariant, the total invariant computation in a Bitcoin block header SHA-256 is:

```
Block 0: 100% of schedule + 100% of compression = fully invariant (midstate)
Block 1: 0% of schedule (fully dependent after W18) + 4.7% of compression (R0-R2)
Total: ~63% of schedule + ~52% of compression = ~58% total invariant
```

### Comparison: Message Schedule vs Compression Influence

| Stage | Invariant | Nonce-dependent |
|-------|-----------|-----------------|
| Block 0 schedule | 64/64 (100%) | 0/64 (0%) |
| Block 0 compression | 64/64 (100%) | 0/64 (0%) |
| Block 1 schedule | 18/64 (28%) | 46/64 (72%) |
| Block 1 compression | 3/64 (4.7%) | 61/64 (95.3%) |

---

## Limitations

1. **Analysis limited to first SHA**: The double-SHA (second hash of the 32-byte result) is not analyzed. The second hash's input is the first hash's output, which is fully nonce-dependent. This is a separate research question.
2. **Synthetic block header**: Uses dummy values for prev_block and merkle_root. Real Bitcoin headers have the same mathematical structure but different bit patterns.
3. **No double-SHA tracing**: The second hash's internal schedule/compression propagation is not analyzed here.

---

## Future Work

1. **RQ-003**: "Which compression rounds can be skipped or cached without affecting correctness?" — Given that R0-R2 are invariant, can we start compression at R3?
2. **Double-SHA analysis**: Trace nonce influence through the second SHA-256 (hash of 32-byte result).
3. **Precomputation experiment**: Implement a SHA-256 that caches the invariant rounds (0-2) and only computes rounds 3-63, measuring actual cycle savings.

---

## Reproducibility

```bash
# Run compression influence tracing
python analysis/message_schedule/nonce_influence.py --compress --output-dir output

# Expected:
#   First non-zero influence round: 67 (R3 of Block 1)
#   First round where ALL 8 vars influenced: 70 (R6 of Block 1)
#   Rounds with full influence: 58/64
```
