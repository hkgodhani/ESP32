# RQ-001: What information changes when only the Bitcoin nonce changes?

## Metadata

- **ID**: RQ-001
- **Status**: Complete
- **Hypothesis**: When only the nonce changes, only W3 of Block 1 (the nonce word) is directly affected; all other changes are caused by diffusion through the message schedule
- **Tools**: `tools/sha256_trace.py`, `analysis/message_schedule/nonce_influence.py`
- **Datasets**: `analysis/message_schedule/output/nonce_influence.csv`

---

## Method

1. Build a Bitcoin block header with all fields fixed except nonce.
2. For each of the 32 nonce bits (0-31), flip that bit and recompute the full SHA-256 message schedule (128 words: 2 blocks × 64 words).
3. Compare each flipped schedule against the base nonce (0x00000000).
4. If any word differs, mark it as "dependent" on that nonce bit.
5. The result is a 32×128 influence matrix.

---

## Results

### Stage A: Input Conditions (W0-W15)

**Block 0 (bytes 0-63 of header):** All 16 input words W0-W15 are completely invariant. The nonce is in bytes 76-79 of the header, which falls in Block 1.

**Block 1 (bytes 64-79 + padding of header):**
- W0-W2 (bytes 64-75): merkle tail, timestamp, nbits — invariant
- **W3 (bytes 76-79): the nonce — 100% influenced by all 32 nonce bits**
- W4-W15: SHA-256 padding (0x80000000, zeros, length=0x280) — invariant

### Stage B: Generated Schedule (W16-W63)

**Block 0:** All 48 generated words (W16-W63) are invariant. No nonce influence reaches them because all input words are invariant.

**Block 1:**
- W16: invariant (depends on W14, W9, W1, W0 — all invariant)
- W17: invariant (depends on W15, W10, W2, W1 — all invariant)
- **W18: first influenced word** (depends on W16, W11, **W3**, W2 — W3 carries nonce)
- W19-W63: 100% influenced by all 32 nonce bits (avalanche effect)

### Stage C: Quantified Influence

| Region | Words | Invariant | Nonce-dependent | % Invariant |
|--------|-------|-----------|-----------------|-------------|
| Block 0 (W0-W63) | 64 | 64 | 0 | 100% |
| Block 1 input (W0-W15) | 16 | 15 | 1 (W3) | 93.75% |
| Block 1 generated (W16-W63) | 48 | 2 (W16-W17) | 46 (W18-W63) | 4.17% |
| **Total** | **128** | **81** | **47** | **63.3%** |

---

## Discussion

### Key Finding 1: Block 0 is completely invariant

This confirms that the entire first 64-byte SHA-256 block is constant across nonce changes. This is expected — the nonce resides in bytes 76-79, which is in Block 1.

**Implication**: All 64 words of Block 0's message schedule can be precomputed once per job. This is what midstate computation does.

### Key Finding 2: Nonce influence first appears at W18

Nonce influence first appears at W18 of Block 1 via the `S0(W3)` term in the message schedule expansion. Once introduced, the avalanche effect spreads the influence to all subsequent words.

**Implication**: W16 and W17 can be precomputed (they depend only on invariant inputs). W18-W63 must be recomputed every nonce change. This is worth 2 saved schedule expansions per hash.

### Key Finding 3: 63.3% of schedule computation is invariant

81 out of 128 schedule words do not change when the nonce changes. This means:
- Block 0's entire schedule (64 words + 64 rounds of compression) is precomputable
- Block 1's W0-W2, W4-W17 (18 words) are precomputable
- Only Block 1's W3 + W18-W63 (47 words) depend on the nonce

**Implication**: The message schedule computation for a Bitcoin block header is 63.3% invariant under nonce variation. Any optimization that caches or skips invariant schedule computation could save ~63% of schedule expansion cycles.

---

## Limitations

1. **Synthetic block header**: This experiment used a minimal block header (dummy prev_block, merkle_root, time, nbits). Real Bitcoin block headers may have different bit patterns, but the mathematical dependencies are identical.
2. **Single SHA-256 only**: This analysis covers only the message schedule, not the compression function. Information propagation through the 64 compression rounds is a separate research question.
3. **Bit-level quantification**: The current tool measures word-level influence (does ANY bit change?). Bit-level quantification (what percentage of bits change?) would provide finer granularity.

---

## Future Work

1. **RQ-002**: "How many compression rounds are required before nonce influence affects every output bit uniformly?"
2. **Bit-level influence**: Extend the Nonce Influence Matrix to track individual bit changes, not just word-level.
3. **Compression analysis**: Trace how nonce influence propagates through the 64 compression rounds.
4. **Real block validation**: Run the analysis on real Bitcoin block headers to verify.
5. **Precomputation optimization**: Implement a SHA-256 that caches invariant schedule words and only recomputes nonce-dependent words.

---

## Reproducibility

```bash
# Generate the Nonce Influence Matrix
python analysis/message_schedule/nonce_influence.py --output-dir output

# Visualize
python analysis/message_schedule/visualize_matrix.py --input output/nonce_influence.csv

# Expected: 81/128 invariant words, 47/128 nonce-dependent words
```
