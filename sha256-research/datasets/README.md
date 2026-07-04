# Datasets — Research Phase 1 (v1.0.0)

Archived raw data for all four research questions. Each CSV includes provenance metadata in comment headers (generator script, git commit, SHA-256 checksum, generation date).

## Files

| File | RQ | Format | Rows | Columns |
|------|----|--------|------|---------|
| `RQ001_nonce_influence.csv` | RQ-001 | CSV (with `#` comment header) | 32 header rows + data | 129: nonce_bit, W0..W127 |
| `RQ002_compression_influence.csv` | RQ-002 | CSV (with `#` comment header) | 32 header rows + data | 1025: nonce_bit, R0_a..R127_h |
| `RQ003_operation_invariance.csv` | RQ-003 | CSV (with `#` comment header) | 1024 | 4: block, round, op_type, is_invariant |
| `RQ004_precompute_verification.csv` | RQ-004 | CSV (with `#` comment header) | 100 | 5: nonce, digest_match, schedule_ops_recomputed, compression_ops_saved, net_ops |

## Column Definitions

### RQ001 — Nonce Influence Matrix
- **nonce_bit** (0-31): Index of the nonce bit being flipped
- **W0..W127** (0 or 1): 1 if flipping this nonce bit changes the value of that schedule word

### RQ002 — Compression Influence Matrix
- **nonce_bit** (0-31): Index of the nonce bit being flipped
- **R0_a..R127_h** (0 or 1): 1 if flipping this nonce bit changes the value of that state variable at that round

### RQ003 — Operation Invariance
- **block** (0-1): SHA-256 block index
- **round** (0-63): Compression round within block
- **op_type**: One of `S1`, `ch`, `temp1`, `S0`, `maj`, `temp2`, `e_new`, `a_new`
- **is_invariant** (0 or 1): 1 = operation output is identical for all nonces

### RQ004 — Precomputation Verification
- **nonce** (0-99): Tested nonce value
- **digest_match** (0 or 1): 1 = precomputed digest matches reference SHA-256
- **schedule_ops_recomputed**: 230 (46 words × ~5 ops)
- **compression_ops_saved**: 29 (beyond standard midstate)
- **net_ops**: -201 (negative = precomputation is a net loss)

## Generation Commands

```bash
# RQ001
python analysis/message_schedule/nonce_influence.py --output-dir analysis/message_schedule/output

# RQ002
python analysis/message_schedule/nonce_influence.py --compress --output-dir analysis/message_schedule/output

# RQ003
python analysis/compute_dependency.py --json --output-dir analysis/message_schedule/output

# RQ004
python experiments/RQ-004/precompute_boundary.py --test-nonces 100
```

## Checksums

```
RQ001_nonce_influence.csv:            c7ce29a270ae86b44062771099c997c712c6678c5e8b4440dddd7ab393366971
RQ002_compression_influence.csv:      4ac544e3f26e0a3f7238ecadf78f51e6c7a4d128fc9bfb961a21120eba3389b1
RQ003_operation_invariance.csv:       e73025994bab6b5b59fe84235fba2bd23f40e6a4dfc562f8d6c19ddaaa88a86a
RQ004_precompute_verification.csv:    5bf7d744dd1b1e8138ae319ca35eabb9670e1e0b99fc7b4bcbbf50ed83e55790
```
