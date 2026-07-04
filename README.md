# ESP32-Miner + SHA-256 Research Platform

## Overview

Two projects in one repository:

### `esp32-miner/` — Production Bitcoin Miner (v1.0)

Dual-core ESP32-D0WD-V3 Bitcoin miner using hardware SHA-256 accelerator.

| Feature | Status |
|---------|--------|
| HW SHA per core | ~138 kH/s |
| SW SHA per core | ~138 kH/s |
| Combined | ~276 kH/s |
| Framework | ESP-IDF 6.0.1 |

**Key capabilities**: Midstate precomputation, baked SHA, cycle-accurate profiler (1:1024 sampling), early termination.

### `sha256-research/` — SHA-256 Research Platform (v1.0.0)

Experimental analysis of how information propagates through SHA-256 under Bitcoin nonce variation. Four research questions completed in a coherent sequence; see [SYNTHESIS.md](sha256-research/SYNTHESIS.md) for the full report.

**Research Phase 1 — Complete.** The precomputation boundary for Bitcoin block headers under nonce-only variation is now evidence-bounded: no algorithm-level optimization beyond the standard midstate yields a net reduction in total computation.

| RQ | Question | Status |
|----|----------|--------|
| 001 | Which schedule words change? | Complete — 64% invariant |
| 002 | How does compression propagate? | Complete — full avalanche by R6 |
| 003 | Which operations are identical? | Complete — 52.8% invariant (29 novel ops beyond midstate) |
| 004 | What is the precomputation boundary? | Complete — negative (-201 ops net loss) |

## Repository Structure

```
├── esp32-miner/          # Production Miner v1 (frozen)
│   ├── src/              # Source code
│   ├── ARCHITECTURE.md   # System design
│   ├── PERFORMANCE.md    # Hashrate benchmarks
│   ├── PROFILER.md       # Profiler methodology
│   ├── VALIDATION.md     # NIST + Bitcoin test vectors
│   ├── ASSUMPTIONS.md    # Documented assumptions
│   ├── NEGATIVE_RESULTS.md  # Dead ends disproven
│   └── ROADMAP.md        # Project roadmap
├── sha256-research/      # Research Platform (v1.0.0)
│   ├── SYNTHESIS.md      # Full report (entry point)
│   ├── reproducibility.md # Step-by-step reproduction
│   ├── LIMITATIONS.md    # Scope boundaries
│   ├── CITATION.cff      # Citation metadata
│   ├── CHANGELOG.md      # Research changelog
│   ├── datasets/         # Archived CSVs with provenance
│   ├── tools/            # SHA-256 trace tools
│   ├── correctness/      # NIST + Bitcoin test vectors
│   ├── analysis/         # Message schedule & dependency analysis
│   └── experiments/      # Research questions (RQ-001 through RQ-004)
└── README.md             # This file
```

## Quick Start (Miner)

```bash
cd esp32-miner
# Build with PlatformIO
pio run -e esp32dev
# Upload
pio run -e esp32dev --target upload --upload-port COM7
```

## Research

```bash
cd sha256-research
# Run SHA-256 self-tests
python tools/sha256_trace.py
# Generate Nonce Influence Matrix (RQ-001)
python analysis/message_schedule/nonce_influence.py --output-dir output
# Trace compression influence (RQ-002)
python analysis/message_schedule/nonce_influence.py --compress --output-dir output
# Compute operation dependency (RQ-003)
python analysis/compute_dependency.py
# Verify precomputation boundary (RQ-004)
python experiments/RQ-004/precompute_boundary.py --test-nonces 100
```

See [reproducibility.md](sha256-research/reproducibility.md) for detailed instructions and expected outputs.

## License

MIT — see [LICENSE](sha256-research/LICENSE).
