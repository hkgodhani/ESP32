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

### `sha256-research/` — SHA-256 Research Platform

Experimental analysis of how information propagates through SHA-256 under Bitcoin nonce variation.

**RQ-001** (Complete): Found that 82/128 (64%) of SHA-256 message schedule words are invariant when only the nonce changes. Nonce influence first appears at W18 of Block 1.

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
├── sha256-research/      # Research Platform
│   ├── tools/            # SHA-256 trace tools
│   ├── correctness/      # NIST + Bitcoin test vectors
│   ├── analysis/         # Message schedule analysis
│   └── experiments/      # Research questions
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
# Run Nonce Influence Matrix analysis
python analysis/message_schedule/nonce_influence.py --output-dir analysis/message_schedule/output
```

## License

GPL v3
