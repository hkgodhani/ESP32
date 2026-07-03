# SHA-256 Research Platform

Experimental analysis of how information propagates through SHA-256 under Bitcoin mining conditions.

## Long-term Objective

Produce the most complete experimental map of how information propagates through SHA-256 under Bitcoin nonce variation.

## Guiding Principles

1. **Correctness first** — Every claim verified against NIST and Bitcoin test vectors.
2. **Measurement first** — Every performance claim backed by benchmark data.
3. **Reproducibility first** — Another person can rerun every experiment.
4. **Optimization follows understanding** — Never optimize something you haven't first characterized.

## Repository Structure

```
sha256-research/
├── README.md
├── correctness/          # Test vectors and verification tools
│   ├── nist/             # NIST FIPS 180-4 test vectors
│   └── bitcoin/          # Bitcoin block test vectors
├── benchmark/            # Cycle-accurate measurement tools
├── analysis/             # SHA-256 structure analysis
│   └── message_schedule/ # Message schedule dependency analysis
├── experiments/          # Research questions
│   └── RQ-001/           # First research question
└── tools/                # Shared utilities
```

## Current Status

| Stage | Status |
|-------|--------|
| Research Platform v1 | In progress |
| RQ-001 | Not started |
| RQ-002 | Not started |

## Research Questions

| ID | Title | Status |
|----|-------|--------|
| RQ-001 | What information changes when only the Bitcoin nonce changes? | Not started |
| RQ-002 | TBD after RQ-001 | Not started |
