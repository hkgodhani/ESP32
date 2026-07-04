# Changelog

All notable changes to the sha256-research project are documented here.

## [v1.0.0] — 2026-07-04

### Research Phase 1 — Complete

First formal release of the SHA-256 research platform. Four research questions completed, reproducibility artifacts archived.

### Added

- RQ-001: Nonce Influence Matrix — 32×128 word-level influence analysis
- RQ-002: Compression Influence — round-by-round state variable tracing
- RQ-003: Operation Dependency — 541/1024 compression operations classified as invariant
- RQ-004: Formal Precomputation Boundary — prototype proving negative net savings (-201 ops)
- SYNTHESIS.md — coherent narrative tying all four RQs together
- datasets/ — archived CSVs with provenance headers and SHA-256 checksums
- reproducibility.md — step-by-step reproduction instructions
- CITATION.cff — citation metadata
- CHANGELOG.md — this file
- LIMITATIONS.md — explicit scope boundaries
- LICENSE — MIT

### Tools

- `tools/sha256_trace.py` — Pure Python SHA-256 with schedule and compression tracing; verified against NIST and hashlib
- `analysis/message_schedule/nonce_influence.py` — Nonce Influence Matrix (word-level and compression-level)
- `analysis/compute_dependency.py` — Operation-level dependency classification
- `analysis/message_schedule/visualize_matrix.py` — Influence matrix visualization
- `experiments/RQ-004/precompute_boundary.py` — Precomputation boundary prototype with verification harness

### Key Results

- 81/128 (63.3%) message schedule words invariant under nonce variation
- Full avalanche by Round 6 of compression
- 541/1024 (52.8%) compression operations invariant, but 512 are standard midstate
- Precomputation boundary: negative (-201 ops net loss)
- Conclusion: Within the classes of optimizations studied, no algorithm-level precomputation beyond midstate yields a net benefit
