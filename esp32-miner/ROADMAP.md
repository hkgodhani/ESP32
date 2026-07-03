# ESP32 FB Miner — Roadmap

## Stage 1: Production Miner v1

| Criterion | Status |
|-----------|--------|
| Correctness verified (NIST + Bitcoin test vectors) | ✓ Complete |
| Profiler verified | ✓ Complete |
| SparkMiner comparison complete | ✓ Complete |
| Performance report | ✓ Complete |
| Architecture document | ✓ Complete |
| Assumptions documented | ✓ Complete |
| Negative results documented | ✓ Complete |
| Repository tagged v1.0 | ⬜ Todo |

**Exit criterion**: All items complete, repository tagged, no further optimization work unless >5% improvement demonstrated.

---

## Stage 2: Research Platform v1

| Criterion | Status |
|-----------|--------|
| Correctness harness (NIST + Bitcoin) | ⬜ Todo |
| Benchmark harness (cycle-accurate) | ⬜ Todo |
| Nonce Influence Matrix tool | ⬜ Todo |

**Exit criterion**: All three tools working and producing reproducible output.

---

## Stage 3: RQ-001

| Criterion | Status |
|-----------|--------|
| Stage A: W0-W15 input analysis | ⬜ Todo |
| Stage B: W16-W63 dependency table | ⬜ Todo |
| Stage C: Quantified influence matrix | ⬜ Todo |
| Report (Hypothesis, Method, Results, Discussion, Limitations, Future) | ⬜ Todo |
| Reproducible dataset (CSV/JSON) | ⬜ Todo |

**Exit criterion**: Dependency dataset, report, and reproducible code published.

---

## Stage 4: RQ-002+

| Criterion | Status |
|-----------|--------|
| RQ-002 defined | ⬜ Todo |
| RQ-002 completed or retired with documented negative result | ⬜ Todo |

**Exit criterion**: Completed or retired with documented negative result.

---

## Guiding Principles

1. **Correctness first** — Every claim must be verified against NIST and Bitcoin test vectors.
2. **Measurement first** — Every performance claim must be backed by benchmark data.
3. **Reproducibility first** — Another person should be able to rerun every experiment.
4. **Optimization follows understanding** — Never optimize something you haven't first characterized.

If an experiment doesn't satisfy all four, it's incomplete.
