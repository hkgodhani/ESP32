# Reproducibility — Research Phase 1 (v1.0.0)

## Environment

- **Operating system**: Windows 10/11
- **Python implementation**: CPython 3.10+
- **CPU architecture**: x86-64
- **Python dependencies**: none beyond standard library
  - `matplotlib` and `numpy` are optional (used only by `visualize_matrix.py`)
- **Random seed**: No randomness — all experiments are deterministic (SHA-256 is a pure function)

## Expected Runtime

| Experiment | Runtime (approx.) |
|------------|-------------------|
| `tools/sha256_trace.py` self-test | <1 second |
| `nonce_influence.py` (schedule only) | 2-5 seconds |
| `nonce_influence.py --compress` | 5-15 seconds |
| `compute_dependency.py` | <1 second |
| `precompute_boundary.py --test-nonces 100` | 0.5-2 seconds |

## Step-by-Step Reproduction

### 0. Clone and set up

```bash
git clone https://github.com/hkgodhani/ESP32.git
cd ESP32/sha256-research
```

### 1. Verify SHA-256 implementation

```bash
python tools/sha256_trace.py
```

**Expected output:**
```
=== NIST Test Vectors ===
  PASS: sha256(b'') = e3b0c442...
  PASS: sha256(b'abc') = ba7816bf...
  PASS: sha256(b'abcdbcdec...') = 248d6a61...
=== Double SHA-256 (hashlib reference) ===
  Double SHA-256: ALL PASS (match hashlib)

NIST: ALL PASS
Double SHA: ALL PASS
```

### 2. Generate Nonce Influence Matrix (RQ-001)

```bash
python analysis/message_schedule/nonce_influence.py --output-dir output
```

**Expected output:**
```
Words influenced by at least 1 nonce bit: 47/128
Words influenced by all 32 nonce bits:   47/128
Completely invariant words:              81/128
```
Note: 81 invariant words with this specific header. The mathematical dependency structure is identical for all Bitcoin block headers.

### 3. Trace compression influence (RQ-002)

```bash
python analysis/message_schedule/nonce_influence.py --compress --output-dir output
```

**Expected output:**
```
First non-zero influence round: 67
First round where ALL 8 vars influenced: ~70
```

Round 67 = Round 3 of Block 1 (absolute indexing). Round 70 = Round 6 of Block 1.

### 4. Compute operation dependency (RQ-003)

```bash
python analysis/compute_dependency.py
```

**Expected lines:**
```
Block 0: 512/512 invariant (100.0%)
...
Invariant operations: 541/1024 (52.8%)
```

### 5. Verify precomputation boundary (RQ-004)

```bash
python experiments/RQ-004/precompute_boundary.py --test-nonces 100
```

**Expected output:**
```
Passed: 100/100
Failed: 0/100
CONFIRMED: 100/100 test nonces match reference SHA-256.
Net new compression savings beyond midstate: 29 ops (2.83%)
True savings: compression(29) - schedule(230) = -201 ops (NET LOSS)
```

### 6. (Optional) Visualize influence matrix

```bash
# Requires matplotlib + numpy
pip install matplotlib numpy
python analysis/message_schedule/visualize_matrix.py --input output/nonce_influence.csv
```

## Dataset Verification

After generating datasets, verify checksums:

```powershell
# PowerShell
Get-FileHash datasets/RQ001_nonce_influence.csv -Algorithm SHA256
Get-FileHash datasets/RQ002_compression_influence.csv -Algorithm SHA256
Get-FileHash datasets/RQ003_operation_invariance.csv -Algorithm SHA256
Get-FileHash datasets/RQ004_precompute_verification.csv -Algorithm SHA256
```

```bash
# Linux/macOS
sha256sum datasets/RQ001_nonce_influence.csv
sha256sum datasets/RQ002_compression_influence.csv
sha256sum datasets/RQ003_operation_invariance.csv
sha256sum datasets/RQ004_precompute_verification.csv
```

Expected checksums are listed in `datasets/README.md`.

## Test Vectors

All SHA-256 test vectors are defined in `tools/sha256_trace.py`:

```python
NIST_VECTORS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
]
```

Double SHA-256 is verified against `hashlib.sha256(hashlib.sha256(data).digest()).digest()`.

## Block Header Model

The synthetic block header used in all experiments:

```python
def build_header(nonce: int) -> bytes:
    return (struct.pack('<I', 1)                # version = 1
            + b'\x00' * 32                      # prev_block = zeros
            + b'\x00' * 32                      # merkle_root = zeros
            + struct.pack('<I', 0x4DAB5D0A)     # time = 0x4DAB5D0A
            + struct.pack('<I', 0x1D00FFFF)     # bits = 0x1D00FFFF
            + struct.pack('<I', nonce))         # nonce = varying
```
