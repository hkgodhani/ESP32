# ESP32 FB Miner — Validation

## NIST Test Vectors

All SHA-256 implementations (software nerdSHA256plus and hardware SHA accelerator) validated against NIST FIPS 180-4 test vectors.

### Test Cases

| Input | Expected Hash | Status |
|-------|--------------|--------|
| Empty string (0 bytes) | `e3b0c44298fc1c14...` | ✓ Verified |
| "abc" (3 bytes) | `ba7816bf8f01cfea...` | ✓ Verified |
| "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (448 bits) | `248d6a61d20638b8...` | ✓ Verified |

## Bitcoin Test Vectors

### Block 100000

| Field | Value |
|-------|-------|
| Hash | `000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506` |
| Nonce | `0x1db83e34` |
| Status | ✓ Verified (both SW and HW implementations) |

### Block 700000

| Field | Value |
|-------|-------|
| Hash | `00000000000000000076c284bf9310a6bb05ee6b5a15b3f151a8b1e91de4e7aa` |
| Nonce | `0x3201f3c4` |
| Status | ✓ Verified (both SW and HW implementations) |

## Midstate Verification

The `nerd_mids()` function (midstate computation) verified by:
1. Computing SHA-256 of first 64 bytes of block header
2. Computing full SHA-256 of 80-byte block header via standard library
3. Comparing intermediate state after first block

## Early Reject Verification

The 16-bit early reject (`(fin & 0xFFFF) != 0`) verified against known block hashes:
- Valid blocks: H0 top 16 bits = 0 (passes reject, goes to full target check)
- Invalid hashes: H0 top 16 bits ≠ 0 (correctly rejected)

## Hardware SHA Register Test

The SHA_TEXT_BASE retention test verified:
1. Engine does NOT modify TEXT_BASE during processing
2. LOAD overwrites TEXT_BASE[0:7] with hash result
3. TEXT_BASE[8:15] persists across LOAD
4. Writing to TEXT_BASE while engine is busy is safe (but causes DPORT contention)
