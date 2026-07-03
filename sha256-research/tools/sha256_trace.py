#!/usr/bin/env python3
"""
Pure Python SHA-256 implementation with message schedule tracing.

Provides:
- Full SHA-256 computation
- Message schedule (W[0..63]) export for analysis
- Round-by-round state tracing
- Correctness verification against known test vectors

Usage:
    python sha256_trace.py                          # Run self-test
    python sha256_trace.py --trace "abc"             # Show message schedule for input
"""

import struct
import sys

# SHA-256 round constants
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# Initial hash values
H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]


def rr(x, n):
    """Rotate right by n bits."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def sha256_pad(data: bytes) -> bytes:
    """Return SHA-256 padded data (multiple of 64 bytes)."""
    ml = len(data) * 8
    data += b'\x80'
    while (len(data) % 64) != 56:
        data += b'\x00'
    data += struct.pack('>Q', ml)
    return data


def sha256_schedule(block: bytes) -> list:
    """Compute message schedule W[0..63] from a 64-byte block.
    
    Returns list of 64 uint32 values.
    """
    assert len(block) == 64
    W = list(struct.unpack('>16I', block))  # W[0..15]

    for t in range(16, 64):
        s0 = rr(W[t - 15], 7) ^ rr(W[t - 15], 18) ^ (W[t - 15] >> 3)
        s1 = rr(W[t - 2], 17) ^ rr(W[t - 2], 19) ^ (W[t - 2] >> 10)
        W.append((W[t - 16] + s0 + W[t - 7] + s1) & 0xFFFFFFFF)

    return W


def sha256_compress(W: list, state: list = None) -> list:
    """Perform SHA-256 compression on message schedule.
    
    Args:
        W: Message schedule (64 uint32 values)
        state: Initial state (8 uint32), or None for IV
    
    Returns:
        Final state (8 uint32)
    """
    assert len(W) == 64

    if state is None:
        state = list(H0)
    a, b, c, d, e, f, g, h = state

    for t in range(64):
        S1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)
        ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g)
        temp1 = (h + S1 + ch + K[t] + W[t]) & 0xFFFFFFFF
        S0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xFFFFFFFF

        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF

    return [(state[i] + v) & 0xFFFFFFFF for i, v in enumerate([a, b, c, d, e, f, g, h])]


def sha256_full(data: bytes, trace: bool = False) -> bytes:
    """Compute full SHA-256 digest.
    
    Args:
        data: Input bytes
        trace: If True, print message schedule and state
    
    Returns:
        32-byte digest
    """
    padded = sha256_pad(data)
    state = list(H0)

    for offset in range(0, len(padded), 64):
        block = padded[offset:offset + 64]
        W = sha256_schedule(block)
        if trace:
            print(f"=== Block {offset // 64} ===")
            for t in range(64):
                print(f"W[{t:2d}] = 0x{W[t]:08x}")
        state = sha256_compress(W, state)
        if trace:
            print(f"State: {[hex(s) for s in state]}")

    return struct.pack('>8I', *state)


def sha256_double(data: bytes) -> bytes:
    """Compute double SHA-256: SHA256(SHA256(data))."""
    first = sha256_full(data)
    return sha256_full(first)


# ---- Test vectors ----

NIST_VECTORS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
]


def test_nist():
    """Run NIST test vectors."""
    print("=== NIST Test Vectors ===")
    all_pass = True
    for data, expected in NIST_VECTORS:
        result = sha256_full(data)
        hex_result = result.hex()
        status = "PASS" if hex_result == expected else "FAIL"
        if status == "FAIL":
            all_pass = False
        print(f"  {status}: sha256({data[:20]!r}...) = {hex_result[:32]}...")
    return all_pass


def test_double_sha256():
    """Verify double SHA-256 against hashlib reference."""
    import hashlib
    print("=== Double SHA-256 (hashlib reference) ===")
    test_inputs = [
        b"hello",
        b"abc",
        bytes(range(80)),  # 80-byte block header pattern
    ]
    all_pass = True
    for data in test_inputs:
        result = sha256_double(data)
        expected = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        status = "PASS" if result == expected else "FAIL"
        if status == "FAIL":
            all_pass = False
            print(f"  {status}: double_sha256({data[:20]!r}) = {result.hex()} != {expected.hex()}")
    if all_pass:
        print(f"  Double SHA-256: ALL PASS (match hashlib)")
    return all_pass


def trace_block_header(header_bytes: bytes):
    """Trace SHA-256 computation for an 80-byte block header."""
    padded = sha256_pad(header_bytes)

    print("=== Block 1 (first 64 bytes) ===")
    block1 = padded[0:64]
    W1 = sha256_schedule(block1)
    for t in range(64):
        if t < 16:
            print(f"W[{t:2d}] = 0x{W1[t]:08x}  (from message)")
        else:
            deps = f"W[{t-16}] W[{t-15}] W[{t-7}] W[{t-2}]"
            print(f"W[{t:2d}] = 0x{W1[t]:08x}  ({deps})")
    state1 = sha256_compress(W1)
    print(f"State after block 1: {[hex(s) for s in state1]}")
    print()

    print("=== Block 2 (remaining 16 bytes + padding) ===")
    block2 = padded[64:128]
    W2 = sha256_schedule(block2)
    for t in range(64):
        if t < 16:
            print(f"W[{t:2d}] = 0x{W2[t]:08x}  (from message)")
        else:
            deps = f"W[{t-16}] W[{t-15}] W[{t-7}] W[{t-2}]"
            print(f"W[{t:2d}] = 0x{W2[t]:08x}  ({deps})")

    print()
    print("=== Double SHA (second hash entirely depends on first 32-byte result) ===")
    first_hash = sha256_full(header_bytes)
    double_hash = sha256_full(first_hash)
    print(f"First SHA:  {first_hash.hex()}")
    print(f"Double SHA: {double_hash.hex()}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--trace":
        data = sys.argv[2].encode() if len(sys.argv) > 2 else b"abc"
        print(f"=== Tracing SHA-256 for input: {data!r} ===")
        result = sha256_full(data, trace=True)
        print(f"\nDigest: {result.hex()}")
    elif len(sys.argv) > 1 and sys.argv[1] == "--trace-block":
        # Example block header (80 bytes with nonce=0)
        example_header = bytes.fromhex(
            "01000000" + "00" * 32 + "00" * 32 + "00000000" "ffff001d" "00000000"
        )
        trace_block_header(example_header)
    else:
        # Run self-tests
        nist_ok = test_nist()
        dbl_ok = test_double_sha256()
        print(f"\nNIST: {'ALL PASS' if nist_ok else 'FAILURES'}")
        print(f"Double SHA: {'ALL PASS' if dbl_ok else 'FAILURES'}")
        sys.exit(0 if (nist_ok and dbl_ok) else 1)
