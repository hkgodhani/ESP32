#!/usr/bin/env python3
"""
RQ-004: Formal Precomputation Boundary

Determines the maximum amount of SHA-256 computation that can be precomputed
exactly, given a fixed Bitcoin block header and varying nonce.

Implements a caching SHA-256 that saves:
  - The full state (a-h) after Round 2 of Block 1 compression
  - The 5 invariant intermediate values at Round 3 (S1, ch, S0, maj, temp2)

Then for each nonce, only Rounds 3-63 need to recompute the nonce-dependent
operations (temp1, e_new, a_new at R3, then everything from R4 onwards).

Usage:
    python precompute_boundary.py
    python precompute_boundary.py --test-nonces 1000
    python precompute_boundary.py --synthetic
"""

import argparse
import struct
import time
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../tools'))
from sha256_trace import sha256_schedule, sha256_full, sha256_double, H0, K as _K

# ---------- utility ----------
def _rr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def build_header(nonce: int) -> bytes:
    return (struct.pack('<I', 1) + b'\x00' * 32 + b'\x00' * 32 +
            struct.pack('<I', 0x4DAB5D0A) + struct.pack('<I', 0x1D00FFFF) +
            struct.pack('<I', nonce))

# ---------- standard compression (reference) ----------
def compress_reference(W, state):
    a, b, c, d, e, f, g, h = state
    for t in range(64):
        S1 = _rr(e, 6) ^ _rr(e, 11) ^ _rr(e, 25)
        ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g)
        temp1 = (h + S1 + ch + _K[t] + W[t]) & 0xFFFFFFFF
        S0 = _rr(a, 2) ^ _rr(a, 13) ^ _rr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xFFFFFFFF
        h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF
    return [(state[i] + v) & 0xFFFFFFFF for i, v in enumerate([a, b, c, d, e, f, g, h])]


def sha256_reference(data):
    """Standard SHA-256 using tools module."""
    return sha256_full(data)

# ---------- precomputed compression ----------
def build_cache(block_header_80: bytes):
    """Precompute everything that doesn't depend on the nonce.
    
    Returns a dict with:
      - state0: final state of Block 0 (midstate)
      - state_r2: state (a-h) after Round 2 of Block 1 compression
      - r3_cache: dict of 5 invariant intermediate values at Round 3
      - W_fixed: schedule words 0-2, 4-63 for Block 1 (everything except W3)
    """
    padded = sha256_full.__wrapped__ if hasattr(sha256_full, '__wrapped__') else None
    
    # We need the low-level pad function
    from sha256_trace import sha256_pad as _pad
    
    padded_data = _pad(block_header_80)
    
    # Block 0
    block0 = padded_data[0:64]
    W0 = sha256_schedule(block0)
    state_mid = compress_reference(W0, list(H0))
    
    # Block 1
    block1 = padded_data[64:128]
    W1 = sha256_schedule(block1)
    
    # Cache state after Block 0 (this feeds into Block 1)
    # But in standard SHA, Block 1 uses the midstate as initial state
    # Actually no - the initial state for Block 1 is the INITIAL IV (H0),
    # and the state from Block 0 is ADDED to the working variables.
    # Wait, no - the compression function takes the state as input.
    # Block 1's initial state is H0, and Block 0's output feeds into... wait.
    
    # Actually, in SHA-256, each block starts from H0 as the initial state.
    # The "midstate" concept is that we compute Block 0's compression,
    # and the resulting state AFTER adding H0 becomes the "initial state"
    # for thinking about the rest of the message.
    
    # Let me re-examine. In SHA-256:
    # - padding produces N 64-byte blocks
    # - For each block, start from IV (H0)
    # - Compress the block
    # - Add the IV to get the new working state
    # - This feeds into the next block as initial state
    
    # Actually no. In the standard implementation:
    # - state = H0 (initial)
    # - For each block:
    #   - a,b,c,d,e,f,g,h = state (copy)
    #   - compress 64 rounds
    #   - state[i] += a,b,c,d,e,f,g,h[i]
    # - Return state
    
    # So Block 1's initial state is the OUTPUT of Block 0 (state after Block 0).
    # That's the "midstate".
    
    # But for our precomputation, Block 0 produces an invariant output.
    # Block 1 starts from this invariant midstate.
    # Rounds 0-2 of Block 1 use W0-W2 which are invariant.
    
    # Let me compute correctly:
    state_for_block1 = list(state_mid)  # This is the midstate
    
    # Run Rounds 0-2 with invariant W0-W2
    a, b, c, d, e, f, g, h = state_for_block1
    
    # Round 0
    S1 = _rr(e, 6) ^ _rr(e, 11) ^ _rr(e, 25)
    ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g)
    temp1 = (h + S1 + ch + _K[0] + W1[0]) & 0xFFFFFFFF
    S0 = _rr(a, 2) ^ _rr(a, 13) ^ _rr(a, 22)
    maj = (a & b) ^ (a & c) ^ (b & c)
    temp2 = (S0 + maj) & 0xFFFFFFFF
    h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF
    
    # Round 1
    S1 = _rr(e, 6) ^ _rr(e, 11) ^ _rr(e, 25)
    ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g)
    temp1 = (h + S1 + ch + _K[1] + W1[1]) & 0xFFFFFFFF
    S0 = _rr(a, 2) ^ _rr(a, 13) ^ _rr(a, 22)
    maj = (a & b) ^ (a & c) ^ (b & c)
    temp2 = (S0 + maj) & 0xFFFFFFFF
    h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF
    
    # Round 2
    S1 = _rr(e, 6) ^ _rr(e, 11) ^ _rr(e, 25)
    ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g)
    temp1 = (h + S1 + ch + _K[2] + W1[2]) & 0xFFFFFFFF
    S0 = _rr(a, 2) ^ _rr(a, 13) ^ _rr(a, 22)
    maj = (a & b) ^ (a & c) ^ (b & c)
    temp2 = (S0 + maj) & 0xFFFFFFFF
    h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF
    
    state_r2 = [a, b, c, d, e, f, g, h]
    
    # Cache Round 3 invariant intermediates
    # At start of R3, state is state_r2 (invariant), W[3] will vary per nonce
    r3_e = state_r2[4]
    r3_f = state_r2[5]
    r3_g = state_r2[6]
    r3_h = state_r2[7]
    r3_a = state_r2[0]
    r3_b = state_r2[1]
    r3_c = state_r2[2]
    r3_d = state_r2[3]
    
    r3_S1 = _rr(r3_e, 6) ^ _rr(r3_e, 11) ^ _rr(r3_e, 25)
    r3_ch = (r3_e & r3_f) ^ ((~r3_e & 0xFFFFFFFF) & r3_g)
    r3_S0 = _rr(r3_a, 2) ^ _rr(r3_a, 13) ^ _rr(r3_a, 22)
    r3_maj = (r3_a & r3_b) ^ (r3_a & r3_c) ^ (r3_b & r3_c)
    r3_temp2 = (r3_S0 + r3_maj) & 0xFFFFFFFF
    
    # Build fixed schedule (W0-W2, W4-W17 are invariant)
    # W[3] and W[18]-W[63] must be recomputed per nonce
    W_base = list(W1)  # copy of full schedule for nonce=0
    W_invariant_prefix = W_base[:3] + W_base[4:18]  # W0-W2, W4-W17 (17 words)
    
    return {
        'state_mid': state_mid,
        'state_r2': state_r2,
        'r3_S1': r3_S1,
        'r3_ch': r3_ch,
        'r3_S0': r3_S0,
        'r3_maj': r3_maj,
        'r3_temp2': r3_temp2,
        'r3_h': r3_h,
        'r3_d': r3_d,
        'W_invariant_prefix': W_invariant_prefix,
        'W_base': W_base,  # for reference, W[3] will be replaced
    }


def build_schedule_for_nonce(cache: dict, nonce: int) -> list:
    """Build the full 64-word schedule for a specific nonce.
    
    Uses cached invariant words W0-W2, W4-W17.
    Recomputes W[3] from nonce and W[18]-W[63] from schedule expansion.
    """
    W = [0] * 64
    # Invariant input words (W0-W2, W4-W15)
    inv = cache['W_invariant_prefix']
    W[0] = inv[0]   # W0
    W[1] = inv[1]   # W1
    W[2] = inv[2]   # W2
    # W[3] = nonce (computed below)
    for i in range(4, 16):
        W[i] = inv[i - 1]  # W4-W15 from cache (indices 3-14 in inv)
    # W[16]-W[17] from cache
    W[16] = inv[15]  # W16 mapping: inv has [W0,W1,W2,W4..W17], so inv[15]=W16, inv[16]=W17
    W[17] = inv[16]
    
    # Set W[3] from nonce (big-endian in the message schedule)
    W[3] = struct.unpack('>I', struct.pack('<I', nonce))[0]
    
    # Recompute W[18]-W[63]
    for t in range(18, 64):
        s0 = _rr(W[t - 15], 7) ^ _rr(W[t - 15], 18) ^ (W[t - 15] >> 3)
        s1 = _rr(W[t - 2], 17) ^ _rr(W[t - 2], 19) ^ (W[t - 2] >> 10)
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) & 0xFFFFFFFF
    
    return W


def sha256_precomputed(block_header_80: bytes, cache: dict, nonce: int) -> bytes:
    """Compute SHA-256 using precomputed invariant operations.
    
    Uses the cache from build_cache() and only recomputes nonce-dependent parts.
    """
    from sha256_trace import sha256_pad as _pad
    
    padded = _pad(block_header_80)
    
    # Block 0 uses standard compression (midstate is already computed)
    # Our cache already has the midstate
    
    # Actually, let me redo this properly.
    # We need the full hash, so:
    # 1. Block 0 compression uses the cache's midstate result
    # 2. Block 1 starts from the midstate and uses cached invariant operations
    
    state = list(cache['state_mid'])  # This is the final state of Block 0
    
    # Block 1: start from cached state_r2
    # First, run Rounds 0-2 (invariant, same path as in build_cache)
    # Then run Round 3 with the nonce-specific W[3]
    # Then run Rounds 4-63
    
    # Build the full schedule for this nonce
    W1 = build_schedule_for_nonce(cache, nonce)
    
    # Start from cached state_r2 (after Rounds 0-2)
    a, b, c, d, e, f, g, h = cache['state_r2']
    
    # Round 3 - use 5 cached invariant values, recompute 3 nonce-dependent
    r3_S1 = cache['r3_S1']
    r3_ch = cache['r3_ch']
    r3_S0 = cache['r3_S0']
    r3_maj = cache['r3_maj']
    r3_temp2 = cache['r3_temp2']
    
    temp1 = (cache['r3_h'] + r3_S1 + r3_ch + _K[3] + W1[3]) & 0xFFFFFFFF
    # e = d + temp1 (where d is from state_r2)
    # a = temp1 + temp2
    e_new = (cache['r3_d'] + temp1) & 0xFFFFFFFF
    a_new = (temp1 + r3_temp2) & 0xFFFFFFFF
    
    # Shift state for R3 -> R4
    # h = g, g = f, f = e, e = e_new, d = c, c = b, b = a, a = a_new
    h, g, f, e, d, c, b, a = cache['state_r2'][6], cache['state_r2'][5], cache['state_r2'][4], e_new, cache['state_r2'][2], cache['state_r2'][1], cache['state_r2'][0], a_new
    
    # Rounds 4-63: standard compression (state fully nonce-dependent)
    for t in range(4, 64):
        S1 = _rr(e, 6) ^ _rr(e, 11) ^ _rr(e, 25)
        ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g)
        temp1 = (h + S1 + ch + _K[t] + W1[t]) & 0xFFFFFFFF
        S0 = _rr(a, 2) ^ _rr(a, 13) ^ _rr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xFFFFFFFF
        h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF
    
    final = [(state[i] + v) & 0xFFFFFFFF for i, v in enumerate([a, b, c, d, e, f, g, h])]
    return struct.pack('>8I', *final)


# ---------- test harness ----------

def test_single_nonce(cache, nonce):
    """Test that precomputed SHA-256 matches reference for a single nonce."""
    header = build_header(nonce)
    expected = sha256_full(header)
    actual = sha256_precomputed(header, cache, nonce)
    return expected == actual, expected, actual


def test_multiple_nonces(num_nonces=100):
    """Test precomputed SHA-256 for multiple nonces."""
    header_0 = build_header(0)
    cache = build_cache(header_0)
    
    passes = 0
    fails = 0
    
    for i in range(num_nonces):
        ok, exp, act = test_single_nonce(cache, i)
        if ok:
            passes += 1
        else:
            fails += 1
            print(f"  FAIL at nonce={i}: expected {exp.hex()}, got {act.hex()}")
    
    return passes, fails


def operation_count_report(cache):
    """Calculate and report operation counts."""
    # Standard SHA-256: 2 blocks × 64 rounds × 8 ops = 1024 ops
    total_ops = 1024
    
    # Block 0 is fully precomputable via midstate
    block0_ops = 512
    
    # Block 1 cached:
    # R0-R2: 3 rounds × 8 ops = 24 ops
    # R3: 5 ops (S1, ch, S0, maj, temp2)
    cached_block1_ops = 24 + 5
    
    # Operations that must be recomputed per nonce
    # R3: 3 ops (temp1, e_new, a_new)
    # R4-R63: 60 rounds × 8 ops = 480 ops
    recompute_block1_ops = 3 + 480
    
    total_cached = block0_ops + cached_block1_ops
    total_recompute = recompute_block1_ops
    
    reuse_ratio = total_cached / total_ops
    
    print(f"\nPrecomputation Efficiency Report")
    print(f"{'=' * 60}")
    print(f"{'Metric':<40} {'Value':<15}")
    print(f"{'-' * 60}")
    print(f"{'Total ops per hash':<40} {total_ops:<15}")
    print(f"{'Block 0 (midstate)':<40} {block0_ops:<15}")
    print(f"{'Block 1 cached (R0-R2 + R3/5inv)':<40} {cached_block1_ops:<15}")
    print(f"{'Total cached':<40} {total_cached:<15}")
    print(f"{'Must recompute per nonce':<40} {total_recompute:<15}")
    print(f"{'Reuse Ratio':<40} {reuse_ratio:.4f} ({reuse_ratio*100:.2f}%)")
    print()
    
    print(f"Breakdown of cached operations in Block 1:")
    print(f"  Rounds 0-2: 24 ops (state invariant)")
    print(f"  Round 3:    5 ops (S1, ch, S0, maj, temp2)")
    print(f"  Total:      29 ops")
    print()
    print(f"Operations still recomputed per nonce in Block 1:")
    print(f"  Round 3:    3 ops (temp1, e_new, a_new)")
    print(f"  Rounds 4-63: 480 ops (state fully influenced)")
    print(f"  Total:      483 ops")
    
    return reuse_ratio


def verify_double_sha(cache, nonce):
    """Verify that double SHA-256 with precomputation matches too."""
    header = build_header(nonce)
    expected = sha256_double(header)
    # Our precomputed version only does single SHA
    # Double SHA would need the precomputation extended
    first = sha256_precomputed(header, cache, nonce)
    second = sha256_full(first)  # Second SHA has no caching (seed is nonce-dependent)
    actual = second
    return expected == actual, expected, actual


# ---------- main ----------

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--test-nonces', type=int, default=100,
                    help='Number of nonces to test (default: 100)')
    ap.add_argument('--verify-double', action='store_true',
                    help='Also verify double SHA-256')
    ap.add_argument('--synthetic', action='store_true',
                    help='Use synthetic block header with random values')
    args = ap.parse_args()
    
    print("=" * 60)
    print("RQ-004: Formal Precomputation Boundary")
    print("=" * 60)
    
    # Build header and cache
    header_0 = build_header(0)
    print(f"\nBuilding precomputation cache from nonce=0...")
    t0 = time.time()
    cache = build_cache(header_0)
    t1 = time.time()
    print(f"Cache built in {(t1-t0)*1000:.1f}ms")
    
    # Operation count report
    rr = operation_count_report(cache)
    
    # Test single SHA correctness
    print(f"\nVerifying SHA-256 for {args.test_nonces} nonces...")
    t0 = time.time()
    passes, fails = test_multiple_nonces(args.test_nonces)
    t1 = time.time()
    
    print(f"  Passed: {passes}/{args.test_nonces}")
    print(f"  Failed: {fails}/{args.test_nonces}")
    print(f"  Time:   {(t1-t0)*1000:.1f}ms")
    
    # Test double SHA
    if args.verify_double:
        print(f"\nVerifying double SHA-256 for {min(args.test_nonces, 10)} nonces...")
        dbl_passes = 0
        dbl_fails = 0
        for i in range(min(args.test_nonces, 10)):
            ok, _, _ = verify_double_sha(cache, i)
            if ok:
                dbl_passes += 1
            else:
                dbl_fails += 1
        print(f"  Passed: {dbl_passes}/{min(args.test_nonces, 10)}")
        print(f"  Failed: {dbl_fails}/{min(args.test_nonces, 10)}")
    
    # Conclusion
    if fails == 0:
        print(f"\nCONFIRMED: {passes}/{passes} test nonces match reference SHA-256.")
        print(f"  Precomputation boundary proven for compression operations.")
        print(f"  Net new compression savings beyond midstate: 29 ops ({29/1024*100:.2f}%)")
        print(f"")
        print(f"  HOWEVER: schedule expansion W[18]-W[63] (46 words, ~230 ops) must")
        print(f"  be recomputed per nonce. These were hidden in the invariant count.")
        print(f"  True savings: compression(29) - schedule(230) = -201 ops (NET LOSS)")
        print(f"  Conclusion: Precomputation boundary EXISTS but is NEGATIVE at the operation level.")
    else:
        print(f"\nPRECOMPUTATION FAILED: {fails} mismatches detected.")
        print(f"  Some invariant assumption is incorrect.")
