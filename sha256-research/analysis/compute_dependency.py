#!/usr/bin/env python3
"""
Computation Dependency Graph for SHA-256 under nonce variation.

For each operation in each round of SHA-256 compression, determines
whether the operation's output is mathematically identical across
all nonce values for a fixed block header.

Operation types per round (8 total):
  1. S1   = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)
  2. ch   = (e & f) ^ ((~e) & g)
  3. temp1 = h + S1 + ch + K + W[t]
  4. S0   = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)
  5. maj  = (a & b) ^ (a & c) ^ (b & c)
  6. temp2 = S0 + maj
  7. e_new = d + temp1
  8. a_new = temp1 + temp2

Usage:
    python compute_dependency.py
    python compute_dependency.py --nonce 42 --blocks 2
    python compute_dependency.py --json --output-dir ./output
"""

import argparse
import json
import os
import struct

# Xoay phải n bit
def _rr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

# SHA-256 constants
_K = [
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
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

_H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

OP_NAMES = ['S1', 'ch', 'temp1', 'S0', 'maj', 'temp2', 'e_new', 'a_new']


def pad(data: bytes) -> bytes:
    ml = len(data) * 8
    data += b'\x80'
    while (len(data) % 64) != 56:
        data += b'\x00'
    data += struct.pack('>Q', ml)
    return data


def schedule(block: bytes) -> list:
    assert len(block) == 64
    W = list(struct.unpack('>16I', block))
    for t in range(16, 64):
        s0 = _rr(W[t - 15], 7) ^ _rr(W[t - 15], 18) ^ (W[t - 15] >> 3)
        s1 = _rr(W[t - 2], 17) ^ _rr(W[t - 2], 19) ^ (W[t - 2] >> 10)
        W.append((W[t - 16] + s0 + W[t - 7] + s1) & 0xFFFFFFFF)
    return W


def compress_trace(W: list, state: list = None) -> tuple:
    if state is None:
        state = list(_H0)
    a, b, c, d, e, f, g, h = state
    trace = []
    for t in range(64):
        S1 = _rr(e, 6) ^ _rr(e, 11) ^ _rr(e, 25)
        ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g)
        temp1 = (h + S1 + ch + _K[t] + W[t]) & 0xFFFFFFFF
        S0 = _rr(a, 2) ^ _rr(a, 13) ^ _rr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xFFFFFFFF
        h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF
        trace.append([a, b, c, d, e, f, g, h])
    return [(state[i] + v) & 0xFFFFFFFF for i, v in enumerate([a, b, c, d, e, f, g, h])], trace


def compress(W: list, state: list = None) -> list:
    if state is None:
        state = list(_H0)
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


def build_header(nonce: int) -> bytes:
    return (struct.pack('<I', 1) + b'\x00' * 32 + b'\x00' * 32 +
            struct.pack('<I', 0x4DAB5D0A) + struct.pack('<I', 0x1D00FFFF) +
            struct.pack('<I', nonce))


def analyze(nonce_base: int = 0, block_count: int = 2) -> dict:
    """Classify each operation in each round as INVARIANT (0) or INFLUENCED (1)."""
    bh = build_header(nonce_base)
    bp = pad(bh)
    fh = build_header(nonce_base ^ 1)
    fp = pad(fh)

    sched_inf = []  # per block: [bool]*64
    state_inf = []  # per block: [[bool]*8]*64

    st = list(_H0)
    for b in range(block_count):
        bb = bp[b*64:(b+1)*64]
        fb = fp[b*64:(b+1)*64]
        Wb = schedule(bb)
        Wf = schedule(fb)
        sched_inf.append([Wb[t] != Wf[t] for t in range(64)])
        _, tb = compress_trace(Wb, st)
        _, tf = compress_trace(Wf, st)
        si = []
        for r in range(64):
            si.append([tb[r][v] != tf[r][v] for v in range(8)])
        state_inf.append(si)
        st = compress(Wb, st)

    # Compute pre-round state influence by comparing base vs flipped at each point
    # We need to track: at each round start, which vars differ between base and flipped
    pre_states = []

    # Track states for both base and flipped through all rounds
    base_states = list(_H0)
    flip_states = list(_H0)
    for b in range(block_count):
        bb = bp[b*64:(b+1)*64]
        fb = fp[b*64:(b+1)*64]
        Wb = schedule(bb)
        Wf = schedule(fb)
        _, tb = compress_trace(Wb, base_states)
        _, tf = compress_trace(Wf, flip_states)
        for r in range(64):
            if r == 0:
                pre_states.append([base_states[v] != flip_states[v] for v in range(8)])
            else:
                pre_states.append([tb[r-1][v] != tf[r-1][v] for v in range(8)])
        base_states = compress(Wb, base_states)
        flip_states = compress(Wf, flip_states)

    results = []
    for b in range(block_count):
        block_res = []
        for r in range(64):
            ar = b * 64 + r
            ps = pre_states[ar]
            wi = sched_inf[b][r]
            ai, bi, ci, di = ps[0], ps[1], ps[2], ps[3]
            ei, fi, gi, hi = ps[4], ps[5], ps[6], ps[7]

            ops = {}
            ops['S1'] = bool(ei)
            ops['ch'] = bool(ei or fi or gi)
            ops['temp1'] = bool(hi or ops['S1'] or ops['ch'] or wi)
            ops['S0'] = bool(ai)
            ops['maj'] = bool(ai or bi or ci)
            ops['temp2'] = bool(ops['S0'] or ops['maj'])
            ops['e_new'] = bool(di or ops['temp1'])
            ops['a_new'] = bool(ops['temp1'] or ops['temp2'])
            block_res.append(ops)
        results.append(block_res)

    return {'nonce': nonce_base, 'blocks': block_count, 'results': results}


def print_report(res: dict):
    print(f"\nComputation Dependency Analysis")
    print(f"{'=' * 60}")
    print(f"Base nonce: 0x{res['nonce']:08x}")

    all_ops = []
    for b in range(res['blocks']):
        print(f"\n{'=' * 60}")
        print(f"Block {b}")
        print(f"{'=' * 60}")
        hdr = f"{'R':<4} " + " ".join(f"{o:<7}" for o in OP_NAMES) + " | W[t]"
        print(hdr)
        print("-" * 60)

        for r in range(64):
            ops = res['results'][b][r]
            if r < 16:
                wlab = 'input'
            elif r < 18:
                wlab = 'gen:I'
            else:
                wlab = 'gen:D'
            line = f"R{r:<3} "
            for o in OP_NAMES:
                line += f"{'I' if not ops[o] else 'D':<7} "
            line += f"| W{r} {wlab}"
            print(line)
            all_ops.append(ops)

        inv = sum(1 for o in OP_NAMES for ops in all_ops if not ops[o])
        tot = len(all_ops) * 8
        print(f"\n  Invariant operations: {inv}/{tot} ({inv/max(tot,1)*100:.1f}%)")

    for o in OP_NAMES:
        cnt = sum(1 for ops in all_ops if not ops[o])
        print(f"  {o:<8}: {cnt}/{len(all_ops)} rounds invariant ({cnt/len(all_ops)*100:.1f}%)")


def export_json(res: dict, path: str):
    out = {'nonce': res['nonce'], 'blocks': res['blocks'], 'op_names': OP_NAMES,
           'operations': [r for b in res['results'] for r in b]}
    with open(path, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"  JSON: {path}")


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--nonce', type=int, default=0)
    p.add_argument('--blocks', type=int, default=2)
    p.add_argument('--json', action='store_true')
    p.add_argument('--output-dir', type=str, default='.')
    a = p.parse_args()

    r = analyze(a.nonce, a.blocks)
    print_report(r)

    if a.json:
        os.makedirs(a.output_dir, exist_ok=True)
        export_json(r, os.path.join(a.output_dir, 'compute_dependency.json'))
