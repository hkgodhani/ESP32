#!/usr/bin/env python3
"""
Nonce Influence Matrix

Analyzes how information from the 32-bit nonce propagates through the
SHA-256 message schedule.

For each nonce bit (0-31) and each message schedule word (W0-W63),
determines whether changing that nonce bit affects that word.

Output:
- CSV: Full influence matrix
- JSON: Machine-readable dependency data
- SVG/PNG: Visualization

Usage:
    python nonce_influence.py                          # Default analysis
    python nonce_influence.py --output-dir ./output     # Save to directory
    python nonce_influence.py --nonce-bits 0 1 15 31    # Test specific bits
"""

import argparse
import csv
import json
import os
import struct
import sys

# Add parent directory for tools import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../tools'))

from sha256_trace import sha256_schedule, sha256_compress, sha256_pad, H0


def build_block_header(nonce: int) -> bytes:
    """Build a minimal 80-byte Bitcoin block header with given nonce.
    
    Only the nonce varies; all other fields are fixed.
    """
    version = struct.pack('<I', 1)
    prev_block = b'\x00' * 32
    merkle_root = b'\x00' * 32
    time = struct.pack('<I', 0x4DAB5D0A)
    bits = struct.pack('<I', 0x1D00FFFF)
    nonce_bytes = struct.pack('<I', nonce)
    return version + prev_block + merkle_root + time + bits + nonce_bytes


def compute_nonce_influence(nonce_base: int = 0,
                            nonce_bits: list = None,
                            block_count: int = 2) -> dict:
    """Compute which schedule words depend on each nonce bit.
    
    For each nonce bit, flips that bit and compares the resulting
    message schedule against the base nonce. Any word that differs
    is marked as "dependent" on that bit.
    
    Returns:
        dict: {
            'base_nonce': int,
            'matrix': { bit_idx: [list of dependent word indices] },
            'word_influence': { word_idx: [list of bits that affect it] },
            'influence_count': { word_idx: int (number of bits affecting it) },
            'total_words': int
        }
    """
    if nonce_bits is None:
        nonce_bits = list(range(32))

    # Build base header
    base_header = build_block_header(nonce_base)
    padded = sha256_pad(base_header)

    # Compute base message schedule for each block
    base_schedules = []
    for b in range(block_count):
        offset = b * 64
        block = padded[offset:offset + 64]
        base_schedules.append(sha256_schedule(block))

    result = {
        'base_nonce': nonce_base,
        'matrix': {},
        'word_influence': {},
        'influence_count': {},
        'total_words': block_count * 64,
    }

    for bit_idx in nonce_bits:
        # Flip the bit
        flipped_nonce = nonce_base ^ (1 << bit_idx)
        flipped_header = build_block_header(flipped_nonce)
        flipped_padded = sha256_pad(flipped_header)

        dependent_words = []

        for b in range(block_count):
            flipped_W = sha256_schedule(flipped_padded[b*64:(b+1)*64])
            base_W = base_schedules[b]

            for t in range(64):
                if flipped_W[t] != base_W[t]:
                    dependent_words.append(b * 64 + t)

        result['matrix'][bit_idx] = dependent_words

        for word_idx in dependent_words:
            if word_idx not in result['word_influence']:
                result['word_influence'][word_idx] = []
            result['word_influence'][word_idx].append(bit_idx)

    # Compute influence counts
    for word_idx in range(block_count * 64):
        result['influence_count'][word_idx] = len(
            result['word_influence'].get(word_idx, [])
        )

    return result


def compute_influence_percentage(result: dict) -> dict:
    """Compute bit-influence percentage for each schedule word.
    
    Influence(W) = (# of nonce bits that affect W) / 32 * 100
    """
    percentages = {}
    for word_idx in range(result['total_words']):
        influenced_by = result['influence_count'].get(word_idx, 0)
        percentages[word_idx] = (influenced_by / 32) * 100
    return percentages


def export_csv(result: dict, filepath: str):
    """Export influence matrix as CSV.
    
    Rows = nonce bits, Columns = schedule words.
    Cell value = 1 if bit affects word, 0 otherwise.
    """
    total = result['total_words']
    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)
        # Header row
        header = ['nonce_bit'] + [f'W{i}' for i in range(total)]
        writer.writerow(header)

        # Data rows
        for bit in range(32):
            row = [bit] + [0] * total
            for word_idx in result['matrix'].get(bit, []):
                row[word_idx + 1] = 1
            writer.writerow(row)

    print(f"  CSV exported: {filepath}")


def export_json(result: dict, filepath: str):
    """Export influence data as JSON."""
    percentages = compute_influence_percentage(result)

    output = {
        'base_nonce': result['base_nonce'],
        'total_words': result['total_words'],
        'word_influence': {},
        'influence_percentage': percentages,
    }

    # Convert word_influence to serializable format
    for word_idx, bits in result['word_influence'].items():
        output['word_influence'][str(word_idx)] = bits

    with open(filepath, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"  JSON exported: {filepath}")


def print_summary(result: dict):
    """Print a text summary of the influence matrix."""
    total = result['total_words']
    percentages = compute_influence_percentage(result)

    print(f"\nNonce Influence Matrix Summary")
    print(f"{'=' * 60}")
    print(f"Base nonce: 0x{result['base_nonce']:08x}")
    print(f"Total schedule words analyzed: {total}")
    print()

    # Word influence table
    print(f"{'Word':<8} {'Block':<6} {'Bits':<6} {'%':<8} {'Affected by bits'}")
    print(f"{'-' * 60}")

    for word_idx in range(total):
        count = result['influence_count'].get(word_idx, 0)
        pct = percentages[word_idx]
        block = word_idx // 64
        local_idx = word_idx % 64

        if count > 0:
            bits_str = ','.join(str(b) for b in result['word_influence'].get(word_idx, []))
        else:
            bits_str = '(none)'

        bar = '#' * (int(pct) // 4)
        print(f"W{local_idx:<3}  Block{block:<3} {count:<6} {pct:<7.1f} {bar} {bits_str}")

    print()

    # Summary statistics
    influenced_words = sum(1 for w in range(total) if result['influence_count'].get(w, 0) > 0)
    fully_influenced = sum(1 for w in range(total) if result['influence_count'].get(w, 0) >= 32)
    invariant_words = total - influenced_words

    print(f"Words influenced by at least 1 nonce bit: {influenced_words}/{total}")
    print(f"Words influenced by all 32 nonce bits:   {fully_influenced}/{total}")
    print(f"Completely invariant words:              {invariant_words}/{total}")

    return percentages


def main():
    parser = argparse.ArgumentParser(description='Nonce Influence Matrix')
    parser.add_argument('--nonce', type=int, default=0,
                        help='Base nonce value (default: 0)')
    parser.add_argument('--nonce-bits', type=int, nargs='+', default=None,
                        help='Specific nonce bits to test (default: all 0-31)')
    parser.add_argument('--blocks', type=int, default=2,
                        help='Number of SHA-256 blocks to analyze (default: 2)')
    parser.add_argument('--output-dir', type=str, default='.',
                        help='Output directory for exported files')
    args = parser.parse_args()

    print("=" * 60)
    print("Nonce Influence Matrix")
    print("=" * 60)
    print(f"Base nonce: 0x{args.nonce:08x}")
    print(f"Blocks:     {args.blocks}")
    print()

    result = compute_nonce_influence(args.nonce, args.nonce_bits, args.blocks)

    print_summary(result)

    # Export
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)

        csv_path = os.path.join(args.output_dir, 'nonce_influence.csv')
        export_csv(result, csv_path)

        json_path = os.path.join(args.output_dir, 'nonce_influence.json')
        export_json(result, json_path)

    print("\nDone.")


if __name__ == '__main__':
    main()
