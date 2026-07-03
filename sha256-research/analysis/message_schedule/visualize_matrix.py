#!/usr/bin/env python3
"""
Visualize the Nonce Influence Matrix as a heatmap.

Reads the CSV output from nonce_influence.py and generates:
- SVG/PNG heatmap (nonce bits × schedule words)
- Color-coded dependency graph

Usage:
    python visualize_matrix.py --input output/nonce_influence.csv --output output/matrix.png
"""

import argparse
import csv
import os
import sys


def read_csv(filepath: str) -> tuple:
    """Read influence matrix CSV.
    
    Returns:
        (headers, matrix) where matrix[bit_idx][word_idx] = 0/1
    """
    with open(filepath, 'r') as f:
        reader = csv.reader(f)
        headers = next(reader)
        bits = []
        matrix = []
        for row in reader:
            bit = int(row[0])
            bits.append(bit)
            matrix.append([int(x) for x in row[1:]])
    return headers[1:], bits, matrix


def print_ascii_heatmap(headers: list, bits: list, matrix: list):
    """Print ASCII heatmap to terminal."""
    n_words = len(headers)
    n_bits = len(bits)

    print("\nNonce Influence Matrix (ASCII heatmap)")
    print(f"{'':>12}", end="")
    for w in range(0, n_words, 4):
        print(f"W{w:<3} ", end="")
    print()

    for bit_idx in range(0, n_bits, 4):
        row_label = f"b{bit_idx}-{min(bit_idx+3, n_bits-1)}"
        print(f"{row_label:>12}", end="")
        for w in range(0, n_words, 4):
            # Show aggregate for 4-word block
            influenced = sum(matrix[b][w] for b in range(bit_idx, min(bit_idx+4, n_bits)))
            if influenced == 0:
                print("  .  ", end="")
            elif influenced < 4:
                print(f"  {influenced}  ", end="")
            else:
                print("  #  ", end="")
        print()

    print(f"\nLegend: . = no influence, # = all 4 bits influence")
    print(f"Numbers = count of influencing bits in this 4×4 block")


def print_word_summary(headers: list, bits: list, matrix: list):
    """Print summary by word group."""
    n_words = len(headers)

    # Group words by block
    block0_words = [w for w in range(64) if any(matrix[b][w] for b in range(32))]
    block1_words = [w for w in range(64, 128) if any(matrix[b][w] for b in range(32))]

    print(f"\nWord Summary")
    print(f"{'=' * 60}")
    print(f"Block 0 (W0-W63): {len(block0_words)}/64 nonce-dependent words")
    print(f"Block 1 (W64-W127): {len(block1_words)}/64 nonce-dependent words")

    if block1_words:
        print(f"First nonce-dependent word in Block 1: W{block1_words[0]} (index {block1_words[0]})")
        print(f"Range of nonce-dependent words: W{block1_words[0]}-W{block1_words[-1]}")


def main():
    parser = argparse.ArgumentParser(description='Visualize Nonce Influence Matrix')
    parser.add_argument('--input', type=str, default='output/nonce_influence.csv',
                        help='Input CSV file from nonce_influence.py')
    parser.add_argument('--output', type=str, default=None,
                        help='Output image file (SVG/PNG)')
    args = parser.parse_args()

    input_path = os.path.join(os.path.dirname(__file__), args.input)
    if not os.path.exists(input_path):
        print(f"Error: Input file not found: {input_path}")
        print("Run nonce_influence.py first to generate the CSV.")
        sys.exit(1)

    headers, bits, matrix = read_csv(input_path)
    n_words = len(headers)
    n_bits = len(bits)

    print(f"Nonce Influence Matrix: {n_bits} bits × {n_words} words")

    print_ascii_heatmap(headers, bits, matrix)
    print_word_summary(headers, bits, matrix)

    if args.output:
        try:
            import matplotlib.pyplot as plt
            import numpy as np

            fig, ax = plt.subplots(figsize=(max(12, n_words * 0.15), 8))
            data = np.array(matrix, dtype=int)
            im = ax.imshow(data, cmap='RdYlGn_r', aspect='auto', interpolation='nearest')

            ax.set_xlabel('Schedule Word')
            ax.set_ylabel('Nonce Bit')
            ax.set_title('Nonce Influence Matrix\n(black = no influence, white = full influence)')

            ax.set_xticks(range(0, n_words, 8))
            ax.set_xticklabels([f'W{w}' for w in range(0, n_words, 8)])
            ax.set_yticks(range(n_bits))
            ax.set_yticklabels(range(n_bits))

            plt.colorbar(im, label='Influence (0=no, 1=yes)')
            plt.tight_layout()
            plt.savefig(args.output, dpi=150)
            print(f"\nHeatmap saved: {args.output}")
        except ImportError:
            print("\nmatplotlib not installed. Install with: pip install matplotlib numpy")
            print("For now, only ASCII visualization available.")

    print("\nTo generate detailed statistics, use:")
    print("  python nonce_influence.py --output-dir output")


if __name__ == '__main__':
    main()
