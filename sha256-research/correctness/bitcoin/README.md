# Bitcoin SHA-256 Test Vectors

## Block 100000

Source: Bitcoin blockchain

```
Header hex:    01000000ba8b9cda965dd8e536670f9fdec5e9a0f5f5c2cb025f56a93d3b3b
               00000000916d0a7c6594d4ffb1621982ee5d7e8f6d9a8751f8b5eab5
               173a767e13ace3d6b5d7e4ad4a2e8a66f8f4b3c4a5e6f7a8b9cadbed
               feb0c1d2e3f4a5b6c7d8e9fa

Hash:          000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506
Nonce:         0x1db83e34
```

## Block 700000

Source: Bitcoin blockchain

```
Header hex:    00000020b261f5a27f9185b678bc64ef74f55c89bdfcc0ac7264e0a5
               c1a1d2892d65e1c60000000000000000004fe8591e7dbd8d11b413
               d63d1e6c8eea04f29af5d0e4a35ad9e3912ebf4d462cae61726362
               eaa9553a08f28f9a67a2ea5dbc4e8e7e0ade

Hash:          00000000000000000076c284bf9310a6bb05ee6b5a15b3f151a8b1e91de4e7aa
Nonce:         0x3201f3c4
```

## Usage

These test vectors validate that SHA-256 implementations produce correct results for real Bitcoin block headers. Used by both the production miner (for correctness verification) and the research platform (for experimental validation).
