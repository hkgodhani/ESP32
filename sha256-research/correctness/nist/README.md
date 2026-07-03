# NIST SHA-256 Test Vectors

Source: NIST FIPS 180-4

## Test Case 1: Empty String

```
Input:    (empty)
Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

## Test Case 2: "abc"

```
Input:    616263
Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

## Test Case 3: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"

```
Input:    6162636462636465636465666465666765666768666768696768696a
          68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071
Expected: 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
```

## Test Case 4: 1,000,000 repetitions of "a"

```
Input:    "a" × 1,000,000
Expected: cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0
```

## Verification

Each test case verified against a known-good SHA-256 implementation.
