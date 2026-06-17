
# nostr-did-key

[![crates.io](https://img.shields.io/crates/v/nostr-did-key.svg)](https://crates.io/crates/nostr-did-key)
[![docs.rs](https://docs.rs/nostr-did-key/badge.svg)](https://docs.rs/nostr-did-key)
[![License](https://img.shields.io/crates/l/nostr-did-key.svg)](LICENSE-MIT)
[![CI](https://github.com/sirraya-labs/nostr-did-key/actions/workflows/ci.yml/badge.svg)](https://github.com/sirraya-labs/nostr-did-key/actions/workflows/ci.yml)

A minimal, zero-dependency Rust implementation of the `did:nostr` public key
transformation pipeline. Converts BIP-340 x-only Nostr public keys into
W3C Multikey representations suitable for DID Documents.

```rust
use nostr_did_key::public_key_to_multikey;

let multikey = public_key_to_multikey(
    "124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2"
).unwrap();

assert_eq!(
    multikey,
    "fe70102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2"
);
```

## What it does

Converts Nostr public keys into the W3C Multikey format required by DID Documents:

```
Nostr hex pubkey (64 chars)
        │
        ▼
  [0x02] + 32 bytes     ← Even parity (BIP-340 canonical)
        │
        ▼
  0xe701 + 33 bytes     ← secp256k1-pub multicodec
        │
        ▼
  f + lowercase hex     ← Multibase base16-lower
        │
        ▼
  publicKeyMultibase    ← Ready for DID Documents
```

## Installation

```toml
[dependencies]
nostr-did-key = "0.1"
```

## Quick Start

### Encode a Nostr pubkey to Multikey

```rust
use nostr_did_key::public_key_to_multikey;

let hex_pubkey = "124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";
let multikey = public_key_to_multikey(hex_pubkey).unwrap();

println!("{}", multikey);
// Output: fe70102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2
```

### Decode a Multikey back to hex pubkey

```rust
use nostr_did_key::multikey_to_bip340_pubkey;

let multikey = "fe70102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";
let hex = multikey_to_bip340_pubkey(multikey).unwrap();

println!("{}", hex);
// Output: 124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2
```

### Roundtrip verification

```rust
use nostr_did_key::{public_key_to_multikey, multikey_to_bip340_pubkey};

let original = "124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";
let multikey = public_key_to_multikey(original).unwrap();
let recovered = multikey_to_bip340_pubkey(&multikey).unwrap();

assert_eq!(original, recovered); // Always true for valid inputs
```

### Error handling

```rust
use nostr_did_key::{public_key_to_multikey, multikey_to_bip340_pubkey};

// Wrong length
let result = public_key_to_multikey("too_short");
// Err(EncodeError::InvalidHexLength { got: 9 })

// Non-hex characters
let result = public_key_to_multikey("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg");
// Err(EncodeError::InvalidHexCharacter { position: 0, character: 'g' })

// Odd parity (encodes a different BIP-340 identity)
let result = multikey_to_bip340_pubkey(
    "fe70103124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2"
);
// Err(DecodeError::OddParityNotCanonical)

// Wrong multicodec
let result = multikey_to_bip340_pubkey(
    "fe80102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2"
);
// Err(DecodeError::InvalidMulticodec)
```

## Features

### `crypto-validation` (optional)

Enable BIP-340 curve validation via `secp256k1`:

```toml
[dependencies]
nostr-did-key = { version = "0.1", features = ["crypto-validation"] }
```

```rust
use nostr_did_key::{public_key_to_multikey, multikey_to_validated_key, ValidatedBip340Key};

// Encode rejects invalid curve points
let result = public_key_to_multikey(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30"
);
// Err(EncodeError::InvalidPublicKey)

// Decode returns a reusable validated key
let multikey = "fe70102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";
let key: ValidatedBip340Key = multikey_to_validated_key(multikey).unwrap();

// Type-level proof of validity — pass to other APIs without re-validation
println!("{}", key.to_hex());
println!("{:?}", key.as_bytes());
```

## API Reference

| Function | Input | Output | Description |
|---|---|---|---|
| `public_key_to_multikey` | 64-char hex | `Result<String, EncodeError>` | Encode pubkey → Multikey |
| `multikey_to_bip340_pubkey` | Multikey string | `Result<String, DecodeError>` | Decode Multikey → hex (even parity only) |
| `multikey_to_validated_key` | Multikey string | `Result<ValidatedBip340Key, DecodeError>` | Decode + validate (requires `crypto-validation`) |
| `ValidatedBip340Key::from_hex` | 64-char hex | `Result<Self, EncodeError>` | Validate a hex pubkey |
| `ValidatedBip340Key::to_hex` | — | `String` | Return hex representation |
| `ValidatedBip340Key::as_bytes` | — | `&[u8; 32]` | Access raw bytes |

## Why even parity only?

BIP-340 defines Schnorr public keys as the x-coordinate with an **implicitly even**
y-coordinate. For any x-coordinate, there are two curve points — one with even y,
one with odd y. BIP-340 unambiguously selects the even-y point. Even parity (`0x02`)
is the only mathematically faithful encoding of a BIP-340 key as a compressed
secp256k1 point.

Odd parity encodes the *other* lift of the x-coordinate — a different point,
a different private key, a different identity. This crate rejects it.

## Design

- **Zero dependencies** (without `crypto-validation`) — only `alloc`
- **`no_std` compatible** — embedded, WASM, bare-metal
- **Stack-allocated final key** — `[u8; 32]` on the decode path
- **Structured errors** — every failure mode has a distinct error variant
- **Round-trip stable** — `decode(encode(x)) == x` for all valid inputs
- **Deterministic** — same input always produces identical output
- **Spec-conformant** — matches [did:nostr v0.0.11](https://nostrcg.github.io/did-nostr/)

## Running the demo

```bash
cargo run --example demo --features crypto-validation
```

Output:

```
══════════════════════════════════════════════
  nostr-did-key v0.1.0 — Demo
══════════════════════════════════════════════

─── Example 1: Spec test vector ───
Input (hex pubkey):  124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2
Output (multikey):   fe70102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2
Roundtrip verified:  124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2
Match:               true

─── Example 2: Real key generation (requires crypto-validation) ───
Generated secret key:  d30c2efe9b2216e7677f86dffdc0d0e915ddcb18e50a3182a95ebf813c5df39a
Generated pubkey (x-only): 141418bd95914cdaca3ce6b40e729a86b52ed4cadc2916eddbf3c814584b152a
Multikey:              fe70102141418bd95914cdaca3ce6b40e729a86b52ed4cadc2916eddbf3c814584b152a
Roundtrip:             true
Validated key hex:     141418bd95914cdaca3ce6b40e729a86b52ed4cadc2916eddbf3c814584b152a

─── Example 3: Error handling ───
Bad length input → invalid hex length: expected 64 characters (32 bytes), got 9
Non-hex input   → invalid hex character 'g' at byte position 0; expected [0-9a-fA-F]
Odd parity      → odd parity is not canonical for BIP-340; the even-y lift is required
Bad multicodec  → invalid multicodec: expected secp256k1-pub (0xe7 0x01)
Bad hex body    → invalid hex in multibase string: expected [0-9a-fA-F]

─── Example 4: Output format ───
Length:       71 chars
Prefix:       f
All hex:      true
No uppercase: true

══════════════════════════════════════════════
  Demo complete
══════════════════════════════════════════════
```

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.


