# nostr-did

[![crates.io](https://img.shields.io/crates/v/nostr-did.svg)](https://crates.io/crates/nostr-did)
[![docs.rs](https://docs.rs/nostr-did/badge.svg)](https://docs.rs/nostr-did)
[![License](https://img.shields.io/crates/l/nostr-did.svg)](LICENSE-MIT)

Generate W3C-compliant DID Documents from `did:nostr` identifiers.

Uses [`nostr-did-key`](https://crates.io/crates/nostr-did-key) for BIP-340 → Multikey
cryptographic transformation and produces fully spec-compliant documents matching
the [Nostr DID Method Specification v0.0.12](https://nostrcg.github.io/did-nostr/).

Maintains the official [conformance test vectors](https://github.com/nostrcg/did-nostr)
for the specification — any implementation can validate correctness against this crate's output.

## Quick Start

```rust
use nostr_did::DocumentBuilder;

let doc = DocumentBuilder::new()
    .build("did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2")
    .unwrap();

println!("{}", serde_json::to_string_pretty(&doc).unwrap());
```

## Output

### §2.3.1 Minimal DID Document (Offline)

Zero network — generated deterministically from the public key alone.
No services, no profile, no signed parts.

```json
{
  "@context": [
    "https://www.w3.org/ns/cid/v1",
    "https://w3id.org/nostr/context"
  ],
  "id": "did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2",
  "type": "DIDNostr",
  "verificationMethod": [
    {
      "id": "did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2#key1",
      "type": "Multikey",
      "controller": "did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2",
      "publicKeyMultibase": "fe70102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2"
    }
  ],
  "authentication": ["#key1"],
  "assertionMethod": ["#key1"]
}
```

### §2.3.3 Complete DID Document (Profile + Social Graph)

Enriched with Nostr kind 0 profile, kind 3 follows, and alsoKnownAs cross-platform links.
`modified` is computed from `max(created_at)` of all signed parts.

```rust
use nostr_did::{DocumentBuilder, Profile};

let profile = Profile {
    name: Some("Alice".into()),
    about: Some("Building the decentralized web".into()),
    picture: Some("https://example.com/alice.jpg".into()),
    nip05: Some("alice@example.com".into()),
    lud16: Some("alice@getalby.com".into()),
    website: Some("https://alice.example.com".into()),
    created_at: Some(1737906600),
};

let doc = DocumentBuilder::new()
    .with_relay("wss://relay.damus.io")
    .with_profile(profile)
    .with_also_known_as(vec![
        "https://alice.example.com/#me".into(),
        "https://social.example.com/@alice".into(),
        "at://alice.bsky.social".into(),
    ])
    .with_follows(vec![
        "did:nostr:32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245".into(),
        "did:nostr:46fcbe3065eaf1ae7811465924e48923363ff3f526bd6f73d7c184147700e3a8".into(),
    ])
    .with_relay_created_at(1737906600)
    .build("did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2")
    .unwrap();
```

```json
{
  "@context": [
    "https://www.w3.org/ns/cid/v1",
    "https://w3id.org/nostr/context"
  ],
  "id": "did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2",
  "type": "DIDNostr",
  "alsoKnownAs": [
    "https://alice.example.com/#me",
    "https://social.example.com/@alice",
    "at://alice.bsky.social"
  ],
  "verificationMethod": [
    {
      "id": "did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2#key1",
      "type": "Multikey",
      "controller": "did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2",
      "publicKeyMultibase": "fe70102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2"
    }
  ],
  "authentication": ["#key1"],
  "assertionMethod": ["#key1"],
  "service": [
    {
      "id": "did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2#relay1",
      "type": "Relay",
      "serviceEndpoint": "wss://relay.damus.io/"
    }
  ],
  "profile": {
    "name": "Alice",
    "about": "Building the decentralized web",
    "picture": "https://example.com/alice.jpg",
    "nip05": "alice@example.com",
    "lud16": "alice@getalby.com",
    "website": "https://alice.example.com",
    "created_at": 1737906600
  },
  "follows": [
    "did:nostr:32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245",
    "did:nostr:46fcbe3065eaf1ae7811465924e48923363ff3f526bd6f73d7c184147700e3a8"
  ],
  "modified": "2025-01-26T15:50:00Z"
}
```

## Installation

```toml
[dependencies]
nostr-did = "0.1"
```

## API Reference

### Constructors

| Method | Description |
|---|---|
| `DocumentBuilder::new()` | Empty builder — produces minimal §2.3.1 documents |
| `DocumentBuilder::with_defaults()` | Pre-seeded with 5 high-availability relays |

### Builder Methods

| Method | Description |
|---|---|
| `build(did)` | Generate the DID Document |
| `with_relay(url)` | Add a single relay URL (deduplicated) |
| `with_relays(vec)` | Replace all relays with a custom set |
| `with_profile(profile)` | Set Nostr kind 0 profile metadata |
| `with_also_known_as(vec)` | Set cross-platform identity links |
| `with_follows(vec)` | Set followed DIDs (kind 3 contacts) |
| `with_relay_created_at(ts)` | Set relay event timestamp for `modified` computation |
| `with_modified(iso8601)` | Explicit modified override (ISO-8601) |

### Types

| Type | Description |
|---|---|
| `DidDocument` | Full W3C-compliant DID Document |
| `VerificationMethod` | Multikey verification method |
| `Service` | Relay or FollowsEndpoint service entry |
| `Profile` | Nostr kind 0 profile metadata |

## Design Decisions

- **Verification method `id` and `controller`** are absolute (`did:nostr:<pubkey>#key1`)
- **`authentication` and `assertionMethod` references** are relative (`"#key1"`) — matches DID authoring conventions
- **`modified`** is computed from `max(created_at)` of all signed parts, not hardcoded
- **Relay IDs** are always indexed (`#relay1`, `#relay2`, ...) regardless of count
- **Parity**: canonical Multikey is even-parity `0x02`; decoders accept `0x03` for interop

## Conformance Suite

This crate generates the official test vectors for the did:nostr specification.
21 vectors covering key transformation, decoding, error cases, and all three
DID Document forms. Vectors are language-agnostic JSON — any implementation
can validate correctness by matching the output.

```bash
cargo run --example generate_test_vectors
```

## Default Relays (`with_defaults()`)

| Relay | Purpose |
|---|---|
| `wss://nos.lol` | General purpose, high uptime |
| `wss://relay.damus.io` | General purpose, Damus ecosystem |
| `wss://relay.primal.net` | General purpose, Primal ecosystem |
| `wss://relay.nostr.band` | Full-text search, network trends |
| `wss://purplepag.es` | Long-form content, user profiles |

## Running the Demo

```bash
cargo run --example demo
```

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)



