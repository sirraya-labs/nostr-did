//! # nostr-did
//!
//! Generate W3C-compliant DID Documents from `did:nostr` identifiers.
//!
//! Uses `nostr-did-key` for BIP-340 → Multikey cryptographic transformation
//! and produces fully spec-compliant DID Documents matching the
//! [Nostr DID Method Specification v0.0.11](https://nostrcg.github.io/did-nostr/).
//!
//! ## Quick start
//!
//! ```rust
//! use nostr_did::DocumentBuilder;
//!
//! let doc = DocumentBuilder::new()
//!     .build("did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2")
//!     .unwrap();
//!
//! println!("{}", serde_json::to_string_pretty(&doc).unwrap());
//! ```

pub mod document;

pub use document::{DidDocument, DocumentBuilder, Profile, Service, VerificationMethod};
