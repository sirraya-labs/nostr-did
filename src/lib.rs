//! # nostr-did-key
//!
//! A minimal Rust implementation of the `did:nostr` public key transformation
//! pipeline. Converts BIP-340 x-only Nostr public keys into W3C Multikey
//! representations, with optional secp256k1 validation.
//!
//! ## Architecture
//!
//! This crate separates three distinct concerns:
//!
//! | Layer | Concern | Always available |
//! |---|---|---|
//! | Representation transform | hex ↔ SEC1 ↔ multicodec ↔ multibase | Yes |
//! | BIP-340 identity semantics | even-y lift is canonical | Yes |
//! | Cryptographic validation | real curve arithmetic | With `crypto-validation` feature |
//!
//! ## Primary API (for DID implementers)
//!
//! ```rust
//! use nostr_did_key::{public_key_to_multikey, multikey_to_bip340_pubkey};
//!
//! // Encode
//! let multikey = public_key_to_multikey(
//!     "124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2"
//! ).unwrap();
//!
//! // Decode with structured error information
//! match multikey_to_bip340_pubkey(&multikey) {
//!     Ok(hex) => println!("Valid BIP-340 key: {hex}"),
//!     Err(e) => eprintln!("Decode failed: {e}"),
//! }
//! ```
//!
//! With `crypto-validation` enabled, you also get type-level validity proofs:
//!
//! ```rust
//! # #[cfg(feature = "crypto-validation")]
//! use nostr_did_key::{multikey_to_validated_key, ValidatedBip340Key};
//!
//! # #[cfg(feature = "crypto-validation")]
//! let key: ValidatedBip340Key = multikey_to_validated_key(
//!     "fe70102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2"
//! ).unwrap();
//! ```
//!
//! ## Multicodec note
//!
//! This crate follows the current `did:nostr` draft and serializes BIP-340
//! keys using the existing `secp256k1-pub` multicodec (`0xe7 0x01`). The
//! multicodec identifies a compressed secp256k1 public key. BIP-340 keys
//! are represented by reconstructing a compressed SEC1 encoding using the
//! canonical even-parity lift (`0x02 || x`). A dedicated BIP-340 multicodec
//! may eventually provide a more precise semantic identifier.
//!
//! ## Design principles
//!
//! - **Zero dependencies** (without `crypto-validation`) — only `alloc`
//! - **`no_std` compatible** — embedded, WASM, bare-metal
//! - **Stack-allocated final key representation** — `[u8; 32]` for the
//!   decoded x-only key; a single allocation during multibase decode
//! - **Structured errors** — every failure mode has a specific error variant
//! - **Syntactic transform by default** — no crypto operations
//! - **Optional BIP-340 validation** — enable `crypto-validation` feature
//! - **Validation on both encode and decode** — symmetric when enabled
//! - **Type-level validity proof** — `ValidatedBip340Key` avoids re-validation
//! - **Round-trip stable** — `decode(encode(x)) == x` for valid BIP-340 inputs

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::cargo,
    clippy::nursery
)]
#![allow(clippy::module_name_repetitions)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during encoding (hex → Multikey).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// Input is not exactly 64 hex characters (representing 32 bytes).
    InvalidHexLength {
        /// The number of characters received.
        got: usize,
    },

    /// Input contains a non-hex character.
    InvalidHexCharacter {
        /// Byte position in the input where the invalid character was found.
        position: usize,
        /// The invalid character that was encountered.
        character: char,
    },

    /// The input does not represent a valid BIP-340 public key.
    ///
    /// Only returned when the `crypto-validation` feature is enabled.
    InvalidPublicKey,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHexLength { got } => {
                write!(
                    f,
                    "invalid hex length: expected 64 characters (32 bytes), got {got}"
                )
            }
            Self::InvalidHexCharacter {
                position,
                character,
            } => {
                write!(
                    f,
                    "invalid hex character '{character}' at byte position {position}; \
                     expected [0-9a-fA-F]"
                )
            }
            Self::InvalidPublicKey => {
                write!(
                    f,
                    "invalid BIP-340 public key: the value cannot be parsed as a \
                     valid secp256k1 x-only public key"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EncodeError {}

/// Errors that can occur during decoding (Multikey → hex).
///
/// Each variant corresponds to a specific stage in the decode pipeline,
/// enabling precise diagnostics for DID Document debugging.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The multibase prefix is missing or uppercase.
    ///
    /// Expected: lowercase `f` for base16-lower encoding.
    InvalidMultibase,

    /// The hex body of the multibase string is invalid.
    InvalidHex,

    /// The multicodec prefix is missing or incorrect.
    ///
    /// Expected: `0xe7 0x01` for `secp256k1-pub` (compressed).
    InvalidMulticodec,

    /// The parity byte is not `0x02` (even) or `0x03` (odd).
    InvalidParity,

    /// The key data has an incorrect length.
    ///
    /// Expected: exactly 32 bytes after the parity byte.
    InvalidKeyLength,

    /// The key uses odd parity, which is not valid for BIP-340.
    ///
    /// BIP-340 public keys use the even-y lift. An odd-parity encoding
    /// represents a different curve point and therefore a different identity.
    OddParityNotCanonical,

    /// The x-coordinate is not a valid secp256k1 point.
    ///
    /// Only returned when the `crypto-validation` feature is enabled.
    InvalidPublicKey,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMultibase => {
                write!(
                    f,
                    "invalid multibase encoding: expected lowercase 'f' prefix \
                     for base16-lower"
                )
            }
            Self::InvalidHex => {
                write!(f, "invalid hex in multibase string: expected [0-9a-fA-F]")
            }
            Self::InvalidMulticodec => {
                write!(f, "invalid multicodec: expected secp256k1-pub (0xe7 0x01)")
            }
            Self::InvalidParity => {
                write!(f, "invalid parity byte: expected 0x02 (even) or 0x03 (odd)")
            }
            Self::InvalidKeyLength => {
                write!(f, "invalid key length: expected 32 bytes after parity byte")
            }
            Self::OddParityNotCanonical => {
                write!(
                    f,
                    "odd parity is not canonical for BIP-340; the even-y lift \
                     is required"
                )
            }
            Self::InvalidPublicKey => {
                write!(
                    f,
                    "invalid BIP-340 public key: x-coordinate is not a valid \
                     secp256k1 curve point"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}

// ---------------------------------------------------------------------------
// Validated key type (crypto-validation only)
// ---------------------------------------------------------------------------

/// A cryptographically valid BIP-340 public key.
///
/// Obtaining a `ValidatedBip340Key` guarantees that the contained 32-byte
/// value can be parsed as a valid BIP-340 x-only public key by the
/// `secp256k1` crate. This type can be passed to other APIs to avoid
/// redundant re-validation.
///
/// ## What this proves
///
/// - The 32-byte value can be parsed as a valid BIP-340 x-only public key
/// - The x-coordinate corresponds to a valid secp256k1 curve point
/// - The value is not the point at infinity
///
/// ## What this does NOT prove
///
/// - That the caller controls the corresponding private key
/// - DID ownership or Nostr identity control
/// - For possession proof, use Schnorr signature verification with a challenge
///
/// Only available with the `crypto-validation` feature enabled.
#[cfg(feature = "crypto-validation")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedBip340Key {
    bytes: [u8; 32],
}

#[cfg(feature = "crypto-validation")]
impl ValidatedBip340Key {
    /// Attempt to validate a raw 32-byte array as a BIP-340 public key.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::InvalidPublicKey`] if validation fails.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, EncodeError> {
        secp256k1::XOnlyPublicKey::from_slice(&bytes)
            .map(|_| Self { bytes })
            .map_err(|_| EncodeError::InvalidPublicKey)
    }

    /// Validate from a 64-character hex string.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::InvalidHexLength`],
    /// [`EncodeError::InvalidHexCharacter`], or
    /// [`EncodeError::InvalidPublicKey`].
    pub fn from_hex(hex: &str) -> Result<Self, EncodeError> {
        let bytes = decode_hex_32(hex).map_err(EncodeError::from)?;
        Self::from_bytes(bytes)
    }

    /// Return the key as a 64-character lowercase hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        bytes_to_hex(&self.bytes)
    }

    /// Access the raw 32-byte x-only public key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

// ---------------------------------------------------------------------------
// Error conversions
// ---------------------------------------------------------------------------

impl From<HexError> for EncodeError {
    fn from(e: HexError) -> Self {
        match e {
            HexError::InvalidLength { got } => Self::InvalidHexLength { got },
            HexError::InvalidCharacter {
                position,
                character,
            } => Self::InvalidHexCharacter {
                position,
                character,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Internal: key codec abstraction
// ---------------------------------------------------------------------------

/// The key encoding scheme used for multicodec wrapping.
///
/// This abstraction isolates the multicodec prefix from the rest of the
/// pipeline. If a dedicated BIP-340 multicodec is standardized, it can
/// be added as a new variant without breaking the encoder/decoder internals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyCodec {
    /// `secp256k1-pub` — compressed secp256k1 public key (33 bytes).
    ///
    /// Multicodec code: `0xe7 0x01`
    ///
    /// This is the encoding specified by the current `did:nostr` draft.
    /// The multicodec identifies a compressed secp256k1 public key.
    /// BIP-340 keys are represented by reconstructing a compressed SEC1
    /// encoding using the canonical even-parity lift (`0x02 || x`).
    /// A dedicated BIP-340 multicodec may eventually provide a more
    /// precise semantic identifier.
    Secp256k1Pub,
}

impl KeyCodec {
    /// The codec currently used by the `did:nostr` specification.
    const CURRENT: Self = Self::Secp256k1Pub;

    fn prefix(self) -> &'static [u8] {
        match self {
            Self::Secp256k1Pub => &[0xe7, 0x01],
        }
    }

    fn wrap(self, data: &[u8]) -> Vec<u8> {
        let prefix = self.prefix();
        let mut out = Vec::with_capacity(prefix.len() + data.len());
        out.extend_from_slice(prefix);
        out.extend_from_slice(data);
        out
    }

    fn unwrap(self, data: &[u8]) -> Option<&[u8]> {
        let prefix = self.prefix();
        if data.len() < prefix.len() {
            return None;
        }
        if data[..prefix.len()] != *prefix {
            return None;
        }
        Some(&data[prefix.len()..])
    }
}

// ---------------------------------------------------------------------------
// Public API: Serialization
// ---------------------------------------------------------------------------

/// Transform a 64-character hex-encoded BIP-340 x-only public key into a
/// `publicKeyMultibase` string for use in `did:nostr` DID Documents.
///
/// Always uses even parity (`0x02`), the canonical BIP-340 encoding.
///
/// ## Validation scope
///
/// Without the `crypto-validation` feature, this function validates only the
/// **encoding format** (hex length and character set). Any 32-byte value is
/// accepted. With `crypto-validation` enabled, the input is additionally
/// validated as a legitimate BIP-340 public key using the `secp256k1` crate.
///
/// # Errors
///
/// Returns [`EncodeError::InvalidHexLength`] or
/// [`EncodeError::InvalidHexCharacter`] for malformed input. With
/// `crypto-validation`, also returns [`EncodeError::InvalidPublicKey`].
///
/// # Example
///
/// ```rust
/// use nostr_did_key::public_key_to_multikey;
///
/// let multikey = public_key_to_multikey(
///     "124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2"
/// ).unwrap();
///
/// assert_eq!(
///     multikey,
///     "fe70102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2"
/// );
/// ```
#[inline]
pub fn public_key_to_multikey(hex_pubkey: &str) -> Result<String, EncodeError> {
    let raw_bytes = decode_hex_32(hex_pubkey)?;

    #[cfg(feature = "crypto-validation")]
    validate_bip340_xonly(&raw_bytes)?;

    Ok(encode_xonly_to_multikey(&raw_bytes))
}

fn encode_xonly_to_multikey(raw_bytes: &[u8; 32]) -> String {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(raw_bytes);

    let with_multicodec = KeyCodec::CURRENT.wrap(&compressed);
    encode_multibase_base16_lower(&with_multicodec)
}

// ---------------------------------------------------------------------------
// Public API: Deserialization
// ---------------------------------------------------------------------------

/// Decode a `publicKeyMultibase` string and enforce canonical BIP-340 encoding.
///
/// This is the **primary decoder for DID implementers**. It enforces:
///
/// - Valid multibase base16-lower encoding (`f` prefix)
/// - Valid hex body
/// - Correct `secp256k1-pub` multicodec (`0xe7 0x01`)
/// - Valid parity byte (`0x02` or `0x03`)
/// - Correct key length (32 bytes after parity)
/// - **Even parity only** (`0x02`) — odd parity encodes a different point
/// - With `crypto-validation`: validates that the x-coordinate is a valid
///   secp256k1 x-only public key per BIP-340
///
/// # Returns
///
/// Returns a distinct [`DecodeError`] variant for each failure mode,
/// enabling precise diagnostics when debugging DID Documents.
///
/// # Example
///
/// ```rust
/// use nostr_did_key::{public_key_to_multikey, multikey_to_bip340_pubkey};
///
/// let original = "124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";
/// let multikey = public_key_to_multikey(original).unwrap();
/// let recovered = multikey_to_bip340_pubkey(&multikey).unwrap();
///
/// assert_eq!(recovered, original);
/// ```
pub fn multikey_to_bip340_pubkey(multikey: &str) -> Result<String, DecodeError> {
    let decoded = decode_multikey_inner(multikey)?;

    if decoded.parity != 0x02 {
        return Err(DecodeError::OddParityNotCanonical);
    }

    #[cfg(feature = "crypto-validation")]
    {
        ValidatedBip340Key::from_bytes(decoded.x_only)
            .map_err(|_| DecodeError::InvalidPublicKey)?;
    }

    Ok(bytes_to_hex(&decoded.x_only))
}

// ---------------------------------------------------------------------------
// Public API: Validated decode (crypto-validation only)
// ---------------------------------------------------------------------------

/// Decode a `publicKeyMultibase` string and return a cryptographically
/// validated BIP-340 public key.
///
/// Like [`multikey_to_bip340_pubkey`], but returns a [`ValidatedBip340Key`]
/// that can be reused without re-validation.
///
/// Only available with the `crypto-validation` feature enabled.
///
/// # Returns
///
/// Returns a distinct [`DecodeError`] variant for each failure mode.
#[cfg(feature = "crypto-validation")]
pub fn multikey_to_validated_key(multikey: &str) -> Result<ValidatedBip340Key, DecodeError> {
    let decoded = decode_multikey_inner(multikey)?;

    if decoded.parity != 0x02 {
        return Err(DecodeError::OddParityNotCanonical);
    }

    ValidatedBip340Key::from_bytes(decoded.x_only).map_err(|_| DecodeError::InvalidPublicKey)
}

// ---------------------------------------------------------------------------
// Internal: multikey decode
// ---------------------------------------------------------------------------

struct RawDecodedKey {
    x_only: [u8; 32],
    parity: u8,
}

/// Multibase decode error — distinguishes prefix from hex failures.
enum MultibaseDecodeError {
    InvalidPrefix,
    InvalidHex,
}

fn decode_multikey_inner(multikey: &str) -> Result<RawDecodedKey, DecodeError> {
    let bytes = match decode_multibase_base16_lower(multikey) {
        Ok(b) => b,
        Err(MultibaseDecodeError::InvalidPrefix) => {
            return Err(DecodeError::InvalidMultibase);
        }
        Err(MultibaseDecodeError::InvalidHex) => {
            return Err(DecodeError::InvalidHex);
        }
    };

    let key_bytes = KeyCodec::CURRENT
        .unwrap(&bytes)
        .ok_or(DecodeError::InvalidMulticodec)?;

    let parity = *key_bytes.first().ok_or(DecodeError::InvalidKeyLength)?;
    if parity != 0x02 && parity != 0x03 {
        return Err(DecodeError::InvalidParity);
    }

    let x_only_slice = key_bytes.get(1..).ok_or(DecodeError::InvalidKeyLength)?;
    if x_only_slice.len() != 32 {
        return Err(DecodeError::InvalidKeyLength);
    }

    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(x_only_slice);

    Ok(RawDecodedKey { x_only, parity })
}

// ---------------------------------------------------------------------------
// Multibase (base16-lower)
// ---------------------------------------------------------------------------

const MULTIBASE_BASE16_LOWER_PREFIX: char = 'f';

fn encode_multibase_base16_lower(data: &[u8]) -> String {
    let hex = bytes_to_hex(data);
    let mut out = String::with_capacity(1 + hex.len());
    out.push(MULTIBASE_BASE16_LOWER_PREFIX);
    out.push_str(&hex);
    out
}

fn decode_multibase_base16_lower(encoded: &str) -> Result<Vec<u8>, MultibaseDecodeError> {
    let hex = encoded
        .strip_prefix(MULTIBASE_BASE16_LOWER_PREFIX)
        .ok_or(MultibaseDecodeError::InvalidPrefix)?;
    decode_hex_to_bytes(hex).ok_or(MultibaseDecodeError::InvalidHex)
}

// ---------------------------------------------------------------------------
// Hex utilities
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum HexError {
    InvalidLength { got: usize },
    InvalidCharacter { position: usize, character: char },
}

const HEX_NIBBLE: [u8; 256] = {
    let mut table = [0xffu8; 256];
    table[b'0' as usize] = 0x0;
    table[b'1' as usize] = 0x1;
    table[b'2' as usize] = 0x2;
    table[b'3' as usize] = 0x3;
    table[b'4' as usize] = 0x4;
    table[b'5' as usize] = 0x5;
    table[b'6' as usize] = 0x6;
    table[b'7' as usize] = 0x7;
    table[b'8' as usize] = 0x8;
    table[b'9' as usize] = 0x9;
    table[b'a' as usize] = 0xa;
    table[b'b' as usize] = 0xb;
    table[b'c' as usize] = 0xc;
    table[b'd' as usize] = 0xd;
    table[b'e' as usize] = 0xe;
    table[b'f' as usize] = 0xf;
    table[b'A' as usize] = 0xa;
    table[b'B' as usize] = 0xb;
    table[b'C' as usize] = 0xc;
    table[b'D' as usize] = 0xd;
    table[b'E' as usize] = 0xe;
    table[b'F' as usize] = 0xf;
    table
};

const HEX_CHARS: [u8; 16] = [
    b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e', b'f',
];

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(HEX_CHARS[(byte >> 4) as usize]);
        hex.push(HEX_CHARS[(byte & 0x0f) as usize]);
    }
    // SAFETY: HEX_CHARS contains only ASCII bytes 0x30-0x39 and 0x61-0x66.
    // All are valid single-byte UTF-8 code points.
    unsafe { String::from_utf8_unchecked(hex) }
}

fn decode_hex_32(hex: &str) -> Result<[u8; 32], HexError> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return Err(HexError::InvalidLength { got: bytes.len() });
    }

    let mut out = [0u8; 32];

    for i in 0..32 {
        let high = HEX_NIBBLE[bytes[i * 2] as usize];
        let low = HEX_NIBBLE[bytes[i * 2 + 1] as usize];

        if high > 0x0f {
            return Err(HexError::InvalidCharacter {
                position: i * 2,
                character: bytes[i * 2] as char,
            });
        }
        if low > 0x0f {
            return Err(HexError::InvalidCharacter {
                position: i * 2 + 1,
                character: bytes[i * 2 + 1] as char,
            });
        }

        out[i] = (high << 4) | low;
    }

    Ok(out)
}

fn decode_hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }

    let mut out = Vec::with_capacity(bytes.len() / 2);

    for chunk in bytes.chunks(2) {
        let high = HEX_NIBBLE[chunk[0] as usize];
        let low = HEX_NIBBLE[chunk[1] as usize];

        if high > 0x0f || low > 0x0f {
            return None;
        }

        out.push((high << 4) | low);
    }

    Some(out)
}

// ---------------------------------------------------------------------------
// Validation (internal)
// ---------------------------------------------------------------------------

#[cfg(feature = "crypto-validation")]
fn validate_bip340_xonly(bytes: &[u8; 32]) -> Result<(), EncodeError> {
    secp256k1::XOnlyPublicKey::from_slice(bytes)
        .map(|_| ())
        .map_err(|_| EncodeError::InvalidPublicKey)
}

#[cfg(not(feature = "crypto-validation"))]
#[allow(dead_code)]
fn validate_bip340_xonly(_bytes: &[u8; 32]) -> Result<(), EncodeError> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC_HEX_PUBKEY: &str =
        "124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";

    const SPEC_EXPECTED_MULTIKEY: &str =
        "fe70102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";

    // -------------------------------------------------------------------
    // Spec conformance
    // -------------------------------------------------------------------

    #[test]
    fn spec_vector_encode() {
        let result = public_key_to_multikey(SPEC_HEX_PUBKEY).unwrap();
        assert_eq!(result, SPEC_EXPECTED_MULTIKEY);
    }

    // -------------------------------------------------------------------
    // Round-trip
    // -------------------------------------------------------------------

    #[test]
    fn roundtrip_spec_key() {
        let multikey = public_key_to_multikey(SPEC_HEX_PUBKEY).unwrap();
        let recovered = multikey_to_bip340_pubkey(&multikey).unwrap();
        assert_eq!(recovered, SPEC_HEX_PUBKEY);
    }

    #[test]
    fn roundtrip_all_zeros() {
        let zeros = "0000000000000000000000000000000000000000000000000000000000000000";
        let multikey = public_key_to_multikey(zeros).unwrap();
        let recovered = multikey_to_bip340_pubkey(&multikey).unwrap();
        assert_eq!(recovered, zeros);
    }

    #[test]
    fn roundtrip_all_ff() {
        let ff = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let multikey = public_key_to_multikey(ff).unwrap();
        let recovered = multikey_to_bip340_pubkey(&multikey).unwrap();
        assert_eq!(recovered, ff);
    }

    // -------------------------------------------------------------------
    // BIP-340 decoder rejects odd parity
    // -------------------------------------------------------------------

    #[test]
    fn bip340_decoder_rejects_odd_parity() {
        let raw = decode_hex_32(SPEC_HEX_PUBKEY).unwrap();
        let mut compressed = [0u8; 33];
        compressed[0] = 0x03;
        compressed[1..].copy_from_slice(&raw);
        let with_codec = KeyCodec::CURRENT.wrap(&compressed);
        let odd_multikey = encode_multibase_base16_lower(&with_codec);

        let result = multikey_to_bip340_pubkey(&odd_multikey);
        assert!(matches!(result, Err(DecodeError::OddParityNotCanonical)));
    }

    // -------------------------------------------------------------------
    // Structured decode errors — every variant is reachable
    // -------------------------------------------------------------------

    #[test]
    fn decode_error_invalid_multibase_missing_prefix() {
        let result = multikey_to_bip340_pubkey("abc123");
        assert!(matches!(result, Err(DecodeError::InvalidMultibase)));
    }

    #[test]
    fn decode_error_invalid_multibase_uppercase() {
        let upper = SPEC_EXPECTED_MULTIKEY.to_uppercase();
        let result = multikey_to_bip340_pubkey(&upper);
        assert!(matches!(result, Err(DecodeError::InvalidMultibase)));
    }

    #[test]
    fn decode_error_invalid_hex() {
        // Correct prefix, but non-hex body
        let result = multikey_to_bip340_pubkey("fggg");
        assert!(matches!(result, Err(DecodeError::InvalidHex)));
    }

    #[test]
    fn decode_error_invalid_multicodec() {
        let bogus = "f000102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";
        let result = multikey_to_bip340_pubkey(bogus);
        assert!(matches!(result, Err(DecodeError::InvalidMulticodec)));
    }

    #[test]
    fn decode_error_invalid_parity() {
        let result = multikey_to_bip340_pubkey("fe70104");
        assert!(matches!(result, Err(DecodeError::InvalidParity)));
    }

    #[test]
    fn decode_error_invalid_key_length() {
        let result = multikey_to_bip340_pubkey("fe70102");
        assert!(matches!(result, Err(DecodeError::InvalidKeyLength)));
    }

    #[test]
    fn decode_error_empty() {
        let result = multikey_to_bip340_pubkey("");
        assert!(matches!(result, Err(DecodeError::InvalidMultibase)));
    }

    // -------------------------------------------------------------------
    // Encode errors
    // -------------------------------------------------------------------

    #[test]
    fn encode_error_invalid_hex_length_too_short() {
        let result = public_key_to_multikey("abc123");
        assert!(matches!(
            result,
            Err(EncodeError::InvalidHexLength { got: 6 })
        ));
    }

    #[test]
    fn encode_error_invalid_hex_length_too_long() {
        let long = "124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd20000";
        let result = public_key_to_multikey(long);
        assert!(matches!(
            result,
            Err(EncodeError::InvalidHexLength { got: 68 })
        ));
    }

    #[test]
    fn encode_error_invalid_hex_length_empty() {
        let result = public_key_to_multikey("");
        assert!(matches!(
            result,
            Err(EncodeError::InvalidHexLength { got: 0 })
        ));
    }

    #[test]
    fn encode_error_invalid_hex_character() {
        let mut input = String::from(SPEC_HEX_PUBKEY);
        input.replace_range(0..1, "g");
        let result = public_key_to_multikey(&input);
        assert!(matches!(
            result,
            Err(EncodeError::InvalidHexCharacter { .. })
        ));
    }

    #[test]
    fn encode_error_all_garbage_hex() {
        let all_g = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
        let result = public_key_to_multikey(all_g);
        assert!(matches!(
            result,
            Err(EncodeError::InvalidHexCharacter { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Output format invariants
    // -------------------------------------------------------------------

    #[test]
    fn multikey_starts_with_f() {
        let result = public_key_to_multikey(SPEC_HEX_PUBKEY).unwrap();
        assert!(result.starts_with('f'));
    }

    #[test]
    fn multikey_all_lowercase() {
        let result = public_key_to_multikey(SPEC_HEX_PUBKEY).unwrap();
        let body = &result[1..];
        assert!(body
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn multikey_exact_length() {
        let result = public_key_to_multikey(SPEC_HEX_PUBKEY).unwrap();
        assert_eq!(result.len(), 71);
    }

    // -------------------------------------------------------------------
    // Determinism
    // -------------------------------------------------------------------

    #[test]
    fn encoding_is_deterministic() {
        let a = public_key_to_multikey(SPEC_HEX_PUBKEY).unwrap();
        let b = public_key_to_multikey(SPEC_HEX_PUBKEY).unwrap();
        assert_eq!(a, b);
    }

    // -------------------------------------------------------------------
    // Case-insensitive hex input
    // -------------------------------------------------------------------

    #[test]
    fn accepts_uppercase_hex() {
        let upper = "124C0FA99407182ECE5A24FAD9B7F6674902FC422843D3128D38A0AFBEE0FDD2";
        let result = public_key_to_multikey(upper).unwrap();
        assert_eq!(result, SPEC_EXPECTED_MULTIKEY);
    }

    #[test]
    fn accepts_mixed_case_hex() {
        let mixed = "124c0fa99407182ece5a24fAD9B7F6674902FC422843d3128d38a0afbee0fdd2";
        let result = public_key_to_multikey(mixed).unwrap();
        assert_eq!(result, SPEC_EXPECTED_MULTIKEY);
    }

    // -------------------------------------------------------------------
    // bytes_to_hex safety
    // -------------------------------------------------------------------

    #[test]
    fn bytes_to_hex_all_byte_values() {
        let bytes: Vec<u8> = (0..=255).collect();
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex.len(), 512);
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    // -------------------------------------------------------------------
    // Display impls
    // -------------------------------------------------------------------

    #[test]
    fn decode_error_display_includes_invalid_hex() {
        let msg = format!("{}", DecodeError::InvalidHex);
        assert!(!msg.is_empty());
        assert!(msg.contains("hex"));
    }

    #[test]
    fn all_decode_errors_have_display() {
        let errors = [
            DecodeError::InvalidMultibase,
            DecodeError::InvalidHex,
            DecodeError::InvalidMulticodec,
            DecodeError::InvalidParity,
            DecodeError::InvalidKeyLength,
            DecodeError::OddParityNotCanonical,
        ];
        for err in &errors {
            assert!(!format!("{err}").is_empty());
        }
    }

    #[test]
    fn all_encode_errors_have_display() {
        let errors = [
            EncodeError::InvalidHexLength { got: 0 },
            EncodeError::InvalidHexCharacter {
                position: 0,
                character: 'z',
            },
        ];
        for err in &errors {
            assert!(!format!("{err}").is_empty());
        }
    }

    // -------------------------------------------------------------------
    // Crypto-validation feature tests
    // -------------------------------------------------------------------

    #[cfg(feature = "crypto-validation")]
    mod crypto_tests {
        use super::*;

        #[test]
        fn validate_spec_key() {
            let key = ValidatedBip340Key::from_hex(SPEC_HEX_PUBKEY).unwrap();
            assert_eq!(key.to_hex(), SPEC_HEX_PUBKEY);
        }

        #[test]
        fn encode_rejects_point_ge_modulus() {
            let p_plus_one = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30";
            let result = public_key_to_multikey(p_plus_one);
            assert!(matches!(result, Err(EncodeError::InvalidPublicKey)));
        }

        #[test]
        fn decode_rejects_point_ge_modulus() {
            let p_plus_one = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30";
            let raw = decode_hex_32(p_plus_one).unwrap();
            let multikey = encode_xonly_to_multikey(&raw);
            let result = multikey_to_bip340_pubkey(&multikey);
            assert!(matches!(result, Err(DecodeError::InvalidPublicKey)));
        }

        #[test]
        fn validated_key_from_bytes() {
            let raw = decode_hex_32(SPEC_HEX_PUBKEY).unwrap();
            let key = ValidatedBip340Key::from_bytes(raw).unwrap();
            assert_eq!(key.as_bytes(), &raw);
        }

        #[test]
        fn validated_key_roundtrip_hex() {
            let key = ValidatedBip340Key::from_hex(SPEC_HEX_PUBKEY).unwrap();
            assert_eq!(key.to_hex(), SPEC_HEX_PUBKEY);
        }

        #[test]
        fn multikey_to_validated_key_roundtrip() {
            let multikey = public_key_to_multikey(SPEC_HEX_PUBKEY).unwrap();
            let key = multikey_to_validated_key(&multikey).unwrap();
            assert_eq!(key.to_hex(), SPEC_HEX_PUBKEY);
        }

        #[test]
        fn multikey_to_validated_key_rejects_odd_parity() {
            let raw = decode_hex_32(SPEC_HEX_PUBKEY).unwrap();
            let mut compressed = [0u8; 33];
            compressed[0] = 0x03;
            compressed[1..].copy_from_slice(&raw);
            let with_codec = KeyCodec::CURRENT.wrap(&compressed);
            let odd_multikey = encode_multibase_base16_lower(&with_codec);

            let result = multikey_to_validated_key(&odd_multikey);
            assert!(matches!(result, Err(DecodeError::OddParityNotCanonical)));
        }

        #[test]
        fn decode_error_display_includes_invalid_public_key() {
            assert!(!format!("{}", DecodeError::InvalidPublicKey).is_empty());
        }

        #[test]
        fn encode_error_display_includes_invalid_public_key() {
            assert!(!format!("{}", EncodeError::InvalidPublicKey).is_empty());
        }
    }
}
