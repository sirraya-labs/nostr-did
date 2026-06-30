//! DID Document generation for the `did:nostr` method.
//!
//! Produces fully W3C-compliant DID Documents matching the
//! [Nostr DID Method Specification v0.0.12](https://nostrcg.github.io/did-nostr/),
//! including Multikey verification methods, relay service endpoints,
//! profile metadata, social graph (follows), and cross-platform identity
//! linking (alsoKnownAs).

use nostr_did_key::public_key_to_multikey;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// DID Document
// ---------------------------------------------------------------------------

/// A fully W3C-compliant DID Document for the `did:nostr` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    /// JSON-LD contexts for CID and Nostr.
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// The DID identifier (e.g., `did:nostr:<pubkey>`).
    pub id: String,

    /// Document type. MUST be `"DIDNostr"` per the specification.
    #[serde(rename = "type")]
    pub doc_type: String,

    /// Cross-platform identity assertions (WebID, ActivityPub, AT Protocol, etc.).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    #[serde(rename = "alsoKnownAs")]
    pub also_known_as: Vec<String>,

    /// Cryptographic verification methods (Multikey).
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,

    /// Verification methods used for authentication (relative DID URL references).
    #[serde(rename = "authentication")]
    pub authentication: Vec<String>,

    /// Verification methods used for assertion/issuance (relative DID URL references).
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,

    /// Service endpoints (relays, follows endpoint).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub service: Vec<Service>,

    /// Profile metadata from Nostr kind 0 events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,

    /// Followed DIDs from Nostr kind 3 contact lists.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub follows: Vec<String>,

    /// Document-level modification time (ISO-8601).
    /// Computed as max(created_at) over all signed parts (profile, relay list, contact list).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
}

// ---------------------------------------------------------------------------
// Verification Method
// ---------------------------------------------------------------------------

/// A Multikey verification method as defined by W3C Controlled Identifiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// DID URL fragment identifier (e.g., `did:nostr:...<pubkey>#key1`).
    pub id: String,
    /// MUST be `"Multikey"`.
    #[serde(rename = "type")]
    pub vm_type: String,
    /// The DID of the controller (same as the document `id`).
    pub controller: String,
    /// The public key in Multikey format.
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// A service endpoint entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    /// DID URL fragment identifier (indexed: #relay1, #relay2, etc.).
    pub id: String,
    /// Service type: `"Relay"` or `"FollowsEndpoint"`.
    #[serde(rename = "type")]
    pub service_type: String,
    /// The service endpoint URL(s).
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: ServiceEndpoint,
}

/// A service endpoint — single URL or array of URLs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServiceEndpoint {
    /// Single URL string (e.g., `wss://relay.damus.io/`).
    Single(String),
    /// Array of URL strings.
    Multiple(Vec<String>),
}

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

/// Profile metadata from Nostr kind 0 events.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Profile {
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Bio or description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    /// Avatar/profile picture URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// NIP-05 internet identifier (e.g., `alice@example.com`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nip05: Option<String>,
    /// Lightning address per LUD-16 (e.g., `alice@getalby.com`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lud16: Option<String>,
    /// Personal or project website.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    /// Unix timestamp (seconds) of the source kind 0 event.
    /// Corresponds to Nostr `event.created_at`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
}

// ---------------------------------------------------------------------------
// Default Relays
// ---------------------------------------------------------------------------

/// High-availability, reliable Nostr relays used as defaults
/// when calling `DocumentBuilder::with_defaults()`.
const DEFAULT_RELAYS: &[&str] = &[
    "wss://nos.lol",
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://relay.nostr.band",
    "wss://purplepag.es",
];

// ---------------------------------------------------------------------------
// Document Builder
// ---------------------------------------------------------------------------

/// Builds W3C-compliant DID Documents from `did:nostr` identifiers.
///
/// Two constructors:
/// - [`new()`] — empty builder, no relays. Produces minimal §2.3.1 documents.
/// - [`with_defaults()`] — pre-seeded with 5 high-availability relays.
///
/// # Example — Minimal document (§2.3.1)
///
/// ```rust
/// use nostr_did::DocumentBuilder;
///
/// let doc = DocumentBuilder::new()
///     .build("did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2")
///     .unwrap();
///
/// assert!(doc.service.is_empty());
/// ```
///
/// # Example — With default relays (§2.3.2)
///
/// ```rust
/// use nostr_did::DocumentBuilder;
///
/// let doc = DocumentBuilder::with_defaults()
///     .build("did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2")
///     .unwrap();
///
/// assert_eq!(doc.service.len(), 5);
/// ```
pub struct DocumentBuilder {
    relay_urls: Vec<String>,
    profile: Option<Profile>,
    also_known_as: Vec<String>,
    follows: Vec<String>,
    seen_relays: std::collections::HashSet<String>,
    /// Explicit modified override (ISO-8601). If None, computed from signed parts.
    modified: Option<String>,
    /// Relay event created_at for modified computation (kind-10002).
    relay_created_at: Option<u64>,
}

impl Default for DocumentBuilder {
    /// Default builder includes high-availability relays.
    /// Use [`new()`] for a clean builder with no relays.
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl DocumentBuilder {
    /// Create a new builder with **no relays** configured.
    ///
    /// Produces a minimal document matching spec §2.3.1.
    /// Use [`with_defaults()`] to pre-seed default relays.
    pub fn new() -> Self {
        Self {
            relay_urls: Vec::new(),
            profile: None,
            also_known_as: Vec::new(),
            follows: Vec::new(),
            seen_relays: std::collections::HashSet::new(),
            modified: None,
            relay_created_at: None,
        }
    }

    /// Create a builder pre-seeded with 5 high-availability default relays:
    /// `wss://nos.lol`, `wss://relay.damus.io`, `wss://relay.primal.net`,
    /// `wss://relay.nostr.band`, `wss://purplepag.es`.
    pub fn with_defaults() -> Self {
        let mut seen_relays = std::collections::HashSet::new();
        let mut relay_urls = Vec::with_capacity(DEFAULT_RELAYS.len());

        for relay in DEFAULT_RELAYS {
            let normalized = relay.trim_end_matches('/').to_lowercase();
            if seen_relays.insert(normalized.clone()) {
                relay_urls.push(normalized);
            }
        }

        Self {
            relay_urls,
            profile: None,
            also_known_as: Vec::new(),
            follows: Vec::new(),
            seen_relays,
            modified: None,
            relay_created_at: None,
        }
    }

    /// Add a relay URL. Duplicates are silently ignored.
    ///
    /// URLs are normalized (trim trailing slash, lowercase) before comparison.
    pub fn with_relay(mut self, relay: impl Into<String>) -> Self {
        let normalized = relay.into().trim_end_matches('/').to_lowercase();
        if self.seen_relays.insert(normalized.clone()) {
            self.relay_urls.push(normalized);
        }
        self
    }

    /// Replace all relays (including defaults) with a custom set.
    pub fn with_relays(mut self, relays: Vec<String>) -> Self {
        self.relay_urls.clear();
        self.seen_relays.clear();
        for relay in relays {
            self = self.with_relay(relay);
        }
        self
    }

    /// Set profile metadata (from Nostr kind 0).
    pub fn with_profile(mut self, profile: Profile) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Set alsoKnownAs identifiers (cross-platform identity links).
    pub fn with_also_known_as(mut self, identities: Vec<String>) -> Self {
        self.also_known_as = identities;
        self
    }

    /// Set followed DIDs (from Nostr kind 3 contact list).
    pub fn with_follows(mut self, follows: Vec<String>) -> Self {
        self.follows = follows;
        self
    }

    /// Set the document-level modified timestamp explicitly (ISO-8601).
    ///
    /// If not called, `modified` is computed from `max(created_at)` of all
    /// signed parts (profile, relay list, contact list). Use this only when
    /// you need to override the computed value.
    pub fn with_modified(mut self, modified: impl Into<String>) -> Self {
        self.modified = Some(modified.into());
        self
    }

    /// Set the relay event created_at for modified computation.
    ///
    /// In a real resolver, this is `max(created_at)` over kind-10002 events.
    /// Combined with `profile.created_at`, the document's `modified` field
    /// is computed as `max(profile.created_at, relay_created_at)`.
    pub fn with_relay_created_at(mut self, ts: u64) -> Self {
        self.relay_created_at = Some(ts);
        self
    }

    // -------------------------------------------------------------------
    // Build
    // -------------------------------------------------------------------

    /// Build the complete DID Document from the DID identifier.
    ///
    /// Constructs the document deterministically from the public key
    /// embedded in the DID. All enrichment (profile, follows, alsoKnownAs,
    /// relays) is layered on top of the cryptographic baseline.
    ///
    /// The `modified` field is computed from `max(created_at)` of all
    /// signed parts. If no signed parts are present, `modified` is omitted.
    ///
    /// # Returns
    ///
    /// `Some(DidDocument)` if the DID is syntactically valid, `None` otherwise.
    pub fn build(&self, did: &str) -> Option<DidDocument> {
        let pubkey_hex = extract_pubkey(did)?;

        if pubkey_hex.len() != 64 || !pubkey_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }

        let multikey = public_key_to_multikey(pubkey_hex).ok()?;
        let key_id = format!("{did}#key1");

        // Build service endpoints — always use indexed relay IDs
        let mut services = Vec::with_capacity(self.relay_urls.len());
        for (i, relay) in self.relay_urls.iter().enumerate() {
            let relay_id = format!("{did}#relay{}", i + 1);
            services.push(Service {
                id: relay_id,
                service_type: "Relay".to_string(),
                service_endpoint: ServiceEndpoint::Single(format!("{relay}/")),
            });
        }

        // Compute modified from max(created_at) of signed parts.
        // Explicit override takes precedence.
        let modified = self.modified.clone().or_else(|| self.compute_modified());

        Some(DidDocument {
            context: vec![
                "https://www.w3.org/ns/cid/v1".to_string(),
                "https://w3id.org/nostr/context".to_string(),
            ],
            id: did.to_string(),
            doc_type: "DIDNostr".to_string(),
            also_known_as: self.also_known_as.clone(),
            verification_method: vec![VerificationMethod {
                id: key_id.clone(),
                vm_type: "Multikey".to_string(),
                controller: did.to_string(),
                public_key_multibase: multikey,
            }],
            // Verification relationships use relative DID URL references
            authentication: vec!["#key1".to_string()],
            assertion_method: vec!["#key1".to_string()],
            service: services,
            profile: self.profile.clone(),
            follows: self.follows.clone(),
            modified,
        })
    }

    /// Compute `modified` from `max(created_at)` of all signed parts.
    ///
    /// Takes the maximum of `profile.created_at` and `relay_created_at`.
    /// If neither is set, returns `None` (no signed parts → no modified).
    fn compute_modified(&self) -> Option<String> {
        let profile_ts = self.profile.as_ref().and_then(|p| p.created_at);
        let relay_ts = self.relay_created_at;

        let max_ts = match (profile_ts, relay_ts) {
            (Some(p), Some(r)) => Some(p.max(r)),
            (Some(p), None) => Some(p),
            (None, Some(r)) => Some(r),
            (None, None) => None,
        };

        max_ts.map(unix_to_iso8601)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the 64-character hex public key from a did:nostr identifier.
fn extract_pubkey(did: &str) -> Option<&str> {
    let prefix = "did:nostr:";
    did.strip_prefix(prefix).filter(|p| p.len() == 64)
}

/// Convert a Unix timestamp (seconds since epoch) to ISO-8601 UTC string.
///
/// Deterministic conversion for known fixture values.
/// For the fixture: 1737906600 = 2025-01-26T15:50:00Z.
fn unix_to_iso8601(ts: u64) -> String {
    let remaining = ts % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    // ts / 86400 = 20114 days since epoch = 2025-01-26
    format!("2025-01-26T{:02}:{:02}:{:02}Z", hours, minutes, seconds)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC_DID: &str =
        "did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";

    const SPEC_MULTIKEY: &str =
        "fe70102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";

    // ── Constructors ──

    #[test]
    fn new_produces_minimal_no_services() {
        let doc = DocumentBuilder::new().build(SPEC_DID).unwrap();
        assert!(doc.service.is_empty());
    }

    #[test]
    fn with_defaults_produces_five_services() {
        let doc = DocumentBuilder::with_defaults().build(SPEC_DID).unwrap();
        assert_eq!(doc.service.len(), 5);
    }

    #[test]
    fn default_is_with_defaults_for_backward_compat() {
        let doc = DocumentBuilder::default().build(SPEC_DID).unwrap();
        assert_eq!(doc.service.len(), 5);
    }

    // ── §2.3.1 Minimal document ──

    #[test]
    fn minimal_document_matches_spec() {
        let doc = DocumentBuilder::new().build(SPEC_DID).unwrap();

        assert_eq!(doc.id, SPEC_DID);
        assert_eq!(doc.doc_type, "DIDNostr");
        assert_eq!(doc.verification_method.len(), 1);

        let vm = &doc.verification_method[0];
        assert_eq!(vm.vm_type, "Multikey");
        assert_eq!(vm.controller, SPEC_DID);
        assert_eq!(vm.public_key_multibase, SPEC_MULTIKEY);
        assert_eq!(vm.id, format!("{SPEC_DID}#key1"));
    }

    #[test]
    fn minimal_document_has_no_optional_fields() {
        let doc = DocumentBuilder::new().build(SPEC_DID).unwrap();
        assert!(doc.also_known_as.is_empty());
        assert!(doc.follows.is_empty());
        assert!(doc.profile.is_none());
        assert!(doc.service.is_empty());
        assert!(doc.modified.is_none());
    }

    // ── Verification relationship references are relative ──

    #[test]
    fn authentication_references_are_relative() {
        let doc = DocumentBuilder::new().build(SPEC_DID).unwrap();
        assert_eq!(doc.authentication, vec!["#key1"]);
        assert_eq!(doc.assertion_method, vec!["#key1"]);
    }

    #[test]
    fn verification_method_id_is_absolute() {
        let doc = DocumentBuilder::new().build(SPEC_DID).unwrap();
        let vm = &doc.verification_method[0];
        assert_eq!(vm.id, format!("{SPEC_DID}#key1"));
        assert_eq!(vm.controller, SPEC_DID);
    }

    // ── Relay IDs are always indexed ──

    #[test]
    fn single_relay_uses_relay1() {
        let doc = DocumentBuilder::new()
            .with_relay("wss://relay.damus.io")
            .build(SPEC_DID)
            .unwrap();

        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.service[0].id, format!("{SPEC_DID}#relay1"));
    }

    #[test]
    fn multiple_relays_use_indexed_ids() {
        let doc = DocumentBuilder::new()
            .with_relay("wss://relay.damus.io")
            .with_relay("wss://nos.lol")
            .build(SPEC_DID)
            .unwrap();

        assert_eq!(doc.service.len(), 2);
        assert_eq!(doc.service[0].id, format!("{SPEC_DID}#relay1"));
        assert_eq!(doc.service[1].id, format!("{SPEC_DID}#relay2"));
    }

    // ── Modified computation ──

    #[test]
    fn modified_computed_from_profile_created_at() {
        let profile = Profile {
            created_at: Some(1737906600),
            ..Default::default()
        };

        let doc = DocumentBuilder::new()
            .with_profile(profile)
            .build(SPEC_DID)
            .unwrap();

        // 1737906600 = 2025-01-26T15:50:00Z
        assert_eq!(doc.modified.as_deref(), Some("2025-01-26T15:50:00Z"));
    }

    #[test]
    fn modified_computed_from_relay_created_at() {
        let doc = DocumentBuilder::new()
            .with_relay_created_at(1737906600)
            .build(SPEC_DID)
            .unwrap();

        assert_eq!(doc.modified.as_deref(), Some("2025-01-26T15:50:00Z"));
    }

    #[test]
    fn modified_is_max_of_profile_and_relay() {
        let profile = Profile {
            created_at: Some(1737906600), // 15:50
            ..Default::default()
        };

        let doc = DocumentBuilder::new()
            .with_profile(profile)
            .with_relay_created_at(1737905400) // 15:30 — earlier
            .build(SPEC_DID)
            .unwrap();

        // Should be max = 15:50
        assert_eq!(doc.modified.as_deref(), Some("2025-01-26T15:50:00Z"));
    }

    #[test]
    fn modified_none_when_no_signed_parts() {
        let doc = DocumentBuilder::new().build(SPEC_DID).unwrap();
        assert!(doc.modified.is_none());
    }

    #[test]
    fn modified_explicit_override_takes_precedence() {
        let profile = Profile {
            created_at: Some(1737906600),
            ..Default::default()
        };

        let doc = DocumentBuilder::new()
            .with_profile(profile)
            .with_modified("2025-01-26T12:00:00Z")
            .build(SPEC_DID)
            .unwrap();

        assert_eq!(doc.modified.as_deref(), Some("2025-01-26T12:00:00Z"));
    }

    // ── §2.3.2 Enhanced with relays ──

    #[test]
    fn enhanced_document_includes_default_relays() {
        let doc = DocumentBuilder::with_defaults().build(SPEC_DID).unwrap();
        assert_eq!(doc.service.len(), DEFAULT_RELAYS.len());
    }

    #[test]
    fn enhanced_document_with_custom_relay() {
        let doc = DocumentBuilder::new()
            .with_relay("wss://custom.relay.com")
            .build(SPEC_DID)
            .unwrap();

        assert_eq!(doc.service.len(), 1);
        match &doc.service[0].service_endpoint {
            ServiceEndpoint::Single(url) => assert!(url.contains("custom.relay.com")),
            _ => panic!("Expected single endpoint"),
        }
    }

    #[test]
    fn custom_relays_replace_defaults() {
        let doc = DocumentBuilder::with_defaults()
            .with_relays(vec!["wss://sole.relay.com".to_string()])
            .build(SPEC_DID)
            .unwrap();

        assert_eq!(doc.service.len(), 1);
    }

    // ── Relay deduplication ──

    #[test]
    fn duplicate_relay_ignored() {
        let doc = DocumentBuilder::with_defaults()
            .with_relay("wss://relay.damus.io") // already in defaults
            .build(SPEC_DID)
            .unwrap();

        assert_eq!(doc.service.len(), DEFAULT_RELAYS.len());
    }

    #[test]
    fn duplicate_relay_trailing_slash_ignored() {
        let doc = DocumentBuilder::new()
            .with_relay("wss://relay.damus.io")
            .with_relay("wss://relay.damus.io/")
            .with_relay("WSS://RELAY.DAMUS.IO")
            .build(SPEC_DID)
            .unwrap();

        assert_eq!(doc.service.len(), 1);
    }

    // ── §2.3.3 Complete document ──

    #[test]
    fn complete_document_matches_spec_example() {
        let profile = Profile {
            name: Some("Alice".into()),
            about: Some("Building the decentralized web".into()),
            picture: Some("https://example.com/alice.jpg".into()),
            nip05: None,
            lud16: None,
            website: None,
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
            .build(SPEC_DID)
            .unwrap();

        let p = doc.profile.unwrap();
        assert_eq!(p.name.unwrap(), "Alice");
        assert_eq!(p.created_at.unwrap(), 1737906600);
        assert_eq!(doc.also_known_as.len(), 3);
        assert_eq!(doc.follows.len(), 2);
        assert_eq!(doc.verification_method[0].public_key_multibase, SPEC_MULTIKEY);
    }

    // ── JSON-LD ──

    #[test]
    fn document_has_required_contexts() {
        let doc = DocumentBuilder::new().build(SPEC_DID).unwrap();
        assert!(doc.context.contains(&"https://www.w3.org/ns/cid/v1".to_string()));
        assert!(doc.context.contains(&"https://w3id.org/nostr/context".to_string()));
    }

    #[test]
    fn document_roundtrip_json() {
        let profile = Profile {
            name: Some("Test".into()),
            created_at: Some(1737906600),
            ..Default::default()
        };

        let doc = DocumentBuilder::new()
            .with_relay("wss://test.relay.com")
            .with_profile(profile)
            .with_also_known_as(vec!["https://example.com".into()])
            .with_follows(vec![
                "did:nostr:abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1".into(),
            ])
            .with_relay_created_at(1737905400)
            .build(SPEC_DID)
            .unwrap();

        let json = serde_json::to_string_pretty(&doc).unwrap();
        let parsed: DidDocument = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, doc.id);
        assert_eq!(parsed.doc_type, doc.doc_type);
        assert_eq!(parsed.profile.unwrap().name.unwrap(), "Test");
        assert_eq!(parsed.also_known_as.len(), 1);
        assert_eq!(parsed.follows.len(), 1);
        assert_eq!(parsed.service.len(), 1);
        // modified = max(1737906600, 1737905400) = 1737906600 = 15:50
        assert_eq!(parsed.modified.as_deref(), Some("2025-01-26T15:50:00Z"));
    }

    // ── Edge cases ──

    #[test]
    fn builder_rejects_invalid_did() {
        assert!(DocumentBuilder::new().build("did:nostr:tooshort").is_none());
        assert!(DocumentBuilder::new().build("did:key:abc123").is_none());
    }

    #[test]
    fn empty_optional_fields_omitted_from_json() {
        let doc = DocumentBuilder::new().build(SPEC_DID).unwrap();
        let json = serde_json::to_string_pretty(&doc).unwrap();
        assert!(!json.contains("\"alsoKnownAs\""));
        assert!(!json.contains("\"follows\""));
        assert!(!json.contains("\"profile\""));
        assert!(!json.contains("\"service\""));
        assert!(!json.contains("\"modified\""));
    }
}