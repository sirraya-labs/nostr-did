//! DID Document generation for the `did:nostr` method.
//!
//! Produces fully W3C-compliant DID Documents matching the
//! [Nostr DID Method Specification v0.0.11](https://nostrcg.github.io/did-nostr/),
//! including Multikey verification methods, relay service endpoints,
//! profile metadata, social graph (follows), and cross-platform identity
//! linking (alsoKnownAs).

use nostr_did_key::public_key_to_multikey;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// DID Document
// ---------------------------------------------------------------------------

/// A fully W3C-compliant DID Document for the `did:nostr` method.
///
/// Implements all fields defined in the Nostr DID Method Specification
/// v0.0.11: `@context`, `id`, `type`, `alsoKnownAs`, `verificationMethod`,
/// `authentication`, `assertionMethod`, `service`, `profile`, and `follows`.
///
/// # Example (Minimal — spec §2.3.1)
///
/// ```json
/// {
///   "@context": [
///     "https://www.w3.org/ns/did/v1",
///     "https://w3id.org/nostr/context"
///   ],
///   "id": "did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2",
///   "type": "DIDNostr",
///   "verificationMethod": [
///     {
///       "id": "did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2#key1",
///       "type": "Multikey",
///       "controller": "did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2",
///       "publicKeyMultibase": "fe70102124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2"
///     }
///   ],
///   "authentication": ["did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2#key1"],
///   "assertionMethod": ["did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2#key1"]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    /// JSON-LD contexts for DID Core and Nostr.
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

    /// Verification methods used for authentication.
    #[serde(rename = "authentication")]
    pub authentication: Vec<String>,

    /// Verification methods used for assertion/issuance.
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
}

// ---------------------------------------------------------------------------
// Verification Method
// ---------------------------------------------------------------------------

/// A Multikey verification method as defined by W3C Controlled Identifiers.
///
/// Uses the `publicKeyMultibase` property with a multicodec-wrapped,
/// multibase-encoded compressed secp256k1 public key.
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
///
/// Per the did:nostr spec, service types include:
/// - `"Relay"` — a Nostr relay WebSocket URL
/// - `"FollowsEndpoint"` — an HTTP endpoint for retrieving the full follow list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    /// DID URL fragment identifier.
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
///
/// All fields are optional. The `timestamp` field contains the
/// `created_at` value from the source Nostr event (Unix seconds),
/// enabling cache freshness checks.
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
    pub timestamp: Option<u64>,
}

// ---------------------------------------------------------------------------
// Default Relays
// ---------------------------------------------------------------------------

/// High-availability, reliable Nostr relays used as defaults.
///
/// Sourced from active public relays with near 100% uptime:
/// - `wss://nos.lol` — General purpose, high uptime
/// - `wss://relay.damus.io` — General purpose, Damus ecosystem
/// - `wss://relay.primal.net` — General purpose, Primal ecosystem
/// - `wss://relay.nostr.band` — Full-text search, network trends
/// - `wss://purplepag.es` — Long-form content, user profiles
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
/// Uses `nostr-did-key` for BIP-340 → Multikey cryptographic transformation
/// and produces documents matching the Nostr DID Method Specification v0.0.11.
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
/// assert_eq!(doc.doc_type, "DIDNostr");
/// assert_eq!(doc.verification_method[0].vm_type, "Multikey");
/// ```
///
/// # Example — Complete document (§2.3.3)
///
/// ```rust
/// use nostr_did::{DocumentBuilder, Profile};
///
/// let profile = Profile {
///     name: Some("Alice".into()),
///     about: Some("Building the decentralized web".into()),
///     picture: Some("https://example.com/alice.jpg".into()),
///     nip05: Some("alice@example.com".into()),
///     lud16: Some("alice@getalby.com".into()),
///     website: Some("https://alice.example.com".into()),
///     timestamp: Some(1737906600),
/// };
///
/// let doc = DocumentBuilder::new()
///     .with_relay("wss://relay.damus.io")
///     .with_profile(profile)
///     .with_also_known_as(vec![
///         "https://alice.example.com/#me".into(),
///         "at://alice.bsky.social".into(),
///     ])
///     .with_follows(vec![
///         "did:nostr:32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245".into(),
///     ])
///     .build("did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2")
///     .unwrap();
/// ```
pub struct DocumentBuilder {
    relay_urls: Vec<String>,
    profile: Option<Profile>,
    also_known_as: Vec<String>,
    follows: Vec<String>,
}

impl Default for DocumentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DocumentBuilder {
    /// Create a new builder with default high-availability relay URLs.
    ///
    /// Default relays:
    /// - `wss://nos.lol`
    /// - `wss://relay.damus.io`
    /// - `wss://relay.primal.net`
    /// - `wss://relay.nostr.band`
    /// - `wss://purplepag.es`
    pub fn new() -> Self {
        Self {
            relay_urls: DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
            profile: None,
            also_known_as: Vec::new(),
            follows: Vec::new(),
        }
    }

    /// Add a relay URL for service endpoint injection.
    ///
    /// Relay URLs should be WebSocket endpoints (e.g., `wss://relay.damus.io`).
    pub fn with_relay(mut self, relay: impl Into<String>) -> Self {
        self.relay_urls.push(relay.into());
        self
    }

    /// Replace all default relays with a custom set.
    pub fn with_relays(mut self, relays: Vec<String>) -> Self {
        self.relay_urls = relays;
        self
    }

    /// Set profile metadata (from Nostr kind 0).
    pub fn with_profile(mut self, profile: Profile) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Set alsoKnownAs identifiers (cross-platform identity links).
    ///
    /// Common values: WebID URLs, ActivityPub handles, AT Protocol DIDs,
    /// other DID methods, social media profiles.
    pub fn with_also_known_as(mut self, identities: Vec<String>) -> Self {
        self.also_known_as = identities;
        self
    }

    /// Set followed DIDs (from Nostr kind 3 contact list).
    pub fn with_follows(mut self, follows: Vec<String>) -> Self {
        self.follows = follows;
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

        // Build service endpoints from relay URLs
        let mut services = Vec::new();
        for (i, relay) in self.relay_urls.iter().enumerate() {
            let relay_id = if self.relay_urls.len() == 1 {
                format!("{did}#relay")
            } else {
                format!("{did}#relay{}", i + 1)
            };
            services.push(Service {
                id: relay_id,
                service_type: "Relay".to_string(),
                service_endpoint: ServiceEndpoint::Single(format!("{relay}/")),
            });
        }

        Some(DidDocument {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
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
            authentication: vec![key_id.clone()],
            assertion_method: vec![key_id],
            service: services,
            profile: self.profile.clone(),
            follows: self.follows.clone(),
        })
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
        assert_eq!(doc.authentication, vec![format!("{SPEC_DID}#key1")]);
        assert_eq!(doc.assertion_method, vec![format!("{SPEC_DID}#key1")]);
    }

    #[test]
    fn minimal_document_has_no_optional_fields() {
        let doc = DocumentBuilder::new().build(SPEC_DID).unwrap();
        assert!(doc.also_known_as.is_empty());
        assert!(doc.follows.is_empty());
        assert!(doc.profile.is_none());
    }

    // ── §2.3.2 Enhanced with relays ──

    #[test]
    fn enhanced_document_includes_default_relays() {
        let doc = DocumentBuilder::new().build(SPEC_DID).unwrap();
        assert_eq!(doc.service.len(), DEFAULT_RELAYS.len());

        let relay_urls: Vec<&str> = doc
            .service
            .iter()
            .filter_map(|s| match &s.service_endpoint {
                ServiceEndpoint::Single(url) => Some(url.as_str()),
                _ => None,
            })
            .collect();

        assert!(relay_urls.iter().any(|u| u.contains("nos.lol")));
        assert!(relay_urls.iter().any(|u| u.contains("relay.damus.io")));
        assert!(relay_urls.iter().any(|u| u.contains("relay.primal.net")));
    }

    #[test]
    fn enhanced_document_with_custom_relay() {
        let doc = DocumentBuilder::new()
            .with_relay("wss://custom.relay.com")
            .build(SPEC_DID)
            .unwrap();

        let custom = doc
            .service
            .iter()
            .find(|s| {
                matches!(&s.service_endpoint, ServiceEndpoint::Single(url) if url.contains("custom.relay.com"))
            })
            .unwrap();
        assert_eq!(custom.service_type, "Relay");
    }

    #[test]
    fn custom_relays_replace_defaults() {
        let doc = DocumentBuilder::new()
            .with_relays(vec!["wss://sole.relay.com".to_string()])
            .build(SPEC_DID)
            .unwrap();

        assert_eq!(doc.service.len(), 1);
        match &doc.service[0].service_endpoint {
            ServiceEndpoint::Single(url) => assert!(url.contains("sole.relay.com")),
            _ => panic!("Expected single endpoint"),
        }
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
            timestamp: Some(1737906600),
        };

        let doc = DocumentBuilder::new()
            .with_relays(vec!["wss://relay.damus.io".to_string()])
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

        // Profile
        let p = doc.profile.unwrap();
        assert_eq!(p.name.unwrap(), "Alice");
        assert_eq!(p.about.unwrap(), "Building the decentralized web");
        assert_eq!(p.timestamp.unwrap(), 1737906600);

        // Also known as
        assert_eq!(doc.also_known_as.len(), 3);
        assert!(doc
            .also_known_as
            .contains(&"at://alice.bsky.social".to_string()));

        // Follows
        assert_eq!(doc.follows.len(), 2);
        assert!(doc.follows[0].starts_with("did:nostr:"));

        // Verification method preserved
        assert_eq!(
            doc.verification_method[0].public_key_multibase,
            SPEC_MULTIKEY
        );
    }

    // ── JSON-LD compliance ──

    #[test]
    fn document_has_required_jsonld_contexts() {
        let doc = DocumentBuilder::new().build(SPEC_DID).unwrap();
        assert!(doc
            .context
            .contains(&"https://www.w3.org/ns/did/v1".to_string()));
        assert!(doc
            .context
            .contains(&"https://w3id.org/nostr/context".to_string()));
    }

    #[test]
    fn document_serializes_valid_jsonld() {
        let doc = DocumentBuilder::new().build(SPEC_DID).unwrap();
        let json = serde_json::to_value(&doc).unwrap();

        // Top-level structure
        assert_eq!(json["id"], SPEC_DID);
        assert_eq!(json["type"], "DIDNostr");

        // Context is an array
        assert!(json["@context"].is_array());

        // Verification method
        let vm = &json["verificationMethod"][0];
        assert_eq!(vm["type"], "Multikey");
        assert_eq!(vm["publicKeyMultibase"], SPEC_MULTIKEY);
        assert_eq!(vm["controller"], SPEC_DID);

        // Verification relationships
        assert!(json["authentication"].is_array());
        assert!(json["assertionMethod"].is_array());
    }

    #[test]
    fn document_roundtrip_json() {
        let doc = DocumentBuilder::new()
            .with_profile(Profile {
                name: Some("Test".into()),
                about: Some("Roundtrip test".into()),
                ..Default::default()
            })
            .with_also_known_as(vec!["https://example.com".into()])
            .with_follows(vec![
                "did:nostr:abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1".into(),
            ])
            .build(SPEC_DID)
            .unwrap();

        let json = serde_json::to_string_pretty(&doc).unwrap();
        let parsed: DidDocument = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, doc.id);
        assert_eq!(parsed.doc_type, doc.doc_type);
        assert_eq!(parsed.profile.unwrap().name.unwrap(), "Test");
        assert_eq!(parsed.also_known_as.len(), 1);
        assert_eq!(parsed.follows.len(), 1);
    }

    // ── Edge cases ──

    #[test]
    fn builder_rejects_invalid_did() {
        assert!(DocumentBuilder::new().build("did:nostr:tooshort").is_none());
        assert!(DocumentBuilder::new().build("did:key:abc123").is_none());
        assert!(DocumentBuilder::new().build("not-a-did").is_none());
    }

    #[test]
    fn builder_rejects_non_hex_pubkey() {
        let bad = "did:nostr:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
        assert!(DocumentBuilder::new().build(bad).is_none());
    }

    #[test]
    fn empty_optional_fields_omitted_from_json() {
        let doc = DocumentBuilder::new().build(SPEC_DID).unwrap();
        let json = serde_json::to_string_pretty(&doc).unwrap();
        assert!(!json.contains("\"alsoKnownAs\""));
        assert!(!json.contains("\"follows\""));
        assert!(!json.contains("\"profile\""));
    }

    #[test]
    fn profile_default_is_all_none() {
        let p = Profile::default();
        assert!(p.name.is_none());
        assert!(p.about.is_none());
        assert!(p.picture.is_none());
        assert!(p.nip05.is_none());
        assert!(p.lud16.is_none());
        assert!(p.website.is_none());
        assert!(p.timestamp.is_none());
    }
}
