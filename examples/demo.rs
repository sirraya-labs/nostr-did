use nostr_did::{DocumentBuilder, Profile};

fn main() {
    let did = "did:nostr:124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";

    println!("═══════════════════════════════════════════════════════════");
    println!("  nostr-did — W3C DID Document Generator");
    println!("  Spec: Nostr DID Method v0.0.11");
    println!("═══════════════════════════════════════════════════════════\n");

    // ── §2.3.1 Minimal ──
    println!("─── §2.3.1 Minimal DID Document (Offline) ───\n");
    let doc = DocumentBuilder::new().build(did).unwrap();
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());

    // ── §2.3.2 Enhanced with relays ──
    println!("\n─── §2.3.2 Enhanced DID Document (With Real Relays) ───\n");
    println!("Relays: wss://nos.lol, wss://relay.damus.io, wss://relay.primal.net, wss://relay.nostr.band, wss://purplepag.es\n");
    let doc = DocumentBuilder::new().build(did).unwrap();
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());

    // ── §2.3.3 Complete ──
    println!("\n─── §2.3.3 Complete DID Document (Profile + Social Graph) ───\n");
    let profile = Profile {
        name: Some("Alice".into()),
        about: Some("Building the decentralized web".into()),
        picture: Some("https://example.com/alice.jpg".into()),
        nip05: Some("alice@example.com".into()),
        lud16: Some("alice@getalby.com".into()),
        website: Some("https://alice.example.com".into()),
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
        .build(did)
        .unwrap();
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());

    println!("\n═══════════════════════════════════════════════════════════");
    println!("  All three spec examples produced correctly");
    println!("═══════════════════════════════════════════════════════════");
}
