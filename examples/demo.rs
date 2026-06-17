use nostr_did_key::*;

fn main() {
    println!("══════════════════════════════════════════════");
    println!("  nostr-did-key v0.1.0 — Demo");
    println!("══════════════════════════════════════════════\n");

    // -------------------------------------------------------------------
    // Example 1: Spec test vector
    // -------------------------------------------------------------------
    println!("─── Example 1: Spec test vector ───");
    let hex_pubkey = "124c0fa99407182ece5a24fad9b7f6674902fc422843d3128d38a0afbee0fdd2";

    match public_key_to_multikey(hex_pubkey) {
        Ok(multikey) => {
            println!("Input (hex pubkey):  {hex_pubkey}");
            println!("Output (multikey):   {multikey}");

            match multikey_to_bip340_pubkey(&multikey) {
                Ok(recovered) => {
                    println!("Roundtrip verified:  {recovered}");
                    println!("Match:               {}", recovered == hex_pubkey);
                }
                Err(e) => println!("Roundtrip failed: {e}"),
            }
        }
        Err(e) => println!("Encode error: {e}"),
    }

    // -------------------------------------------------------------------
    // Example 2: Real secp256k1 key generation
    // -------------------------------------------------------------------
    println!("\n─── Example 2: Real key generation (requires crypto-validation) ───");

    #[cfg(feature = "crypto-validation")]
    {
        use secp256k1::{Secp256k1, SecretKey};

        // Generate a random 32-byte secret key
        let mut random_bytes = [0u8; 32];
        getrandom_fill(&mut random_bytes);

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&random_bytes)
            .expect("random bytes should produce valid secret key");
        let public_key = secret_key.public_key(&secp);
        let xonly = public_key.x_only_public_key().0;

        let generated_hex = bytes_to_hex_demo(&xonly.serialize());
        println!(
            "Generated secret key:  {}",
            bytes_to_hex_demo(&secret_key.secret_bytes())
        );
        println!("Generated pubkey (x-only): {}", generated_hex);

        match public_key_to_multikey(&generated_hex) {
            Ok(multikey) => {
                println!("Multikey:              {multikey}");

                match multikey_to_bip340_pubkey(&multikey) {
                    Ok(recovered) => {
                        println!("Roundtrip:             {}", recovered == generated_hex);
                    }
                    Err(e) => println!("Roundtrip failed: {e}"),
                }

                match multikey_to_validated_key(&multikey) {
                    Ok(validated) => {
                        println!("Validated key hex:     {}", validated.to_hex());
                        println!("Validated key bytes:   {:02x?}", validated.as_bytes());
                    }
                    Err(e) => println!("Validation failed: {e}"),
                }
            }
            Err(e) => println!("Encode error: {e}"),
        }
    }

    #[cfg(not(feature = "crypto-validation"))]
    {
        println!("  (enable --features crypto-validation to see real key generation)");
    }

    // -------------------------------------------------------------------
    // Example 3: Structured error demonstration
    // -------------------------------------------------------------------
    println!("\n─── Example 3: Error handling ───");

    match public_key_to_multikey("too_short") {
        Ok(_) => {}
        Err(e) => println!("Bad length input → {e}"),
    }

    match public_key_to_multikey("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")
    {
        Ok(_) => {}
        Err(e) => println!("Non-hex input   → {e}"),
    }

    let valid_multikey = public_key_to_multikey(hex_pubkey).unwrap();
    let odd_multikey = valid_multikey.replace("fe70102", "fe70103");
    match multikey_to_bip340_pubkey(&odd_multikey) {
        Ok(_) => {}
        Err(e) => println!("Odd parity      → {e}"),
    }

    let bad_codec = valid_multikey.replace("fe701", "fe801");
    match multikey_to_bip340_pubkey(&bad_codec) {
        Ok(_) => {}
        Err(e) => println!("Bad multicodec  → {e}"),
    }

    match multikey_to_bip340_pubkey("fgggg") {
        Ok(_) => {}
        Err(e) => println!("Bad hex body    → {e}"),
    }

    // -------------------------------------------------------------------
    // Example 4: Output format verification
    // -------------------------------------------------------------------
    println!("\n─── Example 4: Output format ───");
    let multikey = public_key_to_multikey(hex_pubkey).unwrap();
    println!("Length:       {} chars", multikey.len());
    println!("Prefix:       {}", &multikey[..1]);
    println!(
        "All hex:      {}",
        multikey[1..].chars().all(|c| c.is_ascii_hexdigit())
    );
    println!(
        "No uppercase: {}",
        multikey[1..].chars().all(|c| !c.is_uppercase())
    );

    println!("\n══════════════════════════════════════════════");
    println!("  Demo complete");
    println!("══════════════════════════════════════════════");
}

/// Fill a buffer with random bytes using the OS random number generator.
/// On Windows this uses BCryptGenRandom. No external rand crate needed.
fn getrandom_fill(buf: &mut [u8]) {
    use std::mem;
    use std::ptr;

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            hAlgorithm: *mut u8,
            pbBuffer: *mut u8,
            cbBuffer: u32,
            dwFlags: u32,
        ) -> i32;
    }

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;

    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };

    if status != 0 {
        // Fallback: use a simple but non-cryptographic seed for demo purposes
        // In production, you'd want proper error handling
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = ((seed >> (i * 8)) & 0xFF) as u8;
        }
    }
}

fn bytes_to_hex_demo(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
