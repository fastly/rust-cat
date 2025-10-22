//! Example demonstrating all CAT-specific claim helper functions
//!
//! This example shows how to use the extended CAT claim helpers including:
//! - CATPOR (Probability of Rejection)
//! - CATNIP (Network IP restrictions)
//! - CATALPN (ALPN protocol restrictions)
//! - CATH (HTTP header requirements)
//! - CATGEO* (Geographic restrictions)
//! - CATTPK (TLS public key pinning)
//! - CATDPOP (DPoP settings)
//! - CATIF/CATIFDATA (Conditional logic)

use common_access_token::{
    cat_keys, catalpn, catdpop, catgeoalt, catgeocoord, catgeoiso3166, cath, catif, catifdata,
    catnip, catpor, cattpk, catv, current_timestamp, Algorithm, KeyId, RegisteredClaims,
    TokenBuilder,
};
use std::collections::BTreeMap;

fn main() {
    let key = b"my-secret-key-for-hmac-sha256";
    let now = current_timestamp();

    println!("=== Extended CAT Claims Example ===\n");

    // Example 1: Token with probability of rejection (CATPOR)
    println!("1. Creating token with CATPOR (25% rejection probability)");
    let token_with_catpor = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("key-1"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("example-issuer")
                .with_expiration(now + 3600),
        )
        .custom_cbor(cat_keys::CATPOR, catpor::create(25))
        .sign(key)
        .expect("Failed to sign token");

    println!("   ✓ Token created with CATPOR: 25% rejection probability\n");

    // Example 2: Token with network IP restrictions (CATNIP)
    println!("2. Creating token with CATNIP (IP restrictions)");
    let token_with_catnip = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("key-2"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("example-issuer")
                .with_expiration(now + 3600),
        )
        .custom_array(
            cat_keys::CATNIP,
            catnip::create(vec!["192.168.1.0/24", "10.0.0.0/8"]),
        )
        .sign(key)
        .expect("Failed to sign token");

    println!("   ✓ Token created with CATNIP: 192.168.1.0/24, 10.0.0.0/8\n");

    // Example 3: Token with ALPN restrictions (CATALPN)
    println!("3. Creating token with CATALPN (HTTP/2 only)");
    let token_with_catalpn = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("key-3"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("example-issuer")
                .with_expiration(now + 3600),
        )
        .custom_array(cat_keys::CATALPN, catalpn::http2_only())
        .sign(key)
        .expect("Failed to sign token");

    println!("   ✓ Token created with CATALPN: h2 only\n");

    // Example 4: Token with HTTP header requirements (CATH)
    println!("4. Creating token with CATH (custom headers)");
    let mut headers = BTreeMap::new();
    headers.insert("X-API-Key", "secret-api-key");
    headers.insert("X-Client-Version", "1.0");

    let token_with_cath = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("key-4"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("example-issuer")
                .with_expiration(now + 3600),
        )
        .custom_cbor(cat_keys::CATH, cath::create(headers))
        .sign(key)
        .expect("Failed to sign token");

    println!("   ✓ Token created with CATH: X-API-Key, X-Client-Version\n");

    // Example 5: Token with geographic restrictions (CATGEO*)
    println!("5. Creating token with geographic restrictions");
    let token_with_geo = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("key-5"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("example-issuer")
                .with_expiration(now + 3600),
        )
        // Country restriction
        .custom_array(cat_keys::CATGEOISO3166, catgeoiso3166::create(vec!["US"]))
        // Coordinate restriction (New York City with 5km radius)
        .custom_cbor(
            cat_keys::CATGEOCOORD,
            catgeocoord::with_radius(40.7128, -74.0060, 5000),
        )
        // Altitude restriction (0-1000 meters)
        .custom_cbor(cat_keys::CATGEOALT, catgeoalt::range(0, 1000))
        .sign(key)
        .expect("Failed to sign token");

    println!("   ✓ Token created with CATGEOISO3166: US");
    println!("   ✓ Token created with CATGEOCOORD: NYC (40.7128, -74.0060) ±5km");
    println!("   ✓ Token created with CATGEOALT: 0-1000m\n");

    // Example 6: Token with TLS public key pinning (CATTPK)
    println!("6. Creating token with CATTPK (TLS key pinning)");
    // In a real scenario, this would be the SHA-256 hash of a certificate's public key
    let public_key_hash = vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ];

    let token_with_cattpk = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("key-6"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("example-issuer")
                .with_expiration(now + 3600),
        )
        .custom_cbor(cat_keys::CATTPK, cattpk::create(public_key_hash.clone()))
        .sign(key)
        .expect("Failed to sign token");

    println!("   ✓ Token created with CATTPK: public key hash (32 bytes)\n");

    // Example 7: Token with DPoP settings (CATDPOP)
    println!("7. Creating token with CATDPOP (DPoP required)");
    let token_with_catdpop = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("key-7"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("example-issuer")
                .with_expiration(now + 3600),
        )
        .custom_cbor(cat_keys::CATDPOP, catdpop::required())
        .sign(key)
        .expect("Failed to sign token");

    println!("   ✓ Token created with CATDPOP: DPoP required\n");

    // Example 8: Token with conditional logic (CATIF/CATIFDATA)
    println!("8. Creating token with CATIF and CATIFDATA");
    let mut condition = BTreeMap::new();
    condition.insert(0, common_access_token::CborValue::Text("role".to_string()));
    condition.insert(
        1,
        common_access_token::CborValue::Text("equals".to_string()),
    );
    condition.insert(2, common_access_token::CborValue::Text("admin".to_string()));

    let mut if_data = BTreeMap::new();
    if_data.insert(0, common_access_token::CborValue::Text("role".to_string()));
    if_data.insert(1, common_access_token::CborValue::Text("admin".to_string()));

    let token_with_catif = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("key-8"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("example-issuer")
                .with_expiration(now + 3600),
        )
        .custom_cbor(cat_keys::CATIF, catif::create(condition))
        .custom_cbor(cat_keys::CATIFDATA, catifdata::create(if_data))
        .sign(key)
        .expect("Failed to sign token");

    println!("   ✓ Token created with CATIF: conditional logic");
    println!("   ✓ Token created with CATIFDATA: role=admin\n");

    // Example 9: Comprehensive token with multiple CAT claims
    println!("9. Creating comprehensive token with multiple CAT claims");
    let comprehensive_token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("comprehensive-key"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("secure-service")
                .with_subject("user-12345")
                .with_audience("api.example.com")
                .with_expiration(now + 7200),
        )
        .custom_cbor(cat_keys::CATV, catv::with_version(1))
        .custom_cbor(cat_keys::CATPOR, catpor::create(10))
        .custom_array(cat_keys::CATNIP, catnip::single("203.0.113.0/24"))
        .custom_array(cat_keys::CATALPN, catalpn::create(vec!["h2", "http/1.1"]))
        .custom_array(cat_keys::CATGEOISO3166, catgeoiso3166::create(vec!["US"]))
        .sign(key)
        .expect("Failed to sign token");

    println!("   ✓ Comprehensive token created with:");
    println!("     - CATV: version 1");
    println!("     - CATPOR: 10% rejection probability");
    println!("     - CATNIP: 203.0.113.0/24");
    println!("     - CATALPN: h2, http/1.1");
    println!("     - CATGEOISO3166: US");

    // Verify all tokens can be encoded
    println!("\n=== Verification ===");
    let tokens = vec![
        ("CATPOR", &token_with_catpor),
        ("CATNIP", &token_with_catnip),
        ("CATALPN", &token_with_catalpn),
        ("CATH", &token_with_cath),
        ("CATGEO*", &token_with_geo),
        ("CATTPK", &token_with_cattpk),
        ("CATDPOP", &token_with_catdpop),
        ("CATIF", &token_with_catif),
        ("Comprehensive", &comprehensive_token),
    ];

    for (name, token) in tokens {
        let token_bytes = token.to_bytes().expect("Failed to encode token");
        println!("✓ {} token encoded ({} bytes)", name, token_bytes.len());
    }

    println!("\n=== All Extended CAT Claims Examples Completed Successfully ===");
}
