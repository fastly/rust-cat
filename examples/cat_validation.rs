use common_access_token::{
    cat_keys, catm, catr, catreplay, catu, current_timestamp, uri_components, Algorithm, KeyId,
    RegisteredClaims, TokenBuilder, VerificationOptions,
};
use std::collections::BTreeMap;

fn main() {
    // Create a key for signing and verification
    let key = b"my-secret-key-for-hmac-sha256";
    let now = current_timestamp() as i64;

    // Create a token with multiple CAT-specific claims
    let token = create_token_with_cat_claims(key, now);

    // Encode token to bytes
    let token_bytes = token.to_bytes().expect("Failed to encode token");
    println!(
        "Token with CAT claims encoded to {} bytes",
        token_bytes.len()
    );

    // Decode the token
    let decoded_token =
        common_access_token::Token::from_bytes(&token_bytes).expect("Failed to decode token");

    // Verify signature
    decoded_token
        .verify(key)
        .expect("Failed to verify signature");

    // Demonstrate different CAT-specific claim validations
    validate_catu_claim(&decoded_token);
    validate_catm_claim(&decoded_token);
    validate_catreplay_claim(&decoded_token);
}

/// Create a token with multiple CAT-specific claims
fn create_token_with_cat_claims(key: &[u8], now: i64) -> common_access_token::Token {
    println!("Creating token with CAT-specific claims...");

    // 1. Create a CATU claim (Common Access Token URI)
    let mut catu_components = BTreeMap::new();

    // Restrict to https scheme
    catu_components.insert(uri_components::SCHEME, catu::exact_match("https"));

    // Restrict to example.com host
    catu_components.insert(uri_components::HOST, catu::suffix_match(".example.com"));

    // Restrict to paths starting with /api
    catu_components.insert(uri_components::PATH, catu::prefix_match("/api"));

    // Restrict to .json extension
    catu_components.insert(uri_components::EXTENSION, catu::exact_match(".json"));

    println!("  Added CATU claim with URI restrictions");

    // 2. Create a CATM claim (Common Access Token Methods)
    let allowed_methods = vec!["GET", "HEAD", "OPTIONS"];
    println!("  Added CATM claim allowing methods: {:?}", allowed_methods);

    // 3. Create a CATR claim (Common Access Token Renewal)
    let renewal_params = catr::automatic_renewal(3600, Some(now + 3000));
    println!("  Added CATR claim with automatic renewal");

    // 4. Create a CATREPLAY claim (prohibit token replay)
    println!("  Added CATREPLAY claim prohibiting token replay");

    // Build the token with all CAT-specific claims
    TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("example-key-id"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("example-issuer")
                .with_subject("example-subject")
                .with_audience("example-audience")
                .with_expiration(now as u64 + 3600) // 1 hour from now
                .with_not_before(now as u64)
                .with_issued_at(now as u64)
                .with_cti(b"token-id-1234".to_vec()),
        )
        // Add CAT-specific claims
        .custom_cbor(cat_keys::CATU, catu::create(catu_components))
        .custom_cbor(cat_keys::CATR, catr::create(renewal_params))
        .custom_cbor(cat_keys::CATREPLAY, catreplay::prohibited())
        .custom_array(cat_keys::CATM, catm::create(allowed_methods))
        .sign(key)
        .expect("Failed to sign token")
}

/// Validate the CATU claim against different URIs
fn validate_catu_claim(token: &common_access_token::Token) {
    println!("\nValidating CATU (URI) claim:");

    // Define URIs to test
    let valid_uri = "https://api.example.com/api/users.json";
    let invalid_scheme_uri = "http://api.example.com/api/users.json";
    let invalid_host_uri = "https://api.other-site.com/api/users.json";
    let invalid_path_uri = "https://api.example.com/users.json";
    let invalid_extension_uri = "https://api.example.com/api/users.xml";

    // Test valid URI
    let options = VerificationOptions::new().verify_catu(true).uri(valid_uri);

    match token.verify_claims(&options) {
        Ok(_) => println!("  VALID URI: {}", valid_uri),
        Err(e) => println!(
            "  ERROR: {} should be valid, but got error: {}",
            valid_uri, e
        ),
    }

    // Test invalid scheme
    let invalid_scheme_options = VerificationOptions::new()
        .verify_catu(true)
        .uri(invalid_scheme_uri);

    match token.verify_claims(&invalid_scheme_options) {
        Ok(_) => println!(
            "  ERROR: {} should be invalid (wrong scheme)",
            invalid_scheme_uri
        ),
        Err(e) => println!(
            "  INVALID URI (as expected): {} - Error: {}",
            invalid_scheme_uri, e
        ),
    }

    // Test invalid host
    let invalid_host_options = VerificationOptions::new()
        .verify_catu(true)
        .uri(invalid_host_uri);

    match token.verify_claims(&invalid_host_options) {
        Ok(_) => println!(
            "  ERROR: {} should be invalid (wrong host)",
            invalid_host_uri
        ),
        Err(e) => println!(
            "  INVALID URI (as expected): {} - Error: {}",
            invalid_host_uri, e
        ),
    }

    // Test invalid path
    let invalid_path_options = VerificationOptions::new()
        .verify_catu(true)
        .uri(invalid_path_uri);

    match token.verify_claims(&invalid_path_options) {
        Ok(_) => println!(
            "  ERROR: {} should be invalid (wrong path)",
            invalid_path_uri
        ),
        Err(e) => println!(
            "  INVALID URI (as expected): {} - Error: {}",
            invalid_path_uri, e
        ),
    }

    // Test invalid extension
    let invalid_extension_options = VerificationOptions::new()
        .verify_catu(true)
        .uri(invalid_extension_uri);

    match token.verify_claims(&invalid_extension_options) {
        Ok(_) => println!(
            "  ERROR: {} should be invalid (wrong extension)",
            invalid_extension_uri
        ),
        Err(e) => println!(
            "  INVALID URI (as expected): {} - Error: {}",
            invalid_extension_uri, e
        ),
    }
}

/// Validate the CATM claim against different HTTP methods
fn validate_catm_claim(token: &common_access_token::Token) {
    println!("\nValidating CATM (HTTP Methods) claim:");

    // Test allowed methods
    for method in &["GET", "HEAD", "OPTIONS"] {
        let options = VerificationOptions::new()
            .verify_catm(true)
            .http_method(*method);

        match token.verify_claims(&options) {
            Ok(_) => println!("  VALID METHOD: {}", method),
            Err(e) => println!("  ERROR: {} should be valid, but got error: {}", method, e),
        }
    }

    // Test disallowed methods
    for method in &["POST", "PUT", "DELETE", "PATCH"] {
        let options = VerificationOptions::new()
            .verify_catm(true)
            .http_method(*method);

        match token.verify_claims(&options) {
            Ok(_) => println!("  ERROR: {} should be invalid method", method),
            Err(e) => println!("  INVALID METHOD (as expected): {} - Error: {}", method, e),
        }
    }
}

/// Validate the CATREPLAY claim
fn validate_catreplay_claim(token: &common_access_token::Token) {
    println!("\nValidating CATREPLAY claim:");

    // Test with token not seen before (should pass)
    let options_not_seen = VerificationOptions::new()
        .verify_catreplay(true)
        .token_seen_before(false);

    match token.verify_claims(&options_not_seen) {
        Ok(_) => println!("  VALID: Token not seen before is accepted (as expected)"),
        Err(e) => println!(
            "  ERROR: Token not seen before should be valid, but got error: {}",
            e
        ),
    }

    // Test with token seen before (should fail with replay prohibited)
    let options_seen = VerificationOptions::new()
        .verify_catreplay(true)
        .token_seen_before(true);

    match token.verify_claims(&options_seen) {
        Ok(_) => println!("  ERROR: Token seen before should be rejected"),
        Err(e) => println!(
            "  INVALID (as expected): Token seen before is rejected - Error: {}",
            e
        ),
    }
}
