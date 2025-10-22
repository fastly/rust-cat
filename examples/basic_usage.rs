use common_access_token::{
    current_timestamp, Algorithm, CborValue, KeyId, RegisteredClaims, TokenBuilder,
    VerificationOptions,
};
use std::collections::BTreeMap;

fn main() {
    // Secret key for signing and verification
    let key = b"my-secret-key-for-hmac-sha256";

    // Create a token with both string and binary key ID examples
    let string_kid_token = create_token_with_string_kid(key);
    let binary_kid_token = create_token_with_binary_kid(key);
    let nested_map_token = create_token_with_nested_map(key);

    // Encode tokens to bytes
    let string_kid_token_bytes = string_kid_token.to_bytes().expect("Failed to encode token");
    let binary_kid_token_bytes = binary_kid_token.to_bytes().expect("Failed to encode token");
    let nested_map_token_bytes = nested_map_token.to_bytes().expect("Failed to encode token");

    println!(
        "Token with string key ID encoded as {} bytes",
        string_kid_token_bytes.len()
    );
    println!(
        "Token with binary key ID encoded as {} bytes",
        binary_kid_token_bytes.len()
    );
    println!(
        "Token with nested map encoded as {} bytes",
        nested_map_token_bytes.len()
    );

    // Decode and verify tokens
    verify_token(&string_kid_token_bytes, key, "string-key-example");
    verify_token(&binary_kid_token_bytes, key, "binary-key-example");
    verify_nested_map_token(&nested_map_token_bytes, key);
}

/// Create a token with a string key ID
fn create_token_with_string_kid(key: &[u8]) -> common_access_token::Token {
    let now = current_timestamp();

    // Create a token with string key ID
    TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("string-key-example"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("example-issuer")
                .with_subject("example-subject")
                .with_audience("example-audience")
                .with_expiration(now + 3600) // 1 hour from now
                .with_not_before(now)
                .with_issued_at(now)
                .with_cti(b"token-id-1234".to_vec()),
        )
        .custom_string(100, "custom-string-value")
        .custom_binary(101, b"custom-binary-value".to_vec())
        .custom_int(102, 12345)
        .sign(key)
        .expect("Failed to sign token")
}

/// Create a token with a binary key ID
fn create_token_with_binary_kid(key: &[u8]) -> common_access_token::Token {
    let now = current_timestamp();
    let binary_kid = vec![0x01, 0x02, 0x03, 0x04, 0x05];

    // Create a token with binary key ID
    TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::binary(binary_kid))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("example-issuer")
                .with_subject("example-subject")
                .with_audience("example-audience")
                .with_expiration(now + 3600) // 1 hour from now
                .with_not_before(now)
                .with_issued_at(now),
        )
        .sign(key)
        .expect("Failed to sign token")
}

/// Create a token with a nested map claim
fn create_token_with_nested_map(key: &[u8]) -> common_access_token::Token {
    let now = current_timestamp();

    // Create a nested map for the token
    let mut nested_map = BTreeMap::new();
    nested_map.insert(1, CborValue::Text("nested-text-value".to_string()));
    nested_map.insert(2, CborValue::Integer(42));
    nested_map.insert(3, CborValue::Bytes(vec![1, 2, 3, 4, 5]));

    // Create a second level nested map
    let mut second_level_map = BTreeMap::new();
    second_level_map.insert(1, CborValue::Text("second-level-text".to_string()));
    second_level_map.insert(2, CborValue::Integer(99));

    // Add the second level map to the first level
    nested_map.insert(4, CborValue::Map(second_level_map));

    // Create a token with a nested map claim
    TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("nested-map-example"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("example-issuer")
                .with_subject("example-subject")
                .with_audience("example-audience")
                .with_expiration(now + 3600) // 1 hour from now
                .with_not_before(now)
                .with_issued_at(now),
        )
        .custom_map(200, nested_map)
        .sign(key)
        .expect("Failed to sign token")
}

/// Verify a token
fn verify_token(token_bytes: &[u8], key: &[u8], expected_token_type: &str) {
    // Decode the token
    let token = match common_access_token::Token::from_bytes(token_bytes) {
        Ok(token) => token,
        Err(err) => {
            println!("Failed to decode {} token: {}", expected_token_type, err);
            return;
        }
    };

    // Verify the signature
    if let Err(err) = token.verify(key) {
        println!(
            "Failed to verify {} token signature: {}",
            expected_token_type, err
        );
        return;
    }

    // Verify the claims
    let options = VerificationOptions::new()
        .verify_exp(true)
        .verify_nbf(true)
        .expected_issuer("example-issuer")
        .expected_audience("example-audience");

    if let Err(err) = token.verify_claims(&options) {
        println!(
            "Failed to verify {} token claims: {}",
            expected_token_type, err
        );
        return;
    }

    // Get the key ID
    let kid = token.header.key_id().expect("No key ID in token");
    let kid_str = match &kid {
        KeyId::Binary(data) => format!("Binary key ID: {:?}", data),
        KeyId::String(data) => format!("String key ID: {}", data),
    };

    println!(
        "Successfully verified {} token ({})",
        expected_token_type, kid_str
    );

    // Print some claims
    if let Some(iss) = &token.claims.registered.iss {
        println!("  Issuer: {}", iss);
    }
    if let Some(sub) = &token.claims.registered.sub {
        println!("  Subject: {}", sub);
    }
    if let Some(exp) = token.claims.registered.exp {
        println!(
            "  Expires at: {} (in {} seconds)",
            exp,
            exp - current_timestamp()
        );
    }
}

/// Verify a token with a nested map claim
fn verify_nested_map_token(token_bytes: &[u8], key: &[u8]) {
    // Decode the token
    let token = match common_access_token::Token::from_bytes(token_bytes) {
        Ok(token) => token,
        Err(err) => {
            println!("Failed to decode nested map token: {}", err);
            return;
        }
    };

    // Verify the signature
    if let Err(err) = token.verify(key) {
        println!("Failed to verify nested map token signature: {}", err);
        return;
    }

    // Verify the claims
    let options = VerificationOptions::new()
        .verify_exp(true)
        .verify_nbf(true)
        .expected_issuer("example-issuer")
        .expected_audience("example-audience");

    if let Err(err) = token.verify_claims(&options) {
        println!("Failed to verify nested map token claims: {}", err);
        return;
    }

    println!("Successfully verified nested map token");

    // Check for the nested map claim
    if let Some(CborValue::Map(map)) = token.claims.custom.get(&200) {
        println!("  Found nested map claim with {} entries", map.len());

        // Print first level entries
        if let Some(CborValue::Text(text)) = map.get(&1) {
            println!("  Entry 1: Text = {}", text);
        }

        if let Some(CborValue::Integer(num)) = map.get(&2) {
            println!("  Entry 2: Integer = {}", num);
        }

        if let Some(CborValue::Bytes(bytes)) = map.get(&3) {
            println!("  Entry 3: Bytes = {:?}", bytes);
        }

        // Check for second level map
        if let Some(CborValue::Map(second_map)) = map.get(&4) {
            println!("  Entry 4: Nested map with {} entries", second_map.len());

            if let Some(CborValue::Text(text)) = second_map.get(&1) {
                println!("    Nested Entry 1: Text = {}", text);
            }

            if let Some(CborValue::Integer(num)) = second_map.get(&2) {
                println!("    Nested Entry 2: Integer = {}", num);
            }
        }
    } else {
        println!("  Nested map claim not found!");
    }
}
