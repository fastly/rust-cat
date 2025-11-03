//! Tests for Common Access Token

use crate::{
    cat_keys, catm, catr, catreplay, catu, cattprint,
    claims::RegisteredClaims,
    constants::{uri_components, tprint_type_values},
    header::{Algorithm, CborValue, KeyId},
    token::{Token, TokenBuilder, VerificationOptions},
    utils::current_timestamp,
};
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Hex};

use std::collections::BTreeMap;

#[test]
fn test_token_creation_and_verification() {
    let key = b"test-key-for-hmac-sha256-algorithm";

    // Create a token
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("test-key-1"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_subject("subject")
                .with_audience("audience")
                .with_expiration(current_timestamp() + 3600) // 1 hour from now
                .with_not_before(current_timestamp())
                .with_issued_at(current_timestamp())
                .with_cti(b"token-id-1234".to_vec()),
        )
        .custom_string(100, "custom-string-value")
        .custom_binary(101, b"custom-binary-value".to_vec())
        .custom_int(102, 12345)
        .sign(key)
        .expect("Failed to sign token");

    // Encode to bytes
    let token_bytes = token.to_bytes().expect("Failed to encode token");

    // Decode from bytes
    let decoded_token = Token::from_bytes(&token_bytes).expect("Failed to decode token");

    // Verify signature
    decoded_token
        .verify(key)
        .expect("Failed to verify signature");

    // Verify claims
    let options = VerificationOptions::new()
        .verify_exp(true)
        .verify_nbf(true)
        .expected_issuer("issuer")
        .expected_audience("audience");

    decoded_token
        .verify_claims(&options)
        .expect("Failed to verify claims");

    // Check that we can access the claims
    assert_eq!(
        decoded_token.claims.registered.iss,
        Some("issuer".to_string())
    );
    assert_eq!(
        decoded_token.claims.registered.sub,
        Some("subject".to_string())
    );
    assert_eq!(
        decoded_token.claims.registered.aud,
        Some("audience".to_string())
    );

    // Check that custom claims exist
    assert!(
        decoded_token.claims.custom.contains_key(&100),
        "Custom string claim not found"
    );
    assert!(
        decoded_token.claims.custom.contains_key(&101),
        "Custom binary claim not found"
    );
    assert!(
        decoded_token.claims.custom.contains_key(&102),
        "Custom int claim not found"
    );
}

#[test]
fn test_token_with_binary_kid() {
    let key = b"test-key-for-hmac-sha256-algorithm";
    let binary_kid = vec![0x01, 0x02, 0x03, 0x04, 0x05];

    // Create a token with binary key ID
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::binary(binary_kid.clone()))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_expiration(current_timestamp() + 3600),
        )
        .sign(key)
        .expect("Failed to sign token");

    // Encode to bytes
    let token_bytes = token.to_bytes().expect("Failed to encode token");

    // Decode from bytes
    let decoded_token = Token::from_bytes(&token_bytes).expect("Failed to decode token");

    // Check that the key ID was preserved
    if let Some(KeyId::Binary(kid)) = decoded_token.header.key_id() {
        assert_eq!(kid, binary_kid);
    } else {
        panic!("Binary key ID not found or has wrong type");
    }
}

#[test]
fn test_expired_token() {
    let key = b"test-key-for-hmac-sha256-algorithm";

    // Create an expired token
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_expiration(current_timestamp() - 3600), // 1 hour ago
        )
        .sign(key)
        .expect("Failed to sign token");

    // Verify claims should fail with Expired error
    let options = VerificationOptions::new().verify_exp(true);
    let result = token.verify_claims(&options);
    assert!(result.is_err());
    match result {
        Err(crate::Error::Expired) => {} // Expected
        _ => panic!("Expected Expired error"),
    }
}

#[test]
fn test_not_yet_valid_token() {
    let key = b"test-key-for-hmac-sha256-algorithm";

    // Create a token that's not yet valid
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_not_before(current_timestamp() + 3600), // 1 hour from now
        )
        .sign(key)
        .expect("Failed to sign token");

    // Verify claims should fail with NotYetValid error
    let options = VerificationOptions::new().verify_nbf(true);
    let result = token.verify_claims(&options);
    assert!(result.is_err());
    match result {
        Err(crate::Error::NotYetValid) => {} // Expected
        _ => panic!("Expected NotYetValid error"),
    }
}

#[test]
fn test_invalid_signature() {
    let key = b"test-key-for-hmac-sha256-algorithm";
    let wrong_key = b"wrong-key-for-verification";

    // Create a token
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(RegisteredClaims::new().with_issuer("issuer"))
        .sign(key)
        .expect("Failed to sign token");

    // Verify with wrong key should fail
    let result = token.verify(wrong_key);
    assert!(result.is_err());
    match result {
        Err(crate::Error::SignatureVerification) => {} // Expected
        _ => panic!("Expected SignatureVerification error"),
    }
}

#[test]
fn test_nested_map_claims() {
    let key = b"test-key-for-hmac-sha256-algorithm";

    // Create a nested map for testing
    let mut nested_map = BTreeMap::new();
    nested_map.insert(1, CborValue::Text("nested-text".to_string()));
    nested_map.insert(2, CborValue::Integer(42));
    nested_map.insert(3, CborValue::Bytes(vec![1, 2, 3, 4]));

    // Create a token with a nested map claim
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(RegisteredClaims::new().with_issuer("issuer"))
        .custom_map(200, nested_map)
        .sign(key)
        .expect("Failed to sign token");

    // Encode to bytes
    let token_bytes = token.to_bytes().expect("Failed to encode token");

    // Decode from bytes
    let decoded_token = Token::from_bytes(&token_bytes).expect("Failed to decode token");

    // Verify the nested map claim exists
    assert!(
        decoded_token.claims.custom.contains_key(&200),
        "Nested map claim not found"
    );

    // Verify the nested map claim has the correct type
    if let Some(CborValue::Map(map)) = decoded_token.claims.custom.get(&200) {
        assert_eq!(map.len(), 3, "Nested map should have 3 entries");

        // Check nested map values
        if let Some(CborValue::Text(text)) = map.get(&1) {
            assert_eq!(text, "nested-text");
        } else {
            panic!("Expected text value in nested map");
        }

        if let Some(CborValue::Integer(num)) = map.get(&2) {
            assert_eq!(*num, 42);
        } else {
            panic!("Expected integer value in nested map");
        }

        if let Some(CborValue::Bytes(bytes)) = map.get(&3) {
            assert_eq!(bytes, &[1, 2, 3, 4]);
        } else {
            panic!("Expected bytes value in nested map");
        }
    } else {
        panic!("Expected Map value for nested map claim");
    }
}

#[test]
fn test_specific_token_verification() {
    // The token string provided
    let token_str = "2D3RhEOhAQWhBExTeW1tZXRyaWMyNTZYmKQBZ2Nkbm5hbWUCeCxBNXMyRnptNUI5UG5EVEVmS3VybGxMdnJUelJLSWl4ZERsMWI0TEZzZlB3PQQaaIqzLBkBOKIFoQJ4Ji9lMDU5Lzc4MTEvMTY0MC80N2UxLTk5MzAtMmE0MzQxZWE4YjEwBqEBeCUvMWJkMWUyNmUtMzQwNy00ODA1LWI4MDYtMTMyMTZiMzRkNGJmWCBxCao7OrEJkkIQ8DcTNUFB-bMV4vUcVohXksntwc42_w";

    // Convert the token string to bytes
    let token_bytes =
        Base64UrlSafeNoPadding::decode_to_vec(token_str, None).expect("Failed to decode base64");

    // Convert the hex key to bytes
    let key_hex = "746573744b6579"; // "testKey" in hex
    let key = Hex::decode_to_vec(key_hex, None).expect("Failed to decode hex key");

    // Decode the token
    let token = Token::from_bytes(&token_bytes).expect("Failed to decode token");

    // Verify the signature
    token.verify(&key).expect("Failed to verify signature");

    // Check registered claims
    assert_eq!(token.claims.registered.iss, Some("cdnname".to_string()));
    assert_eq!(
        token.claims.registered.sub,
        Some("A5s2Fzm5B9PnDTEfKurllLvrTzRKIixdDl1b4LFsfPw=".to_string())
    );
    assert!(token.claims.registered.exp.is_some());

    // Check custom claims - specifically the nested maps at key 312
    if let Some(CborValue::Map(map_312)) = token.claims.custom.get(&312) {
        // Check path in map 5
        if let Some(CborValue::Map(map_5)) = map_312.get(&5) {
            if let Some(CborValue::Text(path)) = map_5.get(&2) {
                assert_eq!(path, "/e059/7811/1640/47e1-9930-2a4341ea8b10");
            } else {
                panic!("Expected path in map 5 not found or has wrong type");
            }
        } else {
            panic!("Expected map at key 5 not found or has wrong type");
        }

        // Check path in map 6
        if let Some(CborValue::Map(map_6)) = map_312.get(&6) {
            if let Some(CborValue::Text(path)) = map_6.get(&1) {
                assert_eq!(path, "/1bd1e26e-3407-4805-b806-13216b34d4bf");
            } else {
                panic!("Expected path in map 6 not found or has wrong type");
            }
        } else {
            panic!("Expected map at key 6 not found or has wrong type");
        }
    } else {
        panic!("Expected map at key 312 not found or has wrong type");
    }
}

#[test]
fn test_catu_validation() {
    let key = b"test-key-for-hmac-sha256-algorithm";

    // Create a token with CATU claim
    let mut catu_components = BTreeMap::new();

    // Restrict to https scheme
    catu_components.insert(uri_components::SCHEME, catu::exact_match("https"));

    // Restrict to example.com host
    catu_components.insert(uri_components::HOST, catu::suffix_match(".example.com"));

    // Restrict to paths starting with /api
    catu_components.insert(uri_components::PATH, catu::prefix_match("/api"));

    // Create a token with CATU claim
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_expiration(current_timestamp() + 3600),
        )
        .custom_cbor(cat_keys::CATU, catu::create(catu_components))
        .sign(key)
        .expect("Failed to sign token");

    // Test valid URI
    let options = VerificationOptions::new()
        .verify_catu(true)
        .uri("https://api.example.com/api/users");

    assert!(token.verify_claims(&options).is_ok());

    // Test invalid scheme
    let invalid_scheme_options = VerificationOptions::new()
        .verify_catu(true)
        .uri("http://api.example.com/api/users");

    assert!(token.verify_claims(&invalid_scheme_options).is_err());

    // Test invalid host
    let invalid_host_options = VerificationOptions::new()
        .verify_catu(true)
        .uri("https://api.other-domain.com/api/users");

    assert!(token.verify_claims(&invalid_host_options).is_err());

    // Test invalid path
    let invalid_path_options = VerificationOptions::new()
        .verify_catu(true)
        .uri("https://api.example.com/users");

    assert!(token.verify_claims(&invalid_path_options).is_err());
}

#[test]
fn test_catm_validation() {
    let key = b"test-key-for-hmac-sha256-algorithm";

    // Create a token with CATM claim (allow GET and POST only)
    let allowed_methods = vec!["GET", "POST"];

    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_expiration(current_timestamp() + 3600),
        )
        .custom_array(cat_keys::CATM, catm::create(allowed_methods))
        .sign(key)
        .expect("Failed to sign token");

    // Test allowed method (GET)
    let get_options = VerificationOptions::new()
        .verify_catm(true)
        .http_method("GET");

    assert!(token.verify_claims(&get_options).is_ok());

    // Test allowed method (POST)
    let post_options = VerificationOptions::new()
        .verify_catm(true)
        .http_method("POST");

    assert!(token.verify_claims(&post_options).is_ok());

    // Test allowed method with different case
    let get_lowercase_options = VerificationOptions::new()
        .verify_catm(true)
        .http_method("get");

    assert!(token.verify_claims(&get_lowercase_options).is_ok());

    // Test disallowed method
    let put_options = VerificationOptions::new()
        .verify_catm(true)
        .http_method("PUT");

    assert!(token.verify_claims(&put_options).is_err());
}

#[test]
fn test_catreplay_validation() {
    let key = b"test-key-for-hmac-sha256-algorithm";

    // Create a token with CATREPLAY claim (replay prohibited)
    let token_prohibited = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_expiration(current_timestamp() + 3600),
        )
        .custom_cbor(cat_keys::CATREPLAY, catreplay::prohibited())
        .sign(key)
        .expect("Failed to sign token");

    // Test token not seen before (should pass)
    let options_not_seen = VerificationOptions::new()
        .verify_catreplay(true)
        .token_seen_before(false);

    assert!(token_prohibited.verify_claims(&options_not_seen).is_ok());

    // Test token seen before (should fail with replay prohibited)
    let options_seen = VerificationOptions::new()
        .verify_catreplay(true)
        .token_seen_before(true);

    assert!(token_prohibited.verify_claims(&options_seen).is_err());

    // Create a token with CATREPLAY claim (replay permitted)
    let token_permitted = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_expiration(current_timestamp() + 3600),
        )
        .custom_cbor(cat_keys::CATREPLAY, catreplay::permitted())
        .sign(key)
        .expect("Failed to sign token");

    // Test token seen before (should pass with replay permitted)
    assert!(token_permitted.verify_claims(&options_seen).is_ok());
}

#[test]
fn test_catr_token() {
    let key = b"test-key-for-hmac-sha256-algorithm";
    let now = current_timestamp();

    // Create a token with automatic renewal CATR claim
    let renewal_params = catr::automatic_renewal(3600, Some((now + 3000) as i64));

    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_expiration(now + 3600),
        )
        .custom_cbor(cat_keys::CATR, catr::create(renewal_params))
        .sign(key)
        .expect("Failed to sign token");

    // Verify token is valid
    let options = VerificationOptions::new()
        .verify_exp(true)
        .expected_issuer("issuer");

    assert!(token.verify_claims(&options).is_ok());

    // Extract and verify the CATR claim
    if let Some(CborValue::Map(catr_map)) = token.claims.custom.get(&cat_keys::CATR) {
        use crate::constants::renewal_params;

        // Check renewal type
        if let Some(CborValue::Integer(renewal_type)) = catr_map.get(&renewal_params::TYPE) {
            assert_eq!(*renewal_type, 0); // Automatic renewal
        } else {
            panic!("Missing or invalid renewal type");
        }

        // Check expiration extension
        if let Some(CborValue::Integer(exp_add)) = catr_map.get(&renewal_params::EXPADD) {
            assert_eq!(*exp_add, 3600);
        } else {
            panic!("Missing or invalid expiration extension");
        }

        // Check deadline
        if let Some(CborValue::Integer(deadline)) = catr_map.get(&renewal_params::DEADLINE) {
            assert_eq!(*deadline, now as i64 + 3000);
        } else {
            panic!("Missing or invalid deadline");
        }
    } else {
        panic!("Missing or invalid CATR claim");
    }
}

#[test]
fn test_complex_uri_match() {
    let key = b"test-key-for-hmac-sha256-algorithm";

    // Create a complex CATU claim with regex and hash matching
    let mut catu_components = BTreeMap::new();

    // Regex pattern for path (matches /users/<uuid>)
    let user_id_pattern = r"^/users/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
    catu_components.insert(
        uri_components::PATH,
        catu::regex_match(user_id_pattern, vec![]),
    );

    // Create a token with complex CATU claim
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_expiration(current_timestamp() + 3600),
        )
        .custom_cbor(cat_keys::CATU, catu::create(catu_components))
        .sign(key)
        .expect("Failed to sign token");

    // Test matching URI with valid UUID
    let options_valid = VerificationOptions::new()
        .verify_catu(true)
        .uri("https://api.example.com/users/550e8400-e29b-41d4-a716-446655440000");

    assert!(token.verify_claims(&options_valid).is_ok());

    // Test non-matching URI
    let options_invalid = VerificationOptions::new()
        .verify_catu(true)
        .uri("https://api.example.com/users/invalid-id");

    assert!(token.verify_claims(&options_invalid).is_err());
}

#[test]
fn test_mac0_token_verification_with_original_bytes() {
    // Test token from the issue - this is a COSE_Mac0 token with tags 61 and 17
    let token_b64 = "2D3RhEOhAQWhBEd0ZXN0S2lkWOCnAWpwcmltZXZpZGVvAngkNWI4ZWQ2YjItZmNhNC00ZWQ1LTkxNWYtNThjZTFiMGYzMDRiB1gkZjI0ZmIxMDctNDA0MS00MTkxLThkMDktOWMzMzZkNWVjNzAyBRpofDGABBpoirIAGQE4ogahAXgkNGFkZGQ5ZTctZTUzMS00NzIxLTlhNjctYjJlNzQ1OTIyMmJiBaECeCYvZTA1OS83ODExLzE2NDAvNDdlMS05OTMwLTJhNDM0MWVhOGIxMBkBQ6MAAgEZA4QEdVgtUFYtQ0ROLUFjY2Vzcy1Ub2tlblggdBNqM-3RwdEOuIZ2UoF-jDq3z7DvNcjUWSISjCiugR4";

    // Decode the token
    let token_bytes =
        Base64UrlSafeNoPadding::decode_to_vec(token_b64, None).expect("Failed to decode base64");

    // Parse the token
    let token = Token::from_bytes(&token_bytes).expect("Failed to parse token");

    // Verify the token with the correct key
    let key = b"testSecret";
    assert!(
        token.verify(key).is_ok(),
        "Token verification should succeed with testSecret"
    );

    // Verify the token fails with wrong key
    let wrong_key = b"wrongKey";
    assert!(
        token.verify(wrong_key).is_err(),
        "Token verification should fail with wrong key"
    );

    // Verify claims (without expiration check as token might be expired)
    let options = VerificationOptions::new()
        .verify_exp(false)
        .verify_nbf(false);
    assert!(
        token.verify_claims(&options).is_ok(),
        "Claims verification should succeed"
    );

    // Check token properties
    assert_eq!(token.header.algorithm(), Some(Algorithm::HmacSha256));
    assert_eq!(
        token.header.key_id(),
        Some(KeyId::Binary(b"testKid".to_vec()))
    );

    // Check some claims
    assert_eq!(token.claims.registered.iss, Some("primevideo".to_string()));
    assert_eq!(
        token.claims.registered.sub,
        Some("5b8ed6b2-fca4-4ed5-915f-58ce1b0f304b".to_string())
    );
}

#[test]
fn test_created_token_format() {
    // Test that tokens created by this library have the correct format
    let key = b"testSecret";

    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("testKid"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("fastly")
                .with_subject("5b8ed6b2-fca4-4ed5-915f-58ce1b0f304b")
                .with_expiration(1752100813),
        )
        .sign(key)
        .expect("Failed to sign token");

    // Encode to bytes
    let token_bytes = token.to_bytes().expect("Failed to encode token");

    // Check that it has the correct CBOR tags for HMAC tokens
    assert_eq!(
        token_bytes[0], 0xd8,
        "First byte should be CBOR tag indicator"
    );
    assert_eq!(token_bytes[1], 0x3d, "Should have tag 61 (CWT)");
    assert_eq!(token_bytes[2], 0xd1, "Should have tag 17 (COSE_Mac0)");
    assert_eq!(
        token_bytes[3], 0x84,
        "Should be followed by 4-element array"
    );

    // Verify the token can be decoded and verified
    let decoded = Token::from_bytes(&token_bytes).expect("Failed to decode token");
    decoded.verify(key).expect("Failed to verify token");
}

#[test]
fn test_create_verify_token_with_catu_filename(){
    let key = b"testSecret";
    let expiration = current_timestamp() + 3600;
    // Create a token with CATU filename restriction

    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("testKid"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("fastly")
                .with_subject("5b8ed6b2-fca4-4ed5-915f-58ce1b0f304b")
                .with_expiration(expiration),
        )
        .custom_cbor(312, catu::create({
            let mut components = BTreeMap::new();
            components.insert(
                uri_components::FILENAME,
                catu::suffix_match("video_3.mp4"),
            );
            components
        }))
        .sign(key)
        .expect("Failed to sign token");

    // Encode to bytes
    let token_bytes = token.to_bytes().expect("Failed to encode token");

    // Verify the token can be decoded and verified
    let decoded_token = Token::from_bytes(&token_bytes).expect("Failed to decode token");
    decoded_token.verify(key).expect("Failed to verify token");

    // Verify including checking catu with a valid URI
    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/us-east/title-1234/video_3.mp4");

    token.verify_claims(&options).expect("Failed to verify token claims");
}

#[test]
fn test_create_verify_token_with_catu_parentpath(){
    let key = b"testSecret";
    let expiration = current_timestamp() + 3600;
    // Create a token with CATU filename restriction

    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("testKid"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("fastly")
                .with_subject("5b8ed6b2-fca4-4ed5-915f-58ce1b0f304b")
                .with_expiration(expiration),
        )
        .custom_cbor(312, catu::create({
            let mut components = BTreeMap::new();
            components.insert(
                uri_components::PARENT_PATH,
                catu::suffix_match("/us-east/title-1234"),
            );
            components
        }))
        .sign(key)
        .expect("Failed to sign token");

    // Encode to bytes
    let token_bytes = token.to_bytes().expect("Failed to encode token");

    // Verify the token can be decoded and verified
    let decoded_token = Token::from_bytes(&token_bytes).expect("Failed to decode token");
    decoded_token.verify(key).expect("Failed to verify token");

    // Verify including checking catu with a valid URI
    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/us-east/title-1234/video_3.mp4");

    token.verify_claims(&options).expect("Failed to verify token claims");
}

#[test]
fn test_create_verify_token_with_catu_stem(){
    let key = b"testSecret";
    let expiration = current_timestamp() + 3600;
    // Create a token with CATU filename restriction

    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("testKid"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("fastly")
                .with_subject("5b8ed6b2-fca4-4ed5-915f-58ce1b0f304b")
                .with_expiration(expiration),
        )
        .custom_cbor(312, catu::create({
            let mut components = BTreeMap::new();
            components.insert(
                uri_components::STEM,
                catu::suffix_match("video_3"),
            );
            components
        }))
        .sign(key)
        .expect("Failed to sign token");

    // Encode to bytes
    let token_bytes = token.to_bytes().expect("Failed to encode token");

    // Verify the token can be decoded and verified
    let decoded_token = Token::from_bytes(&token_bytes).expect("Failed to decode token");
    decoded_token.verify(key).expect("Failed to verify token");

    // Verify including checking catu with a valid URI
    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/us-east/title-1234/video_3.mp4");

    token.verify_claims(&options).expect("Failed to verify token claims");
}

#[test]
fn test_catu_filename_mismatch() {
    let key = b"testSecret";
    let expiration = current_timestamp() + 3600;

    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("testKid"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("fastly")
                .with_subject("5b8ed6b2-fca4-4ed5-915f-58ce1b0f304b")
                .with_expiration(expiration),
        )
        .custom_cbor(312, catu::create({
            let mut components = BTreeMap::new();
            components.insert(
                uri_components::FILENAME,
                catu::suffix_match("video_3.mp4"),
            );
            components
        }))
        .sign(key)
        .expect("Failed to sign token");

    // Verify with a mismatched filename should fail
    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/us-east/title-1234/video_5.mp4");

    assert!(token.verify_claims(&options).is_err(), "Should fail with mismatched filename");
}

#[test]
fn test_catu_parentpath_mismatch() {
    let key = b"testSecret";
    let expiration = current_timestamp() + 3600;

    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("testKid"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("fastly")
                .with_subject("5b8ed6b2-fca4-4ed5-915f-58ce1b0f304b")
                .with_expiration(expiration),
        )
        .custom_cbor(312, catu::create({
            let mut components = BTreeMap::new();
            components.insert(
                uri_components::PARENT_PATH,
                catu::suffix_match("/us-east/title-1234"),
            );
            components
        }))
        .sign(key)
        .expect("Failed to sign token");

    // Verify with a mismatched parent path should fail
    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/us-west/title-5678/video_3.mp4");

    assert!(token.verify_claims(&options).is_err(), "Should fail with mismatched parent path");
}

#[test]
fn test_catu_stem_mismatch() {
    let key = b"testSecret";
    let expiration = current_timestamp() + 3600;

    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("testKid"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("fastly")
                .with_subject("5b8ed6b2-fca4-4ed5-915f-58ce1b0f304b")
                .with_expiration(expiration),
        )
        .custom_cbor(312, catu::create({
            let mut components = BTreeMap::new();
            components.insert(
                uri_components::STEM,
                catu::suffix_match("video_3"),
            );
            components
        }))
        .sign(key)
        .expect("Failed to sign token");

    // Verify with a mismatched stem should fail
    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/us-east/title-1234/audio_1.mp4");

    assert!(token.verify_claims(&options).is_err(), "Should fail with mismatched stem");
}

#[test]
fn test_catu_filename_edge_cases() {
    let key = b"testSecret";
    let expiration = current_timestamp() + 3600;

    // Test with filename without extension
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("testKid"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("fastly")
                .with_subject("5b8ed6b2-fca4-4ed5-915f-58ce1b0f304b")
                .with_expiration(expiration),
        )
        .custom_cbor(312, catu::create({
            let mut components = BTreeMap::new();
            components.insert(
                uri_components::FILENAME,
                catu::suffix_match("README"),
            );
            components
        }))
        .sign(key)
        .expect("Failed to sign token");

    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/docs/README");

    token.verify_claims(&options).expect("Should handle filename without extension");
}

#[test]
fn test_catu_stem_edge_cases() {
    let key = b"testSecret";
    let expiration = current_timestamp() + 3600;

    // Test stem with file that has no extension
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("testKid"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("fastly")
                .with_subject("5b8ed6b2-fca4-4ed5-915f-58ce1b0f304b")
                .with_expiration(expiration),
        )
        .custom_cbor(312, catu::create({
            let mut components = BTreeMap::new();
            components.insert(
                uri_components::STEM,
                catu::suffix_match("Makefile"),
            );
            components
        }))
        .sign(key)
        .expect("Failed to sign token");

    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/project/Makefile");

    token.verify_claims(&options).expect("Should handle stem without extension");
}

#[test]
fn test_catu_parentpath_root() {
    let key = b"testSecret";
    let expiration = current_timestamp() + 3600;

    // Test parent path with file at root
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("testKid"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("fastly")
                .with_subject("5b8ed6b2-fca4-4ed5-915f-58ce1b0f304b")
                .with_expiration(expiration),
        )
        .custom_cbor(312, catu::create({
            let mut components = BTreeMap::new();
            components.insert(
                uri_components::PARENT_PATH,
                catu::suffix_match(""),
            );
            components
        }))
        .sign(key)
        .expect("Failed to sign token");

    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/file.txt");

    token.verify_claims(&options).expect("Should handle root-level files with empty parent path");
}

#[test]
fn test_catu_filename_with_multiple_dots() {
    let key = b"testSecret";
    let expiration = current_timestamp() + 3600;

    // Test filename with multiple dots (e.g., archive.tar.gz)
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("testKid"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("fastly")
                .with_subject("5b8ed6b2-fca4-4ed5-915f-58ce1b0f304b")
                .with_expiration(expiration),
        )
        .custom_cbor(312, catu::create({
            let mut components = BTreeMap::new();
            components.insert(
                uri_components::FILENAME,
                catu::suffix_match("archive.tar.gz"),
            );
            components
        }))
        .sign(key)
        .expect("Failed to sign token");

    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/downloads/archive.tar.gz");

    token.verify_claims(&options).expect("Should handle filenames with multiple dots");
}

#[test]
fn test_catu_stem_with_multiple_dots() {
    let key = b"testSecret";
    let expiration = current_timestamp() + 3600;

    // Test stem extraction from filename with multiple dots
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("testKid"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("fastly")
                .with_subject("5b8ed6b2-fca4-4ed5-915f-58ce1b0f304b")
                .with_expiration(expiration),
        )
        .custom_cbor(312, catu::create({
            let mut components = BTreeMap::new();
            components.insert(
                uri_components::STEM,
                catu::suffix_match("archive.tar"),
            );
            components
        }))
        .sign(key)
        .expect("Failed to sign token");

    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/downloads/archive.tar.gz");

    token.verify_claims(&options).expect("Should handle stem from filenames with multiple dots");
}

#[test]
fn test_cattprint_token() {
    let key = b"test-key-for-hmac-sha256-algorithm";
    let test_fingerprint_type = tprint_type_values::JA4;
    let test_fingerprint_value = "t13d1516h2_8daaf6152771_b186095e22b6";

    // Create a token with CATTPRINT claim
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_expiration(current_timestamp() + 3600),
        )
        .custom_cbor(cat_keys::CATTPRINT, cattprint::create(test_fingerprint_type, test_fingerprint_value))
        .sign(key)
        .expect("Failed to sign token");

    // Extract and verify the CATTPRINT claim
    if let Some(CborValue::Map(cattprint_map)) = token.claims.custom.get(&cat_keys::CATTPRINT) {
        use crate::constants::{tprint_params};

        // Check fingerprint type
        if let Some(CborValue::Text(fingerprint_type)) = cattprint_map.get(&tprint_params::FINGERPRINT_TYPE) {
            assert_eq!(*fingerprint_type, test_fingerprint_type);
        } else {
            panic!("Missing or invalid fingerprint type");
        }

        // Check fingerprint value
        if let Some(CborValue::Text(fingerprint_value)) = cattprint_map.get(&tprint_params::FINGERPRINT_VALUE) {
            assert_eq!(*fingerprint_value, test_fingerprint_value);
        } else {
            panic!("Missing or invalid fingerprint value");
        }
    } else {
        panic!("Missing or invalid CATTPRINT claim");
    }

    // Test valid TLS Fingerprint
    let options = VerificationOptions::new()
        .verify_cattprint(true)
        .fingerprint_type(test_fingerprint_type)
        .fingerprint_value(test_fingerprint_value);

    assert!(token.verify_claims(&options).is_ok());
}