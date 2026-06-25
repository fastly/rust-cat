//! Tests for Common Access Token

use crate::{
    cat_keys, catm, catr, catreplay, cattprint, catu,
    claims::RegisteredClaims,
    constants::{uri_components, FingerprintType},
    header::{Algorithm, AlgorithmClass, CborValue, KeyId},
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
fn test_decoded_token_reencodes_without_breaking_signature() {
    // Regression test: `to_bytes()` must preserve the exact signed bytes of a
    // decoded token (both protected header and payload), otherwise re-encoding
    // a token parsed from the wire would emit a different payload/protected
    // bstr while keeping the original MAC/signature, producing a token that no
    // longer verifies. Uses the external COSE_Mac0 fixture (tags 61 + 17).
    let token_b64 = "2D3RhEOhAQWhBEd0ZXN0S2lkWOCnAWpwcmltZXZpZGVvAngkNWI4ZWQ2YjItZmNhNC00ZWQ1LTkxNWYtNThjZTFiMGYzMDRiB1gkZjI0ZmIxMDctNDA0MS00MTkxLThkMDktOWMzMzZkNWVjNzAyBRpofDGABBpoirIAGQE4ogahAXgkNGFkZGQ5ZTctZTUzMS00NzIxLTlhNjctYjJlNzQ1OTIyMmJiBaECeCYvZTA1OS83ODExLzE2NDAvNDdlMS05OTMwLTJhNDM0MWVhOGIxMBkBQ6MAAgEZA4QEdVgtUFYtQ0ROLUFjY2Vzcy1Ub2tlblggdBNqM-3RwdEOuIZ2UoF-jDq3z7DvNcjUWSISjCiugR4";

    let token_bytes =
        Base64UrlSafeNoPadding::decode_to_vec(token_b64, None).expect("Failed to decode base64");

    let key = b"testSecret";

    // The original decoded token verifies.
    let token = Token::from_bytes(&token_bytes).expect("Failed to parse token");
    assert!(
        token.verify(key).is_ok(),
        "Original decoded token should verify with testSecret"
    );

    // Re-encode it, parse the re-encoded bytes, and verify again. This fails if
    // `to_bytes()` re-encodes the payload (or protected header) instead of
    // reusing the preserved original bytes.
    let reencoded = token.to_bytes().expect("Failed to re-encode token");
    let reparsed = Token::from_bytes(&reencoded).expect("Failed to parse re-encoded token");
    assert!(
        reparsed.verify(key).is_ok(),
        "Re-encoded token should still verify with testSecret"
    );
}

#[test]
fn test_mutated_claims_are_reflected_in_to_bytes() {
    // The `claims` field is public, so a decoded token can be mutated before
    // re-encoding. `to_bytes()` must reflect the mutation rather than silently
    // emit the producer's original (cached) payload bytes. Without the cache
    // validation in `get_payload_bytes`, this emits a token still carrying the
    // original `iss`.
    let token_b64 = "2D3RhEOhAQWhBEd0ZXN0S2lkWOCnAWpwcmltZXZpZGVvAngkNWI4ZWQ2YjItZmNhNC00ZWQ1LTkxNWYtNThjZTFiMGYzMDRiB1gkZjI0ZmIxMDctNDA0MS00MTkxLThkMDktOWMzMzZkNWVjNzAyBRpofDGABBpoirIAGQE4ogahAXgkNGFkZGQ5ZTctZTUzMS00NzIxLTlhNjctYjJlNzQ1OTIyMmJiBaECeCYvZTA1OS83ODExLzE2NDAvNDdlMS05OTMwLTJhNDM0MWVhOGIxMBkBQ6MAAgEZA4QEdVgtUFYtQ0ROLUFjY2Vzcy1Ub2tlblggdBNqM-3RwdEOuIZ2UoF-jDq3z7DvNcjUWSISjCiugR4";
    let token_bytes =
        Base64UrlSafeNoPadding::decode_to_vec(token_b64, None).expect("Failed to decode base64");

    let mut token = Token::from_bytes(&token_bytes).expect("Failed to parse token");
    assert_eq!(token.claims.registered.iss, Some("primevideo".to_string()));

    // Mutate a claim, then re-encode and re-parse.
    token.claims.registered.iss = Some("mutated-issuer".to_string());
    let reencoded = token.to_bytes().expect("Failed to re-encode token");
    let reparsed = Token::from_bytes(&reencoded).expect("Failed to parse re-encoded token");

    // The mutation must be reflected on the wire.
    assert_eq!(
        reparsed.claims.registered.iss,
        Some("mutated-issuer".to_string()),
        "to_bytes() must emit the mutated claims, not the cached original bytes"
    );

    // And because the payload changed, the original MAC no longer matches:
    // the token must fail verification rather than pass with the wrong claims.
    assert!(
        reparsed.verify(b"testSecret").is_err(),
        "A token whose claims were mutated after decode must not verify with the original MAC"
    );
}

#[test]
fn test_unmutated_decoded_token_reuses_original_bytes() {
    // Counterpart to the mutation test: when the claims are *not* changed, the
    // cache-validation path must still reuse the producer's exact original
    // bytes so the round-trip stays byte-faithful (the non-canonical-encoding
    // interop guarantee).
    let token_b64 = "2D3RhEOhAQWhBEd0ZXN0S2lkWOCnAWpwcmltZXZpZGVvAngkNWI4ZWQ2YjItZmNhNC00ZWQ1LTkxNWYtNThjZTFiMGYzMDRiB1gkZjI0ZmIxMDctNDA0MS00MTkxLThkMDktOWMzMzZkNWVjNzAyBRpofDGABBpoirIAGQE4ogahAXgkNGFkZGQ5ZTctZTUzMS00NzIxLTlhNjctYjJlNzQ1OTIyMmJiBaECeCYvZTA1OS83ODExLzE2NDAvNDdlMS05OTMwLTJhNDM0MWVhOGIxMBkBQ6MAAgEZA4QEdVgtUFYtQ0ROLUFjY2Vzcy1Ub2tlblggdBNqM-3RwdEOuIZ2UoF-jDq3z7DvNcjUWSISjCiugR4";
    let token_bytes =
        Base64UrlSafeNoPadding::decode_to_vec(token_b64, None).expect("Failed to decode base64");

    let token = Token::from_bytes(&token_bytes).expect("Failed to parse token");
    let reencoded = token.to_bytes().expect("Failed to re-encode token");

    // Byte-for-byte identical to the producer's original encoding.
    assert_eq!(
        reencoded, token_bytes,
        "Unmutated decoded token must re-encode byte-faithfully"
    );
}

// ---------------------------------------------------------------------------
// Lossy-claim round-trip regression tests.
//
// `Claims` cannot represent every spec-valid CWT payload: a registered claim
// carried with an unexpected CBOR type is dropped by `Claims::from_map`. The
// canonical case is `aud` (key 3) encoded as a CBOR *array* of audiences, which
// RFC 8392 / RFC 7519 permit but `RegisteredClaims.aud: Option<String>` cannot
// hold. A `cti` (key 7) encoded as text is a second, non-conformant-producer
// trigger.
//
// These tokens must still verify (their signed payload bytes are preserved
// byte-faithfully) and round-trip without the dropped claim breaking the
// signature. They regress if `to_bytes`/`verify` re-encode the lossy `Claims`
// projection instead of reusing the producer's original payload bytes.
// ---------------------------------------------------------------------------

/// Append a CBOR byte string (`bstr`) header + contents for `data`.
fn push_bstr(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len < 24 {
        buf.push(0x40 | len as u8);
    } else if len < 256 {
        buf.push(0x58);
        buf.push(len as u8);
    } else {
        buf.push(0x59);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xff) as u8);
    }
    buf.extend_from_slice(data);
}

/// Append a CBOR text string for `s` (only short strings, len < 24).
fn push_text(buf: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    assert!(b.len() < 24, "test helper only handles short text");
    buf.push(0x60 | b.len() as u8);
    buf.extend_from_slice(b);
}

/// Hand-build a tagged COSE_Mac0 (CWT) token from raw protected/payload bstr
/// contents, MACed with HMAC-SHA256 over the `MAC_structure` using `key`.
fn build_mac0_token_bytes(protected: &[u8], payload: &[u8], key: &[u8]) -> Vec<u8> {
    // MAC_structure = ["MAC0", protected : bstr, external_aad : bstr(empty), payload : bstr]
    let mut mac_structure = vec![0x84]; // array(4)
    push_text(&mut mac_structure, "MAC0");
    push_bstr(&mut mac_structure, protected);
    push_bstr(&mut mac_structure, &[]); // external_aad
    push_bstr(&mut mac_structure, payload);

    let mac = crate::utils::compute_hmac_sha256(key, &mac_structure);

    // Tagged COSE_Mac0: tag 61 (CWT), tag 17 (COSE_Mac0), array(4).
    let mut token = vec![0xd8, 0x3d, 0xd1, 0x84];
    push_bstr(&mut token, protected); // 1. protected header
    token.push(0xa0); // 2. unprotected: empty map
    push_bstr(&mut token, payload); // 3. payload
    push_bstr(&mut token, &mac); // 4. MAC
    token
}

#[test]
fn test_aud_as_array_verifies_and_roundtrips() {
    // A spec-valid CWT whose `aud` (key 3) is a CBOR array of audiences — a
    // shape `RegisteredClaims.aud: Option<String>` cannot represent, so the
    // claim is dropped from the decoded `Claims`. The producer's signed payload
    // bytes must still be preserved so the token verifies and round-trips.
    let key = b"testSecret";

    // Protected header { 1 (alg): 5 (HS256) }.
    let protected: &[u8] = &[0xa1, 0x01, 0x05];

    // Payload { 3 (aud): ["aud-one", "aud-two"] }.
    let mut payload = vec![0xa1, 0x03, 0x82]; // map(1), key 3, array(2)
    push_text(&mut payload, "aud-one");
    push_text(&mut payload, "aud-two");

    let token_bytes = build_mac0_token_bytes(protected, &payload, key);

    let token = Token::from_bytes(&token_bytes).expect("decode aud-as-array token");

    // The lossy drop is real and documented: the typed accessor sees no `aud`.
    assert_eq!(
        token.claims.registered.aud, None,
        "array-valued aud cannot be represented by Option<String> and is dropped"
    );

    // Regression: an unmutated token must still verify against the original key.
    assert!(
        token.verify(key).is_ok(),
        "unmutated aud-as-array token must verify (byte-faithful payload reuse)"
    );

    // And it must re-encode byte-for-byte (the dropped claim survives on the wire).
    let reencoded = token.to_bytes().expect("re-encode aud-as-array token");
    assert_eq!(
        reencoded, token_bytes,
        "unmutated lossy token must re-encode byte-faithfully, preserving aud"
    );
    Token::from_bytes(&reencoded)
        .expect("decode round-tripped token")
        .verify(key)
        .expect("round-tripped aud-as-array token should still verify");
}

#[test]
fn test_aud_as_array_mutation_is_reflected() {
    // Counterpart: mutating a claim on a lossy token must still be reflected on
    // the wire (the cache must not silently re-emit the producer's bytes), and
    // the mutated payload must then fail verification against the original MAC.
    let key = b"testSecret";

    let protected: &[u8] = &[0xa1, 0x01, 0x05];
    let mut payload = vec![0xa1, 0x03, 0x82];
    push_text(&mut payload, "aud-one");
    push_text(&mut payload, "aud-two");
    let token_bytes = build_mac0_token_bytes(protected, &payload, key);

    let mut token = Token::from_bytes(&token_bytes).expect("decode aud-as-array token");

    // Set a (representable) issuer claim that was not present in the original.
    token.claims.registered.iss = Some("mutated-issuer".to_string());

    let reencoded = token.to_bytes().expect("re-encode mutated token");
    let reparsed = Token::from_bytes(&reencoded).expect("decode mutated token");

    assert_eq!(
        reparsed.claims.registered.iss,
        Some("mutated-issuer".to_string()),
        "mutation on a lossy token must be reflected on the wire"
    );
    assert!(
        reparsed.verify(key).is_err(),
        "a mutated payload must not verify against the original MAC"
    );
}

#[test]
fn test_cti_as_text_verifies_and_roundtrips() {
    // A second lossy trigger: `cti` (key 7) carried as text rather than bytes.
    // `RegisteredClaims::from_map` only accepts `cti` as bytes, so it is dropped,
    // yet the token must still verify and round-trip byte-faithfully.
    let key = b"testSecret";

    let protected: &[u8] = &[0xa1, 0x01, 0x05];
    // Payload { 7 (cti): "cti-as-text" }.
    let mut payload = vec![0xa1, 0x07];
    push_text(&mut payload, "cti-as-text");
    let token_bytes = build_mac0_token_bytes(protected, &payload, key);

    let token = Token::from_bytes(&token_bytes).expect("decode cti-as-text token");
    assert_eq!(
        token.claims.registered.cti, None,
        "text-valued cti cannot be represented as bytes and is dropped"
    );
    assert!(
        token.verify(key).is_ok(),
        "unmutated cti-as-text token must verify"
    );
    assert_eq!(
        token.to_bytes().expect("re-encode cti-as-text token"),
        token_bytes,
        "unmutated lossy token must re-encode byte-faithfully"
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
fn test_create_verify_token_with_catu_filename() {
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
        .custom_cbor(
            312,
            catu::create({
                let mut components = BTreeMap::new();
                components.insert(uri_components::FILENAME, catu::suffix_match("video_3.mp4"));
                components
            }),
        )
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

    token
        .verify_claims(&options)
        .expect("Failed to verify token claims");
}

#[test]
fn test_create_verify_token_with_catu_parentpath() {
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
        .custom_cbor(
            312,
            catu::create({
                let mut components = BTreeMap::new();
                components.insert(
                    uri_components::PARENT_PATH,
                    catu::suffix_match("/us-east/title-1234"),
                );
                components
            }),
        )
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

    token
        .verify_claims(&options)
        .expect("Failed to verify token claims");
}

#[test]
fn test_create_verify_token_with_catu_stem() {
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
        .custom_cbor(
            312,
            catu::create({
                let mut components = BTreeMap::new();
                components.insert(uri_components::STEM, catu::suffix_match("video_3"));
                components
            }),
        )
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

    token
        .verify_claims(&options)
        .expect("Failed to verify token claims");
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
        .custom_cbor(
            312,
            catu::create({
                let mut components = BTreeMap::new();
                components.insert(uri_components::FILENAME, catu::suffix_match("video_3.mp4"));
                components
            }),
        )
        .sign(key)
        .expect("Failed to sign token");

    // Verify with a mismatched filename should fail
    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/us-east/title-1234/video_5.mp4");

    assert!(
        token.verify_claims(&options).is_err(),
        "Should fail with mismatched filename"
    );
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
        .custom_cbor(
            312,
            catu::create({
                let mut components = BTreeMap::new();
                components.insert(
                    uri_components::PARENT_PATH,
                    catu::suffix_match("/us-east/title-1234"),
                );
                components
            }),
        )
        .sign(key)
        .expect("Failed to sign token");

    // Verify with a mismatched parent path should fail
    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/us-west/title-5678/video_3.mp4");

    assert!(
        token.verify_claims(&options).is_err(),
        "Should fail with mismatched parent path"
    );
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
        .custom_cbor(
            312,
            catu::create({
                let mut components = BTreeMap::new();
                components.insert(uri_components::STEM, catu::suffix_match("video_3"));
                components
            }),
        )
        .sign(key)
        .expect("Failed to sign token");

    // Verify with a mismatched stem should fail
    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/us-east/title-1234/audio_1.mp4");

    assert!(
        token.verify_claims(&options).is_err(),
        "Should fail with mismatched stem"
    );
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
        .custom_cbor(
            312,
            catu::create({
                let mut components = BTreeMap::new();
                components.insert(uri_components::FILENAME, catu::suffix_match("README"));
                components
            }),
        )
        .sign(key)
        .expect("Failed to sign token");

    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/docs/README");

    token
        .verify_claims(&options)
        .expect("Should handle filename without extension");
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
        .custom_cbor(
            312,
            catu::create({
                let mut components = BTreeMap::new();
                components.insert(uri_components::STEM, catu::suffix_match("Makefile"));
                components
            }),
        )
        .sign(key)
        .expect("Failed to sign token");

    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/project/Makefile");

    token
        .verify_claims(&options)
        .expect("Should handle stem without extension");
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
        .custom_cbor(
            312,
            catu::create({
                let mut components = BTreeMap::new();
                components.insert(uri_components::PARENT_PATH, catu::suffix_match(""));
                components
            }),
        )
        .sign(key)
        .expect("Failed to sign token");

    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/file.txt");

    token
        .verify_claims(&options)
        .expect("Should handle root-level files with empty parent path");
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
        .custom_cbor(
            312,
            catu::create({
                let mut components = BTreeMap::new();
                components.insert(
                    uri_components::FILENAME,
                    catu::suffix_match("archive.tar.gz"),
                );
                components
            }),
        )
        .sign(key)
        .expect("Failed to sign token");

    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/downloads/archive.tar.gz");

    token
        .verify_claims(&options)
        .expect("Should handle filenames with multiple dots");
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
        .custom_cbor(
            312,
            catu::create({
                let mut components = BTreeMap::new();
                components.insert(uri_components::STEM, catu::suffix_match("archive.tar"));
                components
            }),
        )
        .sign(key)
        .expect("Failed to sign token");

    let options = VerificationOptions::new()
        .verify_exp(true)
        .require_exp(true)
        .verify_catu(true)
        .uri("https://example.com/downloads/archive.tar.gz");

    token
        .verify_claims(&options)
        .expect("Should handle stem from filenames with multiple dots");
}

#[test]
fn test_cattprint_token() {
    let key = b"test-key-for-hmac-sha256-algorithm";
    let test_fingerprint_type = FingerprintType::JA4;
    let test_fingerprint_value = "t13d1516h2_8daaf6152771_b186095e22b6";

    // Create a token with CATTPRINT claim
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_expiration(current_timestamp() + 3600),
        )
        .custom_cbor(
            cat_keys::CATTPRINT,
            cattprint::create(test_fingerprint_type, test_fingerprint_value),
        )
        .sign(key)
        .expect("Failed to sign token");

    // Extract and verify the CATTPRINT claim
    if let Some(CborValue::Map(cattprint_map)) = token.claims.custom.get(&cat_keys::CATTPRINT) {
        use crate::constants::tprint_params;

        // Check fingerprint type
        if let Some(CborValue::Integer(fingerprint_type)) =
            cattprint_map.get(&tprint_params::FINGERPRINT_TYPE)
        {
            assert_eq!(*fingerprint_type, test_fingerprint_type as i64);
        } else {
            panic!("Missing or invalid fingerprint type");
        }

        // Check fingerprint value
        if let Some(CborValue::Text(fingerprint_value)) =
            cattprint_map.get(&tprint_params::FINGERPRINT_VALUE)
        {
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

#[test]
fn test_cattprint_token_fingerprint_type_not_match() {
    let key = b"test-key-for-hmac-sha256-algorithm";
    let test_fingerprint_type = FingerprintType::JA4;
    let test_fingerprint_value = "t13d1516h2_8daaf6152771_b186095e22b6";

    // Create a token with CATTPRINT claim
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_expiration(current_timestamp() + 3600),
        )
        .custom_cbor(
            cat_keys::CATTPRINT,
            cattprint::create(test_fingerprint_type, test_fingerprint_value),
        )
        .sign(key)
        .expect("Failed to sign token");

    // Extract and verify the CATTPRINT claim
    if let Some(CborValue::Map(cattprint_map)) = token.claims.custom.get(&cat_keys::CATTPRINT) {
        use crate::constants::tprint_params;

        // Check fingerprint type
        if let Some(CborValue::Integer(fingerprint_type)) =
            cattprint_map.get(&tprint_params::FINGERPRINT_TYPE)
        {
            assert_eq!(*fingerprint_type, test_fingerprint_type as i64);
        } else {
            panic!("Missing or invalid fingerprint type");
        }

        // Check fingerprint value
        if let Some(CborValue::Text(fingerprint_value)) =
            cattprint_map.get(&tprint_params::FINGERPRINT_VALUE)
        {
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
        .fingerprint_type(FingerprintType::JA3)
        .fingerprint_value(test_fingerprint_value);

    let result = token.verify_claims(&options);
    assert!(
        result.is_err(),
        "Expected error due to fingerprint type mismatch"
    );
    match result {
        Err(crate::Error::InvalidTLSFingerprintClaim(msg)) => {
            assert_eq!(
                msg, "TLS Fingerprint Type 'JA4' does not match required value 'JA3'",
                "Error message does not match expected value"
            );
        } // Expected
        _ => panic!("Expected InvalidTLSFingerprintClaim error"),
    }
}

#[test]
fn test_cattprint_token_fingerprint_value_not_match() {
    let key = b"test-key-for-hmac-sha256-algorithm";
    let test_fingerprint_type = FingerprintType::JA4;
    let test_fingerprint_value = "t13d1516h2_8daaf6152771_b186095e22b6";

    // Create a token with CATTPRINT claim
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_expiration(current_timestamp() + 3600),
        )
        .custom_cbor(
            cat_keys::CATTPRINT,
            cattprint::create(test_fingerprint_type, test_fingerprint_value),
        )
        .sign(key)
        .expect("Failed to sign token");

    // Extract and verify the CATTPRINT claim
    if let Some(CborValue::Map(cattprint_map)) = token.claims.custom.get(&cat_keys::CATTPRINT) {
        use crate::constants::tprint_params;

        // Check fingerprint type
        if let Some(CborValue::Integer(fingerprint_type)) =
            cattprint_map.get(&tprint_params::FINGERPRINT_TYPE)
        {
            assert_eq!(*fingerprint_type, test_fingerprint_type as i64);
        } else {
            panic!("Missing or invalid fingerprint type");
        }

        // Check fingerprint value
        if let Some(CborValue::Text(fingerprint_value)) =
            cattprint_map.get(&tprint_params::FINGERPRINT_VALUE)
        {
            assert_eq!(*fingerprint_value, test_fingerprint_value);
        } else {
            panic!("Missing or invalid fingerprint value");
        }
    } else {
        panic!("Missing or invalid CATTPRINT claim");
    }

    // Test valid TLS Fingerprint
    let test_fingerprint_value_not_match = "t65a1516h2_8daaf6152771_b186095e22d3";
    let options = VerificationOptions::new()
        .verify_cattprint(true)
        .fingerprint_type(test_fingerprint_type)
        .fingerprint_value(test_fingerprint_value_not_match);

    let result = token.verify_claims(&options);
    assert!(
        result.is_err(),
        "Expected error due to fingerprint type mismatch"
    );
    match result {
        Err(crate::Error::InvalidTLSFingerprintClaim(msg)) => {
            assert_eq!(
                msg,
                "TLS Fingerprint Value 't13d1516h2_8daaf6152771_b186095e22b6' does not match required value 't65a1516h2_8daaf6152771_b186095e22d3'",
                "Error message does not match expected value"
            );
        } // Expected
        _ => panic!("Expected InvalidTLSFingerprintClaim error"),
    }
}

#[test]
fn test_signed_integer_cbor_types() {
    let key = b"test-key-for-hmac-sha256-algorithm";

    // Create a token with negative integer custom claims
    // These will be encoded as I8, I16, I32, I64 CBOR types depending on the value
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_expiration(current_timestamp() + 3600),
        )
        // I8 range: -256 to -25 (e.g., -100)
        .custom_int(200, -100)
        // I16 range: -65536 to -257 (e.g., -1000)
        .custom_int(201, -1000)
        // I32 range: larger negative values (e.g., -100000)
        .custom_int(202, -100000)
        // I64 range: very large negative values
        .custom_int(203, -10000000000i64)
        .sign(key)
        .expect("Failed to sign token");

    // Encode to bytes
    let token_bytes = token.to_bytes().expect("Failed to encode token");

    // Decode from bytes - this should succeed now that we handle I8, I16, I32, I64
    let decoded_token =
        Token::from_bytes(&token_bytes).expect("Failed to decode token with signed integers");

    // Verify signature
    decoded_token
        .verify(key)
        .expect("Failed to verify signature");

    // Check that negative integer claims were preserved correctly
    if let Some(CborValue::Integer(val)) = decoded_token.claims.custom.get(&200) {
        assert_eq!(*val, -100, "I8 value should be preserved");
    } else {
        panic!("Custom claim 200 not found or has wrong type");
    }

    if let Some(CborValue::Integer(val)) = decoded_token.claims.custom.get(&201) {
        assert_eq!(*val, -1000, "I16 value should be preserved");
    } else {
        panic!("Custom claim 201 not found or has wrong type");
    }

    if let Some(CborValue::Integer(val)) = decoded_token.claims.custom.get(&202) {
        assert_eq!(*val, -100000, "I32 value should be preserved");
    } else {
        panic!("Custom claim 202 not found or has wrong type");
    }

    if let Some(CborValue::Integer(val)) = decoded_token.claims.custom.get(&203) {
        assert_eq!(*val, -10000000000i64, "I64 value should be preserved");
    } else {
        panic!("Custom claim 203 not found or has wrong type");
    }
}

#[test]
fn test_signed_integer_in_nested_structures() {
    let key = b"test-key-for-hmac-sha256-algorithm";

    // Create a nested map with negative integers
    let mut nested_map = BTreeMap::new();
    nested_map.insert(1, CborValue::Integer(-50)); // Small negative
    nested_map.insert(2, CborValue::Integer(-500)); // I8/I16 range
    nested_map.insert(3, CborValue::Integer(-50000)); // I16/I32 range

    // Create a token with nested map containing negative integers
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_expiration(current_timestamp() + 3600),
        )
        .custom_map(300, nested_map)
        .sign(key)
        .expect("Failed to sign token");

    // Encode and decode
    let token_bytes = token.to_bytes().expect("Failed to encode token");
    let decoded_token = Token::from_bytes(&token_bytes)
        .expect("Failed to decode token with nested signed integers");

    // Verify the nested map values
    if let Some(CborValue::Map(map)) = decoded_token.claims.custom.get(&300) {
        if let Some(CborValue::Integer(val)) = map.get(&1) {
            assert_eq!(*val, -50);
        } else {
            panic!("Expected integer at key 1");
        }

        if let Some(CborValue::Integer(val)) = map.get(&2) {
            assert_eq!(*val, -500);
        } else {
            panic!("Expected integer at key 2");
        }

        if let Some(CborValue::Integer(val)) = map.get(&3) {
            assert_eq!(*val, -50000);
        } else {
            panic!("Expected integer at key 3");
        }
    } else {
        panic!("Custom claim 300 not found or has wrong type");
    }
}

// ---------------------------------------------------------------------------
// Asymmetric algorithm tests (ES256 / PS256)
//
// The key material below is generated once with OpenSSL and embedded as
// base64-encoded DER so the tests are deterministic and fast (RSA key
// generation at test time would be slow).
//
//   ES256 (P-256):
//     openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out es.pem
//     openssl pkcs8 -topk8 -nocrypt -in es.pem -outform DER         # private (PKCS#8)
//     openssl pkey -in es.pem -pubout -outform DER                  # public  (SPKI)
//
//   PS256 (RSA-2048):
//     openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform DER  # private (PKCS#8)
//     openssl pkey -inform DER -in ps_priv.der -pubout -outform DER              # public  (SPKI)
// ---------------------------------------------------------------------------

/// ES256 PKCS#8 DER private key (base64-encoded).
const ES256_PRIVATE_KEY_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7BOlgwBOMKscTUCaG3RmlSCgUznDdxMn+9Pvoqp4pUOhRANCAARWMcvR3DnF1U15IvgcOyAxr3pJPfOHcF7ESuY+H+ya3LCH03PC1d99/XgN1ldF+wmMxVhY0w9iop10N6tNZDTg";
/// ES256 SPKI DER public key (base64-encoded), matching the private key above.
const ES256_PUBLIC_KEY_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVjHL0dw5xdVNeSL4HDsgMa96ST3zh3BexErmPh/smtywh9NzwtXfff14DdZXRfsJjMVYWNMPYqKddDerTWQ04A==";

/// PS256 PKCS#8 DER private key (base64-encoded).
const PS256_PRIVATE_KEY_B64: &str = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCHjA5iauwvo2sRB529iV1c+p+WuGFzk5EUGFFLYoIHxAwo/rSmZ2/D00epwb4WzOxA4c8+1QA+0rZIN35Fti9Wiunt0b1DgC0tuSglNzpEE5gjhTDcAWZOBPOCMt9pKEuuQC4eqBRxPoG5Y14dVi46/aQOQSqU5I0T3cbeLliTzjXkrvdqySFXMGpM9/I469SZRxZbDgB8wUcB2nTIuwOokjN/Vp+BpMM5QmR66J6aFNi8LqCmQv3grUI1kM1fqrC3az/YcyXcDvjinagyXsGYgW2ZpXIf2760UXv/bASAOO01sgI8zxbIDdG6Vd+7iPhr4b/v6QIj6rpuURFfns2LAgMBAAECggEAH9CdXbdYCZRzYHNnsGGqEtVWmQNdCEo2Lr/IcQfFmnoHGqYyE67Kmm2gb/VkHyjpOQ9nXAmVvakqlMfFsSoicU84uhPVNx9CO22uwRF18R2iQ5ATGEiR0TUzTLeRHbcSEGvLB3IPHkd8Hl327K7aOglntNrR2lHM1UFkWKkLLGHObPoLBSTQLjX5JkvtpUuBgnPVlfBUc5al9+CH+m/SiC4BvVWo4hiHEKCQgMIQ/Dh8UtS9Vk91FIizqKpqBXE6+PNmAnn9ZwRjZoRNBSLn0paAyiEXXdr5rV8zeYU0ktY40J9qWEFOJmTYII4pUK1U8tukrQ0w4LUm17f8zMkufQKBgQC7MGcSrbFWVjlEwA760sG6NKOZb5sL+2etIVAJyfSoGrwr8H4aQA1WFP+pmmlCWsLZj8qfTYSyocwfT/p9aY9Na7ftyks+q1QSsDF+D7frgxmITJeCSwiPa7jnOTrmReqAEOyPn8IlytHIhJbaPxzDxPf572QIAIBgsWhdygn21QKBgQC5X9agS0u2Joypz36ZIilbgbtgmSvFAE/22U0il+3GgXQbjmxPCip1UZm1cBgmLhq12bxU1xYxJpGVPWhEsmkIrOkEfNf/RYlSvVLzbuZLQxeB1g5FDrFb1EbaegrFznv/rFonyXMeRyJ7PHtDttfN5jxNTxTiV3BQ4uobgsai3wKBgFEiW6q26mSXnt7zuApzi1CgPEDnJPb+kyNxivWTOZ4baHBLHv1VwfILy/zBVtpR6J7QOmzt9pROmOEBk3sEY/6Ur/Y7dn3FWP14rRsMyRUlj82KFSl+SEmR0WU3YxYoO8oii8Z84nPrAx68iX4zWM5p82m7n0nwnbRLcQcl6Ue5AoGACjVN42viEnjS/DLx/MrVzjU5tVsZ/vJCdQyIY+RL8seENlREgKHFrso8lbJDki6tx9/isCVcEn7WO4qzKD1O7WxgNKAPYP5aTpUgcUllIzXhoIPCK2lguPbapANefoAdcfnyyQgd78fpDTJKc3MpNSx9m6BEPSalh77HN5afC68CgYBSHR2vz1GuUzHSgU+3xKqGSc+jlroetJ1dC5913Z+9eawW7QrRfmSod+JfEiJSw8eS+5/rGYjKihMtNPyqzadRvZtp0QGZrrm1k1/vqqeeH5Uq6AgH/2Djql4tUvC3gmgpHjY7RyPDv6v+u+L9C6MP0Nu5vVfQwpAmX9bsjn/Tjw==";
/// PS256 SPKI DER public key (base64-encoded), matching the private key above.
const PS256_PUBLIC_KEY_B64: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh4wOYmrsL6NrEQedvYldXPqflrhhc5ORFBhRS2KCB8QMKP60pmdvw9NHqcG+FszsQOHPPtUAPtK2SDd+RbYvVorp7dG9Q4AtLbkoJTc6RBOYI4Uw3AFmTgTzgjLfaShLrkAuHqgUcT6BuWNeHVYuOv2kDkEqlOSNE93G3i5Yk8415K73askhVzBqTPfyOOvUmUcWWw4AfMFHAdp0yLsDqJIzf1afgaTDOUJkeuiemhTYvC6gpkL94K1CNZDNX6qwt2s/2HMl3A744p2oMl7BmIFtmaVyH9u+tFF7/2wEgDjtNbICPM8WyA3RulXfu4j4a+G/7+kCI+q6blERX57NiwIDAQAB";

fn es256_keys() -> (Vec<u8>, Vec<u8>) {
    use ct_codecs::{Base64, Decoder};
    (
        Base64::decode_to_vec(ES256_PRIVATE_KEY_B64, None).expect("valid ES256 private key"),
        Base64::decode_to_vec(ES256_PUBLIC_KEY_B64, None).expect("valid ES256 public key"),
    )
}

fn ps256_keys() -> (Vec<u8>, Vec<u8>) {
    use ct_codecs::{Base64, Decoder};
    (
        Base64::decode_to_vec(PS256_PRIVATE_KEY_B64, None).expect("valid PS256 private key"),
        Base64::decode_to_vec(PS256_PUBLIC_KEY_B64, None).expect("valid PS256 public key"),
    )
}

fn build_signed_token(alg: Algorithm, private_key: &[u8]) -> Token {
    TokenBuilder::new()
        .algorithm(alg)
        .protected_key_id(KeyId::string("asym-key-1"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_subject("subject")
                .with_audience("audience")
                .with_expiration(current_timestamp() + 3600)
                .with_not_before(current_timestamp())
                .with_issued_at(current_timestamp()),
        )
        .custom_string(100, "custom-string-value")
        .custom_int(102, 12345)
        .sign(private_key)
        .expect("Failed to sign token")
}

#[test]
fn test_es256_sign_and_verify() {
    let (private_key, public_key) = es256_keys();

    let token = build_signed_token(Algorithm::Es256, &private_key);

    // ES256 signatures are the fixed 64-byte COSE form (r || s).
    assert_eq!(
        token.signature.len(),
        64,
        "ES256 signature should be 64 bytes"
    );
    assert_eq!(token.header.algorithm(), Some(Algorithm::Es256));

    // Round-trip through encoding.
    let token_bytes = token.to_bytes().expect("Failed to encode token");
    let decoded = Token::from_bytes(&token_bytes).expect("Failed to decode token");

    decoded
        .verify(&public_key)
        .expect("Failed to verify ES256 signature");

    let options = VerificationOptions::new()
        .verify_exp(true)
        .verify_nbf(true)
        .expected_issuer("issuer")
        .expected_audience("audience");
    decoded
        .verify_claims(&options)
        .expect("Failed to verify claims");

    assert_eq!(decoded.get_custom_string(100), Some("custom-string-value"));
    assert_eq!(decoded.get_custom_int(102), Some(12345));
}

#[test]
fn test_ps256_sign_and_verify() {
    let (private_key, public_key) = ps256_keys();

    let token = build_signed_token(Algorithm::Ps256, &private_key);
    assert_eq!(token.header.algorithm(), Some(Algorithm::Ps256));
    // RSA-2048 PSS signature is 256 bytes.
    assert_eq!(
        token.signature.len(),
        256,
        "PS256 signature should be 256 bytes"
    );

    let token_bytes = token.to_bytes().expect("Failed to encode token");
    let decoded = Token::from_bytes(&token_bytes).expect("Failed to decode token");

    decoded
        .verify(&public_key)
        .expect("Failed to verify PS256 signature");

    let options = VerificationOptions::new()
        .verify_exp(true)
        .verify_nbf(true)
        .expected_issuer("issuer")
        .expected_audience("audience");
    decoded
        .verify_claims(&options)
        .expect("Failed to verify claims");
}

#[test]
fn test_es256_uses_cose_sign1_tags() {
    let (private_key, _public_key) = es256_keys();
    let token = build_signed_token(Algorithm::Es256, &private_key);
    let token_bytes = token.to_bytes().expect("Failed to encode token");

    // Asymmetric algorithms must use COSE_Sign1 (tag 18) under the CWT tag (61).
    assert_eq!(
        token_bytes[0], 0xd8,
        "First byte should be CBOR tag indicator"
    );
    assert_eq!(token_bytes[1], 0x3d, "Should have tag 61 (CWT)");
    assert_eq!(token_bytes[2], 0xd2, "Should have tag 18 (COSE_Sign1)");
    assert_eq!(
        token_bytes[3], 0x84,
        "Should be followed by 4-element array"
    );
}

#[test]
fn test_ps256_uses_cose_sign1_tags() {
    let (private_key, _public_key) = ps256_keys();
    let token = build_signed_token(Algorithm::Ps256, &private_key);
    let token_bytes = token.to_bytes().expect("Failed to encode token");

    assert_eq!(
        token_bytes[0], 0xd8,
        "First byte should be CBOR tag indicator"
    );
    assert_eq!(token_bytes[1], 0x3d, "Should have tag 61 (CWT)");
    assert_eq!(token_bytes[2], 0xd2, "Should have tag 18 (COSE_Sign1)");
    assert_eq!(
        token_bytes[3], 0x84,
        "Should be followed by 4-element array"
    );
}

#[test]
fn test_es256_wrong_key_fails() {
    let (private_key, _public_key) = es256_keys();
    // A different, valid P-256 public key (SPKI DER) that does NOT match the
    // signing key. Decoding must succeed so the wrong-key path is always
    // exercised.
    let wrong_public_key = ct_codecs::Base64::decode_to_vec(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElkhvSdit+RZ8AdhbXRhGVYDI2ZNfZjZJkufNFB+xYGCR+MwpsILkSP3AVN51C5xG/JtwVcUTDekjURgBYsuDPA==",
        None,
    )
    .expect("wrong public key should be valid base64");

    let token = build_signed_token(Algorithm::Es256, &private_key);
    let token_bytes = token.to_bytes().expect("Failed to encode token");
    let decoded = Token::from_bytes(&token_bytes).expect("Failed to decode token");

    assert!(
        decoded.verify(&wrong_public_key).is_err(),
        "Verification should fail with a non-matching public key"
    );

    // Verifying against an unrelated but valid PS256 public key must also fail.
    let (_ps_priv, ps_pub) = ps256_keys();
    assert!(
        decoded.verify(&ps_pub).is_err(),
        "ES256 token should not verify against an RSA public key"
    );
}

#[test]
fn test_ps256_wrong_key_fails() {
    let (private_key, _public_key) = ps256_keys();
    let token = build_signed_token(Algorithm::Ps256, &private_key);
    let token_bytes = token.to_bytes().expect("Failed to encode token");
    let decoded = Token::from_bytes(&token_bytes).expect("Failed to decode token");

    // Verify against the ES256 (non-matching) public key.
    let (_es_priv, es_pub) = es256_keys();
    assert!(
        decoded.verify(&es_pub).is_err(),
        "PS256 token should not verify against an EC public key"
    );
}

#[test]
fn test_es256_tampered_payload_fails() {
    let (private_key, public_key) = es256_keys();
    let token = build_signed_token(Algorithm::Es256, &private_key);
    let mut token_bytes = token.to_bytes().expect("Failed to encode token");

    // Mutate a byte that lives inside the encoded payload but does not alter the
    // CBOR structure: the custom string claim "custom-string-value" is stored as
    // a text string, so flipping a byte within its contents keeps the token
    // structurally decodable while invalidating the signed payload.
    let needle = b"custom-string-value";
    let start = token_bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("custom string claim should be present in the encoded token");
    // Flip a low bit in the middle of the string's contents. XOR with 0x01 keeps
    // the byte in the ASCII range so the text string stays valid UTF-8 and the
    // token remains structurally decodable; only the signed bytes change.
    token_bytes[start + 1] ^= 0x01;

    // Decoding must still succeed (the CBOR structure is intact)...
    let decoded =
        Token::from_bytes(&token_bytes).expect("tampered token should still decode structurally");
    // ...but signature verification must reject the tampered payload.
    assert!(
        decoded.verify(&public_key).is_err(),
        "Verification should fail for a tampered ES256 token"
    );
}

#[test]
fn test_ps256_signatures_are_randomized() {
    // PSS uses a random salt, so two signatures over the same input differ,
    // yet both must verify.
    let (private_key, public_key) = ps256_keys();

    // Build both tokens with identical, fixed claims (no calls to
    // `current_timestamp()`) so the signed payload is byte-for-byte the same.
    // The PSS salt is then the only source of entropy, so any difference in
    // the signatures is attributable solely to salt randomization rather than
    // to differing claims.
    let build = || {
        TokenBuilder::new()
            .algorithm(Algorithm::Ps256)
            .protected_key_id(KeyId::string("asym-key-1"))
            .registered_claims(
                RegisteredClaims::new()
                    .with_issuer("issuer")
                    .with_subject("subject")
                    .with_audience("audience")
                    .with_expiration(2_000_000_000)
                    .with_not_before(1_000_000_000)
                    .with_issued_at(1_000_000_000),
            )
            .custom_string(100, "custom-string-value")
            .custom_int(102, 12345)
            .sign(&private_key)
            .expect("Failed to sign token")
    };

    let token_a = build();
    let token_b = build();

    // Sanity check the premise: the signed payloads are identical, so the only
    // thing that can differ between the two signatures is the PSS salt.
    assert_eq!(
        token_a
            .to_signed_payload_bytes()
            .expect("token_a signed payload"),
        token_b
            .to_signed_payload_bytes()
            .expect("token_b signed payload"),
        "signed payloads should be identical so the salt is the only entropy"
    );

    assert_ne!(
        token_a.signature, token_b.signature,
        "PSS signatures should differ due to random salt"
    );

    // Confirm the randomization is observable in the full on-the-wire bytes and
    // is confined to the signature. In COSE_Sign1 the signature is the final
    // `bstr` element, so the two encodings must share an identical prefix (tags,
    // protected/unprotected headers, payload, and the signature's bstr header)
    // and differ only across the trailing signature bytes.
    let bytes_a = token_a.to_bytes().expect("Failed to encode token_a");
    let bytes_b = token_b.to_bytes().expect("Failed to encode token_b");

    // RSA-2048 PSS signatures are a fixed 256 bytes, so both encodings have the
    // same length and the signature occupies the same trailing region in each.
    assert_eq!(
        token_a.signature.len(),
        token_b.signature.len(),
        "PS256 signatures should be the same fixed length"
    );
    assert_eq!(
        bytes_a.len(),
        bytes_b.len(),
        "encoded tokens should be the same length"
    );

    let split = bytes_a.len() - token_a.signature.len();

    assert_eq!(
        bytes_a[..split],
        bytes_b[..split],
        "everything before the signature (headers + payload) must be identical"
    );
    assert_ne!(
        bytes_a[split..],
        bytes_b[split..],
        "the trailing signature bytes must differ due to the random PSS salt"
    );
    // The trailing region is exactly the signature, so the observed difference
    // is the salt and nothing else.
    assert_eq!(&bytes_a[split..], token_a.signature.as_slice());
    assert_eq!(&bytes_b[split..], token_b.signature.as_slice());

    token_a.verify(&public_key).expect("token_a should verify");
    token_b.verify(&public_key).expect("token_b should verify");
}

#[test]
fn test_es256_invalid_private_key_errors() {
    let result = TokenBuilder::new()
        .algorithm(Algorithm::Es256)
        .registered_claims(RegisteredClaims::new().with_issuer("issuer"))
        .sign(b"not-a-valid-der-key");
    assert!(
        matches!(result, Err(crate::error::Error::InvalidKey(_))),
        "Signing with an invalid ES256 key should yield InvalidKey"
    );
}

#[test]
fn test_ps256_invalid_private_key_errors() {
    let result = TokenBuilder::new()
        .algorithm(Algorithm::Ps256)
        .registered_claims(RegisteredClaims::new().with_issuer("issuer"))
        .sign(b"not-a-valid-der-key");
    assert!(
        matches!(result, Err(crate::error::Error::InvalidKey(_))),
        "Signing with an invalid PS256 key should yield InvalidKey"
    );
}

#[test]
fn test_es256_invalid_public_key_errors() {
    let (private_key, _public_key) = es256_keys();
    let token = build_signed_token(Algorithm::Es256, &private_key);
    let result = token.verify(b"not-a-valid-der-key");
    assert!(
        matches!(result, Err(crate::error::Error::InvalidKey(_))),
        "Verifying with an invalid ES256 public key should yield InvalidKey"
    );
}

/// Regression test for the COSE protected-header interop bug.
///
/// COSE signs the *exact* encoded `protected` bstr, not a re-encoding of the
/// decoded header map. This test mints an "external" ES256 token whose
/// protected header encodes the `alg` value (-7) in the valid-but-non-canonical
/// 2-byte form (`0x38 0x06`) rather than the 1-byte form (`0x26`) this crate's
/// encoder emits. Verification must reproduce the original bytes; if it
/// re-encodes the header map instead, the signed input differs and a valid
/// token is rejected.
#[test]
fn test_es256_verifies_noncanonical_protected_header() {
    let (private_key, public_key) = es256_keys();

    // Protected header map {1: -7} with -7 encoded as the non-canonical
    // 2-byte negative int (0x38 0x06). Canonical encoding would be `a1 01 26`.
    let protected: &[u8] = &[0xa1, 0x01, 0x38, 0x06];
    // Payload: an empty claims map (`a0`). Its contents are irrelevant to the
    // signed-bytes question; only the protected header encoding matters here.
    let payload: &[u8] = &[0xa0];

    // Build the COSE Sig_structure exactly as sign1_input() does, but over the
    // non-canonical protected bytes, then sign it.
    let mut sig_structure = vec![0x84]; // array(4)
    sig_structure.push(0x6a); // text(10)
    sig_structure.extend_from_slice(b"Signature1");
    sig_structure.push(0x40 | protected.len() as u8); // bstr(protected.len())
    sig_structure.extend_from_slice(protected);
    sig_structure.push(0x40); // bstr(0) external_aad
    sig_structure.push(0x40 | payload.len() as u8); // bstr(payload.len())
    sig_structure.extend_from_slice(payload);

    let signature = crate::utils::compute_es256(&private_key, &sig_structure)
        .expect("compute_es256 over non-canonical structure");
    assert_eq!(signature.len(), 64);

    // Assemble the full tagged COSE_Sign1 token with the same protected bytes.
    let mut token_bytes = vec![0xd8, 0x3d, 0xd2]; // tag 61 (CWT), tag 18 (COSE_Sign1)
    token_bytes.push(0x84); // array(4)
    token_bytes.push(0x40 | protected.len() as u8); // protected bstr
    token_bytes.extend_from_slice(protected);
    token_bytes.push(0xa0); // unprotected: empty map
    token_bytes.push(0x40 | payload.len() as u8); // payload bstr
    token_bytes.extend_from_slice(payload);
    token_bytes.push(0x58); // bstr, 1-byte length follows
    token_bytes.push(64);
    token_bytes.extend_from_slice(&signature);

    let decoded = Token::from_bytes(&token_bytes).expect("decode non-canonical token");
    assert_eq!(decoded.header.algorithm(), Some(Algorithm::Es256));
    decoded
        .verify(&public_key)
        .expect("non-canonical protected header should still verify");

    // Re-encoding a decoded token must be byte-faithful to the producer's
    // encoding (RFC 9052 §4.4), so the non-canonical protected bytes survive a
    // round-trip and the token still verifies. A canonicalizing re-encode would
    // turn `a1 01 38 06` back into `a1 01 26` and break the signature.
    let reencoded = decoded.to_bytes().expect("re-encode non-canonical token");
    assert_eq!(
        reencoded, token_bytes,
        "to_bytes() must preserve the original protected header bytes"
    );
    Token::from_bytes(&reencoded)
        .expect("decode round-tripped token")
        .verify(&public_key)
        .expect("round-tripped token should still verify");
}

#[test]
fn test_algorithm_identifier_roundtrip() {
    for alg in [Algorithm::HmacSha256, Algorithm::Es256, Algorithm::Ps256] {
        let id = alg.identifier();
        assert_eq!(Algorithm::from_identifier(id), Some(alg));
    }
    assert_eq!(Algorithm::Es256.identifier(), -7);
    assert_eq!(Algorithm::Ps256.identifier(), -37);
    assert!(!Algorithm::Es256.is_mac());
    assert!(!Algorithm::Ps256.is_mac());
    assert!(Algorithm::HmacSha256.is_mac());
}

#[test]
fn test_algorithm_class_and_context() {
    // MAC algorithms map to COSE_Mac0 / "MAC0"; signature algorithms map to
    // COSE_Sign1 / "Signature1" (RFC 9052 §4.4, §6.3).
    assert_eq!(Algorithm::HmacSha256.class(), AlgorithmClass::Mac);
    assert_eq!(Algorithm::Es256.class(), AlgorithmClass::Signature);
    assert_eq!(Algorithm::Ps256.class(), AlgorithmClass::Signature);

    assert_eq!(AlgorithmClass::Mac.context(), "MAC0");
    assert_eq!(AlgorithmClass::Signature.context(), "Signature1");

    // is_mac() is defined in terms of the class, so they must agree.
    for alg in [Algorithm::HmacSha256, Algorithm::Es256, Algorithm::Ps256] {
        assert_eq!(alg.is_mac(), alg.class() == AlgorithmClass::Mac);
    }
}
