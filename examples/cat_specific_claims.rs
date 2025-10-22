use common_access_token::{
    cat_keys, catm, catr, catreplay, catu, current_timestamp, uri_components, Algorithm, KeyId,
    RegisteredClaims, TokenBuilder, VerificationOptions,
};
use std::collections::BTreeMap;

fn main() {
    // Create a key for signing and verification
    let key = b"my-secret-key-for-hmac-sha256";

    // Create a token with CAT-specific claims
    let token = create_token_with_cat_claims(key);

    // Encode token to bytes
    let token_bytes = token.to_bytes().expect("Failed to encode token");
    println!("Token encoded to {} bytes", token_bytes.len());

    // Decode and verify the token
    let decoded_token =
        common_access_token::Token::from_bytes(&token_bytes).expect("Failed to decode token");

    // Verify the signature
    decoded_token
        .verify(key)
        .expect("Failed to verify signature");

    // Verify the claims
    let options = VerificationOptions::new()
        .verify_exp(true)
        .expected_issuer("example-issuer");

    decoded_token
        .verify_claims(&options)
        .expect("Failed to verify claims");

    // Print token information
    print_token_info(&decoded_token);
}

/// Create a token with CAT-specific claims
fn create_token_with_cat_claims(key: &[u8]) -> common_access_token::Token {
    let now = current_timestamp();

    // Create a CATU claim (Common Access Token URI)
    let mut catu_components = BTreeMap::new();

    // Restrict to https scheme
    catu_components.insert(uri_components::SCHEME, catu::exact_match("https"));

    // Restrict to example.com host
    catu_components.insert(uri_components::HOST, catu::suffix_match(".example.com"));

    // Restrict to paths starting with /content
    catu_components.insert(uri_components::PATH, catu::prefix_match("/content"));

    // Restrict to .m3u8 files
    catu_components.insert(uri_components::EXTENSION, catu::exact_match(".m3u8"));

    // Create a CATM claim (Common Access Token Methods)
    let allowed_methods = vec!["GET", "HEAD"];

    // Create a CATR claim (Common Access Token Renewal)
    let renewal_params = catr::automatic_renewal(3600, Some((now + 3000) as i64));

    // Build the token with CAT-specific claims
    TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("example-key-id"))
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
        // Add CAT-specific claims
        .custom_cbor(cat_keys::CATU, catu::create(catu_components))
        .custom_cbor(cat_keys::CATR, catr::create(renewal_params))
        .custom_cbor(cat_keys::CATREPLAY, catreplay::prohibited())
        .custom_int(cat_keys::CATV, 1) // Version 1
        .custom_array(cat_keys::CATM, catm::create(allowed_methods))
        .sign(key)
        .expect("Failed to sign token")
}

/// Print information about a token
fn print_token_info(token: &common_access_token::Token) {
    println!("\nToken Information:");
    println!("------------------");

    // Print registered claims
    if let Some(iss) = &token.claims.registered.iss {
        println!("Issuer: {}", iss);
    }
    if let Some(sub) = &token.claims.registered.sub {
        println!("Subject: {}", sub);
    }
    if let Some(aud) = &token.claims.registered.aud {
        println!("Audience: {}", aud);
    }
    if let Some(exp) = token.claims.registered.exp {
        println!("Expires at: {} (unix timestamp)", exp);
    }
    if let Some(nbf) = token.claims.registered.nbf {
        println!("Not valid before: {} (unix timestamp)", nbf);
    }
    if let Some(iat) = token.claims.registered.iat {
        println!("Issued at: {} (unix timestamp)", iat);
    }
    if let Some(cti) = &token.claims.registered.cti {
        println!("CWT ID: {:?}", cti);
    }

    // Print CAT-specific claims
    println!("\nCAT-specific claims:");

    // Check for CATU claim
    if token.claims.custom.contains_key(&cat_keys::CATU) {
        println!("CATU (URI restrictions): present");
    }

    // Check for CATM claim
    if token.claims.custom.contains_key(&cat_keys::CATM) {
        println!("CATM (HTTP methods): present");
    }

    // Check for CATR claim
    if token.claims.custom.contains_key(&cat_keys::CATR) {
        println!("CATR (Token renewal): present");
    }

    // Check for CATV claim
    if token.claims.custom.contains_key(&cat_keys::CATV) {
        println!("CATV (Version): present");
    }

    // Check for CATREPLAY claim
    if token.claims.custom.contains_key(&cat_keys::CATREPLAY) {
        println!("CATREPLAY (Replay protection): present");
    }
}
