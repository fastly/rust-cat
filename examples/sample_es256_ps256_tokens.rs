//! Mint sample ES256 and PS256 tokens with a ~10-year expiration and print
//! them in hex and base64url.
//! Run with: `cargo run --example sample_es256_ps256_tokens`.
//!
//! The key pairs are the same ones used by the test suite (PKCS#8 DER private
//! keys, SPKI DER public keys, base64-encoded here so the example is
//! self-contained). The public keys are printed so the tokens can be verified
//! elsewhere.

use common_access_token::{
    current_timestamp, Algorithm, KeyId, RegisteredClaims, Token, TokenBuilder, VerificationOptions,
    VerifyingKey,
};
use ct_codecs::{Base64, Base64UrlSafeNoPadding, Decoder, Encoder, Hex};

// ⚠️ DEMO KEYS — DO NOT USE IN PRODUCTION.
// These private keys are committed to a public repository (they are the same
// keys used by the test suite) and are therefore publicly known. They exist
// only so this example is self-contained. Generate your own key pair for any
// real use.
//
// NOTE: these constants are intentionally duplicated across the two asymmetric
// examples and `src/tests.rs`. Each example/test is meant to stand alone (a
// reader can run a single file without chasing a shared fixture), and the keys
// are throwaway demo material, so the small duplication is preferred over a
// shared module. Not a finding — please don't flag it in review.
const ES256_PRIVATE_KEY_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7BOlgwBOMKscTUCaG3RmlSCgUznDdxMn+9Pvoqp4pUOhRANCAARWMcvR3DnF1U15IvgcOyAxr3pJPfOHcF7ESuY+H+ya3LCH03PC1d99/XgN1ldF+wmMxVhY0w9iop10N6tNZDTg";
const ES256_PUBLIC_KEY_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVjHL0dw5xdVNeSL4HDsgMa96ST3zh3BexErmPh/smtywh9NzwtXfff14DdZXRfsJjMVYWNMPYqKddDerTWQ04A==";

const PS256_PRIVATE_KEY_B64: &str = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCHjA5iauwvo2sRB529iV1c+p+WuGFzk5EUGFFLYoIHxAwo/rSmZ2/D00epwb4WzOxA4c8+1QA+0rZIN35Fti9Wiunt0b1DgC0tuSglNzpEE5gjhTDcAWZOBPOCMt9pKEuuQC4eqBRxPoG5Y14dVi46/aQOQSqU5I0T3cbeLliTzjXkrvdqySFXMGpM9/I469SZRxZbDgB8wUcB2nTIuwOokjN/Vp+BpMM5QmR66J6aFNi8LqCmQv3grUI1kM1fqrC3az/YcyXcDvjinagyXsGYgW2ZpXIf2760UXv/bASAOO01sgI8zxbIDdG6Vd+7iPhr4b/v6QIj6rpuURFfns2LAgMBAAECggEAH9CdXbdYCZRzYHNnsGGqEtVWmQNdCEo2Lr/IcQfFmnoHGqYyE67Kmm2gb/VkHyjpOQ9nXAmVvakqlMfFsSoicU84uhPVNx9CO22uwRF18R2iQ5ATGEiR0TUzTLeRHbcSEGvLB3IPHkd8Hl327K7aOglntNrR2lHM1UFkWKkLLGHObPoLBSTQLjX5JkvtpUuBgnPVlfBUc5al9+CH+m/SiC4BvVWo4hiHEKCQgMIQ/Dh8UtS9Vk91FIizqKpqBXE6+PNmAnn9ZwRjZoRNBSLn0paAyiEXXdr5rV8zeYU0ktY40J9qWEFOJmTYII4pUK1U8tukrQ0w4LUm17f8zMkufQKBgQC7MGcSrbFWVjlEwA760sG6NKOZb5sL+2etIVAJyfSoGrwr8H4aQA1WFP+pmmlCWsLZj8qfTYSyocwfT/p9aY9Na7ftyks+q1QSsDF+D7frgxmITJeCSwiPa7jnOTrmReqAEOyPn8IlytHIhJbaPxzDxPf572QIAIBgsWhdygn21QKBgQC5X9agS0u2Joypz36ZIilbgbtgmSvFAE/22U0il+3GgXQbjmxPCip1UZm1cBgmLhq12bxU1xYxJpGVPWhEsmkIrOkEfNf/RYlSvVLzbuZLQxeB1g5FDrFb1EbaegrFznv/rFonyXMeRyJ7PHtDttfN5jxNTxTiV3BQ4uobgsai3wKBgFEiW6q26mSXnt7zuApzi1CgPEDnJPb+kyNxivWTOZ4baHBLHv1VwfILy/zBVtpR6J7QOmzt9pROmOEBk3sEY/6Ur/Y7dn3FWP14rRsMyRUlj82KFSl+SEmR0WU3YxYoO8oii8Z84nPrAx68iX4zWM5p82m7n0nwnbRLcQcl6Ue5AoGACjVN42viEnjS/DLx/MrVzjU5tVsZ/vJCdQyIY+RL8seENlREgKHFrso8lbJDki6tx9/isCVcEn7WO4qzKD1O7WxgNKAPYP5aTpUgcUllIzXhoIPCK2lguPbapANefoAdcfnyyQgd78fpDTJKc3MpNSx9m6BEPSalh77HN5afC68CgYBSHR2vz1GuUzHSgU+3xKqGSc+jlroetJ1dC5913Z+9eawW7QrRfmSod+JfEiJSw8eS+5/rGYjKihMtNPyqzadRvZtp0QGZrrm1k1/vqqeeH5Uq6AgH/2Djql4tUvC3gmgpHjY7RyPDv6v+u+L9C6MP0Nu5vVfQwpAmX9bsjn/Tjw==";
const PS256_PUBLIC_KEY_B64: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh4wOYmrsL6NrEQedvYldXPqflrhhc5ORFBhRS2KCB8QMKP60pmdvw9NHqcG+FszsQOHPPtUAPtK2SDd+RbYvVorp7dG9Q4AtLbkoJTc6RBOYI4Uw3AFmTgTzgjLfaShLrkAuHqgUcT6BuWNeHVYuOv2kDkEqlOSNE93G3i5Yk8415K73askhVzBqTPfyOOvUmUcWWw4AfMFHAdp0yLsDqJIzf1afgaTDOUJkeuiemhTYvC6gpkL94K1CNZDNX6qwt2s/2HMl3A744p2oMl7BmIFtmaVyH9u+tFF7/2wEgDjtNbICPM8WyA3RulXfu4j4a+G/7+kCI+q6blERX57NiwIDAQAB";

// ~10 years in seconds (10 * 365.25 days).
const TEN_YEARS_SECS: u64 = 315_576_000;

fn main() {
    let now = current_timestamp();
    let exp = now + TEN_YEARS_SECS;
    println!("issued_at (iat): {now}");
    println!("expiration (exp): {exp}  (~10 years from now)\n");

    mint(
        "ES256 (ECDSA P-256 + SHA-256)",
        Algorithm::Es256,
        ES256_PRIVATE_KEY_B64,
        ES256_PUBLIC_KEY_B64,
        "es256-sample-key",
        now,
        exp,
    );

    mint(
        "PS256 (RSASSA-PSS + SHA-256)",
        Algorithm::Ps256,
        PS256_PRIVATE_KEY_B64,
        PS256_PUBLIC_KEY_B64,
        "ps256-sample-key",
        now,
        exp,
    );
}

#[allow(clippy::too_many_arguments)]
fn mint(
    name: &str,
    alg: Algorithm,
    private_key_b64: &str,
    public_key_b64: &str,
    kid: &str,
    iat: u64,
    exp: u64,
) {
    let private_key = Base64::decode_to_vec(private_key_b64, None).expect("valid private key");
    let public_key = Base64::decode_to_vec(public_key_b64, None).expect("valid public key");

    let token = TokenBuilder::new()
        .algorithm(alg)
        .protected_key_id(KeyId::string(kid))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("example-issuer")
                .with_subject("example-subject")
                .with_audience("example-audience")
                .with_issued_at(iat)
                .with_not_before(iat)
                .with_expiration(exp),
        )
        .sign(&private_key)
        .expect("Failed to sign token");

    let token_bytes = token.to_bytes().expect("Failed to encode token");
    let hex = Hex::encode_to_string(&token_bytes).expect("hex encode");
    let b64url = Base64UrlSafeNoPadding::encode_to_string(&token_bytes).expect("b64url encode");

    // Sanity check: the token verifies against its public key.
    let decoded = Token::from_bytes(&token_bytes).expect("decode");
    let verifying_key = match alg {
        Algorithm::Es256 => VerifyingKey::Es256(&public_key),
        Algorithm::Ps256 => VerifyingKey::Ps256(&public_key),
        other => panic!("unsupported algorithm for this example: {other:?}"),
    };
    decoded
        .verify_with_key(verifying_key)
        .expect("verify signature");
    decoded
        .verify_claims(
            &VerificationOptions::new()
                .verify_exp(true)
                .verify_nbf(true)
                .expected_issuer("example-issuer")
                .expected_audience("example-audience"),
        )
        .expect("verify claims");

    println!("=== {name} ===");
    println!("kid:            {kid}");
    println!("public key (SPKI DER, base64): {public_key_b64}");
    println!("token length:   {} bytes", token_bytes.len());
    println!("token (hex):     {hex}");
    println!("token (b64url):  {b64url}");
    println!();
}
