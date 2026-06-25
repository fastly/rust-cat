//! Criterion benchmarks for Common Access Token signing and verification.
//!
//! Covers every supported algorithm — HS256 (HMAC-SHA256), ES256 (ECDSA
//! P-256), and PS256 (RSASSA-PSS) — and measures:
//!
//!   * **Signing time**      — building the COSE structure and producing the tag/signature.
//!   * **Verification time** — verifying the tag/signature on an already-decoded token.
//!   * **Signature size**    — the raw tag/signature length, plus the full encoded token size.
//!
//! Timing data is collected by Criterion (`target/criterion/...`). The size
//! data — which Criterion has no notion of — is written to
//! `target/bench/sizes.json` so the report generator can combine both into a
//! single markdown report with graphs.
//!
//! Run with:  `cargo bench --bench cat`
//! Then build a report with: `python3 scripts/bench_report.py`

use std::fs;
use std::path::Path;

use common_access_token::{
    current_timestamp, Algorithm, KeyId, RegisteredClaims, Token, TokenBuilder, VerificationOptions,
};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use ct_codecs::{Base64, Decoder};

// ⚠️ DEMO KEYS — DO NOT USE IN PRODUCTION.
// Identical throwaway key material to `examples/asymmetric_signing.rs`; these
// are publicly committed and exist only so the benchmark is self-contained.
const ES256_PRIVATE_KEY_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7BOlgwBOMKscTUCaG3RmlSCgUznDdxMn+9Pvoqp4pUOhRANCAARWMcvR3DnF1U15IvgcOyAxr3pJPfOHcF7ESuY+H+ya3LCH03PC1d99/XgN1ldF+wmMxVhY0w9iop10N6tNZDTg";
const ES256_PUBLIC_KEY_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVjHL0dw5xdVNeSL4HDsgMa96ST3zh3BexErmPh/smtywh9NzwtXfff14DdZXRfsJjMVYWNMPYqKddDerTWQ04A==";

const PS256_PRIVATE_KEY_B64: &str = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCHjA5iauwvo2sRB529iV1c+p+WuGFzk5EUGFFLYoIHxAwo/rSmZ2/D00epwb4WzOxA4c8+1QA+0rZIN35Fti9Wiunt0b1DgC0tuSglNzpEE5gjhTDcAWZOBPOCMt9pKEuuQC4eqBRxPoG5Y14dVi46/aQOQSqU5I0T3cbeLliTzjXkrvdqySFXMGpM9/I469SZRxZbDgB8wUcB2nTIuwOokjN/Vp+BpMM5QmR66J6aFNi8LqCmQv3grUI1kM1fqrC3az/YcyXcDvjinagyXsGYgW2ZpXIf2760UXv/bASAOO01sgI8zxbIDdG6Vd+7iPhr4b/v6QIj6rpuURFfns2LAgMBAAECggEAH9CdXbdYCZRzYHNnsGGqEtVWmQNdCEo2Lr/IcQfFmnoHGqYyE67Kmm2gb/VkHyjpOQ9nXAmVvakqlMfFsSoicU84uhPVNx9CO22uwRF18R2iQ5ATGEiR0TUzTLeRHbcSEGvLB3IPHkd8Hl327K7aOglntNrR2lHM1UFkWKkLLGHObPoLBSTQLjX5JkvtpUuBgnPVlfBUc5al9+CH+m/SiC4BvVWo4hiHEKCQgMIQ/Dh8UtS9Vk91FIizqKpqBXE6+PNmAnn9ZwRjZoRNBSLn0paAyiEXXdr5rV8zeYU0ktY40J9qWEFOJmTYII4pUK1U8tukrQ0w4LUm17f8zMkufQKBgQC7MGcSrbFWVjlEwA760sG6NKOZb5sL+2etIVAJyfSoGrwr8H4aQA1WFP+pmmlCWsLZj8qfTYSyocwfT/p9aY9Na7ftyks+q1QSsDF+D7frgxmITJeCSwiPa7jnOTrmReqAEOyPn8IlytHIhJbaPxzDxPf572QIAIBgsWhdygn21QKBgQC5X9agS0u2Joypz36ZIilbgbtgmSvFAE/22U0il+3GgXQbjmxPCip1UZm1cBgmLhq12bxU1xYxJpGVPWhEsmkIrOkEfNf/RYlSvVLzbuZLQxeB1g5FDrFb1EbaegrFznv/rFonyXMeRyJ7PHtDttfN5jxNTxTiV3BQ4uobgsai3wKBgFEiW6q26mSXnt7zuApzi1CgPEDnJPb+kyNxivWTOZ4baHBLHv1VwfILy/zBVtpR6J7QOmzt9pROmOEBk3sEY/6Ur/Y7dn3FWP14rRsMyRUlj82KFSl+SEmR0WU3YxYoO8oii8Z84nPrAx68iX4zWM5p82m7n0nwnbRLcQcl6Ue5AoGACjVN42viEnjS/DLx/MrVzjU5tVsZ/vJCdQyIY+RL8seENlREgKHFrso8lbJDki6tx9/isCVcEn7WO4qzKD1O7WxgNKAPYP5aTpUgcUllIzXhoIPCK2lguPbapANefoAdcfnyyQgd78fpDTJKc3MpNSx9m6BEPSalh77HN5afC68CgYBSHR2vz1GuUzHSgU+3xKqGSc+jlroetJ1dC5913Z+9eawW7QrRfmSod+JfEiJSw8eS+5/rGYjKihMtNPyqzadRvZtp0QGZrrm1k1/vqqeeH5Uq6AgH/2Djql4tUvC3gmgpHjY7RyPDv6v+u+L9C6MP0Nu5vVfQwpAmX9bsjn/Tjw==";
const PS256_PUBLIC_KEY_B64: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh4wOYmrsL6NrEQedvYldXPqflrhhc5ORFBhRS2KCB8QMKP60pmdvw9NHqcG+FszsQOHPPtUAPtK2SDd+RbYvVorp7dG9Q4AtLbkoJTc6RBOYI4Uw3AFmTgTzgjLfaShLrkAuHqgUcT6BuWNeHVYuOv2kDkEqlOSNE93G3i5Yk8415K73askhVzBqTPfyOOvUmUcWWw4AfMFHAdp0yLsDqJIzf1afgaTDOUJkeuiemhTYvC6gpkL94K1CNZDNX6qwt2s/2HMl3A744p2oMl7BmIFtmaVyH9u+tFF7/2wEgDjtNbICPM8WyA3RulXfu4j4a+G/7+kCI+q6blERX57NiwIDAQAB";

/// HMAC shared secret for HS256.
const HS256_SECRET: &[u8] = b"benchmark-secret-key-for-hmac-sha256";

/// One algorithm under test, with its signing and verifying key material.
struct AlgCase {
    /// Stable identifier used both as the Criterion benchmark id and the JSON key.
    id: &'static str,
    algorithm: Algorithm,
    /// Key passed to `sign` (HMAC secret, or PKCS#8 DER private key).
    signing_key: Vec<u8>,
    /// Key passed to `verify` (same HMAC secret, or SPKI DER public key).
    verifying_key: Vec<u8>,
}

/// Build the set of algorithms to benchmark.
fn alg_cases() -> Vec<AlgCase> {
    let es_priv = Base64::decode_to_vec(ES256_PRIVATE_KEY_B64, None).expect("valid ES256 private");
    let es_pub = Base64::decode_to_vec(ES256_PUBLIC_KEY_B64, None).expect("valid ES256 public");
    let ps_priv = Base64::decode_to_vec(PS256_PRIVATE_KEY_B64, None).expect("valid PS256 private");
    let ps_pub = Base64::decode_to_vec(PS256_PUBLIC_KEY_B64, None).expect("valid PS256 public");

    vec![
        AlgCase {
            id: "HS256",
            algorithm: Algorithm::HmacSha256,
            signing_key: HS256_SECRET.to_vec(),
            verifying_key: HS256_SECRET.to_vec(),
        },
        AlgCase {
            id: "ES256",
            algorithm: Algorithm::Es256,
            signing_key: es_priv,
            verifying_key: es_pub,
        },
        AlgCase {
            id: "PS256",
            algorithm: Algorithm::Ps256,
            signing_key: ps_priv,
            verifying_key: ps_pub,
        },
    ]
}

/// A representative CAT builder shared across signing benchmarks so every
/// algorithm signs an identically-shaped payload.
fn sample_builder(algorithm: Algorithm) -> TokenBuilder {
    let now = current_timestamp();
    TokenBuilder::new()
        .algorithm(algorithm)
        .protected_key_id(KeyId::string("bench-key-1"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("example-issuer")
                .with_subject("example-subject")
                .with_audience("example-audience")
                .with_expiration(now + 3600)
                .with_not_before(now)
                .with_issued_at(now),
        )
        .custom_string(100, "custom-string-value")
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign");
    for case in alg_cases() {
        group.bench_function(case.id, |b| {
            b.iter_batched(
                || sample_builder(case.algorithm),
                |builder| builder.sign(&case.signing_key).expect("sign"),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");
    for case in alg_cases() {
        // Pre-sign and decode once; the benchmark measures only signature/tag
        // verification, not CBOR decoding.
        let token = sample_builder(case.algorithm)
            .sign(&case.signing_key)
            .expect("sign");
        let bytes = token.to_bytes().expect("encode");
        let decoded = Token::from_bytes(&bytes).expect("decode");

        // Sanity check before timing so a broken setup fails loudly.
        decoded.verify(&case.verifying_key).expect("verify");

        group.bench_function(case.id, |b| {
            b.iter(|| decoded.verify(&case.verifying_key).expect("verify"));
        });
    }
    group.finish();

    // Emit size data alongside the timing benchmarks so the report generator
    // has everything it needs from a single `cargo bench` run.
    write_sizes();
}

/// Measure signature and token sizes for each algorithm and write them to
/// `target/bench/sizes.json` for the report generator to consume.
fn write_sizes() {
    let mut entries = Vec::new();
    for case in alg_cases() {
        let token = sample_builder(case.algorithm)
            .sign(&case.signing_key)
            .expect("sign");
        let token_bytes = token.to_bytes().expect("encode");

        // Verify claims too, just to confirm the sized token is fully valid.
        let options = VerificationOptions::new()
            .verify_exp(true)
            .verify_nbf(true)
            .expected_issuer("example-issuer")
            .expected_audience("example-audience");
        token.verify_claims(&options).expect("claims valid");

        entries.push(format!(
            "    {{\n      \"algorithm\": \"{}\",\n      \"signature_bytes\": {},\n      \"token_bytes\": {}\n    }}",
            case.id,
            token.signature.len(),
            token_bytes.len()
        ));
    }

    let json = format!("{{\n  \"sizes\": [\n{}\n  ]\n}}\n", entries.join(",\n"));

    let dir = Path::new("target/bench");
    fs::create_dir_all(dir).expect("create target/bench");
    fs::write(dir.join("sizes.json"), json).expect("write sizes.json");
}

criterion_group!(benches, bench_sign, bench_verify);
criterion_main!(benches);
