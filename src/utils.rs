//! Utility functions for Common Access Token

use crate::error::Error;
use hmac_sha256::HMAC;

/// Compute HMAC-SHA256 signature
pub fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    HMAC::mac(data, key).to_vec()
}

/// Verify HMAC-SHA256 signature
pub fn verify_hmac_sha256(key: &[u8], data: &[u8], signature: &[u8]) -> Result<(), Error> {
    let computed_mac = HMAC::mac(data, key);

    if ct_codecs::verify(&computed_mac, signature) {
        Ok(())
    } else {
        Err(Error::SignatureVerification)
    }
}

/// Compute an ES256 (ECDSA P-256 + SHA-256) signature over `data`.
///
/// `key` must be a PKCS#8 DER-encoded P-256 private key. The returned signature
/// is the fixed-length 64-byte COSE representation (`r || s`), as required by the
/// COSE specification (RFC 9053 §2.1).
///
/// The signature is normalized to "low-S" form. ECDSA signatures are malleable:
/// for any valid `(r, s)`, the pair `(r, n - s)` is an equally valid signature
/// over the same message. Emitting only low-S signatures yields a canonical
/// encoding (each token has one signature) and interoperates with strict
/// verifiers that reject high-S (e.g. WebCrypto and various COSE stacks). The
/// matching `verify_es256` likewise rejects high-S.
pub fn compute_es256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::pkcs8::DecodePrivateKey;

    let signing_key = SigningKey::from_pkcs8_der(key)
        .map_err(|e| Error::InvalidKey(format!("Invalid ES256 private key: {e}")))?;
    // ECDSA signing with the RustCrypto `ecdsa` crate is deterministic (RFC 6979),
    // so no RNG is required here.
    let signature: Signature = signing_key.sign(data);
    // Normalize to low-S. `normalize_s` returns `Some` only when the signature
    // was high-S; otherwise the original (already low-S) signature is used.
    let signature = signature.normalize_s().unwrap_or(signature);
    Ok(signature.to_bytes().to_vec())
}

/// Verify an ES256 (ECDSA P-256 + SHA-256) signature over `data`.
///
/// `key` must be an SPKI DER-encoded P-256 public key. `signature` must be the
/// fixed-length 64-byte COSE representation (`r || s`).
///
/// High-S signatures are rejected. Because ECDSA signatures are malleable
/// (`(r, s)` and `(r, n - s)` are both valid), accepting high-S would let a
/// third party derive a second valid signature for an unchanged token without
/// the private key. Requiring low-S makes the accepted signature canonical, so
/// the signature bytes are safe to use as an identity/dedup key.
pub fn verify_es256(key: &[u8], data: &[u8], signature: &[u8]) -> Result<(), Error> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    let verifying_key = VerifyingKey::from_public_key_der(key)
        .map_err(|e| Error::InvalidKey(format!("Invalid ES256 public key: {e}")))?;
    let signature = Signature::from_slice(signature).map_err(|_| Error::SignatureVerification)?;
    // Reject high-S (non-canonical) signatures. `normalize_s` returns `Some`
    // exactly when the signature is high-S, so a `Some` here means the input
    // was malleable and must not be accepted.
    if signature.normalize_s().is_some() {
        return Err(Error::SignatureVerification);
    }
    verifying_key
        .verify(data, &signature)
        .map_err(|_| Error::SignatureVerification)
}

/// Compute a PS256 (RSASSA-PSS with SHA-256 and MGF1-SHA-256) signature over `data`.
///
/// `key` must be a PKCS#8 DER-encoded RSA private key. PSS uses a random salt, so
/// an OS-provided RNG is used (WASM-friendly via `getrandom`).
pub fn compute_ps256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::pss::SigningKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use rsa::RsaPrivateKey;

    let private_key = RsaPrivateKey::from_pkcs8_der(key)
        .map_err(|e| Error::InvalidKey(format!("Invalid PS256 private key: {e}")))?;
    let signing_key = SigningKey::<sha2::Sha256>::new(private_key);
    let mut rng = rand_core::OsRng;
    let signature = signing_key.sign_with_rng(&mut rng, data);
    Ok(signature.to_vec())
}

/// Verify a PS256 (RSASSA-PSS with SHA-256 and MGF1-SHA-256) signature over `data`.
///
/// `key` must be an SPKI DER-encoded RSA public key.
pub fn verify_ps256(key: &[u8], data: &[u8], signature: &[u8]) -> Result<(), Error> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;

    let public_key = RsaPublicKey::from_public_key_der(key)
        .map_err(|e| Error::InvalidKey(format!("Invalid PS256 public key: {e}")))?;
    let verifying_key = VerifyingKey::<sha2::Sha256>::new(public_key);
    let signature = Signature::try_from(signature).map_err(|_| Error::SignatureVerification)?;
    verifying_key
        .verify(data, &signature)
        .map_err(|_| Error::SignatureVerification)
}

/// Get current timestamp in seconds since Unix epoch
pub fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
