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

/// Get current timestamp in seconds since Unix epoch
pub fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
