//! Fuzz `Token::from_bytes` and what a verifier does with a decoded token.
//!
//! Run with `cargo +nightly fuzz run decode_token`. Any panic, abort or stack
//! overflow on arbitrary input is a bug: decoding untrusted tokens must only
//! ever return `Ok` or `Err`.
#![no_main]

use common_access_token::{Token, VerificationOptions};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(token) = Token::from_bytes(data) {
        let _ = token.to_bytes();
        let _ = token.verify_claims(&VerificationOptions::new());
    }
});
