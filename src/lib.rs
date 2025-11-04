//! # Common Access Token (CAT)
//!
//! A Rust implementation of the Common Access Token specification, which is based on CBOR Object Signing and Encryption (COSE).
//!
//! ## Overview
//!
//! Common Access Tokens are compact, secure tokens designed for efficient transmission in resource-constrained environments.
//! They use CBOR encoding for smaller token sizes compared to JSON-based tokens like JWT.
//!
//! ## Features
//!
//! - CBOR-encoded tokens for compact representation
//! - Support for both COSE_Sign1 and COSE_Mac0 structures
//! - HMAC-SHA256 authentication
//! - Protected and unprotected headers
//! - Standard registered claims (issuer, subject, audience, expiration, etc.)
//! - Custom claims with string, binary, integer, and nested map values
//! - CAT-specific claims for URI validation (CATU), HTTP method restrictions (CATM),
//!   replay protection (CATREPLAY), and token renewal (CATR)
//! - Comprehensive token verification including CAT-specific claim validation
//!
//! ## Basic Example
//!
//! ```rust
//! use common_access_token::{Algorithm, KeyId, RegisteredClaims, TokenBuilder, VerificationOptions};
//! use common_access_token::current_timestamp;
//!
//! // Create a key for signing and verification
//! let key = b"my-secret-key-for-hmac-sha256";
//! let now = current_timestamp();
//!
//! // Create a token
//! let token = TokenBuilder::new()
//!     .algorithm(Algorithm::HmacSha256)
//!     .protected_key_id(KeyId::string("example-key-id"))
//!     .registered_claims(
//!         RegisteredClaims::new()
//!             .with_issuer("example-issuer")
//!             .with_subject("example-subject")
//!             .with_audience("example-audience")
//!             .with_expiration(now + 3600) // 1 hour from now
//!     )
//!     .custom_string(100, "custom-value")
//!     .sign(key)
//!     .expect("Failed to sign token");
//!
//! // Encode token to bytes
//! let token_bytes = token.to_bytes().expect("Failed to encode token");
//!
//! // Decode and verify the token
//! let decoded_token = common_access_token::Token::from_bytes(&token_bytes)
//!     .expect("Failed to decode token");
//!
//! // Verify the signature
//! decoded_token.verify(key).expect("Failed to verify signature");
//!
//! // Verify the claims
//! let options = VerificationOptions::new()
//!     .verify_exp(true)
//!     .expected_issuer("example-issuer");
//!
//! decoded_token.verify_claims(&options).expect("Failed to verify claims");
//! ```
//!
//! ## CAT-Specific Claims Example
//!
//! ```rust
//! use common_access_token::{
//!     Algorithm, KeyId, RegisteredClaims, TokenBuilder, VerificationOptions,
//!     cat_keys, catm, catr, catreplay, catu, uri_components, current_timestamp,
//!     cattprint, tprint_type_values
//! };
//! use std::collections::BTreeMap;
//!
//! // Create a key for signing and verification
//! let key = b"my-secret-key-for-hmac-sha256";
//! let now = current_timestamp();
//!
//! // Create CATU claim (URI restrictions)
//! let mut catu_components = BTreeMap::new();
//! // Restrict to https scheme
//! catu_components.insert(uri_components::SCHEME, catu::exact_match("https"));
//! // Restrict to example.com host
//! catu_components.insert(uri_components::HOST, catu::suffix_match(".example.com"));
//! // Restrict to paths starting with /api
//! catu_components.insert(uri_components::PATH, catu::prefix_match("/api"));
//!
//! // Create CATM claim (HTTP method restrictions)
//! let allowed_methods = vec!["GET", "HEAD"];
//!
//! // Create a token with CAT-specific claims
//! let token = TokenBuilder::new()
//!     .algorithm(Algorithm::HmacSha256)
//!     .protected_key_id(KeyId::string("example-key-id"))
//!     .registered_claims(
//!         RegisteredClaims::new()
//!             .with_issuer("example-issuer")
//!             .with_expiration(now + 3600)
//!     )
//!     // Add CAT-specific claims
//!     .custom_cbor(cat_keys::CATU, catu::create(catu_components))
//!     .custom_array(cat_keys::CATM, catm::create(allowed_methods))
//!     .custom_cbor(cat_keys::CATREPLAY, catreplay::prohibited())
//!     .custom_cbor(cat_keys::CATTPRINT, cattprint::create(tprint_type_values::JA4, "t13d1516h2_8daaf6152771_b186095e22b6"))
//!     .sign(key)
//!     .expect("Failed to sign token");
//!
//! // Encode token to bytes
//! let token_bytes = token.to_bytes().expect("Failed to encode token");
//!
//! // Decode and verify the token
//! let decoded_token = common_access_token::Token::from_bytes(&token_bytes)
//!     .expect("Failed to decode token");
//!
//! // Verify signature
//! decoded_token.verify(key).expect("Failed to verify signature");
//!
//! // Verify standard claims and CAT-specific claims
//! let options = VerificationOptions::new()
//!     .verify_exp(true)
//!     .expected_issuer("example-issuer")
//!     // Add CAT-specific claim verification
//!     .verify_catu(true)
//!     .uri("https://api.example.com/api/users")
//!     .verify_catm(true)
//!     .http_method("GET")
//!     .verify_catreplay(true)
//!     .token_seen_before(false);
//!
//! decoded_token.verify_claims(&options).expect("Failed to verify all claims");
//! ```

pub mod cat_claims;
pub mod claims;
pub mod constants;
pub mod error;
pub mod header;
pub mod token;
pub mod utils;

pub use cat_claims::{
    catalpn, catdpop, catgeoalt, catgeocoord, catgeoiso3166, cath, catif, catifdata, catm, catnip,
    catpor, catr, catreplay, cattpk, catu, catv, cattprint,
};
pub use claims::{Claims, RegisteredClaims};
pub use constants::{
    cat_keys, cose_algs, cose_labels, cwt_keys, match_types, renewal_params, renewal_types,
    replay_values, uri_components, tprint_params, FingerprintType
};
pub use error::Error;
pub use header::{Algorithm, CborValue, Header, HeaderMap, KeyId};
pub use token::{Token, TokenBuilder, VerificationOptions};
pub use utils::current_timestamp;

/// Re-export minicbor for users of this crate
pub use minicbor;

#[cfg(test)]
mod tests;
