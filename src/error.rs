//! Error types for the Common Access Token library

use std::io::Error as IoError;
use thiserror::Error;

/// Errors that can occur when working with Common Access Tokens
#[derive(Error, Debug)]
pub enum Error {
    /// Error during CBOR encoding
    #[error("CBOR encoding error: {0}")]
    CborEncode(#[from] minicbor::encode::Error<IoError>),

    /// Error during CBOR encoding with infallible writer
    #[error("CBOR encoding error: {0}")]
    CborEncodeInfallible(#[from] minicbor::encode::Error<std::convert::Infallible>),

    /// Error during CBOR decoding
    #[error("CBOR decode error: {0}")]
    CborDecode(#[from] minicbor::decode::Error),

    /// Invalid token format
    #[error("Invalid token format: {0}")]
    InvalidFormat(String),

    /// Invalid algorithm
    #[error("Invalid algorithm: {0}")]
    InvalidAlgorithm(String),

    /// Signature verification failed
    #[error("Signature verification failed. The token's signature does not match the expected signature")]
    SignatureVerification,

    /// Missing required claim
    #[error("Missing required claim: {0}. The token does not contain a required claim")]
    MissingClaim(String),

    /// Token expired
    #[error("Token expired. The token's expiration time (exp) is in the past")]
    Expired,

    /// Token not yet valid
    #[error("Token not yet valid. The token's not-before time (nbf) is in the future")]
    NotYetValid,

    /// Invalid issuer
    #[error("Invalid issuer. The token's issuer (iss) does not match the expected issuer")]
    InvalidIssuer,

    /// Invalid audience
    #[error("Invalid audience. The token's audience (aud) does not match the expected audience")]
    InvalidAudience,

    /// Invalid claim value
    #[error("Invalid claim value: {0}")]
    InvalidClaimValue(String),

    /// Invalid URI claim
    #[error("Invalid URI claim: {0}")]
    InvalidUriClaim(String),

    /// Invalid method claim
    #[error("Invalid method claim: {0}")]
    InvalidMethodClaim(String),

    /// Invalid renewal claim
    #[error("Invalid renewal claim: {0}")]
    InvalidRenewalClaim(String),

    /// Token replay violation
    #[error("Token replay violation: {0}")]
    ReplayViolation(String),

    /// Other error
    #[error("Other error: {0}")]
    Other(String),
}
