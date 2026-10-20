//! Tests for the injectable verification clock

use crate::{
    claims::RegisteredClaims,
    header::Algorithm,
    token::{Token, TokenBuilder, VerificationOptions},
    Error,
};

const NBF: u64 = 1_000_000;
const EXP: u64 = 2_000_000;

fn token() -> Token {
    TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_not_before(NBF)
                .with_expiration(EXP),
        )
        .sign(b"clock-test-key")
        .unwrap()
}

#[test]
fn test_injected_clock_drives_exp_and_nbf() {
    let token = token();
    let at = |now| token.verify_claims(&VerificationOptions::new().now(now));

    assert!(matches!(at(NBF - 1), Err(Error::NotYetValid)));
    assert!(at(NBF).is_ok());
    assert!(at(EXP - 1).is_ok());
    assert!(matches!(at(EXP), Err(Error::Expired)));
}

#[test]
fn test_system_clock_is_the_default() {
    // EXP is in 1970, so the system clock sees the token as expired
    assert_eq!(VerificationOptions::new().now, None);
    assert!(matches!(
        token().verify_claims(&VerificationOptions::new()),
        Err(Error::Expired)
    ));
}

#[test]
fn test_leeway_extends_exp_and_nbf_in_the_permissive_direction() {
    let token = token();
    let at = |now, leeway| token.verify_claims(&VerificationOptions::new().now(now).leeway(leeway));

    // exp: valid until leeway seconds past exp
    assert!(at(EXP + 29, 30).is_ok());
    assert!(matches!(at(EXP + 30, 30), Err(Error::Expired)));
    // nbf: valid from leeway seconds before nbf
    assert!(at(NBF - 30, 30).is_ok());
    assert!(matches!(at(NBF - 31, 30), Err(Error::NotYetValid)));
    // No leeway by default
    assert_eq!(VerificationOptions::new().leeway, 0);
    assert!(matches!(at(EXP, 0), Err(Error::Expired)));
}

#[test]
fn test_leeway_saturates() {
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_not_before(u64::MAX)
                .with_expiration(u64::MAX),
        )
        .sign(b"clock-test-key")
        .unwrap();
    let options = VerificationOptions::new()
        .now(u64::MAX - 1)
        .leeway(u64::MAX);
    assert!(token.verify_claims(&options).is_ok());
}
