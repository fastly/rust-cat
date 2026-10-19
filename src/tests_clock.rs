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
