//! Tests for COSE structure tag handling on decode

use crate::{
    claims::RegisteredClaims,
    header::{Algorithm, KeyId},
    token::{Token, TokenBuilder},
    Error,
};
use ct_codecs::{Base64, Decoder};

const CWT: u8 = 0x3d; // tag 61, encoded as 0xd8 0x3d
const MAC0: u8 = 0xd1; // tag 17
const SIGN1: u8 = 0xd2; // tag 18

// Same demo ES256 key as `src/tests.rs`; DO NOT USE IN PRODUCTION.
const ES256_PRIVATE_KEY_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7BOlgwBOMKscTUCaG3RmlSCgUznDdxMn+9Pvoqp4pUOhRANCAARWMcvR3DnF1U15IvgcOyAxr3pJPfOHcF7ESuY+H+ya3LCH03PC1d99/XgN1ldF+wmMxVhY0w9iop10N6tNZDTg";

/// Sign a token with `alg` and return its encoding: tag 61, COSE tag, array.
fn token_bytes(alg: Algorithm) -> Vec<u8> {
    let key = match alg {
        Algorithm::HmacSha256 => b"cose-tag-test-key".to_vec(),
        _ => Base64::decode_to_vec(ES256_PRIVATE_KEY_B64, None).unwrap(),
    };
    let bytes = TokenBuilder::new()
        .algorithm(alg)
        .protected_key_id(KeyId::string("k"))
        .registered_claims(RegisteredClaims::new().with_issuer("issuer"))
        .sign(&key)
        .unwrap()
        .to_bytes()
        .unwrap();
    assert_eq!(&bytes[..2], &[0xd8, CWT]);
    bytes
}

fn with_structure_tag(mut bytes: Vec<u8>, tag: u8) -> Vec<u8> {
    bytes[2] = tag;
    bytes
}

#[test]
fn test_matching_structure_tag_is_accepted() {
    assert!(Token::from_bytes(&token_bytes(Algorithm::HmacSha256)).is_ok());
    assert!(Token::from_bytes(&token_bytes(Algorithm::Es256)).is_ok());
}

#[test]
fn test_mac0_tag_with_signature_alg_is_rejected() {
    let bytes = with_structure_tag(token_bytes(Algorithm::Es256), MAC0);
    assert!(matches!(
        Token::from_bytes(&bytes),
        Err(Error::StructureTagMismatch {
            tag: 17,
            algorithm: Algorithm::Es256,
            expected: 18,
        })
    ));
}

#[test]
fn test_sign1_tag_with_mac_alg_is_rejected() {
    let bytes = with_structure_tag(token_bytes(Algorithm::HmacSha256), SIGN1);
    assert!(matches!(
        Token::from_bytes(&bytes),
        Err(Error::StructureTagMismatch { .. })
    ));
}

#[test]
fn test_mismatch_is_rejected_without_cwt_tag() {
    // COSE tag only, no leading CWT tag
    let bytes = with_structure_tag(token_bytes(Algorithm::HmacSha256), SIGN1);
    assert!(matches!(
        Token::from_bytes(&bytes[2..]),
        Err(Error::StructureTagMismatch { .. })
    ));
    let bytes = token_bytes(Algorithm::HmacSha256);
    assert!(Token::from_bytes(&bytes[2..]).is_ok());
}

#[test]
fn test_untagged_and_cwt_only_tokens_are_still_accepted() {
    for alg in [Algorithm::HmacSha256, Algorithm::Es256] {
        let bytes = token_bytes(alg);
        // Untagged: drop tag 61 and the COSE tag
        assert!(Token::from_bytes(&bytes[3..]).is_ok());
        // CWT tag only: tag 61 followed directly by the array
        let mut cwt_only = bytes[..2].to_vec();
        cwt_only.extend_from_slice(&bytes[3..]);
        assert!(Token::from_bytes(&cwt_only).is_ok());
    }
}

/// Re-wrap a token's 4-element array in exactly `tags` (outermost first).
fn with_tags(alg: Algorithm, tags: &[u64]) -> Vec<u8> {
    let body = token_bytes(alg)[3..].to_vec(); // drop tags 61 and 17/18
    let mut out = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut out);
    for tag in tags {
        enc.tag(minicbor::data::Tag::new(*tag)).unwrap();
    }
    out.extend_from_slice(&body);
    out
}

#[test]
fn test_accepted_leading_tag_forms() {
    for (alg, structure) in [(Algorithm::HmacSha256, 17), (Algorithm::Es256, 18)] {
        for tags in [&[][..], &[61], &[structure], &[61, structure]] {
            assert!(
                Token::from_bytes(&with_tags(alg, tags)).is_ok(),
                "{alg:?} with tags {tags:?}"
            );
        }
    }
}

#[test]
fn test_unexpected_leading_tags_are_rejected() {
    for (alg, structure, other) in [(Algorithm::HmacSha256, 17, 18), (Algorithm::Es256, 18, 17)] {
        let refused: [&[u64]; 9] = [
            // Something other than the CWT tag in its place
            &[189, structure],
            &[98, structure],
            &[24, structure],
            &[24],
            // Tags in the wrong order or repeated
            &[structure, 61],
            &[61, 61],
            &[other, structure],
            // Three tags
            &[61, 61, structure],
            &[61, structure, structure],
        ];
        for tags in refused {
            assert!(
                matches!(
                    Token::from_bytes(&with_tags(alg, tags)),
                    Err(Error::InvalidFormat(_))
                ),
                "{alg:?} with tags {tags:?}"
            );
        }
        // A structure tag of the wrong class is still a typed mismatch
        assert!(matches!(
            Token::from_bytes(&with_tags(alg, &[61, other])),
            Err(Error::StructureTagMismatch { .. })
        ));
    }
}
