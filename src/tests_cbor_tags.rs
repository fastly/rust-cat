//! Tests for CBOR tags in claim values and RFC 9164 CATNIP entries

use crate::{
    cat_claims::catnip::{self, NetworkIdentifier},
    constants::cat_keys,
    header::{Algorithm, CborValue},
    token::{Token, TokenBuilder},
    Error,
};
use ct_codecs::{Decoder, Encoder, Hex};
use std::collections::BTreeMap;
use std::net::IpAddr;

fn hex(s: &str) -> Vec<u8> {
    Hex::decode_to_vec(s, None).unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// HMAC key from draft-ietf-moq-c4m-02 Appendix A.1: bytes 0x00..=0x1f
fn draft_hmac_key() -> Vec<u8> {
    (0u8..32).collect()
}

/// Wrap a raw claims payload in an unsigned COSE_Mac0 so it can be decoded
fn token_from_payload(payload: &[u8]) -> Token {
    let mut bytes = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut bytes);
    enc.array(4).unwrap();
    enc.bytes(&[0xa1, 0x01, 0x05]).unwrap();
    enc.map(0).unwrap();
    enc.bytes(payload).unwrap();
    enc.bytes(&[]).unwrap();
    Token::from_bytes(&bytes).expect("valid token structure")
}

fn tag(n: u64, v: CborValue) -> CborValue {
    CborValue::Tag(n, Box::new(v))
}

#[test]
fn test_tags_decode_in_arrays_maps_and_nested_tags() {
    // {900: [52(h'c0000201'), {1: 54(h'')}, 1(2(h'00'))]}
    let payload = hex("a1190384\
                       83d83444c0000201a101d83640c1c24100");
    let token = token_from_payload(&payload);
    let mut inner = BTreeMap::new();
    inner.insert(1, tag(54, CborValue::Bytes(vec![])));
    assert_eq!(
        token.get_custom_claim(900),
        Some(&CborValue::Array(vec![
            tag(52, CborValue::Bytes(vec![192, 0, 2, 1])),
            CborValue::Map(inner),
            tag(1, tag(2, CborValue::Bytes(vec![0]))),
        ]))
    );
}

#[test]
fn test_tags_encode_byte_for_byte() {
    let value = CborValue::Array(vec![
        tag(52, CborValue::Bytes(vec![192, 0, 2, 1])),
        tag(1, tag(2, CborValue::Bytes(vec![0]))),
    ]);
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .custom_cbor(900, value.clone())
        .sign(b"key")
        .unwrap();
    let bytes = token.to_bytes().unwrap();
    let expected = hex("82d83444c0000201c1c24100");
    assert!(bytes
        .windows(expected.len())
        .any(|w| w == expected.as_slice()));

    let decoded = Token::from_bytes(&bytes).unwrap();
    decoded.verify(b"key").unwrap();
    assert_eq!(decoded.get_custom_claim(900), Some(&value));
}

#[test]
fn test_draft_vectors_with_tagged_catnip_verify() {
    // draft-ietf-moq-c4m-02 A.3 token_hmac_full and A.6 composite_and both
    // carry RFC 9164 tagged catnip entries, which used to fail to decode.
    let full = Token::from_bytes(&hex(
        "d18448a201051063434154a058abaa01781a68747470733a2f2f6973737565722e6d6f712e657861\
        6d706c650276757365723a616c696365406578616d706c652e636f6d0382781a68747470733a2f2f\
        72656c6179312e6578616d706c652e636f6d781a68747470733a2f2f72656c6179322e6578616d70\
        6c652e636f6d041a65554280051a6553f100061a6553f100074a766563746f722d30303219013601\
        19013781d83444cb007132190138a103a101662f6c6976652f582029c1a6612ce6d49273fd8c0116\
        b9decbc287662d5ba5d67defafaf6ff0c11278",
    ))
    .expect("decode token_hmac_full");
    full.verify(&draft_hmac_key()).expect("token_hmac_full MAC");
    assert_eq!(
        catnip::parse(full.get_custom_claim(cat_keys::CATNIP).unwrap()).unwrap(),
        vec![NetworkIdentifier::Address(ip("203.0.113.50"))]
    );

    let and = Token::from_bytes(&hex(
        "d18448a201051063434154a05841a301781868747470733a2f2f617574682e6578616d706c652e63\
        6f6d041a655542800082a2041a6555428019013601a2041a6555428019013781d834440a00000058\
        208ca3213e71dfe3900fd910fcb7f6d365949e72e81ceba80f2ff24048502e9a1a",
    ))
    .expect("decode composite_and");
    and.verify(&draft_hmac_key()).expect("composite_and MAC");
}

#[test]
fn test_draft_network_identifiers_vector() {
    // draft-ietf-moq-c4m-02 A.2 cbor_network_identifiers:
    // {311: [52(h'c0a80164'), 52([8, h'0a']), 64512, [64512, 64768]]}
    let payload = hex("a119013784d83444c0a80164d8348208410a19fc008219fc0019fd00");
    let token = token_from_payload(&payload);
    let claim = token.get_custom_claim(cat_keys::CATNIP).unwrap();
    let ids = vec![
        NetworkIdentifier::Address(ip("192.168.1.100")),
        NetworkIdentifier::Prefix(ip("10.0.0.0"), 8),
        NetworkIdentifier::Asn(64512),
        NetworkIdentifier::AsnRange(64512, 64768),
    ];
    assert_eq!(catnip::parse(claim).unwrap(), ids);

    // Re-encoding reproduces the vector exactly
    let encoded = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .custom_array(cat_keys::CATNIP, catnip::from_identifiers(&ids))
        .sign(b"key")
        .unwrap()
        .to_bytes()
        .unwrap();
    assert!(encoded
        .windows(payload.len())
        .any(|w| w == payload.as_slice()));
}

#[test]
fn test_catnip_create_encodings() {
    let cases = [
        ("192.168.1.100", "d83444c0a80164"),
        ("10.0.0.0/8", "d8348208410a"),
        // Host bits are cleared
        ("10.1.2.3/8", "d8348208410a"),
        ("192.0.2.0/24", "d834821818 43c00002"),
        ("0.0.0.0/0", "d834820040"),
        ("2001:db8::1", "d8365020010db8000000000000000000000001"),
        ("2001:db8::/32", "d83682182044 20010db8"),
        ("::/0", "d836820040"),
        ("64512", "19fc00"),
    ];
    for (input, expected) in cases {
        let got = catnip::single(input).unwrap();
        let mut bytes = Vec::new();
        let token = TokenBuilder::new()
            .algorithm(Algorithm::HmacSha256)
            .custom_array(900, got.clone())
            .sign(b"key")
            .unwrap();
        bytes.extend(token.to_bytes().unwrap());
        let expected = hex(&expected.replace(' ', ""));
        assert!(
            bytes
                .windows(expected.len())
                .any(|w| w == expected.as_slice()),
            "{input} should encode as {}",
            Hex::encode_to_string(&expected).unwrap()
        );
        // And round-trips through parse
        let reparsed = catnip::parse(&CborValue::Array(got)).unwrap();
        assert_eq!(reparsed, vec![NetworkIdentifier::parse(input).unwrap()]);
    }
}

#[test]
fn test_catnip_rejects_invalid_input() {
    for input in [
        "",
        "abc",
        "300.1.1.1",
        "10.0.0.0/33",
        "2001:db8::/129",
        "10.0.0.0/",
        "99999999999",
    ] {
        assert!(
            matches!(catnip::single(input), Err(Error::InvalidClaimValue(_))),
            "{input:?} should be rejected"
        );
    }

    let bad = [
        (
            "host bits set",
            tag(
                52,
                CborValue::Array(vec![CborValue::Integer(8), CborValue::Bytes(vec![10, 1])]),
            ),
        ),
        (
            "interface form",
            tag(
                52,
                CborValue::Array(vec![
                    CborValue::Bytes(vec![192, 168, 1, 1]),
                    CborValue::Integer(24),
                ]),
            ),
        ),
        ("short address", tag(52, CborValue::Bytes(vec![1, 2]))),
        (
            "prefix too long",
            tag(
                52,
                CborValue::Array(vec![CborValue::Integer(33), CborValue::Bytes(vec![])]),
            ),
        ),
        (
            "address bytes too long",
            tag(
                52,
                CborValue::Array(vec![
                    CborValue::Integer(8),
                    CborValue::Bytes(vec![10, 0, 0, 0, 0]),
                ]),
            ),
        ),
        ("unknown tag", tag(99, CborValue::Bytes(vec![1, 2, 3, 4]))),
        ("negative ASN", CborValue::Integer(-1)),
        (
            "reversed ASN range",
            CborValue::Array(vec![CborValue::Integer(10), CborValue::Integer(5)]),
        ),
        ("text entry", CborValue::Text("10.0.0.0/8".into())),
    ];
    for (name, value) in bad {
        assert!(
            matches!(
                NetworkIdentifier::from_cbor(&value),
                Err(Error::InvalidClaimValue(_))
            ),
            "{name} should be rejected"
        );
    }
    assert!(catnip::parse(&CborValue::Integer(1)).is_err());
}
