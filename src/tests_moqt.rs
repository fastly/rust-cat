//! Tests for MoQ Transport claims (draft-ietf-moq-c4m)

use crate::{
    claims::RegisteredClaims,
    constants::moqt_keys,
    header::{Algorithm, CborValue},
    moqt::{BinMatch, MoqtAction, MoqtClaim, MoqtRequest, MoqtRevalidation, MoqtScope},
    token::{Token, TokenBuilder, VerificationOptions},
    utils::current_timestamp,
    Error,
};
use ct_codecs::{Decoder, Hex};

use MoqtAction::*;

const KEY: &[u8] = b"moqt-test-key";

fn b(s: &str) -> CborValue {
    CborValue::Bytes(s.as_bytes().to_vec())
}

fn ints(v: &[i64]) -> CborValue {
    CborValue::Array(v.iter().map(|i| CborValue::Integer(*i)).collect())
}

fn arr(v: Vec<CborValue>) -> CborValue {
    CborValue::Array(v)
}

fn track(action: MoqtAction, ns: &[&str], name: &str) -> MoqtRequest {
    MoqtRequest::track(action, ns.iter().copied(), name)
}

/// Build an untagged, unsigned COSE_Mac0-shaped token around a raw payload so
/// draft payload vectors can be decoded with `Token::from_bytes`.
fn token_from_payload(payload: &[u8]) -> Token {
    let mut bytes = vec![0x84, 0x43, 0xa1, 0x01, 0x05, 0xa0];
    match payload.len() {
        n if n < 24 => bytes.push(0x40 | n as u8),
        n if n < 256 => bytes.extend([0x58, n as u8]),
        n => bytes.extend([0x59, (n >> 8) as u8, n as u8]),
    }
    bytes.extend_from_slice(payload);
    bytes.push(0x40);
    Token::from_bytes(&bytes).expect("valid token structure")
}

fn signed(builder: TokenBuilder) -> Token {
    let token = builder
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer")
                .with_audience("relay.example.com")
                .with_expiration(current_timestamp() + 3600),
        )
        .sign(KEY)
        .expect("sign");
    let decoded = Token::from_bytes(&token.to_bytes().expect("encode")).expect("decode");
    // TODO(#6): switch to `verify_with_key(VerifyingKey::HmacSha256(KEY))` once merged.
    decoded.verify(KEY).expect("verify");
    decoded
}

fn options(request: MoqtRequest) -> VerificationOptions {
    VerificationOptions::new()
        .expected_audience("relay.example.com")
        .verify_moqt(true)
        .moqt_request(request)
}

#[test]
fn test_moqt_action_codes_round_trip() {
    for code in 0..=8 {
        let action = MoqtAction::from_code(code).expect("known action");
        assert_eq!(action.code(), code);
    }
    assert_eq!(MoqtAction::from_code(9), None);
    assert_eq!(MoqtAction::from_code(-1), None);
}

#[test]
fn test_moqt_exact_namespace_with_trailing_nil() {
    // [[2,3,6,7], ['example','com',nil], '/bob']
    let claim = MoqtClaim::from_cbor(&arr(vec![arr(vec![
        ints(&[2, 3, 6, 7]),
        arr(vec![b("example"), b("com"), CborValue::Null]),
        b("/bob"),
    ])]))
    .unwrap();

    assert!(claim.permits(&track(Publish, &["example", "com"], "/bob")));
    assert!(!claim.permits(&track(Publish, &["example", "com"], "/bob/123")));
    assert!(!claim.permits(&track(Publish, &["example", "com", "x"], "/bob")));
    assert!(!claim.permits(&track(Subscribe, &["example", "com"], "/bob")));

    let built = MoqtClaim::new(vec![MoqtScope::new([
        PublishNamespace,
        SubscribeNamespace,
        Publish,
        Fetch,
    ])
    .namespace_exact("example")
    .namespace_exact("com")
    .namespace_end()
    .track_exact("/bob")]);
    assert_eq!(built, claim);
    assert_eq!(MoqtClaim::from_cbor(&built.to_cbor()).unwrap(), claim);
}

#[test]
fn test_moqt_track_prefix() {
    let claim = MoqtClaim::new(vec![MoqtScope::new([Fetch])
        .namespace_exact("example")
        .namespace_exact("com")
        .namespace_end()
        .track_prefix("/bob")]);

    for name in ["/bob", "/bob/123", "/bob/logs"] {
        assert!(claim.permits(&track(Fetch, &["example", "com"], name)));
    }
    assert!(!claim.permits(&track(Fetch, &["example", "com"], "/alice")));
}

#[test]
fn test_moqt_namespace_prefix_without_track() {
    // [[2,3,6,7], ['example','com']]
    let claim = MoqtClaim::from_cbor(&arr(vec![arr(vec![
        ints(&[2, 3, 6, 7]),
        arr(vec![b("example"), b("com")]),
    ])]))
    .unwrap();

    assert!(claim.permits(&track(Fetch, &["example", "com"], "anything")));
    assert!(claim.permits(&track(Fetch, &["example", "com", "bob"], "logs")));
    assert!(!claim.permits(&track(Fetch, &["example"], "anything")));
    assert!(!claim.permits(&track(Fetch, &["com", "bob"], "anything")));
    assert!(!claim.permits(&track(Fetch, &["alternate", "com"], "anything")));
}

#[test]
fn test_moqt_per_field_prefix_is_case_sensitive() {
    // ['example', [1,'user-'], nil], track '/data'
    let claim = MoqtClaim::from_cbor(&arr(vec![arr(vec![
        ints(&[4]),
        arr(vec![
            b("example"),
            arr(vec![CborValue::Integer(1), b("user-")]),
            CborValue::Null,
        ]),
        b("/data"),
    ])]))
    .unwrap();

    assert!(claim.permits(&track(Subscribe, &["example", "user-alice"], "/data")));
    assert!(!claim.permits(&track(Subscribe, &["example", "USER-alice"], "/data")));
    assert!(!claim.permits(&track(
        Subscribe,
        &["example", "user-alice", "extra"],
        "/data"
    )));
}

#[test]
fn test_moqt_track_suffix() {
    let claim = MoqtClaim::new(vec![MoqtScope::new([Publish])
        .namespace_exact("example")
        .track_suffix(".json")]);

    assert!(claim.permits(&track(Publish, &["example"], "data.json")));
    for name in ["data.JSON", "json", "data.json.bak"] {
        assert!(!claim.permits(&track(Publish, &["example"], name)));
    }
}

#[test]
fn test_moqt_track_without_namespace_encodes_any_first_field() {
    let scope = MoqtScope::new([Subscribe]).track_exact("video");
    let claim = MoqtClaim::new(vec![scope]);
    let parsed = MoqtClaim::from_cbor(&claim.to_cbor()).unwrap();

    assert_eq!(
        parsed.scopes()[0].namespace_matches(),
        &[BinMatch::Prefix(Vec::new())]
    );
    assert!(parsed.permits(&track(Subscribe, &["any"], "video")));
    assert!(!parsed.permits(&track(Subscribe, &["any"], "audio")));
}

#[test]
fn test_moqt_any_scope_may_permit() {
    let claim = MoqtClaim::new(vec![
        MoqtScope::new([Subscribe]).namespace_exact("a"),
        MoqtScope::new([Publish]).namespace_exact("b"),
    ]);

    assert!(claim.permits(&track(Subscribe, &["a"], "t")));
    assert!(claim.permits(&track(Publish, &["b"], "t")));
    assert!(!claim.permits(&track(Publish, &["a"], "t")));
    assert!(!claim.permits(&track(Subscribe, &["b"], "t")));
}

#[test]
fn test_moqt_unknown_action_codes_never_match() {
    let claim = MoqtClaim::from_cbor(&arr(vec![arr(vec![ints(&[99])])])).unwrap();
    assert_eq!(claim.scopes()[0].action_codes(), &[99]);
    for code in 0..=8 {
        let action = MoqtAction::from_code(code).unwrap();
        assert!(!claim.permits(&track(action, &["a"], "t")));
    }
}

#[test]
fn test_moqt_role_publisher() {
    let claim = MoqtClaim::new(vec![MoqtScope::new([PublishNamespace, Publish])
        .namespace_exact("example.com")
        .namespace_exact("alice")
        .track_prefix("video-")]);

    // Namespace actions ignore the track match
    assert!(claim.permits(&MoqtRequest::namespace(
        PublishNamespace,
        ["example.com", "alice"]
    )));
    assert!(claim.permits(&track(Publish, &["example.com", "alice"], "video-hd")));
    assert!(!claim.permits(&track(Publish, &["example.com", "alice"], "audio")));
    assert!(!claim.permits(&track(Publish, &["example.com", "bob"], "video-hd")));
    assert!(!claim.permits(&track(Subscribe, &["example.com", "alice"], "video-hd")));
    assert!(!claim.permits(&MoqtRequest::session(ClientSetup)));
}

#[test]
fn test_moqt_role_subscriber() {
    let claim = MoqtClaim::new(vec![MoqtScope::new([
        ClientSetup,
        Subscribe,
        Fetch,
        TrackStatus,
        RequestUpdate,
    ])
    .namespace_exact("example.com")
    .namespace_exact("alice")]);

    // Session actions ignore namespace and track matches
    assert!(claim.permits(&MoqtRequest::session(ClientSetup)));
    for action in [Subscribe, Fetch, TrackStatus, RequestUpdate] {
        assert!(claim.permits(&track(action, &["example.com", "alice"], "video")));
    }
    assert!(!claim.permits(&MoqtRequest::namespace(
        PublishNamespace,
        ["example.com", "alice"]
    )));
    assert!(!claim.permits(&track(Publish, &["example.com", "alice"], "video")));
}

#[test]
fn test_moqt_namespace_request_shorter_than_scope_is_denied() {
    let claim = MoqtClaim::new(vec![MoqtScope::new([SubscribeNamespace])
        .namespace_exact("example.com")
        .namespace_exact("alice")]);

    assert!(claim.permits(&MoqtRequest::namespace(
        SubscribeNamespace,
        ["example.com", "alice"]
    )));
    assert!(!claim.permits(&MoqtRequest::namespace(SubscribeNamespace, ["example.com"])));
}

#[test]
fn test_moqt_track_action_without_track_is_denied() {
    let claim = MoqtClaim::new(vec![MoqtScope::new([Subscribe])]);
    assert!(claim.permits(&track(Subscribe, &["a"], "t")));
    assert!(!claim.permits(&MoqtRequest::namespace(Subscribe, ["a"])));
}

#[test]
fn test_moqt_malformed_claims_are_rejected() {
    let malformed = [
        ("not an array", CborValue::Integer(1)),
        ("no scopes", arr(vec![])),
        ("empty scope", arr(vec![arr(vec![])])),
        ("empty actions", arr(vec![arr(vec![ints(&[])])])),
        (
            "non-int action",
            arr(vec![arr(vec![arr(vec![CborValue::Text("4".into())])])]),
        ),
        (
            "too many elements",
            arr(vec![arr(vec![
                ints(&[4]),
                arr(vec![b("a")]),
                b("t"),
                b("x"),
            ])]),
        ),
        (
            "empty namespace",
            arr(vec![arr(vec![ints(&[4]), arr(vec![])])]),
        ),
        (
            "nil not last",
            arr(vec![arr(vec![
                ints(&[4]),
                arr(vec![CborValue::Null, b("a")]),
            ])]),
        ),
        (
            "unknown match type",
            arr(vec![arr(vec![
                ints(&[4]),
                arr(vec![arr(vec![CborValue::Integer(3), b("a")])]),
            ])]),
        ),
        (
            "text instead of bytes",
            arr(vec![arr(vec![
                ints(&[4]),
                arr(vec![CborValue::Text("a".into())]),
            ])]),
        ),
        (
            "nil track",
            arr(vec![arr(vec![
                ints(&[4]),
                arr(vec![b("a")]),
                CborValue::Null,
            ])]),
        ),
    ];

    for (name, value) in malformed {
        assert!(
            matches!(
                MoqtClaim::from_cbor(&value),
                Err(Error::InvalidMoqtClaim(_))
            ),
            "{name} should be rejected"
        );

        let token = signed(TokenBuilder::new().custom_cbor(moqt_keys::MOQT, value));
        let result = token.verify_claims(&options(track(Subscribe, &["a"], "t")));
        assert!(
            matches!(result, Err(Error::InvalidMoqtClaim(_))),
            "{name} should fail verification"
        );
    }
}

#[test]
fn test_moqt_verify_claims_round_trip() {
    let token = signed(
        TokenBuilder::new().moqt(MoqtClaim::new(vec![MoqtScope::new([Subscribe])
            .namespace_exact("example.com")
            .namespace_exact("alice")
            .track_prefix("video-")])),
    );

    assert!(token
        .verify_claims(&options(track(
            Subscribe,
            &["example.com", "alice"],
            "video-hd"
        )))
        .is_ok());
    assert!(matches!(
        token.verify_claims(&options(track(
            Subscribe,
            &["example.com", "bob"],
            "video-hd"
        ))),
        Err(Error::MoqtNotAuthorized(_))
    ));
    assert!(matches!(
        token.verify_claims(&options(track(
            Publish,
            &["example.com", "alice"],
            "video-hd"
        ))),
        Err(Error::MoqtNotAuthorized(_))
    ));
}

#[test]
fn test_moqt_session_token_rechecked_per_action() {
    // A relay keeps the token from CLIENT_SETUP and re-checks later actions,
    // such as REQUEST_UPDATE, which carry no token of their own.
    let token = signed(TokenBuilder::new().moqt(MoqtClaim::new(vec![
        MoqtScope::new([ClientSetup, Subscribe, RequestUpdate]).namespace_exact("live"),
    ])));

    let claim = token.moqt_claim().unwrap().expect("moqt claim");
    assert!(claim.permits(&MoqtRequest::session(ClientSetup)));
    assert!(claim.permits(&track(Subscribe, &["live"], "cam1")));
    assert!(claim.permits(&track(RequestUpdate, &["live"], "cam1")));
    assert!(!claim.permits(&track(Fetch, &["live"], "cam1")));

    assert!(token
        .verify_claims(&options(track(RequestUpdate, &["live"], "cam1")))
        .is_ok());
}

#[test]
fn test_moqt_absent_claim_and_require_moqt() {
    let token = signed(TokenBuilder::new());
    let request = track(Subscribe, &["a"], "t");

    assert!(token.verify_claims(&options(request.clone())).is_ok());
    assert!(matches!(
        token.verify_claims(&options(request).require_moqt(true)),
        Err(Error::MissingClaim(claim)) if claim == "moqt"
    ));
}

#[test]
fn test_moqt_verify_requires_request() {
    let token = signed(TokenBuilder::new());
    let options = VerificationOptions::new().verify_moqt(true);
    assert!(matches!(
        token.verify_claims(&options),
        Err(Error::InvalidClaimValue(_))
    ));
}

#[test]
fn test_moqt_reval_handling() {
    let scope = || MoqtClaim::new(vec![MoqtScope::new([Subscribe])]);
    let request = || track(Subscribe, &["a"], "t");

    let token = signed(TokenBuilder::new().moqt(scope()).moqt_reval(300));
    assert_eq!(token.moqt_reval().unwrap(), Some(300.0));

    // Default: this recipient cannot revalidate, so it must reject
    assert!(matches!(
        token.verify_claims(&options(request())),
        Err(Error::MoqtRevalidationUnsupported(_))
    ));
    assert!(token
        .verify_claims(&options(request()).moqt_revalidation(MoqtRevalidation::MinInterval(60)))
        .is_ok());
    assert!(matches!(
        token.verify_claims(
            &options(request()).moqt_revalidation(MoqtRevalidation::MinInterval(600))
        ),
        Err(Error::MoqtRevalidationUnsupported(_))
    ));

    // 0 means "do not revalidate" and is accepted by any recipient
    let token = signed(TokenBuilder::new().moqt(scope()).moqt_reval(0));
    assert_eq!(token.moqt_reval().unwrap(), None);
    assert!(token.verify_claims(&options(request())).is_ok());

    let token = signed(
        TokenBuilder::new()
            .moqt(scope())
            .custom_cbor(moqt_keys::MOQT_REVAL, CborValue::Integer(-1)),
    );
    assert!(matches!(
        token.verify_claims(&options(request())),
        Err(Error::InvalidMoqtClaim(_))
    ));
}

#[test]
fn test_moqt_draft_publisher_vector() {
    // {327: [[[2, 6], ['example.com', 'alice'], [1, 'video-']]]}
    let payload = Hex::decode_to_vec(
        "a1190147818382020682\
         4b6578616d706c652e636f6d\
         45616c696365\
         820146766964656f2d",
        None,
    )
    .unwrap();
    let token = token_from_payload(&payload);
    let claim = token.moqt_claim().unwrap().expect("moqt claim");

    let expected = MoqtClaim::new(vec![MoqtScope::new([PublishNamespace, Publish])
        .namespace_exact("example.com")
        .namespace_exact("alice")
        .track_prefix("video-")]);
    assert_eq!(claim, expected);
    assert!(claim.permits(&track(Publish, &["example.com", "alice"], "video-1080p")));
}

#[test]
fn test_moqt_draft_admin_vector() {
    // {327: [[[0, 1, 2, 3, 4, 5, 6, 7, 8]]]}
    let payload = Hex::decode_to_vec("a1190147818189000102030405060708", None).unwrap();
    let claim = token_from_payload(&payload)
        .moqt_claim()
        .unwrap()
        .expect("moqt claim");

    assert!(claim.permits(&MoqtRequest::session(ClientSetup)));
    assert!(claim.permits(&MoqtRequest::namespace(PublishNamespace, ["any"])));
    assert!(claim.permits(&track(Subscribe, &["any", "ns"], "any-track")));
}

#[test]
fn test_moqt_reval_half_float_vector() {
    // {328: 300.0} encoded as a half-float, as in the draft's test vectors
    let payload = Hex::decode_to_vec("a1190148f95cb0", None).unwrap();
    let token = token_from_payload(&payload);
    assert_eq!(
        token.get_custom_claim(moqt_keys::MOQT_REVAL),
        Some(&CborValue::Float(300.0))
    );
    assert_eq!(token.moqt_reval().unwrap(), Some(300.0));
}

#[test]
fn test_float_encoding_uses_shortest_width() {
    let cases: [(f64, &str); 4] = [
        (300.0, "f95cb0"),
        (1.5, "f93e00"),
        (100000.0, "fa47c35000"),
        (1.1, "fb3ff199999999999a"),
    ];

    for (value, expected_hex) in cases {
        let token = signed(TokenBuilder::new().custom_cbor(900, CborValue::Float(value)));
        assert_eq!(
            token.get_custom_claim(900),
            Some(&CborValue::Float(value)),
            "{value} should round-trip"
        );

        let fresh = TokenBuilder::new()
            .algorithm(Algorithm::HmacSha256)
            .custom_cbor(900, CborValue::Float(value))
            .sign(KEY)
            .unwrap();
        let bytes = fresh.to_bytes().unwrap();
        let expected = Hex::decode_to_vec(expected_hex, None).unwrap();
        assert!(
            bytes
                .windows(expected.len())
                .any(|w| w == expected.as_slice()),
            "{value} should encode as {expected_hex}"
        );
    }
}

#[test]
fn test_moqt_es256_publisher_validates_with_public_key() {
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};

    let signing_key = SigningKey::random(&mut rand_core::OsRng);
    let private_der = signing_key.to_pkcs8_der().unwrap();
    let public_der = signing_key.verifying_key().to_public_key_der().unwrap();

    let token = TokenBuilder::new()
        .algorithm(Algorithm::Es256)
        .registered_claims(
            RegisteredClaims::new()
                .with_audience("publisher.example.com")
                .with_expiration(current_timestamp() + 3600),
        )
        .moqt(MoqtClaim::new(vec![MoqtScope::new([Subscribe])
            .namespace_exact("example.com")
            .namespace_exact("alice")]))
        .sign(private_der.as_bytes())
        .unwrap();

    // The publisher only holds the issuer's public key.
    // TODO(#6): switch to `verify_with_key(VerifyingKey::Es256(..))` once merged.
    let decoded = Token::from_bytes(&token.to_bytes().unwrap()).unwrap();
    decoded.verify(public_der.as_bytes()).unwrap();

    let options = VerificationOptions::new()
        .expected_audience("publisher.example.com")
        .require_aud(true)
        .verify_moqt(true)
        .require_moqt(true);
    assert!(decoded
        .verify_claims(&options.clone().moqt_request(track(
            Subscribe,
            &["example.com", "alice"],
            "video"
        )))
        .is_ok());
    assert!(matches!(
        decoded.verify_claims(&options.moqt_request(track(
            Subscribe,
            &["example.com", "bob"],
            "video"
        ))),
        Err(Error::MoqtNotAuthorized(_))
    ));
}
