//! Tests for MoQ Transport claims (draft-ietf-moq-c4m-02)

use crate::{
    claims::RegisteredClaims,
    constants::{cat_keys, cwt_keys, moqt_keys},
    header::{Algorithm, CborValue, VerifyingKey},
    moqt::{
        BinMatch, MoqtAction, MoqtClaim, MoqtClaimLabels, MoqtRequest, MoqtRevalidation, MoqtScope,
    },
    token::{Token, TokenBuilder, VerificationOptions},
    utils::current_timestamp,
    Error,
};
use ct_codecs::{Base64, Decoder, Hex};
use std::collections::BTreeMap;

use MoqtAction::*;

const KEY: &[u8] = b"moqt-test-key";

// Same demo ES256 key pair as `src/tests.rs`; DO NOT USE IN PRODUCTION.
const ES256_PRIVATE_KEY_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7BOlgwBOMKscTUCaG3RmlSCgUznDdxMn+9Pvoqp4pUOhRANCAARWMcvR3DnF1U15IvgcOyAxr3pJPfOHcF7ESuY+H+ya3LCH03PC1d99/XgN1ldF+wmMxVhY0w9iop10N6tNZDTg";
const ES256_PUBLIC_KEY_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVjHL0dw5xdVNeSL4HDsgMa96ST3zh3BexErmPh/smtywh9NzwtXfff14DdZXRfsJjMVYWNMPYqKddDerTWQ04A==";

fn b(s: &str) -> CborValue {
    CborValue::Bytes(s.as_bytes().to_vec())
}

fn ints(v: &[i64]) -> CborValue {
    CborValue::Array(v.iter().map(|i| CborValue::Integer(*i)).collect())
}

fn arr(v: Vec<CborValue>) -> CborValue {
    CborValue::Array(v)
}

/// A moqt claim value: `{0: [scopes...]}`
fn moqt_map(scopes: Vec<CborValue>) -> CborValue {
    map(vec![(0, arr(scopes))])
}

fn map(entries: Vec<(i32, CborValue)>) -> CborValue {
    CborValue::Map(entries.into_iter().collect::<BTreeMap<_, _>>())
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
    decoded
        .verify_with_key(VerifyingKey::HmacSha256(KEY))
        .expect("verify");
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
    for code in 1..=9 {
        let action = MoqtAction::from_code(code).expect("known action");
        assert_eq!(action.code(), code);
    }
    assert_eq!(MoqtAction::from_code(1), Some(Setup));
    assert_eq!(MoqtAction::from_code(9), Some(SubscribeTracks));
    // Draft -01's CLIENT_SETUP code is unassigned in -02
    assert_eq!(MoqtAction::from_code(0), None);
    assert_eq!(MoqtAction::from_code(10), None);
    assert_eq!(MoqtAction::from_code(-1), None);
}

#[test]
fn test_moqt_exact_namespace_with_trailing_nil() {
    // [[2,3,6,7], ['example','com',nil], '/bob']
    let claim = MoqtClaim::from_cbor(&moqt_map(vec![arr(vec![
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
    let claim = MoqtClaim::from_cbor(&moqt_map(vec![arr(vec![
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
    let claim = MoqtClaim::from_cbor(&moqt_map(vec![arr(vec![
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
    let claim = MoqtClaim::from_cbor(&moqt_map(vec![arr(vec![ints(&[99])])])).unwrap();
    assert_eq!(claim.scopes()[0].action_codes(), &[99]);
    for code in 1..=9 {
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
    assert!(!claim.permits(&MoqtRequest::session(Setup)));
}

#[test]
fn test_moqt_role_subscriber() {
    let claim = MoqtClaim::new(vec![MoqtScope::new([
        Setup,
        Subscribe,
        Fetch,
        TrackStatus,
        RequestUpdate,
    ])
    .namespace_exact("example.com")
    .namespace_exact("alice")]);

    // Session actions ignore namespace and track matches
    assert!(claim.permits(&MoqtRequest::session(Setup)));
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
    let scope = || arr(vec![ints(&[4])]);
    let malformed = [
        ("not a map", CborValue::Integer(1)),
        ("draft-01 bare array", arr(vec![scope()])),
        ("missing scopes key", map(vec![])),
        ("scopes not an array", map(vec![(0, scope())])),
        (
            "unknown map key",
            map(vec![(0, arr(vec![scope()])), (1, CborValue::Integer(0))]),
        ),
        ("no scopes", moqt_map(vec![])),
        ("empty scope", moqt_map(vec![arr(vec![])])),
        ("empty actions", moqt_map(vec![arr(vec![ints(&[])])])),
        (
            "non-int action",
            moqt_map(vec![arr(vec![arr(vec![CborValue::Text("4".into())])])]),
        ),
        (
            "too many elements",
            moqt_map(vec![arr(vec![
                ints(&[4]),
                arr(vec![b("a")]),
                b("t"),
                b("x"),
            ])]),
        ),
        (
            "empty namespace",
            moqt_map(vec![arr(vec![ints(&[4]), arr(vec![])])]),
        ),
        (
            "nil not last",
            moqt_map(vec![arr(vec![
                ints(&[4]),
                arr(vec![CborValue::Null, b("a")]),
            ])]),
        ),
        (
            "unknown match type",
            moqt_map(vec![arr(vec![
                ints(&[4]),
                arr(vec![arr(vec![CborValue::Integer(3), b("a")])]),
            ])]),
        ),
        (
            "map-form exact match",
            // draft -02 §2.1.2 uses `{ /exact/ 0: 'example.com' }` in one
            // example, but the CDDL only allows a bare bstr
            moqt_map(vec![arr(vec![
                ints(&[4]),
                arr(vec![map(vec![(0, b("a"))])]),
            ])]),
        ),
        (
            "text instead of bytes",
            moqt_map(vec![arr(vec![
                ints(&[4]),
                arr(vec![CborValue::Text("a".into())]),
            ])]),
        ),
        (
            "nil track",
            moqt_map(vec![arr(vec![
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
    // A relay keeps the token from SETUP and re-checks later actions,
    // such as REQUEST_UPDATE, which carry no token of their own.
    let token = signed(TokenBuilder::new().moqt(MoqtClaim::new(vec![
        MoqtScope::new([Setup, Subscribe, RequestUpdate]).namespace_exact("live"),
    ])));

    let claim = token.moqt_claim().unwrap().expect("moqt claim");
    assert!(claim.permits(&MoqtRequest::session(Setup)));
    assert!(claim.permits(&track(Subscribe, &["live"], "cam1")));
    assert!(claim.permits(&track(RequestUpdate, &["live"], "cam1")));
    assert!(!claim.permits(&track(Fetch, &["live"], "cam1")));

    assert!(token
        .verify_claims(&options(track(RequestUpdate, &["live"], "cam1")))
        .is_ok());
}

#[test]
fn test_moqt_absent_claim_is_denied() {
    // draft-ietf-moq-c4m §2: once a token is presented, all actions are
    // blocked unless explicitly enabled.
    let token = signed(TokenBuilder::new());
    for request in [
        MoqtRequest::session(Setup),
        MoqtRequest::namespace(SubscribeNamespace, ["a"]),
        track(Subscribe, &["a"], "t"),
    ] {
        assert!(matches!(
            token.verify_claims(&options(request)),
            Err(Error::MoqtNotAuthorized(_))
        ));
    }

    // Without verify_moqt, MoQ claims are not checked at all
    let plain = VerificationOptions::new().expected_audience("relay.example.com");
    assert!(token.verify_claims(&plain).is_ok());
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

/// HMAC key from draft -02 Appendix A.1: bytes 0x00..=0x1f
fn draft_hmac_key() -> Vec<u8> {
    (0u8..32).collect()
}

/// One draft -02 Appendix A.5 vector: a COSE_Mac0 token plus its
/// authorization tests as (action, namespace, track, expected)
struct ScopeVector {
    id: &'static str,
    /// The moqt claim value, as it appears in the vector's payload
    moqt_hex: &'static str,
    cose_hex: &'static str,
    tests: &'static [(i64, &'static [&'static str], &'static str, bool)],
}

const SCOPE_VECTORS: &[ScopeVector] = &[
    ScopeVector {
        id: "moqt_publisher_exact",
        moqt_hex: "a1008183820206824b6578616d706c652e636f6d45616c696365820146766964656f2d",
        cose_hex: "d18448a201051063434154a0584aa301781868747470733a2f2f617574682e6578616d706c652e636f6d041a655542803a00010000a1008183820206824b6578616d706c652e636f6d45616c696365820146766964656f2d5820467c57ade72d6be629b745ef33d6e28ec38ba1ca8bd3feb851f3832af94fe686",
        tests: &[
            (2, &["example.com", "alice"], "video-hd", true),
            (6, &["example.com", "alice"], "video-sd", true),
            (6, &["example.com", "alice"], "audio-main", false),
            (4, &["example.com", "alice"], "video-hd", false),
            (6, &["example.com", "bob"], "video-hd", false),
        ],
    },
    ScopeVector {
        id: "moqt_subscriber_prefix",
        moqt_hex: "a10081828303040781820152636f6e666572656e63652e6578616d706c65",
        cose_hex: "d18448a201051063434154a05845a301781868747470733a2f2f617574682e6578616d706c652e636f6d041a655542803a00010000a10081828303040781820152636f6e666572656e63652e6578616d706c655820e0502202b8c01d5ab61508cd19b7dd943b287be0f26c3d37c12e583ca87a937b",
        tests: &[
            (4, &["conference.example.room1"], "audio", true),
            (7, &["conference.example.room2"], "video", true),
            (4, &["other.domain"], "audio", false),
            (6, &["conference.example.room1"], "audio", false),
        ],
    },
    ScopeVector {
        id: "moqt_multi_scope",
        moqt_hex: "a1008282820206824c6c6976652e6578616d706c654873747564696f2d61828204078182014c6c6976652e6578616d706c65",
        cose_hex: "d18448a201051063434154a05861a401781868747470733a2f2f617574682e6578616d706c652e636f6d041a655542803a00010000a1008282820206824c6c6976652e6578616d706c654873747564696f2d61828204078182014c6c6976652e6578616d706c653a0001000119012c5820f1080af59a719fbcb7a036aa6f9714f52ada467b8c1677c87ade0fcfccaaf50f",
        tests: &[
            (6, &["live.example", "studio-a"], "cam1", true),
            (4, &["live.example.studio-b"], "cam1", true),
            (6, &["live.example", "studio-b"], "cam1", false),
            (2, &["other.example", "studio-a"], "", false),
        ],
    },
    ScopeVector {
        id: "moqt_admin_wildcard",
        moqt_hex: "a100818189000102030405060708",
        cose_hex: "d18448a201051063434154a05835a301781868747470733a2f2f617574682e6578616d706c652e636f6d041a655542803a00010000a1008181890001020304050607085820172ebe07f227a41c319684ef916fdbf142d391fac6902e38bcdcfb3966b46a50",
        // The vector also expects action 0 to pass, but -02 Table 1 leaves 0
        // unassigned (it was CLIENT_SETUP in -01). That case is checked
        // separately in test_moqt_draft02_admin_vector_action_zero.
        tests: &[
            (6, &["any.namespace"], "any-track", true),
            (8, &["any.namespace"], "status", true),
        ],
    },
    ScopeVector {
        id: "moqt_suffix_match",
        moqt_hex: "a100818381048182024c2e6578616d706c652e636f6d8202462d617564696f",
        cose_hex: "d18448a201051063434154a05846a301781868747470733a2f2f617574682e6578616d706c652e636f6d041a655542803a00010000a100818381048182024c2e6578616d706c652e636f6d8202462d617564696f5820602c1ceb2729485a2b5eb09249e254a41d42abd0b63b2846fd677d7fbf593920",
        tests: &[
            (4, &["cdn.example.com"], "stream1-audio", true),
            (4, &["cdn.example.com"], "stream1-video", false),
            (4, &["cdn.other.org"], "stream1-audio", false),
        ],
    },
];

/// Build the request a relay would check for `action`, using only the parts
/// of the Full Track Name that the action carries
fn request_for(action: MoqtAction, ns: &[&str], name: &str) -> MoqtRequest {
    match action.target() {
        crate::moqt::MoqtTarget::Session => MoqtRequest::session(action),
        crate::moqt::MoqtTarget::Namespace => MoqtRequest::namespace(action, ns.iter().copied()),
        crate::moqt::MoqtTarget::Track => track(action, ns, name),
    }
}

fn decode_draft_vector(cose_hex: &str) -> Token {
    let bytes = Hex::decode_to_vec(cose_hex, None).unwrap();
    let token = Token::from_bytes(&bytes).expect("decode draft vector");
    token
        .verify_with_key(VerifyingKey::HmacSha256(&draft_hmac_key()))
        .expect("draft vector MAC verifies");
    token
}

#[test]
fn test_moqt_draft02_scope_vectors() {
    for vector in SCOPE_VECTORS {
        let token = decode_draft_vector(vector.cose_hex);
        let claim = token
            .moqt_claim()
            .unwrap()
            .unwrap_or_else(|| panic!("{}: moqt claim", vector.id));

        for (code, ns, name, expected) in vector.tests {
            let action = MoqtAction::from_code(*code).expect("known action");
            let request = request_for(action, ns, name);
            assert_eq!(
                claim.permits(&request),
                *expected,
                "{}: {request}",
                vector.id
            );

            // The full verify_claims path agrees. The vectors' exp is in the
            // past, so don't check it. multi_scope carries moqt-reval 300.
            let options = VerificationOptions::new()
                .verify_exp(false)
                .verify_moqt(true)
                .moqt_revalidation(MoqtRevalidation::MinInterval(60))
                .moqt_request(request.clone());
            assert_eq!(
                token.verify_claims(&options).is_ok(),
                *expected,
                "{}: verify_claims {request}",
                vector.id
            );
        }

        // Re-encoding the parsed claim reproduces the vector's bytes exactly
        let expected = Hex::decode_to_vec(format!("3a00010000{}", vector.moqt_hex), None).unwrap();
        let encoded = TokenBuilder::new()
            .algorithm(Algorithm::HmacSha256)
            .moqt(claim)
            .sign(KEY)
            .unwrap()
            .to_bytes()
            .unwrap();
        assert!(
            encoded
                .windows(expected.len())
                .any(|w| w == expected.as_slice()),
            "{}: re-encoded claim should match the vector",
            vector.id
        );
    }
}

#[test]
fn test_moqt_draft02_admin_vector_action_zero() {
    // The admin vector lists actions [0..=8] under draft -01 names
    // (ClientSetup, ServerSetup, ...) and expects action 0 to pass. In -02,
    // Table 1 is normative, and it leaves 0 unassigned and makes 1 SETUP. So
    // code 0 is kept as an unknown code that matches nothing, code 1 permits
    // SETUP, and SUBSCRIBE_TRACKS (9) is not granted.
    let token = decode_draft_vector(SCOPE_VECTORS[3].cose_hex);
    let claim = token.moqt_claim().unwrap().expect("moqt claim");
    assert_eq!(
        claim.scopes()[0].action_codes(),
        &[0, 1, 2, 3, 4, 5, 6, 7, 8]
    );
    assert_eq!(MoqtAction::from_code(0), None);
    assert!(claim.permits(&MoqtRequest::session(Setup)));
    assert!(!claim.permits(&MoqtRequest::namespace(SubscribeTracks, ["any"])));
}

#[test]
fn test_moqt_draft02_catu_with_moqt_vector() {
    // cbor_catu_with_moqt (Appendix A.2): catu and moqt in one claim set
    let payload = Hex::decode_to_vec(
        "a2190138a201a1006b6578616d706c652e636f6d03a101652f766f642f\
         3a00010000a1008182820407824b6578616d706c652e636f6d43766f64",
        None,
    )
    .unwrap();
    let token = token_from_payload(&payload);
    assert!(token.has_custom_claim(cat_keys::CATU));
    let claim = token.moqt_claim().unwrap().expect("moqt claim");
    assert_eq!(
        claim,
        MoqtClaim::new(vec![MoqtScope::new([Subscribe, Fetch])
            .namespace_exact("example.com")
            .namespace_exact("vod")])
    );
    assert!(claim.permits(&track(Subscribe, &["example.com", "vod"], "movie")));
    assert!(claim.permits(&track(Fetch, &["example.com", "vod", "x"], "movie")));
    assert!(!claim.permits(&track(Publish, &["example.com", "vod"], "movie")));
}

#[test]
fn test_moqt_reval_draft02_integer_vector() {
    // moqt_multi_scope carries -65538 /moqt-reval/: 300 as an integer
    let token = decode_draft_vector(SCOPE_VECTORS[2].cose_hex);
    assert_eq!(
        token.get_custom_claim(moqt_keys::MOQT_REVAL),
        Some(&CborValue::Integer(300))
    );
    assert_eq!(token.moqt_reval().unwrap(), Some(300.0));
}

#[test]
fn test_moqt_reval_half_float() {
    // moqt-reval is a CDDL `number`, so floats are valid too: {-65538: 300.0}
    // as a half-float
    let payload = Hex::decode_to_vec("a13a00010001f95cb0", None).unwrap();
    let token = token_from_payload(&payload);
    assert_eq!(
        token.get_custom_claim(moqt_keys::MOQT_REVAL),
        Some(&CborValue::Float(300.0))
    );
    assert_eq!(token.moqt_reval().unwrap(), Some(300.0));
}

#[test]
fn test_moqt_claim_encodes_as_map() {
    let claim = MoqtClaim::new(vec![MoqtScope::new([Subscribe])]);
    assert_eq!(claim.to_cbor(), moqt_map(vec![arr(vec![ints(&[4])])]));
}

#[test]
fn test_moqt_draft01_array_form_is_rejected() {
    let legacy = arr(vec![arr(vec![ints(&[4])])]);
    match MoqtClaim::from_cbor(&legacy) {
        Err(Error::InvalidMoqtClaim(msg)) => assert!(msg.contains("draft-ietf-moq-c4m-01")),
        other => panic!("expected InvalidMoqtClaim, got {other:?}"),
    }
}

#[test]
fn test_moqt_subscribe_tracks_is_namespace_scoped() {
    let claim = MoqtClaim::new(vec![MoqtScope::new([SubscribeTracks])
        .namespace_exact("example.com")
        .namespace_exact("alice")
        .track_prefix("video-")]);

    assert_eq!(SubscribeTracks.target(), crate::moqt::MoqtTarget::Namespace);
    // The track match does not apply: SUBSCRIBE_TRACKS carries a namespace
    // prefix only
    assert!(claim.permits(&MoqtRequest::namespace(
        SubscribeTracks,
        ["example.com", "alice"]
    )));
    assert!(claim.permits(&MoqtRequest::namespace(
        SubscribeTracks,
        ["example.com", "alice", "room1"]
    )));
    // A shorter prefix would cover more than the scope grants
    assert!(!claim.permits(&MoqtRequest::namespace(SubscribeTracks, ["example.com"])));
    assert!(!claim.permits(&MoqtRequest::namespace(
        SubscribeNamespace,
        ["example.com", "alice"]
    )));
}

#[test]
fn test_moqt_catreplay_single_connection_requires_cti_and_exp() {
    let scope = || MoqtClaim::new(vec![MoqtScope::new([Subscribe])]);
    let request = || track(Subscribe, &["a"], "t");
    let build = |cti: bool, exp: bool| {
        let mut registered = RegisteredClaims::new().with_audience("relay.example.com");
        if cti {
            registered = registered.with_cti(b"token-1".to_vec());
        }
        if exp {
            registered = registered.with_expiration(current_timestamp() + 3600);
        }
        let token = TokenBuilder::new()
            .algorithm(Algorithm::HmacSha256)
            .registered_claims(registered)
            .custom_int(cat_keys::CATREPLAY, 1)
            .moqt(scope())
            .sign(KEY)
            .unwrap();
        Token::from_bytes(&token.to_bytes().unwrap()).unwrap()
    };

    assert!(build(true, true).verify_claims(&options(request())).is_ok());
    for (cti, exp) in [(false, true), (true, false), (false, false)] {
        assert!(
            matches!(
                build(cti, exp).verify_claims(&options(request())),
                Err(Error::InvalidClaimValue(_))
            ),
            "cti={cti} exp={exp} should be rejected"
        );
    }

    // Reuse on the same connection is allowed: the relay doesn't set
    // token_seen_before. On another connection it does, and the token is
    // rejected.
    let token = build(true, true);
    let replayed = options(request())
        .verify_catreplay(true)
        .token_seen_before(true);
    assert!(matches!(
        token.verify_claims(&replayed),
        Err(Error::ReplayViolation(_))
    ));
}

#[test]
fn test_moqt_cnf_requires_dpop_confirmation() {
    let cnf = map(vec![(5, CborValue::Bytes(vec![0x75; 32]))]); // ckt
    let token = signed(
        TokenBuilder::new()
            .moqt(MoqtClaim::new(vec![MoqtScope::new([Subscribe])]))
            .custom_cbor(cwt_keys::CNF, cnf),
    );
    let request = || track(Subscribe, &["a"], "t");

    assert!(matches!(
        token.verify_claims(&options(request())),
        Err(Error::MoqtDpopRequired(_))
    ));
    assert!(token
        .verify_claims(&options(request()).moqt_dpop_verified(true))
        .is_ok());
    // Confirming DPoP does not bypass the scope check
    assert!(matches!(
        token.verify_claims(&options(track(Publish, &["a"], "t")).moqt_dpop_verified(true)),
        Err(Error::MoqtNotAuthorized(_))
    ));
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
    let private_key = Base64::decode_to_vec(ES256_PRIVATE_KEY_B64, None).unwrap();
    let public_key = Base64::decode_to_vec(ES256_PUBLIC_KEY_B64, None).unwrap();

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
        .sign(&private_key)
        .unwrap();

    // The publisher only holds the issuer's public key.
    let decoded = Token::from_bytes(&token.to_bytes().unwrap()).unwrap();
    decoded
        .verify_with_key(VerifyingKey::Es256(&public_key))
        .unwrap();

    let options = VerificationOptions::new()
        .expected_audience("publisher.example.com")
        .require_aud(true)
        .verify_moqt(true);
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

#[test]
fn test_moqt_custom_claim_labels() {
    // An issuer using non-default labels before IANA assignment
    let labels = MoqtClaimLabels {
        moqt: 60001,
        reval: 60002,
    };
    let claim = MoqtClaim::new(vec![MoqtScope::new([Subscribe]).namespace_exact("a")]);
    let token = signed(
        TokenBuilder::new()
            .custom_cbor(labels.moqt, claim.to_cbor())
            .custom_cbor(labels.reval, CborValue::Integer(120)),
    );
    let request = || track(Subscribe, &["a"], "t");

    // At the default labels the token carries no moqt claim, so it's denied
    assert_eq!(token.moqt_claim().unwrap(), None);
    assert!(matches!(
        token.verify_claims(&options(request())),
        Err(Error::MoqtNotAuthorized(_))
    ));

    // With the issuer's labels, both claims are read and enforced
    assert_eq!(token.moqt_claim_at(labels.moqt).unwrap(), Some(claim));
    assert_eq!(token.moqt_reval_at(labels.reval).unwrap(), Some(120.0));
    let custom = || options(request()).moqt_claim_labels(labels);
    assert!(matches!(
        token.verify_claims(&custom()),
        Err(Error::MoqtRevalidationUnsupported(_))
    ));
    assert!(token
        .verify_claims(&custom().moqt_revalidation(MoqtRevalidation::MinInterval(60)))
        .is_ok());
    assert!(matches!(
        token.verify_claims(
            &custom()
                .moqt_revalidation(MoqtRevalidation::MinInterval(60))
                .moqt_request(track(Subscribe, &["b"], "t"))
        ),
        Err(Error::MoqtNotAuthorized(_))
    ));

    // Default::default() uses the provisional labels, not 0
    assert_eq!(
        VerificationOptions::default().moqt_claim_labels,
        MoqtClaimLabels {
            moqt: moqt_keys::MOQT,
            reval: moqt_keys::MOQT_REVAL
        }
    );
}

#[test]
fn test_moqt_hmac_forgery_over_public_key_is_rejected() {
    // An attacker who knows a validator's ES256 public key forges an HS256
    // token whose MAC uses the public key bytes as the secret, with a scope
    // that would permit the request. The signature check must reject it
    // before any scope is consulted.
    let public_key = Base64::decode_to_vec(ES256_PUBLIC_KEY_B64, None).unwrap();
    let forged = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .moqt(MoqtClaim::new(vec![MoqtScope::new([Subscribe])]))
        .sign(&public_key)
        .unwrap();
    let decoded = Token::from_bytes(&forged.to_bytes().unwrap()).unwrap();

    assert!(matches!(
        decoded.verify_with_key(VerifyingKey::Es256(&public_key)),
        Err(Error::InvalidAlgorithm(_))
    ));
}

#[test]
fn test_moqt_matches_name_ignores_actions() {
    let scope = MoqtScope::new([PublishNamespace, Publish])
        .namespace_exact("example.com")
        .namespace_prefix("user-")
        .namespace_end()
        .track_suffix(".mp4");

    // Names only: actions are not consulted
    assert!(scope.matches_name(&["example.com", "user-alice"], Some(b"cam.mp4".as_slice())));
    assert!(!scope.matches_name(&["example.com", "user-alice"], Some(b"cam.ts".as_slice())));
    // Namespace only when no track is given
    assert!(scope.matches_name(&["example.com", "user-alice"], None));
    // Trailing nil pins the length; shorter namespaces never match
    assert!(!scope.matches_name(&["example.com", "user-alice", "x"], None));
    assert!(!scope.matches_name(&["example.com"], None));
    assert!(!scope.matches_name(&["example.com", "USER-alice"], None));

    // Same answers as permits() for an action the scope lists
    for (ns, name) in [
        (["example.com", "user-alice"], "cam.mp4"),
        (["example.com", "user-alice"], "cam.ts"),
        (["example.com", "admin"], "cam.mp4"),
    ] {
        assert_eq!(
            scope.matches_name(&ns, Some(name.as_bytes())),
            scope.permits(&track(Publish, &ns, name))
        );
    }
}
