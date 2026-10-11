//! Example: Common Access Tokens for Media over QUIC Transport (MoQT), as
//! profiled by draft-ietf-moq-c4m.
//!
//! The `moqt` claim lists scopes: which MoQT actions a token permits, and on
//! which Full Track Names (namespace tuple + track name). The same check
//! applies to every validator role, so this example shows three:
//!
//!   1. An edge relay validating a subscriber's SUBSCRIBE (HMAC secret).
//!   2. An ingest relay validating a publisher's PUBLISH_NAMESPACE + PUBLISH.
//!   3. A publisher validating a relay's SUBSCRIBE with only a public key
//!      (ES256), so no shared secret is handed to publishers.
//!
//! Validators that check later actions against a token from session setup
//! (for example REQUEST_UPDATE) can keep the `Token` and re-run
//! `verify_claims` with a new `MoqtRequest`.

use common_access_token::{
    current_timestamp, Algorithm, KeyId, MoqtAction, MoqtClaim, MoqtRequest, MoqtRevalidation,
    MoqtScope, RegisteredClaims, Token, TokenBuilder, VerificationOptions,
};
use ct_codecs::{Base64, Decoder};

// ⚠️ DEMO KEYS — DO NOT USE IN PRODUCTION. See examples/asymmetric_signing.rs.
const ES256_PRIVATE_KEY_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7BOlgwBOMKscTUCaG3RmlSCgUznDdxMn+9Pvoqp4pUOhRANCAARWMcvR3DnF1U15IvgcOyAxr3pJPfOHcF7ESuY+H+ya3LCH03PC1d99/XgN1ldF+wmMxVhY0w9iop10N6tNZDTg";
const ES256_PUBLIC_KEY_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVjHL0dw5xdVNeSL4HDsgMa96ST3zh3BexErmPh/smtywh9NzwtXfff14DdZXRfsJjMVYWNMPYqKddDerTWQ04A==";
const HMAC_KEY: &[u8] = b"edge-relay-shared-secret";

fn main() {
    edge_relay_validates_subscriber();
    ingest_relay_validates_publisher();
    publisher_validates_relay();
}

fn edge_relay_validates_subscriber() {
    println!("1. Edge relay <- subscriber");

    // Issuer: subscribe to and fetch any track under example.com/alice,
    // revalidating ongoing subscriptions at least every 5 minutes.
    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .protected_key_id(KeyId::string("edge-key-1"))
        .registered_claims(
            RegisteredClaims::new()
                .with_issuer("issuer.example.com")
                .with_audience("relay.example.com")
                .with_expiration(current_timestamp() + 3600),
        )
        .moqt(MoqtClaim::new(vec![MoqtScope::new([
            MoqtAction::ClientSetup,
            MoqtAction::Subscribe,
            MoqtAction::Fetch,
            MoqtAction::RequestUpdate,
        ])
        .namespace_exact("example.com")
        .namespace_exact("alice")]))
        .moqt_reval(300)
        .sign(HMAC_KEY)
        .expect("sign");
    let bytes = token.to_bytes().expect("encode");

    // Relay: verify the signature once per received token...
    let token = Token::from_bytes(&bytes).expect("decode");
    // TODO(#6): switch to `verify_with_key(VerifyingKey::HmacSha256(HMAC_KEY))`.
    token.verify(HMAC_KEY).expect("signature");

    // ...then check each action against it.
    let options = |request| {
        VerificationOptions::new()
            .expected_audience("relay.example.com")
            .require_aud(true)
            .verify_moqt(true)
            .require_moqt(true)
            .moqt_revalidation(MoqtRevalidation::MinInterval(60))
            .moqt_request(request)
    };
    let requests = [
        MoqtRequest::session(MoqtAction::ClientSetup),
        MoqtRequest::track(MoqtAction::Subscribe, ["example.com", "alice"], "video-hd"),
        MoqtRequest::track(MoqtAction::Subscribe, ["example.com", "bob"], "video-hd"),
        MoqtRequest::track(MoqtAction::Publish, ["example.com", "alice"], "video-hd"),
    ];
    for request in requests {
        let summary = request.to_string();
        match token.verify_claims(&options(request)) {
            Ok(()) => println!("   allowed: {summary}"),
            Err(e) => println!("   denied:  {summary} ({e})"),
        }
    }
    if let Some(secs) = token.moqt_reval().expect("valid moqt-reval") {
        println!("   revalidate ongoing actions at least every {secs}s");
    }
    println!();
}

fn ingest_relay_validates_publisher() {
    println!("2. Ingest relay <- publisher");

    let token = TokenBuilder::new()
        .algorithm(Algorithm::HmacSha256)
        .registered_claims(
            RegisteredClaims::new()
                .with_audience("ingest.example.com")
                .with_expiration(current_timestamp() + 3600),
        )
        .moqt(MoqtClaim::new(vec![MoqtScope::new([
            MoqtAction::ClientSetup,
            MoqtAction::PublishNamespace,
            MoqtAction::Publish,
        ])
        .namespace_exact("example.com")
        .namespace_exact("alice")
        .namespace_end()
        .track_prefix("video-")]))
        .sign(HMAC_KEY)
        .expect("sign");

    // A relay holding the token from setup can check the parsed claim
    // directly for each later message.
    let claim = token.moqt_claim().expect("valid moqt").expect("moqt claim");
    let requests = [
        MoqtRequest::namespace(MoqtAction::PublishNamespace, ["example.com", "alice"]),
        MoqtRequest::track(MoqtAction::Publish, ["example.com", "alice"], "video-4k"),
        MoqtRequest::track(MoqtAction::Publish, ["example.com", "alice"], "audio"),
        MoqtRequest::track(
            MoqtAction::Publish,
            ["example.com", "alice", "extra"],
            "video-4k",
        ),
    ];
    for request in requests {
        let verdict = if claim.permits(&request) {
            "allowed"
        } else {
            "denied "
        };
        println!("   {verdict}: {request}");
    }
    println!();
}

fn publisher_validates_relay() {
    println!("3. Publisher <- relay (ES256, public key only)");

    let private_key = Base64::decode_to_vec(ES256_PRIVATE_KEY_B64, None).expect("private key");
    let public_key = Base64::decode_to_vec(ES256_PUBLIC_KEY_B64, None).expect("public key");

    // The relay's own service token, scoped to subscribing upstream.
    let token = TokenBuilder::new()
        .algorithm(Algorithm::Es256)
        .registered_claims(
            RegisteredClaims::new()
                .with_subject("relay.example.com")
                .with_audience("origin.example.com")
                .with_expiration(current_timestamp() + 3600),
        )
        .moqt(MoqtClaim::new(vec![MoqtScope::new([
            MoqtAction::Subscribe,
            MoqtAction::Fetch,
        ])
        .namespace_exact("example.com")]))
        .sign(&private_key)
        .expect("sign");

    let token = Token::from_bytes(&token.to_bytes().expect("encode")).expect("decode");
    // TODO(#6): switch to `verify_with_key(VerifyingKey::Es256(&public_key))`;
    // until then `verify` is not safe against algorithm confusion.
    token.verify(&public_key).expect("signature");

    let options = VerificationOptions::new()
        .expected_audience("origin.example.com")
        .require_aud(true)
        .verify_moqt(true)
        .require_moqt(true)
        .moqt_request(MoqtRequest::track(
            MoqtAction::Subscribe,
            ["example.com", "alice"],
            "video-hd",
        ));
    match token.verify_claims(&options) {
        Ok(()) => println!("   allowed upstream SUBSCRIBE"),
        Err(e) => println!("   denied upstream SUBSCRIBE ({e})"),
    }
}
