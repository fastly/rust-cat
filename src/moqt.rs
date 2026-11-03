//! # MoQ Transport claims (draft-ietf-moq-c4m)
//!
//! This module implements the `moqt` and `moqt-reval` claims defined by
//! [draft-ietf-moq-c4m-02](https://datatracker.ietf.org/doc/draft-ietf-moq-c4m/02/),
//! which profiles Common Access Tokens for Media over QUIC Transport (MoQT).
//! Only draft -02 is supported. Draft -01 claims are rejected (see below).
//!
//! A `moqt` claim is a map whose key 0 holds a list of [`MoqtScope`]s. Each
//! scope lists the MoQT actions it permits and, optionally, which Full Track
//! Names it applies to:
//!
//! ```text
//! moqt-value = { 0 => [ + moqt-scope ], * int => any }
//! moqt-scope = [ moqt-actions, ? [ + moqt-ns-match ], ? moqt-track-match ]
//! bin-match  = bstr / [ match-type, match-value ]   ; 1 = prefix, 2 = suffix
//! ```
//!
//! Map keys other than 0 are reserved for future revisions of the draft. A
//! claim containing any other key is rejected (draft §2.1.1, fail-closed). So
//! is a claim in draft -01's bare-array form. Draft -01 numbered its actions
//! differently, so reading one of its tokens as -02 could grant the wrong
//! action.
//!
//! Matching is bytewise (case-sensitive, no normalization). A request is
//! permitted if *any* scope permits it; once a token carrying a `moqt` claim
//! is presented, everything else is denied.
//!
//! ## Which parts of a scope apply to which action
//!
//! The draft does not say how scope matches apply to actions that have no
//! namespace or track. This implementation scopes them by action kind (see
//! [`MoqtAction::target`]):
//!
//! - **Session** actions (`SETUP`) only require the action to be listed;
//!   namespace and track matches do not apply.
//! - **Namespace** actions (`PUBLISH_NAMESPACE`, `SUBSCRIBE_NAMESPACE`,
//!   `SUBSCRIBE_TRACKS`) must also satisfy the namespace match; the track match
//!   does not apply. This is what makes the draft's publisher example
//!   (`[[2, 6], ns, track]`) usable for `PUBLISH_NAMESPACE`.
//! - **Track** actions (`SUBSCRIBE`, `REQUEST_UPDATE`, `PUBLISH`, `FETCH`,
//!   `TRACK_STATUS`) must satisfy both. A track action with no track name in
//!   the request is always denied.
//!
//! A request namespace with fewer fields than the scope's namespace match is
//! denied: for `SUBSCRIBE_NAMESPACE` that would grant more than the scope
//! allows.
//!
//! The DPoP proof's `actx` claim in draft -02 §4.2 points to the same split. It
//! carries the namespace for actions that target a namespace or a track, and
//! the track name only for actions that target a track.
//!
//! ## Example
//!
//! ```rust
//! use common_access_token::{MoqtAction, MoqtClaim, MoqtRequest, MoqtScope};
//!
//! // Publish under example.com/alice, tracks starting with "video-"
//! let claim = MoqtClaim::new(vec![MoqtScope::new([
//!     MoqtAction::PublishNamespace,
//!     MoqtAction::Publish,
//! ])
//! .namespace_exact("example.com")
//! .namespace_exact("alice")
//! .track_prefix("video-")]);
//!
//! let publish = MoqtRequest::track(MoqtAction::Publish, ["example.com", "alice"], "video-hd");
//! assert!(claim.permits(&publish));
//!
//! let subscribe = MoqtRequest::track(MoqtAction::Subscribe, ["example.com", "alice"], "video-hd");
//! assert!(!claim.permits(&subscribe));
//! ```

use crate::constants::{moqt_actions, moqt_claim_keys, moqt_keys, moqt_match_types};
use crate::error::Error;
use crate::header::CborValue;
use std::collections::BTreeMap;

/// A MoQ Transport action (draft-ietf-moq-c4m-02, Table 1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MoqtAction {
    /// SETUP (1)
    Setup,
    /// PUBLISH_NAMESPACE (2)
    PublishNamespace,
    /// SUBSCRIBE_NAMESPACE (3)
    SubscribeNamespace,
    /// SUBSCRIBE (4)
    Subscribe,
    /// REQUEST_UPDATE (5)
    RequestUpdate,
    /// PUBLISH (6)
    Publish,
    /// FETCH (7)
    Fetch,
    /// TRACK_STATUS (8)
    TrackStatus,
    /// SUBSCRIBE_TRACKS (9)
    SubscribeTracks,
}

/// What part of a Full Track Name an action operates on
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoqtTarget {
    /// The action applies to the session; no namespace or track
    Session,
    /// The action applies to a track namespace (or namespace prefix)
    Namespace,
    /// The action applies to a specific track
    Track,
}

impl MoqtAction {
    /// The action's integer code as carried in the `moqt` claim
    pub fn code(self) -> i64 {
        match self {
            MoqtAction::Setup => moqt_actions::SETUP,
            MoqtAction::PublishNamespace => moqt_actions::PUBLISH_NAMESPACE,
            MoqtAction::SubscribeNamespace => moqt_actions::SUBSCRIBE_NAMESPACE,
            MoqtAction::Subscribe => moqt_actions::SUBSCRIBE,
            MoqtAction::RequestUpdate => moqt_actions::REQUEST_UPDATE,
            MoqtAction::Publish => moqt_actions::PUBLISH,
            MoqtAction::Fetch => moqt_actions::FETCH,
            MoqtAction::TrackStatus => moqt_actions::TRACK_STATUS,
            MoqtAction::SubscribeTracks => moqt_actions::SUBSCRIBE_TRACKS,
        }
    }

    /// Look up an action by its integer code
    pub fn from_code(code: i64) -> Option<Self> {
        Some(match code {
            moqt_actions::SETUP => MoqtAction::Setup,
            moqt_actions::PUBLISH_NAMESPACE => MoqtAction::PublishNamespace,
            moqt_actions::SUBSCRIBE_NAMESPACE => MoqtAction::SubscribeNamespace,
            moqt_actions::SUBSCRIBE => MoqtAction::Subscribe,
            moqt_actions::REQUEST_UPDATE => MoqtAction::RequestUpdate,
            moqt_actions::PUBLISH => MoqtAction::Publish,
            moqt_actions::FETCH => MoqtAction::Fetch,
            moqt_actions::TRACK_STATUS => MoqtAction::TrackStatus,
            moqt_actions::SUBSCRIBE_TRACKS => MoqtAction::SubscribeTracks,
            _ => return None,
        })
    }

    /// Which parts of a scope's matches apply to this action
    pub fn target(self) -> MoqtTarget {
        match self {
            MoqtAction::Setup => MoqtTarget::Session,
            MoqtAction::PublishNamespace
            | MoqtAction::SubscribeNamespace
            | MoqtAction::SubscribeTracks => MoqtTarget::Namespace,
            MoqtAction::Subscribe
            | MoqtAction::RequestUpdate
            | MoqtAction::Publish
            | MoqtAction::Fetch
            | MoqtAction::TrackStatus => MoqtTarget::Track,
        }
    }
}

/// A bytewise match against a namespace field or track name
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinMatch {
    /// The value must equal these bytes
    Exact(Vec<u8>),
    /// The value must start with these bytes
    Prefix(Vec<u8>),
    /// The value must end with these bytes
    Suffix(Vec<u8>),
}

impl BinMatch {
    /// Whether `value` satisfies this match
    pub fn matches(&self, value: &[u8]) -> bool {
        match self {
            BinMatch::Exact(v) => value == v.as_slice(),
            BinMatch::Prefix(v) => value.starts_with(v),
            BinMatch::Suffix(v) => value.ends_with(v),
        }
    }

    fn to_cbor(&self) -> CborValue {
        match self {
            BinMatch::Exact(v) => CborValue::Bytes(v.clone()),
            BinMatch::Prefix(v) => CborValue::Array(vec![
                CborValue::Integer(moqt_match_types::PREFIX),
                CborValue::Bytes(v.clone()),
            ]),
            BinMatch::Suffix(v) => CborValue::Array(vec![
                CborValue::Integer(moqt_match_types::SUFFIX),
                CborValue::Bytes(v.clone()),
            ]),
        }
    }

    fn from_cbor(value: &CborValue) -> Result<Self, Error> {
        match value {
            CborValue::Bytes(v) => Ok(BinMatch::Exact(v.clone())),
            CborValue::Array(arr) => match arr.as_slice() {
                [CborValue::Integer(moqt_match_types::PREFIX), CborValue::Bytes(v)] => {
                    Ok(BinMatch::Prefix(v.clone()))
                }
                [CborValue::Integer(moqt_match_types::SUFFIX), CborValue::Bytes(v)] => {
                    Ok(BinMatch::Suffix(v.clone()))
                }
                _ => Err(invalid("match must be [1 or 2, bstr]")),
            },
            _ => Err(invalid("match must be a bstr or [match-type, bstr]")),
        }
    }
}

/// A single `moqt` scope: permitted actions plus optional name matches
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoqtScope {
    actions: Vec<i64>,
    namespace: Vec<BinMatch>,
    namespace_end: bool,
    track: Option<BinMatch>,
}

impl MoqtScope {
    /// Create a scope permitting `actions` on any namespace and any track
    ///
    /// At least one action is required; a token with an empty action list is
    /// malformed and will be rejected by verifiers.
    pub fn new(actions: impl IntoIterator<Item = MoqtAction>) -> Self {
        Self::from_action_codes(actions.into_iter().map(MoqtAction::code))
    }

    /// Create a scope from raw action codes (including codes this library
    /// does not know, which never match)
    pub fn from_action_codes(codes: impl IntoIterator<Item = i64>) -> Self {
        Self {
            actions: codes.into_iter().collect(),
            namespace: Vec::new(),
            namespace_end: false,
            track: None,
        }
    }

    /// Append a namespace field match
    pub fn namespace_match(mut self, m: BinMatch) -> Self {
        self.namespace.push(m);
        self
    }

    /// Append a namespace field that must equal `value`
    pub fn namespace_exact(self, value: impl Into<Vec<u8>>) -> Self {
        self.namespace_match(BinMatch::Exact(value.into()))
    }

    /// Append a namespace field that must start with `value`
    pub fn namespace_prefix(self, value: impl Into<Vec<u8>>) -> Self {
        self.namespace_match(BinMatch::Prefix(value.into()))
    }

    /// Append a namespace field that must end with `value`
    pub fn namespace_suffix(self, value: impl Into<Vec<u8>>) -> Self {
        self.namespace_match(BinMatch::Suffix(value.into()))
    }

    /// Require the namespace to have exactly the fields matched so far
    ///
    /// This encodes the trailing `nil`. Without it, namespaces with additional
    /// trailing fields are also in scope.
    pub fn namespace_end(mut self) -> Self {
        self.namespace_end = true;
        self
    }

    /// Set the track name match
    ///
    /// The draft's grammar only allows a track match after a namespace match.
    /// If no namespace match has been added, the scope is encoded with a
    /// namespace match of `[[1, h'']]` (any first field), which requires the
    /// namespace to have at least one field, as MoQT namespaces do.
    pub fn track_match(mut self, m: BinMatch) -> Self {
        self.track = Some(m);
        self
    }

    /// Require the track name to equal `value`
    pub fn track_exact(self, value: impl Into<Vec<u8>>) -> Self {
        self.track_match(BinMatch::Exact(value.into()))
    }

    /// Require the track name to start with `value`
    pub fn track_prefix(self, value: impl Into<Vec<u8>>) -> Self {
        self.track_match(BinMatch::Prefix(value.into()))
    }

    /// Require the track name to end with `value`
    pub fn track_suffix(self, value: impl Into<Vec<u8>>) -> Self {
        self.track_match(BinMatch::Suffix(value.into()))
    }

    /// The raw action codes this scope permits
    pub fn action_codes(&self) -> &[i64] {
        &self.actions
    }

    /// The namespace field matches, in order
    pub fn namespace_matches(&self) -> &[BinMatch] {
        &self.namespace
    }

    /// Whether the namespace must have exactly as many fields as matches
    pub fn namespace_is_exact_length(&self) -> bool {
        self.namespace_end
    }

    /// The track name match, if any
    pub fn track(&self) -> Option<&BinMatch> {
        self.track.as_ref()
    }

    /// Whether this scope permits `request`
    pub fn permits(&self, request: &MoqtRequest) -> bool {
        if !self.actions.contains(&request.action.code()) {
            return false;
        }

        match request.action.target() {
            MoqtTarget::Session => true,
            MoqtTarget::Namespace => self.matches_name(&request.namespace, None),
            // A track action with no track name is never permitted
            MoqtTarget::Track => request
                .track
                .as_deref()
                .is_some_and(|track| self.matches_name(&request.namespace, Some(track))),
        }
    }

    /// Whether this scope's name matches cover a namespace and optional track,
    /// regardless of its actions
    ///
    /// This is the matcher [`MoqtScope::permits`] uses. It applies each
    /// namespace field match, the trailing-`nil` length pin, and, when `track`
    /// is `Some`, the track match. With `track = None` only the namespace is
    /// checked, as for namespace actions. A namespace with fewer fields than
    /// the scope's namespace match never matches.
    ///
    /// Use it to re-check names against scopes already selected by action,
    /// for example each track routed to a publisher after PUBLISH_NAMESPACE,
    /// or namespaces returned for SUBSCRIBE_NAMESPACE discovery.
    pub fn matches_name<N: AsRef<[u8]>>(&self, namespace: &[N], track: Option<&[u8]>) -> bool {
        if namespace.len() < self.namespace.len()
            || (self.namespace_end && namespace.len() != self.namespace.len())
        {
            return false;
        }
        if !self
            .namespace
            .iter()
            .zip(namespace)
            .all(|(m, field)| m.matches(field.as_ref()))
        {
            return false;
        }
        match (&self.track, track) {
            (Some(m), Some(track)) => m.matches(track),
            _ => true,
        }
    }

    fn to_cbor(&self) -> CborValue {
        let mut scope = vec![CborValue::Array(
            self.actions
                .iter()
                .map(|a| CborValue::Integer(*a))
                .collect(),
        )];

        let mut ns: Vec<CborValue> = self.namespace.iter().map(BinMatch::to_cbor).collect();
        if self.namespace_end {
            ns.push(CborValue::Null);
        }
        if ns.is_empty() && self.track.is_some() {
            ns.push(BinMatch::Prefix(Vec::new()).to_cbor());
        }
        if !ns.is_empty() {
            scope.push(CborValue::Array(ns));
        }

        if let Some(track) = &self.track {
            scope.push(track.to_cbor());
        }

        CborValue::Array(scope)
    }

    fn from_cbor(value: &CborValue) -> Result<Self, Error> {
        let parts = match value {
            CborValue::Array(parts) if (1..=3).contains(&parts.len()) => parts,
            _ => return Err(invalid("scope must be an array of 1 to 3 elements")),
        };

        let actions = match &parts[0] {
            CborValue::Array(codes) if !codes.is_empty() => codes
                .iter()
                .map(|c| match c {
                    CborValue::Integer(i) => Ok(*i),
                    _ => Err(invalid("action must be an integer")),
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(invalid("actions must be a non-empty array")),
        };

        let mut namespace = Vec::new();
        let mut namespace_end = false;
        if let Some(ns) = parts.get(1) {
            let fields = match ns {
                CborValue::Array(fields) if !fields.is_empty() => fields,
                _ => return Err(invalid("namespace match must be a non-empty array")),
            };
            for (i, field) in fields.iter().enumerate() {
                if *field == CborValue::Null {
                    if i != fields.len() - 1 {
                        return Err(invalid("nil is only allowed as the last namespace match"));
                    }
                    namespace_end = true;
                } else {
                    namespace.push(BinMatch::from_cbor(field)?);
                }
            }
        }

        let track = parts.get(2).map(BinMatch::from_cbor).transpose()?;

        Ok(Self {
            actions,
            namespace,
            namespace_end,
            track,
        })
    }
}

/// The `moqt` claim: a set of scopes, any of which may permit a request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoqtClaim {
    scopes: Vec<MoqtScope>,
}

impl MoqtClaim {
    /// Create a claim from its scopes
    ///
    /// At least one scope is required; a token with an empty `moqt` claim is
    /// malformed and will be rejected by verifiers.
    pub fn new(scopes: Vec<MoqtScope>) -> Self {
        Self { scopes }
    }

    /// The claim's scopes
    pub fn scopes(&self) -> &[MoqtScope] {
        &self.scopes
    }

    /// Whether any scope permits `request`
    pub fn permits(&self, request: &MoqtRequest) -> bool {
        self.scopes.iter().any(|s| s.permits(request))
    }

    /// Encode the claim as a CBOR value (`{0: [scopes...]}`)
    pub fn to_cbor(&self) -> CborValue {
        let mut map = BTreeMap::new();
        map.insert(
            moqt_claim_keys::SCOPES,
            CborValue::Array(self.scopes.iter().map(MoqtScope::to_cbor).collect()),
        );
        CborValue::Map(map)
    }

    /// Parse a claim from a CBOR value
    ///
    /// Parsing is strict: any value outside the draft's grammar is rejected
    /// with [`Error::InvalidMoqtClaim`] rather than ignored, so a malformed
    /// scope can never widen access. Specifically:
    ///
    /// - The map may hold only key 0. Draft -02 §2.1.1 requires any other key
    ///   to be rejected, because a future key might narrow the claim's scope.
    /// - Draft -01's bare-array form is rejected.
    pub fn from_cbor(value: &CborValue) -> Result<Self, Error> {
        let map = match value {
            CborValue::Map(map) => map,
            CborValue::Array(_) => {
                return Err(invalid(
                    "moqt claim is a bare array (draft-ietf-moq-c4m-01 form); \
                     draft-02 requires a map {0: [scopes...]}",
                ))
            }
            _ => return Err(invalid("moqt claim must be a map")),
        };
        if let Some(key) = map.keys().find(|k| **k != moqt_claim_keys::SCOPES) {
            return Err(invalid(&format!("unknown key {key} in moqt claim")));
        }
        match map.get(&moqt_claim_keys::SCOPES) {
            Some(CborValue::Array(scopes)) if !scopes.is_empty() => Ok(Self {
                scopes: scopes
                    .iter()
                    .map(MoqtScope::from_cbor)
                    .collect::<Result<_, _>>()?,
            }),
            Some(_) => Err(invalid("moqt scopes (key 0) must be a non-empty array")),
            None => Err(invalid("moqt claim has no scopes (key 0)")),
        }
    }
}

/// A MoQT request to authorize: an action and the Full Track Name it targets
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoqtRequest {
    /// The action being performed
    pub action: MoqtAction,
    /// The track namespace fields (empty for session actions)
    pub namespace: Vec<Vec<u8>>,
    /// The track name (`None` for session and namespace actions)
    pub track: Option<Vec<u8>>,
}

impl MoqtRequest {
    /// A session-level request, such as `SETUP`
    pub fn session(action: MoqtAction) -> Self {
        Self {
            action,
            namespace: Vec::new(),
            track: None,
        }
    }

    /// A namespace-level request, such as `SUBSCRIBE_NAMESPACE`
    pub fn namespace<I, N>(action: MoqtAction, namespace: I) -> Self
    where
        I: IntoIterator<Item = N>,
        N: Into<Vec<u8>>,
    {
        Self {
            action,
            namespace: namespace.into_iter().map(Into::into).collect(),
            track: None,
        }
    }

    /// A track-level request, such as `SUBSCRIBE`
    pub fn track<I, N>(action: MoqtAction, namespace: I, track: impl Into<Vec<u8>>) -> Self
    where
        I: IntoIterator<Item = N>,
        N: Into<Vec<u8>>,
    {
        Self {
            track: Some(track.into()),
            ..Self::namespace(action, namespace)
        }
    }
}

impl std::fmt::Display for MoqtAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            MoqtAction::Setup => "SETUP",
            MoqtAction::PublishNamespace => "PUBLISH_NAMESPACE",
            MoqtAction::SubscribeNamespace => "SUBSCRIBE_NAMESPACE",
            MoqtAction::Subscribe => "SUBSCRIBE",
            MoqtAction::RequestUpdate => "REQUEST_UPDATE",
            MoqtAction::Publish => "PUBLISH",
            MoqtAction::Fetch => "FETCH",
            MoqtAction::TrackStatus => "TRACK_STATUS",
            MoqtAction::SubscribeTracks => "SUBSCRIBE_TRACKS",
        })
    }
}

/// Formats as `ACTION ns1/ns2 track`, rendering names lossily as UTF-8
impl std::fmt::Display for MoqtRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.action)?;
        if !self.namespace.is_empty() {
            let ns: Vec<_> = self
                .namespace
                .iter()
                .map(|field| String::from_utf8_lossy(field))
                .collect();
            write!(f, " {}", ns.join("/"))?;
        }
        if let Some(track) = &self.track {
            write!(f, " {}", String::from_utf8_lossy(track))?;
        }
        Ok(())
    }
}

/// How a recipient handles the `moqt-reval` (revalidation interval) claim
///
/// The draft requires recipients that cannot revalidate to reject any token
/// carrying a non-zero `moqt-reval`, and recipients to reject intervals shorter
/// than they can support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MoqtRevalidation {
    /// This recipient cannot revalidate tokens
    #[default]
    Unsupported,
    /// This recipient revalidates, at most once per this many seconds
    MinInterval(u64),
}

/// The claim labels under which `moqt` and `moqt-reval` are read
///
/// The defaults (-65537 and -65538, from [`moqt_keys`]) are the Private Use
/// placeholders from draft-ietf-moq-c4m-02's test vectors. IANA has not yet
/// assigned the labels. Until it does, override the defaults to interoperate
/// with issuers that use different labels.
/// Issuers can write a claim at any label with
/// [`TokenBuilder::custom_cbor`](crate::TokenBuilder::custom_cbor) and
/// [`MoqtClaim::to_cbor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoqtClaimLabels {
    /// Label of the moqt (scope) claim
    pub moqt: i32,
    /// Label of the moqt-reval (revalidation interval) claim
    pub reval: i32,
}

impl Default for MoqtClaimLabels {
    fn default() -> Self {
        Self {
            moqt: moqt_keys::MOQT,
            reval: moqt_keys::MOQT_REVAL,
        }
    }
}

/// Parse a `moqt-reval` value, returning `None` when revalidation is not
/// requested (a value of 0)
pub fn parse_moqt_reval(value: &CborValue) -> Result<Option<f64>, Error> {
    let secs = match value {
        CborValue::Integer(i) if *i >= 0 => *i as f64,
        CborValue::Float(f) if f.is_finite() && *f >= 0.0 => *f,
        _ => {
            return Err(invalid(
                "moqt-reval must be a finite, non-negative number of seconds",
            ))
        }
    };
    Ok((secs > 0.0).then_some(secs))
}

fn invalid(msg: &str) -> Error {
    Error::InvalidMoqtClaim(msg.to_string())
}
