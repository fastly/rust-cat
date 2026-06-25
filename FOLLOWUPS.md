# Follow-up items

Deferred findings from the code review of the ES256/PS256 work
(`add-es256-ps256-support`). These were intentionally left out of that change
to keep its scope focused; each is safe to defer and can be picked up
independently.

## Security (separate PR — breaking)

### Algorithm-confusion in `Token::verify`

`verify(key)` selects the verification algorithm from the token's self-declared
`alg` in the protected header, with no way for the caller to pin an expected
algorithm. Now that the crate supports asymmetric key pairs, a relying party
holding only a public key can be attacked: an attacker relabels the header to
`alg = HmacSha256` and computes an HMAC using the (known) public-key bytes as
the MAC secret, and `verify` takes the HMAC path and accepts it. This is the
classic JWT `alg`-confusion attack.

- **Fix direction:** add an expected-algorithm / key-type to `verify` or
  `VerificationOptions` and reject MAC algorithms when an asymmetric key is
  supplied.
- **Why deferred:** the API change (and the design decision about where the
  algorithm expectation should live) is a larger breaking change deserving its
  own PR.
- Location: `src/token.rs` — `Token::verify`.

## Data model (separate PR — breaking)

### Array-valued `aud` is not readable through the typed API

`RegisteredClaims.aud` is `Option<String>` and cannot represent an `aud`
(CWT key 3) encoded as a CBOR **array** of audiences, which RFC 8392 / RFC 7519
permit. On decode, `Claims::from_map` silently drops the array-valued `aud` and
`Token::audience()` returns `None`.

The **correctness** half is already handled: `get_payload_bytes` reuses the
producer's original signed payload bytes (via `baseline_payload_projection`), so
such tokens still **verify** and **round-trip byte-faithfully** even though the
claim is invisible to the typed API (see `test_aud_as_array_verifies_and_roundtrips`
and `test_cti_as_text_verifies_and_roundtrips` in `src/tests.rs`). The urgent
interop/availability regression — valid tokens failing verification — is
resolved.

- **Deferred (not done):** making the array audience *readable* through the
  typed API. That requires changing the type of `RegisteredClaims.aud` (and
  `with_audience` / `audience()`), a breaking public API change.
- **Why deferred:** exposing the value is a nicety with a breaking cost; revisit
  only when bumping a breaking version, and only if a consumer actually needs to
  inspect array audiences. The same lossy-but-now-safe shape affects
  non-conformant producers (e.g. `cti` as text); those are malformed and not
  worth a data-model change.
- Location: `src/claims.rs` — `RegisteredClaims` / `Claims::from_map`.

## Performance (hot path)

### Redundant claims-map rebuild in `get_payload_bytes`

`get_payload_bytes` calls `self.claims.to_map()` (allocating a `BTreeMap` and
deep-cloning every claim value) on every `verify()` / `to_bytes()` for a decoded
token, just to compare against `baseline_payload_projection`, then drops it. The
old code returned `Ok(original.clone())` with no map work. Consider a cheap
fingerprint (length/hash of the encoded claims) or a dirty flag instead.

- Location: `src/token.rs` — `get_payload_bytes`.

### Full CBOR decode in `protected_bytes`

`protected_matches` calls `decode_map(original)` (allocates a fresh `HeaderMap`,
deep-clones every entry) on every `verify()` / `to_bytes()` just to compare and
drop it. The header was already decoded into `self.header.protected` at
`from_bytes` time. Compounding both: an HMAC `verify()` calls `cose_input` twice
(`sign1_input` then `mac0_input`) and `to_bytes()` calls them again, so the
decode + map-rebuild runs 2–4× per operation with no memoization. Compute the
bytes once per public operation and thread them down, or compare
`encode_map(&self.header.protected)` against the cached bytes.

- Location: `src/token.rs` — `protected_bytes` / `protected_matches` / `cose_input`.

## Maintainability / cleanup

### `baseline_payload_projection` is a derivable cached field

It is exactly `Claims::from_map(decode(original_payload_bytes)).to_map()` and is
kept alive for the token's lifetime (≈doubling per-token decode memory). It must
be set consistently at four construction sites. Note the asymmetry:
`protected_bytes` needs no parallel cached field — it derives its comparison on
demand. The payload path could mirror that and drop the field.

- Location: `src/token.rs` — `Token` struct fields, `from_bytes`, `sign`.

### Two divergent mutation-detection mechanisms

The payload uses projection-equality (`claims.to_map() == baseline`) while the
protected header uses decode-and-compare (`decode_map(bytes) == header.protected`).
The divergence is only justified by the payload's lossy `Claims` projection, and
that rationale lives only in prose comments. Consider a single shared helper with
the match-predicate passed in, plus a code-level marker of why they must differ,
so a future "unification" doesn't reintroduce the signature-breaking regression
the caches exist to prevent.

- Location: `src/token.rs` — `get_payload_bytes` / `protected_bytes`.

### `to_bytes` silently emits an untagged, unverifiable token when `alg` is `None`

The `if let Some(alg)` branch emits a bare untagged COSE array when the header
has no algorithm — which the crate's own `verify()` then rejects with
`InvalidFormat("Missing algorithm")`. This state is only reachable via a
hand-built `Token::new`, i.e. a caller bug. Returning `Err(InvalidFormat)` here
would be symmetric with `verify()` / `sign()` and surface the bug instead of
masking it.

- Location: `src/token.rs` — `Token::to_bytes`.

### `Algorithm::is_mac` is redundant with `class()`

`is_mac()` is `matches!(self.class(), AlgorithmClass::Mac)` and has no non-test
caller. Consider dropping it in favor of `class() == AlgorithmClass::Mac`.

- Location: `src/header.rs` — `Algorithm::is_mac`.

### Test helpers re-implement CBOR encoding

`push_bstr` / `push_text` / `build_mac0_token_bytes` hand-roll bstr/text length
prefixes (with implicit size ceilings) that `minicbor::Encoder` already produces.
Low risk today, but they can drift from what the library emits. Test-only.

- Location: `src/tests.rs`.
