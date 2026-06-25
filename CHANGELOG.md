# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unreleased

### Added

- **ES256** (ECDSA using the P-256 curve and SHA-256) signing and verification
  support, producing/consuming `COSE_Sign1` structures.
- **PS256** (RSASSA-PSS using SHA-256 and MGF1 with SHA-256) signing and
  verification support, producing/consuming `COSE_Sign1` structures.
- `Algorithm::Es256` and `Algorithm::Ps256` variants, plus their COSE algorithm
  identifiers (`-7` and `-37`).
- `Error::InvalidKey` for malformed DER key material.
- `examples/asymmetric_signing.rs` and `examples/sample_es256_ps256_tokens.rs`
  demonstrating the new asymmetric algorithms and key formats.

### Changed

- **BREAKING:** `Algorithm` and `Error` are now `#[non_exhaustive]`. Downstream
  `match` expressions over either enum must include a wildcard arm. This is a
  one-time break that allows future variants (additional algorithms or error
  cases) to be added without further breakage.
- **BREAKING:** Minimum supported Rust version (MSRV) raised to `1.88.0`,
  required by the asymmetric crypto dependencies.
- Tokens are tagged according to their algorithm: HMAC (MAC) algorithms use
  `COSE_Mac0` (tag 17) while asymmetric signature algorithms use `COSE_Sign1`
  (tag 18). `Token::from_bytes` accepts both tagged and untagged input.
- `Token::to_bytes` now returns `Error::InvalidFormat` when the protected header
  carries no algorithm, instead of emitting a bare untagged COSE array that the
  crate's own `verify` would reject. This state is only reachable by manually
  constructing a `Token` via `Token::new` without an algorithm.

### Security

- ES256 signatures are now produced in canonical "low-S" form, and `verify`
  rejects high-S (non-canonical) ECDSA signatures. ECDSA signatures are
  malleable — for a valid `(r, s)`, the pair `(r, n - s)` verifies over the same
  message — so without this a third party could derive a second valid signature
  for an unchanged token. Requiring low-S makes the signature bytes a stable
  identity for a token.
- PS256 rejects RSA keys whose modulus is smaller than 2048 bits, on both the
  signing and verification paths. Smaller moduli (e.g. 512- or 1024-bit) are too
  weak to be secure — a 512-bit modulus is factorable on commodity hardware —
  and neither the DER decoders nor PSS verification impose a floor, so without
  this an undersized key would sign and verify normally.

## [0.2.7] - 2025-11-05

### Added

- **CATTPRINT** (TLS Fingerprint) claim support, including verification of
  fingerprint type and value.
- `FingerprintType` enum representing the supported TLS fingerprint types.

### Changed

- TLS fingerprint values are matched case-insensitively (compared in lowercase).
- Updated dependencies.

### Fixed

- Corrected error messages and comments around fingerprint matching.
- Handle signed integer CBOR types when decoding claims.

## [0.2.6] - 2025-10-30

### Added

- **CATU** URI component matching for `FILENAME`, `STEM`, and `PARENT_PATH`.
- Additional tests and documentation for CATU URI components.
- GitHub CI workflow.

### Changed

- Updated dependencies.

[0.3.0]: https://github.com/fastly/rust-cat/compare/0.2.7...HEAD
[0.2.7]: https://github.com/fastly/rust-cat/compare/0.2.6...0.2.7
[0.2.6]: https://github.com/fastly/rust-cat/releases/tag/0.2.6
