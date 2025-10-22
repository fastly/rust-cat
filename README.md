# Common Access Token (CAT) for Rust

[![Crates.io](https://img.shields.io/crates/v/common-access-token.svg)](https://crates.io/crates/common-access-token)
[![Documentation](https://docs.rs/common-access-token/badge.svg)](https://docs.rs/common-access-token)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Rust implementation of the Common Access Token (CAT) specification, which is based on CBOR Object Signing and Encryption (COSE). Common Access Tokens are compact, secure tokens designed for efficient transmission in resource-constrained environments.

## Overview

Common Access Tokens provide a more compact alternative to JSON Web Tokens (JWT) by using CBOR encoding instead of JSON. This makes them ideal for IoT devices, embedded systems, and other environments where bandwidth and processing power are limited.

This library uses the [minicbor](https://crates.io/crates/minicbor) crate for CBOR serialization and deserialization, and supports both COSE_Sign1 and COSE_Mac0 structures for token verification.

## Features

- Compact Representation: CBOR-encoded tokens are significantly smaller than equivalent JWT tokens
- Flexible Token Structure: Support for both protected and unprotected headers
- Multiple Token Formats: Compatible with both COSE_Sign1 and COSE_Mac0 structures
- Standard Claims: Support for all standard CWT claims (iss, sub, aud, exp, nbf, iat, cti)
- Custom Claims: Support for application-specific claims with string, binary, integer, and nested map values
- CAT-specific Claims: Support for CAT-specific claims like CATU (URI restrictions), CATR (token renewal), CATM (HTTP methods), and more
- Key Identifiers: Support for both binary and string key identifiers (kid)
- HMAC-SHA256 Authentication: Secure token signing and verification
- Comprehensive Verification: Validate signatures, expiration times, and other claims
- CAT-specific Validation: Validate URI restrictions, HTTP method constraints, and replay protection

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
common-access-token = "0.2"
```

## Usage

### Creating a token

You can create tokens with various claims and headers using the builder pattern:

```rust
use common_access_token::{
    Algorithm, CborValue, KeyId, RegisteredClaims, TokenBuilder, current_timestamp,
};
use std::collections::BTreeMap;

// Secret key for signing
let key = b"my-secret-key-for-hmac-sha256";
let now = current_timestamp();

// Create a token with string key ID
let token = TokenBuilder::new()
    .algorithm(Algorithm::HmacSha256)
    .protected_key_id(KeyId::string("my-key-id"))
    .registered_claims(
        RegisteredClaims::new()
            .with_issuer("example-issuer")
            .with_subject("example-subject")
            .with_audience("example-audience")
            .with_expiration(now + 3600) // 1 hour from now
            .with_not_before(now)
            .with_issued_at(now)
            .with_cti(b"token-id-1234".to_vec())
    )
    .custom_string(100, "custom-string-value")
    .custom_binary(101, b"custom-binary-value".to_vec())
    .custom_int(102, 12345)
    // You can also add nested maps as claims
    .custom_map(103, {
        let mut map = std::collections::BTreeMap::new();
        map.insert(1, CborValue::Text("nested-value".to_string()));
        map.insert(2, CborValue::Integer(42));
        map
    })
    .sign(key)
    .expect("Failed to sign token");

// Encode token to bytes
let token_bytes = token.to_bytes().expect("Failed to encode token");
```

### Verifying a token

```rust
use common_access_token::{Token, VerificationOptions};

// Decode the token
let token = Token::from_bytes(&token_bytes).expect("Failed to decode token");

// Verify the signature
token.verify(key).expect("Failed to verify signature");

// Verify the claims
let options = VerificationOptions::new()
    .verify_exp(true)
    .verify_nbf(true)
    .expected_issuer("example-issuer")
    .expected_audience("example-audience");

token.verify_claims(&options).expect("Failed to verify claims");

// Access token data
if let Some(kid) = token.header.key_id() {
    match kid {
        KeyId::Binary(data) => println!("Binary key ID: {:?}", data),
        KeyId::String(data) => println!("String key ID: {}", data),
    }
}

if let Some(iss) = &token.claims.registered.iss {
    println!("Issuer: {}", iss);
}

// Access custom claims
if let Some(CborValue::Text(text)) = token.claims.custom.get(&100) {
    println!("Custom string: {}", text);
}

// Access nested map claims
if let Some(CborValue::Map(map)) = token.claims.custom.get(&103) {
    println!("Found nested map with {} entries", map.len());

    if let Some(CborValue::Text(text)) = map.get(&1) {
        println!("Nested text: {}", text);
    }
}
```

## Binary vs String Key IDs

The library supports both binary and string key identifiers:

```rust
// String key ID
let string_kid = KeyId::string("my-key-id");

// Binary key ID
let binary_kid = KeyId::binary(vec![0x01, 0x02, 0x03, 0x04, 0x05]);
```

## Advanced Usage

### Token Format

Common Access Tokens are encoded as CBOR objects following the COSE (CBOR Object Signing and Encryption) specification. When using HMAC algorithms (like HmacSha256), tokens are created as COSE_Mac0 structures with CWT (tag 61) and COSE_Mac0 (tag 17) CBOR tags for compatibility with other CAT implementations.

The token structure is:

```text
COSE_Mac0 = [
  protected: bstr .cbor header_map,
  unprotected: header_map,
  payload: bstr .cbor claims,
  signature: bstr
]
```

### Nested Map Claims

You can include complex structured data in tokens using nested maps:

```rust
use common_access_token::{CborValue, TokenBuilder};
use std::collections::BTreeMap;

// Create a nested map
let mut location_data = BTreeMap::new();
location_data.insert(1, CborValue::Text("coordinates".to_string()));
location_data.insert(2, CborValue::Integer(40));
location_data.insert(3, CborValue::Integer(-74));

// Add it to a token
let token = TokenBuilder::new()
    // ... other token configuration ...
    .custom_map(200, location_data)
    .sign(key)
    .expect("Failed to sign token");
```

### Token Verification Options

You can customize token verification with various options:

```rust
use common_access_token::VerificationOptions;

// Standard verification options
let options = VerificationOptions::new()
    .verify_exp(true)       // Verify expiration time
    .require_exp(true)      // Require expiration claim to be present
    .verify_nbf(true)       // Verify not-before time
    .expected_issuer("trusted-issuer")  // Verify issuer
    .require_iss(true)      // Require issuer claim to be present
    .expected_audience("my-service")    // Verify audience
    .require_aud(true);     // Require audience claim to be present

// CAT-specific verification options
let cat_options = VerificationOptions::new()
    // Standard verification
    .verify_exp(true)
    .expected_issuer("trusted-issuer")

    // CAT-specific verification
    .verify_catu(true)                              // Verify URI restrictions
    .uri("https://api.example.com/users/123")       // URI to verify against

    .verify_catm(true)                              // Verify HTTP method restrictions
    .http_method("GET")                             // HTTP method to verify against

    .verify_catreplay(true)                         // Verify replay protection
    .token_seen_before(false);                      // Whether token has been seen before

token.verify_claims(&options).expect("Failed to verify claims");
token.verify_claims(&cat_options).expect("Failed to verify CAT-specific claims");
```

### Multiple Token Formats Support

This library creates HMAC tokens using the COSE_Mac0 structure with proper CBOR tags for compatibility with other CAT implementations. For verification, the library supports both COSE_Sign1 and COSE_Mac0 structures, automatically trying both formats to ensure backward compatibility:

```rust
// This will work with both COSE_Sign1 and COSE_Mac0 tokens
token.verify(key).expect("Failed to verify signature");
```

## CAT-specific Claims

The Common Access Token (CAT) specification defines several CAT-specific claims that can be used to build tokens with specific access control features. This library provides helper functions for all IANA-registered CAT claims:

### Core Access Control Claims
- CATU (Common Access Token URI) - limits the URI to which the token can provide access
- CATM (Common Access Token Methods) - restricts HTTP methods
- CATREPLAY - controls token replay behavior
- CATR (Common Access Token Renewal) - instructions for token renewal

### Network and Protocol Claims
- CATNIP (Common Access Token Network IP) - IP address restrictions
- CATALPN (Common Access Token ALPN) - TLS ALPN protocol restrictions
- CATH (Common Access Token Header) - HTTP header requirements
- CATTPK (Common Access Token TLS Public Key) - TLS public key pinning

### Geographic Claims
- CATGEOISO3166 - geographic country/region restrictions (ISO 3166 codes)
- CATGEOCOORD - geographic coordinate restrictions
- CATGEOALT - altitude restrictions

### Advanced Claims
- CATV (Common Access Token Version) - CAT specification version
- CATPOR (Common Access Token Probability of Rejection) - probabilistic rate limiting
- CATDPOP (Common Access Token DPoP Settings) - DPoP configuration
- CATIF (Common Access Token If) - conditional logic
- CATIFDATA (Common Access Token If Data) - data for conditional evaluation

The `cat_claims` module provides helper functions and structures for working with all these CAT-specific claims.

### CATU (Common Access Token URI)

The CATU claim allows you to restrict the URI to which the token can provide access. You can specify restrictions on different components of the URI, such as scheme, host, path, etc.

```rust
use common_access_token::{cat_keys, uri_components, catu, TokenBuilder};
use std::collections::BTreeMap;

// Create a CATU claim
let mut catu_components = BTreeMap::new();

// Restrict to https scheme
catu_components.insert(uri_components::SCHEME, catu::exact_match("https"));

// Restrict to example.com host
catu_components.insert(uri_components::HOST, catu::suffix_match(".example.com"));

// Restrict to paths starting with /content
catu_components.insert(uri_components::PATH, catu::prefix_match("/content"));

// Add the CATU claim to the token
let token_builder = TokenBuilder::new()
    // ... other token configuration ...
    .custom_cbor(cat_keys::CATU, catu::create(catu_components));
```

The CATU module provides several match types:

- `exact_match` - exact text match
- `prefix_match` - prefix match
- `suffix_match` - suffix match
- `contains_match` - contains match
- `regex_match` - regular expression match
- `sha256_match` - SHA-256 match
- `sha512_256_match` - SHA-512/256 match

### CATR (Common Access Token Renewal)

The CATR claim provides instructions for token renewal. You can specify different renewal types, such as automatic, cookie, header, or redirect.

```rust
use common_access_token::{cat_keys, catr, TokenBuilder, current_timestamp};

let now = current_timestamp();

// Create an automatic renewal claim
let renewal_params = catr::automatic_renewal(3600, Some((now + 3000) as i64));

// Add the CATR claim to the token
let token_builder = TokenBuilder::new()
    // ... other token configuration ...
    .custom_cbor(cat_keys::CATR, catr::create(renewal_params));
```

The CATR module provides several renewal types:

- `automatic_renewal` - automatic renewal
- `cookie_renewal` - cookie renewal
- `header_renewal` - header renewal
- `redirect_renewal` - redirect renewal

### CATM (Common Access Token Methods)

The CATM claim limits the HTTP methods that can be used with the token.

```rust
use common_access_token::{cat_keys, catm, TokenBuilder};

// Create a CATM claim with allowed methods
let allowed_methods = vec!["GET", "HEAD"];

// Add the CATM claim to the token
let token_builder = TokenBuilder::new()
    // ... other token configuration ...
    .custom_array(cat_keys::CATM, catm::create(allowed_methods));
```

### CATV (Common Access Token Version)

The CATV claim specifies the version of the CAT specification.

```rust
use common_access_token::{cat_keys, catv, TokenBuilder};

// Add the CATV claim to the token
let token_builder = TokenBuilder::new()
    // ... other token configuration ...
    .custom_int(cat_keys::CATV, 1); // Version 1
```

### CAT-specific Claim Keys Reference

The `cat_keys` module provides constants for all CAT-specific claim keys:

- `CATREPLAY` - Common Access Token Replay (catreplay) claim key
- `CATPOR` - Common Access Token Probability of Rejection (catpor) claim key
- `CATV` - Common Access Token Version (catv) claim key
- `CATNIP` - Common Access Token Network IP (catnip) claim key
- `CATU` - Common Access Token URI (catu) claim key
- `CATM` - Common Access Token Methods (catm) claim key
- `CATALPN` - Common Access Token ALPN (catalpn) claim key
- `CATH` - Common Access Token Header (cath) claim key
- `CATGEOISO3166` - Common Access Token Geographic ISO3166 (catgeoiso3166) claim key
- `CATGEOCOORD` - Common Access Token Geographic Coordinate (catgeocoord) claim key
- `CATGEOALT` - Common Access Token Geographic Altitude (catgeoalt) claim key
- `CATTPK` - Common Access Token TLS Public Key (cattpk) claim key
- `CATIFDATA` - Common Access Token If Data (catifdata) claim key
- `CATDPOP` - Common Access Token DPoP Settings (catdpop) claim key
- `CATIF` - Common Access Token If (catif) claim key
- `CATR` - Common Access Token Renewal (catr) claim key

## Examples

See the `examples` directory for complete usage examples:

- `basic_usage.rs`: Demonstrates basic token creation and verification
- `cat_specific_claims.rs`: Demonstrates how to use CAT-specific claims (CATU, CATM, CATR, CATREPLAY)
- `cat_validation.rs`: Shows how to validate CAT-specific claims
- `extended_cat_claims.rs`: Comprehensive examples of all CAT claims including CATPOR, CATNIP, CATALPN, CATH, CATGEO*, CATTPK, CATDPOP, CATIF

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
