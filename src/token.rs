//! Token implementation for Common Access Token

use crate::claims::{Claims, RegisteredClaims};
use crate::constants::tprint_params;
use crate::error::Error;
use crate::header::{Algorithm, CborValue, Header, HeaderMap, KeyId};
use crate::utils::{compute_hmac_sha256, current_timestamp, verify_hmac_sha256};
use minicbor::{Decoder, Encoder};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::Path;

/// Common Access Token structure
#[derive(Debug, Clone)]
pub struct Token {
    /// Token header
    pub header: Header,
    /// Token claims
    pub claims: Claims,
    /// Token signature
    pub signature: Vec<u8>,
    /// Original payload bytes (for verification)
    original_payload_bytes: Option<Vec<u8>>,
}

impl Token {
    /// Create a new token with the given header, claims, and signature
    pub fn new(header: Header, claims: Claims, signature: Vec<u8>) -> Self {
        Self {
            header,
            claims,
            signature,
            original_payload_bytes: None,
        }
    }

    /// Encode the token to CBOR bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);

        // For HMAC algorithms, use COSE_Mac0 format with CWT tag
        if let Some(Algorithm::HmacSha256) = self.header.algorithm() {
            // Apply CWT tag (61)
            enc.tag(minicbor::data::Tag::new(61))?;
            // Apply COSE_Mac0 tag (17)
            enc.tag(minicbor::data::Tag::new(17))?;
        }

        // COSE structure array with 4 items
        enc.array(4)?;

        // 1. Protected header (encoded as CBOR and then as bstr)
        let protected_bytes = encode_map(&self.header.protected)?;
        enc.bytes(&protected_bytes)?;

        // 2. Unprotected header
        encode_map_direct(&self.header.unprotected, &mut enc)?;

        // 3. Payload (encoded as CBOR and then as bstr)
        let claims_map = self.claims.to_map();
        let claims_bytes = encode_map(&claims_map)?;
        enc.bytes(&claims_bytes)?;

        // 4. Signature/MAC
        enc.bytes(&self.signature)?;

        Ok(buf)
    }

    /// Decode a token from CBOR bytes
    ///
    /// This function supports both COSE_Sign1 (tag 18) and COSE_Mac0 (tag 17) structures,
    /// as well as custom tags. It will automatically skip any tags and process the underlying
    /// CBOR array.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut dec = Decoder::new(bytes);

        // Check if the token starts with a tag (COSE_Sign1 tag = 18, COSE_Mac0 tag = 17, or custom tag = 61)
        if dec.datatype()? == minicbor::data::Type::Tag {
            // Skip the tag
            let _ = dec.tag()?;

            // Check for a second tag
            if dec.datatype()? == minicbor::data::Type::Tag {
                let _ = dec.tag()?;
            }
        }

        // Expect array with 4 items
        let array_len = dec.array()?.unwrap_or(0);
        if array_len != 4 {
            return Err(Error::InvalidFormat(format!(
                "Expected array of length 4, got {array_len}"
            )));
        }

        // 1. Protected header
        let protected_bytes = dec.bytes()?;
        let protected = decode_map(protected_bytes)?;

        // 2. Unprotected header
        let unprotected = decode_map_direct(&mut dec)?;

        // Create header
        let header = Header {
            protected,
            unprotected,
        };

        // 3. Payload
        let claims_bytes = dec.bytes()?;
        let claims_map = decode_map(claims_bytes)?;
        let claims = Claims::from_map(&claims_map);

        // 4. Signature
        let signature = dec.bytes()?.to_vec();

        Ok(Self {
            header,
            claims,
            signature,
            original_payload_bytes: Some(claims_bytes.to_vec()),
        })
    }

    /// Verify the token signature
    ///
    /// This function supports both COSE_Sign1 and COSE_Mac0 structures.
    /// It will first try to verify the signature using the COSE_Sign1 structure,
    /// and if that fails, it will try the COSE_Mac0 structure.
    pub fn verify(&self, key: &[u8]) -> Result<(), Error> {
        let alg = self.header.algorithm().ok_or_else(|| {
            Error::InvalidFormat("Missing algorithm in protected header".to_string())
        })?;

        match alg {
            Algorithm::HmacSha256 => {
                // Try with COSE_Sign1 structure first
                let sign1_input = self.sign1_input()?;
                let sign1_result = verify_hmac_sha256(key, &sign1_input, &self.signature);

                if sign1_result.is_ok() {
                    return Ok(());
                }

                // If COSE_Sign1 verification fails, try COSE_Mac0 structure
                let mac0_input = self.mac0_input()?;
                verify_hmac_sha256(key, &mac0_input, &self.signature)
            }
        }
    }

    /// Verify the token claims
    pub fn verify_claims(&self, options: &VerificationOptions) -> Result<(), Error> {
        let now = current_timestamp();

        // Check expiration
        if options.verify_exp {
            if let Some(exp) = self.claims.registered.exp {
                if now >= exp {
                    return Err(Error::Expired);
                }
            } else if options.require_exp {
                return Err(Error::MissingClaim("exp".to_string()));
            }
        }

        // Check not before
        if options.verify_nbf {
            if let Some(nbf) = self.claims.registered.nbf {
                if now < nbf {
                    return Err(Error::NotYetValid);
                }
            }
        }

        // Check issuer
        if let Some(expected_iss) = &options.expected_issuer {
            if let Some(iss) = &self.claims.registered.iss {
                if iss != expected_iss {
                    return Err(Error::InvalidIssuer);
                }
            } else if options.require_iss {
                return Err(Error::MissingClaim("iss".to_string()));
            }
        }

        // Check audience
        if let Some(expected_aud) = &options.expected_audience {
            if let Some(aud) = &self.claims.registered.aud {
                if aud != expected_aud {
                    return Err(Error::InvalidAudience);
                }
            } else if options.require_aud {
                return Err(Error::MissingClaim("aud".to_string()));
            }
        }

        // Check CAT-specific claims
        if options.verify_catu {
            self.verify_catu_claim(options)?;
        }

        if options.verify_catm {
            self.verify_catm_claim(options)?;
        }

        if options.verify_catreplay {
            self.verify_catreplay_claim(options)?;
        }

        if options.verify_cattprint {
            self.verify_cattprint_claim(options)?;
        }

        Ok(())
    }

    /// Verify the CATU (URI) claim against the provided URI
    fn verify_catu_claim(&self, options: &VerificationOptions) -> Result<(), Error> {
        use crate::constants::{cat_keys, uri_components};
        use url::Url;

        // Get the URI to verify against
        let uri = match &options.uri {
            Some(uri) => uri,
            None => {
                return Err(Error::InvalidClaimValue(
                    "No URI provided for CATU verification".to_string(),
                ))
            }
        };

        // Parse the URI
        let parsed_uri = match Url::parse(uri) {
            Ok(url) => url,
            Err(_) => {
                return Err(Error::InvalidClaimValue(format!(
                    "Invalid URI format: {uri}"
                )))
            }
        };

        // Parse the Path from the URI
        let parsed_path = Path::new(parsed_uri.path());

        // Check if token has CATU claim
        let catu_claim = match self.claims.custom.get(&cat_keys::CATU) {
            Some(claim) => claim,
            None => return Ok(()), // No CATU claim, so nothing to verify
        };

        // CATU claim should be a map
        let component_map = match catu_claim {
            CborValue::Map(map) => map,
            _ => {
                return Err(Error::InvalidUriClaim(
                    "CATU claim is not a map".to_string(),
                ))
            }
        };

        // Verify each component in the CATU claim
        for (component_key, component_value) in component_map {
            match *component_key {
                uri_components::SCHEME => {
                    self.verify_uri_component(
                        &parsed_uri.scheme().to_string(),
                        component_value,
                        "scheme",
                    )?;
                }
                uri_components::HOST => {
                    self.verify_uri_component(
                        &parsed_uri.host_str().unwrap_or("").to_string(),
                        component_value,
                        "host",
                    )?;
                }
                uri_components::PORT => {
                    let port = parsed_uri.port().map(|p| p.to_string()).unwrap_or_default();
                    self.verify_uri_component(&port, component_value, "port")?;
                }
                uri_components::PATH => {
                    self.verify_uri_component(
                        &parsed_uri.path().to_string(),
                        component_value,
                        "path",
                    )?;
                }
                uri_components::QUERY => {
                    let query = parsed_uri.query().unwrap_or("").to_string();
                    self.verify_uri_component(&query, component_value, "query")?;
                }
                uri_components::PARENT_PATH => {
                    // Extract parent directory path from URI path.
                    // For URI "https://example.com/a/b/file.txt", this extracts "/a/b".
                    // For root-level files, this returns an empty string.
                    // Non-UTF8 paths are converted to empty strings.
                    let parent_path = parsed_path.parent().unwrap_or(Path::new("")).to_str().unwrap_or("").to_string();
                    self.verify_uri_component(&parent_path, component_value, "parent_path")?;
                }
                uri_components::FILENAME => {
                    // Extract complete filename (with extension) from URI path.
                    // For URI "https://example.com/path/video.mp4", this extracts "video.mp4".
                    // For paths without a filename, this returns an empty string.
                    // Non-UTF8 filenames are converted to empty strings.
                    let filename = parsed_path.file_name().unwrap_or(OsStr::new("")).to_str().unwrap_or("").to_string();
                    self.verify_uri_component(&filename, component_value, "filename")?;
                }
                uri_components::STEM => {
                    // Extract filename without extension from URI path.
                    // For URI "https://example.com/path/video.mp4", this extracts "video".
                    // For "archive.tar.gz", this extracts "archive.tar" (only last extension removed).
                    // For files without extension, returns the entire filename.
                    // Non-UTF8 stems are converted to empty strings.
                    let stem = parsed_path.file_stem().unwrap_or(OsStr::new("")).to_str().unwrap_or("").to_string();
                    self.verify_uri_component(&stem, component_value, "stem")?;
                }
                uri_components::EXTENSION => {
                    // Extract file extension from path
                    let path = parsed_uri.path();
                    let extension = path.split('.').next_back().unwrap_or("").to_string();
                    if !path.contains('.') || path.ends_with('.') {
                        // No extension or ends with dot
                        self.verify_uri_component(&"".to_string(), component_value, "extension")?;
                    } else {
                        self.verify_uri_component(
                            &format!(".{extension}"),
                            component_value,
                            "extension",
                        )?;
                    }
                }
                _ => {
                    // Ignore unsupported components
                }
            }
        }

        Ok(())
    }

    /// Verify a URI component against match conditions
    fn verify_uri_component(
        &self,
        component: &String,
        match_conditions: &CborValue,
        component_name: &str,
    ) -> Result<(), Error> {
        use crate::constants::match_types;
        use hmac_sha256::Hash as Sha256Hash;
        use hmac_sha512::Hash as Sha512Hash;
        use regex::Regex;

        // Match conditions should be a map
        let match_map = match match_conditions {
            CborValue::Map(map) => map,
            _ => {
                return Err(Error::InvalidUriClaim(format!(
                    "Match conditions for {component_name} is not a map"
                )))
            }
        };

        for (match_type, match_value) in match_map {
            match *match_type {
                match_types::EXACT => {
                    if let CborValue::Text(text) = match_value {
                        if component != text {
                            return Err(Error::InvalidUriClaim(format!(
                                "URI component {component_name} '{component}' does not exactly match required value '{text}'"
                            )));
                        }
                    }
                }
                match_types::PREFIX => {
                    if let CborValue::Text(prefix) = match_value {
                        if !component.starts_with(prefix) {
                            return Err(Error::InvalidUriClaim(format!(
                                "URI component {component_name} '{component}' does not start with required prefix '{prefix}'"
                            )));
                        }
                    }
                }
                match_types::SUFFIX => {
                    if let CborValue::Text(suffix) = match_value {
                        if !component.ends_with(suffix) {
                            return Err(Error::InvalidUriClaim(format!(
                                "URI component {component_name} '{component}' does not end with required suffix '{suffix}'"
                            )));
                        }
                    }
                }
                match_types::CONTAINS => {
                    if let CborValue::Text(contained) = match_value {
                        if !component.contains(contained) {
                            return Err(Error::InvalidUriClaim(format!(
                                "URI component {component_name} '{component}' does not contain required text '{contained}'"
                            )));
                        }
                    }
                }
                match_types::REGEX => {
                    if let CborValue::Array(array) = match_value {
                        if let Some(CborValue::Text(pattern)) = array.first() {
                            match Regex::new(pattern) {
                                Ok(regex) => {
                                    if !regex.is_match(component) {
                                        return Err(Error::InvalidUriClaim(format!(
                                            "URI component {component_name} '{component}' does not match required regex pattern '{pattern}'"
                                        )));
                                    }
                                }
                                Err(_) => {
                                    return Err(Error::InvalidUriClaim(format!(
                                        "Invalid regex pattern: {pattern}"
                                    )))
                                }
                            }
                        }
                    }
                }
                match_types::SHA256 => {
                    if let CborValue::Bytes(expected_hash) = match_value {
                        let hash = Sha256Hash::hash(component.as_bytes());

                        if !ct_codecs::verify(&hash, expected_hash.as_slice()) {
                            return Err(Error::InvalidUriClaim(format!(
                                "URI component {component_name} '{component}' SHA-256 hash does not match expected value"
                            )));
                        }
                    }
                }
                match_types::SHA512_256 => {
                    if let CborValue::Bytes(expected_hash) = match_value {
                        let hash = Sha512Hash::hash(component.as_bytes());
                        let truncated_hash = &hash[0..32]; // Take first 256 bits (32 bytes)

                        if !ct_codecs::verify(truncated_hash, &expected_hash[..]) {
                            return Err(Error::InvalidUriClaim(format!(
                                "URI component {component_name} '{component}' SHA-512/256 hash does not match expected value"
                            )));
                        }
                    }
                }
                _ => {
                    // Ignore unsupported match types
                }
            }
        }

        Ok(())
    }

    /// Verify the CATM (HTTP method) claim against the provided method
    fn verify_catm_claim(&self, options: &VerificationOptions) -> Result<(), Error> {
        use crate::constants::cat_keys;

        // Get the HTTP method to verify against
        let method = match &options.http_method {
            Some(method) => method,
            None => {
                return Err(Error::InvalidClaimValue(
                    "No HTTP method provided for CATM verification".to_string(),
                ))
            }
        };

        // Check if token has CATM claim
        let catm_claim = match self.claims.custom.get(&cat_keys::CATM) {
            Some(claim) => claim,
            None => return Ok(()), // No CATM claim, so nothing to verify
        };

        // CATM claim should be an array of allowed methods
        let allowed_methods = match catm_claim {
            CborValue::Array(methods) => methods,
            _ => {
                return Err(Error::InvalidMethodClaim(
                    "CATM claim is not an array".to_string(),
                ))
            }
        };

        // Check if the provided method is in the allowed methods list
        let method_upper = method.to_uppercase();
        let method_allowed = allowed_methods.iter().any(|m| {
            if let CborValue::Text(allowed) = m {
                allowed.to_uppercase() == method_upper
            } else {
                false
            }
        });

        if !method_allowed {
            return Err(Error::InvalidMethodClaim(format!(
                "HTTP method '{}' is not allowed. Permitted methods: {:?}",
                method,
                allowed_methods
                    .iter()
                    .filter_map(|m| if let CborValue::Text(t) = m {
                        Some(t.as_str())
                    } else {
                        None
                    })
                    .collect::<Vec<&str>>()
            )));
        }

        Ok(())
    }

    /// Verify the CATREPLAY claim for token replay protection
    fn verify_catreplay_claim(&self, options: &VerificationOptions) -> Result<(), Error> {
        use crate::constants::{cat_keys, replay_values};

        // Check if token has CATREPLAY claim
        let catreplay_claim = match self.claims.custom.get(&cat_keys::CATREPLAY) {
            Some(claim) => claim,
            None => return Ok(()), // No CATREPLAY claim, so nothing to verify
        };

        // Get the replay protection value
        let replay_value = match catreplay_claim {
            CborValue::Integer(value) => *value as i32,
            _ => {
                return Err(Error::InvalidClaimValue(
                    "CATREPLAY claim is not an integer".to_string(),
                ))
            }
        };

        match replay_value {
            replay_values::PERMITTED => {
                // Replay is permitted, no verification needed
                Ok(())
            }
            replay_values::PROHIBITED => {
                // Replay is prohibited, check if token has been seen before
                if options.token_seen_before {
                    Err(Error::ReplayViolation(
                        "Token replay is prohibited".to_string(),
                    ))
                } else {
                    Ok(())
                }
            }
            replay_values::REUSE_DETECTION => {
                // Reuse is detected but allowed, no error returned
                // Implementations should log or notify about reuse
                Ok(())
            }
            _ => Err(Error::InvalidClaimValue(format!(
                "Invalid CATREPLAY value: {replay_value}"
            ))),
        }
    }

    /// Verify the CATTPRINT (TLS Fingerprint) claim against the provided fingerprint type and value
    fn verify_cattprint_claim(&self, options: &VerificationOptions) -> Result<(), Error> {
        use crate::constants::cat_keys;

        // Get the Fingerprint type to verify against
        let fingerprint_type = match &options.fingerprint_type {
            Some(fingerprint_type) => fingerprint_type,
            None => {
                return Err(Error::InvalidClaimValue(
                    "No Fingerprint Type provided for CATTPRINT verification".to_string(),
                ))
            }
        };

        // Get the Fingerprint value to verify against
        let fingerprint_value = match &options.fingerprint_value {
            Some(fingerprint_value) => fingerprint_value,
            None => {
                return Err(Error::InvalidClaimValue(
                    "No Fingerprint Value provided for CATTPRINT verification".to_string(),
                ))
            }
        };

        // Check if token has CATTPRINT claim
        let cattprint_claim = match self.claims.custom.get(&cat_keys::CATTPRINT) {
            Some(claim) => claim,
            None => return Ok(()), // No CATTPRINT claim, so nothing to verify
        };

        // CATTPRINT claim should be a map of 2 values
        let cattprint_map = match cattprint_claim {
            CborValue::Map(cattprint_map) => cattprint_map,
            _ => {
                return Err(Error::InvalidTLSFingerprintClaim(
                    "CATTPRINT claim is not a map".to_string(),
                ))
            }
        };

        // Check if the provided Fingerprint Type matches
        let fingerprint_type_upper = fingerprint_type.to_uppercase();
        let claim_fingerprint_type = cattprint_map.get(&tprint_params::FINGERPRINT_TYPE);
        if let Some(CborValue::Text(claim_type)) = claim_fingerprint_type {
            if claim_type.to_uppercase() != fingerprint_type_upper {
                return Err(Error::InvalidTLSFingerprintClaim(format!(
                    "TLS Fingerprint Type '{}' does not match required value '{}'",
                    claim_type, fingerprint_type
                )));
            }
        } else {
            return Err(Error::InvalidTLSFingerprintClaim(
                "Missing or invalid Fingerprint Type in CATTPRINT claim".to_string(),
            ));
        }

        // Check if the provided Fingerprint Value matches
        let fingerprint_value_upper = fingerprint_value.to_uppercase();
        let claim_fingerprint_value = cattprint_map.get(&tprint_params::FINGERPRINT_VALUE);
        if let Some(CborValue::Text(claim_value)) = claim_fingerprint_value {
            if claim_value.to_uppercase() != fingerprint_value_upper {
                return Err(Error::InvalidTLSFingerprintClaim(format!(
                    "TLS Fingerprint Value '{}' does not match required value '{}'",
                    claim_value, fingerprint_value
                )));
            }
        } else {
            return Err(Error::InvalidTLSFingerprintClaim(
                "Missing or invalid Fingerprint Value in CATTPRINT claim".to_string(),
            ));
        }

        Ok(())
    }

    // Note: signature_input method removed as we now use mac0_input for HMAC algorithms

    /// Get the encoded payload bytes, using original bytes if available
    fn get_payload_bytes(&self) -> Result<Vec<u8>, Error> {
        if let Some(ref original) = self.original_payload_bytes {
            // Use original bytes for verification
            Ok(original.clone())
        } else {
            // Encode claims for newly created tokens
            let claims_map = self.claims.to_map();
            encode_map(&claims_map)
        }
    }

    /// Get the COSE_Sign1 signature input
    fn sign1_input(&self) -> Result<Vec<u8>, Error> {
        // Sig_structure = [
        //   context : "Signature1",
        //   protected : bstr .cbor header_map,
        //   external_aad : bstr,
        //   payload : bstr .cbor claims
        // ]

        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);

        // Start array with 4 items
        enc.array(4)?;

        // 1. Context
        enc.str("Signature1")?;

        // 2. Protected header
        let protected_bytes = encode_map(&self.header.protected)?;
        enc.bytes(&protected_bytes)?;

        // 3. External AAD (empty in our case)
        enc.bytes(&[])?;

        // 4. Payload
        let claims_bytes = self.get_payload_bytes()?;
        enc.bytes(&claims_bytes)?;

        Ok(buf)
    }

    /// Get the COSE_Mac0 signature input
    fn mac0_input(&self) -> Result<Vec<u8>, Error> {
        // Mac_structure = [
        //   context : "MAC0",
        //   protected : bstr .cbor header_map,
        //   external_aad : bstr,
        //   payload : bstr .cbor claims
        // ]

        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);

        // Start array with 4 items
        enc.array(4)?;

        // 1. Context
        enc.str("MAC0")?;

        // 2. Protected header
        let protected_bytes = encode_map(&self.header.protected)?;
        enc.bytes(&protected_bytes)?;

        // 3. External AAD (empty in our case)
        enc.bytes(&[])?;

        // 4. Payload
        let claims_bytes = self.get_payload_bytes()?;
        enc.bytes(&claims_bytes)?;

        Ok(buf)
    }

    // Convenience methods for common token operations

    /// Check if the token has expired
    ///
    /// Returns `true` if the token has an expiration claim and the current time is at or after it.
    /// Returns `false` if the token has no expiration claim or if it hasn't expired yet.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{TokenBuilder, Algorithm, RegisteredClaims, current_timestamp};
    ///
    /// let key = b"my-secret-key";
    /// let now = current_timestamp();
    ///
    /// // Token that expires in 1 hour
    /// let token = TokenBuilder::new()
    ///     .algorithm(Algorithm::HmacSha256)
    ///     .registered_claims(RegisteredClaims::new().with_expiration(now + 3600))
    ///     .sign(key)
    ///     .unwrap();
    ///
    /// assert!(!token.is_expired());
    /// ```
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.claims.registered.exp {
            current_timestamp() >= exp
        } else {
            false
        }
    }

    /// Get the duration until token expiration
    ///
    /// Returns `Some(Duration)` if the token has an expiration claim and hasn't expired yet.
    /// Returns `None` if the token has no expiration claim or has already expired.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{TokenBuilder, Algorithm, RegisteredClaims, current_timestamp};
    ///
    /// let key = b"my-secret-key";
    /// let now = current_timestamp();
    ///
    /// let token = TokenBuilder::new()
    ///     .algorithm(Algorithm::HmacSha256)
    ///     .registered_claims(RegisteredClaims::new().with_expiration(now + 3600))
    ///     .sign(key)
    ///     .unwrap();
    ///
    /// if let Some(duration) = token.expires_in() {
    ///     println!("Token expires in {} seconds", duration.as_secs());
    /// }
    /// ```
    pub fn expires_in(&self) -> Option<std::time::Duration> {
        if let Some(exp) = self.claims.registered.exp {
            let now = current_timestamp();
            if now < exp {
                Some(std::time::Duration::from_secs(exp - now))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Check if the token is valid based on the not-before (nbf) claim
    ///
    /// Returns `true` if the token has no nbf claim or if the current time is at or after it.
    /// Returns `false` if the token has an nbf claim and the current time is before it.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{TokenBuilder, Algorithm, RegisteredClaims, current_timestamp};
    ///
    /// let key = b"my-secret-key";
    /// let now = current_timestamp();
    ///
    /// let token = TokenBuilder::new()
    ///     .algorithm(Algorithm::HmacSha256)
    ///     .registered_claims(RegisteredClaims::new().with_not_before(now))
    ///     .sign(key)
    ///     .unwrap();
    ///
    /// assert!(token.is_valid_yet());
    /// ```
    pub fn is_valid_yet(&self) -> bool {
        if let Some(nbf) = self.claims.registered.nbf {
            current_timestamp() >= nbf
        } else {
            true
        }
    }

    /// Get the issuer claim value
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{TokenBuilder, Algorithm, RegisteredClaims};
    ///
    /// let key = b"my-secret-key";
    /// let token = TokenBuilder::new()
    ///     .algorithm(Algorithm::HmacSha256)
    ///     .registered_claims(RegisteredClaims::new().with_issuer("example-issuer"))
    ///     .sign(key)
    ///     .unwrap();
    ///
    /// assert_eq!(token.issuer(), Some("example-issuer"));
    /// ```
    pub fn issuer(&self) -> Option<&str> {
        self.claims.registered.iss.as_deref()
    }

    /// Get the subject claim value
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{TokenBuilder, Algorithm, RegisteredClaims};
    ///
    /// let key = b"my-secret-key";
    /// let token = TokenBuilder::new()
    ///     .algorithm(Algorithm::HmacSha256)
    ///     .registered_claims(RegisteredClaims::new().with_subject("user-123"))
    ///     .sign(key)
    ///     .unwrap();
    ///
    /// assert_eq!(token.subject(), Some("user-123"));
    /// ```
    pub fn subject(&self) -> Option<&str> {
        self.claims.registered.sub.as_deref()
    }

    /// Get the audience claim value
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{TokenBuilder, Algorithm, RegisteredClaims};
    ///
    /// let key = b"my-secret-key";
    /// let token = TokenBuilder::new()
    ///     .algorithm(Algorithm::HmacSha256)
    ///     .registered_claims(RegisteredClaims::new().with_audience("api-service"))
    ///     .sign(key)
    ///     .unwrap();
    ///
    /// assert_eq!(token.audience(), Some("api-service"));
    /// ```
    pub fn audience(&self) -> Option<&str> {
        self.claims.registered.aud.as_deref()
    }

    /// Get the expiration timestamp
    pub fn expiration(&self) -> Option<u64> {
        self.claims.registered.exp
    }

    /// Get the not-before timestamp
    pub fn not_before(&self) -> Option<u64> {
        self.claims.registered.nbf
    }

    /// Get the issued-at timestamp
    pub fn issued_at(&self) -> Option<u64> {
        self.claims.registered.iat
    }

    /// Get a custom claim as a string
    ///
    /// Returns `Some(&str)` if the claim exists and is a text value, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{TokenBuilder, Algorithm};
    ///
    /// let key = b"my-secret-key";
    /// let token = TokenBuilder::new()
    ///     .algorithm(Algorithm::HmacSha256)
    ///     .custom_string(100, "custom-value")
    ///     .sign(key)
    ///     .unwrap();
    ///
    /// assert_eq!(token.get_custom_string(100), Some("custom-value"));
    /// assert_eq!(token.get_custom_string(999), None);
    /// ```
    pub fn get_custom_string(&self, key: i32) -> Option<&str> {
        match self.claims.custom.get(&key) {
            Some(CborValue::Text(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Get a custom claim as an integer
    ///
    /// Returns `Some(i64)` if the claim exists and is an integer value, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{TokenBuilder, Algorithm};
    ///
    /// let key = b"my-secret-key";
    /// let token = TokenBuilder::new()
    ///     .algorithm(Algorithm::HmacSha256)
    ///     .custom_int(100, 42)
    ///     .sign(key)
    ///     .unwrap();
    ///
    /// assert_eq!(token.get_custom_int(100), Some(42));
    /// assert_eq!(token.get_custom_int(999), None);
    /// ```
    pub fn get_custom_int(&self, key: i32) -> Option<i64> {
        match self.claims.custom.get(&key) {
            Some(CborValue::Integer(i)) => Some(*i),
            _ => None,
        }
    }

    /// Get a custom claim as binary data
    ///
    /// Returns `Some(&[u8])` if the claim exists and is a bytes value, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{TokenBuilder, Algorithm};
    ///
    /// let key = b"my-secret-key";
    /// let data = vec![1, 2, 3, 4];
    /// let token = TokenBuilder::new()
    ///     .algorithm(Algorithm::HmacSha256)
    ///     .custom_binary(100, data.clone())
    ///     .sign(key)
    ///     .unwrap();
    ///
    /// assert_eq!(token.get_custom_binary(100), Some(data.as_slice()));
    /// assert_eq!(token.get_custom_binary(999), None);
    /// ```
    pub fn get_custom_binary(&self, key: i32) -> Option<&[u8]> {
        match self.claims.custom.get(&key) {
            Some(CborValue::Bytes(b)) => Some(b.as_slice()),
            _ => None,
        }
    }

    /// Get a reference to a custom claim value
    ///
    /// Returns `Some(&CborValue)` if the claim exists, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{TokenBuilder, Algorithm, CborValue};
    ///
    /// let key = b"my-secret-key";
    /// let token = TokenBuilder::new()
    ///     .algorithm(Algorithm::HmacSha256)
    ///     .custom_string(100, "value")
    ///     .sign(key)
    ///     .unwrap();
    ///
    /// if let Some(CborValue::Text(s)) = token.get_custom_claim(100) {
    ///     assert_eq!(s, "value");
    /// }
    /// ```
    pub fn get_custom_claim(&self, key: i32) -> Option<&CborValue> {
        self.claims.custom.get(&key)
    }

    /// Check if a custom claim exists
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{TokenBuilder, Algorithm};
    ///
    /// let key = b"my-secret-key";
    /// let token = TokenBuilder::new()
    ///     .algorithm(Algorithm::HmacSha256)
    ///     .custom_string(100, "value")
    ///     .sign(key)
    ///     .unwrap();
    ///
    /// assert!(token.has_custom_claim(100));
    /// assert!(!token.has_custom_claim(999));
    /// ```
    pub fn has_custom_claim(&self, key: i32) -> bool {
        self.claims.custom.contains_key(&key)
    }
}

/// Options for token verification
#[derive(Debug, Clone, Default)]
pub struct VerificationOptions {
    /// Verify expiration claim
    pub verify_exp: bool,
    /// Require expiration claim
    pub require_exp: bool,
    /// Verify not before claim
    pub verify_nbf: bool,
    /// Expected issuer
    pub expected_issuer: Option<String>,
    /// Require issuer claim
    pub require_iss: bool,
    /// Expected audience
    pub expected_audience: Option<String>,
    /// Require audience claim
    pub require_aud: bool,
    /// Verify CAT-specific URI claim (CATU) against provided URI
    pub verify_catu: bool,
    /// URI to verify against CATU claim
    pub uri: Option<String>,
    /// Verify CAT-specific HTTP methods claim (CATM) against provided method
    pub verify_catm: bool,
    /// HTTP method to verify against CATM claim
    pub http_method: Option<String>,
    /// Verify CAT-specific replay protection (CATREPLAY)
    pub verify_catreplay: bool,
    /// Whether the token has been seen before (for replay protection)
    pub token_seen_before: bool,
    /// Verify CAT-specific TLS Fingerprint claim (CATTPRINT) against provided Fingerprint Type and Value
    pub verify_cattprint: bool,
    /// Fingerprint Type to verify against CATTPRINT claim
    pub fingerprint_type: Option<String>,
    /// Fingerprint Value to verify against CATTPRINT claim
    pub fingerprint_value: Option<String>,
}

impl VerificationOptions {
    /// Create new default verification options
    pub fn new() -> Self {
        Self {
            verify_exp: true,
            require_exp: false,
            verify_nbf: true,
            expected_issuer: None,
            require_iss: false,
            expected_audience: None,
            require_aud: false,
            verify_catu: false,
            uri: None,
            verify_catm: false,
            http_method: None,
            verify_catreplay: false,
            token_seen_before: false,
            verify_cattprint: false,
            fingerprint_type: None,
            fingerprint_value: None,
        }
    }

    /// Set whether to verify expiration
    pub fn verify_exp(mut self, verify: bool) -> Self {
        self.verify_exp = verify;
        self
    }

    /// Set whether to require expiration
    pub fn require_exp(mut self, require: bool) -> Self {
        self.require_exp = require;
        self
    }

    /// Set whether to verify not before
    pub fn verify_nbf(mut self, verify: bool) -> Self {
        self.verify_nbf = verify;
        self
    }

    /// Set expected issuer
    pub fn expected_issuer<S: Into<String>>(mut self, issuer: S) -> Self {
        self.expected_issuer = Some(issuer.into());
        self
    }

    /// Set whether to require issuer
    pub fn require_iss(mut self, require: bool) -> Self {
        self.require_iss = require;
        self
    }

    /// Set expected audience
    pub fn expected_audience<S: Into<String>>(mut self, audience: S) -> Self {
        self.expected_audience = Some(audience.into());
        self
    }

    /// Set whether to require audience
    pub fn require_aud(mut self, require: bool) -> Self {
        self.require_aud = require;
        self
    }

    /// Set whether to verify CAT-specific URI claim (CATU)
    pub fn verify_catu(mut self, verify: bool) -> Self {
        self.verify_catu = verify;
        self
    }

    /// Set URI to verify against CATU claim
    pub fn uri<S: Into<String>>(mut self, uri: S) -> Self {
        self.uri = Some(uri.into());
        self
    }

    /// Set whether to verify CAT-specific HTTP methods claim (CATM)
    pub fn verify_catm(mut self, verify: bool) -> Self {
        self.verify_catm = verify;
        self
    }

    /// Set HTTP method to verify against CATM claim
    pub fn http_method<S: Into<String>>(mut self, method: S) -> Self {
        self.http_method = Some(method.into());
        self
    }

    /// Set whether to verify CAT-specific replay protection (CATREPLAY)
    pub fn verify_catreplay(mut self, verify: bool) -> Self {
        self.verify_catreplay = verify;
        self
    }

    /// Set whether the token has been seen before (for replay protection)
    pub fn token_seen_before(mut self, seen: bool) -> Self {
        self.token_seen_before = seen;
        self
    }

    /// Set whether to verify CAT-specific TLS Fingerprint claim (CATTPRINT)
    pub fn verify_cattprint(mut self, verify: bool) -> Self {
        self.verify_cattprint = verify;
        self
    }

    /// Set fingerprint type to verify for the CATTPRINT claim
    pub fn fingerprint_type<S: Into<String>>(mut self, fingerprint_type: S) -> Self {
        self.fingerprint_type = Some(fingerprint_type.into());
        self
    }

    /// Set fingerprint value to verify for the CATTPRINT claim
    pub fn fingerprint_value<S: Into<String>>(mut self, fingerprint_value: S) -> Self {
        self.fingerprint_value = Some(fingerprint_value.into());
        self
    }
}

/// Builder for creating tokens
#[derive(Debug, Clone, Default)]
pub struct TokenBuilder {
    header: Header,
    claims: Claims,
}

impl TokenBuilder {
    /// Create a new token builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the algorithm
    pub fn algorithm(mut self, alg: Algorithm) -> Self {
        self.header = self.header.with_algorithm(alg);
        self
    }

    /// Set the key identifier in the protected header
    pub fn protected_key_id(mut self, kid: KeyId) -> Self {
        self.header = self.header.with_protected_key_id(kid);
        self
    }

    /// Set the key identifier in the unprotected header
    pub fn unprotected_key_id(mut self, kid: KeyId) -> Self {
        self.header = self.header.with_unprotected_key_id(kid);
        self
    }

    /// Set the registered claims
    pub fn registered_claims(mut self, claims: RegisteredClaims) -> Self {
        self.claims = self.claims.with_registered_claims(claims);
        self
    }

    /// Add a custom claim with a string value
    pub fn custom_string<S: Into<String>>(mut self, key: i32, value: S) -> Self {
        self.claims = self.claims.with_custom_string(key, value);
        self
    }

    /// Add a custom claim with a binary value
    pub fn custom_binary<B: Into<Vec<u8>>>(mut self, key: i32, value: B) -> Self {
        self.claims = self.claims.with_custom_binary(key, value);
        self
    }

    /// Add a custom claim with an integer value
    pub fn custom_int(mut self, key: i32, value: i64) -> Self {
        self.claims = self.claims.with_custom_int(key, value);
        self
    }

    /// Add a custom claim with a nested map value
    pub fn custom_map(mut self, key: i32, value: BTreeMap<i32, CborValue>) -> Self {
        self.claims = self.claims.with_custom_map(key, value);
        self
    }

    /// Add a custom claim with a CborValue directly
    pub fn custom_cbor(mut self, key: i32, value: CborValue) -> Self {
        self.claims.custom.insert(key, value);
        self
    }

    /// Add a custom claim with an array value
    pub fn custom_array(mut self, key: i32, value: Vec<CborValue>) -> Self {
        self.claims.custom.insert(key, CborValue::Array(value));
        self
    }

    /// Set expiration time relative to now (in seconds)
    ///
    /// This is a convenience method that sets the expiration claim to the current time plus the specified number of seconds.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{TokenBuilder, Algorithm, current_timestamp};
    ///
    /// let key = b"my-secret-key";
    ///
    /// // Token expires in 1 hour
    /// let token = TokenBuilder::new()
    ///     .algorithm(Algorithm::HmacSha256)
    ///     .expires_in_secs(3600)
    ///     .sign(key)
    ///     .unwrap();
    ///
    /// assert!(!token.is_expired());
    /// ```
    pub fn expires_in_secs(mut self, seconds: u64) -> Self {
        let exp = current_timestamp() + seconds;
        self.claims.registered.exp = Some(exp);
        self
    }

    /// Set expiration time relative to now using a Duration
    ///
    /// This is a convenience method that sets the expiration claim to the current time plus the specified duration.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{TokenBuilder, Algorithm};
    /// use std::time::Duration;
    ///
    /// let key = b"my-secret-key";
    ///
    /// // Token expires in 1 hour
    /// let token = TokenBuilder::new()
    ///     .algorithm(Algorithm::HmacSha256)
    ///     .expires_in(Duration::from_secs(3600))
    ///     .sign(key)
    ///     .unwrap();
    ///
    /// assert!(!token.is_expired());
    /// ```
    pub fn expires_in(self, duration: std::time::Duration) -> Self {
        self.expires_in_secs(duration.as_secs())
    }

    /// Set token lifetime with issued-at and expiration claims
    ///
    /// This convenience method sets both the `iat` (issued at) and `exp` (expiration) claims.
    /// The issued-at is set to the current time, and expiration is set to current time plus the specified seconds.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{TokenBuilder, Algorithm};
    ///
    /// let key = b"my-secret-key";
    ///
    /// // Token valid for 1 hour
    /// let token = TokenBuilder::new()
    ///     .algorithm(Algorithm::HmacSha256)
    ///     .valid_for_secs(3600)
    ///     .sign(key)
    ///     .unwrap();
    ///
    /// assert!(token.issued_at().is_some());
    /// assert!(token.expiration().is_some());
    /// ```
    pub fn valid_for_secs(mut self, seconds: u64) -> Self {
        let now = current_timestamp();
        self.claims.registered.iat = Some(now);
        self.claims.registered.exp = Some(now + seconds);
        self
    }

    /// Set token lifetime with issued-at and expiration claims using a Duration
    ///
    /// This convenience method sets both the `iat` (issued at) and `exp` (expiration) claims.
    /// The issued-at is set to the current time, and expiration is set to current time plus the specified duration.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{TokenBuilder, Algorithm};
    /// use std::time::Duration;
    ///
    /// let key = b"my-secret-key";
    ///
    /// // Token valid for 1 hour
    /// let token = TokenBuilder::new()
    ///     .algorithm(Algorithm::HmacSha256)
    ///     .valid_for(Duration::from_secs(3600))
    ///     .sign(key)
    ///     .unwrap();
    ///
    /// assert!(token.issued_at().is_some());
    /// assert!(token.expiration().is_some());
    /// ```
    pub fn valid_for(self, duration: std::time::Duration) -> Self {
        self.valid_for_secs(duration.as_secs())
    }

    /// Build and sign the token
    pub fn sign(self, key: &[u8]) -> Result<Token, Error> {
        // Ensure we have an algorithm
        let alg = self.header.algorithm().ok_or_else(|| {
            Error::InvalidFormat("Missing algorithm in protected header".to_string())
        })?;

        // Create token without signature
        let token = Token {
            header: self.header,
            claims: self.claims,
            signature: Vec::new(),
            original_payload_bytes: None,
        };

        // Compute signature input based on algorithm
        // HMAC algorithms use COSE_Mac0 structure, others use COSE_Sign1
        let (_signature_input, signature) = match alg {
            Algorithm::HmacSha256 => {
                let mac_input = token.mac0_input()?;
                let mac = compute_hmac_sha256(key, &mac_input);
                (mac_input, mac)
            }
        };

        // Create final token with signature
        Ok(Token {
            header: token.header,
            claims: token.claims,
            signature,
            original_payload_bytes: None,
        })
    }
}

// Helper functions for CBOR encoding/decoding

fn encode_map(map: &HeaderMap) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);

    encode_map_direct(map, &mut enc)?;

    Ok(buf)
}

/// Encode a CBOR value directly to the encoder
fn encode_cbor_value(value: &CborValue, enc: &mut Encoder<&mut Vec<u8>>) -> Result<(), Error> {
    match value {
        CborValue::Integer(i) => {
            enc.i64(*i)?;
        }
        CborValue::Bytes(b) => {
            enc.bytes(b)?;
        }
        CborValue::Text(s) => {
            enc.str(s)?;
        }
        CborValue::Map(nested_map) => {
            // Create a nested encoder for the map
            encode_map_direct(nested_map, enc)?;
        }
        CborValue::Array(arr) => {
            // Create a nested encoder for the array
            enc.array(arr.len() as u64)?;
            for item in arr {
                encode_cbor_value(item, enc)?;
            }
        }
        CborValue::Null => {
            enc.null()?;
        }
    }
    Ok(())
}

fn encode_map_direct(map: &HeaderMap, enc: &mut Encoder<&mut Vec<u8>>) -> Result<(), Error> {
    enc.map(map.len() as u64)?;

    for (key, value) in map {
        enc.i32(*key)?;
        encode_cbor_value(value, enc)?;
    }

    Ok(())
}

fn decode_map(bytes: &[u8]) -> Result<HeaderMap, Error> {
    let mut dec = Decoder::new(bytes);
    decode_map_direct(&mut dec)
}

/// Decode a CBOR array
fn decode_array(dec: &mut Decoder<'_>) -> Result<Vec<CborValue>, Error> {
    let array_len = dec.array()?.unwrap_or(0);
    let mut array = Vec::with_capacity(array_len as usize);

    for _ in 0..array_len {
        // Try to decode based on the datatype
        let datatype = dec.datatype()?;

        // Handle each type separately
        let value = if datatype == minicbor::data::Type::Int {
            // Integer value
            let i = dec.i64()?;
            CborValue::Integer(i)
        } else if datatype == minicbor::data::Type::U8
            || datatype == minicbor::data::Type::U16
            || datatype == minicbor::data::Type::U32
            || datatype == minicbor::data::Type::U64
        {
            // Unsigned integer value
            let i = dec.u64()? as i64;
            CborValue::Integer(i)
        } else if datatype == minicbor::data::Type::Bytes {
            // Byte string
            let b = dec.bytes()?;
            CborValue::Bytes(b.to_vec())
        } else if datatype == minicbor::data::Type::String {
            // Text string
            let s = dec.str()?;
            CborValue::Text(s.to_string())
        } else if datatype == minicbor::data::Type::Map {
            // Nested map
            let nested_map = decode_map_direct(dec)?;
            CborValue::Map(nested_map)
        } else if datatype == minicbor::data::Type::Array {
            // Nested array
            let nested_array = decode_array(dec)?;
            CborValue::Array(nested_array)
        } else if datatype == minicbor::data::Type::Null {
            // Null value
            dec.null()?;
            CborValue::Null
        } else {
            // Unsupported type
            return Err(Error::InvalidFormat(format!(
                "Unsupported CBOR type in array: {datatype:?}"
            )));
        };

        array.push(value);
    }

    Ok(array)
}

fn decode_map_direct(dec: &mut Decoder<'_>) -> Result<HeaderMap, Error> {
    let map_len = dec.map()?.unwrap_or(0);
    let mut map = HeaderMap::new();

    for _ in 0..map_len {
        let key = dec.i32()?;

        // Try to decode based on the datatype
        let datatype = dec.datatype()?;

        // Handle each type separately
        let value = if datatype == minicbor::data::Type::Int {
            // Integer value
            let i = dec.i64()?;
            CborValue::Integer(i)
        } else if datatype == minicbor::data::Type::U8
            || datatype == minicbor::data::Type::U16
            || datatype == minicbor::data::Type::U32
            || datatype == minicbor::data::Type::U64
        {
            // Unsigned integer value
            let i = dec.u64()? as i64;
            CborValue::Integer(i)
        } else if datatype == minicbor::data::Type::Bytes {
            // Byte string
            let b = dec.bytes()?;
            CborValue::Bytes(b.to_vec())
        } else if datatype == minicbor::data::Type::String {
            // Text string
            let s = dec.str()?;
            CborValue::Text(s.to_string())
        } else if datatype == minicbor::data::Type::Map {
            // Nested map
            let nested_map = decode_map_direct(dec)?;
            CborValue::Map(nested_map)
        } else if datatype == minicbor::data::Type::Array {
            // Array
            let array = decode_array(dec)?;
            CborValue::Array(array)
        } else if datatype == minicbor::data::Type::Null {
            // Null value
            dec.null()?;
            CborValue::Null
        } else {
            // Unsupported type
            return Err(Error::InvalidFormat(format!(
                "Unsupported CBOR type: {datatype:?}"
            )));
        };

        map.insert(key, value);
    }

    Ok(map)
}
