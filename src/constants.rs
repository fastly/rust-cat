//! # Constants for Common Access Token
//!
//! This module provides centralized constants used throughout the Common Access Token library.
//! It includes constants for CAT-specific claim keys, URI components, match types, and more.

/// CAT-specific claim keys
pub mod cat_keys {
    /// Common Access Token Replay (catreplay) claim key
    pub const CATREPLAY: i32 = 308;
    /// Common Access Token Probability of Rejection (catpor) claim key
    pub const CATPOR: i32 = 309;
    /// Common Access Token Version (catv) claim key
    pub const CATV: i32 = 310;
    /// Common Access Token Network IP (catnip) claim key
    pub const CATNIP: i32 = 311;
    /// Common Access Token URI (catu) claim key
    pub const CATU: i32 = 312;
    /// Common Access Token Methods (catm) claim key
    pub const CATM: i32 = 313;
    /// Common Access Token ALPN (catalpn) claim key
    pub const CATALPN: i32 = 314;
    /// Common Access Token Header (cath) claim key
    pub const CATH: i32 = 315;
    /// Common Access Token Geographic ISO3166 (catgeoiso3166) claim key
    pub const CATGEOISO3166: i32 = 316;
    /// Common Access Token Geographic Coordinate (catgeocoord) claim key
    pub const CATGEOCOORD: i32 = 317;
    /// Common Access Token Altitude (catgeoalt) claim key
    pub const CATGEOALT: i32 = 318;
    /// Common Access Token TLS Public Key (cattpk) claim key
    pub const CATTPK: i32 = 319;
    /// Common Access Token If Data (catifdata) claim key
    pub const CATIFDATA: i32 = 320;
    /// Common Access Token DPoP Settings (catdpop) claim key
    pub const CATDPOP: i32 = 321;
    /// Common Access Token If (catif) claim key
    pub const CATIF: i32 = 322;
    /// Common Access Token Renewal (catr) claim key
    pub const CATR: i32 = 323;
    /// Common Access Token TLS Fingerprint (cattprint) claim key
    pub const CATTPRINT: i32 = 324;
}

/// URI component identifiers for CATU claim
pub mod uri_components {
    /// Scheme (RFC 3986 Section 3.1)
    pub const SCHEME: i32 = 0;
    /// Host (RFC 3986 Section 3.2.2)
    pub const HOST: i32 = 1;
    /// Port (RFC 3986 Section 3.2.3)
    pub const PORT: i32 = 2;
    /// Path (RFC 3986 Section 3.3)
    pub const PATH: i32 = 3;
    /// Query (RFC 3986 Section 3.4)
    pub const QUERY: i32 = 4;
    /// Parent path
    pub const PARENT_PATH: i32 = 5;
    /// Filename
    pub const FILENAME: i32 = 6;
    /// Stem
    pub const STEM: i32 = 7;
    /// Extension
    pub const EXTENSION: i32 = 8;
}

/// Match types for CATU claim
pub mod match_types {
    /// Exact text match
    pub const EXACT: i32 = 0;
    /// Prefix match
    pub const PREFIX: i32 = 1;
    /// Suffix match
    pub const SUFFIX: i32 = 2;
    /// Contains match
    pub const CONTAINS: i32 = 3;
    /// Regular expression match
    pub const REGEX: i32 = 4;
    /// SHA-256 match
    pub const SHA256: i32 = -1;
    /// SHA-512/256 match
    pub const SHA512_256: i32 = -2;
}

/// Renewal types for CATR claim
pub mod renewal_types {
    /// Automatic renewal
    pub const AUTOMATIC: i32 = 0;
    /// Cookie renewal
    pub const COOKIE: i32 = 1;
    /// Header renewal
    pub const HEADER: i32 = 2;
    /// Redirect renewal
    pub const REDIRECT: i32 = 3;
}

/// Renewal parameter labels for CATR claim
pub mod renewal_params {
    /// Renewal type
    pub const TYPE: i32 = 0;
    /// Expiration extension
    pub const EXPADD: i32 = 1;
    /// Renewal deadline
    pub const DEADLINE: i32 = 2;
    /// Name for cookie
    pub const COOKIE_NAME: i32 = 3;
    /// Name for header
    pub const HEADER_NAME: i32 = 4;
    /// Additional cookie parameters
    pub const COOKIE_PARAMS: i32 = 5;
    /// Additional header parameters
    pub const HEADER_PARAMS: i32 = 6;
    /// Status code for redirects
    pub const STATUS_CODE: i32 = 7;
}

/// CATREPLAY values
pub mod replay_values {
    /// Replay is permitted
    pub const PERMITTED: i32 = 0;
    /// Replay is prohibited
    pub const PROHIBITED: i32 = 1;
    /// Reuse-detection
    pub const REUSE_DETECTION: i32 = 2;
}

// Parameter labels for CATTPRINT claim
pub mod tprint_params {
    /// TLS Fingerprint Type
    pub const FINGERPRINT_TYPE: i32 = 0;
    /// TLS Fingerprint Value
    pub const FINGERPRINT_VALUE: i32 = 1;
}

// Values for Fingerprint Types for CATTPRINT claims
// Possible fingerprint-type values: JA3, JA4, JA4S, JA4H, JA4L, JA4X, JA4SSH, JA4T, JA4TS, JA4TScan
pub mod tprint_type_values {
    // JA3
    pub const JA3: &str = "JA3";
    // JA4
    pub const JA4: &str = "JA4";
    // JA4S
    pub const JA4S: &str = "JA4S";
    // JA4H
    pub const JA4H: &str = "JA4H";
    // JA4L
    pub const JA4L: &str = "JA4L";
    // JA4X
    pub const JA4X: &str = "JA4X";
    // JA4SSH
    pub const JA4SSH: &str = "JA4SSH";
    // JA4T
    pub const JA4T: &str = "JA4T";
    // JA4TS
    pub const JA4TS: &str = "JA4TS";
    // JA4TScan
    pub const JA4TSCAN: &str = "JA4TScan";
}

/// CWT claim keys as defined in RFC 8392
pub mod cwt_keys {
    /// Issuer claim key
    pub const ISS: i32 = 1;
    /// Subject claim key
    pub const SUB: i32 = 2;
    /// Audience claim key
    pub const AUD: i32 = 3;
    /// Expiration time claim key
    pub const EXP: i32 = 4;
    /// Not before claim key
    pub const NBF: i32 = 5;
    /// Issued at claim key
    pub const IAT: i32 = 6;
    /// CWT ID claim key
    pub const CTI: i32 = 7;
}

/// COSE header parameter labels
pub mod cose_labels {
    /// Algorithm (used in protected header)
    pub const ALG: i32 = 1;
    /// Key identifier (used in protected or unprotected header)
    pub const KID: i32 = 4;
}

/// COSE algorithm identifiers
pub mod cose_algs {
    /// HMAC with SHA-256 (COSE algorithm identifier: 5)
    pub const HMAC_SHA_256: i32 = 5;
}
