//! # CAT-specific Claims
//!
//! This module provides helper functions and structures for working with
//! Common Access Token (CAT) specific claims as defined in the CAT specification.
//!
//! ## Available CAT Claims
//!
//! - **CATU** (Common Access Token URI) - limits the URI to which the token can provide access
//! - **CATR** (Common Access Token Renewal) - instructions for token renewal
//! - **CATM** (Common Access Token Methods) - limits HTTP methods
//! - **CATREPLAY** - controls token replay behavior
//! - **CATV** (Common Access Token Version) - CAT specification version
//! - **CATPOR** (Common Access Token Probability of Rejection) - probabilistic rate limiting
//! - **CATNIP** (Common Access Token Network IP) - IP address restrictions
//! - **CATALPN** (Common Access Token ALPN) - TLS ALPN protocol restrictions
//! - **CATH** (Common Access Token Header) - HTTP header requirements
//! - **CATGEOISO3166** - geographic country/region restrictions
//! - **CATGEOCOORD** - geographic coordinate restrictions
//! - **CATGEOALT** - altitude restrictions
//! - **CATTPK** (Common Access Token TLS Public Key) - TLS public key pinning
//! - **CATDPOP** (Common Access Token DPoP Settings) - DPoP configuration
//! - **CATIF** (Common Access Token If) - conditional logic
//! - **CATIFDATA** (Common Access Token If Data) - data for conditional evaluation
//! - **CATTPRINT** (Common Access Token TLS Fingerprint) - TLS fingerprint restrictions
//!
//! ## CATU Claim (URI Validation)
//!
//! The CATU claim allows you to specify URI component restrictions. For example:
//!
//! ```rust
//! use common_access_token::{catu, uri_components, cat_keys};
//! use std::collections::BTreeMap;
//!
//! // Create a CATU claim for URI validation
//! let mut catu_components = BTreeMap::new();
//!
//! // Restrict to https scheme
//! catu_components.insert(uri_components::SCHEME, catu::exact_match("https"));
//!
//! // Restrict to example.com host
//! catu_components.insert(uri_components::HOST, catu::suffix_match(".example.com"));
//!
//! // Restrict to paths starting with /api
//! catu_components.insert(uri_components::PATH, catu::prefix_match("/api"));
//!
//! // Create the CATU claim
//! let catu_claim = catu::create(catu_components);
//! ```
//!
//! ## CATM Claim (HTTP Methods)
//!
//! The CATM claim restricts which HTTP methods are allowed:
//!
//! ```rust
//! use common_access_token::{catm, cat_keys};
//!
//! // Create a CATM claim allowing only GET and HEAD methods
//! let allowed_methods = vec!["GET", "HEAD"];
//! let catm_claim = catm::create(allowed_methods);
//! ```
//!
//! ## CATREPLAY Claim (Replay Protection)
//!
//! The CATREPLAY claim controls token replay behavior:
//!
//! ```rust
//! use common_access_token::{catreplay, cat_keys};
//!
//! // Create a CATREPLAY claim that prohibits token reuse
//! let catreplay_claim = catreplay::prohibited();
//!
//! // Or allow token reuse
//! let catreplay_permitted = catreplay::permitted();
//!
//! // Or enable reuse detection
//! let catreplay_detect = catreplay::reuse_detection();
//! ```
//!
//! ## CATR Claim (Token Renewal)
//!
//! The CATR claim provides instructions for token renewal:
//!
//! ```rust
//! use common_access_token::{catr, cat_keys};
//! use common_access_token::current_timestamp;
//!
//! let now = current_timestamp();
//!
//! // Create an automatic renewal claim
//! // This extends expiration by 3600 seconds with a deadline 3000 seconds from now
//! let renewal_params = catr::automatic_renewal(3600, Some((now + 3000) as i64));
//! let catr_claim = catr::create(renewal_params);
//!
//! // Or create a cookie-based renewal claim
//! let cookie_renewal = catr::cookie_renewal(
//!     3600,
//!     Some((now + 3000) as i64),
//!     Some("session"),
//!     Some(vec!["Secure", "HttpOnly"])
//! );
//! ```
//!
//! ## CATTPRINT Claim (TLS Fingerprint)
//!
//! The CATTPRINT claim provides instructions for validating a TLS Fingerprint:
//!
//! ```rust
//! use common_access_token::{cattprint, tprint_type_values};
//!
//! // Create a tls fingerprint claim
//! // Possible fingerprint-type values: JA3, JA4, JA4S, JA4H, JA4L, JA4X, JA4SSH, JA4T, JA4TS, JA4TScan
//! // Example JA4 value: t13d1516h2_8daaf6152771_b186095e22b6
//! let cattprint_claim = cattprint::create(tprint_type_values::JA4, "t13d1516h2_8daaf6152771_b186095e22b6");
//! ```

use crate::header::CborValue;
use std::collections::BTreeMap;

/// CAT-specific claim keys
pub mod keys {
    use crate::constants::cat_keys;

    /// Common Access Token Replay (catreplay) claim key
    pub const CATREPLAY: i32 = cat_keys::CATREPLAY;
    /// Common Access Token Probability of Rejection (catpor) claim key
    pub const CATPOR: i32 = cat_keys::CATPOR;
    /// Common Access Token Version (catv) claim key
    pub const CATV: i32 = cat_keys::CATV;
    /// Common Access Token Network IP (catnip) claim key
    pub const CATNIP: i32 = cat_keys::CATNIP;
    /// Common Access Token URI (catu) claim key
    pub const CATU: i32 = cat_keys::CATU;
    /// Common Access Token Methods (catm) claim key
    pub const CATM: i32 = cat_keys::CATM;
    /// Common Access Token ALPN (catalpn) claim key
    pub const CATALPN: i32 = cat_keys::CATALPN;
    /// Common Access Token Header (cath) claim key
    pub const CATH: i32 = cat_keys::CATH;
    /// Common Access Token Geographic ISO3166 (catgeoiso3166) claim key
    pub const CATGEOISO3166: i32 = cat_keys::CATGEOISO3166;
    /// Common Access Token Geographic Coordinate (catgeocoord) claim key
    pub const CATGEOCOORD: i32 = cat_keys::CATGEOCOORD;
    /// Common Access Token Altitude (catgeoalt) claim key
    pub const CATGEOALT: i32 = cat_keys::CATGEOALT;
    /// Common Access Token TLS Public Key (cattpk) claim key
    pub const CATTPK: i32 = cat_keys::CATTPK;
    /// Common Access Token If Data (catifdata) claim key
    pub const CATIFDATA: i32 = cat_keys::CATIFDATA;
    /// Common Access Token DPoP Settings (catdpop) claim key
    pub const CATDPOP: i32 = cat_keys::CATDPOP;
    /// Common Access Token If (catif) claim key
    pub const CATIF: i32 = cat_keys::CATIF;
    /// Common Access Token Renewal (catr) claim key
    pub const CATR: i32 = cat_keys::CATR;
    /// Common Access Token TLS Fingerprint (cattprint) claim key
    pub const CATTPRINT: i32 = cat_keys::CATTPRINT;
}

/// Helper functions for creating CATTPRINT (Common Access Token TLS Fingerprint) claims
pub mod cattprint {
    use super::*;
    use crate::constants::{tprint_params};

    pub fn create(fingerprint_type: &str, fingerprint_value: &str) -> CborValue {
        let mut params = BTreeMap::new();
        params.insert(tprint_params::FINGERPRINT_TYPE, CborValue::Text(fingerprint_type.to_string()));
        params.insert(tprint_params::FINGERPRINT_VALUE, CborValue::Text(fingerprint_value.to_string()));
        CborValue::Map(params)
    }
}


/// Helper functions for creating CATU (Common Access Token URI) claims
pub mod catu {
    use super::*;
    use crate::constants::match_types;

    /// Creates a CATU claim with the specified URI component restrictions
    pub fn create(components: BTreeMap<i32, BTreeMap<i32, CborValue>>) -> CborValue {
        let mut map = BTreeMap::new();
        for (component_key, match_map) in components {
            let mut inner_map = BTreeMap::new();
            for (match_type, match_value) in match_map {
                inner_map.insert(match_type, match_value);
            }
            map.insert(component_key, CborValue::Map(inner_map));
        }
        CborValue::Map(map)
    }

    /// Creates a match condition for exact text matching
    pub fn exact_match(text: &str) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(match_types::EXACT, CborValue::Text(text.to_string()));
        map
    }

    /// Creates a match condition for prefix matching
    pub fn prefix_match(prefix: &str) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(match_types::PREFIX, CborValue::Text(prefix.to_string()));
        map
    }

    /// Creates a match condition for suffix matching
    pub fn suffix_match(suffix: &str) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(match_types::SUFFIX, CborValue::Text(suffix.to_string()));
        map
    }

    /// Creates a match condition for contains matching
    pub fn contains_match(text: &str) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(match_types::CONTAINS, CborValue::Text(text.to_string()));
        map
    }

    /// Creates a match condition for regex matching
    pub fn regex_match(pattern: &str, groups: Vec<Option<String>>) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();

        let mut array = vec![CborValue::Text(pattern.to_string())];
        for group in groups {
            match group {
                Some(text) => array.push(CborValue::Text(text)),
                None => array.push(CborValue::Null),
            }
        }

        map.insert(match_types::REGEX, CborValue::Array(array));
        map
    }

    /// Creates a match condition for SHA-256 matching
    pub fn sha256_match(hash: Vec<u8>) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(match_types::SHA256, CborValue::Bytes(hash));
        map
    }

    /// Creates a match condition for SHA-512/256 matching
    pub fn sha512_256_match(hash: Vec<u8>) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(match_types::SHA512_256, CborValue::Bytes(hash));
        map
    }
}

/// Helper functions for creating CATR (Common Access Token Renewal) claims
pub mod catr {
    use super::*;
    use crate::constants::{renewal_params, renewal_types};

    /// Creates a CATR claim with the specified renewal parameters
    pub fn create(params: BTreeMap<i32, CborValue>) -> CborValue {
        CborValue::Map(params)
    }

    /// Creates an automatic renewal claim
    pub fn automatic_renewal(exp_add: i64, deadline: Option<i64>) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(
            renewal_params::TYPE,
            CborValue::Integer(renewal_types::AUTOMATIC as i64),
        );
        map.insert(renewal_params::EXPADD, CborValue::Integer(exp_add));

        if let Some(deadline_value) = deadline {
            map.insert(renewal_params::DEADLINE, CborValue::Integer(deadline_value));
        }

        map
    }

    /// Creates a cookie renewal claim
    pub fn cookie_renewal(
        exp_add: i64,
        deadline: Option<i64>,
        cookie_name: Option<&str>,
        additional_params: Option<Vec<&str>>,
    ) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(
            renewal_params::TYPE,
            CborValue::Integer(renewal_types::COOKIE as i64),
        );
        map.insert(renewal_params::EXPADD, CborValue::Integer(exp_add));

        if let Some(deadline_value) = deadline {
            map.insert(renewal_params::DEADLINE, CborValue::Integer(deadline_value));
        }

        if let Some(name) = cookie_name {
            map.insert(
                renewal_params::COOKIE_NAME,
                CborValue::Text(name.to_string()),
            );
        }

        if let Some(params) = additional_params {
            let params_array: Vec<CborValue> = params
                .into_iter()
                .map(|s| CborValue::Text(s.to_string()))
                .collect();
            map.insert(
                renewal_params::COOKIE_PARAMS,
                CborValue::Array(params_array),
            );
        }

        map
    }

    /// Creates a header renewal claim
    pub fn header_renewal(
        exp_add: i64,
        deadline: Option<i64>,
        header_name: Option<&str>,
        additional_params: Option<Vec<&str>>,
    ) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(
            renewal_params::TYPE,
            CborValue::Integer(renewal_types::HEADER as i64),
        );
        map.insert(renewal_params::EXPADD, CborValue::Integer(exp_add));

        if let Some(deadline_value) = deadline {
            map.insert(renewal_params::DEADLINE, CborValue::Integer(deadline_value));
        }

        if let Some(name) = header_name {
            map.insert(
                renewal_params::HEADER_NAME,
                CborValue::Text(name.to_string()),
            );
        }

        if let Some(params) = additional_params {
            let params_array: Vec<CborValue> = params
                .into_iter()
                .map(|s| CborValue::Text(s.to_string()))
                .collect();
            map.insert(
                renewal_params::HEADER_PARAMS,
                CborValue::Array(params_array),
            );
        }

        map
    }

    /// Creates a redirect renewal claim
    pub fn redirect_renewal(
        exp_add: i64,
        deadline: Option<i64>,
        status_code: Option<i64>,
    ) -> BTreeMap<i32, CborValue> {
        let mut map = BTreeMap::new();
        map.insert(
            renewal_params::TYPE,
            CborValue::Integer(renewal_types::REDIRECT as i64),
        );
        map.insert(renewal_params::EXPADD, CborValue::Integer(exp_add));

        if let Some(deadline_value) = deadline {
            map.insert(renewal_params::DEADLINE, CborValue::Integer(deadline_value));
        }

        if let Some(code) = status_code {
            map.insert(renewal_params::STATUS_CODE, CborValue::Integer(code));
        }

        map
    }
}

/// Helper functions for creating CATM (Common Access Token Methods) claims
pub mod catm {
    use super::*;

    /// Creates a CATM claim with the specified HTTP methods
    pub fn create(methods: Vec<&str>) -> Vec<CborValue> {
        methods
            .into_iter()
            .map(|s| CborValue::Text(s.to_string()))
            .collect()
    }
}

/// Helper functions for creating CATREPLAY claims
pub mod catreplay {
    use super::*;
    use crate::constants::replay_values;

    /// Creates a CATREPLAY claim with the specified value
    pub fn create(value: i32) -> CborValue {
        CborValue::Integer(value as i64)
    }

    /// Creates a CATREPLAY claim with "permitted" value
    pub fn permitted() -> CborValue {
        CborValue::Integer(replay_values::PERMITTED as i64)
    }

    /// Creates a CATREPLAY claim with "prohibited" value
    pub fn prohibited() -> CborValue {
        CborValue::Integer(replay_values::PROHIBITED as i64)
    }

    /// Creates a CATREPLAY claim with "reuse detection" value
    pub fn reuse_detection() -> CborValue {
        CborValue::Integer(replay_values::REUSE_DETECTION as i64)
    }
}

/// Helper functions for creating CATV (Common Access Token Version) claims
pub mod catv {
    use super::*;

    /// Creates a CATV claim with version 1
    pub fn create() -> CborValue {
        CborValue::Integer(1)
    }

    /// Creates a CATV claim with a specific version number
    pub fn with_version(version: i64) -> CborValue {
        CborValue::Integer(version)
    }
}

/// Helper functions for creating CATPOR (Common Access Token Probability of Rejection) claims
///
/// CATPOR specifies the probability that a token might be rejected, used for probabilistic
/// rate limiting or load shedding.
pub mod catpor {
    use super::*;

    /// Creates a CATPOR claim with a probability value (0.0 to 1.0)
    ///
    /// The probability is encoded as an integer representing the percentage (0-100).
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::cat_claims::catpor;
    ///
    /// // 25% probability of rejection
    /// let catpor_claim = catpor::create(25);
    /// ```
    pub fn create(probability_percent: i64) -> CborValue {
        CborValue::Integer(probability_percent)
    }
}

/// Helper functions for creating CATNIP (Common Access Token Network IP) claims
///
/// CATNIP restricts the IP addresses from which the token can be used.
pub mod catnip {
    use super::*;

    /// Creates a CATNIP claim with a list of allowed IP addresses or ranges
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::cat_claims::catnip;
    ///
    /// // Allow specific IP addresses
    /// let catnip_claim = catnip::create(vec!["192.168.1.100", "10.0.0.0/8"]);
    /// ```
    pub fn create(ip_addresses: Vec<&str>) -> Vec<CborValue> {
        ip_addresses
            .into_iter()
            .map(|ip| CborValue::Text(ip.to_string()))
            .collect()
    }

    /// Creates a CATNIP claim with a single IP address
    pub fn single(ip_address: &str) -> Vec<CborValue> {
        vec![CborValue::Text(ip_address.to_string())]
    }
}

/// Helper functions for creating CATALPN (Common Access Token ALPN) claims
///
/// CATALPN restricts the TLS Application-Layer Protocol Negotiation values.
pub mod catalpn {
    use super::*;

    /// Creates a CATALPN claim with a list of allowed ALPN protocols
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::cat_claims::catalpn;
    ///
    /// // Allow HTTP/2 and HTTP/1.1
    /// let catalpn_claim = catalpn::create(vec!["h2", "http/1.1"]);
    /// ```
    pub fn create(protocols: Vec<&str>) -> Vec<CborValue> {
        protocols
            .into_iter()
            .map(|proto| CborValue::Text(proto.to_string()))
            .collect()
    }

    /// Creates a CATALPN claim for HTTP/2 only
    pub fn http2_only() -> Vec<CborValue> {
        vec![CborValue::Text("h2".to_string())]
    }

    /// Creates a CATALPN claim for HTTP/1.1 only
    pub fn http1_only() -> Vec<CborValue> {
        vec![CborValue::Text("http/1.1".to_string())]
    }
}

/// Helper functions for creating CATH (Common Access Token Header) claims
///
/// CATH specifies HTTP header requirements or restrictions.
pub mod cath {
    use super::*;

    /// Creates a CATH claim with header name-value pairs
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::cat_claims::cath;
    /// use std::collections::BTreeMap;
    ///
    /// let mut headers = BTreeMap::new();
    /// headers.insert("X-Custom-Header", "required-value");
    /// headers.insert("User-Agent", "MyApp/1.0");
    /// let cath_claim = cath::create(headers);
    /// ```
    pub fn create(headers: BTreeMap<&str, &str>) -> CborValue {
        let mut map = BTreeMap::new();
        for (i, (key, value)) in headers.iter().enumerate() {
            let mut header_map = BTreeMap::new();
            header_map.insert(0, CborValue::Text(key.to_string()));
            header_map.insert(1, CborValue::Text(value.to_string()));
            map.insert(i as i32, CborValue::Map(header_map));
        }
        CborValue::Map(map)
    }
}

/// Helper functions for creating CATGEOISO3166 (Common Access Token Geographic ISO3166) claims
///
/// CATGEOISO3166 restricts token usage to specific countries or regions.
pub mod catgeoiso3166 {
    use super::*;

    /// Creates a CATGEOISO3166 claim with ISO 3166 country codes
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::cat_claims::catgeoiso3166;
    ///
    /// // Allow usage in US and Canada
    /// let catgeoiso3166_claim = catgeoiso3166::create(vec!["US", "CA"]);
    /// ```
    pub fn create(country_codes: Vec<&str>) -> Vec<CborValue> {
        country_codes
            .into_iter()
            .map(|code| CborValue::Text(code.to_string()))
            .collect()
    }
}

/// Helper functions for creating CATGEOCOORD (Common Access Token Geographic Coordinate) claims
///
/// CATGEOCOORD restricts token usage based on geographic coordinates.
pub mod catgeocoord {
    use super::*;

    /// Creates a CATGEOCOORD claim with latitude and longitude
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::cat_claims::catgeocoord;
    ///
    /// // Center of New York City
    /// let catgeocoord_claim = catgeocoord::create(40.7128, -74.0060);
    /// ```
    pub fn create(latitude: f64, longitude: f64) -> CborValue {
        let mut map = BTreeMap::new();
        // Using i64 representation of coordinates (multiply by 1e7 for precision)
        map.insert(0, CborValue::Integer((latitude * 10_000_000.0) as i64));
        map.insert(1, CborValue::Integer((longitude * 10_000_000.0) as i64));
        CborValue::Map(map)
    }

    /// Creates a CATGEOCOORD claim with latitude, longitude, and radius in meters
    pub fn with_radius(latitude: f64, longitude: f64, radius_meters: i64) -> CborValue {
        let mut map = BTreeMap::new();
        map.insert(0, CborValue::Integer((latitude * 10_000_000.0) as i64));
        map.insert(1, CborValue::Integer((longitude * 10_000_000.0) as i64));
        map.insert(2, CborValue::Integer(radius_meters));
        CborValue::Map(map)
    }
}

/// Helper functions for creating CATGEOALT (Common Access Token Geographic Altitude) claims
///
/// CATGEOALT restricts token usage based on altitude.
pub mod catgeoalt {
    use super::*;

    /// Creates a CATGEOALT claim with altitude in meters
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::cat_claims::catgeoalt;
    ///
    /// // Sea level
    /// let catgeoalt_claim = catgeoalt::create(0);
    /// ```
    pub fn create(altitude_meters: i64) -> CborValue {
        CborValue::Integer(altitude_meters)
    }

    /// Creates a CATGEOALT claim with altitude range (min and max in meters)
    pub fn range(min_meters: i64, max_meters: i64) -> CborValue {
        let mut map = BTreeMap::new();
        map.insert(0, CborValue::Integer(min_meters));
        map.insert(1, CborValue::Integer(max_meters));
        CborValue::Map(map)
    }
}

/// Helper functions for creating CATTPK (Common Access Token TLS Public Key) claims
///
/// CATTPK pins the token to a specific TLS public key or certificate.
pub mod cattpk {
    use super::*;

    /// Creates a CATTPK claim with a public key hash
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::cat_claims::cattpk;
    ///
    /// // SHA-256 hash of the public key
    /// let key_hash = vec![0x01, 0x02, 0x03]; // truncated for example
    /// let cattpk_claim = cattpk::create(key_hash);
    /// ```
    pub fn create(public_key_hash: Vec<u8>) -> CborValue {
        CborValue::Bytes(public_key_hash)
    }

    /// Creates a CATTPK claim with multiple public key hashes
    pub fn multiple(public_key_hashes: Vec<Vec<u8>>) -> Vec<CborValue> {
        public_key_hashes
            .into_iter()
            .map(CborValue::Bytes)
            .collect()
    }
}

/// Helper functions for creating CATDPOP (Common Access Token DPoP Settings) claims
///
/// CATDPOP provides settings for Demonstrating Proof-of-Possession.
pub mod catdpop {
    use super::*;

    /// Creates a CATDPOP claim with DPoP configuration
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::cat_claims::catdpop;
    /// use std::collections::BTreeMap;
    ///
    /// let mut dpop_config = BTreeMap::new();
    /// dpop_config.insert(0, common_access_token::CborValue::Integer(1)); // version
    /// dpop_config.insert(1, common_access_token::CborValue::Text("RS256".to_string())); // algorithm
    /// let catdpop_claim = catdpop::create(dpop_config);
    /// ```
    pub fn create(config: BTreeMap<i32, CborValue>) -> CborValue {
        CborValue::Map(config)
    }

    /// Creates a basic CATDPOP claim requiring DPoP
    pub fn required() -> CborValue {
        let mut map = BTreeMap::new();
        map.insert(0, CborValue::Integer(1)); // required
        CborValue::Map(map)
    }
}

/// Helper functions for creating CATIF (Common Access Token If) claims
///
/// CATIF provides conditional logic for token handling.
pub mod catif {
    use super::*;

    /// Creates a CATIF claim with conditional expressions
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::cat_claims::catif;
    /// use std::collections::BTreeMap;
    ///
    /// let mut condition = BTreeMap::new();
    /// condition.insert(0, common_access_token::CborValue::Text("status".to_string()));
    /// condition.insert(1, common_access_token::CborValue::Text("eq".to_string()));
    /// condition.insert(2, common_access_token::CborValue::Integer(200));
    /// let catif_claim = catif::create(condition);
    /// ```
    pub fn create(condition: BTreeMap<i32, CborValue>) -> CborValue {
        CborValue::Map(condition)
    }
}

/// Helper functions for creating CATIFDATA (Common Access Token If Data) claims
///
/// CATIFDATA provides data for conditional evaluation in CATIF.
pub mod catifdata {
    use super::*;

    /// Creates a CATIFDATA claim with data values
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::cat_claims::catifdata;
    /// use std::collections::BTreeMap;
    ///
    /// let mut data = BTreeMap::new();
    /// data.insert(0, common_access_token::CborValue::Text("user_role".to_string()));
    /// data.insert(1, common_access_token::CborValue::Text("admin".to_string()));
    /// let catifdata_claim = catifdata::create(data);
    /// ```
    pub fn create(data: BTreeMap<i32, CborValue>) -> CborValue {
        CborValue::Map(data)
    }
}
