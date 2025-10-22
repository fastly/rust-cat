//! # Claims for Common Access Token
//!
//! This module provides the claims structure and related types for Common Access Tokens.
//!
//! Claims in Common Access Tokens are divided into two categories:
//!
//! - **Registered Claims**: Standard claims defined in RFC 8392, such as issuer, subject, audience, and expiration time.
//! - **Custom Claims**: Application-specific claims that can contain any CBOR-encodable value.
//!
//! Claims are used to convey information about the token subject and context, and can be used for
//! authorization decisions by the token verifier.

use crate::header::CborValue;
use std::collections::BTreeMap;

/// CWT claim keys as defined in RFC 8392
pub mod keys {
    use crate::constants::cwt_keys;

    /// Issuer claim key
    pub const ISS: i32 = cwt_keys::ISS;
    /// Subject claim key
    pub const SUB: i32 = cwt_keys::SUB;
    /// Audience claim key
    pub const AUD: i32 = cwt_keys::AUD;
    /// Expiration time claim key
    pub const EXP: i32 = cwt_keys::EXP;
    /// Not before claim key
    pub const NBF: i32 = cwt_keys::NBF;
    /// Issued at claim key
    pub const IAT: i32 = cwt_keys::IAT;
    /// CWT ID claim key
    pub const CTI: i32 = cwt_keys::CTI;
}

/// Type alias for claims map
pub type ClaimsMap = BTreeMap<i32, CborValue>;

/// Standard registered claims as defined in RFC 8392.
///
/// These claims are standardized and have well-defined meanings:
///
/// - **iss** (Issuer): Identifies the principal that issued the token.
/// - **sub** (Subject): Identifies the principal that is the subject of the token.
/// - **aud** (Audience): Identifies the recipients that the token is intended for.
/// - **exp** (Expiration Time): Identifies the expiration time on or after which the token MUST NOT be accepted.
/// - **nbf** (Not Before): Identifies the time before which the token MUST NOT be accepted.
/// - **iat** (Issued At): Identifies the time at which the token was issued.
/// - **cti** (CWT ID): Provides a unique identifier for the token.
///
/// # Example
///
/// ```
/// use common_access_token::RegisteredClaims;
/// use common_access_token::current_timestamp;
///
/// let now = current_timestamp();
/// let claims = RegisteredClaims::new()
///     .with_issuer("example-issuer")
///     .with_subject("user-123")
///     .with_audience("example-service")
///     .with_expiration(now + 3600) // 1 hour from now
///     .with_not_before(now)
///     .with_issued_at(now);
///
/// assert_eq!(claims.iss, Some("example-issuer".to_string()));
/// assert_eq!(claims.sub, Some("user-123".to_string()));
/// assert_eq!(claims.exp.unwrap(), now + 3600);
/// ```
#[derive(Debug, Clone, Default)]
pub struct RegisteredClaims {
    /// Issuer - identifies the principal that issued the token
    pub iss: Option<String>,
    /// Subject - identifies the principal that is the subject of the token
    pub sub: Option<String>,
    /// Audience - identifies the recipients that the token is intended for
    pub aud: Option<String>,
    /// Expiration time (seconds since Unix epoch) - token must not be accepted after this time
    pub exp: Option<u64>,
    /// Not before (seconds since Unix epoch) - token must not be accepted before this time
    pub nbf: Option<u64>,
    /// Issued at (seconds since Unix epoch) - when the token was issued
    pub iat: Option<u64>,
    /// CWT ID - unique identifier for the token
    pub cti: Option<Vec<u8>>,
}

impl RegisteredClaims {
    /// Creates a new empty set of registered claims.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::RegisteredClaims;
    ///
    /// let claims = RegisteredClaims::new();
    /// assert!(claims.iss.is_none());
    /// assert!(claims.sub.is_none());
    /// assert!(claims.exp.is_none());
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the issuer claim.
    ///
    /// The issuer claim identifies the principal that issued the token.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::RegisteredClaims;
    ///
    /// let claims = RegisteredClaims::new().with_issuer("https://auth.example.com");
    /// assert_eq!(claims.iss, Some("https://auth.example.com".to_string()));
    /// ```
    pub fn with_issuer<S: Into<String>>(mut self, iss: S) -> Self {
        self.iss = Some(iss.into());
        self
    }

    /// Sets the subject claim.
    ///
    /// The subject claim identifies the principal that is the subject of the token.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::RegisteredClaims;
    ///
    /// let claims = RegisteredClaims::new().with_subject("user-123");
    /// assert_eq!(claims.sub, Some("user-123".to_string()));
    /// ```
    pub fn with_subject<S: Into<String>>(mut self, sub: S) -> Self {
        self.sub = Some(sub.into());
        self
    }

    /// Sets the audience claim.
    ///
    /// The audience claim identifies the recipients that the token is intended for.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::RegisteredClaims;
    ///
    /// let claims = RegisteredClaims::new().with_audience("https://api.example.com");
    /// assert_eq!(claims.aud, Some("https://api.example.com".to_string()));
    /// ```
    pub fn with_audience<S: Into<String>>(mut self, aud: S) -> Self {
        self.aud = Some(aud.into());
        self
    }

    /// Sets the expiration time claim.
    ///
    /// The expiration time claim identifies the time on or after which the token
    /// MUST NOT be accepted for processing. The value is a Unix timestamp (seconds
    /// since the Unix epoch).
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::RegisteredClaims;
    /// use common_access_token::current_timestamp;
    ///
    /// let now = current_timestamp();
    /// let claims = RegisteredClaims::new().with_expiration(now + 3600); // 1 hour from now
    /// assert_eq!(claims.exp, Some(now + 3600));
    /// ```
    pub fn with_expiration(mut self, exp: u64) -> Self {
        self.exp = Some(exp);
        self
    }

    /// Sets the not before claim.
    ///
    /// The not before claim identifies the time before which the token
    /// MUST NOT be accepted for processing. The value is a Unix timestamp (seconds
    /// since the Unix epoch).
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::RegisteredClaims;
    /// use common_access_token::current_timestamp;
    ///
    /// let now = current_timestamp();
    /// let claims = RegisteredClaims::new().with_not_before(now); // Valid from now
    /// assert_eq!(claims.nbf, Some(now));
    /// ```
    pub fn with_not_before(mut self, nbf: u64) -> Self {
        self.nbf = Some(nbf);
        self
    }

    /// Sets the issued at claim.
    ///
    /// The issued at claim identifies the time at which the token was issued.
    /// The value is a Unix timestamp (seconds since the Unix epoch).
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::RegisteredClaims;
    /// use common_access_token::current_timestamp;
    ///
    /// let now = current_timestamp();
    /// let claims = RegisteredClaims::new().with_issued_at(now);
    /// assert_eq!(claims.iat, Some(now));
    /// ```
    pub fn with_issued_at(mut self, iat: u64) -> Self {
        self.iat = Some(iat);
        self
    }

    /// Sets the CWT ID claim.
    ///
    /// The CWT ID claim provides a unique identifier for the token.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::RegisteredClaims;
    ///
    /// let id = vec![1, 2, 3, 4];
    /// let claims = RegisteredClaims::new().with_cti(id.clone());
    /// assert_eq!(claims.cti, Some(id));
    /// ```
    pub fn with_cti<T: Into<Vec<u8>>>(mut self, cti: T) -> Self {
        self.cti = Some(cti.into());
        self
    }

    /// Set token lifetime with issued-at, not-before, and expiration claims
    ///
    /// This is a convenience method that sets all three time-related claims:
    /// - `iat` (issued at) is set to the current time
    /// - `nbf` (not before) is set to the current time
    /// - `exp` (expiration) is set to current time plus the specified seconds
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{RegisteredClaims, current_timestamp};
    ///
    /// // Token valid for 1 hour
    /// let claims = RegisteredClaims::new().with_lifetime_secs(3600);
    ///
    /// let now = current_timestamp();
    /// assert_eq!(claims.iat, Some(now));
    /// assert_eq!(claims.nbf, Some(now));
    /// assert_eq!(claims.exp, Some(now + 3600));
    /// ```
    pub fn with_lifetime_secs(mut self, seconds: u64) -> Self {
        let now = crate::utils::current_timestamp();
        self.iat = Some(now);
        self.nbf = Some(now);
        self.exp = Some(now + seconds);
        self
    }

    /// Set token lifetime with issued-at, not-before, and expiration claims using a Duration
    ///
    /// This is a convenience method that sets all three time-related claims:
    /// - `iat` (issued at) is set to the current time
    /// - `nbf` (not before) is set to the current time
    /// - `exp` (expiration) is set to current time plus the specified duration
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{RegisteredClaims, current_timestamp};
    /// use std::time::Duration;
    ///
    /// // Token valid for 1 hour
    /// let claims = RegisteredClaims::new().with_lifetime(Duration::from_secs(3600));
    ///
    /// let now = current_timestamp();
    /// assert_eq!(claims.iat, Some(now));
    /// assert_eq!(claims.nbf, Some(now));
    /// assert_eq!(claims.exp, Some(now + 3600));
    /// ```
    pub fn with_lifetime(self, duration: std::time::Duration) -> Self {
        self.with_lifetime_secs(duration.as_secs())
    }

    /// Check if the claims have expired
    ///
    /// Returns `true` if there's an expiration claim and the current time is at or after it.
    /// Returns `false` if there's no expiration claim or it hasn't expired yet.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{RegisteredClaims, current_timestamp};
    ///
    /// let now = current_timestamp();
    /// let claims = RegisteredClaims::new().with_expiration(now + 3600);
    /// assert!(!claims.is_expired());
    ///
    /// let expired = RegisteredClaims::new().with_expiration(now - 100);
    /// assert!(expired.is_expired());
    /// ```
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.exp {
            crate::utils::current_timestamp() >= exp
        } else {
            false
        }
    }

    /// Check if the claims are valid based on the not-before claim
    ///
    /// Returns `true` if there's no nbf claim or if the current time is at or after it.
    /// Returns `false` if there's an nbf claim and the current time is before it.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{RegisteredClaims, current_timestamp};
    ///
    /// let now = current_timestamp();
    /// let claims = RegisteredClaims::new().with_not_before(now);
    /// assert!(claims.is_valid_yet());
    ///
    /// let future = RegisteredClaims::new().with_not_before(now + 3600);
    /// assert!(!future.is_valid_yet());
    /// ```
    pub fn is_valid_yet(&self) -> bool {
        if let Some(nbf) = self.nbf {
            crate::utils::current_timestamp() >= nbf
        } else {
            true
        }
    }

    /// Converts registered claims to a claims map.
    ///
    /// This method is primarily used internally for token encoding.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::RegisteredClaims;
    /// use common_access_token::header::CborValue;
    /// use common_access_token::claims::keys;
    ///
    /// let claims = RegisteredClaims::new()
    ///     .with_issuer("example-issuer")
    ///     .with_subject("user-123");
    ///
    /// let map = claims.to_map();
    /// assert!(matches!(map.get(&keys::ISS), Some(CborValue::Text(s)) if s == "example-issuer"));
    /// assert!(matches!(map.get(&keys::SUB), Some(CborValue::Text(s)) if s == "user-123"));
    /// ```
    pub fn to_map(&self) -> ClaimsMap {
        let mut map = ClaimsMap::new();

        if let Some(iss) = &self.iss {
            map.insert(keys::ISS, CborValue::Text(iss.clone()));
        }

        if let Some(sub) = &self.sub {
            map.insert(keys::SUB, CborValue::Text(sub.clone()));
        }

        if let Some(aud) = &self.aud {
            map.insert(keys::AUD, CborValue::Text(aud.clone()));
        }

        if let Some(exp) = self.exp {
            map.insert(keys::EXP, CborValue::Integer(exp as i64));
        }

        if let Some(nbf) = self.nbf {
            map.insert(keys::NBF, CborValue::Integer(nbf as i64));
        }

        if let Some(iat) = self.iat {
            map.insert(keys::IAT, CborValue::Integer(iat as i64));
        }

        if let Some(cti) = &self.cti {
            map.insert(keys::CTI, CborValue::Bytes(cti.clone()));
        }

        map
    }

    /// Extracts registered claims from a claims map.
    ///
    /// This method is primarily used internally for token decoding.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{RegisteredClaims, CborValue};
    /// use common_access_token::claims::{keys, ClaimsMap};
    ///
    /// let mut map = ClaimsMap::new();
    /// map.insert(keys::ISS, CborValue::Text("example-issuer".to_string()));
    /// map.insert(keys::SUB, CborValue::Text("user-123".to_string()));
    ///
    /// let claims = RegisteredClaims::from_map(&map);
    /// assert_eq!(claims.iss, Some("example-issuer".to_string()));
    /// assert_eq!(claims.sub, Some("user-123".to_string()));
    /// ```
    pub fn from_map(map: &ClaimsMap) -> Self {
        let mut claims = Self::new();

        if let Some(CborValue::Text(iss)) = map.get(&keys::ISS) {
            claims.iss = Some(iss.clone());
        }

        if let Some(CborValue::Text(sub)) = map.get(&keys::SUB) {
            claims.sub = Some(sub.clone());
        }

        if let Some(CborValue::Text(aud)) = map.get(&keys::AUD) {
            claims.aud = Some(aud.clone());
        }

        if let Some(CborValue::Integer(exp)) = map.get(&keys::EXP) {
            claims.exp = Some(*exp as u64);
        }

        if let Some(CborValue::Integer(nbf)) = map.get(&keys::NBF) {
            claims.nbf = Some(*nbf as u64);
        }

        if let Some(CborValue::Integer(iat)) = map.get(&keys::IAT) {
            claims.iat = Some(*iat as u64);
        }

        if let Some(CborValue::Bytes(cti)) = map.get(&keys::CTI) {
            claims.cti = Some(cti.clone());
        }

        claims
    }
}

/// Claims for a Common Access Token.
///
/// This struct combines standard registered claims with custom application-specific claims.
/// It provides a flexible way to include both standardized information and custom data
/// in a token.
///
/// # Example
///
/// ```
/// use common_access_token::{Claims, RegisteredClaims};
/// use common_access_token::current_timestamp;
///
/// let now = current_timestamp();
/// let registered_claims = RegisteredClaims::new()
///     .with_issuer("example-issuer")
///     .with_expiration(now + 3600);
///
/// let claims = Claims::new()
///     .with_registered_claims(registered_claims)
///     .with_custom_string(100, "custom-value")
///     .with_custom_int(101, 42);
///
/// // Access claims
/// assert_eq!(claims.registered.iss, Some("example-issuer".to_string()));
/// ```
#[derive(Debug, Clone, Default)]
pub struct Claims {
    /// Standard registered claims as defined in RFC 8392
    pub registered: RegisteredClaims,
    /// Custom application-specific claims with integer keys
    pub custom: ClaimsMap,
}

impl Claims {
    /// Creates a new empty claims set with no registered or custom claims.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::Claims;
    ///
    /// let claims = Claims::new();
    /// assert!(claims.registered.iss.is_none());
    /// assert!(claims.custom.is_empty());
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the registered claims.
    ///
    /// This method replaces any existing registered claims with the provided ones.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{Claims, RegisteredClaims};
    ///
    /// let registered = RegisteredClaims::new()
    ///     .with_issuer("example-issuer")
    ///     .with_subject("user-123");
    ///
    /// let claims = Claims::new().with_registered_claims(registered);
    /// assert_eq!(claims.registered.iss, Some("example-issuer".to_string()));
    /// ```
    pub fn with_registered_claims(mut self, registered: RegisteredClaims) -> Self {
        self.registered = registered;
        self
    }

    /// Adds a custom claim with a string value.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::Claims;
    /// use common_access_token::header::CborValue;
    ///
    /// let claims = Claims::new().with_custom_string(100, "custom-value");
    /// assert!(matches!(claims.custom.get(&100), Some(CborValue::Text(s)) if s == "custom-value"));
    /// ```
    pub fn with_custom_string<S: Into<String>>(mut self, key: i32, value: S) -> Self {
        self.custom.insert(key, CborValue::Text(value.into()));
        self
    }

    /// Adds a custom claim with a binary value.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::Claims;
    /// use common_access_token::header::CborValue;
    ///
    /// let binary_data = vec![0x01, 0x02, 0x03];
    /// let claims = Claims::new().with_custom_binary(101, binary_data.clone());
    /// assert!(matches!(claims.custom.get(&101), Some(CborValue::Bytes(b)) if b == &binary_data));
    /// ```
    pub fn with_custom_binary<B: Into<Vec<u8>>>(mut self, key: i32, value: B) -> Self {
        self.custom.insert(key, CborValue::Bytes(value.into()));
        self
    }

    /// Adds a custom claim with an integer value.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::Claims;
    /// use common_access_token::header::CborValue;
    ///
    /// let claims = Claims::new().with_custom_int(102, 42);
    /// assert!(matches!(claims.custom.get(&102), Some(CborValue::Integer(i)) if *i == 42));
    /// ```
    pub fn with_custom_int(mut self, key: i32, value: i64) -> Self {
        self.custom.insert(key, CborValue::Integer(value));
        self
    }

    /// Adds a custom claim with a nested map value.
    ///
    /// This allows for complex structured data to be included in the token.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{Claims, CborValue};
    /// use std::collections::BTreeMap;
    ///
    /// let mut nested_map = BTreeMap::new();
    /// nested_map.insert(1, CborValue::Text("nested-value".to_string()));
    ///
    /// let claims = Claims::new().with_custom_map(103, nested_map);
    /// if let Some(CborValue::Map(map)) = claims.custom.get(&103) {
    ///     if let Some(CborValue::Text(value)) = map.get(&1) {
    ///         assert_eq!(value, "nested-value");
    ///     }
    /// }
    /// ```
    pub fn with_custom_map(mut self, key: i32, value: BTreeMap<i32, CborValue>) -> Self {
        self.custom.insert(key, CborValue::Map(value));
        self
    }

    /// Get a custom claim as a string
    ///
    /// Returns `Some(&str)` if the claim exists and is a text value, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::Claims;
    ///
    /// let claims = Claims::new().with_custom_string(100, "custom-value");
    /// assert_eq!(claims.get_custom_string(100), Some("custom-value"));
    /// assert_eq!(claims.get_custom_string(999), None);
    /// ```
    pub fn get_custom_string(&self, key: i32) -> Option<&str> {
        match self.custom.get(&key) {
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
    /// use common_access_token::Claims;
    ///
    /// let claims = Claims::new().with_custom_int(100, 42);
    /// assert_eq!(claims.get_custom_int(100), Some(42));
    /// assert_eq!(claims.get_custom_int(999), None);
    /// ```
    pub fn get_custom_int(&self, key: i32) -> Option<i64> {
        match self.custom.get(&key) {
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
    /// use common_access_token::Claims;
    ///
    /// let data = vec![1, 2, 3, 4];
    /// let claims = Claims::new().with_custom_binary(100, data.clone());
    /// assert_eq!(claims.get_custom_binary(100), Some(data.as_slice()));
    /// assert_eq!(claims.get_custom_binary(999), None);
    /// ```
    pub fn get_custom_binary(&self, key: i32) -> Option<&[u8]> {
        match self.custom.get(&key) {
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
    /// use common_access_token::{Claims, CborValue};
    ///
    /// let claims = Claims::new().with_custom_string(100, "value");
    /// if let Some(CborValue::Text(s)) = claims.get_custom_claim(100) {
    ///     assert_eq!(s, "value");
    /// }
    /// ```
    pub fn get_custom_claim(&self, key: i32) -> Option<&CborValue> {
        self.custom.get(&key)
    }

    /// Check if a custom claim exists
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::Claims;
    ///
    /// let claims = Claims::new().with_custom_string(100, "value");
    /// assert!(claims.has_custom_claim(100));
    /// assert!(!claims.has_custom_claim(999));
    /// ```
    pub fn has_custom_claim(&self, key: i32) -> bool {
        self.custom.contains_key(&key)
    }

    /// Converts all claims (registered and custom) to a combined claims map.
    ///
    /// This method is primarily used internally for token encoding.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{Claims, RegisteredClaims};
    ///
    /// let claims = Claims::new()
    ///     .with_registered_claims(RegisteredClaims::new().with_issuer("example-issuer"))
    ///     .with_custom_string(100, "custom-value");
    ///
    /// let map = claims.to_map();
    /// assert_eq!(map.len(), 2); // One registered claim + one custom claim
    /// ```
    pub fn to_map(&self) -> ClaimsMap {
        let mut map = self.registered.to_map();

        // Add custom claims
        for (key, value) in &self.custom {
            map.insert(*key, value.clone());
        }

        map
    }

    /// Creates a Claims struct from a claims map.
    ///
    /// This method is primarily used internally for token decoding.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{Claims, CborValue};
    /// use common_access_token::claims::{keys, ClaimsMap};
    ///
    /// let mut map = ClaimsMap::new();
    /// map.insert(keys::ISS, CborValue::Text("example-issuer".to_string()));
    /// map.insert(100, CborValue::Text("custom-value".to_string()));
    ///
    /// let claims = Claims::from_map(&map);
    /// assert_eq!(claims.registered.iss, Some("example-issuer".to_string()));
    /// assert!(claims.custom.contains_key(&100));
    /// ```
    pub fn from_map(map: &ClaimsMap) -> Self {
        let registered = RegisteredClaims::from_map(map);

        // Extract custom claims (all keys not in the registered claims)
        let mut custom = ClaimsMap::new();
        for (key, value) in map {
            if !matches!(
                *key,
                keys::ISS | keys::SUB | keys::AUD | keys::EXP | keys::NBF | keys::IAT | keys::CTI
            ) {
                custom.insert(*key, value.clone());
            }
        }

        Self { registered, custom }
    }
}
