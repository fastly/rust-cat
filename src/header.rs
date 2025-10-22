//! # Header Types for Common Access Token
//!
//! This module provides the header structure and related types for Common Access Tokens.
//!
//! Headers in Common Access Tokens are divided into two categories:
//!
//! - **Protected Headers**: These headers are integrity-protected and are part of the signature input.
//! - **Unprotected Headers**: These headers are not integrity-protected and can be modified without invalidating the signature.
//!
//! The most important header parameters are:
//!
//! - **Algorithm (alg)**: Specifies the cryptographic algorithm used to secure the token.
//! - **Key ID (kid)**: Identifies the key used to secure the token.

use crate::constants::cose_algs;
use std::collections::BTreeMap;

/// Supported algorithms for token signing and verification.
///
/// This enum represents the cryptographic algorithms that can be used
/// to sign and verify Common Access Tokens.
///
/// Currently, only HMAC-SHA256 is supported, but the design allows for
/// easy extension to support additional algorithms in the future.
///
/// # Example
///
/// ```
/// use common_access_token::Algorithm;
///
/// // Create a token with HMAC-SHA256 algorithm
/// let alg = Algorithm::HmacSha256;
/// assert_eq!(alg.identifier(), 5); // COSE algorithm identifier
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// HMAC with SHA-256 (COSE algorithm identifier: 5)
    HmacSha256,
}

impl Algorithm {
    /// Get the algorithm identifier as defined in the COSE spec
    pub fn identifier(&self) -> i32 {
        match self {
            Algorithm::HmacSha256 => cose_algs::HMAC_SHA_256,
        }
    }

    /// Create an Algorithm from an identifier
    pub fn from_identifier(id: i32) -> Option<Self> {
        match id {
            cose_algs::HMAC_SHA_256 => Some(Algorithm::HmacSha256),
            _ => None,
        }
    }
}

/// Key identifier that can be either a binary or string value.
///
/// The key identifier (kid) is used to indicate which key was used to secure the token.
/// This allows the recipient to select the appropriate key for verification without
/// having to try each key.
///
/// # Examples
///
/// Creating a string key identifier:
///
/// ```
/// use common_access_token::KeyId;
///
/// let string_kid = KeyId::string("my-key-2023");
/// ```
///
/// Creating a binary key identifier:
///
/// ```
/// use common_access_token::KeyId;
///
/// let binary_kid = KeyId::binary(vec![0x01, 0x02, 0x03, 0x04]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyId {
    /// Binary key identifier (for binary key identifiers like UUIDs or hashes)
    Binary(Vec<u8>),
    /// String key identifier (for human-readable key identifiers)
    String(String),
}

impl KeyId {
    /// Create a new binary key identifier
    pub fn binary<T: Into<Vec<u8>>>(data: T) -> Self {
        KeyId::Binary(data.into())
    }

    /// Create a new string key identifier
    pub fn string<T: Into<String>>(data: T) -> Self {
        KeyId::String(data.into())
    }

    /// Get the key identifier as bytes
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KeyId::Binary(data) => data,
            KeyId::String(data) => data.as_bytes(),
        }
    }
}

/// CBOR value type for header and claim values.
///
/// This enum represents the different types of values that can be stored
/// in token headers and claims. It supports the most common CBOR data types:
/// integers, byte strings, text strings, and maps (which can contain nested values).
///
/// # Examples
///
/// Creating different types of CBOR values:
///
/// ```
/// use common_access_token::CborValue;
/// use std::collections::BTreeMap;
///
/// // Integer value
/// let int_value = CborValue::Integer(42);
///
/// // Text string value
/// let text_value = CborValue::Text("Hello, world!".to_string());
///
/// // Byte string value
/// let bytes_value = CborValue::Bytes(vec![0x01, 0x02, 0x03]);
///
/// // Map value (nested CBOR map)
/// let mut map = BTreeMap::new();
/// map.insert(1, CborValue::Text("nested value".to_string()));
/// let map_value = CborValue::Map(map);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum CborValue {
    /// Integer value (signed 64-bit integer)
    Integer(i64),
    /// Byte string value (binary data)
    Bytes(Vec<u8>),
    /// Text string value (UTF-8 encoded string)
    Text(String),
    /// Map value (nested CBOR map with integer keys and CBOR values)
    Map(BTreeMap<i32, CborValue>),
    /// Array value (list of CBOR values)
    Array(Vec<CborValue>),
    /// Null value
    Null,
}

/// Type alias for header maps
pub type HeaderMap = BTreeMap<i32, CborValue>;

/// COSE header parameter labels
pub mod labels {
    use crate::constants::cose_labels;

    /// Algorithm (used in protected header)
    pub const ALG: i32 = cose_labels::ALG;
    /// Key identifier (used in protected or unprotected header)
    pub const KID: i32 = cose_labels::KID;
}

/// Header for a Common Access Token.
///
/// The header contains metadata about the token, such as the algorithm used
/// for signing and the key identifier. It is divided into two parts:
///
/// - **Protected Header**: Contains parameters that are integrity-protected and
///   included in the signature input. This typically includes the algorithm.
///
/// - **Unprotected Header**: Contains parameters that are not integrity-protected
///   and can be modified without invalidating the signature. This might include
///   non-critical metadata.
///
/// # Examples
///
/// Creating a header with algorithm and key identifier:
///
/// ```
/// use common_access_token::{Algorithm, Header, KeyId};
///
/// let header = Header::new()
///     .with_algorithm(Algorithm::HmacSha256)
///     .with_protected_key_id(KeyId::string("my-key-2023"));
///
/// assert_eq!(header.algorithm(), Some(Algorithm::HmacSha256));
/// ```
#[derive(Debug, Clone, Default)]
pub struct Header {
    /// Protected header parameters (must be integrity protected)
    pub protected: HeaderMap,
    /// Unprotected header parameters
    pub unprotected: HeaderMap,
}

impl Header {
    /// Creates a new empty header with no parameters.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::Header;
    ///
    /// let header = Header::new();
    /// assert!(header.protected.is_empty());
    /// assert!(header.unprotected.is_empty());
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the algorithm in the protected header.
    ///
    /// The algorithm is always placed in the protected header because
    /// it is a critical parameter that must be integrity-protected.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{Algorithm, Header};
    ///
    /// let header = Header::new().with_algorithm(Algorithm::HmacSha256);
    /// assert_eq!(header.algorithm(), Some(Algorithm::HmacSha256));
    /// ```
    pub fn with_algorithm(mut self, alg: Algorithm) -> Self {
        self.protected
            .insert(labels::ALG, CborValue::Integer(alg.identifier() as i64));
        self
    }

    /// Sets the key identifier in the protected header.
    ///
    /// The key identifier in the protected header is integrity-protected
    /// and cannot be modified without invalidating the signature.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{Header, KeyId};
    ///
    /// let header = Header::new().with_protected_key_id(KeyId::string("my-key-2023"));
    /// if let Some(KeyId::String(kid)) = header.key_id() {
    ///     assert_eq!(kid, "my-key-2023");
    /// }
    /// ```
    pub fn with_protected_key_id(mut self, kid: KeyId) -> Self {
        match kid {
            KeyId::Binary(data) => {
                self.protected.insert(labels::KID, CborValue::Bytes(data));
            }
            KeyId::String(data) => {
                self.protected.insert(labels::KID, CborValue::Text(data));
            }
        }
        self
    }

    /// Sets the key identifier in the unprotected header.
    ///
    /// The key identifier in the unprotected header is not integrity-protected
    /// and can be modified without invalidating the signature.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{Header, KeyId};
    ///
    /// let header = Header::new().with_unprotected_key_id(KeyId::string("my-key-2023"));
    /// if let Some(KeyId::String(kid)) = header.key_id() {
    ///     assert_eq!(kid, "my-key-2023");
    /// }
    /// ```
    pub fn with_unprotected_key_id(mut self, kid: KeyId) -> Self {
        match kid {
            KeyId::Binary(data) => {
                self.unprotected.insert(labels::KID, CborValue::Bytes(data));
            }
            KeyId::String(data) => {
                self.unprotected.insert(labels::KID, CborValue::Text(data));
            }
        }
        self
    }

    /// Gets the algorithm from the protected header.
    ///
    /// Returns `None` if the algorithm is not present or is not a valid algorithm.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{Algorithm, Header};
    ///
    /// let header = Header::new().with_algorithm(Algorithm::HmacSha256);
    /// assert_eq!(header.algorithm(), Some(Algorithm::HmacSha256));
    ///
    /// let empty_header = Header::new();
    /// assert_eq!(empty_header.algorithm(), None);
    /// ```
    pub fn algorithm(&self) -> Option<Algorithm> {
        if let Some(CborValue::Integer(alg)) = self.protected.get(&labels::ALG) {
            Algorithm::from_identifier(*alg as i32)
        } else {
            None
        }
    }

    /// Gets the key identifier from the protected or unprotected header.
    ///
    /// This method first checks the protected header, and if the key identifier
    /// is not found there, it checks the unprotected header.
    ///
    /// Returns `None` if the key identifier is not present in either header.
    ///
    /// # Example
    ///
    /// ```
    /// use common_access_token::{Header, KeyId};
    ///
    /// let header = Header::new().with_protected_key_id(KeyId::string("my-key-2023"));
    /// if let Some(KeyId::String(kid)) = header.key_id() {
    ///     assert_eq!(kid, "my-key-2023");
    /// }
    ///
    /// let empty_header = Header::new();
    /// assert_eq!(empty_header.key_id(), None);
    /// ```
    pub fn key_id(&self) -> Option<KeyId> {
        // First check protected header
        if let Some(kid) = self.protected.get(&labels::KID) {
            return match kid {
                CborValue::Bytes(data) => Some(KeyId::Binary(data.clone())),
                CborValue::Text(data) => Some(KeyId::String(data.clone())),
                _ => None,
            };
        }

        // Then check unprotected header
        if let Some(kid) = self.unprotected.get(&labels::KID) {
            return match kid {
                CborValue::Bytes(data) => Some(KeyId::Binary(data.clone())),
                CborValue::Text(data) => Some(KeyId::String(data.clone())),
                _ => None,
            };
        }

        None
    }
}
