//! Content-addressed hash parsing and Reference Object (`apl-spec.md §4`).
//!
//! This module implements the two content-addressed primitives:
//!
//! 1. **Hash string parsing** (`§4.1`, `§4.2`) — every content-addressed reference
//!    in APL uses `sha256:<lowercase-hex>`. apl-core only supports SHA-256; any
//!    other prefix is rejected.
//!
//! 2. **Reference Object** (`§4.5`) — `{ "hash": "sha256:...", "resolver_hint": "optional-string" }`.
//!
//! # Critical Principle (`§4.4`)
//!
//! `hash` is **identity**. `resolver_hint` is a resolution convenience. apl-core
//! MUST NOT treat `resolver_hint` as part of identity under any circumstance.
//! Two references with the same `hash` and different `resolver_hint` refer to the
//! same artifact.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A validated SHA-256 hash value (32 bytes).
///
/// Per `apl-spec.md §4.1`, APL Core v0.1 uses SHA-256 exclusively. Instances of
/// `Hash` guarantee that the underlying byte sequence was produced from a
/// syntactically valid `sha256:<lowercase-hex>` string (or from a direct
/// canonical-hash computation over JCS bytes in JCS-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash([u8; 32]);

impl Hash {
    /// Construct a `Hash` from a raw 32-byte array.
    ///
    /// This constructor performs no validation; it is intended for use when
    /// the bytes come from a trusted hash computation (e.g. `sha2::Sha256`
    /// applied to JCS output).
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Access the underlying 32-byte array.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume the wrapper, returning the raw bytes.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Render as `sha256:<lowercase-hex>`.
///
/// # Examples
///
/// ```
/// use apl_core::core::hash::parse_hash_string;
///
/// let h = parse_hash_string(
///     "sha256:0000000000000000000000000000000000000000000000000000000000000000"
/// ).unwrap();
/// assert_eq!(h.to_string(), "sha256:0000000000000000000000000000000000000000000000000000000000000000");
/// ```
impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", hex::encode(self.0))
    }
}

impl Serialize for Hash {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        parse_hash_string(&s).map_err(serde::de::Error::custom)
    }
}

/// A Reference Object per `apl-spec.md §4.5`.
///
/// `hash` is identity (`§4.4`). `resolver_hint` is a convenience for resolution
/// and MUST NOT be used as canonical identity.
///
/// # Examples
///
/// ```
/// use apl_core::core::hash::Reference;
/// use serde_json::json;
///
/// let v = json!({ "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000" });
/// let r = Reference::parse(&v).unwrap();
/// assert_eq!(r.resolver_hint, None);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// Canonical identity hash. REQUIRED.
    pub hash: Hash,
    /// Resolver hint. OPTIONAL, but if present MUST be a non-empty string.
    pub resolver_hint: Option<String>,
}

impl Reference {
    /// Parse a Reference Object from a `serde_json::Value`.
    ///
    /// Enforces the typing rules of `apl-spec.md §4.5`:
    /// - `hash` is REQUIRED and MUST be a valid hash string
    /// - `resolver_hint`, if present and non-null, MUST be a non-empty string
    /// - JSON `null` for `resolver_hint` is treated as absent
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the value does not conform to `§4.5`.
    ///
    /// # Examples
    ///
    /// ```
    /// use apl_core::core::hash::Reference;
    /// use serde_json::json;
    ///
    /// let v = json!({
    ///     "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    ///     "resolver_hint": "https://registry.example/frames/x"
    /// });
    /// let r = Reference::parse(&v).unwrap();
    /// assert_eq!(r.resolver_hint.as_deref(), Some("https://registry.example/frames/x"));
    /// ```
    pub fn parse(value: &serde_json::Value) -> Result<Self, ParseError> {
        let obj = value.as_object().ok_or(ParseError::NotObject)?;

        let hash_val = obj.get("hash").ok_or(ParseError::HashMissing)?;
        let hash_str = hash_val.as_str().ok_or(ParseError::HashNotString)?;
        let hash = parse_hash_string(hash_str)?;

        let resolver_hint = match obj.get("resolver_hint") {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => {
                let s = v.as_str().ok_or(ParseError::ResolverHintNotString)?;
                if s.is_empty() {
                    return Err(ParseError::ResolverHintEmpty);
                }
                Some(s.to_owned())
            }
        };

        Ok(Self {
            hash,
            resolver_hint,
        })
    }
}

/// Parse errors that arise from hash and reference parsing.
///
/// These errors carry enough context for CORE-VERIFY-1 to emit the correct
/// `Diagnostic` and `FailureClass`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    // --- Hash string ---
    /// Prefix is not `sha256:`.
    UnsupportedAlgorithm {
        /// The observed prefix (everything up to and including the first `:`,
        /// or the whole input if no `:` is present).
        observed: String,
    },
    /// Hex body does not have exactly 64 characters.
    InvalidLength {
        /// Actual number of characters after the `sha256:` prefix.
        actual: usize,
    },
    /// Hex body contains a character outside `[0-9a-f]`.
    InvalidHexCharacter {
        /// Offending character.
        character: char,
    },
    /// Input is empty.
    Empty,

    // --- Reference object ---
    /// Reference value is not a JSON object.
    NotObject,
    /// `hash` field missing.
    HashMissing,
    /// `hash` field is not a JSON string.
    HashNotString,
    /// `resolver_hint` is present but is not a JSON string.
    ResolverHintNotString,
    /// `resolver_hint` is an empty string.
    ResolverHintEmpty,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlgorithm { observed } => {
                write!(f, "unsupported hash algorithm prefix: {:?}", observed)
            }
            Self::InvalidLength { actual } => {
                write!(f, "sha256 hex body must be 64 characters, got {}", actual)
            }
            Self::InvalidHexCharacter { character } => {
                write!(f, "non-hex character in sha256 body: {:?}", character)
            }
            Self::Empty => write!(f, "empty hash string"),
            Self::NotObject => write!(f, "reference value is not a JSON object"),
            Self::HashMissing => write!(f, "reference object is missing the REQUIRED `hash` field"),
            Self::HashNotString => write!(f, "reference `hash` field is not a JSON string"),
            Self::ResolverHintNotString => {
                write!(f, "reference `resolver_hint` is not a JSON string")
            }
            Self::ResolverHintEmpty => {
                write!(f, "reference `resolver_hint` must be non-empty if present")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse `sha256:<lowercase-hex-64>` into a validated [`Hash`].
///
/// Per `apl-spec.md §4.2` the prefix is case-sensitive and the hex body MUST
/// be lowercase. Uppercase hex or any other algorithm prefix is rejected.
///
/// # Errors
///
/// Returns a [`ParseError`] variant describing the exact violation.
///
/// # Examples
///
/// ```
/// use apl_core::core::hash::parse_hash_string;
///
/// let h = parse_hash_string(
///     "sha256:0000000000000000000000000000000000000000000000000000000000000000"
/// ).unwrap();
/// assert_eq!(h.as_bytes(), &[0u8; 32]);
/// ```
pub fn parse_hash_string(s: &str) -> Result<Hash, ParseError> {
    if s.is_empty() {
        return Err(ParseError::Empty);
    }

    // Per §4.2 the prefix is exactly "sha256:" (case-sensitive).
    let rest = match s.strip_prefix("sha256:") {
        Some(rest) => rest,
        None => {
            let observed = match s.find(':') {
                Some(idx) => s[..=idx].to_owned(),
                None => s.to_owned(),
            };
            return Err(ParseError::UnsupportedAlgorithm { observed });
        }
    };

    if rest.len() != 64 {
        return Err(ParseError::InvalidLength { actual: rest.len() });
    }

    // Case-sensitive lowercase-hex check per §4.2 (uppercase MUST be rejected).
    for c in rest.chars() {
        if !matches!(c, '0'..='9' | 'a'..='f') {
            return Err(ParseError::InvalidHexCharacter { character: c });
        }
    }

    // Length and charset guarantee a successful decode into 32 bytes.
    let mut out = [0u8; 32];
    // SAFETY: we validated above that `rest` is exactly 64 lowercase-hex chars,
    // which decode to exactly 32 bytes without error.
    hex::decode_to_slice(rest, &mut out).unwrap_or_else(|_| {
        unreachable!("validated above: 64 lowercase-hex chars decode to 32 bytes")
    });
    Ok(Hash(out))
}

#[cfg(test)]
mod hash_parse_tests {
    use super::*;

    const ZERO_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn valid() -> String {
        format!("sha256:{}", ZERO_HEX)
    }

    #[test]
    fn accepts_valid_zero_hash() {
        let h = parse_hash_string(&valid()).unwrap();
        assert_eq!(h.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn accepts_valid_ff_hash() {
        let s = format!("sha256:{}", "f".repeat(64));
        let h = parse_hash_string(&s).unwrap();
        assert_eq!(h.as_bytes(), &[0xff; 32]);
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(parse_hash_string(""), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_missing_prefix() {
        let err = parse_hash_string(ZERO_HEX).unwrap_err();
        assert!(matches!(err, ParseError::UnsupportedAlgorithm { .. }));
    }

    #[test]
    fn rejects_wrong_algorithm() {
        let err = parse_hash_string(&format!("md5:{}", "0".repeat(32))).unwrap_err();
        match err {
            ParseError::UnsupportedAlgorithm { observed } => assert_eq!(observed, "md5:"),
            other => panic!("expected UnsupportedAlgorithm, got {:?}", other),
        }
    }

    #[test]
    fn rejects_uppercase_prefix() {
        // Prefix is case-sensitive: "SHA256:" is NOT "sha256:".
        let err = parse_hash_string(&format!("SHA256:{}", ZERO_HEX)).unwrap_err();
        assert!(matches!(err, ParseError::UnsupportedAlgorithm { .. }));
    }

    #[test]
    fn rejects_uppercase_hex_body() {
        let err = parse_hash_string(&format!("sha256:{}", "A".repeat(64))).unwrap_err();
        match err {
            ParseError::InvalidHexCharacter { character } => assert_eq!(character, 'A'),
            other => panic!("expected InvalidHexCharacter, got {:?}", other),
        }
    }

    #[test]
    fn rejects_short_body() {
        let err = parse_hash_string("sha256:abc").unwrap_err();
        assert_eq!(err, ParseError::InvalidLength { actual: 3 });
    }

    #[test]
    fn rejects_long_body() {
        let err = parse_hash_string(&format!("sha256:{}", "0".repeat(65))).unwrap_err();
        assert_eq!(err, ParseError::InvalidLength { actual: 65 });
    }

    #[test]
    fn rejects_non_hex_char() {
        // 'g' is not a hex digit.
        let body: String = "0".repeat(63).chars().chain(std::iter::once('g')).collect();
        let err = parse_hash_string(&format!("sha256:{}", body)).unwrap_err();
        assert_eq!(err, ParseError::InvalidHexCharacter { character: 'g' });
    }

    #[test]
    fn display_roundtrip() {
        let h = parse_hash_string(&valid()).unwrap();
        assert_eq!(h.to_string(), valid());
    }

    #[test]
    fn copy_and_hash_and_ord() {
        let h1 = parse_hash_string(&valid()).unwrap();
        let h2 = h1; // Copy
        assert_eq!(h1, h2);
        let mut set = std::collections::HashSet::new();
        set.insert(h1);
        assert!(set.contains(&h2));
    }

    #[test]
    fn serde_roundtrip() {
        let h = parse_hash_string(&valid()).unwrap();
        let j = serde_json::to_string(&h).unwrap();
        let parsed: Hash = serde_json::from_str(&j).unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn serde_rejects_invalid() {
        let bad = r#""sha256:ZZ""#;
        assert!(serde_json::from_str::<Hash>(bad).is_err());
    }
}

#[cfg(test)]
mod reference_parse_tests {
    use super::*;
    use serde_json::json;

    fn h() -> String {
        format!("sha256:{}", "0".repeat(64))
    }

    #[test]
    fn accepts_hash_only() {
        let v = json!({ "hash": h() });
        let r = Reference::parse(&v).unwrap();
        assert_eq!(r.hash.to_string(), h());
        assert_eq!(r.resolver_hint, None);
    }

    #[test]
    fn accepts_with_resolver_hint() {
        let v = json!({ "hash": h(), "resolver_hint": "https://registry.example/frames/x" });
        let r = Reference::parse(&v).unwrap();
        assert_eq!(
            r.resolver_hint.as_deref(),
            Some("https://registry.example/frames/x")
        );
    }

    #[test]
    fn accepts_null_resolver_hint_as_absent() {
        let v = json!({ "hash": h(), "resolver_hint": null });
        let r = Reference::parse(&v).unwrap();
        assert_eq!(r.resolver_hint, None);
    }

    #[test]
    fn rejects_missing_hash() {
        let v = json!({});
        assert_eq!(Reference::parse(&v), Err(ParseError::HashMissing));
    }

    #[test]
    fn rejects_non_string_hash() {
        let v = json!({ "hash": 42 });
        assert_eq!(Reference::parse(&v), Err(ParseError::HashNotString));
    }

    #[test]
    fn rejects_invalid_hash_value() {
        let v = json!({ "hash": "md5:abc" });
        let err = Reference::parse(&v).unwrap_err();
        assert!(matches!(err, ParseError::UnsupportedAlgorithm { .. }));
    }

    #[test]
    fn rejects_empty_resolver_hint() {
        let v = json!({ "hash": h(), "resolver_hint": "" });
        assert_eq!(Reference::parse(&v), Err(ParseError::ResolverHintEmpty));
    }

    #[test]
    fn rejects_non_string_resolver_hint() {
        let v = json!({ "hash": h(), "resolver_hint": 42 });
        assert_eq!(Reference::parse(&v), Err(ParseError::ResolverHintNotString));
    }

    #[test]
    fn rejects_non_object() {
        let v = json!("not an object");
        assert_eq!(Reference::parse(&v), Err(ParseError::NotObject));
    }

    #[test]
    fn hash_identity_is_independent_of_resolver_hint() {
        // Per §4.4 — `resolver_hint` is NOT part of identity.
        let a = Reference::parse(&json!({ "hash": h() })).unwrap();
        let b = Reference::parse(&json!({ "hash": h(), "resolver_hint": "https://a" })).unwrap();
        let c = Reference::parse(&json!({ "hash": h(), "resolver_hint": "https://b" })).unwrap();
        assert_eq!(a.hash, b.hash);
        assert_eq!(b.hash, c.hash);
    }
}

#[cfg(test)]
mod hash_constructor_tests {
    use super::*;

    #[test]
    fn from_bytes_roundtrips_with_as_bytes() {
        let raw = [0xab_u8; 32];
        let h = Hash::from_bytes(raw);
        assert_eq!(h.as_bytes(), &raw);
    }

    #[test]
    fn from_bytes_zero_array() {
        let h = Hash::from_bytes([0u8; 32]);
        assert_eq!(h.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn from_bytes_ff_array() {
        let raw = [0xff_u8; 32];
        let h = Hash::from_bytes(raw);
        assert_eq!(h.as_bytes(), &[0xff_u8; 32]);
    }

    #[test]
    fn into_bytes_returns_original_array() {
        let raw: [u8; 32] = core::array::from_fn(|i| i as u8);
        let h = Hash::from_bytes(raw);
        assert_eq!(h.into_bytes(), raw);
    }

    #[test]
    fn into_bytes_consumes_and_matches_as_bytes() {
        let raw = [0x42_u8; 32];
        let h = Hash::from_bytes(raw);
        let as_b = *h.as_bytes();
        assert_eq!(h.into_bytes(), as_b);
    }

    #[test]
    fn from_bytes_via_parse_roundtrip() {
        // Verify from_bytes produces the same value as parse_hash_string.
        let raw = [0xde_u8; 32];
        let h_direct = Hash::from_bytes(raw);
        let s = format!("sha256:{}", hex::encode(raw));
        let h_parsed = parse_hash_string(&s).unwrap();
        assert_eq!(h_direct, h_parsed);
    }
}

#[cfg(test)]
mod parse_error_display_tests {
    use super::*;

    #[test]
    fn display_unsupported_algorithm_contains_observed() {
        let err = ParseError::UnsupportedAlgorithm {
            observed: "md5:".to_owned(),
        };
        let s = format!("{err}");
        assert!(!s.is_empty());
        assert!(
            s.contains("md5:"),
            "expected observed prefix in message, got: {s}"
        );
    }

    #[test]
    fn display_unsupported_algorithm_no_colon() {
        let err = ParseError::UnsupportedAlgorithm {
            observed: "notahash".to_owned(),
        };
        let s = format!("{err}");
        assert!(!s.is_empty());
        assert!(
            s.contains("notahash"),
            "expected observed value in message, got: {s}"
        );
    }

    #[test]
    fn display_invalid_length_contains_actual() {
        let err = ParseError::InvalidLength { actual: 3 };
        let s = format!("{err}");
        assert!(!s.is_empty());
        assert!(
            s.contains('3'),
            "expected actual length in message, got: {s}"
        );
    }

    #[test]
    fn display_invalid_hex_character_contains_char() {
        let err = ParseError::InvalidHexCharacter { character: 'Z' };
        let s = format!("{err}");
        assert!(!s.is_empty());
        assert!(s.contains('Z'), "expected character in message, got: {s}");
    }

    #[test]
    fn display_empty_is_non_empty() {
        let s = format!("{}", ParseError::Empty);
        assert!(!s.is_empty());
    }

    #[test]
    fn display_not_object_is_non_empty() {
        let s = format!("{}", ParseError::NotObject);
        assert!(!s.is_empty());
    }

    #[test]
    fn display_hash_missing_is_non_empty() {
        let s = format!("{}", ParseError::HashMissing);
        assert!(!s.is_empty());
    }

    #[test]
    fn display_hash_not_string_is_non_empty() {
        let s = format!("{}", ParseError::HashNotString);
        assert!(!s.is_empty());
    }

    #[test]
    fn display_resolver_hint_not_string_is_non_empty() {
        let s = format!("{}", ParseError::ResolverHintNotString);
        assert!(!s.is_empty());
    }

    #[test]
    fn display_resolver_hint_empty_is_non_empty() {
        let s = format!("{}", ParseError::ResolverHintEmpty);
        assert!(!s.is_empty());
    }

    #[test]
    fn parse_error_implements_std_error() {
        // Ensures the Error trait impl compiles and is usable via trait objects.
        let err: Box<dyn std::error::Error> = Box::new(ParseError::Empty);
        assert!(!err.to_string().is_empty());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Every syntactically valid `sha256:<lowercase-hex-64>` parses and
        /// round-trips through `Display`.
        #[test]
        fn arbitrary_lowercase_hex_roundtrips(bytes in any::<[u8; 32]>()) {
            let s = format!("sha256:{}", hex::encode(bytes));
            let h = parse_hash_string(&s).unwrap();
            prop_assert_eq!(h.as_bytes(), &bytes);
            prop_assert_eq!(h.to_string(), s);
        }

        /// Any string not matching the grammar is rejected without panicking.
        #[test]
        fn reject_random_strings(s in "[A-Za-z0-9:]{0,80}") {
            let _ = parse_hash_string(&s); // Must not panic.
        }

        /// from_bytes/into_bytes are inverse operations for arbitrary byte arrays.
        #[test]
        fn from_bytes_into_bytes_inverse(raw in any::<[u8; 32]>()) {
            let h = Hash::from_bytes(raw);
            prop_assert_eq!(h.into_bytes(), raw);
        }

        /// Display messages for all ParseError variants are non-empty strings.
        #[test]
        fn parse_error_display_non_empty_for_unsupported_algorithm(obs in "[a-z]{0,10}:?") {
            let err = ParseError::UnsupportedAlgorithm { observed: obs };
            prop_assert!(!err.to_string().is_empty());
        }

        #[test]
        fn parse_error_display_non_empty_for_invalid_length(actual in 0usize..200) {
            let err = ParseError::InvalidLength { actual };
            prop_assert!(!err.to_string().is_empty());
        }
    }
}
