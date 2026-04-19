//! APL Transformation parsing and typing rules per `apl-spec.md §8`.
//!
//! A [`Transformation`] is a declared semantic effect of a conversion.
//! Both [`Transformation::preserves`] and [`Transformation::losses`] MUST be
//! explicitly present. Absence of `losses` MAY be encoded as an empty array but
//! MUST NOT be interpreted as "unknown" (`apl-spec.md §8.3`,
//! `apl-constitution.md §7`).
//!
//! # Parsing
//!
//! [`Transformation::parse`] enforces the grammar from `§8.2`–`§8.3` and rejects
//! any value that violates the typing rules.
//!
//! # Example
//!
//! ```
//! use serde_json::json;
//! use apl_core::core::transformation::Transformation;
//!
//! let v = json!({
//!     "version":   "0.1",
//!     "procedure": "raw-to-jpeg-export",
//!     "preserves": ["aspect-ratio"],
//!     "losses":    ["color-grade"]
//! });
//! let t = Transformation::parse(&v).unwrap();
//! assert_eq!(t.version, "0.1");
//! let _ = t.canonical_hash();
//! ```

use std::collections::HashSet;

use serde_json::Value;

use crate::core::{frame::StringOrObject, hash::Hash, jcs::canonical_hash};

/// An APL Transformation per `apl-spec.md §8`.
///
/// Holds the four mandatory fields plus the original [`serde_json::Value`].
/// The raw value is retained for [`Transformation::canonical_hash`]
/// recomputation and for profile-level inspection of additional fields.
///
/// # Invariant
///
/// [`Transformation::losses`] being an empty `Vec` is a **valid** declaration
/// of "nothing is lost". Missing `losses` entirely produces
/// [`TransformationParseError::LossesMissing`] (a distinct error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transformation {
    /// Always `"0.1"` for APL Core v0.1.
    pub version: String,
    /// Identifier or description of the conversion procedure.
    ///
    /// Either a non-empty string or a non-empty object (`§8.2`).
    pub procedure: StringOrObject,
    /// Properties that the transformation preserves. MUST be present; MAY be
    /// empty (`§8.3`).
    pub preserves: Vec<String>,
    /// Properties that the transformation loses. MUST be present; MAY be empty
    /// but MUST NOT mean "unknown" (`§8.3`).
    pub losses: Vec<String>,
    /// Original JSON value, retained for hashing and profile inspection.
    pub raw: Value,
}

/// Errors produced by [`Transformation::parse`].
///
/// Every variant maps one-to-one to a distinct invalidity condition so callers
/// can react precisely to whichever structural constraint was violated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformationParseError {
    /// Input value is not a JSON object.
    TransformationNotObject,
    /// `"version"` key is absent.
    VersionMissing,
    /// `"version"` value is present but not `"0.1"`.
    VersionUnsupported {
        /// The unsupported version string that was found.
        got: String,
    },
    /// `"procedure"` key is absent.
    ProcedureMissing,
    /// `"procedure"` value is neither a non-empty string nor a non-empty object.
    ProcedureInvalid,
    /// `"preserves"` key is absent.
    PreservesMissing,
    /// `"preserves"` value is not a valid array of unique non-empty strings.
    PreservesInvalid,
    /// `"losses"` key is absent.
    LossesMissing,
    /// `"losses"` value is not a valid array of unique non-empty strings.
    LossesInvalid,
}

impl Transformation {
    /// Parse a JSON value into a [`Transformation`].
    ///
    /// Enforces the full grammar from `apl-spec.md §8.2`–`§8.3`:
    ///
    /// - `version` MUST equal `"0.1"`.
    /// - `procedure` MUST be a non-empty string or a non-empty object.
    /// - `preserves` MUST be present and contain only unique non-empty strings.
    /// - `losses` MUST be present and contain only unique non-empty strings.
    ///
    /// # Errors
    ///
    /// Returns the first [`TransformationParseError`] variant that applies,
    /// evaluated in top-to-bottom field order.
    ///
    /// # Example
    ///
    /// ```
    /// use serde_json::json;
    /// use apl_core::core::transformation::{Transformation, TransformationParseError};
    ///
    /// let err = Transformation::parse(&json!("not-an-object")).unwrap_err();
    /// assert_eq!(err, TransformationParseError::TransformationNotObject);
    /// ```
    pub fn parse(v: &Value) -> Result<Transformation, TransformationParseError> {
        use TransformationParseError::{
            LossesInvalid, LossesMissing, PreservesInvalid, PreservesMissing, ProcedureInvalid,
            ProcedureMissing, TransformationNotObject, VersionMissing, VersionUnsupported,
        };

        let obj = v.as_object().ok_or(TransformationNotObject)?;

        // --- version ---
        let version_str = obj
            .get("version")
            .ok_or(VersionMissing)?
            .as_str()
            .ok_or_else(|| VersionUnsupported {
                got: "<non-string>".into(),
            })?;
        if version_str != "0.1" {
            return Err(VersionUnsupported {
                got: version_str.to_owned(),
            });
        }

        // --- procedure ---
        let procedure = match obj.get("procedure").ok_or(ProcedureMissing)? {
            Value::String(s) if !s.is_empty() => StringOrObject::String(s.clone()),
            Value::Object(m) if !m.is_empty() => StringOrObject::Object(m.clone()),
            _ => return Err(ProcedureInvalid),
        };

        // --- preserves ---
        let preserves = parse_string_array_allow_empty(
            obj.get("preserves").ok_or(PreservesMissing)?,
            PreservesInvalid,
        )?;

        // --- losses ---
        let losses =
            parse_string_array_allow_empty(obj.get("losses").ok_or(LossesMissing)?, LossesInvalid)?;

        Ok(Transformation {
            version: version_str.to_owned(),
            procedure,
            preserves,
            losses,
            raw: v.clone(),
        })
    }

    /// SHA-256 of the JCS-canonical bytes of the original JSON value.
    ///
    /// The hash is computed from [`Transformation::raw`], which is the exact
    /// [`Value`] passed to [`Transformation::parse`]. Key order in the input
    /// does not affect the result because JCS sorts object keys before hashing.
    ///
    /// # Example
    ///
    /// ```
    /// use serde_json::json;
    /// use apl_core::core::transformation::Transformation;
    ///
    /// let v = json!({
    ///     "version": "0.1",
    ///     "procedure": "export",
    ///     "preserves": [],
    ///     "losses": []
    /// });
    /// let a = Transformation::parse(&v).unwrap();
    /// let b = Transformation::parse(&v).unwrap();
    /// assert_eq!(a.canonical_hash(), b.canonical_hash());
    /// ```
    #[must_use]
    pub fn canonical_hash(&self) -> Hash {
        canonical_hash(&self.raw)
    }
}

/// Parse a JSON array of unique non-empty strings, or return `err` on any
/// structural violation (non-array, non-string item, empty-string item,
/// duplicate item).
///
/// An empty array is valid and yields an empty `Vec`.
fn parse_string_array_allow_empty(
    v: &Value,
    err: TransformationParseError,
) -> Result<Vec<String>, TransformationParseError> {
    let arr = v.as_array().ok_or_else(|| err.clone())?;
    let mut out = Vec::with_capacity(arr.len());
    let mut seen: HashSet<String> = HashSet::with_capacity(arr.len());
    for item in arr {
        let s = item.as_str().ok_or_else(|| err.clone())?;
        if s.is_empty() {
            return Err(err);
        }
        if !seen.insert(s.to_owned()) {
            return Err(err);
        }
        out.push(s.to_owned());
    }
    Ok(out)
}

#[cfg(test)]
mod positive_tests {
    use serde_json::json;

    use super::{StringOrObject, Transformation};

    fn minimal() -> serde_json::Value {
        json!({
            "version":   "0.1",
            "procedure": "raw-to-jpeg-export",
            "preserves": [],
            "losses":    []
        })
    }

    /// AC1: accepts a minimal transformation with non-empty `procedure`, empty
    /// `preserves`, empty `losses`.
    #[test]
    fn accepts_minimal() {
        let t = Transformation::parse(&minimal()).unwrap();
        assert_eq!(t.version, "0.1");
        assert!(matches!(t.procedure, StringOrObject::String(_)));
    }

    /// AC7/AC8: accepts `procedure` as non-empty string.
    #[test]
    fn accepts_string_procedure() {
        let t = Transformation::parse(&minimal()).unwrap();
        assert!(matches!(t.procedure, StringOrObject::String(ref s) if !s.is_empty()));
    }

    /// AC8: accepts `procedure` as non-empty object.
    #[test]
    fn accepts_object_procedure() {
        let mut v = minimal();
        v["procedure"] = json!({ "method_id": "denoise-v2", "threshold": 0.7 });
        let t = Transformation::parse(&v).unwrap();
        assert!(matches!(t.procedure, StringOrObject::Object(_)));
    }

    /// Populated `preserves` and `losses` are accepted and parsed correctly.
    #[test]
    fn preserves_and_losses_populated() {
        let mut v = minimal();
        v["preserves"] = json!(["pixel-count", "aspect-ratio"]);
        v["losses"] = json!(["color-grade", "denoise-artifacts"]);
        let t = Transformation::parse(&v).unwrap();
        assert_eq!(t.preserves.len(), 2);
        assert_eq!(t.losses.len(), 2);
    }

    /// AC12: `canonical_hash` is deterministic for identical inputs.
    #[test]
    fn hash_is_deterministic() {
        let a = Transformation::parse(&minimal()).unwrap();
        let b = Transformation::parse(&minimal()).unwrap();
        assert_eq!(a.canonical_hash(), b.canonical_hash());
    }

    /// AC12: hash is key-order-independent (JCS normalises key order).
    #[test]
    fn hash_is_key_order_independent() {
        let ordered = json!({
            "version":   "0.1",
            "procedure": "export",
            "preserves": [],
            "losses":    []
        });
        let reordered = json!({
            "losses":    [],
            "preserves": [],
            "procedure": "export",
            "version":   "0.1"
        });
        let a = Transformation::parse(&ordered).unwrap();
        let b = Transformation::parse(&reordered).unwrap();
        assert_eq!(a.canonical_hash(), b.canonical_hash());
    }
}

#[cfg(test)]
mod negative_tests {
    use serde_json::json;

    use super::{Transformation, TransformationParseError};

    fn base() -> serde_json::Value {
        json!({
            "version":   "0.1",
            "procedure": "p",
            "preserves": [],
            "losses":    []
        })
    }

    /// AC2: rejects non-object input.
    #[test]
    fn non_object() {
        assert_eq!(
            Transformation::parse(&json!("x")),
            Err(TransformationParseError::TransformationNotObject)
        );
    }

    /// AC3: rejects missing `version`.
    #[test]
    fn version_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("version");
        assert_eq!(
            Transformation::parse(&v),
            Err(TransformationParseError::VersionMissing)
        );
    }

    /// AC3: rejects unsupported `version`.
    #[test]
    fn version_wrong() {
        let mut v = base();
        v["version"] = json!("0.2");
        assert_eq!(
            Transformation::parse(&v),
            Err(TransformationParseError::VersionUnsupported { got: "0.2".into() })
        );
    }

    /// AC4: rejects missing `procedure`.
    #[test]
    fn procedure_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("procedure");
        assert_eq!(
            Transformation::parse(&v),
            Err(TransformationParseError::ProcedureMissing)
        );
    }

    /// AC5: rejects empty-string `procedure`.
    #[test]
    fn procedure_empty_string() {
        let mut v = base();
        v["procedure"] = json!("");
        assert_eq!(
            Transformation::parse(&v),
            Err(TransformationParseError::ProcedureInvalid)
        );
    }

    /// AC6: rejects empty-object `procedure`.
    #[test]
    fn procedure_empty_object() {
        let mut v = base();
        v["procedure"] = json!({});
        assert_eq!(
            Transformation::parse(&v),
            Err(TransformationParseError::ProcedureInvalid)
        );
    }

    /// AC9: rejects missing `preserves`.
    #[test]
    fn preserves_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("preserves");
        assert_eq!(
            Transformation::parse(&v),
            Err(TransformationParseError::PreservesMissing)
        );
    }

    /// AC10: rejects missing `losses`.
    #[test]
    fn losses_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("losses");
        assert_eq!(
            Transformation::parse(&v),
            Err(TransformationParseError::LossesMissing)
        );
    }

    /// AC11: rejects duplicate entries in `preserves`.
    #[test]
    fn preserves_duplicate() {
        let mut v = base();
        v["preserves"] = json!(["x", "x"]);
        assert_eq!(
            Transformation::parse(&v),
            Err(TransformationParseError::PreservesInvalid)
        );
    }

    /// AC11: rejects duplicate entries in `losses`.
    #[test]
    fn losses_duplicate() {
        let mut v = base();
        v["losses"] = json!(["y", "y"]);
        assert_eq!(
            Transformation::parse(&v),
            Err(TransformationParseError::LossesInvalid)
        );
    }

    /// AC11: rejects empty-string entry in `losses`.
    #[test]
    fn losses_contains_empty_string() {
        let mut v = base();
        v["losses"] = json!([""]);
        assert_eq!(
            Transformation::parse(&v),
            Err(TransformationParseError::LossesInvalid)
        );
    }

    /// `preserves` that is not an array is rejected.
    #[test]
    fn preserves_not_array() {
        let mut v = base();
        v["preserves"] = json!("oops");
        assert_eq!(
            Transformation::parse(&v),
            Err(TransformationParseError::PreservesInvalid)
        );
    }

    /// `losses` that is not an array is rejected.
    #[test]
    fn losses_not_array() {
        let mut v = base();
        v["losses"] = json!(42);
        assert_eq!(
            Transformation::parse(&v),
            Err(TransformationParseError::LossesInvalid)
        );
    }
}
