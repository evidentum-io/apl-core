//! APL Frame parsing, kernel validation and typing rules per `apl-spec.md §6`.
//!
//! A [`Frame`] is the resolved JSON artifact identified by a `frame_ref.hash`.
//! [`Frame::parse`] enforces the mandatory kernel (`§6.1`) and typing rules
//! (`§6.2`), and exposes [`Frame::canonical_hash`] so resolver-side code can
//! verify `§9.5` ("hash of resolved frame MUST match pinned hash").
//!
//! # Mandatory Kernel (`§6.1`)
//!
//! Every frame MUST contain:
//!
//! - `version`
//! - `observer`
//! - `aspect`
//! - `invariance`
//! - `exclusions`
//!
//! Plus **at least one of** `procedure` OR `instrument` (disjunction).
//!
//! Plus **at least one of** `scope` OR `resolution` (disjunction).

use std::collections::HashSet;

use serde_json::Value;

use crate::core::{
    hash::{Hash, Reference},
    jcs::canonical_hash,
};

/// A parsed APL Frame per `apl-spec.md §6`.
///
/// Holds typed kernel fields plus the original [`serde_json::Value`]. The raw
/// value is retained for:
///
/// - [`Frame::canonical_hash`] recomputation (`§9.5`)
/// - profile-level inspection of additional fields
/// - `extends` composition (outside v0.1 scope; placeholder)
///
/// # Example
///
/// ```
/// use serde_json::json;
/// use apl_core::core::frame::{Frame, Observer};
///
/// let v = json!({
///     "version": "0.1",
///     "observer": "acme-eval-runner",
///     "procedure": "benchmark-run",
///     "aspect": ["accuracy"],
///     "scope": "mmlu/dev",
///     "invariance": ["JSON serialization of score object"],
///     "exclusions": ["no claim about out-of-distribution behavior"]
/// });
///
/// let frame = Frame::parse(&v).unwrap();
/// assert_eq!(frame.version, "0.1");
/// assert!(matches!(frame.observer, Observer::String(ref s) if s == "acme-eval-runner"));
/// assert!(frame.has_aspect("accuracy"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Protocol version; always `"0.1"` in v0.1.
    pub version: String,
    /// Who or what made the observation (`§6.2`).
    pub observer: Observer,
    /// Non-empty list of unique aspect identifiers (`§6.2`).
    pub aspect: Vec<String>,
    /// Non-empty list of unique invariance statements (`§6.2`).
    pub invariance: Vec<String>,
    /// Non-empty list of unique exclusion statements (`§6.2`).
    pub exclusions: Vec<String>,
    /// Optional procedure description; at least one of `procedure` / `instrument` MUST be present.
    pub procedure: Option<StringOrObject>,
    /// Optional instrument description; at least one of `procedure` / `instrument` MUST be present.
    pub instrument: Option<StringOrObject>,
    /// Optional scope description; at least one of `scope` / `resolution` MUST be present.
    pub scope: Option<StringOrObject>,
    /// Optional resolution description; at least one of `scope` / `resolution` MUST be present.
    pub resolution: Option<StringOrObject>,
    /// Optional parent-frame reference for composition hints (`§6.5`).
    ///
    /// v0.1 parses the reference but does NOT flatten inherited fields.
    pub extends: Option<Reference>,
    /// Original JSON value. Used for [`Frame::canonical_hash`] recomputation.
    pub raw: Value,
}

/// The `observer` field of a frame (`apl-spec.md §6.2`).
///
/// Observer MAY be a non-empty JSON string or a non-empty JSON object.
/// A dedicated enum (rather than reusing [`StringOrObject`]) makes observer's
/// special role in APL's identity story visible in the AST (`apl-spec.md §18.2`).
///
/// # Example
///
/// ```
/// use serde_json::json;
/// use apl_core::core::frame::{Frame, Observer};
///
/// let v = json!({
///     "version": "0.1",
///     "observer": { "id": "camera-01", "org": "reuters" },
///     "instrument": { "sensor": "sony-a1" },
///     "aspect": ["scene-light-capture"],
///     "resolution": { "format": "bayer-raw" },
///     "invariance": ["lossless-file-relocation"],
///     "exclusions": ["no-claim-about-denoised-output"]
/// });
///
/// let frame = Frame::parse(&v).unwrap();
/// assert!(matches!(frame.observer, Observer::Object(_)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observer {
    /// Non-empty string observer.
    String(String),
    /// Non-empty object observer.
    Object(serde_json::Map<String, Value>),
}

/// A generic kernel field value that MAY be either a non-empty string or a
/// non-empty object (`apl-spec.md §6.2`).
///
/// Used for `procedure`, `instrument`, `scope`, and `resolution`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringOrObject {
    /// Non-empty string value.
    String(String),
    /// Non-empty object value.
    Object(serde_json::Map<String, Value>),
}

/// Errors produced by [`Frame::parse`], mapping one-to-one to the invalidity
/// bullets in `apl-spec.md §10.4`.
///
/// Every variant is intentionally distinct so callers can react precisely to
/// whichever structural constraint was violated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameParseError {
    /// Frame root is not a JSON object (`§10.4` catch-all for "frame kernel missing").
    FrameNotObject,

    /// `frame.version` key is absent.
    FrameVersionMissing,

    /// `frame.version` is present but its value is not the string `"0.1"` (`§10.4`).
    FrameVersionUnsupported {
        /// The actual value that was found.
        got: String,
    },

    /// `frame.observer` is absent, or is an empty string, or is an empty object,
    /// or is any other non-string/non-object type (`§10.4`).
    FrameObserverInvalid,

    /// `frame.aspect` is absent, is not an array, is empty, contains a non-string
    /// entry, contains an empty-string entry, or contains a duplicate (`§10.4`).
    FrameAspectInvalid,

    /// `frame.invariance` fails the same rules as `aspect` (`§10.4`).
    FrameInvarianceInvalid,

    /// `frame.exclusions` fails the same rules as `aspect` (`§10.4`).
    FrameExclusionsInvalid,

    /// A kernel field (`procedure`, `instrument`, `scope`, or `resolution`) is
    /// present but is not a non-empty string or non-empty object (`§6.2`, `§10.4`).
    FrameKernelValueInvalid,

    /// Both `procedure` and `instrument` are absent (`§10.4`).
    FrameProcedureOrInstrumentMissing,

    /// Both `scope` and `resolution` are absent (`§10.4`).
    FrameScopeOrResolutionMissing,

    /// `extends` is present but is not a valid Reference Object (`§6.5`).
    FrameExtendsInvalid,
}

impl std::fmt::Display for FrameParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrameNotObject => write!(f, "frame is not a JSON object"),
            Self::FrameVersionMissing => write!(f, "frame.version is missing"),
            Self::FrameVersionUnsupported { got } => {
                write!(
                    f,
                    "frame.version unsupported: got \"{got}\", expected \"0.1\""
                )
            }
            Self::FrameObserverInvalid => {
                write!(
                    f,
                    "frame.observer is missing or invalid \
                     (must be non-empty string or non-empty object)"
                )
            }
            Self::FrameAspectInvalid => {
                write!(
                    f,
                    "frame.aspect is missing, empty, or contains invalid/duplicate entries"
                )
            }
            Self::FrameInvarianceInvalid => {
                write!(
                    f,
                    "frame.invariance is missing, empty, or contains invalid/duplicate entries"
                )
            }
            Self::FrameExclusionsInvalid => {
                write!(
                    f,
                    "frame.exclusions is missing, empty, or contains invalid/duplicate entries"
                )
            }
            Self::FrameKernelValueInvalid => {
                write!(
                    f,
                    "kernel field value must be a non-empty string or non-empty object"
                )
            }
            Self::FrameProcedureOrInstrumentMissing => {
                write!(
                    f,
                    "at least one of frame.procedure or frame.instrument must be present"
                )
            }
            Self::FrameScopeOrResolutionMissing => {
                write!(
                    f,
                    "at least one of frame.scope or frame.resolution must be present"
                )
            }
            Self::FrameExtendsInvalid => {
                write!(
                    f,
                    "frame.extends is present but is not a valid Reference Object"
                )
            }
        }
    }
}

impl std::error::Error for FrameParseError {}

impl Frame {
    /// Parse a JSON value into a [`Frame`].
    ///
    /// Performs all structural and kernel checks from `apl-spec.md §6.2` and
    /// maps every failure in `§10.4` to a distinct [`FrameParseError`] variant.
    ///
    /// # Errors
    ///
    /// Returns [`FrameParseError`] if any structural or kernel constraint is violated.
    ///
    /// # Example
    ///
    /// ```
    /// use serde_json::json;
    /// use apl_core::core::frame::{Frame, FrameParseError};
    ///
    /// // Non-object input is rejected
    /// assert_eq!(Frame::parse(&json!(42)), Err(FrameParseError::FrameNotObject));
    ///
    /// // Wrong version is rejected
    /// let v = json!({
    ///     "version": "0.2",
    ///     "observer": "o",
    ///     "procedure": "p",
    ///     "aspect": ["a"],
    ///     "scope": "s",
    ///     "invariance": ["i"],
    ///     "exclusions": ["e"]
    /// });
    /// assert_eq!(
    ///     Frame::parse(&v),
    ///     Err(FrameParseError::FrameVersionUnsupported { got: "0.2".into() })
    /// );
    /// ```
    pub fn parse(v: &Value) -> Result<Self, FrameParseError> {
        use FrameParseError::{
            FrameExtendsInvalid, FrameNotObject, FrameObserverInvalid, FrameVersionMissing,
            FrameVersionUnsupported,
        };

        let obj = v.as_object().ok_or(FrameNotObject)?;

        // version (§6.2)
        let version_v = obj.get("version").ok_or(FrameVersionMissing)?;
        let version_str = version_v.as_str().ok_or_else(|| FrameVersionUnsupported {
            got: "<non-string>".into(),
        })?;
        if version_str != "0.1" {
            return Err(FrameVersionUnsupported {
                got: version_str.to_owned(),
            });
        }

        // observer (§6.2)
        let observer = parse_observer(obj.get("observer").ok_or(FrameObserverInvalid)?)?;

        // aspect / invariance / exclusions (§6.2)
        let aspect = parse_unique_string_array(
            obj.get("aspect")
                .ok_or(FrameParseError::FrameAspectInvalid)?,
            FrameParseError::FrameAspectInvalid,
        )?;
        let invariance = parse_unique_string_array(
            obj.get("invariance")
                .ok_or(FrameParseError::FrameInvarianceInvalid)?,
            FrameParseError::FrameInvarianceInvalid,
        )?;
        let exclusions = parse_unique_string_array(
            obj.get("exclusions")
                .ok_or(FrameParseError::FrameExclusionsInvalid)?,
            FrameParseError::FrameExclusionsInvalid,
        )?;

        // procedure / instrument — at least one required (§6.2 disjunction)
        let procedure = parse_optional_string_or_object(obj.get("procedure"))?;
        let instrument = parse_optional_string_or_object(obj.get("instrument"))?;
        if procedure.is_none() && instrument.is_none() {
            return Err(FrameParseError::FrameProcedureOrInstrumentMissing);
        }

        // scope / resolution — at least one required (§6.2 disjunction)
        let scope = parse_optional_string_or_object(obj.get("scope"))?;
        let resolution = parse_optional_string_or_object(obj.get("resolution"))?;
        if scope.is_none() && resolution.is_none() {
            return Err(FrameParseError::FrameScopeOrResolutionMissing);
        }

        // extends (§6.5) — optional Reference Object; null treated as absent
        let extends = match obj.get("extends") {
            None | Some(Value::Null) => None,
            Some(val) => Some(Reference::parse(val).map_err(|_| FrameExtendsInvalid)?),
        };

        Ok(Self {
            version: version_str.to_owned(),
            observer,
            aspect,
            invariance,
            exclusions,
            procedure,
            instrument,
            scope,
            resolution,
            extends,
            raw: v.clone(),
        })
    }

    /// Compute the SHA-256 of the JCS-canonical bytes of the frame's original JSON value.
    ///
    /// This is the identity check required by `apl-spec.md §9.5`:
    /// "hash of resolved frame MUST match pinned hash".
    ///
    /// The hash is computed from [`Frame::raw`] (the value as returned by the
    /// resolver) rather than from a reconstruction of typed fields, so that any
    /// unknown fields present in the original document are preserved in the hash.
    ///
    /// # Example
    ///
    /// ```
    /// use serde_json::json;
    /// use apl_core::core::frame::Frame;
    ///
    /// let a = json!({
    ///     "version": "0.1", "observer": "o", "procedure": "p",
    ///     "aspect": ["a"], "scope": "s",
    ///     "invariance": ["i"], "exclusions": ["e"]
    /// });
    /// let b = json!({
    ///     "exclusions": ["e"], "invariance": ["i"],
    ///     "scope": "s", "aspect": ["a"],
    ///     "procedure": "p", "observer": "o", "version": "0.1"
    /// });
    /// let f_a = Frame::parse(&a).unwrap();
    /// let f_b = Frame::parse(&b).unwrap();
    /// // JCS sorts keys before hashing, so key order is irrelevant.
    /// assert_eq!(f_a.canonical_hash(), f_b.canonical_hash());
    /// ```
    #[must_use]
    pub fn canonical_hash(&self) -> Hash {
        canonical_hash(&self.raw)
    }

    /// Returns `true` if `aspect` is present in [`Frame::aspect`].
    ///
    /// # Example
    ///
    /// ```
    /// use serde_json::json;
    /// use apl_core::core::frame::Frame;
    ///
    /// let v = json!({
    ///     "version": "0.1", "observer": "o", "procedure": "p",
    ///     "aspect": ["accuracy", "pass-rate"], "scope": "s",
    ///     "invariance": ["i"], "exclusions": ["e"]
    /// });
    /// let f = Frame::parse(&v).unwrap();
    /// assert!(f.has_aspect("accuracy"));
    /// assert!(f.has_aspect("pass-rate"));
    /// assert!(!f.has_aspect("judge-score"));
    /// ```
    #[must_use]
    pub fn has_aspect(&self, aspect: &str) -> bool {
        self.aspect.iter().any(|a| a == aspect)
    }
}

/// Parse `observer` from its JSON value per `§6.2`.
fn parse_observer(v: &Value) -> Result<Observer, FrameParseError> {
    match v {
        Value::String(s) if !s.is_empty() => Ok(Observer::String(s.clone())),
        Value::Object(m) if !m.is_empty() => Ok(Observer::Object(m.clone())),
        _ => Err(FrameParseError::FrameObserverInvalid),
    }
}

/// Parse an optional kernel field that MUST be either a non-empty string or a
/// non-empty object when present (`§6.2`).
///
/// `None` and JSON `null` are treated as absent (returns `Ok(None)`).
fn parse_optional_string_or_object(
    v: Option<&Value>,
) -> Result<Option<StringOrObject>, FrameParseError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if !s.is_empty() => Ok(Some(StringOrObject::String(s.clone()))),
        Some(Value::Object(m)) if !m.is_empty() => Ok(Some(StringOrObject::Object(m.clone()))),
        _ => Err(FrameParseError::FrameKernelValueInvalid),
    }
}

/// Parse a non-empty array of unique non-empty strings (`§6.2`).
///
/// Returns `err` (cloned) on any violation: not-an-array, empty array,
/// non-string element, empty-string element, or duplicate element.
fn parse_unique_string_array(
    v: &Value,
    err: FrameParseError,
) -> Result<Vec<String>, FrameParseError> {
    let arr = v.as_array().ok_or_else(|| err.clone())?;
    if arr.is_empty() {
        return Err(err);
    }
    let mut out = Vec::with_capacity(arr.len());
    let mut seen = HashSet::new();
    for item in arr {
        let s = item.as_str().ok_or_else(|| err.clone())?;
        if s.is_empty() {
            return Err(err.clone());
        }
        if !seen.insert(s.to_owned()) {
            return Err(err.clone());
        }
        out.push(s.to_owned());
    }
    Ok(out)
}

#[cfg(test)]
mod positive_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ai_eval_example_from_spec_14_2() {
        let v = json!({
            "version": "0.1",
            "observer": "acme-eval-runner",
            "procedure": "benchmark-run",
            "aspect": ["accuracy"],
            "scope": "mmlu/dev",
            "invariance": ["JSON serialization of score object"],
            "exclusions": [
                "no claim about out-of-distribution behavior",
                "no claim about deployment safety"
            ]
        });
        let f = Frame::parse(&v).unwrap();
        assert_eq!(f.version, "0.1");
        assert!(matches!(f.observer, Observer::String(ref s) if s == "acme-eval-runner"));
        assert_eq!(f.aspect, vec!["accuracy".to_owned()]);
        assert!(f.procedure.is_some());
        assert!(f.scope.is_some());
        assert!(f.instrument.is_none());
        assert!(f.resolution.is_none());
    }

    #[test]
    fn photojournalism_raw_sensor_from_kernel_stress_1_1() {
        let v = json!({
            "version": "0.1",
            "observer": {
                "id": "reuters-camera-17",
                "organization": "reuters"
            },
            "instrument": {
                "sensor": "sony-a1",
                "lens": "24-70mm-f2.8"
            },
            "aspect": ["scene-light-capture"],
            "resolution": {
                "format": "bayer-raw",
                "bit_depth": 14
            },
            "invariance": ["lossless-file-relocation", "container-preserving-copy"],
            "exclusions": [
                "no-claim-about-denoised-output",
                "no-claim-about-color-graded-derivatives"
            ]
        });
        let f = Frame::parse(&v).unwrap();
        assert!(matches!(f.observer, Observer::Object(_)));
        assert!(f.instrument.is_some());
        assert!(f.procedure.is_none());
        assert!(f.resolution.is_some());
        assert!(f.scope.is_none());
    }

    #[test]
    fn scientific_measurement_spectrometer_from_kernel_stress_2_1() {
        let v = json!({
            "version": "0.1",
            "observer": {
                "lab": "acme-water-lab",
                "operator_role": "batch-runner"
            },
            "procedure": {
                "protocol_id": "trace-lead-assay-v3",
                "calibration_id": "cal-2026-04-17"
            },
            "instrument": {
                "instrument_id": "icp-ms-07"
            },
            "aspect": ["compound-concentration"],
            "scope": {
                "sample_matrix": "water",
                "analyte": "lead",
                "batch": "042"
            },
            "resolution": {
                "limit_of_quantification": "0.01-ppm"
            },
            "invariance": ["unit-preserving-result-serialization"],
            "exclusions": ["no-claim-about-causality", "no-claim-outside-declared-protocol"]
        });
        let f = Frame::parse(&v).unwrap();
        assert!(f.procedure.is_some() && f.instrument.is_some());
        assert!(f.scope.is_some() && f.resolution.is_some());
    }

    #[test]
    fn canonical_hash_is_deterministic() {
        let v = json!({
            "version": "0.1",
            "observer": "o",
            "procedure": "p",
            "aspect": ["a"],
            "scope": "s",
            "invariance": ["i"],
            "exclusions": ["e"]
        });
        let f = Frame::parse(&v).unwrap();
        assert_eq!(f.canonical_hash(), f.canonical_hash());
    }

    #[test]
    fn canonical_hash_is_key_order_independent() {
        let a = json!({
            "version": "0.1", "observer": "o", "procedure": "p",
            "aspect": ["a"], "scope": "s",
            "invariance": ["i"], "exclusions": ["e"]
        });
        let b = json!({
            "exclusions": ["e"], "invariance": ["i"],
            "scope": "s", "aspect": ["a"],
            "procedure": "p", "observer": "o", "version": "0.1"
        });
        let f_a = Frame::parse(&a).unwrap();
        let f_b = Frame::parse(&b).unwrap();
        assert_eq!(f_a.canonical_hash(), f_b.canonical_hash());
    }

    #[test]
    fn has_aspect_returns_true_for_contained() {
        let v = json!({
            "version": "0.1", "observer": "o", "procedure": "p",
            "aspect": ["accuracy", "pass-rate"], "scope": "s",
            "invariance": ["i"], "exclusions": ["e"]
        });
        let f = Frame::parse(&v).unwrap();
        assert!(f.has_aspect("accuracy"));
        assert!(f.has_aspect("pass-rate"));
        assert!(!f.has_aspect("judge-score"));
    }

    #[test]
    fn extends_reference_accepted() {
        let v = json!({
            "version": "0.1", "observer": "o", "procedure": "p",
            "aspect": ["a"], "scope": "s",
            "invariance": ["i"], "exclusions": ["e"],
            "extends": { "hash": format!("sha256:{}", "0".repeat(64)) }
        });
        let f = Frame::parse(&v).unwrap();
        assert!(f.extends.is_some());
    }

    #[test]
    fn only_procedure_with_scope_accepted() {
        let v = json!({
            "version": "0.1", "observer": "o",
            "procedure": "p",
            "aspect": ["a"], "scope": "s",
            "invariance": ["i"], "exclusions": ["e"]
        });
        assert!(Frame::parse(&v).is_ok());
    }

    #[test]
    fn only_instrument_with_resolution_accepted() {
        let v = json!({
            "version": "0.1", "observer": "o",
            "instrument": "i",
            "aspect": ["a"], "resolution": "r",
            "invariance": ["inv"], "exclusions": ["ex"]
        });
        assert!(Frame::parse(&v).is_ok());
    }

    #[test]
    fn both_procedure_and_instrument_both_scope_and_resolution_accepted() {
        let v = json!({
            "version": "0.1", "observer": "o",
            "procedure": "p", "instrument": "i",
            "aspect": ["a"],
            "scope": "s", "resolution": "r",
            "invariance": ["inv"], "exclusions": ["ex"]
        });
        assert!(Frame::parse(&v).is_ok());
    }
}

#[cfg(test)]
mod negative_tests {
    use super::*;
    use serde_json::json;

    fn base() -> serde_json::Value {
        json!({
            "version": "0.1",
            "observer": "o",
            "procedure": "p",
            "aspect": ["a"],
            "scope": "s",
            "invariance": ["i"],
            "exclusions": ["e"]
        })
    }

    #[test]
    fn non_object_root() {
        assert_eq!(
            Frame::parse(&json!(42)),
            Err(FrameParseError::FrameNotObject)
        );
    }

    #[test]
    fn version_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("version");
        assert_eq!(Frame::parse(&v), Err(FrameParseError::FrameVersionMissing));
    }

    #[test]
    fn version_wrong() {
        let mut v = base();
        v["version"] = json!("0.2");
        assert_eq!(
            Frame::parse(&v),
            Err(FrameParseError::FrameVersionUnsupported { got: "0.2".into() })
        );
    }

    #[test]
    fn observer_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("observer");
        assert_eq!(Frame::parse(&v), Err(FrameParseError::FrameObserverInvalid));
    }

    #[test]
    fn observer_empty_string() {
        let mut v = base();
        v["observer"] = json!("");
        assert_eq!(Frame::parse(&v), Err(FrameParseError::FrameObserverInvalid));
    }

    #[test]
    fn observer_empty_object() {
        let mut v = base();
        v["observer"] = json!({});
        assert_eq!(Frame::parse(&v), Err(FrameParseError::FrameObserverInvalid));
    }

    #[test]
    fn observer_integer() {
        let mut v = base();
        v["observer"] = json!(42);
        assert_eq!(Frame::parse(&v), Err(FrameParseError::FrameObserverInvalid));
    }

    #[test]
    fn aspect_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("aspect");
        assert_eq!(Frame::parse(&v), Err(FrameParseError::FrameAspectInvalid));
    }

    #[test]
    fn aspect_empty() {
        let mut v = base();
        v["aspect"] = json!([]);
        assert_eq!(Frame::parse(&v), Err(FrameParseError::FrameAspectInvalid));
    }

    #[test]
    fn aspect_duplicate() {
        let mut v = base();
        v["aspect"] = json!(["x", "x"]);
        assert_eq!(Frame::parse(&v), Err(FrameParseError::FrameAspectInvalid));
    }

    #[test]
    fn aspect_empty_entry() {
        let mut v = base();
        v["aspect"] = json!(["a", ""]);
        assert_eq!(Frame::parse(&v), Err(FrameParseError::FrameAspectInvalid));
    }

    #[test]
    fn aspect_non_string_entry() {
        let mut v = base();
        v["aspect"] = json!(["a", 1]);
        assert_eq!(Frame::parse(&v), Err(FrameParseError::FrameAspectInvalid));
    }

    #[test]
    fn invariance_empty() {
        let mut v = base();
        v["invariance"] = json!([]);
        assert_eq!(
            Frame::parse(&v),
            Err(FrameParseError::FrameInvarianceInvalid)
        );
    }

    #[test]
    fn exclusions_empty() {
        let mut v = base();
        v["exclusions"] = json!([]);
        assert_eq!(
            Frame::parse(&v),
            Err(FrameParseError::FrameExclusionsInvalid)
        );
    }

    #[test]
    fn procedure_and_instrument_both_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("procedure");
        assert_eq!(
            Frame::parse(&v),
            Err(FrameParseError::FrameProcedureOrInstrumentMissing)
        );
    }

    #[test]
    fn scope_and_resolution_both_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("scope");
        assert_eq!(
            Frame::parse(&v),
            Err(FrameParseError::FrameScopeOrResolutionMissing)
        );
    }

    #[test]
    fn procedure_empty_string() {
        let mut v = base();
        v["procedure"] = json!("");
        assert_eq!(
            Frame::parse(&v),
            Err(FrameParseError::FrameKernelValueInvalid)
        );
    }

    #[test]
    fn scope_empty_object() {
        let mut v = base();
        v["scope"] = json!({});
        assert_eq!(
            Frame::parse(&v),
            Err(FrameParseError::FrameKernelValueInvalid)
        );
    }

    #[test]
    fn extends_invalid_reference() {
        let mut v = base();
        v["extends"] = json!("not-a-reference");
        assert_eq!(Frame::parse(&v), Err(FrameParseError::FrameExtendsInvalid));
    }
}

#[cfg(test)]
mod hash_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn two_different_frames_have_different_hashes() {
        let a = Frame::parse(&json!({
            "version": "0.1", "observer": "a", "procedure": "p",
            "aspect": ["x"], "scope": "s",
            "invariance": ["i"], "exclusions": ["e"]
        }))
        .unwrap();
        let b = Frame::parse(&json!({
            "version": "0.1", "observer": "b", "procedure": "p",
            "aspect": ["x"], "scope": "s",
            "invariance": ["i"], "exclusions": ["e"]
        }))
        .unwrap();
        assert_ne!(a.canonical_hash(), b.canonical_hash());
    }
}

#[cfg(test)]
mod error_display_tests {
    use super::*;
    use serde_json::json;

    // ---- std::error::Error impl ----

    #[test]
    fn frame_parse_error_implements_std_error() {
        let err: &dyn std::error::Error = &FrameParseError::FrameNotObject;
        // Simply obtaining a reference to a dyn Error proves the impl exists.
        let msg = err.to_string();
        assert!(!msg.is_empty());
    }

    // ---- Display: every variant ----

    #[test]
    fn display_frame_not_object() {
        let msg = format!("{}", FrameParseError::FrameNotObject);
        assert!(!msg.is_empty());
        assert!(
            msg.contains("not a JSON object"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn display_frame_version_missing() {
        let msg = format!("{}", FrameParseError::FrameVersionMissing);
        assert!(!msg.is_empty());
        assert!(msg.contains("version"), "unexpected message: {msg}");
    }

    #[test]
    fn display_frame_version_unsupported_contains_got_value() {
        let err = FrameParseError::FrameVersionUnsupported { got: "9.9".into() };
        let msg = format!("{err}");
        assert!(!msg.is_empty());
        assert!(msg.contains("9.9"), "unexpected message: {msg}");
    }

    #[test]
    fn display_frame_observer_invalid() {
        let msg = format!("{}", FrameParseError::FrameObserverInvalid);
        assert!(!msg.is_empty());
        assert!(msg.contains("observer"), "unexpected message: {msg}");
    }

    #[test]
    fn display_frame_aspect_invalid() {
        let msg = format!("{}", FrameParseError::FrameAspectInvalid);
        assert!(!msg.is_empty());
        assert!(msg.contains("aspect"), "unexpected message: {msg}");
    }

    #[test]
    fn display_frame_invariance_invalid() {
        let msg = format!("{}", FrameParseError::FrameInvarianceInvalid);
        assert!(!msg.is_empty());
        assert!(msg.contains("invariance"), "unexpected message: {msg}");
    }

    #[test]
    fn display_frame_exclusions_invalid() {
        let msg = format!("{}", FrameParseError::FrameExclusionsInvalid);
        assert!(!msg.is_empty());
        assert!(msg.contains("exclusions"), "unexpected message: {msg}");
    }

    #[test]
    fn display_frame_kernel_value_invalid() {
        let msg = format!("{}", FrameParseError::FrameKernelValueInvalid);
        assert!(!msg.is_empty());
        assert!(msg.contains("kernel"), "unexpected message: {msg}");
    }

    #[test]
    fn display_frame_procedure_or_instrument_missing() {
        let msg = format!("{}", FrameParseError::FrameProcedureOrInstrumentMissing);
        assert!(!msg.is_empty());
        assert!(
            msg.contains("procedure") || msg.contains("instrument"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn display_frame_scope_or_resolution_missing() {
        let msg = format!("{}", FrameParseError::FrameScopeOrResolutionMissing);
        assert!(!msg.is_empty());
        assert!(
            msg.contains("scope") || msg.contains("resolution"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn display_frame_extends_invalid() {
        let msg = format!("{}", FrameParseError::FrameExtendsInvalid);
        assert!(!msg.is_empty());
        assert!(msg.contains("extends"), "unexpected message: {msg}");
    }

    // ---- Uncovered parse path: version field is non-string JSON value ----

    #[test]
    fn version_non_string_json_value_yields_unsupported_with_non_string_tag() {
        // When `version` is a JSON number (not a string), the parser cannot call
        // `.as_str()` and falls back to the `<non-string>` sentinel (lines 291-293).
        let v = json!({
            "version": 1,
            "observer": "o",
            "procedure": "p",
            "aspect": ["a"],
            "scope": "s",
            "invariance": ["i"],
            "exclusions": ["e"]
        });
        let err = Frame::parse(&v).unwrap_err();
        assert_eq!(
            err,
            FrameParseError::FrameVersionUnsupported {
                got: "<non-string>".into()
            }
        );
        // The Display message must also contain the sentinel value.
        let msg = format!("{err}");
        assert!(msg.contains("<non-string>"), "unexpected message: {msg}");
    }
}
