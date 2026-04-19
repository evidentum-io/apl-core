//! APL Bridge parsing and typing rules per `apl-spec.md §7`.
//!
//! A [`Bridge`] describes when claims from two frames MAY be compared. Core
//! bridge validity covers the mandatory fields and typing rules in `§7.2`–`§7.3`.
//! Profile-level applicability (e.g. AI-Eval `bridge_kind` semantics) is layered
//! on top in AI-EVAL-BRIDGE-1.
//!
//! # Critical Invariant (`apl-spec.md §7.4`)
//!
//! A Bridge is **directional** — it licenses `source_frame → target_frame`
//! comparison only. Bilateral comparison requires two bridges.

use std::collections::HashSet;

use serde_json::Value;

use crate::core::hash::{Hash, Reference};
use crate::core::jcs::canonical_hash;

/// An APL Bridge per `apl-spec.md §7`.
///
/// Stores the parsed typed fields plus the original JSON value in [`Bridge::raw`]
/// for canonical-hash recomputation and profile-level extension access (e.g.
/// AI-Eval reads `bridge.raw["bridge_kind"]`).
///
/// # Directionality
///
/// A bridge licenses `source_frame → target_frame` comparison only. Bilateral
/// comparison requires two bridges (`apl-spec.md §7.4`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bridge {
    /// Bridge schema version. MUST be `"0.1"` for this implementation.
    pub version: String,
    /// Reference to the source frame (`apl-spec.md §7.2`). REQUIRED.
    pub source_frame: Reference,
    /// Reference to the target frame (`apl-spec.md §7.2`). REQUIRED.
    pub target_frame: Reference,
    /// Scope of comparison (`apl-spec.md §7.2`, `§7.3`). REQUIRED.
    pub comparison_scope: ComparisonScope,
    /// `assumptions` MUST be present. MAY be an empty array (`§7.3`).
    pub assumptions: Vec<String>,
    /// `losses` MUST be present. MAY be an empty array, but empty MUST NOT
    /// mean "unknown" (`§7.3`). `apl-core` stores empty as `Vec::new()`.
    pub losses: Vec<String>,
    /// Original JSON for canonical-hash recomputation and profile-level
    /// access (e.g. AI-Eval reads `bridge.raw["bridge_kind"]`).
    pub raw: Value,
}

/// `comparison_scope` per `apl-spec.md §7.3`.
///
/// Describes which aspects of the source and target frames are being compared
/// and what the semantic relation between them is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparisonScope {
    /// Source aspects being compared. REQUIRED, non-empty, unique non-empty strings.
    pub source_aspects: Vec<String>,
    /// Target aspects being compared. REQUIRED, non-empty, unique non-empty strings.
    pub target_aspects: Vec<String>,
    /// Semantic relation type. REQUIRED, non-empty string.
    pub relation_type: String,
}

/// Errors that can arise when parsing a [`Bridge`] from JSON.
///
/// Each variant maps to a specific validation rule in `apl-spec.md §7.3`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeParseError {
    /// The root JSON value is not an object.
    BridgeNotObject,

    /// The `version` field is missing.
    VersionMissing,
    /// The `version` field is present but not `"0.1"`. Contains the actual value observed.
    VersionUnsupported {
        /// The version string that was found (or `"<non-string>"` if not a string).
        got: String,
    },

    /// The `source_frame` field is missing.
    SourceFrameMissing,
    /// The `source_frame` field is present but is not a valid Reference Object.
    SourceFrameInvalid,

    /// The `target_frame` field is missing.
    TargetFrameMissing,
    /// The `target_frame` field is present but is not a valid Reference Object.
    TargetFrameInvalid,

    /// The `comparison_scope` field is missing.
    ComparisonScopeMissing,
    /// The `comparison_scope` field is present but is not a JSON object.
    ComparisonScopeNotObject,

    /// The `source_aspects` field inside `comparison_scope` is missing.
    SourceAspectsMissing,
    /// The `source_aspects` field is present but is not a non-empty array of
    /// unique non-empty strings.
    SourceAspectsInvalid,

    /// The `target_aspects` field inside `comparison_scope` is missing.
    TargetAspectsMissing,
    /// The `target_aspects` field is present but is not a non-empty array of
    /// unique non-empty strings.
    TargetAspectsInvalid,

    /// The `relation_type` field inside `comparison_scope` is missing.
    RelationTypeMissing,
    /// The `relation_type` field is present but is not a non-empty string.
    RelationTypeInvalid,

    /// The `assumptions` field is missing.
    AssumptionsMissing,
    /// The `assumptions` field is present but is not an array of unique non-empty strings.
    AssumptionsInvalid,

    /// The `losses` field is missing.
    LossesMissing,
    /// The `losses` field is present but is not an array of unique non-empty strings.
    LossesInvalid,
}

impl Bridge {
    /// Parse a JSON value into a [`Bridge`].
    ///
    /// Enforces all typing rules in `apl-spec.md §7.3`. Does NOT enforce
    /// frame-match, scope-match, or profile-applicability — those live in
    /// RELATION-1 and AI-EVAL-BRIDGE-1.
    ///
    /// # Errors
    ///
    /// Returns a [`BridgeParseError`] variant describing the first violation
    /// encountered.
    ///
    /// # Examples
    ///
    /// ```
    /// use apl_core::core::bridge::Bridge;
    /// use serde_json::json;
    ///
    /// fn h(v: u8) -> String {
    ///     format!("sha256:{}", hex::encode([v; 32]))
    /// }
    ///
    /// let value = json!({
    ///     "version": "0.1",
    ///     "source_frame": { "hash": h(0xaa) },
    ///     "target_frame": { "hash": h(0xbb) },
    ///     "comparison_scope": {
    ///         "source_aspects": ["accuracy"],
    ///         "target_aspects": ["accuracy"],
    ///         "relation_type": "score-delta"
    ///     },
    ///     "assumptions": [],
    ///     "losses": []
    /// });
    ///
    /// let bridge = Bridge::parse(&value).unwrap();
    /// assert_eq!(bridge.version, "0.1");
    /// assert!(bridge.assumptions.is_empty());
    /// assert!(bridge.losses.is_empty());
    /// ```
    pub fn parse(v: &Value) -> Result<Self, BridgeParseError> {
        use BridgeParseError::{
            AssumptionsMissing, ComparisonScopeMissing, LossesMissing, SourceFrameMissing,
            TargetFrameMissing,
        };

        let obj = v.as_object().ok_or(BridgeParseError::BridgeNotObject)?;

        let version_str = obj
            .get("version")
            .ok_or(BridgeParseError::VersionMissing)?
            .as_str()
            .ok_or_else(|| BridgeParseError::VersionUnsupported {
                got: "<non-string>".into(),
            })?;
        if version_str != "0.1" {
            return Err(BridgeParseError::VersionUnsupported {
                got: version_str.to_owned(),
            });
        }

        let source_frame = Reference::parse(obj.get("source_frame").ok_or(SourceFrameMissing)?)
            .map_err(|_| BridgeParseError::SourceFrameInvalid)?;

        let target_frame = Reference::parse(obj.get("target_frame").ok_or(TargetFrameMissing)?)
            .map_err(|_| BridgeParseError::TargetFrameInvalid)?;

        let cs_v = obj.get("comparison_scope").ok_or(ComparisonScopeMissing)?;
        let comparison_scope = parse_comparison_scope(cs_v)?;

        let assumptions = parse_string_array_allow_empty(
            obj.get("assumptions").ok_or(AssumptionsMissing)?,
            BridgeParseError::AssumptionsInvalid,
        )?;

        let losses = parse_string_array_allow_empty(
            obj.get("losses").ok_or(LossesMissing)?,
            BridgeParseError::LossesInvalid,
        )?;

        Ok(Self {
            version: version_str.to_owned(),
            source_frame,
            target_frame,
            comparison_scope,
            assumptions,
            losses,
            raw: v.clone(),
        })
    }

    /// SHA-256 of the JCS-canonical bytes of the original JSON value.
    ///
    /// Deterministic and key-order-independent per `apl-spec.md §4.3`.
    ///
    /// # Examples
    ///
    /// ```
    /// use apl_core::core::bridge::Bridge;
    /// use serde_json::json;
    ///
    /// fn h(v: u8) -> String {
    ///     format!("sha256:{}", hex::encode([v; 32]))
    /// }
    ///
    /// let value = json!({
    ///     "version": "0.1",
    ///     "source_frame": { "hash": h(0xaa) },
    ///     "target_frame": { "hash": h(0xbb) },
    ///     "comparison_scope": {
    ///         "source_aspects": ["accuracy"],
    ///         "target_aspects": ["accuracy"],
    ///         "relation_type": "score-delta"
    ///     },
    ///     "assumptions": [],
    ///     "losses": []
    /// });
    ///
    /// let b1 = Bridge::parse(&value).unwrap();
    /// let b2 = Bridge::parse(&value).unwrap();
    /// assert_eq!(b1.canonical_hash(), b2.canonical_hash());
    /// ```
    #[must_use]
    pub fn canonical_hash(&self) -> Hash {
        canonical_hash(&self.raw)
    }
}

/// Parse a `comparison_scope` object.
fn parse_comparison_scope(v: &Value) -> Result<ComparisonScope, BridgeParseError> {
    let obj = v
        .as_object()
        .ok_or(BridgeParseError::ComparisonScopeNotObject)?;

    let source_aspects = parse_unique_nonempty_string_array(
        obj.get("source_aspects")
            .ok_or(BridgeParseError::SourceAspectsMissing)?,
        BridgeParseError::SourceAspectsInvalid,
    )?;

    let target_aspects = parse_unique_nonempty_string_array(
        obj.get("target_aspects")
            .ok_or(BridgeParseError::TargetAspectsMissing)?,
        BridgeParseError::TargetAspectsInvalid,
    )?;

    let rt_v = obj
        .get("relation_type")
        .ok_or(BridgeParseError::RelationTypeMissing)?;
    let rt = rt_v.as_str().ok_or(BridgeParseError::RelationTypeInvalid)?;
    if rt.is_empty() {
        return Err(BridgeParseError::RelationTypeInvalid);
    }

    Ok(ComparisonScope {
        source_aspects,
        target_aspects,
        relation_type: rt.to_owned(),
    })
}

/// Parse a non-empty array of unique non-empty strings.
///
/// Used for `source_aspects` and `target_aspects` which MUST be non-empty.
fn parse_unique_nonempty_string_array(
    v: &Value,
    err: BridgeParseError,
) -> Result<Vec<String>, BridgeParseError> {
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

/// Parse an array of unique non-empty strings that MAY be empty (`§7.3`).
///
/// Used for `assumptions` and `losses` which MUST be present but MAY be empty
/// arrays. Individual entries, if present, MUST be non-empty and unique.
fn parse_string_array_allow_empty(
    v: &Value,
    err: BridgeParseError,
) -> Result<Vec<String>, BridgeParseError> {
    let arr = v.as_array().ok_or_else(|| err.clone())?;
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

    fn h(v: u8) -> String {
        format!("sha256:{}", hex::encode([v; 32]))
    }

    fn minimal_bridge() -> Value {
        json!({
            "version": "0.1",
            "source_frame": { "hash": h(0xaa) },
            "target_frame": { "hash": h(0xbb) },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        })
    }

    #[test]
    fn accepts_minimal() {
        let b = Bridge::parse(&minimal_bridge()).unwrap();
        assert_eq!(b.version, "0.1");
        assert_eq!(b.source_frame.hash.to_string(), h(0xaa));
        assert_eq!(b.target_frame.hash.to_string(), h(0xbb));
        assert_eq!(b.comparison_scope.relation_type, "score-delta");
        assert!(b.assumptions.is_empty());
        assert!(b.losses.is_empty());
    }

    #[test]
    fn accepts_ai_eval_bridge_kind_extension() {
        let mut v = minimal_bridge();
        v["bridge_kind"] = json!("runner-equivalence");
        let b = Bridge::parse(&v).unwrap();
        // Core does not type bridge_kind; it is preserved in raw.
        assert_eq!(
            b.raw.get("bridge_kind").unwrap(),
            &json!("runner-equivalence")
        );
    }

    #[test]
    fn accepts_multiple_aspects() {
        let mut v = minimal_bridge();
        v["comparison_scope"]["source_aspects"] = json!(["accuracy", "pass-rate"]);
        v["comparison_scope"]["target_aspects"] = json!(["accuracy", "pass-rate"]);
        let b = Bridge::parse(&v).unwrap();
        assert_eq!(b.comparison_scope.source_aspects.len(), 2);
    }

    #[test]
    fn hash_is_deterministic() {
        let b1 = Bridge::parse(&minimal_bridge()).unwrap();
        let b2 = Bridge::parse(&minimal_bridge()).unwrap();
        assert_eq!(b1.canonical_hash(), b2.canonical_hash());
    }

    #[test]
    fn hash_is_key_order_independent() {
        // Build two bridges where the JSON key order differs but content is the same.
        // serde_json with preserve_order maintains insertion order, so we compare
        // canonical_hash which must normalize key ordering via JCS.
        let v1 = json!({
            "version": "0.1",
            "source_frame": { "hash": h(0xaa) },
            "target_frame": { "hash": h(0xbb) },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        // Same content, different top-level key order.
        let v2 = json!({
            "losses": [],
            "assumptions": [],
            "comparison_scope": {
                "relation_type": "score-delta",
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"]
            },
            "target_frame": { "hash": h(0xbb) },
            "source_frame": { "hash": h(0xaa) },
            "version": "0.1"
        });
        let b1 = Bridge::parse(&v1).unwrap();
        let b2 = Bridge::parse(&v2).unwrap();
        assert_eq!(b1.canonical_hash(), b2.canonical_hash());
    }

    #[test]
    fn preserves_aspect_order() {
        let mut v = minimal_bridge();
        v["comparison_scope"]["source_aspects"] = json!(["z-aspect", "a-aspect", "m-aspect"]);
        let b = Bridge::parse(&v).unwrap();
        assert_eq!(
            b.comparison_scope.source_aspects,
            vec!["z-aspect", "a-aspect", "m-aspect"]
        );
    }

    #[test]
    fn accepts_non_empty_assumptions_and_losses() {
        let mut v = minimal_bridge();
        v["assumptions"] = json!(["assumption-a", "assumption-b"]);
        v["losses"] = json!(["loss-x"]);
        let b = Bridge::parse(&v).unwrap();
        assert_eq!(b.assumptions, vec!["assumption-a", "assumption-b"]);
        assert_eq!(b.losses, vec!["loss-x"]);
    }
}

#[cfg(test)]
mod negative_tests {
    use super::*;
    use serde_json::json;

    fn h(v: u8) -> String {
        format!("sha256:{}", hex::encode([v; 32]))
    }

    fn base() -> Value {
        json!({
            "version": "0.1",
            "source_frame": { "hash": h(0xaa) },
            "target_frame": { "hash": h(0xbb) },
            "comparison_scope": {
                "source_aspects": ["a"],
                "target_aspects": ["b"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        })
    }

    #[test]
    fn non_object() {
        assert_eq!(
            Bridge::parse(&json!(42)),
            Err(BridgeParseError::BridgeNotObject)
        );
    }

    #[test]
    fn non_object_array() {
        assert_eq!(
            Bridge::parse(&json!([1, 2, 3])),
            Err(BridgeParseError::BridgeNotObject)
        );
    }

    #[test]
    fn non_object_null() {
        assert_eq!(
            Bridge::parse(&json!(null)),
            Err(BridgeParseError::BridgeNotObject)
        );
    }

    #[test]
    fn version_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("version");
        assert_eq!(Bridge::parse(&v), Err(BridgeParseError::VersionMissing));
    }

    #[test]
    fn version_wrong() {
        let mut v = base();
        v["version"] = json!("0.9");
        assert_eq!(
            Bridge::parse(&v),
            Err(BridgeParseError::VersionUnsupported { got: "0.9".into() })
        );
    }

    #[test]
    fn version_non_string() {
        let mut v = base();
        v["version"] = json!(1);
        assert_eq!(
            Bridge::parse(&v),
            Err(BridgeParseError::VersionUnsupported {
                got: "<non-string>".into()
            })
        );
    }

    #[test]
    fn source_frame_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("source_frame");
        assert_eq!(Bridge::parse(&v), Err(BridgeParseError::SourceFrameMissing));
    }

    #[test]
    fn source_frame_invalid() {
        let mut v = base();
        v["source_frame"] = json!("not-a-reference");
        assert_eq!(Bridge::parse(&v), Err(BridgeParseError::SourceFrameInvalid));
    }

    #[test]
    fn target_frame_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("target_frame");
        assert_eq!(Bridge::parse(&v), Err(BridgeParseError::TargetFrameMissing));
    }

    #[test]
    fn target_frame_invalid() {
        let mut v = base();
        v["target_frame"] = json!("not-a-reference");
        assert_eq!(Bridge::parse(&v), Err(BridgeParseError::TargetFrameInvalid));
    }

    #[test]
    fn comparison_scope_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("comparison_scope");
        assert_eq!(
            Bridge::parse(&v),
            Err(BridgeParseError::ComparisonScopeMissing)
        );
    }

    #[test]
    fn comparison_scope_not_object() {
        let mut v = base();
        v["comparison_scope"] = json!("string");
        assert_eq!(
            Bridge::parse(&v),
            Err(BridgeParseError::ComparisonScopeNotObject)
        );
    }

    #[test]
    fn source_aspects_missing() {
        let mut v = base();
        v["comparison_scope"]
            .as_object_mut()
            .unwrap()
            .remove("source_aspects");
        assert_eq!(
            Bridge::parse(&v),
            Err(BridgeParseError::SourceAspectsMissing)
        );
    }

    #[test]
    fn source_aspects_empty() {
        let mut v = base();
        v["comparison_scope"]["source_aspects"] = json!([]);
        assert_eq!(
            Bridge::parse(&v),
            Err(BridgeParseError::SourceAspectsInvalid)
        );
    }

    #[test]
    fn source_aspects_empty_entry() {
        let mut v = base();
        v["comparison_scope"]["source_aspects"] = json!([""]);
        assert_eq!(
            Bridge::parse(&v),
            Err(BridgeParseError::SourceAspectsInvalid)
        );
    }

    #[test]
    fn source_aspects_duplicate() {
        let mut v = base();
        v["comparison_scope"]["source_aspects"] = json!(["x", "x"]);
        assert_eq!(
            Bridge::parse(&v),
            Err(BridgeParseError::SourceAspectsInvalid)
        );
    }

    #[test]
    fn target_aspects_missing() {
        let mut v = base();
        v["comparison_scope"]
            .as_object_mut()
            .unwrap()
            .remove("target_aspects");
        assert_eq!(
            Bridge::parse(&v),
            Err(BridgeParseError::TargetAspectsMissing)
        );
    }

    #[test]
    fn target_aspects_duplicate() {
        let mut v = base();
        v["comparison_scope"]["target_aspects"] = json!(["x", "x"]);
        assert_eq!(
            Bridge::parse(&v),
            Err(BridgeParseError::TargetAspectsInvalid)
        );
    }

    #[test]
    fn target_aspects_empty_entry() {
        let mut v = base();
        v["comparison_scope"]["target_aspects"] = json!([""]);
        assert_eq!(
            Bridge::parse(&v),
            Err(BridgeParseError::TargetAspectsInvalid)
        );
    }

    #[test]
    fn relation_type_missing() {
        let mut v = base();
        v["comparison_scope"]
            .as_object_mut()
            .unwrap()
            .remove("relation_type");
        assert_eq!(
            Bridge::parse(&v),
            Err(BridgeParseError::RelationTypeMissing)
        );
    }

    #[test]
    fn relation_type_empty() {
        let mut v = base();
        v["comparison_scope"]["relation_type"] = json!("");
        assert_eq!(
            Bridge::parse(&v),
            Err(BridgeParseError::RelationTypeInvalid)
        );
    }

    #[test]
    fn relation_type_non_string() {
        let mut v = base();
        v["comparison_scope"]["relation_type"] = json!(42);
        assert_eq!(
            Bridge::parse(&v),
            Err(BridgeParseError::RelationTypeInvalid)
        );
    }

    #[test]
    fn assumptions_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("assumptions");
        assert_eq!(Bridge::parse(&v), Err(BridgeParseError::AssumptionsMissing));
    }

    #[test]
    fn assumptions_empty_entry() {
        let mut v = base();
        v["assumptions"] = json!([""]);
        assert_eq!(Bridge::parse(&v), Err(BridgeParseError::AssumptionsInvalid));
    }

    #[test]
    fn assumptions_duplicate() {
        let mut v = base();
        v["assumptions"] = json!(["x", "x"]);
        assert_eq!(Bridge::parse(&v), Err(BridgeParseError::AssumptionsInvalid));
    }

    #[test]
    fn losses_missing() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("losses");
        assert_eq!(Bridge::parse(&v), Err(BridgeParseError::LossesMissing));
    }

    #[test]
    fn losses_duplicate() {
        let mut v = base();
        v["losses"] = json!(["x", "x"]);
        assert_eq!(Bridge::parse(&v), Err(BridgeParseError::LossesInvalid));
    }

    #[test]
    fn losses_empty_entry() {
        let mut v = base();
        v["losses"] = json!([""]);
        assert_eq!(Bridge::parse(&v), Err(BridgeParseError::LossesInvalid));
    }
}
