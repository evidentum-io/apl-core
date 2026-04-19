//! `VerifierOutput` and related types per `apl-spec.md §13`.
//!
//! These types carry the result of a single-receipt verification call
//! or a pairwise relation evaluation. All types implement `Serialize`
//! and `Deserialize` with field names and enum values matching the
//! normative JSON shape of `apl-spec.md §13`.

use serde::{Deserialize, Serialize};

use crate::diagnostics::DiagnosticCode;
use crate::failure::FailureClass;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Outcome of APL core verification per `apl-spec.md §13`.
///
/// A receipt either passes all 14 normative checks (`AplValid`) or fails at
/// least one (`AplInvalid`). When `AplInvalid`, `failure_classes` and
/// `diagnostics` carry the full error record.
///
/// # JSON Serialization
///
/// Serializes as `"apl-valid"` or `"apl-invalid"` (kebab-case).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoreOutcome {
    /// All 14 normative checks passed.
    AplValid,
    /// At least one normative check failed.
    AplInvalid,
}

/// Relation-layer outcome per `apl-spec.md §13` and `apl-relation-spec.md §7`.
///
/// Single-receipt verification always returns `RelationNotEvaluated`.
/// Pairwise evaluation returns one of the other variants.
///
/// # JSON Serialization
///
/// Serializes as `"relation-not-evaluated"`, `"same-frame-comparable"`,
/// `"bridged-comparable"`, or `"incomparable"` (kebab-case).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelationOutcome {
    /// Relation layer was not evaluated (single-receipt mode).
    RelationNotEvaluated,
    /// Both receipts reference the same frame and aspects match.
    SameFrameComparable,
    /// A bridge artifact bridges the two receipts' frames.
    BridgedComparable,
    /// The pair is not semantically comparable under the query constraints.
    Incomparable,
}

// ---------------------------------------------------------------------------
// VerifierOutput
// ---------------------------------------------------------------------------

/// Full output of a verification call per `apl-spec.md §13`.
///
/// Produced by single-receipt verification or pairwise evaluation.
///
/// # Field Order
///
/// Fields are declared in the canonical order specified by `apl-spec.md §13`:
/// `core_outcome`, `relation_outcome`, `failure_classes`, `diagnostics`.
/// `serde` emits fields in declaration order, ensuring stable wire output.
///
/// # Invariants
///
/// - `core_outcome == AplValid` implies `failure_classes.is_empty()`.
/// - `core_outcome == AplInvalid` implies `failure_classes` is non-empty.
/// - `relation_outcome` is always present; use `RelationNotEvaluated` for
///   single-receipt mode — never omit the field.
/// - `failure_classes` and `diagnostics` are always present as arrays; empty
///   arrays are emitted as `[]`, never omitted.
/// - Diagnostics are ordered canonically: carrier → claim structure →
///   frame binding → frame kernel → aspect linkage → core outcome →
///   relation hints → transformation declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierOutput {
    /// Core verification outcome.
    pub core_outcome: CoreOutcome,
    /// Relation-layer outcome; always `RelationNotEvaluated` for single-receipt mode.
    pub relation_outcome: RelationOutcome,
    /// Zero or more failure classes; empty iff `core_outcome == AplValid`.
    pub failure_classes: Vec<FailureClass>,
    /// Ordered diagnostic codes per `apl-spec.md §12.3`.
    pub diagnostics: Vec<DiagnosticCode>,
}

impl VerifierOutput {
    /// Serialize to compact JSON per `apl-spec.md §13`.
    ///
    /// Field order matches the normative shape: `core_outcome`,
    /// `relation_outcome`, `failure_classes`, `diagnostics`.
    ///
    /// # Panics
    ///
    /// Cannot panic: `serde_json::to_string` only fails on types with
    /// non-string map keys or custom serializers that return errors; this
    /// type has neither.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|e| unreachable!("VerifierOutput serialization cannot fail: {e}"))
    }

    /// Serialize to pretty-printed JSON, suitable for CLI output.
    ///
    /// # Panics
    ///
    /// Cannot panic for the same reasons as [`Self::to_json`].
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|e| unreachable!("VerifierOutput serialization cannot fail: {e}"))
    }

    /// Parse from JSON. Returns a `serde_json::Error` on unknown field values
    /// (e.g. unrecognized `core_outcome` string) or malformed structure.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the JSON does not match the expected shape or
    /// contains an unknown enum variant.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

// ---------------------------------------------------------------------------
// PairwiseOutput + SideCore
// ---------------------------------------------------------------------------

/// Per-side condensed core result inside [`PairwiseOutput`].
///
/// Carries only the fields that are meaningful at the pairwise level:
/// the binary core outcome and any associated failure classes.
/// Full per-side diagnostics are available by running single-receipt
/// verification separately via `verify_receipt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SideCore {
    /// Core verification outcome for this side.
    pub core_outcome: CoreOutcome,
    /// Failure classes for this side; empty when `core_outcome == AplValid`.
    pub failure_classes: Vec<FailureClass>,
}

/// Output of pairwise relation evaluation per `apl-spec.md §13` and
/// `apl-relation-spec.md §7.8`.
///
/// Produced by `evaluate_relation`. The `left` and `right` fields carry
/// condensed per-side core results. The `relation_outcome` and `diagnostics`
/// fields carry the pairwise relation result.
///
/// # JSON Layout
///
/// ```json
/// {
///   "left":  { "core_outcome": "apl-valid", "failure_classes": [] },
///   "right": { "core_outcome": "apl-valid", "failure_classes": [] },
///   "relation_outcome": "same-frame-comparable",
///   "diagnostics": ["apl-same-frame", "apl-same-frame-aspect-match"]
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairwiseOutput {
    /// Condensed core result for the left receipt.
    pub left: SideCore,
    /// Condensed core result for the right receipt.
    pub right: SideCore,
    /// Pairwise relation outcome.
    pub relation_outcome: RelationOutcome,
    /// Pairwise diagnostics per `apl-relation-spec.md §9`.
    pub diagnostics: Vec<DiagnosticCode>,
}

impl PairwiseOutput {
    /// Serialize to compact JSON.
    ///
    /// # Panics
    ///
    /// Cannot panic: same reasoning as [`VerifierOutput::to_json`].
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|e| unreachable!("PairwiseOutput serialization cannot fail: {e}"))
    }

    /// Serialize to pretty-printed JSON, suitable for CLI output.
    ///
    /// # Panics
    ///
    /// Cannot panic for the same reasons as [`Self::to_json`].
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|e| unreachable!("PairwiseOutput serialization cannot fail: {e}"))
    }

    /// Parse from JSON. Returns a `serde_json::Error` on unknown field values
    /// or malformed structure.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the JSON does not match the expected shape or
    /// contains an unknown enum variant.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics::{
        APL_ASPECT_REF_OUT_OF_FRAME, APL_BRIDGE_APPLICABLE, APL_CROSS_FRAME, APL_FRAME_BOUND,
        APL_FRAME_KERNEL_MISSING, APL_PAIR_LEFT_INVALID, APL_PRESENT, APL_SAME_FRAME,
        APL_SAME_FRAME_ASPECT_MATCH, APL_VALID, CARRIER_INVALID, CARRIER_VALID, FAILURE_FRAME,
        FAILURE_SEMANTIC_LINKAGE,
    };

    // -----------------------------------------------------------------------
    // Basic variant tests (pre-existing)
    // -----------------------------------------------------------------------

    #[test]
    fn core_outcome_variants() {
        assert_ne!(CoreOutcome::AplValid, CoreOutcome::AplInvalid);
        let v = CoreOutcome::AplValid;
        let c = v;
        assert_eq!(v, c);
    }

    #[test]
    fn relation_outcome_variants() {
        assert_ne!(
            RelationOutcome::RelationNotEvaluated,
            RelationOutcome::SameFrameComparable
        );
    }

    #[test]
    fn verifier_output_clone_and_eq() {
        let out = VerifierOutput {
            core_outcome: CoreOutcome::AplValid,
            relation_outcome: RelationOutcome::RelationNotEvaluated,
            failure_classes: Vec::new(),
            diagnostics: vec![CARRIER_VALID, APL_VALID],
        };
        let cloned = out.clone();
        assert_eq!(out, cloned);
    }

    #[test]
    fn verifier_output_debug() {
        let out = VerifierOutput {
            core_outcome: CoreOutcome::AplInvalid,
            relation_outcome: RelationOutcome::RelationNotEvaluated,
            failure_classes: vec![FailureClass::CarrierFailure],
            diagnostics: vec![CARRIER_INVALID],
        };
        let s = format!("{out:?}");
        assert!(s.contains("AplInvalid"));
        assert!(s.contains("CarrierFailure"));
    }

    // -----------------------------------------------------------------------
    // Serialization shape tests (AC1-AC9)
    // -----------------------------------------------------------------------

    #[test]
    fn valid_output_shape() {
        let o = VerifierOutput {
            core_outcome: CoreOutcome::AplValid,
            relation_outcome: RelationOutcome::RelationNotEvaluated,
            failure_classes: vec![],
            diagnostics: vec![CARRIER_VALID, APL_PRESENT, APL_FRAME_BOUND],
        };
        let j = serde_json::to_string(&o).unwrap();
        // Exact shape from apl-spec.md §13.
        let expected = r#"{"core_outcome":"apl-valid","relation_outcome":"relation-not-evaluated","failure_classes":[],"diagnostics":["carrier-valid","apl-present","apl-frame-bound"]}"#;
        assert_eq!(j, expected);
    }

    #[test]
    fn invalid_output_shape_from_spec() {
        let o = VerifierOutput {
            core_outcome: CoreOutcome::AplInvalid,
            relation_outcome: RelationOutcome::RelationNotEvaluated,
            failure_classes: vec![FailureClass::SemanticLinkageFailure],
            diagnostics: vec![FAILURE_SEMANTIC_LINKAGE, APL_ASPECT_REF_OUT_OF_FRAME],
        };
        let j = serde_json::to_string(&o).unwrap();
        let expected = r#"{"core_outcome":"apl-invalid","relation_outcome":"relation-not-evaluated","failure_classes":["semantic-linkage-failure"],"diagnostics":["failure-semantic-linkage","apl-aspect-ref-out-of-frame"]}"#;
        assert_eq!(j, expected);
    }

    #[test]
    fn all_relation_outcomes_serialize_correctly() {
        assert_eq!(
            serde_json::to_string(&RelationOutcome::RelationNotEvaluated).unwrap(),
            r#""relation-not-evaluated""#
        );
        assert_eq!(
            serde_json::to_string(&RelationOutcome::SameFrameComparable).unwrap(),
            r#""same-frame-comparable""#
        );
        assert_eq!(
            serde_json::to_string(&RelationOutcome::BridgedComparable).unwrap(),
            r#""bridged-comparable""#
        );
        assert_eq!(
            serde_json::to_string(&RelationOutcome::Incomparable).unwrap(),
            r#""incomparable""#
        );
    }

    #[test]
    fn empty_arrays_emitted_explicitly() {
        let o = VerifierOutput {
            core_outcome: CoreOutcome::AplValid,
            relation_outcome: RelationOutcome::RelationNotEvaluated,
            failure_classes: vec![],
            diagnostics: vec![],
        };
        let j = serde_json::to_string(&o).unwrap();
        assert!(j.contains(r#""failure_classes":[]"#));
        assert!(j.contains(r#""diagnostics":[]"#));
    }

    #[test]
    fn roundtrip() {
        let o = VerifierOutput {
            core_outcome: CoreOutcome::AplInvalid,
            relation_outcome: RelationOutcome::Incomparable,
            failure_classes: vec![FailureClass::FrameFailure],
            diagnostics: vec![APL_FRAME_KERNEL_MISSING, FAILURE_FRAME],
        };
        let j = serde_json::to_string(&o).unwrap();
        let back: VerifierOutput = serde_json::from_str(&j).unwrap();
        assert_eq!(o, back);
    }

    #[test]
    fn unknown_core_outcome_rejected() {
        let j = r#"{"core_outcome":"apl-unknown","relation_outcome":"relation-not-evaluated","failure_classes":[],"diagnostics":[]}"#;
        assert!(serde_json::from_str::<VerifierOutput>(j).is_err());
    }

    #[test]
    fn core_outcome_apl_valid_serializes_as_kebab() {
        assert_eq!(
            serde_json::to_string(&CoreOutcome::AplValid).unwrap(),
            r#""apl-valid""#
        );
        assert_eq!(
            serde_json::to_string(&CoreOutcome::AplInvalid).unwrap(),
            r#""apl-invalid""#
        );
    }

    #[test]
    fn pretty_print_is_indented_json() {
        let o = VerifierOutput {
            core_outcome: CoreOutcome::AplValid,
            relation_outcome: RelationOutcome::RelationNotEvaluated,
            failure_classes: vec![],
            diagnostics: vec![CARRIER_VALID],
        };
        let pretty = o.to_json_pretty();
        assert!(pretty.contains('\n'));
        assert!(pretty.contains("  "));
    }

    #[test]
    fn to_json_and_from_json_roundtrip() {
        let o = VerifierOutput {
            core_outcome: CoreOutcome::AplValid,
            relation_outcome: RelationOutcome::RelationNotEvaluated,
            failure_classes: vec![],
            diagnostics: vec![CARRIER_VALID],
        };
        let back = VerifierOutput::from_json(&o.to_json()).unwrap();
        assert_eq!(o, back);
    }

    // -----------------------------------------------------------------------
    // PairwiseOutput tests
    // -----------------------------------------------------------------------

    #[test]
    fn same_frame_comparable_shape() {
        let o = PairwiseOutput {
            left: SideCore {
                core_outcome: CoreOutcome::AplValid,
                failure_classes: vec![],
            },
            right: SideCore {
                core_outcome: CoreOutcome::AplValid,
                failure_classes: vec![],
            },
            relation_outcome: RelationOutcome::SameFrameComparable,
            diagnostics: vec![APL_SAME_FRAME, APL_SAME_FRAME_ASPECT_MATCH],
        };
        let j = serde_json::to_string(&o).unwrap();
        let expected = r#"{"left":{"core_outcome":"apl-valid","failure_classes":[]},"right":{"core_outcome":"apl-valid","failure_classes":[]},"relation_outcome":"same-frame-comparable","diagnostics":["apl-same-frame","apl-same-frame-aspect-match"]}"#;
        assert_eq!(j, expected);
    }

    #[test]
    fn bridged_comparable_roundtrip() {
        let o = PairwiseOutput {
            left: SideCore {
                core_outcome: CoreOutcome::AplValid,
                failure_classes: vec![],
            },
            right: SideCore {
                core_outcome: CoreOutcome::AplValid,
                failure_classes: vec![],
            },
            relation_outcome: RelationOutcome::BridgedComparable,
            diagnostics: vec![APL_CROSS_FRAME, APL_BRIDGE_APPLICABLE],
        };
        let j = serde_json::to_string(&o).unwrap();
        let back: PairwiseOutput = serde_json::from_str(&j).unwrap();
        assert_eq!(o, back);
    }

    #[test]
    fn left_invalid_yields_relation_not_evaluated() {
        let o = PairwiseOutput {
            left: SideCore {
                core_outcome: CoreOutcome::AplInvalid,
                failure_classes: vec![FailureClass::SemanticLinkageFailure],
            },
            right: SideCore {
                core_outcome: CoreOutcome::AplValid,
                failure_classes: vec![],
            },
            relation_outcome: RelationOutcome::RelationNotEvaluated,
            diagnostics: vec![APL_PAIR_LEFT_INVALID],
        };
        let j = serde_json::to_string(&o).unwrap();
        assert!(j.contains(r#""relation_outcome":"relation-not-evaluated""#));
        assert!(j.contains(r#""apl-pair-left-invalid""#));
    }
}
