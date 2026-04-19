//! `VerifierOutput` and related types per `apl-spec.md §13`.
//!
//! These types carry the result of a single-receipt verification call
//! (`CORE-VERIFY-1`) or a pairwise relation evaluation (`RELATION-1`).

use crate::diagnostics::DiagnosticCode;
use crate::failure::FailureClass;

/// Outcome of APL core verification per `apl-spec.md §13`.
///
/// A receipt either passes all 14 normative checks (`AplValid`) or fails at
/// least one (`AplInvalid`). When `AplInvalid`, `failure_classes` and
/// `diagnostics` carry the full error record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Full output of a verification call per `apl-spec.md §13`.
///
/// Produced by [`crate::core::verify::verify_receipt`] (single-receipt)
/// or by `RELATION-1` (pairwise).
///
/// # Invariants
///
/// - `core_outcome == AplValid` implies `failure_classes.is_empty()`.
/// - `core_outcome == AplInvalid` implies `failure_classes` is non-empty.
/// - Diagnostics are ordered canonically: carrier → claim structure →
///   frame binding → frame kernel → aspect linkage → core outcome →
///   relation hints → transformation declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics::{APL_VALID, CARRIER_INVALID, CARRIER_VALID};

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
}
