//! Opaque proof token produced by a successful CORE-VERIFY-1 run.
//!
//! The only way to obtain a [`VerifiedReceipt`] is via [`crate::core::verify::verify_receipt`].
//! External callers cannot construct one directly because all fields are private.
//! This makes [`crate::core::evaluate::ReceiptInput::Prevalidated`] unforgeable
//! at the type-system level for Core validity.
//!
//! # Profile Conformance
//!
//! A `VerifiedReceipt` proves that the receipt passed CORE-VERIFY-1. It does NOT
//! prove profile conformance. When [`crate::core::evaluate::evaluate_relation`] is
//! invoked with an active profile, that profile's per-side hooks (`check_claim`,
//! `check_frame`, `cross_check`) are re-run on both sides at pairwise time,
//! regardless of which profile (if any) was supplied when the receipt was verified.

use crate::core::claim::Claim;
use crate::core::frame::Frame;
use crate::core::output::VerifierOutput;

/// Opaque proof that a receipt passed CORE-VERIFY-1.
///
/// The only way to obtain a `VerifiedReceipt` is via `verify_receipt` (its
/// variant that returns `(VerifierOutput, Option<VerifiedReceipt>)`). External
/// callers cannot construct one directly; all inner fields are private. This
/// makes `ReceiptInput::Prevalidated` unforgeable at the type-system level for
/// Core validity.
///
/// This token does NOT prove profile conformance. If `evaluate_relation` is
/// invoked with an active profile, that profile's per-side hooks will be
/// re-run on both sides at pairwise time, regardless of which profile (if any)
/// was supplied when the receipt was verified.
#[derive(Debug, Clone)]
pub struct VerifiedReceipt {
    output: VerifierOutput,
    claim: Claim,
    frame: Frame,
}

impl VerifiedReceipt {
    /// Construct a `VerifiedReceipt`. Only callable within the crate — external
    /// callers must obtain a token via `verify_receipt`.
    pub(crate) fn new(output: VerifierOutput, claim: Claim, frame: Frame) -> Self {
        Self {
            output,
            claim,
            frame,
        }
    }

    /// Return a reference to the `VerifierOutput` from CORE-VERIFY-1.
    #[must_use]
    pub fn output(&self) -> &VerifierOutput {
        &self.output
    }

    /// Return a reference to the parsed `Claim`.
    #[must_use]
    pub fn claim(&self) -> &Claim {
        &self.claim
    }

    /// Return a reference to the resolved `Frame`.
    #[must_use]
    pub fn frame(&self) -> &Frame {
        &self.frame
    }

    /// Destructure into the inner `(VerifierOutput, Claim, Frame)` triple.
    ///
    /// Only callable within the crate — used by `evaluate_relation` to unpack
    /// the opaque token without any runtime consistency checks (the type system
    /// guarantees they already passed).
    pub(crate) fn into_parts(self) -> (VerifierOutput, Claim, Frame) {
        (self.output, self.claim, self.frame)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::core::output::{CoreOutcome, RelationOutcome};

    fn make_output() -> VerifierOutput {
        VerifierOutput {
            core_outcome: CoreOutcome::AplValid,
            relation_outcome: RelationOutcome::RelationNotEvaluated,
            failure_classes: Vec::new(),
            diagnostics: vec![crate::diagnostics::APL_VALID],
        }
    }

    fn make_claim() -> Claim {
        let h = format!("sha256:{}", "1".repeat(64));
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "m" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.78 }
            },
            "frame_ref": { "hash": h }
        });
        Claim::parse(&v).expect("valid claim fixture")
    }

    fn make_frame() -> Frame {
        let v = json!({
            "version": "0.1",
            "observer": "o",
            "procedure": "p",
            "aspect": ["accuracy"],
            "scope": "s",
            "invariance": ["i"],
            "exclusions": ["e"]
        });
        Frame::parse(&v).expect("valid frame fixture")
    }

    #[test]
    fn accessors_return_correct_values() {
        let output = make_output();
        let claim = make_claim();
        let frame = make_frame();
        let token = VerifiedReceipt::new(output.clone(), claim, frame);

        assert_eq!(token.output().core_outcome, CoreOutcome::AplValid);
        // claim() and frame() return references without panicking.
        let _ = token.claim();
        let _ = token.frame();
    }

    #[test]
    fn clone_produces_equal_token() {
        let token = VerifiedReceipt::new(make_output(), make_claim(), make_frame());
        let cloned = token.clone();
        assert_eq!(cloned.output().core_outcome, token.output().core_outcome,);
    }

    #[test]
    fn into_parts_destructures_correctly() {
        let output = make_output();
        let claim = make_claim();
        let frame = make_frame();
        let token = VerifiedReceipt::new(output.clone(), claim, frame);
        let (out, _claim, _frame) = token.into_parts();
        assert_eq!(out.core_outcome, CoreOutcome::AplValid);
    }

    #[test]
    fn debug_format_contains_type_name() {
        let token = VerifiedReceipt::new(make_output(), make_claim(), make_frame());
        let debug_str = format!("{token:?}");
        assert!(debug_str.contains("VerifiedReceipt"));
    }
}
