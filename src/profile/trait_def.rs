//! Profile trait — pluggable hook for vertical-profile checks.
//!
//! A [`Profile`] is an optional extension point invoked by
//! [`crate::core::verify::verify_receipt`] after all core APL checks pass
//! (steps 1–8 of the 14-step algorithm). It allows vertical profiles (e.g.
//! AI-Eval, Photojournalism) to enforce profile-specific invariants without
//! modifying the core algorithm.
//!
//! # Hook Invocation Order (single-receipt)
//!
//! 1. [`Profile::check_claim`] — claim-only invariants (e.g. allowed predicates).
//! 2. [`Profile::check_frame`] — frame-only invariants.
//! 3. [`Profile::cross_check`] — joint invariants requiring both claim and frame.
//!
//! Each hook short-circuits on `Err`: if `check_claim` fails, `check_frame`
//! and `cross_check` are NOT invoked.
//!
//! # Hook Invocation Order (pairwise, RELATION-1)
//!
//! 4. [`Profile::check_pairwise_relation`] — invoked AFTER Core preconditions
//!    and statement structural compatibility pass, BEFORE the frame-equality
//!    branch is selected. Applies to both same-frame and cross-frame paths.
//! 5. [`Profile::check_bridge_applicability`] — invoked PER bridge candidate on
//!    the cross-frame path, AFTER Core frame-match and scope-match pass.

use crate::core::bridge::Bridge;
use crate::core::claim::Claim;
use crate::core::frame::Frame;
use crate::core::relation::RelationQuery;
use crate::diagnostics::Diagnostic;
use crate::failure::FailureClass;

/// Error type returned by a failing profile hook.
///
/// The verifier propagates both fields verbatim into `VerifierOutput`:
/// - `failure_class` is appended to `failure_classes`.
/// - `diagnostics` are appended (after the already-accumulated prefix) to
///   `diagnostics`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileFailure {
    /// The failure class this profile violation maps to.
    pub failure_class: FailureClass,
    /// Ordered diagnostic codes for this failure.
    pub diagnostics: Vec<Diagnostic>,
}

/// Result type for profile hook invocations.
pub type ProfileCheckResult = Result<(), ProfileFailure>;

/// Pluggable vertical-profile check hooks.
///
/// Implement this trait to enforce profile-specific invariants on top of the
/// core APL verification algorithm. A profile may inspect `Claim`, `Frame`, or
/// both (via `cross_check`), and return `Err(ProfileFailure)` to reject the
/// receipt.
///
/// # Object Safety
///
/// This trait is object-safe. Pass it as `Option<&dyn Profile>` to
/// [`crate::core::verify::verify_receipt`].
///
/// # Default Implementations
///
/// All three hooks default to `Ok(())` so that a profile only needs to
/// override the hooks it cares about.
pub trait Profile: Send + Sync {
    /// Unique identifier for this profile (for diagnostics and logging).
    fn id(&self) -> &'static str;

    /// Check claim-only invariants.
    ///
    /// Called after core claim-structure and frame-resolution checks pass.
    /// The default implementation accepts all claims.
    ///
    /// # Errors
    ///
    /// Returns `Err(ProfileFailure)` if the claim violates a profile constraint.
    fn check_claim(&self, _claim: &Claim) -> ProfileCheckResult {
        Ok(())
    }

    /// Check frame-only invariants.
    ///
    /// Called after `check_claim` returns `Ok(())`.
    /// The default implementation accepts all frames.
    ///
    /// # Errors
    ///
    /// Returns `Err(ProfileFailure)` if the frame violates a profile constraint.
    fn check_frame(&self, _frame: &Frame) -> ProfileCheckResult {
        Ok(())
    }

    /// Check joint claim+frame invariants.
    ///
    /// Called after both `check_claim` and `check_frame` return `Ok(())`.
    /// This is the only point where invariants requiring BOTH claim and frame
    /// can be enforced (e.g. `benchmark_id` equality between
    /// `claim.statement.content.benchmark_id` and `frame.scope.benchmark_id`).
    ///
    /// The default implementation accepts all (claim, frame) pairs.
    ///
    /// # Errors
    ///
    /// Returns `Err(ProfileFailure)` if the pair violates a joint constraint.
    fn cross_check(&self, _claim: &Claim, _frame: &Frame) -> ProfileCheckResult {
        Ok(())
    }

    /// Check pairwise relation invariants (RELATION-1, step 10a).
    ///
    /// Invoked AFTER Core preconditions and statement structural compatibility
    /// pass, BEFORE the frame-equality branch is selected. Applies to both
    /// same-frame and cross-frame paths.
    ///
    /// Profiles use this hook to enforce query-level restrictions (e.g. allowed
    /// predicate or `relation_type` values) that must apply to ALL pairs,
    /// including same-frame ones.
    ///
    /// # Arguments
    ///
    /// * `left_claim` — parsed claim for the left receipt.
    /// * `right_claim` — parsed claim for the right receipt.
    /// * `left_frame` — resolved frame for the left receipt.
    /// * `right_frame` — resolved frame for the right receipt.
    /// * `query` — the pairwise relation query.
    ///
    /// # Errors
    ///
    /// Returns `Err` with profile-specific diagnostics if the pair violates a
    /// profile constraint. The diagnostics are appended to `PairwiseOutput`.
    fn check_pairwise_relation(
        &self,
        _left_claim: &Claim,
        _right_claim: &Claim,
        _left_frame: &Frame,
        _right_frame: &Frame,
        _query: &RelationQuery,
    ) -> Result<(), Vec<Diagnostic>> {
        Ok(())
    }

    /// Check bridge-level applicability invariants (RELATION-1, step 16 profile hook).
    ///
    /// Invoked PER bridge candidate on the cross-frame path, AFTER Core
    /// frame-match and scope-match pass. Profiles use this hook to enforce
    /// bridge-kind-specific constraints (e.g. AI-Eval `bridge_kind` field check).
    ///
    /// # Arguments
    ///
    /// * `bridge` — the candidate bridge that passed Core applicability.
    /// * `left_frame` — resolved frame for the left receipt.
    /// * `right_frame` — resolved frame for the right receipt.
    /// * `query` — the pairwise relation query.
    ///
    /// # Errors
    ///
    /// Returns `Err` with profile-specific diagnostics if the bridge is not
    /// applicable under the profile constraints. The candidate is skipped.
    fn check_bridge_applicability(
        &self,
        _bridge: &Bridge,
        _left_frame: &Frame,
        _right_frame: &Frame,
        _query: &RelationQuery,
    ) -> Result<(), Vec<Diagnostic>> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct AcceptAll;

    impl Profile for AcceptAll {
        fn id(&self) -> &'static str {
            "accept-all"
        }
    }

    struct RejectOnClaim;

    impl Profile for RejectOnClaim {
        fn id(&self) -> &'static str {
            "reject-on-claim"
        }

        fn check_claim(&self, _claim: &Claim) -> ProfileCheckResult {
            Err(ProfileFailure {
                failure_class: FailureClass::ClaimStructureFailure,
                diagnostics: vec![Diagnostic::AplClaimKindUnsupported],
            })
        }
    }

    struct RejectOnCross;

    impl Profile for RejectOnCross {
        fn id(&self) -> &'static str {
            "reject-on-cross"
        }

        fn cross_check(&self, _claim: &Claim, _frame: &Frame) -> ProfileCheckResult {
            Err(ProfileFailure {
                failure_class: FailureClass::SemanticLinkageFailure,
                diagnostics: vec![Diagnostic::AplAspectRefOutOfFrame],
            })
        }
    }

    fn make_claim() -> Claim {
        let h = format!("sha256:{}", "1".repeat(64));
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 1 }
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
    fn accept_all_profile_all_hooks_ok() {
        let p = AcceptAll;
        let claim = make_claim();
        let frame = make_frame();
        assert_eq!(p.check_claim(&claim), Ok(()));
        assert_eq!(p.check_frame(&frame), Ok(()));
        assert_eq!(p.cross_check(&claim, &frame), Ok(()));
    }

    #[test]
    fn reject_on_claim_returns_failure() {
        let p = RejectOnClaim;
        let claim = make_claim();
        let result = p.check_claim(&claim);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err
            .diagnostics
            .contains(&Diagnostic::AplClaimKindUnsupported));
    }

    #[test]
    fn reject_on_cross_check_returns_failure() {
        let p = RejectOnCross;
        let claim = make_claim();
        let frame = make_frame();
        assert_eq!(p.check_claim(&claim), Ok(()));
        assert_eq!(p.check_frame(&frame), Ok(()));
        let result = p.cross_check(&claim, &frame);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.failure_class, FailureClass::SemanticLinkageFailure);
    }

    #[test]
    fn profile_failure_clone_and_eq() {
        let f = ProfileFailure {
            failure_class: FailureClass::FrameFailure,
            diagnostics: vec![Diagnostic::AplFrameKernelMissing],
        };
        assert_eq!(f.clone(), f);
    }

    #[test]
    fn profile_is_object_safe() {
        let p: &dyn Profile = &AcceptAll;
        assert_eq!(p.id(), "accept-all");
    }

    #[test]
    fn reject_on_claim_id_is_accessible() {
        let p = RejectOnClaim;
        assert_eq!(p.id(), "reject-on-claim");
    }

    #[test]
    fn reject_on_cross_id_is_accessible() {
        let p = RejectOnCross;
        assert_eq!(p.id(), "reject-on-cross");
    }

    #[test]
    fn default_check_frame_returns_ok() {
        // AcceptAll only overrides id(); check_frame falls through to the default impl.
        let p = AcceptAll;
        let frame = make_frame();
        assert_eq!(p.check_frame(&frame), Ok(()));
    }

    #[test]
    fn default_cross_check_returns_ok() {
        // AcceptAll only overrides id(); cross_check falls through to the default impl.
        let p = AcceptAll;
        let claim = make_claim();
        let frame = make_frame();
        assert_eq!(p.cross_check(&claim, &frame), Ok(()));
    }

    #[test]
    fn reject_on_claim_default_check_frame_returns_ok() {
        // RejectOnClaim overrides check_claim but not check_frame; default must return Ok.
        let p = RejectOnClaim;
        let frame = make_frame();
        assert_eq!(p.check_frame(&frame), Ok(()));
    }

    #[test]
    fn reject_on_cross_default_check_claim_returns_ok() {
        // RejectOnCross overrides cross_check but not check_claim; default must return Ok.
        let p = RejectOnCross;
        let claim = make_claim();
        assert_eq!(p.check_claim(&claim), Ok(()));
    }

    #[test]
    fn default_check_pairwise_relation_returns_ok() {
        // AcceptAll does not override check_pairwise_relation; the default
        // no-op body (lines 132-141) must return Ok(()).
        let p = AcceptAll;
        let claim = make_claim();
        let frame = make_frame();
        let query = crate::core::relation::RelationQuery::parse(&json!({
            "left_aspects":  ["accuracy"],
            "right_aspects": ["accuracy"],
            "predicate":     "score",
            "relation_type": "score-delta"
        }))
        .expect("valid query fixture");

        let result = p.check_pairwise_relation(&claim, &claim, &frame, &frame, &query);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn default_check_bridge_applicability_returns_ok() {
        // AcceptAll does not override check_bridge_applicability; the default
        // no-op body (lines 160-168) must return Ok(()).
        let p = AcceptAll;
        let frame = make_frame();
        let query = crate::core::relation::RelationQuery::parse(&json!({
            "left_aspects":  ["accuracy"],
            "right_aspects": ["accuracy"],
            "predicate":     "score",
            "relation_type": "score-delta"
        }))
        .expect("valid query fixture");

        let h_src = format!("sha256:{}", "a".repeat(64));
        let h_tgt = format!("sha256:{}", "b".repeat(64));
        let bridge_value = json!({
            "version": "0.1",
            "source_frame": { "hash": h_src },
            "target_frame": { "hash": h_tgt },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        let bridge =
            crate::core::bridge::Bridge::parse(&bridge_value).expect("valid bridge fixture");

        let result = p.check_bridge_applicability(&bridge, &frame, &frame, &query);
        assert_eq!(result, Ok(()));
    }
}
