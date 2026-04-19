//! Profile trait — pluggable hook for vertical-profile checks.
//!
//! A [`Profile`] is the extension point through which vertical profiles (e.g.
//! AI-Eval, Photojournalism) plug into APL verification. Profiles MAY tighten
//! core requirements but MUST NOT weaken them. The architecture guarantees this
//! structurally: profile hooks are called only AFTER the relevant Core checks
//! have already passed.
//!
//! # Contract
//!
//! Per `apl-spec.md §9.10` and `§17`: "Profiles MAY tighten relation-layer
//! requirements and MAY introduce additional `claim.kind`, required bridge
//! semantics, or required transformation declarations." Per
//! `apl-relation-spec.md §6.4`: "Profiles MUST NOT weaken core requirements on
//! directionality, frame match or scope match."
//!
//! # Hook Invocation Order (single-receipt, CORE-VERIFY-1)
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
//!    branch is selected. Applies to BOTH same-frame and cross-frame paths.
//! 5. [`Profile::check_bridge_applicability`] — invoked PER bridge candidate on
//!    the cross-frame path ONLY, AFTER Core frame-match and scope-match pass.

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

/// Result type for single-receipt profile hook invocations.
///
/// On rejection the profile returns a [`ProfileFailure`] that carries the
/// failure class and the diagnostics to append to the verifier output.
pub type ProfileCheckResult = Result<(), ProfileFailure>;

/// Result type for bridge-applicability and pairwise-relation profile hooks.
///
/// On rejection the profile returns a list of diagnostics to append to
/// `PairwiseOutput.diagnostics`. No failure class is needed because the
/// relation-layer output does not have a `failure_classes` field.
pub type BridgeCheckResult = Result<(), Vec<Diagnostic>>;

/// Pluggable vertical-profile check hooks per `apl-spec.md §17` and `§9.10`.
///
/// Profiles MAY tighten core requirements but MUST NOT weaken them. A profile
/// receives only the artifacts and the query — it cannot inspect whether Core
/// already accepted or rejected a bridge, so it can only add its own verdict on
/// top of the Core verdict.
///
/// # Object Safety
///
/// This trait is object-safe (`Box<dyn Profile>` and `&dyn Profile` both work)
/// because all methods take `&self`, there are no associated types, no generic
/// methods, and no `Self` return types.
///
/// # Default Implementations
///
/// All five hooks default to `Ok(())` so that a profile only needs to override
/// the hooks relevant to its invariants.
pub trait Profile: Send + Sync + 'static {
    /// Human-readable profile identifier used only for diagnostic messages and
    /// logging; not part of the APL protocol wire format.
    fn id(&self) -> &'static str;

    /// Single-receipt claim check.
    ///
    /// Called by CORE-VERIFY-1 after Core steps 1–8 complete (carrier, claim
    /// parse, frame resolve, kernel, aspect linkage). Use this hook to enforce
    /// claim-only profile invariants (e.g. allowed `claim.kind` or `predicate`
    /// values per `apl-spec.md §17`).
    ///
    /// On `Err(profile_failure)`, CORE-VERIFY-1 sets `core_outcome =
    /// AplInvalid`, `failure_classes = [failure.failure_class]`, and appends
    /// `failure.diagnostics`. The remaining hooks (`check_frame`,
    /// `cross_check`) are NOT invoked.
    ///
    /// Default: accepts all core-valid claims (no-op).
    ///
    /// # Errors
    ///
    /// Returns `Err(ProfileFailure)` if the claim violates a profile invariant.
    fn check_claim(&self, _claim: &Claim) -> ProfileCheckResult {
        Ok(())
    }

    /// Single-receipt frame check.
    ///
    /// Called by CORE-VERIFY-1 after `check_claim` returns `Ok(())`. Same
    /// rejection semantics as `check_claim`. Use this hook for frame-only
    /// profile invariants (e.g. allowed `frame.scope` shapes).
    ///
    /// Default: accepts all core-valid frames (no-op).
    ///
    /// # Errors
    ///
    /// Returns `Err(ProfileFailure)` if the frame violates a profile invariant.
    fn check_frame(&self, _frame: &Frame) -> ProfileCheckResult {
        Ok(())
    }

    /// Single-receipt joint claim + frame check.
    ///
    /// Called by CORE-VERIFY-1 after BOTH `check_claim` and `check_frame`
    /// return `Ok(())`. This is the only hook that can enforce invariants
    /// requiring both artifacts simultaneously — e.g. AI-Eval §5.4
    /// (`frame.aspect[0] == claim.aspect_refs[0]`) and §6.2
    /// (`claim.statement.content.benchmark_id ==
    /// frame.scope.benchmark_id`).
    ///
    /// Same rejection semantics as `check_claim`. If `check_claim` or
    /// `check_frame` already failed, this hook is NOT invoked.
    ///
    /// Default: accepts all core-valid (claim, frame) pairs (no-op).
    ///
    /// # Errors
    ///
    /// Returns `Err(ProfileFailure)` if the pair violates a joint profile
    /// invariant.
    fn cross_check(&self, _claim: &Claim, _frame: &Frame) -> ProfileCheckResult {
        Ok(())
    }

    /// Pairwise profile gate — applies to BOTH same-frame and cross-frame paths.
    ///
    /// Called by RELATION-1 after structural preconditions (§7.3–§7.7) have
    /// passed and BEFORE the frame-equality branch selects same-frame vs
    /// cross-frame. Use this hook to enforce profile-level restrictions on the
    /// query (e.g. allowed `predicate`, allowed `relation_type`) that must hold
    /// regardless of whether the pair is same-frame-comparable or
    /// bridged-comparable.
    ///
    /// On `Err(diagnostics)`, RELATION-1 returns `Incomparable` with the
    /// diagnostics appended, without entering the same-frame branch or
    /// collecting bridge candidates.
    ///
    /// # Arguments
    ///
    /// * `_left` — parsed claim for the left receipt.
    /// * `_right` — parsed claim for the right receipt.
    /// * `_left_frame` — resolved frame for the left receipt.
    /// * `_right_frame` — resolved frame for the right receipt.
    /// * `_query` — the pairwise relation query.
    ///
    /// Default: accept (no tightening).
    ///
    /// # Errors
    ///
    /// Returns `Err(Vec<Diagnostic>)` if the pair violates a profile constraint.
    /// The diagnostics are appended to `PairwiseOutput.diagnostics`.
    fn check_pairwise_relation(
        &self,
        _left: &Claim,
        _right: &Claim,
        _left_frame: &Frame,
        _right_frame: &Frame,
        _query: &RelationQuery,
    ) -> BridgeCheckResult {
        Ok(())
    }

    /// Pairwise bridge applicability check (cross-frame path only).
    ///
    /// Called by RELATION-1 for every candidate bridge that has ALREADY passed
    /// Core frame-match and scope-match, AND after `check_pairwise_relation`
    /// returned `Ok(())`. Use this hook for bridge-kind-specific tightening
    /// (e.g. AI-Eval §7.7 procedure identity checks by `bridge_kind`).
    ///
    /// On `Err(diagnostics)`, the candidate is rejected and the loop continues
    /// with the next candidate. The profile MUST NOT accept a bridge that would
    /// violate directionality, frame match, or scope match — Core already
    /// enforced those and the profile hook is additive only.
    ///
    /// # Arguments
    ///
    /// * `_bridge` — the candidate bridge that passed Core applicability.
    /// * `_source_frame` — resolved frame for the left receipt.
    /// * `_target_frame` — resolved frame for the right receipt.
    /// * `_query` — the pairwise relation query.
    ///
    /// Default: accept (no tightening).
    ///
    /// # Errors
    ///
    /// Returns `Err(Vec<Diagnostic>)` if the bridge is not applicable under the
    /// profile constraints. The diagnostics are appended to
    /// `PairwiseOutput.diagnostics` and the candidate is skipped.
    fn check_bridge_applicability(
        &self,
        _bridge: &Bridge,
        _source_frame: &Frame,
        _target_frame: &Frame,
        _query: &RelationQuery,
    ) -> BridgeCheckResult {
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

    // AC1: trait object safety via Box<dyn Profile>
    #[test]
    fn usable_as_box_dyn_profile() {
        let p: Box<dyn Profile> = Box::new(AcceptAll);
        assert_eq!(p.id(), "accept-all");
    }

    // AC12: Profile: Send + Sync + 'static so that Box<dyn Profile> can be
    // shared across threads.
    #[test]
    fn send_sync_static_bound() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<AcceptAll>();
        assert_send_sync_static::<Box<dyn Profile>>();
    }

    #[test]
    fn default_check_pairwise_relation_returns_ok() {
        // AcceptAll does not override check_pairwise_relation; the default
        // no-op must return Ok(()).
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
        // no-op must return Ok(()).
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
