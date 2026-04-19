//! APL/AI-Eval v0.1 profile per apl-ai-eval-profile.md.

use apl_core::core::bridge::Bridge;
use apl_core::core::claim::Claim;
use apl_core::core::frame::Frame;
use apl_core::core::relation::RelationQuery;
use apl_core::profile::trait_def::{BridgeCheckResult, Profile, ProfileCheckResult};

use crate::bridge;
use crate::claim;
use crate::frame;

/// Allowed aspect identifiers for the APL/AI-Eval profile (apl-ai-eval-profile.md §3.4, §5.4).
pub(crate) const AI_EVAL_ALLOWED_ASPECTS: &[&str] =
    &["accuracy", "judge-score", "pass-rate", "tool-success-rate"];

/// Allowed unit strings for statement content (apl-ai-eval-profile.md §6.1).
pub(crate) const AI_EVAL_ALLOWED_UNITS: &[&str] = &["fraction", "percent", "points"];

/// Required exclusion markers that every AI-Eval frame MUST carry (apl-ai-eval-profile.md §5.5).
pub(crate) const AI_EVAL_REQUIRED_EXCLUSIONS: &[&str] = &[
    "no-production-readiness-claim",
    "no-deployment-safety-claim",
    "no-out-of-scope-generalization-claim",
];

/// The `APL/AI-Eval v0.1` profile.
///
/// Implements the claim-level, frame-level, cross-check, and pairwise relation
/// hooks defined in `apl-ai-eval-profile.md`. The profile is stateless: a single
/// shared instance can be used across threads and across many verification calls.
///
/// # Example
///
/// ```
/// use apl_ai_eval::AiEvalProfile;
/// use apl_core::profile::trait_def::Profile;
///
/// let profile = AiEvalProfile;
/// assert_eq!(profile.id(), "apl/ai-eval/v0.1");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct AiEvalProfile;

impl Profile for AiEvalProfile {
    fn id(&self) -> &'static str {
        "apl/ai-eval/v0.1"
    }

    /// Claim-level checks per apl-ai-eval-profile.md §§3-4, §6, §8.
    ///
    /// # Errors
    ///
    /// Returns `Err(ProfileFailure)` if the claim violates any AI-Eval profile invariant.
    fn check_claim(&self, c: &Claim) -> ProfileCheckResult {
        claim::check_claim(c)
    }

    /// Frame-level checks per apl-ai-eval-profile.md §5, §8.
    ///
    /// # Errors
    ///
    /// Returns `Err(ProfileFailure)` if the frame violates any AI-Eval frame invariant.
    fn check_frame(&self, f: &Frame) -> ProfileCheckResult {
        frame::check_frame(f)
    }

    /// Joint claim+frame cross-check per apl-ai-eval-profile.md §5.4 and §6.2.
    ///
    /// Enforces aspect alignment (`frame.aspect[0] == claim.aspect_refs[0]`) and
    /// benchmark_id equality (`claim.statement.content.benchmark_id ==
    /// frame.scope.benchmark_id`).
    ///
    /// # Errors
    ///
    /// Returns `Err(ProfileFailure)` if the pair violates either joint invariant.
    fn cross_check(&self, c: &Claim, f: &Frame) -> ProfileCheckResult {
        claim::cross_check(c, f)
    }

    /// Pairwise profile gate per apl-ai-eval-profile.md §7.1.
    ///
    /// Enforces that `query.predicate == "score"`, `query.relation_type` is in
    /// `{"score-delta", "repeatability-check"}`, and both `left_aspects` and
    /// `right_aspects` have cardinality 1. Applies to BOTH same-frame and
    /// cross-frame paths.
    ///
    /// # Errors
    ///
    /// Returns `Err(Vec<Diagnostic>)` if any pairwise query constraint is violated.
    fn check_pairwise_relation(
        &self,
        left: &Claim,
        right: &Claim,
        left_frame: &Frame,
        right_frame: &Frame,
        query: &RelationQuery,
    ) -> BridgeCheckResult {
        claim::check_pairwise_relation(left, right, left_frame, right_frame, query)
    }

    /// Bridge applicability check per apl-ai-eval-profile.md §7.7.
    ///
    /// # Errors
    ///
    /// Returns `Err(Vec<Diagnostic>)` if the bridge does not satisfy AI-Eval
    /// profile constraints.
    fn check_bridge_applicability(
        &self,
        b: &Bridge,
        source_frame: &Frame,
        target_frame: &Frame,
        query: &RelationQuery,
    ) -> BridgeCheckResult {
        bridge::check_ai_eval_bridge_applicability(b, source_frame, target_frame, query)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod mod_tests {
    use super::*;
    use apl_core::core::bridge::Bridge;
    use apl_core::core::claim::Claim;
    use apl_core::core::frame::Frame;
    use apl_core::core::relation::RelationQuery;
    use apl_core::profile::trait_def::Profile;
    use serde_json::json;

    fn h(b: u8) -> String {
        format!("sha256:{}", hex::encode([b; 32]))
    }

    // Profile::id() returns the expected string.
    #[test]
    fn profile_id_returns_expected_string() {
        let profile = AiEvalProfile;
        assert_eq!(profile.id(), "apl/ai-eval/v0.1");
    }

    // Default trait produces an instance with the correct id.
    // AiEvalProfile is a unit struct; Default::default() and the struct literal are identical.
    #[test]
    fn default_instance_has_correct_id() {
        #[allow(clippy::default_constructed_unit_structs)]
        let profile = AiEvalProfile::default();
        assert_eq!(profile.id(), "apl/ai-eval/v0.1");
    }

    // Profile::id() works via &dyn Profile.
    #[test]
    fn id_works_via_dyn_profile() {
        let profile: &dyn Profile = &AiEvalProfile;
        assert_eq!(profile.id(), "apl/ai-eval/v0.1");
    }

    // check_bridge_applicability via &dyn Profile returns Ok(()).
    #[test]
    fn check_bridge_applicability_via_dyn_profile_returns_ok() {
        let bridge = Bridge::parse(&json!({
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
        }))
        .expect("valid bridge fixture");

        let src = Frame::parse(&json!({
            "version": "0.1",
            "observer": "src-lab",
            "procedure": "p",
            "aspect": ["accuracy"],
            "scope": "s",
            "invariance": ["i"],
            "exclusions": ["e"]
        }))
        .expect("valid frame fixture");

        let tgt = Frame::parse(&json!({
            "version": "0.1",
            "observer": "tgt-lab",
            "procedure": "p",
            "aspect": ["accuracy"],
            "scope": "s",
            "invariance": ["i"],
            "exclusions": ["e"]
        }))
        .expect("valid frame fixture");

        let query = RelationQuery::parse(&json!({
            "left_aspects": ["accuracy"],
            "right_aspects": ["accuracy"],
            "predicate": "score",
            "relation_type": "score-delta"
        }))
        .expect("valid query fixture");

        let profile: &dyn Profile = &AiEvalProfile;
        assert!(
            profile
                .check_bridge_applicability(&bridge, &src, &tgt, &query)
                .is_ok(),
            "bridge applicability stub must return Ok(())"
        );
    }

    // check_claim delegates correctly via &dyn Profile.
    #[test]
    fn check_claim_delegates_via_dyn_profile() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:x",
                    "artifact_digest": h(0x42)
                },
                "aspect_refs": ["accuracy"],
                "statement": {
                    "predicate": "score",
                    "content": {
                        "benchmark_id": "mmlu",
                        "metric_id": "accuracy",
                        "value": 0.5,
                        "unit": "fraction"
                    }
                }
            },
            "frame_ref": { "hash": h(0x11) }
        });
        let claim = Claim::parse(&v).expect("valid claim fixture");
        let profile: &dyn Profile = &AiEvalProfile;
        assert!(profile.check_claim(&claim).is_ok());
    }
}
