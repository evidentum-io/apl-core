//! AI-Eval bridge applicability algorithm per apl-ai-eval-profile.md §7.7.
//! Profile-specific diagnostics per §7.8.
//!
//! Full implementation is provided by AI-EVAL-BRIDGE-1. This module declares
//! the function signature required by [`super::profile::AiEvalProfile`].

use apl_core::core::bridge::Bridge;
use apl_core::core::frame::Frame;
use apl_core::core::relation::RelationQuery;
use apl_core::profile::trait_def::BridgeCheckResult;

/// Check whether `bridge` is applicable under the AI-Eval profile constraints
/// (apl-ai-eval-profile.md §7.7).
///
/// # Errors
///
/// Returns `Err(Vec<Diagnostic>)` if the bridge violates any AI-Eval
/// profile-specific applicability constraint. The diagnostics are appended to
/// `PairwiseOutput.diagnostics` and the candidate bridge is skipped.
pub fn check_ai_eval_bridge_applicability(
    _bridge: &Bridge,
    _source_frame: &Frame,
    _target_frame: &Frame,
    _query: &RelationQuery,
) -> BridgeCheckResult {
    // Full implementation lives in AI-EVAL-BRIDGE-1.
    // Until that spec is implemented, this hook passes through to Core.
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod bridge_tests {
    use super::*;
    use crate::profile::AiEvalProfile;
    use apl_core::core::bridge::Bridge;
    use apl_core::core::frame::Frame;
    use apl_core::core::relation::RelationQuery;
    use apl_core::profile::trait_def::Profile;
    use serde_json::json;

    fn make_bridge() -> Bridge {
        let v = json!({
            "version": "0.1",
            "source_frame": { "hash": format!("sha256:{}", "a".repeat(64)) },
            "target_frame": { "hash": format!("sha256:{}", "b".repeat(64)) },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        Bridge::parse(&v).expect("valid bridge fixture")
    }

    fn make_frame(observer: &str) -> Frame {
        let v = json!({
            "version": "0.1",
            "observer": observer,
            "procedure": "p",
            "aspect": ["accuracy"],
            "scope": "s",
            "invariance": ["i"],
            "exclusions": ["e"]
        });
        Frame::parse(&v).expect("valid frame fixture")
    }

    fn make_query() -> RelationQuery {
        let v = json!({
            "left_aspects": ["accuracy"],
            "right_aspects": ["accuracy"],
            "predicate": "score",
            "relation_type": "score-delta"
        });
        RelationQuery::parse(&v).expect("valid query fixture")
    }

    // Direct invocation of the stub returns Ok(()).
    #[test]
    fn stub_returns_ok_directly() {
        let bridge = make_bridge();
        let src = make_frame("src-lab");
        let tgt = make_frame("tgt-lab");
        let query = make_query();
        assert!(
            check_ai_eval_bridge_applicability(&bridge, &src, &tgt, &query).is_ok(),
            "stub must return Ok(())"
        );
    }

    // Delegation through AiEvalProfile::check_bridge_applicability also returns Ok(()).
    #[test]
    fn stub_returns_ok_via_profile_delegation() {
        let bridge = make_bridge();
        let src = make_frame("src-lab");
        let tgt = make_frame("tgt-lab");
        let query = make_query();
        assert!(
            AiEvalProfile
                .check_bridge_applicability(&bridge, &src, &tgt, &query)
                .is_ok(),
            "profile delegation must propagate Ok(())"
        );
    }
}
