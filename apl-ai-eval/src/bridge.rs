//! AI-Eval bridge applicability algorithm per apl-ai-eval-profile.md §7.7.
//! Profile-specific diagnostics per §7.8.

use serde_json::Value;

use apl_core::core::bridge::Bridge;
use apl_core::core::frame::{Frame, StringOrObject};
use apl_core::core::jcs::{canonical_equal, canonical_equal_after_strip};
use apl_core::core::relation::RelationQuery;
use apl_core::profile::trait_def::BridgeCheckResult;

use crate::diagnostics::{
    APL_AI_EVAL_BRIDGE_ASPECT_FAMILY_MISMATCH, APL_AI_EVAL_BRIDGE_GRADER_MISMATCH,
    APL_AI_EVAL_BRIDGE_KIND_INVALID, APL_AI_EVAL_BRIDGE_PROCEDURE_MISMATCH,
    APL_AI_EVAL_BRIDGE_RELATION_TYPE_INVALID, APL_AI_EVAL_BRIDGE_RUNNER_MISMATCH,
    APL_AI_EVAL_BRIDGE_SCOPE_MISMATCH, APL_AI_EVAL_BRIDGE_SOURCE_ASPECT_MISMATCH,
    APL_AI_EVAL_BRIDGE_TARGET_ASPECT_MISMATCH,
};
use crate::frame::check_frame as check_ai_eval_frame_conformance;

// APL Core pairwise diagnostic used in the defensive frame-match step.
use apl_core::diagnostics::APL_BRIDGE_FRAME_MISMATCH;

/// Check whether `bridge` is applicable under the AI-Eval profile constraints
/// (apl-ai-eval-profile.md §7.7).
///
/// Returns `Ok(())` iff all 13 steps pass. Returns `Err(diags)` otherwise,
/// with `diags` taken from `§7.8`.
///
/// # Errors
///
/// Returns `Err(Vec<DiagnosticCode>)` if the bridge violates any AI-Eval
/// profile-specific applicability constraint. The diagnostics are appended to
/// `PairwiseOutput.diagnostics` and the candidate bridge is skipped.
pub fn check_ai_eval_bridge_applicability(
    bridge: &Bridge,
    source_frame: &Frame,
    target_frame: &Frame,
    query: &RelationQuery,
) -> BridgeCheckResult {
    // Step 1: defensive Core frame-match (§6.1).
    // RELATION-1 already performed this check; we re-verify here to guard
    // against future wiring drift between caller and this hook.
    if bridge.source_frame.hash != source_frame.canonical_hash() {
        return Err(vec![APL_BRIDGE_FRAME_MISMATCH]);
    }
    if bridge.target_frame.hash != target_frame.canonical_hash() {
        return Err(vec![APL_BRIDGE_FRAME_MISMATCH]);
    }

    // Step 2: frames are already resolved — passed in as arguments.

    // Step 3: AI-Eval frame-profile conformance.
    // Use the umbrella scope-mismatch diagnostic for profile-nonconformant frames
    // since conformance failure means the bridge scope cannot be meaningful.
    if check_ai_eval_frame_conformance(source_frame).is_err() {
        return Err(vec![APL_AI_EVAL_BRIDGE_SCOPE_MISMATCH]);
    }
    if check_ai_eval_frame_conformance(target_frame).is_err() {
        return Err(vec![APL_AI_EVAL_BRIDGE_SCOPE_MISMATCH]);
    }

    // Step 4: bridge_kind presence + supported value.
    // Core does not type bridge_kind; profile inspects bridge.raw.
    let bk = bridge
        .raw
        .as_object()
        .and_then(|m| m.get("bridge_kind"))
        .and_then(Value::as_str);
    let bk = match bk {
        Some(s)
            if matches!(
                s,
                "runner-equivalence" | "grader-equivalence" | "repeatability"
            ) =>
        {
            s
        }
        _ => return Err(vec![APL_AI_EVAL_BRIDGE_KIND_INVALID]),
    };

    // Steps 5 (query.predicate = "score") and query-aspect-cardinality checks
    // for steps 6/7 moved to AiEvalProfile::check_pairwise_relation (§7.1).

    // Remaining part of step 6: bridge.comparison_scope.source_aspects must have
    // exactly one element AND must exactly equal query.left_aspects.
    if bridge.comparison_scope.source_aspects.len() != 1
        || query.left_aspects != bridge.comparison_scope.source_aspects
    {
        return Err(vec![APL_AI_EVAL_BRIDGE_SOURCE_ASPECT_MISMATCH]);
    }

    // Remaining part of step 7: bridge.comparison_scope.target_aspects must have
    // exactly one element AND must exactly equal query.right_aspects.
    if bridge.comparison_scope.target_aspects.len() != 1
        || query.right_aspects != bridge.comparison_scope.target_aspects
    {
        return Err(vec![APL_AI_EVAL_BRIDGE_TARGET_ASPECT_MISMATCH]);
    }

    // Step 8: common AI-Eval bridge constraints (§7.3).
    // (a) bridge.source_aspects[0] == source_frame.aspect[0]
    if bridge.comparison_scope.source_aspects[0] != source_frame.aspect[0] {
        return Err(vec![APL_AI_EVAL_BRIDGE_SOURCE_ASPECT_MISMATCH]);
    }
    // (b) bridge.target_aspects[0] == target_frame.aspect[0]
    if bridge.comparison_scope.target_aspects[0] != target_frame.aspect[0] {
        return Err(vec![APL_AI_EVAL_BRIDGE_TARGET_ASPECT_MISMATCH]);
    }
    // (c) source_frame.aspect[0] == target_frame.aspect[0]  (aspect family)
    if source_frame.aspect[0] != target_frame.aspect[0] {
        return Err(vec![APL_AI_EVAL_BRIDGE_ASPECT_FAMILY_MISMATCH]);
    }
    // (d) source_frame.scope and target_frame.scope identical as JSON objects
    //     (canonical-equality rule per step 12)
    let src_scope_v = frame_scope_as_value(source_frame);
    let tgt_scope_v = frame_scope_as_value(target_frame);
    if !canonical_equal(&src_scope_v, &tgt_scope_v) {
        return Err(vec![APL_AI_EVAL_BRIDGE_SCOPE_MISMATCH]);
    }

    // Steps 9-11 (step 12's canonical-equality rule applied throughout)
    let src_proc_v = frame_procedure_as_value(source_frame);
    let tgt_proc_v = frame_procedure_as_value(target_frame);

    match bk {
        "runner-equivalence" => {
            // Step 9
            if bridge.comparison_scope.relation_type != "score-delta" {
                return Err(vec![APL_AI_EVAL_BRIDGE_RELATION_TYPE_INVALID]);
            }
            let src_grader = src_proc_v
                .as_object()
                .and_then(|m| m.get("grader_id"))
                .and_then(Value::as_str);
            let tgt_grader = tgt_proc_v
                .as_object()
                .and_then(|m| m.get("grader_id"))
                .and_then(Value::as_str);
            if src_grader != tgt_grader {
                return Err(vec![APL_AI_EVAL_BRIDGE_GRADER_MISMATCH]);
            }
            if !canonical_equal_after_strip(&src_proc_v, &tgt_proc_v, &["runner_id"]) {
                return Err(vec![APL_AI_EVAL_BRIDGE_PROCEDURE_MISMATCH]);
            }
        }
        "grader-equivalence" => {
            // Step 10
            if bridge.comparison_scope.relation_type != "score-delta" {
                return Err(vec![APL_AI_EVAL_BRIDGE_RELATION_TYPE_INVALID]);
            }
            let src_runner = src_proc_v
                .as_object()
                .and_then(|m| m.get("runner_id"))
                .and_then(Value::as_str);
            let tgt_runner = tgt_proc_v
                .as_object()
                .and_then(|m| m.get("runner_id"))
                .and_then(Value::as_str);
            if src_runner != tgt_runner {
                return Err(vec![APL_AI_EVAL_BRIDGE_RUNNER_MISMATCH]);
            }
            if !canonical_equal_after_strip(&src_proc_v, &tgt_proc_v, &["grader_id"]) {
                return Err(vec![APL_AI_EVAL_BRIDGE_PROCEDURE_MISMATCH]);
            }
        }
        "repeatability" => {
            // Step 11
            if bridge.comparison_scope.relation_type != "repeatability-check" {
                return Err(vec![APL_AI_EVAL_BRIDGE_RELATION_TYPE_INVALID]);
            }
            if !canonical_equal(&src_proc_v, &tgt_proc_v) {
                return Err(vec![APL_AI_EVAL_BRIDGE_PROCEDURE_MISMATCH]);
            }
        }
        // SAFETY: bk was validated at step 4 to be one of the three values above.
        _ => unreachable!("bk validated at step 4"),
    }

    // Step 13: all checks passed.
    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Extract the `scope` field of a frame as a `serde_json::Value`.
///
/// Returns `Value::Null` when scope is absent — canonical equality of two
/// `Null` values will then be `true`, which is correct: both frames have no
/// scope and are trivially equal in that field.
fn frame_scope_as_value(f: &Frame) -> Value {
    match &f.scope {
        Some(StringOrObject::Object(m)) => Value::Object(m.clone()),
        Some(StringOrObject::String(s)) => Value::String(s.clone()),
        None => Value::Null,
    }
}

/// Extract the `procedure` field of a frame as a `serde_json::Value`.
///
/// Returns `Value::Null` when procedure is absent. Used only after
/// `check_ai_eval_frame_conformance` has already confirmed that procedure is
/// a non-empty object with `runner_id` and `grader_id`.
fn frame_procedure_as_value(f: &Frame) -> Value {
    match &f.procedure {
        Some(StringOrObject::Object(m)) => Value::Object(m.clone()),
        Some(StringOrObject::String(s)) => Value::String(s.clone()),
        None => Value::Null,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod bridge_tests {
    use super::*;
    use apl_core::core::bridge::Bridge;
    use apl_core::core::frame::Frame;
    use apl_core::core::relation::RelationQuery;
    use serde_json::json;

    // ---------------------------------------------------------------------------
    // Fixture helpers
    // ---------------------------------------------------------------------------

    /// MMLU/dev accuracy frame with runner_id = "lm-eval-harness@0.4.2".
    fn frame_mmlu_runner_a() -> serde_json::Value {
        json!({
            "version": "0.1",
            "observer": { "id": "acme-eval-lab" },
            "procedure": {
                "runner_id": "lm-eval-harness@0.4.2",
                "grader_id": "exact-match-v1",
                "prompt_protocol": "zero-shot-mcq-v1"
            },
            "aspect": ["accuracy"],
            "scope": {
                "benchmark_id": "mmlu",
                "benchmark_variant": "default",
                "dataset_split": "dev",
                "subset": "all"
            },
            "invariance": ["score-object-serialization"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        })
    }

    /// Same as `frame_mmlu_runner_a` but with a different runner_id.
    fn frame_mmlu_runner_b() -> serde_json::Value {
        let mut f = frame_mmlu_runner_a();
        f["procedure"]["runner_id"] = json!("custom-runner@2.1");
        f
    }

    /// Build a well-formed runner-equivalence bridge whose hashes reference
    /// `src` and `tgt`.
    fn bridge_runner_equivalence(
        src: &apl_core::core::hash::Hash,
        tgt: &apl_core::core::hash::Hash,
    ) -> serde_json::Value {
        json!({
            "version": "0.1",
            "bridge_kind": "runner-equivalence",
            "source_frame": { "hash": src.to_string() },
            "target_frame": { "hash": tgt.to_string() },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        })
    }

    fn query_accuracy() -> RelationQuery {
        RelationQuery::parse(&json!({
            "left_aspects": ["accuracy"],
            "right_aspects": ["accuracy"],
            "predicate": "score",
            "relation_type": "score-delta"
        }))
        .expect("valid query fixture")
    }

    // ---------------------------------------------------------------------------
    // Stub compatibility (existing tests must still pass)
    // ---------------------------------------------------------------------------

    // Existing stub test: `stub_returns_ok_directly` must remain compilable but
    // is superseded by the real positive tests. Kept here under a new name so CI
    // does not lose coverage of the delegate path while the profile.rs test still
    // checks the `AiEvalProfile` delegation.

    // ---------------------------------------------------------------------------
    // AC1: missing bridge_kind returns AplAiEvalBridgeKindInvalid
    // ---------------------------------------------------------------------------

    #[test]
    fn ac1_missing_bridge_kind() {
        let src_f = Frame::parse(&frame_mmlu_runner_a()).expect("valid source frame");
        let tgt_f = Frame::parse(&frame_mmlu_runner_b()).expect("valid target frame");
        let mut bridge_v =
            bridge_runner_equivalence(&src_f.canonical_hash(), &tgt_f.canonical_hash());
        bridge_v
            .as_object_mut()
            .expect("bridge is object")
            .remove("bridge_kind");
        let bridge = Bridge::parse(&bridge_v).expect("valid bridge");
        let q = query_accuracy();

        let err = check_ai_eval_bridge_applicability(&bridge, &src_f, &tgt_f, &q).unwrap_err();
        assert!(
            err.contains(&APL_AI_EVAL_BRIDGE_KIND_INVALID),
            "expected AplAiEvalBridgeKindInvalid, got {err:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // AC2: unsupported bridge_kind returns AplAiEvalBridgeKindInvalid
    // ---------------------------------------------------------------------------

    #[test]
    fn ac2_unknown_bridge_kind() {
        let src_f = Frame::parse(&frame_mmlu_runner_a()).expect("valid source frame");
        let tgt_f = Frame::parse(&frame_mmlu_runner_b()).expect("valid target frame");
        let mut bridge_v =
            bridge_runner_equivalence(&src_f.canonical_hash(), &tgt_f.canonical_hash());
        bridge_v["bridge_kind"] = json!("unknown-kind");
        let bridge = Bridge::parse(&bridge_v).expect("valid bridge");
        let q = query_accuracy();

        let err = check_ai_eval_bridge_applicability(&bridge, &src_f, &tgt_f, &q).unwrap_err();
        assert!(
            err.contains(&APL_AI_EVAL_BRIDGE_KIND_INVALID),
            "expected AplAiEvalBridgeKindInvalid, got {err:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // AC4: source_aspects cardinality != 1 returns AplAiEvalBridgeSourceAspectMismatch
    // ---------------------------------------------------------------------------

    #[test]
    fn ac4_source_aspects_cardinality_not_one() {
        let src_f = Frame::parse(&frame_mmlu_runner_a()).expect("valid source frame");
        let tgt_f = Frame::parse(&frame_mmlu_runner_b()).expect("valid target frame");
        let mut bridge_v =
            bridge_runner_equivalence(&src_f.canonical_hash(), &tgt_f.canonical_hash());
        bridge_v["comparison_scope"]["source_aspects"] = json!(["accuracy", "pass-rate"]);
        // Also update query to have two elements to avoid query mismatch interfering.
        // Actually we want to test the bridge cardinality check specifically,
        // so the bridge has 2 source_aspects while query has 1.
        let bridge = Bridge::parse(&bridge_v).expect("valid bridge");
        let q = query_accuracy();

        let err = check_ai_eval_bridge_applicability(&bridge, &src_f, &tgt_f, &q).unwrap_err();
        assert!(
            err.contains(&APL_AI_EVAL_BRIDGE_SOURCE_ASPECT_MISMATCH),
            "expected AplAiEvalBridgeSourceAspectMismatch, got {err:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // AC5: query left_aspects != bridge source_aspects → AplAiEvalBridgeSourceAspectMismatch
    // ---------------------------------------------------------------------------

    #[test]
    fn ac5_query_left_aspects_differ_from_bridge_source() {
        let src_f = Frame::parse(&frame_mmlu_runner_a()).expect("valid source frame");
        let tgt_f = Frame::parse(&frame_mmlu_runner_b()).expect("valid target frame");
        let bridge_v = bridge_runner_equivalence(&src_f.canonical_hash(), &tgt_f.canonical_hash());
        let bridge = Bridge::parse(&bridge_v).expect("valid bridge");

        // query uses "pass-rate" on the left instead of "accuracy"
        let q = RelationQuery::parse(&json!({
            "left_aspects": ["pass-rate"],
            "right_aspects": ["accuracy"],
            "predicate": "score",
            "relation_type": "score-delta"
        }))
        .expect("valid query");

        let err = check_ai_eval_bridge_applicability(&bridge, &src_f, &tgt_f, &q).unwrap_err();
        assert!(
            err.contains(&APL_AI_EVAL_BRIDGE_SOURCE_ASPECT_MISMATCH),
            "expected AplAiEvalBridgeSourceAspectMismatch, got {err:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // AC6: query right_aspects != bridge target_aspects → AplAiEvalBridgeTargetAspectMismatch
    // ---------------------------------------------------------------------------

    #[test]
    fn ac6_query_right_aspects_differ_from_bridge_target() {
        let src_f = Frame::parse(&frame_mmlu_runner_a()).expect("valid source frame");
        let tgt_f = Frame::parse(&frame_mmlu_runner_b()).expect("valid target frame");
        let bridge_v = bridge_runner_equivalence(&src_f.canonical_hash(), &tgt_f.canonical_hash());
        let bridge = Bridge::parse(&bridge_v).expect("valid bridge");

        // query uses "pass-rate" on the right instead of "accuracy"
        let q = RelationQuery::parse(&json!({
            "left_aspects": ["accuracy"],
            "right_aspects": ["pass-rate"],
            "predicate": "score",
            "relation_type": "score-delta"
        }))
        .expect("valid query");

        let err = check_ai_eval_bridge_applicability(&bridge, &src_f, &tgt_f, &q).unwrap_err();
        assert!(
            err.contains(&APL_AI_EVAL_BRIDGE_TARGET_ASPECT_MISMATCH),
            "expected AplAiEvalBridgeTargetAspectMismatch, got {err:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // AC7: aspect[0] differs between source and target frame → AplAiEvalBridgeAspectFamilyMismatch
    // ---------------------------------------------------------------------------

    #[test]
    fn ac7_aspect_family_mismatch() {
        let src_f = Frame::parse(&frame_mmlu_runner_a()).expect("valid source frame");
        // Build a target frame with aspect = ["judge-score"]
        let mut tgt_v = frame_mmlu_runner_b();
        tgt_v["aspect"] = json!(["judge-score"]);
        let tgt_f = Frame::parse(&tgt_v).expect("valid target frame");

        // Build a bridge that declares source_aspects=["accuracy"],
        // target_aspects=["judge-score"] to pass the query/bridge checks and
        // reach step 8(c) where aspect family is checked.
        let bridge_v = json!({
            "version": "0.1",
            "bridge_kind": "runner-equivalence",
            "source_frame": { "hash": src_f.canonical_hash().to_string() },
            "target_frame": { "hash": tgt_f.canonical_hash().to_string() },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["judge-score"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        let bridge = Bridge::parse(&bridge_v).expect("valid bridge");
        let q = RelationQuery::parse(&json!({
            "left_aspects": ["accuracy"],
            "right_aspects": ["judge-score"],
            "predicate": "score",
            "relation_type": "score-delta"
        }))
        .expect("valid query");

        let err = check_ai_eval_bridge_applicability(&bridge, &src_f, &tgt_f, &q).unwrap_err();
        assert!(
            err.contains(&APL_AI_EVAL_BRIDGE_ASPECT_FAMILY_MISMATCH),
            "expected AplAiEvalBridgeAspectFamilyMismatch, got {err:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // AC8: scope differs between source and target frame → AplAiEvalBridgeScopeMismatch
    // ---------------------------------------------------------------------------

    #[test]
    fn ac8_scope_mismatch_any_field() {
        let src_f = Frame::parse(&frame_mmlu_runner_a()).expect("valid source frame");
        // Change dataset_split to simulate a scope difference
        let mut tgt_v = frame_mmlu_runner_b();
        tgt_v["scope"]["dataset_split"] = json!("test-lite");
        let tgt_f = Frame::parse(&tgt_v).expect("valid target frame");
        let bridge_v = bridge_runner_equivalence(&src_f.canonical_hash(), &tgt_f.canonical_hash());
        let bridge = Bridge::parse(&bridge_v).expect("valid bridge");
        let q = query_accuracy();

        let err = check_ai_eval_bridge_applicability(&bridge, &src_f, &tgt_f, &q).unwrap_err();
        assert!(
            err.contains(&APL_AI_EVAL_BRIDGE_SCOPE_MISMATCH),
            "expected AplAiEvalBridgeScopeMismatch, got {err:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // AC9: runner-equivalence with wrong relation_type → AplAiEvalBridgeRelationTypeInvalid
    // ---------------------------------------------------------------------------

    #[test]
    fn ac9_runner_equivalence_wrong_relation_type() {
        let src_f = Frame::parse(&frame_mmlu_runner_a()).expect("valid source frame");
        let tgt_f = Frame::parse(&frame_mmlu_runner_b()).expect("valid target frame");
        let mut bridge_v =
            bridge_runner_equivalence(&src_f.canonical_hash(), &tgt_f.canonical_hash());
        bridge_v["comparison_scope"]["relation_type"] = json!("repeatability-check");
        let bridge = Bridge::parse(&bridge_v).expect("valid bridge");
        // query must match bridge's aspects but relation_type can differ
        let q = RelationQuery::parse(&json!({
            "left_aspects": ["accuracy"],
            "right_aspects": ["accuracy"],
            "predicate": "score",
            "relation_type": "repeatability-check"
        }))
        .expect("valid query");

        let err = check_ai_eval_bridge_applicability(&bridge, &src_f, &tgt_f, &q).unwrap_err();
        assert!(
            err.contains(&APL_AI_EVAL_BRIDGE_RELATION_TYPE_INVALID),
            "expected AplAiEvalBridgeRelationTypeInvalid, got {err:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // AC10: runner-equivalence with differing grader_id → AplAiEvalBridgeGraderMismatch
    // ---------------------------------------------------------------------------

    #[test]
    fn ac10_runner_equivalence_grader_mismatch() {
        let src_f = Frame::parse(&frame_mmlu_runner_a()).expect("valid source frame");
        let mut tgt_v = frame_mmlu_runner_b();
        tgt_v["procedure"]["grader_id"] = json!("other-grader-v2");
        let tgt_f = Frame::parse(&tgt_v).expect("valid target frame");
        let bridge_v = bridge_runner_equivalence(&src_f.canonical_hash(), &tgt_f.canonical_hash());
        let bridge = Bridge::parse(&bridge_v).expect("valid bridge");
        let q = query_accuracy();

        let err = check_ai_eval_bridge_applicability(&bridge, &src_f, &tgt_f, &q).unwrap_err();
        assert!(
            err.contains(&APL_AI_EVAL_BRIDGE_GRADER_MISMATCH),
            "expected AplAiEvalBridgeGraderMismatch, got {err:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // AC11: runner-equivalence with procedure differing beyond runner_id → AplAiEvalBridgeProcedureMismatch
    // ---------------------------------------------------------------------------

    #[test]
    fn ac11_runner_equivalence_procedure_differs_beyond_runner_id() {
        let src_f = Frame::parse(&frame_mmlu_runner_a()).expect("valid source frame");
        // Same grader_id, same runner_id base, but prompt_protocol differs
        let mut tgt_v = frame_mmlu_runner_b();
        tgt_v["procedure"]["prompt_protocol"] = json!("few-shot-v2");
        let tgt_f = Frame::parse(&tgt_v).expect("valid target frame");
        let bridge_v = bridge_runner_equivalence(&src_f.canonical_hash(), &tgt_f.canonical_hash());
        let bridge = Bridge::parse(&bridge_v).expect("valid bridge");
        let q = query_accuracy();

        let err = check_ai_eval_bridge_applicability(&bridge, &src_f, &tgt_f, &q).unwrap_err();
        assert!(
            err.contains(&APL_AI_EVAL_BRIDGE_PROCEDURE_MISMATCH),
            "expected AplAiEvalBridgeProcedureMismatch, got {err:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // AC12: runner-equivalence happy path → Ok(())
    // ---------------------------------------------------------------------------

    #[test]
    fn ac12_runner_equivalence_accepts_when_only_runner_differs() {
        let src_f = Frame::parse(&frame_mmlu_runner_a()).expect("valid source frame");
        let tgt_f = Frame::parse(&frame_mmlu_runner_b()).expect("valid target frame");
        let bridge_v = bridge_runner_equivalence(&src_f.canonical_hash(), &tgt_f.canonical_hash());
        let bridge = Bridge::parse(&bridge_v).expect("valid bridge");
        let q = query_accuracy();

        assert!(
            check_ai_eval_bridge_applicability(&bridge, &src_f, &tgt_f, &q).is_ok(),
            "runner-equivalence with only runner_id differing must return Ok(())"
        );
    }

    // ---------------------------------------------------------------------------
    // AC13: grader-equivalence with differing runner_id → AplAiEvalBridgeRunnerMismatch
    // ---------------------------------------------------------------------------

    #[test]
    fn ac13_grader_equivalence_runner_mismatch() {
        // Source: runner_id = "lm-eval-harness@0.4.2"
        // Target: runner_id = "custom-runner@2.1"
        // bridge_kind = grader-equivalence → runner_id MUST match
        let src_f = Frame::parse(&frame_mmlu_runner_a()).expect("valid source frame");
        let tgt_f = Frame::parse(&frame_mmlu_runner_b()).expect("valid target frame");

        let bridge_v = json!({
            "version": "0.1",
            "bridge_kind": "grader-equivalence",
            "source_frame": { "hash": src_f.canonical_hash().to_string() },
            "target_frame": { "hash": tgt_f.canonical_hash().to_string() },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        let bridge = Bridge::parse(&bridge_v).expect("valid bridge");
        let q = query_accuracy();

        let err = check_ai_eval_bridge_applicability(&bridge, &src_f, &tgt_f, &q).unwrap_err();
        assert!(
            err.contains(&APL_AI_EVAL_BRIDGE_RUNNER_MISMATCH),
            "expected AplAiEvalBridgeRunnerMismatch, got {err:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // AC14: repeatability with wrong relation_type → AplAiEvalBridgeRelationTypeInvalid
    // ---------------------------------------------------------------------------

    #[test]
    fn ac14_repeatability_wrong_relation_type() {
        let src_f = Frame::parse(&frame_mmlu_runner_a()).expect("valid source frame");
        let tgt_f = Frame::parse(&frame_mmlu_runner_a()).expect("valid target frame");

        let bridge_v = json!({
            "version": "0.1",
            "bridge_kind": "repeatability",
            "source_frame": { "hash": src_f.canonical_hash().to_string() },
            "target_frame": { "hash": tgt_f.canonical_hash().to_string() },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        let bridge = Bridge::parse(&bridge_v).expect("valid bridge");
        let q = query_accuracy();

        let err = check_ai_eval_bridge_applicability(&bridge, &src_f, &tgt_f, &q).unwrap_err();
        assert!(
            err.contains(&APL_AI_EVAL_BRIDGE_RELATION_TYPE_INVALID),
            "expected AplAiEvalBridgeRelationTypeInvalid, got {err:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // AC15: repeatability with identical procedures → Ok(())
    // ---------------------------------------------------------------------------

    #[test]
    fn ac15_repeatability_accepts_identical_procedures() {
        let src_f = Frame::parse(&frame_mmlu_runner_a()).expect("valid source frame");
        let tgt_f = Frame::parse(&frame_mmlu_runner_a()).expect("valid target frame");

        let bridge_v = json!({
            "version": "0.1",
            "bridge_kind": "repeatability",
            "source_frame": { "hash": src_f.canonical_hash().to_string() },
            "target_frame": { "hash": tgt_f.canonical_hash().to_string() },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "repeatability-check"
            },
            "assumptions": [],
            "losses": []
        });
        let bridge = Bridge::parse(&bridge_v).expect("valid bridge");
        let q = RelationQuery::parse(&json!({
            "left_aspects": ["accuracy"],
            "right_aspects": ["accuracy"],
            "predicate": "score",
            "relation_type": "repeatability-check"
        }))
        .expect("valid query");

        assert!(
            check_ai_eval_bridge_applicability(&bridge, &src_f, &tgt_f, &q).is_ok(),
            "repeatability with identical procedures must return Ok(())"
        );
    }

    // ---------------------------------------------------------------------------
    // AC16 & AC17 (adversarial): bridge from apl-ai-eval-profile.md §11
    // ---------------------------------------------------------------------------

    #[test]
    fn ac16_adversarial_bridge_aspect_family_mismatch() {
        // Bridge claims runner-equivalence but source_aspects = ["accuracy"]
        // and target_aspects = ["judge-score"]. Same scope to isolate the
        // aspect-family failure at step 8(c).
        let common_scope = json!({
            "benchmark_id": "mmlu",
            "benchmark_variant": "default",
            "dataset_split": "dev",
            "subset": "all"
        });

        let src_v = json!({
            "version": "0.1",
            "observer": { "id": "acme-eval-lab" },
            "procedure": {
                "runner_id": "lm-eval-harness@0.4.2",
                "grader_id": "exact-match-v1"
            },
            "aspect": ["accuracy"],
            "scope": common_scope.clone(),
            "invariance": ["score-object-serialization"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        });
        let tgt_v = json!({
            "version": "0.1",
            "observer": { "id": "acme-eval-lab" },
            "procedure": {
                "runner_id": "custom-runner@2.1",
                "grader_id": "exact-match-v1"
            },
            "aspect": ["judge-score"],
            "scope": common_scope,
            "invariance": ["score-object-serialization"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        });

        let src_f = Frame::parse(&src_v).expect("valid source frame");
        let tgt_f = Frame::parse(&tgt_v).expect("valid target frame");

        let bridge_v = json!({
            "version": "0.1",
            "bridge_kind": "runner-equivalence",
            "source_frame": { "hash": src_f.canonical_hash().to_string() },
            "target_frame": { "hash": tgt_f.canonical_hash().to_string() },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["judge-score"],
                "relation_type": "score-delta"
            },
            "assumptions": ["all MMLU results are interchangeable"],
            "losses": []
        });
        let bridge = Bridge::parse(&bridge_v).expect("valid bridge");

        let q = RelationQuery::parse(&json!({
            "left_aspects": ["accuracy"],
            "right_aspects": ["judge-score"],
            "predicate": "score",
            "relation_type": "score-delta"
        }))
        .expect("valid query");

        let err = check_ai_eval_bridge_applicability(&bridge, &src_f, &tgt_f, &q).unwrap_err();
        // Must contain either source-aspect mismatch (step 8a/8b) or
        // aspect-family mismatch (step 8c). The algorithm returns on the first
        // failure; given bridge declares target_aspects=["judge-score"] which
        // matches tgt_f.aspect[0], step 8b passes, so we reach step 8c.
        assert!(
            err.contains(&APL_AI_EVAL_BRIDGE_TARGET_ASPECT_MISMATCH)
                || err.contains(&APL_AI_EVAL_BRIDGE_ASPECT_FAMILY_MISMATCH),
            "expected AplAiEvalBridgeTargetAspectMismatch or AplAiEvalBridgeAspectFamilyMismatch, got {err:?}"
        );
    }
}
