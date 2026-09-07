//! AI-Eval claim profile checks per apl-ai-eval-profile.md §§3-4, §6, §8.
//!
//! This module provides the claim-level, cross-check, and pairwise-gate
//! implementations for the `APL/AI-Eval v1.0` profile.

use serde_json::Value;

use apl_core::core::claim::{Claim, Statement};
use apl_core::core::frame::{Frame, StringOrObject};
use apl_core::core::hash::parse_hash_string;
use apl_core::core::relation::RelationQuery;
use apl_core::diagnostics::{
    DiagnosticCode, APL_ASPECT_REFS_INVALID, APL_ASPECT_REF_OUT_OF_FRAME, APL_FRAME_ASPECT_INVALID,
    APL_STATEMENT_INVALID, APL_SUBJECT_DIGEST_INVALID, APL_SUBJECT_ID_INVALID, APL_SUBJECT_INVALID,
    APL_SUBJECT_MISSING,
};
use apl_core::profile::trait_def::{BridgeCheckResult, ProfileCheckResult, ProfileFailure};
use apl_core::FailureClass;

use crate::diagnostics::{
    APL_AI_EVAL_BENCHMARK_ID_MISMATCH, APL_AI_EVAL_PREDICATE_DISALLOWED,
    APL_AI_EVAL_PREDICATE_INVALID, APL_AI_EVAL_QUERY_LEFT_ASPECTS_CARDINALITY_INVALID,
    APL_AI_EVAL_QUERY_RIGHT_ASPECTS_CARDINALITY_INVALID, APL_AI_EVAL_RELATION_TYPE_INVALID,
};
use crate::profile::{AI_EVAL_ALLOWED_ASPECTS, AI_EVAL_ALLOWED_UNITS};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check claim-level AI-Eval profile invariants (apl-ai-eval-profile.md §§3-4, §6, §8).
///
/// # Errors
///
/// Returns `Err(ProfileFailure)` if any claim-level invariant is violated.
pub fn check_claim(claim: &Claim) -> ProfileCheckResult {
    // §3.2 — predicate MUST be "score" under the AI-Eval profile.
    // The predicate IS present (Core already checked §5.7); it is just not in
    // the profile's allowed set.
    if claim.claim.statement.predicate != "score" {
        return Err(profile_err(
            FailureClass::ClaimStructureFailure,
            vec![APL_AI_EVAL_PREDICATE_DISALLOWED],
        ));
    }

    // §3.3 — aspect cardinality: exactly one aspect_ref required.
    if claim.claim.aspect_refs.len() != 1 {
        return Err(profile_err(
            FailureClass::ClaimStructureFailure,
            vec![APL_ASPECT_REFS_INVALID],
        ));
    }

    // §3.4 — allowed aspect values.
    let aspect = claim.claim.aspect_refs[0].as_str();
    if !AI_EVAL_ALLOWED_ASPECTS.contains(&aspect) {
        return Err(profile_err(
            FailureClass::ClaimStructureFailure,
            vec![APL_ASPECT_REFS_INVALID],
        ));
    }

    // §4 — subject shape.
    check_subject(claim)?;

    // §6 — statement.content shape.
    check_content(&claim.claim.statement, aspect)?;

    Ok(())
}

/// Cross-check enforcing joint claim+frame invariants (apl-ai-eval-profile.md §5.4 and §6.2).
///
/// Called after both `check_claim` and `check_frame` have returned `Ok(())`.
///
/// - §5.4: `frame.aspect[0]` MUST equal `claim.aspect_refs[0]`.
/// - §6.2: `claim.statement.content.benchmark_id` MUST equal `frame.scope.benchmark_id`.
///
/// # Errors
///
/// Returns `Err(ProfileFailure)` if either joint invariant is violated.
pub fn cross_check(claim: &Claim, frame: &Frame) -> ProfileCheckResult {
    // §5.4 — aspect alignment.
    // frame.aspect cardinality is already guaranteed by check_frame (defensive
    // guard below handles the case where cross_check is called standalone).
    if frame.aspect.len() != 1 {
        return Err(profile_err(
            FailureClass::FrameFailure,
            vec![APL_FRAME_ASPECT_INVALID],
        ));
    }
    if claim.claim.aspect_refs.len() != 1 {
        return Err(profile_err(
            FailureClass::ClaimStructureFailure,
            vec![APL_ASPECT_REFS_INVALID],
        ));
    }
    if frame.aspect[0] != claim.claim.aspect_refs[0] {
        return Err(profile_err(
            FailureClass::SemanticLinkageFailure,
            vec![APL_ASPECT_REF_OUT_OF_FRAME],
        ));
    }

    // §6.2 — benchmark_id linkage.
    // This is a joint claim/frame invariant; failure is a semantic-linkage
    // failure because each artifact is individually valid — they simply do not
    // link semantically.
    let claim_bid = claim
        .claim
        .statement
        .content
        .as_object()
        .and_then(|m| m.get("benchmark_id"))
        .and_then(Value::as_str);
    let frame_bid = match &frame.scope {
        Some(StringOrObject::Object(m)) => m.get("benchmark_id").and_then(Value::as_str),
        _ => None,
    };
    match (claim_bid, frame_bid) {
        (Some(a), Some(b)) if a == b => {}
        _ => {
            return Err(profile_err(
                FailureClass::SemanticLinkageFailure,
                vec![APL_AI_EVAL_BENCHMARK_ID_MISMATCH],
            ));
        }
    }

    Ok(())
}

/// Pairwise profile gate per apl-ai-eval-profile.md §7.1.
///
/// Applies to BOTH same-frame and cross-frame paths. Enforces:
/// - `query.predicate == "score"`
/// - `query.relation_type` in `{"score-delta", "repeatability-check"}`
/// - `query.left_aspects.len() == 1` and `query.right_aspects.len() == 1`
///
/// # Errors
///
/// Returns `Err(Vec<Diagnostic>)` if any pairwise constraint is violated.
pub fn check_pairwise_relation(
    _left: &Claim,
    _right: &Claim,
    _left_frame: &Frame,
    _right_frame: &Frame,
    query: &RelationQuery,
) -> BridgeCheckResult {
    // §7.1 — query predicate MUST be "score".
    if query.predicate != "score" {
        return Err(vec![APL_AI_EVAL_PREDICATE_INVALID]);
    }

    // §7.1 — query relation_type MUST be one of {"score-delta", "repeatability-check"}.
    match query.relation_type.as_str() {
        "score-delta" | "repeatability-check" => {}
        _ => return Err(vec![APL_AI_EVAL_RELATION_TYPE_INVALID]),
    }

    // §7.8.2 — left_aspects cardinality MUST be exactly 1.
    if query.left_aspects.len() != 1 {
        return Err(vec![APL_AI_EVAL_QUERY_LEFT_ASPECTS_CARDINALITY_INVALID]);
    }

    // §7.8.2 — right_aspects cardinality MUST be exactly 1.
    if query.right_aspects.len() != 1 {
        return Err(vec![APL_AI_EVAL_QUERY_RIGHT_ASPECTS_CARDINALITY_INVALID]);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Check subject shape per apl-ai-eval-profile.md §4.
fn check_subject(claim: &Claim) -> ProfileCheckResult {
    let subj = &claim.claim.subject.full;

    // §4 — subject.type MUST be "model-build".
    let type_str = subj.get("type").and_then(Value::as_str).ok_or_else(|| {
        profile_err(
            FailureClass::ClaimStructureFailure,
            vec![APL_SUBJECT_INVALID],
        )
    })?;
    if type_str != "model-build" {
        return Err(profile_err(
            FailureClass::ClaimStructureFailure,
            vec![APL_SUBJECT_INVALID],
        ));
    }

    // §4.1 — artifact_digest REQUIRED and MUST be a valid sha256:<hex> hash.
    let digest_str = subj
        .get("artifact_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            profile_err(
                FailureClass::ClaimStructureFailure,
                vec![APL_SUBJECT_DIGEST_INVALID],
            )
        })?;
    parse_hash_string(digest_str).map_err(|_| {
        profile_err(
            FailureClass::ClaimStructureFailure,
            vec![APL_SUBJECT_DIGEST_INVALID],
        )
    })?;

    // §4.1 — id REQUIRED and MUST be a non-empty string.
    let id_v = subj.get("id").ok_or_else(|| {
        profile_err(
            FailureClass::ClaimStructureFailure,
            vec![APL_SUBJECT_MISSING],
        )
    })?;
    let s = id_v.as_str().ok_or_else(|| {
        profile_err(
            FailureClass::ClaimStructureFailure,
            vec![APL_SUBJECT_ID_INVALID],
        )
    })?;
    if s.is_empty() {
        return Err(profile_err(
            FailureClass::ClaimStructureFailure,
            vec![APL_SUBJECT_ID_INVALID],
        ));
    }

    // §4.2 — optional string fields MUST be non-empty when present.
    for key in ["build_id", "provider", "model_family"] {
        if let Some(v) = subj.get(key) {
            let s = v.as_str().ok_or_else(|| {
                profile_err(
                    FailureClass::ClaimStructureFailure,
                    vec![APL_SUBJECT_INVALID],
                )
            })?;
            if s.is_empty() {
                return Err(profile_err(
                    FailureClass::ClaimStructureFailure,
                    vec![APL_SUBJECT_INVALID],
                ));
            }
        }
    }

    Ok(())
}

/// Check statement.content shape per apl-ai-eval-profile.md §6.
fn check_content(statement: &Statement, aspect: &str) -> ProfileCheckResult {
    let content = statement.content.as_object().ok_or_else(|| {
        profile_err(
            FailureClass::ClaimStructureFailure,
            vec![APL_STATEMENT_INVALID],
        )
    })?;

    // §6.1 — benchmark_id: required non-empty string.
    let _benchmark_id = non_empty_string(content, "benchmark_id")?;

    // §6.1 — metric_id: required non-empty string.
    let metric_id = non_empty_string(content, "metric_id")?;

    // §6.1 — value: required JSON number.
    match content.get("value") {
        Some(v) if v.is_number() => {}
        _ => {
            return Err(profile_err(
                FailureClass::ClaimStructureFailure,
                vec![APL_STATEMENT_INVALID],
            ));
        }
    }

    // §6.1 — unit: required, MUST be in the allowed set.
    let unit = non_empty_string(content, "unit")?;
    if !AI_EVAL_ALLOWED_UNITS.contains(&unit.as_str()) {
        return Err(profile_err(
            FailureClass::ClaimStructureFailure,
            vec![APL_STATEMENT_INVALID],
        ));
    }

    // §6.1 — sample_count: optional, MUST be a positive integer (>= 1) when present.
    if let Some(sc) = content.get("sample_count") {
        match sc.as_u64() {
            Some(n) if n >= 1 => {}
            _ => {
                return Err(profile_err(
                    FailureClass::ClaimStructureFailure,
                    vec![APL_STATEMENT_INVALID],
                ));
            }
        }
    }

    // §6.1 — aggregation: optional, MUST be a non-empty string when present.
    if let Some(agg) = content.get("aggregation") {
        if agg.as_str().map(str::is_empty).unwrap_or(true) {
            return Err(profile_err(
                FailureClass::ClaimStructureFailure,
                vec![APL_STATEMENT_INVALID],
            ));
        }
    }

    // §6.3 — aspect-to-metric compatibility.
    let metric_ok = match aspect {
        "accuracy" => ["accuracy", "exact-match", "f1"].contains(&metric_id.as_str()),
        "judge-score" => metric_id == "judge-score",
        "pass-rate" => metric_id == "pass-rate" || is_passat_pattern(&metric_id),
        "tool-success-rate" => metric_id == "tool-success-rate",
        _ => false,
    };
    if !metric_ok {
        return Err(profile_err(
            FailureClass::ClaimStructureFailure,
            vec![APL_STATEMENT_INVALID],
        ));
    }

    Ok(())
}

/// Returns `true` iff `s` matches `pass@<positive-integer>` (apl-ai-eval-profile.md §6.3).
///
/// The integer MUST be >= 1; `pass@0` is rejected.
fn is_passat_pattern(s: &str) -> bool {
    if !s.starts_with("pass@") {
        return false;
    }
    match s[5..].parse::<u64>() {
        Ok(n) => n >= 1,
        Err(_) => false,
    }
}

/// Extract a required non-empty string from a JSON object field.
fn non_empty_string(
    m: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, ProfileFailure> {
    let s = m.get(key).and_then(Value::as_str).ok_or_else(|| {
        profile_err(
            FailureClass::ClaimStructureFailure,
            vec![APL_STATEMENT_INVALID],
        )
    })?;
    if s.is_empty() {
        return Err(profile_err(
            FailureClass::ClaimStructureFailure,
            vec![APL_STATEMENT_INVALID],
        ));
    }
    Ok(s.to_owned())
}

/// Construct a `ProfileFailure` from a failure class and diagnostic list.
fn profile_err(failure_class: FailureClass, diagnostics: Vec<DiagnosticCode>) -> ProfileFailure {
    ProfileFailure {
        failure_class,
        diagnostics,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod claim_tests {
    use super::*;
    use crate::profile::AiEvalProfile;
    use apl_core::core::claim::{Claim, ClaimInner, ClaimKind, Statement, Subject};
    use apl_core::core::hash::{Hash, Reference};
    use apl_core::diagnostics::{
        APL_ASPECT_REFS_INVALID, APL_STATEMENT_INVALID, APL_SUBJECT_DIGEST_INVALID,
        APL_SUBJECT_ID_INVALID, APL_SUBJECT_INVALID, APL_SUBJECT_MISSING,
    };
    use apl_core::profile::trait_def::Profile;
    use apl_core::FailureClass;
    use serde_json::json;

    fn h(b: u8) -> String {
        format!("sha256:{}", hex::encode([b; 32]))
    }

    fn valid_ai_eval_claim() -> Claim {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:acme-gpt-7b-build-42",
                    "build_id": "42",
                    "artifact_digest": h(0x42),
                    "provider": "acme",
                    "model_family": "acme-gpt-7b"
                },
                "aspect_refs": ["accuracy"],
                "statement": {
                    "predicate": "score",
                    "content": {
                        "benchmark_id": "mmlu",
                        "metric_id": "accuracy",
                        "value": 0.781,
                        "unit": "fraction"
                    }
                }
            },
            "frame_ref": { "hash": h(0x11) }
        });
        Claim::parse(&v).expect("valid claim fixture")
    }

    // AC14 partial: accepts valid AI-Eval claim.
    #[test]
    fn accepts_valid_ai_eval_claim() {
        assert!(AiEvalProfile.check_claim(&valid_ai_eval_claim()).is_ok());
    }

    // AC1: predicate != "score" → ClaimStructureFailure + AplAiEvalPredicateDisallowed.
    #[test]
    fn rejects_predicate_not_score() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:acme-gpt-7b-build-42",
                    "artifact_digest": h(0x42)
                },
                "aspect_refs": ["accuracy"],
                "statement": {
                    "predicate": "other",
                    "content": {
                        "benchmark_id": "mmlu",
                        "metric_id": "accuracy",
                        "value": 0.781,
                        "unit": "fraction"
                    }
                }
            },
            "frame_ref": { "hash": h(0x11) }
        });
        let c = Claim::parse(&v).expect("claim must parse at core level");
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_AI_EVAL_PREDICATE_DISALLOWED));
    }

    // AC2: aspect_refs.len() != 1 → ClaimStructureFailure.
    #[test]
    fn rejects_multiple_aspect_refs() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:acme-gpt-7b-build-42",
                    "artifact_digest": h(0x42)
                },
                "aspect_refs": ["accuracy", "pass-rate"],
                "statement": {
                    "predicate": "score",
                    "content": {
                        "benchmark_id": "mmlu",
                        "metric_id": "accuracy",
                        "value": 0.781,
                        "unit": "fraction"
                    }
                }
            },
            "frame_ref": { "hash": h(0x11) }
        });
        let c = Claim::parse(&v).expect("claim must parse at core level");
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_ASPECT_REFS_INVALID));
    }

    // AC3: aspect not in allowed set.
    #[test]
    fn rejects_aspect_not_in_allowed_set() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:x",
                    "artifact_digest": h(0x42)
                },
                "aspect_refs": ["unknown-aspect"],
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
        let c = Claim::parse(&v).expect("claim must parse at core level");
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_ASPECT_REFS_INVALID));
    }

    // AC4: subject.type != "model-build".
    #[test]
    fn rejects_subject_type_not_model_build() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "dataset",
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
        let c = Claim::parse(&v).expect("claim must parse at core level");
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_SUBJECT_INVALID));
    }

    // AC4: subject.type missing.
    #[test]
    fn rejects_subject_type_missing() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
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
        let c = Claim::parse(&v).expect("claim must parse at core level");
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_SUBJECT_INVALID));
    }

    // AC5: artifact_digest missing.
    #[test]
    fn rejects_artifact_digest_missing() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:x"
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
        let c = Claim::parse(&v).expect("claim must parse at core level");
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_SUBJECT_DIGEST_INVALID));
    }

    // AC6: artifact_digest not matching sha256:<hex>.
    #[test]
    fn rejects_artifact_digest_invalid_format() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:x",
                    "artifact_digest": "md5:abc123"
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
        let c = Claim::parse(&v).expect("claim must parse at core level");
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_SUBJECT_DIGEST_INVALID));
    }

    // §4.1: subject.id absent → ClaimStructureFailure + AplSubjectMissing.
    //
    // Core accepts a subject that has `digest` (core-level field) but no `id`.
    // AI-Eval additionally requires `id` as a mandatory field, so the profile
    // check must reject it with APL_SUBJECT_MISSING rather than silently
    // passing the claim.
    #[test]
    fn rejects_subject_without_id_as_absent() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "digest": h(0x11),
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
        let c = Claim::parse(&v).expect("claim must parse at core level");
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_SUBJECT_MISSING));
        assert!(!err.diagnostics.contains(&APL_SUBJECT_ID_INVALID));
    }

    /// Build a `Claim` directly from a hand-crafted subject map, bypassing
    /// `Claim::parse`. This lets tests reach the defensive `id` branches in
    /// `check_subject` that Core already gates at parse time.
    fn claim_with_raw_subject(subject_map: serde_json::Map<String, serde_json::Value>) -> Claim {
        Claim {
            version: "0.1".to_owned(),
            frame_ref: Reference {
                hash: Hash::from_bytes([0x11u8; 32]),
                resolver_hint: None,
            },
            bridge_refs: None,
            transformation_refs: None,
            claim: ClaimInner {
                kind: ClaimKind::Observation,
                subject: Subject {
                    id: None,
                    digest: None,
                    full: subject_map,
                },
                aspect_refs: vec!["accuracy".to_owned()],
                statement: Statement {
                    predicate: "score".to_owned(),
                    content: json!({
                        "benchmark_id": "mmlu",
                        "metric_id": "accuracy",
                        "value": 0.5,
                        "unit": "fraction"
                    }),
                },
                related_frames: None,
            },
        }
    }

    // §4.1: subject.id present as a non-string (integer) → ClaimStructureFailure + AplSubjectIdInvalid.
    //
    // Core rejects `subject.id` that is not a non-empty string at parse time, so
    // this branch in `check_subject` is defensive. The test reaches it by
    // constructing a `Claim` directly, bypassing `Claim::parse`.
    #[test]
    fn rejects_subject_id_non_string() {
        let mut map = serde_json::Map::new();
        map.insert("type".to_owned(), json!("model-build"));
        map.insert("id".to_owned(), json!(42));
        map.insert("artifact_digest".to_owned(), json!(h(0x42)));
        let claim = claim_with_raw_subject(map);
        let err = check_subject(&claim).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_SUBJECT_ID_INVALID));
    }

    // §4.1: subject.id present as an empty string → ClaimStructureFailure + AplSubjectIdInvalid.
    //
    // Core rejects `subject.id` that is not a non-empty string at parse time, so
    // this branch in `check_subject` is defensive. The test reaches it by
    // constructing a `Claim` directly, bypassing `Claim::parse`.
    #[test]
    fn rejects_subject_id_empty_string() {
        let mut map = serde_json::Map::new();
        map.insert("type".to_owned(), json!("model-build"));
        map.insert("id".to_owned(), json!(""));
        map.insert("artifact_digest".to_owned(), json!(h(0x42)));
        let claim = claim_with_raw_subject(map);
        let err = check_subject(&claim).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_SUBJECT_ID_INVALID));
    }

    // AC7: unit not in allowed set.
    #[test]
    fn rejects_unit_out_of_set() {
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
                        "unit": "raw-score"
                    }
                }
            },
            "frame_ref": { "hash": h(0x11) }
        });
        let c = Claim::parse(&v).expect("claim must parse at core level");
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_STATEMENT_INVALID));
    }

    // AC8: aspect/metric mismatch.
    #[test]
    fn rejects_aspect_metric_mismatch() {
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
                        "metric_id": "judge-score",
                        "value": 0.5,
                        "unit": "fraction"
                    }
                }
            },
            "frame_ref": { "hash": h(0x11) }
        });
        let c = Claim::parse(&v).expect("claim must parse at core level");
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_STATEMENT_INVALID));
    }

    // AC9: accepts pass@k when aspect = "pass-rate".
    #[test]
    fn accepts_pass_at_k_pattern() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:x",
                    "artifact_digest": h(0x42)
                },
                "aspect_refs": ["pass-rate"],
                "statement": {
                    "predicate": "score",
                    "content": {
                        "benchmark_id": "humaneval",
                        "metric_id": "pass@10",
                        "value": 0.85,
                        "unit": "fraction"
                    }
                }
            },
            "frame_ref": { "hash": h(0x11) }
        });
        let c = Claim::parse(&v).expect("claim must parse at core level");
        assert!(AiEvalProfile.check_claim(&c).is_ok());
    }

    // pass@0 MUST be rejected.
    #[test]
    fn rejects_pass_at_zero() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:x",
                    "artifact_digest": h(0x42)
                },
                "aspect_refs": ["pass-rate"],
                "statement": {
                    "predicate": "score",
                    "content": {
                        "benchmark_id": "humaneval",
                        "metric_id": "pass@0",
                        "value": 0.85,
                        "unit": "fraction"
                    }
                }
            },
            "frame_ref": { "hash": h(0x11) }
        });
        let c = Claim::parse(&v).expect("claim must parse at core level");
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert!(err.diagnostics.contains(&APL_STATEMENT_INVALID));
    }

    // AC15: "Invalid Profile Example" from §12 — missing subject.type and subject.artifact_digest.
    #[test]
    fn invalid_profile_example_from_spec_12_rejected() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "model:acme-gpt-7b" },
                "aspect_refs": ["accuracy"],
                "statement": {
                    "predicate": "score",
                    "content": {
                        "benchmark_id": "mmlu",
                        "metric_id": "accuracy",
                        "value": 0.781,
                        "unit": "fraction"
                    }
                }
            },
            "frame_ref": { "hash": format!("sha256:{}", "c".repeat(64)) }
        });
        let c = Claim::parse(&v).expect("claim must parse at core level");
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_SUBJECT_INVALID));
    }
}

#[cfg(test)]
mod cross_check_tests {
    use super::*;
    use crate::profile::AiEvalProfile;
    use apl_core::core::claim::Claim;
    use apl_core::core::frame::Frame;
    use apl_core::diagnostics::APL_ASPECT_REF_OUT_OF_FRAME;
    use apl_core::profile::trait_def::Profile;
    use apl_core::FailureClass;
    use serde_json::json;

    fn h(b: u8) -> String {
        format!("sha256:{}", hex::encode([b; 32]))
    }

    fn make_claim(aspect: &str, benchmark_id: &str) -> Claim {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:x",
                    "artifact_digest": h(0x42)
                },
                "aspect_refs": [aspect],
                "statement": {
                    "predicate": "score",
                    "content": {
                        "benchmark_id": benchmark_id,
                        "metric_id": "accuracy",
                        "value": 0.5,
                        "unit": "fraction"
                    }
                }
            },
            "frame_ref": { "hash": h(0x11) }
        });
        Claim::parse(&v).expect("valid claim fixture")
    }

    fn make_frame(aspect: &str, benchmark_id: &str) -> Frame {
        let v = json!({
            "version": "0.1",
            "observer": { "id": "acme-eval-lab" },
            "procedure": {
                "runner_id": "lm-eval-harness@0.4.2",
                "grader_id": "exact-match-v1"
            },
            "aspect": [aspect],
            "scope": {
                "benchmark_id": benchmark_id,
                "benchmark_variant": "default",
                "dataset_split": "dev"
            },
            "invariance": ["score-object-serialization"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        });
        Frame::parse(&v).expect("valid frame fixture")
    }

    // AC12: benchmark_id mismatch → SemanticLinkageFailure + AplAiEvalBenchmarkIdMismatch.
    #[test]
    fn rejects_benchmark_id_mismatch() {
        let c = make_claim("accuracy", "mmlu");
        let f = make_frame("accuracy", "gpqa");
        let err = AiEvalProfile.cross_check(&c, &f).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::SemanticLinkageFailure);
        assert!(err.diagnostics.contains(&APL_AI_EVAL_BENCHMARK_ID_MISMATCH));
    }

    // AC13: aspect mismatch → SemanticLinkageFailure + AplAspectRefOutOfFrame.
    #[test]
    fn rejects_aspect_mismatch() {
        let c = make_claim("accuracy", "mmlu");
        let f = make_frame("pass-rate", "mmlu");
        let err = AiEvalProfile.cross_check(&c, &f).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::SemanticLinkageFailure);
        assert!(err.diagnostics.contains(&APL_ASPECT_REF_OUT_OF_FRAME));
    }

    // AC14 partial: matching claim+frame accepted.
    #[test]
    fn accepts_matching_claim_and_frame() {
        let c = make_claim("accuracy", "mmlu");
        let f = make_frame("accuracy", "mmlu");
        assert!(AiEvalProfile.cross_check(&c, &f).is_ok());
    }
}

#[cfg(test)]
mod pairwise_gate_tests {
    use super::*;
    use crate::diagnostics::{
        APL_AI_EVAL_BRIDGE_SOURCE_ASPECT_MISMATCH, APL_AI_EVAL_BRIDGE_TARGET_ASPECT_MISMATCH,
    };
    use crate::profile::AiEvalProfile;
    use apl_core::core::claim::Claim;
    use apl_core::core::frame::Frame;
    use apl_core::core::relation::RelationQuery;
    use apl_core::profile::trait_def::Profile;
    use serde_json::json;

    fn h(b: u8) -> String {
        format!("sha256:{}", hex::encode([b; 32]))
    }

    fn make_claim_score(aspect: &str) -> Claim {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:x",
                    "artifact_digest": h(0x42)
                },
                "aspect_refs": [aspect],
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
        Claim::parse(&v).expect("valid claim fixture")
    }

    fn make_frame_simple() -> Frame {
        let v = json!({
            "version": "0.1",
            "observer": "acme",
            "procedure": "p",
            "aspect": ["accuracy"],
            "scope": "s",
            "invariance": ["i"],
            "exclusions": ["e"]
        });
        Frame::parse(&v).expect("valid frame fixture")
    }

    fn make_query(
        predicate: &str,
        relation_type: &str,
        left: &[&str],
        right: &[&str],
    ) -> RelationQuery {
        let v = json!({
            "left_aspects": left,
            "right_aspects": right,
            "predicate": predicate,
            "relation_type": relation_type
        });
        RelationQuery::parse(&v).expect("valid query fixture")
    }

    // AC16: predicate != "score" → AplAiEvalPredicateInvalid.
    #[test]
    fn rejects_predicate_not_score_same_frame_path() {
        let c = make_claim_score("accuracy");
        let f = make_frame_simple();
        let q = make_query("count", "score-delta", &["accuracy"], &["accuracy"]);
        let err = AiEvalProfile
            .check_pairwise_relation(&c, &c, &f, &f, &q)
            .unwrap_err();
        assert!(err.contains(&APL_AI_EVAL_PREDICATE_INVALID));
    }

    // AC17: relation_type not in allowed set.
    #[test]
    fn rejects_relation_type_not_allowed_same_frame_path() {
        let c = make_claim_score("accuracy");
        let f = make_frame_simple();
        let q = make_query("score", "score-ratio", &["accuracy"], &["accuracy"]);
        let err = AiEvalProfile
            .check_pairwise_relation(&c, &c, &f, &f, &q)
            .unwrap_err();
        assert!(err.contains(&APL_AI_EVAL_RELATION_TYPE_INVALID));
    }

    // AC16: cross-frame path also rejects bad predicate.
    #[test]
    fn rejects_predicate_not_score_cross_frame_path() {
        let c = make_claim_score("accuracy");
        let f1 = make_frame_simple();
        let f2 = {
            let v = json!({
                "version": "0.1",
                "observer": "other",
                "procedure": "p",
                "aspect": ["accuracy"],
                "scope": "s2",
                "invariance": ["i"],
                "exclusions": ["e"]
            });
            Frame::parse(&v).expect("valid frame fixture")
        };
        let q = make_query("count", "score-delta", &["accuracy"], &["accuracy"]);
        let err = AiEvalProfile
            .check_pairwise_relation(&c, &c, &f1, &f2, &q)
            .unwrap_err();
        assert!(err.contains(&APL_AI_EVAL_PREDICATE_INVALID));
    }

    // AC17: cross-frame path also rejects disallowed relation_type.
    #[test]
    fn rejects_disallowed_relation_type_on_cross_frame_pair() {
        let c = make_claim_score("accuracy");
        let f = make_frame_simple();
        let q = make_query("score", "score-ratio", &["accuracy"], &["accuracy"]);
        let err = AiEvalProfile
            .check_pairwise_relation(&c, &c, &f, &f, &q)
            .unwrap_err();
        assert!(err.contains(&APL_AI_EVAL_RELATION_TYPE_INVALID));
    }

    // AC16+AC17: accepts score-delta.
    #[test]
    fn accepts_score_delta_on_same_frame_pair() {
        let c = make_claim_score("accuracy");
        let f = make_frame_simple();
        let q = make_query("score", "score-delta", &["accuracy"], &["accuracy"]);
        assert!(AiEvalProfile
            .check_pairwise_relation(&c, &c, &f, &f, &q)
            .is_ok());
    }

    // AC16+AC17: accepts repeatability-check.
    #[test]
    fn accepts_repeatability_check_on_same_frame_pair() {
        let c = make_claim_score("accuracy");
        let f = make_frame_simple();
        let q = make_query("score", "repeatability-check", &["accuracy"], &["accuracy"]);
        assert!(AiEvalProfile
            .check_pairwise_relation(&c, &c, &f, &f, &q)
            .is_ok());
    }

    // AC18: left_aspects cardinality != 1.
    #[test]
    fn rejects_left_aspects_cardinality_not_one() {
        let c = make_claim_score("accuracy");
        let f = make_frame_simple();
        let q = make_query(
            "score",
            "score-delta",
            &["accuracy", "pass-rate"],
            &["accuracy"],
        );
        let err = AiEvalProfile
            .check_pairwise_relation(&c, &c, &f, &f, &q)
            .unwrap_err();
        assert!(err.contains(&APL_AI_EVAL_QUERY_LEFT_ASPECTS_CARDINALITY_INVALID));
        assert!(!err.contains(&APL_AI_EVAL_BRIDGE_SOURCE_ASPECT_MISMATCH));
    }

    // AC18: right_aspects cardinality != 1.
    #[test]
    fn rejects_right_aspects_cardinality_not_one() {
        let c = make_claim_score("accuracy");
        let f = make_frame_simple();
        let q = make_query(
            "score",
            "score-delta",
            &["accuracy"],
            &["accuracy", "pass-rate"],
        );
        let err = AiEvalProfile
            .check_pairwise_relation(&c, &c, &f, &f, &q)
            .unwrap_err();
        assert!(err.contains(&APL_AI_EVAL_QUERY_RIGHT_ASPECTS_CARDINALITY_INVALID));
        assert!(!err.contains(&APL_AI_EVAL_BRIDGE_TARGET_ASPECT_MISMATCH));
    }
}

#[cfg(test)]
mod is_passat_tests {
    use super::*;

    #[test]
    fn pass_at_1_is_valid() {
        assert!(is_passat_pattern("pass@1"));
    }

    #[test]
    fn pass_at_10_is_valid() {
        assert!(is_passat_pattern("pass@10"));
    }

    #[test]
    fn pass_at_0_is_invalid() {
        assert!(!is_passat_pattern("pass@0"));
    }

    #[test]
    fn pass_at_negative_is_invalid() {
        assert!(!is_passat_pattern("pass@-1"));
    }

    #[test]
    fn pass_rate_without_at_is_not_passat() {
        assert!(!is_passat_pattern("pass-rate"));
    }

    #[test]
    fn pass_at_non_numeric_is_invalid() {
        assert!(!is_passat_pattern("pass@k"));
    }

    #[test]
    fn pass_at_empty_suffix_is_invalid() {
        assert!(!is_passat_pattern("pass@"));
    }
}

#[cfg(test)]
mod cross_check_guard_tests {
    use super::*;
    use crate::profile::AiEvalProfile;
    use apl_core::core::claim::Claim;
    use apl_core::core::frame::Frame;
    use apl_core::diagnostics::{APL_ASPECT_REFS_INVALID, APL_FRAME_ASPECT_INVALID};
    use apl_core::profile::trait_def::Profile;
    use apl_core::FailureClass;
    use serde_json::json;

    fn h(b: u8) -> String {
        format!("sha256:{}", hex::encode([b; 32]))
    }

    fn make_claim_two_aspects() -> Claim {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:x",
                    "artifact_digest": h(0x42)
                },
                "aspect_refs": ["accuracy", "pass-rate"],
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
        Claim::parse(&v).expect("claim must parse at core level")
    }

    fn make_frame_two_aspects() -> Frame {
        let v = json!({
            "version": "0.1",
            "observer": "acme",
            "procedure": "p",
            "aspect": ["accuracy", "pass-rate"],
            "scope": "s",
            "invariance": ["i"],
            "exclusions": ["e"]
        });
        Frame::parse(&v).expect("frame with two aspects must parse")
    }

    fn make_frame_one_aspect(aspect: &str, benchmark_id: &str) -> Frame {
        let v = json!({
            "version": "0.1",
            "observer": { "id": "acme-eval-lab" },
            "procedure": {
                "runner_id": "lm-eval-harness@0.4.2",
                "grader_id": "exact-match-v1"
            },
            "aspect": [aspect],
            "scope": {
                "benchmark_id": benchmark_id,
                "benchmark_variant": "default",
                "dataset_split": "dev"
            },
            "invariance": ["score-object-serialization"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        });
        Frame::parse(&v).expect("valid frame fixture")
    }

    fn make_claim_one_aspect(aspect: &str, benchmark_id: &str) -> Claim {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:x",
                    "artifact_digest": h(0x42)
                },
                "aspect_refs": [aspect],
                "statement": {
                    "predicate": "score",
                    "content": {
                        "benchmark_id": benchmark_id,
                        "metric_id": "accuracy",
                        "value": 0.5,
                        "unit": "fraction"
                    }
                }
            },
            "frame_ref": { "hash": h(0x11) }
        });
        Claim::parse(&v).expect("valid claim fixture")
    }

    // cross_check defensive guard: frame.aspect.len() != 1 → FrameFailure + AplFrameAspectInvalid.
    #[test]
    fn cross_check_rejects_frame_with_multiple_aspects() {
        let claim = make_claim_one_aspect("accuracy", "mmlu");
        let frame = make_frame_two_aspects();
        let err = cross_check(&claim, &frame).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::FrameFailure);
        assert!(err.diagnostics.contains(&APL_FRAME_ASPECT_INVALID));
    }

    // cross_check defensive guard: claim.aspect_refs.len() != 1 → ClaimStructureFailure.
    #[test]
    fn cross_check_rejects_claim_with_multiple_aspect_refs() {
        let claim = make_claim_two_aspects();
        let frame = make_frame_one_aspect("accuracy", "mmlu");
        let err = cross_check(&claim, &frame).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_ASPECT_REFS_INVALID));
    }

    // cross_check: frame.scope is not an object → SemanticLinkageFailure + AplAiEvalBenchmarkIdMismatch.
    #[test]
    fn cross_check_rejects_when_frame_scope_has_no_benchmark_id() {
        let claim = make_claim_one_aspect("accuracy", "mmlu");
        let frame_v = json!({
            "version": "0.1",
            "observer": "acme",
            "procedure": "p",
            "aspect": ["accuracy"],
            "scope": "no-benchmark-id-here",
            "invariance": ["i"],
            "exclusions": ["e"]
        });
        let frame = Frame::parse(&frame_v).expect("frame with string scope parses");
        let err = AiEvalProfile.cross_check(&claim, &frame).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::SemanticLinkageFailure);
        assert!(err.diagnostics.contains(&APL_AI_EVAL_BENCHMARK_ID_MISMATCH));
    }
}

#[cfg(test)]
mod subject_optional_fields_tests {
    use crate::profile::AiEvalProfile;
    use apl_core::core::claim::Claim;
    use apl_core::diagnostics::APL_SUBJECT_INVALID;
    use apl_core::profile::trait_def::Profile;
    use apl_core::FailureClass;
    use serde_json::json;

    fn h(b: u8) -> String {
        format!("sha256:{}", hex::encode([b; 32]))
    }

    // §4.2 — optional field build_id is a non-string → AplSubjectInvalid.
    #[test]
    fn rejects_build_id_non_string() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:x",
                    "artifact_digest": h(0x42),
                    "build_id": 99
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
        let c = Claim::parse(&v).expect("claim must parse at core level");
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_SUBJECT_INVALID));
    }

    // §4.2 — optional field provider is an empty string → AplSubjectInvalid.
    #[test]
    fn rejects_provider_empty_string() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:x",
                    "artifact_digest": h(0x42),
                    "provider": ""
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
        let c = Claim::parse(&v).expect("claim must parse at core level");
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_SUBJECT_INVALID));
    }

    // §4.2 — optional field model_family is a non-string → AplSubjectInvalid.
    #[test]
    fn rejects_model_family_non_string() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:x",
                    "artifact_digest": h(0x42),
                    "model_family": true
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
        let c = Claim::parse(&v).expect("claim must parse at core level");
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_SUBJECT_INVALID));
    }
}

#[cfg(test)]
mod content_validation_tests {
    use crate::profile::AiEvalProfile;
    use apl_core::core::claim::Claim;
    use apl_core::diagnostics::APL_STATEMENT_INVALID;
    use apl_core::profile::trait_def::Profile;
    use apl_core::FailureClass;
    use serde_json::json;

    fn h(b: u8) -> String {
        format!("sha256:{}", hex::encode([b; 32]))
    }

    fn base_claim_with_content(content: serde_json::Value) -> Claim {
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
                    "content": content
                }
            },
            "frame_ref": { "hash": h(0x11) }
        });
        Claim::parse(&v).expect("claim must parse at core level")
    }

    // content is not an object → AplStatementInvalid.
    #[test]
    fn rejects_content_not_object() {
        let c = base_claim_with_content(json!("string-content"));
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::ClaimStructureFailure);
        assert!(err.diagnostics.contains(&APL_STATEMENT_INVALID));
    }

    // benchmark_id missing → AplStatementInvalid.
    #[test]
    fn rejects_benchmark_id_missing() {
        let c = base_claim_with_content(json!({
            "metric_id": "accuracy",
            "value": 0.5,
            "unit": "fraction"
        }));
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert!(err.diagnostics.contains(&APL_STATEMENT_INVALID));
    }

    // benchmark_id empty string → AplStatementInvalid.
    #[test]
    fn rejects_benchmark_id_empty_string() {
        let c = base_claim_with_content(json!({
            "benchmark_id": "",
            "metric_id": "accuracy",
            "value": 0.5,
            "unit": "fraction"
        }));
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert!(err.diagnostics.contains(&APL_STATEMENT_INVALID));
    }

    // metric_id missing → AplStatementInvalid.
    #[test]
    fn rejects_metric_id_missing() {
        let c = base_claim_with_content(json!({
            "benchmark_id": "mmlu",
            "value": 0.5,
            "unit": "fraction"
        }));
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert!(err.diagnostics.contains(&APL_STATEMENT_INVALID));
    }

    // value missing → AplStatementInvalid.
    #[test]
    fn rejects_value_missing() {
        let c = base_claim_with_content(json!({
            "benchmark_id": "mmlu",
            "metric_id": "accuracy",
            "unit": "fraction"
        }));
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert!(err.diagnostics.contains(&APL_STATEMENT_INVALID));
    }

    // value is a string (not number) → AplStatementInvalid.
    #[test]
    fn rejects_value_not_number() {
        let c = base_claim_with_content(json!({
            "benchmark_id": "mmlu",
            "metric_id": "accuracy",
            "value": "high",
            "unit": "fraction"
        }));
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert!(err.diagnostics.contains(&APL_STATEMENT_INVALID));
    }

    // sample_count = 0 → AplStatementInvalid.
    #[test]
    fn rejects_sample_count_zero() {
        let c = base_claim_with_content(json!({
            "benchmark_id": "mmlu",
            "metric_id": "accuracy",
            "value": 0.5,
            "unit": "fraction",
            "sample_count": 0
        }));
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert!(err.diagnostics.contains(&APL_STATEMENT_INVALID));
    }

    // sample_count is a string → AplStatementInvalid.
    #[test]
    fn rejects_sample_count_non_integer() {
        let c = base_claim_with_content(json!({
            "benchmark_id": "mmlu",
            "metric_id": "accuracy",
            "value": 0.5,
            "unit": "fraction",
            "sample_count": "many"
        }));
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert!(err.diagnostics.contains(&APL_STATEMENT_INVALID));
    }

    // aggregation = "" → AplStatementInvalid.
    #[test]
    fn rejects_aggregation_empty_string() {
        let c = base_claim_with_content(json!({
            "benchmark_id": "mmlu",
            "metric_id": "accuracy",
            "value": 0.5,
            "unit": "fraction",
            "aggregation": ""
        }));
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert!(err.diagnostics.contains(&APL_STATEMENT_INVALID));
    }

    // aggregation = 42 (non-string) → AplStatementInvalid.
    #[test]
    fn rejects_aggregation_non_string() {
        let c = base_claim_with_content(json!({
            "benchmark_id": "mmlu",
            "metric_id": "accuracy",
            "value": 0.5,
            "unit": "fraction",
            "aggregation": 42
        }));
        let err = AiEvalProfile.check_claim(&c).unwrap_err();
        assert!(err.diagnostics.contains(&APL_STATEMENT_INVALID));
    }

    // All four aspect/metric match arms: judge-score, pass-rate (literal), tool-success-rate.
    #[test]
    fn accepts_judge_score_aspect_metric() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:x",
                    "artifact_digest": h(0x42)
                },
                "aspect_refs": ["judge-score"],
                "statement": {
                    "predicate": "score",
                    "content": {
                        "benchmark_id": "mt-bench",
                        "metric_id": "judge-score",
                        "value": 8.5,
                        "unit": "points"
                    }
                }
            },
            "frame_ref": { "hash": h(0x11) }
        });
        let c = Claim::parse(&v).expect("valid claim fixture");
        assert!(AiEvalProfile.check_claim(&c).is_ok());
    }

    #[test]
    fn accepts_pass_rate_literal_metric() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:x",
                    "artifact_digest": h(0x42)
                },
                "aspect_refs": ["pass-rate"],
                "statement": {
                    "predicate": "score",
                    "content": {
                        "benchmark_id": "humaneval",
                        "metric_id": "pass-rate",
                        "value": 0.75,
                        "unit": "fraction"
                    }
                }
            },
            "frame_ref": { "hash": h(0x11) }
        });
        let c = Claim::parse(&v).expect("valid claim fixture");
        assert!(AiEvalProfile.check_claim(&c).is_ok());
    }

    #[test]
    fn accepts_tool_success_rate_aspect_metric() {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:x",
                    "artifact_digest": h(0x42)
                },
                "aspect_refs": ["tool-success-rate"],
                "statement": {
                    "predicate": "score",
                    "content": {
                        "benchmark_id": "agentbench",
                        "metric_id": "tool-success-rate",
                        "value": 0.9,
                        "unit": "fraction"
                    }
                }
            },
            "frame_ref": { "hash": h(0x11) }
        });
        let c = Claim::parse(&v).expect("valid claim fixture");
        assert!(AiEvalProfile.check_claim(&c).is_ok());
    }

    // §6.1 unit "percent" is valid.
    #[test]
    fn accepts_unit_percent() {
        let c = base_claim_with_content(json!({
            "benchmark_id": "mmlu",
            "metric_id": "accuracy",
            "value": 78.1,
            "unit": "percent"
        }));
        assert!(AiEvalProfile.check_claim(&c).is_ok());
    }

    // §6.1 sample_count = 1 is valid.
    #[test]
    fn accepts_sample_count_one() {
        let c = base_claim_with_content(json!({
            "benchmark_id": "mmlu",
            "metric_id": "accuracy",
            "value": 0.5,
            "unit": "fraction",
            "sample_count": 1
        }));
        assert!(AiEvalProfile.check_claim(&c).is_ok());
    }

    // §6.1 aggregation non-empty string is valid.
    #[test]
    fn accepts_aggregation_non_empty() {
        let c = base_claim_with_content(json!({
            "benchmark_id": "mmlu",
            "metric_id": "accuracy",
            "value": 0.5,
            "unit": "fraction",
            "aggregation": "mean"
        }));
        assert!(AiEvalProfile.check_claim(&c).is_ok());
    }

    // §6.3 accuracy/exact-match metric is valid.
    #[test]
    fn accepts_accuracy_aspect_with_exact_match_metric() {
        let c = base_claim_with_content(json!({
            "benchmark_id": "mmlu",
            "metric_id": "exact-match",
            "value": 0.6,
            "unit": "fraction"
        }));
        assert!(AiEvalProfile.check_claim(&c).is_ok());
    }

    // §6.3 accuracy/f1 metric is valid.
    #[test]
    fn accepts_accuracy_aspect_with_f1_metric() {
        let c = base_claim_with_content(json!({
            "benchmark_id": "mmlu",
            "metric_id": "f1",
            "value": 0.7,
            "unit": "fraction"
        }));
        assert!(AiEvalProfile.check_claim(&c).is_ok());
    }
}
