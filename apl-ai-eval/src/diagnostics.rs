//! AI-Eval profile diagnostic codes per `apl-ai-eval-profile.md §7.8`.

use apl_core::diagnostics::DiagnosticCode;

// ---------------------------------------------------------------------------
// apl-ai-eval-profile.md §7.8 — Profile diagnostics (bridge)
// ---------------------------------------------------------------------------

/// AI-Eval bridge: `bridge_kind` field is missing, is not a string, or is not
/// in the allowed set `{"runner-equivalence", "grader-equivalence", "repeatability"}`
/// per `apl-ai-eval-profile.md §7.2`.
pub const APL_AI_EVAL_BRIDGE_KIND_INVALID: DiagnosticCode =
    DiagnosticCode::new("apl-ai-eval-bridge-kind-invalid");
/// AI-Eval bridge: source aspect does not match the expected profile aspect.
pub const APL_AI_EVAL_BRIDGE_SOURCE_ASPECT_MISMATCH: DiagnosticCode =
    DiagnosticCode::new("apl-ai-eval-bridge-source-aspect-mismatch");
/// AI-Eval bridge: target aspect does not match the expected profile aspect.
pub const APL_AI_EVAL_BRIDGE_TARGET_ASPECT_MISMATCH: DiagnosticCode =
    DiagnosticCode::new("apl-ai-eval-bridge-target-aspect-mismatch");
/// AI-Eval bridge: source and target aspects are from different aspect families.
pub const APL_AI_EVAL_BRIDGE_ASPECT_FAMILY_MISMATCH: DiagnosticCode =
    DiagnosticCode::new("apl-ai-eval-bridge-aspect-family-mismatch");
/// AI-Eval bridge: `comparison_scope` does not cover the query scope.
pub const APL_AI_EVAL_BRIDGE_SCOPE_MISMATCH: DiagnosticCode =
    DiagnosticCode::new("apl-ai-eval-bridge-scope-mismatch");
/// AI-Eval bridge: `comparison_scope.relation_type` is incompatible with `bridge_kind`.
pub const APL_AI_EVAL_BRIDGE_RELATION_TYPE_INVALID: DiagnosticCode =
    DiagnosticCode::new("apl-ai-eval-bridge-relation-type-invalid");
/// AI-Eval bridge: `runner` field does not match.
pub const APL_AI_EVAL_BRIDGE_RUNNER_MISMATCH: DiagnosticCode =
    DiagnosticCode::new("apl-ai-eval-bridge-runner-mismatch");
/// AI-Eval bridge: `grader` field does not match.
pub const APL_AI_EVAL_BRIDGE_GRADER_MISMATCH: DiagnosticCode =
    DiagnosticCode::new("apl-ai-eval-bridge-grader-mismatch");
/// AI-Eval bridge: `procedure` field does not match.
pub const APL_AI_EVAL_BRIDGE_PROCEDURE_MISMATCH: DiagnosticCode =
    DiagnosticCode::new("apl-ai-eval-bridge-procedure-mismatch");

// ---------------------------------------------------------------------------
// apl-ai-eval-profile.md §7.8 — Profile diagnostics (claim / pairwise-query / cross-check)
// ---------------------------------------------------------------------------

/// AI-Eval claim: predicate is present but not in the profile's allowed set.
pub const APL_AI_EVAL_PREDICATE_DISALLOWED: DiagnosticCode =
    DiagnosticCode::new("apl-ai-eval-predicate-disallowed");
/// AI-Eval pairwise: query `predicate` is not `"score"`.
pub const APL_AI_EVAL_PREDICATE_INVALID: DiagnosticCode =
    DiagnosticCode::new("apl-ai-eval-predicate-invalid");
/// AI-Eval pairwise: query `relation_type` is not in the allowed set.
pub const APL_AI_EVAL_RELATION_TYPE_INVALID: DiagnosticCode =
    DiagnosticCode::new("apl-ai-eval-relation-type-invalid");
/// AI-Eval pairwise gate: `query.left_aspects` does not contain exactly one element.
pub const APL_AI_EVAL_QUERY_LEFT_ASPECTS_CARDINALITY_INVALID: DiagnosticCode =
    DiagnosticCode::new("apl-ai-eval-query-left-aspects-cardinality-invalid");
/// AI-Eval pairwise gate: `query.right_aspects` does not contain exactly one element.
pub const APL_AI_EVAL_QUERY_RIGHT_ASPECTS_CARDINALITY_INVALID: DiagnosticCode =
    DiagnosticCode::new("apl-ai-eval-query-right-aspects-cardinality-invalid");
/// AI-Eval claim: `statement.content.benchmark_id` differs from `frame.scope.benchmark_id`.
pub const APL_AI_EVAL_BENCHMARK_ID_MISMATCH: DiagnosticCode =
    DiagnosticCode::new("apl-ai-eval-benchmark-id-mismatch");
