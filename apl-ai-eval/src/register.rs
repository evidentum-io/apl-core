//! Registration of AI-Eval profile diagnostic codes.
//!
//! Downstream applications that deserialize [`apl_core::diagnostics::DiagnosticCode`]
//! values from AI-Eval JSON output MUST call [`register`] once at startup,
//! before any deserialization takes place. The simplest placement is at the
//! top of `main()` or in a `#[ctor]`-style init if the runtime supports it.
//!
//! # Example
//!
//! ```rust
//! apl_ai_eval::register();
//! ```

use crate::diagnostics::{
    APL_AI_EVAL_BENCHMARK_ID_MISMATCH, APL_AI_EVAL_BRIDGE_ASPECT_FAMILY_MISMATCH,
    APL_AI_EVAL_BRIDGE_GRADER_MISMATCH, APL_AI_EVAL_BRIDGE_KIND_INVALID,
    APL_AI_EVAL_BRIDGE_PROCEDURE_MISMATCH, APL_AI_EVAL_BRIDGE_RELATION_TYPE_INVALID,
    APL_AI_EVAL_BRIDGE_RUNNER_MISMATCH, APL_AI_EVAL_BRIDGE_SCOPE_MISMATCH,
    APL_AI_EVAL_BRIDGE_SOURCE_ASPECT_MISMATCH, APL_AI_EVAL_BRIDGE_TARGET_ASPECT_MISMATCH,
    APL_AI_EVAL_PREDICATE_DISALLOWED, APL_AI_EVAL_PREDICATE_INVALID,
    APL_AI_EVAL_QUERY_LEFT_ASPECTS_CARDINALITY_INVALID,
    APL_AI_EVAL_QUERY_RIGHT_ASPECTS_CARDINALITY_INVALID, APL_AI_EVAL_RELATION_TYPE_INVALID,
};

/// Register all AI-Eval profile diagnostic codes into the apl-core whitelist
/// registry.
///
/// Must be called once at application startup before any deserialization of
/// `DiagnosticCode` values that originate from AI-Eval JSON output. Calling
/// this function multiple times is safe and idempotent.
pub fn register() {
    apl_core::diagnostics::register_diagnostic_codes(&[
        APL_AI_EVAL_BRIDGE_KIND_INVALID.as_str(),
        APL_AI_EVAL_BRIDGE_SOURCE_ASPECT_MISMATCH.as_str(),
        APL_AI_EVAL_BRIDGE_TARGET_ASPECT_MISMATCH.as_str(),
        APL_AI_EVAL_BRIDGE_ASPECT_FAMILY_MISMATCH.as_str(),
        APL_AI_EVAL_BRIDGE_SCOPE_MISMATCH.as_str(),
        APL_AI_EVAL_BRIDGE_RELATION_TYPE_INVALID.as_str(),
        APL_AI_EVAL_BRIDGE_RUNNER_MISMATCH.as_str(),
        APL_AI_EVAL_BRIDGE_GRADER_MISMATCH.as_str(),
        APL_AI_EVAL_BRIDGE_PROCEDURE_MISMATCH.as_str(),
        APL_AI_EVAL_PREDICATE_DISALLOWED.as_str(),
        APL_AI_EVAL_PREDICATE_INVALID.as_str(),
        APL_AI_EVAL_RELATION_TYPE_INVALID.as_str(),
        APL_AI_EVAL_QUERY_LEFT_ASPECTS_CARDINALITY_INVALID.as_str(),
        APL_AI_EVAL_QUERY_RIGHT_ASPECTS_CARDINALITY_INVALID.as_str(),
        APL_AI_EVAL_BENCHMARK_ID_MISMATCH.as_str(),
    ]);
}
