//! AI-Eval frame profile checks per apl-ai-eval-profile.md §5, §8.

use serde_json::Value;

use apl_core::core::frame::{Frame, StringOrObject};
use apl_core::diagnostics::{
    DiagnosticCode, APL_FRAME_ASPECT_INVALID, APL_FRAME_EXCLUSIONS_INVALID,
    APL_FRAME_KERNEL_MISSING, APL_FRAME_SCOPE_OR_RESOLUTION_MISSING,
};
use apl_core::profile::trait_def::{ProfileCheckResult, ProfileFailure};
use apl_core::FailureClass;

use crate::profile::{AI_EVAL_ALLOWED_ASPECTS, AI_EVAL_REQUIRED_EXCLUSIONS};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check frame-level AI-Eval profile invariants (apl-ai-eval-profile.md §5, §8).
///
/// # Errors
///
/// Returns `Err(ProfileFailure)` if any frame-level invariant is violated.
pub fn check_frame(frame: &Frame) -> ProfileCheckResult {
    // §5.2 — procedure MUST be an object with non-empty runner_id + grader_id.
    let proc_obj = match &frame.procedure {
        Some(StringOrObject::Object(m)) => m,
        _ => {
            return Err(profile_err(
                FailureClass::FrameFailure,
                vec![APL_FRAME_KERNEL_MISSING],
            ));
        }
    };
    require_non_empty_string(proc_obj, "runner_id", APL_FRAME_KERNEL_MISSING)?;
    require_non_empty_string(proc_obj, "grader_id", APL_FRAME_KERNEL_MISSING)?;

    // §5.3 — scope MUST be an object with benchmark_id, benchmark_variant, dataset_split.
    let scope_obj = match &frame.scope {
        Some(StringOrObject::Object(m)) => m,
        _ => {
            return Err(profile_err(
                FailureClass::FrameFailure,
                vec![APL_FRAME_SCOPE_OR_RESOLUTION_MISSING],
            ));
        }
    };
    require_non_empty_string(scope_obj, "benchmark_id", APL_FRAME_KERNEL_MISSING)?;
    require_non_empty_string(scope_obj, "benchmark_variant", APL_FRAME_KERNEL_MISSING)?;
    require_non_empty_string(scope_obj, "dataset_split", APL_FRAME_KERNEL_MISSING)?;

    // §5.4 — aspect cardinality: exactly one element required.
    if frame.aspect.len() != 1 {
        return Err(profile_err(
            FailureClass::FrameFailure,
            vec![APL_FRAME_ASPECT_INVALID],
        ));
    }
    // §5.4 — allowed aspect values.
    let aspect = frame.aspect[0].as_str();
    if !AI_EVAL_ALLOWED_ASPECTS.contains(&aspect) {
        return Err(profile_err(
            FailureClass::FrameFailure,
            vec![APL_FRAME_ASPECT_INVALID],
        ));
    }

    // §5.5 — required exclusion markers must all be present.
    for marker in AI_EVAL_REQUIRED_EXCLUSIONS {
        if !frame.exclusions.iter().any(|e| e == *marker) {
            return Err(profile_err(
                FailureClass::FrameFailure,
                vec![APL_FRAME_EXCLUSIONS_INVALID],
            ));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Require `obj[key]` to be a non-empty string; return `diagnostic` on failure.
fn require_non_empty_string(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    diagnostic: DiagnosticCode,
) -> ProfileCheckResult {
    let s = obj
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| profile_err(FailureClass::FrameFailure, vec![diagnostic]))?;
    if s.is_empty() {
        return Err(profile_err(FailureClass::FrameFailure, vec![diagnostic]));
    }
    Ok(())
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
mod frame_tests {
    use crate::profile::AiEvalProfile;
    use apl_core::core::frame::Frame;
    use apl_core::diagnostics::{
        APL_FRAME_ASPECT_INVALID, APL_FRAME_EXCLUSIONS_INVALID, APL_FRAME_KERNEL_MISSING,
        APL_FRAME_SCOPE_OR_RESOLUTION_MISSING,
    };
    use apl_core::profile::trait_def::Profile;
    use apl_core::FailureClass;
    use serde_json::json;

    fn valid_ai_eval_frame() -> Frame {
        let v = json!({
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
        });
        Frame::parse(&v).expect("valid frame fixture")
    }

    // AC14 partial: MMLU reference frame accepted.
    #[test]
    fn accepts_reference_mmlu_frame() {
        assert!(AiEvalProfile.check_frame(&valid_ai_eval_frame()).is_ok());
    }

    // AC10: procedure not object → FrameFailure.
    #[test]
    fn rejects_procedure_not_object() {
        let v = json!({
            "version": "0.1",
            "observer": "acme",
            "procedure": "lm-eval-harness",
            "aspect": ["accuracy"],
            "scope": {
                "benchmark_id": "mmlu",
                "benchmark_variant": "default",
                "dataset_split": "dev"
            },
            "invariance": ["i"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        });
        let f = Frame::parse(&v).expect("core parse must succeed");
        let err = AiEvalProfile.check_frame(&f).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::FrameFailure);
        assert!(err.diagnostics.contains(&APL_FRAME_KERNEL_MISSING));
    }

    // AC10: procedure missing runner_id → FrameFailure + AplFrameKernelMissing.
    #[test]
    fn rejects_procedure_missing_runner_id() {
        let v = json!({
            "version": "0.1",
            "observer": "acme",
            "procedure": { "grader_id": "g" },
            "aspect": ["accuracy"],
            "scope": {
                "benchmark_id": "mmlu",
                "benchmark_variant": "default",
                "dataset_split": "dev"
            },
            "invariance": ["i"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        });
        let f = Frame::parse(&v).expect("core parse must succeed");
        let err = AiEvalProfile.check_frame(&f).unwrap_err();
        assert!(err.diagnostics.contains(&APL_FRAME_KERNEL_MISSING));
    }

    // AC10: procedure missing grader_id.
    #[test]
    fn rejects_procedure_missing_grader_id() {
        let v = json!({
            "version": "0.1",
            "observer": "acme",
            "procedure": { "runner_id": "r" },
            "aspect": ["accuracy"],
            "scope": {
                "benchmark_id": "mmlu",
                "benchmark_variant": "default",
                "dataset_split": "dev"
            },
            "invariance": ["i"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        });
        let f = Frame::parse(&v).expect("core parse must succeed");
        let err = AiEvalProfile.check_frame(&f).unwrap_err();
        assert!(err.diagnostics.contains(&APL_FRAME_KERNEL_MISSING));
    }

    // scope missing dataset_split → FrameFailure.
    #[test]
    fn rejects_scope_missing_dataset_split() {
        let v = json!({
            "version": "0.1",
            "observer": "acme",
            "procedure": { "runner_id": "r", "grader_id": "g" },
            "aspect": ["accuracy"],
            "scope": {
                "benchmark_id": "mmlu",
                "benchmark_variant": "default"
            },
            "invariance": ["i"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        });
        let f = Frame::parse(&v).expect("core parse must succeed");
        let err = AiEvalProfile.check_frame(&f).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::FrameFailure);
        assert!(err.diagnostics.contains(&APL_FRAME_KERNEL_MISSING));
    }

    // AC11: missing required exclusion markers.
    #[test]
    fn rejects_missing_required_exclusion() {
        let v = json!({
            "version": "0.1",
            "observer": "acme",
            "procedure": { "runner_id": "r", "grader_id": "g" },
            "aspect": ["accuracy"],
            "scope": {
                "benchmark_id": "mmlu",
                "benchmark_variant": "default",
                "dataset_split": "dev"
            },
            "invariance": ["i"],
            "exclusions": ["no-deployment-safety-claim"]
        });
        let f = Frame::parse(&v).expect("core parse must succeed");
        let err = AiEvalProfile.check_frame(&f).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::FrameFailure);
        assert!(err.diagnostics.contains(&APL_FRAME_EXCLUSIONS_INVALID));
    }

    // AC11: all three exclusions present but none others needed.
    #[test]
    fn accepts_all_three_required_exclusions_present() {
        assert!(AiEvalProfile.check_frame(&valid_ai_eval_frame()).is_ok());
    }

    // aspect not in allowed set.
    #[test]
    fn rejects_aspect_not_in_allowed_set() {
        let v = json!({
            "version": "0.1",
            "observer": "acme",
            "procedure": { "runner_id": "r", "grader_id": "g" },
            "aspect": ["deployment-safety"],
            "scope": {
                "benchmark_id": "mmlu",
                "benchmark_variant": "default",
                "dataset_split": "dev"
            },
            "invariance": ["i"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        });
        let f = Frame::parse(&v).expect("core parse must succeed");
        let err = AiEvalProfile.check_frame(&f).unwrap_err();
        assert!(err.diagnostics.contains(&APL_FRAME_ASPECT_INVALID));
    }

    // scope is not an object → FrameFailure + AplFrameScopeOrResolutionMissing.
    #[test]
    fn rejects_scope_not_object() {
        let v = json!({
            "version": "0.1",
            "observer": "acme",
            "procedure": { "runner_id": "r", "grader_id": "g" },
            "aspect": ["accuracy"],
            "scope": "plain-string-scope",
            "invariance": ["i"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        });
        let f = Frame::parse(&v).expect("core parse must succeed");
        let err = AiEvalProfile.check_frame(&f).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::FrameFailure);
        assert!(err
            .diagnostics
            .contains(&APL_FRAME_SCOPE_OR_RESOLUTION_MISSING));
    }

    // scope missing benchmark_variant → FrameFailure + AplFrameKernelMissing.
    #[test]
    fn rejects_scope_missing_benchmark_variant() {
        let v = json!({
            "version": "0.1",
            "observer": "acme",
            "procedure": { "runner_id": "r", "grader_id": "g" },
            "aspect": ["accuracy"],
            "scope": {
                "benchmark_id": "mmlu",
                "dataset_split": "dev"
            },
            "invariance": ["i"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        });
        let f = Frame::parse(&v).expect("core parse must succeed");
        let err = AiEvalProfile.check_frame(&f).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::FrameFailure);
        assert!(err.diagnostics.contains(&APL_FRAME_KERNEL_MISSING));
    }

    // aspect.len() != 1 (multiple) → FrameFailure + AplFrameAspectInvalid.
    #[test]
    fn rejects_aspect_cardinality_two() {
        let v = json!({
            "version": "0.1",
            "observer": "acme",
            "procedure": { "runner_id": "r", "grader_id": "g" },
            "aspect": ["accuracy", "pass-rate"],
            "scope": {
                "benchmark_id": "mmlu",
                "benchmark_variant": "default",
                "dataset_split": "dev"
            },
            "invariance": ["i"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        });
        let f = Frame::parse(&v).expect("core parse must succeed");
        let err = AiEvalProfile.check_frame(&f).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::FrameFailure);
        assert!(err.diagnostics.contains(&APL_FRAME_ASPECT_INVALID));
    }

    // runner_id is an empty string → FrameFailure + AplFrameKernelMissing.
    #[test]
    fn rejects_runner_id_empty_string() {
        let v = json!({
            "version": "0.1",
            "observer": "acme",
            "procedure": { "runner_id": "", "grader_id": "g" },
            "aspect": ["accuracy"],
            "scope": {
                "benchmark_id": "mmlu",
                "benchmark_variant": "default",
                "dataset_split": "dev"
            },
            "invariance": ["i"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        });
        let f = Frame::parse(&v).expect("core parse must succeed");
        let err = AiEvalProfile.check_frame(&f).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::FrameFailure);
        assert!(err.diagnostics.contains(&APL_FRAME_KERNEL_MISSING));
    }

    // grader_id is an empty string → FrameFailure + AplFrameKernelMissing.
    #[test]
    fn rejects_grader_id_empty_string() {
        let v = json!({
            "version": "0.1",
            "observer": "acme",
            "procedure": { "runner_id": "r", "grader_id": "" },
            "aspect": ["accuracy"],
            "scope": {
                "benchmark_id": "mmlu",
                "benchmark_variant": "default",
                "dataset_split": "dev"
            },
            "invariance": ["i"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        });
        let f = Frame::parse(&v).expect("core parse must succeed");
        let err = AiEvalProfile.check_frame(&f).unwrap_err();
        assert_eq!(err.failure_class, FailureClass::FrameFailure);
        assert!(err.diagnostics.contains(&APL_FRAME_KERNEL_MISSING));
    }

    // §8.5 — reference frames for all four reference benchmark families.

    #[test]
    fn accepts_10_1_mmlu_dev_accuracy() {
        assert!(AiEvalProfile.check_frame(&valid_ai_eval_frame()).is_ok());
    }

    #[test]
    fn accepts_10_2_gpqa_diamond() {
        let v = json!({
            "version": "0.1",
            "observer": { "id": "acme-eval-lab" },
            "procedure": {
                "runner_id": "lm-eval-harness@0.4.2",
                "grader_id": "exact-match-v1"
            },
            "aspect": ["accuracy"],
            "scope": {
                "benchmark_id": "gpqa",
                "benchmark_variant": "diamond",
                "dataset_split": "test"
            },
            "invariance": ["score-object-serialization"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        });
        let f = Frame::parse(&v).expect("valid frame fixture");
        assert!(AiEvalProfile.check_frame(&f).is_ok());
    }

    #[test]
    fn accepts_10_3_humaneval_pass_rate() {
        let v = json!({
            "version": "0.1",
            "observer": { "id": "acme-eval-lab" },
            "procedure": {
                "runner_id": "evalplus@0.2.0",
                "grader_id": "pass-at-k-v1"
            },
            "aspect": ["pass-rate"],
            "scope": {
                "benchmark_id": "humaneval",
                "benchmark_variant": "default",
                "dataset_split": "test"
            },
            "invariance": ["score-object-serialization"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        });
        let f = Frame::parse(&v).expect("valid frame fixture");
        assert!(AiEvalProfile.check_frame(&f).is_ok());
    }

    #[test]
    fn accepts_10_4_agentbench_tool_success() {
        let v = json!({
            "version": "0.1",
            "observer": { "id": "acme-eval-lab" },
            "procedure": {
                "runner_id": "agentbench@1.0.0",
                "grader_id": "tool-success-v1"
            },
            "aspect": ["tool-success-rate"],
            "scope": {
                "benchmark_id": "agentbench",
                "benchmark_variant": "default",
                "dataset_split": "test"
            },
            "invariance": ["score-object-serialization"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        });
        let f = Frame::parse(&v).expect("valid frame fixture");
        assert!(AiEvalProfile.check_frame(&f).is_ok());
    }
}
