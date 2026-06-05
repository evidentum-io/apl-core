//! Frame validity checks.

use serde_json::Value;

use apl_core::core::frame::Frame;
use apl_core::core::hash::Reference;
use apl_core::diagnostics::DiagnosticCode;
use apl_core::profile::trait_def::{ProfileCheckResult, ProfileFailure};
use apl_core::FailureClass;

use crate::diagnostics::{
    APL_ATS_EMPTY_SOURCE_DESCRIPTORS, APL_ATS_FRAME_NOT_PROFILE, APL_ATS_INVALID_CONFIDENCE,
    APL_ATS_INVALID_SOURCE_DESCRIPTOR, APL_ATS_MISSING_CLASSIFICATION, APL_ATS_MISSING_CONFIDENCE,
    APL_ATS_MISSING_METHODOLOGY, APL_ATS_MISSING_SOURCE_DESCRIPTORS,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check frame-level ATS profile invariants.
///
/// # Errors
///
/// Returns `Err(ProfileFailure)` if any ATS frame invariant is violated.
/// Rules 1-5 use `FailureClass::FrameFailure`, rule 6 uses
/// `FailureClass::ReferenceFailure`.
pub fn check_frame(frame: &Frame) -> ProfileCheckResult {
    // Rule 1 — profile field must be "APL/ATS".
    match frame.raw.get("profile").and_then(Value::as_str) {
        Some(s) if s == PROFILE_STRING => {}
        _ => {
            return Err(profile_err(
                FailureClass::FrameFailure,
                vec![APL_ATS_FRAME_NOT_PROFILE],
            ));
        }
    }

    // Rule 2 — source_descriptors must exist and be a non-empty JSON array.
    let sd_array = match frame.raw.get("source_descriptors") {
        Some(Value::Array(arr)) => {
            if arr.is_empty() {
                return Err(profile_err(
                    FailureClass::FrameFailure,
                    vec![APL_ATS_EMPTY_SOURCE_DESCRIPTORS],
                ));
            }
            arr
        }
        _ => {
            return Err(profile_err(
                FailureClass::FrameFailure,
                vec![APL_ATS_MISSING_SOURCE_DESCRIPTORS],
            ));
        }
    };

    // Rule 3 — each source descriptor must be an object with a non-empty source_type.
    for elem in sd_array {
        let obj = elem.as_object().ok_or_else(|| {
            profile_err(
                FailureClass::FrameFailure,
                vec![APL_ATS_INVALID_SOURCE_DESCRIPTOR],
            )
        })?;
        require_non_empty_string(obj, "source_type", APL_ATS_INVALID_SOURCE_DESCRIPTOR)?;
    }

    // Rule 4 — confidence_level must be one of "high", "moderate", "low".
    let confidence_str = frame
        .raw
        .get("confidence_level")
        .and_then(Value::as_str)
        .ok_or_else(|| profile_err(FailureClass::FrameFailure, vec![APL_ATS_MISSING_CONFIDENCE]))?;
    if !ALLOWED_CONFIDENCE_LEVELS.contains(&confidence_str) {
        return Err(profile_err(
            FailureClass::FrameFailure,
            vec![APL_ATS_INVALID_CONFIDENCE],
        ));
    }

    // Rule 5 — classification_marking must exist, be a string, and non-empty after trim.
    match frame
        .raw
        .get("classification_marking")
        .and_then(Value::as_str)
    {
        Some(s) if !s.trim().is_empty() => {}
        _ => {
            return Err(profile_err(
                FailureClass::FrameFailure,
                vec![APL_ATS_MISSING_CLASSIFICATION],
            ));
        }
    }

    // Rule 6 — methodology_ref must exist, not be null, and parse as a valid Reference.
    let method_ref_val = frame.raw.get("methodology_ref").ok_or_else(|| {
        profile_err(
            FailureClass::ReferenceFailure,
            vec![APL_ATS_MISSING_METHODOLOGY],
        )
    })?;
    if method_ref_val.is_null() {
        return Err(profile_err(
            FailureClass::ReferenceFailure,
            vec![APL_ATS_MISSING_METHODOLOGY],
        ));
    }
    Reference::parse(method_ref_val).map_err(|_| {
        profile_err(
            FailureClass::ReferenceFailure,
            vec![APL_ATS_MISSING_METHODOLOGY],
        )
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

const PROFILE_STRING: &str = "APL/ATS";
const ALLOWED_CONFIDENCE_LEVELS: &[&str] = &["high", "moderate", "low"];

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
// Tests (in submodule)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "frame_tests.rs"]
mod frame_tests;
