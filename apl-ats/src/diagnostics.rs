//! APL/ATS profile diagnostic codes.

use apl_core::diagnostics::DiagnosticCode;

// ---------------------------------------------------------------------------
// APL/ATS profile diagnostics — Frame validation
// ---------------------------------------------------------------------------

/// Frame is missing `source_descriptors` field.
pub const APL_ATS_MISSING_SOURCE_DESCRIPTORS: DiagnosticCode =
    DiagnosticCode::new("apl-ats-missing-source-descriptors");
/// Frame `source_descriptors` is an empty array.
pub const APL_ATS_EMPTY_SOURCE_DESCRIPTORS: DiagnosticCode =
    DiagnosticCode::new("apl-ats-empty-source-descriptors");
/// A `source_descriptors` element fails structural validation.
pub const APL_ATS_INVALID_SOURCE_DESCRIPTOR: DiagnosticCode =
    DiagnosticCode::new("apl-ats-invalid-source-descriptor");
/// Frame is missing `confidence_level` field.
pub const APL_ATS_MISSING_CONFIDENCE: DiagnosticCode =
    DiagnosticCode::new("apl-ats-missing-confidence");
/// `confidence_level` is not one of `"high"`, `"moderate"`, `"low"`.
pub const APL_ATS_INVALID_CONFIDENCE: DiagnosticCode =
    DiagnosticCode::new("apl-ats-invalid-confidence");
/// Frame is missing `classification_marking` field.
pub const APL_ATS_MISSING_CLASSIFICATION: DiagnosticCode =
    DiagnosticCode::new("apl-ats-missing-classification");
/// Frame is missing `methodology_ref` field.
pub const APL_ATS_MISSING_METHODOLOGY: DiagnosticCode =
    DiagnosticCode::new("apl-ats-missing-methodology");
/// Bridge `comparison_scope` is missing `source_descriptors` mapping when frames differ.
pub const APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP: DiagnosticCode =
    DiagnosticCode::new("apl-ats-bridge-no-descriptor-map");
/// Frame `profile` field does not equal `"APL/ATS"`.
pub const APL_ATS_FRAME_NOT_PROFILE: DiagnosticCode =
    DiagnosticCode::new("apl-ats-frame-not-profile");

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_is_idempotent() {
        // register() must not panic when called multiple times.
        crate::register();
        crate::register();
        // If we reach here, both calls succeeded without panicking.
    }

    #[test]
    fn all_nine_codes_registered() {
        crate::register();

        let codes = [
            APL_ATS_MISSING_SOURCE_DESCRIPTORS.as_str(),
            APL_ATS_EMPTY_SOURCE_DESCRIPTORS.as_str(),
            APL_ATS_INVALID_SOURCE_DESCRIPTOR.as_str(),
            APL_ATS_MISSING_CONFIDENCE.as_str(),
            APL_ATS_INVALID_CONFIDENCE.as_str(),
            APL_ATS_MISSING_CLASSIFICATION.as_str(),
            APL_ATS_MISSING_METHODOLOGY.as_str(),
            APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP.as_str(),
            APL_ATS_FRAME_NOT_PROFILE.as_str(),
        ];

        for code in &codes {
            let json = format!("\"{code}\"");
            let result: Result<DiagnosticCode, _> = serde_json::from_str(&json);
            assert!(
                result.is_ok(),
                "code {code} must deserialize successfully after register()"
            );
        }
    }

    #[test]
    fn unknown_code_rejected() {
        crate::register();

        let result: Result<DiagnosticCode, _> = serde_json::from_str("\"apl-ats-fake-code\"");
        assert!(
            result.is_err(),
            "unregistered code must produce a deserialization error"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown diagnostic code"),
            "error message must mention 'unknown diagnostic code', got: {err}"
        );
    }

    #[test]
    fn diagnostic_code_strings_match_spec() {
        assert_eq!(
            APL_ATS_MISSING_SOURCE_DESCRIPTORS.as_str(),
            "apl-ats-missing-source-descriptors"
        );
        assert_eq!(
            APL_ATS_EMPTY_SOURCE_DESCRIPTORS.as_str(),
            "apl-ats-empty-source-descriptors"
        );
        assert_eq!(
            APL_ATS_INVALID_SOURCE_DESCRIPTOR.as_str(),
            "apl-ats-invalid-source-descriptor"
        );
        assert_eq!(
            APL_ATS_MISSING_CONFIDENCE.as_str(),
            "apl-ats-missing-confidence"
        );
        assert_eq!(
            APL_ATS_INVALID_CONFIDENCE.as_str(),
            "apl-ats-invalid-confidence"
        );
        assert_eq!(
            APL_ATS_MISSING_CLASSIFICATION.as_str(),
            "apl-ats-missing-classification"
        );
        assert_eq!(
            APL_ATS_MISSING_METHODOLOGY.as_str(),
            "apl-ats-missing-methodology"
        );
        assert_eq!(
            APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP.as_str(),
            "apl-ats-bridge-no-descriptor-map"
        );
        assert_eq!(
            APL_ATS_FRAME_NOT_PROFILE.as_str(),
            "apl-ats-frame-not-profile"
        );
    }
}
