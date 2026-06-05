//! Tests for frame validity checks.

use crate::diagnostics::{
    APL_ATS_EMPTY_SOURCE_DESCRIPTORS, APL_ATS_FRAME_NOT_PROFILE, APL_ATS_INVALID_CONFIDENCE,
    APL_ATS_INVALID_SOURCE_DESCRIPTOR, APL_ATS_MISSING_CLASSIFICATION, APL_ATS_MISSING_CONFIDENCE,
    APL_ATS_MISSING_METHODOLOGY, APL_ATS_MISSING_SOURCE_DESCRIPTORS,
};
use crate::profile::AtsProfile;
use apl_core::core::frame::Frame;
use apl_core::profile::trait_def::Profile;
use apl_core::FailureClass;
use serde_json::json;

fn valid_ats_frame() -> Frame {
    let v = json!({
        "version": "0.1",
        "observer": "CIA/DI/Office of Transnational Issues",
        "procedure": "structured-analytic-technique/ACH",
        "aspect": ["nuclear_capability_assessment"],
        "scope": "DPRK nuclear program Q2 2026",
        "invariance": ["assessment framework"],
        "exclusions": ["no claim about delivery systems readiness"],
        "profile": "APL/ATS",
        "source_descriptors": [{"source_type": "HUMINT"}],
        "confidence_level": "moderate",
        "classification_marking": "TS//SCI//NOFORN",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    Frame::parse(&v).expect("valid frame fixture")
}

// Test 1: full valid frame passes.
#[test]
fn should_return_ok_for_valid_ats_frame() {
    assert!(AtsProfile.check_frame(&valid_ats_frame()).is_ok());
}

// Test 2: no profile field.
#[test]
fn should_reject_when_profile_absent() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "source_descriptors": [{"source_type": "HUMINT"}],
        "confidence_level": "moderate",
        "classification_marking": "TS",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::FrameFailure);
    assert!(err.diagnostics.contains(&APL_ATS_FRAME_NOT_PROFILE));
}

// Test 3: wrong profile value.
#[test]
fn should_reject_when_profile_is_wrong_value() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "profile": "APL/AI-Eval",
        "source_descriptors": [{"source_type": "HUMINT"}],
        "confidence_level": "moderate",
        "classification_marking": "TS",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::FrameFailure);
    assert!(err.diagnostics.contains(&APL_ATS_FRAME_NOT_PROFILE));
}

// Test 4: source_descriptors absent.
#[test]
fn should_reject_when_source_descriptors_absent() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "profile": "APL/ATS",
        "confidence_level": "moderate",
        "classification_marking": "TS",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::FrameFailure);
    assert!(err
        .diagnostics
        .contains(&APL_ATS_MISSING_SOURCE_DESCRIPTORS));
}

// Test 5: source_descriptors is not an array (string value).
#[test]
fn should_reject_when_source_descriptors_not_array() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "profile": "APL/ATS",
        "source_descriptors": "not-an-array",
        "confidence_level": "moderate",
        "classification_marking": "TS",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::FrameFailure);
    assert!(err
        .diagnostics
        .contains(&APL_ATS_MISSING_SOURCE_DESCRIPTORS));
}

// Test 6: source_descriptors is an empty array.
#[test]
fn should_reject_when_source_descriptors_empty_array() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "profile": "APL/ATS",
        "source_descriptors": [],
        "confidence_level": "moderate",
        "classification_marking": "TS",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::FrameFailure);
    assert!(err.diagnostics.contains(&APL_ATS_EMPTY_SOURCE_DESCRIPTORS));
}

// Test 7: source descriptor element is not an object (string instead).
#[test]
fn should_reject_when_source_descriptor_not_object() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "profile": "APL/ATS",
        "source_descriptors": ["not-an-object"],
        "confidence_level": "moderate",
        "classification_marking": "TS",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::FrameFailure);
    assert!(err.diagnostics.contains(&APL_ATS_INVALID_SOURCE_DESCRIPTOR));
}

// Test 8: source descriptor missing source_type field.
#[test]
fn should_reject_when_source_type_missing() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "profile": "APL/ATS",
        "source_descriptors": [{"not_source_type": "x"}],
        "confidence_level": "moderate",
        "classification_marking": "TS",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::FrameFailure);
    assert!(err.diagnostics.contains(&APL_ATS_INVALID_SOURCE_DESCRIPTOR));
}

// Test 9: source_type is an empty string.
#[test]
fn should_reject_when_source_type_empty() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "profile": "APL/ATS",
        "source_descriptors": [{"source_type": ""}],
        "confidence_level": "moderate",
        "classification_marking": "TS",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::FrameFailure);
    assert!(err.diagnostics.contains(&APL_ATS_INVALID_SOURCE_DESCRIPTOR));
}

// Test 10: confidence_level absent.
#[test]
fn should_reject_when_confidence_level_absent() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "profile": "APL/ATS",
        "source_descriptors": [{"source_type": "HUMINT"}],
        "classification_marking": "TS",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::FrameFailure);
    assert!(err.diagnostics.contains(&APL_ATS_MISSING_CONFIDENCE));
}

// Test 11: confidence_level is not a string (number 123).
#[test]
fn should_reject_when_confidence_level_not_string() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "profile": "APL/ATS",
        "source_descriptors": [{"source_type": "HUMINT"}],
        "confidence_level": 123,
        "classification_marking": "TS",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::FrameFailure);
    assert!(err.diagnostics.contains(&APL_ATS_MISSING_CONFIDENCE));
}

// Test 12: confidence_level has invalid value "unknown".
#[test]
fn should_reject_when_confidence_level_invalid() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "profile": "APL/ATS",
        "source_descriptors": [{"source_type": "HUMINT"}],
        "confidence_level": "unknown",
        "classification_marking": "TS",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::FrameFailure);
    assert!(err.diagnostics.contains(&APL_ATS_INVALID_CONFIDENCE));
}

// Test 13: confidence_level "high" passes.
#[test]
fn should_accept_when_confidence_level_is_high() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "profile": "APL/ATS",
        "source_descriptors": [{"source_type": "HUMINT"}],
        "confidence_level": "high",
        "classification_marking": "TS",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    assert!(AtsProfile.check_frame(&f).is_ok());
}

// Test 14: classification_marking absent.
#[test]
fn should_reject_when_classification_marking_absent() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "profile": "APL/ATS",
        "source_descriptors": [{"source_type": "HUMINT"}],
        "confidence_level": "moderate",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::FrameFailure);
    assert!(err.diagnostics.contains(&APL_ATS_MISSING_CLASSIFICATION));
}

// Test 15: classification_marking is empty string "".
#[test]
fn should_reject_when_classification_marking_empty() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "profile": "APL/ATS",
        "source_descriptors": [{"source_type": "HUMINT"}],
        "confidence_level": "moderate",
        "classification_marking": "",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::FrameFailure);
    assert!(err.diagnostics.contains(&APL_ATS_MISSING_CLASSIFICATION));
}

// Test 16: classification_marking is whitespace only "   ".
#[test]
fn should_reject_when_classification_marking_whitespace_only() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "profile": "APL/ATS",
        "source_descriptors": [{"source_type": "HUMINT"}],
        "confidence_level": "moderate",
        "classification_marking": "   ",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::FrameFailure);
    assert!(err.diagnostics.contains(&APL_ATS_MISSING_CLASSIFICATION));
}

// Test 17: methodology_ref absent.
#[test]
fn should_reject_when_methodology_ref_absent() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "profile": "APL/ATS",
        "source_descriptors": [{"source_type": "HUMINT"}],
        "confidence_level": "moderate",
        "classification_marking": "TS"
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::ReferenceFailure);
    assert!(err.diagnostics.contains(&APL_ATS_MISSING_METHODOLOGY));
}

// Test 18: methodology_ref has invalid hash "md5:abc".
#[test]
fn should_reject_when_methodology_ref_has_invalid_hash() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "profile": "APL/ATS",
        "source_descriptors": [{"source_type": "HUMINT"}],
        "confidence_level": "moderate",
        "classification_marking": "TS",
        "methodology_ref": {"hash": "md5:abc"}
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::ReferenceFailure);
    assert!(err.diagnostics.contains(&APL_ATS_MISSING_METHODOLOGY));
}

// Test 19: methodology_ref is null.
#[test]
fn should_reject_when_methodology_ref_is_null() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "profile": "APL/ATS",
        "source_descriptors": [{"source_type": "HUMINT"}],
        "confidence_level": "moderate",
        "classification_marking": "TS",
        "methodology_ref": null
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::ReferenceFailure);
    assert!(err.diagnostics.contains(&APL_ATS_MISSING_METHODOLOGY));
}

// Test 20: minimal valid ATS frame passes.
#[test]
fn should_accept_minimal_valid_ats_frame() {
    assert!(AtsProfile.check_frame(&valid_ats_frame()).is_ok());
}

// Test 21: fail-fast — missing both profile and source_descriptors returns
// APL_ATS_FRAME_NOT_PROFILE (first check), not source_descriptors error.
#[test]
fn should_fail_fast_on_first_violation() {
    let v = json!({
        "version": "0.1",
        "observer": "test",
        "procedure": "test",
        "aspect": ["test"],
        "scope": "test",
        "invariance": ["test"],
        "exclusions": ["test"],
        "confidence_level": "moderate",
        "classification_marking": "TS",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    let err = AtsProfile.check_frame(&f).unwrap_err();
    assert_eq!(err.failure_class, FailureClass::FrameFailure);
    assert!(err.diagnostics.contains(&APL_ATS_FRAME_NOT_PROFILE));
    assert!(!err
        .diagnostics
        .contains(&APL_ATS_MISSING_SOURCE_DESCRIPTORS));
}

// Test 22: frame from profile example.
#[test]
fn should_accept_frame_from_spec_example() {
    let v = json!({
        "version": "0.1",
        "profile": "APL/ATS",
        "observer": "CIA/DI/Office of Transnational Issues",
        "procedure": "structured-analytic-technique/ACH",
        "instrument": "analyst-judgment",
        "aspect": ["nuclear_capability_assessment"],
        "scope": "DPRK nuclear program Q2 2026",
        "invariance": ["assessment framework", "source evaluation criteria"],
        "exclusions": ["no claim about delivery systems readiness", "no claim about fissile material stockpile quantity"],
        "source_descriptors": [{"source_type": "HUMINT", "source_reliability": "B", "information_credibility": "2", "icd206_ref": {"hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}],
        "methodology_ref": {"hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
        "confidence_level": "moderate",
        "classification_marking": "TS//SCI//NOFORN",
        "assumptions": ["satellite imagery from April 2026 reflects current operational status"],
        "alternative_analyses": [{"hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}],
        "customer_context": "to inform diplomatic engagement strategy"
    });
    let f = Frame::parse(&v).expect("core parse must succeed");
    assert!(AtsProfile.check_frame(&f).is_ok());
}
