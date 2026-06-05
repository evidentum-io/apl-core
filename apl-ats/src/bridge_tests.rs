//! Tests for bridge applicability checks under APL/ATS profile constraints.

use super::check_bridge_applicability;
use crate::diagnostics::APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP;
use apl_core::core::bridge::Bridge;
use apl_core::core::frame::Frame;
use apl_core::core::hash::Hash;
use apl_core::core::relation::RelationQuery;
use apl_core::diagnostics::APL_BRIDGE_FRAME_MISMATCH;
use serde_json::json;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Build a minimal valid ATS frame.
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

/// Build a second ATS frame whose canonical hash differs from the first.
///
/// Changes the `observer` field so the canonical hash is different from
/// `valid_ats_frame()` while keeping the same aspect and scope.
fn valid_ats_frame_b() -> Frame {
    let v = json!({
        "version": "0.1",
        "observer": "NSA/Research Directorate",
        "procedure": "structured-analytic-technique/ACH",
        "aspect": ["nuclear_capability_assessment"],
        "scope": "DPRK nuclear program Q2 2026",
        "invariance": ["assessment framework"],
        "exclusions": ["no claim about delivery systems readiness"],
        "profile": "APL/ATS",
        "source_descriptors": [{"source_type": "SIGINT"}],
        "confidence_level": "high",
        "classification_marking": "TS//SI//NOFORN",
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    });
    Frame::parse(&v).expect("valid frame fixture")
}

/// Build a valid bridge with a `source_descriptors` mapping.
fn valid_bridge(src_hash: &Hash, tgt_hash: &Hash) -> Bridge {
    let v = json!({
        "version": "0.1",
        "source_frame": { "hash": src_hash.to_string() },
        "target_frame": { "hash": tgt_hash.to_string() },
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "assessor-equivalence",
            "source_descriptors": [
                {
                    "source_index": 0,
                    "assumptions": ["equal reliability"]
                }
            ]
        },
        "assumptions": [],
        "losses": []
    });
    Bridge::parse(&v).expect("valid bridge fixture")
}

/// Build a valid `RelationQuery` for tests.
fn dummy_query() -> RelationQuery {
    RelationQuery::parse(&json!({
        "left_aspects": ["nuclear_capability_assessment"],
        "right_aspects": ["nuclear_capability_assessment"],
        "predicate": "score",
        "relation_type": "assessor-equivalence"
    }))
    .expect("valid query fixture")
}

// ---------------------------------------------------------------------------
// Test 1: Same frame — identical hashes → Ok
// ---------------------------------------------------------------------------

#[test]
fn should_accept_when_frames_are_identical() {
    let frame = valid_ats_frame();
    let hash = frame.canonical_hash();
    let bridge = valid_bridge(&hash, &hash);
    let query = dummy_query();

    assert!(
        check_bridge_applicability(&bridge, &frame, &frame, &query).is_ok(),
        "identical frames must be accepted"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Different frames with valid mapping → Ok
// ---------------------------------------------------------------------------

#[test]
fn should_accept_when_different_frames_with_valid_mapping() {
    let src = valid_ats_frame();
    let tgt = valid_ats_frame_b();
    let bridge = valid_bridge(&src.canonical_hash(), &tgt.canonical_hash());
    let query = dummy_query();

    assert!(
        check_bridge_applicability(&bridge, &src, &tgt, &query).is_ok(),
        "different frames with valid source_descriptors mapping must be accepted"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Empty source_descriptors array → Ok
// ---------------------------------------------------------------------------

#[test]
fn should_accept_when_mapping_is_empty_array() {
    let src = valid_ats_frame();
    let tgt = valid_ats_frame_b();

    let v = json!({
        "version": "0.1",
        "source_frame": { "hash": src.canonical_hash().to_string() },
        "target_frame": { "hash": tgt.canonical_hash().to_string() },
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "assessor-equivalence",
            "source_descriptors": []
        },
        "assumptions": [],
        "losses": []
    });
    let bridge = Bridge::parse(&v).expect("valid bridge");
    let query = dummy_query();

    assert!(
        check_bridge_applicability(&bridge, &src, &tgt, &query).is_ok(),
        "empty source_descriptors array must be accepted"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Empty assumptions array → Ok
// ---------------------------------------------------------------------------

#[test]
fn should_accept_when_assumptions_is_empty_array() {
    let src = valid_ats_frame();
    let tgt = valid_ats_frame_b();

    let v = json!({
        "version": "0.1",
        "source_frame": { "hash": src.canonical_hash().to_string() },
        "target_frame": { "hash": tgt.canonical_hash().to_string() },
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "assessor-equivalence",
            "source_descriptors": [
                {
                    "source_index": 0,
                    "assumptions": []
                }
            ]
        },
        "assumptions": [],
        "losses": []
    });
    let bridge = Bridge::parse(&v).expect("valid bridge");
    let query = dummy_query();

    assert!(
        check_bridge_applicability(&bridge, &src, &tgt, &query).is_ok(),
        "element with empty assumptions array must be accepted"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Missing source_descriptors key for different frames → Err
// ---------------------------------------------------------------------------

#[test]
fn should_reject_when_mapping_absent_for_different_frames() {
    let src = valid_ats_frame();
    let tgt = valid_ats_frame_b();

    let v = json!({
        "version": "0.1",
        "source_frame": { "hash": src.canonical_hash().to_string() },
        "target_frame": { "hash": tgt.canonical_hash().to_string() },
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "assessor-equivalence"
        },
        "assumptions": [],
        "losses": []
    });
    let bridge = Bridge::parse(&v).expect("valid bridge");
    let query = dummy_query();

    let err = check_bridge_applicability(&bridge, &src, &tgt, &query).unwrap_err();
    assert!(
        err.contains(&APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP),
        "expected APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 6: source_descriptors is not an array → Err
// ---------------------------------------------------------------------------

#[test]
fn should_reject_when_mapping_is_not_array() {
    let src = valid_ats_frame();
    let tgt = valid_ats_frame_b();

    let v = json!({
        "version": "0.1",
        "source_frame": { "hash": src.canonical_hash().to_string() },
        "target_frame": { "hash": tgt.canonical_hash().to_string() },
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "assessor-equivalence",
            "source_descriptors": "not-an-array"
        },
        "assumptions": [],
        "losses": []
    });
    let bridge = Bridge::parse(&v).expect("valid bridge");
    let query = dummy_query();

    let err = check_bridge_applicability(&bridge, &src, &tgt, &query).unwrap_err();
    assert!(
        err.contains(&APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP),
        "expected APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP for non-array mapping, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 7: Element is not an object → Err
// ---------------------------------------------------------------------------

#[test]
fn should_reject_when_element_not_object() {
    let src = valid_ats_frame();
    let tgt = valid_ats_frame_b();

    let v = json!({
        "version": "0.1",
        "source_frame": { "hash": src.canonical_hash().to_string() },
        "target_frame": { "hash": tgt.canonical_hash().to_string() },
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "assessor-equivalence",
            "source_descriptors": ["not-an-object"]
        },
        "assumptions": [],
        "losses": []
    });
    let bridge = Bridge::parse(&v).expect("valid bridge");
    let query = dummy_query();

    let err = check_bridge_applicability(&bridge, &src, &tgt, &query).unwrap_err();
    assert!(
        err.contains(&APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP),
        "expected APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP for non-object element, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 8: source_index missing → Err
// ---------------------------------------------------------------------------

#[test]
fn should_reject_when_source_index_missing() {
    let src = valid_ats_frame();
    let tgt = valid_ats_frame_b();

    let v = json!({
        "version": "0.1",
        "source_frame": { "hash": src.canonical_hash().to_string() },
        "target_frame": { "hash": tgt.canonical_hash().to_string() },
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "assessor-equivalence",
            "source_descriptors": [
                {
                    "assumptions": ["equal reliability"]
                }
            ]
        },
        "assumptions": [],
        "losses": []
    });
    let bridge = Bridge::parse(&v).expect("valid bridge");
    let query = dummy_query();

    let err = check_bridge_applicability(&bridge, &src, &tgt, &query).unwrap_err();
    assert!(
        err.contains(&APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP),
        "expected APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP for missing source_index, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 9: source_index is a float → Err
// ---------------------------------------------------------------------------

#[test]
fn should_reject_when_source_index_is_float() {
    let src = valid_ats_frame();
    let tgt = valid_ats_frame_b();

    let v = json!({
        "version": "0.1",
        "source_frame": { "hash": src.canonical_hash().to_string() },
        "target_frame": { "hash": tgt.canonical_hash().to_string() },
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "assessor-equivalence",
            "source_descriptors": [
                {
                    "source_index": 0.5,
                    "assumptions": ["equal reliability"]
                }
            ]
        },
        "assumptions": [],
        "losses": []
    });
    let bridge = Bridge::parse(&v).expect("valid bridge");
    let query = dummy_query();

    let err = check_bridge_applicability(&bridge, &src, &tgt, &query).unwrap_err();
    assert!(
        err.contains(&APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP),
        "expected APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP for float source_index, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 10: source_index is a string → Err
// ---------------------------------------------------------------------------

#[test]
fn should_reject_when_source_index_is_string() {
    let src = valid_ats_frame();
    let tgt = valid_ats_frame_b();

    let v = json!({
        "version": "0.1",
        "source_frame": { "hash": src.canonical_hash().to_string() },
        "target_frame": { "hash": tgt.canonical_hash().to_string() },
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "assessor-equivalence",
            "source_descriptors": [
                {
                    "source_index": "0",
                    "assumptions": ["equal reliability"]
                }
            ]
        },
        "assumptions": [],
        "losses": []
    });
    let bridge = Bridge::parse(&v).expect("valid bridge");
    let query = dummy_query();

    let err = check_bridge_applicability(&bridge, &src, &tgt, &query).unwrap_err();
    assert!(
        err.contains(&APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP),
        "expected APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP for string source_index, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 11: source_index is null → Err
// ---------------------------------------------------------------------------

#[test]
fn should_reject_when_source_index_is_null() {
    let src = valid_ats_frame();
    let tgt = valid_ats_frame_b();

    let v = json!({
        "version": "0.1",
        "source_frame": { "hash": src.canonical_hash().to_string() },
        "target_frame": { "hash": tgt.canonical_hash().to_string() },
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "assessor-equivalence",
            "source_descriptors": [
                {
                    "source_index": null,
                    "assumptions": ["equal reliability"]
                }
            ]
        },
        "assumptions": [],
        "losses": []
    });
    let bridge = Bridge::parse(&v).expect("valid bridge");
    let query = dummy_query();

    let err = check_bridge_applicability(&bridge, &src, &tgt, &query).unwrap_err();
    assert!(
        err.contains(&APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP),
        "expected APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP for null source_index, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 12: assumptions missing → Err
// ---------------------------------------------------------------------------

#[test]
fn should_reject_when_assumptions_missing() {
    let src = valid_ats_frame();
    let tgt = valid_ats_frame_b();

    let v = json!({
        "version": "0.1",
        "source_frame": { "hash": src.canonical_hash().to_string() },
        "target_frame": { "hash": tgt.canonical_hash().to_string() },
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "assessor-equivalence",
            "source_descriptors": [
                {
                    "source_index": 0
                }
            ]
        },
        "assumptions": [],
        "losses": []
    });
    let bridge = Bridge::parse(&v).expect("valid bridge");
    let query = dummy_query();

    let err = check_bridge_applicability(&bridge, &src, &tgt, &query).unwrap_err();
    assert!(
        err.contains(&APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP),
        "expected APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP for missing assumptions, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 13: assumptions is not an array → Err
// ---------------------------------------------------------------------------

#[test]
fn should_reject_when_assumptions_is_not_array() {
    let src = valid_ats_frame();
    let tgt = valid_ats_frame_b();

    let v = json!({
        "version": "0.1",
        "source_frame": { "hash": src.canonical_hash().to_string() },
        "target_frame": { "hash": tgt.canonical_hash().to_string() },
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "assessor-equivalence",
            "source_descriptors": [
                {
                    "source_index": 0,
                    "assumptions": "not-an-array"
                }
            ]
        },
        "assumptions": [],
        "losses": []
    });
    let bridge = Bridge::parse(&v).expect("valid bridge");
    let query = dummy_query();

    let err = check_bridge_applicability(&bridge, &src, &tgt, &query).unwrap_err();
    assert!(
        err.contains(&APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP),
        "expected APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP for non-array assumptions, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 14: assumptions contains non-string elements → Err
// ---------------------------------------------------------------------------

#[test]
fn should_reject_when_assumptions_contains_non_string() {
    let src = valid_ats_frame();
    let tgt = valid_ats_frame_b();

    // Case a: integer element.
    let v_int = json!({
        "version": "0.1",
        "source_frame": { "hash": src.canonical_hash().to_string() },
        "target_frame": { "hash": tgt.canonical_hash().to_string() },
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "assessor-equivalence",
            "source_descriptors": [
                {
                    "source_index": 0,
                    "assumptions": [1]
                }
            ]
        },
        "assumptions": [],
        "losses": []
    });
    let bridge = Bridge::parse(&v_int).expect("valid bridge");
    let query = dummy_query();

    let err = check_bridge_applicability(&bridge, &src, &tgt, &query).unwrap_err();
    assert!(
        err.contains(&APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP),
        "expected APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP for assumptions containing integer, got {err:?}"
    );

    // Case b: null element.
    let v_null = json!({
        "version": "0.1",
        "source_frame": { "hash": src.canonical_hash().to_string() },
        "target_frame": { "hash": tgt.canonical_hash().to_string() },
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "assessor-equivalence",
            "source_descriptors": [
                {
                    "source_index": 0,
                    "assumptions": [null]
                }
            ]
        },
        "assumptions": [],
        "losses": []
    });
    let bridge = Bridge::parse(&v_null).expect("valid bridge");
    let query = dummy_query();

    let err = check_bridge_applicability(&bridge, &src, &tgt, &query).unwrap_err();
    assert!(
        err.contains(&APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP),
        "expected APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP for assumptions containing null, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 15: Source frame hash mismatch → APL_BRIDGE_FRAME_MISMATCH
// ---------------------------------------------------------------------------

#[test]
fn should_reject_when_source_frame_hash_mismatch() {
    let src = valid_ats_frame();
    let tgt = valid_ats_frame_b();

    // Build a bridge whose source_frame.hash is the target's hash, not the
    // actual source frame's hash.
    let v = json!({
        "version": "0.1",
        "source_frame": { "hash": tgt.canonical_hash().to_string() },
        "target_frame": { "hash": tgt.canonical_hash().to_string() },
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "assessor-equivalence",
            "source_descriptors": [
                {
                    "source_index": 0,
                    "assumptions": ["equal reliability"]
                }
            ]
        },
        "assumptions": [],
        "losses": []
    });
    let bridge = Bridge::parse(&v).expect("valid bridge");
    let query = dummy_query();

    let err = check_bridge_applicability(&bridge, &src, &tgt, &query).unwrap_err();
    assert!(
        err.contains(&APL_BRIDGE_FRAME_MISMATCH),
        "expected APL_BRIDGE_FRAME_MISMATCH for source hash mismatch, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 16: Target frame hash mismatch → APL_BRIDGE_FRAME_MISMATCH
// ---------------------------------------------------------------------------

#[test]
fn should_reject_when_target_frame_hash_mismatch() {
    let src = valid_ats_frame();
    let tgt = valid_ats_frame_b();

    // Build a bridge whose target_frame.hash is the source's hash, not the
    // actual target frame's hash.
    let v = json!({
        "version": "0.1",
        "source_frame": { "hash": src.canonical_hash().to_string() },
        "target_frame": { "hash": src.canonical_hash().to_string() },
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "assessor-equivalence",
            "source_descriptors": [
                {
                    "source_index": 0,
                    "assumptions": ["equal reliability"]
                }
            ]
        },
        "assumptions": [],
        "losses": []
    });
    let bridge = Bridge::parse(&v).expect("valid bridge");
    let query = dummy_query();

    let err = check_bridge_applicability(&bridge, &src, &tgt, &query).unwrap_err();
    assert!(
        err.contains(&APL_BRIDGE_FRAME_MISMATCH),
        "expected APL_BRIDGE_FRAME_MISMATCH for target hash mismatch, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 17: Mapping with multiple descriptors → Ok
// ---------------------------------------------------------------------------

#[test]
fn should_accept_mapping_with_multiple_descriptors() {
    let src = valid_ats_frame();
    let tgt = valid_ats_frame_b();

    let v = json!({
        "version": "0.1",
        "source_frame": { "hash": src.canonical_hash().to_string() },
        "target_frame": { "hash": tgt.canonical_hash().to_string() },
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "assessor-equivalence",
            "source_descriptors": [
                {
                    "source_index": 0,
                    "assumptions": ["equal reliability"]
                },
                {
                    "source_index": 1,
                    "assumptions": ["independent corroboration"]
                }
            ]
        },
        "assumptions": [],
        "losses": []
    });
    let bridge = Bridge::parse(&v).expect("valid bridge");
    let query = dummy_query();

    assert!(
        check_bridge_applicability(&bridge, &src, &tgt, &query).is_ok(),
        "mapping with multiple descriptors must be accepted"
    );
}
