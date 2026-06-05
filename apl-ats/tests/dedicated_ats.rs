//! Dedicated (non-vector-driven) integration tests for the ATS profile.
//!
//! These tests exercise specific scenarios that are not covered by the
//! declarative vector fixtures in [`common`] and run via [`vectors_ats`].
//!
//! # Shared harness
//!
//! Mock carriers, `setup()`, and helper types are imported from the sibling
//! module [`common`].  Core APL types come from `apl_core::prelude`.

mod common;

use apl_ats::AtsProfile;
use common::*;
use apl_core::prelude::*;

// ---------------------------------------------------------------------------
// Happy-path: valid ATS receipt accepted with profile
// ---------------------------------------------------------------------------

/// Verify that a minimal valid ATS receipt is accepted when processed with
/// the AtsProfile. This is the "happy path" integration test.
#[test]
fn valid_ats_receipt_accepted_with_profile() {
    setup();

    let frame = serde_json::json!({
        "version": "0.1",
        "observer": "CIA/DI/Office of Transnational Issues",
        "procedure": "structured-analytic-technique/ACH",
        "instrument": "analyst-judgment",
        "aspect": ["nuclear_capability_assessment"],
        "scope": "DPRK nuclear program Q2 2026",
        "invariance": ["assessment framework", "source evaluation criteria"],
        "exclusions": [
            "no claim about delivery systems readiness",
            "no claim about fissile material stockpile quantity"
        ],
        "profile": "APL/ATS",
        "source_descriptors": [{"source_type": "HUMINT"}],
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "confidence_level": "moderate",
        "classification_marking": "TS//SCI//NOFORN"
    });

    let hash = canonical_hash(&frame);

    let mut frames = InMemoryFrameResolver::new();
    frames.insert(frame);

    let bridges = InMemoryBridgeResolver::new();

    let metadata = serde_json::json!({
        "apl": {
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {"id": "DPRK-nuclear-assessment-2026"},
                "aspect_refs": ["nuclear_capability_assessment"],
                "statement": {
                    "predicate": "assess",
                    "content": {"judgment": "DPRK has a baseline nuclear capability"}
                }
            },
            "frame_ref": {"hash": hash.to_string()}
        }
    });

    let carrier = MockCarrier { metadata };
    let profile = AtsProfile;

    let out = verify_receipt(b"", &carrier, &frames, &bridges, Some(&profile)).0;

    assert_eq!(
        out.core_outcome,
        CoreOutcome::AplValid,
        "ATS receipt must be valid; full output: {}",
        out.to_json_pretty()
    );
}

// ---------------------------------------------------------------------------
// Bridge without descriptor mapping is rejected
// ---------------------------------------------------------------------------

/// Verify that two individually valid ATS receipts with different frames
/// are incomparable when a bridge lacks the required source_descriptors
/// mapping.
#[test]
fn bridge_without_descriptor_mapping_is_rejected() {
    setup();

    let frame_a = serde_json::json!({
        "version": "0.1",
        "observer": "CIA/DI",
        "procedure": "ACH",
        "aspect": ["nuclear_capability_assessment"],
        "scope": "DPRK Q2 2026",
        "invariance": ["framework"],
        "exclusions": ["no delivery systems claim"],
        "profile": "APL/ATS",
        "source_descriptors": [{"source_type": "HUMINT"}],
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "confidence_level": "moderate",
        "classification_marking": "TS//SCI//NOFORN"
    });

    let frame_b = serde_json::json!({
        "version": "0.1",
        "observer": "NSA/RD",
        "procedure": "ACH",
        "aspect": ["nuclear_capability_assessment"],
        "scope": "DPRK Q2 2026",
        "invariance": ["framework"],
        "exclusions": ["no delivery systems claim"],
        "profile": "APL/ATS",
        "source_descriptors": [{"source_type": "SIGINT"}],
        "methodology_ref": {
            "hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "confidence_level": "high",
        "classification_marking": "TS//SI//NOFORN"
    });

    let hash_a = canonical_hash(&frame_a);
    let hash_b = canonical_hash(&frame_b);

    assert_ne!(
        hash_a, hash_b,
        "Frame A and Frame B must have different hashes for this test to be meaningful"
    );

    let mut frames = InMemoryFrameResolver::new();
    frames.insert(frame_a);
    frames.insert(frame_b);

    let bridges = InMemoryBridgeResolver::new();

    let query = RelationQuery::parse(&serde_json::json!({
        "left_aspects": ["nuclear_capability_assessment"],
        "right_aspects": ["nuclear_capability_assessment"],
        "predicate": "assess",
        "relation_type": "alternative-analysis"
    }))
    .expect("query must parse");

    // Bridge with NO source_descriptors in comparison_scope — this is the key
    // deviation that should cause rejection under ATS profile.
    let bridge = serde_json::json!({
        "version": "0.1",
        "source_frame": {"hash": hash_a.to_string()},
        "target_frame": {"hash": hash_b.to_string()},
        "comparison_scope": {
            "source_aspects": ["nuclear_capability_assessment"],
            "target_aspects": ["nuclear_capability_assessment"],
            "relation_type": "alternative-analysis"
        },
        "assumptions": [],
        "losses": []
    });

    // The bridge must be referenced via bridge_refs in both claims
    // so the evaluator can match by canonical hash.
    let bridge_hash = canonical_hash(&bridge).to_string();

    let meta_left = serde_json::json!({
        "apl": {
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {"id": "x"},
                "aspect_refs": ["nuclear_capability_assessment"],
                "statement": {
                    "predicate": "assess",
                    "content": {"judgment": "X"}
                }
            },
            "frame_ref": {"hash": hash_a.to_string()},
            "bridge_refs": [{"hash": bridge_hash}]
        }
    });

    let meta_right = serde_json::json!({
        "apl": {
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {"id": "x"},
                "aspect_refs": ["nuclear_capability_assessment"],
                "statement": {
                    "predicate": "assess",
                    "content": {"judgment": "X"}
                }
            },
            "frame_ref": {"hash": hash_b.to_string()},
            "bridge_refs": [{"hash": bridge_hash}]
        }
    });

    let carrier = DispatchMockCarrier {
        left: meta_left,
        right: meta_right,
    };

    let profile = AtsProfile;
    let input = PairwiseInput {
        left: ReceiptInput::Bytes(b"left"),
        right: ReceiptInput::Bytes(b"right"),
        query,
        supplied_bridges: vec![bridge],
    };

    let out = evaluate_relation(input, &carrier, &frames, &bridges, Some(&profile));

    // Both sides individually are valid.
    assert_eq!(
        out.left.core_outcome,
        CoreOutcome::AplValid,
        "left side must be core-valid; diagnostics: {:?}",
        out.diagnostics
    );
    assert_eq!(
        out.right.core_outcome,
        CoreOutcome::AplValid,
        "right side must be core-valid; diagnostics: {:?}",
        out.diagnostics
    );

    // The pair is incomparable because the bridge lacks source_descriptors mapping.
    assert_eq!(
        out.relation_outcome,
        RelationOutcome::Incomparable,
        "bridge without source_descriptors must yield Incomparable; full output: {}",
        out.to_json_pretty()
    );

    // The bridge-no-descriptor-map diagnostic must be present.
    let has_no_map = out
        .diagnostics
        .iter()
        .any(|d| d.as_str() == "apl-ats-bridge-no-descriptor-map");
    assert!(
        has_no_map,
        "apl-ats-bridge-no-descriptor-map must be present; actual: {:?}",
        out.diagnostics
    );
}
