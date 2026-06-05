//! Shared harness for ATS vector-driven integration tests.
//!
//! This module is not a test crate — it is imported by `vectors_ats.rs` and
//! `dedicated_ats.rs` via `mod common;`.  See the individual test files for
//! the top-level `#[test]` functions.
//!
//! Dead-code warnings are suppressed because not every test binary uses every
//! item exported by this shared module (Cargo compiles each `tests/*.rs` as a
//! separate crate with its own copy of this module).

#![allow(dead_code)]

use std::{fs, path::Path, sync::OnceLock};

use apl_ats::AtsProfile;
use apl_core::prelude::*;
use serde::Deserialize;
use serde_json::Value;

// ---------------------------------------------------------------------------
// One-time setup
// ---------------------------------------------------------------------------

/// Register the ATS profile and diagnostic codes.  Idempotent across tests.
pub fn setup() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        apl_ats::register();
    });
}

// ---------------------------------------------------------------------------
// Vector structs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SingleVector {
    pub name: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub description: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub source: String,
    pub metadata_apl: Value,
    #[serde(default)]
    pub frames: Vec<Value>,
    #[serde(default)]
    pub bridges: Vec<Value>,
    #[serde(default)]
    pub carrier: Option<String>,
    pub profile: Option<String>,
    pub expected: SingleExpected,
}

#[derive(Deserialize)]
pub struct SingleExpected {
    pub core_outcome: String,
    pub relation_outcome: String,
    #[serde(default)]
    pub failure_classes_contains: Vec<String>,
    #[serde(default)]
    pub diagnostics_contains: Vec<String>,
    #[serde(default)]
    pub diagnostics_absent: Vec<String>,
}

#[derive(Deserialize)]
pub struct PairwiseVector {
    pub name: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub description: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub source: String,
    pub left: SideVector,
    pub right: SideVector,
    #[serde(default)]
    pub frames: Vec<Value>,
    #[serde(default)]
    pub bridges: Vec<Value>,
    #[serde(default)]
    pub supplied_bridges: Vec<Value>,
    pub query: Value,
    pub profile: Option<String>,
    pub expected: PairwiseExpected,
}

#[derive(Deserialize)]
pub struct SideVector {
    pub metadata_apl: Value,
}

#[derive(Deserialize)]
pub struct PairwiseExpected {
    pub left_core: String,
    pub right_core: String,
    pub relation_outcome: String,
    #[serde(default)]
    pub diagnostics_contains: Vec<String>,
    #[serde(default)]
    pub diagnostics_absent: Vec<String>,
}

// ---------------------------------------------------------------------------
// Mock carriers
// ---------------------------------------------------------------------------

pub struct MockCarrier {
    pub metadata: Value,
}

impl CarrierVerifier for MockCarrier {
    fn verify_carrier(&self, _bytes: &[u8]) -> CarrierOutcome {
        CarrierOutcome::Valid {
            payload: vec![],
            metadata: self.metadata.clone(),
        }
    }
}

pub struct AlwaysInvalidCarrier;

impl CarrierVerifier for AlwaysInvalidCarrier {
    fn verify_carrier(&self, _bytes: &[u8]) -> CarrierOutcome {
        CarrierOutcome::Invalid {
            reason: Some("mock carrier always invalid".to_owned()),
        }
    }
}

pub struct DispatchMockCarrier {
    pub left: Value,
    pub right: Value,
}

impl CarrierVerifier for DispatchMockCarrier {
    fn verify_carrier(&self, bytes: &[u8]) -> CarrierOutcome {
        let metadata = match bytes {
            b"left" => self.left.clone(),
            b"right" => self.right.clone(),
            other => {
                return CarrierOutcome::Invalid {
                    reason: Some(format!(
                        "DispatchMockCarrier: unknown dispatch key {:?}",
                        other
                    )),
                };
            }
        };
        CarrierOutcome::Valid {
            payload: vec![],
            metadata,
        }
    }
}

// ---------------------------------------------------------------------------
// Hash-placeholder substitution
// ---------------------------------------------------------------------------

/// Replace hash placeholders in `v` recursively.
///
/// Supported placeholder forms:
///
/// - `"<FRAME_HASH:N>"` — replaced with `canonical_hash(frames[N])`.
/// - `"<BRIDGE_HASH:N>"` — replaced with `canonical_hash(supplied_bridges[N])`.
///   FRAME_HASH placeholders in supplied_bridges must be resolved first before
///   computing BRIDGE_HASH values.
pub fn substitute_hash_placeholders(v: &mut Value, frames: &[Value], supplied_bridges: &[Value]) {
    match v {
        Value::Object(map) => {
            for (_, val) in map.iter_mut() {
                substitute_hash_placeholders(val, frames, supplied_bridges);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                substitute_hash_placeholders(item, frames, supplied_bridges);
            }
        }
        Value::String(s) => {
            if let Some(idx_str) = s
                .strip_prefix("<FRAME_HASH:")
                .and_then(|tail| tail.strip_suffix('>'))
            {
                let idx: usize = idx_str
                    .parse()
                    .unwrap_or_else(|_| panic!("invalid FRAME_HASH index: {s}"));
                let frame = frames.get(idx).unwrap_or_else(|| {
                    panic!(
                        "FRAME_HASH placeholder index {idx} out of range (frames.len={})",
                        frames.len()
                    )
                });
                *s = canonical_hash(frame).to_string();
            } else if let Some(idx_str) = s
                .strip_prefix("<BRIDGE_HASH:")
                .and_then(|tail| tail.strip_suffix('>'))
            {
                let idx: usize = idx_str
                    .parse()
                    .unwrap_or_else(|_| panic!("invalid BRIDGE_HASH index: {s}"));
                let bridge = supplied_bridges.get(idx).unwrap_or_else(|| {
                    panic!(
                        "BRIDGE_HASH placeholder index {idx} out of range (supplied_bridges.len={})",
                        supplied_bridges.len()
                    )
                });
                *s = canonical_hash(bridge).to_string();
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Single-receipt vector runner
// ---------------------------------------------------------------------------

pub fn run_single_vector(path: &Path) {
    setup();
    let src = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e));
    let mut v: SingleVector = serde_json::from_str(&src)
        .unwrap_or_else(|e| panic!("cannot parse {}: {}", path.display(), e));

    // Only "ats" profile is expected for vectors in this harness.
    match v.profile.as_deref() {
        Some("ats") => {}
        other => panic!(
            "[{}] ATS harness requires profile=ats; got {:?}",
            v.name, other
        ),
    }

    // Two-pass hash substitution for frames (needed because ATS frames contain
    // methodology_ref.hash that may use FRAME_HASH placeholders).
    // Pass 1: compute hashes of original frames (with placeholders),
    //         substitute those hashes into frame copies.
    let mut mutable_frames: Vec<Value> = v.frames.iter().map(|f| f.clone()).collect();
    for j in 0..mutable_frames.len() {
        substitute_hash_placeholders(&mut mutable_frames[j], &v.frames, &[]);
    }

    // Pass 2: substitute metadata_apl using the resolved frames (so frame_ref
    //         hashes match the frames in the resolver).
    substitute_hash_placeholders(&mut v.metadata_apl, &mutable_frames, &[]);

    let mut frames = InMemoryFrameResolver::new();
    for f in &mutable_frames {
        frames.insert(f.clone());
    }
    let mut bridges_resolver = InMemoryBridgeResolver::new();
    for b in &v.bridges {
        bridges_resolver.insert(b.clone());
    }

    let metadata = serde_json::json!({ "apl": v.metadata_apl });
    let profile = AtsProfile;

    let out = match v.carrier.as_deref() {
        None | Some("valid") => {
            let carrier = MockCarrier { metadata };
            verify_receipt(b"", &carrier, &frames, &bridges_resolver, Some(&profile)).0
        }
        Some("invalid") => {
            let carrier = AlwaysInvalidCarrier;
            verify_receipt(b"", &carrier, &frames, &bridges_resolver, Some(&profile)).0
        }
        Some(other) => panic!("[{}] unknown carrier value: {other}", v.name),
    };

    assert_single_expected(&v.name, &out, &v.expected);
}

pub fn assert_single_expected(name: &str, out: &VerifierOutput, expected: &SingleExpected) {
    let core_got = match out.core_outcome {
        CoreOutcome::AplValid => "apl-valid",
        CoreOutcome::AplInvalid => "apl-invalid",
    };
    assert_eq!(
        core_got,
        expected.core_outcome,
        "[{name}] core_outcome mismatch: got={core_got}, expected={}\nfull output: {}",
        expected.core_outcome,
        out.to_json_pretty(),
    );

    let relation_got = match out.relation_outcome {
        RelationOutcome::RelationNotEvaluated => "relation-not-evaluated",
        RelationOutcome::SameFrameComparable => "same-frame-comparable",
        RelationOutcome::BridgedComparable => "bridged-comparable",
        RelationOutcome::Incomparable => "incomparable",
    };
    assert_eq!(
        relation_got,
        expected.relation_outcome,
        "[{name}] relation_outcome mismatch\nfull output: {}",
        out.to_json_pretty(),
    );

    for want in &expected.failure_classes_contains {
        let present = out.failure_classes.iter().any(|f| f.as_str() == *want);
        assert!(
            present,
            "[{name}] missing failure_class: {want}\nactual: {:?}\nfull: {}",
            out.failure_classes,
            out.to_json_pretty(),
        );
    }

    for want in &expected.diagnostics_contains {
        let present = out.diagnostics.iter().any(|d| d.as_str() == *want);
        assert!(
            present,
            "[{name}] missing diagnostic: {want}\nactual: {:?}\nfull: {}",
            out.diagnostics,
            out.to_json_pretty(),
        );
    }

    for forbidden in &expected.diagnostics_absent {
        let present = out.diagnostics.iter().any(|d| d.as_str() == *forbidden);
        assert!(
            !present,
            "[{name}] forbidden diagnostic present: {forbidden}\nactual: {:?}\nfull: {}",
            out.diagnostics,
            out.to_json_pretty(),
        );
    }
}

// ---------------------------------------------------------------------------
// Pairwise vector runner
// ---------------------------------------------------------------------------

pub fn run_pairwise_vector(path: &Path) {
    setup();
    let src = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e));
    let mut v: PairwiseVector = serde_json::from_str(&src)
        .unwrap_or_else(|e| panic!("cannot parse {}: {}", path.display(), e));

    match v.profile.as_deref() {
        Some("ats") => {}
        other => panic!(
            "[{}] ATS harness requires profile=ats; got {:?}",
            v.name, other
        ),
    }

    // Two-pass hash substitution for frames (needed because ATS frames contain
    // methodology_ref.hash that may use FRAME_HASH placeholders).
    let mut mutable_frames: Vec<Value> = v.frames.iter().map(|f| f.clone()).collect();
    for j in 0..mutable_frames.len() {
        substitute_hash_placeholders(&mut mutable_frames[j], &v.frames, &[]);
    }

    // Substitute FRAME_HASH in supplied_bridges using the resolved frames so
    // source/target frame hashes match the hashes in the frame resolver.
    for b in v.supplied_bridges.iter_mut() {
        substitute_hash_placeholders(b, &mutable_frames, &[]);
    }
    substitute_hash_placeholders(&mut v.left.metadata_apl, &mutable_frames, &v.supplied_bridges);
    substitute_hash_placeholders(&mut v.right.metadata_apl, &mutable_frames, &v.supplied_bridges);

    let mut frames = InMemoryFrameResolver::new();
    for f in &mutable_frames {
        frames.insert(f.clone());
    }
    let mut bridges_resolver = InMemoryBridgeResolver::new();
    for b in &v.bridges {
        let mut bv = b.clone();
        substitute_hash_placeholders(&mut bv, &mutable_frames, &[]);
        bridges_resolver.insert(bv);
    }

    let query = RelationQuery::parse(&v.query)
        .unwrap_or_else(|e| panic!("cannot parse query in {}: {e:?}", path.display()));

    let carrier = DispatchMockCarrier {
        left: serde_json::json!({ "apl": v.left.metadata_apl }),
        right: serde_json::json!({ "apl": v.right.metadata_apl }),
    };

    let profile = AtsProfile;
    let input = PairwiseInput {
        left: ReceiptInput::Bytes(b"left"),
        right: ReceiptInput::Bytes(b"right"),
        query,
        supplied_bridges: v.supplied_bridges.clone(),
    };

    let out = evaluate_relation(input, &carrier, &frames, &bridges_resolver, Some(&profile));

    let left_core_got = match out.left.core_outcome {
        CoreOutcome::AplValid => "apl-valid",
        CoreOutcome::AplInvalid => "apl-invalid",
    };
    assert_eq!(
        left_core_got,
        v.expected.left_core,
        "[{}] left core_outcome mismatch\nfull output: {}",
        v.name,
        out.to_json_pretty(),
    );

    let right_core_got = match out.right.core_outcome {
        CoreOutcome::AplValid => "apl-valid",
        CoreOutcome::AplInvalid => "apl-invalid",
    };
    assert_eq!(
        right_core_got,
        v.expected.right_core,
        "[{}] right core_outcome mismatch\nfull output: {}",
        v.name,
        out.to_json_pretty(),
    );

    let relation_got = match out.relation_outcome {
        RelationOutcome::RelationNotEvaluated => "relation-not-evaluated",
        RelationOutcome::SameFrameComparable => "same-frame-comparable",
        RelationOutcome::BridgedComparable => "bridged-comparable",
        RelationOutcome::Incomparable => "incomparable",
    };
    assert_eq!(
        relation_got,
        v.expected.relation_outcome,
        "[{}] relation_outcome mismatch: got={relation_got}, expected={}\nfull output: {}",
        v.name,
        v.expected.relation_outcome,
        out.to_json_pretty(),
    );

    for want in &v.expected.diagnostics_contains {
        let present = out.diagnostics.iter().any(|d| d.as_str() == *want);
        assert!(
            present,
            "[{}] missing diagnostic: {want}\nactual: {:?}\nfull output: {}",
            v.name,
            out.diagnostics,
            out.to_json_pretty(),
        );
    }

    for forbidden in &v.expected.diagnostics_absent {
        let present = out.diagnostics.iter().any(|d| d.as_str() == *forbidden);
        assert!(
            !present,
            "[{}] forbidden diagnostic present: {forbidden}\nactual: {:?}\nfull output: {}",
            v.name,
            out.diagnostics,
            out.to_json_pretty(),
        );
    }
}
