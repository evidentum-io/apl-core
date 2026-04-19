//! Vector-driven integration tests for apl-core.
//!
//! Loads every fixture from `test_data/vectors/single/` and
//! `test_data/vectors/pairwise/` and runs the fixtures through the core
//! verifier and pairwise evaluator respectively, asserting that the outputs
//! match the `expected` block in each file.
//!
//! # Mock carrier
//!
//! ATL carrier integration is not available in apl-core. All single-receipt
//! vectors use a `MockCarrier` that unconditionally returns `CarrierOutcome::Valid`
//! and wraps the vector's `metadata_apl` value in the expected `{"apl": ...}`
//! envelope. This exercises every APL-layer verification step while bypassing
//! ATL cryptography, which is tested in `atl-core` directly.
//!
//! Pairwise vectors use a `DispatchMockCarrier` that distinguishes the two
//! sides by the magic sentinel bytes `b"left"` and `b"right"`. The pairwise
//! harness passes those bytes as `ReceiptInput::Bytes`; the carrier dispatches
//! accordingly.
//!
//! Vectors whose `carrier` field equals `"invalid"` use a `AlwaysInvalidCarrier`
//! that unconditionally returns `CarrierOutcome::Invalid`, which lets the
//! carrier-failure test class be exercised without any ATL dependency.
//!
//! # Hash placeholder substitution
//!
//! Fixture files use `"<FRAME_HASH:N>"` as the `frame_ref.hash` value (and
//! wherever else a hash needs to reference `frames[N]`). The harness calls
//! `substitute_hash_placeholders` to replace every such string with the actual
//! `canonical_hash` of `frames[N]` before passing the claim to the verifier.
//! This avoids hand-coding SHA-256 values in fixture files.

use std::{fs, path::Path};

use apl_core::prelude::*;
use serde::Deserialize;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SingleVector {
    name: String,
    #[serde(default)]
    description: String,
    #[allow(dead_code)]
    #[serde(default)]
    source: String,
    metadata_apl: Value,
    #[serde(default)]
    frames: Vec<Value>,
    #[serde(default)]
    bridges: Vec<Value>,
    /// Optional carrier override. Supported values: `null` (default, always-valid)
    /// and `"invalid"` (always-invalid, for carrier-failure vectors).
    #[serde(default)]
    carrier: Option<String>,
    /// Profile identifier. Only `null` is accepted here; profile-specific vectors
    /// live in the `apl-ai-eval` crate.
    #[serde(default)]
    profile: Option<String>,
    expected: SingleExpected,
}

#[derive(Deserialize)]
struct SingleExpected {
    core_outcome: String,
    relation_outcome: String,
    #[serde(default)]
    failure_classes_contains: Vec<String>,
    #[serde(default)]
    diagnostics_contains: Vec<String>,
    #[serde(default)]
    diagnostics_absent: Vec<String>,
}

#[derive(Deserialize)]
struct PairwiseVector {
    name: String,
    #[allow(dead_code)]
    #[serde(default)]
    description: String,
    #[allow(dead_code)]
    #[serde(default)]
    source: String,
    left: SideVector,
    right: SideVector,
    #[serde(default)]
    frames: Vec<Value>,
    #[serde(default)]
    bridges: Vec<Value>,
    #[serde(default)]
    supplied_bridges: Vec<Value>,
    query: Value,
    #[serde(default)]
    profile: Option<String>,
    expected: PairwiseExpected,
}

#[derive(Deserialize)]
struct SideVector {
    metadata_apl: Value,
}

#[derive(Deserialize)]
struct PairwiseExpected {
    left_core: String,
    right_core: String,
    relation_outcome: String,
    #[serde(default)]
    diagnostics_contains: Vec<String>,
    #[serde(default)]
    diagnostics_absent: Vec<String>,
}

// ---------------------------------------------------------------------------
// Mock carrier
// ---------------------------------------------------------------------------

/// Mock carrier that always returns `CarrierOutcome::Valid` with the provided
/// `metadata` value. Used for all non-carrier-failure single-receipt vectors.
struct MockCarrier {
    metadata: Value,
}

impl CarrierVerifier for MockCarrier {
    fn verify_carrier(&self, _bytes: &[u8]) -> CarrierOutcome {
        CarrierOutcome::Valid {
            payload: vec![],
            metadata: self.metadata.clone(),
        }
    }
}

/// Mock carrier that always returns `CarrierOutcome::Invalid`. Used for the
/// `carrier-failure` test vector.
struct AlwaysInvalidCarrier;

impl CarrierVerifier for AlwaysInvalidCarrier {
    fn verify_carrier(&self, _bytes: &[u8]) -> CarrierOutcome {
        CarrierOutcome::Invalid {
            reason: Some("mock carrier always invalid".to_owned()),
        }
    }
}

/// Dispatch carrier for pairwise vectors. Routes by sentinel bytes.
///
/// The pairwise harness passes `b"left"` and `b"right"` as the carrier bytes
/// for the respective sides.
struct DispatchMockCarrier {
    left: Value,
    right: Value,
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

/// Replace every `"<FRAME_HASH:N>"` placeholder in `v` with the
/// `canonical_hash` of `frames[N]`.
///
/// The substitution is recursive — it walks the entire JSON tree so that
/// placeholders inside nested objects (e.g. inside a bridge's `source_frame`)
/// are also replaced.
fn substitute_hash_placeholders(v: &mut Value, frames: &[Value]) {
    match v {
        Value::Object(map) => {
            for (_, val) in map.iter_mut() {
                substitute_hash_placeholders(val, frames);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                substitute_hash_placeholders(item, frames);
            }
        }
        Value::String(s) => {
            if let Some(idx_str) = s
                .strip_prefix("<FRAME_HASH:")
                .and_then(|tail| tail.strip_suffix('>'))
            {
                let idx: usize = idx_str
                    .parse()
                    .unwrap_or_else(|_| panic!("invalid FRAME_HASH index in placeholder: {s}"));
                let frame = frames.get(idx).unwrap_or_else(|| {
                    panic!(
                        "FRAME_HASH placeholder index {idx} out of range (frames.len = {})",
                        frames.len()
                    )
                });
                *s = canonical_hash(frame).to_string();
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Single-receipt vector runner
// ---------------------------------------------------------------------------

fn run_single_vector(path: &Path) {
    let src = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e));
    let mut v: SingleVector = serde_json::from_str(&src)
        .unwrap_or_else(|e| panic!("cannot parse {}: {}", path.display(), e));

    // Substitute hash placeholders in metadata_apl using the frames array.
    substitute_hash_placeholders(&mut v.metadata_apl, &v.frames);

    // Build the frame resolver.
    let mut frames = InMemoryFrameResolver::new();
    for f in &v.frames {
        frames.insert(f.clone());
    }
    // Build the bridge resolver.
    let mut bridges = InMemoryBridgeResolver::new();
    for b in &v.bridges {
        bridges.insert(b.clone());
    }

    // Select carrier based on `carrier` field.
    let metadata = serde_json::json!({ "apl": v.metadata_apl });
    let out = match v.carrier.as_deref() {
        None | Some("valid") => {
            let carrier = MockCarrier { metadata };
            call_single(&carrier, &frames, &bridges, &v)
        }
        Some("invalid") => {
            let carrier = AlwaysInvalidCarrier;
            call_single(&carrier, &frames, &bridges, &v)
        }
        Some(other) => panic!("[{}] unknown carrier value: {other}", v.name),
    };

    assert_single_expected(&v.name, &v.description, &out, &v.expected);
}

fn call_single(
    carrier: &dyn CarrierVerifier,
    frames: &InMemoryFrameResolver,
    bridges: &InMemoryBridgeResolver,
    v: &SingleVector,
) -> VerifierOutput {
    match v.profile.as_deref() {
        None => verify_receipt(b"", carrier, frames, bridges, None),
        Some(p) => panic!(
            "[{}] core harness only handles profile=null; got '{p}'. AI-Eval vectors must live in apl-ai-eval/tests/",
            v.name
        ),
    }
}

fn assert_single_expected(
    name: &str,
    description: &str,
    out: &VerifierOutput,
    expected: &SingleExpected,
) {
    let core_got = match out.core_outcome {
        CoreOutcome::AplValid => "apl-valid",
        CoreOutcome::AplInvalid => "apl-invalid",
    };
    assert_eq!(
        core_got,
        expected.core_outcome,
        "[{name}] core_outcome mismatch\ndescription: {description}\ngot={core_got}, expected={}\nfull output: {}",
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
        "[{name}] relation_outcome mismatch: got={relation_got}, expected={}\nfull output: {}",
        expected.relation_outcome,
        out.to_json_pretty(),
    );

    for want in &expected.failure_classes_contains {
        let present = out.failure_classes.iter().any(|f| f.as_str() == want);
        assert!(
            present,
            "[{name}] missing failure_class: {want}\nactual failure_classes: {:?}\nfull output: {}",
            out.failure_classes,
            out.to_json_pretty(),
        );
    }

    for want in &expected.diagnostics_contains {
        let present = out.diagnostics.iter().any(|d| d.as_str() == *want);
        assert!(
            present,
            "[{name}] missing diagnostic: {want}\nactual diagnostics: {:?}\nfull output: {}",
            out.diagnostics,
            out.to_json_pretty(),
        );
    }

    for forbidden in &expected.diagnostics_absent {
        let present = out.diagnostics.iter().any(|d| d.as_str() == *forbidden);
        assert!(
            !present,
            "[{name}] forbidden diagnostic present: {forbidden}\nactual diagnostics: {:?}\nfull output: {}",
            out.diagnostics,
            out.to_json_pretty(),
        );
    }
}

// ---------------------------------------------------------------------------
// Pairwise vector runner
// ---------------------------------------------------------------------------

fn run_pairwise_vector(path: &Path) {
    let src = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e));
    let mut v: PairwiseVector = serde_json::from_str(&src)
        .unwrap_or_else(|e| panic!("cannot parse {}: {}", path.display(), e));

    // Substitute hash placeholders in both sides and supplied bridges.
    substitute_hash_placeholders(&mut v.left.metadata_apl, &v.frames);
    substitute_hash_placeholders(&mut v.right.metadata_apl, &v.frames);
    for b in v.supplied_bridges.iter_mut() {
        substitute_hash_placeholders(b, &v.frames);
    }

    // Build resolvers.
    let mut frames = InMemoryFrameResolver::new();
    for f in &v.frames {
        frames.insert(f.clone());
    }
    let mut bridges = InMemoryBridgeResolver::new();
    for b in &v.bridges {
        // Bridges registered in the resolver also need hash substitution.
        let mut bv = b.clone();
        substitute_hash_placeholders(&mut bv, &v.frames);
        bridges.insert(bv);
    }

    let query = RelationQuery::parse(&v.query)
        .unwrap_or_else(|e| panic!("cannot parse query in {}: {e:?}", path.display()));

    let left_metadata = serde_json::json!({ "apl": v.left.metadata_apl });
    let right_metadata = serde_json::json!({ "apl": v.right.metadata_apl });
    let carrier = DispatchMockCarrier {
        left: left_metadata,
        right: right_metadata,
    };

    let input = PairwiseInput {
        left: ReceiptInput::Bytes(b"left"),
        right: ReceiptInput::Bytes(b"right"),
        query,
        supplied_bridges: v.supplied_bridges.clone(),
    };

    let out = match v.profile.as_deref() {
        None => evaluate_relation(input, &carrier, &frames, &bridges, None),
        Some(p) => panic!(
            "core harness only handles profile=null; got '{p}'. AI-Eval vectors must live in apl-ai-eval/tests/"
        ),
    };

    // Check per-side core outcomes.
    let left_core_got = match out.left.core_outcome {
        CoreOutcome::AplValid => "apl-valid",
        CoreOutcome::AplInvalid => "apl-invalid",
    };
    assert_eq!(
        left_core_got, v.expected.left_core,
        "[{}] left core_outcome mismatch",
        v.name
    );
    let right_core_got = match out.right.core_outcome {
        CoreOutcome::AplValid => "apl-valid",
        CoreOutcome::AplInvalid => "apl-invalid",
    };
    assert_eq!(
        right_core_got, v.expected.right_core,
        "[{}] right core_outcome mismatch",
        v.name
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

// ---------------------------------------------------------------------------
// Top-level test functions
// ---------------------------------------------------------------------------

#[test]
fn all_single_vectors() {
    let dir = Path::new("test_data/vectors/single");
    assert!(
        dir.exists(),
        "test_data/vectors/single directory not found; run from crate root"
    );

    let mut count = 0;
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("cannot read test_data/vectors/single")
        .map(|e| e.expect("dir entry error").path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    entries.sort();

    for path in entries {
        run_single_vector(&path);
        count += 1;
    }

    assert!(
        count > 0,
        "no single vectors found in test_data/vectors/single"
    );
}

#[test]
fn all_pairwise_vectors() {
    let dir = Path::new("test_data/vectors/pairwise");
    assert!(
        dir.exists(),
        "test_data/vectors/pairwise directory not found; run from crate root"
    );

    let mut count = 0;
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("cannot read test_data/vectors/pairwise")
        .map(|e| e.expect("dir entry error").path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    entries.sort();

    for path in entries {
        run_pairwise_vector(&path);
        count += 1;
    }

    assert!(
        count > 0,
        "no pairwise vectors found in test_data/vectors/pairwise"
    );
}
