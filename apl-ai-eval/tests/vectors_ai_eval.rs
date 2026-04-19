//! Vector-driven integration tests for the AI-Eval vertical profile.
//!
//! Loads every fixture from `test_data/vectors/single/` and
//! `test_data/vectors/pairwise/` inside the `apl-ai-eval` crate and runs them
//! through the core verifier and pairwise evaluator with the [`AiEvalProfile`]
//! active.
//!
//! # Mock carrier
//!
//! All vectors use a `MockCarrier` or `DispatchMockCarrier` (same approach as
//! the core harness in `apl-core/tests/vectors_core.rs`). ATL cryptography is
//! tested in `atl-core`; this harness focuses on the APL+AI-Eval profile logic.
//!
//! # Hash-placeholder substitution
//!
//! Fixtures use `"<FRAME_HASH:N>"` placeholders. The harness replaces them
//! with `canonical_hash(frames[N])` before passing data to the verifier.
//!
//! # Profile gate
//!
//! All vectors in `apl-ai-eval/test_data/vectors/` must declare
//! `"profile": "ai-eval"`. The harness panics if any vector omits the profile
//! or uses an unrecognized one — AI-Eval vectors are expected to require the
//! profile.

use std::{fs, path::Path};

use apl_ai_eval::AiEvalProfile;
use apl_core::prelude::*;
use serde::Deserialize;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SingleVector {
    name: String,
    #[allow(dead_code)]
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
    #[serde(default)]
    carrier: Option<String>,
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
// Mock carriers
// ---------------------------------------------------------------------------

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

struct AlwaysInvalidCarrier;

impl CarrierVerifier for AlwaysInvalidCarrier {
    fn verify_carrier(&self, _bytes: &[u8]) -> CarrierOutcome {
        CarrierOutcome::Invalid {
            reason: Some("mock carrier always invalid".to_owned()),
        }
    }
}

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
                    .unwrap_or_else(|_| panic!("invalid FRAME_HASH index: {s}"));
                let frame = frames.get(idx).unwrap_or_else(|| {
                    panic!(
                        "FRAME_HASH placeholder index {idx} out of range (frames.len={})",
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

    // Only "ai-eval" profile is expected for vectors in this harness.
    match v.profile.as_deref() {
        Some("ai-eval") => {}
        other => panic!(
            "[{}] AI-Eval harness requires profile=ai-eval; got {:?}",
            v.name, other
        ),
    }

    substitute_hash_placeholders(&mut v.metadata_apl, &v.frames);

    let mut frames = InMemoryFrameResolver::new();
    for f in &v.frames {
        frames.insert(f.clone());
    }
    let mut bridges_resolver = InMemoryBridgeResolver::new();
    for b in &v.bridges {
        bridges_resolver.insert(b.clone());
    }

    let metadata = serde_json::json!({ "apl": v.metadata_apl });
    let profile = AiEvalProfile;

    let out = match v.carrier.as_deref() {
        None | Some("valid") => {
            let carrier = MockCarrier { metadata };
            verify_receipt(b"", &carrier, &frames, &bridges_resolver, Some(&profile))
        }
        Some("invalid") => {
            let carrier = AlwaysInvalidCarrier;
            verify_receipt(b"", &carrier, &frames, &bridges_resolver, Some(&profile))
        }
        Some(other) => panic!("[{}] unknown carrier value: {other}", v.name),
    };

    assert_single_expected(&v.name, &out, &v.expected);
}

fn assert_single_expected(name: &str, out: &VerifierOutput, expected: &SingleExpected) {
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

fn run_pairwise_vector(path: &Path) {
    let src = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e));
    let mut v: PairwiseVector = serde_json::from_str(&src)
        .unwrap_or_else(|e| panic!("cannot parse {}: {}", path.display(), e));

    match v.profile.as_deref() {
        Some("ai-eval") => {}
        other => panic!(
            "[{}] AI-Eval harness requires profile=ai-eval; got {:?}",
            v.name, other
        ),
    }

    substitute_hash_placeholders(&mut v.left.metadata_apl, &v.frames);
    substitute_hash_placeholders(&mut v.right.metadata_apl, &v.frames);
    for b in v.supplied_bridges.iter_mut() {
        substitute_hash_placeholders(b, &v.frames);
    }

    let mut frames = InMemoryFrameResolver::new();
    for f in &v.frames {
        frames.insert(f.clone());
    }
    let mut bridges_resolver = InMemoryBridgeResolver::new();
    for b in &v.bridges {
        let mut bv = b.clone();
        substitute_hash_placeholders(&mut bv, &v.frames);
        bridges_resolver.insert(bv);
    }

    let query = RelationQuery::parse(&v.query)
        .unwrap_or_else(|e| panic!("cannot parse query in {}: {e:?}", path.display()));

    let carrier = DispatchMockCarrier {
        left: serde_json::json!({ "apl": v.left.metadata_apl }),
        right: serde_json::json!({ "apl": v.right.metadata_apl }),
    };

    let profile = AiEvalProfile;
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

// ---------------------------------------------------------------------------
// Top-level test functions
// ---------------------------------------------------------------------------

#[test]
fn all_single_vectors_ai_eval() {
    let dir = Path::new("test_data/vectors/single");
    assert!(
        dir.exists(),
        "test_data/vectors/single directory not found; run from apl-ai-eval crate root"
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
        "no single vectors found in apl-ai-eval/test_data/vectors/single"
    );
}

#[test]
fn all_pairwise_vectors_ai_eval() {
    let dir = Path::new("test_data/vectors/pairwise");
    assert!(
        dir.exists(),
        "test_data/vectors/pairwise directory not found; run from apl-ai-eval crate root"
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
        "no pairwise vectors found in apl-ai-eval/test_data/vectors/pairwise"
    );
}

// ---------------------------------------------------------------------------
// Dedicated test: The Two MMLU Scores
// ---------------------------------------------------------------------------

/// Dedicated test for the canonical adversarial demo.
///
/// Verifies that two individually valid AI-Eval receipts with different frames
/// (different runner, grader, and dataset_split) are incomparable when no
/// bridge is supplied.
#[test]
fn two_mmlu_scores_incomparable_with_ai_eval_profile() {
    let frame_a = serde_json::json!({
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
    let frame_b = serde_json::json!({
        "version": "0.1",
        "observer": { "id": "acme-eval-lab" },
        "procedure": {
            "runner_id": "custom-runner@2.1",
            "grader_id": "llm-judge-v3",
            "prompt_protocol": "zero-shot-mcq-v1"
        },
        "aspect": ["accuracy"],
        "scope": {
            "benchmark_id": "mmlu",
            "benchmark_variant": "default",
            "dataset_split": "test-lite"
        },
        "invariance": ["score-object-serialization"],
        "exclusions": [
            "no-production-readiness-claim",
            "no-deployment-safety-claim",
            "no-out-of-scope-generalization-claim"
        ]
    });

    let hash_a = canonical_hash(&frame_a);
    let hash_b = canonical_hash(&frame_b);

    let mut frames = InMemoryFrameResolver::new();
    frames.insert(frame_a);
    frames.insert(frame_b);
    let bridges = InMemoryBridgeResolver::new();

    let meta_left = serde_json::json!({
        "apl": {
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:acme-gpt-7b-build-42",
                    "build_id": "42",
                    "artifact_digest": "sha256:4242424242424242424242424242424242424242424242424242424242424242",
                    "provider": "acme",
                    "model_family": "acme-gpt-7b"
                },
                "aspect_refs": ["accuracy"],
                "statement": {
                    "predicate": "score",
                    "content": {
                        "benchmark_id": "mmlu",
                        "metric_id": "accuracy",
                        "value": 0.781,
                        "unit": "fraction"
                    }
                }
            },
            "frame_ref": { "hash": hash_a.to_string() }
        }
    });
    let meta_right = serde_json::json!({
        "apl": {
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {
                    "type": "model-build",
                    "id": "model:acme-gpt-7b-build-44",
                    "build_id": "44",
                    "artifact_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
                    "provider": "acme",
                    "model_family": "acme-gpt-7b"
                },
                "aspect_refs": ["accuracy"],
                "statement": {
                    "predicate": "score",
                    "content": {
                        "benchmark_id": "mmlu",
                        "metric_id": "accuracy",
                        "value": 0.790,
                        "unit": "fraction"
                    }
                }
            },
            "frame_ref": { "hash": hash_b.to_string() }
        }
    });

    let carrier = DispatchMockCarrier {
        left: meta_left,
        right: meta_right,
    };

    let query = RelationQuery::parse(&serde_json::json!({
        "left_aspects":  ["accuracy"],
        "right_aspects": ["accuracy"],
        "predicate":     "score",
        "relation_type": "score-delta"
    }))
    .expect("query must parse");

    let profile = AiEvalProfile;
    let input = PairwiseInput {
        left: ReceiptInput::Bytes(b"left"),
        right: ReceiptInput::Bytes(b"right"),
        query,
        supplied_bridges: vec![],
    };

    let out = evaluate_relation(input, &carrier, &frames, &bridges, Some(&profile));

    // Both sides must be individually valid.
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

    // Without a bridge, the pair is incomparable.
    assert_eq!(
        out.relation_outcome,
        RelationOutcome::Incomparable,
        "The Two MMLU Scores must be Incomparable without a bridge; full output: {}",
        out.to_json_pretty()
    );

    // The cross-frame and bridge-not-found diagnostics must be present.
    let has_cross_frame = out
        .diagnostics
        .iter()
        .any(|d| d.as_str() == "apl-cross-frame");
    assert!(
        has_cross_frame,
        "apl-cross-frame must be present; actual: {:?}",
        out.diagnostics
    );

    let has_bridge_not_found = out
        .diagnostics
        .iter()
        .any(|d| d.as_str() == "apl-bridge-not-found");
    assert!(
        has_bridge_not_found,
        "apl-bridge-not-found must be present; actual: {:?}",
        out.diagnostics
    );
}
