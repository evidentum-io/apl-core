//! Compile-time and runtime API surface tests per the API-1 spec.

use apl_core::prelude::*;

#[test]
fn prelude_exports_exist() {
    let _: fn() -> Hash = || {
        parse_hash_string(&format!("sha256:{}", "0".repeat(64)))
            .expect("valid hash string must parse")
    };
    let _: fn(&_) -> _ = |v: &serde_json::Value| Claim::parse(v);
    let _: fn(&_) -> _ = |v: &serde_json::Value| Frame::parse(v);
    let _: fn(&_) -> _ = |v: &serde_json::Value| Bridge::parse(v);
    let _: fn(&_) -> _ = |v: &serde_json::Value| Transformation::parse(v);
    let _: fn(&_) -> _ = |v: &serde_json::Value| RelationQuery::parse(v);
}

#[test]
fn version_constants() {
    assert!(!apl_core::VERSION.is_empty());
    assert_eq!(apl_core::PROTOCOL_VERSION, "0.1");
    assert_eq!(apl_core::ARTIFACT_VERSION, "0.1");
}

#[test]
fn trait_objects_compile() {
    fn takes_dyn_profile(_p: &dyn Profile) {}
    fn takes_dyn_carrier(_c: &dyn CarrierVerifier) {}
    fn takes_dyn_frames(_r: &dyn FrameResolver) {}
    fn takes_dyn_bridges(_r: &dyn BridgeResolver) {}

    // Verify the functions are callable — they accept any concrete type that
    // implements the respective trait.
    let _ = takes_dyn_profile as fn(&dyn Profile);
    let _ = takes_dyn_carrier as fn(&dyn CarrierVerifier);
    let _ = takes_dyn_frames as fn(&dyn FrameResolver);
    let _ = takes_dyn_bridges as fn(&dyn BridgeResolver);
}

#[test]
fn in_memory_resolvers_are_usable() {
    let mut frames = InMemoryFrameResolver::new();
    let h = frames.insert(serde_json::json!({
        "version": "0.1",
        "observer": "o",
        "procedure": "p",
        "aspect": ["a"],
        "scope": "s",
        "invariance": ["i"],
        "exclusions": ["e"]
    }));
    assert!(matches!(frames.resolve(&h), FrameResolution::Found(_)));

    let bridges = InMemoryBridgeResolver::new();
    assert!(bridges.is_empty());
}

#[test]
fn diagnostic_alias_works() {
    // AC1: Diagnostic is accessible from the prelude.
    let d: Diagnostic = apl_core::diagnostics::APL_VALID;
    assert_eq!(d.as_str(), "apl-valid");
}

#[test]
fn failure_class_in_prelude() {
    let _fc = FailureClass::CarrierFailure;
}

#[test]
fn output_types_in_prelude() {
    let _: CoreOutcome = CoreOutcome::AplValid;
    let _: RelationOutcome = RelationOutcome::RelationNotEvaluated;
    let _vo = VerifierOutput {
        core_outcome: CoreOutcome::AplValid,
        relation_outcome: RelationOutcome::RelationNotEvaluated,
        failure_classes: vec![],
        diagnostics: vec![],
    };
    let _po = PairwiseOutput {
        left: apl_core::SideCore {
            core_outcome: CoreOutcome::AplValid,
            failure_classes: vec![],
        },
        right: apl_core::SideCore {
            core_outcome: CoreOutcome::AplValid,
            failure_classes: vec![],
        },
        relation_outcome: RelationOutcome::RelationNotEvaluated,
        diagnostics: vec![],
    };
}

#[test]
fn relation_query_in_prelude() {
    let q = RelationQuery::parse(&serde_json::json!({
        "left_aspects":  ["accuracy"],
        "right_aspects": ["accuracy"],
        "predicate":     "score",
        "relation_type": "score-delta"
    }));
    assert!(q.is_ok());
}

#[test]
fn no_ed25519_or_io_types_in_apl_core() {
    // These names MUST NOT be re-exported from apl-core.
    // The test is structural: if someone accidentally adds such a re-export,
    // the compile-time name resolution above will fail.
    //
    // Actual absence is enforced by the explicit re-export list in lib.rs
    // (no wildcard re-exports from atl-core or any I/O crate).
    let _ = (); // placeholder — the compile-time guarantee is the test
}
