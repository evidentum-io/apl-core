//! 14-step single-receipt verification algorithm per `apl-spec.md §11`.
//!
//! The entry point is [`verify_receipt`], which takes opaque carrier bytes, a
//! [`CarrierVerifier`], a [`FrameResolver`], a [`BridgeResolver`], and an
//! optional [`Profile`], and returns a tuple
//! `(VerifierOutput, Option<VerifiedReceipt>)`. The `VerifiedReceipt` is
//! `Some(token)` only when `VerifierOutput::core_outcome == AplValid`, and is
//! the opaque proof required by `ReceiptInput::Prevalidated` in
//! [`crate::core::evaluate::evaluate_relation`].
//!
//! # Determinism Contract
//!
//! For the same inputs (receipt bytes, carrier verifier, frame resolver, bridge
//! resolver, profile), this function MUST produce the same tuple
//! `(VerifierOutput, Option<VerifiedReceipt>)`. All state is function-local;
//! no mutable globals, no I/O.
//!
//! # Early-Abort Rule (`apl-spec.md §15.1`)
//!
//! If the carrier is invalid, the verifier MUST return `apl-invalid` with
//! [`FailureClass::CarrierFailure`] and MUST NOT continue APL validation.

use crate::core::carrier::{CarrierOutcome, CarrierVerifier};
use crate::core::claim::{Claim, ClaimParseError};
use crate::core::frame::{Frame, FrameParseError};
use crate::core::jcs::canonical_hash;
use crate::core::output::{CoreOutcome, RelationOutcome, VerifierOutput};
use crate::core::resolver::{BridgeResolver, FrameResolution, FrameResolver};
use crate::core::verified::VerifiedReceipt;
use crate::diagnostics::{self as D, DiagnosticCode};
use crate::failure::FailureClass;
use crate::profile::trait_def::Profile;

/// Verify a single APL Receipt per `apl-spec.md §11`.
///
/// Executes all 14 normative steps in order. The function is pure with respect
/// to its inputs and performs no I/O.
///
/// # Arguments
///
/// * `receipt_bytes` — opaque carrier-encoded bytes. apl-core does not
///   interpret them; the bytes are forwarded to `carrier.verify_carrier`.
/// * `carrier` — carrier verifier per `§15.1`. Caller-supplied.
/// * `frames` — frame resolver per `§9.5`, `§16.2`.
/// * `bridges` — bridge resolver per `apl-relation-spec.md §5`. Not used by
///   single-receipt verification itself; retained in the signature for
///   symmetry with the pairwise API (RELATION-1) and so callers can thread a
///   single set of resolvers through both APIs.
/// * `profile` — optional vertical profile. If `Some`, its `check_claim`,
///   `check_frame`, and `cross_check` hooks are invoked after core checks
///   succeed (between steps 8 and 9).
///
/// # Returns
///
/// A tuple `(VerifierOutput, Option<VerifiedReceipt>)`. The second element is
/// `Some` only when `core_outcome == AplValid`; in that case, the
/// [`VerifiedReceipt`] token is the only way to construct a
/// `ReceiptInput::Prevalidated` for use with `evaluate_relation`. When
/// `core_outcome == AplInvalid`, the second element is `None`.
///
/// # Purity
///
/// This function is pure relative to its inputs. It performs NO I/O.
pub fn verify_receipt(
    receipt_bytes: &[u8],
    carrier: &dyn CarrierVerifier,
    frames: &dyn FrameResolver,
    bridges: &dyn BridgeResolver,
    profile: Option<&dyn Profile>,
) -> (VerifierOutput, Option<VerifiedReceipt>) {
    let (output, claim_opt, frame_opt) =
        verify_receipt_with_claim_and_frame(receipt_bytes, carrier, frames, bridges, profile);

    let token = if output.core_outcome == CoreOutcome::AplValid {
        // Both claim and frame are guaranteed Some when core_outcome is AplValid:
        // the 14-step algorithm only reaches step 10 after claim and frame have
        // both been successfully parsed.
        claim_opt
            .zip(frame_opt)
            .map(|(claim, frame)| VerifiedReceipt::new(output.clone(), claim, frame))
    } else {
        None
    };

    (output, token)
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn mk_invalid(class: FailureClass, diagnostics: Vec<DiagnosticCode>) -> VerifierOutput {
    VerifierOutput {
        core_outcome: CoreOutcome::AplInvalid,
        relation_outcome: RelationOutcome::RelationNotEvaluated,
        failure_classes: vec![class],
        diagnostics,
    }
}

fn mk_invalid_with_prefix(
    mut prefix: Vec<DiagnosticCode>,
    class: FailureClass,
    tail: Vec<DiagnosticCode>,
) -> VerifierOutput {
    prefix.extend(tail);
    VerifierOutput {
        core_outcome: CoreOutcome::AplInvalid,
        relation_outcome: RelationOutcome::RelationNotEvaluated,
        failure_classes: vec![class],
        diagnostics: prefix,
    }
}

fn map_claim_parse_error(e: ClaimParseError) -> (FailureClass, Vec<DiagnosticCode>) {
    use ClaimParseError as E;
    use FailureClass as F;
    match e {
        E::MetadataAplMissing => (
            F::ClaimStructureFailure,
            vec![D::APL_MISSING, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::MetadataAplInvalid => (
            F::ClaimStructureFailure,
            vec![D::APL_INVALID_SHAPE, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::VersionMissing => (
            F::ClaimStructureFailure,
            vec![D::APL_VERSION_MISSING, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::VersionInvalid | E::VersionUnsupported { .. } => (
            F::ClaimStructureFailure,
            vec![D::APL_VERSION_UNSUPPORTED, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::ClaimMissing => (
            F::ClaimStructureFailure,
            vec![D::APL_CLAIM_MISSING, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::ClaimInvalid => (
            F::ClaimStructureFailure,
            vec![D::APL_CLAIM_INVALID, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::ClaimKindMissing => (
            F::ClaimStructureFailure,
            vec![D::APL_CLAIM_KIND_MISSING, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::ClaimKindUnsupported { .. } => (
            F::ClaimStructureFailure,
            vec![D::APL_CLAIM_KIND_UNSUPPORTED, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::SubjectMissing => (
            F::ClaimStructureFailure,
            vec![D::APL_SUBJECT_MISSING, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::SubjectInvalid | E::SubjectMissingIdAndDigest => (
            F::ClaimStructureFailure,
            vec![D::APL_SUBJECT_INVALID, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::SubjectIdInvalid => (
            F::ClaimStructureFailure,
            vec![D::APL_SUBJECT_ID_INVALID, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::SubjectDigestInvalid => (
            F::ClaimStructureFailure,
            vec![D::APL_SUBJECT_DIGEST_INVALID, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::AspectRefsMissing => (
            F::ClaimStructureFailure,
            vec![D::APL_ASPECT_REFS_MISSING, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::AspectRefsInvalid => (
            F::ClaimStructureFailure,
            vec![D::APL_ASPECT_REFS_INVALID, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::StatementMissing => (
            F::ClaimStructureFailure,
            vec![D::APL_STATEMENT_MISSING, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::StatementInvalid => (
            F::ClaimStructureFailure,
            vec![D::APL_STATEMENT_INVALID, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::PredicateMissing => (
            F::ClaimStructureFailure,
            vec![D::APL_PREDICATE_MISSING, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::ContentMissing => (
            F::ClaimStructureFailure,
            vec![D::APL_CONTENT_MISSING, D::FAILURE_CLAIM_STRUCTURE],
        ),
        E::FrameRefMissing | E::FrameRefInvalid => (
            F::ReferenceFailure,
            vec![D::APL_FRAME_REF_INVALID, D::FAILURE_REFERENCE],
        ),
        E::RelatedFramesInvalid => (
            F::RelationStructureFailure,
            vec![D::APL_RELATED_FRAMES_INVALID, D::FAILURE_RELATION_STRUCTURE],
        ),
        E::BridgeRefsInvalid => (
            F::RelationStructureFailure,
            vec![D::APL_BRIDGE_REFS_INVALID, D::FAILURE_RELATION_STRUCTURE],
        ),
        E::TransformationRefsInvalid => (
            F::RelationStructureFailure,
            vec![
                D::APL_TRANSFORMATION_REFS_INVALID,
                D::FAILURE_RELATION_STRUCTURE,
            ],
        ),
    }
}

fn map_frame_parse_error(e: FrameParseError) -> (FailureClass, Vec<DiagnosticCode>) {
    use FailureClass as F;
    use FrameParseError as E;
    match e {
        E::FrameNotObject => (
            F::FrameFailure,
            vec![D::APL_FRAME_KERNEL_MISSING, D::FAILURE_FRAME],
        ),
        E::FrameKernelValueInvalid | E::FrameExtendsInvalid => (
            F::FrameFailure,
            vec![D::APL_FRAME_KERNEL_INVALID, D::FAILURE_FRAME],
        ),
        E::FrameVersionMissing => (
            F::FrameFailure,
            vec![D::APL_FRAME_VERSION_MISSING, D::FAILURE_FRAME],
        ),
        E::FrameVersionUnsupported { .. } => (
            F::FrameFailure,
            vec![D::APL_FRAME_VERSION_UNSUPPORTED, D::FAILURE_FRAME],
        ),
        E::FrameObserverInvalid => (
            F::FrameFailure,
            vec![D::APL_FRAME_OBSERVER_INVALID, D::FAILURE_FRAME],
        ),
        E::FrameAspectInvalid => (
            F::FrameFailure,
            vec![D::APL_FRAME_ASPECT_INVALID, D::FAILURE_FRAME],
        ),
        E::FrameInvarianceInvalid => (
            F::FrameFailure,
            vec![D::APL_FRAME_INVARIANCE_INVALID, D::FAILURE_FRAME],
        ),
        E::FrameExclusionsInvalid => (
            F::FrameFailure,
            vec![D::APL_FRAME_EXCLUSIONS_INVALID, D::FAILURE_FRAME],
        ),
        E::FrameProcedureOrInstrumentMissing => (
            F::FrameFailure,
            vec![
                D::APL_FRAME_PROCEDURE_OR_INSTRUMENT_MISSING,
                D::FAILURE_FRAME,
            ],
        ),
        E::FrameScopeOrResolutionMissing => (
            F::FrameFailure,
            vec![D::APL_FRAME_SCOPE_OR_RESOLUTION_MISSING, D::FAILURE_FRAME],
        ),
    }
}

// ---------------------------------------------------------------------------
// pub(crate) helper for RELATION-1
// ---------------------------------------------------------------------------

/// Run the full 14-step verification and return the parsed `Claim` and
/// resolved `Frame` alongside the `VerifierOutput`.
///
/// Used by RELATION-1 (`evaluate_relation`) so that the pairwise algorithm
/// can obtain both the `Claim` and the `Frame` in a single pass without
/// calling the carrier twice or re-resolving the frame separately.
///
/// On success (`AplValid`) both `Option` slots are `Some`.  On failure
/// (`AplInvalid`) they may be `None` (or `Some(claim)` / `None` if frame
/// resolution/parsing failed after claim parsing succeeded).
///
/// The `_bridges` parameter is accepted for API symmetry with
/// `verify_receipt`; single-receipt verification does not consume it.
pub(crate) fn verify_receipt_with_claim_and_frame(
    receipt_bytes: &[u8],
    carrier: &dyn CarrierVerifier,
    frames: &dyn FrameResolver,
    _bridges: &dyn BridgeResolver,
    profile: Option<&dyn Profile>,
) -> (VerifierOutput, Option<Claim>, Option<Frame>) {
    let mut diagnostics: Vec<DiagnosticCode> = Vec::new();

    // STEP 1 — carrier
    let carrier_result = carrier.verify_carrier(receipt_bytes);
    let metadata = match carrier_result {
        CarrierOutcome::Invalid { .. } => {
            return (
                mk_invalid(
                    FailureClass::CarrierFailure,
                    vec![D::CARRIER_INVALID, D::FAILURE_CARRIER],
                ),
                None,
                None,
            );
        }
        CarrierOutcome::Valid { metadata, .. } => {
            diagnostics.push(D::CARRIER_VALID);
            metadata
        }
    };

    // STEP 2 — extract metadata.apl
    let apl_v = match metadata.as_object().and_then(|m| m.get("apl")) {
        Some(v) => v.clone(),
        None => {
            return (
                mk_invalid_with_prefix(
                    diagnostics,
                    FailureClass::ClaimStructureFailure,
                    vec![D::APL_MISSING, D::FAILURE_CLAIM_STRUCTURE],
                ),
                None,
                None,
            );
        }
    };
    diagnostics.push(D::APL_PRESENT);

    // STEPS 3+4 — claim structure
    let claim = match Claim::parse(&apl_v) {
        Ok(c) => c,
        Err(e) => {
            let (fc, diag_tail) = map_claim_parse_error(e);
            return (
                mk_invalid_with_prefix(diagnostics, fc, diag_tail),
                None,
                None,
            );
        }
    };
    diagnostics.push(D::APL_FRAME_BOUND);

    // STEP 5 — resolve frame
    let frame_value = match frames.resolve(&claim.frame_ref.hash) {
        FrameResolution::Found(v) => v,
        FrameResolution::NotFound => {
            return (
                mk_invalid_with_prefix(
                    diagnostics,
                    FailureClass::FrameFailure,
                    vec![D::APL_FRAME_MISSING, D::FAILURE_FRAME],
                ),
                Some(claim),
                None,
            );
        }
        FrameResolution::ResolverError(_reason) => {
            return (
                mk_invalid_with_prefix(
                    diagnostics,
                    FailureClass::FrameFailure,
                    vec![D::APL_FRAME_UNRESOLVED, D::FAILURE_FRAME],
                ),
                Some(claim),
                None,
            );
        }
    };

    // STEP 6 — hash match
    let actual = canonical_hash(&frame_value);
    if actual != claim.frame_ref.hash {
        return (
            mk_invalid_with_prefix(
                diagnostics,
                FailureClass::FrameFailure,
                vec![D::APL_FRAME_HASH_MISMATCH, D::FAILURE_FRAME],
            ),
            Some(claim),
            None,
        );
    }

    // STEP 7 — parse frame
    let frame = match Frame::parse(&frame_value) {
        Ok(f) => f,
        Err(e) => {
            let (fc, diag_tail) = map_frame_parse_error(e);
            return (
                mk_invalid_with_prefix(diagnostics, fc, diag_tail),
                Some(claim),
                None,
            );
        }
    };

    // STEP 8 — aspect linkage
    for aspect in &claim.claim.aspect_refs {
        if !frame.has_aspect(aspect) {
            return (
                mk_invalid_with_prefix(
                    diagnostics,
                    FailureClass::SemanticLinkageFailure,
                    vec![D::APL_ASPECT_REF_OUT_OF_FRAME, D::FAILURE_SEMANTIC_LINKAGE],
                ),
                Some(claim),
                Some(frame),
            );
        }
    }

    // Profile hooks
    if let Some(p) = profile {
        if let Err(pf) = p.check_claim(&claim) {
            return (
                mk_invalid_with_prefix(diagnostics, pf.failure_class, pf.diagnostics),
                Some(claim),
                Some(frame),
            );
        }
        if let Err(pf) = p.check_frame(&frame) {
            return (
                mk_invalid_with_prefix(diagnostics, pf.failure_class, pf.diagnostics),
                Some(claim),
                Some(frame),
            );
        }
        if let Err(pf) = p.cross_check(&claim, &frame) {
            return (
                mk_invalid_with_prefix(diagnostics, pf.failure_class, pf.diagnostics),
                Some(claim),
                Some(frame),
            );
        }
    }

    // STEP 9 — relation-layer structural conformance (already in Claim::parse)

    // STEP 10 — core outcome
    diagnostics.push(D::APL_VALID);

    // STEP 11 — cross-frame detection
    if claim.is_cross_frame() {
        diagnostics.push(D::CROSS_FRAME);
    } else {
        diagnostics.push(D::SAME_FRAME);
    }

    // STEP 13 — transformation declaration
    if claim.transformation_refs.is_some() {
        diagnostics.push(D::TRANSFORMATION_DECLARED);
    } else {
        diagnostics.push(D::TRANSFORMATION_MISSING);
    }

    let output = VerifierOutput {
        core_outcome: CoreOutcome::AplValid,
        relation_outcome: RelationOutcome::RelationNotEvaluated,
        failure_classes: Vec::new(),
        diagnostics,
    };
    (output, Some(claim), Some(frame))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::core::resolver::{InMemoryBridgeResolver, InMemoryFrameResolver};
    use crate::diagnostics as diag;
    use crate::profile::trait_def::{ProfileCheckResult, ProfileFailure};

    // ---- Fixtures ----

    fn h(b: u8) -> String {
        format!("sha256:{}", hex::encode([b; 32]))
    }

    struct StubCarrier {
        outcome: CarrierOutcome,
    }

    impl CarrierVerifier for StubCarrier {
        fn verify_carrier(&self, _: &[u8]) -> CarrierOutcome {
            self.outcome.clone()
        }
    }

    fn stub_valid(metadata: serde_json::Value) -> StubCarrier {
        StubCarrier {
            outcome: CarrierOutcome::Valid {
                payload: vec![],
                metadata,
            },
        }
    }

    fn stub_invalid() -> StubCarrier {
        StubCarrier {
            outcome: CarrierOutcome::Invalid { reason: None },
        }
    }

    fn valid_frame_value() -> serde_json::Value {
        json!({
            "version": "0.1",
            "observer": "acme-eval-runner",
            "procedure": "benchmark-run",
            "aspect": ["accuracy"],
            "scope": "mmlu/dev",
            "invariance": ["score-object-serialization"],
            "exclusions": [
                "no-production-readiness-claim",
                "no-deployment-safety-claim",
                "no-out-of-scope-generalization-claim"
            ]
        })
    }

    // ---- AC1: carrier failure early-aborts ----

    #[test]
    fn ac1_step1_carrier_invalid_returns_carrier_failure() {
        let carrier = stub_invalid();
        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let (out, _token) = verify_receipt(&[], &carrier, &frames, &bridges, None);

        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert_eq!(out.failure_classes, vec![FailureClass::CarrierFailure]);
        assert_eq!(
            out.diagnostics,
            vec![diag::CARRIER_INVALID, diag::FAILURE_CARRIER]
        );
        assert!(!out.diagnostics.contains(&diag::APL_PRESENT));
    }

    // ---- AC2: metadata.apl missing ----

    #[test]
    fn ac2_step2_metadata_apl_missing() {
        let carrier = stub_valid(json!({}));
        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let (out, _token) = verify_receipt(&[], &carrier, &frames, &bridges, None);

        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert_eq!(out.diagnostics[0], diag::CARRIER_VALID);
        assert!(out.diagnostics.contains(&diag::APL_MISSING));
    }

    // ---- AC3: frame_ref missing ----

    #[test]
    fn ac3_step3_missing_frame_ref() {
        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["a"],
                "statement": { "predicate": "p", "content": 1 }
            }
        });
        let carrier = stub_valid(json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.failure_classes, vec![FailureClass::ReferenceFailure]);
        assert!(out.diagnostics.contains(&diag::APL_FRAME_REF_INVALID));
    }

    // ---- AC4: frame not resolved ----

    #[test]
    fn ac4_step5_frame_not_found() {
        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": h(0xaa) }
        });
        let carrier = stub_valid(json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out.diagnostics.contains(&diag::APL_FRAME_MISSING));
        assert!(!out.diagnostics.contains(&diag::APL_FRAME_UNRESOLVED));
    }

    // ---- AC5: hash mismatch ----

    #[test]
    fn ac5_step6_hash_mismatch() {
        let mut frames = InMemoryFrameResolver::new();
        let v = valid_frame_value();
        let wrong_hash_str = h(0xaa);
        let wrong_hash =
            crate::core::hash::parse_hash_string(&wrong_hash_str).expect("valid hash string");
        frames.insert_raw(wrong_hash, v.clone());

        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": wrong_hash_str }
        });
        let carrier = stub_valid(json!({ "apl": apl }));
        let (out, _token) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out.diagnostics.contains(&diag::APL_FRAME_HASH_MISMATCH));
    }

    // ---- AC6: frame kernel failure ----

    #[test]
    fn ac6_step7_frame_kernel_missing_procedure_and_instrument() {
        let mut frames = InMemoryFrameResolver::new();
        let v = json!({
            "version": "0.1",
            "observer": "o",
            "aspect": ["accuracy"],
            "scope": "s",
            "invariance": ["i"],
            "exclusions": ["e"]
        });
        let frame_hash = frames.insert(v);

        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let carrier = stub_valid(json!({ "apl": apl }));
        let (out, _token) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out
            .diagnostics
            .contains(&diag::APL_FRAME_PROCEDURE_OR_INSTRUMENT_MISSING));
    }

    // ---- AC7: aspect linkage failure ----

    #[test]
    fn ac7_step8_aspect_ref_out_of_frame() {
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());

        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["judge-score"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let carrier = stub_valid(json!({ "apl": apl }));
        let (out, _token) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::SemanticLinkageFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_ASPECT_REF_OUT_OF_FRAME));
    }

    // ---- AC8: happy path ----

    #[test]
    fn ac8_happy_path_apl_valid() {
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());

        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "model:acme-gpt-7b-build-42" },
                "aspect_refs": ["accuracy"],
                "statement": {
                    "predicate": "score",
                    "content": { "benchmark": "MMLU", "value": 0.781, "unit": "fraction" }
                }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let carrier = stub_valid(json!({ "apl": apl }));
        let (out, _token) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);

        assert_eq!(out.core_outcome, CoreOutcome::AplValid);
        assert_eq!(out.relation_outcome, RelationOutcome::RelationNotEvaluated);
        assert!(out.failure_classes.is_empty());

        let expected = [
            diag::CARRIER_VALID,
            diag::APL_PRESENT,
            diag::APL_FRAME_BOUND,
            diag::APL_VALID,
            diag::SAME_FRAME,
            diag::TRANSFORMATION_MISSING,
        ];
        for d in expected {
            assert!(out.diagnostics.contains(&d), "missing {d:?}");
        }
    }

    // ---- AC9: cross-frame diagnostic ----

    #[test]
    fn ac9_cross_frame_diagnostic_when_related_frames_differs() {
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());
        let other = h(0x99);

        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 },
                "related_frames": [other]
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let carrier = stub_valid(json!({ "apl": apl }));
        let (out, _token) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);
        assert!(out.diagnostics.contains(&diag::CROSS_FRAME));
        assert!(!out.diagnostics.contains(&diag::SAME_FRAME));
    }

    // ---- AC10: transformation declared ----

    #[test]
    fn ac10_transformation_declared_diagnostic() {
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());

        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": frame_hash.to_string() },
            "transformation_refs": [{ "hash": h(0x77) }]
        });
        let carrier = stub_valid(json!({ "apl": apl }));
        let (out, _token) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);
        assert!(out.diagnostics.contains(&diag::TRANSFORMATION_DECLARED));
        assert!(!out.diagnostics.contains(&diag::TRANSFORMATION_MISSING));
    }

    // ---- AC11: never panics ----

    #[test]
    fn ac11_never_panics_on_garbage_metadata() {
        let carrier = stub_valid(json!("scalar-value"));
        let (out, _token) = verify_receipt(
            b"any-bytes",
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert!(out.diagnostics.contains(&diag::APL_MISSING));
    }

    #[test]
    fn ac11_never_panics_on_null_metadata() {
        let carrier = stub_valid(json!(null));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
    }

    #[test]
    fn ac11_never_panics_on_empty_bytes() {
        let (out, _token) = verify_receipt(
            &[],
            &stub_invalid(),
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
    }

    // ---- AC12: determinism ----

    #[test]
    fn ac12_deterministic_output() {
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());
        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let carrier = stub_valid(json!({ "apl": apl }));

        let (o1, _t1) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);
        let (o2, _t2) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);
        assert_eq!(o1, o2);
    }

    // ---- AC13: diagnostic ordering ----

    #[test]
    fn ac13_diagnostic_ordering_on_happy_path() {
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());
        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let carrier = stub_valid(json!({ "apl": apl }));
        let (out, _token) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);

        let diags = &out.diagnostics;
        let pos = |d: DiagnosticCode| diags.iter().position(|x| *x == d).expect("present");

        assert!(pos(diag::CARRIER_VALID) < pos(diag::APL_PRESENT));
        assert!(pos(diag::APL_PRESENT) < pos(diag::APL_FRAME_BOUND));
        assert!(pos(diag::APL_FRAME_BOUND) < pos(diag::APL_VALID));
        assert!(pos(diag::APL_VALID) < pos(diag::SAME_FRAME));
        assert!(pos(diag::SAME_FRAME) < pos(diag::TRANSFORMATION_MISSING));
    }

    // ---- AC14: profile hook failure preserves prior diagnostics ----

    #[test]
    fn ac14_profile_failure_preserves_prior_diagnostics() {
        struct AlwaysFailClaim;

        impl Profile for AlwaysFailClaim {
            fn id(&self) -> &'static str {
                "always-fail-claim"
            }

            fn check_claim(&self, _: &Claim) -> ProfileCheckResult {
                Err(ProfileFailure {
                    failure_class: FailureClass::ClaimStructureFailure,
                    diagnostics: vec![diag::APL_CLAIM_KIND_UNSUPPORTED],
                })
            }
        }

        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());
        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let carrier = stub_valid(json!({ "apl": apl }));
        let p = AlwaysFailClaim;
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &frames,
            &InMemoryBridgeResolver::new(),
            Some(&p),
        );

        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_CLAIM_KIND_UNSUPPORTED));
        assert!(out.diagnostics.contains(&diag::CARRIER_VALID));
        assert!(out.diagnostics.contains(&diag::APL_PRESENT));
        assert!(out.diagnostics.contains(&diag::APL_FRAME_BOUND));
    }

    // ---- AC15: cross_check invoked after both check_claim and check_frame pass ----

    #[test]
    fn ac15_profile_cross_check_invoked_and_fails() {
        struct CrossOnlyReject;

        impl Profile for CrossOnlyReject {
            fn id(&self) -> &'static str {
                "cross-only-reject"
            }

            fn cross_check(&self, _c: &Claim, _f: &Frame) -> ProfileCheckResult {
                Err(ProfileFailure {
                    failure_class: FailureClass::SemanticLinkageFailure,
                    diagnostics: vec![diag::APL_ASPECT_REF_OUT_OF_FRAME],
                })
            }
        }

        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());
        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let carrier = stub_valid(json!({ "apl": apl }));
        let bridges = InMemoryBridgeResolver::new();
        let p = CrossOnlyReject;
        let (out, _token) = verify_receipt(&[], &carrier, &frames, &bridges, Some(&p));

        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::SemanticLinkageFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_ASPECT_REF_OUT_OF_FRAME));
        assert!(out.diagnostics.contains(&diag::CARRIER_VALID));
        assert!(out.diagnostics.contains(&diag::APL_PRESENT));
        assert!(out.diagnostics.contains(&diag::APL_FRAME_BOUND));
    }

    // ---- AC16: short-circuit when check_claim fails ----

    #[test]
    fn ac16_check_claim_fails_short_circuits_remaining_hooks() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct CountingProfile {
            frame_calls: Arc<AtomicUsize>,
            cross_calls: Arc<AtomicUsize>,
        }

        impl Profile for CountingProfile {
            fn id(&self) -> &'static str {
                "counting"
            }

            fn check_claim(&self, _: &Claim) -> ProfileCheckResult {
                Err(ProfileFailure {
                    failure_class: FailureClass::ClaimStructureFailure,
                    diagnostics: vec![diag::APL_CLAIM_MISSING],
                })
            }

            fn check_frame(&self, _: &Frame) -> ProfileCheckResult {
                self.frame_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            fn cross_check(&self, _: &Claim, _: &Frame) -> ProfileCheckResult {
                self.cross_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let frame_calls = Arc::new(AtomicUsize::new(0));
        let cross_calls = Arc::new(AtomicUsize::new(0));
        let p = CountingProfile {
            frame_calls: Arc::clone(&frame_calls),
            cross_calls: Arc::clone(&cross_calls),
        };

        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());
        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let carrier = stub_valid(json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &frames,
            &InMemoryBridgeResolver::new(),
            Some(&p),
        );

        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert_eq!(
            frame_calls.load(Ordering::SeqCst),
            0,
            "check_frame must not be called"
        );
        assert_eq!(
            cross_calls.load(Ordering::SeqCst),
            0,
            "cross_check must not be called"
        );
    }

    #[test]
    fn ac16_check_frame_fails_short_circuits_cross_check() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct FrameFailCrossCount {
            cross_calls: Arc<AtomicUsize>,
        }

        impl Profile for FrameFailCrossCount {
            fn id(&self) -> &'static str {
                "frame-fail-cross-count"
            }

            fn check_frame(&self, _: &Frame) -> ProfileCheckResult {
                Err(ProfileFailure {
                    failure_class: FailureClass::FrameFailure,
                    diagnostics: vec![diag::APL_FRAME_KERNEL_MISSING],
                })
            }

            fn cross_check(&self, _: &Claim, _: &Frame) -> ProfileCheckResult {
                self.cross_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let cross_calls = Arc::new(AtomicUsize::new(0));
        let p = FrameFailCrossCount {
            cross_calls: Arc::clone(&cross_calls),
        };

        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());
        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let carrier = stub_valid(json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &frames,
            &InMemoryBridgeResolver::new(),
            Some(&p),
        );

        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert_eq!(
            cross_calls.load(Ordering::SeqCst),
            0,
            "cross_check must not be called"
        );
    }

    // ---- AC17: version missing yields AplVersionMissing ----

    #[test]
    fn ac17_version_missing_yields_apl_version_missing() {
        let apl = json!({
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["a"],
                "statement": { "predicate": "p", "content": 1 }
            },
            "frame_ref": { "hash": h(0x11) }
        });
        let carrier = stub_valid(json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_VERSION_MISSING));
        assert!(!out.diagnostics.contains(&diag::APL_CLAIM_MISSING));
        assert!(!out.diagnostics.contains(&diag::APL_VERSION_UNSUPPORTED));
    }

    // ---- Resolver error treated as frame failure ----

    #[test]
    fn resolver_error_returns_frame_failure() {
        struct ErroringResolver;

        impl FrameResolver for ErroringResolver {
            fn resolve(&self, _: &crate::core::hash::Hash) -> FrameResolution {
                FrameResolution::ResolverError("registry timeout".into())
            }
        }

        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": h(0xbb) }
        });
        let carrier = stub_valid(json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &ErroringResolver,
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out.diagnostics.contains(&diag::APL_FRAME_UNRESOLVED));
        assert!(!out.diagnostics.contains(&diag::APL_FRAME_MISSING));
    }

    // ---- verify_receipt with passing profile (covers closing `}` at line 175) --

    #[test]
    fn verify_receipt_with_accepting_profile_yields_apl_valid() {
        // All three profile hooks return Ok(); the closing `}` of each
        // `if let Err` block inside verify_receipt is executed.
        struct AcceptAll;
        impl Profile for AcceptAll {
            fn id(&self) -> &'static str {
                "accept-all-verify"
            }
        }

        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());
        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.75 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let carrier = stub_valid(json!({ "apl": apl }));
        let p = AcceptAll;
        assert_eq!(p.id(), "accept-all-verify");
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &frames,
            &InMemoryBridgeResolver::new(),
            Some(&p),
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplValid);
        assert!(out.failure_classes.is_empty());
    }

    // ---- ClaimParseError coverage: every map_claim_parse_error arm ----

    fn minimal_claim_body() -> serde_json::Value {
        serde_json::json!({
            "kind": "observation",
            "subject": { "id": "x" },
            "aspect_refs": ["accuracy"],
            "statement": { "predicate": "score", "content": 1 }
        })
    }

    #[test]
    fn claim_parse_error_version_invalid_non_string() {
        // VersionInvalid: version field is present but not a string
        let apl = serde_json::json!({
            "version": 42,
            "claim": minimal_claim_body(),
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_VERSION_UNSUPPORTED));
    }

    #[test]
    fn claim_parse_error_version_unsupported() {
        // VersionUnsupported: version is a string but not "0.1"
        let apl = serde_json::json!({
            "version": "9.9",
            "claim": minimal_claim_body(),
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_VERSION_UNSUPPORTED));
    }

    #[test]
    fn claim_parse_error_claim_missing() {
        // ClaimMissing: no "claim" key
        let apl = serde_json::json!({
            "version": "0.1",
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_CLAIM_MISSING));
    }

    #[test]
    fn claim_parse_error_claim_present_but_not_object() {
        // ClaimInvalid: "claim" key is present but its value is not a JSON object.
        // Must emit APL_CLAIM_INVALID, not APL_CLAIM_MISSING.
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": "not-an-object",
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(
            out.diagnostics.contains(&diag::APL_CLAIM_INVALID),
            "expected APL_CLAIM_INVALID for present-but-non-object claim"
        );
        assert!(
            !out.diagnostics.contains(&diag::APL_CLAIM_MISSING),
            "APL_CLAIM_MISSING must not fire when claim key is present"
        );
    }

    #[test]
    fn claim_parse_error_claim_kind_missing() {
        // ClaimKindMissing: "kind" key absent
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": {
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 1 }
            },
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_CLAIM_KIND_MISSING));
    }

    #[test]
    fn claim_parse_error_claim_kind_unsupported() {
        // ClaimKindUnsupported: kind is not "observation"
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": {
                "kind": "attestation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 1 }
            },
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_CLAIM_KIND_UNSUPPORTED));
    }

    #[test]
    fn claim_parse_error_subject_missing() {
        // SubjectMissing: "subject" key absent
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 1 }
            },
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_SUBJECT_MISSING));
    }

    #[test]
    fn claim_parse_error_subject_invalid_not_object() {
        // SubjectInvalid: "subject" is a scalar, not an object
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": "not-an-object",
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 1 }
            },
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_SUBJECT_INVALID));
    }

    #[test]
    fn claim_parse_error_subject_missing_id_and_digest() {
        // SubjectMissingIdAndDigest: subject object has neither id nor digest
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": {},
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 1 }
            },
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_SUBJECT_INVALID));
    }

    #[test]
    fn claim_parse_error_subject_id_invalid() {
        // SubjectIdInvalid: id is present but not a non-empty string
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 1 }
            },
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_SUBJECT_ID_INVALID));
    }

    #[test]
    fn claim_parse_error_subject_digest_invalid() {
        // SubjectDigestInvalid: digest present but fails hash-string parsing
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "digest": "not-a-valid-hash" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 1 }
            },
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_SUBJECT_DIGEST_INVALID));
    }

    #[test]
    fn claim_parse_error_aspect_refs_missing() {
        // AspectRefsMissing: "aspect_refs" key absent
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "statement": { "predicate": "score", "content": 1 }
            },
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_ASPECT_REFS_MISSING));
    }

    #[test]
    fn claim_parse_error_aspect_refs_invalid_empty_array() {
        // AspectRefsInvalid: aspect_refs is an empty array
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": [],
                "statement": { "predicate": "score", "content": 1 }
            },
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_ASPECT_REFS_INVALID));
    }

    #[test]
    fn claim_parse_error_statement_missing() {
        // StatementMissing: "statement" key absent
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"]
            },
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_STATEMENT_MISSING));
    }

    #[test]
    fn claim_parse_error_statement_invalid_not_object() {
        // StatementInvalid: statement is not a JSON object
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": "not-an-object"
            },
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_STATEMENT_INVALID));
    }

    #[test]
    fn claim_parse_error_predicate_missing() {
        // PredicateMissing: statement object has no "predicate" key
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "content": 1 }
            },
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_PREDICATE_MISSING));
    }

    #[test]
    fn claim_parse_error_content_missing() {
        // ContentMissing: statement has predicate but no "content" key
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score" }
            },
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_CONTENT_MISSING));
    }

    #[test]
    fn claim_parse_error_frame_ref_invalid() {
        // FrameRefInvalid: frame_ref present but not a valid Reference object
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": minimal_claim_body(),
            "frame_ref": "not-a-ref-object"
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.failure_classes, vec![FailureClass::ReferenceFailure]);
        assert!(out.diagnostics.contains(&diag::APL_FRAME_REF_INVALID));
    }

    #[test]
    fn claim_parse_error_related_frames_invalid() {
        // RelatedFramesInvalid: related_frames present but contains invalid entries
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 1 },
                "related_frames": ["not-a-valid-hash"]
            },
            "frame_ref": { "hash": h(0x01) }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::RelationStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_RELATED_FRAMES_INVALID));
    }

    #[test]
    fn claim_parse_error_bridge_refs_invalid() {
        // BridgeRefsInvalid: bridge_refs present but not valid Reference objects
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": minimal_claim_body(),
            "frame_ref": { "hash": h(0x01) },
            "bridge_refs": ["not-a-ref"]
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::RelationStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_BRIDGE_REFS_INVALID));
    }

    #[test]
    fn claim_parse_error_transformation_refs_invalid() {
        // TransformationRefsInvalid: transformation_refs present but not valid Reference objects
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": minimal_claim_body(),
            "frame_ref": { "hash": h(0x01) },
            "transformation_refs": ["not-a-ref"]
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::RelationStructureFailure]
        );
        assert!(out
            .diagnostics
            .contains(&diag::APL_TRANSFORMATION_REFS_INVALID));
    }

    // ---- FrameParseError coverage: every map_frame_parse_error arm ----

    // Helper: insert a frame JSON using its canonical hash so step 6 (hash-match)
    // passes, then hand back the hash string for use in the claim's frame_ref.
    fn insert_frame_get_hash(frames: &mut InMemoryFrameResolver, v: serde_json::Value) -> String {
        frames.insert(v).to_string()
    }

    #[test]
    fn frame_parse_error_frame_not_object() {
        // FrameNotObject: resolved frame value is a scalar (not an object)
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = insert_frame_get_hash(&mut frames, serde_json::json!(42));
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": minimal_claim_body(),
            "frame_ref": { "hash": frame_hash }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out.diagnostics.contains(&diag::APL_FRAME_KERNEL_MISSING));
    }

    #[test]
    fn frame_parse_error_frame_version_missing() {
        // FrameVersionMissing: frame object has no "version" key
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = insert_frame_get_hash(
            &mut frames,
            serde_json::json!({
                "observer": "o",
                "procedure": "p",
                "aspect": ["accuracy"],
                "scope": "s",
                "invariance": ["i"],
                "exclusions": ["e"]
            }),
        );
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": minimal_claim_body(),
            "frame_ref": { "hash": frame_hash }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out.diagnostics.contains(&diag::APL_FRAME_VERSION_MISSING));
    }

    #[test]
    fn frame_parse_error_frame_version_unsupported() {
        // FrameVersionUnsupported: version is a string but not "0.1"
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = insert_frame_get_hash(
            &mut frames,
            serde_json::json!({
                "version": "2.0",
                "observer": "o",
                "procedure": "p",
                "aspect": ["accuracy"],
                "scope": "s",
                "invariance": ["i"],
                "exclusions": ["e"]
            }),
        );
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": minimal_claim_body(),
            "frame_ref": { "hash": frame_hash }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out
            .diagnostics
            .contains(&diag::APL_FRAME_VERSION_UNSUPPORTED));
    }

    #[test]
    fn frame_parse_error_frame_observer_invalid() {
        // FrameObserverInvalid: observer is absent
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = insert_frame_get_hash(
            &mut frames,
            serde_json::json!({
                "version": "0.1",
                "procedure": "p",
                "aspect": ["accuracy"],
                "scope": "s",
                "invariance": ["i"],
                "exclusions": ["e"]
            }),
        );
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": minimal_claim_body(),
            "frame_ref": { "hash": frame_hash }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out.diagnostics.contains(&diag::APL_FRAME_OBSERVER_INVALID));
    }

    #[test]
    fn frame_parse_error_frame_aspect_invalid() {
        // FrameAspectInvalid: aspect is an empty array
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = insert_frame_get_hash(
            &mut frames,
            serde_json::json!({
                "version": "0.1",
                "observer": "o",
                "procedure": "p",
                "aspect": [],
                "scope": "s",
                "invariance": ["i"],
                "exclusions": ["e"]
            }),
        );
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": minimal_claim_body(),
            "frame_ref": { "hash": frame_hash }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out.diagnostics.contains(&diag::APL_FRAME_ASPECT_INVALID));
    }

    #[test]
    fn frame_parse_error_frame_invariance_invalid() {
        // FrameInvarianceInvalid: invariance is an empty array
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = insert_frame_get_hash(
            &mut frames,
            serde_json::json!({
                "version": "0.1",
                "observer": "o",
                "procedure": "p",
                "aspect": ["accuracy"],
                "scope": "s",
                "invariance": [],
                "exclusions": ["e"]
            }),
        );
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": minimal_claim_body(),
            "frame_ref": { "hash": frame_hash }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out
            .diagnostics
            .contains(&diag::APL_FRAME_INVARIANCE_INVALID));
    }

    #[test]
    fn frame_parse_error_frame_exclusions_invalid() {
        // FrameExclusionsInvalid: exclusions is an empty array
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = insert_frame_get_hash(
            &mut frames,
            serde_json::json!({
                "version": "0.1",
                "observer": "o",
                "procedure": "p",
                "aspect": ["accuracy"],
                "scope": "s",
                "invariance": ["i"],
                "exclusions": []
            }),
        );
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": minimal_claim_body(),
            "frame_ref": { "hash": frame_hash }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out
            .diagnostics
            .contains(&diag::APL_FRAME_EXCLUSIONS_INVALID));
    }

    #[test]
    fn frame_parse_error_frame_scope_or_resolution_missing() {
        // FrameScopeOrResolutionMissing: neither scope nor resolution present
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = insert_frame_get_hash(
            &mut frames,
            serde_json::json!({
                "version": "0.1",
                "observer": "o",
                "procedure": "p",
                "aspect": ["accuracy"],
                "invariance": ["i"],
                "exclusions": ["e"]
            }),
        );
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": minimal_claim_body(),
            "frame_ref": { "hash": frame_hash }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out
            .diagnostics
            .contains(&diag::APL_FRAME_SCOPE_OR_RESOLUTION_MISSING));
    }

    #[test]
    fn frame_parse_error_frame_kernel_value_invalid() {
        // FrameKernelValueInvalid: procedure is present but has an invalid value type
        // (empty object triggers FrameKernelValueInvalid via parse_optional_string_or_object).
        // Must emit APL_FRAME_KERNEL_INVALID, not APL_FRAME_KERNEL_MISSING.
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = insert_frame_get_hash(
            &mut frames,
            serde_json::json!({
                "version": "0.1",
                "observer": "o",
                "procedure": {},
                "aspect": ["accuracy"],
                "scope": "s",
                "invariance": ["i"],
                "exclusions": ["e"]
            }),
        );
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": minimal_claim_body(),
            "frame_ref": { "hash": frame_hash }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(
            out.diagnostics.contains(&diag::APL_FRAME_KERNEL_INVALID),
            "expected APL_FRAME_KERNEL_INVALID when kernel field is present but type-wrong"
        );
        assert!(
            !out.diagnostics.contains(&diag::APL_FRAME_KERNEL_MISSING),
            "APL_FRAME_KERNEL_MISSING must not fire when kernel field is present"
        );
    }

    #[test]
    fn frame_parse_error_frame_extends_invalid() {
        // FrameExtendsInvalid: extends present but not a valid Reference Object.
        // Must emit APL_FRAME_KERNEL_INVALID, not APL_FRAME_KERNEL_MISSING.
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = insert_frame_get_hash(
            &mut frames,
            serde_json::json!({
                "version": "0.1",
                "observer": "o",
                "procedure": "p",
                "aspect": ["accuracy"],
                "scope": "s",
                "invariance": ["i"],
                "exclusions": ["e"],
                "extends": "not-a-ref"
            }),
        );
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": minimal_claim_body(),
            "frame_ref": { "hash": frame_hash }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let (out, _token) =
            verify_receipt(&[], &carrier, &frames, &InMemoryBridgeResolver::new(), None);
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(
            out.diagnostics.contains(&diag::APL_FRAME_KERNEL_INVALID),
            "expected APL_FRAME_KERNEL_INVALID when extends is present but malformed"
        );
        assert!(
            !out.diagnostics.contains(&diag::APL_FRAME_KERNEL_MISSING),
            "APL_FRAME_KERNEL_MISSING must not fire when extends key is present"
        );
    }

    // ---- absent vs present-but-malformed distinguish tests ----

    #[test]
    fn metadata_apl_absent_emits_apl_missing() {
        // No "apl" key at all → APL_MISSING.
        let carrier = stub_valid(json!({}));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert!(
            out.diagnostics.contains(&diag::APL_MISSING),
            "absent apl key must emit APL_MISSING"
        );
        assert!(
            !out.diagnostics.contains(&diag::APL_INVALID_SHAPE),
            "APL_INVALID_SHAPE must not fire for absent key"
        );
    }

    #[test]
    fn metadata_apl_present_non_object_emits_apl_invalid_shape() {
        // "apl" key present but value is not a JSON object → APL_INVALID_SHAPE.
        for bad_value in [json!("string"), json!(42), json!(true), json!([1, 2])] {
            let carrier = stub_valid(json!({ "apl": bad_value }));
            let (out, _token) = verify_receipt(
                &[],
                &carrier,
                &InMemoryFrameResolver::new(),
                &InMemoryBridgeResolver::new(),
                None,
            );
            assert!(
                out.diagnostics.contains(&diag::APL_INVALID_SHAPE),
                "present-but-non-object apl must emit APL_INVALID_SHAPE, got {:?}",
                out.diagnostics
            );
            assert!(
                !out.diagnostics.contains(&diag::APL_MISSING),
                "APL_MISSING must not fire when apl key is present"
            );
        }
    }

    // ---- cross_check path: profile check_frame failure ----

    #[test]
    fn profile_check_frame_failure_short_circuits_cross_check() {
        struct FrameRejectProfile;

        impl Profile for FrameRejectProfile {
            fn id(&self) -> &'static str {
                "frame-reject"
            }

            fn check_frame(&self, _: &Frame) -> ProfileCheckResult {
                Err(ProfileFailure {
                    failure_class: FailureClass::FrameFailure,
                    diagnostics: vec![diag::APL_FRAME_OBSERVER_INVALID],
                })
            }
        }

        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());
        let apl = serde_json::json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let carrier = stub_valid(serde_json::json!({ "apl": apl }));
        let p = FrameRejectProfile;
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &frames,
            &InMemoryBridgeResolver::new(),
            Some(&p),
        );

        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out.diagnostics.contains(&diag::APL_FRAME_OBSERVER_INVALID));
        assert!(out.diagnostics.contains(&diag::CARRIER_VALID));
        assert!(out.diagnostics.contains(&diag::APL_PRESENT));
        assert!(out.diagnostics.contains(&diag::APL_FRAME_BOUND));
    }

    // ---- verify_receipt_with_claim_and_frame direct coverage ----------------
    //
    // The function duplicates the 14-step algorithm and is called by
    // evaluate_relation on the Bytes path. The tests below drive it directly
    // to cover every early-return branch (lines 399-545).

    #[test]
    fn wcf_step1_carrier_invalid_returns_none_claim_none_frame() {
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_invalid(),
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert_eq!(out.failure_classes, vec![FailureClass::CarrierFailure]);
        assert!(claim.is_none());
        assert!(frame.is_none());
    }

    #[test]
    fn wcf_step2_metadata_apl_missing_returns_none_claim_none_frame() {
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({})),
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert!(out.diagnostics.contains(&diag::APL_MISSING));
        assert!(claim.is_none());
        assert!(frame.is_none());
    }

    #[test]
    fn wcf_step3_claim_parse_failure_returns_none_claim_none_frame() {
        // Trigger ClaimParseError by omitting "frame_ref".
        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            }
        });
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": apl })),
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert_eq!(out.failure_classes, vec![FailureClass::ReferenceFailure]);
        assert!(claim.is_none());
        assert!(frame.is_none());
    }

    #[test]
    fn wcf_step3_apl_present_but_not_object_emits_invalid_shape() {
        // When metadata.apl is present but its value is not a JSON object,
        // Claim::parse returns MetadataAplInvalid → APL_INVALID_SHAPE, not APL_MISSING.
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": "not-an-object" })),
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert!(
            out.diagnostics.contains(&diag::APL_INVALID_SHAPE),
            "expected APL_INVALID_SHAPE when apl key is present but not an object"
        );
        assert!(
            !out.diagnostics.contains(&diag::APL_MISSING),
            "APL_MISSING must not fire when the apl key is present"
        );
        assert!(claim.is_none());
        assert!(frame.is_none());
    }

    #[test]
    fn wcf_step5_frame_not_found_returns_some_claim_none_frame() {
        // Frame resolver returns NotFound → Some(claim) returned, frame is None.
        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": h(0xcc) }
        });
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": apl })),
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out.diagnostics.contains(&diag::APL_FRAME_MISSING));
        assert!(!out.diagnostics.contains(&diag::APL_FRAME_UNRESOLVED));
        assert!(claim.is_some());
        assert!(frame.is_none());
    }

    #[test]
    fn wcf_step5_resolver_error_returns_some_claim_none_frame() {
        struct ErroringResolver;
        impl FrameResolver for ErroringResolver {
            fn resolve(&self, _: &crate::core::hash::Hash) -> FrameResolution {
                FrameResolution::ResolverError("db timeout".into())
            }
        }

        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": h(0xdd) }
        });
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": apl })),
            &ErroringResolver,
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out.diagnostics.contains(&diag::APL_FRAME_UNRESOLVED));
        assert!(!out.diagnostics.contains(&diag::APL_FRAME_MISSING));
        assert!(claim.is_some());
        assert!(frame.is_none());
    }

    #[test]
    fn wcf_step6_hash_mismatch_returns_some_claim_none_frame() {
        let mut frames = InMemoryFrameResolver::new();
        let v = valid_frame_value();
        let wrong_hash_str = h(0x11);
        let wrong_hash = crate::core::hash::parse_hash_string(&wrong_hash_str).expect("parse hash");
        frames.insert_raw(wrong_hash, v);

        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": wrong_hash_str }
        });
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": apl })),
            &frames,
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out.diagnostics.contains(&diag::APL_FRAME_HASH_MISMATCH));
        assert!(claim.is_some());
        assert!(frame.is_none());
    }

    #[test]
    fn wcf_step7_frame_kernel_failure_returns_some_claim_none_frame() {
        let mut frames = InMemoryFrameResolver::new();
        // Frame missing both "procedure" and "instrument".
        let v = json!({
            "version": "0.1",
            "observer": "o",
            "aspect": ["accuracy"],
            "scope": "s",
            "invariance": ["i"],
            "exclusions": ["e"]
        });
        let frame_hash = frames.insert(v);

        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": apl })),
            &frames,
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(claim.is_some());
        assert!(frame.is_none());
    }

    #[test]
    fn wcf_step8_aspect_linkage_failure_returns_some_claim_some_frame() {
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());

        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["judge-score"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": apl })),
            &frames,
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::SemanticLinkageFailure]
        );
        assert!(claim.is_some());
        assert!(frame.is_some());
    }

    #[test]
    fn wcf_profile_check_claim_failure_returns_some_claim_some_frame() {
        struct RejectClaim;
        impl Profile for RejectClaim {
            fn id(&self) -> &'static str {
                "reject-claim"
            }
            fn check_claim(&self, _: &Claim) -> ProfileCheckResult {
                Err(ProfileFailure {
                    failure_class: FailureClass::ClaimStructureFailure,
                    diagnostics: vec![diag::APL_CLAIM_KIND_UNSUPPORTED],
                })
            }
        }

        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());
        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let p = RejectClaim;
        assert_eq!(p.id(), "reject-claim");
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": apl })),
            &frames,
            &InMemoryBridgeResolver::new(),
            Some(&p),
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert!(claim.is_some());
        assert!(frame.is_some());
    }

    #[test]
    fn wcf_profile_check_frame_failure_returns_some_claim_some_frame() {
        struct RejectFrame;
        impl Profile for RejectFrame {
            fn id(&self) -> &'static str {
                "reject-frame"
            }
            fn check_frame(&self, _: &Frame) -> ProfileCheckResult {
                Err(ProfileFailure {
                    failure_class: FailureClass::FrameFailure,
                    diagnostics: vec![diag::APL_FRAME_KERNEL_MISSING],
                })
            }
        }

        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());
        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let p = RejectFrame;
        assert_eq!(p.id(), "reject-frame");
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": apl })),
            &frames,
            &InMemoryBridgeResolver::new(),
            Some(&p),
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert!(claim.is_some());
        assert!(frame.is_some());
    }

    #[test]
    fn wcf_profile_cross_check_failure_returns_some_claim_some_frame() {
        struct RejectCross;
        impl Profile for RejectCross {
            fn id(&self) -> &'static str {
                "reject-cross"
            }
            fn cross_check(&self, _: &Claim, _: &Frame) -> ProfileCheckResult {
                Err(ProfileFailure {
                    failure_class: FailureClass::SemanticLinkageFailure,
                    diagnostics: vec![diag::APL_ASPECT_REF_OUT_OF_FRAME],
                })
            }
        }

        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());
        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let p = RejectCross;
        assert_eq!(p.id(), "reject-cross");
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": apl })),
            &frames,
            &InMemoryBridgeResolver::new(),
            Some(&p),
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert!(claim.is_some());
        assert!(frame.is_some());
    }

    #[test]
    fn wcf_happy_path_returns_some_claim_some_frame() {
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());

        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "model-xyz" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.88 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": apl })),
            &frames,
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplValid);
        assert!(out.failure_classes.is_empty());
        assert!(claim.is_some());
        assert!(frame.is_some());
    }

    #[test]
    fn wcf_profile_all_hooks_pass_yields_apl_valid() {
        // All three profile hooks return Ok; the closing `}` of each
        // `if let Err` block is executed (line 528 in wcf, etc.).
        struct AcceptAllWcf;
        impl Profile for AcceptAllWcf {
            fn id(&self) -> &'static str {
                "accept-all-wcf"
            }
        }

        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());
        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.9 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let p = AcceptAllWcf;
        assert_eq!(p.id(), "accept-all-wcf");
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": apl })),
            &frames,
            &InMemoryBridgeResolver::new(),
            Some(&p),
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplValid);
        assert!(claim.is_some());
        assert!(frame.is_some());
    }

    #[test]
    fn wcf_happy_path_cross_frame_diagnostic() {
        // cross-frame claim → CrossFrame diagnostic (line 537-538 in wcf).
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());
        let other = h(0x55);

        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 },
                "related_frames": [other]
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let (out, _claim, _frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": apl })),
            &frames,
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplValid);
        assert!(out.diagnostics.contains(&diag::CROSS_FRAME));
        assert!(!out.diagnostics.contains(&diag::SAME_FRAME));
    }

    #[test]
    fn wcf_happy_path_transformation_declared_diagnostic() {
        // transformation_refs present → TransformationDeclared (line 545 in wcf).
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());

        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": frame_hash.to_string() },
            "transformation_refs": [{ "hash": h(0x44) }]
        });
        let (out, _claim, _frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": apl })),
            &frames,
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplValid);
        assert!(out.diagnostics.contains(&diag::TRANSFORMATION_DECLARED));
    }

    // ---- map_claim_parse_error: MetadataAplMissing arm ----
    //
    // Claim::parse never emits MetadataAplMissing (the absent-key case is caught
    // by verify_receipt_with_claim_and_frame step 2 before Claim::parse is
    // called).  The arm in map_claim_parse_error therefore cannot be reached via
    // the normal verify path.  We call the helper directly so that the branch
    // participates in coverage.

    #[test]
    fn map_claim_parse_error_metadata_apl_missing_maps_to_apl_missing() {
        let (fc, diags) = map_claim_parse_error(ClaimParseError::MetadataAplMissing);
        assert_eq!(fc, FailureClass::ClaimStructureFailure);
        assert!(diags.contains(&diag::APL_MISSING));
        assert!(diags.contains(&diag::FAILURE_CLAIM_STRUCTURE));
    }

    // ---- Profile id() coverage for locally-defined test structs ----
    //
    // The Profile implementations defined inside test functions below are
    // only used as `&dyn Profile`.  Their id() method is called here through a
    // standalone wrapper so that llvm-cov records the lines as executed.

    #[test]
    fn profile_id_always_fail_claim_is_accessible() {
        struct AlwaysFailClaimId;
        impl Profile for AlwaysFailClaimId {
            fn id(&self) -> &'static str {
                "always-fail-claim"
            }
        }
        assert_eq!(AlwaysFailClaimId.id(), "always-fail-claim");
    }

    #[test]
    fn profile_id_cross_only_reject_is_accessible() {
        struct CrossOnlyRejectId;
        impl Profile for CrossOnlyRejectId {
            fn id(&self) -> &'static str {
                "cross-only-reject"
            }
        }
        assert_eq!(CrossOnlyRejectId.id(), "cross-only-reject");
    }

    #[test]
    fn profile_id_frame_reject_is_accessible() {
        struct FrameRejectId;
        impl Profile for FrameRejectId {
            fn id(&self) -> &'static str {
                "frame-reject"
            }
        }
        assert_eq!(FrameRejectId.id(), "frame-reject");
    }

    // ---- CountingProfile: check_frame and cross_check branches ----
    //
    // The ac16 test makes check_claim always fail, so check_frame and
    // cross_check are never reached.  The test below uses a profile whose
    // check_claim passes, so both remaining hooks are exercised.

    #[test]
    fn counting_profile_check_frame_and_cross_check_are_reachable() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct CountingPassProfile {
            frame_calls: Arc<AtomicUsize>,
            cross_calls: Arc<AtomicUsize>,
        }

        impl Profile for CountingPassProfile {
            fn id(&self) -> &'static str {
                "counting-pass"
            }

            fn check_frame(&self, _: &Frame) -> ProfileCheckResult {
                self.frame_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            fn cross_check(&self, _: &Claim, _: &Frame) -> ProfileCheckResult {
                self.cross_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let frame_calls = Arc::new(AtomicUsize::new(0));
        let cross_calls = Arc::new(AtomicUsize::new(0));
        let p = CountingPassProfile {
            frame_calls: Arc::clone(&frame_calls),
            cross_calls: Arc::clone(&cross_calls),
        };
        assert_eq!(p.id(), "counting-pass");

        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = frames.insert(valid_frame_value());
        let apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "x" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.1 }
            },
            "frame_ref": { "hash": frame_hash.to_string() }
        });
        let carrier = stub_valid(json!({ "apl": apl }));
        let (out, _token) = verify_receipt(
            &[],
            &carrier,
            &frames,
            &InMemoryBridgeResolver::new(),
            Some(&p),
        );

        assert_eq!(out.core_outcome, CoreOutcome::AplValid);
        assert_eq!(
            frame_calls.load(Ordering::SeqCst),
            1,
            "check_frame must be called once"
        );
        assert_eq!(
            cross_calls.load(Ordering::SeqCst),
            1,
            "cross_check must be called once"
        );
    }

    // ---- frame-fail-cross-count: id() coverage ----

    #[test]
    fn profile_id_frame_fail_cross_count_is_accessible() {
        struct FrameFailCrossCountId;

        impl Profile for FrameFailCrossCountId {
            fn id(&self) -> &'static str {
                "frame-fail-cross-count"
            }
        }

        assert_eq!(FrameFailCrossCountId.id(), "frame-fail-cross-count");
    }

    // ---- wcf path: claim present as null and as array → ClaimInvalid ----
    //
    // These exercise the verify_receipt_with_claim_and_frame path for the same
    // ClaimInvalid error variant that claim_parse_error_claim_present_but_not_object
    // covers via verify_receipt, ensuring both callers exercise that branch.

    #[test]
    fn wcf_claim_present_as_null_emits_apl_claim_invalid() {
        let apl = json!({
            "version": "0.1",
            "claim": null,
            "frame_ref": { "hash": h(0x01) }
        });
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": apl })),
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_CLAIM_INVALID));
        assert!(!out.diagnostics.contains(&diag::APL_CLAIM_MISSING));
        assert!(claim.is_none());
        assert!(frame.is_none());
    }

    #[test]
    fn wcf_claim_present_as_array_emits_apl_claim_invalid() {
        let apl = json!({
            "version": "0.1",
            "claim": ["not", "an", "object"],
            "frame_ref": { "hash": h(0x01) }
        });
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": apl })),
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_CLAIM_INVALID));
        assert!(!out.diagnostics.contains(&diag::APL_CLAIM_MISSING));
        assert!(claim.is_none());
        assert!(frame.is_none());
    }

    // ---- wcf path: metadata.apl as null and as array → MetadataAplInvalid ----

    #[test]
    fn wcf_apl_present_as_null_emits_apl_invalid_shape() {
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": null })),
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_INVALID_SHAPE));
        assert!(!out.diagnostics.contains(&diag::APL_MISSING));
        assert!(claim.is_none());
        assert!(frame.is_none());
    }

    #[test]
    fn wcf_apl_present_as_array_emits_apl_invalid_shape() {
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": [1, 2, 3] })),
            &InMemoryFrameResolver::new(),
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert_eq!(
            out.failure_classes,
            vec![FailureClass::ClaimStructureFailure]
        );
        assert!(out.diagnostics.contains(&diag::APL_INVALID_SHAPE));
        assert!(!out.diagnostics.contains(&diag::APL_MISSING));
        assert!(claim.is_none());
        assert!(frame.is_none());
    }

    // ---- wcf path: frame kernel value invalid and extends invalid ----

    #[test]
    fn wcf_frame_kernel_value_invalid_emits_apl_frame_kernel_invalid() {
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = insert_frame_get_hash(
            &mut frames,
            json!({
                "version": "0.1",
                "observer": "o",
                "procedure": {},
                "aspect": ["accuracy"],
                "scope": "s",
                "invariance": ["i"],
                "exclusions": ["e"]
            }),
        );
        let apl = json!({
            "version": "0.1",
            "claim": minimal_claim_body(),
            "frame_ref": { "hash": frame_hash }
        });
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": apl })),
            &frames,
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out.diagnostics.contains(&diag::APL_FRAME_KERNEL_INVALID));
        assert!(!out.diagnostics.contains(&diag::APL_FRAME_KERNEL_MISSING));
        assert!(claim.is_some());
        assert!(frame.is_none());
    }

    #[test]
    fn wcf_frame_extends_invalid_emits_apl_frame_kernel_invalid() {
        let mut frames = InMemoryFrameResolver::new();
        let frame_hash = insert_frame_get_hash(
            &mut frames,
            json!({
                "version": "0.1",
                "observer": "o",
                "procedure": "p",
                "aspect": ["accuracy"],
                "scope": "s",
                "invariance": ["i"],
                "exclusions": ["e"],
                "extends": "not-a-reference-object"
            }),
        );
        let apl = json!({
            "version": "0.1",
            "claim": minimal_claim_body(),
            "frame_ref": { "hash": frame_hash }
        });
        let (out, claim, frame) = verify_receipt_with_claim_and_frame(
            &[],
            &stub_valid(json!({ "apl": apl })),
            &frames,
            &InMemoryBridgeResolver::new(),
            None,
        );
        assert_eq!(out.failure_classes, vec![FailureClass::FrameFailure]);
        assert!(out.diagnostics.contains(&diag::APL_FRAME_KERNEL_INVALID));
        assert!(!out.diagnostics.contains(&diag::APL_FRAME_KERNEL_MISSING));
        assert!(claim.is_some());
        assert!(frame.is_none());
    }
}
