//! Diagnostic status codes per `apl-spec.md §12.3`,
//! `apl-relation-spec.md §9`, and `apl-ai-eval-profile.md §7.8`.
//!
//! Each [`Diagnostic`] variant is an opaque tag that maps 1-to-1 to a
//! kebab-case string in the normative sources. Diagnostics MUST NOT carry
//! payload — they are opaque markers only.

use serde::{Deserialize, Serialize};

/// Opaque diagnostic status codes.
///
/// Each variant maps to a kebab-case string literal taken verbatim from the
/// normative source. Grouped in declaration order matching the spec.
///
/// This enum is `#[non_exhaustive]` because the normative vocabulary may grow
/// with new spec revisions. Callers must handle `_` in match expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Diagnostic {
    // ===== apl-spec.md §12.3 — Failure class markers =====
    /// Failure class marker: carrier layer failed.
    FailureCarrier,
    /// Failure class marker: claim structure violated.
    FailureClaimStructure,
    /// Failure class marker: reference object malformed.
    FailureReference,
    /// Failure class marker: frame binding or resolution failed.
    FailureFrame,
    /// Failure class marker: aspect ref not in frame.
    FailureSemanticLinkage,
    /// Failure class marker: relation structure invalid.
    FailureRelationStructure,

    // ===== apl-spec.md §12.3 — Carrier =====
    /// Carrier signature verified successfully.
    CarrierValid,
    /// Carrier signature failed verification.
    CarrierInvalid,

    // ===== apl-spec.md §12.3 — APL envelope =====
    /// `metadata.apl` is present.
    AplPresent,
    /// `metadata.apl` is absent.
    AplMissing,
    /// `metadata.apl.version` field is absent.
    AplVersionMissing,
    /// `metadata.apl.version` names an unsupported protocol version.
    AplVersionUnsupported,

    // ===== apl-spec.md §12.3 — Claim structure =====
    /// `metadata.apl.claim` is absent.
    AplClaimMissing,
    /// `claim.kind` field is absent.
    AplClaimKindMissing,
    /// `claim.kind` names an unsupported kind.
    AplClaimKindUnsupported,
    /// `claim.subject` is absent.
    AplSubjectMissing,
    /// `claim.subject` fails structural validation.
    AplSubjectInvalid,
    /// `claim.subject.id` is absent or malformed.
    AplSubjectIdInvalid,
    /// `claim.subject.digest` is absent or malformed.
    AplSubjectDigestInvalid,
    /// `claim.aspect_refs` array is absent.
    AplAspectRefsMissing,
    /// `claim.aspect_refs` array fails structural validation.
    AplAspectRefsInvalid,
    /// An element of `claim.aspect_refs` is not listed in the resolved frame's aspects.
    AplAspectRefOutOfFrame,
    /// `claim.statement` is absent.
    AplStatementMissing,
    /// `claim.statement` fails structural validation.
    AplStatementInvalid,
    /// `claim.statement.predicate` is absent.
    AplPredicateMissing,
    /// `claim.statement.content` is absent.
    AplContentMissing,

    // ===== apl-spec.md §12.3 — Frame binding & resolution =====
    /// Receipt is bound to a frame (frame_ref is present and valid).
    AplFrameBound,
    /// `frame_ref` object fails structural validation.
    AplFrameRefInvalid,
    /// Frame artifact was not found by the resolver.
    AplFrameMissing,
    /// `frame_ref.hash` field is absent or malformed.
    AplFrameHashInvalid,
    /// Frame could not be resolved (infra failure or timeout).
    AplFrameUnresolved,
    /// Resolved frame's canonical hash does not match `frame_ref.hash`.
    AplFrameHashMismatch,
    /// `frame.version` field is absent.
    AplFrameVersionMissing,
    /// `frame.version` names an unsupported frame schema version.
    AplFrameVersionUnsupported,
    /// `frame.observer` fails structural validation.
    AplFrameObserverInvalid,
    /// `frame.aspect` array fails structural validation.
    AplFrameAspectInvalid,
    /// `frame.invariance` fails structural validation.
    AplFrameInvarianceInvalid,
    /// `frame.exclusions` fails structural validation.
    AplFrameExclusionsInvalid,
    /// `frame.procedure` or `frame.instrument` is absent (both required).
    AplFrameProcedureOrInstrumentMissing,
    /// `frame.scope` or `frame.resolution` is absent (both required).
    AplFrameScopeOrResolutionMissing,
    /// `frame.kernel` is absent.
    AplFrameKernelMissing,

    // ===== apl-spec.md §12.3 — Relation-layer envelope =====
    /// `claim.related_frames` array fails structural validation.
    AplRelatedFramesInvalid,
    /// `claim.bridge_refs` array fails structural validation.
    AplBridgeRefsInvalid,
    /// `claim.transformation_refs` array fails structural validation.
    AplTransformationRefsInvalid,

    // ===== apl-spec.md §12.3 — Core outcome markers =====
    /// Receipt passed all verifier checks.
    AplValid,
    /// Receipt failed one or more verifier checks.
    AplInvalid,

    // ===== apl-spec.md §12.3 — Relation outcome markers =====
    /// Both receipts reference the same frame.
    SameFrame,
    /// Receipts reference different frames.
    CrossFrame,
    /// A bridge artifact was found and is applicable.
    Bridged,
    /// No applicable bridge artifact was found.
    Unbridged,
    /// The pair is semantically comparable under the query constraints.
    Comparable,
    /// The pair is not semantically comparable under the query constraints.
    Incomparable,

    // ===== apl-spec.md §12.3 — Transformation markers =====
    /// A transformation is declared for this pair.
    TransformationDeclared,
    /// No transformation is declared for this pair.
    TransformationMissing,
    /// The transformation declares a loss of information.
    LossDeclared,
    /// The transformation does not declare a loss of information.
    LossUndeclared,

    // ===== apl-relation-spec.md §9 — Pairwise diagnostics =====
    /// The left receipt of the pair is `apl-invalid`.
    AplPairLeftInvalid,
    /// The right receipt of the pair is `apl-invalid`.
    AplPairRightInvalid,
    /// The `RelationQuery` object fails structural validation.
    AplRelationQueryInvalid,
    /// `query.left_aspects` contains an aspect not in the left receipt's claim.
    AplRelationQueryLeftAspectsOutOfClaim,
    /// `query.right_aspects` contains an aspect not in the right receipt's claim.
    AplRelationQueryRightAspectsOutOfClaim,
    /// `query.predicate` does not match both receipts' `claim.statement.predicate`.
    AplRelationQueryPredicateMismatch,
    /// Both receipts reference the same frame (pairwise path).
    AplSameFrame,
    /// Same-frame pair: queried aspects match.
    AplSameFrameAspectMatch,
    /// Same-frame pair: queried aspects do not match.
    AplSameFrameAspectMismatch,
    /// Statement `content` types differ between the two receipts.
    AplStatementContentTypeMismatch,
    /// Statement `content` object shapes differ between the two receipts.
    AplStatementObjectShapeMismatch,
    /// Receipts reference different frames (cross-frame path).
    AplCrossFrame,
    /// A bridge artifact for this pair fails structural validation.
    AplBridgeInvalid,
    /// No bridge artifact was found for this pair.
    AplBridgeNotFound,
    /// Bridge artifact frame references do not match the receipt pair.
    AplBridgeFrameMismatch,
    /// Bridge artifact scope does not cover the query.
    AplBridgeScopeMismatch,
    /// Bridge artifact is applicable to the query.
    AplBridgeApplicable,
    /// Transformation is declared in the bridge artifact for this pair.
    AplTransformationDeclared,

    // ===== apl-ai-eval-profile.md §7.8 — Profile diagnostics (bridge) =====
    /// AI-Eval bridge: `bridge_kind` is not `"ai-eval"`.
    AplAiEvalBridgeKindInvalid,
    /// AI-Eval bridge: source aspect does not match the expected profile aspect.
    AplAiEvalBridgeSourceAspectMismatch,
    /// AI-Eval bridge: target aspect does not match the expected profile aspect.
    AplAiEvalBridgeTargetAspectMismatch,
    /// AI-Eval bridge: source and target aspects are from different aspect families.
    AplAiEvalBridgeAspectFamilyMismatch,
    /// AI-Eval bridge: `comparison_scope` does not cover the query scope.
    AplAiEvalBridgeScopeMismatch,
    /// AI-Eval bridge: `comparison_scope.relation_type` is incompatible with `bridge_kind`.
    AplAiEvalBridgeRelationTypeInvalid,
    /// AI-Eval bridge: `runner` field does not match.
    AplAiEvalBridgeRunnerMismatch,
    /// AI-Eval bridge: `grader` field does not match.
    AplAiEvalBridgeGraderMismatch,
    /// AI-Eval bridge: `procedure` field does not match.
    AplAiEvalBridgeProcedureMismatch,

    // ===== apl-ai-eval-profile.md §7.8 — Profile diagnostics (claim / pairwise-query / cross-check) =====
    //
    // These codes make the public diagnostic contract semantically precise.
    // Each is distinct from any bridge-level code:
    //
    // * `AplAiEvalPredicateDisallowed` — claim predicate is present but not in
    //   the profile's allowed set (e.g. predicate = "count" under AI-Eval).
    //   Distinct from `apl-predicate-missing`.
    // * `AplAiEvalPredicateInvalid` — pairwise query `predicate` is not
    //   `"score"`. Distinct from both `apl-predicate-missing` and the
    //   bridge-kind-specific `apl-ai-eval-bridge-relation-type-invalid`.
    // * `AplAiEvalRelationTypeInvalid` — pairwise query `relation_type` is not
    //   in {"score-delta","repeatability-check"}. Distinct from
    //   `apl-ai-eval-bridge-relation-type-invalid` (which applies to a
    //   bridge artifact's `comparison_scope.relation_type` vs `bridge_kind`).
    // * `AplAiEvalBenchmarkIdMismatch` — claim
    //   `statement.content.benchmark_id` differs from
    //   `frame.scope.benchmark_id` (§6.2). Joint claim+frame invariant.
    /// AI-Eval claim: predicate is present but not in the profile's allowed set.
    AplAiEvalPredicateDisallowed,
    /// AI-Eval pairwise: query `predicate` is not `"score"`.
    AplAiEvalPredicateInvalid,
    /// AI-Eval pairwise: query `relation_type` is not in the allowed set.
    AplAiEvalRelationTypeInvalid,
    /// AI-Eval claim: `statement.content.benchmark_id` differs from `frame.scope.benchmark_id`.
    AplAiEvalBenchmarkIdMismatch,
}

impl Diagnostic {
    /// Kebab-case string exactly as it appears in the normative source.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailureCarrier => "failure-carrier",
            Self::FailureClaimStructure => "failure-claim-structure",
            Self::FailureReference => "failure-reference",
            Self::FailureFrame => "failure-frame",
            Self::FailureSemanticLinkage => "failure-semantic-linkage",
            Self::FailureRelationStructure => "failure-relation-structure",

            Self::CarrierValid => "carrier-valid",
            Self::CarrierInvalid => "carrier-invalid",

            Self::AplPresent => "apl-present",
            Self::AplMissing => "apl-missing",
            Self::AplVersionMissing => "apl-version-missing",
            Self::AplVersionUnsupported => "apl-version-unsupported",

            Self::AplClaimMissing => "apl-claim-missing",
            Self::AplClaimKindMissing => "apl-claim-kind-missing",
            Self::AplClaimKindUnsupported => "apl-claim-kind-unsupported",
            Self::AplSubjectMissing => "apl-subject-missing",
            Self::AplSubjectInvalid => "apl-subject-invalid",
            Self::AplSubjectIdInvalid => "apl-subject-id-invalid",
            Self::AplSubjectDigestInvalid => "apl-subject-digest-invalid",
            Self::AplAspectRefsMissing => "apl-aspect-refs-missing",
            Self::AplAspectRefsInvalid => "apl-aspect-refs-invalid",
            Self::AplAspectRefOutOfFrame => "apl-aspect-ref-out-of-frame",
            Self::AplStatementMissing => "apl-statement-missing",
            Self::AplStatementInvalid => "apl-statement-invalid",
            Self::AplPredicateMissing => "apl-predicate-missing",
            Self::AplContentMissing => "apl-content-missing",

            Self::AplFrameBound => "apl-frame-bound",
            Self::AplFrameRefInvalid => "apl-frame-ref-invalid",
            Self::AplFrameMissing => "apl-frame-missing",
            Self::AplFrameHashInvalid => "apl-frame-hash-invalid",
            Self::AplFrameUnresolved => "apl-frame-unresolved",
            Self::AplFrameHashMismatch => "apl-frame-hash-mismatch",
            Self::AplFrameVersionMissing => "apl-frame-version-missing",
            Self::AplFrameVersionUnsupported => "apl-frame-version-unsupported",
            Self::AplFrameObserverInvalid => "apl-frame-observer-invalid",
            Self::AplFrameAspectInvalid => "apl-frame-aspect-invalid",
            Self::AplFrameInvarianceInvalid => "apl-frame-invariance-invalid",
            Self::AplFrameExclusionsInvalid => "apl-frame-exclusions-invalid",
            Self::AplFrameProcedureOrInstrumentMissing => {
                "apl-frame-procedure-or-instrument-missing"
            }
            Self::AplFrameScopeOrResolutionMissing => "apl-frame-scope-or-resolution-missing",
            Self::AplFrameKernelMissing => "apl-frame-kernel-missing",

            Self::AplRelatedFramesInvalid => "apl-related-frames-invalid",
            Self::AplBridgeRefsInvalid => "apl-bridge-refs-invalid",
            Self::AplTransformationRefsInvalid => "apl-transformation-refs-invalid",

            Self::AplValid => "apl-valid",
            Self::AplInvalid => "apl-invalid",

            Self::SameFrame => "same-frame",
            Self::CrossFrame => "cross-frame",
            Self::Bridged => "bridged",
            Self::Unbridged => "unbridged",
            Self::Comparable => "comparable",
            Self::Incomparable => "incomparable",

            Self::TransformationDeclared => "transformation-declared",
            Self::TransformationMissing => "transformation-missing",
            Self::LossDeclared => "loss-declared",
            Self::LossUndeclared => "loss-undeclared",

            Self::AplPairLeftInvalid => "apl-pair-left-invalid",
            Self::AplPairRightInvalid => "apl-pair-right-invalid",
            Self::AplRelationQueryInvalid => "apl-relation-query-invalid",
            Self::AplRelationQueryLeftAspectsOutOfClaim => {
                "apl-relation-query-left-aspects-out-of-claim"
            }
            Self::AplRelationQueryRightAspectsOutOfClaim => {
                "apl-relation-query-right-aspects-out-of-claim"
            }
            Self::AplRelationQueryPredicateMismatch => "apl-relation-query-predicate-mismatch",
            Self::AplSameFrame => "apl-same-frame",
            Self::AplSameFrameAspectMatch => "apl-same-frame-aspect-match",
            Self::AplSameFrameAspectMismatch => "apl-same-frame-aspect-mismatch",
            Self::AplStatementContentTypeMismatch => "apl-statement-content-type-mismatch",
            Self::AplStatementObjectShapeMismatch => "apl-statement-object-shape-mismatch",
            Self::AplCrossFrame => "apl-cross-frame",
            Self::AplBridgeInvalid => "apl-bridge-invalid",
            Self::AplBridgeNotFound => "apl-bridge-not-found",
            Self::AplBridgeFrameMismatch => "apl-bridge-frame-mismatch",
            Self::AplBridgeScopeMismatch => "apl-bridge-scope-mismatch",
            Self::AplBridgeApplicable => "apl-bridge-applicable",
            Self::AplTransformationDeclared => "apl-transformation-declared",

            Self::AplAiEvalBridgeKindInvalid => "apl-ai-eval-bridge-kind-invalid",
            Self::AplAiEvalBridgeSourceAspectMismatch => {
                "apl-ai-eval-bridge-source-aspect-mismatch"
            }
            Self::AplAiEvalBridgeTargetAspectMismatch => {
                "apl-ai-eval-bridge-target-aspect-mismatch"
            }
            Self::AplAiEvalBridgeAspectFamilyMismatch => {
                "apl-ai-eval-bridge-aspect-family-mismatch"
            }
            Self::AplAiEvalBridgeScopeMismatch => "apl-ai-eval-bridge-scope-mismatch",
            Self::AplAiEvalBridgeRelationTypeInvalid => "apl-ai-eval-bridge-relation-type-invalid",
            Self::AplAiEvalBridgeRunnerMismatch => "apl-ai-eval-bridge-runner-mismatch",
            Self::AplAiEvalBridgeGraderMismatch => "apl-ai-eval-bridge-grader-mismatch",
            Self::AplAiEvalBridgeProcedureMismatch => "apl-ai-eval-bridge-procedure-mismatch",

            Self::AplAiEvalPredicateDisallowed => "apl-ai-eval-predicate-disallowed",
            Self::AplAiEvalPredicateInvalid => "apl-ai-eval-predicate-invalid",
            Self::AplAiEvalRelationTypeInvalid => "apl-ai-eval-relation-type-invalid",
            Self::AplAiEvalBenchmarkIdMismatch => "apl-ai-eval-benchmark-id-mismatch",
        }
    }

    /// Is this diagnostic a failure-class marker (`apl-spec.md §12.3`)?
    #[must_use]
    pub fn is_failure_marker(self) -> bool {
        matches!(
            self,
            Self::FailureCarrier
                | Self::FailureClaimStructure
                | Self::FailureReference
                | Self::FailureFrame
                | Self::FailureSemanticLinkage
                | Self::FailureRelationStructure
        )
    }

    /// Is this diagnostic from the AI-Eval profile set (`apl-ai-eval-profile.md §7.8`)?
    #[must_use]
    pub fn is_ai_eval(self) -> bool {
        matches!(
            self,
            Self::AplAiEvalBridgeKindInvalid
                | Self::AplAiEvalBridgeSourceAspectMismatch
                | Self::AplAiEvalBridgeTargetAspectMismatch
                | Self::AplAiEvalBridgeAspectFamilyMismatch
                | Self::AplAiEvalBridgeScopeMismatch
                | Self::AplAiEvalBridgeRelationTypeInvalid
                | Self::AplAiEvalBridgeRunnerMismatch
                | Self::AplAiEvalBridgeGraderMismatch
                | Self::AplAiEvalBridgeProcedureMismatch
                | Self::AplAiEvalPredicateDisallowed
                | Self::AplAiEvalPredicateInvalid
                | Self::AplAiEvalRelationTypeInvalid
                | Self::AplAiEvalBenchmarkIdMismatch
        )
    }

    /// Is this diagnostic from the pairwise relation set (`apl-relation-spec.md §9`)?
    #[must_use]
    pub fn is_pairwise(self) -> bool {
        matches!(
            self,
            Self::AplPairLeftInvalid
                | Self::AplPairRightInvalid
                | Self::AplRelationQueryInvalid
                | Self::AplRelationQueryLeftAspectsOutOfClaim
                | Self::AplRelationQueryRightAspectsOutOfClaim
                | Self::AplRelationQueryPredicateMismatch
                | Self::AplSameFrame
                | Self::AplSameFrameAspectMatch
                | Self::AplSameFrameAspectMismatch
                | Self::AplStatementContentTypeMismatch
                | Self::AplStatementObjectShapeMismatch
                | Self::AplCrossFrame
                | Self::AplBridgeInvalid
                | Self::AplBridgeNotFound
                | Self::AplBridgeFrameMismatch
                | Self::AplBridgeScopeMismatch
                | Self::AplBridgeApplicable
                | Self::AplTransformationDeclared
        )
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    /// Every diagnostic from `apl-spec.md §12.3` is represented.
    /// This list is taken verbatim from the normative source.
    #[test]
    fn spec_12_3_codes_are_all_present() {
        let required = [
            "failure-carrier",
            "failure-claim-structure",
            "failure-reference",
            "failure-frame",
            "failure-semantic-linkage",
            "failure-relation-structure",
            "carrier-valid",
            "carrier-invalid",
            "apl-present",
            "apl-missing",
            "apl-version-missing",
            "apl-version-unsupported",
            "apl-claim-missing",
            "apl-claim-kind-missing",
            "apl-claim-kind-unsupported",
            "apl-subject-missing",
            "apl-subject-invalid",
            "apl-subject-id-invalid",
            "apl-subject-digest-invalid",
            "apl-aspect-refs-missing",
            "apl-aspect-refs-invalid",
            "apl-aspect-ref-out-of-frame",
            "apl-statement-missing",
            "apl-statement-invalid",
            "apl-predicate-missing",
            "apl-content-missing",
            "apl-frame-bound",
            "apl-frame-ref-invalid",
            "apl-frame-missing",
            "apl-frame-hash-invalid",
            "apl-frame-unresolved",
            "apl-frame-hash-mismatch",
            "apl-frame-version-missing",
            "apl-frame-version-unsupported",
            "apl-frame-observer-invalid",
            "apl-frame-aspect-invalid",
            "apl-frame-invariance-invalid",
            "apl-frame-exclusions-invalid",
            "apl-frame-procedure-or-instrument-missing",
            "apl-frame-scope-or-resolution-missing",
            "apl-frame-kernel-missing",
            "apl-related-frames-invalid",
            "apl-bridge-refs-invalid",
            "apl-transformation-refs-invalid",
            "apl-valid",
            "apl-invalid",
            "same-frame",
            "cross-frame",
            "bridged",
            "unbridged",
            "comparable",
            "incomparable",
            "transformation-declared",
            "transformation-missing",
            "loss-declared",
            "loss-undeclared",
        ];

        for s in required {
            let quoted = format!("\"{s}\"");
            let decoded: Diagnostic = serde_json::from_str(&quoted)
                .unwrap_or_else(|e| panic!("diagnostic {s:?} not covered: {e}"));
            assert_eq!(decoded.as_str(), s, "round-trip mismatch for {s}");
        }
    }

    /// Every diagnostic from `apl-relation-spec.md §9`.
    #[test]
    fn pairwise_codes_are_all_present() {
        let required = [
            "apl-pair-left-invalid",
            "apl-pair-right-invalid",
            "apl-relation-query-invalid",
            "apl-relation-query-left-aspects-out-of-claim",
            "apl-relation-query-right-aspects-out-of-claim",
            "apl-relation-query-predicate-mismatch",
            "apl-same-frame",
            "apl-same-frame-aspect-match",
            "apl-same-frame-aspect-mismatch",
            "apl-statement-content-type-mismatch",
            "apl-statement-object-shape-mismatch",
            "apl-cross-frame",
            "apl-bridge-invalid",
            "apl-bridge-not-found",
            "apl-bridge-frame-mismatch",
            "apl-bridge-scope-mismatch",
            "apl-bridge-applicable",
            "apl-transformation-declared",
        ];
        for s in required {
            let quoted = format!("\"{s}\"");
            let decoded: Diagnostic = serde_json::from_str(&quoted)
                .unwrap_or_else(|e| panic!("pairwise diagnostic {s:?} missing: {e}"));
            assert_eq!(decoded.as_str(), s);
        }
    }

    /// Every diagnostic from `apl-ai-eval-profile.md §7.8` (including the
    /// four additional codes for claim / pairwise-query / cross-check that
    /// apl-core introduces).
    #[test]
    fn ai_eval_codes_are_all_present() {
        let required = [
            "apl-ai-eval-bridge-kind-invalid",
            "apl-ai-eval-bridge-source-aspect-mismatch",
            "apl-ai-eval-bridge-target-aspect-mismatch",
            "apl-ai-eval-bridge-aspect-family-mismatch",
            "apl-ai-eval-bridge-scope-mismatch",
            "apl-ai-eval-bridge-relation-type-invalid",
            "apl-ai-eval-bridge-runner-mismatch",
            "apl-ai-eval-bridge-grader-mismatch",
            "apl-ai-eval-bridge-procedure-mismatch",
            "apl-ai-eval-predicate-disallowed",
            "apl-ai-eval-predicate-invalid",
            "apl-ai-eval-relation-type-invalid",
            "apl-ai-eval-benchmark-id-mismatch",
        ];
        for s in required {
            let quoted = format!("\"{s}\"");
            let decoded: Diagnostic = serde_json::from_str(&quoted)
                .unwrap_or_else(|e| panic!("ai-eval diagnostic {s:?} missing: {e}"));
            assert!(decoded.is_ai_eval(), "{decoded:?} should be AI-Eval");
            assert_eq!(decoded.as_str(), s);
        }
    }

    /// Invalid diagnostic strings are rejected.
    #[test]
    fn unknown_diagnostic_rejected() {
        let bad = r#""some-unknown-code""#;
        assert!(serde_json::from_str::<Diagnostic>(bad).is_err());
    }

    /// Categorization helpers.
    #[test]
    fn categorization_helpers() {
        assert!(Diagnostic::FailureCarrier.is_failure_marker());
        assert!(!Diagnostic::AplValid.is_failure_marker());
        assert!(Diagnostic::AplBridgeApplicable.is_pairwise());
        assert!(!Diagnostic::AplBridgeApplicable.is_ai_eval());
        assert!(Diagnostic::AplAiEvalBridgeAspectFamilyMismatch.is_ai_eval());
    }

    /// Serde serialization produces the exact normative string.
    #[test]
    fn ai_eval_bridge_aspect_family_mismatch_serde() {
        let json = serde_json::to_string(&Diagnostic::AplAiEvalBridgeAspectFamilyMismatch)
            .expect("serialization must succeed");
        assert_eq!(json, r#""apl-ai-eval-bridge-aspect-family-mismatch""#);
    }
}

#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Serialization roundtrip is identity for every Diagnostic value we can
        /// construct. Either parses to a Diagnostic or not; if it parses,
        /// round-trip must hold.
        #[test]
        fn diagnostic_roundtrip_proptest(s in "[a-z][a-z0-9-]{1,80}") {
            let quoted = format!("\"{s}\"");
            if let Ok(d) = serde_json::from_str::<Diagnostic>(&quoted) {
                prop_assert_eq!(d.as_str(), s.as_str());
            }
        }
    }
}
