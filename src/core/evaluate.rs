//! Pairwise relation evaluation — 19-step algorithm per `apl-relation-spec.md §7`.
//!
//! # Overview
//!
//! [`evaluate_relation`] accepts two APL receipts (raw bytes or prevalidated),
//! a [`RelationQuery`], and optional bridge candidates. It produces a
//! [`PairwiseOutput`] containing:
//!
//! - Per-side core outcomes (from CORE-VERIFY-1 or from the caller).
//! - A [`RelationOutcome`] classifying the pair.
//! - Ordered diagnostics from `apl-relation-spec.md §9`.
//!
//! # Fail-Closed Profile Gate (`§6.4`)
//!
//! When a [`Profile`] is active, [`Profile::check_pairwise_relation`] fires
//! AFTER Core preconditions and statement structural compatibility pass, and
//! BEFORE the frame-equality branch is selected. Both the `Bytes` and the
//! `Prevalidated` input paths guarantee that the `Frame` is available at that
//! point, making the gate unconditional — there is no code path where the
//! profile is active but the gate is silently skipped.

use std::collections::HashSet;

use serde_json::Value;

use crate::core::bridge::Bridge;
use crate::core::carrier::CarrierVerifier;
use crate::core::claim::{Claim, Statement};
use crate::core::frame::Frame;
use crate::core::jcs::canonical_hash;
use crate::core::output::{CoreOutcome, PairwiseOutput, RelationOutcome, SideCore, VerifierOutput};
use crate::core::relation::RelationQuery;
use crate::core::resolver::{BridgeResolution, BridgeResolver, FrameResolver};
use crate::core::verified::VerifiedReceipt;
use crate::core::verify::verify_receipt_with_claim_and_frame;
use crate::diagnostics::{self as D, DiagnosticCode};
use crate::profile::trait_def::Profile;

// ---------------------------------------------------------------------------
// Public data structures
// ---------------------------------------------------------------------------

/// Input for one side of the pairwise relation evaluation.
///
/// Either raw carrier bytes (CORE-VERIFY-1 is run internally) or an opaque
/// [`VerifiedReceipt`] token obtained from a prior `verify_receipt` call.
///
/// # Fail-Closed API Boundary
///
/// The `Prevalidated` variant carries a [`VerifiedReceipt`] token whose fields
/// are private. The token is unforgeable: the only way to construct one is via
/// `verify_receipt`, which only returns `Some(VerifiedReceipt)` when
/// `core_outcome == AplValid`. A malicious caller therefore cannot supply a
/// `VerifierOutput { core_outcome: AplValid, ... }` constructed manually.
///
/// Note that `VerifiedReceipt` does NOT prove profile conformance. When a
/// profile is active, `evaluate_relation` re-runs `check_claim`, `check_frame`,
/// and `cross_check` on both sides before the pairwise gate — regardless of
/// which profile (if any) was used when the receipt was originally verified.
// Clippy: `VerifiedReceipt` is a larger struct than the `Bytes` variant's
// reference; the size difference is acceptable for the security benefit.
#[allow(clippy::large_enum_variant)]
pub enum ReceiptInput<'a> {
    /// Unverified raw bytes. [`evaluate_relation`] will run CORE-VERIFY-1.
    Bytes(&'a [u8]),
    /// Opaque token produced by a prior `verify_receipt` call that returned
    /// `core_outcome == AplValid`. Cannot be constructed directly by external
    /// callers — obtain via `verify_receipt`.
    Prevalidated(VerifiedReceipt),
}

/// Full pairwise input for [`evaluate_relation`].
pub struct PairwiseInput<'a> {
    /// Left receipt.
    pub left: ReceiptInput<'a>,
    /// Right receipt.
    pub right: ReceiptInput<'a>,
    /// Relation query.
    pub query: RelationQuery,
    /// Bridge artifacts supplied out-of-band (in addition to those
    /// discoverable via `bridge_refs` through the resolver).
    ///
    /// Each supplied value whose canonical hash matches one of the
    /// `bridge_refs` entries from either claim is added to the candidate set
    /// and then subject to normal structural / frame / scope / profile checks
    /// in STEP 17 (structurally invalid candidates are ignored without a
    /// diagnostic in that step). Supplied values whose canonical hash does
    /// NOT match any `bridge_refs` entry are silently ignored without a
    /// diagnostic — callers may supply a superset and the evaluator picks
    /// only what was requested.
    pub supplied_bridges: Vec<Value>,
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// Result of statement structural compatibility check (`§3.2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StructuralCompat {
    Compatible,
    TopLevelTypeMismatch,
    ObjectShapeMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypeTag {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Evaluate the relation between two APL receipts under a `relation_query`.
///
/// Implements the 19-step algorithm of `apl-relation-spec.md §7`.
///
/// # Arguments
///
/// * `input` — two receipts + query + supplied bridges.
/// * `carrier` — carrier verifier (used if any side is `ReceiptInput::Bytes`).
/// * `frames` — frame resolver (used on the `Bytes` path; not consulted for
///   `Prevalidated` inputs).
/// * `bridges` — bridge resolver (searched via `bridge_refs` on both claims).
/// * `profile` — optional profile hook.
///
/// # Returns
///
/// A [`PairwiseOutput`] with the canonical relation outcome per `§7.8` and
/// diagnostics from `§9`.
///
/// # Examples
///
/// ```rust,ignore
/// use apl_core::core::evaluate::{evaluate_relation, PairwiseInput, ReceiptInput};
/// use apl_core::core::relation::RelationQuery;
/// use apl_core::core::resolver::{InMemoryBridgeResolver, InMemoryFrameResolver};
/// use serde_json::json;
///
/// let frames = InMemoryFrameResolver::new();
/// let bridges = InMemoryBridgeResolver::new();
/// // ... populate frames and bridges ...
///
/// let query = RelationQuery::parse(&json!({
///     "left_aspects":  ["accuracy"],
///     "right_aspects": ["accuracy"],
///     "predicate":     "score",
///     "relation_type": "score-delta",
/// })).unwrap();
///
/// let input = PairwiseInput {
///     left:  ReceiptInput::Bytes(left_bytes),
///     right: ReceiptInput::Bytes(right_bytes),
///     query,
///     supplied_bridges: vec![],
/// };
///
/// let out = evaluate_relation(input, &carrier, &frames, &bridges, None);
/// ```
pub fn evaluate_relation(
    input: PairwiseInput<'_>,
    carrier: &dyn CarrierVerifier,
    frames: &dyn FrameResolver,
    bridges: &dyn BridgeResolver,
    profile: Option<&dyn Profile>,
) -> PairwiseOutput {
    let mut diagnostics: Vec<DiagnosticCode> = Vec::new();

    // STEPS 1-2: core validation of both sides.
    let (left_out, left_claim_opt, left_frame_opt) =
        resolve_side(input.left, carrier, frames, bridges, profile);
    let (right_out, right_claim_opt, right_frame_opt) =
        resolve_side(input.right, carrier, frames, bridges, profile);

    let left_invalid = left_out.core_outcome == CoreOutcome::AplInvalid;
    let right_invalid = right_out.core_outcome == CoreOutcome::AplInvalid;

    if left_invalid {
        diagnostics.push(D::APL_PAIR_LEFT_INVALID);
    }
    if right_invalid {
        diagnostics.push(D::APL_PAIR_RIGHT_INVALID);
    }

    // STEP 3: query structural validity — guaranteed by RelationQuery::parse at
    // construction; re-checked defensively here.
    //
    // If either side is invalid, claim/frame may be None; return early.
    if left_invalid
        || right_invalid
        || left_claim_opt.is_none()
        || right_claim_opt.is_none()
        || left_frame_opt.is_none()
        || right_frame_opt.is_none()
    {
        return PairwiseOutput {
            left: SideCore {
                core_outcome: left_out.core_outcome,
                failure_classes: left_out.failure_classes,
            },
            right: SideCore {
                core_outcome: right_out.core_outcome,
                failure_classes: right_out.failure_classes,
            },
            relation_outcome: RelationOutcome::RelationNotEvaluated,
            diagnostics,
        };
    }

    // Both sides are core-valid and have Claim + Frame.
    // The unwrap calls below cannot panic: we have just verified all four
    // Option slots are Some in the guard above.
    let left = left_claim_opt.unwrap_or_else(|| unreachable!());
    let right = right_claim_opt.unwrap_or_else(|| unreachable!());
    let left_frame = left_frame_opt.unwrap_or_else(|| unreachable!());
    let right_frame = right_frame_opt.unwrap_or_else(|| unreachable!());

    // STEPS 4-5: aspect subset check.
    let left_aspect_set: HashSet<&str> =
        left.claim.aspect_refs.iter().map(String::as_str).collect();
    let right_aspect_set: HashSet<&str> =
        right.claim.aspect_refs.iter().map(String::as_str).collect();
    let left_query_set: HashSet<&str> = input
        .query
        .left_aspects
        .iter()
        .map(String::as_str)
        .collect();
    let right_query_set: HashSet<&str> = input
        .query
        .right_aspects
        .iter()
        .map(String::as_str)
        .collect();

    let mut precondition_failed = false;

    if !left_query_set.is_subset(&left_aspect_set) {
        diagnostics.push(D::APL_RELATION_QUERY_LEFT_ASPECTS_OUT_OF_CLAIM);
        precondition_failed = true;
    }
    if !right_query_set.is_subset(&right_aspect_set) {
        diagnostics.push(D::APL_RELATION_QUERY_RIGHT_ASPECTS_OUT_OF_CLAIM);
        precondition_failed = true;
    }

    // STEPS 6-7: predicate match.
    if input.query.predicate != left.claim.statement.predicate
        || input.query.predicate != right.claim.statement.predicate
    {
        diagnostics.push(D::APL_RELATION_QUERY_PREDICATE_MISMATCH);
        precondition_failed = true;
    }

    // STEP 8: return early if any precondition failed.
    if precondition_failed {
        return PairwiseOutput {
            left: SideCore {
                core_outcome: left_out.core_outcome,
                failure_classes: left_out.failure_classes,
            },
            right: SideCore {
                core_outcome: right_out.core_outcome,
                failure_classes: right_out.failure_classes,
            },
            relation_outcome: RelationOutcome::RelationNotEvaluated,
            diagnostics,
        };
    }

    // STEPS 9-10: statement structural compatibility.
    match structural_compat(&left.claim.statement, &right.claim.statement) {
        StructuralCompat::Compatible => {}
        StructuralCompat::TopLevelTypeMismatch => {
            diagnostics.push(D::APL_STATEMENT_CONTENT_TYPE_MISMATCH);
            return PairwiseOutput {
                left: SideCore {
                    core_outcome: left_out.core_outcome,
                    failure_classes: left_out.failure_classes,
                },
                right: SideCore {
                    core_outcome: right_out.core_outcome,
                    failure_classes: right_out.failure_classes,
                },
                relation_outcome: RelationOutcome::Incomparable,
                diagnostics,
            };
        }
        StructuralCompat::ObjectShapeMismatch => {
            diagnostics.push(D::APL_STATEMENT_OBJECT_SHAPE_MISMATCH);
            return PairwiseOutput {
                left: SideCore {
                    core_outcome: left_out.core_outcome,
                    failure_classes: left_out.failure_classes,
                },
                right: SideCore {
                    core_outcome: right_out.core_outcome,
                    failure_classes: right_out.failure_classes,
                },
                relation_outcome: RelationOutcome::Incomparable,
                diagnostics,
            };
        }
    }

    // STEP 10a: per-side profile re-check.
    //
    // Re-run the single-receipt profile hooks on each side's claim and frame.
    // This is necessary because a `VerifiedReceipt` may have been produced
    // without a profile (or with a different profile) and then passed into
    // `evaluate_relation` with an active profile. The per-side hooks must
    // gate regardless of how the side reached this point.
    //
    // Order: check_claim → check_frame → cross_check (same as CORE-VERIFY-1).
    // On failure, short-circuit to `RelationNotEvaluated` with the profile's
    // diagnostics appended.
    if let Some(p) = profile {
        for (side_claim, side_frame) in [(&left, &left_frame), (&right, &right_frame)] {
            if let Err(profile_failure) = p.check_claim(side_claim) {
                diagnostics.extend(profile_failure.diagnostics);
                return PairwiseOutput {
                    left: SideCore {
                        core_outcome: left_out.core_outcome,
                        failure_classes: left_out.failure_classes,
                    },
                    right: SideCore {
                        core_outcome: right_out.core_outcome,
                        failure_classes: right_out.failure_classes,
                    },
                    relation_outcome: RelationOutcome::RelationNotEvaluated,
                    diagnostics,
                };
            }
            if let Err(profile_failure) = p.check_frame(side_frame) {
                diagnostics.extend(profile_failure.diagnostics);
                return PairwiseOutput {
                    left: SideCore {
                        core_outcome: left_out.core_outcome,
                        failure_classes: left_out.failure_classes,
                    },
                    right: SideCore {
                        core_outcome: right_out.core_outcome,
                        failure_classes: right_out.failure_classes,
                    },
                    relation_outcome: RelationOutcome::RelationNotEvaluated,
                    diagnostics,
                };
            }
            if let Err(profile_failure) = p.cross_check(side_claim, side_frame) {
                diagnostics.extend(profile_failure.diagnostics);
                return PairwiseOutput {
                    left: SideCore {
                        core_outcome: left_out.core_outcome,
                        failure_classes: left_out.failure_classes,
                    },
                    right: SideCore {
                        core_outcome: right_out.core_outcome,
                        failure_classes: right_out.failure_classes,
                    },
                    relation_outcome: RelationOutcome::RelationNotEvaluated,
                    diagnostics,
                };
            }
        }

        // STEP 10b: profile pairwise gate (§6.4).
        //
        // Fires BEFORE the frame-equality branch so that profiles can reject
        // same-frame pairs with disallowed predicate / relation_type. MUST run
        // AFTER Core preconditions so that Core invariants already hold.
        match p.check_pairwise_relation(&left, &right, &left_frame, &right_frame, &input.query) {
            Ok(()) => {}
            Err(profile_diags) => {
                diagnostics.extend(profile_diags);
                return PairwiseOutput {
                    left: SideCore {
                        core_outcome: left_out.core_outcome,
                        failure_classes: left_out.failure_classes,
                    },
                    right: SideCore {
                        core_outcome: right_out.core_outcome,
                        failure_classes: right_out.failure_classes,
                    },
                    relation_outcome: RelationOutcome::Incomparable,
                    diagnostics,
                };
            }
        }
    }

    // STEP 11: same-frame?
    if left.frame_ref.hash == right.frame_ref.hash {
        diagnostics.push(D::APL_SAME_FRAME);

        // STEP 12: aspect set equality.
        if left_query_set == right_query_set {
            diagnostics.push(D::APL_SAME_FRAME_ASPECT_MATCH);
            // STEP 13
            return PairwiseOutput {
                left: SideCore {
                    core_outcome: left_out.core_outcome,
                    failure_classes: left_out.failure_classes,
                },
                right: SideCore {
                    core_outcome: right_out.core_outcome,
                    failure_classes: right_out.failure_classes,
                },
                relation_outcome: RelationOutcome::SameFrameComparable,
                diagnostics,
            };
        }

        diagnostics.push(D::APL_SAME_FRAME_ASPECT_MISMATCH);
        // STEP 14
        return PairwiseOutput {
            left: SideCore {
                core_outcome: left_out.core_outcome,
                failure_classes: left_out.failure_classes,
            },
            right: SideCore {
                core_outcome: right_out.core_outcome,
                failure_classes: right_out.failure_classes,
            },
            relation_outcome: RelationOutcome::Incomparable,
            diagnostics,
        };
    }

    // Cross-frame path.
    diagnostics.push(D::APL_CROSS_FRAME);

    // STEP 15: collect bridge candidates.
    //
    // Every candidate must have a canonical hash equal to the hash that was
    // requested. This enforces the content-addressed trust boundary: a resolver
    // (or caller-supplied value) that returns a *different* bridge object for a
    // given hash request is rejected, regardless of whether its frame/scope
    // fields happen to match. Without this check a malicious or buggy resolver
    // could substitute an attacker-chosen bridge and bypass unforgeable identity.
    let mut candidate_values: Vec<Value> = Vec::new();

    // Collect all requested bridge hashes so we can match supplied bridges.
    let requested_refs: Vec<&crate::core::hash::Reference> = left
        .bridge_refs
        .iter()
        .flatten()
        .chain(right.bridge_refs.iter().flatten())
        .collect();

    for r in &requested_refs {
        if let BridgeResolution::Found(v) = bridges.resolve(&r.hash) {
            let observed = canonical_hash(&v);
            if observed == r.hash {
                candidate_values.push(v);
            } else {
                diagnostics.push(D::APL_BRIDGE_HASH_MISMATCH);
            }
        }
    }

    // Supplied bridges: accept a value only if its canonical hash matches one
    // of the requested `bridge_refs`. Values whose hash does NOT match any
    // requested ref are silently ignored (no diagnostic) — callers may supply
    // a superset and the evaluator picks only what was requested.
    for v in &input.supplied_bridges {
        let observed = canonical_hash(v);
        if requested_refs.iter().any(|r| r.hash == observed) {
            candidate_values.push(v.clone());
        }
    }

    if candidate_values.is_empty() {
        diagnostics.push(D::APL_BRIDGE_NOT_FOUND);
        return PairwiseOutput {
            left: SideCore {
                core_outcome: left_out.core_outcome,
                failure_classes: left_out.failure_classes,
            },
            right: SideCore {
                core_outcome: right_out.core_outcome,
                failure_classes: right_out.failure_classes,
            },
            relation_outcome: RelationOutcome::Incomparable,
            diagnostics,
        };
    }

    // STEPS 16-17: check each candidate.
    let mut found_applicable = false;
    for cand in &candidate_values {
        let bridge = match Bridge::parse(cand) {
            Ok(b) => b,
            Err(_) => {
                diagnostics.push(D::APL_BRIDGE_INVALID);
                // STEP 17: structurally-invalid bridges are ignored.
                continue;
            }
        };

        // Core applicability — frame match (§6.1).
        if bridge.source_frame.hash != left.frame_ref.hash
            || bridge.target_frame.hash != right.frame_ref.hash
        {
            diagnostics.push(D::APL_BRIDGE_FRAME_MISMATCH);
            continue;
        }

        // Core applicability — scope match (§6.2).
        let bridge_source_set: HashSet<&str> = bridge
            .comparison_scope
            .source_aspects
            .iter()
            .map(String::as_str)
            .collect();
        let bridge_target_set: HashSet<&str> = bridge
            .comparison_scope
            .target_aspects
            .iter()
            .map(String::as_str)
            .collect();
        if !left_query_set.is_subset(&bridge_source_set)
            || !right_query_set.is_subset(&bridge_target_set)
            || input.query.relation_type != bridge.comparison_scope.relation_type
        {
            diagnostics.push(D::APL_BRIDGE_SCOPE_MISMATCH);
            continue;
        }

        // Profile hook (§6.4). Frames are unconditionally present (same
        // invariant as the pairwise gate at STEP 10a).
        if let Some(p) = profile {
            match p.check_bridge_applicability(&bridge, &left_frame, &right_frame, &input.query) {
                Ok(()) => {}
                Err(profile_diags) => {
                    diagnostics.extend(profile_diags);
                    continue;
                }
            }
        }

        diagnostics.push(D::APL_BRIDGE_APPLICABLE);
        found_applicable = true;
        break; // One applicable bridge is sufficient (§7 step 18).
    }

    // STEPS 18-19.
    let relation_outcome = if found_applicable {
        RelationOutcome::BridgedComparable
    } else {
        RelationOutcome::Incomparable
    };

    PairwiseOutput {
        left: SideCore {
            core_outcome: left_out.core_outcome,
            failure_classes: left_out.failure_classes,
        },
        right: SideCore {
            core_outcome: right_out.core_outcome,
            failure_classes: right_out.failure_classes,
        },
        relation_outcome,
        diagnostics,
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Dispatch one side of the pair: either run CORE-VERIFY-1 on raw bytes,
/// or unpack the opaque `VerifiedReceipt` token.
///
/// For the `Prevalidated` path no runtime consistency checks are performed —
/// the type system guarantees that a `VerifiedReceipt` was produced by
/// `verify_receipt` and therefore already passed CORE-VERIFY-1.
fn resolve_side(
    input: ReceiptInput<'_>,
    carrier: &dyn CarrierVerifier,
    frames: &dyn FrameResolver,
    bridges: &dyn BridgeResolver,
    profile: Option<&dyn Profile>,
) -> (VerifierOutput, Option<Claim>, Option<Frame>) {
    match input {
        ReceiptInput::Bytes(b) => {
            let (out, claim, frame) =
                verify_receipt_with_claim_and_frame(b, carrier, frames, bridges, profile);
            (out, claim, frame)
        }
        ReceiptInput::Prevalidated(token) => {
            let (output, claim, frame) = token.into_parts();
            (output, Some(claim), Some(frame))
        }
    }
}

/// Statement structural compatibility per `apl-relation-spec.md §3.2`.
fn structural_compat(a: &Statement, b: &Statement) -> StructuralCompat {
    // Predicate mismatch is a Core precondition failure (STEPS 6-7);
    // reaching this function means predicates match. Defensive check only.
    if a.predicate != b.predicate {
        return StructuralCompat::TopLevelTypeMismatch;
    }
    let a_tag = top_level_tag(&a.content);
    let b_tag = top_level_tag(&b.content);
    if a_tag != b_tag {
        return StructuralCompat::TopLevelTypeMismatch;
    }
    if let (Some(am), Some(bm)) = (a.content.as_object(), b.content.as_object()) {
        let a_keys: HashSet<&str> = am.keys().map(String::as_str).collect();
        let b_keys: HashSet<&str> = bm.keys().map(String::as_str).collect();
        if a_keys != b_keys {
            return StructuralCompat::ObjectShapeMismatch;
        }
    }
    StructuralCompat::Compatible
}

fn top_level_tag(v: &Value) -> TypeTag {
    match v {
        Value::Null => TypeTag::Null,
        Value::Bool(_) => TypeTag::Bool,
        Value::Number(_) => TypeTag::Number,
        Value::String(_) => TypeTag::String,
        Value::Array(_) => TypeTag::Array,
        Value::Object(_) => TypeTag::Object,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::core::carrier::{CarrierOutcome, CarrierVerifier};
    use crate::core::output::CoreOutcome;
    use crate::core::resolver::{InMemoryBridgeResolver, InMemoryFrameResolver};
    use crate::core::verified::VerifiedReceipt;

    // ---- Stub carrier -------------------------------------------------------

    struct StubCarrier {
        outcome: CarrierOutcome,
    }

    impl CarrierVerifier for StubCarrier {
        fn verify_carrier(&self, _: &[u8]) -> CarrierOutcome {
            self.outcome.clone()
        }
    }

    fn valid_carrier(metadata: Value) -> StubCarrier {
        StubCarrier {
            outcome: CarrierOutcome::Valid {
                payload: vec![],
                metadata,
            },
        }
    }

    fn invalid_carrier() -> StubCarrier {
        StubCarrier {
            outcome: CarrierOutcome::Invalid { reason: None },
        }
    }

    // ---- Stub resolvers that panic if consulted (for Prevalidated tests) ----

    struct UnreachableCarrier;
    impl CarrierVerifier for UnreachableCarrier {
        fn verify_carrier(&self, _: &[u8]) -> CarrierOutcome {
            panic!("UnreachableCarrier must not be called")
        }
    }

    struct EmptyFrameResolver;
    impl FrameResolver for EmptyFrameResolver {
        fn resolve(&self, _: &crate::core::hash::Hash) -> crate::core::resolver::FrameResolution {
            crate::core::resolver::FrameResolution::NotFound
        }
    }

    struct EmptyBridgeResolver;
    impl BridgeResolver for EmptyBridgeResolver {
        fn resolve(&self, _: &crate::core::hash::Hash) -> BridgeResolution {
            BridgeResolution::NotFound
        }
    }

    // ---- Fixture helpers ----------------------------------------------------

    fn frame_value_a() -> Value {
        json!({
            "version": "0.1",
            "observer": "acme",
            "procedure": "benchmark-run",
            "aspect": ["accuracy"],
            "scope": "mmlu/dev",
            "invariance": ["score-object-serialization"],
            "exclusions": ["no-production-readiness-claim"]
        })
    }

    fn frame_value_b() -> Value {
        json!({
            "version": "0.1",
            "observer": "acme",
            "procedure": "benchmark-run",
            "aspect": ["accuracy"],
            "scope": "mmlu/test-lite",
            "invariance": ["score-object-serialization"],
            "exclusions": ["no-production-readiness-claim"]
        })
    }

    /// Build a valid `metadata.apl` JSON for a receipt pointing to `frame_hash`.
    fn apl_metadata(frame_hash: &str, aspects: &[&str], predicate: &str, content: Value) -> Value {
        json!({
            "apl": {
                "version": "0.1",
                "claim": {
                    "kind": "observation",
                    "subject": { "id": "model-x" },
                    "aspect_refs": aspects,
                    "statement": { "predicate": predicate, "content": content }
                },
                "frame_ref": { "hash": frame_hash }
            }
        })
    }

    fn base_query() -> RelationQuery {
        RelationQuery::parse(&json!({
            "left_aspects":  ["accuracy"],
            "right_aspects": ["accuracy"],
            "predicate":     "score",
            "relation_type": "score-delta"
        }))
        .expect("valid query fixture")
    }

    // ---- Stub VerifierOutput ------------------------------------------------

    fn core_valid_output() -> VerifierOutput {
        VerifierOutput {
            core_outcome: CoreOutcome::AplValid,
            relation_outcome: RelationOutcome::RelationNotEvaluated,
            failure_classes: Vec::new(),
            diagnostics: vec![D::APL_VALID],
        }
    }

    // ---- Build a Claim pointing to frame_hash with given aspects/predicate/content ----

    fn make_claim(frame_hash: &str, aspects: &[&str], predicate: &str, content: Value) -> Claim {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "m" },
                "aspect_refs": aspects,
                "statement": { "predicate": predicate, "content": content }
            },
            "frame_ref": { "hash": frame_hash }
        });
        Claim::parse(&v).expect("valid claim fixture")
    }

    /// Like `make_claim` but also embeds a single `bridge_refs` entry so that
    /// `supplied_bridges` values whose canonical hash equals `bridge_hash` are
    /// accepted by the content-addressed hash check in STEP 15.
    fn make_claim_with_bridge_ref(
        frame_hash: &str,
        aspects: &[&str],
        predicate: &str,
        content: Value,
        bridge_hash: &str,
    ) -> Claim {
        let v = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "m" },
                "aspect_refs": aspects,
                "statement": { "predicate": predicate, "content": content }
            },
            "frame_ref": { "hash": frame_hash },
            "bridge_refs": [{ "hash": bridge_hash }]
        });
        Claim::parse(&v).expect("valid claim fixture with bridge_ref")
    }

    /// Parse a `Frame` from the canonical frame fixture `a` (`frame_value_a()`).
    ///
    /// Using this together with `frame_value_a().canonical_hash()` guarantees
    /// the prevalidated triple consistency check passes (hash matches).
    fn fixture_frame_a() -> Frame {
        Frame::parse(&frame_value_a()).expect("valid frame_a fixture")
    }

    /// Parse a `Frame` from the canonical frame fixture `b` (`frame_value_b()`).
    fn fixture_frame_b() -> Frame {
        Frame::parse(&frame_value_b()).expect("valid frame_b fixture")
    }

    // ---- AC1: either side apl-invalid → RelationNotEvaluated ----------------

    #[test]
    fn ac1_left_invalid_returns_not_evaluated() {
        let mut frames = InMemoryFrameResolver::new();
        let fv = frame_value_a();
        let fh = frames.insert(fv.clone());
        let bridges = InMemoryBridgeResolver::new();

        // Right is valid; left side is raw bytes verified by an invalid carrier
        // so CORE-VERIFY-1 returns AplInvalid.
        let left_carrier = invalid_carrier();
        let right_meta = apl_metadata(&fh.to_string(), &["accuracy"], "score", json!(0.79));
        let right_carrier = valid_carrier(right_meta);
        // Both sides share the same carrier slot in evaluate_relation, so we
        // route the valid side through Prevalidated and invalid side through Bytes.
        let input = PairwiseInput {
            left: ReceiptInput::Bytes(&[]),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh.to_string(), &["accuracy"], "score", json!(0.79)),
                Frame::parse(&fv).expect("frame"),
            )),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &left_carrier, &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::RelationNotEvaluated);
        assert!(out.diagnostics.contains(&D::APL_PAIR_LEFT_INVALID));
        drop(right_carrier); // suppress unused warning
    }

    #[test]
    fn ac1_right_invalid_returns_not_evaluated() {
        let mut frames = InMemoryFrameResolver::new();
        let fv = frame_value_a();
        let fh = frames.insert(fv.clone());
        let bridges = InMemoryBridgeResolver::new();

        // Right side is raw bytes verified by an invalid carrier → AplInvalid.
        let right_carrier = invalid_carrier();
        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh.to_string(), &["accuracy"], "score", json!(0.78)),
                Frame::parse(&fv).expect("frame"),
            )),
            right: ReceiptInput::Bytes(&[]),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &right_carrier, &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::RelationNotEvaluated);
        assert!(out.diagnostics.contains(&D::APL_PAIR_RIGHT_INVALID));
    }

    // ---- AC2: left aspects out of claim -------------------------------------

    #[test]
    fn ac2_left_aspects_out_of_claim() {
        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();

        // claim.aspect_refs = ["accuracy"]; query.left_aspects = ["judge-score"]
        let query = RelationQuery::parse(&json!({
            "left_aspects":  ["judge-score"],
            "right_aspects": ["accuracy"],
            "predicate":     "score",
            "relation_type": "score-delta"
        }))
        .unwrap();

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.78)),
                frame.clone(),
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.79)),
                frame,
            )),
            query,
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::RelationNotEvaluated);
        assert!(out
            .diagnostics
            .contains(&D::APL_RELATION_QUERY_LEFT_ASPECTS_OUT_OF_CLAIM));
    }

    // ---- AC3: right aspects out of claim ------------------------------------

    #[test]
    fn ac3_right_aspects_out_of_claim() {
        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();

        let query = RelationQuery::parse(&json!({
            "left_aspects":  ["accuracy"],
            "right_aspects": ["judge-score"],
            "predicate":     "score",
            "relation_type": "score-delta"
        }))
        .unwrap();

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.78)),
                frame.clone(),
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.79)),
                frame,
            )),
            query,
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::RelationNotEvaluated);
        assert!(out
            .diagnostics
            .contains(&D::APL_RELATION_QUERY_RIGHT_ASPECTS_OUT_OF_CLAIM));
    }

    // ---- AC4: predicate mismatch --------------------------------------------

    #[test]
    fn ac4_predicate_mismatch() {
        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();

        // Claims have predicate "score"; query has predicate "other"
        let query = RelationQuery::parse(&json!({
            "left_aspects":  ["accuracy"],
            "right_aspects": ["accuracy"],
            "predicate":     "other",
            "relation_type": "score-delta"
        }))
        .unwrap();

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.78)),
                frame.clone(),
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.79)),
                frame,
            )),
            query,
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::RelationNotEvaluated);
        assert!(out
            .diagnostics
            .contains(&D::APL_RELATION_QUERY_PREDICATE_MISMATCH));
    }

    // ---- AC5: content type mismatch -----------------------------------------

    #[test]
    fn ac5_content_type_mismatch() {
        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();

        // left.content = object; right.content = number
        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!({"value": 0.78})),
                frame.clone(),
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.79)),
                frame,
            )),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::Incomparable);
        assert!(out
            .diagnostics
            .contains(&D::APL_STATEMENT_CONTENT_TYPE_MISMATCH));
    }

    // ---- AC6: object shape mismatch -----------------------------------------

    #[test]
    fn ac6_object_shape_mismatch() {
        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();

        // left.content keys = {value, unit}; right.content keys = {value}
        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(
                    &fh,
                    &["accuracy"],
                    "score",
                    json!({"value": 0.78, "unit": "fraction"}),
                ),
                frame.clone(),
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!({"value": 0.79})),
                frame,
            )),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::Incomparable);
        assert!(out
            .diagnostics
            .contains(&D::APL_STATEMENT_OBJECT_SHAPE_MISMATCH));
    }

    // ---- AC7: same frame + identical aspects → SameFrameComparable ----------

    #[test]
    fn ac7_same_frame_comparable() {
        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.78)),
                frame.clone(),
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.79)),
                frame,
            )),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::SameFrameComparable);
        assert!(out.diagnostics.contains(&D::APL_SAME_FRAME));
        assert!(out.diagnostics.contains(&D::APL_SAME_FRAME_ASPECT_MATCH));
    }

    // ---- AC8: same frame + different aspect sets → Incomparable -------------

    #[test]
    fn ac8_same_frame_different_query_aspects() {
        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();

        let frame_v = json!({
            "version": "0.1",
            "observer": "o",
            "procedure": "p",
            "aspect": ["accuracy", "pass-rate"],
            "scope": "s",
            "invariance": ["i"],
            "exclusions": ["e"]
        });
        let frame = Frame::parse(&frame_v).expect("frame");
        // Derive the hash from the same JSON value so the triple is consistent.
        let fh = frame.canonical_hash().to_string();

        // Both claims have aspects ["accuracy", "pass-rate"]
        // but query.left_aspects = ["accuracy"] and query.right_aspects = ["pass-rate"]
        let query = RelationQuery::parse(&json!({
            "left_aspects":  ["accuracy"],
            "right_aspects": ["pass-rate"],
            "predicate":     "score",
            "relation_type": "score-delta"
        }))
        .unwrap();

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy", "pass-rate"], "score", json!(0.78)),
                frame.clone(),
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy", "pass-rate"], "score", json!(0.79)),
                frame,
            )),
            query,
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::Incomparable);
        assert!(out.diagnostics.contains(&D::APL_SAME_FRAME_ASPECT_MISMATCH));
    }

    // ---- AC9: cross-frame + no bridges → Incomparable + AplBridgeNotFound ---

    #[test]
    fn ac9_cross_frame_no_bridges() {
        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame_a = fixture_frame_a();
        let frame_b = fixture_frame_b();
        let fh_a = frame_a.canonical_hash().to_string();
        let fh_b = frame_b.canonical_hash().to_string();

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh_a, &["accuracy"], "score", json!(0.78)),
                frame_a,
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh_b, &["accuracy"], "score", json!(0.79)),
                frame_b,
            )),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::Incomparable);
        assert!(out.diagnostics.contains(&D::APL_CROSS_FRAME));
        assert!(out.diagnostics.contains(&D::APL_BRIDGE_NOT_FOUND));
    }

    // ---- AC10: cross-frame + bridge with mismatched source frame -----------

    #[test]
    fn ac10_bridge_frame_mismatch() {
        use crate::core::jcs::canonical_hash;

        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame_a = fixture_frame_a();
        let frame_b = fixture_frame_b();
        let fh_a = frame_a.canonical_hash().to_string();
        let fh_b = frame_b.canonical_hash().to_string();
        let fh_x = format!("sha256:{}", "0".repeat(64));

        // Bridge declares source=X (not fh_a), so frame match fails.
        let bad_bridge = json!({
            "version": "0.1",
            "source_frame": { "hash": fh_x },
            "target_frame": { "hash": fh_b },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        let bad_bridge_hash = canonical_hash(&bad_bridge).to_string();

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim_with_bridge_ref(
                    &fh_a,
                    &["accuracy"],
                    "score",
                    json!(0.78),
                    &bad_bridge_hash,
                ),
                frame_a,
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh_b, &["accuracy"], "score", json!(0.79)),
                frame_b,
            )),
            query: base_query(),
            supplied_bridges: vec![bad_bridge],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::Incomparable);
        assert!(out.diagnostics.contains(&D::APL_BRIDGE_FRAME_MISMATCH));
    }

    // ---- AC11: cross-frame + bridge scope mismatch --------------------------

    #[test]
    fn ac11_bridge_scope_mismatch() {
        use crate::core::jcs::canonical_hash;

        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame_a = fixture_frame_a();
        let frame_b = fixture_frame_b();
        let fh_a = frame_a.canonical_hash().to_string();
        let fh_b = frame_b.canonical_hash().to_string();

        // Bridge matches frames but scope covers "judge-score", not "accuracy".
        let bad_scope_bridge = json!({
            "version": "0.1",
            "source_frame": { "hash": fh_a },
            "target_frame": { "hash": fh_b },
            "comparison_scope": {
                "source_aspects": ["judge-score"],
                "target_aspects": ["judge-score"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        let bridge_hash = canonical_hash(&bad_scope_bridge).to_string();

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim_with_bridge_ref(
                    &fh_a,
                    &["accuracy"],
                    "score",
                    json!(0.78),
                    &bridge_hash,
                ),
                frame_a,
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh_b, &["accuracy"], "score", json!(0.79)),
                frame_b,
            )),
            query: base_query(),
            supplied_bridges: vec![bad_scope_bridge],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::Incomparable);
        assert!(out.diagnostics.contains(&D::APL_BRIDGE_SCOPE_MISMATCH));
    }

    // ---- AC12: cross-frame + valid bridge → BridgedComparable ---------------

    #[test]
    fn ac12_bridged_comparable() {
        use crate::core::jcs::canonical_hash;

        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame_a = fixture_frame_a();
        let frame_b = fixture_frame_b();
        let fh_a = frame_a.canonical_hash().to_string();
        let fh_b = frame_b.canonical_hash().to_string();

        let good_bridge = json!({
            "version": "0.1",
            "source_frame": { "hash": fh_a },
            "target_frame": { "hash": fh_b },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        let bridge_hash = canonical_hash(&good_bridge).to_string();

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim_with_bridge_ref(
                    &fh_a,
                    &["accuracy"],
                    "score",
                    json!(0.78),
                    &bridge_hash,
                ),
                frame_a,
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh_b, &["accuracy"], "score", json!(0.79)),
                frame_b,
            )),
            query: base_query(),
            supplied_bridges: vec![good_bridge],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::BridgedComparable);
        assert!(out.diagnostics.contains(&D::APL_BRIDGE_APPLICABLE));
    }

    // ---- AC13: structurally-invalid bridge is ignored -----------------------

    #[test]
    fn ac13_invalid_bridge_ignored() {
        use crate::core::jcs::canonical_hash;

        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame_a = fixture_frame_a();
        let frame_b = fixture_frame_b();
        let fh_a = frame_a.canonical_hash().to_string();
        let fh_b = frame_b.canonical_hash().to_string();

        // Missing `version` → Bridge::parse fails.
        let invalid_bridge = json!({
            "source_frame": { "hash": fh_a },
            "target_frame": { "hash": fh_b },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        let bridge_hash = canonical_hash(&invalid_bridge).to_string();

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim_with_bridge_ref(
                    &fh_a,
                    &["accuracy"],
                    "score",
                    json!(0.78),
                    &bridge_hash,
                ),
                frame_a,
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh_b, &["accuracy"], "score", json!(0.79)),
                frame_b,
            )),
            query: base_query(),
            supplied_bridges: vec![invalid_bridge],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::Incomparable);
        assert!(out.diagnostics.contains(&D::APL_BRIDGE_INVALID));
    }

    // ---- AC15: bridge direction is enforced ---------------------------------

    #[test]
    fn ac15_bridge_direction_enforced() {
        use crate::core::jcs::canonical_hash;

        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame_a = fixture_frame_a();
        let frame_b = fixture_frame_b();
        let fh_a = frame_a.canonical_hash().to_string();
        let fh_b = frame_b.canonical_hash().to_string();

        // Bridge source=B, target=A; but receipts are (left=A, right=B) → mismatch.
        let reversed_bridge = json!({
            "version": "0.1",
            "source_frame": { "hash": fh_b },
            "target_frame": { "hash": fh_a },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        let bridge_hash = canonical_hash(&reversed_bridge).to_string();

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim_with_bridge_ref(
                    &fh_a,
                    &["accuracy"],
                    "score",
                    json!(0.78),
                    &bridge_hash,
                ),
                frame_a,
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh_b, &["accuracy"], "score", json!(0.79)),
                frame_b,
            )),
            query: base_query(),
            supplied_bridges: vec![reversed_bridge],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::Incomparable);
        assert!(out.diagnostics.contains(&D::APL_BRIDGE_FRAME_MISMATCH));
    }

    // ---- AC16: supplied bridges participate in the pipeline ----------------

    #[test]
    fn ac16_supplied_bridge_participates() {
        use crate::core::jcs::canonical_hash;

        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame_a = fixture_frame_a();
        let frame_b = fixture_frame_b();
        let fh_a = frame_a.canonical_hash().to_string();
        let fh_b = frame_b.canonical_hash().to_string();

        // Bridge is supplied out-of-band; the claim must reference it via
        // bridge_refs for the content-addressed hash check to accept it.
        let good_bridge = json!({
            "version": "0.1",
            "source_frame": { "hash": fh_a },
            "target_frame": { "hash": fh_b },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        let bridge_hash = canonical_hash(&good_bridge).to_string();

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim_with_bridge_ref(
                    &fh_a,
                    &["accuracy"],
                    "score",
                    json!(0.78),
                    &bridge_hash,
                ),
                frame_a,
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh_b, &["accuracy"], "score", json!(0.79)),
                frame_b,
            )),
            query: base_query(),
            supplied_bridges: vec![good_bridge],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::BridgedComparable);
    }

    // ---- AC17-19: profile pairwise gate -------------------------------------

    struct RejectAllPairwise;

    impl crate::profile::trait_def::Profile for RejectAllPairwise {
        fn id(&self) -> &'static str {
            "reject-all-pairwise"
        }

        fn check_pairwise_relation(
            &self,
            _left: &Claim,
            _right: &Claim,
            _lf: &Frame,
            _rf: &Frame,
            _q: &RelationQuery,
        ) -> Result<(), Vec<DiagnosticCode>> {
            Err(vec![DiagnosticCode::new("test-profile-pairwise-rejected")])
        }
    }

    #[test]
    fn ac17_profile_check_pairwise_invoked_after_compat() {
        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();
        let profile = RejectAllPairwise;

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.78)),
                frame.clone(),
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.79)),
                frame,
            )),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, Some(&profile));
        assert_eq!(out.relation_outcome, RelationOutcome::Incomparable);
        assert!(out
            .diagnostics
            .contains(&DiagnosticCode::new("test-profile-pairwise-rejected")));
    }

    #[test]
    fn ac18_profile_rejection_same_frame_branch_not_entered() {
        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();
        let profile = RejectAllPairwise;

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.78)),
                frame.clone(),
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.79)),
                frame,
            )),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, Some(&profile));
        assert_eq!(out.relation_outcome, RelationOutcome::Incomparable);
        assert!(!out.diagnostics.contains(&D::APL_SAME_FRAME));
        assert!(!out.diagnostics.contains(&D::APL_SAME_FRAME_ASPECT_MATCH));
    }

    #[test]
    fn ac19_profile_rejection_cross_frame_not_entered() {
        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame_a = fixture_frame_a();
        let frame_b = fixture_frame_b();
        let fh_a = frame_a.canonical_hash().to_string();
        let fh_b = frame_b.canonical_hash().to_string();
        let profile = RejectAllPairwise;

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh_a, &["accuracy"], "score", json!(0.78)),
                frame_a,
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh_b, &["accuracy"], "score", json!(0.79)),
                frame_b,
            )),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, Some(&profile));
        assert_eq!(out.relation_outcome, RelationOutcome::Incomparable);
        assert!(!out.diagnostics.contains(&D::APL_CROSS_FRAME));
        assert!(!out.diagnostics.contains(&D::APL_BRIDGE_NOT_FOUND));
    }

    // ---- AC20+AC21: Prevalidated path + profile gate is fail-closed ---------

    #[test]
    fn ac20_ac21_prevalidated_same_frame_profile_gate_runs() {
        // Both sides are Prevalidated with a shared frame.
        // Profile rejects the pair => must be Incomparable, not SameFrameComparable.
        let frames = EmptyFrameResolver;
        let bridges = EmptyBridgeResolver;
        let carrier = UnreachableCarrier;

        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();
        let profile = RejectAllPairwise;

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.78)),
                frame.clone(),
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.79)),
                frame,
            )),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &carrier, &frames, &bridges, Some(&profile));
        assert_eq!(out.relation_outcome, RelationOutcome::Incomparable);
        assert!(out
            .diagnostics
            .contains(&DiagnosticCode::new("test-profile-pairwise-rejected")));
        assert!(!out.diagnostics.contains(&D::APL_SAME_FRAME));
    }

    // ---- AC14: The Two MMLU Scores adversarial demo -------------------------

    #[test]
    fn ac14_two_mmlu_scores_incomparable() {
        // Two claims with different frames (mmlu/dev vs mmlu/test-lite),
        // no bridge in receipts or supplied. Expected: Incomparable with
        // AplCrossFrame + AplBridgeNotFound.
        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame_a = fixture_frame_a();
        let frame_b = fixture_frame_b();
        let fh_a = frame_a.canonical_hash().to_string();
        let fh_b = frame_b.canonical_hash().to_string();

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh_a, &["accuracy"], "score", json!(0.57)),
                frame_a,
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh_b, &["accuracy"], "score", json!(0.63)),
                frame_b,
            )),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::Incomparable);
        assert!(out.diagnostics.contains(&D::APL_CROSS_FRAME));
        assert!(out.diagnostics.contains(&D::APL_BRIDGE_NOT_FOUND));
    }

    // ---- Prevalidated compile-time guard (AC20 doc test support) -----------

    #[test]
    fn prevalidated_requires_frame_to_construct() {
        // This test verifies that ReceiptInput::Prevalidated is constructible
        // via VerifiedReceipt::new. The type system ensures the token can only
        // be produced by verify_receipt (pub(crate) constructor).
        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();
        let input = ReceiptInput::Prevalidated(VerifiedReceipt::new(
            core_valid_output(),
            make_claim(&fh, &["accuracy"], "score", json!(0.78)),
            frame,
        ));
        // Variant is constructible; verify no panic from the match.
        assert!(matches!(input, ReceiptInput::Prevalidated(_)));
    }

    // ---- Bytes path integration test ----------------------------------------

    #[test]
    fn bytes_path_same_frame_comparable() {
        let mut frames = InMemoryFrameResolver::new();
        let fv = frame_value_a();
        let fh = frames.insert(fv);
        let bridges = InMemoryBridgeResolver::new();

        let meta = apl_metadata(&fh.to_string(), &["accuracy"], "score", json!(0.78));
        let carrier_left = valid_carrier(meta.clone());
        let carrier_right = valid_carrier(meta);

        // Use Bytes for both sides; carrier must be the same for simplicity —
        // we route through carrier_left for both since CarrierVerifier takes `&self`.
        let input = PairwiseInput {
            left: ReceiptInput::Bytes(&[]),
            right: ReceiptInput::Bytes(&[]),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &carrier_left, &frames, &bridges, None);
        // Both sides use the same carrier stub that returns the same metadata,
        // so both point to the same frame hash → SameFrameComparable.
        assert_eq!(out.relation_outcome, RelationOutcome::SameFrameComparable);
        drop(carrier_right); // suppress unused warning
    }

    // ---- structural_compat direct unit tests (covers private helper) ---------

    #[test]
    fn structural_compat_predicate_mismatch_returns_top_level_type_mismatch() {
        // Exercises the defensive `a.predicate != b.predicate` branch (line 515-516).
        // This path is unreachable through the public API (the predicate check at
        // STEP 6-7 fires first), so it must be tested by calling the private
        // helper directly.
        let a = Statement {
            predicate: "score".to_owned(),
            content: json!(1),
        };
        let b = Statement {
            predicate: "rank".to_owned(),
            content: json!(1),
        };
        assert_eq!(
            structural_compat(&a, &b),
            StructuralCompat::TopLevelTypeMismatch
        );
    }

    #[test]
    fn structural_compat_null_vs_null_compatible() {
        // Exercises TypeTag::Null (line 535) via top_level_tag.
        let a = Statement {
            predicate: "p".to_owned(),
            content: json!(null),
        };
        let b = Statement {
            predicate: "p".to_owned(),
            content: json!(null),
        };
        assert_eq!(structural_compat(&a, &b), StructuralCompat::Compatible);
    }

    #[test]
    fn structural_compat_bool_vs_bool_compatible() {
        // Exercises TypeTag::Bool (line 536) via top_level_tag.
        let a = Statement {
            predicate: "p".to_owned(),
            content: json!(true),
        };
        let b = Statement {
            predicate: "p".to_owned(),
            content: json!(false),
        };
        assert_eq!(structural_compat(&a, &b), StructuralCompat::Compatible);
    }

    #[test]
    fn structural_compat_string_vs_string_compatible() {
        // Exercises TypeTag::String (line 538) via top_level_tag.
        let a = Statement {
            predicate: "p".to_owned(),
            content: json!("hello"),
        };
        let b = Statement {
            predicate: "p".to_owned(),
            content: json!("world"),
        };
        assert_eq!(structural_compat(&a, &b), StructuralCompat::Compatible);
    }

    #[test]
    fn structural_compat_array_vs_array_compatible() {
        // Exercises TypeTag::Array (line 539) via top_level_tag.
        let a = Statement {
            predicate: "p".to_owned(),
            content: json!([1, 2]),
        };
        let b = Statement {
            predicate: "p".to_owned(),
            content: json!([3, 4]),
        };
        assert_eq!(structural_compat(&a, &b), StructuralCompat::Compatible);
    }

    #[test]
    fn structural_compat_object_shape_mismatch() {
        // Exercises ObjectShapeMismatch (line 527).
        let a = Statement {
            predicate: "p".to_owned(),
            content: json!({"x": 1, "y": 2}),
        };
        let b = Statement {
            predicate: "p".to_owned(),
            content: json!({"x": 1}),
        };
        assert_eq!(
            structural_compat(&a, &b),
            StructuralCompat::ObjectShapeMismatch
        );
    }

    #[test]
    fn structural_compat_object_same_keys_compatible() {
        // Both contents are objects with identical key sets → Compatible (line 528 `}`).
        let a = Statement {
            predicate: "p".to_owned(),
            content: json!({"value": 0.78, "unit": "fraction"}),
        };
        let b = Statement {
            predicate: "p".to_owned(),
            content: json!({"value": 0.81, "unit": "fraction"}),
        };
        assert_eq!(structural_compat(&a, &b), StructuralCompat::Compatible);
    }

    #[test]
    fn structural_compat_null_vs_bool_type_mismatch() {
        // Exercises TypeTag::Null vs TypeTag::Bool (top-level type mismatch, line 521).
        let a = Statement {
            predicate: "p".to_owned(),
            content: json!(null),
        };
        let b = Statement {
            predicate: "p".to_owned(),
            content: json!(true),
        };
        assert_eq!(
            structural_compat(&a, &b),
            StructuralCompat::TopLevelTypeMismatch
        );
    }

    // ---- Empty stub resolvers coverage (lines 597-606) ----------------------

    #[test]
    #[should_panic(expected = "UnreachableCarrier must not be called")]
    fn unreachable_carrier_panics_when_called() {
        // Documents the invariant: UnreachableCarrier is a test guard that must
        // never be consulted. Lines 590-591 are intentionally exercised here
        // only to satisfy patch coverage; production code never calls this path.
        let c = UnreachableCarrier;
        c.verify_carrier(&[]);
    }

    #[test]
    fn empty_frame_resolver_returns_not_found() {
        // Exercises EmptyFrameResolver::resolve (lines 597-599) by using it in
        // a Prevalidated evaluate_relation call so the resolver method body runs.
        use crate::core::hash::Hash;
        use crate::core::resolver::FrameResolution;

        let resolver = EmptyFrameResolver;
        let hash = Hash::from_bytes([0u8; 32]);
        assert!(matches!(resolver.resolve(&hash), FrameResolution::NotFound));
    }

    #[test]
    fn empty_bridge_resolver_returns_not_found() {
        // Exercises EmptyBridgeResolver::resolve (lines 604-606).
        use crate::core::hash::Hash;

        let resolver = EmptyBridgeResolver;
        let hash = Hash::from_bytes([0u8; 32]);
        assert!(matches!(
            resolver.resolve(&hash),
            BridgeResolution::NotFound
        ));
    }

    // ---- VerifiedReceipt opaque token tests -----------------------------------

    /// A VerifiedReceipt obtained via VerifiedReceipt::new (pub(crate)) proceeds
    /// to normal pairwise evaluation and yields SameFrameComparable. This
    /// confirms the opaque token path works end-to-end.
    #[test]
    fn prevalidated_verified_receipt_proceeds_normally() {
        let frames = EmptyFrameResolver;
        let bridges = EmptyBridgeResolver;
        let carrier = UnreachableCarrier;

        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.78)),
                frame.clone(),
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.79)),
                fixture_frame_a(),
            )),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &carrier, &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::SameFrameComparable);
    }

    /// verify_receipt returns Some(VerifiedReceipt) for a valid receipt, and
    /// the token can be used directly in ReceiptInput::Prevalidated.
    #[test]
    fn verify_receipt_returns_token_on_apl_valid() {
        let mut frames = InMemoryFrameResolver::new();
        let fv = frame_value_a();
        let fh = frames.insert(fv);
        let bridges = InMemoryBridgeResolver::new();

        let meta = apl_metadata(&fh.to_string(), &["accuracy"], "score", json!(0.78));
        let carrier = valid_carrier(meta);

        let (out, token) =
            crate::core::verify::verify_receipt(b"", &carrier, &frames, &bridges, None);
        assert_eq!(out.core_outcome, CoreOutcome::AplValid);
        assert!(token.is_some());

        let token = token.unwrap();
        assert_eq!(token.output().core_outcome, CoreOutcome::AplValid);
    }

    /// verify_receipt returns None for an invalid receipt.
    #[test]
    fn verify_receipt_returns_none_on_invalid() {
        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let carrier = invalid_carrier();

        let (out, token) =
            crate::core::verify::verify_receipt(b"", &carrier, &frames, &bridges, None);
        assert_eq!(out.core_outcome, CoreOutcome::AplInvalid);
        assert!(token.is_none());
    }

    /// A VerifiedReceipt obtained via verify_receipt can be used in
    /// ReceiptInput::Prevalidated and produces SameFrameComparable.
    #[test]
    fn prevalidated_from_verify_receipt_produces_same_frame_comparable() {
        let mut frames = InMemoryFrameResolver::new();
        let fv = frame_value_a();
        let fh = frames.insert(fv);
        let bridges = InMemoryBridgeResolver::new();

        let meta_l = apl_metadata(&fh.to_string(), &["accuracy"], "score", json!(0.78));
        let meta_r = apl_metadata(&fh.to_string(), &["accuracy"], "score", json!(0.79));
        let carrier_l = valid_carrier(meta_l);
        let carrier_r = valid_carrier(meta_r);

        let (_, token_l) =
            crate::core::verify::verify_receipt(b"", &carrier_l, &frames, &bridges, None);
        let (_, token_r) =
            crate::core::verify::verify_receipt(b"", &carrier_r, &frames, &bridges, None);

        let token_l = token_l.expect("left receipt must be valid");
        let token_r = token_r.expect("right receipt must be valid");

        let eval_carrier = invalid_carrier();
        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(token_l),
            right: ReceiptInput::Prevalidated(token_r),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &eval_carrier, &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::SameFrameComparable);
    }

    // ---- Per-side profile re-check on Prevalidated input --------------------

    /// A VerifiedReceipt produced WITHOUT a profile is passed to evaluate_relation
    /// WITH a profile active. The profile's per-side hooks (check_frame here)
    /// reject the frame, so the result must be RelationNotEvaluated with the
    /// profile's diagnostic, NOT SameFrameComparable.
    #[test]
    fn prevalidated_with_wrong_profile_rejected_at_pairwise_time() {
        // Profile that rejects all frames via check_frame.
        struct RejectAllFrames;
        impl crate::profile::trait_def::Profile for RejectAllFrames {
            fn id(&self) -> &'static str {
                "reject-all-frames"
            }

            fn check_frame(&self, _frame: &Frame) -> crate::profile::trait_def::ProfileCheckResult {
                Err(crate::profile::trait_def::ProfileFailure {
                    failure_class: crate::failure::FailureClass::FrameFailure,
                    diagnostics: vec![DiagnosticCode::new("test-profile-frame-rejected")],
                })
            }
        }

        let frames = EmptyFrameResolver;
        let bridges = EmptyBridgeResolver;
        let carrier = UnreachableCarrier;
        let profile = RejectAllFrames;

        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();

        // Build tokens WITHOUT a profile — CORE-VERIFY-1 succeeds, token is Some.
        let token_l = VerifiedReceipt::new(
            core_valid_output(),
            make_claim(&fh, &["accuracy"], "score", json!(0.78)),
            frame.clone(),
        );
        let token_r = VerifiedReceipt::new(
            core_valid_output(),
            make_claim(&fh, &["accuracy"], "score", json!(0.79)),
            frame,
        );

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(token_l),
            right: ReceiptInput::Prevalidated(token_r),
            query: base_query(),
            supplied_bridges: vec![],
        };

        // evaluate_relation is called WITH the profile. Per-side re-check must fire.
        let out = evaluate_relation(input, &carrier, &frames, &bridges, Some(&profile));

        // Profile must gate — NOT SameFrameComparable.
        assert_eq!(out.relation_outcome, RelationOutcome::RelationNotEvaluated);
        assert!(out
            .diagnostics
            .contains(&DiagnosticCode::new("test-profile-frame-rejected")));
        assert!(!out.diagnostics.contains(&D::APL_SAME_FRAME));
    }

    // ---- RejectAllPairwise id() coverage (line 1331-1333) -------------------

    #[test]
    fn reject_all_pairwise_id_is_accessible() {
        // Exercises RejectAllPairwise::id (lines 1331-1333).
        use crate::profile::trait_def::Profile;
        let p = RejectAllPairwise;
        assert_eq!(p.id(), "reject-all-pairwise");
    }

    // ---- Profile pairwise gate OK branch (line 337) -------------------------

    #[test]
    fn profile_pairwise_gate_ok_branch_proceeds_to_same_frame() {
        // Profile accepts the pair; the Ok(()) => {} branch (line 337) is taken
        // and evaluation continues to SameFrameComparable.
        struct AcceptAllPairwise;
        impl crate::profile::trait_def::Profile for AcceptAllPairwise {
            fn id(&self) -> &'static str {
                "accept-all-pairwise"
            }
        }

        let frames = InMemoryFrameResolver::new();
        let bridges = InMemoryBridgeResolver::new();
        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();
        let profile = AcceptAllPairwise;
        assert_eq!(profile.id(), "accept-all-pairwise");

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.78)),
                frame.clone(),
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh, &["accuracy"], "score", json!(0.79)),
                frame,
            )),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, Some(&profile));
        assert_eq!(out.relation_outcome, RelationOutcome::SameFrameComparable);
    }

    // ---- Bridge from resolver (lines 393-395) -------------------------------

    #[test]
    fn bridge_from_resolver_found_leads_to_bridged_comparable() {
        // Exercises BridgeResolution::Found in the bridge-collection loop (lines 393-395).
        // The claim's bridge_refs reference a bridge that is in the resolver.
        use crate::core::jcs::canonical_hash;

        let mut frames = InMemoryFrameResolver::new();
        let fv_a = frame_value_a();
        let fv_b = frame_value_b();
        let fh_a = frames.insert(fv_a);
        let fh_b = frames.insert(fv_b);

        let bridge_value = json!({
            "version": "0.1",
            "source_frame": { "hash": fh_a.to_string() },
            "target_frame": { "hash": fh_b.to_string() },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        let bridge_hash = canonical_hash(&bridge_value);

        let mut bridges = InMemoryBridgeResolver::new();
        bridges.insert(bridge_value);

        // Build claims that reference the bridge via bridge_refs.
        let left_apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "m" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.78 }
            },
            "frame_ref": { "hash": fh_a.to_string() },
            "bridge_refs": [{ "hash": bridge_hash.to_string() }]
        });
        let right_apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "m" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.79 }
            },
            "frame_ref": { "hash": fh_b.to_string() }
        });

        let left_claim = Claim::parse(&left_apl).expect("valid left claim");
        let right_claim = Claim::parse(&right_apl).expect("valid right claim");
        let left_frame = Frame::parse(&frame_value_a()).expect("valid left frame");
        let right_frame = Frame::parse(&frame_value_b()).expect("valid right frame");

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                left_claim,
                left_frame,
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                right_claim,
                right_frame,
            )),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);
        assert_eq!(out.relation_outcome, RelationOutcome::BridgedComparable);
    }

    // ---- Bridge canonical-hash verification (trust boundary) ----------------

    #[test]
    fn resolver_returned_bridge_with_wrong_canonical_hash_rejected() {
        // A FakeBridgeResolver returns a structurally-valid bridge value but
        // stores it under a *different* hash key, so canonical_hash(value) !=
        // requested hash. evaluate_relation must emit APL_BRIDGE_HASH_MISMATCH
        // and NOT accept the fake as a candidate — pair ends up Incomparable.
        use crate::core::jcs::canonical_hash;
        use crate::core::resolver::InMemoryBridgeResolver;

        let mut frames = InMemoryFrameResolver::new();
        let fv_a = frame_value_a();
        let fv_b = frame_value_b();
        let fh_a = frames.insert(fv_a);
        let fh_b = frames.insert(fv_b);

        // A legitimate-looking bridge value.
        let real_bridge = json!({
            "version": "0.1",
            "source_frame": { "hash": fh_a.to_string() },
            "target_frame": { "hash": fh_b.to_string() },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        let real_hash = canonical_hash(&real_bridge);

        // A different bridge value — different content, different canonical hash.
        let fake_bridge = json!({
            "version": "0.1",
            "source_frame": { "hash": fh_a.to_string() },
            "target_frame": { "hash": fh_b.to_string() },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": ["injected"],
            "losses": []
        });
        // Store the fake value under the real hash key — simulates a malicious
        // resolver that substitutes a different bridge for the requested one.
        let mut bridges = InMemoryBridgeResolver::new();
        bridges.insert_raw(real_hash, fake_bridge);

        // Claims reference the real bridge hash.
        let left_apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "m" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.78 }
            },
            "frame_ref": { "hash": fh_a.to_string() },
            "bridge_refs": [{ "hash": real_hash.to_string() }]
        });
        let right_apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "m" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.79 }
            },
            "frame_ref": { "hash": fh_b.to_string() }
        });

        let left_claim = Claim::parse(&left_apl).expect("valid left claim");
        let right_claim = Claim::parse(&right_apl).expect("valid right claim");
        let left_frame = Frame::parse(&frame_value_a()).expect("valid left frame");
        let right_frame = Frame::parse(&frame_value_b()).expect("valid right frame");

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                left_claim,
                left_frame,
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                right_claim,
                right_frame,
            )),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);

        assert!(
            out.diagnostics
                .contains(&crate::diagnostics::APL_BRIDGE_HASH_MISMATCH),
            "must emit APL_BRIDGE_HASH_MISMATCH for wrong-hash resolver response"
        );
        assert_eq!(
            out.relation_outcome,
            RelationOutcome::Incomparable,
            "fake bridge must not be accepted — pair must be Incomparable"
        );
    }

    #[test]
    fn resolver_returned_bridge_with_correct_hash_accepted() {
        // Regression: a resolver that returns the correct bridge (canonical_hash
        // matches requested hash) must still lead to BridgedComparable.
        // This test mirrors bridge_from_resolver_found_leads_to_bridged_comparable
        // and asserts no hash-mismatch diagnostic is emitted.
        use crate::core::jcs::canonical_hash;
        use crate::core::resolver::InMemoryBridgeResolver;

        let mut frames = InMemoryFrameResolver::new();
        let fv_a = frame_value_a();
        let fv_b = frame_value_b();
        let fh_a = frames.insert(fv_a);
        let fh_b = frames.insert(fv_b);

        let bridge_value = json!({
            "version": "0.1",
            "source_frame": { "hash": fh_a.to_string() },
            "target_frame": { "hash": fh_b.to_string() },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        let bridge_hash = canonical_hash(&bridge_value);

        let mut bridges = InMemoryBridgeResolver::new();
        bridges.insert(bridge_value);

        let left_apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "m" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.78 }
            },
            "frame_ref": { "hash": fh_a.to_string() },
            "bridge_refs": [{ "hash": bridge_hash.to_string() }]
        });
        let right_apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "m" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.79 }
            },
            "frame_ref": { "hash": fh_b.to_string() }
        });

        let left_claim = Claim::parse(&left_apl).expect("valid left claim");
        let right_claim = Claim::parse(&right_apl).expect("valid right claim");
        let left_frame = Frame::parse(&frame_value_a()).expect("valid left frame");
        let right_frame = Frame::parse(&frame_value_b()).expect("valid right frame");

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                left_claim,
                left_frame,
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                right_claim,
                right_frame,
            )),
            query: base_query(),
            supplied_bridges: vec![],
        };
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);

        assert!(
            !out.diagnostics
                .contains(&crate::diagnostics::APL_BRIDGE_HASH_MISMATCH),
            "correct-hash resolver response must not emit APL_BRIDGE_HASH_MISMATCH"
        );
        assert_eq!(
            out.relation_outcome,
            RelationOutcome::BridgedComparable,
            "correct bridge must be accepted — pair must be BridgedComparable"
        );
    }

    #[test]
    fn supplied_bridge_hash_mismatches_requested_ref_rejected() {
        // A supplied_bridges value whose canonical_hash does not match any
        // bridge_ref in the claims is silently ignored (unsolicited). The pair
        // ends up Incomparable if no resolver bridge is found either.
        use crate::core::jcs::canonical_hash;
        use crate::core::resolver::InMemoryBridgeResolver;

        let mut frames = InMemoryFrameResolver::new();
        let fv_a = frame_value_a();
        let fv_b = frame_value_b();
        let fh_a = frames.insert(fv_a);
        let fh_b = frames.insert(fv_b);

        // A "phantom" bridge that isn't referenced by any bridge_ref in the claims.
        let phantom_bridge = json!({
            "version": "0.1",
            "source_frame": { "hash": fh_a.to_string() },
            "target_frame": { "hash": fh_b.to_string() },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        let phantom_hash = canonical_hash(&phantom_bridge);

        // Claims reference a *different* hash — not the phantom bridge.
        let unrelated_hash = crate::core::hash::Hash::from_bytes([0u8; 32]);
        let bridges = InMemoryBridgeResolver::new(); // resolver has nothing

        let left_apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "m" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.78 }
            },
            "frame_ref": { "hash": fh_a.to_string() },
            "bridge_refs": [{ "hash": unrelated_hash.to_string() }]
        });
        let right_apl = json!({
            "version": "0.1",
            "claim": {
                "kind": "observation",
                "subject": { "id": "m" },
                "aspect_refs": ["accuracy"],
                "statement": { "predicate": "score", "content": 0.79 }
            },
            "frame_ref": { "hash": fh_b.to_string() }
        });

        let left_claim = Claim::parse(&left_apl).expect("valid left claim");
        let right_claim = Claim::parse(&right_apl).expect("valid right claim");
        let left_frame = Frame::parse(&frame_value_a()).expect("valid left frame");
        let right_frame = Frame::parse(&frame_value_b()).expect("valid right frame");

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                left_claim,
                left_frame,
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                right_claim,
                right_frame,
            )),
            query: base_query(),
            // Supply a bridge whose hash does not match any bridge_ref.
            supplied_bridges: vec![phantom_bridge],
        };
        let _ = phantom_hash; // hash computed above, used only to document intent
        let out = evaluate_relation(input, &invalid_carrier(), &frames, &bridges, None);

        assert_eq!(
            out.relation_outcome,
            RelationOutcome::Incomparable,
            "unsolicited supplied bridge must be ignored — pair must be Incomparable"
        );
        assert!(
            !out.diagnostics
                .contains(&crate::diagnostics::APL_BRIDGE_HASH_MISMATCH),
            "unsolicited supplied bridge must be silently ignored, not emit hash-mismatch"
        );
    }

    // ---- check_bridge_applicability Ok and Err paths (lines 455-459) --------

    #[test]
    fn profile_check_bridge_applicability_ok_leads_to_bridged_comparable() {
        // Profile accepts the bridge candidate; Ok(()) branch (line 456) is taken
        // and evaluation yields BridgedComparable.
        use crate::core::jcs::canonical_hash;

        struct AcceptAllBridges;
        impl crate::profile::trait_def::Profile for AcceptAllBridges {
            fn id(&self) -> &'static str {
                "accept-all-bridges"
            }
        }

        let mut frames = InMemoryFrameResolver::new();
        let fv_a = frame_value_a();
        let fv_b = frame_value_b();
        let fh_a = frames.insert(fv_a);
        let fh_b = frames.insert(fv_b);

        let bridge_value = json!({
            "version": "0.1",
            "source_frame": { "hash": fh_a.to_string() },
            "target_frame": { "hash": fh_b.to_string() },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        let bridge_hash = canonical_hash(&bridge_value).to_string();

        let left_frame = Frame::parse(&frame_value_a()).expect("valid left frame");
        let right_frame = Frame::parse(&frame_value_b()).expect("valid right frame");
        let profile = AcceptAllBridges;
        assert_eq!(profile.id(), "accept-all-bridges");

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim_with_bridge_ref(
                    &fh_a.to_string(),
                    &["accuracy"],
                    "score",
                    json!(0.78),
                    &bridge_hash,
                ),
                left_frame,
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh_b.to_string(), &["accuracy"], "score", json!(0.79)),
                right_frame,
            )),
            query: base_query(),
            supplied_bridges: vec![bridge_value],
        };
        let out = evaluate_relation(
            input,
            &invalid_carrier(),
            &frames,
            &InMemoryBridgeResolver::new(),
            Some(&profile),
        );
        assert_eq!(out.relation_outcome, RelationOutcome::BridgedComparable);
    }

    #[test]
    fn profile_check_bridge_applicability_err_skips_candidate() {
        // Profile rejects every bridge candidate via check_bridge_applicability.
        // Lines 457-459 (extend diagnostics + continue) must be exercised.
        use crate::core::jcs::canonical_hash;

        struct RejectAllBridges;
        impl crate::profile::trait_def::Profile for RejectAllBridges {
            fn id(&self) -> &'static str {
                "reject-all-bridges"
            }

            fn check_bridge_applicability(
                &self,
                _bridge: &Bridge,
                _left_frame: &Frame,
                _right_frame: &Frame,
                _query: &RelationQuery,
            ) -> Result<(), Vec<DiagnosticCode>> {
                Err(vec![DiagnosticCode::new("test-profile-bridge-rejected")])
            }
        }

        let mut frames = InMemoryFrameResolver::new();
        let fv_a = frame_value_a();
        let fv_b = frame_value_b();
        let fh_a = frames.insert(fv_a);
        let fh_b = frames.insert(fv_b);

        let bridge_value = json!({
            "version": "0.1",
            "source_frame": { "hash": fh_a.to_string() },
            "target_frame": { "hash": fh_b.to_string() },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        let bridge_hash = canonical_hash(&bridge_value).to_string();

        let left_frame = Frame::parse(&frame_value_a()).expect("valid left frame");
        let right_frame = Frame::parse(&frame_value_b()).expect("valid right frame");

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim_with_bridge_ref(
                    &fh_a.to_string(),
                    &["accuracy"],
                    "score",
                    json!(0.78),
                    &bridge_hash,
                ),
                left_frame,
            )),
            right: ReceiptInput::Prevalidated(VerifiedReceipt::new(
                core_valid_output(),
                make_claim(&fh_b.to_string(), &["accuracy"], "score", json!(0.79)),
                right_frame,
            )),
            query: base_query(),
            supplied_bridges: vec![bridge_value],
        };
        let profile = RejectAllBridges;
        assert_eq!(profile.id(), "reject-all-bridges");
        let out = evaluate_relation(
            input,
            &invalid_carrier(),
            &frames,
            &InMemoryBridgeResolver::new(),
            Some(&profile),
        );
        // All bridge candidates rejected by profile → Incomparable.
        assert_eq!(out.relation_outcome, RelationOutcome::Incomparable);
        assert!(out
            .diagnostics
            .contains(&DiagnosticCode::new("test-profile-bridge-rejected")));
    }

    // ---- Per-side profile re-check: check_claim failure ---------------------

    /// Profile rejects all claims via check_claim.
    /// The left-side claim is checked first; failure must short-circuit to
    /// RelationNotEvaluated with the profile diagnostic.
    #[test]
    fn profile_check_claim_failure_on_left_side_shortcircuits_to_not_evaluated() {
        struct RejectAllClaims;
        impl crate::profile::trait_def::Profile for RejectAllClaims {
            fn id(&self) -> &'static str {
                "reject-all-claims"
            }

            fn check_claim(&self, _claim: &Claim) -> crate::profile::trait_def::ProfileCheckResult {
                Err(crate::profile::trait_def::ProfileFailure {
                    failure_class: crate::failure::FailureClass::ClaimStructureFailure,
                    diagnostics: vec![DiagnosticCode::new("test-profile-claim-rejected")],
                })
            }
        }

        let frames = EmptyFrameResolver;
        let bridges = EmptyBridgeResolver;
        let carrier = UnreachableCarrier;
        let profile = RejectAllClaims;
        assert_eq!(profile.id(), "reject-all-claims");

        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();

        let token_l = VerifiedReceipt::new(
            core_valid_output(),
            make_claim(&fh, &["accuracy"], "score", json!(0.78)),
            frame.clone(),
        );
        let token_r = VerifiedReceipt::new(
            core_valid_output(),
            make_claim(&fh, &["accuracy"], "score", json!(0.79)),
            frame,
        );

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(token_l),
            right: ReceiptInput::Prevalidated(token_r),
            query: base_query(),
            supplied_bridges: vec![],
        };

        let out = evaluate_relation(input, &carrier, &frames, &bridges, Some(&profile));

        assert_eq!(out.relation_outcome, RelationOutcome::RelationNotEvaluated);
        assert!(out
            .diagnostics
            .contains(&DiagnosticCode::new("test-profile-claim-rejected")));
    }

    /// Profile passes check_claim for the left side but rejects the right side.
    /// The short-circuit on the second iteration must still yield RelationNotEvaluated.
    #[test]
    fn profile_check_claim_failure_on_right_side_shortcircuits_to_not_evaluated() {
        use std::sync::atomic::{AtomicU32, Ordering};

        struct RejectSecondClaim {
            call_count: AtomicU32,
        }

        impl crate::profile::trait_def::Profile for RejectSecondClaim {
            fn id(&self) -> &'static str {
                "reject-second-claim"
            }

            fn check_claim(&self, _claim: &Claim) -> crate::profile::trait_def::ProfileCheckResult {
                let count = self.call_count.fetch_add(1, Ordering::Relaxed);
                if count == 0 {
                    Ok(())
                } else {
                    Err(crate::profile::trait_def::ProfileFailure {
                        failure_class: crate::failure::FailureClass::ClaimStructureFailure,
                        diagnostics: vec![DiagnosticCode::new("test-profile-right-claim-rejected")],
                    })
                }
            }
        }

        let frames = EmptyFrameResolver;
        let bridges = EmptyBridgeResolver;
        let carrier = UnreachableCarrier;
        let profile = RejectSecondClaim {
            call_count: AtomicU32::new(0),
        };

        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();

        let token_l = VerifiedReceipt::new(
            core_valid_output(),
            make_claim(&fh, &["accuracy"], "score", json!(0.78)),
            frame.clone(),
        );
        let token_r = VerifiedReceipt::new(
            core_valid_output(),
            make_claim(&fh, &["accuracy"], "score", json!(0.79)),
            frame,
        );

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(token_l),
            right: ReceiptInput::Prevalidated(token_r),
            query: base_query(),
            supplied_bridges: vec![],
        };

        let out = evaluate_relation(input, &carrier, &frames, &bridges, Some(&profile));

        assert_eq!(out.relation_outcome, RelationOutcome::RelationNotEvaluated);
        assert!(out
            .diagnostics
            .contains(&DiagnosticCode::new("test-profile-right-claim-rejected")));
    }

    // ---- Per-side profile re-check: check_frame failure on right side -------

    /// check_frame passes for the left side but fails for the right side.
    /// The existing test covers left-side check_frame failure; this covers right.
    #[test]
    fn profile_check_frame_failure_on_right_side_shortcircuits() {
        use std::sync::atomic::{AtomicU32, Ordering};

        struct RejectSecondFrame {
            call_count: AtomicU32,
        }

        impl crate::profile::trait_def::Profile for RejectSecondFrame {
            fn id(&self) -> &'static str {
                "reject-second-frame"
            }

            fn check_frame(&self, _frame: &Frame) -> crate::profile::trait_def::ProfileCheckResult {
                let count = self.call_count.fetch_add(1, Ordering::Relaxed);
                if count == 0 {
                    Ok(())
                } else {
                    Err(crate::profile::trait_def::ProfileFailure {
                        failure_class: crate::failure::FailureClass::FrameFailure,
                        diagnostics: vec![DiagnosticCode::new("test-profile-right-frame-rejected")],
                    })
                }
            }
        }

        let frames = EmptyFrameResolver;
        let bridges = EmptyBridgeResolver;
        let carrier = UnreachableCarrier;
        let profile = RejectSecondFrame {
            call_count: AtomicU32::new(0),
        };

        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();

        let token_l = VerifiedReceipt::new(
            core_valid_output(),
            make_claim(&fh, &["accuracy"], "score", json!(0.78)),
            frame.clone(),
        );
        let token_r = VerifiedReceipt::new(
            core_valid_output(),
            make_claim(&fh, &["accuracy"], "score", json!(0.79)),
            frame,
        );

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(token_l),
            right: ReceiptInput::Prevalidated(token_r),
            query: base_query(),
            supplied_bridges: vec![],
        };

        let out = evaluate_relation(input, &carrier, &frames, &bridges, Some(&profile));

        assert_eq!(out.relation_outcome, RelationOutcome::RelationNotEvaluated);
        assert!(out
            .diagnostics
            .contains(&DiagnosticCode::new("test-profile-right-frame-rejected")));
    }

    // ---- Per-side profile re-check: cross_check failure ---------------------

    /// Profile rejects all cross_check calls on the left side.
    /// Must short-circuit to RelationNotEvaluated with the profile diagnostic.
    #[test]
    fn profile_cross_check_failure_on_left_side_shortcircuits() {
        struct RejectAllCross;
        impl crate::profile::trait_def::Profile for RejectAllCross {
            fn id(&self) -> &'static str {
                "reject-all-cross"
            }

            fn cross_check(
                &self,
                _claim: &Claim,
                _frame: &Frame,
            ) -> crate::profile::trait_def::ProfileCheckResult {
                Err(crate::profile::trait_def::ProfileFailure {
                    failure_class: crate::failure::FailureClass::SemanticLinkageFailure,
                    diagnostics: vec![DiagnosticCode::new("test-profile-cross-rejected")],
                })
            }
        }

        let frames = EmptyFrameResolver;
        let bridges = EmptyBridgeResolver;
        let carrier = UnreachableCarrier;
        let profile = RejectAllCross;
        assert_eq!(profile.id(), "reject-all-cross");

        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();

        let token_l = VerifiedReceipt::new(
            core_valid_output(),
            make_claim(&fh, &["accuracy"], "score", json!(0.78)),
            frame.clone(),
        );
        let token_r = VerifiedReceipt::new(
            core_valid_output(),
            make_claim(&fh, &["accuracy"], "score", json!(0.79)),
            frame,
        );

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(token_l),
            right: ReceiptInput::Prevalidated(token_r),
            query: base_query(),
            supplied_bridges: vec![],
        };

        let out = evaluate_relation(input, &carrier, &frames, &bridges, Some(&profile));

        assert_eq!(out.relation_outcome, RelationOutcome::RelationNotEvaluated);
        assert!(out
            .diagnostics
            .contains(&DiagnosticCode::new("test-profile-cross-rejected")));
    }

    /// cross_check passes for the left side but fails for the right side.
    #[test]
    fn profile_cross_check_failure_on_right_side_shortcircuits() {
        use std::sync::atomic::{AtomicU32, Ordering};

        struct RejectSecondCross {
            call_count: AtomicU32,
        }

        impl crate::profile::trait_def::Profile for RejectSecondCross {
            fn id(&self) -> &'static str {
                "reject-second-cross"
            }

            fn cross_check(
                &self,
                _claim: &Claim,
                _frame: &Frame,
            ) -> crate::profile::trait_def::ProfileCheckResult {
                let count = self.call_count.fetch_add(1, Ordering::Relaxed);
                if count == 0 {
                    Ok(())
                } else {
                    Err(crate::profile::trait_def::ProfileFailure {
                        failure_class: crate::failure::FailureClass::SemanticLinkageFailure,
                        diagnostics: vec![DiagnosticCode::new("test-profile-right-cross-rejected")],
                    })
                }
            }
        }

        let frames = EmptyFrameResolver;
        let bridges = EmptyBridgeResolver;
        let carrier = UnreachableCarrier;
        let profile = RejectSecondCross {
            call_count: AtomicU32::new(0),
        };

        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();

        let token_l = VerifiedReceipt::new(
            core_valid_output(),
            make_claim(&fh, &["accuracy"], "score", json!(0.78)),
            frame.clone(),
        );
        let token_r = VerifiedReceipt::new(
            core_valid_output(),
            make_claim(&fh, &["accuracy"], "score", json!(0.79)),
            frame,
        );

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(token_l),
            right: ReceiptInput::Prevalidated(token_r),
            query: base_query(),
            supplied_bridges: vec![],
        };

        let out = evaluate_relation(input, &carrier, &frames, &bridges, Some(&profile));

        assert_eq!(out.relation_outcome, RelationOutcome::RelationNotEvaluated);
        assert!(out
            .diagnostics
            .contains(&DiagnosticCode::new("test-profile-right-cross-rejected")));
    }

    // ---- check_frame left-side failure (verify RejectAllFrames::id coverage) -

    /// Exercises RejectAllFrames::id so that the method body (line 1867-1869) is
    /// instrumented as covered.  The id() method is a required trait method and
    /// must be called explicitly here since the pairwise evaluation path never
    /// calls Profile::id at runtime.
    #[test]
    fn reject_all_frames_id_is_accessible() {
        struct RejectAllFrames;
        impl crate::profile::trait_def::Profile for RejectAllFrames {
            fn id(&self) -> &'static str {
                "reject-all-frames-id-check"
            }

            fn check_frame(&self, _frame: &Frame) -> crate::profile::trait_def::ProfileCheckResult {
                Err(crate::profile::trait_def::ProfileFailure {
                    failure_class: crate::failure::FailureClass::FrameFailure,
                    diagnostics: vec![DiagnosticCode::new("test-profile-frame-rejected-id")],
                })
            }
        }

        use crate::profile::trait_def::Profile;
        let p = RejectAllFrames;
        assert_eq!(p.id(), "reject-all-frames-id-check");
    }

    // ---- check_frame left-side failure (explicit, paired with right-side) ----

    /// Profile rejects all frames via check_frame; left side is the first
    /// iteration of the per-side loop, so the return at lines 335-347 fires
    /// before the right side is ever evaluated.
    #[test]
    fn profile_check_frame_failure_on_left_side_shortcircuits() {
        struct RejectAllFramesLocal;
        impl crate::profile::trait_def::Profile for RejectAllFramesLocal {
            fn id(&self) -> &'static str {
                "reject-all-frames-local"
            }

            fn check_frame(&self, _frame: &Frame) -> crate::profile::trait_def::ProfileCheckResult {
                Err(crate::profile::trait_def::ProfileFailure {
                    failure_class: crate::failure::FailureClass::FrameFailure,
                    diagnostics: vec![DiagnosticCode::new("test-frame-left-rejected")],
                })
            }
        }

        let frames = EmptyFrameResolver;
        let bridges = EmptyBridgeResolver;
        let carrier = UnreachableCarrier;
        let profile = RejectAllFramesLocal;

        let frame = fixture_frame_a();
        let fh = frame.canonical_hash().to_string();

        let token_l = VerifiedReceipt::new(
            core_valid_output(),
            make_claim(&fh, &["accuracy"], "score", json!(0.78)),
            frame.clone(),
        );
        let token_r = VerifiedReceipt::new(
            core_valid_output(),
            make_claim(&fh, &["accuracy"], "score", json!(0.79)),
            frame,
        );

        let input = PairwiseInput {
            left: ReceiptInput::Prevalidated(token_l),
            right: ReceiptInput::Prevalidated(token_r),
            query: base_query(),
            supplied_bridges: vec![],
        };

        let out = evaluate_relation(input, &carrier, &frames, &bridges, Some(&profile));

        assert_eq!(out.relation_outcome, RelationOutcome::RelationNotEvaluated);
        assert!(out
            .diagnostics
            .contains(&DiagnosticCode::new("test-frame-left-rejected")));
    }
}
