//! Diagnostic status codes per `apl-spec.md §12.3`,
//! `apl-relation-spec.md §9`, and `apl-ai-eval-profile.md §7.8`.
//!
//! Diagnostics are opaque string tokens that map 1-to-1 to the kebab-case
//! strings in the normative sources. They MUST NOT carry payload — they are
//! opaque markers only.
//!
//! # Extensibility
//!
//! [`DiagnosticCode`] is a `#[repr(transparent)]` newtype over `&'static str`.
//! New codes can be added without a breaking change: callers pattern-match on
//! values they know and ignore unknown codes via the catch-all `_` arm
//! (or comparison with the named constants in this module).
//!
//! # Deserialization (whitelist)
//!
//! `DiagnosticCode` is deserialized against a process-wide whitelist of
//! registered codes. apl-core auto-registers its core and pairwise constants
//! on first deserialize. Vertical profiles (e.g. `apl-ai-eval`) expose a
//! `register()` function that downstream applications call once at startup
//! to extend the registry with profile-specific codes. Any code NOT in the
//! registry at deserialize time yields a serde error.
//!
//! This is a deliberate trust boundary: arbitrary strings from untrusted JSON
//! cannot silently grow the intern table.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Core type
// ---------------------------------------------------------------------------

/// An opaque diagnostic status code.
///
/// Each instance wraps a `&'static str` taken verbatim from the normative
/// source (kebab-case). Constants for every defined code are declared in this
/// module.
///
/// # Serialization
///
/// Serializes as a plain JSON string — the same kebab-case value the normative
/// source uses.
///
/// # Deserialization
///
/// Deserialization looks up the incoming string in a process-wide whitelist of
/// registered codes. The registry is bounded by registered codes only —
/// arbitrary strings from untrusted JSON will produce a serde error rather
/// than growing any table. Two deserialized instances of the same registered
/// code are pointer-equal to the original `&'static str` constant.
///
/// # Ordering
///
/// The `PartialOrd`/`Ord` implementations delegate to the inner `str` and
/// exist only for use in sorted collections. The ordering has no normative
/// significance.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DiagnosticCode(&'static str);

impl DiagnosticCode {
    /// Construct a `DiagnosticCode` from a `&'static str`.
    ///
    /// The string SHOULD be a kebab-case code from a normative source, but no
    /// validation is performed here; the only invariant is that the string is
    /// `'static`.
    #[must_use]
    pub const fn new(code: &'static str) -> Self {
        Self(code)
    }

    /// Return the kebab-case string exactly as it appears in the normative source.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    /// Returns `true` if this code belongs to the failure-class marker set.
    ///
    /// Failure markers have the `failure-` prefix and are defined in
    /// `apl-spec.md §12.3`.
    #[must_use]
    pub fn is_failure_marker(self) -> bool {
        self.0.starts_with("failure-")
    }

    /// Returns `true` if this code belongs to the AI-Eval profile set
    /// (`apl-ai-eval-profile.md §7.8`).
    #[must_use]
    pub fn is_ai_eval(self) -> bool {
        self.0.starts_with("apl-ai-eval-")
    }

    /// Returns `true` if this code belongs to the pairwise relation set
    /// (`apl-relation-spec.md §9`).
    #[must_use]
    pub fn is_pairwise(self) -> bool {
        matches!(
            self.0,
            "apl-pair-left-invalid"
                | "apl-pair-right-invalid"
                | "apl-relation-query-invalid"
                | "apl-relation-query-left-aspects-out-of-claim"
                | "apl-relation-query-right-aspects-out-of-claim"
                | "apl-relation-query-predicate-mismatch"
                | "apl-same-frame"
                | "apl-same-frame-aspect-match"
                | "apl-same-frame-aspect-mismatch"
                | "apl-statement-content-type-mismatch"
                | "apl-statement-object-shape-mismatch"
                | "apl-cross-frame"
                | "apl-bridge-invalid"
                | "apl-bridge-not-found"
                | "apl-bridge-frame-mismatch"
                | "apl-bridge-scope-mismatch"
                | "apl-bridge-applicable"
                | "apl-bridge-hash-mismatch"
                | "apl-transformation-declared"
        )
    }
}

impl fmt::Display for DiagnosticCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl Serialize for DiagnosticCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0)
    }
}

// ---------------------------------------------------------------------------
// Process-wide whitelist registry
// ---------------------------------------------------------------------------

/// Process-wide whitelist registry of known diagnostic codes.
///
/// Keys are `&'static str` references pointing directly to the string literals
/// embedded in the binary (the same pointers held by the constants in this
/// module). Values are `()` — the key is the value.
///
/// Using `&'static str` as key means `get_key_value` can return the stored
/// pointer, which is then handed to `DiagnosticCode::new` — preserving
/// pointer equality with the named constants.
static REGISTRY: OnceLock<Mutex<HashMap<&'static str, ()>>> = OnceLock::new();

/// Extend the registry with additional `&'static str` codes.
///
/// This function is idempotent: registering the same code twice has no effect.
///
/// # Usage
///
/// Vertical profiles (e.g. `apl-ai-eval`) call this once at startup (or via
/// their own `register()` function) to add their profile-specific constants
/// so that deserialization succeeds for those codes.
pub fn register_diagnostic_codes(codes: &[&'static str]) {
    let reg = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    // A panicking thread holding this lock is not a concern: the registry is
    // insert-only, so a partial insertion is still a consistent state.
    let mut map = reg
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for &c in codes {
        map.insert(c, ());
    }
}

/// Ensure all apl-core constants are registered.
///
/// Called automatically before the first deserialization. Downstream code
/// does not need to call this explicitly.
fn ensure_core_registered() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        register_diagnostic_codes(&[
            // Failure class markers
            FAILURE_CARRIER.as_str(),
            FAILURE_CLAIM_STRUCTURE.as_str(),
            FAILURE_REFERENCE.as_str(),
            FAILURE_FRAME.as_str(),
            FAILURE_SEMANTIC_LINKAGE.as_str(),
            FAILURE_RELATION_STRUCTURE.as_str(),
            // Carrier
            CARRIER_VALID.as_str(),
            CARRIER_INVALID.as_str(),
            // APL envelope
            APL_PRESENT.as_str(),
            APL_MISSING.as_str(),
            APL_VERSION_MISSING.as_str(),
            APL_VERSION_UNSUPPORTED.as_str(),
            // Claim structure
            APL_CLAIM_MISSING.as_str(),
            APL_CLAIM_KIND_MISSING.as_str(),
            APL_CLAIM_KIND_UNSUPPORTED.as_str(),
            APL_SUBJECT_MISSING.as_str(),
            APL_SUBJECT_INVALID.as_str(),
            APL_SUBJECT_ID_INVALID.as_str(),
            APL_SUBJECT_DIGEST_INVALID.as_str(),
            APL_ASPECT_REFS_MISSING.as_str(),
            APL_ASPECT_REFS_INVALID.as_str(),
            APL_ASPECT_REF_OUT_OF_FRAME.as_str(),
            APL_STATEMENT_MISSING.as_str(),
            APL_STATEMENT_INVALID.as_str(),
            APL_PREDICATE_MISSING.as_str(),
            APL_CONTENT_MISSING.as_str(),
            // Frame binding & resolution
            APL_FRAME_BOUND.as_str(),
            APL_FRAME_REF_INVALID.as_str(),
            APL_FRAME_MISSING.as_str(),
            APL_FRAME_HASH_INVALID.as_str(),
            APL_FRAME_UNRESOLVED.as_str(),
            APL_FRAME_HASH_MISMATCH.as_str(),
            APL_FRAME_VERSION_MISSING.as_str(),
            APL_FRAME_VERSION_UNSUPPORTED.as_str(),
            APL_FRAME_OBSERVER_INVALID.as_str(),
            APL_FRAME_ASPECT_INVALID.as_str(),
            APL_FRAME_INVARIANCE_INVALID.as_str(),
            APL_FRAME_EXCLUSIONS_INVALID.as_str(),
            APL_FRAME_PROCEDURE_OR_INSTRUMENT_MISSING.as_str(),
            APL_FRAME_SCOPE_OR_RESOLUTION_MISSING.as_str(),
            APL_FRAME_KERNEL_MISSING.as_str(),
            // Relation-layer envelope
            APL_RELATED_FRAMES_INVALID.as_str(),
            APL_BRIDGE_REFS_INVALID.as_str(),
            APL_TRANSFORMATION_REFS_INVALID.as_str(),
            // Core outcome markers
            APL_VALID.as_str(),
            APL_INVALID.as_str(),
            // Relation outcome markers
            SAME_FRAME.as_str(),
            CROSS_FRAME.as_str(),
            BRIDGED.as_str(),
            UNBRIDGED.as_str(),
            COMPARABLE.as_str(),
            INCOMPARABLE.as_str(),
            // Transformation markers
            TRANSFORMATION_DECLARED.as_str(),
            TRANSFORMATION_MISSING.as_str(),
            LOSS_DECLARED.as_str(),
            LOSS_UNDECLARED.as_str(),
            // Pairwise diagnostics
            APL_PAIR_LEFT_INVALID.as_str(),
            APL_PAIR_RIGHT_INVALID.as_str(),
            APL_RELATION_QUERY_INVALID.as_str(),
            APL_RELATION_QUERY_LEFT_ASPECTS_OUT_OF_CLAIM.as_str(),
            APL_RELATION_QUERY_RIGHT_ASPECTS_OUT_OF_CLAIM.as_str(),
            APL_RELATION_QUERY_PREDICATE_MISMATCH.as_str(),
            APL_SAME_FRAME.as_str(),
            APL_SAME_FRAME_ASPECT_MATCH.as_str(),
            APL_SAME_FRAME_ASPECT_MISMATCH.as_str(),
            APL_STATEMENT_CONTENT_TYPE_MISMATCH.as_str(),
            APL_STATEMENT_OBJECT_SHAPE_MISMATCH.as_str(),
            APL_CROSS_FRAME.as_str(),
            APL_BRIDGE_INVALID.as_str(),
            APL_BRIDGE_NOT_FOUND.as_str(),
            APL_BRIDGE_FRAME_MISMATCH.as_str(),
            APL_BRIDGE_SCOPE_MISMATCH.as_str(),
            APL_BRIDGE_APPLICABLE.as_str(),
            APL_BRIDGE_HASH_MISMATCH.as_str(),
            APL_TRANSFORMATION_DECLARED.as_str(),
        ]);
    });
}

impl<'de> Deserialize<'de> for DiagnosticCode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        ensure_core_registered();
        let reg = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
        let map = reg
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((&known, ())) = map.get_key_value(s.as_str()) {
            Ok(DiagnosticCode::new(known))
        } else {
            Err(serde::de::Error::custom(format!(
                "unknown diagnostic code: {s}"
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// apl-spec.md §12.3 — Failure class markers
// ---------------------------------------------------------------------------

/// Failure class marker: carrier layer failed.
pub const FAILURE_CARRIER: DiagnosticCode = DiagnosticCode::new("failure-carrier");
/// Failure class marker: claim structure violated.
pub const FAILURE_CLAIM_STRUCTURE: DiagnosticCode = DiagnosticCode::new("failure-claim-structure");
/// Failure class marker: reference object malformed.
pub const FAILURE_REFERENCE: DiagnosticCode = DiagnosticCode::new("failure-reference");
/// Failure class marker: frame binding or resolution failed.
pub const FAILURE_FRAME: DiagnosticCode = DiagnosticCode::new("failure-frame");
/// Failure class marker: aspect ref not in frame.
pub const FAILURE_SEMANTIC_LINKAGE: DiagnosticCode =
    DiagnosticCode::new("failure-semantic-linkage");
/// Failure class marker: relation structure invalid.
pub const FAILURE_RELATION_STRUCTURE: DiagnosticCode =
    DiagnosticCode::new("failure-relation-structure");

// ---------------------------------------------------------------------------
// apl-spec.md §12.3 — Carrier
// ---------------------------------------------------------------------------

/// Carrier signature verified successfully.
pub const CARRIER_VALID: DiagnosticCode = DiagnosticCode::new("carrier-valid");
/// Carrier signature failed verification.
pub const CARRIER_INVALID: DiagnosticCode = DiagnosticCode::new("carrier-invalid");

// ---------------------------------------------------------------------------
// apl-spec.md §12.3 — APL envelope
// ---------------------------------------------------------------------------

/// `metadata.apl` is present.
pub const APL_PRESENT: DiagnosticCode = DiagnosticCode::new("apl-present");
/// `metadata.apl` is absent.
pub const APL_MISSING: DiagnosticCode = DiagnosticCode::new("apl-missing");
/// `metadata.apl.version` field is absent.
pub const APL_VERSION_MISSING: DiagnosticCode = DiagnosticCode::new("apl-version-missing");
/// `metadata.apl.version` names an unsupported protocol version.
pub const APL_VERSION_UNSUPPORTED: DiagnosticCode = DiagnosticCode::new("apl-version-unsupported");

// ---------------------------------------------------------------------------
// apl-spec.md §12.3 — Claim structure
// ---------------------------------------------------------------------------

/// `metadata.apl.claim` is absent.
pub const APL_CLAIM_MISSING: DiagnosticCode = DiagnosticCode::new("apl-claim-missing");
/// `claim.kind` field is absent.
pub const APL_CLAIM_KIND_MISSING: DiagnosticCode = DiagnosticCode::new("apl-claim-kind-missing");
/// `claim.kind` names an unsupported kind.
pub const APL_CLAIM_KIND_UNSUPPORTED: DiagnosticCode =
    DiagnosticCode::new("apl-claim-kind-unsupported");
/// `claim.subject` is absent.
pub const APL_SUBJECT_MISSING: DiagnosticCode = DiagnosticCode::new("apl-subject-missing");
/// `claim.subject` fails structural validation.
pub const APL_SUBJECT_INVALID: DiagnosticCode = DiagnosticCode::new("apl-subject-invalid");
/// `claim.subject.id` is absent or malformed.
pub const APL_SUBJECT_ID_INVALID: DiagnosticCode = DiagnosticCode::new("apl-subject-id-invalid");
/// `claim.subject.digest` is absent or malformed.
pub const APL_SUBJECT_DIGEST_INVALID: DiagnosticCode =
    DiagnosticCode::new("apl-subject-digest-invalid");
/// `claim.aspect_refs` array is absent.
pub const APL_ASPECT_REFS_MISSING: DiagnosticCode = DiagnosticCode::new("apl-aspect-refs-missing");
/// `claim.aspect_refs` array fails structural validation.
pub const APL_ASPECT_REFS_INVALID: DiagnosticCode = DiagnosticCode::new("apl-aspect-refs-invalid");
/// An element of `claim.aspect_refs` is not listed in the resolved frame's aspects.
pub const APL_ASPECT_REF_OUT_OF_FRAME: DiagnosticCode =
    DiagnosticCode::new("apl-aspect-ref-out-of-frame");
/// `claim.statement` is absent.
pub const APL_STATEMENT_MISSING: DiagnosticCode = DiagnosticCode::new("apl-statement-missing");
/// `claim.statement` fails structural validation.
pub const APL_STATEMENT_INVALID: DiagnosticCode = DiagnosticCode::new("apl-statement-invalid");
/// `claim.statement.predicate` is absent.
pub const APL_PREDICATE_MISSING: DiagnosticCode = DiagnosticCode::new("apl-predicate-missing");
/// `claim.statement.content` is absent.
pub const APL_CONTENT_MISSING: DiagnosticCode = DiagnosticCode::new("apl-content-missing");

// ---------------------------------------------------------------------------
// apl-spec.md §12.3 — Frame binding & resolution
// ---------------------------------------------------------------------------

/// Receipt is bound to a frame (`frame_ref` is present and valid).
pub const APL_FRAME_BOUND: DiagnosticCode = DiagnosticCode::new("apl-frame-bound");
/// `frame_ref` object fails structural validation.
pub const APL_FRAME_REF_INVALID: DiagnosticCode = DiagnosticCode::new("apl-frame-ref-invalid");
/// Frame artifact was not found by the resolver.
pub const APL_FRAME_MISSING: DiagnosticCode = DiagnosticCode::new("apl-frame-missing");
/// `frame_ref.hash` field is absent or malformed.
pub const APL_FRAME_HASH_INVALID: DiagnosticCode = DiagnosticCode::new("apl-frame-hash-invalid");
/// Frame could not be resolved (infra failure or timeout).
pub const APL_FRAME_UNRESOLVED: DiagnosticCode = DiagnosticCode::new("apl-frame-unresolved");
/// Resolved frame's canonical hash does not match `frame_ref.hash`.
pub const APL_FRAME_HASH_MISMATCH: DiagnosticCode = DiagnosticCode::new("apl-frame-hash-mismatch");
/// `frame.version` field is absent.
pub const APL_FRAME_VERSION_MISSING: DiagnosticCode =
    DiagnosticCode::new("apl-frame-version-missing");
/// `frame.version` names an unsupported frame schema version.
pub const APL_FRAME_VERSION_UNSUPPORTED: DiagnosticCode =
    DiagnosticCode::new("apl-frame-version-unsupported");
/// `frame.observer` fails structural validation.
pub const APL_FRAME_OBSERVER_INVALID: DiagnosticCode =
    DiagnosticCode::new("apl-frame-observer-invalid");
/// `frame.aspect` array fails structural validation.
pub const APL_FRAME_ASPECT_INVALID: DiagnosticCode =
    DiagnosticCode::new("apl-frame-aspect-invalid");
/// `frame.invariance` fails structural validation.
pub const APL_FRAME_INVARIANCE_INVALID: DiagnosticCode =
    DiagnosticCode::new("apl-frame-invariance-invalid");
/// `frame.exclusions` fails structural validation.
pub const APL_FRAME_EXCLUSIONS_INVALID: DiagnosticCode =
    DiagnosticCode::new("apl-frame-exclusions-invalid");
/// `frame.procedure` or `frame.instrument` is absent (both required).
pub const APL_FRAME_PROCEDURE_OR_INSTRUMENT_MISSING: DiagnosticCode =
    DiagnosticCode::new("apl-frame-procedure-or-instrument-missing");
/// `frame.scope` or `frame.resolution` is absent (both required).
pub const APL_FRAME_SCOPE_OR_RESOLUTION_MISSING: DiagnosticCode =
    DiagnosticCode::new("apl-frame-scope-or-resolution-missing");
/// `frame.kernel` is absent.
pub const APL_FRAME_KERNEL_MISSING: DiagnosticCode =
    DiagnosticCode::new("apl-frame-kernel-missing");

// ---------------------------------------------------------------------------
// apl-spec.md §12.3 — Relation-layer envelope
// ---------------------------------------------------------------------------

/// `claim.related_frames` array fails structural validation.
pub const APL_RELATED_FRAMES_INVALID: DiagnosticCode =
    DiagnosticCode::new("apl-related-frames-invalid");
/// `claim.bridge_refs` array fails structural validation.
pub const APL_BRIDGE_REFS_INVALID: DiagnosticCode = DiagnosticCode::new("apl-bridge-refs-invalid");
/// `claim.transformation_refs` array fails structural validation.
pub const APL_TRANSFORMATION_REFS_INVALID: DiagnosticCode =
    DiagnosticCode::new("apl-transformation-refs-invalid");

// ---------------------------------------------------------------------------
// apl-spec.md §12.3 — Core outcome markers
// ---------------------------------------------------------------------------

/// Receipt passed all verifier checks.
pub const APL_VALID: DiagnosticCode = DiagnosticCode::new("apl-valid");
/// Receipt failed one or more verifier checks.
pub const APL_INVALID: DiagnosticCode = DiagnosticCode::new("apl-invalid");

// ---------------------------------------------------------------------------
// apl-spec.md §12.3 — Relation outcome markers
// ---------------------------------------------------------------------------

/// Both receipts reference the same frame.
pub const SAME_FRAME: DiagnosticCode = DiagnosticCode::new("same-frame");
/// Receipts reference different frames.
pub const CROSS_FRAME: DiagnosticCode = DiagnosticCode::new("cross-frame");
/// A bridge artifact was found and is applicable.
pub const BRIDGED: DiagnosticCode = DiagnosticCode::new("bridged");
/// No applicable bridge artifact was found.
pub const UNBRIDGED: DiagnosticCode = DiagnosticCode::new("unbridged");
/// The pair is semantically comparable under the query constraints.
pub const COMPARABLE: DiagnosticCode = DiagnosticCode::new("comparable");
/// The pair is not semantically comparable under the query constraints.
pub const INCOMPARABLE: DiagnosticCode = DiagnosticCode::new("incomparable");

// ---------------------------------------------------------------------------
// apl-spec.md §12.3 — Transformation markers
// ---------------------------------------------------------------------------

/// A transformation is declared for this pair.
pub const TRANSFORMATION_DECLARED: DiagnosticCode = DiagnosticCode::new("transformation-declared");
/// No transformation is declared for this pair.
pub const TRANSFORMATION_MISSING: DiagnosticCode = DiagnosticCode::new("transformation-missing");
/// The transformation declares a loss of information.
pub const LOSS_DECLARED: DiagnosticCode = DiagnosticCode::new("loss-declared");
/// The transformation does not declare a loss of information.
pub const LOSS_UNDECLARED: DiagnosticCode = DiagnosticCode::new("loss-undeclared");

// ---------------------------------------------------------------------------
// apl-relation-spec.md §9 — Pairwise diagnostics
// ---------------------------------------------------------------------------

/// The left receipt of the pair is `apl-invalid`.
pub const APL_PAIR_LEFT_INVALID: DiagnosticCode = DiagnosticCode::new("apl-pair-left-invalid");
/// The right receipt of the pair is `apl-invalid`.
pub const APL_PAIR_RIGHT_INVALID: DiagnosticCode = DiagnosticCode::new("apl-pair-right-invalid");
/// The `RelationQuery` object fails structural validation.
pub const APL_RELATION_QUERY_INVALID: DiagnosticCode =
    DiagnosticCode::new("apl-relation-query-invalid");
/// `query.left_aspects` contains an aspect not in the left receipt's claim.
pub const APL_RELATION_QUERY_LEFT_ASPECTS_OUT_OF_CLAIM: DiagnosticCode =
    DiagnosticCode::new("apl-relation-query-left-aspects-out-of-claim");
/// `query.right_aspects` contains an aspect not in the right receipt's claim.
pub const APL_RELATION_QUERY_RIGHT_ASPECTS_OUT_OF_CLAIM: DiagnosticCode =
    DiagnosticCode::new("apl-relation-query-right-aspects-out-of-claim");
/// `query.predicate` does not match both receipts' `claim.statement.predicate`.
pub const APL_RELATION_QUERY_PREDICATE_MISMATCH: DiagnosticCode =
    DiagnosticCode::new("apl-relation-query-predicate-mismatch");
/// Both receipts reference the same frame (pairwise path).
pub const APL_SAME_FRAME: DiagnosticCode = DiagnosticCode::new("apl-same-frame");
/// Same-frame pair: queried aspects match.
pub const APL_SAME_FRAME_ASPECT_MATCH: DiagnosticCode =
    DiagnosticCode::new("apl-same-frame-aspect-match");
/// Same-frame pair: queried aspects do not match.
pub const APL_SAME_FRAME_ASPECT_MISMATCH: DiagnosticCode =
    DiagnosticCode::new("apl-same-frame-aspect-mismatch");
/// Statement `content` types differ between the two receipts.
pub const APL_STATEMENT_CONTENT_TYPE_MISMATCH: DiagnosticCode =
    DiagnosticCode::new("apl-statement-content-type-mismatch");
/// Statement `content` object shapes differ between the two receipts.
pub const APL_STATEMENT_OBJECT_SHAPE_MISMATCH: DiagnosticCode =
    DiagnosticCode::new("apl-statement-object-shape-mismatch");
/// Receipts reference different frames (cross-frame path).
pub const APL_CROSS_FRAME: DiagnosticCode = DiagnosticCode::new("apl-cross-frame");
/// A bridge artifact for this pair fails structural validation.
pub const APL_BRIDGE_INVALID: DiagnosticCode = DiagnosticCode::new("apl-bridge-invalid");
/// No bridge artifact was found for this pair.
pub const APL_BRIDGE_NOT_FOUND: DiagnosticCode = DiagnosticCode::new("apl-bridge-not-found");
/// Bridge artifact frame references do not match the receipt pair.
pub const APL_BRIDGE_FRAME_MISMATCH: DiagnosticCode =
    DiagnosticCode::new("apl-bridge-frame-mismatch");
/// Bridge artifact scope does not cover the query.
pub const APL_BRIDGE_SCOPE_MISMATCH: DiagnosticCode =
    DiagnosticCode::new("apl-bridge-scope-mismatch");
/// Bridge artifact is applicable to the query.
pub const APL_BRIDGE_APPLICABLE: DiagnosticCode = DiagnosticCode::new("apl-bridge-applicable");
/// Resolved bridge canonical hash does not match the requested `bridge_ref.hash`.
///
/// Emitted when a resolver returns a bridge value whose `canonical_hash` does not equal
/// the hash that was requested. This guards the content-addressed trust boundary: a
/// resolver must not substitute a different bridge for the one pinned by the claim.
pub const APL_BRIDGE_HASH_MISMATCH: DiagnosticCode =
    DiagnosticCode::new("apl-bridge-hash-mismatch");
/// Transformation is declared in the bridge artifact for this pair.
pub const APL_TRANSFORMATION_DECLARED: DiagnosticCode =
    DiagnosticCode::new("apl-transformation-declared");

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_code_as_str() {
        assert_eq!(DiagnosticCode::new("foo").as_str(), "foo");
        assert_eq!(APL_VALID.as_str(), "apl-valid");
        assert_eq!(FAILURE_CARRIER.as_str(), "failure-carrier");
    }

    #[test]
    fn diagnostic_code_serialize_as_string() {
        let json = serde_json::to_string(&APL_VALID).expect("serialization must succeed");
        assert_eq!(json, r#""apl-valid""#);

        let json2 = serde_json::to_string(&FAILURE_CARRIER).expect("serialization must succeed");
        assert_eq!(json2, r#""failure-carrier""#);
    }

    #[test]
    fn diagnostic_code_is_ai_eval() {
        assert!(DiagnosticCode::new("apl-ai-eval-predicate-disallowed").is_ai_eval());
        assert!(DiagnosticCode::new("apl-ai-eval-bridge-aspect-family-mismatch").is_ai_eval());
        assert!(!APL_VALID.is_ai_eval());
        assert!(!APL_BRIDGE_APPLICABLE.is_ai_eval());
        assert!(!FAILURE_CARRIER.is_ai_eval());
    }

    #[test]
    fn diagnostic_code_is_pairwise() {
        assert!(APL_BRIDGE_APPLICABLE.is_pairwise());
        assert!(APL_SAME_FRAME.is_pairwise());
        assert!(APL_CROSS_FRAME.is_pairwise());
        assert!(APL_PAIR_LEFT_INVALID.is_pairwise());
        assert!(!APL_VALID.is_pairwise());
        assert!(!FAILURE_CARRIER.is_pairwise());
        assert!(!DiagnosticCode::new("apl-ai-eval-predicate-disallowed").is_pairwise());
    }

    #[test]
    fn diagnostic_code_is_failure_marker() {
        assert!(FAILURE_CARRIER.is_failure_marker());
        assert!(FAILURE_CLAIM_STRUCTURE.is_failure_marker());
        assert!(FAILURE_FRAME.is_failure_marker());
        assert!(FAILURE_SEMANTIC_LINKAGE.is_failure_marker());
        assert!(FAILURE_RELATION_STRUCTURE.is_failure_marker());
        assert!(FAILURE_REFERENCE.is_failure_marker());
        assert!(!APL_VALID.is_failure_marker());
        assert!(!APL_BRIDGE_APPLICABLE.is_failure_marker());
    }

    #[test]
    fn diagnostic_code_display() {
        assert_eq!(format!("{}", APL_VALID), "apl-valid");
        assert_eq!(format!("{}", FAILURE_CARRIER), "failure-carrier");
    }

    #[test]
    fn unknown_diagnostic_code_rejected_on_deserialize() {
        let result: Result<DiagnosticCode, _> = serde_json::from_str(r#""fake-code-xyz""#);
        assert!(
            result.is_err(),
            "unknown diagnostic code must produce a deserialization error"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown diagnostic code"),
            "error message must mention 'unknown diagnostic code', got: {err}"
        );
    }

    #[test]
    fn registered_core_code_deserializes_to_pointer_identical_static() {
        // Verify that deserializing a registered core code yields a value that
        // is content-equal to the named constant, AND that two independent
        // deserializations of the same code share the same underlying pointer
        // (i.e. the registry always returns the same `&'static str` slot).
        //
        // Note: Rust `const` items do not guarantee pointer identity across
        // different use sites — the compiler may duplicate the underlying
        // string literal. We therefore verify pointer stability via two
        // deserialization calls rather than directly against `APL_VALID.as_str()`.
        let a: DiagnosticCode =
            serde_json::from_str(r#""apl-valid""#).expect("deserialization must succeed");
        let b: DiagnosticCode =
            serde_json::from_str(r#""apl-valid""#).expect("deserialization must succeed");
        // Content must match the named constant.
        assert_eq!(
            a.as_str(),
            APL_VALID.as_str(),
            "deserialized code must match APL_VALID content"
        );
        // Both deserialized values must be pointer-identical (same registry slot).
        assert!(
            std::ptr::eq(a.as_str() as *const str, b.as_str() as *const str),
            "two deserializations of the same code must return pointer-identical &'static str"
        );
    }

    #[test]
    fn deserialize_same_code_twice_shares_pointer() {
        let a: DiagnosticCode =
            serde_json::from_str(r#""apl-valid""#).expect("deserialization must succeed");
        let b: DiagnosticCode =
            serde_json::from_str(r#""apl-valid""#).expect("deserialization must succeed");
        assert!(
            std::ptr::eq(a.as_str(), b.as_str()),
            "two deserializations of the same code must return pointer-identical &'static str"
        );
    }

    #[test]
    fn register_diagnostic_codes_extends_registry() {
        register_diagnostic_codes(&["custom-test-code-unique-abc123"]);
        let result: Result<DiagnosticCode, _> =
            serde_json::from_str(r#""custom-test-code-unique-abc123""#);
        assert!(
            result.is_ok(),
            "after registration, the custom code must deserialize successfully"
        );
    }

    #[test]
    fn deserialize_roundtrip_through_json() {
        use crate::core::output::{CoreOutcome, RelationOutcome, VerifierOutput};

        let original = VerifierOutput {
            core_outcome: CoreOutcome::AplValid,
            relation_outcome: RelationOutcome::RelationNotEvaluated,
            failure_classes: vec![],
            diagnostics: vec![APL_VALID, CARRIER_VALID, APL_FRAME_BOUND],
        };

        let json = serde_json::to_string(&original).expect("serialization must succeed");
        let roundtripped: VerifierOutput =
            serde_json::from_str(&json).expect("deserialization must succeed");

        assert_eq!(original, roundtripped);
    }
}
