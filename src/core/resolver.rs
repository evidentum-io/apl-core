//! `FrameResolver` and `BridgeResolver` traits with in-memory default
//! implementations per `apl-spec.md §9.5`, `§16.2`, and
//! `apl-relation-spec.md §5`.
//!
//! # Design Overview
//!
//! Two parallel abstractions — one for Frames, one for Bridges — share the same
//! three-variant resolution result pattern:
//!
//! | Variant | Meaning |
//! |---------|---------|
//! | `Found(value)` | Artifact located; caller MUST verify `canonical_hash(&value) == requested_hash` |
//! | `NotFound` | No compatible source has this hash |
//! | `ResolverError(msg)` | Infrastructure failure (per `§16.3`, NOT itself a core failure) |
//!
//! # Security Note
//!
//! Resolver-returned JSON is **untrusted** until hash-matched. Any
//! `FrameResolver::resolve` result might be a malicious document.
//! CORE-VERIFY-1 MUST recompute `canonical_hash` and compare to the pinned hash
//! before calling `Frame::parse`. This spec deliberately does NOT perform the
//! hash check inside the resolver — the resolver is an infrastructure layer; the
//! verifier is the trust boundary.

use std::collections::HashMap;

use serde_json::Value;

use crate::core::hash::Hash;
use crate::core::jcs::canonical_hash;

// ── FrameResolution ──────────────────────────────────────────────────────────

/// Result of a [`FrameResolver::resolve`] call.
#[derive(Debug, Clone)]
pub enum FrameResolution {
    /// Frame was found. The value is the raw JSON the resolver returned.
    ///
    /// Caller MUST verify that `canonical_hash(&value) == requested_hash`
    /// before accepting it (`apl-spec.md §9.5`).
    Found(Value),

    /// No compatible source has this hash.
    ///
    /// Per `§9.5`: if ALL compatible sources return `NotFound`, this is a
    /// `FrameFailure`.
    NotFound,

    /// The resolver hit an infrastructure error.
    ///
    /// Per `§16.3`, a transient registry failure is NOT in itself a core
    /// failure — the caller decides whether any OTHER compatible source can
    /// still resolve the frame.
    ResolverError(String),
}

// ── FrameResolver trait ──────────────────────────────────────────────────────

/// Abstraction over frame lookup per `apl-spec.md §9.5`, `§16.2`.
///
/// apl-core ships only the trait and [`InMemoryFrameResolver`]. Filesystem-
/// and network-backed implementations live in `apl-cli`.
///
/// # Contract
///
/// - `resolve` MUST be pure with respect to its input: the same hash MUST
///   produce the same `FrameResolution` within a single verifier invocation.
///   (A resolver that is re-queried across invocations MAY observe external
///   store changes, but a single verification run MUST see a stable view.)
/// - `resolve` MUST NOT panic on any input.
/// - `resolve` MUST NOT mutate external state observable by callers.
/// - Implementations that perform I/O (filesystem, network) MUST translate
///   any failure into `FrameResolution::ResolverError` rather than panicking
///   or propagating host errors. This preserves `verify_receipt`'s
///   determinism contract (`src/core/verify.rs` module docstring).
pub trait FrameResolver: Send + Sync {
    /// Look up a frame by its canonical identity hash.
    fn resolve(&self, hash: &Hash) -> FrameResolution;
}

// ── BridgeResolution ─────────────────────────────────────────────────────────

/// Result of a [`BridgeResolver::resolve`] call.
///
/// Same contract as [`FrameResolution`], parameterized for bridge lookup.
#[derive(Debug, Clone)]
pub enum BridgeResolution {
    /// Bridge artifact found. Caller MUST verify the canonical hash.
    Found(Value),
    /// No compatible source has this hash.
    NotFound,
    /// Infrastructure error; not in itself a core failure.
    ResolverError(String),
}

// ── BridgeResolver trait ─────────────────────────────────────────────────────

/// Abstraction over bridge lookup per `apl-relation-spec.md §5`.
///
/// Sources of bridge artifacts per `§5`:
/// - `left_receipt.bridge_refs`
/// - `right_receipt.bridge_refs`
/// - supplied bridge artifacts
/// - local bridge cache
/// - compatible registry retrieval
///
/// The trait sees a flat lookup; the caller orchestrates source priority.
///
/// # Contract
///
/// Same as [`FrameResolver`]: `resolve` MUST be pure within a single
/// pairwise evaluation, MUST NOT panic, MUST NOT mutate externally
/// observable state, and MUST surface any I/O failure as
/// `BridgeResolution::ResolverError` rather than propagating host errors.
pub trait BridgeResolver: Send + Sync {
    /// Look up a bridge by its canonical identity hash.
    fn resolve(&self, hash: &Hash) -> BridgeResolution;
}

// ── InMemoryFrameResolver ────────────────────────────────────────────────────

/// A `HashMap`-backed in-memory frame resolver.
///
/// Intended for tests and embedded verifiers that ship their own bundle.
/// The name communicates suitability for tests, but the implementation is
/// production-grade for in-process use.
#[derive(Debug, Default, Clone)]
pub struct InMemoryFrameResolver {
    store: HashMap<Hash, Value>,
}

impl InMemoryFrameResolver {
    /// Create an empty in-memory resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a frame value, automatically keying it by its canonical hash.
    ///
    /// The hash is computed via [`canonical_hash`] over the JCS-canonical
    /// bytes of `value`. Subsequent calls to [`FrameResolver::resolve`] with
    /// the returned hash will return `Found(value)`.
    ///
    /// Returns the computed hash.
    pub fn insert(&mut self, value: Value) -> Hash {
        let h = canonical_hash(&value);
        self.store.insert(h, value);
        h
    }

    /// Insert a frame value under an explicit hash (even if the canonical
    /// hash differs).
    ///
    /// Intended **only** for negative-test construction — it allows storing a
    /// value under a hash that does NOT match the canonical hash of the value,
    /// so callers can verify that CORE-VERIFY-1 correctly rejects mismatched
    /// content.
    pub fn insert_raw(&mut self, hash: Hash, value: Value) {
        self.store.insert(hash, value);
    }

    /// Returns the number of frames stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Returns `true` if no frames are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}

impl FrameResolver for InMemoryFrameResolver {
    fn resolve(&self, hash: &Hash) -> FrameResolution {
        match self.store.get(hash) {
            Some(v) => FrameResolution::Found(v.clone()),
            None => FrameResolution::NotFound,
        }
    }
}

// ── InMemoryBridgeResolver ───────────────────────────────────────────────────

/// A `HashMap`-backed in-memory bridge resolver.
///
/// Symmetric to [`InMemoryFrameResolver`]; see that type for full docs.
#[derive(Debug, Default, Clone)]
pub struct InMemoryBridgeResolver {
    store: HashMap<Hash, Value>,
}

impl InMemoryBridgeResolver {
    /// Create an empty in-memory resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a bridge value, automatically keying it by its canonical hash.
    ///
    /// Returns the computed hash.
    pub fn insert(&mut self, value: Value) -> Hash {
        let h = canonical_hash(&value);
        self.store.insert(h, value);
        h
    }

    /// Insert a bridge value under an explicit hash (even if the canonical
    /// hash differs). Intended for negative-test construction only.
    pub fn insert_raw(&mut self, hash: Hash, value: Value) {
        self.store.insert(hash, value);
    }

    /// Returns the number of bridges stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Returns `true` if no bridges are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}

impl BridgeResolver for InMemoryBridgeResolver {
    fn resolve(&self, hash: &Hash) -> BridgeResolution {
        match self.store.get(hash) {
            Some(v) => BridgeResolution::Found(v.clone()),
            None => BridgeResolution::NotFound,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod frame_resolver_tests {
    use serde_json::json;

    use super::*;

    /// Extracts the inner `Value` from `FrameResolution::Found`; panics otherwise.
    ///
    /// Using a named helper avoids `if let` / `match` arms in test bodies,
    /// which prevents llvm-cov from flagging the unreachable else-branch as
    /// uncovered lines in patch-coverage checks.
    #[track_caller]
    fn unwrap_frame_found(r: FrameResolution) -> Value {
        match r {
            FrameResolution::Found(v) => v,
            other => panic!("expected Found, got {other:?}"),
        }
    }

    fn sample_frame() -> Value {
        json!({
            "version": "0.1",
            "observer": "o",
            "procedure": "p",
            "aspect": ["a"],
            "scope": "s",
            "invariance": ["i"],
            "exclusions": ["e"]
        })
    }

    /// AC4, AC6: `insert` returns the canonical hash; `resolve` returns `Found`.
    #[test]
    fn insert_and_resolve_roundtrip() {
        let mut r = InMemoryFrameResolver::new();
        let v = sample_frame();
        let h = r.insert(v.clone());
        assert_eq!(h, canonical_hash(&v));

        assert_eq!(unwrap_frame_found(r.resolve(&h)), v);
    }

    /// AC5: `resolve` returns `NotFound` for an unknown hash.
    #[test]
    fn not_found_for_missing_hash() {
        let r = InMemoryFrameResolver::new();
        let h = canonical_hash(&json!({ "x": 1 }));
        assert!(matches!(r.resolve(&h), FrameResolution::NotFound));
    }

    /// AC7: `insert_raw` stores under a mismatched hash; value returned verbatim.
    #[test]
    fn insert_raw_allows_hash_mismatch() {
        let mut r = InMemoryFrameResolver::new();
        let v = json!({ "a": 1 });
        let wrong_hash = canonical_hash(&json!({ "a": 2 }));
        r.insert_raw(wrong_hash, v.clone());

        assert_eq!(unwrap_frame_found(r.resolve(&wrong_hash)), v);
        // The correct hash for `v` is NOT stored.
        let correct = canonical_hash(&v);
        assert!(matches!(r.resolve(&correct), FrameResolution::NotFound));
    }

    /// AC9: `InMemoryFrameResolver` is usable as `Box<dyn FrameResolver>`.
    #[test]
    fn usable_as_dyn_trait_object() {
        let mut r = InMemoryFrameResolver::new();
        r.insert(sample_frame());
        let boxed: Box<dyn FrameResolver> = Box::new(r);
        let h = canonical_hash(&sample_frame());
        assert!(matches!(boxed.resolve(&h), FrameResolution::Found(_)));
    }

    /// AC10: Two different frames get distinct hashes and do not collide.
    #[test]
    fn distinct_frames_get_distinct_hashes() {
        let mut r = InMemoryFrameResolver::new();
        let h1 = r.insert(json!({ "x": 1 }));
        let h2 = r.insert(json!({ "x": 2 }));
        assert_ne!(h1, h2);
        assert_eq!(r.len(), 2);

        assert_eq!(unwrap_frame_found(r.resolve(&h1)), json!({ "x": 1 }));
        assert_eq!(unwrap_frame_found(r.resolve(&h2)), json!({ "x": 2 }));
    }

    #[test]
    fn new_resolver_is_empty() {
        let r = InMemoryFrameResolver::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn len_tracks_inserts() {
        let mut r = InMemoryFrameResolver::new();
        assert_eq!(r.len(), 0);
        r.insert(json!({ "a": 1 }));
        assert_eq!(r.len(), 1);
        r.insert(json!({ "b": 2 }));
        assert_eq!(r.len(), 2);
    }

    /// Inserting the same value twice keeps len at 1 (HashMap dedup).
    #[test]
    fn duplicate_insert_does_not_grow_store() {
        let mut r = InMemoryFrameResolver::new();
        let v = json!({ "x": 42 });
        let h1 = r.insert(v.clone());
        let h2 = r.insert(v.clone());
        assert_eq!(h1, h2);
        assert_eq!(r.len(), 1);
    }

    /// `FrameResolution::ResolverError` variant is constructable, cloneable,
    /// and debuggable — covers the derived impl branches for this variant.
    #[test]
    fn frame_resolution_resolver_error_variant() {
        let e = FrameResolution::ResolverError("registry unreachable".into());
        let cloned = e.clone();
        let s = format!("{cloned:?}");
        assert!(s.contains("ResolverError"));
        assert!(s.contains("registry unreachable"));
    }

    /// `FrameResolution::NotFound` and `Found` debug representations.
    #[test]
    fn frame_resolution_debug_all_variants() {
        let not_found = FrameResolution::NotFound;
        assert!(format!("{not_found:?}").contains("NotFound"));

        let found = FrameResolution::Found(json!({ "x": 1 }));
        assert!(format!("{found:?}").contains("Found"));
    }

    /// Exercises the panic arm of `unwrap_frame_found` — the `NotFound` branch
    /// must be reachable for 100% branch coverage of the helper.
    #[test]
    #[should_panic(expected = "expected Found")]
    fn unwrap_frame_found_panics_on_not_found() {
        unwrap_frame_found(FrameResolution::NotFound);
    }

    /// Exercises the panic arm of `unwrap_frame_found` with a `ResolverError`.
    #[test]
    #[should_panic(expected = "expected Found")]
    fn unwrap_frame_found_panics_on_resolver_error() {
        unwrap_frame_found(FrameResolution::ResolverError("io error".into()));
    }
}

#[cfg(test)]
mod bridge_resolver_tests {
    use serde_json::json;

    use super::*;

    /// Extracts the inner `Value` from `BridgeResolution::Found`; panics otherwise.
    #[track_caller]
    fn unwrap_bridge_found(r: BridgeResolution) -> Value {
        match r {
            BridgeResolution::Found(v) => v,
            other => panic!("expected Found, got {other:?}"),
        }
    }

    /// AC8: `InMemoryBridgeResolver` behaves identically to the frame resolver.
    #[test]
    fn bridge_lookup_works() {
        let mut r = InMemoryBridgeResolver::new();
        let b = json!({
            "version": "0.1",
            "source_frame": { "hash": format!("sha256:{}", "0".repeat(64)) },
            "target_frame": { "hash": format!("sha256:{}", "1".repeat(64)) },
            "comparison_scope": {
                "source_aspects": ["accuracy"],
                "target_aspects": ["accuracy"],
                "relation_type": "score-delta"
            },
            "assumptions": [],
            "losses": []
        });
        let h = r.insert(b.clone());
        assert_eq!(unwrap_bridge_found(r.resolve(&h)), b);
    }

    #[test]
    fn bridge_not_found_for_missing_hash() {
        let r = InMemoryBridgeResolver::new();
        let h = canonical_hash(&json!({ "x": 1 }));
        assert!(matches!(r.resolve(&h), BridgeResolution::NotFound));
    }

    #[test]
    fn bridge_insert_raw_allows_hash_mismatch() {
        let mut r = InMemoryBridgeResolver::new();
        let v = json!({ "bridge": "data" });
        let wrong_hash = canonical_hash(&json!({ "other": "data" }));
        r.insert_raw(wrong_hash, v.clone());

        assert_eq!(unwrap_bridge_found(r.resolve(&wrong_hash)), v);
        let correct = canonical_hash(&v);
        assert!(matches!(r.resolve(&correct), BridgeResolution::NotFound));
    }

    /// AC9: `InMemoryBridgeResolver` is usable as `Box<dyn BridgeResolver>`.
    #[test]
    fn usable_as_dyn_bridge_resolver() {
        let mut r = InMemoryBridgeResolver::new();
        let v = json!({ "bridge": 1 });
        let h = r.insert(v.clone());
        let boxed: Box<dyn BridgeResolver> = Box::new(r);
        assert_eq!(unwrap_bridge_found(boxed.resolve(&h)), v);
    }

    /// AC10: Two different bridges get distinct hashes.
    #[test]
    fn distinct_bridges_get_distinct_hashes() {
        let mut r = InMemoryBridgeResolver::new();
        let h1 = r.insert(json!({ "x": 1 }));
        let h2 = r.insert(json!({ "x": 2 }));
        assert_ne!(h1, h2);
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn new_bridge_resolver_is_empty() {
        let r = InMemoryBridgeResolver::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    /// `BridgeResolution::ResolverError` variant is constructable, cloneable,
    /// and debuggable — covers the derived impl branches for this variant.
    #[test]
    fn bridge_resolution_resolver_error_variant() {
        let e = BridgeResolution::ResolverError("network timeout".into());
        let cloned = e.clone();
        let s = format!("{cloned:?}");
        assert!(s.contains("ResolverError"));
        assert!(s.contains("network timeout"));
    }

    /// `BridgeResolution::NotFound` and `Found` debug representations.
    #[test]
    fn bridge_resolution_debug_all_variants() {
        let not_found = BridgeResolution::NotFound;
        assert!(format!("{not_found:?}").contains("NotFound"));

        let found = BridgeResolution::Found(json!({ "x": 1 }));
        assert!(format!("{found:?}").contains("Found"));
    }

    /// Exercises the panic arm of `unwrap_bridge_found` — the `NotFound` branch.
    #[test]
    #[should_panic(expected = "expected Found")]
    fn unwrap_bridge_found_panics_on_not_found() {
        unwrap_bridge_found(BridgeResolution::NotFound);
    }

    /// Exercises the panic arm of `unwrap_bridge_found` with a `ResolverError`.
    #[test]
    #[should_panic(expected = "expected Found")]
    fn unwrap_bridge_found_panics_on_resolver_error() {
        unwrap_bridge_found(BridgeResolution::ResolverError("timeout".into()));
    }
}
