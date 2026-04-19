//! Canonical equality helpers per `apl-spec.md §4.3.1`.
//!
//! This module provides the four canonical-equality primitives required by the
//! APL specification. All canonicalization is delegated to
//! `atl_core::jcs::canonicalize`, which implements RFC 8785 (JSON
//! Canonicalization Scheme). `apl-core` does **not** re-implement JCS.
//!
//! # Functions
//!
//! | Function | Purpose |
//! |----------|---------|
//! | [`canonical_bytes`] | JCS bytes — single point of contact with `atl-core` |
//! | [`canonical_equal`] | Exact-byte equality of two JCS forms |
//! | [`canonical_equal_after_strip`] | Equality after top-level field removal |
//! | [`canonical_hash`] | SHA-256 of JCS bytes (frame identity check) |
//!
//! # Canonical Identity Rule
//!
//! Per `apl-spec.md §4.3.1`, the **only** normatively compatible way to check
//! whether two APL JSON objects are identical is through exact byte equality of
//! their JCS-canonical representations. Do **not** use `serde_json::Value PartialEq`
//! for identity checks because it does not normalize number formatting, key
//! ordering, or string-escape equivalences.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::core::hash::Hash;

/// Compute the JCS-canonical byte representation of a JSON value.
///
/// This is the **single point of contact** between `apl-core` and
/// `atl_core::jcs::canonicalize`. All other functions in this module call this
/// one; no other module in `apl-core` should call `atl_core::jcs` directly.
///
/// Per RFC 8785 the output is always valid UTF-8.
///
/// # Arguments
///
/// * `v` — any valid `serde_json::Value`
///
/// # Returns
///
/// UTF-8 bytes of the JCS canonical form (RFC 8785).
///
/// # Examples
///
/// ```rust
/// use apl_core::core::jcs::canonical_bytes;
/// use serde_json::json;
///
/// let bytes = canonical_bytes(&json!({"b": 1, "a": 2}));
/// assert_eq!(bytes, br#"{"a":2,"b":1}"#);
/// ```
#[must_use]
pub fn canonical_bytes(v: &Value) -> Vec<u8> {
    // `atl_core::jcs::canonicalize` returns a `String`; take its UTF-8 bytes.
    // Per RFC 8785 the output is always valid UTF-8.
    atl_core::canonicalize(v).into_bytes()
}

/// Exact-byte equality of the JCS-canonical representations of `a` and `b`.
///
/// This is the **only** normatively compatible way to check JSON-object identity
/// per `apl-spec.md §4.3.1`. Callers **must not** fall back to
/// `serde_json::Value` structural comparison because it does not normalize
/// number formatting, key ordering, or string escape equivalences.
///
/// # Examples
///
/// ```rust
/// use apl_core::core::jcs::canonical_equal;
/// use serde_json::json;
///
/// // Key order is irrelevant — JCS sorts keys.
/// let a = json!({"b": 1, "a": 2});
/// let b = json!({"a": 2, "b": 1});
/// assert!(canonical_equal(&a, &b));
///
/// // Different values are not equal.
/// assert!(!canonical_equal(&json!({"x": "a"}), &json!({"x": "b"})));
/// ```
#[must_use]
pub fn canonical_equal(a: &Value, b: &Value) -> bool {
    canonical_bytes(a) == canonical_bytes(b)
}

/// Canonical equality after stripping the listed top-level fields from each
/// input object.
///
/// Returns `false` if either input is not a JSON object. "Stripping a field" is
/// only defined for objects; non-object inputs are a programmer error, but
/// `false` is preferred over a panic because this helper operates on
/// potentially untrusted JSON.
///
/// Only **top-level** fields are removed. Nested-field removal is not supported
/// and not required by any normative APL specification section.
///
/// # Arguments
///
/// * `a`, `b` — JSON objects to compare
/// * `fields` — top-level keys to remove from each input before canonicalization.
///   Duplicates and missing keys are harmless.
///
/// # Examples
///
/// ```rust
/// use apl_core::core::jcs::canonical_equal_after_strip;
/// use serde_json::json;
///
/// let a = json!({"runner_id": "x", "grader_id": "g", "other": 1});
/// let b = json!({"runner_id": "y", "grader_id": "g", "other": 1});
///
/// // Differ only in runner_id — equal after stripping it.
/// assert!(canonical_equal_after_strip(&a, &b, &["runner_id"]));
///
/// // Still differ in another field when stripping grader_id instead.
/// assert!(!canonical_equal_after_strip(&a, &b, &["grader_id"]));
///
/// // Non-object inputs always return false.
/// assert!(!canonical_equal_after_strip(&json!("str"), &json!("str"), &[]));
/// ```
#[must_use]
pub fn canonical_equal_after_strip(a: &Value, b: &Value, fields: &[&str]) -> bool {
    // Only objects are strippable. Non-object inputs trivially return false.
    let Some(obj_a) = a.as_object() else {
        return false;
    };
    let Some(obj_b) = b.as_object() else {
        return false;
    };

    // Clone once; strip; wrap back into Value for canonicalization.
    let mut stripped_a: serde_json::Map<String, Value> = obj_a.clone();
    let mut stripped_b: serde_json::Map<String, Value> = obj_b.clone();
    for f in fields {
        stripped_a.remove(*f);
        stripped_b.remove(*f);
    }

    canonical_equal(&Value::Object(stripped_a), &Value::Object(stripped_b))
}

/// SHA-256 of the JCS-canonical bytes of `v`, as a validated [`Hash`].
///
/// This is the canonical-identity computation mandated by `apl-spec.md §4.3`:
/// "canonical identity MUST be computed as SHA-256 of the JCS-canonicalized
/// JSON bytes". Used by resolver-side integrity checks (`apl-spec.md §9.5`):
/// the hash of a resolved frame MUST match `frame_ref.hash`.
///
/// # Examples
///
/// ```rust
/// use apl_core::core::jcs::canonical_hash;
/// use serde_json::json;
///
/// // Key order does not affect the hash.
/// let h1 = canonical_hash(&json!({"b": 1, "a": 2}));
/// let h2 = canonical_hash(&json!({"a": 2, "b": 1}));
/// assert_eq!(h1, h2);
///
/// // Same value always produces the same hash (deterministic).
/// let v = json!({"x": 1, "y": [1, 2, 3]});
/// assert_eq!(canonical_hash(&v), canonical_hash(&v));
/// ```
#[must_use]
pub fn canonical_hash(v: &Value) -> Hash {
    let bytes = canonical_bytes(v);
    let digest = Sha256::digest(&bytes);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&digest);
    Hash::from_bytes(arr)
}

#[cfg(test)]
mod canonical_equal_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_does_not_matter() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert!(canonical_equal(&a, &b));
    }

    #[test]
    fn number_form_normalized() {
        // Per RFC 8785 / JCS, `1.0` and `1` canonicalize identically.
        assert!(canonical_equal(&json!({"x": 1.0}), &json!({"x": 1})));
        assert!(canonical_equal(&json!(1.500_f64), &json!(1.5_f64)));
    }

    #[test]
    fn differing_values_not_equal() {
        assert!(!canonical_equal(&json!({"x": "a"}), &json!({"x": "b"})));
    }

    #[test]
    fn differing_keys_not_equal() {
        assert!(!canonical_equal(&json!({"x": 1}), &json!({"y": 1})));
    }

    #[test]
    fn nested_order_independence() {
        let a = json!({"outer": {"b": 2, "a": 1}});
        let b = json!({"outer": {"a": 1, "b": 2}});
        assert!(canonical_equal(&a, &b));
    }

    #[test]
    fn array_order_matters() {
        // Arrays are ordered; [1,2] != [2,1].
        assert!(!canonical_equal(&json!([1, 2]), &json!([2, 1])));
        assert!(canonical_equal(&json!([1, 2]), &json!([1, 2])));
    }

    #[test]
    fn primitive_values() {
        assert!(canonical_equal(&json!("hello"), &json!("hello")));
        assert!(canonical_equal(&json!(null), &json!(null)));
        assert!(canonical_equal(&json!(true), &json!(true)));
        assert!(!canonical_equal(&json!(true), &json!(false)));
    }
}

#[cfg(test)]
mod strip_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identical_after_strip_runner_id() {
        let a = json!({
            "runner_id": "lm-eval-harness@0.4.2",
            "grader_id": "exact-match-v1",
            "prompt_protocol": "zero-shot-mcq-v1"
        });
        let b = json!({
            "runner_id": "custom-runner@2.1",
            "grader_id": "exact-match-v1",
            "prompt_protocol": "zero-shot-mcq-v1"
        });
        assert!(canonical_equal_after_strip(&a, &b, &["runner_id"]));
    }

    #[test]
    fn different_in_another_field() {
        let a = json!({"runner_id": "x", "grader_id": "g1"});
        let b = json!({"runner_id": "y", "grader_id": "g2"});
        // Only runner_id is stripped; grader_id still differs.
        assert!(!canonical_equal_after_strip(&a, &b, &["runner_id"]));
    }

    #[test]
    fn strip_multiple_fields() {
        let a = json!({"a": 1, "b": 2, "c": 3});
        let b = json!({"a": 9, "b": 8, "c": 3});
        assert!(canonical_equal_after_strip(&a, &b, &["a", "b"]));
    }

    #[test]
    fn empty_strip_list_equivalent_to_canonical_equal() {
        let a = json!({"x": 1, "y": 2});
        let b = json!({"y": 2, "x": 1});
        assert_eq!(
            canonical_equal_after_strip(&a, &b, &[]),
            canonical_equal(&a, &b),
        );
    }

    #[test]
    fn non_object_inputs_always_false() {
        assert!(!canonical_equal_after_strip(
            &json!("str"),
            &json!("str"),
            &[]
        ));
        assert!(!canonical_equal_after_strip(
            &json!([1, 2]),
            &json!([1, 2]),
            &[]
        ));
        assert!(!canonical_equal_after_strip(
            &json!({"a": 1}),
            &json!("str"),
            &[]
        ));
    }

    #[test]
    fn missing_field_in_strip_list_is_harmless() {
        let a = json!({"a": 1});
        let b = json!({"a": 1});
        assert!(canonical_equal_after_strip(&a, &b, &["nonexistent"]));
    }

    #[test]
    fn duplicate_field_in_strip_list_is_harmless() {
        let a = json!({"a": 1, "b": 2});
        let b = json!({"a": 9, "b": 2});
        assert!(canonical_equal_after_strip(&a, &b, &["a", "a"]));
    }
}

#[cfg(test)]
mod hash_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deterministic() {
        let v = json!({"x": 1, "y": [1, 2, 3]});
        assert_eq!(canonical_hash(&v), canonical_hash(&v));
    }

    #[test]
    fn key_order_independent() {
        let a = json!({"x": 1, "y": 2});
        let b = json!({"y": 2, "x": 1});
        assert_eq!(canonical_hash(&a), canonical_hash(&b));
    }

    #[test]
    fn different_content_different_hash() {
        assert_ne!(
            canonical_hash(&json!({"x": 1})),
            canonical_hash(&json!({"x": 2})),
        );
    }

    #[test]
    fn matches_sha256_of_atl_jcs_output() {
        // Sanity check: canonical_bytes must produce the same result as
        // calling atl_core::jcs::canonicalize directly.
        let v = json!({"b": 1, "a": 2});
        let bytes = canonical_bytes(&v);
        let from_atl = atl_core::canonicalize(&v).into_bytes();
        assert_eq!(bytes, from_atl);

        let h = canonical_hash(&v);
        let expected = Sha256::digest(&bytes);
        // `expected` is a GenericArray<u8, U32>; compare via slice.
        assert_eq!(h.as_bytes(), expected.as_slice());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arb_scalar() -> impl Strategy<Value = serde_json::Value> {
        prop_oneof![
            Just(serde_json::Value::Null),
            any::<bool>().prop_map(serde_json::Value::Bool),
            any::<i64>().prop_map(|n| serde_json::json!(n)),
            ".*".prop_map(serde_json::Value::String),
        ]
    }

    proptest! {
        #[test]
        fn reflexive(v in arb_scalar()) {
            prop_assert!(canonical_equal(&v, &v));
        }

        #[test]
        fn hash_reflexive(v in arb_scalar()) {
            prop_assert_eq!(canonical_hash(&v), canonical_hash(&v));
        }

        #[test]
        fn strip_symmetric(
            a in prop::collection::hash_map(".*", any::<i64>(), 0..5),
            b in prop::collection::hash_map(".*", any::<i64>(), 0..5),
            fields in prop::collection::vec(".*", 0..3),
        ) {
            let a_val = serde_json::to_value(&a).unwrap();
            let b_val = serde_json::to_value(&b).unwrap();
            let fields_refs: Vec<&str> = fields.iter().map(String::as_str).collect();
            // Symmetry: strip(a,b) == strip(b,a).
            prop_assert_eq!(
                canonical_equal_after_strip(&a_val, &b_val, &fields_refs),
                canonical_equal_after_strip(&b_val, &a_val, &fields_refs),
            );
        }
    }
}
