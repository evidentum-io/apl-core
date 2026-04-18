//! Canonical equality helpers per apl-spec.md §4.3.1.
//!
//! Thin wrappers around `atl_core::jcs::canonicalize`. Provides:
//! - `canonical_equal(a, b)` — exact-byte equality of JCS canonical forms
//! - `canonical_equal_after_strip(a, b, fields)` — equality after field removal
//!
//! Implementation pending.
