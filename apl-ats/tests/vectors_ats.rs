//! Vector-driven integration tests for the ATS vertical profile.
//!
//! Loads every fixture from `test_data/vectors/single/` and
//! `test_data/vectors/pairwise/` inside the `apl-ats` crate and runs them
//! through the core verifier and pairwise evaluator with the [`AtsProfile`]
//! active.
//!
//! # Shared harness
//!
//! All shared types, mock carriers, hash-placeholder substitution, and
//! vector-runner functions live in the sibling module [`common`].  This file
//! only contains the top-level `#[test]` discovery functions.
//!
//! # Dedicated integration tests
//!
//! Manual scenario tests (not driven by vector files) live in
//! [`dedicated_ats`] (file `tests/dedicated_ats.rs`).

mod common;

use common::*;
use std::{fs, path::Path};

// ---------------------------------------------------------------------------
// Single vector runner test
// ---------------------------------------------------------------------------

#[test]
fn all_single_vectors_ats() {
    let dir = Path::new("test_data/vectors/single");
    assert!(
        dir.exists(),
        "test_data/vectors/single directory not found; run from apl-ats crate root"
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
        count >= 17,
        "expected >= 17 single vectors, found {count}"
    );
}

// ---------------------------------------------------------------------------
// Pairwise vector runner test
// ---------------------------------------------------------------------------

#[test]
fn all_pairwise_vectors_ats() {
    let dir = Path::new("test_data/vectors/pairwise");
    assert!(
        dir.exists(),
        "test_data/vectors/pairwise directory not found; run from apl-ats crate root"
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
        count >= 16,
        "expected >= 16 pairwise vectors, found {count}"
    );
}
