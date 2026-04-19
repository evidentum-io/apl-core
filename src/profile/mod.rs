//! Vertical profiles and the [`Profile`] trait.
//!
//! The [`Profile`] trait is the extension point through which vertical profiles
//! plug into APL verification.
//!
//! # Re-exports
//!
//! The most commonly used items are re-exported at this level so callers need
//! not import directly from the `trait_def` submodule.

pub mod trait_def;
pub use trait_def::{BridgeCheckResult, Profile, ProfileCheckResult, ProfileFailure};
