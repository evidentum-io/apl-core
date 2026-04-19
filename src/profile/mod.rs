//! Vertical profiles and the [`Profile`] trait.
//!
//! The [`Profile`] trait is the extension point through which vertical profiles
//! plug into APL verification. See [`trait_def`] for the full contract.
//!
//! # Re-exports
//!
//! The most commonly used items are re-exported at this level so callers need
//! not import directly from [`trait_def`].

pub mod trait_def;
pub use trait_def::{BridgeCheckResult, Profile, ProfileCheckResult, ProfileFailure};

#[cfg(feature = "profile-ai-eval")]
pub mod ai_eval;
