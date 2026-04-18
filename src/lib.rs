//! apl-core: Pure verification library for APL Protocol v0.1
//!
//! This crate is the reference Rust implementation of APL verification for the
//! `APL-on-ATL` profile. It provides:
//!
//! - Structural validation of APL claims, frames, bridges and transformations
//! - Single-receipt verification (apl-spec.md §11)
//! - Pairwise relation evaluation (apl-relation-spec.md §7)
//! - Pluggable vertical profiles (AI-Eval included)
//!
//! It contains NO I/O operations and NO carrier cryptography. Carrier verification
//! is delegated through the `CarrierVerifier` trait (apl-spec.md §15.1). The
//! reference carrier impl lives in `apl-cli`, which plugs in `atl-core`.
//!
//! # What apl-core IS
//!
//! - Pure structural verification
//! - Canonical equality helpers over JCS (wraps `atl-core::jcs`)
//! - Trait-based resolvers (`FrameResolver`, `BridgeResolver`) with in-memory
//!   defaults for testing
//! - AI-Eval profile (gated behind `profile-ai-eval` feature)
//!
//! # What apl-core is NOT
//!
//! - No carrier cryptography (see `atl-core` via `apl-cli`)
//! - No filesystem or network I/O (see `apl-cli`)
//! - No receipt generation (APL v0.1 defines only verification)
//! - No CLI (see `apl-cli`)
//!
//! # Example: Verify a Single Receipt
//!
//! ```rust,ignore
//! use apl_core::prelude::*;
//!
//! let receipt_bytes: &[u8] = /* carrier-encoded receipt bytes */;
//! let carrier_verifier = MyCarrierVerifier::new(/* trusted key */);
//! let frames = InMemoryFrameResolver::from_json_files(&frame_paths)?;
//! let bridges = InMemoryBridgeResolver::default();
//!
//! let output = verify_receipt(
//!     receipt_bytes,
//!     &carrier_verifier,
//!     &frames,
//!     &bridges,
//!     None, // no profile
//! );
//!
//! assert_eq!(output.core_outcome, CoreOutcome::AplValid);
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]
#![deny(unsafe_code)]

pub mod core;
pub mod profile;

mod diagnostics;
mod error;
mod failure;
mod prelude;

// Re-exports
pub use diagnostics::Diagnostic;
pub use error::{AplError, AplResult};
pub use failure::FailureClass;
#[allow(unused_imports)]
// prelude is currently empty; items will be added in API-1
pub use prelude::*;
