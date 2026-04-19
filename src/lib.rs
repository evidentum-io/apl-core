//! # apl-core
//!
//! Pure verification library for the APL Protocol v0.1 (Anchored Parallax Log),
//! reference profile `APL-on-ATL`.
//!
//! apl-core provides:
//!
//! - **Structural validation** of APL claims, frames, bridges, transformations
//! - **Single-receipt verification** per `apl-spec.md §11`
//! - **Pairwise relation evaluation** per `apl-relation-spec.md §7`
//! - **Canonical equality** helpers over JCS (via `atl-core::jcs`)
//! - **Pluggable vertical profiles** via the [`profile::trait_def::Profile`] trait
//! - **Trait-based dependency injection** for carrier verification and artifact
//!   resolution
//!
//! apl-core contains NO I/O and NO carrier cryptography. The [`CarrierVerifier`]
//! trait is the sole integration point with the carrier layer (typically
//! `atl-core`, wired through `apl-cli`).
//!
//! ## Quick Start: Verify a Single Receipt
//!
//! ```rust,ignore
//! use apl_core::prelude::*;
//!
//! let receipt_bytes: &[u8] = /* opaque carrier bytes */;
//! let carrier: &dyn CarrierVerifier = /* provided by apl-cli */;
//! let frames = InMemoryFrameResolver::new();
//! let bridges = InMemoryBridgeResolver::new();
//!
//! let (output, verified) = verify_receipt(
//!     receipt_bytes, carrier, &frames, &bridges, None,
//! );
//!
//! match output.core_outcome {
//!     CoreOutcome::AplValid => {
//!         println!("{}", output.to_json_pretty());
//!         // `verified` is `Some(VerifiedReceipt)` — an opaque token that can
//!         // be passed to `evaluate_relation` via `ReceiptInput::Prevalidated`
//!         // without re-running carrier validation.
//!         let _reusable: VerifiedReceipt = verified.unwrap();
//!     }
//!     CoreOutcome::AplInvalid => {
//!         // `verified` is `None` — the token is only minted for AplValid receipts.
//!         println!("invalid: {:?}", output.failure_classes);
//!         for d in &output.diagnostics {
//!             println!("  - {d}");
//!         }
//!     }
//! }
//! ```
//!
//! ## Quick Start: Pairwise Relation
//!
//! ```rust,ignore
//! use apl_core::prelude::*;
//!
//! let input = PairwiseInput {
//!     left:  ReceiptInput::Bytes(left_bytes),
//!     right: ReceiptInput::Bytes(right_bytes),
//!     query: RelationQuery::parse(&query_json).unwrap(),
//!     supplied_bridges: vec![],
//! };
//!
//! let output = evaluate_relation(
//!     input, carrier, &frames, &bridges, None,
//! );
//!
//! assert_eq!(output.relation_outcome, RelationOutcome::Incomparable);
//! ```
//!
//! ## Architecture
//!
//! ```text
//! apl-core (this)    Pure APL verification; no I/O, no carrier crypto.
//!      ^
//!      |
//! apl-cli            Wires `atl-core` into CarrierVerifier;
//!                    provides filesystem/network resolvers.
//!                    Separate crate, next cycle.
//! ```
//!
//! ## In-memory resolver doc-test
//!
//! ```
//! use apl_core::prelude::*;
//!
//! let mut frames = InMemoryFrameResolver::new();
//! let h = frames.insert(serde_json::json!({
//!     "version": "0.1",
//!     "observer": "o",
//!     "procedure": "p",
//!     "aspect": ["a"],
//!     "scope": "s",
//!     "invariance": ["i"],
//!     "exclusions": ["e"]
//! }));
//! assert!(matches!(frames.resolve(&h), FrameResolution::Found(_)));
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]
#![deny(unsafe_code)]

// ============================================================================
// Core modules
// ============================================================================

/// Core APL verification modules (pure, no I/O).
pub mod core;

/// Pluggable vertical profile extension point.
pub mod profile;

// ============================================================================
// Error types, failure classes, diagnostics
// ============================================================================

/// Diagnostic status codes per `apl-spec.md §12.3`.
pub mod diagnostics;

mod error;
mod failure;

/// Convenient re-exports for common use cases.
pub mod prelude;

pub use diagnostics::DiagnosticCode;
pub use error::{AplError, AplResult};
pub use failure::FailureClass;

// ============================================================================
// Re-exports at crate root for convenience
// ============================================================================

// Content-addressed types
pub use core::hash::{parse_hash_string, Hash, ParseError, Reference};

// JCS wrappers
pub use core::jcs::{
    canonical_bytes, canonical_equal, canonical_equal_after_strip, canonical_hash,
};

// Protocol artifact types
pub use core::bridge::{Bridge, BridgeParseError, ComparisonScope};
pub use core::claim::{Claim, ClaimInner, ClaimKind, ClaimParseError, Statement, Subject};
pub use core::frame::{Frame, FrameParseError, Observer, StringOrObject};
pub use core::transformation::{Transformation, TransformationParseError};

// Carrier + resolvers
pub use core::carrier::{CarrierOutcome, CarrierVerifier};
pub use core::resolver::{
    BridgeResolution, BridgeResolver, FrameResolution, FrameResolver, InMemoryBridgeResolver,
    InMemoryFrameResolver,
};

// Verification entry points
pub use core::evaluate::{evaluate_relation, PairwiseInput, ReceiptInput};
pub use core::verified::VerifiedReceipt;
pub use core::verify::verify_receipt;

// Output types
pub use core::output::{CoreOutcome, PairwiseOutput, RelationOutcome, SideCore, VerifierOutput};

// Relation query
pub use core::relation::{RelationQuery, RelationQueryParseError};

// Profile trait
pub use profile::trait_def::{BridgeCheckResult, Profile, ProfileCheckResult, ProfileFailure};

// ============================================================================
// Version constants
// ============================================================================

/// Crate version, taken from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// APL Protocol version implemented by this crate.
pub const PROTOCOL_VERSION: &str = "0.1";

/// APL claim / frame / bridge / transformation artifact version string.
pub const ARTIFACT_VERSION: &str = "0.1";
