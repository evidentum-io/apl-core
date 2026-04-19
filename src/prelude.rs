//! Convenient re-exports for common use cases.
//!
//! Import everything via:
//!
//! ```rust,ignore
//! use apl_core::prelude::*;
//! ```

// Errors, failures, diagnostics
pub use crate::diagnostics::DiagnosticCode as Diagnostic;
pub use crate::error::{AplError, AplResult};
pub use crate::failure::FailureClass;

// Content-addressed types
pub use crate::core::hash::{parse_hash_string, Hash, Reference};

// Canonical equality
pub use crate::core::jcs::{canonical_equal, canonical_equal_after_strip, canonical_hash};

// Protocol types
pub use crate::core::bridge::{Bridge, ComparisonScope};
pub use crate::core::claim::{Claim, ClaimKind, Statement, Subject};
pub use crate::core::frame::{Frame, Observer};
pub use crate::core::transformation::Transformation;

// Carrier + resolvers
pub use crate::core::carrier::{CarrierOutcome, CarrierVerifier};
pub use crate::core::resolver::{
    BridgeResolution, BridgeResolver, FrameResolution, FrameResolver, InMemoryBridgeResolver,
    InMemoryFrameResolver,
};

// Entry points
pub use crate::core::evaluate::{evaluate_relation, PairwiseInput, ReceiptInput};
pub use crate::core::verify::verify_receipt;

// Outputs
pub use crate::core::output::{CoreOutcome, PairwiseOutput, RelationOutcome, VerifierOutput};

// Relation query
pub use crate::core::relation::RelationQuery;

// Profile
pub use crate::profile::trait_def::Profile;
