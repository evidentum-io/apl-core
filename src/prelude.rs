//! Convenient re-exports for common use cases.
//!
//! ```rust,ignore
//! use apl_core::prelude::*;
//! ```

pub use crate::core::carrier::{CarrierOutcome, CarrierVerifier};
pub use crate::core::claim::{Claim, ClaimInner, ClaimKind, ClaimParseError, Statement, Subject};
pub use crate::core::frame::{Frame, FrameParseError};
pub use crate::core::output::{CoreOutcome, RelationOutcome, VerifierOutput};
pub use crate::core::resolver::{
    BridgeResolution, BridgeResolver, FrameResolution, FrameResolver, InMemoryBridgeResolver,
    InMemoryFrameResolver,
};
pub use crate::core::verify::verify_receipt;
pub use crate::profile::trait_def::{Profile, ProfileCheckResult, ProfileFailure};
