//! Core APL verification modules (pure, no I/O).

pub mod bridge;
pub mod carrier;
pub mod claim;
pub mod evaluate;
pub mod frame;
pub mod hash;
pub mod jcs;
pub mod output;
pub mod receipt;
pub mod relation;
pub mod resolver;
pub mod transformation;
pub mod verify;

pub use bridge::{Bridge, BridgeParseError, ComparisonScope};
pub use carrier::{CarrierOutcome, CarrierVerifier};
pub use claim::{Claim, ClaimInner, ClaimKind, ClaimParseError, Statement, Subject};
pub use evaluate::{evaluate_relation, PairwiseInput, ReceiptInput};
pub use frame::{Frame, FrameParseError, Observer, StringOrObject};
pub use hash::{parse_hash_string, Hash, ParseError, Reference};
pub use jcs::{canonical_bytes, canonical_equal, canonical_equal_after_strip, canonical_hash};
pub use output::{CoreOutcome, PairwiseOutput, RelationOutcome, SideCore, VerifierOutput};
pub use relation::{RelationQuery, RelationQueryParseError};
pub use resolver::{
    BridgeResolution, BridgeResolver, FrameResolution, FrameResolver, InMemoryBridgeResolver,
    InMemoryFrameResolver,
};
pub use transformation::{Transformation, TransformationParseError};
pub use verify::verify_receipt;
