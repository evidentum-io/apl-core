//! Core APL verification modules (pure, no I/O).

pub mod bridge;
pub mod carrier;
pub mod claim;
pub mod frame;
pub mod hash;
pub mod jcs;
pub mod output;
pub mod receipt;
pub mod relation;
pub mod resolver;
pub mod transformation;
pub mod verify;

pub use hash::{parse_hash_string, Hash, ParseError, Reference};
pub use jcs::{canonical_bytes, canonical_equal, canonical_equal_after_strip, canonical_hash};
