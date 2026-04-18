//! Core error types for apl-core.
//!
//! These errors cover structural parsing, canonical-equality failures, and
//! resolver-side failures. Verifier-level outcomes (valid/invalid) are NOT
//! errors — they are returned via `VerifierOutput`.

use thiserror::Error;

/// Main error type for apl-core operations.
#[derive(Debug, Error)]
pub enum AplError {
    /// Placeholder - will be expanded in a future wave.
    #[error("not implemented")]
    NotImplemented,
}

/// Result type alias using AplError
pub type AplResult<T> = Result<T, AplError>;
