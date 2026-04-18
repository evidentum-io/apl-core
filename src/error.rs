//! Core error types for apl-core.
//!
//! These errors represent library-level failures: JSON parse errors,
//! resolver infrastructure failures, JCS canonicalization errors, profile
//! misuse, and invalid arguments.
//!
//! ## Critical Distinction
//!
//! [`AplError`] and `apl-invalid` are orthogonal. A malformed `frame_ref.hash`
//! string returned by a `FrameResolver` is a `FailureClass::ReferenceFailure`
//! reported inside a `VerifierOutput` with outcome `apl-invalid` — NOT a Rust
//! [`Err`]. An internal Rust error (e.g. allocation failure, programmer
//! mistake) is an [`AplError`].

use thiserror::Error;

/// Library-level errors that are NOT verifier-level outcomes.
///
/// A verifier-level `apl-invalid` is NOT an [`AplError`]: it is a successful
/// return of a `VerifierOutput`. [`AplError`] represents programmer mistakes,
/// resolver infrastructure failures, and pre-parse catastrophic errors that
/// prevent even constructing a `VerifierOutput`.
///
/// Parse errors inside `metadata.apl` DO NOT go through [`AplError`]; they
/// become `FailureClass::ClaimStructureFailure` inside a normal
/// `VerifierOutput`.
#[derive(Debug, Error)]
pub enum AplError {
    // ========== JSON-level errors ==========
    /// Underlying JSON parse error (e.g. the carrier payload could not be
    /// decoded as JSON at all).
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    // ========== Resolver-side errors ==========
    /// Resolver reported an internal infrastructure failure (NOT "hash not
    /// found" — that is a verifier-level outcome reported through the
    /// `FrameResolution::NotFound` / `BridgeResolution::NotFound` variants).
    #[error("resolver infrastructure error: {0}")]
    ResolverInfrastructure(String),

    // ========== Canonical-equality internal errors ==========
    /// JCS canonicalization reported an internal error.
    #[error("JCS canonicalization error: {0}")]
    Jcs(String),

    // ========== Profile misuse ==========
    /// Caller supplied a profile that declared a `relation_type` or
    /// `bridge_kind` that the profile itself does not support (programmer
    /// mistake).
    #[error("profile misuse: {0}")]
    ProfileMisuse(String),

    // ========== Catch-all ==========
    /// Invalid argument (e.g. empty byte slice passed as receipt).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

/// Result type alias for apl-core operations.
pub type AplResult<T> = Result<T, AplError>;

impl From<hex::FromHexError> for AplError {
    fn from(e: hex::FromHexError) -> Self {
        Self::InvalidArgument(format!("hex decode error: {e}"))
    }
}

#[cfg(test)]
mod apl_error_tests {
    use super::*;

    #[test]
    fn send_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<AplError>();
    }

    #[test]
    fn json_conversion() {
        let e: AplError = serde_json::from_str::<serde_json::Value>("not-json")
            .unwrap_err()
            .into();
        assert!(matches!(e, AplError::Json(_)));
    }

    #[test]
    fn hex_conversion() {
        let e: AplError = hex::decode("zz").unwrap_err().into();
        assert!(matches!(e, AplError::InvalidArgument(_)));
    }

    #[test]
    fn resolver_infrastructure_error_message() {
        let e = AplError::ResolverInfrastructure("timeout".to_string());
        assert!(e.to_string().contains("timeout"));
    }

    #[test]
    fn jcs_error_message() {
        let e = AplError::Jcs("cycle detected".to_string());
        assert!(e.to_string().contains("cycle"));
    }

    #[test]
    fn profile_misuse_error_message() {
        let e = AplError::ProfileMisuse("unknown bridge_kind".to_string());
        assert!(e.to_string().contains("unknown bridge_kind"));
    }

    #[test]
    fn invalid_argument_error_message() {
        let e = AplError::InvalidArgument("empty receipt".to_string());
        assert!(e.to_string().contains("empty receipt"));
    }
}
