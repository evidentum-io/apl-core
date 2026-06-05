//! Registration of APL/ATS profile diagnostic codes.
//!
//! Downstream applications that deserialize [`apl_core::diagnostics::DiagnosticCode`]
//! values from APL/ATS JSON output MUST call [`register`] once at startup,
//! before any deserialization takes place. The simplest placement is at the
//! top of `main()` or in a `#[ctor]`-style init if the runtime supports it.
//!
//! # Example
//!
//! ```rust
//! apl_ats::register();
//! ```

use crate::diagnostics::{
    APL_ATS_MISSING_SOURCE_DESCRIPTORS, APL_ATS_EMPTY_SOURCE_DESCRIPTORS,
    APL_ATS_INVALID_SOURCE_DESCRIPTOR, APL_ATS_MISSING_CONFIDENCE,
    APL_ATS_INVALID_CONFIDENCE, APL_ATS_MISSING_CLASSIFICATION,
    APL_ATS_MISSING_METHODOLOGY, APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP,
    APL_ATS_FRAME_NOT_PROFILE,
};

/// Register all APL/ATS diagnostic codes into the apl-core whitelist registry.
///
/// Must be called once at application startup before any deserialization of
/// `DiagnosticCode` values that originate from APL/ATS JSON output. Calling
/// this function multiple times is safe and idempotent.
///
/// # Example
///
/// ```rust
/// apl_ats::register();
/// ```
pub fn register() {
    apl_core::diagnostics::register_diagnostic_codes(&[
        APL_ATS_MISSING_SOURCE_DESCRIPTORS.as_str(),
        APL_ATS_EMPTY_SOURCE_DESCRIPTORS.as_str(),
        APL_ATS_INVALID_SOURCE_DESCRIPTOR.as_str(),
        APL_ATS_MISSING_CONFIDENCE.as_str(),
        APL_ATS_INVALID_CONFIDENCE.as_str(),
        APL_ATS_MISSING_CLASSIFICATION.as_str(),
        APL_ATS_MISSING_METHODOLOGY.as_str(),
        APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP.as_str(),
        APL_ATS_FRAME_NOT_PROFILE.as_str(),
    ]);
}
