//! AI-Eval profile for APL Protocol — reference implementation of `APL/AI-Eval v1.0`.

#![deny(unsafe_code)]

pub mod bridge;
pub mod claim;
pub mod diagnostics;
pub mod frame;
pub mod profile;
pub mod register;

pub use profile::AiEvalProfile;
pub use register::register;
