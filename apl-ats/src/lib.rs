//! APL/ATS vertical profile for APL Protocol — Analytic Tradecraft Standards.

#![deny(unsafe_code)]

pub mod diagnostics;
mod register;
mod frame;
mod bridge;
mod profile;

pub use profile::AtsProfile;
pub use register::register;
