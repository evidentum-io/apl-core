//! Bridge tightening for APL/ATS profile.
//!
//! When two frames claim different canonical hashes, the bridge MUST carry a
//! `comparison_scope.source_descriptors` mapping that correlates source indices
//! and assumptions between the frames.

use serde_json::Value;

use apl_core::core::bridge::Bridge;
use apl_core::core::frame::Frame;
use apl_core::core::relation::RelationQuery;
use apl_core::diagnostics::APL_BRIDGE_FRAME_MISMATCH;
use apl_core::profile::trait_def::BridgeCheckResult;

use crate::diagnostics::APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP;

/// Check whether a bridge is applicable under APL/ATS profile constraints.
///
/// # Algorithm (fail-fast)
///
/// 1. **Defensive frame-match:** verify that the bridge's `source_frame.hash`
///    and `target_frame.hash` match the resolved frames' canonical hashes.
///    Returns `Err([APL_BRIDGE_FRAME_MISMATCH])` on mismatch.
/// 2. **Same-frame test:** if the source and target frames share the same
///    canonical hash, return `Ok(())` — no descriptor mapping is needed.
/// 3. **Source descriptors mapping validation:** when frames differ, access
///    `bridge.raw["comparison_scope"]["source_descriptors"]` and validate:
///    - Must exist and be a JSON array (empty array is valid).
///    - Each element must be an object with `source_index` (integer) and
///      `assumptions` (array of strings).
///
///    Returns `Err([APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP])` on any violation.
///
/// # Errors
///
/// Returns `Err(Vec<DiagnosticCode>)` if the bridge is not applicable.
pub fn check_bridge_applicability(
    bridge: &Bridge,
    source_frame: &Frame,
    target_frame: &Frame,
    _query: &RelationQuery,
) -> BridgeCheckResult {
    // Step 1: defensive frame-match.
    // Verify that the bridge's pinned hashes match the resolved frames.
    if bridge.source_frame.hash != source_frame.canonical_hash() {
        return Err(vec![APL_BRIDGE_FRAME_MISMATCH]);
    }
    if bridge.target_frame.hash != target_frame.canonical_hash() {
        return Err(vec![APL_BRIDGE_FRAME_MISMATCH]);
    }

    // Step 2: same-frame test.
    // When source and target are the same frame, no descriptor mapping
    // cross-walk is needed.
    if source_frame.canonical_hash() == target_frame.canonical_hash() {
        return Ok(());
    }

    // Step 3: source descriptors mapping validation for cross-frame bridges.
    let mapping = bridge
        .raw
        .get("comparison_scope")
        .and_then(|cs| cs.get("source_descriptors"))
        .ok_or_else(|| vec![APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP])?;

    validate_source_descriptors_mapping(mapping)
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Validate the `source_descriptors` array from the bridge's comparison scope.
///
/// The mapping MUST be a JSON array. An empty array is valid (no descriptors to
/// correlate). Each element is validated by [`validate_mapping_element`].
fn validate_source_descriptors_mapping(mapping: &Value) -> BridgeCheckResult {
    let arr = mapping
        .as_array()
        .ok_or_else(|| vec![APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP])?;

    for elem in arr {
        validate_mapping_element(elem)?;
    }

    Ok(())
}

/// Validate a single element of the `source_descriptors` array.
///
/// Each element MUST be a JSON object with:
/// - `source_index`: MUST be present and MUST be a JSON integer
///   (float values like `0.5` are rejected because `Value::as_i64()` returns
///   `None` for non-integer numbers).
/// - `assumptions`: MUST be present and MUST be an array of strings.
///   Empty assumptions arrays and empty individual strings are valid.
fn validate_mapping_element(element: &Value) -> BridgeCheckResult {
    let obj = element
        .as_object()
        .ok_or_else(|| vec![APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP])?;

    // Validate source_index: required, must be a JSON integer.
    let source_index = obj
        .get("source_index")
        .ok_or_else(|| vec![APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP])?;
    if source_index.as_i64().is_none() {
        return Err(vec![APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP]);
    }

    // Validate assumptions: required, must be an array of strings.
    let assumptions = obj
        .get("assumptions")
        .ok_or_else(|| vec![APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP])?;
    let assumptions_arr = assumptions
        .as_array()
        .ok_or_else(|| vec![APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP])?;

    for a in assumptions_arr {
        if !a.is_string() {
            return Err(vec![APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP]);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests (in submodule)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "bridge_tests.rs"]
mod bridge_tests;
