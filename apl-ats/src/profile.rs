//! Profile trait implementation.

use apl_core::core::bridge::Bridge;
use apl_core::core::frame::Frame;
use apl_core::core::relation::RelationQuery;
use apl_core::profile::trait_def::{BridgeCheckResult, Profile, ProfileCheckResult};

use crate::{bridge, frame};

/// Analytic tradecraft standards profile marker.
///
/// Stateless, thread-safe unit struct.
#[derive(Debug, Clone, Copy, Default)]
pub struct AtsProfile;

impl Profile for AtsProfile {
    fn id(&self) -> &'static str {
        "apl/ats/v0.1"
    }

    fn check_frame(&self, f: &Frame) -> ProfileCheckResult {
        frame::check_frame(f)
    }

    fn check_bridge_applicability(
        &self,
        b: &Bridge,
        source_frame: &Frame,
        target_frame: &Frame,
        query: &RelationQuery,
    ) -> BridgeCheckResult {
        bridge::check_bridge_applicability(b, source_frame, target_frame, query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apl_core::profile::trait_def::Profile;

    #[test]
    fn profile_id_returns_expected_string() {
        let profile = AtsProfile;
        assert_eq!(profile.id(), "apl/ats/v0.1");
    }

    #[test]
    fn default_instance_has_correct_id() {
        #[allow(clippy::default_constructed_unit_structs)]
        let profile = AtsProfile::default();
        assert_eq!(profile.id(), "apl/ats/v0.1");
    }

    #[test]
    fn id_works_via_dyn_profile() {
        let profile: &dyn Profile = &AtsProfile;
        assert_eq!(profile.id(), "apl/ats/v0.1");
    }
}
