//! Profile trait implementation.

use apl_core::core::frame::Frame;
use apl_core::profile::trait_def::{Profile, ProfileCheckResult};

use crate::frame;

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
