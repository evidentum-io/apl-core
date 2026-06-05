//! Profile trait implementation.

use apl_core::{
    core::{bridge::Bridge, frame::Frame, relation::RelationQuery},
    profile::trait_def::{BridgeCheckResult, Profile, ProfileCheckResult},
};
use crate::{bridge, frame};

/// APL/ATS profile marker.
#[derive(Debug, Clone, Copy, Default)]
pub struct AtsProfile;

impl Profile for AtsProfile {
    fn id(&self) -> &'static str { "apl/ats/v1.0" }
    fn check_frame(&self, f: &Frame) -> ProfileCheckResult { frame::check_frame(f) }
    fn check_bridge_applicability(&self, b: &Bridge, s: &Frame, t: &Frame, q: &RelationQuery) -> BridgeCheckResult {
        bridge::check_bridge_applicability(b, s, t, q)
    }
}

#[cfg(test)]
mod tests {
    use { super::*, crate::diagnostics::{APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP, APL_ATS_FRAME_NOT_PROFILE},
        apl_core::{ core::{bridge::Bridge, claim::Claim, frame::Frame, relation::RelationQuery},
            profile::trait_def::Profile }, serde_json::json };

    const H: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn mkf(o: &str, t: &str, c: &str, m: &str) -> Frame {
        Frame::parse(&json!({ "version":"0.1","observer":o,"procedure":"p",
            "aspect":["a"],"scope":"s","invariance":["i"],"exclusions":["e"],
            "profile":"APL/ATS","source_descriptors":[{"source_type":t}],
            "confidence_level":c,"classification_marking":m,"methodology_ref":{"hash":H}
        })).unwrap()
    }

    fn mkb(sh: &str, th: &str) -> Bridge {
        Bridge::parse(&json!({ "version":"0.1",
            "source_frame":{"hash":sh},"target_frame":{"hash":th},
            "comparison_scope":{"source_aspects":["a"],"target_aspects":["a"],"relation_type":"rd"},
            "assumptions":[],"losses":[]
        })).unwrap()
    }

    fn mkc() -> Claim {
        Claim::parse(&json!({ "version":"0.1",
            "claim":{"kind":"observation","subject":{"id":"x"},"aspect_refs":["a"],"statement":{"predicate":"p","content":1}},
            "frame_ref":{"hash":H}
        })).unwrap()
    }

    #[test] fn id_returns_v1_0() {
        assert_eq!(AtsProfile.id(), "apl/ats/v1.0");
        assert_eq!(AtsProfile::default().id(), "apl/ats/v1.0");
        assert_eq!((&AtsProfile as &dyn Profile).id(), "apl/ats/v1.0");
    }

    #[test] fn deleg_check_frame() {
        assert_eq!(AtsProfile.check_frame(&mkf("cia","HUMINT","moderate","TS")), Ok(()));
        let f = Frame::parse(&json!({ "version":"0.1","observer":"x","procedure":"p",
            "aspect":["a"],"scope":"s","invariance":["i"],"exclusions":["e"]
        })).unwrap();
        let e = AtsProfile.check_frame(&f).unwrap_err();
        assert!(e.diagnostics.contains(&APL_ATS_FRAME_NOT_PROFILE));
    }

    #[test] fn deleg_check_bridge() {
        let f = mkf("cia","HUMINT","moderate","TS");
        let q = RelationQuery::parse(&json!({ "left_aspects":["a"],"right_aspects":["a"],
            "predicate":"p","relation_type":"rd" })).unwrap();
        let h = f.canonical_hash().to_string();
        assert_eq!(AtsProfile.check_bridge_applicability(&mkb(&h,&h),&f,&f,&q), Ok(()));
        let f2 = mkf("nsa","SIGINT","high","TS//SI");
        let e = AtsProfile.check_bridge_applicability(
            &mkb(&f.canonical_hash().to_string(), &f2.canonical_hash().to_string()), &f,&f2,&q
        ).unwrap_err();
        assert!(e.contains(&APL_ATS_BRIDGE_NO_DESCRIPTOR_MAP));
    }

    #[test] fn check_claim_ok() {
        assert_eq!(AtsProfile.check_claim(&mkc()), Ok(()));
    }

    #[test] fn cross_check_ok() {
        assert_eq!(AtsProfile.cross_check(&mkc(), &mkf("cia","HUMINT","moderate","TS")), Ok(()));
    }

    #[test] fn pairwise_relation_ok() {
        assert_eq!(AtsProfile.check_pairwise_relation(&mkc(),&mkc(),&mkf("cia","HUMINT","moderate","TS"),&mkf("cia","HUMINT","moderate","TS"),&RelationQuery::parse(&json!({ "left_aspects":["a"],"right_aspects":["a"],"predicate":"p","relation_type":"rd" })).unwrap()), Ok(()));
    }
}
