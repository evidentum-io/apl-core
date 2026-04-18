//! Failure classes per `apl-spec.md §10`.
//!
//! A failure class is a coarse marker attached to an invalid receipt. An
//! `apl-valid` receipt MUST have an empty `failure_classes` collection. An
//! `apl-invalid` receipt MUST carry at least one failure class.

use serde::{Deserialize, Serialize};

/// Failure classes per `apl-spec.md §10`.
///
/// Verifier SHOULD classify each invalid receipt into one or more failure
/// classes. An `apl-valid` receipt MUST report an empty `failure_classes`.
/// An `apl-invalid` receipt MUST report at least one failure class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureClass {
    /// Carrier proof failed verification (`apl-spec.md §10.1`).
    CarrierFailure,

    /// `metadata.apl` structure is missing or violates typing rules
    /// (`apl-spec.md §10.2`).
    ClaimStructureFailure,

    /// `frame_ref` or related reference object is missing or malformed
    /// (`apl-spec.md §10.3`).
    ReferenceFailure,

    /// Frame cannot be resolved, hash mismatch, or kernel violation
    /// (`apl-spec.md §10.4`).
    FrameFailure,

    /// `claim.aspect_refs` element not in `frame.aspect`
    /// (`apl-spec.md §10.5`).
    SemanticLinkageFailure,

    /// `claim.related_frames`, `bridge_refs`, or `transformation_refs` is
    /// structurally invalid (`apl-spec.md §10.6`).
    RelationStructureFailure,
}

impl FailureClass {
    /// Kebab-case string exactly as it appears in normative text.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CarrierFailure => "carrier-failure",
            Self::ClaimStructureFailure => "claim-structure-failure",
            Self::ReferenceFailure => "reference-failure",
            Self::FrameFailure => "frame-failure",
            Self::SemanticLinkageFailure => "semantic-linkage-failure",
            Self::RelationStructureFailure => "relation-structure-failure",
        }
    }

    /// Does this failure class originate from the carrier layer?
    #[must_use]
    pub fn is_carrier(self) -> bool {
        matches!(self, Self::CarrierFailure)
    }

    /// Is this failure class structural (claim / reference / frame / linkage)?
    #[must_use]
    pub fn is_structural(self) -> bool {
        matches!(
            self,
            Self::ClaimStructureFailure
                | Self::ReferenceFailure
                | Self::FrameFailure
                | Self::SemanticLinkageFailure
        )
    }

    /// Is this failure class relation-layer?
    #[must_use]
    pub fn is_relation(self) -> bool {
        matches!(self, Self::RelationStructureFailure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact six failure classes enumerated in `apl-spec.md §10`.
    #[test]
    fn failure_class_count_is_six() {
        let all = [
            FailureClass::CarrierFailure,
            FailureClass::ClaimStructureFailure,
            FailureClass::ReferenceFailure,
            FailureClass::FrameFailure,
            FailureClass::SemanticLinkageFailure,
            FailureClass::RelationStructureFailure,
        ];
        assert_eq!(all.len(), 6);
    }

    #[test]
    fn failure_class_kebab_strings() {
        assert_eq!(FailureClass::CarrierFailure.as_str(), "carrier-failure");
        assert_eq!(
            FailureClass::ClaimStructureFailure.as_str(),
            "claim-structure-failure"
        );
        assert_eq!(FailureClass::ReferenceFailure.as_str(), "reference-failure");
        assert_eq!(FailureClass::FrameFailure.as_str(), "frame-failure");
        assert_eq!(
            FailureClass::SemanticLinkageFailure.as_str(),
            "semantic-linkage-failure"
        );
        assert_eq!(
            FailureClass::RelationStructureFailure.as_str(),
            "relation-structure-failure"
        );
    }

    #[test]
    fn failure_class_serde_kebab() {
        let json = serde_json::to_string(&FailureClass::SemanticLinkageFailure)
            .expect("serialization must succeed");
        assert_eq!(json, r#""semantic-linkage-failure""#);
    }

    #[test]
    fn failure_class_serde_carrier() {
        let json = serde_json::to_string(&FailureClass::CarrierFailure)
            .expect("serialization must succeed");
        assert_eq!(json, r#""carrier-failure""#);
    }

    #[test]
    fn is_carrier_helper() {
        assert!(FailureClass::CarrierFailure.is_carrier());
        assert!(!FailureClass::FrameFailure.is_carrier());
    }

    #[test]
    fn is_structural_helper() {
        assert!(FailureClass::ClaimStructureFailure.is_structural());
        assert!(FailureClass::ReferenceFailure.is_structural());
        assert!(FailureClass::FrameFailure.is_structural());
        assert!(FailureClass::SemanticLinkageFailure.is_structural());
        assert!(!FailureClass::CarrierFailure.is_structural());
        assert!(!FailureClass::RelationStructureFailure.is_structural());
    }

    #[test]
    fn is_relation_helper() {
        assert!(FailureClass::RelationStructureFailure.is_relation());
        assert!(!FailureClass::FrameFailure.is_relation());
    }
}
