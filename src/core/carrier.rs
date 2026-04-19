//! `CarrierVerifier` trait declaration per `apl-spec.md §15.1`.
//!
//! apl-core declares only the trait. The reference impl lives in `apl-cli` and
//! delegates to `atl_core::verify_receipt`.
//!
//! # Critical Design Constraint
//!
//! Per `apl-spec.md §15.1`: "Compatible APL-on-ATL verifier MUST rely on
//! external carrier verifier as a black box and MUST NOT override ATL
//! cryptographic verification inside APL layer."
//!
//! apl-core consumes [`CarrierVerifier::verify_carrier`] as an opaque
//! boolean-plus-payload function and **never** inspects the carrier format.

use serde_json::Value;

/// Result of a carrier verification call per `apl-spec.md §15.1`.
///
/// This type is the full contract between apl-core and any carrier layer.
/// apl-core MUST NOT peek into the carrier format beyond what this enum
/// exposes.
#[derive(Debug, Clone)]
pub enum CarrierOutcome {
    /// Carrier proof verified successfully.
    ///
    /// `payload` is the carrier payload (may be empty bytes).
    /// `metadata` is the authoritative metadata object from which apl-core
    /// will extract `metadata.apl` (`§15.1`, `§15.2`).
    Valid {
        /// Carrier payload bytes, passed through opaquely.
        payload: Vec<u8>,
        /// Metadata object from which `metadata.apl` is extracted.
        metadata: Value,
    },

    /// Carrier proof failed verification.
    ///
    /// apl-core MUST stop APL validation and return `apl-invalid` with
    /// `FailureClass::CarrierFailure`.
    Invalid {
        /// Optional diagnostic string from the carrier layer. apl-core does
        /// NOT parse this; it is for logging only.
        reason: Option<String>,
    },
}

/// The carrier verification interface per `apl-spec.md §15.1`.
///
/// apl-core ships only the trait. `apl-cli` provides the reference impl that
/// delegates to `atl_core::verify_receipt`.
///
/// # Contract
///
/// - `verify_carrier` MUST be pure with respect to its input: the same bytes
///   MUST produce the same `CarrierOutcome`.
/// - `verify_carrier` MUST NOT panic on any input.
/// - `verify_carrier` MUST NOT perform network I/O or mutate external state.
///
/// Implementations MAY hold internal state (e.g. a trusted public key).
///
/// # Object Safety
///
/// This trait is object-safe. Use `&dyn CarrierVerifier` or
/// `Arc<dyn CarrierVerifier>` to pass it across module boundaries.
pub trait CarrierVerifier: Send + Sync {
    /// Verify the carrier proof over `receipt_bytes` and return the outcome.
    fn verify_carrier(&self, receipt_bytes: &[u8]) -> CarrierOutcome;
}

#[cfg(test)]
mod carrier_tests {
    use super::*;

    /// Extracts `(payload, metadata)` from a `Valid` outcome; panics on `Invalid`.
    ///
    /// Using a named helper keeps test bodies free of match-arms, which avoids
    /// llvm-cov flagging the unreachable else-branch of every `if let` as uncovered.
    #[track_caller]
    fn unwrap_valid(outcome: CarrierOutcome) -> (Vec<u8>, serde_json::Value) {
        match outcome {
            CarrierOutcome::Valid { payload, metadata } => (payload, metadata),
            CarrierOutcome::Invalid { reason } => {
                panic!("expected Valid, got Invalid {{ reason: {reason:?} }}");
            }
        }
    }

    /// Extracts the `reason` from an `Invalid` outcome; panics on `Valid`.
    #[track_caller]
    fn unwrap_invalid(outcome: CarrierOutcome) -> Option<String> {
        match outcome {
            CarrierOutcome::Invalid { reason } => reason,
            CarrierOutcome::Valid { .. } => panic!("expected Invalid, got Valid"),
        }
    }

    struct AlwaysValid;

    impl CarrierVerifier for AlwaysValid {
        fn verify_carrier(&self, _: &[u8]) -> CarrierOutcome {
            CarrierOutcome::Valid {
                payload: vec![],
                metadata: serde_json::json!({}),
            }
        }
    }

    struct AlwaysInvalid;

    impl CarrierVerifier for AlwaysInvalid {
        fn verify_carrier(&self, _: &[u8]) -> CarrierOutcome {
            CarrierOutcome::Invalid { reason: None }
        }
    }

    /// AC1, AC9: Trait is object-safe and usable via `&dyn CarrierVerifier`.
    #[test]
    fn trait_is_object_safe() {
        let v: &dyn CarrierVerifier = &AlwaysValid;
        assert!(matches!(
            v.verify_carrier(&[]),
            CarrierOutcome::Valid { .. }
        ));
        let i: &dyn CarrierVerifier = &AlwaysInvalid;
        assert!(matches!(
            i.verify_carrier(&[]),
            CarrierOutcome::Invalid { .. }
        ));
    }

    /// AC9: Usable as `Box<dyn CarrierVerifier>` (trait object on heap).
    #[test]
    fn boxed_dyn_carrier_verifier() {
        let boxed: Box<dyn CarrierVerifier> = Box::new(AlwaysValid);
        let (payload, metadata) = unwrap_valid(boxed.verify_carrier(b"any bytes"));
        assert!(payload.is_empty());
        assert_eq!(metadata, serde_json::json!({}));
    }

    /// AC2: `CarrierOutcome::Valid` carries both `payload: Vec<u8>` and
    /// `metadata: Value`.
    #[test]
    fn valid_carries_payload_and_metadata() {
        struct WithPayload;
        impl CarrierVerifier for WithPayload {
            fn verify_carrier(&self, _: &[u8]) -> CarrierOutcome {
                CarrierOutcome::Valid {
                    payload: vec![1, 2, 3],
                    metadata: serde_json::json!({ "apl": { "version": "0.1" } }),
                }
            }
        }

        let verifier: &dyn CarrierVerifier = &WithPayload;
        let (payload, metadata) = unwrap_valid(verifier.verify_carrier(&[]));
        assert_eq!(payload, vec![1u8, 2, 3]);
        assert_eq!(metadata, serde_json::json!({ "apl": { "version": "0.1" } }));
    }

    /// AC3: `CarrierOutcome::Invalid` carries an optional reason.
    #[test]
    fn invalid_carries_optional_reason() {
        struct InvalidWithReason;
        impl CarrierVerifier for InvalidWithReason {
            fn verify_carrier(&self, _: &[u8]) -> CarrierOutcome {
                CarrierOutcome::Invalid {
                    reason: Some("signature mismatch".into()),
                }
            }
        }

        let verifier: &dyn CarrierVerifier = &InvalidWithReason;
        let reason = unwrap_invalid(verifier.verify_carrier(&[]));
        assert_eq!(reason.as_deref(), Some("signature mismatch"));

        // None reason is also valid.
        let none_verifier: &dyn CarrierVerifier = &AlwaysInvalid;
        let reason2 = unwrap_invalid(none_verifier.verify_carrier(&[]));
        assert!(reason2.is_none());
    }

    /// Exercises the panic arm of `unwrap_valid` — ensures the helper's
    /// `Invalid` branch is reached and the test framework sees a deliberate panic.
    #[test]
    #[should_panic(expected = "expected Valid")]
    fn unwrap_valid_panics_on_invalid() {
        unwrap_valid(CarrierOutcome::Invalid { reason: None });
    }

    /// Exercises the panic arm of `unwrap_invalid` — ensures the helper's
    /// `Valid` branch is reached and the test framework sees a deliberate panic.
    #[test]
    #[should_panic(expected = "expected Invalid")]
    fn unwrap_invalid_panics_on_valid() {
        unwrap_invalid(CarrierOutcome::Valid {
            payload: vec![],
            metadata: serde_json::json!({}),
        });
    }

    /// `CarrierOutcome` implements `Clone` — both variants cloneable.
    #[test]
    fn carrier_outcome_clone() {
        let valid = CarrierOutcome::Valid {
            payload: vec![1, 2, 3],
            metadata: serde_json::json!({ "k": "v" }),
        };
        let cloned = valid.clone();
        assert!(matches!(cloned, CarrierOutcome::Valid { .. }));

        let invalid = CarrierOutcome::Invalid {
            reason: Some("err".into()),
        };
        let cloned_inv = invalid.clone();
        assert!(matches!(cloned_inv, CarrierOutcome::Invalid { .. }));
    }

    /// `CarrierOutcome` implements `Debug` — both variants format without panic.
    #[test]
    fn carrier_outcome_debug() {
        let valid = CarrierOutcome::Valid {
            payload: vec![],
            metadata: serde_json::json!({}),
        };
        let s = format!("{valid:?}");
        assert!(s.contains("Valid"));

        let invalid = CarrierOutcome::Invalid { reason: None };
        let s = format!("{invalid:?}");
        assert!(s.contains("Invalid"));
    }
}
