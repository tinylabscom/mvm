//! Validation of host-root-signed native supervisor lifetime control.
//!
//! The caller supplies a root independently loaded from trusted host state,
//! never from the request. Host-root holders are existing trusted operators;
//! this is not caller registration, and does not resist a host administrator.

use ed25519_dalek::VerifyingKey;

use super::broker_control::{self, ControlRequest, SignedControl};
pub use mvm_contract::protocol::hvf_control::{HvfInstance, HvfInstanceControl};

/// A stop cannot be pre-signed indefinitely. Connection deadlines impose a
/// separate monotonic bound; wall-clock rollback cannot extend that deadline.
pub const MAX_STOP_AGE_SECS: u64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum HvfControlError {
    #[error("invalid host control signature")]
    Signature(#[from] broker_control::ControlError),
    #[error("wrong HVF control operation or ownership generation")]
    Binding,
    #[error("HVF stop request is stale or from the future")]
    Freshness,
}

pub fn verify_challenge(
    signed: &SignedControl,
    root: &VerifyingKey,
    expected: &HvfInstance,
    nonce: &[u8; 32],
) -> Result<[u8; 32], HvfControlError> {
    match broker_control::verify(signed, root)? {
        ControlRequest::HvfInstanceV1(HvfInstanceControl::Challenge {
            instance,
            client_nonce,
            connection_nonce,
        }) if instance == expected && client_nonce == nonce => Ok(*connection_nonce),
        _ => Err(HvfControlError::Binding),
    }
}

/// Validate under the same linearization lock as handoff and STOP publication.
/// The server consumes the connection after one request, including rejection;
/// the validator alone does not supply replay protection.
pub fn verify_stop(
    signed: &SignedControl,
    root: &VerifyingKey,
    current: &HvfInstance,
    connection: &[u8; 32],
    now_secs: u64,
) -> Result<(), HvfControlError> {
    match broker_control::verify(signed, root)? {
        ControlRequest::HvfInstanceV1(HvfInstanceControl::StopHvfInstance {
            instance,
            connection_nonce,
            issued_at_secs,
        }) if instance == current && connection_nonce == connection => {
            match now_secs.checked_sub(*issued_at_secs) {
                Some(age) if age <= MAX_STOP_AGE_SECS => Ok(()),
                _ => Err(HvfControlError::Freshness),
            }
        }
        _ => Err(HvfControlError::Binding),
    }
}

pub fn verify_finalized(
    signed: &SignedControl,
    root: &VerifyingKey,
    expected: &HvfInstance,
) -> Result<(), HvfControlError> {
    match broker_control::verify(signed, root)? {
        ControlRequest::HvfInstanceV1(HvfInstanceControl::Finalized { instance })
            if instance == expected =>
        {
            Ok(())
        }
        _ => Err(HvfControlError::Binding),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn instance() -> HvfInstance {
        HvfInstance {
            vm_id: "owned-test".into(),
            boot_nonce: [3; 32],
        }
    }

    fn signed(operation: HvfInstanceControl) -> SignedControl {
        broker_control::sign(ControlRequest::HvfInstanceV1(operation), &[7; 32]).unwrap()
    }

    fn root() -> VerifyingKey {
        SigningKey::from_bytes(&[7; 32]).verifying_key()
    }

    fn stop() -> SignedControl {
        signed(HvfInstanceControl::StopHvfInstance {
            instance: instance(),
            connection_nonce: [4; 32],
            issued_at_secs: 100,
        })
    }

    #[test]
    fn stop_roundtrip_rejects_wrong_root_vm_generation_connection_and_time() {
        let original = stop();
        let json = serde_json::to_vec(&original).unwrap();
        let decoded: SignedControl = serde_json::from_slice(&json).unwrap();
        assert_eq!(original, decoded);
        assert!(verify_stop(&decoded, &root(), &instance(), &[4; 32], 100).is_ok());
        assert!(verify_stop(&decoded, &root(), &instance(), &[4; 32], 130).is_ok());
        assert!(verify_stop(&decoded, &root(), &instance(), &[4; 32], 131).is_err());
        assert!(verify_stop(&decoded, &root(), &instance(), &[4; 32], 99).is_err());
        assert!(verify_stop(&decoded, &root(), &instance(), &[5; 32], 100).is_err());
        let mut wrong = instance();
        wrong.vm_id = "other-vm".into();
        assert!(verify_stop(&decoded, &root(), &wrong, &[4; 32], 100).is_err());
        wrong = instance();
        wrong.boot_nonce = [5; 32];
        assert!(verify_stop(&decoded, &root(), &wrong, &[4; 32], 100).is_err());
        let wrong_root = SigningKey::from_bytes(&[8; 32]).verifying_key();
        assert!(verify_stop(&decoded, &wrong_root, &instance(), &[4; 32], 100).is_err());
        let mut tampered = decoded;
        tampered.sig = "invalid".into();
        assert!(verify_stop(&tampered, &root(), &instance(), &[4; 32], 100).is_err());
    }

    #[test]
    fn challenge_requires_fresh_client_nonce_and_is_not_stop_or_finalization() {
        let challenge = signed(HvfInstanceControl::Challenge {
            instance: instance(),
            client_nonce: [6; 32],
            connection_nonce: [4; 32],
        });
        assert_eq!(
            verify_challenge(&challenge, &root(), &instance(), &[6; 32]).unwrap(),
            [4; 32]
        );
        assert!(verify_challenge(&challenge, &root(), &instance(), &[9; 32]).is_err());
        assert!(verify_stop(&challenge, &root(), &instance(), &[4; 32], 100).is_err());
        assert!(verify_finalized(&challenge, &root(), &instance()).is_err());
        assert!(verify_challenge(&stop(), &root(), &instance(), &[6; 32]).is_err());
        assert!(verify_finalized(&stop(), &root(), &instance()).is_err());
    }

    #[test]
    fn finalization_is_signed_and_generation_bound() {
        let terminal = signed(HvfInstanceControl::Finalized {
            instance: instance(),
        });
        assert!(verify_finalized(&terminal, &root(), &instance()).is_ok());
        let mut reused = instance();
        reused.boot_nonce = [9; 32];
        assert!(verify_finalized(&terminal, &root(), &reused).is_err());
        assert!(verify_stop(&terminal, &root(), &instance(), &[4; 32], 100).is_err());
    }

    #[test]
    fn malformed_or_extra_fields_are_rejected() {
        let mut value = serde_json::to_value(stop()).unwrap();
        value["request"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SignedControl>(value).is_err());
    }

    #[test]
    fn every_operation_roundtrips_and_tampering_invalidates_its_signature() {
        for message in [
            stop(),
            signed(HvfInstanceControl::Challenge {
                instance: instance(),
                client_nonce: [6; 32],
                connection_nonce: [4; 32],
            }),
            signed(HvfInstanceControl::Finalized {
                instance: instance(),
            }),
        ] {
            let mut value = serde_json::to_value(&message).unwrap();
            let decoded: SignedControl = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(message, decoded);
            assert!(broker_control::verify(&decoded, &root()).is_ok());
            value["request"]["instance"]["vm_id"] = serde_json::json!("substituted-vm");
            let changed: SignedControl = serde_json::from_value(value).unwrap();
            assert!(broker_control::verify(&changed, &root()).is_err());
        }
    }

    #[test]
    fn changing_signed_operation_or_domain_does_not_reuse_authority() {
        let mut request = stop();
        request.request = ControlRequest::HvfInstanceV1(HvfInstanceControl::Finalized {
            instance: instance(),
        });
        assert!(verify_finalized(&request, &root(), &instance()).is_err());
        request.request =
            ControlRequest::Deregister(mvm_contract::protocol::broker_control::DeregisterVm {
                vm_id: instance().vm_id,
            });
        assert!(broker_control::verify(&request, &root()).is_err());
    }

    #[test]
    fn wire_domain_and_existing_deregister_canonical_bytes_are_pinned() {
        let bytes = serde_jcs::to_vec(&stop().request).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains(r#""kind":"hvf_instance_v1""#));
        assert!(text.contains(r#""operation":"stop_hvf_instance""#));
        let request =
            ControlRequest::Deregister(mvm_contract::protocol::broker_control::DeregisterVm {
                vm_id: "vm-1".into(),
            });
        assert_eq!(
            serde_jcs::to_vec(&request).unwrap(),
            br#"{"kind":"deregister","vm_id":"vm-1"}"#
        );
    }
}
