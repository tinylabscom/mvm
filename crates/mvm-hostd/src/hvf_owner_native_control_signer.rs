//! Closed, in-process signing for the actual bound cold-HVF generation.
//!
//! This module opens no transport and exposes no arbitrary signing, instance,
//! PID, path, socket or process-adoption operation.

use mvm_contract::protocol::{
    hvf_control::HvfInstanceControl, hvf_entrypoint_owner::FreshAdmissionRequest,
};
use mvm_core::{
    crypto::hvf_owner_grant::provider_identity,
    protocol::broker_control::{ControlRequest, SignedControl},
};
use mvm_runtime::workload_runner::runner::OriginalHvfOwnerBinding;
use mvm_vmm::host::hvf_stop::BoundStopAuthorization;
use thiserror::Error;

use crate::{
    host_signer::keystore::Keystore,
    hvf_owner_grants::{
        BoundControlAuthorization, BoundOwnerBirthReceipt, OwnerGrantStore, OwnerGrantStoreError,
    },
};

pub struct OwnerNativeControlSigner {
    issuer: String,
    key: Keystore,
    grants: OwnerGrantStore,
}

trait StopBinding {
    fn instance(&self) -> &mvm_contract::protocol::hvf_control::HvfInstance;
    fn connection_nonce(&self) -> [u8; 32];
}

impl StopBinding for BoundStopAuthorization {
    fn instance(&self) -> &mvm_contract::protocol::hvf_control::HvfInstance {
        self.instance()
    }

    fn connection_nonce(&self) -> [u8; 32] {
        self.connection_nonce()
    }
}

impl std::fmt::Debug for OwnerNativeControlSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnerNativeControlSigner")
            .field("issuer", &self.issuer)
            .field("grants", &self.grants)
            .finish_non_exhaustive()
    }
}

impl OwnerNativeControlSigner {
    /// Bind this closed key holder to one commissioned provider namespace.
    ///
    /// # Errors
    /// Refuses a key, issuer or commissioning epoch different from the journal.
    pub fn new(
        issuer: impl Into<String>,
        provider_epoch: u64,
        key: Keystore,
        grants: OwnerGrantStore,
    ) -> Result<Self, OwnerNativeControlError> {
        let issuer = issuer.into();
        if issuer.is_empty()
            || issuer.len() > 256
            || issuer.chars().any(char::is_control)
            || provider_epoch == 0
            || provider_identity(&issuer, &key.verifying_key(), provider_epoch)
                != grants.provider_id()
        {
            return Err(OwnerNativeControlError::ProviderMismatch);
        }
        Ok(Self {
            issuer,
            key,
            grants,
        })
    }

    /// Sign one connection-bound stop for the actual retained original owner.
    ///
    /// # Errors
    /// Refuses any state except exact, fresh `Bound` custody and any mismatch
    /// in provider, admission, canonical plan or original generation.
    pub fn sign_original_stop(
        &self,
        receipt: &BoundOwnerBirthReceipt,
        admission: &FreshAdmissionRequest,
        original: OriginalHvfOwnerBinding<'_>,
        stop: &BoundStopAuthorization,
    ) -> Result<SignedControl, OwnerNativeControlError> {
        let authorization = self
            .grants
            .authorize_bound_original_control(receipt, admission, original)?;
        self.sign_authorized(authorization, stop)
    }

    fn sign_authorized(
        &self,
        mut authorization: BoundControlAuthorization<'_>,
        stop: &impl StopBinding,
    ) -> Result<SignedControl, OwnerNativeControlError> {
        if authorization.instance() != stop.instance() {
            return Err(OwnerNativeControlError::Grant(
                OwnerGrantStoreError::Conflict,
            ));
        }
        authorization.check_current()?;
        let operation = HvfInstanceControl::StopHvfInstance {
            instance: authorization.instance().clone(),
            connection_nonce: stop.connection_nonce(),
            issued_at_secs: authorization.observed_at_secs(),
        };
        let signed = self
            .key
            .sign_control(ControlRequest::HvfInstanceV1(operation))?;
        authorization.recheck()?;
        Ok(signed)
    }

    #[cfg(test)]
    fn sign_original_control_parts(
        &self,
        receipt: &BoundOwnerBirthReceipt,
        admission: &FreshAdmissionRequest,
        canonical_plan_digest: [u8; 32],
        instance: mvm_contract::protocol::hvf_control::HvfInstance,
        connection_nonce: [u8; 32],
        stop_instance: mvm_contract::protocol::hvf_control::HvfInstance,
    ) -> Result<SignedControl, OwnerNativeControlError> {
        struct TestStopBinding {
            instance: mvm_contract::protocol::hvf_control::HvfInstance,
            connection_nonce: [u8; 32],
        }
        impl StopBinding for TestStopBinding {
            fn instance(&self) -> &mvm_contract::protocol::hvf_control::HvfInstance {
                &self.instance
            }

            fn connection_nonce(&self) -> [u8; 32] {
                self.connection_nonce
            }
        }
        let authorization = self.grants.authorize_bound_control_parts_for_test(
            receipt,
            admission,
            canonical_plan_digest,
            instance,
        )?;
        self.sign_authorized(
            authorization,
            &TestStopBinding {
                instance: stop_instance,
                connection_nonce,
            },
        )
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OwnerNativeControlError {
    #[error("HVF owner native-control signer is bound to another commissioned provider")]
    ProviderMismatch,
    #[error(transparent)]
    Grant(#[from] OwnerGrantStoreError),
    #[error(transparent)]
    Control(#[from] mvm_core::protocol::broker_control::ControlError),
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        os::unix::fs::PermissionsExt as _,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };

    use ed25519_dalek::SigningKey;
    use mvm_contract::protocol::hvf_control::HvfInstance;
    use mvm_contract::protocol::hvf_entrypoint_owner::{FreshOwnerBinding, OwnerGrant, VERSION};
    use mvm_core::{
        crypto::hvf_owner_grant::{
            OwnerGrantExpectation, provider_identity, sign_owner_grant, verify_owner_grant,
        },
        plan::{sign_plan, test_support::PlanFixture},
        protocol::broker_control,
    };
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::hvf_owner_grants::{OwnerGrantClock, OwnerGrantStore};

    #[derive(Debug)]
    struct Clock(AtomicU64);

    impl OwnerGrantClock for Clock {
        fn now_secs(&self) -> std::io::Result<u64> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    struct Fixture {
        _state: tempfile::TempDir,
        signer: OwnerNativeControlSigner,
        receipt: BoundOwnerBirthReceipt,
        admission: FreshAdmissionRequest,
        instance: HvfInstance,
        verifying: ed25519_dalek::VerifyingKey,
        clock: Arc<Clock>,
    }

    fn make_fixture(grant_id: [u8; 32]) -> Fixture {
        let provider_key = SigningKey::from_bytes(&[7; 32]);
        let verifying = provider_key.verifying_key();
        let plan = PlanFixture::new().build();
        let canonical_plan = sign_plan(&plan, &SigningKey::from_bytes(&[3; 32]), "fixture")
            .0
            .payload;
        let admission = FreshAdmissionRequest {
            binding: FreshOwnerBinding {
                version: VERSION,
                operation_id: grant_id,
                owner_incarnation: [2; 32],
                controlling_principal: [3; 32],
                installation: [4; 16],
                tenant_id: plan.tenant.0,
                workload_id: plan.workload.0,
                canonical_plan_digest: Sha256::digest(&canonical_plan).into(),
                frozen_inputs_digest: [5; 32],
                policy_revision: [6; 32],
                expires_at_secs: 90,
            },
            canonical_plan,
        };
        let signed = sign_owner_grant(
            OwnerGrant {
                version: VERSION,
                issuer: "provider".into(),
                provider_epoch: 1,
                grant_id,
                request_digest: admission.digest().unwrap(),
                issued_at_secs: 10,
                expires_at_secs: 100,
            },
            &provider_key,
        )
        .unwrap();
        let verified = verify_owner_grant(
            &signed,
            &admission,
            OwnerGrantExpectation {
                issuer: "provider",
                issuer_key: &verifying,
                provider_epoch: 1,
                operation_id: admission.binding.operation_id,
                owner_incarnation: admission.binding.owner_incarnation,
                controlling_principal: admission.binding.controlling_principal,
                installation: admission.binding.installation,
                tenant_id: &admission.binding.tenant_id,
                workload_id: &admission.binding.workload_id,
                canonical_plan_digest: admission.binding.canonical_plan_digest,
                frozen_inputs_digest: admission.binding.frozen_inputs_digest,
                policy_revision: admission.binding.policy_revision,
                expires_at_secs: admission.binding.expires_at_secs,
            },
            50,
        )
        .unwrap();
        let state = tempfile::tempdir().unwrap();
        std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let clock = Arc::new(Clock(AtomicU64::new(50)));
        let store_clock: Arc<dyn OwnerGrantClock> = clock.clone();
        let grants = OwnerGrantStore::initialize(
            state.path().join("owner-grants.json"),
            provider_identity("provider", &verifying, 1),
            store_clock,
        )
        .unwrap();
        let consumed = grants.consume(verified).unwrap();
        let reservation = grants.reserve_birth(consumed, &admission).unwrap();
        let instance = HvfInstance {
            vm_id: admission.binding.workload_id.clone(),
            boot_nonce: [9; 32],
        };
        let receipt = grants
            .bind_prepared_instance_for_test(reservation, instance.clone())
            .unwrap();
        let key_path = state.path().join("provider-key");
        std::fs::write(&key_path, [7; 32]).unwrap();
        let signer = OwnerNativeControlSigner::new(
            "provider",
            1,
            Keystore::load_from_file(&key_path).unwrap(),
            grants,
        )
        .unwrap();
        Fixture {
            _state: state,
            signer,
            receipt,
            admission,
            instance,
            verifying,
            clock,
        }
    }

    #[test]
    fn exact_bound_owner_signs_only_connection_bound_stop() {
        let fixture = make_fixture([20; 32]);
        let sign = || {
            fixture.signer.sign_original_control_parts(
                &fixture.receipt,
                &fixture.admission,
                fixture.admission.binding.canonical_plan_digest,
                fixture.instance.clone(),
                [12; 32],
                fixture.instance.clone(),
            )
        };
        let first = sign().unwrap();
        let second = sign().unwrap();
        assert_eq!(first, second);
        assert!(matches!(
            broker_control::verify(&first, &fixture.verifying).unwrap(),
            ControlRequest::HvfInstanceV1(HvfInstanceControl::StopHvfInstance {
                instance,
                connection_nonce,
                issued_at_secs: 50,
            }) if instance == &fixture.instance && connection_nonce == &[12; 32]
        ));
        assert!(
            broker_control::verify(&first, &SigningKey::from_bytes(&[99; 32]).verifying_key())
                .is_err()
        );
    }

    #[test]
    fn changed_plan_or_generation_refuses_before_key_use() {
        let fixture = make_fixture([24; 32]);
        let before = Keystore::test_signing_calls();
        assert!(matches!(
            fixture.signer.sign_original_control_parts(
                &fixture.receipt,
                &fixture.admission,
                [99; 32],
                fixture.instance.clone(),
                [12; 32],
                fixture.instance.clone(),
            ),
            Err(OwnerNativeControlError::Grant(
                OwnerGrantStoreError::Conflict
            ))
        ));
        let mut wrong = fixture.instance.clone();
        wrong.boot_nonce[0] ^= 1;
        assert!(matches!(
            fixture.signer.sign_original_control_parts(
                &fixture.receipt,
                &fixture.admission,
                fixture.admission.binding.canonical_plan_digest,
                wrong,
                [12; 32],
                fixture.instance.clone(),
            ),
            Err(OwnerNativeControlError::Grant(
                OwnerGrantStoreError::Conflict
            ))
        ));
        let mut wrong_stop = fixture.instance.clone();
        wrong_stop.boot_nonce[0] ^= 1;
        assert!(matches!(
            fixture.signer.sign_original_control_parts(
                &fixture.receipt,
                &fixture.admission,
                fixture.admission.binding.canonical_plan_digest,
                fixture.instance.clone(),
                [12; 32],
                wrong_stop,
            ),
            Err(OwnerNativeControlError::Grant(
                OwnerGrantStoreError::Conflict
            ))
        ));
        assert_eq!(Keystore::test_signing_calls(), before);
    }

    #[test]
    fn expired_or_regressed_authority_refuses_before_key_use() {
        for (grant_id, now, expected) in [
            ([25; 32], 90, OwnerGrantStoreError::Expired),
            ([26; 32], 40, OwnerGrantStoreError::ClockRegression),
        ] {
            let fixture = make_fixture(grant_id);
            fixture.clock.0.store(now, Ordering::SeqCst);
            let before = Keystore::test_signing_calls();
            let result = fixture.signer.sign_original_control_parts(
                &fixture.receipt,
                &fixture.admission,
                fixture.admission.binding.canonical_plan_digest,
                fixture.instance.clone(),
                [12; 32],
                fixture.instance.clone(),
            );
            match expected {
                OwnerGrantStoreError::Expired => assert!(matches!(
                    result,
                    Err(OwnerNativeControlError::Grant(
                        OwnerGrantStoreError::Expired
                    ))
                )),
                OwnerGrantStoreError::ClockRegression => assert!(matches!(
                    result,
                    Err(OwnerNativeControlError::Grant(
                        OwnerGrantStoreError::ClockRegression
                    ))
                )),
                _ => unreachable!("test covers only authority-time refusal"),
            }
            assert_eq!(Keystore::test_signing_calls(), before);
        }
    }

    #[test]
    fn durability_or_post_sign_expiry_returns_no_control_envelope() {
        let fixture = make_fixture([27; 32]);
        let failing_store = fixture
            .signer
            .grants
            .with_commit(|_, _| Err(std::io::Error::other("injected durability failure")));
        let key_path = fixture._state.path().join("retry-key");
        std::fs::write(&key_path, [7; 32]).unwrap();
        let signer = OwnerNativeControlSigner::new(
            "provider",
            1,
            Keystore::load_from_file(&key_path).unwrap(),
            failing_store,
        )
        .unwrap();
        let before = Keystore::test_signing_calls();
        assert!(matches!(
            signer.sign_original_control_parts(
                &fixture.receipt,
                &fixture.admission,
                fixture.admission.binding.canonical_plan_digest,
                fixture.instance.clone(),
                [12; 32],
                fixture.instance.clone(),
            ),
            Err(OwnerNativeControlError::Grant(
                OwnerGrantStoreError::CommitUnknown { .. }
            ))
        ));
        assert_eq!(Keystore::test_signing_calls(), before);

        let fixture = make_fixture([28; 32]);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let writer_calls = Arc::clone(&calls);
        let writer_clock = Arc::clone(&fixture.clock);
        let delayed_store = fixture.signer.grants.with_commit(move |path, bytes| {
            mvm_core::atomic_io::write_private(path, bytes).map_err(std::io::Error::other)?;
            let call = writer_calls.fetch_add(1, Ordering::SeqCst);
            writer_clock
                .0
                .store(if call == 0 { 80 } else { 90 }, Ordering::SeqCst);
            Ok(())
        });
        let key_path = fixture._state.path().join("delayed-key");
        std::fs::write(&key_path, [7; 32]).unwrap();
        let signer = OwnerNativeControlSigner::new(
            "provider",
            1,
            Keystore::load_from_file(&key_path).unwrap(),
            delayed_store,
        )
        .unwrap();
        let before = Keystore::test_signing_calls();
        assert!(matches!(
            signer.sign_original_control_parts(
                &fixture.receipt,
                &fixture.admission,
                fixture.admission.binding.canonical_plan_digest,
                fixture.instance.clone(),
                [12; 32],
                fixture.instance.clone(),
            ),
            Err(OwnerNativeControlError::Grant(
                OwnerGrantStoreError::Expired
            ))
        ));
        assert_eq!(Keystore::test_signing_calls(), before + 1);

        let fixture = make_fixture([29; 32]);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let writer_calls = Arc::clone(&calls);
        let writer_clock = Arc::clone(&fixture.clock);
        let failing_store = fixture.signer.grants.with_commit(move |path, bytes| {
            mvm_core::atomic_io::write_private(path, bytes).map_err(std::io::Error::other)?;
            let call = writer_calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                writer_clock.0.store(80, Ordering::SeqCst);
            }
            if call == 1 {
                Err(std::io::Error::other(
                    "injected post-sign durability failure",
                ))
            } else {
                Ok(())
            }
        });
        let key_path = fixture._state.path().join("post-sign-key");
        std::fs::write(&key_path, [7; 32]).unwrap();
        let signer = OwnerNativeControlSigner::new(
            "provider",
            1,
            Keystore::load_from_file(&key_path).unwrap(),
            failing_store,
        )
        .unwrap();
        let before = Keystore::test_signing_calls();
        assert!(matches!(
            signer.sign_original_control_parts(
                &fixture.receipt,
                &fixture.admission,
                fixture.admission.binding.canonical_plan_digest,
                fixture.instance.clone(),
                [12; 32],
                fixture.instance.clone(),
            ),
            Err(OwnerNativeControlError::Grant(
                OwnerGrantStoreError::CommitUnknown { .. }
            ))
        ));
        assert_eq!(Keystore::test_signing_calls(), before + 1);
    }

    #[test]
    fn audit_closing_and_closed_states_refuse_before_key_use() {
        for close in [false, true] {
            let fixture = make_fixture([if close { 31 } else { 30 }; 32]);
            let duplicate = fixture.receipt.duplicate_for_test();
            let closure = fixture
                .signer
                .grants
                .begin_audit_close(fixture.receipt, &fixture.admission, &fixture.instance)
                .unwrap();
            if close {
                let _closed = fixture.signer.grants.finish_audit_close(closure).unwrap();
            }
            let before = Keystore::test_signing_calls();
            assert!(matches!(
                fixture.signer.sign_original_control_parts(
                    &duplicate,
                    &fixture.admission,
                    fixture.admission.binding.canonical_plan_digest,
                    fixture.instance.clone(),
                    [12; 32],
                    fixture.instance.clone(),
                ),
                Err(OwnerNativeControlError::Grant(
                    OwnerGrantStoreError::Conflict
                ))
            ));
            assert_eq!(Keystore::test_signing_calls(), before);
        }
    }
}
