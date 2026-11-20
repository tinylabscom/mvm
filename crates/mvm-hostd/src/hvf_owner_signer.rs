//! Closed key-holder acceptance for one durably consumed HVF owner admission.
//!
//! This type exposes no arbitrary signing method and opens no transport. The
//! future protected authority service owns peer authentication and invokes it
//! only after durable grant consumption.

use mvm_contract::protocol::hvf_entrypoint_owner::FreshAdmissionRequest;
use mvm_core::crypto::hvf_owner_grant::provider_identity;
use thiserror::Error;

use crate::{
    host_signer::keystore::Keystore,
    hvf_owner_grants::{OwnerGrantStore, OwnerGrantStoreError},
};

/// Exact public request accepted by the closed admission signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAdmissionSignRequest {
    pub grant_id: [u8; 32],
    pub admission: FreshAdmissionRequest,
}

/// Plan signature returned to the protected runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAdmissionSignature {
    pub issuer: String,
    pub sig_alg: u8,
    pub signature: Vec<u8>,
    pub signer_pubkey: Vec<u8>,
    pub expires_at_secs: u64,
}

/// Closed signer refusal.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OwnerAdmissionSignError {
    #[error("HVF owner signer is bound to another commissioned provider")]
    ProviderMismatch,
    #[error("HVF owner admission request is invalid")]
    InvalidRequest,
    #[error(transparent)]
    Grant(#[from] OwnerGrantStoreError),
}

/// Provider-bound key holder with only exact owner-admission signing.
pub struct OwnerAdmissionSigner {
    issuer: String,
    key: Keystore,
    grants: OwnerGrantStore,
}

impl std::fmt::Debug for OwnerAdmissionSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnerAdmissionSigner")
            .field("issuer", &self.issuer)
            .field("grants", &self.grants)
            .finish_non_exhaustive()
    }
}

impl OwnerAdmissionSigner {
    /// Bind a key holder to one commissioned provider namespace.
    ///
    /// # Errors
    /// Refuses a key, issuer or commissioning epoch different from the journal.
    pub fn new(
        issuer: impl Into<String>,
        provider_epoch: u64,
        key: Keystore,
        grants: OwnerGrantStore,
    ) -> Result<Self, OwnerAdmissionSignError> {
        let issuer = issuer.into();
        if issuer.is_empty()
            || issuer.len() > 256
            || issuer.chars().any(char::is_control)
            || provider_epoch == 0
            || provider_identity(&issuer, &key.verifying_key(), provider_epoch)
                != grants.provider_id()
        {
            return Err(OwnerAdmissionSignError::ProviderMismatch);
        }
        Ok(Self {
            issuer,
            key,
            grants,
        })
    }

    /// Sign only the exact canonical plan bound to a consumed owner grant.
    ///
    /// Exact retries produce the same deterministic Ed25519 signature and no
    /// additional consumption, authority or native effect. Re-establishing
    /// journal durability is an intentional storage effect.
    ///
    /// # Errors
    /// Refuses changed/unconsumed grants, expiry, malformed bindings and any
    /// payload that is not the supported canonical `ExecutionPlan` encoding.
    pub fn sign_admission(
        &self,
        request: &OwnerAdmissionSignRequest,
    ) -> Result<OwnerAdmissionSignature, OwnerAdmissionSignError> {
        request
            .admission
            .validate()
            .map_err(|_| OwnerAdmissionSignError::InvalidRequest)?;
        let digest = request
            .admission
            .digest()
            .map_err(|_| OwnerAdmissionSignError::InvalidRequest)?;
        let mut consumed = self.grants.authorize_consumed(request.grant_id, digest)?;
        if !crate::host_signer::server::plan_payload::is_supported_canonical_plan(
            &request.admission.canonical_plan,
        ) {
            return Err(OwnerAdmissionSignError::InvalidRequest);
        }
        consumed.check_current()?;
        let signed = self.key.sign(&request.admission.canonical_plan);
        let expires_at_secs = consumed.recheck()?;
        Ok(OwnerAdmissionSignature {
            issuer: self.issuer.clone(),
            sig_alg: signed.sig_alg,
            signature: signed.signature,
            signer_pubkey: signed.pub_key_bytes,
            expires_at_secs,
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    use ed25519_dalek::{Signature, SigningKey, Verifier as _, VerifyingKey};
    use mvm_contract::protocol::hvf_entrypoint_owner::{FreshOwnerBinding, OwnerGrant, VERSION};
    use mvm_core::{
        crypto::hvf_owner_grant::{
            OwnerGrantExpectation, provider_identity, sign_owner_grant, verify_owner_grant,
        },
        plan::{ExecutionPlan, compute_plan_id, sign_plan, test_support::PlanFixture},
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
        _directory: tempfile::TempDir,
        signer: OwnerAdmissionSigner,
        request: OwnerAdmissionSignRequest,
        clock: Arc<Clock>,
    }

    fn fixture() -> Fixture {
        use std::os::unix::fs::PermissionsExt as _;

        let key = SigningKey::from_bytes(&[7; 32]);
        let verifying = key.verifying_key();
        let plan = PlanFixture::new().build();
        let canonical_plan = sign_plan(&plan, &SigningKey::from_bytes(&[3; 32]), "fixture")
            .0
            .payload;
        let admission = FreshAdmissionRequest {
            binding: FreshOwnerBinding {
                version: VERSION,
                operation_id: [1; 32],
                owner_incarnation: [2; 32],
                controlling_principal: [3; 32],
                installation: [4; 16],
                tenant_id: plan.tenant.0.clone(),
                workload_id: plan.workload.0.clone(),
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
                grant_id: [8; 32],
                request_digest: admission.digest().unwrap(),
                issued_at_secs: 10,
                expires_at_secs: 100,
            },
            &key,
        )
        .unwrap();
        let verified = verify_owner_grant(
            &signed,
            &admission,
            OwnerGrantExpectation {
                issuer: "provider",
                issuer_key: &verifying,
                provider_epoch: 1,
                operation_id: [1; 32],
                owner_incarnation: [2; 32],
                controlling_principal: [3; 32],
                installation: [4; 16],
                tenant_id: &plan.tenant.0,
                workload_id: &plan.workload.0,
                canonical_plan_digest: Sha256::digest(&admission.canonical_plan).into(),
                frozen_inputs_digest: [5; 32],
                policy_revision: [6; 32],
                expires_at_secs: 90,
            },
            50,
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let clock = Arc::new(Clock(AtomicU64::new(50)));
        let grants = OwnerGrantStore::initialize(
            directory.path().join("owner-grants.json"),
            provider_identity("provider", &verifying, 1),
            clock.clone(),
        )
        .unwrap();
        grants.consume(verified).unwrap();
        let key_path = directory.path().join("provider-key");
        std::fs::write(&key_path, [7; 32]).unwrap();
        let signer = OwnerAdmissionSigner::new(
            "provider",
            1,
            Keystore::load_from_file(&key_path).unwrap(),
            grants,
        )
        .unwrap();
        Fixture {
            _directory: directory,
            signer,
            request: OwnerAdmissionSignRequest {
                grant_id: [8; 32],
                admission,
            },
            clock,
        }
    }

    #[test]
    fn exact_consumed_canonical_plan_is_the_only_signed_payload() {
        let fixture = fixture();
        let signed = fixture.signer.sign_admission(&fixture.request).unwrap();
        assert_eq!(signed.issuer, "provider");
        assert_eq!(signed.expires_at_secs, 90);
        let public_key: [u8; 32] = signed.signer_pubkey.as_slice().try_into().unwrap();
        let key = VerifyingKey::from_bytes(&public_key).unwrap();
        let signature = Signature::from_slice(&signed.signature).unwrap();
        key.verify(&fixture.request.admission.canonical_plan, &signature)
            .unwrap();
        assert_eq!(
            fixture.signer.sign_admission(&fixture.request).unwrap(),
            signed
        );
    }

    #[test]
    fn changed_unconsumed_noncanonical_and_expired_requests_never_reach_the_key() {
        let fixture = fixture();
        let before = Keystore::test_signing_calls();

        let mut changed = fixture.request.clone();
        changed.admission.canonical_plan.push(b' ');
        changed.admission.binding.canonical_plan_digest =
            Sha256::digest(&changed.admission.canonical_plan).into();
        assert!(matches!(
            fixture.signer.sign_admission(&changed),
            Err(OwnerAdmissionSignError::Grant(
                OwnerGrantStoreError::Conflict
            ))
        ));

        changed = fixture.request.clone();
        changed.grant_id[0] ^= 1;
        assert!(matches!(
            fixture.signer.sign_admission(&changed),
            Err(OwnerAdmissionSignError::Grant(
                OwnerGrantStoreError::Conflict
            ))
        ));

        changed = fixture.request.clone();
        let mut other_plan: ExecutionPlan =
            serde_json::from_slice(&changed.admission.canonical_plan).unwrap();
        other_plan.workload.0.push_str("-other");
        other_plan.plan_id = compute_plan_id(&other_plan);
        changed.admission.canonical_plan =
            sign_plan(&other_plan, &SigningKey::from_bytes(&[3; 32]), "fixture")
                .0
                .payload;
        changed.admission.binding.canonical_plan_digest =
            Sha256::digest(&changed.admission.canonical_plan).into();
        assert!(matches!(
            fixture.signer.sign_admission(&changed),
            Err(OwnerAdmissionSignError::Grant(
                OwnerGrantStoreError::Conflict
            ))
        ));

        changed = fixture.request.clone();
        changed.admission.binding.owner_incarnation[0] ^= 1;
        assert!(matches!(
            fixture.signer.sign_admission(&changed),
            Err(OwnerAdmissionSignError::Grant(
                OwnerGrantStoreError::Conflict
            ))
        ));

        fixture.clock.0.store(40, Ordering::SeqCst);
        assert!(matches!(
            fixture.signer.sign_admission(&fixture.request),
            Err(OwnerAdmissionSignError::Grant(
                OwnerGrantStoreError::Conflict
            ))
        ));
        fixture.clock.0.store(90, Ordering::SeqCst);
        assert!(matches!(
            fixture.signer.sign_admission(&fixture.request),
            Err(OwnerAdmissionSignError::Grant(
                OwnerGrantStoreError::Expired
            ))
        ));
        assert_eq!(Keystore::test_signing_calls(), before);
    }

    #[test]
    fn signer_key_and_commissioning_epoch_must_match_the_journal() {
        let fixture = fixture();
        let wrong_key = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(wrong_key.path(), [9; 32]).unwrap();
        let correct_key = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(correct_key.path(), [7; 32]).unwrap();
        assert!(matches!(
            OwnerAdmissionSigner::new(
                "provider",
                1,
                Keystore::load_from_file(wrong_key.path()).unwrap(),
                fixture.signer.grants.clone()
            ),
            Err(OwnerAdmissionSignError::ProviderMismatch)
        ));
        assert!(matches!(
            OwnerAdmissionSigner::new(
                "provider",
                2,
                Keystore::load_from_file(correct_key.path()).unwrap(),
                fixture.signer.grants.clone()
            ),
            Err(OwnerAdmissionSignError::ProviderMismatch)
        ));
        assert!(matches!(
            OwnerAdmissionSigner::new(
                "other-provider",
                1,
                Keystore::load_from_file(correct_key.path()).unwrap(),
                fixture.signer.grants
            ),
            Err(OwnerAdmissionSignError::ProviderMismatch)
        ));
    }

    #[test]
    fn a_consumed_noncanonical_plan_still_refuses_before_key_use() {
        let fixture = fixture();
        let key = SigningKey::from_bytes(&[7; 32]);
        let verifying = key.verifying_key();
        let mut admission = fixture.request.admission.clone();
        admission.canonical_plan.push(b' ');
        admission.binding.canonical_plan_digest = Sha256::digest(&admission.canonical_plan).into();
        let signed = sign_owner_grant(
            OwnerGrant {
                version: VERSION,
                issuer: "provider".into(),
                provider_epoch: 1,
                grant_id: [10; 32],
                request_digest: admission.digest().unwrap(),
                issued_at_secs: 10,
                expires_at_secs: 100,
            },
            &key,
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
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let clock = Arc::new(Clock(AtomicU64::new(50)));
        let grants = OwnerGrantStore::initialize(
            directory.path().join("owner-grants.json"),
            provider_identity("provider", &verifying, 1),
            clock,
        )
        .unwrap();
        grants.consume(verified).unwrap();
        let key_path = directory.path().join("provider-key");
        std::fs::write(&key_path, [7; 32]).unwrap();
        let signer = OwnerAdmissionSigner::new(
            "provider",
            1,
            Keystore::load_from_file(&key_path).unwrap(),
            grants,
        )
        .unwrap();
        let before = Keystore::test_signing_calls();
        assert!(matches!(
            signer.sign_admission(&OwnerAdmissionSignRequest {
                grant_id: [10; 32],
                admission,
            }),
            Err(OwnerAdmissionSignError::InvalidRequest)
        ));
        assert_eq!(Keystore::test_signing_calls(), before);
    }

    #[test]
    fn durability_and_post_storage_expiry_are_checked_before_key_use() {
        let fixture = fixture();
        let key = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(key.path(), [7; 32]).unwrap();
        let before = Keystore::test_signing_calls();

        let uncertain = fixture.signer.grants.with_commit(|path, bytes| {
            mvm_core::atomic_io::write_private(path, bytes).map_err(std::io::Error::other)?;
            Err(std::io::Error::other("injected durability uncertainty"))
        });
        let signer = OwnerAdmissionSigner::new(
            "provider",
            1,
            Keystore::load_from_file(key.path()).unwrap(),
            uncertain,
        )
        .unwrap();
        assert!(matches!(
            signer.sign_admission(&fixture.request),
            Err(OwnerAdmissionSignError::Grant(
                OwnerGrantStoreError::CommitUnknown { .. }
            ))
        ));

        fixture.clock.0.store(50, Ordering::SeqCst);
        let clock = Arc::clone(&fixture.clock);
        let delayed = fixture.signer.grants.with_commit(move |path, bytes| {
            clock.0.store(90, Ordering::SeqCst);
            mvm_core::atomic_io::write_private(path, bytes).map_err(std::io::Error::other)
        });
        let signer = OwnerAdmissionSigner::new(
            "provider",
            1,
            Keystore::load_from_file(key.path()).unwrap(),
            delayed,
        )
        .unwrap();
        assert!(matches!(
            signer.sign_admission(&fixture.request),
            Err(OwnerAdmissionSignError::Grant(
                OwnerGrantStoreError::Expired
            ))
        ));
        assert_eq!(Keystore::test_signing_calls(), before);
    }

    #[test]
    fn expiry_during_the_post_sign_time_floor_commit_releases_no_signature() {
        let fixture = fixture();
        let key = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(key.path(), [7; 32]).unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        let commit_calls = Arc::clone(&calls);
        let clock = Arc::clone(&fixture.clock);
        let staged = fixture.signer.grants.with_commit(move |path, bytes| {
            let call = commit_calls.fetch_add(1, Ordering::SeqCst);
            clock
                .0
                .store(if call == 0 { 89 } else { 91 }, Ordering::SeqCst);
            mvm_core::atomic_io::write_private(path, bytes).map_err(std::io::Error::other)
        });
        let signer = OwnerAdmissionSigner::new(
            "provider",
            1,
            Keystore::load_from_file(key.path()).unwrap(),
            staged,
        )
        .unwrap();
        let before = Keystore::test_signing_calls();
        assert!(matches!(
            signer.sign_admission(&fixture.request),
            Err(OwnerAdmissionSignError::Grant(
                OwnerGrantStoreError::Expired
            ))
        ));
        assert_eq!(Keystore::test_signing_calls(), before + 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
