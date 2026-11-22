//! Closed, in-process audit closure for one bound cold-HVF owner birth.
//!
//! This module opens no endpoint and accepts no caller-selected audit category,
//! payload, path, PID, instance or bytes-to-sign.

use std::sync::Arc;

use mvm_agentd::vsock::EntrypointEvent;
use mvm_contract::protocol::hvf_entrypoint_owner::FreshAdmissionRequest;
use mvm_core::plan::ExecutionPlan;
use mvm_runtime::workload_runner::runner::NativeCompletion;
use thiserror::Error;

use crate::{
    audit::{emitter::AuditEmitter, session::SealReason},
    host_signer::server::plan_payload,
    hvf_owner_grants::{
        BoundOwnerBirthReceipt, ClosedOwnerAuditReceipt, OwnerAuditTransitionError,
        OwnerGrantStore, UncertainOwnerAudit,
    },
};

pub struct OwnerAuditSigner {
    grants: OwnerGrantStore,
    emitter: Arc<AuditEmitter>,
}

impl OwnerAuditSigner {
    #[must_use]
    pub fn new(grants: OwnerGrantStore, emitter: Arc<AuditEmitter>) -> Self {
        Self { grants, emitter }
    }

    /// Close exactly one successfully completed original-owner audit.
    ///
    /// Audit intent is durable before the first append. Any later error returns
    /// only uncertain custody and cannot be retried through this API.
    ///
    /// # Errors
    /// Refuses noncanonical plans, non-exit terminal evidence, mismatched
    /// native custody, expired authority and ambiguous audit/storage outcomes.
    pub fn close_completed(
        &self,
        receipt: BoundOwnerBirthReceipt,
        admission: &FreshAdmissionRequest,
        completion: &NativeCompletion,
    ) -> Result<ClosedOwnerAuditReceipt, OwnerAuditCloseError> {
        let exit_code = match completion.terminal() {
            EntrypointEvent::Exit { code } => *code,
            _ => {
                return Err(OwnerAuditCloseError::InvalidRequest {
                    quarantine: receipt.into_uncertain_audit(),
                });
            }
        };
        self.close_completed_evidence(receipt, admission, completion.evidence(), exit_code)
    }

    fn close_completed_evidence(
        &self,
        receipt: BoundOwnerBirthReceipt,
        admission: &FreshAdmissionRequest,
        evidence: &mvm_runtime::workload_runner::runner::NativeCompletionEvidence,
        exit_code: i32,
    ) -> Result<ClosedOwnerAuditReceipt, OwnerAuditCloseError> {
        if !plan_payload::is_supported_canonical_plan(&admission.canonical_plan) {
            return Err(OwnerAuditCloseError::InvalidRequest {
                quarantine: receipt.into_uncertain_audit(),
            });
        }
        let plan: ExecutionPlan = match serde_json::from_slice(&admission.canonical_plan) {
            Ok(plan) => plan,
            Err(_) => {
                return Err(OwnerAuditCloseError::InvalidRequest {
                    quarantine: receipt.into_uncertain_audit(),
                });
            }
        };
        if plan.tenant.0 != admission.binding.tenant_id
            || plan.workload.0 != admission.binding.workload_id
            || evidence.canonical_plan_digest != Some(admission.binding.canonical_plan_digest)
        {
            return Err(OwnerAuditCloseError::InvalidRequest {
                quarantine: receipt.into_uncertain_audit(),
            });
        }
        if self.emitter.require_open_admitted_session(&plan).is_err() {
            return Err(OwnerAuditCloseError::InvalidRequest {
                quarantine: receipt.into_uncertain_audit(),
            });
        }
        let closure = self
            .grants
            .begin_audit_close(receipt, admission, &evidence.instance)
            .map_err(OwnerAuditCloseError::Transition)?;
        debug_assert_eq!(closure.instance(), &evidence.instance);
        let audit = self.emitter.batched(|| {
            self.emitter
                .emit_native_completion_evidence(&plan, evidence)?;
            self.emitter.emit_exited(&plan, exit_code, "hvf")?;
            self.emitter.seal_session(&plan, SealReason::Exited)?;
            self.emitter.publish_root(&plan.tenant.0)?;
            Ok(())
        });
        if let Err(source) = audit {
            return Err(OwnerAuditCloseError::Audit {
                quarantine: closure.into_uncertain(),
                source,
            });
        }
        self.grants
            .finish_audit_close(closure)
            .map_err(OwnerAuditCloseError::Transition)
    }
}

#[derive(Debug, Error)]
pub enum OwnerAuditCloseError {
    #[error("owner audit close request is invalid")]
    InvalidRequest { quarantine: UncertainOwnerAudit },
    #[error(transparent)]
    Transition(#[from] OwnerAuditTransitionError),
    #[error("owner audit close outcome is uncertain")]
    Audit {
        quarantine: UncertainOwnerAudit,
        #[source]
        source: anyhow::Error,
    },
}

impl OwnerAuditCloseError {
    pub fn into_uncertain(self) -> UncertainOwnerAudit {
        match self {
            Self::InvalidRequest { quarantine } => quarantine,
            Self::Transition(error) => error.into_parts().0,
            Self::Audit { quarantine, .. } => quarantine,
        }
    }
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
    use mvm_contract::protocol::hvf_entrypoint_owner::{FreshOwnerBinding, OwnerGrant, VERSION};
    use mvm_core::{
        crypto::hvf_owner_grant::{
            OwnerGrantExpectation, provider_identity, sign_owner_grant, verify_owner_grant,
        },
        plan::{ExecutionPlan, sign_plan, test_support::PlanFixture},
        protocol::hvf_control::HvfInstance,
    };
    use mvm_runtime::workload_runner::runner::NativeCompletionEvidence;
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
        audit_dir: tempfile::TempDir,
        signer: OwnerAuditSigner,
        receipt: BoundOwnerBirthReceipt,
        admission: FreshAdmissionRequest,
        evidence: NativeCompletionEvidence,
        plan: ExecutionPlan,
        emitter: Arc<AuditEmitter>,
    }

    fn fixture(with_admission: bool) -> Fixture {
        let provider_key = SigningKey::from_bytes(&[7; 32]);
        let verifying = provider_key.verifying_key();
        let unsigned = PlanFixture::new().build();
        let canonical_plan = sign_plan(&unsigned, &SigningKey::from_bytes(&[3; 32]), "fixture")
            .0
            .payload;
        let plan: ExecutionPlan = serde_json::from_slice(&canonical_plan).unwrap();
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
        let grants = OwnerGrantStore::initialize(
            state.path().join("owner-grants.json"),
            provider_identity("provider", &verifying, 1),
            Arc::new(Clock(AtomicU64::new(50))),
        )
        .unwrap();
        let consumed = grants.consume(verified).unwrap();
        let reservation = grants.reserve_birth(consumed, &admission).unwrap();
        let instance = HvfInstance {
            vm_id: plan.workload.0.clone(),
            boot_nonce: [9; 32],
        };
        let receipt = grants
            .bind_prepared_instance_for_test(reservation, instance.clone())
            .unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let emitter = Arc::new(
            AuditEmitter::with_dir(SigningKey::from_bytes(&[11; 32]), audit_dir.path()).unwrap(),
        );
        if with_admission {
            emitter.emit_admitted(&plan, "host:test").unwrap();
            emitter.require_open_admitted_session(&plan).unwrap();
        }
        let signer = OwnerAuditSigner::new(grants, Arc::clone(&emitter));
        let evidence = NativeCompletionEvidence {
            instance,
            canonical_plan_digest: Some(admission.binding.canonical_plan_digest),
            rootfs_sha256: plan.image.sha256.clone(),
            rootfs_roothash: String::new(),
            runtime_archive_sha256: None,
            runtime_version: None,
            runtime_overlay_roothash: None,
            network_policy: Default::default(),
        };
        Fixture {
            _state: state,
            audit_dir,
            signer,
            receipt,
            admission,
            evidence,
            plan,
            emitter,
        }
    }

    #[test]
    fn exact_bound_completion_closes_the_existing_chain_once() {
        let fixture = fixture(true);
        let closed = fixture
            .signer
            .close_completed_evidence(fixture.receipt, &fixture.admission, &fixture.evidence, 0)
            .unwrap();
        assert_eq!(closed.grant_id(), [8; 32]);
        assert_eq!(
            fixture.signer.grants.birth_disposition([8; 32]).unwrap(),
            Some(crate::hvf_owner_grants::OwnerBirthDisposition::AuditClosed)
        );
        let verification = crate::audit::session::verify_session(
            fixture.audit_dir.path(),
            &fixture.plan.tenant.0,
            &fixture.plan.plan_id.0,
            &fixture.emitter.verifying_key(),
        );
        assert_eq!(
            verification.verdict,
            crate::audit::session::Verdict::Verified
        );
        let chain = std::fs::read_to_string(
            fixture
                .audit_dir
                .path()
                .join(format!("{}.jsonl", fixture.plan.tenant.0)),
        )
        .unwrap();
        let completed = chain.find("\"event\":\"plan.native_completed\"").unwrap();
        let exited = chain.find("\"event\":\"plan.exited\"").unwrap();
        let sealed = chain.find("\"event\":\"session.sealed\"").unwrap();
        assert!(completed < exited && exited < sealed);
        let root_path = crate::audit::emitter::audit_root_path_for_tenant(
            fixture.audit_dir.path(),
            &fixture.plan.tenant.0,
        );
        let root: mvm_contract::merkle::SignedAuditRoot =
            serde_json::from_str(&std::fs::read_to_string(root_path).unwrap()).unwrap();
        assert_eq!(
            mvm_contract::merkle::verify_signed_root(&root, &fixture.emitter.verifying_key()),
            Ok(())
        );
        assert_eq!(root.tree_size as usize, chain.lines().count());
    }

    #[test]
    fn changed_plan_digest_or_missing_admitted_chain_refuses_before_audit_intent() {
        let mut changed = fixture(true);
        changed.evidence.canonical_plan_digest = Some([99; 32]);
        assert!(matches!(
            changed.signer.close_completed_evidence(
                changed.receipt,
                &changed.admission,
                &changed.evidence,
                0,
            ),
            Err(OwnerAuditCloseError::InvalidRequest { .. })
        ));
        assert_eq!(
            changed.signer.grants.birth_disposition([8; 32]).unwrap(),
            Some(crate::hvf_owner_grants::OwnerBirthDisposition::Bound)
        );

        let empty = fixture(false);
        assert!(matches!(
            empty.signer.close_completed_evidence(
                empty.receipt,
                &empty.admission,
                &empty.evidence,
                0,
            ),
            Err(OwnerAuditCloseError::InvalidRequest { .. })
        ));
        assert_eq!(
            empty.signer.grants.birth_disposition([8; 32]).unwrap(),
            Some(crate::hvf_owner_grants::OwnerBirthDisposition::Bound)
        );
    }

    #[test]
    fn audit_or_final_journal_failure_returns_only_uncertain_custody() {
        let blocked = fixture(true);
        let chain = blocked
            .audit_dir
            .path()
            .join(format!("{}.jsonl", blocked.plan.tenant.0));
        std::fs::set_permissions(&chain, std::fs::Permissions::from_mode(0o400)).unwrap();
        let error = blocked
            .signer
            .close_completed_evidence(blocked.receipt, &blocked.admission, &blocked.evidence, 0)
            .unwrap_err();
        assert!(matches!(error, OwnerAuditCloseError::Audit { .. }));
        assert_eq!(
            blocked.signer.grants.birth_disposition([8; 32]).unwrap(),
            Some(crate::hvf_owner_grants::OwnerBirthDisposition::AuditClosing)
        );

        let finalizing = fixture(true);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let writer_calls = Arc::clone(&calls);
        let store = finalizing.signer.grants.with_commit(move |path, bytes| {
            mvm_core::atomic_io::write_private(path, bytes).map_err(std::io::Error::other)?;
            if writer_calls.fetch_add(1, Ordering::SeqCst) == 1 {
                Err(std::io::Error::other(
                    "injected final audit-state uncertainty",
                ))
            } else {
                Ok(())
            }
        });
        let signer = OwnerAuditSigner::new(store, Arc::clone(&finalizing.emitter));
        let error = signer
            .close_completed_evidence(
                finalizing.receipt,
                &finalizing.admission,
                &finalizing.evidence,
                0,
            )
            .unwrap_err();
        assert!(matches!(error, OwnerAuditCloseError::Transition(_)));
        assert_eq!(
            signer.grants.birth_disposition([8; 32]).unwrap(),
            Some(crate::hvf_owner_grants::OwnerBirthDisposition::AuditClosed)
        );
    }
}
