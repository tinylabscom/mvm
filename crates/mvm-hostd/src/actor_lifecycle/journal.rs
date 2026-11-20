//! Encrypted lifecycle receipts; recovery never turns an intent into a launch.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};
use mvm_contract::protocol::workload_actor::{ActorBindingId, ActorHandle, ParentIdentity};
use mvm_core::crypto::aead::{self, Key};
use mvm_core::util::atomic_io::{FileLock, NewFile, write_private, write_private_new};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::DerivedChildMailbox;
use crate::actor_reservations::ReservationIdentity;

const MAX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 4096;
const DOMAIN: &[u8] = b"mvm.actor.lifecycle.journal.v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChildRecord {
    pub parent: ParentIdentity,
    pub request_id: ActorBindingId,
    pub reservation: ReservationIdentity,
    pub host_reservation: String,
    pub child_workload: String,
    pub handle: ActorHandle,
    pub mailbox: DerivedChildMailbox,
    pub child_plan_digest: Option<[u8; 32]>,
    pub teardown: Option<mvm_runtime::actor_teardown::ActorTeardownJournal>,
    pub terminal_evidence_digest: Option<[u8; 32]>,
    pub state: ChildState,
    pub release_request: Option<ActorBindingId>,
}

impl ChildRecord {
    pub(super) fn matches_handle(&self, parent: &ParentIdentity, handle: &ActorHandle) -> bool {
        self.parent == *parent && self.handle == *handle
    }

    pub(super) fn begin_release(&mut self, key: &ActorBindingId) {
        self.release_request = Some(key.clone());
        self.state = match self.state {
            ChildState::Pending | ChildState::Prepared | ChildState::Cancelling => {
                ChildState::Cancelling
            }
            ChildState::Dispatching | ChildState::Running | ChildState::Stopping => {
                ChildState::Stopping
            }
            ChildState::Terminal => ChildState::Terminal,
            ChildState::Cancelled => ChildState::Cancelled,
        };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ChildState {
    Pending,
    Prepared,
    Dispatching,
    Running,
    Stopping,
    Terminal,
    Cancelling,
    Cancelled,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Records {
    version: u32,
    pub children: Vec<ChildRecord>,
    #[serde(default)]
    pub attempts: Vec<AttemptRecord>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AttemptRecord {
    pub parent: ParentIdentity,
    pub request_id: ActorBindingId,
    pub reservation: ReservationIdentity,
    pub host_reservation: String,
    pub child: mvm_contract::plan::ExecutionPlan,
    pub mailbox_preparing: bool,
    pub terminal_evidence_digest: Option<[u8; 32]>,
}

impl Records {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && self.children.len().saturating_add(self.attempts.len()) <= MAX_RECORDS,
            "invalid actor journal"
        );
        for (index, attempt) in self.attempts.iter().enumerate() {
            ensure!(
                !self.attempts[..index]
                    .iter()
                    .any(|other| other.child.workload == attempt.child.workload
                        || other.reservation == attempt.reservation)
                    && !self
                        .children
                        .iter()
                        .any(|child| child.child_workload == attempt.child.workload.0
                            || child.reservation == attempt.reservation),
                "conflicting actor attempt journal"
            );
        }
        for (index, record) in self.children.iter().enumerate() {
            ensure!(
                !self.children[..index].iter().any(|other| {
                    other.handle.token == record.handle.token
                        || other.child_workload == record.child_workload
                        || (other.reservation.tenant == record.reservation.tenant
                            && other.reservation.workflow == record.reservation.workflow
                            && other.request_id == record.request_id)
                }),
                "conflicting actor journal"
            );
            match record.state {
                ChildState::Pending => ensure!(
                    record.child_plan_digest.is_none() && record.teardown.is_none(),
                    "pending actor has dispatched identity"
                ),
                ChildState::Cancelling | ChildState::Cancelled => ensure!(
                    record.teardown.is_none(),
                    "never-dispatched actor has native custody"
                ),
                ChildState::Prepared
                | ChildState::Dispatching
                | ChildState::Running
                | ChildState::Stopping
                | ChildState::Terminal => ensure!(
                    record.child_plan_digest.is_some(),
                    "actor record lacks its prepared plan"
                ),
            }
            if matches!(record.state, ChildState::Terminal | ChildState::Cancelled) {
                ensure!(
                    record.terminal_evidence_digest.is_some(),
                    "terminal actor record lacks cleanup evidence"
                );
            } else {
                ensure!(
                    record.terminal_evidence_digest.is_none(),
                    "nonterminal actor has terminal evidence"
                );
            }
        }
        Ok(())
    }
}

/// A host-owned encrypted receipt store. Its key is never supplied by a guest.
pub struct ActorJournal {
    path: PathBuf,
    key: Key,
    #[cfg(test)]
    next_write_failure: std::sync::atomic::AtomicU8,
}

impl ActorJournal {
    /// Create new state without replacing retained idempotency or handle history.
    pub fn create(path: &Path, key: Key) -> Result<Self> {
        let _lock = FileLock::acquire(path)?;
        let store = Self {
            path: path.to_owned(),
            key,
            #[cfg(test)]
            next_write_failure: std::sync::atomic::AtomicU8::new(0),
        };
        let records = Records {
            version: 1,
            children: Vec::new(),
            attempts: Vec::new(),
        };
        let bytes = store.encode(&records)?;
        ensure!(
            write_private_new(path, &bytes)? == NewFile::Created,
            "actor journal exists"
        );
        Ok(store)
    }

    /// Reopen with the original key; absent, wrong-key and corrupt state refuse.
    pub fn open(path: &Path, key: Key) -> Result<Self> {
        let store = Self {
            path: path.to_owned(),
            key,
            #[cfg(test)]
            next_write_failure: std::sync::atomic::AtomicU8::new(0),
        };
        let _lock = store.lock()?;
        store.read()?;
        Ok(store)
    }

    pub(super) fn lock(&self) -> Result<FileLock> {
        FileLock::acquire(&self.path)
    }

    pub(super) fn read(&self) -> Result<Records> {
        let mut bytes = Vec::new();
        std::fs::File::open(&self.path)?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "actor journal exceeds bound"
        );
        let plaintext = Zeroizing::new(aead::open(&self.key, &bytes, DOMAIN)?);
        let records: Records = serde_json::from_slice(&plaintext)?;
        records.validate()?;
        Ok(records)
    }

    pub(super) fn write(&self, records: &Records) -> Result<()> {
        #[cfg(test)]
        let failure = self
            .next_write_failure
            .swap(0, std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        ensure!(failure != 1, "injected actor write failure before commit");
        write_private(&self.path, &self.encode(records)?)?;
        #[cfg(test)]
        ensure!(failure != 2, "injected actor write failure after commit");
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn fail_next_write(&self, committed: bool) {
        self.next_write_failure.store(
            if committed { 2 } else { 1 },
            std::sync::atomic::Ordering::SeqCst,
        );
    }

    fn encode(&self, records: &Records) -> Result<Vec<u8>> {
        records.validate()?;
        ensure!(
            records.children.len() <= MAX_RECORDS,
            "actor receipt capacity exhausted"
        );
        let bytes = Zeroizing::new(serde_json::to_vec(records)?);
        ensure!(
            (bytes.len() as u64) < MAX_BYTES - 128,
            "actor journal exceeds bound"
        );
        Ok(aead::seal(&self.key, &bytes, DOMAIN))
    }
}

#[cfg(test)]
pub(super) fn fixture_record(keys: &Path) -> ChildRecord {
    tests::record(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::plan::{PlanId, TenantId, WorkloadId};
    use mvm_contract::protocol::mailbox::{BootId, ExecutionEpoch, MailboxGrant, MailboxId};
    use mvm_contract::protocol::workload_actor::{ActorToken, ControllerIdentity};

    pub(super) fn record(keys: &Path) -> ChildRecord {
        crate::audit::host_keypair::load_or_init_at(keys).unwrap();
        let mailbox = MailboxId::from_bytes([5; 32]);
        let epoch = ExecutionEpoch::new(1).unwrap();
        let authority = crate::mailbox_launch::authority_key_for(keys, &mailbox, epoch)
            .unwrap()
            .to_bytes();
        let grant = MailboxGrant {
            mailbox,
            authority_key: authority,
            epoch,
            report: None,
            retention: None,
            service_blind: None,
        };
        let derived =
            crate::mailbox_launch::derive_launch_keys(keys, &grant, &Key::random()).unwrap();
        let (_, sealer) = derived.trust();
        let capability =
            mvm_core::mailbox::sign_capability(sealer.capability.clone(), &sealer.authority_key)
                .unwrap();
        let address = capability.grant.address;
        let parent = ParentIdentity {
            controller: ControllerIdentity {
                tenant: TenantId("local".into()),
                workload: WorkloadId("parent".into()),
                execution_epoch: epoch,
                boot_id: BootId::from_bytes([1; 32]),
                generation: std::num::NonZeroU64::new(1).unwrap(),
            },
            plan_id: PlanId("sha256:parent".into()),
        };
        ChildRecord {
            parent,
            request_id: ActorBindingId::new("launch-1").unwrap(),
            reservation: ReservationIdentity {
                tenant: [1; 32],
                workflow: [2; 32],
                controller: [3; 32],
                controller_generation: 1,
                idempotency_key: [4; 32],
                template_digest: [5; 32],
                parent_plan_digest: [6; 32],
                request_digest: [7; 32],
            },
            host_reservation: "host-hold".into(),
            child_workload: "actor-child".into(),
            handle: ActorHandle {
                token: ActorToken::from_bytes([77; 32]),
                mailbox: address,
            },
            mailbox: DerivedChildMailbox {
                grant,
                address,
                parent_capability: capability.clone(),
                child_capability: capability,
                parent_issuer_key: authority,
                child_issuer_key: authority,
            },
            child_plan_digest: None,
            teardown: None,
            terminal_evidence_digest: None,
            state: ChildState::Pending,
            release_request: None,
        }
    }

    #[test]
    fn reopen_requires_original_key_and_committed_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("actors");
        let key = [7; 32];
        let store = ActorJournal::create(&path, Key::from_bytes(key)).unwrap();
        assert!(ActorJournal::create(&path, Key::random()).is_err());
        assert!(ActorJournal::open(&path, Key::from_bytes([8; 32])).is_err());
        assert!(ActorJournal::open(&path, Key::from_bytes(key)).is_ok());
        let _lock = store.lock().unwrap();
        let records = store.read().unwrap();
        store.write(&records).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(!bytes.windows(b"children".len()).any(|w| w == b"children"));
        std::fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
        assert!(store.read().is_err());
    }

    #[test]
    fn every_crash_checkpoint_preserves_exact_binding_and_unknown_intent() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        mvm_core::private_fs::ensure_private_dir(&keys).unwrap();
        let record = record(&keys);
        let path = dir.path().join("actors");
        let store = ActorJournal::create(&path, Key::from_bytes([9; 32])).unwrap();
        let mut records = Records {
            version: 1,
            children: vec![record],
            attempts: Vec::new(),
        };
        for state in [
            ChildState::Pending,
            ChildState::Prepared,
            ChildState::Dispatching,
            ChildState::Running,
            ChildState::Stopping,
            ChildState::Terminal,
        ] {
            records.children[0].state = state;
            if state != ChildState::Pending {
                records.children[0].child_plan_digest = Some([8; 32]);
            }
            if state == ChildState::Terminal {
                records.children[0].terminal_evidence_digest = Some([10; 32]);
            }
            store.write(&records).unwrap();
            let reopened = ActorJournal::open(&path, Key::from_bytes([9; 32])).unwrap();
            let recovered = reopened.read().unwrap();
            assert_eq!(recovered.children[0].state, state);
            assert_eq!(recovered.children[0].handle, records.children[0].handle);
            assert_eq!(
                recovered.children[0].reservation,
                records.children[0].reservation
            );
            let bytes = std::fs::read(&path).unwrap();
            let token = serde_json::to_vec(&records.children[0].handle.token).unwrap();
            assert!(!bytes.windows(token.len()).any(|window| window == token));
        }
        records.children.push(records.children[0].clone());
        assert!(
            store.write(&records).is_err(),
            "duplicate identity cannot authorize another child"
        );
        assert!(
            store.read().is_ok(),
            "invalid update preserves committed history"
        );
    }

    #[test]
    fn pre_receipt_failures_preserve_cleanup_identity_without_authorizing_dispatch() {
        let dir = tempfile::tempdir().unwrap();
        let original = record(dir.path());
        let path = dir.path().join("attempts");
        let store = ActorJournal::create(&path, Key::from_bytes([9; 32])).unwrap();
        let mut records = store.read().unwrap();
        let mut child = mvm_core::plan::test_support::PlanFixture::new().build();
        child.workload.0 = original.child_workload.clone();
        records.attempts.push(AttemptRecord {
            parent: original.parent,
            request_id: original.request_id,
            reservation: original.reservation,
            host_reservation: original.host_reservation,
            child,
            mailbox_preparing: false,
            terminal_evidence_digest: None,
        });
        for preparing in [false, true] {
            records.attempts[0].mailbox_preparing = preparing;
            store.write(&records).unwrap();
            let reopened = ActorJournal::open(&path, Key::from_bytes([9; 32])).unwrap();
            let recovered = reopened.read().unwrap();
            assert!(recovered.children.is_empty());
            assert_eq!(recovered.attempts[0].mailbox_preparing, preparing);
            assert_eq!(recovered.attempts[0].child, records.attempts[0].child);
            assert!(recovered.attempts[0].terminal_evidence_digest.is_none());
        }
        records.attempts[0].terminal_evidence_digest = Some([7; 32]);
        store.write(&records).unwrap();
        assert!(
            store.read().unwrap().attempts[0]
                .terminal_evidence_digest
                .is_some()
        );
    }

    #[test]
    fn handle_authorizes_only_original_parent_boot_and_exact_mailbox() {
        let dir = tempfile::tempdir().unwrap();
        let record = record(dir.path());
        assert!(record.matches_handle(&record.parent, &record.handle));
        let mut forged = record.handle.clone();
        forged.token = ActorToken::from_bytes([78; 32]);
        assert!(!record.matches_handle(&record.parent, &forged));
        let mut altered = record.handle.clone();
        altered.mailbox.mailbox = MailboxId::from_bytes([6; 32]);
        assert!(!record.matches_handle(&record.parent, &altered));
        let mut caller = record.parent.clone();
        caller.controller.workload = WorkloadId("other-parent".into());
        assert!(!record.matches_handle(&caller, &record.handle));
        caller = record.parent.clone();
        caller.controller.execution_epoch = ExecutionEpoch::new(2).unwrap();
        assert!(!record.matches_handle(&caller, &record.handle));
        caller = record.parent.clone();
        caller.controller.boot_id = BootId::from_bytes([8; 32]);
        assert!(!record.matches_handle(&caller, &record.handle));
        caller = record.parent.clone();
        caller.controller.generation = std::num::NonZeroU64::new(2).unwrap();
        assert!(!record.matches_handle(&caller, &record.handle));
    }

    #[test]
    fn admission_failure_pending_cleanup_reopens_without_poisoning_other_child() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let keys = dir.path().join("keys");
        mvm_core::private_fs::ensure_private_dir(&keys).unwrap();
        let first = record(&keys);
        let mut second = first.clone();
        second.request_id = ActorBindingId::new("launch-2").unwrap();
        second.child_workload = "actor-other".into();
        second.handle.token = ActorToken::from_bytes([88; 32]);
        second.child_plan_digest = Some([19; 32]);
        second.state = ChildState::Running;
        let path = dir.path().join("actors");
        let store = ActorJournal::create(&path, Key::from_bytes([9; 32])).unwrap();
        let mut records = Records {
            version: 1,
            children: vec![first, second],
            attempts: Vec::new(),
        };
        store.write(&records).unwrap();

        let now = chrono::Utc::now();
        let mut plan = mvm_core::plan::test_support::PlanFixture::new()
            .validity(
                now - chrono::Duration::hours(2),
                now - chrono::Duration::hours(1),
            )
            .build();
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        let admission = crate::plan_admission::admit_plan_for_run(
            &plan,
            &crate::plan_admission::SystemClock,
            &crate::plan_admission::InMemoryNonceLedger::new(),
            Some(&keys),
            None,
            None,
            crate::plan_admission::RunPosture::without_backend(mvm_core::plan::Variant::Dev),
        );
        assert!(admission.is_err(), "an expired plan cannot admit");
        records.children[0].begin_release(&ActorBindingId::new("shutdown-1").unwrap());
        assert_eq!(records.children[0].state, ChildState::Cancelling);
        assert!(records.children[0].child_plan_digest.is_none());
        store.write(&records).unwrap();
        let reopened = ActorJournal::open(&path, Key::from_bytes([9; 32])).unwrap();
        let mut records = reopened.read().unwrap();
        records.children[0].state = ChildState::Cancelled;
        records.children[0].terminal_evidence_digest = Some([20; 32]);
        reopened.write(&records).unwrap();
        records.children[1].begin_release(&ActorBindingId::new("release-2").unwrap());
        assert_eq!(records.children[1].state, ChildState::Stopping);
        reopened.write(&records).unwrap();
        records.children[1].state = ChildState::Terminal;
        records.children[1].terminal_evidence_digest = Some([21; 32]);
        reopened.write(&records).unwrap();
        assert_eq!(
            reopened.read().unwrap().children[0].state,
            ChildState::Cancelled
        );

        records.children[0].state = ChildState::Stopping;
        records.children[0].terminal_evidence_digest = None;
        assert!(
            reopened.write(&records).is_err(),
            "writer rejects missing prepared digest"
        );
        let bytes = aead::seal(
            &Key::from_bytes([9; 32]),
            &serde_json::to_vec(&records).unwrap(),
            DOMAIN,
        );
        write_private(&path, &bytes).unwrap();
        assert!(
            reopened.read().is_err(),
            "reader enforces the identical invariant"
        );
    }
}
