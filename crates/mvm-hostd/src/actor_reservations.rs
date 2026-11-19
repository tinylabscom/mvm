//! Durable, process-shared reservations before any child launch or host effect.
//!
//! The trusted lifecycle owner supplies authenticated ceilings and identities.
//! This journal is not guest authority. Keep its directory private and use one
//! canonical journal per host. Direct workload launches do not open this store.
//! The global ceiling here covers actor charges only; the launch coordinator
//! must also hold ordinary host capacity, including non-actor workloads.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use mvm_contract::protocol::actor_budget::{ActorBudget, ActorResources};
use mvm_core::util::atomic_io::{FileLock, NewFile, write_private, write_private_new};
use serde::{Deserialize, Serialize};

/// Hard retention bound; full stores refuse new work rather than forget replay history.
pub const MAX_RESERVATIONS: usize = 4096;
const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;

/// Hash-only bindings; callers hash canonical authenticated identities, never payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationIdentity {
    pub tenant: [u8; 32],
    pub workflow: [u8; 32],
    pub controller: [u8; 32],
    pub controller_generation: u64,
    pub idempotency_key: [u8; 32],
    pub template_digest: [u8; 32],
    pub parent_plan_digest: [u8; 32],
    pub request_digest: [u8; 32],
}

impl ReservationIdentity {
    fn same_key(&self, other: &Self) -> bool {
        self.tenant == other.tenant
            && self.workflow == other.workflow
            && self.idempotency_key == other.idempotency_key
    }
}

/// One child and its full resource shape, never an unbounded batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationRequest {
    pub identity: ReservationIdentity,
    pub resources: ActorResources,
}

/// Independent authenticated ceilings, pinned for the lifetime of each scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationCeilings {
    pub tenant: ActorBudget,
    pub workflow: ActorBudget,
    pub controller: ActorBudget,
}

/// Recovery never treats elapsed time or an absent process handle as cleanup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ReservationState {
    Pending,
    Prepared { child_plan_digest: [u8; 32] },
    Running { child_plan_digest: [u8; 32] },
    Terminal { result_digest: [u8; 32] },
}

/// Durable receipt; contains no commands, credentials, results or mailbox payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub request: ReservationRequest,
    pub ceilings: ReservationCeilings,
    pub state: ReservationState,
}

/// Only `Reserved` permits the caller to begin a new launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReserveOutcome {
    Reserved(Reservation),
    /// Includes ambiguous pending recovery: reconcile, never launch again.
    Existing(Reservation),
}

#[derive(Debug, thiserror::Error)]
pub enum ReservationError {
    #[error("actor reservation I/O failed; do not launch, reconcile durable state")]
    Io(#[from] std::io::Error),
    #[error("actor reservation lock failed")]
    Lock(#[source] anyhow::Error),
    #[error("invalid actor reservation journal")]
    Corrupt,
    #[error("actor reservation ceiling or retention bound exhausted")]
    Exhausted,
    #[error("actor reservation replay or ceiling conflicts")]
    Conflict,
    #[error("actor reservation does not exist")]
    NotFound,
}

type Result<T> = std::result::Result<T, ReservationError>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    host: ActorBudget,
    records: Vec<Reservation>,
}

/// Explicitly initialized host-wide journal. No cached mutable accounting.
#[derive(Debug)]
pub struct ActorReservations {
    path: PathBuf,
}

impl ActorReservations {
    /// Initialize a new journal with an actor-only host subceiling.
    ///
    /// The directory must already be private and trusted. The launch owner must
    /// separately bind total host admission, including ordinary workload charges.
    /// Existing journals are never overwritten. Missing state during reopen is
    /// an error, not permission to reset lifetime attempts.
    pub fn create(path: &Path, host: ActorBudget) -> Result<Self> {
        let store = Self {
            path: path.to_owned(),
        };
        let _lock = store.lock()?;
        let journal = Journal {
            version: 1,
            host,
            records: Vec::new(),
        };
        let bytes = serde_json::to_vec(&journal).map_err(|_| ReservationError::Corrupt)?;
        if write_private_new(path, &bytes)? != NewFile::Created {
            return Err(ReservationError::Conflict);
        }
        Ok(store)
    }

    /// Open existing state, refusing corruption and retaining all live charges.
    pub fn open(path: &Path) -> Result<Self> {
        let store = Self {
            path: path.to_owned(),
        };
        let _lock = store.lock()?;
        store.read()?;
        Ok(store)
    }

    /// Reopen the host-global journal only under its original actor subceiling.
    pub fn open_with_host_budget(path: &Path, expected: ActorBudget) -> Result<Self> {
        let store = Self {
            path: path.to_owned(),
        };
        let _lock = store.lock()?;
        if store.read()?.host != expected {
            return Err(ReservationError::Conflict);
        }
        Ok(store)
    }

    fn lock(&self) -> Result<FileLock> {
        let directory = self.path.parent().ok_or(ReservationError::Corrupt)?;
        let metadata = std::fs::symlink_metadata(directory)?;
        mvm_core::private_fs::require_current_owner(&metadata)?;
        if !metadata.is_dir() || mvm_core::private_fs::mode_bits(directory, &metadata)? & 0o077 != 0
        {
            return Err(ReservationError::Corrupt);
        }
        crate::admission_budget::acquire_lock(&self.path.with_extension("lock"))
            .map_err(ReservationError::Lock)
    }

    fn read(&self) -> Result<Journal> {
        let bytes = crate::admission_budget::read_private(&self.path, MAX_JOURNAL_BYTES as usize)
            .map_err(|error| ReservationError::Io(std::io::Error::other(error)))?
            .ok_or_else(|| {
                ReservationError::Io(std::io::Error::from(std::io::ErrorKind::NotFound))
            })?;
        let journal: Journal =
            serde_json::from_slice(&bytes).map_err(|_| ReservationError::Corrupt)?;
        if journal.version != 1 || journal.records.len() > MAX_RESERVATIONS {
            return Err(ReservationError::Corrupt);
        }
        check_budget(&journal).map_err(|_| ReservationError::Corrupt)?;
        Ok(journal)
    }

    fn write(&self, journal: &Journal) -> Result<()> {
        let bytes = serde_json::to_vec(journal).map_err(|_| ReservationError::Corrupt)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(ReservationError::Exhausted);
        }
        write_private(&self.path, &bytes)?;
        Ok(())
    }

    /// Reserve all four scopes in one locked durable transaction.
    pub fn reserve(
        &self,
        request: ReservationRequest,
        ceilings: ReservationCeilings,
    ) -> Result<ReserveOutcome> {
        self.reserve_with(request, ceilings, Self::write)
    }

    fn reserve_with(
        &self,
        request: ReservationRequest,
        ceilings: ReservationCeilings,
        persist: impl FnOnce(&Self, &Journal) -> Result<()>,
    ) -> Result<ReserveOutcome> {
        let _lock = self.lock()?;
        let mut journal = self.read()?;
        if let Some(record) = journal
            .records
            .iter()
            .find(|r| r.request.identity.same_key(&request.identity))
        {
            return if record.request == request && record.ceilings == ceilings {
                Ok(ReserveOutcome::Existing(record.clone()))
            } else {
                Err(ReservationError::Conflict)
            };
        }
        if journal.records.len() == MAX_RESERVATIONS {
            return Err(ReservationError::Exhausted);
        }
        let record = Reservation {
            request,
            ceilings,
            state: ReservationState::Pending,
        };
        journal.records.push(record.clone());
        check_budget(&journal)?;
        persist(self, &journal)?;
        Ok(ReserveOutcome::Reserved(record))
    }

    /// Read the current receipt without changing accounting or authorizing dispatch.
    pub fn observe(&self, identity: &ReservationIdentity) -> Result<Reservation> {
        let _lock = self.lock()?;
        let journal = self.read()?;
        let record = journal
            .records
            .into_iter()
            .find(|r| r.request.identity.same_key(identity))
            .ok_or(ReservationError::NotFound)?;
        if &record.request.identity != identity {
            return Err(ReservationError::Conflict);
        }
        Ok(record)
    }

    /// Bind the derived child plan before dispatch. Recovery cannot redispatch it.
    pub fn mark_prepared(
        &self,
        identity: &ReservationIdentity,
        child_plan_digest: [u8; 32],
    ) -> Result<Reservation> {
        self.transition(identity, ReservationState::Prepared { child_plan_digest })
    }

    /// Record a launch owned by the trusted lifecycle owner; never relaunch a retry.
    pub fn mark_running(
        &self,
        identity: &ReservationIdentity,
        child_plan_digest: [u8; 32],
    ) -> Result<Reservation> {
        self.transition(identity, ReservationState::Running { child_plan_digest })
    }

    /// Trusted lifecycle-owner entry point, deliberately not a guest wire command.
    ///
    /// Call only after confirming child death and reaping every lease and host
    /// effect. The terminal result digest and resource release commit together.
    /// This includes failed launches whose absence of effects was reconciled.
    pub fn reconcile_terminal(
        &self,
        identity: &ReservationIdentity,
        result_digest: [u8; 32],
    ) -> Result<Reservation> {
        self.transition(identity, ReservationState::Terminal { result_digest })
    }

    fn transition(
        &self,
        identity: &ReservationIdentity,
        state: ReservationState,
    ) -> Result<Reservation> {
        let _lock = self.lock()?;
        let mut journal = self.read()?;
        let record = journal
            .records
            .iter_mut()
            .find(|r| r.request.identity.same_key(identity))
            .ok_or(ReservationError::NotFound)?;
        if &record.request.identity != identity {
            return Err(ReservationError::Conflict);
        }
        let allowed = match (&record.state, &state) {
            (old, new) if old == new => true,
            (ReservationState::Pending, ReservationState::Prepared { .. }) => true,
            (
                ReservationState::Prepared {
                    child_plan_digest: old,
                },
                ReservationState::Running {
                    child_plan_digest: new,
                },
            ) => old == new,
            (
                ReservationState::Pending
                | ReservationState::Prepared { .. }
                | ReservationState::Running { .. },
                ReservationState::Terminal { .. },
            ) => true,
            _ => false,
        };
        if !allowed {
            return Err(ReservationError::Conflict);
        }
        record.state = state;
        let receipt = record.clone();
        self.write(&journal)?;
        Ok(receipt)
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Scope {
    Host,
    Tenant([u8; 32]),
    Workflow([u8; 32], [u8; 32]),
    Controller([u8; 32], [u8; 32], [u8; 32], u64),
}

fn check_budget(journal: &Journal) -> Result<()> {
    let mut scopes = BTreeMap::new();
    let mut keys = BTreeSet::new();
    for record in &journal.records {
        let id = &record.request.identity;
        if !keys.insert((id.tenant, id.workflow, id.idempotency_key)) {
            return Err(ReservationError::Conflict);
        }
        let budgets = [
            (Scope::Host, journal.host),
            (Scope::Tenant(id.tenant), record.ceilings.tenant),
            (
                Scope::Workflow(id.tenant, id.workflow),
                record.ceilings.workflow,
            ),
            (
                Scope::Controller(
                    id.tenant,
                    id.workflow,
                    id.controller,
                    id.controller_generation,
                ),
                record.ceilings.controller,
            ),
        ];
        for (scope, ceiling) in budgets {
            let (pinned, usage, attempts) =
                scopes
                    .entry(scope)
                    .or_insert((ceiling, ActorResources::default(), 0u64));
            if *pinned != ceiling {
                return Err(ReservationError::Conflict);
            }
            *attempts = attempts.checked_add(1).ok_or(ReservationError::Exhausted)?;
            if !matches!(record.state, ReservationState::Terminal { .. }) {
                let mut committed = record.request.resources;
                if matches!(record.state, ReservationState::Running { .. }) {
                    committed.concurrent_launches = 0;
                }
                *usage = usage
                    .checked_add(committed)
                    .ok_or(ReservationError::Exhausted)?;
            }
            if *attempts > ceiling.max_total_attempts
                || !usage.fits_within(ceiling.resources)
                || !record.request.resources.fits_within(ceiling.resources)
            {
                return Err(ReservationError::Exhausted);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn budget() -> ActorBudget {
        ActorBudget {
            resources: ActorResources {
                live_vms: 1,
                memory_bytes: 64,
                ..Default::default()
            },
            max_total_attempts: 2,
        }
    }

    fn request(key: u8) -> ReservationRequest {
        ReservationRequest {
            identity: ReservationIdentity {
                tenant: [1; 32],
                workflow: [2; 32],
                controller: [3; 32],
                controller_generation: 1,
                idempotency_key: [key; 32],
                template_digest: [4; 32],
                parent_plan_digest: [5; 32],
                request_digest: [6; 32],
            },
            resources: budget().resources,
        }
    }

    fn ceilings() -> ReservationCeilings {
        ReservationCeilings {
            tenant: budget(),
            workflow: budget(),
            controller: budget(),
        }
    }

    fn private_directory() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        mvm_core::config::create_private_dir(dir.path()).unwrap();
        dir
    }

    fn store() -> (tempfile::TempDir, ActorReservations) {
        let dir = private_directory();
        let store = ActorReservations::create(&dir.path().join("actors.json"), budget()).unwrap();
        (dir, store)
    }

    #[cfg(unix)]
    #[test]
    fn create_and_reopen_require_a_private_parent_without_repairing_it() {
        let dir = private_directory();
        let path = dir.path().join("actors.json");
        mvm_core::private_fs::set_mode(dir.path(), 0o755).unwrap();
        assert!(matches!(
            ActorReservations::create(&path, budget()),
            Err(ReservationError::Corrupt)
        ));
        assert!(!path.exists());
        assert!(!path.with_extension("lock").exists());

        mvm_core::config::create_private_dir(dir.path()).unwrap();
        let store = ActorReservations::create(&path, budget()).unwrap();
        store.reserve(request(7), ceilings()).unwrap();
        let before = fs::read(&path).unwrap();
        mvm_core::private_fs::set_mode(dir.path(), 0o755).unwrap();
        assert!(matches!(
            ActorReservations::open(&path),
            Err(ReservationError::Corrupt)
        ));
        assert!(ActorReservations::open_with_host_budget(&path, budget()).is_err());
        assert!(store.reserve(request(8), ceilings()).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(
            mvm_core::private_fs::mode_bits(dir.path(), &fs::metadata(dir.path()).unwrap())
                .unwrap(),
            0o755
        );
        mvm_core::config::create_private_dir(dir.path()).unwrap();
        assert!(matches!(
            ActorReservations::open(&path)
                .unwrap()
                .reserve(request(7), ceilings())
                .unwrap(),
            ReserveOutcome::Existing(_)
        ));
    }

    #[test]
    fn retries_bind_identity_and_terminal_never_refunds_attempts() {
        let (_dir, store) = store();
        let first = request(7);
        assert!(matches!(
            store.reserve(first.clone(), ceilings()).unwrap(),
            ReserveOutcome::Reserved(_)
        ));
        assert!(matches!(
            store.reserve(first.clone(), ceilings()).unwrap(),
            ReserveOutcome::Existing(_)
        ));
        let mut conflict = first.clone();
        conflict.identity.request_digest = [9; 32];
        assert!(matches!(
            store.reserve(conflict, ceilings()),
            Err(ReservationError::Conflict)
        ));
        store.mark_prepared(&first.identity, [10; 32]).unwrap();
        assert!(store.mark_running(&first.identity, [11; 32]).is_err());
        store.mark_running(&first.identity, [10; 32]).unwrap();
        store.reconcile_terminal(&first.identity, [12; 32]).unwrap();
        store.reconcile_terminal(&first.identity, [12; 32]).unwrap();
        assert!(store.reconcile_terminal(&first.identity, [13; 32]).is_err());
        assert!(store.mark_prepared(&first.identity, [10; 32]).is_err());
        store.reserve(request(8), ceilings()).unwrap();
        store
            .reconcile_terminal(&request(8).identity, [12; 32])
            .unwrap();
        assert!(matches!(
            store.reserve(request(9), ceilings()),
            Err(ReservationError::Exhausted)
        ));
        assert_eq!(store.read().unwrap().records.len(), 2);
    }

    #[test]
    fn reopening_refuses_a_different_host_subceiling() {
        let (_dir, store) = store();
        assert!(ActorReservations::open_with_host_budget(&store.path, budget()).is_ok());
        let mut widened = budget();
        widened.resources.live_vms += 1;
        assert!(matches!(
            ActorReservations::open_with_host_budget(&store.path, widened),
            Err(ReservationError::Conflict)
        ));
        let mut narrowed = budget();
        narrowed.max_total_attempts -= 1;
        assert!(ActorReservations::open_with_host_budget(&store.path, narrowed).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn substituted_lock_and_state_are_refused_without_touching_the_target() {
        let (dir, store) = store();
        let victim = dir.path().join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        let lock = store.path.with_extension("lock");
        fs::remove_file(&lock).unwrap();
        std::os::unix::fs::symlink(&victim, &lock).unwrap();
        assert!(ActorReservations::open(&store.path).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
        fs::remove_file(&lock).unwrap();
        fs::hard_link(&victim, &lock).unwrap();
        assert!(ActorReservations::open(&store.path).is_err());
        fs::remove_file(&lock).unwrap();
        fs::remove_file(&store.path).unwrap();
        std::os::unix::fs::symlink(&victim, &store.path).unwrap();
        assert!(ActorReservations::open(&store.path).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
    }

    #[test]
    fn running_releases_only_launch_slots_and_preserves_requested_charge() {
        let dir = private_directory();
        let mut ceiling = budget();
        ceiling.resources.live_vms = 2;
        ceiling.resources.memory_bytes = 128;
        ceiling.resources.concurrent_launches = 1;
        let ceilings = ReservationCeilings {
            tenant: ceiling,
            workflow: ceiling,
            controller: ceiling,
        };
        let store = ActorReservations::create(&dir.path().join("actors.json"), ceiling).unwrap();
        let mut first = request(7);
        first.resources.concurrent_launches = 1;
        let mut second = request(8);
        second.resources.concurrent_launches = 1;
        store.reserve(first.clone(), ceilings).unwrap();
        assert!(store.reserve(second.clone(), ceilings).is_err());
        store.mark_prepared(&first.identity, [10; 32]).unwrap();
        assert!(store.reserve(second.clone(), ceilings).is_err());
        store.mark_running(&first.identity, [10; 32]).unwrap();
        store.reserve(second, ceilings).unwrap();
        let receipt = store.observe(&first.identity).unwrap();
        assert_eq!(receipt.request, first);
        assert_eq!(receipt.request.resources.concurrent_launches, 1);
        assert!(matches!(
            store.reserve(first, ceilings).unwrap(),
            ReserveOutcome::Existing(_)
        ));
    }

    #[test]
    fn independent_instances_contend_for_last_slot() {
        let (_dir, store) = store();
        let barrier = std::sync::Barrier::new(8);
        let results = std::thread::scope(|scope| {
            let threads: Vec<_> = (10..18)
                .map(|key| {
                    let path = &store.path;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        let independent = ActorReservations::open(path).unwrap();
                        barrier.wait();
                        independent.reserve(request(key), ceilings())
                    })
                })
                .collect();
            threads
                .into_iter()
                .map(|t| t.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(store.read().unwrap().records.len(), 1);
    }

    #[test]
    fn multidimensional_refusal_and_scope_conflict_have_no_partial_charge() {
        let (_dir, store) = store();
        let mut too_large = request(7);
        too_large.resources.memory_bytes = 65;
        assert!(store.reserve(too_large, ceilings()).is_err());
        assert!(store.read().unwrap().records.is_empty());
        store.reserve(request(7), ceilings()).unwrap();
        let mut changed = ceilings();
        changed.tenant.max_total_attempts += 1;
        assert!(store.reserve(request(8), changed).is_err());
        store
            .reconcile_terminal(&request(7).identity, [12; 32])
            .unwrap();
        assert!(matches!(
            store.reserve(request(8), changed),
            Err(ReservationError::Conflict)
        ));
        assert_eq!(store.read().unwrap().records.len(), 1);
    }

    #[test]
    fn reopen_retains_pending_prepared_and_running() {
        for phase in 0..3 {
            let (_dir, store) = store();
            let first = request(7);
            store.reserve(first.clone(), ceilings()).unwrap();
            if phase > 0 {
                store.mark_prepared(&first.identity, [10; 32]).unwrap();
            }
            if phase > 1 {
                store.mark_running(&first.identity, [10; 32]).unwrap();
            }
            let reopened = ActorReservations::open(&store.path).unwrap();
            assert!(matches!(
                reopened.reserve(first, ceilings()).unwrap(),
                ReserveOutcome::Existing(_)
            ));
            assert!(reopened.reserve(request(8), ceilings()).is_err());
        }
    }

    #[test]
    fn corrupt_truncated_missing_and_duplicate_state_refuse() {
        let (_dir, store) = store();
        store.reserve(request(7), ceilings()).unwrap();
        let mut journal = store.read().unwrap();
        journal.records.push(journal.records[0].clone());
        write_private(&store.path, &serde_json::to_vec(&journal).unwrap()).unwrap();
        assert!(ActorReservations::open(&store.path).is_err());
        for data in [b"{".as_slice(), b"{}", b"null"] {
            fs::write(&store.path, data).unwrap();
            assert!(ActorReservations::open(&store.path).is_err());
        }
        fs::remove_file(&store.path).unwrap();
        assert!(ActorReservations::open(&store.path).is_err());
    }

    #[test]
    fn failed_publication_never_returns_success_or_changes_prior_state() {
        let (_dir, store) = store();
        let journal = store.read().unwrap();
        let original = fs::read(&store.path).unwrap();
        let blocked = ActorReservations {
            path: store.path.with_file_name("blocked"),
        };
        fs::create_dir(&blocked.path).unwrap();
        assert!(blocked.write(&journal).is_err());
        assert_eq!(fs::read(&store.path).unwrap(), original);
        assert!(ActorReservations::create(&store.path, budget()).is_err());
    }

    #[test]
    fn failed_commit_before_or_after_publication_never_authorizes_launch() {
        let (_dir, store) = store();
        let failure = || ReservationError::Io(std::io::Error::other("injected commit failure"));
        assert!(
            store
                .reserve_with(request(7), ceilings(), |_, _| Err(failure()))
                .is_err()
        );
        assert!(store.read().unwrap().records.is_empty());
        assert!(
            store
                .reserve_with(request(7), ceilings(), |store, journal| {
                    store.write(journal)?;
                    // A directory sync can report failure after the rename became visible.
                    Err(failure())
                })
                .is_err()
        );
        let reopened = ActorReservations::open(&store.path).unwrap();
        assert!(matches!(
            reopened.reserve(request(7), ceilings()).unwrap(),
            ReserveOutcome::Existing(_)
        ));
        assert_eq!(
            reopened.observe(&request(7).identity).unwrap().state,
            ReservationState::Pending
        );
        assert!(reopened.reserve(request(8), ceilings()).is_err());
    }

    #[test]
    fn all_four_scopes_share_one_transaction_and_overflow_refuses() {
        let (_dir, store) = store();
        let mut journal = store.read().unwrap();
        journal.host.resources.memory_bytes = u64::MAX;
        journal.host.resources.live_vms = 3;
        let mut wide = ceilings();
        wide.tenant = journal.host;
        wide.workflow = journal.host;
        wide.controller = journal.host;
        store.write(&journal).unwrap();
        let mut first = request(7);
        first.resources.memory_bytes = u64::MAX;
        store.reserve(first, wide).unwrap();
        let mut second = request(8);
        second.identity.tenant = [55; 32];
        second.resources.memory_bytes = 1;
        assert!(store.reserve(second, wide).is_err());
        assert_eq!(store.read().unwrap().records.len(), 1);
    }

    #[test]
    fn each_independent_scope_can_refuse_without_partial_accounting() {
        for scope in 0..4 {
            let dir = private_directory();
            let wide = ActorBudget {
                resources: ActorResources {
                    live_vms: 2,
                    memory_bytes: 128,
                    ..Default::default()
                },
                max_total_attempts: 2,
            };
            let mut budgets = [wide; 4];
            budgets[scope] = budget();
            let store =
                ActorReservations::create(&dir.path().join("actors.json"), budgets[0]).unwrap();
            let ceilings = ReservationCeilings {
                tenant: budgets[1],
                workflow: budgets[2],
                controller: budgets[3],
            };
            store.reserve(request(7), ceilings).unwrap();
            let before = fs::read(&store.path).unwrap();
            assert!(
                store.reserve(request(8), ceilings).is_err(),
                "scope {scope}"
            );
            assert_eq!(fs::read(&store.path).unwrap(), before);
            let mut foreign = request(7).identity;
            foreign.controller_generation += 1;
            assert!(store.observe(&foreign).is_err());
            assert!(store.reconcile_terminal(&foreign, [12; 32]).is_err());
        }
    }

    #[test]
    fn subprocess_reservation_worker() {
        let Some(path) = std::env::var_os("MVM_ACTOR_RESERVATION_TEST_PATH") else {
            return;
        };
        let key = std::env::var("MVM_ACTOR_RESERVATION_TEST_KEY")
            .unwrap()
            .parse()
            .unwrap();
        let store = ActorReservations::open(Path::new(&path)).unwrap();
        let result = store.reserve(request(key), ceilings());
        assert!(matches!(
            result,
            Ok(ReserveOutcome::Reserved(_)) | Err(ReservationError::Exhausted)
        ));
        fs::write(
            store.path.with_extension(format!("result-{key}")),
            if result.is_ok() {
                b"yes".as_slice()
            } else {
                b"no".as_slice()
            },
        )
        .unwrap();
    }

    #[test]
    fn separate_processes_cannot_both_reserve_the_last_slot() {
        let (_dir, store) = store();
        let children: Vec<_> = [7, 8]
            .into_iter()
            .map(|key| {
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "actor_reservations::tests::subprocess_reservation_worker",
                    ])
                    .env("MVM_ACTOR_RESERVATION_TEST_PATH", &store.path)
                    .env("MVM_ACTOR_RESERVATION_TEST_KEY", key.to_string())
                    .stdout(std::process::Stdio::null())
                    .spawn()
                    .unwrap()
            })
            .collect();
        for mut child in children {
            assert!(child.wait().unwrap().success());
        }
        let wins = [7, 8]
            .into_iter()
            .filter(|key| {
                fs::read(store.path.with_extension(format!("result-{key}"))).unwrap() == b"yes"
            })
            .count();
        assert_eq!(wins, 1);
        assert_eq!(store.read().unwrap().records.len(), 1);
    }

    #[test]
    fn journal_growth_is_bounded_without_forgetting_terminal_replay() {
        let (_dir, store) = store();
        let mut journal = store.read().unwrap();
        journal.host.max_total_attempts = MAX_RESERVATIONS as u64 + 1;
        let mut limits = ceilings();
        limits.tenant = journal.host;
        limits.workflow = journal.host;
        limits.controller = journal.host;
        for index in 0..MAX_RESERVATIONS {
            let mut request = request(0);
            request.identity.idempotency_key[..8].copy_from_slice(&(index as u64).to_le_bytes());
            journal.records.push(Reservation {
                request,
                ceilings: limits,
                state: ReservationState::Terminal {
                    result_digest: [12; 32],
                },
            });
        }
        store.write(&journal).unwrap();
        let bytes = fs::read(&store.path).unwrap();
        assert!(bytes.len() as u64 <= MAX_JOURNAL_BYTES);
        let mut next = request(0);
        next.identity.idempotency_key[..8]
            .copy_from_slice(&(MAX_RESERVATIONS as u64).to_le_bytes());
        assert!(matches!(
            store.reserve(next, limits),
            Err(ReservationError::Exhausted)
        ));
        assert_eq!(fs::read(&store.path).unwrap(), bytes);
        assert!(matches!(
            store
                .reserve(journal.records[0].request.clone(), limits)
                .unwrap(),
            ReserveOutcome::Existing(_)
        ));
    }
}
