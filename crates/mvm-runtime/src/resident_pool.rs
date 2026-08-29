//! Process-local ownership for resident warm parents.
//!
//! The on-disk [`crate::standby_pool::SupervisorStandbyPool`] protects
//! reservations across launcher processes. A resident backend also needs a
//! process-local boundary around the live parent handle: selecting an idle
//! parent and marking it claimed must be one operation, and an abandoned
//! claim must return capacity automatically.
//!
//! This registry is deliberately backend-neutral. It does not advertise a
//! backend capability or perform snapshot/restore itself. A backend may add a
//! verified live parent only after its own readiness and lineage checks have
//! completed; the actual restore/fork implementation remains the driver's
//! responsibility.

use std::collections::BTreeMap;
use std::sync::Mutex;

use mvm_core::vm_backend::{StandbyCompat, StandbyHandle, StandbyState};

/// Errors returned by the resident parent registry.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResidentPoolError {
    /// A parent id was empty and therefore could not be tracked safely.
    #[error("resident warm parent id must not be empty")]
    EmptyId,
    /// A parent without a captured checkpoint has not passed the registry's
    /// minimum lineage boundary.
    #[error("resident warm parent '{id}' has no captured checkpoint")]
    MissingCheckpoint { id: String },
    /// Only idle parents may enter the available set.
    #[error("resident warm parent '{id}' must be idle, got {state:?}")]
    NotIdle { id: String, state: StandbyState },
    /// A parent id is already registered.
    #[error("resident warm parent '{0}' is already registered")]
    Duplicate(String),
    /// An operation named a parent that is not in the registry.
    #[error("resident warm parent '{0}' is not registered")]
    NotFound(String),
    /// A release or finalization was attempted for an idle parent.
    #[error("resident warm parent '{0}' is not claimed")]
    NotClaimed(String),
    /// The registry mutex was poisoned after a panic in another owner.
    #[error("resident warm parent registry is poisoned")]
    Poisoned,
}

type RegistryResult<T> = std::result::Result<T, ResidentPoolError>;

struct ResidentParent {
    handle: StandbyHandle,
}

/// Atomic process-local reservation registry for live warm parents.
pub struct ResidentWarmPool {
    parents: Mutex<BTreeMap<String, ResidentParent>>,
}

impl ResidentWarmPool {
    /// Create an empty resident parent registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            parents: Mutex::new(BTreeMap::new()),
        }
    }

    /// Register a parent that has completed readiness verification and has a
    /// captured checkpoint anchoring its content and lineage.
    pub fn insert_verified(&self, handle: StandbyHandle) -> RegistryResult<()> {
        if handle.id.is_empty() {
            return Err(ResidentPoolError::EmptyId);
        }
        if handle.parent_checkpoint.is_none() {
            return Err(ResidentPoolError::MissingCheckpoint {
                id: handle.id.clone(),
            });
        }
        if handle.state != StandbyState::Idle {
            return Err(ResidentPoolError::NotIdle {
                id: handle.id.clone(),
                state: handle.state,
            });
        }

        let mut parents = self
            .parents
            .lock()
            .map_err(|_| ResidentPoolError::Poisoned)?;
        if parents.contains_key(&handle.id) {
            return Err(ResidentPoolError::Duplicate(handle.id));
        }
        let id = handle.id.clone();
        parents.insert(id, ResidentParent { handle });
        Ok(())
    }

    /// Reserve one compatible idle parent. Reservation is atomic with
    /// selection, so concurrent claimers cannot receive the same parent.
    pub fn reserve_compatible(
        &self,
        want: &StandbyCompat,
    ) -> RegistryResult<Option<ResidentWarmLease<'_>>> {
        let mut parents = self
            .parents
            .lock()
            .map_err(|_| ResidentPoolError::Poisoned)?;
        let Some(id) = parents.iter().find_map(|(id, parent)| {
            (parent.handle.state == StandbyState::Idle && parent.handle.is_compatible(want))
                .then(|| id.clone())
        }) else {
            return Ok(None);
        };
        let parent = parents
            .get_mut(&id)
            .ok_or_else(|| ResidentPoolError::NotFound(id.clone()))?;
        parent.handle.state = StandbyState::Claimed;
        Ok(Some(ResidentWarmLease {
            pool: self,
            id,
            finalized: false,
        }))
    }

    /// Number of currently available resident parents.
    pub fn idle_count(&self) -> RegistryResult<usize> {
        let parents = self
            .parents
            .lock()
            .map_err(|_| ResidentPoolError::Poisoned)?;
        Ok(parents
            .values()
            .filter(|parent| parent.handle.state == StandbyState::Idle)
            .count())
    }

    /// Number of registered parents, including claimed parents.
    pub fn len(&self) -> RegistryResult<usize> {
        Ok(self
            .parents
            .lock()
            .map_err(|_| ResidentPoolError::Poisoned)?
            .len())
    }

    /// Whether no resident parents are registered.
    pub fn is_empty(&self) -> RegistryResult<bool> {
        Ok(self.len()? == 0)
    }

    fn release_claim(&self, id: &str) -> RegistryResult<()> {
        let mut parents = self
            .parents
            .lock()
            .map_err(|_| ResidentPoolError::Poisoned)?;
        let parent = parents
            .get_mut(id)
            .ok_or_else(|| ResidentPoolError::NotFound(id.to_string()))?;
        if parent.handle.state != StandbyState::Claimed {
            return Err(ResidentPoolError::NotClaimed(id.to_string()));
        }
        parent.handle.state = StandbyState::Idle;
        Ok(())
    }

    fn finalize_claim(&self, id: &str) -> RegistryResult<StandbyHandle> {
        let mut parents = self
            .parents
            .lock()
            .map_err(|_| ResidentPoolError::Poisoned)?;
        let parent = parents
            .get(id)
            .ok_or_else(|| ResidentPoolError::NotFound(id.to_string()))?;
        if parent.handle.state != StandbyState::Claimed {
            return Err(ResidentPoolError::NotClaimed(id.to_string()));
        }
        parents
            .remove(id)
            .map(|parent| parent.handle)
            .ok_or_else(|| ResidentPoolError::NotFound(id.to_string()))
    }
}

impl Default for ResidentWarmPool {
    fn default() -> Self {
        Self::new()
    }
}

/// A single-owner reservation of one resident warm parent.
pub struct ResidentWarmLease<'a> {
    pool: &'a ResidentWarmPool,
    id: String,
    finalized: bool,
}

impl ResidentWarmLease<'_> {
    /// The id of the reserved parent.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Snapshot the reserved parent handle for the backend restore operation.
    pub fn handle(&self) -> RegistryResult<StandbyHandle> {
        let parents = self
            .pool
            .parents
            .lock()
            .map_err(|_| ResidentPoolError::Poisoned)?;
        parents
            .get(&self.id)
            .map(|parent| parent.handle.clone())
            .ok_or_else(|| ResidentPoolError::NotFound(self.id.clone()))
    }

    /// Return the parent to the idle set after a child-side failure that did
    /// not damage the parent.
    pub fn release(mut self) -> RegistryResult<()> {
        let result = self.pool.release_claim(&self.id);
        if result.is_ok() {
            self.finalized = true;
        }
        result
    }

    /// Consume the parent after a successful child restore. The returned
    /// handle remains marked claimed so callers can retain an audit trail of
    /// the one-shot reservation while the parent leaves the pool.
    pub fn commit(mut self) -> RegistryResult<StandbyHandle> {
        let result = self.pool.finalize_claim(&self.id);
        if result.is_ok() {
            self.finalized = true;
        }
        result
    }

    /// Remove the parent from rotation after a failed validation or restore.
    pub fn quarantine(mut self) -> RegistryResult<StandbyHandle> {
        let result = self.pool.finalize_claim(&self.id);
        if result.is_ok() {
            self.finalized = true;
        }
        result
    }
}

impl Drop for ResidentWarmLease<'_> {
    fn drop(&mut self) {
        if !self.finalized
            && let Err(error) = self.pool.release_claim(&self.id)
        {
            tracing::warn!(parent = %self.id, %error, "resident warm parent release on drop failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;

    use super::*;

    fn compatibility(kernel: &str) -> StandbyCompat {
        StandbyCompat {
            template_id: Some("python-3.12".into()),
            kernel_sha256: kernel.into(),
            vcpus: 2,
            mem_mib: 256,
            image_sha256: Some("image".into()),
            root_strategy: Default::default(),
            vsock_egress: true,
        }
    }

    fn handle(id: &str, kernel: &str, state: StandbyState) -> StandbyHandle {
        let compat = compatibility(kernel);
        StandbyHandle {
            id: id.into(),
            template_id: compat.template_id,
            control_socket: format!("/tmp/{id}.sock"),
            pid: 0,
            kernel_sha256: compat.kernel_sha256,
            vcpus: compat.vcpus,
            mem_mib: compat.mem_mib,
            binding_nonce: format!("nonce-{id}"),
            spawned_unix_secs: 1,
            state,
            image_sha256: compat.image_sha256,
            root_strategy: compat.root_strategy,
            parent_checkpoint: Some(format!("checkpoint-{id}")),
            preloaded_child_vm_name: None,
            vsock_egress: compat.vsock_egress,
        }
    }

    #[test]
    fn registration_requires_idle_checkpointed_parent() {
        let pool = ResidentWarmPool::new();
        let mut missing_checkpoint = handle("missing", "kernel", StandbyState::Idle);
        missing_checkpoint.parent_checkpoint = None;
        assert_eq!(
            pool.insert_verified(missing_checkpoint),
            Err(ResidentPoolError::MissingCheckpoint {
                id: "missing".into()
            })
        );
        assert_eq!(
            pool.insert_verified(handle("claimed", "kernel", StandbyState::Claimed)),
            Err(ResidentPoolError::NotIdle {
                id: "claimed".into(),
                state: StandbyState::Claimed,
            })
        );
        pool.insert_verified(handle("duplicate", "kernel", StandbyState::Idle))
            .expect("first registration succeeds");
        assert_eq!(
            pool.insert_verified(handle("duplicate", "kernel", StandbyState::Idle)),
            Err(ResidentPoolError::Duplicate("duplicate".into()))
        );
    }

    #[test]
    fn reserve_is_exact_and_drop_returns_capacity() {
        let pool = ResidentWarmPool::new();
        pool.insert_verified(handle("python", "kernel-a", StandbyState::Idle))
            .expect("parent registers");
        pool.insert_verified(handle("other", "kernel-b", StandbyState::Idle))
            .expect("parent registers");

        let lease = pool
            .reserve_compatible(&compatibility("kernel-a"))
            .expect("reserve succeeds")
            .expect("matching parent exists");
        assert_eq!(lease.id(), "python");
        assert_eq!(
            lease.handle().expect("reserved parent loads").state,
            StandbyState::Claimed
        );
        assert_eq!(pool.idle_count().expect("count succeeds"), 1);
        drop(lease);
        assert_eq!(pool.idle_count().expect("count succeeds"), 2);
        assert!(
            pool.reserve_compatible(&compatibility("missing"))
                .expect("reserve succeeds")
                .is_none()
        );
    }

    #[test]
    fn commit_consumes_parent_and_quarantine_removes_parent() {
        let pool = ResidentWarmPool::new();
        pool.insert_verified(handle("committed", "kernel", StandbyState::Idle))
            .expect("parent registers");
        pool.insert_verified(handle("quarantined", "kernel", StandbyState::Idle))
            .expect("parent registers");

        let committed = pool
            .reserve_compatible(&compatibility("kernel"))
            .expect("reserve succeeds")
            .expect("parent exists")
            .commit()
            .expect("commit succeeds");
        assert_eq!(committed.id, "committed");
        assert_eq!(pool.len().expect("count succeeds"), 1);

        let quarantined = pool
            .reserve_compatible(&compatibility("kernel"))
            .expect("reserve succeeds")
            .expect("parent exists")
            .quarantine()
            .expect("quarantine succeeds");
        assert_eq!(quarantined.id, "quarantined");
        assert!(pool.is_empty().expect("empty check succeeds"));
    }

    #[test]
    fn concurrent_reservation_returns_one_parent_to_one_claim() {
        let pool = Arc::new(ResidentWarmPool::new());
        pool.insert_verified(handle("only", "kernel", StandbyState::Idle))
            .expect("parent registers");
        let barrier = Arc::new(Barrier::new(2));
        let release_barrier = Arc::new(Barrier::new(2));
        let (sender, receiver) = mpsc::channel();
        let mut threads = Vec::new();
        for _ in 0..2 {
            let pool = Arc::clone(&pool);
            let barrier = Arc::clone(&barrier);
            let release_barrier = Arc::clone(&release_barrier);
            let sender = sender.clone();
            threads.push(thread::spawn(move || {
                barrier.wait();
                let lease = pool
                    .reserve_compatible(&compatibility("kernel"))
                    .expect("reserve succeeds");
                let reserved = lease.is_some();
                sender
                    .send(reserved)
                    .expect("result receiver remains active");
                release_barrier.wait();
                drop(lease);
            }));
        }
        drop(sender);
        for thread in threads {
            thread.join().expect("reservation thread exits");
        }
        let results: Vec<_> = receiver.iter().collect();
        assert_eq!(results.iter().filter(|reserved| **reserved).count(), 1);
        assert_eq!(pool.idle_count().expect("count succeeds"), 1);
    }
}
