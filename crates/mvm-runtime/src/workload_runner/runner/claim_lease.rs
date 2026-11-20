//! The reservation a warm claim holds on its standby parent, and what a claim
//! that does not commit gives back.

use std::path::PathBuf;

use super::BrokerGuard;
use crate::driver::VmmDriver;
use crate::standby_pool::SupervisorStandbyPool;
use crate::workload_runner::claim::EndpointHandle;
use mvm_core::vm_backend::VmId;

enum ChildTermination {
    Pending,
    Confirmed,
    Unknown,
}

/// Release-unless-committed lease for a reserved parent and a partially-built
/// child. A claim reserves the parent (`mark_claimed`) and then materializes a
/// child dir; if a later step fails and the child is confirmed stopped, this guard
/// returns the healthy parent to claimable and removes the orphaned child dir.
/// Uncertain termination retains both the child state and the parent reservation.
/// Only a claim that boots the child calls
/// [`commit`](Self::commit), disarming both. A parent that failed VERIFICATION is
/// quarantined by removal upstream and never reaches this guard, so releasing
/// here only ever returns a parent that verified healthy.
pub(super) struct WarmClaimLease<'a> {
    pool: &'a SupervisorStandbyPool,
    driver: &'a dyn VmmDriver,
    parent_id: &'a str,
    child_dir: Option<PathBuf>,
    preloaded_child: Option<String>,
    committed: bool,
    termination: ChildTermination,
    quarantined: bool,
    endpoint: Option<EndpointHandle>,
    broker: Option<BrokerGuard>,
}

impl<'a> WarmClaimLease<'a> {
    pub(super) fn new(
        pool: &'a SupervisorStandbyPool,
        parent_id: &'a str,
        driver: &'a dyn VmmDriver,
    ) -> Self {
        Self {
            pool,
            driver,
            parent_id,
            child_dir: None,
            preloaded_child: None,
            committed: false,
            termination: ChildTermination::Pending,
            quarantined: false,
            endpoint: None,
            broker: None,
        }
    }

    /// Track the child dir so an early return after materialize removes it.
    pub(super) fn track_child_dir(&mut self, dir: PathBuf) {
        self.child_dir = Some(dir);
    }

    /// Track a paused child process so an early claim refusal cannot leave a
    /// VMM alive after its pool reservation is returned.
    pub(super) fn track_preloaded_child(&mut self, vm_name: String) {
        self.preloaded_child = Some(vm_name);
    }

    /// Resource rollback follows the child's termination decision, never precedes it.
    pub(super) fn track_endpoint(&mut self, endpoint: EndpointHandle) {
        self.endpoint = Some(endpoint);
    }

    pub(super) fn track_broker(&mut self, broker: BrokerGuard) {
        self.broker = Some(broker);
    }

    fn retain_resources(&mut self) {
        if let Some(endpoint) = &mut self.endpoint {
            endpoint.defuse();
        }
        if let Some(broker) = &mut self.broker {
            broker.defuse();
        }
    }

    /// The child booted: disarm. The parent stays `Claimed` (the stop/reaper path
    /// owns it) and the child dir is real state, not an orphan.
    pub(super) fn commit(&mut self) {
        self.committed = true;
    }

    /// Preserve the reservation and child state until termination can be established.
    pub(super) fn retain_unknown_child(&mut self) {
        self.termination = ChildTermination::Unknown;
    }

    /// A successful explicit stop must not be retried through an already-gone handle.
    pub(super) fn confirm_child_stopped(&mut self) {
        self.termination = ChildTermination::Confirmed;
    }

    /// Preserve both the reservation and child state when a failed stop
    /// cannot prove the child is gone. Neither may be reused or deleted.
    pub(super) fn retain_uncertain_child(&mut self) {
        self.committed = true;
    }

    /// The parent can never be restored on this host: drop it from the pool
    /// rather than return it to rotation, where every later claim would fail the
    /// same way until its TTL. Removal waits until any paused child is confirmed
    /// stopped; unknown termination keeps the reservation instead.
    pub(super) fn quarantine(&mut self) {
        // Defer removal until Drop establishes that no preloaded child remains live.
        self.quarantined = true;
    }
}

impl Drop for WarmClaimLease<'_> {
    fn drop(&mut self) {
        if self.committed || matches!(self.termination, ChildTermination::Unknown) {
            self.retain_resources();
            return;
        }
        if let Some(vm_name) = &self.preloaded_child {
            let id = VmId(vm_name.clone());
            if !matches!(self.termination, ChildTermination::Confirmed)
                && let Err(error) = self.driver.attach(&id).and_then(|vm| vm.kill())
            {
                tracing::warn!(
                    vm = %vm_name,
                    %error,
                    "preloaded child stop unconfirmed; retaining child state and parent reservation"
                );
                self.retain_resources();
                return;
            }
            // The child is confirmed stopped. The record has to stop naming
            // it: left alone it keeps advertising a paused VMM that no longer
            // exists, so every later claim refuses on a missing control socket
            // while the pool still counts the parent as usable capacity. The
            // parent and its checkpoint are healthy, so demote rather than
            // remove; the next claim materializes a fresh child from it.
            if let Err(error) = self.pool.demote_to_saved_state(self.parent_id) {
                tracing::warn!(
                    parent = %self.parent_id,
                    child = %vm_name,
                    %error,
                    "could not demote standby to saved-state after its preloaded child was \
                     destroyed; it will refuse every claim until reaped"
                );
            }
        }
        // Reapers need the retained child directory. Run them after confirmed
        // termination, before releasing the reservation or removing the directory.
        drop(self.broker.take());
        drop(self.endpoint.take());
        if self.quarantined {
            if let Err(error) = self.pool.remove(self.parent_id) {
                tracing::warn!(parent = %self.parent_id, %error, "removing unrestorable parent after child stop");
            }
        } else if let Err(error) = self.pool.mark_idle(self.parent_id) {
            tracing::warn!(parent = %self.parent_id, %error, "returning reserved standby parent to claimable after child stop");
        }
        if let Some(dir) = &self.child_dir {
            match std::fs::remove_dir_all(dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => tracing::warn!(
                    dir = %dir.display(),
                    error = %e,
                    "removing orphaned child dir after a failed claim"
                ),
            }
        }
    }
}
