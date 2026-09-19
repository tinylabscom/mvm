//! The reservation a warm claim holds on its standby parent, and what a claim
//! that does not commit gives back.

use std::path::PathBuf;

use crate::driver::VmmDriver;
use crate::standby_pool::SupervisorStandbyPool;
use mvm_core::vm_backend::VmId;

/// Release-unless-committed lease for a reserved parent and a partially-built
/// child. A claim reserves the parent (`mark_claimed`) and then materializes a
/// child dir; if any later step fails, this guard returns the (verified, healthy)
/// parent to claimable — so a failed claim never strands warm capacity — and
/// removes the orphaned child dir. Only a claim that boots the child calls
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
    quarantined: bool,
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
            quarantined: false,
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

    /// The child booted: disarm. The parent stays `Claimed` (the stop/reaper path
    /// owns it) and the child dir is real state, not an orphan.
    pub(super) fn commit(&mut self) {
        self.committed = true;
    }

    /// The parent can never be restored on this host: drop it from the pool
    /// rather than return it to rotation, where every later claim would fail the
    /// same way until its TTL. The child dir and any paused child are still
    /// cleaned up on drop.
    pub(super) fn quarantine(&mut self) {
        if let Err(e) = self.pool.remove(self.parent_id) {
            tracing::warn!(
                parent = %self.parent_id,
                error = %e,
                "failed to drop a standby parent this host cannot restore; it stays claimed (unclaimable) until the pool reaper"
            );
        }
        self.quarantined = true;
    }
}

impl Drop for WarmClaimLease<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if self.quarantined {
            // Already removed; releasing it would put it back in rotation.
        } else if let Err(e) = self.pool.mark_idle(self.parent_id) {
            tracing::warn!(
                parent = %self.parent_id,
                error = %e,
                "returning reserved standby parent to claimable after a failed claim"
            );
        }
        if let Some(vm_name) = &self.preloaded_child {
            let id = VmId(vm_name.clone());
            if let Err(error) = self.driver.attach(&id).and_then(|vm| vm.kill()) {
                tracing::warn!(
                    vm = %vm_name,
                    %error,
                    "stopping preloaded standby child after failed claim"
                );
            }
            // The child is gone either way — killed above, or already dead and
            // about to lose its state dir below. The record has to stop naming
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
