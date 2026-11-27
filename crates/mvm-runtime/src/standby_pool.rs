//! The backend-agnostic supervisor standby pool registry.
//!
//! Records each prelaunched standby as `<pool_root>/<id>/standby.json` (the control
//! UDS lives alongside as `control-<nonce>.sock`, bound by the backend's spawn impl).
//! Selection/liveness/removal are backend-agnostic; only `spawn_standby`/`claim_standby`
//! on the `VmBackend` impl know how to actually launch. Default-off: with
//! `warm_pool_size == 0` the orchestration never constructs a pool.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::vm_backend::{StandbyCompat, StandbyHandle, StandbyState};

use crate::vm::instance_snapshot::MachineLifecycleLock;

/// Filename of the per-standby metadata JSON inside its dir.
const HANDLE_FILE: &str = "standby.json";

/// Marker in a preloaded child's state dir naming the standby that owns it.
/// A cold launch refuses a name whose state carries it.
pub const PRELOADED_CHILD_RESERVATION_FILE: &str = ".preloaded-child-reservation";

/// Polls, with doubling delay from 10 ms, for a released standby's process to
/// exit before its child state is removed.
const RELEASE_EXIT_POLLS: u32 = 5;

/// A parked standby is a low-cost saved-state snapshot; it may outlive the warm
/// TTL by this factor before the reaper finally removes it.
const PARKED_TTL_MULTIPLIER: u64 = 6;

/// Default TTL the lazy reapers ([`SupervisorStandbyPool::reap_stale`]) apply to
/// idle standbys. There is no daemon, so expiry is enforced on-use: both the
/// launch path and `cache prune` reap standbys older than this. Set a little
/// above the always-warm idle window (residency `idle_timeout`, 20 min) so a
/// freshly-warmed spare survives to its next claim, while a one-off run's
/// leftover spare is cleaned by the next mvmctl invocation.
pub const STANDBY_POOL_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// A view over `~/.mvm/pool/` (or a test root). Cheap to construct; all state is on disk.
pub struct SupervisorStandbyPool {
    root: PathBuf,
}

impl SupervisorStandbyPool {
    /// Open the pool at the real `~/.mvm/pool/` root.
    pub fn open() -> Result<Self> {
        Ok(Self::at(mvm_core::config::mvm_pool_dir()?))
    }

    /// Open at an explicit root (test seam).
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The pool's root directory. Callers that need to serialize across the
    /// whole pool (e.g. an exclusive warm lock) anchor on this.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Persist (or update) a standby's handle under `<root>/<id>/standby.json`,
    /// creating the dir `0700`.
    pub fn record(&self, h: &StandbyHandle) -> Result<()> {
        let dir = self.root.join(&h.id);
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        set_mode_0700(&dir)?;
        let json = serde_json::to_vec_pretty(h)?;
        std::fs::write(dir.join(HANDLE_FILE), json)
            .with_context(|| format!("write {} handle", h.id))?;
        Ok(())
    }

    /// Load one standby's handle by id.
    pub fn load(&self, id: &str) -> Result<StandbyHandle> {
        let path = self.root.join(id).join(HANDLE_FILE);
        let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Load a selected record, distinguishing a confirmed concurrent removal.
    ///
    /// Malformed and unreadable records remain errors: only `NotFound` proves
    /// that the selected parent was consumed between selection and reservation.
    pub(crate) fn load_selected(&self, id: &str) -> Result<Option<StandbyHandle>> {
        let path = self.root.join(id).join(HANDLE_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("read {}", path.display()));
            }
        };
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    /// All recorded handles (ignoring unreadable/garbage dirs — they get reaped by
    /// [`reap_stale`](Self::reap_stale)).
    pub fn list(&self) -> Result<Vec<StandbyHandle>> {
        let mut out = Vec::new();
        let rd = match std::fs::read_dir(&self.root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e).context("read pool root"),
        };
        for entry in rd.flatten() {
            if let Ok(h) = self.load(&entry.file_name().to_string_lossy()) {
                out.push(h);
            }
        }
        Ok(out)
    }

    /// Pick a claimable standby compatible with `want` (kernel + fixed resources + image)
    /// — the claim candidate. `None` means "no compatible warm standby; cold-boot." Skips
    /// claimed and dead entries. Saved-state standbys (pid=0) are considered live: their
    /// TTL controls expiry, not a process liveness check. Both `Idle` and `Parked`
    /// standbys are claimable; parked standbys resume from their saved state.
    ///
    /// A standby with a preloaded child is never selected here: its child can
    /// serve only a launch admitted under that child's name, which
    /// [`reserve_preloaded_compatible`](Self::reserve_preloaded_compatible)
    /// arranges before admission.
    pub fn select_idle_compatible(&self, want: &StandbyCompat) -> Result<Option<StandbyHandle>> {
        Ok(self
            .list()?
            .into_iter()
            .find(|h| Self::is_ordinary_candidate(h, want)))
    }

    fn is_ordinary_candidate(h: &StandbyHandle, want: &StandbyCompat) -> bool {
        h.preloaded_child_vm_name.is_none()
            && h.state.is_claimable()
            && h.is_compatible(want)
            && Self::is_live_or_saved(h)
    }

    /// Reserve one compatible standby whose paused child is ready, before the
    /// launch is admitted, by taking that child's lifecycle gate.
    ///
    /// The launch then admits its plan under the child's name, so the signed
    /// identity is the identity of the VM that runs. The gate is the
    /// reservation: a second launcher cannot take it, and the reapers skip a
    /// child whose gate is held. The pool record stays claimable until the
    /// claim marks it.
    pub fn reserve_preloaded_compatible(
        &self,
        want: &StandbyCompat,
    ) -> Result<Option<(StandbyHandle, MachineLifecycleLock)>> {
        let _claim_guard = mvm_core::atomic_io::FileLock::acquire(&self.root.join("claim"))?;
        for h in self.list()? {
            let Some(child) = h.preloaded_child_vm_name.as_deref() else {
                continue;
            };
            if !(h.state.is_claimable() && h.is_compatible(want) && pid_alive(h.pid)) {
                continue;
            }
            if let Some(lifecycle) = MachineLifecycleLock::try_acquire(child)? {
                return Ok(Some((h, lifecycle)));
            }
        }
        Ok(None)
    }

    /// Give up a reservation the launch cannot use, through the same teardown
    /// the reapers use. The parent's checkpoint is still sound, so the standby
    /// stays in the pool as saved-state and the launch can fork from it. A
    /// record the claim already reserved, consumed or demoted is left as it is.
    pub fn release_reserved_preload(
        &self,
        reserved: &StandbyHandle,
        lifecycle: &MachineLifecycleLock,
    ) -> Result<()> {
        let _claim_guard = mvm_core::atomic_io::FileLock::acquire(&self.root.join("claim"))?;
        let Some(current) = self.load_selected(&reserved.id)? else {
            return Ok(());
        };
        if !current.state.is_claimable()
            || current.preloaded_child_vm_name.as_deref() != Some(lifecycle.name())
        {
            return Ok(());
        }
        self.release_live(&current, Some(lifecycle), Release::KeepParent)
            .map(|_| ())
    }

    /// Atomically reserve one compatible warm parent.
    ///
    /// Selection and the persisted `Claimed` transition must share one lock;
    /// otherwise two launchers can both observe the same idle parent before
    /// either writes its reservation. The returned handle is already reserved
    /// and must be removed after the backend consumes its one-shot control
    /// channel.
    pub fn claim_idle_compatible(&self, want: &StandbyCompat) -> Result<Option<StandbyHandle>> {
        let _claim_guard = mvm_core::atomic_io::FileLock::acquire(&self.root.join("claim"))?;
        let Some(mut handle) = self
            .list()?
            .into_iter()
            .find(|h| Self::is_ordinary_candidate(h, want))
        else {
            return Ok(None);
        };
        self.mark_claimed(&handle.id)?;
        handle.state = StandbyState::Claimed;
        Ok(Some(handle))
    }

    /// True when the recorded standby still has a resource that can be claimed or displayed
    /// as live. Saved-state standbys have no process; the snapshot payload is the resource.
    pub fn is_live_or_saved(h: &StandbyHandle) -> bool {
        h.is_saved_state() || pid_alive(h.pid)
    }

    /// Count of live idle standbys compatible with `want` — drives replenish-to-target.
    pub fn idle_count_compatible(&self, want: &StandbyCompat) -> Result<usize> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|h| {
                h.state == StandbyState::Idle && h.is_compatible(want) && Self::is_live_or_saved(h)
            })
            .count())
    }

    /// Evict the oldest idle or parked parents for one template until their
    /// recorded memory footprint fits `max_memory_mib`.
    ///
    /// Claimed parents are never selected: a launcher may already be consuming
    /// one, and removing its registry entry here would turn a reservation into
    /// an untracked live VM. Template identities are compared exactly; legacy
    /// records with `None` remain in the image-agnostic pool.
    pub fn evict_to_memory_budget(
        &self,
        template_id: Option<&str>,
        max_memory_mib: u64,
    ) -> Result<Vec<String>> {
        self.evict_oldest_where(max_memory_mib, |h| h.template_id.as_deref() == template_id)
    }

    /// Evict the oldest idle or parked parents of one launch shape until their
    /// recorded memory footprint fits `max_memory_mib`.
    ///
    /// The per-shape bound a warm sweep applies to what it just warmed. Keyed on
    /// the whole compatibility key rather than the template, because every OCI
    /// image shares the `None` template: bounding by template let a sweep for
    /// one image evict every other image's standbys.
    pub fn evict_compatible_to_memory_budget(
        &self,
        want: &StandbyCompat,
        max_memory_mib: u64,
    ) -> Result<Vec<String>> {
        self.evict_oldest_where(max_memory_mib, |h| h.is_compatible(want))
    }

    /// Evict the oldest unclaimed standbys of any shape until the guest memory
    /// they hold fits `max_memory_mib`.
    ///
    /// The host-wide bound on standbys. Only standbys with a live process hold
    /// guest memory; a saved-state standby is a snapshot on disk and is neither
    /// counted nor evicted.
    pub fn evict_to_total_memory(&self, max_memory_mib: u64) -> Result<Vec<String>> {
        self.evict_oldest_where(max_memory_mib, |h| !h.is_saved_state() && pid_alive(h.pid))
    }

    /// Guest memory, in MiB, held by unclaimed standbys with a live process.
    pub fn idle_live_memory_mib(&self) -> Result<u64> {
        Ok(self
            .list()?
            .iter()
            .filter(|h| {
                matches!(h.state, StandbyState::Idle | StandbyState::Parked)
                    && !h.is_saved_state()
                    && pid_alive(h.pid)
            })
            .fold(0u64, |total, h| total.saturating_add(u64::from(h.mem_mib))))
    }

    fn evict_oldest_where(
        &self,
        max_memory_mib: u64,
        selects: impl Fn(&StandbyHandle) -> bool,
    ) -> Result<Vec<String>> {
        // Share the claim lock with reservation so a parent cannot be selected
        // for eviction from an idle listing while another launcher claims it.
        let _budget_guard = mvm_core::atomic_io::FileLock::acquire(&self.root.join("claim"))?;
        let mut candidates: Vec<_> = self
            .list()?
            .into_iter()
            .filter(|h| matches!(h.state, StandbyState::Idle | StandbyState::Parked) && selects(h))
            .collect();
        let mut memory_mib = candidates
            .iter()
            .fold(0u64, |total, h| total.saturating_add(u64::from(h.mem_mib)));
        candidates.sort_by_key(|h| h.spawned_unix_secs);

        let mut evicted = Vec::new();
        for h in candidates {
            if memory_mib <= max_memory_mib {
                break;
            }
            if h.is_saved_state() {
                self.remove(&h.id)?;
            } else if !self.release_live(&h, None, Release::Remove)? {
                continue;
            }
            memory_mib = memory_mib.saturating_sub(u64::from(h.mem_mib));
            evicted.push(h.id);
        }
        Ok(evicted)
    }

    /// Mark a standby `Claimed` (persisted) — so a concurrent launch won't double-claim.
    pub fn mark_claimed(&self, id: &str) -> Result<()> {
        let mut h = self.load(id)?;
        h.state = StandbyState::Claimed;
        self.record(&h)
    }

    /// Return a `Claimed` standby to `Idle` (claimable). The inverse of
    /// [`mark_claimed`](Self::mark_claimed): a launch that reserved a healthy warm
    /// parent but then failed for a reason that is NOT the parent's fault must put
    /// it back in rotation, rather than strand it `Claimed` until the TTL reaper
    /// deletes it — which would shrink warm capacity on every failed claim. A
    /// tampered or un-audited parent is quarantined by [`remove`](Self::remove)
    /// instead; it must never be released back here.
    pub fn mark_idle(&self, id: &str) -> Result<()> {
        let mut h = self.load(id)?;
        h.state = StandbyState::Idle;
        self.record(&h)
    }

    /// Demote a standby that has lost its preloaded child back to saved-only.
    ///
    /// A preloaded child is an optimization layered on the parent's checkpoint:
    /// the record owns a paused VMM *instead of* being saved-only. When a claim
    /// fails, its cleanup destroys that child — but the parent and its
    /// checkpoint are still healthy, so the record must go on advertising the
    /// parent while no longer naming a child that has been killed and whose
    /// state dir is gone.
    ///
    /// Without this the record stayed `Idle` pointing at a destroyed child, so
    /// every later claim against it failed with `Firecracker socket … does not
    /// exist — VM is not running`, while `idle_count_compatible` still counted
    /// it — capacity the pool advertised, could never serve, and which
    /// `warm_to_target` therefore never replaced. Clearing `pid` restores the
    /// `is_saved_state` sentinel so the next claim materializes a fresh child
    /// from the checkpoint instead.
    pub fn demote_to_saved_state(&self, id: &str) -> Result<()> {
        let mut h = self.load(id)?;
        h.preloaded_child_vm_name = None;
        h.control_socket = String::new();
        h.pid = 0;
        self.record(&h)
    }

    /// Remove a standby's dir (after claim/boot, or when reaping a dead one).
    pub fn remove(&self, id: &str) -> Result<()> {
        let dir = self.root.join(id);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("remove {}", dir.display())),
        }
    }

    /// Reap standbys that are dead (pid gone) or expired (`now - spawned > ttl`).
    ///
    /// Saved-state standbys (pid=0) have no running supervisor. An idle saved-state
    /// standby that ages past the warm TTL is demoted to `Parked` rather than removed:
    /// parked standbys remain claimable and are only removed once they age past
    /// `PARKED_TTL_MULTIPLIER × ttl`. Live-supervisor standbys are SIGTERMed before
    /// their dir is removed when they expire while still running.
    pub fn reap_stale(&self, ttl: std::time::Duration, now: u64) -> Result<Vec<String>> {
        let ttl_secs = ttl.as_secs();
        let mut reaped = Vec::new();
        for h in self.list()? {
            let age = now.saturating_sub(h.spawned_unix_secs);
            let expired = age > ttl_secs;
            if h.is_saved_state() {
                let parked_ttl_secs = ttl_secs.saturating_mul(PARKED_TTL_MULTIPLIER);
                match h.state {
                    // Past the extended parked TTL: remove.
                    StandbyState::Parked if age > parked_ttl_secs => {
                        self.remove(&h.id)?;
                        reaped.push(h.id);
                    }
                    // Under the parked TTL: keep — do nothing.
                    StandbyState::Parked => {}
                    // Idle saved-state that aged out: demote to parked, keep it claimable.
                    StandbyState::Idle if expired => {
                        let mut parked = h.clone();
                        parked.state = StandbyState::Parked;
                        self.record(&parked)?;
                    }
                    // Claimed-but-expired (stuck): remove.
                    _ if expired => {
                        self.remove(&h.id)?;
                        reaped.push(h.id);
                    }
                    _ => {}
                }
            } else if h.state == StandbyState::Claimed {
                // A claimed standby's process is the claimed VM, owned by its
                // run. A record its claimer never removed is only stale data.
                if expired || !pid_alive(h.pid) {
                    self.remove(&h.id)?;
                    reaped.push(h.id);
                }
            } else if (!pid_alive(h.pid) || expired)
                && self.release_live(&h, None, Release::Remove)?
            {
                reaped.push(h.id);
            }
        }
        Ok(reaped)
    }

    /// Tear down one standby through the teardown expiry and eviction use. The
    /// entry for any other drain of the pool: it returns `false`, touching
    /// nothing, for a claimed record and for a preloaded child whose lifecycle
    /// gate a launch holds.
    ///
    /// `child_gate` is the preloaded child's gate when the caller holds it.
    pub fn discard(
        &self,
        h: &StandbyHandle,
        child_gate: Option<&MachineLifecycleLock>,
    ) -> Result<bool> {
        self.release_live(h, child_gate, Release::Remove)
    }

    /// Stop a standby's process and remove its record: the one teardown for a
    /// live standby, used by expiry, the memory budget and a released
    /// reservation.
    ///
    /// A preloaded child holds the parent's decrypted memory image in its state
    /// dir, so that dir goes with it, under the child's lifecycle gate. A child
    /// whose gate another launch holds is reserved and left alone (`false`).
    fn release_live(
        &self,
        h: &StandbyHandle,
        held: Option<&MachineLifecycleLock>,
        release: Release,
    ) -> Result<bool> {
        let mut acquired = None;
        let child_gate = match (h.preloaded_child_vm_name.as_deref(), held) {
            (None, _) => None,
            (Some(child), Some(held)) => {
                held.require_name(child)?;
                Some(held)
            }
            (Some(child), None) => match MachineLifecycleLock::try_acquire(child)? {
                Some(lifecycle) => Some(&*acquired.insert(lifecycle)),
                None => return Ok(false),
            },
        };
        if h.state == StandbyState::Claimed {
            return Ok(false);
        }
        let alive = pid_alive(h.pid);
        // A preloaded child's pid is signalled only while the child's own
        // state still names it, so a recycled pid is never reached.
        let verified = child_gate.is_none_or(|gate| child_state_names_pid(gate.name(), h.pid));
        if alive && verified {
            terminate_standby_process(h.pid);
        }
        let Some(gate) = child_gate else {
            self.remove(&h.id)?;
            if !alive {
                reap_dead_standby_runtime(&h.id);
            }
            return Ok(true);
        };
        wait_for_exit(h.pid);
        // A child that did not go away keeps its parent out of rotation.
        if remove_preloaded_child_state(gate.name()) && release == Release::KeepParent {
            self.demote_to_saved_state(&h.id)?;
        } else {
            self.remove(&h.id)?;
        }
        Ok(true)
    }
}

/// What a released standby leaves in the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Release {
    /// Drop the standby entirely.
    Remove,
    /// Drop only its preloaded child; the parent stays claimable saved-state.
    KeepParent,
}

/// Wait, bounded, for a signalled standby process to exit. An earlier
/// invocation started it, so this one holds no child handle or pidfd to wait
/// on; a process still alive after the last poll keeps its state dir, which the
/// orphan sweep removes once the process is gone.
fn wait_for_exit(pid: u32) {
    let mut delay = std::time::Duration::from_millis(10);
    for _ in 0..RELEASE_EXIT_POLLS {
        if !pid_alive(pid) {
            return;
        }
        std::thread::sleep(delay);
        delay = delay.saturating_mul(2);
    }
}

/// Whether the child's state dir carries a live pid marker naming `pid`; a
/// marker that records the process start time must also match it.
fn child_state_names_pid(child: &str, pid: u32) -> bool {
    use mvm_vmm::host::process_liveness::{live_process_pid_file, read_pid_file};
    live_process_pid_file(&mvm_core::config::vm_state_dir(child))
        .and_then(|marker| read_pid_file(&marker))
        .is_some_and(|recorded| i32::try_from(pid) == Ok(recorded))
}

/// Remove a released preloaded child's state dir, plaintext memory image
/// included. The caller holds the child's lifecycle gate. `false` when the dir
/// stays behind.
fn remove_preloaded_child_state(child: &str) -> bool {
    let state_dir = mvm_core::config::vm_state_dir(child);
    match crate::vm::reconcile::reap_unowned_state_dir_locked(&state_dir) {
        Ok(true) => true,
        Ok(false) => {
            tracing::warn!(
                child,
                "preloaded child still running after release; the orphan sweep removes its state"
            );
            false
        }
        Err(error) => {
            tracing::warn!(%error, child, "removing a released preloaded child failed");
            false
        }
    }
}

/// Ask a standby's process to stop. For a standby whose pool record is gone,
/// so the usual remove-and-reap path cannot reach it.
pub fn terminate_standby_process(pid: u32) {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return;
    };
    if pid <= 1 {
        return;
    }
    // SAFETY: SIGTERM to a pid the pool recorded as a standby this host
    // started; a pid that has since exited makes this a no-op.
    unsafe { libc::kill(pid, libc::SIGTERM) };
}

/// Collect the exit of a standby supervisor this process spawned. A pid that
/// is not this process's child, or was already collected, is a no-op.
pub fn reap_standby_child(pid: u32) {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return;
    };
    // SAFETY: waitpid with WNOHANG and a null status pointer only collects the
    // exit of a child of this process.
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
}

/// Whether `pid` names a running process. An exited supervisor its parent has
/// not yet reaped is a zombie, which still answers `kill(pid, 0)`, so this
/// asks the shared liveness probe that treats a zombie as gone.
fn pid_alive(pid: u32) -> bool {
    i32::try_from(pid).is_ok_and(mvm_vmm::host::process_liveness::pid_is_alive)
}

/// Remove the runtime state a dead standby's supervisor left behind. The pool
/// record was the only owner keeping the sweep away from it, and the record is
/// gone by now. Best-effort: a state directory something else still holds is
/// left for the next sweep.
fn reap_dead_standby_runtime(id: &str) {
    let state_dir = mvm_core::config::vm_state_dir(id);
    let instance_dir = mvm_core::config::instance_dir(id);
    if let Err(error) = crate::vm::reconcile::reap_unowned_state_dir(&state_dir, &instance_dir) {
        tracing::debug!(%error, standby = id, "removing a dead standby's state directory failed");
    }
}

fn set_mode_0700(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", p.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::vm_backend::{StandbyCompat, StandbyHandle, StandbyState};

    #[test]
    fn selected_load_distinguishes_removed_from_malformed_records() {
        let tmp = tempfile::tempdir().expect("pool");
        let pool = SupervisorStandbyPool::at(tmp.path());
        assert!(
            pool.load_selected("winner-removed")
                .expect("confirmed absence")
                .is_none()
        );

        let malformed_dir = tmp.path().join("malformed");
        std::fs::create_dir_all(&malformed_dir).expect("malformed record dir");
        std::fs::write(malformed_dir.join(HANDLE_FILE), b"{not json").expect("malformed record");
        let error = pool
            .load_selected("malformed")
            .expect_err("malformed record is not reservation loss");
        assert!(
            error.to_string().contains("key must be a string"),
            "{error:#}"
        );
    }

    #[test]
    fn standby_pool_ttl_exceeds_always_warm_idle_window() {
        // The on-use reaper (launch path + `cache prune`) must not evict a
        // freshly-warmed spare before its next claim, so the reap TTL has to sit
        // above the always-warm idle window. If the residency idle window grows
        // past this, the launch reaper would churn the very spare it warms.
        let warm_idle = mvm_core::residency::ResidencyPolicy::always_warm()
            .idle_timeout()
            .expect("always-warm has an idle timeout");
        assert!(
            STANDBY_POOL_TTL > warm_idle,
            "STANDBY_POOL_TTL {STANDBY_POOL_TTL:?} must exceed always-warm idle {warm_idle:?}"
        );
    }

    fn handle(id: &str, kernel: &str, state: StandbyState) -> StandbyHandle {
        StandbyHandle {
            id: id.into(),
            template_id: None,
            control_socket: format!("/p/{id}/control.sock"),
            pid: std::process::id(), // a live pid so liveness passes
            kernel_sha256: kernel.into(),
            vcpus: 2,
            mem_mib: 1024,
            binding_nonce: "ab".repeat(32),
            spawned_unix_secs: 1,
            state,
            image_sha256: None,
            root_strategy: Default::default(),
            parent_checkpoint: None,
            preloaded_child_vm_name: None,
            vsock_egress: false,
        }
    }

    /// A fully populated `StandbyHandle` for tests that don't care about the
    /// specific compat/state fields, just a valid handle to round-trip.
    fn sample_handle(id: &str) -> StandbyHandle {
        StandbyHandle {
            id: id.into(),
            template_id: None,
            control_socket: format!("/p/{id}/control.sock"),
            pid: std::process::id(),
            kernel_sha256: "aa".repeat(32),
            vcpus: 2,
            mem_mib: 1024,
            binding_nonce: "ab".repeat(32),
            spawned_unix_secs: 1,
            state: StandbyState::Idle,
            image_sha256: None,
            root_strategy: Default::default(),
            parent_checkpoint: None,
            preloaded_child_vm_name: None,
            vsock_egress: false,
        }
    }

    fn compat(kernel: &str) -> StandbyCompat {
        StandbyCompat {
            template_id: None,
            kernel_sha256: kernel.into(),
            vcpus: 2,
            mem_mib: 1024,
            image_sha256: None,
            root_strategy: Default::default(),
            vsock_egress: false,
        }
    }

    #[test]
    fn record_then_load_roundtrips_under_pool_root() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&handle("s1", "aa", StandbyState::Idle))
            .unwrap();
        let loaded = pool.load("s1").unwrap();
        assert_eq!(loaded.id, "s1");
        assert_eq!(loaded.state, StandbyState::Idle);
    }

    #[test]
    fn select_idle_matches_kernel_and_skips_claimed_and_dead() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&handle("claimed", "aa", StandbyState::Claimed))
            .unwrap();
        let mut dead = handle("dead", "aa", StandbyState::Idle);
        dead.pid = 999_999; // not a live pid
        pool.record(&dead).unwrap();
        pool.record(&handle("good", "aa", StandbyState::Idle))
            .unwrap();
        pool.record(&handle("wrong-kernel", "bb", StandbyState::Idle))
            .unwrap();

        let picked = pool.select_idle_compatible(&compat("aa")).unwrap();
        assert_eq!(picked.unwrap().id, "good");
        assert!(
            pool.select_idle_compatible(&compat("cc"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn select_idle_skips_resource_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mut big = handle("big", "aa", StandbyState::Idle);
        big.vcpus = 8; // same kernel, different cpus → not compatible
        pool.record(&big).unwrap();
        assert!(
            pool.select_idle_compatible(&compat("aa"))
                .unwrap()
                .is_none()
        );
    }

    /// A restored child inherits its guest's egress enablement from the parent's
    /// saved memory, so the pool partitions on it: neither enablement may be
    /// served by a parent of the other, and the replenish counts them separately
    /// so each half fills its own set.
    #[test]
    fn egress_enablement_partitions_the_pool_in_both_directions() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let deny_key = compat("aa");
        let egress_key = StandbyCompat {
            vsock_egress: true,
            ..deny_key.clone()
        };

        pool.record(&handle("no-egress-parent", "aa", StandbyState::Idle))
            .unwrap();
        assert!(
            pool.select_idle_compatible(&egress_key).unwrap().is_none(),
            "a parent that booted no egress client must not serve a launch needing one"
        );
        assert_eq!(pool.idle_count_compatible(&egress_key).unwrap(), 0);
        assert_eq!(pool.idle_count_compatible(&deny_key).unwrap(), 1);

        let mut egress_parent = handle("egress-parent", "aa", StandbyState::Idle);
        egress_parent.vsock_egress = true;
        pool.record(&egress_parent).unwrap();
        assert_eq!(
            pool.select_idle_compatible(&egress_key)
                .unwrap()
                .map(|h| h.id),
            Some("egress-parent".to_string())
        );
        assert_eq!(
            pool.select_idle_compatible(&deny_key)
                .unwrap()
                .map(|h| h.id),
            Some("no-egress-parent".to_string()),
            "and the egress parent must not be handed to the deny-all launch either"
        );
        assert_eq!(pool.idle_count_compatible(&egress_key).unwrap(), 1);
        assert_eq!(pool.idle_count_compatible(&deny_key).unwrap(), 1);
    }

    #[test]
    fn atomic_claim_reserves_a_parent_before_returning_it() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let want = compat("aa");
        pool.record(&handle("parent", "aa", StandbyState::Idle))
            .unwrap();

        let claimed = pool
            .claim_idle_compatible(&want)
            .unwrap()
            .expect("compatible parent");
        assert_eq!(claimed.id, "parent");
        assert_eq!(claimed.state, StandbyState::Claimed);
        assert_eq!(pool.load("parent").unwrap().state, StandbyState::Claimed);
        assert!(
            pool.claim_idle_compatible(&want).unwrap().is_none(),
            "a reserved parent must not be claimable twice"
        );
    }

    #[test]
    fn template_bound_parent_never_matches_a_different_template() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mut parent = handle("template-parent", "aa", StandbyState::Idle);
        parent.template_id = Some("template-a".into());
        pool.record(&parent).unwrap();

        let mut wrong_template = compat("aa");
        wrong_template.template_id = Some("template-b".into());
        assert!(
            pool.select_idle_compatible(&wrong_template)
                .unwrap()
                .is_none(),
            "warm parents must not cross template identities"
        );
    }

    #[test]
    fn memory_budget_evicts_oldest_parent_within_one_template() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mut old = saved_handle("old", "aa", "img", StandbyState::Idle);
        old.template_id = Some("template-a".into());
        old.spawned_unix_secs = 1;
        let mut recent = saved_handle("recent", "aa", "img", StandbyState::Parked);
        recent.template_id = Some("template-a".into());
        recent.spawned_unix_secs = 2;
        let mut other = saved_handle("other", "aa", "img", StandbyState::Idle);
        other.template_id = Some("template-b".into());
        pool.record(&old).unwrap();
        pool.record(&recent).unwrap();
        pool.record(&other).unwrap();

        let evicted = pool
            .evict_to_memory_budget(Some("template-a"), 1024)
            .unwrap();
        assert_eq!(evicted, vec!["old"]);
        assert!(pool.load("recent").is_ok());
        assert!(pool.load("other").is_ok());
    }

    #[test]
    fn memory_budget_never_evicts_claimed_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mut claimed = saved_handle("claimed", "aa", "img", StandbyState::Claimed);
        claimed.template_id = Some("template-a".into());
        pool.record(&claimed).unwrap();

        assert!(
            pool.evict_to_memory_budget(Some("template-a"), 0)
                .unwrap()
                .is_empty()
        );
        assert_eq!(pool.load("claimed").unwrap().state, StandbyState::Claimed);
    }

    #[test]
    fn a_shape_budget_never_evicts_another_images_standby() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mut a_old = saved_handle("a-old", "aa", "image-a", StandbyState::Idle);
        a_old.spawned_unix_secs = 1;
        let mut a_new = saved_handle("a-new", "aa", "image-a", StandbyState::Idle);
        a_new.spawned_unix_secs = 2;
        let mut b = saved_handle("b", "aa", "image-b", StandbyState::Idle);
        b.spawned_unix_secs = 0;
        for h in [&a_old, &a_new, &b] {
            pool.record(h).unwrap();
        }

        let evicted = pool
            .evict_compatible_to_memory_budget(&a_new.compat(), 1024)
            .unwrap();
        assert_eq!(evicted, vec!["a-old"]);
        assert!(
            pool.load("b").is_ok(),
            "every OCI image shares the None template; a sweep for one must not evict another"
        );
    }

    /// A live standby whose pid is a real child this test owns, so an
    /// eviction's SIGTERM lands on it rather than on the test process.
    fn live_handle(id: &str, child: &std::process::Child, spawned: u64) -> StandbyHandle {
        let mut h = handle(id, "aa", StandbyState::Idle);
        h.pid = child.id();
        h.spawned_unix_secs = spawned;
        h
    }

    fn sleeper() -> std::process::Child {
        std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawning a stand-in standby process")
    }

    #[test]
    fn the_total_budget_evicts_the_oldest_live_standbys_of_any_shape() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mut oldest = sleeper();
        let mut newer = sleeper();
        let mut newest_child = sleeper();
        pool.record(&live_handle("oldest", &oldest, 1)).unwrap();
        pool.record(&live_handle("newer", &newer, 2)).unwrap();
        let mut newest = live_handle("newest", &newest_child, 3);
        newest.image_sha256 = Some("another-image".into());
        pool.record(&newest).unwrap();
        // A snapshot on disk holds no guest memory and is not counted.
        pool.record(&saved_handle("saved", "aa", "img", StandbyState::Idle))
            .unwrap();
        assert_eq!(pool.idle_live_memory_mib().unwrap(), 3 * 1024);

        let evicted = pool.evict_to_total_memory(1024).unwrap();
        assert_eq!(evicted, vec!["oldest", "newer"]);
        assert_eq!(pool.idle_live_memory_mib().unwrap(), 1024);
        assert!(pool.load("saved").is_ok());
        // The evicted standbys' processes were told to stop.
        for child in [&mut oldest, &mut newer] {
            let status = child.wait().expect("waiting for the evicted stand-in");
            assert!(!status.success());
        }
        let _ = newest_child.kill();
        let _ = newest_child.wait();
    }

    #[test]
    fn remove_deletes_the_standby_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&handle("s1", "aa", StandbyState::Idle))
            .unwrap();
        assert!(tmp.path().join("s1").exists());
        pool.remove("s1").unwrap();
        assert!(!tmp.path().join("s1").exists());
    }

    #[test]
    fn mark_idle_returns_a_claimed_standby_to_claimable() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&handle("s1", "aa", StandbyState::Idle))
            .unwrap();
        pool.mark_claimed("s1").unwrap();
        assert_eq!(pool.load("s1").unwrap().state, StandbyState::Claimed);
        // A failed claim that is not the parent's fault releases it back to Idle,
        // so a later launch can claim it again instead of losing warm capacity.
        pool.mark_idle("s1").unwrap();
        let released = pool.load("s1").unwrap();
        assert_eq!(released.state, StandbyState::Idle);
        assert!(released.state.is_claimable());
    }

    #[test]
    fn reap_removes_dead_and_expired_keeps_live_recent() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let now = mvm_core::time::now_unix_secs();
        // Live + recent (spawned now) → kept.
        let mut keep = handle("keep", "aa", StandbyState::Idle);
        keep.spawned_unix_secs = now;
        pool.record(&keep).unwrap();
        // Dead pid → reaped regardless of age.
        let mut dead = handle("dead", "aa", StandbyState::Idle);
        dead.pid = 999_999;
        dead.spawned_unix_secs = now;
        pool.record(&dead).unwrap();
        // Live but spawned long ago → expired → reaped (SIGTERM'd then removed). Use a
        // real throwaway child so the reaper's SIGTERM hits a safe pid, not the test runner.
        let mut sleeper = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let mut old = handle("old", "aa", StandbyState::Idle);
        old.pid = sleeper.id();
        old.spawned_unix_secs = 1;
        pool.record(&old).unwrap();

        let reaped = pool
            .reap_stale(std::time::Duration::from_secs(3600), now)
            .unwrap();
        assert!(reaped.contains(&"dead".to_string()));
        assert!(reaped.contains(&"old".to_string()));
        assert!(!reaped.contains(&"keep".to_string()));
        assert!(pool.load("keep").is_ok());
        assert!(pool.load("dead").is_err());
        assert!(pool.load("old").is_err());
        // The live-expired standby's supervisor was SIGTERM'd.
        let _ = sleeper.wait();
    }

    /// A child that has exited and not been waited on: a zombie.
    fn zombie_child() -> std::process::Child {
        let child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        wait_until_exited(pid);
        child
    }

    /// Block until `pid` has exited, without reaping it.
    fn wait_until_exited(pid: u32) {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: waitid with WNOWAIT only observes the child's exit and
        // leaves it unreaped; `info` is a valid out-pointer.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        assert_eq!(rc, 0, "waiting for the stand-in to exit");
    }

    #[test]
    fn a_zombie_supervisor_is_not_alive() {
        let mut child = zombie_child();
        assert!(!pid_alive(child.id()));
        assert!(pid_alive(std::process::id()));
        child.wait().unwrap();
    }

    #[test]
    fn a_zombie_standby_is_dead_and_its_record_and_state_dir_are_reaped() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mut child = zombie_child();
        let mut stopped = handle("standby-stopped", "aa", StandbyState::Idle);
        stopped.pid = child.id();
        stopped.spawned_unix_secs = mvm_core::time::now_unix_secs();
        pool.record(&stopped).unwrap();
        let state_dir = mvm_core::config::vm_state_dir("standby-stopped");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(state_dir.join("snapshot.ram"), b"ram").unwrap();
        std::fs::write(state_dir.join("hvf.pid"), child.id().to_string()).unwrap();

        let loaded = pool.load("standby-stopped").unwrap();
        assert!(!SupervisorStandbyPool::is_live_or_saved(&loaded));
        assert_eq!(pool.idle_count_compatible(&compat("aa")).unwrap(), 0);

        let reaped = pool
            .reap_stale(
                std::time::Duration::from_secs(3600),
                stopped.spawned_unix_secs,
            )
            .unwrap();
        assert_eq!(reaped, vec!["standby-stopped".to_string()]);
        assert!(pool.load("standby-stopped").is_err(), "no idle record");
        assert!(!state_dir.exists(), "no state directory");
        child.wait().unwrap();
    }

    #[test]
    fn idle_count_for_kernel_counts_only_live_idle_matches() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&handle("a", "aa", StandbyState::Idle)).unwrap();
        pool.record(&handle("b", "aa", StandbyState::Claimed))
            .unwrap();
        assert_eq!(pool.idle_count_compatible(&compat("aa")).unwrap(), 1);
    }

    #[test]
    fn is_live_or_saved_distinguishes_dead_processes_from_saved_state() {
        let live = handle("live", "aa", StandbyState::Idle);
        assert!(SupervisorStandbyPool::is_live_or_saved(&live));

        let mut dead = handle("dead", "aa", StandbyState::Idle);
        dead.pid = 999_999;
        assert!(!SupervisorStandbyPool::is_live_or_saved(&dead));

        let saved = saved_handle("saved", "aa", "img", StandbyState::Idle);
        assert!(SupervisorStandbyPool::is_live_or_saved(&saved));
    }

    // ── saved-state standby tests (HVF) ──────────────────────────────────────────

    fn saved_handle(id: &str, kernel: &str, image: &str, state: StandbyState) -> StandbyHandle {
        StandbyHandle {
            id: id.into(),
            template_id: None,
            control_socket: format!("/p/{id}/control.sock"),
            pid: 0, // no live supervisor for saved-state standbys
            kernel_sha256: kernel.into(),
            vcpus: 2,
            mem_mib: 1024,
            binding_nonce: "ab".repeat(32),
            spawned_unix_secs: 1,
            state,
            image_sha256: Some(image.into()),
            root_strategy: Default::default(),
            parent_checkpoint: None,
            preloaded_child_vm_name: None,
            vsock_egress: false,
        }
    }

    fn hvf_compat(kernel: &str, image: &str) -> StandbyCompat {
        StandbyCompat {
            template_id: None,
            kernel_sha256: kernel.into(),
            vcpus: 2,
            mem_mib: 1024,
            image_sha256: Some(image.into()),
            root_strategy: Default::default(),
            vsock_egress: false,
        }
    }

    /// A saved-state standby (pid=0) is selected despite having no live process.
    #[test]
    fn select_idle_finds_saved_state_standby_without_live_pid() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&saved_handle("hvf1", "kk", "img-aa", StandbyState::Idle))
            .unwrap();
        let picked = pool
            .select_idle_compatible(&hvf_compat("kk", "img-aa"))
            .unwrap();
        assert_eq!(picked.unwrap().id, "hvf1");
    }

    /// Image sha must match exactly — wrong image returns None.
    #[test]
    fn select_idle_rejects_saved_standby_on_image_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&saved_handle("hvf1", "kk", "img-aa", StandbyState::Idle))
            .unwrap();
        // libkrun compat (None) does not match an HVF standby (Some).
        assert!(
            pool.select_idle_compatible(&compat("kk"))
                .unwrap()
                .is_none()
        );
        // Different image sha also misses.
        assert!(
            pool.select_idle_compatible(&hvf_compat("kk", "img-bb"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn reap_demotes_idle_saved_state_expired_to_parked_not_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let now = 1_000_000u64;
        // Idle saved-state (pid=0), expired by the warm ttl.
        let mut h = saved_handle("hvf1", "aa", "img", StandbyState::Idle);
        h.spawned_unix_secs = now - 7_200; // 2h old
        pool.record(&h).unwrap();

        let reaped = pool
            .reap_stale(std::time::Duration::from_secs(3_600), now)
            .unwrap();

        assert!(!reaped.contains(&"hvf1".to_string()), "demoted, not reaped");
        assert_eq!(pool.load("hvf1").unwrap().state, StandbyState::Parked);
    }

    #[test]
    fn reap_keeps_parked_under_parked_ttl_and_removes_over_it() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let now = 1_000_000u64;
        let ttl = std::time::Duration::from_secs(3_600);

        let mut young = saved_handle("p_young", "aa", "img", StandbyState::Parked);
        young.spawned_unix_secs = now - 4 * 3_600; // older than warm ttl, under parked ttl
        pool.record(&young).unwrap();

        let mut old = saved_handle("p_old", "aa", "img", StandbyState::Parked);
        old.spawned_unix_secs = now - 100 * 3_600; // well past parked ttl
        pool.record(&old).unwrap();

        let reaped = pool.reap_stale(ttl, now).unwrap();

        assert!(
            !reaped.contains(&"p_young".to_string()),
            "young parked kept"
        );
        assert!(reaped.contains(&"p_old".to_string()), "old parked removed");
        assert_eq!(pool.load("p_young").unwrap().state, StandbyState::Parked);
    }

    #[test]
    fn reap_still_removes_live_pid_expired_standby() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let now = 1_000_000u64;
        // Live-pid standby (pid!=0, dead pid) expired — libkrun stays reap-to-cold.
        let mut h = handle("lk1", "aa", StandbyState::Idle);
        h.pid = 999_999; // not alive
        h.spawned_unix_secs = now - 7_200;
        pool.record(&h).unwrap();

        let reaped = pool
            .reap_stale(std::time::Duration::from_secs(3_600), now)
            .unwrap();
        assert!(reaped.contains(&"lk1".to_string()));
        assert!(pool.load("lk1").is_err(), "removed");
    }

    /// A recent saved standby (pid=0) is kept idle; an expired idle one is demoted to
    /// Parked (not removed) on the first reap pass.
    #[test]
    fn select_claims_compatible_parked_saved_state_standby() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let want = hvf_compat("aa", "img");
        let parked = saved_handle("vzp", "aa", "img", StandbyState::Parked);
        pool.record(&parked).unwrap();

        let got = pool.select_idle_compatible(&want).unwrap();
        assert_eq!(got.map(|h| h.id), Some("vzp".to_string()));
    }

    #[test]
    fn reap_keeps_recent_saved_standby_and_demotes_expired_one() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let now = mvm_core::time::now_unix_secs();

        let mut recent = saved_handle("hvf-keep", "kk", "img", StandbyState::Idle);
        recent.spawned_unix_secs = now;
        pool.record(&recent).unwrap();

        let mut old = saved_handle("hvf-old", "kk", "img", StandbyState::Idle);
        old.spawned_unix_secs = 1; // ancient — past warm TTL, demoted to Parked
        pool.record(&old).unwrap();

        let reaped = pool
            .reap_stale(std::time::Duration::from_secs(3600), now)
            .unwrap();

        assert!(!reaped.contains(&"hvf-keep".to_string()));
        assert!(
            !reaped.contains(&"hvf-old".to_string()),
            "demoted, not reaped"
        );
        assert!(pool.load("hvf-keep").is_ok());
        assert_eq!(pool.load("hvf-old").unwrap().state, StandbyState::Parked);
    }

    #[test]
    fn reap_keeps_parked_at_exact_parked_ttl_boundary() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let now = 1_000_000u64;
        let ttl_secs = 3_600u64;
        let mut h = saved_handle("p_edge", "aa", "img", StandbyState::Parked);
        h.spawned_unix_secs = now - ttl_secs * 6; // exactly 6×ttl
        pool.record(&h).unwrap();
        let reaped = pool
            .reap_stale(std::time::Duration::from_secs(ttl_secs), now)
            .unwrap();
        assert!(
            !reaped.contains(&"p_edge".to_string()),
            "exact boundary kept (strict >)"
        );
        assert_eq!(pool.load("p_edge").unwrap().state, StandbyState::Parked);
    }

    #[test]
    fn record_and_load_round_trip_parent_checkpoint() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mut h = sample_handle("sb-parent-ckpt");
        h.parent_checkpoint = Some("standby-sb-parent-ckpt".to_string());

        pool.record(&h).unwrap();
        let loaded = pool.load("sb-parent-ckpt").unwrap();

        assert_eq!(
            loaded.parent_checkpoint.as_deref(),
            Some("standby-sb-parent-ckpt"),
            "the captured parent checkpoint must survive the pool's on-disk round trip"
        );
    }

    /// A handle written before this field existed still loads, defaulting to
    /// `None` — an uncaptured parent is simply not claimable.
    #[test]
    fn handle_without_parent_checkpoint_loads_as_none() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let dir = tmp.path().join("sb-legacy");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("standby.json"),
            br#"{"id":"sb-legacy","control_socket":"/tmp/s.sock","pid":0,
                 "kernel_sha256":"abc","vcpus":2,"mem_mib":512,"binding_nonce":"n",
                 "spawned_unix_secs":1,"state":"idle"}"#,
        )
        .unwrap();

        let loaded = pool.load("sb-legacy").unwrap();

        assert_eq!(loaded.parent_checkpoint, None);
    }

    /// A preloaded standby: a live paused child process recorded on the
    /// parent, whose plaintext memory image sits in the child's state dir.
    fn preloaded_handle(
        id: &str,
        child_vm: &str,
        process: &std::process::Child,
        spawned: u64,
    ) -> StandbyHandle {
        let mut h = live_handle(id, process, spawned);
        h.preloaded_child_vm_name = Some(child_vm.into());
        let state = mvm_core::config::vm_state_dir(child_vm);
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("mem.bin"), b"plaintext guest memory").unwrap();
        std::fs::write(state.join(PRELOADED_CHILD_RESERVATION_FILE), id).unwrap();
        std::fs::write(state.join("fc.pid"), process.id().to_string()).unwrap();
        h
    }

    /// A stand-in paused VMM that ignores SIGTERM, so a release cannot see it
    /// exit inside its bounded wait.
    fn stubborn() -> std::process::Child {
        let child = std::process::Command::new("sh")
            .args(["-c", "trap '' TERM; while :; do sleep 1; done"])
            .spawn()
            .expect("spawning a stand-in that ignores SIGTERM");
        // The trap must be installed before the release signals it.
        std::thread::sleep(std::time::Duration::from_millis(100));
        child
    }

    fn isolated_home() -> (mvm_core::util::test_env::TestEnv, tempfile::TempDir) {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        (env, home)
    }

    #[test]
    fn ordinary_selection_never_takes_a_preloaded_standby() {
        let (_env, _home) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mut process = sleeper();
        pool.record(&preloaded_handle("pre", "child-pre-a", &process, 1))
            .unwrap();

        assert!(
            pool.select_idle_compatible(&compat("aa"))
                .unwrap()
                .is_none()
        );
        assert!(pool.claim_idle_compatible(&compat("aa")).unwrap().is_none());

        let _ = process.kill();
        let _ = process.wait();
    }

    #[test]
    fn a_preloaded_reservation_holds_the_childs_lifecycle_gate_until_dropped() {
        let (_env, _home) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mut process = sleeper();
        pool.record(&preloaded_handle("pre", "child-pre-b", &process, 1))
            .unwrap();

        let (handle, lifecycle) = pool
            .reserve_preloaded_compatible(&compat("aa"))
            .unwrap()
            .expect("an idle preloaded standby is reserved");
        assert_eq!(handle.id, "pre");
        assert_eq!(lifecycle.name(), "child-pre-b");
        assert!(
            pool.reserve_preloaded_compatible(&compat("aa"))
                .unwrap()
                .is_none(),
            "a second launcher cannot reserve the same child"
        );
        assert!(
            pool.reserve_preloaded_compatible(&compat("bb"))
                .unwrap()
                .is_none(),
            "an incompatible standby is never reserved"
        );
        drop(lifecycle);
        assert!(
            pool.reserve_preloaded_compatible(&compat("aa"))
                .unwrap()
                .is_some()
        );

        let _ = process.kill();
        let _ = process.wait();
    }

    #[test]
    fn expiry_stops_a_preloaded_child_and_removes_its_memory_image() {
        let (_env, _home) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mut process = sleeper();
        pool.record(&preloaded_handle("pre", "child-pre-c", &process, 1))
            .unwrap();
        let child_state = mvm_core::config::vm_state_dir("child-pre-c");

        let reaped = pool
            .reap_stale(std::time::Duration::from_secs(60), 10_000)
            .unwrap();

        assert_eq!(reaped, vec!["pre".to_string()]);
        assert!(!process.wait().unwrap().success(), "paused child stopped");
        assert!(!child_state.exists(), "plaintext mem.bin removed with it");
    }

    #[test]
    fn expiry_skips_a_preloaded_standby_a_launch_has_reserved() {
        let (_env, _home) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mut process = sleeper();
        pool.record(&preloaded_handle("pre", "child-pre-d", &process, 1))
            .unwrap();
        let held =
            crate::vm::instance_snapshot::MachineLifecycleLock::acquire("child-pre-d").unwrap();

        let reaped = pool
            .reap_stale(std::time::Duration::from_secs(60), 10_000)
            .unwrap();

        assert!(reaped.is_empty(), "a reserved child is not torn down");
        assert!(pool.load("pre").is_ok());
        drop(held);
        let _ = process.kill();
        let _ = process.wait();
    }

    /// A claim marks the record `Claimed` and the claimer removes it once the
    /// child runs. A launcher that dies first leaves the record behind; the
    /// child it names is now someone's running VM and must not be signalled
    /// or have its state removed — only the stale record goes.
    #[test]
    fn expiry_never_stops_a_claimed_child_whose_record_outlived_its_claimer() {
        let (_env, _home) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mut process = sleeper();
        let mut claimed = preloaded_handle("pre", "child-pre-g", &process, 1);
        claimed.state = StandbyState::Claimed;
        pool.record(&claimed).unwrap();

        let reaped = pool
            .reap_stale(std::time::Duration::from_secs(60), 10_000)
            .unwrap();

        assert_eq!(reaped, vec!["pre".to_string()], "the stale record goes");
        assert!(pool.load("pre").is_err());
        assert!(
            process.try_wait().unwrap().is_none(),
            "the running child is untouched"
        );
        assert!(
            mvm_core::config::vm_state_dir("child-pre-g")
                .join("mem.bin")
                .exists()
        );
        let _ = process.kill();
        let _ = process.wait();
    }

    /// The record's pid is trusted only when the child's own state names it:
    /// a recycled or mismatched pid is never signalled.
    #[test]
    fn a_record_pid_the_childs_state_does_not_name_is_never_signalled() {
        let (_env, _home) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mut recorded = sleeper();
        let mut actual = sleeper();
        pool.record(&preloaded_handle("pre", "child-pre-h", &recorded, 1))
            .unwrap();
        let state = mvm_core::config::vm_state_dir("child-pre-h");
        std::fs::write(state.join("fc.pid"), actual.id().to_string()).unwrap();

        pool.reap_stale(std::time::Duration::from_secs(60), 10_000)
            .unwrap();

        assert!(
            recorded.try_wait().unwrap().is_none(),
            "unverified pid not signalled"
        );
        assert!(
            state.join("mem.bin").exists(),
            "a live child keeps its state"
        );
        for process in [&mut recorded, &mut actual] {
            let _ = process.kill();
            let _ = process.wait();
        }
    }

    /// A child that outlives the bounded wait keeps its state dir for the
    /// orphan sweep, and its parent leaves the pool rather than advertising a
    /// saved-state parent beside a live child.
    #[test]
    fn a_child_still_alive_after_release_keeps_its_state_and_drops_its_parent() {
        let (_env, _home) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mut process = stubborn();
        pool.record(&preloaded_handle("pre", "child-pre-i", &process, 1))
            .unwrap();
        let (handle, lifecycle) = pool
            .reserve_preloaded_compatible(&compat("aa"))
            .unwrap()
            .unwrap();

        pool.release_reserved_preload(&handle, &lifecycle).unwrap();

        assert!(
            process.try_wait().unwrap().is_none(),
            "the stand-in survived"
        );
        assert!(mvm_core::config::vm_state_dir("child-pre-i").exists());
        assert!(
            pool.load("pre").is_err(),
            "no saved-state parent beside a live child"
        );
        let _ = process.kill();
        let _ = process.wait();
    }

    #[test]
    fn budget_eviction_removes_a_preloaded_childs_memory_image() {
        let (_env, _home) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mut process = sleeper();
        pool.record(&preloaded_handle("pre", "child-pre-e", &process, 1))
            .unwrap();

        assert_eq!(pool.evict_to_total_memory(0).unwrap(), vec!["pre"]);

        assert!(!process.wait().unwrap().success());
        assert!(!mvm_core::config::vm_state_dir("child-pre-e").exists());
    }

    #[test]
    fn a_released_reservation_keeps_its_parent_as_saved_state() {
        let (_env, _home) = isolated_home();
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mut process = sleeper();
        pool.record(&preloaded_handle("pre", "child-pre-f", &process, 1))
            .unwrap();
        let (handle, lifecycle) = pool
            .reserve_preloaded_compatible(&compat("aa"))
            .unwrap()
            .unwrap();

        pool.release_reserved_preload(&handle, &lifecycle).unwrap();

        assert!(!process.wait().unwrap().success());
        assert!(!mvm_core::config::vm_state_dir("child-pre-f").exists());
        let kept = pool.load("pre").expect("the parent stays in the pool");
        assert_eq!(kept.preloaded_child_vm_name, None);
        assert!(kept.is_saved_state(), "the parent is saved-state again");
        assert!(
            pool.select_idle_compatible(&compat("aa"))
                .unwrap()
                .is_some(),
            "a launch can now fork from it"
        );
        // A second release of an already demoted record is a no-op.
        pool.release_reserved_preload(&handle, &lifecycle).unwrap();
    }
}
