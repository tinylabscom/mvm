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

/// Filename of the per-standby metadata JSON inside its dir.
const HANDLE_FILE: &str = "standby.json";

/// A parked standby is a low-cost saved-state snapshot; it may outlive the warm
/// TTL by this factor before the reaper finally removes it.
const PARKED_TTL_MULTIPLIER: u64 = 6;

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
    pub fn select_idle_compatible(&self, want: &StandbyCompat) -> Result<Option<StandbyHandle>> {
        Ok(self
            .list()?
            .into_iter()
            .find(|h| h.state.is_claimable() && h.is_compatible(want) && Self::is_live_or_saved(h)))
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

    /// Mark a standby `Claimed` (persisted) — so a concurrent launch won't double-claim.
    pub fn mark_claimed(&self, id: &str) -> Result<()> {
        let mut h = self.load(id)?;
        h.state = StandbyState::Claimed;
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
            } else {
                let alive = pid_alive(h.pid);
                if !alive || expired {
                    if alive {
                        // Live but expired — SIGTERM before removing state.
                        // SAFETY: SIGTERM to a pid this host spawned; a stale pid is a no-op.
                        unsafe { libc::kill(h.pid as libc::pid_t, libc::SIGTERM) };
                    }
                    self.remove(&h.id)?;
                    reaped.push(h.id);
                }
            }
        }
        Ok(reaped)
    }
}

/// Seconds since the Unix epoch (best-effort; clamps a pre-epoch clock to 0). The reaper's
/// `now` argument so callers can inject a fixed clock in tests.
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `kill(pid, 0)` liveness — 0 ⇒ the process exists.
fn pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
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

    fn handle(id: &str, kernel: &str, state: StandbyState) -> StandbyHandle {
        StandbyHandle {
            id: id.into(),
            control_socket: format!("/p/{id}/control.sock").into(),
            pid: std::process::id(), // a live pid so liveness passes
            kernel_sha256: kernel.into(),
            vcpus: 2,
            mem_mib: 1024,
            binding_nonce: "ab".repeat(32),
            spawned_unix_secs: 1,
            state,
            image_sha256: None,
        }
    }

    fn compat(kernel: &str) -> StandbyCompat {
        StandbyCompat {
            kernel_sha256: kernel.into(),
            vcpus: 2,
            mem_mib: 1024,
            image_sha256: None,
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
    fn reap_removes_dead_and_expired_keeps_live_recent() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let now = now_unix_secs();
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

    // ── saved-state standby tests (Vz) ───────────────────────────────────────────

    fn saved_handle(id: &str, kernel: &str, image: &str, state: StandbyState) -> StandbyHandle {
        StandbyHandle {
            id: id.into(),
            control_socket: format!("/p/{id}/control.sock").into(),
            pid: 0, // no live supervisor for saved-state standbys
            kernel_sha256: kernel.into(),
            vcpus: 2,
            mem_mib: 1024,
            binding_nonce: "ab".repeat(32),
            spawned_unix_secs: 1,
            state,
            image_sha256: Some(image.into()),
        }
    }

    fn vz_compat(kernel: &str, image: &str) -> StandbyCompat {
        StandbyCompat {
            kernel_sha256: kernel.into(),
            vcpus: 2,
            mem_mib: 1024,
            image_sha256: Some(image.into()),
        }
    }

    /// A saved-state standby (pid=0) is selected despite having no live process.
    #[test]
    fn select_idle_finds_saved_state_standby_without_live_pid() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&saved_handle("vz1", "kk", "img-aa", StandbyState::Idle))
            .unwrap();
        let picked = pool
            .select_idle_compatible(&vz_compat("kk", "img-aa"))
            .unwrap();
        assert_eq!(picked.unwrap().id, "vz1");
    }

    /// Image sha must match exactly — wrong image returns None.
    #[test]
    fn select_idle_rejects_saved_standby_on_image_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&saved_handle("vz1", "kk", "img-aa", StandbyState::Idle))
            .unwrap();
        // libkrun compat (None) does not match a Vz standby (Some).
        assert!(
            pool.select_idle_compatible(&compat("kk"))
                .unwrap()
                .is_none()
        );
        // Different image sha also misses.
        assert!(
            pool.select_idle_compatible(&vz_compat("kk", "img-bb"))
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
        let mut h = saved_handle("vz1", "aa", "img", StandbyState::Idle);
        h.spawned_unix_secs = now - 7_200; // 2h old
        pool.record(&h).unwrap();

        let reaped = pool
            .reap_stale(std::time::Duration::from_secs(3_600), now)
            .unwrap();

        assert!(!reaped.contains(&"vz1".to_string()), "demoted, not reaped");
        assert_eq!(pool.load("vz1").unwrap().state, StandbyState::Parked);
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
        let want = vz_compat("aa", "img");
        let parked = saved_handle("vzp", "aa", "img", StandbyState::Parked);
        pool.record(&parked).unwrap();

        let got = pool.select_idle_compatible(&want).unwrap();
        assert_eq!(got.map(|h| h.id), Some("vzp".to_string()));
    }

    #[test]
    fn reap_keeps_recent_saved_standby_and_demotes_expired_one() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let now = now_unix_secs();

        let mut recent = saved_handle("vz-keep", "kk", "img", StandbyState::Idle);
        recent.spawned_unix_secs = now;
        pool.record(&recent).unwrap();

        let mut old = saved_handle("vz-old", "kk", "img", StandbyState::Idle);
        old.spawned_unix_secs = 1; // ancient — past warm TTL, demoted to Parked
        pool.record(&old).unwrap();

        let reaped = pool
            .reap_stale(std::time::Duration::from_secs(3600), now)
            .unwrap();

        assert!(!reaped.contains(&"vz-keep".to_string()));
        assert!(
            !reaped.contains(&"vz-old".to_string()),
            "demoted, not reaped"
        );
        assert!(pool.load("vz-keep").is_ok());
        assert_eq!(pool.load("vz-old").unwrap().state, StandbyState::Parked);
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
}
