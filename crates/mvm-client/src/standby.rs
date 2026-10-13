//! What standbys may cost the host, and how long they may sit unclaimed.
//!
//! An unnamed run leaves one standby of the image it booted so the next run of
//! that image starts warm. Those standbys are bounded twice:
//!
//! - **memory** — their guest RAM, summed across every image, stays within the
//!   configured standby budget and within whatever headroom the host budget
//!   leaves after the live machines' admitted charge. The oldest standbys are
//!   released to make room; one that cannot fit is not prepared.
//! - **time** — a standby nobody claims is released after the residency idle
//!   timeout. One process per host stays behind as the watcher that does it,
//!   and exits once there is nothing left to release.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use mvm_core::vm_backend::StandbyState;
use mvm_runtime::standby_pool::SupervisorStandbyPool;

/// How often the idle watcher looks at the pool.
const WATCH_TICK: Duration = Duration::from_secs(5);

/// The lock the one idle watcher per host holds, beside the pool.
const WATCH_LOCK: &str = "idle-watch";

/// The memory standbys may hold: the standby budget, and the host budget when
/// one is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandbyBudget {
    /// Guest RAM, in MiB, idle standbys may hold in total.
    pub standby_mib: u64,
    /// The host-wide headroom for guest RAM, if the operator set one.
    pub host_mib: Option<u64>,
}

/// Release standbys idle past `idle_timeout`, then make room for `needed_mib`
/// more by releasing the oldest. Returns whether the new standby fits; when it
/// does not, nothing is released for it.
///
/// # Errors
///
/// If the pool cannot be read or a released standby cannot be removed.
pub fn make_room(budget: StandbyBudget, needed_mib: u64, idle_timeout: Duration) -> Result<bool> {
    let pool = SupervisorStandbyPool::open()?;
    release_idle(&pool, idle_timeout);
    let host = budget.host_mib.map(|budget_mib| HostRoom {
        budget_mib,
        committed_mib: mvm_hostd::admission_budget::committed().memory_mib,
    });
    let Some(keep_mib) = standby_room(budget.standby_mib, host, needed_mib) else {
        return Ok(false);
    };
    let released = pool.evict_to_total_memory(keep_mib)?;
    if !released.is_empty() {
        tracing::info!(
            count = released.len(),
            "released older standbys to make room"
        );
    }
    Ok(true)
}

/// Stay behind and release idle standbys on time, unless another process
/// already is. Returns once no live standby is left to release.
///
/// Also the backstop for a pool whose home is deleted out from under it — a
/// test harness's temporary home, say: the standbys' processes would otherwise
/// outlive every record of them, so the watcher stops the ones it last saw.
pub fn watch_idle(idle_timeout: Duration) {
    match SupervisorStandbyPool::open() {
        Ok(pool) => watch_idle_in(&pool, idle_timeout, WATCH_TICK),
        Err(error) => tracing::debug!(%error, "cannot open the standby pool to watch it"),
    }
}

/// What the host budget leaves for standbys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HostRoom {
    budget_mib: u64,
    committed_mib: u64,
}

/// How much guest memory the standbys already held may keep so that
/// `needed_mib` more fits, or `None` when it cannot fit at all.
///
/// The bound is the smaller of the standby budget and the host budget's
/// headroom after the live machines' admitted charge. Standbys carry no
/// admitted charge of their own, so they are bounded here rather than counted
/// by admission.
fn standby_room(standby_budget_mib: u64, host: Option<HostRoom>, needed_mib: u64) -> Option<u64> {
    let bound = match host {
        Some(room) => standby_budget_mib.min(room.budget_mib.saturating_sub(room.committed_mib)),
        None => standby_budget_mib,
    };
    bound.checked_sub(needed_mib)
}

/// Release every standby that has sat unclaimed past the idle timeout.
fn release_idle(pool: &SupervisorStandbyPool, idle_timeout: Duration) {
    match pool.reap_stale(idle_timeout, mvm_core::time::now_unix_secs()) {
        Ok(released) if !released.is_empty() => {
            tracing::info!(count = released.len(), "released idle standbys");
        }
        Ok(_) => {}
        Err(error) => tracing::debug!(%error, "releasing idle standbys failed"),
    }
}

/// Standbys holding a live process, by id, with that process's pid.
fn live_standbys(pool: &SupervisorStandbyPool) -> BTreeMap<String, u32> {
    pool.list()
        .unwrap_or_default()
        .into_iter()
        .filter(|h| {
            matches!(h.state, StandbyState::Idle | StandbyState::Parked)
                && !h.is_saved_state()
                && SupervisorStandbyPool::is_live_or_saved(h)
        })
        .map(|h| (h.id, h.pid))
        .collect()
}

fn watch_idle_in(pool: &SupervisorStandbyPool, idle_timeout: Duration, tick: Duration) {
    let lock_path = pool.root().join(WATCH_LOCK);
    loop {
        let Ok(Some(guard)) = mvm_core::atomic_io::FileLock::try_acquire(&lock_path) else {
            return;
        };
        let mut seen = live_standbys(pool);
        while !seen.is_empty() {
            std::thread::sleep(tick);
            if !pool_root_exists(pool.root()) {
                stop_orphaned(&seen);
                return;
            }
            release_idle(pool, idle_timeout);
            seen = live_standbys(pool);
        }
        drop(guard);
        // A refill that recorded its standby while this watcher held the lock
        // gave up watching; look once more after letting go, and take the
        // watch back if one appeared.
        if live_standbys(pool).is_empty() {
            return;
        }
    }
}

fn pool_root_exists(root: &Path) -> bool {
    root.is_dir()
}

fn stop_orphaned(seen: &BTreeMap<String, u32>) {
    for (id, pid) in seen {
        tracing::info!(standby = %id, pid, "stopping a standby whose pool was removed");
        mvm_runtime::standby_pool::terminate_standby_process(*pid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_standby_fits_the_standby_budget_after_what_is_already_held() {
        assert_eq!(standby_room(2048, None, 512), Some(1536));
        assert_eq!(standby_room(512, None, 512), Some(0));
        assert_eq!(standby_room(256, None, 512), None);
        assert_eq!(standby_room(0, None, 512), None);
    }

    #[test]
    fn the_host_budget_bounds_standbys_after_live_machines() {
        let room = HostRoom {
            budget_mib: 4096,
            committed_mib: 3072,
        };
        // The host leaves 1024; the standby budget would allow 2048.
        assert_eq!(standby_room(2048, Some(room), 512), Some(512));
        let full = HostRoom {
            budget_mib: 4096,
            committed_mib: 4000,
        };
        assert_eq!(standby_room(2048, Some(full), 512), None);
        let over = HostRoom {
            budget_mib: 1024,
            committed_mib: 2048,
        };
        assert_eq!(standby_room(2048, Some(over), 512), None);
    }

    #[test]
    fn the_watcher_lets_go_when_nothing_is_left_to_release() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        // An empty pool: the watcher takes the lock, finds nothing, and
        // returns without sleeping, leaving the lock free for the next one.
        watch_idle_in(&pool, Duration::from_secs(60), Duration::from_secs(60));
        assert!(
            mvm_core::atomic_io::FileLock::try_acquire(&tmp.path().join(WATCH_LOCK))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_second_watcher_does_not_wait_on_the_first() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let _held = mvm_core::atomic_io::FileLock::acquire(&tmp.path().join(WATCH_LOCK)).unwrap();
        let started = std::time::Instant::now();
        watch_idle_in(&pool, Duration::from_secs(60), Duration::from_secs(60));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// A pool whose home was deleted leaves its standbys' processes running
    /// with no record of them; the watcher stops the ones it last saw.
    #[test]
    fn the_watcher_stops_standbys_whose_pool_was_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("pool");
        let pool = SupervisorStandbyPool::at(&root);
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawning a stand-in standby process");
        let handle = mvm_core::vm_backend::StandbyHandle {
            id: "s1".into(),
            template_id: None,
            control_socket: String::new(),
            pid: child.id(),
            kernel_sha256: "k".into(),
            vcpus: 1,
            mem_mib: 256,
            binding_nonce: "ab".repeat(32),
            spawned_unix_secs: mvm_core::time::now_unix_secs(),
            state: StandbyState::Idle,
            image_sha256: None,
            root_strategy: Default::default(),
            parent_checkpoint: None,
            preloaded_child_vm_name: None,
            vsock_egress: false,
        };
        pool.record(&handle).unwrap();
        let remover = {
            let root = root.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                std::fs::remove_dir_all(&root).unwrap();
            })
        };
        watch_idle_in(&pool, Duration::from_secs(3600), Duration::from_millis(200));
        remover.join().unwrap();
        let status = child.wait().expect("waiting for the stand-in");
        assert!(!status.success(), "the orphaned standby was stopped");
    }
}
