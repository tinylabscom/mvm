//! One waiter for every child process in the guest.
//!
//! When the agent is PID 1 it must reap orphans re-parented to it, or the
//! guest accumulates zombies. But `waitpid(-1, …)` reaps *any* child,
//! including one that some other part of the agent spawned and is polling
//! with [`std::process::Child::try_wait`]. Whichever waiter gets there
//! first consumes the status; the loser sees `ECHILD` and has no way to
//! learn what the process actually did.
//!
//! That is not hypothetical. With a `SIGCHLD` handler reaping in the
//! background, `stream_exec` lost every workload exit status: a command
//! that exited 0, one that exited 3, and one that exited 7 all surfaced
//! as `-1`, and the host reported 255 for all three. Unit tests could not
//! see it, because a test process is never PID 1 and so never installed
//! the reaper.
//!
//! So there is exactly one waiter here, and it publishes.
//!
//! - Code that spawns a child registers it with [`OwnedChild`], an RAII
//!   token that deregisters on drop.
//! - [`install_orphan_reaper`] starts a polling thread. It reaps
//!   everything, records the status of *registered* pids in a table, and
//!   discards the rest — those are the orphans it exists to clean up.
//! - Owners call [`try_wait`] / [`wait`] instead of the inherent `Child`
//!   methods. Those consult the table when the kernel says `ECHILD`.
//!
//! The reaper's `waitpid` + publish, and an owner's `try_wait` + lookup,
//! each run under the same mutex. So an owner either wins the race and
//! reads the status from the kernel, or loses it and finds the status
//! already in the table — there is no interleaving where the status is
//! observable by neither, and therefore no retry loop. The lock is held
//! only across non-blocking calls, so a long-lived child never blocks
//! orphan reaping.
//!
//! Everything degrades to the plain `Child` methods when no reaper is
//! installed, which is every unit test and every non-PID-1 process.

use std::collections::{HashMap, HashSet};
use std::io;
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// How often the orphan reaper sweeps. Zombie orphans are harmless while
/// they wait — they hold a pid table slot and nothing else — so this
/// trades a little latency for not needing an async-signal-safe handler.
const REAP_INTERVAL: Duration = Duration::from_millis(200);

/// First poll gap for [`wait`] once a reaper is running and the kernel may
/// not be the one to hand us the status. Short so a quick command returns
/// promptly.
const WAIT_POLL_MIN: Duration = Duration::from_millis(1);

/// Ceiling the [`wait`] poll gap backs off to. A workload can run for
/// hours; polling it at the initial cadence the whole time would burn a
/// core for nothing.
const WAIT_POLL_MAX: Duration = Duration::from_millis(50);

/// Set once [`install_orphan_reaper`] has started the sweeper. Until then
/// every entry point here delegates straight to the inherent `Child`
/// methods, so nothing changes for a process that is not PID 1.
static REAPER_RUNNING: AtomicBool = AtomicBool::new(false);

/// Pids some part of the agent owns and intends to wait on, plus the exit
/// statuses the reaper collected on their behalf.
///
/// One mutex covers both so that "is this pid owned?" and "record its
/// status" are a single atomic step against an owner's own wait.
#[derive(Default)]
struct Registry {
    owned: HashSet<i32>,
    reaped: HashMap<i32, i32>,
}

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(Mutex::default)
}

/// Registration token for a child this process spawned and will wait on.
///
/// Hold it from just after spawn until the last [`try_wait`] / [`wait`]
/// call for that child. While it is alive the reaper records the child's
/// status instead of discarding it; on drop the pid and any unread status
/// are forgotten, so the table cannot grow without bound.
pub struct OwnedChild {
    pid: i32,
}

impl OwnedChild {
    /// Register `pid` as owned. Cheap and safe to call when no reaper is
    /// running — the registry simply goes unread.
    pub fn new(pid: u32) -> Self {
        let pid = pid as i32;
        register_in(registry(), pid);
        Self { pid }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        deregister_in(registry(), self.pid);
    }
}

/// Non-blocking wait, safe against a concurrently running orphan reaper.
///
/// Same contract as [`Child::try_wait`]: `Ok(None)` means still running.
/// The difference is that a status already collected by the reaper is
/// returned here rather than lost to `ECHILD`.
pub fn try_wait(child: &mut Child) -> io::Result<Option<ExitStatus>> {
    if !REAPER_RUNNING.load(Ordering::Acquire) {
        return child.try_wait();
    }
    try_wait_in(registry(), child)
}

/// Blocking wait, safe against a concurrently running orphan reaper.
///
/// With a reaper installed this polls [`try_wait`] rather than blocking in
/// the kernel, because the reaper may be the one that actually collects
/// the status. Without a reaper it is a straight [`Child::wait`].
pub fn wait(child: &mut Child) -> io::Result<ExitStatus> {
    if !REAPER_RUNNING.load(Ordering::Acquire) {
        return child.wait();
    }
    let mut gap = WAIT_POLL_MIN;
    loop {
        match try_wait_in(registry(), child)? {
            Some(status) => return Ok(status),
            None => {
                std::thread::sleep(gap);
                gap = (gap * 2).min(WAIT_POLL_MAX);
            }
        }
    }
}

/// Start the orphan reaper. Call once, from PID 1, before anything spawns
/// a child.
///
/// Replaces the `SIGCHLD` handler this agent used to install: a handler
/// must be async-signal-safe, so it could not take a lock, so it could not
/// publish what it reaped — which is precisely how it destroyed owned
/// children's exit statuses. A plain thread can lock, so it can publish.
pub fn install_orphan_reaper() {
    if REAPER_RUNNING.swap(true, Ordering::AcqRel) {
        return;
    }
    std::thread::Builder::new()
        .name("mvm-orphan-reaper".to_string())
        .spawn(|| {
            loop {
                reap_in(registry(), waitpid_any);
                std::thread::sleep(REAP_INTERVAL);
            }
        })
        .expect("spawn orphan reaper thread");
}

// ---------------------------------------------------------------------------
// Registry operations, parameterised over the registry and the reap syscall
// so they can be exercised without touching process-global state or the real
// `waitpid(-1)` — which in a threaded test binary would steal other tests'
// children.
// ---------------------------------------------------------------------------

fn register_in(reg: &Mutex<Registry>, pid: i32) {
    if let Ok(mut reg) = reg.lock() {
        reg.owned.insert(pid);
    }
}

fn deregister_in(reg: &Mutex<Registry>, pid: i32) {
    if let Ok(mut reg) = reg.lock() {
        reg.owned.remove(&pid);
        reg.reaped.remove(&pid);
    }
}

fn try_wait_in(reg: &Mutex<Registry>, child: &mut Child) -> io::Result<Option<ExitStatus>> {
    let pid = child.id() as i32;
    let Ok(mut reg) = reg.lock() else {
        return child.try_wait();
    };
    // A status the reaper already collected settles it — the kernel has
    // nothing left to tell us about this pid.
    if let Some(raw) = reg.reaped.remove(&pid) {
        return Ok(Some(exit_status_from_raw(raw)));
    }
    match child.try_wait() {
        Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {
            // The reaper cannot have published between the lookup above and
            // here — it takes this same lock to publish. So ECHILD means the
            // status was consumed by something that never recorded it, and
            // there is genuinely nothing left to report.
            Ok(reg.reaped.remove(&pid).map(exit_status_from_raw))
        }
        other => other,
    }
}

/// Drain every exited child through `waitpid`, recording the ones an
/// [`OwnedChild`] claims and discarding the rest.
///
/// `waitpid` writes the raw status through its out-param and returns the
/// reaped pid, `0` when children exist but none have exited, or a negative
/// value when there are none at all — i.e. `waitpid(-1, …, WNOHANG)`.
fn reap_in(reg: &Mutex<Registry>, mut waitpid: impl FnMut(&mut i32) -> i32) {
    let Ok(mut reg) = reg.lock() else {
        return;
    };
    loop {
        let mut raw = 0;
        let pid = waitpid(&mut raw);
        if pid <= 0 {
            return;
        }
        if reg.owned.contains(&pid) {
            reg.reaped.insert(pid, raw);
        }
    }
}

fn waitpid_any(raw: &mut i32) -> i32 {
    // SAFETY: `waitpid` writes only through `raw`, a live caller-owned
    // `i32`. `WNOHANG` means it never blocks, so the registry lock the
    // caller holds is held for a bounded, non-blocking span.
    unsafe { libc::waitpid(-1, raw, libc::WNOHANG) }
}

fn exit_status_from_raw(raw: i32) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    ExitStatus::from_raw(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    /// A private registry per test. The process-global one is deliberately
    /// untouched here: these tests run as threads under `cargo test`, and
    /// mutating shared reaper state would make them race each other.
    fn fresh_registry() -> Mutex<Registry> {
        Mutex::default()
    }

    fn spawn_exiting_with(code: i32) -> Child {
        Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("exit {code}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn")
    }

    /// Play the sweeper against one specific pid until it collects the
    /// status, so the test never touches `waitpid(-1)` — which in this
    /// threaded test binary would steal other tests' children.
    ///
    /// A zombie is still a live pid as far as `kill(pid, 0)` is concerned,
    /// so polling for the process to "disappear" would hang forever; the
    /// reap itself is the only thing that reports exit.
    fn reap_until_collected(reg: &Mutex<Registry>, pid: i32) {
        for _ in 0..500 {
            reap_in(reg, |raw| {
                // SAFETY: writes only through `raw`; targeted at our own child.
                unsafe { libc::waitpid(pid, raw, libc::WNOHANG) }
            });
            if reg.lock().unwrap().reaped.contains_key(&pid) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("child {pid} was never collected");
    }

    #[test]
    fn the_global_entry_points_are_plain_child_waits_until_a_reaper_runs() {
        assert!(
            !REAPER_RUNNING.load(Ordering::Acquire),
            "a unit test is never PID 1, so it must never install the reaper"
        );
        let mut child = spawn_exiting_with(3);
        assert_eq!(wait(&mut child).expect("wait").code(), Some(3));
    }

    #[test]
    fn an_owner_recovers_the_exit_code_the_reaper_collected() {
        // The exact loss this module exists to prevent, against the real
        // kernel: the reaper gets to the child first, so the owner's
        // `try_wait` sees ECHILD — and must still report the true code.
        let reg = fresh_registry();
        let mut child = spawn_exiting_with(7);
        let pid = child.id() as i32;
        register_in(&reg, pid);
        reap_until_collected(&reg, pid);

        assert!(
            child.try_wait().is_err(),
            "precondition: the kernel must now answer ECHILD for this pid"
        );
        let status = try_wait_in(&reg, &mut child).expect("try_wait after reap");
        assert_eq!(
            status.and_then(|s| s.code()),
            Some(7),
            "the owner must recover the exit code the reaper collected"
        );
    }

    #[test]
    fn a_recovered_status_is_handed_out_once() {
        // The table is drained on read, so a second poll cannot resurrect a
        // stale status and report the same exit twice.
        let reg = fresh_registry();
        let mut child = spawn_exiting_with(4);
        let pid = child.id() as i32;
        register_in(&reg, pid);
        reap_until_collected(&reg, pid);

        assert_eq!(
            try_wait_in(&reg, &mut child)
                .unwrap()
                .and_then(|s| s.code()),
            Some(4)
        );
        assert_eq!(
            try_wait_in(&reg, &mut child).unwrap(),
            None,
            "a drained status must not be replayed"
        );
    }

    #[test]
    fn an_unowned_pid_is_discarded_rather_than_accumulated() {
        // Orphans are what the reaper exists for, but nobody will ever ask
        // for their status, so keeping it would leak the table.
        let reg = fresh_registry();
        let mut scripted = vec![(4242, 0), (4243, 1 << 8)].into_iter();
        reap_in(&reg, |raw| match scripted.next() {
            Some((pid, status)) => {
                *raw = status;
                pid
            }
            None => 0,
        });
        assert!(reg.lock().unwrap().reaped.is_empty());
    }

    #[test]
    fn reaping_stops_at_the_first_non_positive_answer() {
        // `0` means "children exist, none exited". Treating it as anything
        // but a stop condition would spin the reaper thread hot.
        let reg = fresh_registry();
        register_in(&reg, 4242);
        let mut calls = 0;
        let mut scripted = vec![4242, 0, 4243].into_iter();
        reap_in(&reg, |raw| {
            calls += 1;
            *raw = 0;
            scripted.next().unwrap_or(-1)
        });
        assert_eq!(calls, 2, "must stop at the 0, not keep draining");
        let reg = reg.lock().unwrap();
        assert!(reg.reaped.contains_key(&4242));
        assert!(!reg.reaped.contains_key(&4243));
    }

    #[test]
    fn only_owned_pids_are_recorded() {
        let reg = fresh_registry();
        register_in(&reg, 4242);
        let mut scripted = vec![(4242, 3 << 8), (9999, 5 << 8)].into_iter();
        reap_in(&reg, |raw| match scripted.next() {
            Some((pid, status)) => {
                *raw = status;
                pid
            }
            None => 0,
        });
        let reg = reg.lock().unwrap();
        assert_eq!(reg.reaped.get(&4242), Some(&(3 << 8)));
        assert!(!reg.reaped.contains_key(&9999));
    }

    #[test]
    fn deregistering_forgets_the_pid_and_any_unread_status() {
        let reg = fresh_registry();
        register_in(&reg, 4242);
        reg.lock().unwrap().reaped.insert(4242, 0);
        deregister_in(&reg, 4242);
        let reg = reg.lock().unwrap();
        assert!(!reg.owned.contains(&4242));
        assert!(
            !reg.reaped.contains_key(&4242),
            "an unread status must not outlive its owner, or the table grows forever"
        );
    }

    #[test]
    fn the_owned_token_registers_and_deregisters_in_the_global_registry() {
        // The RAII wiring itself, on a pid no real child can hold.
        let pid = 0x7f00_0001u32;
        {
            let _owned = OwnedChild::new(pid);
            assert!(registry().lock().unwrap().owned.contains(&(pid as i32)));
        }
        assert!(!registry().lock().unwrap().owned.contains(&(pid as i32)));
    }

    #[test]
    fn raw_status_decoding_matches_the_kernel_encoding() {
        // wait(2) packs a normal exit as `code << 8`.
        assert_eq!(exit_status_from_raw(3 << 8).code(), Some(3));
        assert_eq!(exit_status_from_raw(0).code(), Some(0));
    }
}
