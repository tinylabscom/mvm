//! Signal handling and config hot-reload.
//!
//! On SIGTERM / SIGINT, the agent flips `SHUTDOWN_REQUESTED` (atomic
//! store, async-signal-safe). The accept loop polls the flag at
//! each iteration and after every `accept()` return (signals deliver
//! `EINTR` to the syscall, which already triggers the loop's
//! continue path). Once the flag flips, the loop breaks and
//! `shutdown_subsystems` runs:
//!   1. Sets the warm-process pool's shutdown atomic so new
//!      dispatches refuse fast-fail.
//!   2. SIGTERMs/SIGKILLs idle workers via `WorkerPool::shutdown`.
//!   3. Sleeps a configurable grace so in-flight calls drain.
//!
//! A second SIGTERM/SIGINT during drain calls `_exit(128 + signo)`
//! directly so a wedged drain doesn't strand operators. `_exit` is
//! async-signal-safe; nothing else in the handler needs to be
//! (the pool drain happens after the loop, in a normal Rust
//! context).
//!
//! The handler itself does only atomic stores and (on second signal)
//! `_exit`. It does not allocate, lock, or call any non-async-
//! signal-safe libc routine — see `man 7 signal-safety`.

use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Duration;

use mvm_agentd::lifecycle_hooks;

use crate::config::{AgentConfig, default_port};
use crate::globals::{
    AGENT_CONFIG_PATH, HOT_BUSY_THRESHOLD_BITS, HOT_SAMPLE_INTERVAL_SECS, RELOAD_REQUESTED,
    SHUTDOWN_REQUESTED, SHUTDOWN_SIGNAL_COUNT, WARM_POOL,
};

/// Maximum time to give the before_stop hook before SIGKILL.
pub(crate) const SHUTDOWN_HOOK_GRACE: Duration = Duration::from_secs(10);

/// Sleep between shutdown-hook completion checks.
pub(crate) const SHUTDOWN_HOOK_POLL: Duration = Duration::from_millis(200);

// Baked-in lifecycle hook path. The Nix factory at
// `nix/lib/factories/mkFunctionService.nix` always emits this
// script (no-op `:` body when the user declared no commands for
// the phase). The agent only needs to know the canonical path;
// missing-script fall-through is handled inside `lifecycle_hooks`
// defensively.
pub(crate) const BEFORE_STOP_HOOK: &str = "/etc/mvm/hooks/before_stop.sh";

/// SIGTERM/SIGINT handler. Async-signal-safe — only atomic stores
/// and (on repeat-signal) `_exit`. Never allocates, never locks.
///
/// First signal: flip `SHUTDOWN_REQUESTED`. The accept loop in
/// `main` observes the flag and runs `shutdown_subsystems`.
///
/// Second signal: `_exit(128 + signo)`. POSIX convention for
/// signal-killed processes; matches what bash sees as the process
/// exit code.
unsafe extern "C" fn on_shutdown_signal(sig: libc::c_int) {
    let prior = SHUTDOWN_SIGNAL_COUNT.fetch_add(1, Ordering::AcqRel);
    if prior >= 1 {
        // Operator's second SIGTERM/SIGINT — bail out without
        // waiting for any drain. `_exit` is async-signal-safe.
        // SAFETY: libc call with a valid status integer.
        unsafe {
            libc::_exit(128 + sig);
        }
    }
    SHUTDOWN_REQUESTED.store(true, Ordering::Release);
}

/// SIGHUP handler.
///
/// Flips `RELOAD_REQUESTED`. The accept loop polls it between
/// iterations and, when set, calls `apply_reload` to re-read the
/// config file and update the hot-reloadable atomics. Unlike
/// the shutdown handler, this does NOT escalate on repeat — each
/// SIGHUP triggers a fresh reload.
///
/// Async-signal-safe — only an atomic store.
unsafe extern "C" fn on_reload_signal(_sig: libc::c_int) {
    RELOAD_REQUESTED.store(true, Ordering::Release);
}

/// Install handlers for SIGTERM and SIGINT. Best-effort: if
/// `sigaction` fails for any reason, the agent logs and continues
/// — graceful drain is a nice-to-have, not load-bearing. On a
/// microVM lifecycle the handler usually never fires anyway because
/// the kernel teardown is abrupt; the handler matters when an
/// operator manually `kill -TERM`s the agent or when in-place
/// updates land later.
///
/// `#[inline(never)]` is load-bearing for the symbol-contract
/// gate (`scripts/check-prod-agent-no-exec.sh`) which asserts
/// this symbol is present as positive evidence the handlers are
/// wired in. Mirrors the same pattern on `handle_run_entrypoint`
/// and `dispatch_via_warm_pool`.
#[inline(never)]
pub(crate) fn install_signal_handlers() {
    // SAFETY: zeroed sigaction is the documented "use defaults"
    // sentinel. We populate sa_sigaction (handler), sa_mask (no
    // signals blocked during handler), and leave sa_flags = 0
    // (default disposition: restart syscalls handled by libc, but
    // we deliberately want EINTR on accept).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_shutdown_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        // sa_flags = 0: do NOT set SA_RESTART. The accept syscall
        // returns EINTR when a signal lands, which is exactly how
        // we want the loop to wake up.
        let term_rc = libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        let int_rc = libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        if term_rc != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("mvm-guest-agent: sigaction(SIGTERM) failed: {err}");
        }
        if int_rc != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("mvm-guest-agent: sigaction(SIGINT) failed: {err}");
        }

        // SIGHUP handler. Separate sigaction because the
        // dispositions differ: SIGHUP should NOT escalate on
        // repeat (each delivery triggers a fresh reload).
        let mut sa_hup: libc::sigaction = std::mem::zeroed();
        sa_hup.sa_sigaction = on_reload_signal as *const () as usize;
        libc::sigemptyset(&mut sa_hup.sa_mask);
        let hup_rc = libc::sigaction(libc::SIGHUP, &sa_hup, std::ptr::null_mut());
        if hup_rc != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("mvm-guest-agent: sigaction(SIGHUP) failed: {err}");
        }
    }
}

/// Re-read the agent config file and apply the hot-reloadable
/// subset to live atomics. Called from the accept loop when
/// `RELOAD_REQUESTED` is set (SIGHUP). Never terminates the agent;
/// reload errors log and continue with the
/// prior values.
///
/// ## Reload-safety review
///
/// `AgentConfig` carries three fields. The decisions are:
///
/// - `port: u32` — **NOT reloadable.** Changing it would require
///   re-binding the listening socket, which would terminate every
///   live vsock connection. Operator must restart the agent.
/// - `busy_threshold: f64` — **reloadable.** Read every monitoring
///   loop iteration via `HOT_BUSY_THRESHOLD_BITS`.
/// - `sample_interval_secs: u64` — **reloadable.** Read every
///   monitoring loop iteration via `HOT_SAMPLE_INTERVAL_SECS`.
///
/// A reload that changes `port` logs a warning and leaves the
/// running port in place. Future hot-reloadable fields extend this
/// function; non-reloadable ones inherit the warning pattern.
pub(crate) fn apply_reload() {
    let Some(path) = AGENT_CONFIG_PATH.get() else {
        eprintln!("mvm-guest-agent: reload skipped — config path not captured");
        return;
    };
    let data = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "mvm-guest-agent: reload skipped — failed to read {}: {e}",
                path.display()
            );
            return;
        }
    };
    let new_cfg = match serde_json::from_str::<AgentConfig>(&data) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "mvm-guest-agent: reload skipped — failed to parse {}: {e}",
                path.display()
            );
            return;
        }
    };
    apply_reload_to_atomics(&new_cfg);
}

/// Test seam — applies a parsed config to the hot atomics without
/// touching the filesystem. Production wraps this through
/// [`apply_reload`].
fn apply_reload_to_atomics(new_cfg: &AgentConfig) {
    // Compare to the current values so we log meaningful diffs.
    let cur_thresh = f64::from_bits(HOT_BUSY_THRESHOLD_BITS.load(Ordering::Acquire));
    let cur_interval = HOT_SAMPLE_INTERVAL_SECS.load(Ordering::Acquire);

    if (new_cfg.busy_threshold - cur_thresh).abs() > f64::EPSILON {
        HOT_BUSY_THRESHOLD_BITS.store(new_cfg.busy_threshold.to_bits(), Ordering::Release);
        eprintln!(
            "mvm-guest-agent: reload — busy_threshold {cur_thresh} → {}",
            new_cfg.busy_threshold
        );
    }
    if new_cfg.sample_interval_secs != cur_interval {
        HOT_SAMPLE_INTERVAL_SECS.store(new_cfg.sample_interval_secs, Ordering::Release);
        eprintln!(
            "mvm-guest-agent: reload — sample_interval_secs {cur_interval} → {}",
            new_cfg.sample_interval_secs
        );
    }
    // `port` is not reloadable. The accept socket is already bound;
    // changing it would terminate live connections. Log if it
    // changed so the operator knows a restart is needed.
    //
    // We can't compare against the live port (it isn't stored in a
    // hot atomic — that would imply it's hot-reloadable, which it
    // isn't). Instead the warning fires unconditionally when the
    // file's port differs from the default, on the theory that an
    // operator who edited the config wants to know it didn't take.
    if new_cfg.port != default_port() {
        eprintln!(
            "mvm-guest-agent: reload — port={} on disk; the running agent \
             keeps its boot-time port (restart to apply)",
            new_cfg.port
        );
    }
}

/// Drain all subsystems before exiting. Currently the only one
/// that benefits from a graceful shutdown is the warm-process
/// pool (cold-tier `RunEntrypoint` calls hold no long-lived
/// resources). Adding more drains here is the natural extension
/// point if future additions (snapshot finalization, integration
/// teardown) want orderly exit.
pub(crate) fn shutdown_subsystems(grace: Duration) {
    eprintln!("mvm-guest-agent: shutdown requested; draining for up to {grace:?}");
    // Run the workload's baked `before_stop.sh` hook *before*
    // tearing down the worker
    // pool so the hook can still see live workers (e.g. to flush
    // application state through them). Best-effort: missing script /
    // non-zero exit / grace overrun all log + continue. SIGKILL on
    // the agent itself bypasses this entire path by design.
    run_before_stop_hook();
    if let Some(Some(pool)) = WARM_POOL.get() {
        pool.shutdown(grace);
    }
    eprintln!("mvm-guest-agent: drain complete; exiting");
}

/// Fire the baked `before_stop.sh` hook with the configured grace
/// deadline. Log-only: shutdown continues regardless of outcome. The
/// Nix factory always bakes this script (no-op `:` body when no
/// commands declared), but we treat `ScriptMissing` as success so a
/// half-assembled rootfs doesn't wedge teardown.
pub(crate) fn run_before_stop_hook() {
    match lifecycle_hooks::run_shutdown_hook(
        Path::new(BEFORE_STOP_HOOK),
        SHUTDOWN_HOOK_GRACE,
        SHUTDOWN_HOOK_POLL,
    ) {
        Ok(()) => {
            eprintln!("mvm-guest-agent: before_stop hook completed cleanly");
        }
        Err(lifecycle_hooks::ShutdownError::ScriptMissing { script }) => {
            eprintln!(
                "mvm-guest-agent: before_stop hook `{}` not present; nothing to run",
                script.display()
            );
        }
        Err(e) => {
            eprintln!("mvm-guest-agent: before_stop hook failed (continuing shutdown): {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path as StdPath, PathBuf};
    use std::sync::Mutex;

    use crate::boot::{AFTER_START_HOOK, READINESS_INTERVAL, READINESS_TIMEOUT};

    // ─── signal handling unit tests ───────────────────────────
    //
    // These exercise the handler in isolation by calling the
    // `extern "C"` function directly with a synthetic signo. We
    // deliberately do NOT raise real signals against the test
    // process — Cargo runs tests in a single shared binary and
    // a real SIGTERM would terminate every concurrent test.
    //
    // The tests share global statics with the rest of the binary,
    // so each test resets `SHUTDOWN_REQUESTED` and
    // `SHUTDOWN_SIGNAL_COUNT` at the start. Using a Mutex around
    // the reset+invoke serializes signal-handler tests so they
    // don't observe each other's state mutations.

    static SIGNAL_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_shutdown_state() {
        SHUTDOWN_REQUESTED.store(false, Ordering::Release);
        SHUTDOWN_SIGNAL_COUNT.store(0, Ordering::Release);
    }

    #[test]
    fn signal_handler_flips_shutdown_flag_on_first_signal() {
        let _g = SIGNAL_TEST_LOCK
            .lock()
            .expect("signal-test mutex not poisoned");
        reset_shutdown_state();
        assert!(!SHUTDOWN_REQUESTED.load(Ordering::Acquire));
        // SAFETY: the handler is async-signal-safe and only stores
        // an atomic on first invocation; SIGTERM signo is a valid
        // libc constant.
        unsafe {
            on_shutdown_signal(libc::SIGTERM);
        }
        assert!(SHUTDOWN_REQUESTED.load(Ordering::Acquire));
        assert_eq!(SHUTDOWN_SIGNAL_COUNT.load(Ordering::Acquire), 1);
    }

    #[test]
    fn signal_handler_increments_count_idempotent_first_call() {
        // Calling once must leave count==1, flag==true. Calling
        // again would `_exit` per the second-signal escalation,
        // so we never invoke the handler twice in tests.
        let _g = SIGNAL_TEST_LOCK
            .lock()
            .expect("signal-test mutex not poisoned");
        reset_shutdown_state();
        // SAFETY: the handler only performs async-signal-safe atomic stores;
        // calling it directly (not from a real signal) with a valid signal
        // number is sound, and one call stays below the second-signal `_exit`.
        unsafe {
            on_shutdown_signal(libc::SIGINT);
        }
        assert_eq!(SHUTDOWN_SIGNAL_COUNT.load(Ordering::Acquire), 1);
        assert!(SHUTDOWN_REQUESTED.load(Ordering::Acquire));
    }

    #[test]
    fn install_signal_handlers_does_not_panic() {
        // Installing twice should be safe; sigaction overwrites.
        // We don't assert the prior disposition is preserved
        // because the test runner may have its own handlers.
        install_signal_handlers();
        install_signal_handlers();
    }

    // ─── SIGHUP config reload ──────────────────────────────

    fn reset_reload_state() {
        RELOAD_REQUESTED.store(false, Ordering::Release);
    }

    #[test]
    fn signal_handler_flips_reload_flag_on_sighup() {
        let _g = SIGNAL_TEST_LOCK
            .lock()
            .expect("signal-test mutex not poisoned");
        reset_reload_state();
        assert!(!RELOAD_REQUESTED.load(Ordering::Acquire));
        // SAFETY: handler is async-signal-safe and only stores an
        // atomic; SIGHUP signo is a valid libc constant.
        unsafe {
            on_reload_signal(libc::SIGHUP);
        }
        assert!(RELOAD_REQUESTED.load(Ordering::Acquire));
    }

    #[test]
    fn signal_handler_reload_is_idempotent_on_repeat() {
        // Unlike SIGTERM/SIGINT, SIGHUP must NOT escalate on the
        // second delivery — each one is a fresh reload request.
        let _g = SIGNAL_TEST_LOCK
            .lock()
            .expect("signal-test mutex not poisoned");
        reset_reload_state();
        // SAFETY: the SIGHUP handler only does an atomic store and never
        // escalates; calling it directly with a valid signal number is sound.
        unsafe {
            on_reload_signal(libc::SIGHUP);
            on_reload_signal(libc::SIGHUP);
            on_reload_signal(libc::SIGHUP);
        }
        assert!(RELOAD_REQUESTED.load(Ordering::Acquire));
        // No `_exit` happened or this test wouldn't have returned.
    }

    #[test]
    fn apply_reload_updates_hot_atomics_with_new_values() {
        let _g = SIGNAL_TEST_LOCK
            .lock()
            .expect("signal-test mutex not poisoned");
        // Seed the atomics to known values.
        HOT_BUSY_THRESHOLD_BITS.store(0.1f64.to_bits(), Ordering::Release);
        HOT_SAMPLE_INTERVAL_SECS.store(5, Ordering::Release);

        let new_cfg = AgentConfig {
            port: default_port(),
            busy_threshold: 0.75,
            sample_interval_secs: 30,
        };
        apply_reload_to_atomics(&new_cfg);

        let updated_thresh = f64::from_bits(HOT_BUSY_THRESHOLD_BITS.load(Ordering::Acquire));
        let updated_interval = HOT_SAMPLE_INTERVAL_SECS.load(Ordering::Acquire);
        assert!(
            (updated_thresh - 0.75).abs() < f64::EPSILON,
            "busy_threshold not updated: got {updated_thresh}"
        );
        assert_eq!(updated_interval, 30);
    }

    #[test]
    fn apply_reload_is_noop_when_values_unchanged() {
        // If the on-disk config matches the live state, the
        // reload path runs without changing anything — the
        // monitoring loop sees the same values.
        let _g = SIGNAL_TEST_LOCK
            .lock()
            .expect("signal-test mutex not poisoned");
        HOT_BUSY_THRESHOLD_BITS.store(0.5f64.to_bits(), Ordering::Release);
        HOT_SAMPLE_INTERVAL_SECS.store(10, Ordering::Release);

        let same_cfg = AgentConfig {
            port: default_port(),
            busy_threshold: 0.5,
            sample_interval_secs: 10,
        };
        apply_reload_to_atomics(&same_cfg);

        assert_eq!(
            HOT_BUSY_THRESHOLD_BITS.load(Ordering::Acquire),
            0.5f64.to_bits()
        );
        assert_eq!(HOT_SAMPLE_INTERVAL_SECS.load(Ordering::Acquire), 10);
    }

    #[test]
    fn apply_reload_handles_partial_update() {
        // Only busy_threshold differs; sample_interval_secs stays.
        let _g = SIGNAL_TEST_LOCK
            .lock()
            .expect("signal-test mutex not poisoned");
        HOT_BUSY_THRESHOLD_BITS.store(0.2f64.to_bits(), Ordering::Release);
        HOT_SAMPLE_INTERVAL_SECS.store(7, Ordering::Release);

        let new_cfg = AgentConfig {
            port: default_port(),
            busy_threshold: 0.9,
            sample_interval_secs: 7,
        };
        apply_reload_to_atomics(&new_cfg);

        assert!(
            (f64::from_bits(HOT_BUSY_THRESHOLD_BITS.load(Ordering::Acquire)) - 0.9).abs()
                < f64::EPSILON
        );
        assert_eq!(HOT_SAMPLE_INTERVAL_SECS.load(Ordering::Acquire), 7);
    }

    #[test]
    fn apply_reload_logs_warning_when_port_differs() {
        // The port is not reloadable; a non-default port in the
        // file should log a warning. We can't easily capture
        // stderr in a test, but we can prove the function doesn't
        // panic or update the (non-existent) port atomic.
        let _g = SIGNAL_TEST_LOCK
            .lock()
            .expect("signal-test mutex not poisoned");
        let new_cfg = AgentConfig {
            port: 9999,
            busy_threshold: crate::config::default_busy_threshold(),
            sample_interval_secs: crate::config::default_sample_interval_secs(),
        };
        apply_reload_to_atomics(&new_cfg);
        // Pass — no panic. The eprintln warning is by-eye.
    }

    #[test]
    fn shutdown_subsystems_no_pool_runs_quickly() {
        // With no warm pool active (the default for cold-tier
        // tests), shutdown_subsystems should return promptly —
        // it has nothing to drain.
        let start = std::time::Instant::now();
        shutdown_subsystems(Duration::from_millis(50));
        // No warm pool → no drain sleep → must return in well
        // under the grace.
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "shutdown_subsystems with no pool should return quickly"
        );
    }

    // ─── lifecycle-hook wiring tests ──────────────────
    //
    // The production agent points at `/etc/mvm/hooks/{after_start,
    // before_stop}.sh` baked by the Nix factory. The unit tests below
    // exercise the wiring helpers against tempdir-baked scripts via
    // the underlying `mvm_agentd::lifecycle_hooks` API — the production
    // wrappers (`wait_for_after_start`, `run_before_stop_hook`) are
    // thin path-resolution + logging shells over that API, so we test
    // the API contract end-to-end through them by parameterizing on
    // the path. Direct calls to `wait_for_after_start` /
    // `run_before_stop_hook` exercise the const-path wrappers and
    // assert they tolerate a missing production hook (the agent's
    // unit-test environment never has `/etc/mvm/hooks/*` baked).

    fn write_hook_script(dir: &StdPath, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        let staging = dir.join(format!("{name}.tmp"));
        let mut f = fs::File::create(&staging).expect("create hook script");
        f.write_all(body.as_bytes()).expect("write hook body");
        f.sync_all().expect("sync hook body");
        drop(f);
        let mut perms = fs::metadata(&staging).expect("hook metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&staging, perms).expect("chmod hook");
        fs::rename(&staging, &p).expect("publish hook");
        p
    }

    #[test]
    fn run_before_stop_hook_tolerates_missing_production_path() {
        // The const path `/etc/mvm/hooks/before_stop.sh` does not
        // exist in unit-test environments. The wrapper must not
        // panic, must not exit, must log + continue. We can't easily
        // assert log content here, so the assertion is "this returns
        // without panicking" — the wrapper has no return value.
        run_before_stop_hook();
    }

    #[test]
    fn run_shutdown_hook_via_lifecycle_api_writes_marker() {
        // A workload whose before_stop.sh writes a marker file proves
        // shutdown hooks fired on clean teardown. We can't reach the
        // const path, but we can prove the underlying API the wrapper
        // calls honors the contract.
        let tmp = tempfile::tempdir().expect("tempdir");
        let marker = tmp.path().join("stopped.marker");
        let body = format!(
            "#!/bin/sh\necho fired > {marker}\n",
            marker = marker.display()
        );
        let script = write_hook_script(tmp.path(), "before_stop.sh", &body);
        lifecycle_hooks::run_shutdown_hook(&script, SHUTDOWN_HOOK_GRACE, SHUTDOWN_HOOK_POLL)
            .expect("clean shutdown hook");
        let contents = fs::read_to_string(&marker).expect("marker file present");
        assert_eq!(contents.trim(), "fired");
    }

    #[test]
    fn run_shutdown_hook_via_lifecycle_api_kills_after_grace() {
        // The shutdown wrapper SIGKILLs a runaway hook after the
        // configured grace deadline so a buggy `before_stop.sh`
        // can't wedge teardown.
        let tmp = tempfile::tempdir().expect("tempdir");
        let script = write_hook_script(tmp.path(), "slow.sh", "#!/bin/sh\nsleep 5\n");
        let err = lifecycle_hooks::run_shutdown_hook(
            &script,
            Duration::from_millis(200),
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                lifecycle_hooks::ShutdownError::GraceExceeded { .. }
                    | lifecycle_hooks::ShutdownError::NonZeroExit { .. }
            ),
            "runaway hook must not succeed; got {err:?}"
        );
    }

    #[test]
    fn readiness_constants_match_plan_73() {
        // Lock in the readiness tunables — guards against an accidental
        // edit that would silently soften the readiness deadline.
        assert_eq!(READINESS_TIMEOUT, Duration::from_secs(30));
        assert_eq!(READINESS_INTERVAL, Duration::from_millis(200));
        assert_eq!(SHUTDOWN_HOOK_GRACE, Duration::from_secs(10));
        assert_eq!(SHUTDOWN_HOOK_POLL, Duration::from_millis(200));
        assert_eq!(AFTER_START_HOOK, "/etc/mvm/hooks/after_start.sh");
        assert_eq!(BEFORE_STOP_HOOK, "/etc/mvm/hooks/before_stop.sh");
    }
}
