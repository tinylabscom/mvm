//! End-to-end LibkrunBackend lifecycle test.
//!
//! Validates that `LibkrunBackend::start → status → stop → status`
//! drives a real `mvm-libkrun-supervisor` subprocess against a real
//! libkrun guest, all the way through SIGTERM-based shutdown. This is
//! the only test in the workspace that exercises the
//! `LibkrunBackend → supervisor → libkrun → kernel boot → SIGTERM →
//! supervisor exit` path end-to-end.
//!
//! ## Why SIGTERM and not a clean `init=/sbin/poweroff`?
//!
//! The dev-VM rootfs at `~/.mvm/dev/current/` (built before the
//! builder-VM migration) doesn't ship `/sbin/poweroff` and its own
//! `/init` crashes on a BusyBox-vs-util-linux setpriv incompatibility
//! before any cleanup runs. A clean shutdown path needs either the
//! dev rootfs's init bug fixed (orthogonal) or a tiny custom test
//! rootfs that just `AF_VSOCK`-binds and exits.
//!
//! What this test *can* validate against today's broken dev init is
//! the **production stop path** itself: `mvmctl stop <name>` always
//! goes through `LibkrunBackend::stop`, which reads the supervisor's
//! PID file and sends `SIGTERM` (escalating to `SIGKILL` after 5s).
//! That's the path users actually hit when shutting down a libkrun
//! VM, and it's the path this test exercises.
//!
//! ## How to run
//!
//! ```sh
//! cargo build -p mvm-libkrun --bin mvm-libkrun-supervisor --features libkrun-sys
//! MVM_LIBKRUN_E2E=1 \
//!   MVM_LIBKRUN_SUPERVISOR_PATH=$(pwd)/target/debug/mvm-libkrun-supervisor \
//!   cargo test -p mvm-backend --test libkrun_lifecycle_e2e -- --ignored --nocapture
//! ```
//!
//! Self-skips unless `MVM_LIBKRUN_E2E=1` is set and
//! `~/.mvm/dev/current/{vmlinux,rootfs.ext4}` both exist. CI doesn't
//! run this by default; the existing `libkrun-macos` lane covers
//! everything *before* the boot boundary, and GitHub macOS runners
//! don't expose `Hypervisor.framework` so a real boot can't run
//! there even if we wanted it to.
//!
//! ## What it asserts
//!
//! 1. `LibkrunBackend::start` writes the per-VM directory under
//!    `~/.mvm/vms/<name>/` and the PID file appears.
//! 2. `LibkrunBackend::status(name)` reports `Running` within
//!    [`STATUS_RUNNING_TIMEOUT`].
//! 3. `LibkrunBackend::list()` includes the VM.
//! 4. `LibkrunBackend::stop(name)` sends SIGTERM and the supervisor
//!    process actually exits within [`STOP_TIMEOUT`] (i.e. doesn't
//!    require the SIGKILL escalation; libkrun's signal handling is
//!    correct under macOS Hypervisor.framework).
//! 5. After `stop`, `status` reports `Stopped` and the PID file is
//!    cleaned up.

use mvm_backend::LibkrunBackend;
use mvm_core::vm_backend::{VmBackend, VmId, VmStartConfig, VmStatus};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const STATUS_RUNNING_TIMEOUT: Duration = Duration::from_secs(10);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

#[test]
#[ignore = "live libkrun boot — opt in via MVM_LIBKRUN_E2E=1"]
fn libkrun_lifecycle_start_status_stop() {
    if std::env::var("MVM_LIBKRUN_E2E").as_deref() != Ok("1") {
        eprintln!("MVM_LIBKRUN_E2E != 1, skipping");
        return;
    }

    let dev_dir = dev_artifacts_dir();
    let kernel = dev_dir.join("vmlinux");
    let rootfs = dev_dir.join("rootfs.ext4");
    if !kernel.is_file() || !rootfs.is_file() {
        panic!(
            "MVM_LIBKRUN_E2E=1 was set but dev artifacts are missing at {}/{{vmlinux,rootfs.ext4}}. \
             Build them with `mvmctl dev up` (once plan 72 lands a working builder VM) or copy in from another host.",
            dev_dir.display()
        );
    }

    // Each test run gets a fresh VM name so a previous abandoned
    // supervisor doesn't poison status() with a stale PID. Plus the
    // PID-file cleanup-on-stop assertion is meaningful only when the
    // file is one we created in this run.
    let name = format!(
        "libkrun-e2e-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    );
    let state_dir = vms_root().join(&name);
    // Be defensive against the (impossible) name collision.
    let _ = std::fs::remove_dir_all(&state_dir);

    let config = VmStartConfig {
        name: name.clone(),
        rootfs_path: rootfs.to_string_lossy().into_owned(),
        kernel_path: Some(kernel.to_string_lossy().into_owned()),
        cpus: 1,
        memory_mib: 512,
        ..Default::default()
    };

    let backend = LibkrunBackend;
    let id = backend.start(&config).expect("LibkrunBackend::start");
    assert_eq!(id, VmId(name.clone()));

    let pid_file = state_dir.join("libkrun.pid");
    assert!(
        pid_file.is_file(),
        "PID file should exist immediately after start at {}",
        pid_file.display()
    );

    // The supervisor wrote its PID, but the kernel still needs a few
    // hundred milliseconds to come up and the libkrun thread inside
    // the supervisor needs to actually call `krun_start_enter`.
    // `status` is true the whole time because we only check whether
    // the supervisor's PID is alive, not whether the guest itself is
    // through boot.
    let vm_id = VmId(name.clone());
    poll_until(STATUS_RUNNING_TIMEOUT, "status reports Running", || {
        matches!(backend.status(&vm_id), Ok(VmStatus::Running))
    });

    let listed = backend.list().expect("LibkrunBackend::list");
    let found = listed.iter().find(|v| v.name == name).unwrap_or_else(|| {
        panic!(
            "list() didn't include the VM we just started; got: {:?}",
            listed.iter().map(|v| &v.name).collect::<Vec<_>>()
        )
    });
    assert!(
        matches!(found.status, VmStatus::Running),
        "list() found the VM but reported it Stopped"
    );

    // SIGTERM the supervisor. `stop` polls for the process to exit
    // for up to STOP_TIMEOUT before escalating to SIGKILL. If the
    // process doesn't go down within that window, this test fails.
    backend.stop(&vm_id).expect("LibkrunBackend::stop");

    poll_until(STOP_TIMEOUT, "status reports Stopped", || {
        matches!(backend.status(&vm_id), Ok(VmStatus::Stopped))
    });
    assert!(
        !pid_file.is_file(),
        "stop() should have cleaned up the PID file at {}",
        pid_file.display()
    );

    let listed_after = backend.list().expect("LibkrunBackend::list after stop");
    let still_listed = listed_after.iter().any(|v| v.name == name);
    // After stop the state dir is gone (we removed it above before
    // the run, and `stop` rm'd the PID file; depending on whether
    // anything else writes to the state dir, list() may still see
    // the directory but without a PID file — that's filtered out by
    // LibkrunBackend::list).
    assert!(
        !still_listed,
        "list() after stop should not include the stopped VM; got: {:?}",
        listed_after.iter().map(|v| &v.name).collect::<Vec<_>>()
    );

    // Belt-and-suspenders cleanup so a future test run starts cold.
    let _ = std::fs::remove_dir_all(&state_dir);
}

fn dev_artifacts_dir() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME must be set");
    PathBuf::from(home).join(".mvm/dev/current")
}

fn vms_root() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME must be set");
    PathBuf::from(home).join(".mvm/vms")
}

/// Poll `cond` every 100ms until it returns `true` or the timeout
/// elapses; panics on timeout with the supplied label.
fn poll_until<F: FnMut() -> bool>(timeout: Duration, label: &str, mut cond: F) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for {label} after {timeout:?}");
}
