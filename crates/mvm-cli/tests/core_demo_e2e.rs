//! The core demo, end to end: `dev up` (builder VM) → `compile` the
//! hello-app → `up` (build in-VM, boot, wait for the guest agent over
//! vsock) → teardown. This is the regression guard for the whole spine.
//!
//! Gated on `MVM_E2E_SMOKE=1` because it needs libkrun + the builder VM
//! and runs for minutes; the default (ungated) run skips and passes.
//!
//! On macOS the workload microVM runs via libkrun (vsock-capable; the
//! path the guest agent answers on). `--hypervisor libkrun` is passed
//! explicitly so the test doesn't depend on `up`'s per-host auto-select
//! preferring libkrun over apple-container on macOS 26+ (which is a
//! deliberate apple-container priority for general use; the demo wants
//! the vsock path).
//!
//! `up` waits for the guest agent (`wait_for_guest_agent` → vsock Ping)
//! and only prints `Guest agent not reachable.` on failure — so `up`
//! exiting 0 *without* that line is the boot→ping proof.

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

fn mvmctl(args: &[&str]) -> std::process::Output {
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("mvmctl").expect("locate mvmctl");
    cmd.args(args);
    // The E2E pins the builder backend to libkrun on macOS so the
    // test doesn't depend on the Swift mvm-vz-supervisor having been
    // built. Plan 98's auto-select would otherwise pick Vz on macOS
    // 26+ Apple Silicon and bail with "mvm-vz-supervisor binary not
    // found." Both pins are per-child so they don't leak into other
    // tests running in the same cargo invocation.
    #[cfg(target_os = "macos")]
    {
        cmd.env("MVM_BUILDER_BACKEND", "libkrun");
        // Pin the libkrun supervisor to a freshly built binary. `cargo
        // test -p mvm-cli` does NOT rebuild the separate
        // `mvm-libkrun-supervisor` bin crate (mvm-cli doesn't depend on
        // it), so without this the test execs whatever stale supervisor
        // sits next to mvmctl. A supervisor built before the gvproxy
        // stdout/stderr-redirect fix spawns gvproxy with inherited fds;
        // on guest poweroff libkrun's `exit()` skips
        // `GvproxyHandle::Drop`, orphaning a gvproxy that still holds
        // this test's `Command` capture pipes — `output()` then never
        // sees EOF and the run hangs forever. `resolve_supervisor_path`
        // honors this override ahead of the next-to-exe fallback.
        cmd.env("MVM_LIBKRUN_SUPERVISOR_PATH", libkrun_supervisor_path());
    }
    cmd.output().expect("spawn mvmctl")
}

/// Resolve the on-disk `mvm-libkrun-supervisor` path and fail loudly if it
/// is missing or stale, once per process. `cargo test -p mvm-cli` does NOT
/// build this binary — it's a separate bin crate outside mvm-cli's
/// dependency graph, gated behind `required-features = ["libkrun-sys"]`.
/// So we don't build it inline (that means a second cargo invocation in a
/// foreign feature universe — it thrashes shared-dep fingerprints and
/// recompiles mid-test). Instead the `just e2e-core-demo` recipe builds it
/// first, and this guard pins `MVM_LIBKRUN_SUPERVISOR_PATH` to it after
/// asserting it postdates its sources. A supervisor built before the
/// gvproxy stdout/stderr-redirect fix orphans a gvproxy that holds this
/// test's capture pipes and hangs the run forever — turning that silent
/// hang into a one-line "rebuild first" error is the whole point.
#[cfg(target_os = "macos")]
fn libkrun_supervisor_path() -> &'static std::path::PathBuf {
    static PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        // Test binary lives at `<target>/<profile>/deps/<exe>`.
        let profile_dir = std::env::current_exe()
            .expect("test current_exe")
            .ancestors()
            .nth(2)
            .expect("target profile dir from test exe")
            .to_path_buf();
        let bin = profile_dir.join("mvm-libkrun-supervisor");

        let how = "build it first:\n  \
                   cargo build -p mvm-libkrun-supervisor --features libkrun-sys\n\
                   (or just `just e2e-core-demo`, which does this then runs this test)";
        let bin_mtime = bin
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or_else(|_| {
                panic!(
                    "mvm-libkrun-supervisor not found at {} — {how}",
                    bin.display()
                )
            });

        // `<manifest>/../` is `crates/`; the two crates whose sources
        // compile into the supervisor binary.
        let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates dir");
        let newest_src = newest_mtime(&crates_dir.join("mvm-libkrun/src"))
            .max(newest_mtime(&crates_dir.join("mvm-libkrun-supervisor/src")));
        assert!(
            bin_mtime >= newest_src,
            "mvm-libkrun-supervisor at {} is STALE (older than its sources) — {how}",
            bin.display()
        );
        bin
    })
}

/// Newest mtime of any file under `dir` (recursive), or the epoch if the
/// tree is empty/unreadable. Used to detect a supervisor binary built
/// before the sources that compile into it.
#[cfg(target_os = "macos")]
fn newest_mtime(dir: &std::path::Path) -> std::time::SystemTime {
    let mut newest = std::time::SystemTime::UNIX_EPOCH;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            let m = if p.is_dir() {
                newest_mtime(&p)
            } else {
                e.metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            };
            newest = newest.max(m);
        }
    }
    newest
}

/// On macOS the workload microVM must run via libkrun (vsock-capable).
/// On Linux the host's native Firecracker is correct. The E2E threads
/// `--hypervisor` through so it doesn't rely on `up`'s host-specific
/// auto-select choosing the same backend the test assumes.
fn workload_hypervisor() -> &'static str {
    if cfg!(target_os = "macos") {
        "libkrun"
    } else {
        "firecracker"
    }
}

#[test]
fn core_demo_dev_compile_up_ping() {
    if std::env::var("MVM_E2E_SMOKE").ok().as_deref() != Some("1") {
        eprintln!("skipping core-demo E2E; set MVM_E2E_SMOKE=1 to run");
        return;
    }
    let out = tempfile::tempdir().expect("tmp out");
    let app = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/python/hello-app/app.py"
    );

    // 1) builder VM up (idempotent).
    let dev_up = mvmctl(&["dev", "up"]);
    assert!(
        dev_up.status.success(),
        "dev up failed: {}",
        String::from_utf8_lossy(&dev_up.stderr)
    );

    // 2) lower the decorator app to flake.nix + launch.json.
    let c = mvmctl(&["compile", app, "--out", out.path().to_str().unwrap()]);
    assert!(
        c.status.success(),
        "compile failed: {}",
        String::from_utf8_lossy(&c.stderr)
    );

    // 3) build + boot the workload microVM; `up` waits for the agent.
    //    Exit 0 with no "not reachable" line == the agent answered.
    let up = mvmctl(&[
        "up",
        "--hypervisor",
        workload_hypervisor(),
        "--flake",
        out.path().to_str().unwrap(),
    ]);
    let log = String::from_utf8_lossy(&up.stderr);
    assert!(up.status.success(), "up failed: {log}");
    assert!(
        !log.contains("Guest agent not reachable"),
        "agent never answered: {log}"
    );

    // 4) tear down the builder (best-effort).
    let _ = mvmctl(&["dev", "down"]);
}
