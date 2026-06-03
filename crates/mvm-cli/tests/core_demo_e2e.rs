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
//!
//! NO-FREEZE design (this test cost multiple whole sessions, frozen).
//! Two independent guards make a hang impossible:
//!   1. A process-level **watchdog** thread (`arm_watchdog`) that
//!      `exit(124)`s after a hard deadline — the test process can never
//!      run forever regardless of any orphaned child.
//!   2. Every `mvmctl` call is **bounded**: stdio is redirected to files
//!      (so nothing captures a pipe an orphaned gvproxy could hold open —
//!      the original `Command::output()` EOF-wait freeze) and the child
//!      is spawned in its own process group, SIGKILLed whole on timeout.

use assert_cmd::cargo::CommandCargoExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Per-step wall-clock ceilings. The in-VM `nix build` on first `up`
/// and a cold builder-VM image build on first `dev up` are the long
/// poles; everything else is seconds. On expiry the step's process
/// group is SIGKILLed and the step is reported as timed out.
const DEV_UP_BUDGET: Duration = Duration::from_secs(900);
const COMPILE_BUDGET: Duration = Duration::from_secs(180);
const UP_BUDGET: Duration = Duration::from_secs(900);
const DOWN_BUDGET: Duration = Duration::from_secs(120);

/// Outcome of one bounded `mvmctl` invocation.
struct Step {
    success: bool,
    /// stdout + stderr concatenated. mvm's UI (`ui::info`/`ui::warn`)
    /// writes to **stdout**, while build/runtime errors land on stderr,
    /// so any assertion on mvm output must scan both — checking only one
    /// stream silently misses the other (e.g. "Guest agent not
    /// reachable." is a `ui::warn` on stdout).
    output: String,
    timed_out: bool,
}

/// Run `mvmctl <args>` bounded by `budget`, capturing stdout/stderr to
/// `<scratch>/<label>.{stdout,stderr}.log`. NEVER blocks on a pipe: the
/// freeze that cost us multiple sessions was `Command::output()` waiting
/// on pipe EOF that an orphaned gvproxy held open (libkrun `exit()`s on
/// guest poweroff, skipping `GvproxyHandle::Drop`). Here stdio goes to
/// files (no pipe to hold) and the child runs in its own process group,
/// SIGKILLed whole on timeout so the supervisor + gvproxy are reaped.
fn mvmctl(args: &[&str], scratch: &std::path::Path, label: &str, budget: Duration) -> Step {
    let out_path = scratch.join(format!("{label}.stdout.log"));
    let err_path = scratch.join(format!("{label}.stderr.log"));
    let out_f = std::fs::File::create(&out_path).expect("create stdout log");
    let err_f = std::fs::File::create(&err_path).expect("create stderr log");

    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("mvmctl").expect("locate mvmctl");
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out_f))
        .stderr(Stdio::from(err_f))
        // Own process group (pgid == child pid) so a timeout can SIGKILL
        // the whole tree — mvmctl, its supervisor, and gvproxy.
        .process_group(0);
    // The E2E pins the builder backend to libkrun on macOS so the test
    // doesn't depend on the Swift mvm-vz-supervisor having been built.
    // Plan 98's auto-select would otherwise pick Vz on macOS 26+ Apple
    // Silicon and bail with "mvm-vz-supervisor binary not found." Both
    // pins are per-child so they don't leak into other tests in the same
    // cargo invocation.
    #[cfg(target_os = "macos")]
    {
        cmd.env("MVM_BUILDER_BACKEND", "libkrun");
        // Pin the libkrun supervisor to a freshly built binary. `cargo
        // test -p mvm-cli` does NOT rebuild the separate
        // `mvm-libkrun-supervisor` bin crate (mvm-cli doesn't depend on
        // it), so without this the test execs whatever stale supervisor
        // sits next to mvmctl. `resolve_supervisor_path` honors this
        // override ahead of the next-to-exe fallback.
        cmd.env("MVM_LIBKRUN_SUPERVISOR_PATH", libkrun_supervisor_path());
    }

    let mut child = cmd.spawn().expect("spawn mvmctl");
    let pgid = child.id() as i32;
    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait().expect("try_wait mvmctl") {
            Some(s) => break Some(s),
            None if start.elapsed() >= budget => {
                // SIGKILL the whole process group, then reap the leader.
                // SAFETY: pgid is this child's own group (process_group(0)).
                unsafe { libc::kill(-pgid, libc::SIGKILL) };
                let _ = child.wait();
                timed_out = true;
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(200)),
        }
    };

    let mut output = std::fs::read_to_string(&out_path).unwrap_or_default();
    output.push_str(&std::fs::read_to_string(&err_path).unwrap_or_default());
    Step {
        success: status.map(|s| s.success()).unwrap_or(false),
        output,
        timed_out,
    }
}

/// Arm a hard process-level deadline. If the test is still alive after
/// `secs`, print a pointer to the per-step logs and `exit(124)` so the
/// process can never hang the session — a backstop above the per-step
/// timeouts in `mvmctl`. Override via `MVM_E2E_DEADLINE_SECS`.
fn arm_watchdog(secs: u64, scratch: std::path::PathBuf) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(secs));
        eprintln!(
            "core_demo_e2e WATCHDOG: hard deadline {secs}s hit — aborting to \
             avoid a frozen session. Per-step logs: {}",
            scratch.display()
        );
        std::process::exit(124);
    });
}

/// Stable, non-auto-deleted scratch dir for step logs + the compiled
/// flake, so a failure (or a watchdog `exit`, which skips destructors)
/// leaves logs behind for triage. Cleaned at the start of each run.
/// Override via `MVM_E2E_SCRATCH`.
fn scratch_dir() -> std::path::PathBuf {
    let d = std::env::var_os("MVM_E2E_SCRATCH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("mvm-core-demo-e2e"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("create scratch dir");
    d
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

    let scratch = scratch_dir();
    eprintln!(
        "core_demo_e2e scratch (logs + compiled flake): {}",
        scratch.display()
    );

    let deadline = std::env::var("MVM_E2E_DEADLINE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2400);
    arm_watchdog(deadline, scratch.clone());

    let out = scratch.join("compiled");
    std::fs::create_dir_all(&out).expect("create compile out dir");
    let app = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/python/hello-app/app.py"
    );

    // 1) builder VM up (idempotent).
    let dev_up = mvmctl(&["dev", "up"], &scratch, "dev-up", DEV_UP_BUDGET);
    assert!(
        !dev_up.timed_out,
        "dev up timed out (>{DEV_UP_BUDGET:?}); output:\n{}",
        dev_up.output
    );
    assert!(dev_up.success, "dev up failed: {}", dev_up.output);

    // 2) lower the decorator app to flake.nix + launch.json.
    let c = mvmctl(
        &["compile", app, "--out", out.to_str().unwrap()],
        &scratch,
        "compile",
        COMPILE_BUDGET,
    );
    assert!(
        !c.timed_out,
        "compile timed out (>{COMPILE_BUDGET:?}); output:\n{}",
        c.output
    );
    assert!(c.success, "compile failed: {}", c.output);

    // 3) build + boot the workload microVM; `up` waits for the agent
    //    over vsock (`wait_for_guest_agent` → protocol Ping). The proof
    //    is twofold and scans BOTH streams (`up.output`): the wait
    //    actually ran ("Waiting for guest agent...") AND it succeeded
    //    (no "Guest agent not reachable."). Checking only one of these
    //    is how this test previously false-greened — `up` used to skip
    //    the wait entirely on libkrun, and the warn line lands on
    //    stdout, not stderr.
    let up = mvmctl(
        &[
            "up",
            "--hypervisor",
            workload_hypervisor(),
            "--flake",
            out.to_str().unwrap(),
        ],
        &scratch,
        "up",
        UP_BUDGET,
    );
    assert!(
        !up.timed_out,
        "up timed out (>{UP_BUDGET:?}); output:\n{}",
        up.output
    );
    assert!(up.success, "up failed: {}", up.output);
    assert!(
        up.output.contains("Waiting for guest agent"),
        "up never waited for the guest agent (boot→ping not exercised): {}",
        up.output
    );
    assert!(
        !up.output.contains("Guest agent not reachable"),
        "guest agent never answered the vsock ping: {}",
        up.output
    );

    // 4) tear down the builder (best-effort, still bounded).
    let _ = mvmctl(&["dev", "down"], &scratch, "dev-down", DOWN_BUDGET);
}
