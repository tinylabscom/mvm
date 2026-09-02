//! Steps for the end-to-end launch suite: every README-documented way to get a
//! workload running, driven against a real guest on whatever backend this host
//! actually has.
//!
//! Deliberately not `@firecracker`-tagged. The existing live README scenario is,
//! which means it is skipped everywhere without `/dev/kvm` — so on macOS, where
//! HVF is the default backend, nothing in the suite ever booted a guest. A
//! launch regression that only reproduced on the macOS default therefore had no
//! lane that could see it. These scenarios run wherever `mvmctl` can boot.
//!
//! The other difference from the existing live steps is the home. Those use a
//! fresh `tempfile::tempdir()` per scenario, so every scenario re-acquires the
//! kernel, the runtime overlay, the initramfs and the OCI rootfs from cold —
//! minutes each, which is why only one such scenario exists. A launch suite has
//! to cover a dozen shapes, so these share one artifact-warm home for the whole
//! run and pay that cost once.

use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use cucumber::{given, then, when};
use mvm_conformance::IsolatedHome;

use crate::steps::cli::{mvmctl_command, workspace_root};
use crate::world::{CliWorld, LaunchRecord};

/// Env var naming the artifact-warm `MVM_HOME` these scenarios share.
///
/// Unset means the operator's real home, which is the point when running this
/// locally: it is the cache a developer's own launches use, so a boot budget
/// measured against it is the budget they actually experience.
const E2E_HOME_ENV: &str = "MVM_E2E_HOME";

/// Console lines that mean the guest never reached a working control plane.
///
/// Each is a real failure this suite exists to catch. They are matched on the
/// guest console rather than on the exit status because the host's own error
/// for all of them is the same unhelpful readiness timeout — "guest agent did
/// not become reachable within 30s" — which names none of them.
const GUEST_BOOT_FAILURES: &[(&str, &str)] = &[
    (
        "Kernel panic",
        "PID 1 exited, so the kernel panicked; the lines above it say why",
    ),
    (
        "no guest agent resolved",
        "/mvm/runtime was empty at boot: the runtime overlay was not mounted",
    ),
    (
        "no egress client resolved",
        "/mvm/runtime carried no egress client, so admitted egress was unreachable",
    ),
    (
        "refusing to boot",
        "the guest init fail-closed on a missing part of the runtime",
    ),
];

pub(crate) fn e2e_home() -> PathBuf {
    std::env::var_os(E2E_HOME_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(mvm_core::config::mvm_home()))
}

/// Parse `dispatch_window=<n>ms` out of the `phase-timing` line.
///
/// Read from the CLI's own emitted timing rather than measured around the
/// process, so the number asserted is the number the launch budget is defined
/// in: guest-dispatchable, excluding process startup and teardown.
fn parse_dispatch_window_ms(output: &str) -> Option<f64> {
    output
        .lines()
        .find(|line| line.contains("phase-timing:"))?
        .split_whitespace()
        .find_map(|token| token.strip_prefix("dispatch_window="))?
        .strip_suffix("ms")?
        .parse()
        .ok()
}

/// Split a scenario's argument string into argv, honouring single quotes.
///
/// Whitespace-splitting is what the older CLI steps do, and it cannot express
/// the shape most of these scenarios need: `-- sh -c 'echo hello'` is one argv
/// entry, not two. Single quotes only — the feature text is already inside
/// cucumber's double-quoted `{string}`, so double quotes cannot appear here.
fn shell_split(args: &str) -> Vec<String> {
    let mut argv = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut started = false;

    for ch in args.chars() {
        match ch {
            '\'' => {
                in_quotes = !in_quotes;
                // A quote begins a token even when the quoted body is empty,
                // so `''` survives as a real (empty) argument.
                started = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if started {
                    argv.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }
    assert!(
        !in_quotes,
        "unbalanced single quote in argument string {args:?}"
    );
    if started {
        argv.push(current);
    }
    argv
}

fn run_in_e2e_home(args: &str, extra_env: &[(&str, &str)]) -> LaunchRecord {
    let home = e2e_home();
    let mut command: Command = mvmctl_command();
    command
        .current_dir(workspace_root())
        .args(shell_split(args))
        .isolated_home(&home)
        .env("MVM_PHASE_TIMING", "1");
    for (key, value) in extra_env {
        command.env(key, value);
    }

    // The runtime-SDK scenarios hand `mvmctl` a Python script that imports
    // `mvm`, and the in-repo SDK is not installed into any interpreter. Put it
    // on the import path the same way the SDK scenarios do, so `run --mode
    // plan|live` exercises the real transport rather than failing on an import.
    let sdk_python = workspace_root().join("crates/mvm-sdk/sdks/python");
    let pythonpath = match std::env::var_os("PYTHONPATH") {
        Some(existing) => {
            let mut paths = vec![sdk_python];
            paths.extend(std::env::split_paths(&existing));
            std::env::join_paths(paths).expect("join Python SDK import paths")
        }
        None => sdk_python.into_os_string(),
    };
    command.env("PYTHONPATH", pythonpath);

    let started = Instant::now();
    let output = command.output().expect("failed to spawn mvmctl");
    let wall = started.elapsed();

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let dispatch_window_ms =
        parse_dispatch_window_ms(&stdout).or_else(|| parse_dispatch_window_ms(&stderr));

    LaunchRecord {
        stdout,
        stderr,
        exit_code: output.status.code().unwrap_or(-1),
        dispatch_window_ms,
        wall,
    }
}

#[given(expr = "an artifact-warm mvm home")]
fn artifact_warm_home(world: &mut CliWorld) {
    let home = e2e_home();
    assert!(
        home.is_dir(),
        "the e2e suite needs an artifact-warm MVM_HOME at {}. Run `mvmctl bootstrap` \
         first, or point {E2E_HOME_ENV} at a home that has one. These scenarios boot \
         real guests; acquiring the kernel, overlay and initramfs from cold inside a \
         scenario would take minutes each.",
        home.display()
    );
    world.e2e_home = Some(home);
}

/// Remove a named machine left behind by an earlier run, ignoring the common
/// case where there is nothing to remove.
///
/// These scenarios deliberately share the operator's real, artifact-warm home
/// rather than a fresh tempdir, so persistent state outlives a run — and a
/// scenario that fails halfway leaves its machine registered. Without this the
/// *next* run fails at `machine create` with "already exists", which reads as a
/// launch regression rather than as residue.
#[given(expr = "no machine named {string}")]
fn no_machine_named(_world: &mut CliWorld, name: String) {
    let _ = run_in_e2e_home(&format!("machine stop {name} --yes"), &[]);
    let _ = run_in_e2e_home(&format!("machine rm {name} --yes"), &[]);
}

#[when(expr = "I launch {string}")]
fn launch(world: &mut CliWorld, args: String) {
    world.last_launch = Some(run_in_e2e_home(&args, &[]));
}

#[when(expr = "I launch {string} with env {string} set to {string}")]
fn launch_with_env(world: &mut CliWorld, args: String, key: String, value: String) {
    world.last_launch = Some(run_in_e2e_home(&args, &[(&key, &value)]));
}

/// How long an interactive launch is given before the PTY read is abandoned.
///
/// Generous on purpose: this is a real cold boot on whatever backend the host
/// has, and a timeout that fires early would report a slow machine as a broken
/// console. Nothing hangs on it in the passing case — the read ends when the
/// child closes the PTY.
const INTERACTIVE_LAUNCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(240);

/// Run `mvmctl` with a real terminal on its stdin.
///
/// `-t`/`--tty` refuses outright without one — "interactive `-t`/`--tty` needs
/// a terminal on stdin" — so every other step in this file, which drives
/// `Command::output()` over piped stdin, stops at the CLI before the guest is
/// ever asked to open a console. That is exactly why a guest whose `openpty()`
/// failed on every OCI image passed this suite.
///
/// The child gets the PTY slave on all three descriptors and the parent keeps
/// the master, reading until EOF. stdout and stderr are the same stream on a
/// terminal, which is what a terminal is; the record carries the combined
/// bytes in `stdout` and leaves `stderr` empty.
fn run_interactive_in_e2e_home(args: &str) -> LaunchRecord {
    use std::io::Read;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::process::Stdio;

    let pty =
        nix::pty::openpty(None, None).expect("allocate a host PTY for the interactive launch");
    let (master, slave): (OwnedFd, OwnedFd) = (pty.master, pty.slave);

    let home = e2e_home();
    let mut command: Command = mvmctl_command();
    command
        .current_dir(workspace_root())
        .args(shell_split(args))
        .isolated_home(&home)
        .env("MVM_PHASE_TIMING", "1")
        // A terminal the guest shell can actually address. Without it the
        // shell falls back to `dumb` and some images print nothing at all,
        // which would read as a console failure.
        .env("TERM", "xterm")
        .stdin(Stdio::from(
            slave.try_clone().expect("dup the PTY slave for stdin"),
        ))
        .stdout(Stdio::from(
            slave.try_clone().expect("dup the PTY slave for stdout"),
        ))
        .stderr(Stdio::from(slave));

    let started = Instant::now();
    let mut child = command.spawn().expect("failed to spawn mvmctl on a PTY");
    // The parent's copy of the slave is gone once `command` is dropped; only
    // the child holds one. Without that the master never sees EOF and the read
    // below blocks for the full timeout on a *successful* run.
    drop(command);

    let (tx, rx) = std::sync::mpsc::channel();
    let master_fd = master.as_raw_fd();
    std::thread::spawn(move || {
        // SAFETY: `master_fd` is the live PTY master owned by `master` in the
        // parent frame, which outlives this read: the frame joins on `rx`
        // before dropping it.
        let mut reader =
            unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(master_fd) };
        let mut buf = Vec::new();
        // EIO is how a PTY master reports "the last slave closed" on Linux,
        // and it arrives instead of EOF. Whatever was read before it is the
        // session's output, not an error.
        let _ = reader.read_to_end(&mut buf);
        std::mem::forget(reader);
        let _ = tx.send(buf);
    });

    let combined = rx
        .recv_timeout(INTERACTIVE_LAUNCH_TIMEOUT)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_else(|_| {
            let _ = child.kill();
            String::new()
        });
    let status = child.wait().expect("wait for the interactive mvmctl");
    let wall = started.elapsed();
    drop(master);

    let dispatch_window_ms = parse_dispatch_window_ms(&combined);
    LaunchRecord {
        stdout: combined,
        stderr: String::new(),
        exit_code: status.code().unwrap_or(-1),
        dispatch_window_ms,
        wall,
    }
}

#[when(expr = "I launch {string} on a terminal")]
fn launch_on_a_terminal(world: &mut CliWorld, args: String) {
    world.last_launch = Some(run_interactive_in_e2e_home(&args));
}

/// The guest's controlling terminal must be a `devpts` slave.
///
/// `tty` printing `/dev/pts/N` is the whole claim: it means `openpty()` found
/// the slave filesystem, which is the mount whose absence produced "console
/// open failed: openpty() failed" on every OCI image. `not a tty` is the
/// answer when the console was never allocated, and a bare path check would
/// accept it.
#[then(expr = "the guest console is a pseudo-terminal")]
fn guest_console_is_a_pty(world: &mut CliWorld) {
    let record = last(world);
    let output = record.combined();
    assert!(
        output.contains("/dev/pts/"),
        "the guest's controlling terminal must be a devpts slave (`/dev/pts/N`), \
         which is what proves the guest mounted devpts and openpty() succeeded. \
         Got:\n{output}"
    );
    assert!(
        !output.contains("openpty() failed"),
        "the guest could not allocate a PTY: {output}"
    );
}

fn last(world: &CliWorld) -> &LaunchRecord {
    world
        .last_launch
        .as_ref()
        .expect("a launch step must run before this assertion")
}

#[then(expr = "the launch succeeds")]
fn launch_succeeds(world: &mut CliWorld) {
    let record = last(world);
    assert_eq!(
        record.exit_code, 0,
        "launch exited {}.\n--- stdout ---\n{}\n--- stderr ---\n{}",
        record.exit_code, record.stdout, record.stderr
    );
}

#[then(expr = "the launch fails")]
fn launch_fails(world: &mut CliWorld) {
    let record = last(world);
    assert_ne!(
        record.exit_code, 0,
        "launch was expected to fail but exited 0.\n--- stdout ---\n{}",
        record.stdout
    );
}

#[then(expr = "the launch exits with code {int}")]
fn launch_exits_with(world: &mut CliWorld, code: i64) {
    let record = last(world);
    assert_eq!(
        record.exit_code, code as i32,
        "expected exit {code}, got {}.\n--- stderr ---\n{}",
        record.exit_code, record.stderr
    );
}

/// Assert on the guest's own stdout, never the combined streams.
///
/// `combined()` carries the CLI's diagnostics too — including the
/// `MVM_PHASE_TIMING` table, which is full of digits. A short expectation like
/// `"2"` matched that noise and passed without the guest ever printing it. The
/// guest's output arrives on stdout; the diagnostics do not.
#[then(expr = "the guest printed {string}")]
fn guest_printed(world: &mut CliWorld, expected: String) {
    let record = last(world);
    assert!(
        record.stdout.contains(&expected),
        "guest stdout did not contain {expected:?}.\n--- stdout ---\n{}\n--- stderr ---\n{}",
        record.stdout,
        record.stderr
    );
}

/// Assert the guest's stdout is exactly one line with this content.
///
/// For a one-word answer like `nproc`, `contains` is too weak to be worth
/// asserting: "1" is a substring of "16". This pins the whole line.
#[then(expr = "the guest printed exactly {string}")]
fn guest_printed_exactly(world: &mut CliWorld, expected: String) {
    let record = last(world);
    let actual = record.stdout.trim();
    assert_eq!(
        actual, expected,
        "guest stdout was {actual:?}, expected exactly {expected:?}.\n--- stderr ---\n{}",
        record.stderr
    );
}

/// Assert the guest's *last* stdout line.
///
/// `the guest printed exactly` compares the whole of stdout, which is right
/// when the command's output is all there is. It is wrong whenever mvm prints
/// chrome first: a `[mvm]` warning is not a defect and not guest output, but it
/// arrives on the same stream in the plain (non-JSON) case — deliberately, and
/// consistently across the CLI. Verbs that emit a machine-readable envelope
/// route chrome to stderr instead (`set_chrome_to_stderr`), so nothing is
/// polluted there.
///
/// Still strict about the value: `contains` would pass "1" against "16".
#[then(expr = "the guest's last line is {string}")]
fn guest_last_line_is(world: &mut CliWorld, expected: String) {
    let record = last(world);
    let actual = record
        .stdout
        .lines()
        .rfind(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim();
    assert_eq!(
        actual, expected,
        "guest's last stdout line was {actual:?}, expected {expected:?}.\n--- stdout ---\n{}",
        record.stdout
    );
}

#[then(expr = "the output mentions {string}")]
fn output_mentions(world: &mut CliWorld, expected: String) {
    let record = last(world);
    assert!(
        record.combined().contains(&expected),
        "output did not mention {expected:?}.\n--- combined ---\n{}",
        record.combined()
    );
}

/// The regression guard proper.
///
/// A guest that boots without its runtime overlay dies as a kernel panic, and
/// the host reports only an agent-readiness timeout. Asserting on the console
/// signature instead means the failure names itself.
#[then(expr = "the guest control plane came up")]
fn guest_control_plane_came_up(world: &mut CliWorld) {
    let record = last(world);
    let combined = record.combined();
    for (needle, meaning) in GUEST_BOOT_FAILURES {
        assert!(
            !combined.contains(needle),
            "guest console carries {needle:?} — {meaning}.\n--- combined ---\n{combined}"
        );
    }
    assert!(
        !combined.contains("did not become reachable"),
        "the guest agent never became reachable.\n--- combined ---\n{combined}"
    );
}

#[then(expr = "the warm launch meets its hard dispatch ceiling")]
fn warm_launch_meets_hard_dispatch_ceiling(world: &mut CliWorld) {
    let record = last(world);
    let observed = record.dispatch_window_ms.unwrap_or_else(|| {
        panic!(
            "no `phase-timing: ... dispatch_window=` line in the launch output, so the \
             boot budget could not be measured at all.\n--- combined ---\n{}",
            record.combined()
        )
    });
    assert!(
        mvm_cli::launch_contract::within_warm_start_slo_ms(observed),
        "dispatch window was {observed:.1}ms; the warm-claim contract is strictly under {:.0}ms",
        mvm_cli::launch_contract::WARM_START_MAX_MS,
    );
}

/// Record the budget without failing on it.
///
/// The cold dispatch window on this host is a known open number tracked
/// separately from correctness; a suite that fails on it would be red for a
/// reason unrelated to whether the launch modes work, and would stop being run.
/// Printing it keeps the number visible on every run instead.
#[then(expr = "the dispatch window is recorded")]
fn dispatch_window_recorded(world: &mut CliWorld) {
    let record = last(world);
    match record.dispatch_window_ms {
        Some(ms) => println!("[e2e] dispatch window: {ms:.1}ms (wall {:?})", record.wall),
        None => println!(
            "[e2e] dispatch window: not reported (wall {:?})",
            record.wall
        ),
    }
}

mod tests {
    #[test]
    fn shell_split_keeps_a_quoted_command_as_one_argument() {
        assert_eq!(
            super::shell_split("machine run --image alpine -- sh -c 'echo hello world'"),
            vec![
                "machine",
                "run",
                "--image",
                "alpine",
                "--",
                "sh",
                "-c",
                "echo hello world",
            ],
        );
    }

    #[test]
    fn shell_split_handles_plain_whitespace_arguments() {
        assert_eq!(super::shell_split("machine ls"), vec!["machine", "ls"]);
    }

    #[test]
    fn shell_split_preserves_an_empty_quoted_argument() {
        assert_eq!(super::shell_split("run ''"), vec!["run", ""]);
    }

    #[test]
    #[should_panic(expected = "unbalanced single quote")]
    fn shell_split_refuses_an_unbalanced_quote() {
        // Silently dropping the rest of a malformed argument string would make
        // a scenario assert against a command it did not mean to run.
        super::shell_split("machine run -- sh -c 'oops");
    }
}
