//! Write-only console capture helpers shared by VMM backends.
//!
//! A sealed production guest must never have an interactive console input
//! path. Backends open the host-side log file with write-only, truncate-on-open
//! semantics so the host can read the log but cannot write to the guest console.

use std::io;
use std::path::Path;
use std::process::Stdio;

/// Open a write-only, truncated console log file.
///
/// This is the shared primitive used by every concrete backend to capture
/// guest console output without creating an interactive input channel.
pub fn open_console_capture(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
}

/// File name the per-VM supervisor's stderr is captured to inside a VM state
/// directory.
pub const SUPERVISOR_STDERR_LOG: &str = "supervisor.stderr.log";

/// Stderr for a per-VM supervisor that outlives the process spawning it.
///
/// Never `Stdio::inherit()` on the happy path, and that is the whole point. The
/// supervisor owns its guest for the VM's entire life, so an inherited stderr
/// keeps the *spawning* process's stderr file descriptor open for that entire
/// life. `mvmctl machine start` itself returns in well under a second, but any
/// caller that captures stderr through a pipe and reads to EOF never sees EOF:
/// `Command::output()`, Python's `subprocess.run(capture_output=True)` — which
/// is how the SDK's live transport shells every verb — or any `2>&1 |` pipeline.
/// Redirecting to a file instead makes the same command return immediately,
/// which is why the failure is invisible interactively at a TTY and only bites
/// under automation.
///
/// The fallback to `inherit` covers an unwritable state directory: losing the
/// supervisor's diagnostics entirely would be worse than a caller that hangs,
/// and a state dir that cannot be written is already a failing boot.
pub fn supervisor_stderr(state_dir: &Path) -> Stdio {
    open_console_capture(&state_dir.join(SUPERVISOR_STDERR_LOG))
        .map(Stdio::from)
        .unwrap_or_else(|_| Stdio::inherit())
}

/// How many trailing lines of the supervisor's stderr an error message carries.
const SUPERVISOR_STDERR_TAIL_LINES: usize = 20;

/// The supervisor's own last words, formatted as a suffix for a launch error.
///
/// A per-VM supervisor that dies before its guest exists writes nothing to the
/// guest console — the guest never ran — so an error naming only `console.log`
/// names an empty file. The reason it refused is on its stderr, and a transient
/// run deletes that file along with the state directory before anyone can open
/// it. Inlining the tail is the only way the reason reaches the person who ran
/// the command.
///
/// Returns an empty string when the supervisor said nothing, so a caller can
/// append it unconditionally.
///
/// Line-bounded and line-preserving, unlike the network endpoint's byte-bounded
/// `stderr_tail`, which collapses onto one line. A supervisor's refusal is an
/// `anyhow` report — a summary, a blank line, a `Caused by:` block — and
/// collapsing that is what makes it unreadable at exactly the moment it is the
/// only evidence there is.
pub fn supervisor_stderr_detail(state_dir: &Path) -> String {
    let path = state_dir.join(SUPERVISOR_STDERR_LOG);
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return String::new();
    };
    let lines = contents.lines().collect::<Vec<_>>();
    let tail = lines[lines.len().saturating_sub(SUPERVISOR_STDERR_TAIL_LINES)..].join("\n");
    let tail = tail.trim();
    if tail.is_empty() {
        return String::new();
    }
    format!(
        "\nsupervisor stderr ({}):\n{tail}{}",
        path.display(),
        stale_supervisor_hint(tail)
    )
}

/// The one diagnosis an unknown config field admits.
///
/// The host↔supervisor config types deny unknown fields, so a field the
/// supervisor does not recognise means its binary predates the `mvmctl` that
/// wrote the config — not a bad value. Nothing in the exit status the launch
/// path sees distinguishes that from any other refusal; only the stderr can.
///
/// The rebuild it names carries the running binary's own profile. Advising a
/// bare `cargo build` from a release `mvmctl` rebuilds the debug helper the
/// release one does not use, so the command appears to succeed and the next
/// launch fails identically.
///
/// It no longer advises re-signing. Both supervisors sign themselves on first
/// launch — `mvm-hvf-supervisor` from its own `main`, `mvm-libkrun-supervisor`
/// through `codesign::ensure_signed` — so a separate signing step was a fourth
/// instruction that never had to be followed, in a message read by someone
/// already several layers from the cause.
fn stale_supervisor_hint(stderr_tail: &str) -> String {
    if !stderr_tail.contains("unknown field") {
        return String::new();
    }
    let profile = std::env::current_exe()
        .ok()
        .as_deref()
        .and_then(crate::host::aux_bin::build_profile_of);
    format!(
        "\n\nThat supervisor binary is older than this mvmctl: it refused a config field \
         this build sends. Rebuild it with `{}`. It signs itself on first launch, so no \
         separate signing step is needed.",
        helper_rebuild_command(profile)
    )
}

/// The rebuild command to print, for a running binary of `profile`.
///
/// `None` — an installed binary, or a test harness under `target/<p>/deps` —
/// falls back to cargo's default profile. That is the safe direction: the debug
/// form is what a contributor most often wants, and naming `--release` to
/// someone who is not running a release binary would have them rebuild a helper
/// they do not use and watch the next launch fail identically.
fn helper_rebuild_command(profile: Option<crate::host::aux_bin::BuildProfile>) -> String {
    let flag = profile.map_or("", crate::host::aux_bin::BuildProfile::cargo_flag);
    format!("cargo build{flag} -p mvm-hostd --bins")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_stderr_creates_the_log_inside_the_state_dir() {
        let dir = tempfile::tempdir().unwrap();
        let _stdio = supervisor_stderr(dir.path());
        let log = dir.path().join(SUPERVISOR_STDERR_LOG);
        assert!(
            log.is_file(),
            "supervisor stderr must land in a file, not the caller's fd: {} missing",
            log.display()
        );
    }

    #[test]
    fn supervisor_stderr_truncates_a_previous_boots_log() {
        // Each boot's diagnostics stand alone; a stale tail read as this boot's
        // is how a fixed build looks broken.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join(SUPERVISOR_STDERR_LOG);
        std::fs::write(&log, b"previous boot noise").unwrap();
        let _stdio = supervisor_stderr(dir.path());
        assert_eq!(std::fs::read(&log).unwrap(), b"");
    }

    #[test]
    fn supervisor_stderr_falls_back_when_the_state_dir_is_absent() {
        // Must not panic: an unwritable state dir is a failing boot that should
        // report its own error, not abort inside stdio setup.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-state-dir");
        let _stdio = supervisor_stderr(&missing);
    }

    #[test]
    fn failure_detail_carries_the_supervisor_stderr_into_the_message() {
        // The whole point: a transient run deletes the state dir, so a message
        // that only names the file leaves nothing to read.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(SUPERVISOR_STDERR_LOG),
            b"Error: parse HvfSupervisorConfig JSON from stdin\n",
        )
        .unwrap();
        let detail = supervisor_stderr_detail(dir.path());
        assert!(
            detail.contains("parse HvfSupervisorConfig JSON from stdin"),
            "stderr must be inlined, got: {detail}"
        );
        assert!(detail.contains(SUPERVISOR_STDERR_LOG), "got: {detail}");
    }

    #[test]
    fn failure_detail_is_empty_when_the_supervisor_said_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(supervisor_stderr_detail(dir.path()), "");
        std::fs::write(dir.path().join(SUPERVISOR_STDERR_LOG), b"   \n\n").unwrap();
        assert_eq!(supervisor_stderr_detail(dir.path()), "");
    }

    #[test]
    fn failure_detail_keeps_only_the_tail_of_a_long_log() {
        let dir = tempfile::tempdir().unwrap();
        let body: String = (0..200).map(|i| format!("line {i}\n")).collect();
        std::fs::write(dir.path().join(SUPERVISOR_STDERR_LOG), body).unwrap();
        let detail = supervisor_stderr_detail(dir.path());
        assert!(detail.contains("line 199"), "tail must survive: {detail}");
        assert!(
            !detail.contains("line 0\n"),
            "head must be dropped: {detail}"
        );
    }

    #[test]
    fn failure_detail_names_the_rebuild_when_the_supervisor_is_older_than_the_host() {
        // An unknown config field means one thing only: the binary predates the
        // mvmctl that wrote the config. Say so, and name the fix.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(SUPERVISOR_STDERR_LOG),
            b"unknown field `vcpus`, expected one of `kernel`, `cmdline`\n",
        )
        .unwrap();
        let detail = supervisor_stderr_detail(dir.path());
        assert!(
            detail.contains("-p mvm-hostd --bins"),
            "an unknown field must name the rebuild: {detail}"
        );
        assert!(
            !detail.contains("mvmctl env sign"),
            "both supervisors self-sign; a signing step is an instruction that \
             never has to be followed: {detail}"
        );
    }

    /// A bare `cargo build` run from a release mvmctl rebuilds the debug helper
    /// the release one does not use: the command succeeds and the next launch
    /// fails identically. The flag has to follow the binary being run.
    #[test]
    fn the_rebuild_command_carries_the_running_binarys_profile() {
        use crate::host::aux_bin::BuildProfile;

        assert_eq!(
            helper_rebuild_command(Some(BuildProfile::Release)),
            "cargo build --release -p mvm-hostd --bins"
        );
        assert_eq!(
            helper_rebuild_command(Some(BuildProfile::Debug)),
            "cargo build -p mvm-hostd --bins"
        );
        // An installed binary, or this very test harness, which sits under
        // `target/<profile>/deps` and so reads as no profile at all.
        assert_eq!(
            helper_rebuild_command(None),
            "cargo build -p mvm-hostd --bins"
        );
    }

    #[test]
    fn failure_detail_leaves_an_ordinary_error_without_a_rebuild_hint() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(SUPERVISOR_STDERR_LOG),
            b"Error: create vcpu: HV_ERROR\n",
        )
        .unwrap();
        let detail = supervisor_stderr_detail(dir.path());
        assert!(!detail.contains("-p mvm-hostd --bins"), "got: {detail}");
        assert!(detail.contains("HV_ERROR"), "got: {detail}");
    }
}
