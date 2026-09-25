//! Tests for `scripts/smoke-fresh-install.sh`, the release gate that installs a
//! tag into a throwaway HOME and runs the README's first command.
//!
//! The real smoke needs a published release and a host that boots guests, so
//! these drive the script with a stand-in installer that puts a fake `mvmctl`
//! on the throwaway PATH. What is under test is the verdict: a smoke that
//! cannot go red is a gate that reports green over a broken release.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/smoke-fresh-install.sh")
}

/// An installer that writes `mvmctl_body` to `$HOME/.local/bin/mvmctl`, and
/// exits with `status`.
fn stand_in_installer(dir: &Path, mvmctl_body: &str, status: i32) -> PathBuf {
    let installer = dir.join("install.sh");
    let script = format!(
        "#!/bin/sh\nset -eu\nmkdir -p \"$HOME/.local/bin\"\ncat > \"$HOME/.local/bin/mvmctl\" <<'MVMCTL'\n{mvmctl_body}\nMVMCTL\nchmod 0755 \"$HOME/.local/bin/mvmctl\"\necho installed\nexit {status}\n"
    );
    std::fs::write(&installer, script).unwrap();
    installer
}

/// A fake `mvmctl` that reports `version` and answers `machine run` with
/// `run_body`, which sees the command's argv as `"$@"` after `machine run`.
fn fake_mvmctl(version: &str, run_body: &str) -> String {
    format!(
        "#!/bin/sh\ncase \"$1\" in\n  --version) echo 'mvmctl {version}' ;;\n  machine) shift 2\n{run_body}\n    ;;\nesac"
    )
}

/// Echo the argument after `--`, as a guest would.
const ECHO_TOKEN: &str =
    "    while [ \"$1\" != -- ]; do shift; done; shift; [ \"$1\" = echo ] && shift; echo \"$1\"";

struct Smoke {
    dir: tempfile::TempDir,
}

impl Smoke {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn out(&self) -> PathBuf {
        self.dir.path().join("out")
    }

    fn run(&self, installer: &Path, version: Option<&str>, envs: &[(&str, &str)]) -> Output {
        let mut command = Command::new("sh");
        command
            .arg(script())
            .env("MVM_SMOKE_INSTALLER", installer)
            .env("MVM_SMOKE_OUT", self.out())
            .env_remove("GITHUB_ACTIONS")
            .env_remove("GITHUB_STEP_SUMMARY");
        if let Some(version) = version {
            command.arg(version);
        }
        for (key, value) in envs {
            command.env(key, value);
        }
        command.output().unwrap()
    }

    fn transcript(&self) -> String {
        std::fs::read_to_string(self.out().join("transcript.log")).unwrap_or_default()
    }
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn a_first_command_that_prints_the_token_passes() {
    let smoke = Smoke::new();
    let installer = stand_in_installer(smoke.dir.path(), &fake_mvmctl("1.2.3", ECHO_TOKEN), 0);

    let output = smoke.run(&installer, Some("v1.2.3"), &[]);

    assert!(output.status.success(), "{}", combined(&output));
    let transcript = smoke.transcript();
    assert!(
        transcript.contains("PASS: mvmctl 1.2.3 installed in"),
        "{transcript}"
    );
    assert!(
        transcript.contains("mvmctl machine run --image alpine -- echo mvm-fresh-install-"),
        "the transcript must name the command it ran: {transcript}"
    );
}

#[test]
fn a_first_command_that_exits_zero_without_the_token_fails() {
    let smoke = Smoke::new();
    let installer = stand_in_installer(
        smoke.dir.path(),
        &fake_mvmctl("1.2.3", "    echo 'booted, but said nothing'"),
        0,
    );

    let output = smoke.run(&installer, Some("v1.2.3"), &[]);

    assert_eq!(output.status.code(), Some(1), "{}", combined(&output));
    assert!(
        smoke
            .transcript()
            .contains("exited 0 without printing mvm-fresh-install-"),
        "{}",
        smoke.transcript()
    );
}

#[test]
fn a_first_command_that_fails_fails_the_smoke() {
    let smoke = Smoke::new();
    let installer = stand_in_installer(
        smoke.dir.path(),
        &fake_mvmctl(
            "0.18.0-rc.1",
            "    echo 'initramfs version mismatch: expected 0.18.0-rc.1, got Some(\"0.18.0\")' >&2; exit 1",
        ),
        0,
    );

    let output = smoke.run(&installer, Some("v0.18.0-rc.1"), &[]);

    assert_eq!(output.status.code(), Some(1), "{}", combined(&output));
    let transcript = smoke.transcript();
    assert!(
        transcript.contains("FAIL: the first command exited 1"),
        "{transcript}"
    );
    assert!(
        transcript.contains("initramfs version mismatch"),
        "the transcript must carry the command's stderr: {transcript}"
    );
}

#[test]
fn a_first_command_over_budget_fails_and_is_stopped() {
    let smoke = Smoke::new();
    let installer = stand_in_installer(
        smoke.dir.path(),
        &fake_mvmctl("1.2.3", "    exec sleep 600"),
        0,
    );

    let started = std::time::Instant::now();
    let output = smoke.run(
        &installer,
        Some("v1.2.3"),
        &[("MVM_SMOKE_RUN_BUDGET_SECS", "2")],
    );

    assert_eq!(output.status.code(), Some(1), "{}", combined(&output));
    assert!(
        smoke
            .transcript()
            .contains("FAIL: the first command did not finish within 2s"),
        "{}",
        smoke.transcript()
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(120),
        "the budget must stop the command, not wait for it"
    );
}

#[test]
fn a_failed_install_fails_before_any_first_command() {
    let smoke = Smoke::new();
    let installer = stand_in_installer(smoke.dir.path(), &fake_mvmctl("1.2.3", ECHO_TOKEN), 3);

    let output = smoke.run(&installer, Some("v1.2.3"), &[]);

    assert_eq!(output.status.code(), Some(1), "{}", combined(&output));
    let transcript = smoke.transcript();
    assert!(
        transcript.contains("FAIL: the install exited 3"),
        "{transcript}"
    );
    assert!(
        !transcript.contains("first command ("),
        "no first command may run after a failed install: {transcript}"
    );
}

#[test]
fn a_pinned_install_that_leaves_another_version_fails() {
    let smoke = Smoke::new();
    let installer = stand_in_installer(smoke.dir.path(), &fake_mvmctl("0.17.0", ECHO_TOKEN), 0);

    let output = smoke.run(&installer, Some("v0.18.0"), &[]);

    assert_eq!(output.status.code(), Some(1), "{}", combined(&output));
    assert!(
        smoke
            .transcript()
            .contains("the install pinned to v0.18.0 left 'mvmctl 0.17.0' on PATH"),
        "{}",
        smoke.transcript()
    );
}

/// The first command runs as a new user's would: from the throwaway HOME, with
/// none of the caller's `MVM_*` settings, the pin handed to the installer only,
/// and stdin at end-of-file rather than an inherited terminal or pipe.
#[test]
fn the_smoke_runs_in_a_rebuilt_environment_with_stdin_at_eof() {
    let smoke = Smoke::new();
    let record = smoke.dir.path().join("seen");
    let body = format!(
        "    {{ echo \"HOME=$HOME\"; echo \"MVM_HOME=${{MVM_HOME:-unset}}\"; echo \"MVM_VERSION=${{MVM_VERSION:-unset}}\"; \
         if [ -t 0 ]; then echo stdin=tty; elif [ -z \"$(cat)\" ]; then echo stdin=eof; else echo stdin=data; fi; }} > '{}'\n{ECHO_TOKEN}",
        record.display()
    );
    let installer = stand_in_installer(smoke.dir.path(), &fake_mvmctl("1.2.3", &body), 0);

    let output = smoke.run(
        &installer,
        Some("v1.2.3"),
        &[("MVM_HOME", "/nonexistent/caller-state")],
    );

    assert!(output.status.success(), "{}", combined(&output));
    let seen = std::fs::read_to_string(&record).unwrap();
    assert!(seen.contains("MVM_HOME=unset"), "{seen}");
    assert!(
        seen.contains("MVM_VERSION=unset"),
        "the pin is the installer's, not the first command's: {seen}"
    );
    assert!(seen.contains("stdin=eof"), "{seen}");
    let home = seen
        .lines()
        .find_map(|line| line.strip_prefix("HOME="))
        .unwrap();
    assert!(
        home.contains("/mvm-fresh.") && home.ends_with("/home"),
        "the first command must run from the throwaway HOME, got {home}"
    );
    assert!(
        !Path::new(home).exists(),
        "the throwaway HOME must be removed afterwards"
    );
}

#[test]
fn a_usage_error_is_exit_two() {
    let smoke = Smoke::new();
    let installer = stand_in_installer(smoke.dir.path(), &fake_mvmctl("1.2.3", ECHO_TOKEN), 0);

    for args in [&["--help"][..], &["v1", "v2"][..], &["v1;rm"][..]] {
        let output = Command::new("sh")
            .arg(script())
            .args(args)
            .env("MVM_SMOKE_INSTALLER", &installer)
            .env("MVM_SMOKE_OUT", smoke.out())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            combined(&output)
        );
    }
}
