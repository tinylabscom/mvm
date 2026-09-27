//! Tests for `scripts/smoke-fresh-install.sh`, the release gate that installs a
//! tag into a throwaway HOME and runs the README's first command.
//!
//! The real smoke needs a published release and a host that boots guests, so
//! these drive the script with a stand-in installer that puts a fake `mvmctl`
//! on the throwaway PATH. What is under test is the verdict: a smoke that
//! cannot go red is a gate that reports green over a broken release.
//!
//! The smoke boots three times: the README's first command, the same command
//! again from the same HOME, and a boot binding an SDK host service. The fake
//! answers all three, and caches a runtime overlay the way a release binary's
//! first boot does, so the second boot has something to reuse.

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
/// Every run first caches a runtime overlay unless one is already cached, as
/// a release binary's first boot does.
fn fake_mvmctl(version: &str, run_body: &str) -> String {
    fake_mvmctl_with(version, CACHE_OVERLAY_ONCE, run_body)
}

/// [`fake_mvmctl`] with `prelude` in place of the overlay cache step.
fn fake_mvmctl_with(version: &str, prelude: &str, run_body: &str) -> String {
    format!(
        "#!/bin/sh\ncase \"$1\" in\n  --version) echo 'mvmctl {version}' ;;\n  machine) shift 2\n{prelude}\n{run_body}\n    ;;\nesac"
    )
}

/// Install a runtime overlay into the cache when none is there yet.
const CACHE_OVERLAY_ONCE: &str = "    cache=\"$HOME/.mvm/cache/runtime-overlay/1.2.3/aarch64\"; \
     [ -f \"$cache/overlay.ext4\" ] || { mkdir -p \"$cache\"; echo overlay > \"$cache/overlay.ext4\"; }";

/// Install the initramfs on every run, the way a boot that rejects its cached
/// copy fetches it again: a new file renamed over the old one.
const REFETCH_INITRAMFS_EVERY_RUN: &str = "    cache=\"$HOME/.mvm/cache/initramfs/1.2.3/aarch64\"; \
     mkdir -p \"$cache\"; echo initramfs > \"$cache/initramfs.new\"; \
     mv \"$cache/initramfs.new\" \"$cache/initramfs.cpio.gz\"";

/// Cache the overlay once, and rewrite a validation stamp beside it on every
/// run, as the resolver may without fetching anything.
const CACHE_OVERLAY_ONCE_AND_RESTAMP: &str = "    cache=\"$HOME/.mvm/cache/runtime-overlay/1.2.3/aarch64\"; \
     [ -f \"$cache/overlay.ext4\" ] || { mkdir -p \"$cache\"; echo overlay > \"$cache/overlay.ext4\"; }; \
     echo stamp > \"$cache/.validated.new\"; mv \"$cache/.validated.new\" \"$cache/.validated-v1.json\"";

/// Print the token the command after `--` would print, as a guest would: the
/// argument of `echo`, or of the first `echo` in an `sh -c` script.
const ECHO_TOKEN: &str = "    while [ \"$1\" != -- ]; do shift; done; shift\n\
     if [ \"$1\" = sh ]; then set -- $3; while [ \"$1\" != echo ]; do shift; done; fi\n\
     [ \"$1\" = echo ] && shift; echo \"${1%;}\"";

/// Fail the Nth and later `machine run`, counting in the throwaway HOME.
fn fail_from_run(n: u32, message: &str) -> String {
    format!(
        "    runs=$(( $(cat \"$HOME/runs\" 2>/dev/null || echo 0) + 1 )); echo \"$runs\" > \"$HOME/runs\"\n\
         if [ \"$runs\" -ge {n} ]; then echo '{message}' >&2; exit 1; fi\n{ECHO_TOKEN}"
    )
}

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
    assert!(
        transcript.contains("second boot from the same HOME (mvmctl machine run --image alpine -- echo mvm-fresh-install-")
            && transcript.contains("-second </dev/null)"),
        "the transcript must name the second boot's command: {transcript}"
    );
    assert!(
        transcript
            .contains("mvmctl machine run --image alpine --host-service host.time.v1 -- sh -c")
            && transcript.contains("/mvm/sdk/lib/libmvm_host_services.so"),
        "the transcript must name the SDK boot's command: {transcript}"
    );
    assert!(
        transcript.contains("runtime-overlay/1.2.3/aarch64/overlay.ext4"),
        "the transcript must carry the cache the second boot was held to: {transcript}"
    );
    for step in ["first command", "second boot", "SDK boot"] {
        assert!(
            transcript.contains(&format!("--- {step} exited 0 after ")),
            "the transcript must time the {step}: {transcript}"
        );
    }
    assert!(
        transcript.contains("second boot:    ") && transcript.contains("SDK boot:       "),
        "the transcript must summarise every boot's time: {transcript}"
    );
    assert!(
        transcript.contains("a second boot from the same HOME in")
            && transcript.contains("a boot binding host.time.v1 saw the SDK sidecar in"),
        "{transcript}"
    );
}

/// A download-mode artifact whose VERSION is not the binary's own boots once,
/// because the first boot runs what it has just fetched, and fails from the
/// second boot on.
#[test]
fn a_second_boot_that_fails_fails_the_smoke() {
    let smoke = Smoke::new();
    let installer = stand_in_installer(
        smoke.dir.path(),
        &fake_mvmctl(
            "1.2.3",
            &fail_from_run(2, "initramfs version mismatch: expected 1.2.3, got 1.2.2"),
        ),
        0,
    );

    let output = smoke.run(&installer, Some("v1.2.3"), &[]);

    assert_eq!(output.status.code(), Some(1), "{}", combined(&output));
    let transcript = smoke.transcript();
    assert!(
        transcript.contains("--- first command exited 0 after "),
        "{transcript}"
    );
    assert!(
        transcript.contains("FAIL: the second boot exited 1"),
        "{transcript}"
    );
    assert!(
        transcript.contains("initramfs version mismatch"),
        "the transcript must carry the second boot's stderr: {transcript}"
    );
    assert!(
        !transcript.contains("SDK boot ("),
        "no SDK boot may run after a failed second boot: {transcript}"
    );
}

#[test]
fn a_second_boot_over_budget_fails_and_is_stopped() {
    let smoke = Smoke::new();
    let body = format!(
        "    [ -f \"$HOME/booted\" ] && exec sleep 600; touch \"$HOME/booted\"\n{ECHO_TOKEN}"
    );
    let installer = stand_in_installer(smoke.dir.path(), &fake_mvmctl("1.2.3", &body), 0);

    let started = std::time::Instant::now();
    let output = smoke.run(
        &installer,
        Some("v1.2.3"),
        &[("MVM_SMOKE_SECOND_RUN_BUDGET_SECS", "2")],
    );

    assert_eq!(output.status.code(), Some(1), "{}", combined(&output));
    assert!(
        smoke
            .transcript()
            .contains("FAIL: the second boot did not finish within 2s"),
        "{}",
        smoke.transcript()
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(120),
        "the budget must stop the second boot, not wait for it"
    );
}

/// A second boot that prints its token but fetched an artifact again has
/// rejected what the first cached: the overlay re-download on every boot.
#[test]
fn a_second_boot_that_fetches_again_fails() {
    let smoke = Smoke::new();
    let installer = stand_in_installer(
        smoke.dir.path(),
        &fake_mvmctl_with("1.2.3", REFETCH_INITRAMFS_EVERY_RUN, ECHO_TOKEN),
        0,
    );

    let output = smoke.run(&installer, Some("v1.2.3"), &[]);

    assert_eq!(output.status.code(), Some(1), "{}", combined(&output));
    let transcript = smoke.transcript();
    assert!(
        transcript.contains("--- second boot exited 0 after "),
        "the second boot itself succeeded: {transcript}"
    );
    assert!(
        transcript.contains(
            "FAIL: the second boot replaced or removed what the first cached, so it fetched it \
             again: initramfs/1.2.3/aarch64/initramfs.cpio.gz"
        ),
        "{transcript}"
    );
}

/// A validation stamp rewritten beside the cached overlay is the resolver's
/// bookkeeping, not a fetch: the artifacts themselves are the ones it cached.
#[test]
fn a_second_boot_that_only_restamps_the_cache_passes() {
    let smoke = Smoke::new();
    let installer = stand_in_installer(
        smoke.dir.path(),
        &fake_mvmctl_with("1.2.3", CACHE_OVERLAY_ONCE_AND_RESTAMP, ECHO_TOKEN),
        0,
    );

    let output = smoke.run(&installer, Some("v1.2.3"), &[]);

    assert!(output.status.success(), "{}", combined(&output));
    let transcript = smoke.transcript();
    assert!(
        transcript.contains("PASS: mvmctl 1.2.3 installed in"),
        "{transcript}"
    );
    assert!(
        !transcript.contains(".validated-v1.json"),
        "the snapshot must leave the resolver's stamps out: {transcript}"
    );
}

/// Nothing cached means nothing for the second boot to be held to, and a
/// check that has nothing to compare cannot go red.
#[test]
fn a_first_boot_that_caches_nothing_fails() {
    let smoke = Smoke::new();
    let installer = stand_in_installer(
        smoke.dir.path(),
        &fake_mvmctl_with("1.2.3", "", ECHO_TOKEN),
        0,
    );

    let output = smoke.run(&installer, Some("v1.2.3"), &[]);

    assert_eq!(output.status.code(), Some(1), "{}", combined(&output));
    let transcript = smoke.transcript();
    assert!(
        transcript.contains("cached no runtime overlay or initramfs under"),
        "{transcript}"
    );
    assert!(
        !transcript.contains("second boot from the same HOME ("),
        "{transcript}"
    );
}

/// The SDK sidecar is downloaded only for a workload that binds an SDK host
/// service, so neither plain boot can see it refused.
#[test]
fn an_sdk_boot_that_fails_fails_the_smoke() {
    let smoke = Smoke::new();
    let body = format!(
        "    case \" $* \" in *' --host-service host.time.v1 '*) \
         echo 'SDK sidecar version mismatch: expected \"1.2.3\", cache holds \"1.2.2\"' >&2; exit 1 ;; esac\n{ECHO_TOKEN}"
    );
    let installer = stand_in_installer(smoke.dir.path(), &fake_mvmctl("1.2.3", &body), 0);

    let output = smoke.run(&installer, Some("v1.2.3"), &[]);

    assert_eq!(output.status.code(), Some(1), "{}", combined(&output));
    let transcript = smoke.transcript();
    assert!(
        transcript.contains("--- second boot exited 0 after "),
        "{transcript}"
    );
    assert!(
        transcript.contains("FAIL: the SDK boot exited 1"),
        "{transcript}"
    );
    assert!(
        transcript.contains("SDK sidecar version mismatch"),
        "the transcript must carry the SDK boot's stderr: {transcript}"
    );
}

#[test]
fn an_sdk_boot_over_budget_fails_and_is_stopped() {
    let smoke = Smoke::new();
    let body =
        format!("    case \" $* \" in *' --host-service '*) exec sleep 600 ;; esac\n{ECHO_TOKEN}");
    let installer = stand_in_installer(smoke.dir.path(), &fake_mvmctl("1.2.3", &body), 0);

    let started = std::time::Instant::now();
    let output = smoke.run(
        &installer,
        Some("v1.2.3"),
        &[("MVM_SMOKE_SDK_RUN_BUDGET_SECS", "2")],
    );

    assert_eq!(output.status.code(), Some(1), "{}", combined(&output));
    assert!(
        smoke
            .transcript()
            .contains("FAIL: the SDK boot did not finish within 2s"),
        "{}",
        smoke.transcript()
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(120),
        "the budget must stop the SDK boot, not wait for it"
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

#[test]
fn a_budget_that_is_not_a_positive_whole_number_is_exit_two() {
    let smoke = Smoke::new();
    let installer = stand_in_installer(smoke.dir.path(), &fake_mvmctl("1.2.3", ECHO_TOKEN), 0);

    for budget in [
        "MVM_SMOKE_RUN_BUDGET_SECS",
        "MVM_SMOKE_SECOND_RUN_BUDGET_SECS",
        "MVM_SMOKE_SDK_RUN_BUDGET_SECS",
    ] {
        for value in ["0", "1.5", "soon"] {
            let output = smoke.run(&installer, Some("v1.2.3"), &[(budget, value)]);
            assert_eq!(
                output.status.code(),
                Some(2),
                "{budget}={value}: {}",
                combined(&output)
            );
        }
    }
}

/// Each step's budget is what reports a slow step, with a transcript saying
/// which one. A job timeout below their sum would cancel the smoke first, and
/// say only that the job ran long.
#[test]
fn the_job_timeout_covers_every_default_budget() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let script = std::fs::read_to_string(script()).unwrap();
    let budgets: u64 = [
        "MVM_SMOKE_INSTALL_BUDGET_SECS",
        "MVM_SMOKE_RUN_BUDGET_SECS",
        "MVM_SMOKE_SECOND_RUN_BUDGET_SECS",
        "MVM_SMOKE_SDK_RUN_BUDGET_SECS",
    ]
    .iter()
    .map(|var| {
        let marker = format!("${{{var}:-");
        let start = script
            .find(&marker)
            .unwrap_or_else(|| panic!("the script must default {var}"))
            + marker.len();
        let digits: String = script[start..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse::<u64>().unwrap()
    })
    .sum();

    let workflow =
        std::fs::read_to_string(root.join(".github/workflows/first-run-smoke.yml")).unwrap();
    let minutes: u64 = workflow
        .lines()
        .find_map(|line| line.trim().strip_prefix("timeout-minutes:"))
        .expect("the first-run job must set a timeout")
        .trim()
        .parse()
        .unwrap();

    assert!(
        minutes * 60 > budgets,
        "the job timeout ({minutes} min) must exceed the smoke's summed default budgets ({budgets} s)"
    );
}
