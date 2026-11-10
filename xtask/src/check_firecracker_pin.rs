//! `xtask check-firecracker-pin`
//!
//! Firecracker runs every Linux guest, so the bytes that run it must be named by
//! this tree. Its version and digests used to be written wherever a script
//! needed them, and the install path downloaded the upstream tarball and put it
//! in `/usr/local/bin` without checking it at all.
//!
//! The pin lives in `crates/mvm-core/firecracker.lock` now, and this gate holds
//! the places that cannot call a Rust API to it. Five things fail:
//!
//!   - The default Firecracker version in `mvm-core` is not the locked one.
//!   - `scripts/locked-firecracker.sh` prints something other than what the
//!     lock pins.
//!   - The remote KVM runner names a version or digest other than the locked
//!     one.
//!   - Any `FC_VERSION` literal in a workflow, script or provisioning file
//!     names a version other than the locked one.
//!   - A file outside the allow-list names a download from the upstream
//!     Firecracker release page. Every such download is a place the bytes that
//!     boot guests were never compared with the lock.
//!
//! The allow-list must shrink, and it cannot rot: an entry whose file no longer
//! names a download fails too.

use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use mvm_core::arch::GuestArch;
use mvm_core::config::FC_VERSION_DEFAULT;
use mvm_core::firecracker_lock::FirecrackerLock;

/// The lock, relative to the workspace root.
const LOCK_FILE: &str = "crates/mvm-core/firecracker.lock";

/// The reader every shell and YAML consumer goes through.
const READER: &str = "scripts/locked-firecracker.sh";

/// The remote KVM runner, which checks a tarball it cannot read the lock for.
const REMOTE_RUNNER: &str = "scripts/run-gcp-kvm-test-remote.sh";

/// Trees whose files could name a Firecracker download. Documentation and specs
/// are excluded: prose about a release is a record, not a fetch.
const SCANNED_DIRS: [&str; 5] = [".github", "scripts", "crates", "just", "nix"];

/// What a download from the upstream release page looks like in a file.
const DOWNLOAD_PATTERN: &str = "firecracker-microvm/firecracker/releases/download";

/// Files that may name an upstream Firecracker download, and why.
const ALLOWED_DOWNLOADS: &[(&str, &str)] = &[
    (
        "crates/mvm-backends/src/fc/host.rs",
        "bootstrap installs Firecracker from the upstream tarball; this entry goes when it \
         installs the locked, digest-checked artifact instead",
    ),
    (
        REMOTE_RUNNER,
        "the remote runner checks its tarball against a digest this gate compares to the lock",
    ),
    (
        ".github/workflows/bdd.yml",
        "installs the tarball unverified; migrate to a verified install that reads the lock",
    ),
    (
        ".github/workflows/ci-main.yml",
        "installs the tarball unverified in two jobs; migrate to a verified install that reads the lock",
    ),
    (
        ".github/workflows/e2e-docs.yml",
        "installs the tarball unverified; migrate to a verified install that reads the lock",
    ),
    (
        "nix/ops/hetzner/cloud-init.yaml",
        "provisions a fresh VM with no checkout, so it cannot read the lock; migrate to verify \
         against pinned digests this gate compares to the lock",
    ),
];

/// The version the lock pins, spelled the way `mvm-core` spells its default.
fn default_version_finding(default: &str, lock: &FirecrackerLock) -> Option<String> {
    (default != lock.version).then(|| {
        format!(
            "mvm_core::config::FC_VERSION_DEFAULT is {default} but {LOCK_FILE} pins {}",
            lock.version
        )
    })
}

/// The value of a `name=value` line in a shell script, without quotes.
fn shell_assignment<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let value = line.trim().strip_prefix(name)?.strip_prefix('=')?;
        Some(value.trim().trim_matches(|c| c == '"' || c == '\''))
    })
}

/// What the remote KVM runner pins, against what the lock pins.
fn runner_findings(text: &str, lock: &FirecrackerLock) -> Vec<String> {
    let expectations = [
        (
            "firecracker_version",
            lock.version.trim_start_matches('v').to_string(),
        ),
        (
            "firecracker_sha256",
            lock.pin(GuestArch::X86_64)
                .tarball_sha256
                .as_str()
                .to_string(),
        ),
    ];
    expectations
        .into_iter()
        .filter_map(|(name, locked)| match shell_assignment(text, name) {
            Some(written) if written == locked => None,
            Some(written) => Some(format!(
                "{REMOTE_RUNNER} sets {name}={written} but {LOCK_FILE} pins {locked}"
            )),
            None => Some(format!(
                "{REMOTE_RUNNER} no longer sets {name}; this gate compares it to {LOCK_FILE}"
            )),
        })
        .collect()
}

/// `FC_VERSION: vX.Y.Z` or `FC_VERSION="vX.Y.Z"` lines whose version is not the
/// locked one. Until every consumer reads the lock, a hand-copied version is the
/// likeliest way for the VMM CI exercises to differ from the one users run.
fn version_literal_findings(relative: &str, text: &str, lock: &FirecrackerLock) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("FC_VERSION")?;
            let value = rest.strip_prefix(':').or_else(|| rest.strip_prefix('='))?;
            let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
            let is_version =
                value.starts_with('v') && value[1..].starts_with(|c: char| c.is_ascii_digit());
            (is_version && value != lock.version).then(|| {
                format!(
                    "{relative} sets FC_VERSION to {value} but {LOCK_FILE} pins {}",
                    lock.version
                )
            })
        })
        .collect()
}

/// A download from the upstream release page, if `relative` is not allowed one.
fn download_finding(relative: &str, text: &str) -> Option<String> {
    let allowed = ALLOWED_DOWNLOADS.iter().any(|(path, _)| *path == relative);
    (text.contains(DOWNLOAD_PATTERN) && !allowed).then(|| {
        format!(
            "{relative} names a Firecracker download ({DOWNLOAD_PATTERN}) and is not on the \
             allow-list: read the digest from {LOCK_FILE} and verify before using the bytes"
        )
    })
}

/// Allow-list entries whose file no longer names a download.
fn stale_allowances(seen: &BTreeSet<String>) -> Vec<String> {
    ALLOWED_DOWNLOADS
        .iter()
        .filter(|(path, _)| !seen.contains(*path))
        .map(|(path, why)| {
            format!(
                "{path} is on the download allow-list ({why}) but no longer names one; remove it"
            )
        })
        .collect()
}

/// Every field the reader serves, with the value the parsed lock holds.
fn reader_expectations(lock: &FirecrackerLock) -> Vec<(Vec<String>, String)> {
    let mut rows = vec![
        (vec!["repository".to_string()], lock.repository.clone()),
        (vec!["version".to_string()], lock.version.clone()),
    ];
    for arch in [GuestArch::X86_64, GuestArch::Aarch64] {
        let pin = lock.pin(arch);
        let arch_name = arch.to_string();
        for (field, value) in [
            ("tarball", pin.tarball.clone()),
            ("tarball_sha256", pin.tarball_sha256.as_str().to_string()),
            ("binary", pin.binary.clone()),
            ("binary_sha256", pin.binary_sha256.as_str().to_string()),
            ("binary_size", pin.binary_size.to_string()),
        ] {
            rows.push((vec![field.to_string(), arch_name.clone()], value));
        }
    }
    rows
}

fn check_reader_agrees(workspace: &Path, lock: &FirecrackerLock) -> Result<()> {
    let reader = workspace.join(READER);
    for (args, locked) in reader_expectations(lock) {
        let output = Command::new(&reader)
            .args(&args)
            .output()
            .with_context(|| format!("running {READER} {}", args.join(" ")))?;
        if !output.status.success() {
            bail!(
                "check-firecracker-pin: {READER} {} exited {}: {}",
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let printed = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if printed != locked {
            bail!(
                "check-firecracker-pin: {READER} {} prints {printed:?} but {LOCK_FILE} pins \
                 {locked:?}; the reader and the lock must say the same thing",
                args.join(" ")
            );
        }
    }
    Ok(())
}

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let lock_path = workspace.join(LOCK_FILE);
    let lock_text = std::fs::read_to_string(&lock_path)
        .with_context(|| format!("reading {}", lock_path.display()))?;
    let lock = FirecrackerLock::parse(&lock_text)
        .with_context(|| format!("parsing {}", lock_path.display()))?;

    let mut findings: Vec<String> = default_version_finding(FC_VERSION_DEFAULT, &lock)
        .into_iter()
        .collect();

    let runner_path = workspace.join(REMOTE_RUNNER);
    let runner = std::fs::read_to_string(&runner_path)
        .with_context(|| format!("reading {}", runner_path.display()))?;
    findings.extend(runner_findings(&runner, &lock));

    let mut seen = BTreeSet::new();
    for dir in SCANNED_DIRS {
        crate::fs_walk::walk_files(&workspace.join(dir), &mut |path| {
            let Ok(text) = std::fs::read_to_string(path) else {
                // Binary fixtures live under these trees; a file that is not
                // UTF-8 names no download.
                return;
            };
            let relative = path
                .strip_prefix(workspace)
                .unwrap_or(path)
                .display()
                .to_string();
            if text.contains(DOWNLOAD_PATTERN) {
                seen.insert(relative.clone());
            }
            findings.extend(download_finding(&relative, &text));
            findings.extend(version_literal_findings(&relative, &text, &lock));
        })?;
    }
    findings.extend(stale_allowances(&seen));

    if !findings.is_empty() {
        bail!(
            "check-firecracker-pin: {} finding(s) against {LOCK_FILE} (locked: {}):\n  {}",
            findings.len(),
            lock.version,
            findings.join("\n  ")
        );
    }

    check_reader_agrees(workspace, &lock)?;

    eprintln!(
        "check-firecracker-pin: clean (Firecracker {} pinned by {LOCK_FILE})",
        lock.version
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock() -> FirecrackerLock {
        mvm_core::firecracker_lock::firecracker_lock().clone()
    }

    fn runner_text(lock: &FirecrackerLock) -> String {
        format!(
            "firecracker_version={}\nfirecracker_sha256={}\n",
            lock.version.trim_start_matches('v'),
            lock.pin(GuestArch::X86_64).tarball_sha256.as_str()
        )
    }

    #[test]
    fn the_locked_version_is_the_default() {
        let lock = lock();
        assert_eq!(default_version_finding(&lock.version, &lock), None);
        let finding = default_version_finding("v0.0.1", &lock).expect("a drifted default");
        assert!(finding.contains("v0.0.1") && finding.contains(&lock.version));
    }

    #[test]
    fn a_runner_that_matches_the_lock_is_clean() {
        let lock = lock();
        assert!(runner_findings(&runner_text(&lock), &lock).is_empty());
    }

    #[test]
    fn a_runner_with_another_version_or_digest_is_refused() {
        let lock = lock();
        let text = runner_text(&lock)
            .replace(lock.version.trim_start_matches('v'), "0.0.1")
            .replace(
                lock.pin(GuestArch::X86_64).tarball_sha256.as_str(),
                &"0".repeat(64),
            );
        assert_eq!(runner_findings(&text, &lock).len(), 2);
    }

    #[test]
    fn a_runner_that_stopped_pinning_is_refused_not_ignored() {
        let findings = runner_findings("echo nothing pinned here\n", &lock());
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .all(|finding| finding.contains("no longer sets"))
        );
    }

    #[test]
    fn a_shell_assignment_is_read_with_or_without_quotes() {
        assert_eq!(
            shell_assignment("a=1\nb=\"two\"\nc='3'\n", "b"),
            Some("two")
        );
        assert_eq!(shell_assignment("a=1\nb=\"two\"\nc='3'\n", "c"), Some("3"));
        assert_eq!(shell_assignment("  a=1\n", "a"), Some("1"));
        assert_eq!(shell_assignment("aa=1\n", "a"), None);
    }

    #[test]
    fn a_download_outside_the_allow_list_is_a_finding() {
        let text = format!("curl https://github.com/{DOWNLOAD_PATTERN}/v1/x.tgz");
        let finding = download_finding("scripts/new.sh", &text).expect("an unlisted download");
        assert!(finding.contains("scripts/new.sh") && finding.contains("allow-list"));
    }

    #[test]
    fn an_allowed_download_and_a_file_without_one_are_clean() {
        let text = format!("curl https://github.com/{DOWNLOAD_PATTERN}/v1/x.tgz");
        let (allowed, _) = ALLOWED_DOWNLOADS[0];
        assert_eq!(download_finding(allowed, &text), None);
        assert_eq!(download_finding("scripts/other.sh", "echo hello"), None);
    }

    #[test]
    fn a_hand_copied_version_that_is_not_the_locked_one_is_a_finding() {
        let lock = lock();
        let drifted = "env:\n      FC_VERSION: v0.0.1\n";
        let findings = version_literal_findings("a.yml", drifted, &lock);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("v0.0.1") && findings[0].contains(&lock.version));
        let shell = "    FC_VERSION=\"v0.0.1\"\n";
        assert_eq!(version_literal_findings("a.yaml", shell, &lock).len(), 1);
    }

    #[test]
    fn the_locked_version_and_unrelated_names_are_not_findings() {
        let lock = lock();
        let same = format!(
            "      FC_VERSION: {}\n    FC_VERSION=\"{}\"\n",
            lock.version, lock.version
        );
        assert!(version_literal_findings("a.yml", &same, &lock).is_empty());
        // A different variable, a build-time override and a non-version value
        // are none of this check's business.
        for other in [
            "MVM_FC_VERSION: v0.0.1",
            "FC_VERSION_DEFAULT: v0.0.1",
            "FC_VERSION: ${{ inputs.version }}",
            "# FC_VERSION: v0.0.1",
        ] {
            assert!(
                version_literal_findings("a.yml", other, &lock).is_empty(),
                "{other} must not be a finding"
            );
        }
    }

    #[test]
    fn an_allowance_whose_file_stopped_naming_a_download_is_stale() {
        let everything: BTreeSet<String> = ALLOWED_DOWNLOADS
            .iter()
            .map(|(path, _)| (*path).to_string())
            .collect();
        assert!(stale_allowances(&everything).is_empty());
        let stale = stale_allowances(&BTreeSet::new());
        assert_eq!(stale.len(), ALLOWED_DOWNLOADS.len());
        assert!(stale.iter().all(|finding| finding.contains("remove it")));
    }

    #[test]
    fn the_reader_is_checked_for_every_field_of_both_architectures() {
        let rows = reader_expectations(&lock());
        // Two top-level fields and five per architecture.
        assert_eq!(rows.len(), 2 + 5 * 2);
        assert!(
            rows.iter()
                .any(|(args, _)| args == &["binary_size", "aarch64"])
        );
    }
}
