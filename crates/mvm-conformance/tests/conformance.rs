//! Entry point for the dev-only cucumber-rs conformance harness.
//!
//! Wires the Gherkin scenarios under `features/suites/` to the step
//! definitions in the sibling `steps`/`world` modules and runs them against
//! the built `mvmctl` binary — and, as later suites land, the `mvm-client`
//! facade directly. Scenarios tagged `@wip` describe coverage whose steps
//! aren't implemented yet; they are filtered out here so the suite stays
//! green while a suite is still a stub. Remove the tag in the same change
//! that lands its steps.
//!
//! This is a `harness = false` test target (see the crate's `Cargo.toml`):
//! cucumber drives its own scenario loop instead of the standard `#[test]`
//! harness, so it needs a plain `fn main()`.
//!
//! The `World` type and step definitions live under `tests/` (this crate
//! root's own module tree) rather than `src/`: `cucumber` is a
//! dev-dependency, and Cargo never exposes a package's dev-dependencies to
//! its own `[lib]` target — only to test/example/bench targets themselves —
//! so cucumber-coupled code has to live in this test binary. Step logic
//! that doesn't need cucumber's macros belongs in `src/lib.rs` instead,
//! where it can be unit-tested independent of the cucumber runner.

mod steps;
mod world;

use std::path::{Path, PathBuf};

use cucumber::World as _;
use cucumber::gherkin::{Feature, Rule, Scenario};
use mvm_conformance::{RuntimeCaps, scenario_should_run};
use world::CliWorld;

#[tokio::main]
async fn main() {
    // Cargo will not rebuild another package's binary for this test target,
    // so a stale `mvmctl` silently drives every CLI scenario. Left alone
    // that surfaces as a pile of unrelated assertion failures, which is
    // exactly the wrong signal — the scenarios are fine, the binary is old.
    // Check it up front and say so.
    if let Err(problem) = check_mvmctl_freshness() {
        eprintln!("\nconformance: {problem}\n");
        std::process::exit(2);
    }

    // Warm-restore scenarios mutate the process `MVM_HOME` and call
    // in-process seal/verify helpers. Run all scenarios sequentially so
    // no other thread observes the environment mid-scenario.
    CliWorld::cucumber()
        .max_concurrent_scenarios(1)
        .filter_run_and_exit(features_dir(), should_run)
        .await;
}

/// Refuse to run against an `mvmctl` that is missing or older than the
/// sources it is built from.
///
/// The freshness bar is deliberately coarse — newest source mtime versus
/// binary mtime. It cannot prove the binary is correct, only that it
/// predates a change, which is the failure mode that actually bites: edit
/// the CLI, run the suite, and spend an hour reading scenario diffs.
fn check_mvmctl_freshness() -> Result<(), String> {
    let binary = mvmctl_path();
    let Ok(binary_meta) = std::fs::metadata(&binary) else {
        return Err(format!(
            "no mvmctl binary at {}.\n\
             The CLI scenarios drive the built binary as a subprocess, and cargo does \
             not build it for this target.\n\
             Run: cargo build --bin mvmctl",
            binary.display()
        ));
    };
    let Ok(binary_time) = binary_meta.modified() else {
        return Ok(());
    };

    let repo = steps::cli::workspace_root();
    let Some((newest, newest_at)) = newest_source(&repo.join("crates")) else {
        return Ok(());
    };
    if newest_at > binary_time {
        return Err(format!(
            "mvmctl at {} is older than {}.\n\
             The CLI scenarios would run against the stale binary and fail in ways \
             that look like broken scenarios rather than a stale build.\n\
             Run: cargo build --bin mvmctl",
            binary.display(),
            newest.display()
        ));
    }
    Ok(())
}

/// Where `assert_cmd`'s `cargo_bin` looks: the test binary's target
/// directory, two levels up from `deps/`.
fn mvmctl_path() -> PathBuf {
    let mut dir = std::env::current_exe().unwrap_or_default();
    dir.pop(); // the test binary's own name
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("mvmctl")
}

/// The most recently modified `.rs` file under `root`, if any.
fn newest_source(root: &Path) -> Option<(PathBuf, std::time::SystemTime)> {
    fn walk(dir: &Path, best: &mut Option<(PathBuf, std::time::SystemTime)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                // `target/` under a crate would swamp the scan and is not source.
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                walk(&path, best);
            } else if path.extension().is_some_and(|e| e == "rs")
                && let Ok(modified) = meta.modified()
                && best.as_ref().is_none_or(|(_, t)| modified > *t)
            {
                *best = Some((path, modified));
            }
        }
    }
    let mut best = None;
    walk(root, &mut best);
    best
}

/// Decide whether a scenario runs from its tags and the host's probed
/// capabilities. The tag semantics live in the crate lib (`scenario_should_run`)
/// so they can be unit-tested without a cucumber runner; this wrapper only
/// supplies the real host capabilities. An absent required capability yields a
/// clean skip, never a failure — so the suite stays green on hosts without KVM
/// (GitHub-hosted ARM runners, or any dev box lacking `/dev/kvm`).
fn should_run(_feature: &Feature, _rule: Option<&Rule>, scenario: &Scenario) -> bool {
    scenario_should_run(&scenario.tags, probe_caps())
}

/// Probe the host for the capabilities the tag gates require. Re-run per
/// scenario by cucumber's filter callback; the syscalls are cheap.
fn probe_caps() -> RuntimeCaps {
    RuntimeCaps {
        live_opted_in: std::env::var_os("MVM_BDD_LIVE").is_some(),
        firecracker_bootable: kvm_openable() && firecracker_on_path(),
        bundle_fixture: bundle_fixture_path().is_some(),
    }
}

/// The operator-supplied `.mvmpkg` a bundle-boot scenario installs, when
/// `MVM_BDD_BUNDLE` names one that actually exists.
pub(crate) fn bundle_fixture_path() -> Option<std::path::PathBuf> {
    let path = std::path::PathBuf::from(std::env::var_os("MVM_BDD_BUNDLE")?);
    path.is_file().then_some(path)
}

/// `/dev/kvm` exists and this process can open it read-write — the mode a real
/// KVM user (Firecracker) needs, and the meaningful check since the node can be
/// present but group-gated.
fn kvm_openable() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

/// A `firecracker` binary is resolvable on `PATH`.
fn firecracker_on_path() -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join("firecracker").is_file()))
        .unwrap_or(false)
}

/// `features/suites/` lives at the repo root, two levels above this crate's
/// manifest directory. Resolved from `CARGO_MANIFEST_DIR` at compile time so
/// the suite runs correctly regardless of the process's working directory.
fn features_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("features")
        .join("suites")
}
