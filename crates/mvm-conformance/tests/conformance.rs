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
mod support;
mod world;

use std::path::{Path, PathBuf};

use cucumber::World as _;
use cucumber::gherkin::{Feature, Rule, Scenario};
use mvm_conformance::{RuntimeCaps, ScenarioGate, scenario_gate_for_ci};
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
    // `filter_run` rather than `filter_run_and_exit`: the latter calls
    // `process::exit`, which runs no destructors and leaves no point at which
    // the skip tally can be printed. This reproduces its exit behaviour around
    // the report.
    let writer = CliWorld::cucumber()
        .max_concurrent_scenarios(1)
        .filter_run(features_dir(), should_run)
        .await;

    report_skips();
    let unexpected_skips = unexpected_skips();

    // `execution_has_failed` comes from the `Stats` trait, which the concrete
    // writer only exposes when the trait is in scope.
    use cucumber::writer::Stats as _;
    if writer.execution_has_failed() {
        std::process::exit(1);
    }
    if !unexpected_skips.is_empty() {
        eprintln!();
        eprintln!(
            "!!! {} scenario(s) were skipped that this lane does not tolerate:",
            unexpected_skips.iter().map(|(_, n)| n).sum::<usize>()
        );
        for (reason, count) in &unexpected_skips {
            eprintln!("!!!   {count:>3}  {reason}");
        }
        eprintln!(
            "!!! A skipped scenario is coverage this run did not have. Under \
             MVM_BDD_STRICT_SKIPS the lane fails rather than reporting a pass \
             that quietly proved less than the last one."
        );
        eprintln!(
            "!!! Either give the host the capability, or add the reason to \
             MVM_BDD_ALLOWED_SKIPS in the lane that set this policy."
        );
        std::process::exit(1);
    }
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
    let workspace_root = steps::cli::workspace_root();
    if let Some(binary) = std::env::var_os("CARGO_BIN_EXE_mvmctl") {
        return resolve_binary_path(binary.into(), &workspace_root);
    }
    let mut dir = std::env::current_exe().unwrap_or_default();
    dir.pop(); // the test binary's own name
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("mvmctl")
}

fn resolve_binary_path(binary: PathBuf, workspace_root: &Path) -> PathBuf {
    if binary.is_absolute() {
        binary
    } else {
        workspace_root.join(binary)
    }
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
    let gate = scenario_gate_for_ci(
        &scenario.tags,
        probe_caps(),
        std::env::var_os("MVM_BDD_CI_LIVE_ONLY").is_some(),
    );
    record_gate(gate);
    matches!(gate, ScenarioGate::Run)
}

/// Tally of every filter decision, so the run can say what it declined to
/// attempt. A green suite that is silent about its skips reads as full
/// coverage, and the `@live` scenarios it skips are exactly the ones that boot
/// a real microVM.
static SKIPPED: std::sync::Mutex<Vec<ScenarioGate>> = std::sync::Mutex::new(Vec::new());

fn record_gate(gate: ScenarioGate) {
    if gate == ScenarioGate::Run {
        return;
    }
    if let Ok(mut skipped) = SKIPPED.lock() {
        skipped.push(gate);
    }
}

/// Skips this lane declined to tolerate, as `(reason, count)`.
///
/// Empty unless `MVM_BDD_STRICT_SKIPS` is set, so a developer running the suite
/// on a laptop still gets the tally and not a failure. A release-gating lane
/// sets it, because there the tally is advice nobody reads at the moment it
/// matters: a runner that quietly lost a capability produces a green run that
/// proved less than the one before it, and nothing says so.
///
/// `MVM_BDD_ALLOWED_SKIPS` is a comma-separated list of [`ScenarioGate::as_str`]
/// names the lane accepts — `@wip` work, a latency budget the host cannot hold,
/// a backend that genuinely has no memory-snapshot tier. Everything else fails.
fn unexpected_skips() -> Vec<(&'static str, usize)> {
    if std::env::var_os("MVM_BDD_STRICT_SKIPS").is_none() {
        return Vec::new();
    }
    let allowed_raw = std::env::var("MVM_BDD_ALLOWED_SKIPS").unwrap_or_default();
    let allowed: std::collections::BTreeSet<&str> = allowed_raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();

    let Ok(skipped) = SKIPPED.lock() else {
        return Vec::new();
    };
    let mut counts: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    for gate in skipped.iter() {
        let name = gate.as_str();
        if allowed.contains(name) {
            continue;
        }
        *counts.entry(name).or_default() += 1;
    }
    counts.into_iter().collect()
}

/// Print one line per skip reason, after the run.
fn report_skips() {
    let Ok(skipped) = SKIPPED.lock() else {
        return;
    };
    if skipped.is_empty() {
        eprintln!("[bdd] no scenarios skipped");
        return;
    }
    let mut counts: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    for gate in skipped.iter() {
        if let Some(reason) = gate.reason() {
            *counts.entry(reason).or_default() += 1;
        }
    }
    eprintln!("[bdd] {} scenario(s) did NOT run:", skipped.len());
    for (reason, count) in counts {
        eprintln!("[bdd]   {count:>3}  {reason}");
    }
    eprintln!("[bdd] a green suite is not full coverage while any of these are nonzero.");
}

/// Probe the host for the capabilities the tag gates require. Re-run per
/// scenario by cucumber's filter callback; the syscalls are cheap.
fn probe_caps() -> RuntimeCaps {
    RuntimeCaps {
        live_opted_in: std::env::var_os("MVM_BDD_LIVE").is_some(),
        firecracker_bootable: kvm_openable() && firecracker_on_path(),
        bundle_fixture: bundle_fixture_path().is_some() && bundle_pubkey_path().is_some(),
        node_available: binary_on_path("node"),
        workload_kernel: workload_kernel_path().is_some(),
        guest_bin_dir: guest_bin_dir_available(),
        sdk_sidecar: sdk_sidecar_cached(),
        perf_budget_host: std::env::var_os("MVM_BDD_PERF_BUDGET").is_some(),
        tls_tunnel_client: std::env::var_os("MVM_BDD_TLS_CLIENT").is_some(),
        memory_snapshot: memory_snapshot_supported(),
        dir_share: dir_share_supported(),
    }
}

/// Whether the SDK sidecar image is in the version-keyed cache.
///
/// Admission refuses a workload that binds an SDK host service without it, so
/// a scenario that binds one cannot pass on a host where the image was never
/// built. Globbed on version rather than hardcoded so a bump does not silently
/// turn this into "never available".
fn sdk_sidecar_cached() -> bool {
    let sidecar_root = mvm_core::config::mvm_cache_dir_at(live_home())
        .join(mvm_fs::sdk_sidecar::SDK_SIDECAR_CACHE_DIR);
    mvm_conformance::sidecar_image_cached_in(
        &sidecar_root,
        mvm_fs::sdk_sidecar::SDK_SIDECAR_IMAGE_FILE,
    )
}

/// The mvm home the live scenarios actually run against.
///
/// The runner exports `MVM_E2E_HOME`; it does not set `MVM_HOME`. So
/// `mvm_core::config`'s ambient helpers resolve the *default* home inside this
/// process, which is a different directory from the one every live step hands
/// to `mvmctl`. A capability probe reading the default home reports on
/// artifacts the scenario will never see: where that home happens to hold the
/// image, the gate says "available", the scenario runs against the isolated
/// home, and admission refuses it there — a setup gap surfacing as a product
/// failure. Both paths are the same on a developer laptop, so this is visible
/// only in the isolated configuration the gate exists to serve.
fn live_home() -> std::path::PathBuf {
    std::env::var_os("MVM_E2E_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(mvm_core::config::mvm_home()))
}

/// Whether a prebuilt guest-binary directory was named and exists.
///
/// The variable appears in no Justfile recipe, no CI lane and no document, so
/// requiring it silently meant these scenarios could never pass — they simply
/// panicked on the missing variable the moment the live opt-in turned them on.
fn guest_bin_dir_available() -> bool {
    std::env::var_os("MVM_BDD_GUEST_BIN_DIR")
        .map(std::path::PathBuf::from)
        .is_some_and(|d| d.is_dir())
}

/// Whether the active backend can capture a full-VM memory snapshot here.
///
/// Declared by the operator rather than probed. `doctor --json` reports a tier
/// per backend, not for the one a launch would actually select, so deciding
/// this automatically would mean re-deriving backend auto-selection here — a
/// copy that drifts silently and, when it drifts, either skips a scenario that
/// could have run or fails one that never could.
///
/// `mvmctl doctor` prints the matrix; a host whose active backend reports
/// `save-restore` sets `MVM_BDD_SNAPSHOT=1`. Firecracker reports `unsupported`,
/// which is why the Linux lane leaves it unset.
/// Whether the active backend serves a live host-directory share (virtio-fs).
///
/// Declared by the operator rather than probed, matching
/// `memory_snapshot_supported`: the answer depends on which backend a launch
/// would actually select, and re-deriving that here would be a copy that
/// drifts. libkrun and HVF serve a share; Firecracker has no virtio-fs device
/// and refuses a `DirShare` volume before boot.
fn dir_share_supported() -> bool {
    std::env::var_os("MVM_BDD_DIR_SHARE").is_some()
}

fn memory_snapshot_supported() -> bool {
    std::env::var_os("MVM_BDD_SNAPSHOT").is_some()
}

/// The operator-supplied `.mvmpkg` a bundle scenario installs, when
/// `MVM_BDD_BUNDLE` names one that actually exists.
pub(crate) fn bundle_fixture_path() -> Option<std::path::PathBuf> {
    let path = std::path::PathBuf::from(std::env::var_os("MVM_BDD_BUNDLE")?);
    path.is_file().then_some(path)
}

/// The publisher key the fixture was sealed under (`MVM_BDD_BUNDLE_PUBKEY`),
/// 32 raw Ed25519 bytes as `mvmctl trust add` reads them.
///
/// Required alongside the archive, because a bundle installs into an isolated
/// `MVM_HOME` whose trust store starts empty and verification correctly refuses
/// an unknown `key_id`. Without this the scenario could never have passed —
/// which is exactly what it did, invisibly, for as long as nobody set
/// `MVM_BDD_BUNDLE` at all.
pub(crate) fn bundle_pubkey_path() -> Option<std::path::PathBuf> {
    let path = std::path::PathBuf::from(std::env::var_os("MVM_BDD_BUNDLE_PUBKEY")?);
    path.is_file().then_some(path)
}

/// A prebuilt workload kernel for the block-volume scenarios.
///
/// `MVM_BDD_WORKLOAD_KERNEL` names one explicitly. When it is unset the host's
/// own builder-VM cache is used — the same file the step would otherwise ask an
/// operator to point at by hand, at the path `mvmctl` already writes it to. That
/// default is what makes the lane runnable: the variable appears in no Justfile
/// recipe, no CI lane and no document, so requiring it meant the scenarios ran
/// nowhere.
pub(crate) fn workload_kernel_path() -> Option<std::path::PathBuf> {
    if let Some(explicit) = std::env::var_os("MVM_BDD_WORKLOAD_KERNEL") {
        let path = std::path::PathBuf::from(explicit);
        return path.is_file().then_some(path);
    }
    let cached = mvm_build::kernel_fetch::cached_kernel_path(
        std::path::Path::new(&mvm_core::config::default_mvm_cache_dir()),
        std::env::consts::ARCH,
        "workload",
    );
    cached.is_file().then_some(cached)
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
    binary_on_path("firecracker")
}

/// Whether `name` resolves to a file on `PATH`.
fn binary_on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).is_file()))
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

#[cfg(test)]
mod tests {
    #[test]
    fn relative_binary_paths_are_resolved_from_the_workspace_root() {
        assert_eq!(
            super::resolve_binary_path(
                std::path::PathBuf::from("target/debug/mvmctl"),
                std::path::Path::new("/workspace")
            ),
            std::path::PathBuf::from("/workspace/target/debug/mvmctl")
        );
    }

    #[test]
    fn absolute_binary_paths_are_preserved() {
        assert_eq!(
            super::resolve_binary_path(
                std::path::PathBuf::from("/tmp/mvmctl"),
                std::path::Path::new("/workspace")
            ),
            std::path::PathBuf::from("/tmp/mvmctl")
        );
    }
}
