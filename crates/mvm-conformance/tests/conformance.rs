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
    CliWorld::filter_run(features_dir(), should_run).await;
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
    }
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
