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
use world::CliWorld;

const PENDING_TAG: &str = "wip";

/// Scenarios that boot a real microVM and reach the network; opt in with
/// `MVM_BDD_LIVE=1` (skipped in the default hermetic lane).
const LIVE_TAG: &str = "live";

#[tokio::main]
async fn main() {
    CliWorld::filter_run(features_dir(), should_run).await;
}

/// Keep a scenario unless it is pending-implementation (`@wip`) or a live
/// scenario (`@live`) that must be opted into. A `@live` scenario boots a real
/// microVM and reaches the network, so it can't run in the default hermetic
/// lane — set `MVM_BDD_LIVE=1` on a host with a working backend to include it.
fn should_run(_feature: &Feature, _rule: Option<&Rule>, scenario: &Scenario) -> bool {
    let tags = &scenario.tags;
    if tags.iter().any(|tag| tag == PENDING_TAG) {
        return false;
    }
    if tags.iter().any(|tag| tag == LIVE_TAG) && std::env::var_os("MVM_BDD_LIVE").is_none() {
        return false;
    }
    true
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
