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

#[tokio::main]
async fn main() {
    CliWorld::filter_run(features_dir(), not_pending).await;
}

/// Keep a scenario only if it isn't tagged as pending-implementation.
fn not_pending(_feature: &Feature, _rule: Option<&Rule>, scenario: &Scenario) -> bool {
    !scenario.tags.iter().any(|tag| tag == PENDING_TAG)
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
