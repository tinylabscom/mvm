//! Entry point for the dev-only cucumber-rs conformance harness.
//!
//! Wires the Gherkin scenarios under `features/suites/` to real step
//! definitions and runs them against the built `mvmctl` binary — and, as
//! later suites land, the `mvm-client` facade directly. Scenarios tagged
//! `@wip` describe coverage whose steps aren't implemented yet; they are
//! filtered out here so the suite stays green while a suite is still a
//! stub. Remove the tag in the same change that lands its steps.

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
