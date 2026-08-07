//! Generic step definitions for conformance claim scenarios.
//!
//! Claim feature files (e.g. `features/suites/s6_admission_audit/
//! signed_execution_plan_claim.feature`) share a single shape: the claim is
//! registered in `model/claims.toml`, its suite is implemented in
//! `features/suites/`, and every witness on the claim resolves to a real
//! function or CI artifact. These steps re-use the same helpers that back
//! the R3 meta-gate so the BDD witness and the unit-test gate can never
//! disagree.

use cucumber::{given, then, when};
use mvm_conformance::claims::{
    self, find_claim, has_suite_scenario, repo_root, unresolved_witnesses,
};

use crate::world::CliWorld;

fn root() -> std::path::PathBuf {
    repo_root()
}

fn set_current_claim(world: &mut CliWorld, id: &str) {
    world.current_claim_id = Some(id.to_string());
}

fn current_claim(world: &CliWorld) -> claims::Claim {
    let id = world
        .current_claim_id
        .as_ref()
        .expect("a claim scenario must first set the current claim id");
    find_claim(&root(), id).unwrap_or_else(|| panic!("claim {id} is not registered"))
}

#[given(regex = r"^the scenario is registered for (MVM-[A-Z]+-\d+)$")]
fn scenario_is_registered(world: &mut CliWorld, id: String) {
    let claim = find_claim(&root(), &id)
        .unwrap_or_else(|| panic!("claim {id} is not registered in model/claims.toml"));
    assert_eq!(claim.id, id, "loaded claim id must match the scenario id");
    set_current_claim(world, &id);
}

#[when(regex = r"^the suite for (MVM-[A-Z]+-\d+) is implemented$")]
fn suite_is_implemented(world: &mut CliWorld, id: String) {
    let claim = find_claim(&root(), &id)
        .unwrap_or_else(|| panic!("claim {id} is not registered in model/claims.toml"));
    assert!(
        has_suite_scenario(&root(), &claim),
        "claim {} suite '{}' has no implemented scenario in features/suites/",
        claim.id,
        claim.suite
    );
    set_current_claim(world, &id);
}

#[then(regex = r"^the witness tests pass$")]
fn witness_tests_pass(world: &mut CliWorld) {
    let claim = current_claim(world);
    let unresolved = unresolved_witnesses(&root(), &claim);
    assert!(
        unresolved.is_empty(),
        "claim {} has unresolved witnesses: {}",
        claim.id,
        unresolved.join(", ")
    );
}
