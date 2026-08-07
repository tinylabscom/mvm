//! R2/R3 meta-gate for the conformance claim register.
//!
//! R3: every capability begins as a register row, then a Gherkin scenario,
//! then a witness. This test loads `model/claims.toml`, parses every
//! `features/suites/**/*.feature` file for ID/level tags, and fails if:
//!   - a registered claim has no scenario,
//!   - a scenario names an unregistered ID,
//!   - a scenario's level tag disagrees with the register,
//!   - a registered claim has no resolvable witness.
//!
//! R2: the honesty levels only mean something if the suite respects them.
//! The structural half (every claim has exactly one level, every some-true
//! claim cites an authority) is enforced by `xtask check-conformance`. The
//! behavioural half --- that no `open` claim is asserted as established ---
//! is enforced by `xtask check-honesty`.

use mvm_conformance::claims::{self, find_claim, load_scenarios, repo_root, unresolved_witnesses};

#[test]
fn every_registered_claim_has_a_scenario_and_witness() {
    let root = repo_root();
    let claims = claims::load_claims(&root);
    let scenarios = load_scenarios(&root);

    let by_scenario: std::collections::BTreeMap<&str, &claims::Scenario> =
        scenarios.iter().map(|s| (s.id.as_str(), s)).collect();

    let mut errors = Vec::new();

    for claim in &claims {
        let Some(scenario) = by_scenario.get(claim.id.as_str()) else {
            errors.push(format!(
                "R3: {} is registered but has no scenario in features/suites/",
                claim.id
            ));
            continue;
        };
        if scenario.level != claim.level.as_str() {
            errors.push(format!(
                "R2: {} is tagged `{}` in {} but `{}` in the register",
                claim.id,
                scenario.level,
                scenario.suite,
                claim.level.as_str()
            ));
        }
        if scenario.steps.is_empty() {
            errors.push(format!(
                "R3: scenario `{}` in {} has no steps",
                scenario.statement, scenario.suite
            ));
        }

        let unresolved = unresolved_witnesses(&root, claim);
        if !unresolved.is_empty() {
            errors.push(format!(
                "R3: {} has unresolved witnesses: {}",
                claim.id,
                unresolved.join(", ")
            ));
        }
    }

    let registered: std::collections::BTreeSet<&str> =
        claims.iter().map(|c| c.id.as_str()).collect();
    for scenario in &scenarios {
        if scenario.id.is_empty() {
            // Untagged scenarios are allowed: they exercise product behaviour
            // that is not (yet) part of the formal claim register.
            continue;
        }
        if !registered.contains(scenario.id.as_str()) {
            errors.push(format!(
                "R3: scenario `{}` in {} names `{}`, which is not in the register",
                scenario.statement, scenario.suite, scenario.id
            ));
        }
    }

    assert!(
        errors.is_empty(),
        "conformance meta-gate failed:\n\n{}",
        errors.join("\n")
    );

    eprintln!(
        "R3 meta-gate: {} registered claims, {} scenarios",
        claims.len(),
        scenarios.len()
    );
}

#[test]
fn claim_lookup_by_id_round_trips() {
    let root = repo_root();
    let ids = claims::registered_ids(&root);
    for id in &ids {
        assert!(
            find_claim(&root, id).is_some(),
            "registered id {id} must be findable"
        );
    }
}
