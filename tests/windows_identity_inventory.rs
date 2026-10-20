//! Keep the complete known inventory distinct from the finite runtime witnesses.

use std::collections::BTreeSet;

const HELPER: &str = include_str!("../.github/scripts/run-windows-identity-tests.ps1");
const EMITTER_PREFIX: &str = "image_source::build::emitter::tests::";
const NEW_KNOWN_TEST: &str = "a_partial_set_from_a_checkout_without_a_declaration_records_none";

fn array_entries(variable: &str) -> Vec<&str> {
    let marker = format!("${variable} = @(");
    let body = HELPER
        .split_once(&marker)
        .expect("inventory array must exist")
        .1
        .split_once(')')
        .expect("inventory array must close")
        .0;
    body.split(',')
        .map(|entry| {
            entry
                .trim()
                .strip_prefix('\'')
                .and_then(|entry| entry.strip_suffix('\''))
                .expect("inventory entries must remain literal test IDs")
        })
        .collect()
}

#[test]
fn complete_emitter_inventory_keeps_new_known_cases_without_expanding_required_cases() {
    let known = array_entries("emitterTests");
    let required = array_entries("requiredEmitterTests");
    assert_eq!(known.len(), 7);
    assert_eq!(
        known.iter().copied().collect::<BTreeSet<_>>().len(),
        known.len()
    );
    assert!(known.contains(&NEW_KNOWN_TEST));
    assert_eq!(
        required,
        [
            "image_source::build::emitter::tests::changed_identity_refuses_and_cleans_up",
            "image_source::build::emitter::tests::post_inspection_staged_mutation_refuses_and_cleans_up",
        ]
    );
    for name in &required {
        assert!(known.contains(&name.strip_prefix(EMITTER_PREFIX).unwrap()));
    }
    assert!(!required.contains(&format!("{EMITTER_PREFIX}{NEW_KNOWN_TEST}").as_str()));
    assert_eq!(
        array_entries("gitTests").len()
            + required.len()
            + array_entries("requiredPairTests").len()
            + array_entries("coreTests").len(),
        32
    );
}

#[test]
fn inventory_enforcement_still_compares_exact_known_sets_and_executes_required_subset() {
    assert!(HELPER.contains(
        "Compare-Object ($Expected | Sort-Object) ($selected | Sort-Object) -CaseSensitive"
    ));
    assert!(HELPER.contains(
        "Test-Inventory $build 'emitter' $emitterTests 'image_source::build::emitter::tests::' $requiredEmitterTests"
    ));
    assert!(HELPER.contains("foreach ($name in $Required)"));
    assert!(HELPER.contains("if ($Expected -cnotcontains $name)"));
    assert!(HELPER.contains("'--exact', '--test-threads=1', '--nocapture'"));
    assert!(HELPER.contains(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;"));
    assert!(HELPER.contains("$results.Count -ne 33"));
}

#[test]
fn application_reader_refusal_is_an_additive_required_source_bound_witness() {
    let application = array_entries("applicationTests");
    assert_eq!(
        application,
        [
            "registry_pack_store::tests::open_application_descriptor_preserves_unsupported_safe_reader_refusal"
        ]
    );
    assert!(HELPER.contains(
        "Test-Inventory $core 'application-local-reader-refusal' $applicationTests $applicationTests[0]"
    ));
    assert!(HELPER.contains("$applicationTests.Count -ne 1"));
    assert!(HELPER.contains("if ($ignoredNames -ccontains $name)"));
    let controls = HELPER
        .split_once("function Control-Hashes {")
        .unwrap()
        .1
        .split_once("function Compile-Test {")
        .unwrap()
        .0;
    assert!(controls.contains("'crates/mvm-core/src/registry_pack_store.rs'"));
    let original_required = array_entries("gitTests").len()
        + array_entries("requiredEmitterTests").len()
        + array_entries("requiredPairTests").len()
        + array_entries("coreTests").len();
    assert_eq!(original_required, 32);
    assert_eq!(original_required + application.len(), 33);
}
