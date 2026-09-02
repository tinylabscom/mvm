//! The published launch-budget table must equal what the gate enforces.
//!
//! `mvm_cli::bench::doc_table` renders the budget section from
//! `LaunchLane::budgets()`, which is the same accessor `validate_matrix_report`
//! reads. This test pins the committed page to that render, so changing a
//! budget constant without regenerating the page fails here instead of leaving
//! a public number that no longer describes the gate.

use std::path::{Path, PathBuf};

use mvm_cli::bench::doc_table::{
    BEGIN_MARKER, END_MARKER, extract_budget_section, render_budget_section,
};

/// The root package's manifest dir is the repo root.
fn performance_page() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("public/src/content/docs/reference/performance.md")
}

fn read_page() -> String {
    let path = performance_page();
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

#[test]
fn published_budget_table_matches_the_gated_budgets() {
    let page = read_page();
    let found = extract_budget_section(&page).unwrap_or_else(|| {
        panic!(
            "{} is missing the generated region delimited by\n  {BEGIN_MARKER}\n  {END_MARKER}",
            performance_page().display()
        )
    });
    let expected = render_budget_section();
    let expected = expected.trim_end_matches('\n');

    assert_eq!(
        found,
        expected,
        "the published launch-budget table has drifted from the budgets the \
         matrix gate enforces.\n\nReplace the region between the markers in \
         {} with:\n\n{expected}\n",
        performance_page().display()
    );
}

/// The page must keep saying that the budgets are ceilings. Without this the
/// table reads as measured results, which is the specific misreading the page
/// exists to prevent.
#[test]
fn page_distinguishes_budgets_from_measurements() {
    let page = read_page();
    assert!(
        page.contains("not percentiles anyone observed"),
        "the page must state that the published budgets are ceilings, not results"
    );
}

#[test]
fn page_publishes_the_seeded_firecracker_report_as_measurement() {
    let page = read_page();
    for expected in [
        "Intel i7-7700",
        "Firecracker v1.14.1",
        "rotational md-RAID",
        "20 (+2 warm-ups)",
        "171.5 ms",
        "176.0 ms",
        "178.0 ms",
        "523ffd3f2904696141edd806861093abb1011de00d6c345b7acc3be27f4ee6c4",
    ] {
        assert!(
            page.contains(expected),
            "the seeded Firecracker measurement must publish {expected:?}"
        );
    }
}

/// A gate that cannot fail is not a gate: perturbing a number inside the
/// generated region must be detected by the same comparison the real test runs.
#[test]
fn drifted_table_is_detected() {
    let page = read_page();
    let perturbed = page.replace("| 200 ms |", "| 199 ms |");
    assert_ne!(
        perturbed, page,
        "expected a 200 ms budget cell in the committed page to perturb"
    );

    let found = extract_budget_section(&perturbed).expect("markers survive the perturbation");
    assert_ne!(
        found,
        render_budget_section().trim_end_matches('\n'),
        "a changed budget cell went undetected by the drift comparison"
    );
}
