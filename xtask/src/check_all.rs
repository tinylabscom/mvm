//! `xtask check-all` — every policy gate the lint lane runs, in one pass.
//!
//! These used to be sixty consecutive `cargo run -p xtask -- check-<name>`
//! steps in `ci.yml`'s lint-policy job. That shape had two costs. It ran
//! them serially and stopped at the first failure, so a branch breaking
//! four gates was fixed and re-pushed four times, each round trip paying a
//! full lane. And the list lived only in the YAML, so the only way to know
//! what CI enforced was to read the workflow — which is why more than one
//! session's notes say "derive the gate list by grepping the workflows".
//!
//! The list is here now, and [`main`](crate::main) dispatches individual
//! gates from the same table, so a gate cannot exist as a subcommand and
//! silently sit outside the lane.

use anyhow::{Result, bail};
use std::path::Path;

/// A gate: the subcommand name, and the function behind it.
pub type Gate = (&'static str, fn(&Path) -> Result<()>);

/// The mutation gate defaults to pinning the surface rather than mutating
/// it — the run itself costs hours and belongs to the nightly.
fn mutation_witnesses_surface_pin(workspace: &Path) -> Result<()> {
    crate::check_mutation_witnesses::run(
        workspace,
        crate::check_mutation_witnesses::Mode::PinOnly,
        None,
    )
}

/// Read-only: `--write` regenerates the model and is a developer action.
fn conformance_read_only(workspace: &Path) -> Result<()> {
    crate::check_conformance::run(workspace, false)
}

fn stubs_match_schemas(workspace: &Path) -> Result<()> {
    crate::gen_stubs::check(workspace)
}

fn ir_fixtures_match_schemas(workspace: &Path) -> Result<()> {
    crate::ir_parity::check(workspace)
}

/// Every gate the lint lane enforces, in the order the lane ran them.
///
/// Order is presentation only — each gate reads the tree and writes
/// nothing — but keeping it makes a diff against the old workflow legible.
pub const GATES: &[Gate] = &[
    ("check-adr-coverage", crate::check_adr_coverage::run),
    (
        "check-no-display-on-secret-types",
        crate::check_no_display_on_secret_types::run,
    ),
    ("check-audit-positional", crate::check_audit_positional::run),
    (
        "check-build-egress-callers",
        crate::check_build_egress_callers::run,
    ),
    (
        "check-verified-kernel-reads",
        crate::check_verified_kernel_reads::run,
    ),
    ("check-no-host-nix", crate::check_no_host_nix::run),
    ("check-no-vz", crate::check_no_vz::run),
    ("check-forbidden-deps", crate::check_forbidden_deps::run),
    ("check-doc-claims", crate::check_doc_claims::run),
    (
        "check-machine-doc-guards",
        crate::check_machine_doc_guards::run,
    ),
    ("check-no-overclaim", crate::check_no_overclaim::run),
    ("check-two-surfaces", crate::check_two_surfaces::run),
    (
        "check-no-spec-refs-in-comments",
        crate::check_no_spec_refs_in_comments::run,
    ),
    (
        "check-no-string-backend-dispatch",
        crate::check_no_string_backend_dispatch::run,
    ),
    ("check-single-home", crate::check_single_home::run),
    (
        "check-test-home-isolation",
        crate::check_test_home_isolation::run,
    ),
    (
        "check-no-network-literals",
        crate::check_no_network_literals::run,
    ),
    (
        "check-cli-runtime-surface",
        crate::check_cli_runtime_surface::run,
    ),
    (
        "check-cli-help-matches-docs",
        crate::check_cli_help_matches_docs::run,
    ),
    ("check-abi-layout", crate::check_abi_layout::run),
    ("check-claim-catalog", crate::check_claim_catalog::run),
    ("check-sprint-append", crate::check_sprint_append::run),
    ("check-plan-names", crate::check_plan_names::run),
    ("check-mutation-witnesses", mutation_witnesses_surface_pin),
    ("check-sdk-cdylib-deps", crate::check_sdk_cdylib_deps::run),
    (
        "check-witness-citations",
        crate::check_witness_citations::run,
    ),
    ("check-asserted-absence", crate::check_asserted_absence::run),
    ("check-agent-notes", crate::check_agent_notes::run),
    ("check-dormant-controls", crate::check_dormant_controls::run),
    ("check-conformance", conformance_read_only),
    ("check-deferrals", crate::check_deferrals::run),
    ("check-honesty", crate::check_honesty::run),
    ("check-trust-gradient", crate::check_trust_gradient::run),
    (
        "check-single-network-path",
        crate::check_single_network_path::run,
    ),
    ("check-no-virtio-fs", crate::check_no_virtio_fs::run),
    (
        "check-single-workload-env",
        crate::check_single_workload_env::run,
    ),
    (
        "check-no-guest-tool-client",
        crate::check_no_guest_tool_client::run,
    ),
    (
        "check-one-guest-protocol",
        crate::check_one_guest_protocol::run,
    ),
    (
        "check-single-exec-secs-writer",
        crate::check_single_exec_secs_writer::run,
    ),
    (
        "check-single-host-predicate",
        crate::check_single_host_predicate::run,
    ),
    (
        "check-stream-redaction-seam",
        crate::check_stream_redaction_seam::run,
    ),
    (
        "check-guest-init-parity",
        crate::check_guest_init_parity::run,
    ),
    (
        "check-require-grant-token-allowlist",
        crate::check_require_grant_token_allowlist::run,
    ),
    (
        "check-mvm-host-binaries-sync",
        crate::check_mvm_host_binaries_sync::run,
    ),
    (
        "check-per-vm-host-binaries-sync",
        crate::check_per_vm_host_binaries_sync::run,
    ),
    (
        "check-core-runtime-free",
        crate::check_core_runtime_free::run,
    ),
    (
        "check-sdk-transport-free",
        crate::check_sdk_transport_free::run,
    ),
    (
        "check-content-address-determinism",
        crate::check_content_address_determinism::run,
    ),
    ("check-closure-budget", crate::check_closure_budget::run),
    (
        "check-workspace-dep-inheritance",
        crate::check_workspace_dep_inheritance::run,
    ),
    (
        "check-feature-closure-budget",
        crate::check_feature_closure_budget::run,
    ),
    ("check-duplicate-majors", crate::check_duplicate_majors::run),
    ("check-workflow-paths", crate::check_workflow_paths::run),
    (
        "check-guest-agent-runtime-free",
        crate::check_guest_agent_runtime_free::run,
    ),
    (
        "check-guest-agent-in-all-images",
        crate::check_guest_agent_in_all_images::run,
    ),
    (
        "check-guest-images-no-builder-tools",
        crate::check_guest_images_no_builder_tools::run,
    ),
    (
        "check-guest-binary-lists",
        crate::check_guest_binary_lists::run,
    ),
    (
        "check-builder-shell-job-sites",
        crate::check_builder_shell_job_sites::run,
    ),
    (
        "check-guest-entropy-seed",
        crate::check_guest_entropy_seed::run,
    ),
    (
        "check-runtime-overlay-version",
        crate::check_runtime_overlay_version::run,
    ),
    ("check-file-size", crate::check_file_size::run),
    ("check-stubs", stubs_match_schemas),
    ("check-ir-parity", ir_fixtures_match_schemas),
    // Not in the lint lane before this table existed, and in no other
    // workflow either: they were reachable as subcommands and run by
    // nothing. All three pass on a clean tree, so they were not excluded
    // for failing — they were simply never wired in, which is the failure
    // mode the completeness test below now makes impossible.
    (
        "check-backend-resource-controls",
        crate::check_backend_resource_controls::run,
    ),
    ("check-vcpu-ceilings", crate::check_vcpu_ceilings::run),
    ("check-private-mvm-dirs", crate::check_private_mvm_dirs::run),
    (
        "check-single-fixture-corpus",
        crate::check_single_fixture_corpus::run,
    ),
    (
        "check-single-grants-projection",
        crate::check_single_grants_projection::run,
    ),
];

/// Run every gate, and report all of them.
///
/// Deliberately not fail-fast. The point of the change that introduced this
/// is that a contributor should learn about all four broken gates in one
/// run, not one per push.
pub fn run_all(workspace: &Path) -> Result<()> {
    let mut failed: Vec<(&str, String)> = Vec::new();

    for (name, gate) in GATES {
        match gate(workspace) {
            Ok(()) => eprintln!("  ok   {name}"),
            Err(error) => {
                eprintln!("  FAIL {name}");
                failed.push((name, format!("{error:#}")));
            }
        }
    }

    if !failed.is_empty() {
        let detail = failed
            .iter()
            .map(|(name, error)| format!("── {name} ───────────────\n{error}"))
            .collect::<Vec<_>>()
            .join("\n\n");
        bail!(
            "check-all: {} of {} gate(s) failed:\n\n{}\n\n\
             Each is reproducible on its own with `cargo run -p xtask -- <gate>`.",
            failed.len(),
            GATES.len(),
            detail
        );
    }

    eprintln!("check-all: {} gate(s) clean", GATES.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gates deliberately outside `check-all`, each with the reason.
    ///
    /// The list is exhaustive and asserted against `main.rs` below, so a
    /// new gate cannot be added as a subcommand and quietly run nowhere —
    /// which is exactly what had happened to three of the entries above.
    const NOT_IN_LINT_LANE: &[(&str, &str)] = &[
        ("check-all", "this driver"),
        (
            "check-binary-size",
            "needs a release binary; runs in release.yml",
        ),
        (
            "check-claim-witness-freshness",
            "asks whether scheduled lanes ran; has its own workflow",
        ),
        (
            "check-declared-backing",
            "runs --self-test alongside itself, so it stays a step of its own",
        ),
        (
            "check-kernel-config-budget",
            "takes a path to a resolved kernel .config; belongs to the kernel lane",
        ),
        (
            "check-kernel-pin-freshness",
            "queries upstream over the network; has its own scheduled workflow",
        ),
        (
            "check-nextest-groups",
            "needs cargo-nextest; runs in the test job",
        ),
        (
            "check-release-evidence",
            "asks whether a two-hour documented-surface run covered this exact \
             tree, which is a release-time question and false for every PR by \
             construction; runs in e2e-docs.yml's evidence job",
        ),
    ];

    fn dispatched_gates() -> Vec<String> {
        let src = include_str!("main.rs");
        let mut found: Vec<String> = src
            .match_indices("Some(\"check-")
            .filter_map(|(i, _)| {
                let rest = &src[i + "Some(\"".len()..];
                rest.find('"').map(|end| rest[..end].to_string())
            })
            .collect();
        found.sort();
        found.dedup();
        found
    }

    /// Every gate is either in the lane or excluded on the record.
    #[test]
    fn every_dispatched_gate_is_in_the_lane_or_excluded_with_a_reason() {
        let excluded: Vec<&str> = NOT_IN_LINT_LANE.iter().map(|(n, _)| *n).collect();
        let in_lane: Vec<&str> = GATES.iter().map(|(n, _)| *n).collect();

        for gate in dispatched_gates() {
            let known = in_lane.contains(&gate.as_str()) || excluded.contains(&gate.as_str());
            assert!(
                known,
                "{gate} is dispatched by main.rs but is in neither check-all's \
                 GATES nor NOT_IN_LINT_LANE — a gate that runs nowhere is not \
                 a gate. Add it to the table, or exclude it with a reason."
            );
        }
    }

    /// The exclusion list may not outlive the gates it names.
    #[test]
    fn every_exclusion_names_a_real_gate() {
        let dispatched = dispatched_gates();
        for (gate, reason) in NOT_IN_LINT_LANE {
            assert!(
                dispatched.iter().any(|d| d == gate),
                "{gate} is excluded from the lint lane ({reason}) but main.rs \
                 no longer dispatches it — drop the exclusion"
            );
        }
    }

    /// No gate is in the table twice, and none is both in and out.
    #[test]
    fn the_table_and_the_exclusions_are_disjoint_and_unique() {
        let mut names: Vec<&str> = GATES.iter().map(|(n, _)| *n).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(before, names.len(), "a gate appears twice in GATES");

        for (excluded, _) in NOT_IN_LINT_LANE {
            assert!(
                !names.contains(excluded),
                "{excluded} is both in GATES and excluded from the lane"
            );
        }
    }
}
