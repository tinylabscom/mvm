use anyhow::Result;
use std::path::PathBuf;
use xtask::network_perf;

// Only the gen-man path (gated behind `man`) uses these.
#[cfg(feature = "man")]
use anyhow::Context;
#[cfg(feature = "man")]
use std::path::Path;

mod build_dev_image;
mod check_abi_layout;
mod check_adr_coverage;
mod check_agent_notes;
mod check_all;
mod check_asserted_absence;
mod check_audit_positional;
mod check_backend_resource_controls;
mod check_binary_size;
mod check_build_egress_callers;
mod check_builder_shell_job_sites;
mod check_claim_catalog;
mod check_claim_witness_freshness;
mod check_cli_help_matches_docs;
mod check_cli_runtime_surface;
mod check_closure_budget;
mod check_conformance;
mod check_content_address_determinism;
mod check_core_runtime_free;
mod check_declared_backing;
mod check_deferrals;
mod check_doc_claims;
mod check_dormant_controls;
mod check_duplicate_majors;
mod check_feature_closure_budget;
mod check_file_size;
mod check_forbidden_deps;
mod check_guest_agent_in_all_images;
mod check_guest_agent_runtime_free;
mod check_guest_binary_lists;
mod check_guest_entropy_seed;
mod check_guest_images_no_builder_tools;
mod check_guest_init_parity;
mod check_honesty;
pub(crate) mod check_kernel_config_budget;
mod check_kernel_pin_freshness;
mod check_machine_doc_guards;
mod check_mutation_witnesses;
mod check_mvm_host_binaries_sync;
mod check_nextest_groups;
mod check_no_display_on_secret_types;
mod check_no_guest_tool_client;
mod check_no_host_nix;
mod check_no_network_literals;
mod check_no_overclaim;
mod check_no_spec_refs_in_comments;
mod check_no_string_backend_dispatch;
mod check_no_virtio_fs;
mod check_no_vz;
mod check_one_guest_protocol;
mod check_per_vm_host_binaries_sync;
mod check_plan_names;
mod check_private_mvm_dirs;
mod check_require_grant_token_allowlist;
mod check_runtime_overlay_version;
mod check_sdk_cdylib_deps;
mod check_sdk_transport_free;
mod check_single_exec_secs_writer;
mod check_single_fixture_corpus;
mod check_single_grants_projection;
mod check_single_home;
mod check_single_host_predicate;
mod check_single_network_path;
mod check_single_workload_env;
mod check_sprint_append;
mod check_stream_redaction_seam;
mod check_test_home_isolation;
mod check_trust_gradient;
mod check_two_surfaces;
mod check_vcpu_ceilings;
mod check_verified_kernel_reads;
mod check_witness_citations;
mod check_workflow_paths;
mod check_workspace_dep_inheritance;
mod claims_ledger;
mod fs_walk;
mod gen_sdk_surface;
mod gen_stubs;
mod ir_parity;
mod perf;
mod prose_citations;
mod release_evidence;
mod rust_source;
mod sprint;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("gen-man") => {
            #[cfg(feature = "man")]
            {
                let output_dir = parse_output_dir(&args).unwrap_or_else(default_man_dir);
                gen_man(&output_dir)
            }
            // Man-page generation pulls mvm-cli (and its heavy build.rs), so it
            // lives behind the off-by-default `man` feature. release.yml is the
            // only caller and builds with `--features man`.
            #[cfg(not(feature = "man"))]
            {
                let _ = &args;
                anyhow::bail!(
                    "gen-man requires the `man` feature: cargo run -p xtask --features man -- gen-man"
                )
            }
        }
        Some("check-adr-coverage") => {
            let workspace = workspace_root();
            check_adr_coverage::run(&workspace)
        }
        Some("check-no-display-on-secret-types") => {
            let workspace = workspace_root();
            check_no_display_on_secret_types::run(&workspace)
        }
        Some("check-audit-positional") => {
            let workspace = workspace_root();
            check_audit_positional::run(&workspace)
        }
        Some("check-build-egress-callers") => {
            let workspace = workspace_root();
            check_build_egress_callers::run(&workspace)
        }
        Some("check-verified-kernel-reads") => {
            let workspace = workspace_root();
            check_verified_kernel_reads::run(&workspace)
        }
        Some("check-no-host-nix") => {
            let workspace = workspace_root();
            check_no_host_nix::run(&workspace)
        }
        Some("check-no-vz") => {
            let workspace = workspace_root();
            check_no_vz::run(&workspace)
        }
        Some("check-doc-claims") => {
            let workspace = workspace_root();
            check_doc_claims::run(&workspace)
        }
        Some("check-cli-help-matches-docs") => {
            let workspace = workspace_root();
            check_cli_help_matches_docs::run(&workspace)
        }
        Some("check-machine-doc-guards") => {
            let workspace = workspace_root();
            check_machine_doc_guards::run(&workspace)
        }
        Some("check-forbidden-deps") => {
            let workspace = workspace_root();
            check_forbidden_deps::run(&workspace)
        }
        Some("check-core-runtime-free") => {
            let workspace = workspace_root();
            check_core_runtime_free::run(&workspace)
        }
        Some("check-content-address-determinism") => {
            let workspace = workspace_root();
            check_content_address_determinism::run(&workspace)
        }
        Some("check-deferrals") => {
            let workspace = workspace_root();
            check_deferrals::run(&workspace)
        }
        Some("check-honesty") => {
            let workspace = workspace_root();
            check_honesty::run(&workspace)
        }
        Some("check-builder-shell-job-sites") => {
            let workspace = workspace_root();
            check_builder_shell_job_sites::run(&workspace)
        }
        Some("check-guest-entropy-seed") => {
            let workspace = workspace_root();
            check_guest_entropy_seed::run(&workspace)
        }
        Some("check-closure-budget") => {
            let workspace = workspace_root();
            check_closure_budget::run(&workspace)
        }
        Some("check-workspace-dep-inheritance") => {
            let workspace = workspace_root();
            check_workspace_dep_inheritance::run(&workspace)
        }
        Some("check-feature-closure-budget") => {
            let workspace = workspace_root();
            check_feature_closure_budget::run(&workspace)
        }
        Some("check-duplicate-majors") => {
            let workspace = workspace_root();
            check_duplicate_majors::run(&workspace)
        }
        Some("check-guest-agent-runtime-free") => {
            let workspace = workspace_root();
            check_guest_agent_runtime_free::run(&workspace)
        }
        Some("check-sdk-transport-free") => {
            let workspace = workspace_root();
            check_sdk_transport_free::run(&workspace)
        }
        Some("check-guest-agent-in-all-images") => {
            let workspace = workspace_root();
            check_guest_agent_in_all_images::run(&workspace)
        }
        Some("check-guest-images-no-builder-tools") => {
            let workspace = workspace_root();
            check_guest_images_no_builder_tools::run(&workspace)
        }
        Some("check-guest-binary-lists") => {
            let workspace = workspace_root();
            check_guest_binary_lists::run(&workspace)
        }
        Some("check-no-overclaim") => {
            let workspace = workspace_root();
            check_no_overclaim::run(&workspace)
        }
        Some("check-two-surfaces") => {
            let workspace = workspace_root();
            check_two_surfaces::run(&workspace)
        }
        Some("check-single-grants-projection") => {
            let workspace = workspace_root();
            check_single_grants_projection::run(&workspace)
        }
        Some("check-single-exec-secs-writer") => {
            let workspace = workspace_root();
            check_single_exec_secs_writer::run(&workspace)
        }
        Some("check-single-host-predicate") => {
            let workspace = workspace_root();
            check_single_host_predicate::run(&workspace)
        }
        Some("check-backend-resource-controls") => {
            let workspace = workspace_root();
            check_backend_resource_controls::run(&workspace)
        }
        Some("check-no-spec-refs-in-comments") => {
            let workspace = workspace_root();
            check_no_spec_refs_in_comments::run(&workspace)
        }
        Some("check-no-string-backend-dispatch") => {
            let workspace = workspace_root();
            check_no_string_backend_dispatch::run(&workspace)
        }
        Some("check-plan-names") => {
            let workspace = workspace_root();
            check_plan_names::run(&workspace)
        }
        Some("record-release-evidence") => {
            let workspace = workspace_root();
            let usage = || anyhow::anyhow!("usage: record-release-evidence <lane> <suite-log>");
            let lane = args.get(2).ok_or_else(usage)?;
            let log = args.get(3).ok_or_else(usage)?;
            release_evidence::record(&workspace, lane, std::path::Path::new(log))
        }
        Some("check-release-evidence") => {
            let workspace = workspace_root();
            let lanes: Vec<String> = args[2..]
                .iter()
                .filter(|a| !a.starts_with('-'))
                .cloned()
                .collect();
            release_evidence::check(&workspace, &lanes)
        }
        Some("check-single-fixture-corpus") => {
            let workspace = workspace_root();
            check_single_fixture_corpus::run(&workspace)
        }
        Some("check-single-home") => {
            let workspace = workspace_root();
            check_single_home::run(&workspace)
        }
        Some("check-test-home-isolation") => {
            let workspace = workspace_root();
            check_test_home_isolation::run(&workspace)
        }
        Some("check-no-network-literals") => {
            let workspace = workspace_root();
            check_no_network_literals::run(&workspace)
        }
        Some("check-cli-runtime-surface") => {
            let workspace = workspace_root();
            check_cli_runtime_surface::run(&workspace)
        }
        Some("check-abi-layout") => {
            let workspace = workspace_root();
            check_abi_layout::run(&workspace)
        }
        Some("check-claim-witness-freshness") => {
            let workspace = workspace_root();
            // Reporting-chain checks are for the scheduled run; see the
            // module docs for why a pull request must not fail on them.
            let reporting = args.iter().any(|a| a == "--check-reporting");
            check_claim_witness_freshness::run(&workspace, reporting)
        }
        Some("check-sdk-cdylib-deps") => {
            let workspace = workspace_root();
            check_sdk_cdylib_deps::run(&workspace)
        }
        Some("check-witness-citations") => {
            let workspace = workspace_root();
            check_witness_citations::run(&workspace)
        }
        Some("check-asserted-absence") => {
            let workspace = workspace_root();
            check_asserted_absence::run(&workspace)
        }
        Some("check-agent-notes") => {
            let workspace = workspace_root();
            check_agent_notes::run(&workspace)
        }
        Some("check-declared-backing") => {
            let workspace = workspace_root();
            if std::env::args().any(|a| a == "--self-test") {
                check_declared_backing::self_test()
            } else {
                check_declared_backing::run(&workspace)
            }
        }
        Some("check-dormant-controls") => {
            let workspace = workspace_root();
            check_dormant_controls::run(&workspace)
        }
        Some("check-claim-catalog") => {
            let workspace = workspace_root();
            check_claim_catalog::run(&workspace)
        }
        Some("check-sprint-append") => {
            let workspace = workspace_root();
            check_sprint_append::run(&workspace)
        }
        Some("sprint") => {
            let workspace = workspace_root();
            sprint::run(&workspace)
        }
        Some("check-mutation-witnesses") => {
            let workspace = workspace_root();
            // Default is the cheap surface pin, so the PR lint lane can
            // run this without cargo-mutants installed. The mutation run
            // itself is opt-in because it costs hours.
            let write = args.iter().any(|a| a == "--write-baseline");
            let run = args.iter().any(|a| a == "--run");
            let mode = match (write, run) {
                (true, true) => check_mutation_witnesses::Mode::RewriteBaseline,
                (true, false) => check_mutation_witnesses::Mode::RepinSurface,
                (false, true) => check_mutation_witnesses::Mode::Run,
                (false, false) => check_mutation_witnesses::Mode::PinOnly,
            };
            // `--package <name>` shards a `--run` so each CI job finishes
            // inside the six-hour job cap; unset means the whole surface. A
            // package that outgrew one job takes the `<name>/<i>of<n>` form.
            let shard = args
                .iter()
                .position(|a| a == "--package")
                .and_then(|i| args.get(i + 1))
                .map(|raw| check_mutation_witnesses::parse_shard_spec(raw))
                .transpose()?;
            check_mutation_witnesses::run(&workspace, mode, shard.as_ref())
        }
        Some("check-nextest-groups") => {
            let workspace = workspace_root();
            check_nextest_groups::run(&workspace)
        }
        Some("check-conformance") => {
            let workspace = workspace_root();
            let write = args.iter().any(|a| a == "--write");
            check_conformance::run(&workspace, write)
        }
        Some("check-trust-gradient") => {
            let workspace = workspace_root();
            check_trust_gradient::run(&workspace)
        }
        Some("check-one-guest-protocol") => {
            let workspace = workspace_root();
            check_one_guest_protocol::run(&workspace)
        }
        Some("check-no-guest-tool-client") => {
            let workspace = workspace_root();
            check_no_guest_tool_client::run(&workspace)
        }
        Some("check-no-virtio-fs") => {
            let workspace = workspace_root();
            check_no_virtio_fs::run(&workspace)
        }
        Some("check-single-network-path") => {
            let workspace = workspace_root();
            check_single_network_path::run(&workspace)
        }
        Some("check-vcpu-ceilings") => {
            let workspace = workspace_root();
            check_vcpu_ceilings::run(&workspace)
        }
        Some("check-private-mvm-dirs") => {
            let workspace = workspace_root();
            check_private_mvm_dirs::run(&workspace)
        }
        Some("check-guest-init-parity") => {
            let workspace = workspace_root();
            check_guest_init_parity::run(&workspace)
        }
        Some("check-single-workload-env") => {
            let workspace = workspace_root();
            check_single_workload_env::run(&workspace)
        }
        Some("check-stream-redaction-seam") => {
            let workspace = workspace_root();
            check_stream_redaction_seam::run(&workspace)
        }
        Some("check-require-grant-token-allowlist") => {
            let workspace = workspace_root();
            check_require_grant_token_allowlist::run(&workspace)
        }
        Some("check-mvm-host-binaries-sync") => {
            let workspace = workspace_root();
            check_mvm_host_binaries_sync::run(&workspace)
        }
        Some("check-per-vm-host-binaries-sync") => {
            let workspace = workspace_root();
            check_per_vm_host_binaries_sync::run(&workspace)
        }
        Some("check-workflow-paths") => {
            let workspace = workspace_root();
            check_workflow_paths::run(&workspace)
        }
        Some("check-runtime-overlay-version") => {
            let workspace = workspace_root();
            check_runtime_overlay_version::run(&workspace)
        }
        Some("check-file-size") => {
            let workspace = workspace_root();
            check_file_size::run(&workspace)
        }
        Some("check-binary-size") => check_binary_size::run(&args[2..]),
        Some("check-kernel-config-budget") => check_kernel_config_budget::run(&args[2..]),
        Some("check-kernel-pin-freshness") => {
            let workspace = workspace_root();
            check_kernel_pin_freshness::run(&workspace, &args[2..])
        }
        Some("perf") => perf::run(&args[2..]),
        Some("network-perf") => network_perf::run(&args[2..]),
        Some("build-dev-image") => {
            let workspace = workspace_root();
            build_dev_image::run(&args[2..], &workspace)
        }
        Some("gen-stubs") => {
            let workspace = workspace_root();
            gen_stubs::generate(&workspace)
        }
        Some("check-stubs") => {
            let workspace = workspace_root();
            gen_stubs::check(&workspace)
        }
        Some("gen-ir-parity") => {
            let workspace = workspace_root();
            ir_parity::generate(&workspace)
        }
        Some("check-ir-parity") => {
            let workspace = workspace_root();
            ir_parity::check(&workspace)
        }
        Some("check-all") => {
            let workspace = workspace_root();
            check_all::run_all(&workspace)
        }
        Some(other) => anyhow::bail!(
            "Unknown xtask: {:?}. Available: gen-man, check-all, check-adr-coverage, check-no-display-on-secret-types, check-audit-positional, check-doc-claims, check-machine-doc-guards, check-forbidden-deps, check-core-runtime-free, check-sdk-transport-free, check-sdk-cdylib-deps, check-content-address-determinism, check-deferrals, check-honesty, check-closure-budget, check-workspace-dep-inheritance, check-duplicate-majors, check-binary-size, check-kernel-config-budget, check-kernel-pin-freshness, check-builder-shell-job-sites, check-guest-entropy-seed, check-guest-agent-runtime-free, check-guest-agent-in-all-images, check-guest-images-no-builder-tools, check-guest-binary-lists, check-no-overclaim, check-two-surfaces, check-no-spec-refs-in-comments, check-no-string-backend-dispatch, check-plan-names, record-release-evidence, check-release-evidence, check-single-home, check-single-fixture-corpus, check-test-home-isolation, check-no-network-literals, check-cli-runtime-surface, check-cli-help-matches-docs, check-claim-catalog, check-sprint-append, sprint, check-dormant-controls, check-witness-citations, check-asserted-absence, check-agent-notes, check-declared-backing, check-claim-witness-freshness, check-abi-layout, check-mutation-witnesses, check-nextest-groups, check-conformance, check-trust-gradient, check-single-network-path, check-no-virtio-fs, check-no-guest-tool-client, check-one-guest-protocol, check-single-workload-env, check-build-egress-callers, check-verified-kernel-reads, check-stream-redaction-seam, check-guest-init-parity, check-require-grant-token-allowlist, check-mvm-host-binaries-sync, check-per-vm-host-binaries-sync, check-workflow-paths, check-runtime-overlay-version, check-single-grants-projection, check-single-exec-secs-writer, check-single-host-predicate, check-backend-resource-controls, check-vcpu-ceilings, perf, network-perf, build-dev-image, gen-stubs, check-stubs, gen-ir-parity, check-ir-parity",
            other
        ),
        None => {
            eprintln!("Usage: cargo xtask <task>");
            eprintln!("Available tasks:");
            eprintln!(
                "  gen-man [--output-dir DIR]              Generate man pages into DIR (default: man/) — build with --features man"
            );
            eprintln!(
                "  check-adr-coverage                      Report ADRs with no code references"
            );
            eprintln!(
                "  check-no-display-on-secret-types        Plan 63 W2 lint: reject Debug/Display on secret-named types"
            );
            eprintln!(
                "  check-audit-positional                  Plan 60 Phase 4 lint: reject positional audit::emit / event-chain calls"
            );
            eprintln!(
                "  check-doc-claims                        Plan 74 W0 lint: reject gated marketing phrases in public docs"
            );
            eprintln!(
                "  check-cli-help-matches-docs             Hold `mvmctl --help` and the CLI reference to the same verb set"
            );
            eprintln!(
                "  check-machine-doc-guards                Plan 200 lint: require machine use-case/limitations docs and reject beginner overclaims"
            );
            eprintln!(
                "  check-forbidden-deps                    Reject sea-*/mysql in Cargo.lock + sigstore/opendal/pgp in mvmctl's default closure"
            );
            eprintln!(
                "  check-core-runtime-free                 Plan 126 B5: assert mvm-core's default build pulls no tokio"
            );
            eprintln!(
                "  check-sdk-transport-free                Assert mvm-sdk's default build (the cdylib closure) pulls no mvm-http/rustls/ring/tokio"
            );
            eprintln!(
                "  check-content-address-determinism       Assert serde_json in mvm-core/mvm-contract has no preserve_order (stable key order → deterministic plan_id/checkpoint digests)"
            );
            eprintln!(
                "  check-deferrals                         Verify no deferred TODO/FIXME/unimplemented!/placeholder markers"
            );
            eprintln!(
                "  check-honesty                         Verify no open/some-true claim is asserted as established in docs"
            );
            eprintln!(
                "  check-builder-shell-job-sites           Plan 204 WS-D: freeze the set of files that construct a legacy builder shell-job request"
            );
            eprintln!(
                "  check-guest-entropy-seed                Every VMM boot path must seed the guest CSPRNG via /chosen/rng-seed"
            );
            eprintln!(
                "  check-closure-budget                    Plan 200: assert mvmctl's default linux + macOS closures stay within their crate budgets"
            );
            eprintln!(
                "  check-duplicate-majors                  Plan 200: assert no new crate resolves at two incompatible majors"
            );
            eprintln!(
                "  check-binary-size --path P --budget-bytes N  Plan 200: assert a built release binary stays within a byte budget"
            );
            eprintln!(
                "  check-guest-agent-runtime-free          Plan 124 A: assert mvm-guest's Linux closure pulls no tokio/async-trait/rtnetlink"
            );
            eprintln!(
                "  check-guest-agent-in-all-images         Plan 124 B: assert every bootable image's launch path forks mvm-guest-agent"
            );
            eprintln!(
                "  check-guest-images-no-builder-tools     assert mkGuest never bakes mvmctl / mvm-builderd into workload guest images"
            );
            eprintln!(
                "  check-guest-binary-lists                assert the four OCI guest-binary name lists agree and name real [[bin]]s"
            );
            eprintln!(
                "  check-runtime-overlay-version           Plan 124 C: assert the runtime-overlay flake's overlayVersion matches the workspace version"
            );
            eprintln!(
                "  check-no-overclaim                      Plan 75 W0 lint: refuse gated phrases from claim frontmatter embedded in specs/adrs/ outside exempt paths"
            );
            eprintln!(
                "  check-no-spec-refs-in-comments         Reject plan/PR/ADR/sprint/workstream citations in source comments"
            );
            eprintln!(
                "  check-no-string-backend-dispatch       Reject backend.name() == \"…\" / matches!(…name()…) dispatch — use VmBackend::kind()"
            );
            eprintln!(
                "  check-single-home                      Reject host-path derivations that bypass mvm-core::config's single MVM_HOME root"
            );
            eprintln!(
                "  check-test-home-isolation              Reject tests that move MVM_HOME but not HOME in files that can reach the MVM_HOME-ignoring default cache"
            );
            eprintln!(
                "  check-cli-runtime-surface              Reject mvm_runtime::vm::name_registry + AnyBackend reaches in mvm-cli drive-a-machine code — route through the mvm-client facade"
            );
            eprintln!(
                "  check-no-network-literals              Reject baked IPs/ports/tmp-sockets — route through mvm-core::dev_network / guest_netd"
            );
            eprintln!(
                "  check-abi-layout                       Verify every #[repr(C)] type carries a compile-time size + alignment contract"
            );
            eprintln!(
                "  check-claim-catalog                    Verify the claims ledger embedded in specs/adrs/001-microvm-security-posture.md — witnesses still exist in the tree"
            );
            eprintln!(
                "  check-sprint-append                    specs/SPRINT.md's delivery archive stays frozen — new entries go in specs/sprint/delivery/"
            );
            eprintln!(
                "  sprint                                 Render specs/sprint/delivery/ as one document, newest first"
            );
            println!(
                "  check-sdk-cdylib-deps                  mvm-sdk's default closure carries no host HTTP/TLS/async stack"
            );
            eprintln!(
                "  check-witness-citations                Prose that names a witness must name one that exists"
            );
            println!(
                "  check-asserted-absence                 Prose that says a name was never written must stay right about that"
            );
            println!(
                "  check-agent-notes                      Committed agent findings parse, are dated, and link to notes that exist"
            );
            println!(
                "  check-declared-backing                 Claim-bearing prose declares what backs it (--self-test)"
            );
            println!(
                "  check-dormant-controls                 Security-relevant controls declare whether they have a production caller; the dormant list may only shrink"
            );
            println!(
                "  check-mutation-witnesses               Pin the mutation surface derived from the claims ledger; --run mutates it and ratchets survivors; --write-baseline re-pins (add --run to also re-record misses)"
            );
            println!(
                "  check-nextest-groups                   Verify every cargo-nextest test-group override still matches at least one test"
            );
            eprintln!(
                "  check-conformance                      Verify model/*.toml is the single source and CONFORMANCE.md is up to date"
            );
            eprintln!(
                "  check-trust-gradient                   Verify trust-gradient ledger: monotonic tiers, workload forbidden authorities, witnesses"
            );
            eprintln!(
                "  check-stream-redaction-seam            Assert StreamRedaction stays newtype-sealed over the curated ruleset and every StreamBroker is built through it"
            );
            eprintln!(
                "  check-require-grant-token-allowlist     assert mvm.require_grant=1 appears only in the four backend builders + mvm-guest/vsock.rs"
            );
            eprintln!(
                "  check-mvm-host-binaries-sync            Plan 115 / ADR-004: assert Rust manifest and Nix attrset agree"
            );
            eprintln!(
                "  check-per-vm-host-binaries-sync         assert release.yml builds+packages every spawnable per-VM binary"
            );
            eprintln!(
                "  check-single-network-path              assert one endpoint, one NetworkFlow channel, no guest NIC/L3 path, and one workload socket owner"
            );
            eprintln!(
                "  check-vcpu-ceilings                    assert no backend derives its declared vCPU ceiling from a wire type's MAX"
            );
            println!(
                "  check-no-virtio-fs                     ratchet the virtio-fs attach surface: builder VM and FFI only, may shrink but never grow"
            );
            eprintln!(
                "  check-workflow-paths                    assert every workflow working-directory and cargo-fuzz target still exists"
            );
            eprintln!(
                "  perf <subcommand>                       Plan 60 Phase 9 perf gates (rootfs-size, boot)"
            );
            eprintln!(
                "  network-perf <subcommand>               Validate and compare labelled network benchmark reports"
            );
            eprintln!(
                "  build-dev-image [--arch <arch>]         Build the dev VM image and drop it into nix/images/dev-prebuilt/<arch>/"
            );
            eprintln!(
                "  gen-stubs                               Regenerate the workload-IR + host↔guest-protocol JSON schemas and their Python/TS SDK types"
            );
            eprintln!(
                "  check-plan-names                        CI gate — fail if a new plan is named by number"
            );
            eprintln!(
                "  record-release-evidence <lane> <log>    Record that a documented-surface lane ran clean against this tree"
            );
            eprintln!(
                "  check-release-evidence [lane...]        CI gate — fail unless each lane's evidence covers the current tree"
            );
            eprintln!(
                "  check-single-fixture-corpus             CI gate — fail if the golden machine-fixtures corpus is shadowed"
            );
            println!(
                "  check-stubs                             CI gate — fail if any generated schema/stub is stale"
            );
            eprintln!(
                "  gen-ir-parity                          Regenerate Python/TypeScript shared IR fixtures"
            );
            eprintln!(
                "  check-ir-parity                        Re-run SDK fixtures and fail on IR drift"
            );
            std::process::exit(1);
        }
    }
}

/// Resolve the workspace root from the xtask manifest dir. xtask's
/// `CARGO_MANIFEST_DIR` resolves to `<workspace>/xtask/`, so the
/// workspace root is the parent directory.
fn workspace_root() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
    manifest
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or(manifest)
}

#[cfg(feature = "man")]
fn parse_output_dir(args: &[String]) -> Option<PathBuf> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--output-dir" {
            return iter.next().map(PathBuf::from);
        }
    }
    None
}

#[cfg(feature = "man")]
fn default_man_dir() -> PathBuf {
    workspace_root().join("man")
}

#[cfg(test)]
mod guest_init_tests {
    #[test]
    fn guest_init_detaches_workload_stdin_from_console() {
        // The sealed-workload arm must source the boot command with stdin
        // redirected away from the input-less serial console; otherwise a
        // workload that reads stdin EOF-crashes shortly after boot.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../nix/lib/mk-guest.nix");
        let init = std::fs::read_to_string(path).expect("read mk-guest.nix");
        assert!(
            init.contains(". \"$MVM_BOOT\" </dev/null"),
            "mk-guest.nix workload arm must redirect the workload's stdin to /dev/null"
        );
    }
}

#[cfg(feature = "man")]
pub fn gen_man(output_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(output_dir).with_context(|| {
        format!(
            "Failed to create output directory: {}",
            output_dir.display()
        )
    })?;

    let cmd = mvm_cli::commands::cli_command();
    generate_man_pages(&cmd, output_dir)?;

    println!("Man pages written to: {}", output_dir.display());
    Ok(())
}

/// Generate man pages for `cmd` and each of its subcommands.
///
/// Top-level page: `<cmd_name>.1`
/// Subcommand pages: `<cmd_name>-<sub>.1`
#[cfg(feature = "man")]
fn generate_man_pages(cmd: &clap::Command, output_dir: &Path) -> Result<()> {
    let cmd_name = cmd.get_name().to_string();

    // Generate top-level man page.
    write_man_page(cmd, &output_dir.join(format!("{cmd_name}.1")))?;

    // Generate one page per direct subcommand.
    for sub in cmd.get_subcommands() {
        let sub_page_name = format!("{cmd_name}-{}", sub.get_name());
        write_man_page(sub, &output_dir.join(format!("{sub_page_name}.1")))?;
    }

    Ok(())
}

#[cfg(feature = "man")]
fn write_man_page(cmd: &clap::Command, path: &Path) -> Result<()> {
    let mut file = std::fs::File::create(path)
        .with_context(|| format!("Failed to create {}", path.display()))?;
    clap_mangen::Man::new(cmd.clone())
        .render(&mut file)
        .with_context(|| format!("Failed to render man page for {}", cmd.get_name()))?;
    println!("  {}", path.display());
    Ok(())
}

// All tests here exercise gen-man, which only exists under the `man` feature.
#[cfg(all(test, feature = "man"))]
mod tests {
    use super::*;

    #[test]
    fn gen_man_creates_main_page() {
        let tmp = tempfile::tempdir().unwrap();
        gen_man(tmp.path()).unwrap();

        let main_page = tmp.path().join("mvmctl.1");
        assert!(main_page.exists(), "mvmctl.1 should be generated");

        let content = std::fs::read_to_string(&main_page).unwrap();
        assert!(
            content.contains("mvmctl"),
            "man page should contain the command name"
        );
        assert!(content.contains(".TH"), "man page should have a .TH header");
    }

    #[test]
    fn gen_man_creates_subcommand_pages() {
        let tmp = tempfile::tempdir().unwrap();
        gen_man(tmp.path()).unwrap();

        // At least one subcommand page should be generated.
        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("mvmctl-"))
            .collect();
        assert!(
            !entries.is_empty(),
            "at least one subcommand man page should be generated"
        );
    }
}
