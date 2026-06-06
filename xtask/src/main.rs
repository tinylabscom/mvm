use anyhow::Result;
use std::path::PathBuf;

// Only the gen-man path (gated behind `man`) uses these.
#[cfg(feature = "man")]
use anyhow::Context;
#[cfg(feature = "man")]
use std::path::Path;

mod build_dev_image;
mod check_adr_coverage;
mod check_audit_positional;
mod check_claim_catalog;
mod check_core_runtime_free;
mod check_doc_claims;
mod check_forbidden_deps;
mod check_guest_agent_in_all_images;
mod check_guest_agent_runtime_free;
mod check_mvm_host_binaries_sync;
mod check_no_display_on_secret_types;
mod check_no_overclaim;
mod check_spec_numbers;
mod gen_stubs;
mod perf;

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
        Some("check-doc-claims") => {
            let workspace = workspace_root();
            check_doc_claims::run(&workspace)
        }
        Some("check-forbidden-deps") => {
            let workspace = workspace_root();
            check_forbidden_deps::run(&workspace)
        }
        Some("check-core-runtime-free") => {
            let workspace = workspace_root();
            check_core_runtime_free::run(&workspace)
        }
        Some("check-guest-agent-runtime-free") => {
            let workspace = workspace_root();
            check_guest_agent_runtime_free::run(&workspace)
        }
        Some("check-guest-agent-in-all-images") => {
            let workspace = workspace_root();
            check_guest_agent_in_all_images::run(&workspace)
        }
        Some("check-no-overclaim") => {
            let workspace = workspace_root();
            check_no_overclaim::run(&workspace)
        }
        Some("check-spec-numbers") => {
            let workspace = workspace_root();
            check_spec_numbers::run(&workspace)
        }
        Some("check-claim-catalog") => {
            let workspace = workspace_root();
            check_claim_catalog::run(&workspace)
        }
        Some("check-mvm-host-binaries-sync") => {
            let workspace = workspace_root();
            check_mvm_host_binaries_sync::run(&workspace)
        }
        Some("perf") => perf::run(&args[2..]),
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
        Some(other) => anyhow::bail!(
            "Unknown xtask: {:?}. Available: gen-man, check-adr-coverage, check-no-display-on-secret-types, check-audit-positional, check-doc-claims, check-forbidden-deps, check-core-runtime-free, check-guest-agent-runtime-free, check-guest-agent-in-all-images, check-no-overclaim, check-spec-numbers, check-claim-catalog, check-mvm-host-binaries-sync, perf, build-dev-image, gen-stubs, check-stubs",
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
                "  check-forbidden-deps                    Reject sea-* and mysql crates in Cargo.lock"
            );
            eprintln!(
                "  check-core-runtime-free                 Plan 126 B5: assert mvm-core's default build pulls no tokio"
            );
            eprintln!(
                "  check-guest-agent-runtime-free          Plan 124 A: assert mvm-guest's Linux closure pulls no tokio/async-trait/rtnetlink"
            );
            eprintln!(
                "  check-guest-agent-in-all-images         Plan 124 B: assert every bootable image's launch path forks mvm-guest-agent"
            );
            eprintln!(
                "  check-no-overclaim                      Plan 75 W0 lint: refuse gated phrases from specs/claims/ outside exempt paths"
            );
            eprintln!(
                "  check-spec-numbers                     Reject duplicate numeric prefixes in specs/plans and specs/adrs"
            );
            eprintln!(
                "  check-claim-catalog                    Verify specs/claims/catalog.md witnesses still exist in the tree"
            );
            eprintln!(
                "  check-mvm-host-binaries-sync            Plan 115 / ADR-065: assert Rust manifest and Nix attrset agree"
            );
            eprintln!(
                "  perf <subcommand>                       Plan 60 Phase 9 perf gates (rootfs-size, boot)"
            );
            eprintln!(
                "  build-dev-image [--arch <arch>]         Build the dev VM image and drop it into nix/images/dev-prebuilt/<arch>/"
            );
            eprintln!(
                "  gen-stubs                               Plan 60 Phase 5: regenerate schema/workload-ir-v0.json + Python/TS IR types from mvm-ir"
            );
            eprintln!(
                "  check-stubs                             Plan 60 Phase 5: CI gate — fail if generated stubs are stale"
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
