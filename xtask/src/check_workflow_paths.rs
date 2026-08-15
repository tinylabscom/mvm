//! `xtask check-workflow-paths`
//!
//! CI lint — assert every path a workflow points at still exists in the
//! tree. Two references are checked, both of which have silently rotted:
//!
//!   - `working-directory: <dir>` must name a real directory. A crate
//!     rename leaves the workflow pointing at a deleted path, and the
//!     step then dies with "No such file or directory" before running
//!     anything it was supposed to run.
//!   - `cargo fuzz run [--fuzz-dir <d>] <target>` must resolve to a
//!     `<working-directory>/<d>/fuzz_targets/<target>.rs`.
//!
//! This is a file-existence check, so it is cheap enough for the PR lint
//! lane — which matters, because the workflows it guards mostly run on
//! tags and cron, where a break is invisible for days.

use anyhow::{Context, Result, bail};
use std::path::Path;

/// A `cargo fuzz run` invocation resolved against its step's directory.
#[derive(Debug, PartialEq, Eq)]
struct FuzzInvocation {
    crate_dir: String,
    fuzz_dir: String,
    target: String,
}

pub fn run(workspace: &Path) -> Result<()> {
    let workflows = workflow_files(workspace)?;
    let members = workspace_package_names(workspace)?;
    let mut problems = Vec::new();
    let mut checked_dirs = 0usize;
    let mut checked_targets = 0usize;
    let mut checked_packages = 0usize;

    for path in &workflows {
        let src =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        for dir in working_directories(&src) {
            // A templated path (`${{ matrix.crate }}`) is resolved from the
            // matrix entries, which this gate checks via the fuzz targets
            // below; there is no literal path to stat here.
            if dir.contains("${{") {
                continue;
            }
            checked_dirs += 1;
            if !workspace.join(&dir).is_dir() {
                problems.push(format!("{name}: working-directory {dir:?} does not exist"));
            }
        }

        for inv in fuzz_invocations(&src) {
            if inv.crate_dir.contains("${{") || inv.target.contains("${{") {
                continue;
            }
            checked_targets += 1;
            let rel = format!(
                "{}/{}/fuzz_targets/{}.rs",
                inv.crate_dir, inv.fuzz_dir, inv.target
            );
            if !workspace.join(&rel).is_file() {
                problems.push(format!("{name}: fuzz target {rel:?} does not exist"));
            }
        }

        for pkg in cargo_package_flags(&src) {
            if pkg.contains("${{") {
                continue;
            }
            checked_packages += 1;
            if !members.contains(&pkg) {
                problems.push(format!(
                    "{name}: `cargo ... -p {pkg}` names no workspace member"
                ));
            }
        }
    }

    if !problems.is_empty() {
        bail!(
            "check-workflow-paths: {} stale workflow reference(s):\n  {}\n\n\
             A workflow step pointing at a path that no longer exists fails \
             before it runs anything. Update the workflow in the same change \
             that moves or renames the directory.",
            problems.len(),
            problems.join("\n  ")
        );
    }

    eprintln!(
        "check-workflow-paths: clean ({} working-directory, {} fuzz target(s), {} cargo -p package(s) across {} workflow file(s))",
        checked_dirs,
        checked_targets,
        checked_packages,
        workflows.len()
    );
    Ok(())
}

/// Every package name declared by a workspace member, plus the root package.
///
/// Read from the manifests rather than `cargo metadata` so the gate stays a
/// cheap file-parse that can run in the PR lint lane — the same reason the
/// path checks above stat rather than build.
fn workspace_package_names(root: &Path) -> Result<std::collections::HashSet<String>> {
    let root_manifest = root.join("Cargo.toml");
    let src = std::fs::read_to_string(&root_manifest)
        .with_context(|| format!("read {}", root_manifest.display()))?;

    let mut names = std::collections::HashSet::new();
    if let Some(n) = package_name(&src) {
        names.insert(n);
    }
    for member in workspace_members(&src) {
        let manifest = root.join(&member).join("Cargo.toml");
        let Ok(body) = std::fs::read_to_string(&manifest) else {
            // A members entry pointing at a deleted directory is its own bug,
            // but it is the workspace's to report — `cargo` fails loudly on it
            // long before this gate runs.
            continue;
        };
        if let Some(n) = package_name(&body) {
            names.insert(n);
        }
    }
    Ok(names)
}

/// `members = [...]` entries from a workspace manifest, unquoted.
fn workspace_members(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_members = false;
    for line in src.lines() {
        let t = line.trim();
        if t.starts_with("members") && t.contains('[') {
            in_members = true;
            continue;
        }
        if in_members {
            if t.starts_with(']') {
                break;
            }
            let v = t.trim_end_matches(',').trim().trim_matches('"');
            if !v.is_empty() && !v.starts_with('#') {
                out.push(v.to_string());
            }
        }
    }
    out
}

/// The `name = "..."` under a manifest's `[package]` table.
fn package_name(src: &str) -> Option<String> {
    let mut in_package = false;
    for line in src.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_package = t == "[package]";
            continue;
        }
        if in_package && let Some(rest) = t.strip_prefix("name") {
            let v = rest
                .trim_start()
                .strip_prefix('=')?
                .trim()
                .trim_matches('"');
            return Some(v.to_string());
        }
    }
    None
}

/// Package names passed to cargo via `-p` / `--package` in a workflow.
///
/// Scoped to lines that actually invoke cargo. Other tools spell `-p`
/// differently — `tar -p`, `gh release -p`, `mkdir -p` — and matching those
/// would make the gate reject names that were never package references. The
/// scan is line-based, so a `-p` continued onto the next line via `\` is
/// missed; that is a deliberate false-negative, since the alternative is
/// guessing at shell continuation and producing false positives instead.
fn cargo_package_flags(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in src.lines() {
        // Comment lines describe commands, they do not run them, and prose
        // wraps names in backticks that are not part of the name.
        if line.trim_start().starts_with('#') {
            continue;
        }
        // `cargo` must appear as its own command token before the flag.
        // Substring matching would take `mkdir -p .cargo` — where the *path*
        // contains "cargo" — as a package reference.
        let mut saw_cargo = false;
        let mut it = line.split_whitespace();
        while let Some(tok) = it.next() {
            let bare = tok.trim_matches(['"', '\'', '`', '\\']);
            if bare == "cargo" || bare.ends_with("/cargo") {
                saw_cargo = true;
                continue;
            }
            if !saw_cargo {
                continue;
            }
            let value = match bare {
                "-p" | "--package" => it.next(),
                _ => bare.strip_prefix("--package="),
            };
            if let Some(v) = value {
                let v = v.trim_matches(['"', '\'', '`', '\\', ',']);
                // `${{ matrix.crate }}` and `${CRATE}` resolve at run time;
                // there is no literal name to check.
                if v.is_empty() || v.starts_with('-') || v.starts_with('$') {
                    continue;
                }
                out.push(v.to_string());
            }
        }
    }
    out
}

fn workflow_files(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    let dir = root.join(".github/workflows");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry?.path();
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e == "yml" || e == "yaml");
        if is_yaml {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Every `working-directory:` value in a workflow, unquoted.
fn working_directories(src: &str) -> Vec<String> {
    src.lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("working-directory:")?;
            let v = rest.trim().trim_matches(['"', '\'']);
            (!v.is_empty()).then(|| v.to_string())
        })
        .collect()
}

/// Resolve each `cargo fuzz run` against the `working-directory` in scope.
///
/// Steps are scanned in order: a `working-directory:` line sets the
/// directory for the `cargo fuzz run` that follows it in the same step.
fn fuzz_invocations(src: &str) -> Vec<FuzzInvocation> {
    let mut out = Vec::new();
    let mut current_dir: Option<String> = None;

    for line in src.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("working-directory:") {
            current_dir = Some(rest.trim().trim_matches(['"', '\'']).to_string());
            continue;
        }
        // A matrix `include:` entry carries its own crate/dir/target trio
        // inline, so it is self-describing and resolved without the
        // step-scoped `working-directory`.
        if let Some(inv) = matrix_entry(trimmed) {
            out.push(inv);
            continue;
        }
        if let Some(idx) = trimmed.find("cargo fuzz run")
            && let Some(dir) = current_dir.clone()
        {
            let args = &trimmed[idx + "cargo fuzz run".len()..];
            if let Some(inv) = parse_fuzz_args(args, &dir) {
                out.push(inv);
            }
        }
    }
    out
}

/// `- { crate: crates/x, dir: fuzz, target: t }` → a resolved invocation.
fn matrix_entry(line: &str) -> Option<FuzzInvocation> {
    let body = line.strip_prefix("- {")?.strip_suffix('}')?;
    let mut crate_dir = None;
    let mut fuzz_dir = None;
    let mut target = None;
    for field in body.split(',') {
        let (k, v) = field.split_once(':')?;
        let v = v.trim().trim_matches(['"', '\'']).to_string();
        match k.trim() {
            "crate" => crate_dir = Some(v),
            "dir" => fuzz_dir = Some(v),
            "target" => target = Some(v),
            _ => {}
        }
    }
    Some(FuzzInvocation {
        crate_dir: crate_dir?,
        fuzz_dir: fuzz_dir?,
        target: target?,
    })
}

/// Pull `--fuzz-dir <d>` (default `fuzz`) and the first bare word — the
/// target — out of the arguments after `cargo fuzz run`.
fn parse_fuzz_args(args: &str, crate_dir: &str) -> Option<FuzzInvocation> {
    let mut fuzz_dir = "fuzz".to_string();
    let mut target = None;
    let mut it = args.split_whitespace();
    while let Some(tok) = it.next() {
        // `--` starts libFuzzer's own arguments; the target precedes it.
        if tok == "--" {
            break;
        }
        if tok == "--fuzz-dir" {
            if let Some(d) = it.next() {
                fuzz_dir = d.trim_matches(['"', '\'']).to_string();
            }
            continue;
        }
        if tok.starts_with('-') {
            continue;
        }
        if target.is_none() {
            target = Some(tok.trim_matches(['"', '\'']).to_string());
        }
    }
    Some(FuzzInvocation {
        crate_dir: crate_dir.to_string(),
        fuzz_dir,
        target: target?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ci_workflow() -> String {
        workflow("ci.yml")
    }

    fn workflow(name: &str) -> String {
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join(".github/workflows")
                .join(name),
        )
        .unwrap_or_else(|error| panic!("{name} must be readable: {error}"))
    }

    fn job_block<'a>(workflow: &'a str, job: &str) -> &'a str {
        let marker = format!("  {job}:\n");
        let start = workflow
            .find(&marker)
            .unwrap_or_else(|| panic!("workflow is missing the {job} job"));
        let rest_start = start + marker.len();
        let rest = &workflow[rest_start..];
        let end = rest
            .match_indices("\n  ")
            .find_map(|(offset, _)| {
                let line = rest[offset + 1..].lines().next()?;
                (!line.starts_with("    ") && line.ends_with(':')).then_some(rest_start + offset)
            })
            .unwrap_or(workflow.len());
        &workflow[start..end]
    }

    #[test]
    fn working_directories_are_unquoted() {
        let src = "    working-directory: crates/mvm-agentd\n  working-directory: \"crates/x\"\n";
        assert_eq!(
            working_directories(src),
            vec!["crates/mvm-agentd", "crates/x"]
        );
    }

    #[test]
    fn fuzz_dir_defaults_to_fuzz() {
        let inv = parse_fuzz_args(" fuzz_guest_request -- -max_total_time=5", "crates/a").unwrap();
        assert_eq!(inv.fuzz_dir, "fuzz");
        assert_eq!(inv.target, "fuzz_guest_request");
    }

    #[test]
    fn explicit_fuzz_dir_is_honoured() {
        let inv = parse_fuzz_args(" --fuzz-dir fuzz-oci unpack_layer -- -x", "crates/b").unwrap();
        assert_eq!(inv.fuzz_dir, "fuzz-oci");
        assert_eq!(inv.target, "unpack_layer");
    }

    #[test]
    fn libfuzzer_args_are_not_mistaken_for_the_target() {
        // Everything after `--` belongs to libFuzzer, so a bare word there
        // must not win when the target itself is missing.
        assert!(parse_fuzz_args(" -- -max_total_time=5", "crates/c").is_none());
    }

    #[test]
    fn matrix_entries_resolve_without_a_working_directory() {
        let src = "        include:\n          - { crate: crates/mvm-fs, dir: fuzz-oci, target: unpack_layer }\n";
        assert_eq!(
            fuzz_invocations(src),
            vec![FuzzInvocation {
                crate_dir: "crates/mvm-fs".to_string(),
                fuzz_dir: "fuzz-oci".to_string(),
                target: "unpack_layer".to_string(),
            }]
        );
    }

    #[test]
    fn step_scoped_working_directory_applies_to_the_run_that_follows() {
        let src = "      - name: x\n        working-directory: crates/mvm-sdk\n        run: cargo fuzz run fuzz_runtime_recording -- -max_total_time=1\n";
        assert_eq!(
            fuzz_invocations(src),
            vec![FuzzInvocation {
                crate_dir: "crates/mvm-sdk".to_string(),
                fuzz_dir: "fuzz".to_string(),
                target: "fuzz_runtime_recording".to_string(),
            }]
        );
    }

    #[test]
    fn pull_request_ci_does_not_repeat_the_workspace_or_upload_target_caches() {
        let workflow = ci_workflow();
        let lint = job_block(&workflow, "lint");
        assert!(lint.contains("name: Lint (fmt + clippy + policy)"));
        assert!(lint.contains("needs: [scope, lint-core, lint-policy, lint-features]"));

        for unexpected in [
            "cargo nextest run --workspace --features test-support",
            "cargo nextest run -p xtask --features man",
            "uses: actions/cache@v5",
        ] {
            assert!(
                !lint.contains(unexpected),
                "CI lint job must not contain {unexpected:?}"
            );
        }

        let lint_core = job_block(&workflow, "lint-core");
        assert!(lint_core.contains("cargo clippy --all-targets -- -D warnings"));
        let lint_policy = job_block(&workflow, "lint-policy");
        assert!(lint_policy.contains("name: Invariant"));
        assert!(lint_policy.contains("bash scripts/check-no-orchestration-server.sh"));
        assert!(lint_policy.contains("cargo run -p xtask -- check-conformance"));
        let lint_features = job_block(&workflow, "lint-features");
        for expected in [
            "cargo nextest run -p mvm-backends --features test-support --lib",
            "cargo nextest run -p mvm-runtime --features test-support --lib",
            "cargo nextest run -p mvm-client --features test-support --lib",
            "cargo nextest run -p mvm-cli --features test-support --lib",
            "cargo nextest run -p mvmctl --features test-support --test audit_emissions_live",
            "cargo check -p mvm-cli --features test-support --example verification_loop",
        ] {
            assert!(
                lint_features.contains(expected),
                "CI feature lane must contain {expected:?}"
            );
        }
        assert_eq!(
            lint_features
                .matches("cargo nextest run -p mvm-backends --features test-support --lib")
                .count(),
            1,
            "feature coverage must not repeat the same mvm-backends test command"
        );

        let test = job_block(&workflow, "test");
        assert!(test.contains("name: Test"));
        assert!(test.contains(
            "needs: [scope, test-workspace, test-linux, test-release-witness, test-ebpf-telemetry, kernel]"
        ));

        // Every lane the aggregate names must also be read back in the loop that
        // compares results against the scope decision. A lane in `needs` but not
        // in the loop is gated on nothing but its own scheduling.
        for expected in [
            "\"$WORKSPACE_RESULT\"",
            "\"$LINUX_RESULT\"",
            "\"$RELEASE_WITNESS_RESULT\"",
            "\"$EBPF_RESULT\"",
            "\"$KERNEL_RESULT\"",
        ] {
            assert!(
                test.contains(expected),
                "Test aggregate must compare {expected} against the scope decision"
            );
        }

        // The release-profile lane is the only one that runs with trapping
        // overflow and debug assertions off, i.e. the only one that witnesses
        // what actually ships. A lane that runs but is not in the aggregate's
        // `needs` is a lane that cannot fail the merge, so pin both halves.
        let release_witness = job_block(&workflow, "test-release-witness");
        assert!(release_witness.contains("--cargo-profile release-witness"));
        for expected in [
            "-p mvm-fs",
            "-p mvm-core",
            "-p mvm-contract",
            "-p mvm-hostd",
        ] {
            assert!(
                release_witness.contains(expected),
                "release-witness lane must cover {expected:?}"
            );
        }

        let test_workspace = job_block(&workflow, "test-workspace");
        assert!(!test_workspace.contains("uses: actions/cache@v5"));
        assert!(test_workspace.contains("cargo nextest run -p xtask --features man"));
        let test_linux = job_block(&workflow, "test-linux");
        assert!(test_linux.contains("bash scripts/ci-linux-coverage.sh"));
        assert!(!test_workspace.contains("ci-linux-coverage.sh"));

        let linux_coverage = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("scripts/ci-linux-coverage.sh"),
        )
        .expect("Linux coverage script must be readable");
        for expected in [
            "cargo +1.96.0 build -p mvm-contract --target wasm32-unknown-unknown",
            "cargo test -p mvm-conformance --test meta",
            "just bdd",
        ] {
            assert!(
                linux_coverage.contains(expected),
                "Linux coverage script must contain {expected:?}"
            );
        }
    }

    #[test]
    fn merge_group_ci_skips_rust_work_for_non_code_diffs_without_losing_gates() {
        let workflow = ci_workflow();
        let scope = job_block(&workflow, "scope");
        for expected in [
            "MG_BASE: ${{ github.event.merge_group.base_sha }}",
            "MG_HEAD: ${{ github.event.merge_group.head_sha }}",
            "PR_BASE: ${{ github.event.pull_request.base.sha }}",
            "PR_HEAD: ${{ github.event.pull_request.head.sha }}",
            "git diff --name-only -z",
            "grep -zE",
            "could not diff $BASE..$HEAD — running every lane to stay safe",
            "invalid or missing ${name} scope",
            "code=true",
            "nix=true",
            "architecture=true",
            "kernel=true",
        ] {
            assert!(
                scope.contains(expected),
                "CI scope must contain fail-closed classifier fragment {expected:?}"
            );
        }

        for job in [
            "lint-core",
            "lint-features",
            "test-workspace",
            "test-release-witness",
            "test-linux",
            "test-ebpf-telemetry",
        ] {
            let block = job_block(&workflow, job);
            assert!(
                block.contains("needs: [scope]"),
                "{job} must depend on CI scope"
            );
            assert!(
                block.contains("if: needs.scope.outputs.code == 'true'"),
                "{job} must skip expensive Rust work for non-code diffs"
            );
        }

        // `cargo install --locked` pins the installed crate's own dependencies
        // but not which version of that crate is installed, so an upstream
        // release retroactively changes this lane. Now that the lane gates the
        // merge, an unpinned install lets a publish elsewhere block the queue.
        let ebpf = job_block(&workflow, "test-ebpf-telemetry");
        assert!(
            ebpf.contains("cargo +nightly install --locked --version ")
                && ebpf.contains("bpf-linker"),
            "eBPF lane must install a pinned bpf-linker version"
        );

        let policy = job_block(&workflow, "lint-policy");
        assert!(policy.contains("needs: [scope]"));
        assert!(!policy.contains("needs.scope.outputs.code == 'true'"));
        assert!(policy.contains("needs.scope.outputs.architecture == 'true'"));

        let nix = job_block(&workflow, "nix-flake-check");
        assert!(nix.contains("needs: [scope]"));
        assert!(nix.contains("needs.scope.outputs.nix == 'true'"));

        let kernel = job_block(&workflow, "kernel");
        assert!(kernel.contains("needs: [scope]"));
        assert!(kernel.contains("if: needs.scope.outputs.kernel == 'true'"));
        assert!(kernel.contains("name: Build kernels (${{ matrix.arch }})"));
        assert!(kernel.contains("needs.scope.outputs.kernel == 'true'"));

        for aggregate in ["lint", "test"] {
            let block = job_block(&workflow, aggregate);
            assert!(block.contains("needs.scope.result"));
            assert!(block.contains("SCOPE_CODE: ${{ needs.scope.outputs.code }}"));
            assert!(
                block.contains("true) required=success")
                    && block.contains("false) required=skipped")
                    && block.contains(r#"if [ "$result" != "$required" ]"#),
                "{aggregate} must require success or skip exactly as scope decided"
            );
        }
    }

    #[test]
    fn mutation_cli_shard_installs_its_embedded_host_toolchain() {
        let workflow = workflow("security.yml");
        let mutation = job_block(&workflow, "mutation-witnesses");
        let install = concat!(
            "      - name: Install mvm-cli embedded-host toolchain\n",
            "        if: matrix.package == 'mvm-cli'\n",
            "        uses: ./.github/actions/install-zigbuild",
        );
        assert!(
            mutation.contains(install),
            "the mvm-cli mutation shard must install the pinned Zig toolchain"
        );
        assert!(
            mutation.find(install) < mutation.find("Mutate this package's claim surface"),
            "the embedded-host toolchain must be installed before cargo-mutants builds mvm-cli"
        );
    }

    #[test]
    fn removed_mcp_server_stays_out_of_ci() {
        let workflow = ci_workflow();
        for removed in [
            "MCP server stdio roundtrip",
            "mcp-server-smoke",
            "test-mcp-roundtrip.sh",
            "Install MCP smoke dependency",
        ] {
            assert!(
                !workflow.contains(removed),
                "removed MCP server CI surface returned: {removed}"
            );
        }
    }

    #[test]
    fn required_workflows_keep_merge_group_runs_independent_and_conclusive() {
        let expected_group = "group: ${{ github.workflow }}-${{ github.event_name }}-${{ github.event_name == 'workflow_dispatch' && github.run_id || github.ref }}";
        let expected_cancel = "cancel-in-progress: ${{ github.event_name == 'pull_request' }}";

        let ci = ci_workflow();
        assert!(ci.contains("merge_group:\n    types: [checks_requested]"));
        assert!(ci.contains(expected_group));
        assert!(ci.contains(expected_cancel));
        assert!(!ci.contains("cancel-in-progress: true"));
        assert!(ci.contains("permissions:\n  contents: read"));
        for required_name in [
            "name: Lint (fmt + clippy + policy)",
            "name: Test",
            "name: Invariant",
            "name: Nix flake check (Linux eval)",
            "name: Build kernels (${{ matrix.arch }})",
        ] {
            assert!(ci.contains(required_name), "required check name drifted");
        }

        let architecture = workflow("architecture.yml");
        assert!(!architecture.contains("pull_request:"));
        assert!(!architecture.contains("merge_group:"));
        assert!(architecture.contains("workflow_dispatch:"));

        let kernel = workflow("kernel-build.yml");
        assert!(!kernel.contains("pull_request:"));
        assert!(!kernel.contains("merge_group:"));
        assert!(kernel.contains("workflow_dispatch:"));
        assert!(kernel.contains("push:"));
    }

    #[test]
    fn trusted_main_warms_workspace_and_nix_outputs_for_validation() {
        let cache_action = workflow("../actions/rust-cache/action.yml");
        assert!(cache_action.contains("prefix-key: v1-rust"));
        assert!(cache_action.contains("cache-workspace-crates: \"true\""));
        assert!(cache_action.contains("save-if: ${{ inputs.save }}"));

        let warm = workflow("cache-warm.yml");
        assert!(warm.contains("DeterminateSystems/magic-nix-cache-action@v14"));
        assert!(warm.contains("Build Nix outputs to populate the binary cache"));
        assert!(warm.contains("save: \"true\""));

        let ci = ci_workflow();
        let nix = job_block(&ci, "nix-flake-check");
        assert!(nix.contains("DeterminateSystems/magic-nix-cache-action@v14"));
        assert!(nix.contains("use-flakehub: false"));
        assert!(nix.contains("diagnostic-endpoint: \"\""));
    }

    #[test]
    fn kernel_validation_and_release_reuse_one_builder_script() {
        let ci = ci_workflow();
        let ci_kernel = job_block(&ci, "kernel");
        let release = workflow("kernel-build.yml");
        let expected = "bash scripts/build-kernel-artifacts.sh \"$ARCH\"";
        assert!(ci_kernel.contains(expected));
        assert!(release.contains(expected));

        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let status = std::process::Command::new("bash")
            .arg("scripts/build-kernel-artifacts.sh")
            .arg("not-an-architecture")
            .current_dir(workspace)
            .status()
            .expect("kernel builder input validation must execute");
        assert_eq!(status.code(), Some(2));
    }

    #[test]
    fn test_support_source_owners_match_the_targeted_ci_lane() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut unexpected = Vec::new();
        crate::fs_walk::for_each_file(&workspace, Some("rs"), &mut |path, contents| {
            if !contents.contains("feature = \"test-support\"") {
                return;
            }
            let relative = path
                .strip_prefix(&workspace)
                .expect("workspace-relative path");
            let owned = [
                "crates/mvm-backends/",
                "crates/mvm-cli/",
                "crates/mvm-client/",
                "crates/mvm-core/",
                "crates/mvm-runtime/",
                "crates/mvm-backends/",
                "crates/mvm-vmm/",
                "tests/audit_emissions_live.rs",
            ]
            .iter()
            .any(|prefix| relative.to_string_lossy().starts_with(*prefix));
            if !owned {
                unexpected.push(relative.display().to_string());
            }
        })
        .expect("test-support source scan must succeed");

        assert!(
            unexpected.is_empty(),
            "new test-support source owners need an explicit targeted CI command: {unexpected:?}"
        );
    }

    /// The bug this check was written for: `ci-full.yml` invoked
    /// `cargo test -p mvm-jailer-lite` after that crate was absorbed into
    /// `mvm-hostd`, so the only lane exercising Landlock + seccomp
    /// confinement could not resolve its own package. The lane is
    /// `workflow_dispatch`-only, which is why it went unnoticed.
    #[test]
    fn a_cargo_p_naming_a_dead_crate_is_caught() {
        let flags = cargo_package_flags("          cargo test -p mvm-jailer-lite \\");
        assert_eq!(flags, vec!["mvm-jailer-lite".to_string()]);

        let members =
            workspace_package_names(Path::new(env!("CARGO_MANIFEST_DIR")).join("..").as_path())
                .expect("read workspace members");
        assert!(
            members.contains("mvm-hostd"),
            "sanity: mvm-hostd must be a member"
        );
        assert!(
            !members.contains("mvm-jailer-lite"),
            "mvm-jailer-lite was absorbed into mvm-hostd and must not resolve"
        );
    }

    /// `-p` belongs to plenty of tools that are not cargo. Matching those
    /// would make the gate reject names that were never package references.
    #[test]
    fn non_cargo_dash_p_is_not_treated_as_a_package() {
        for line in [
            "          tar -xzf -p dist",
            "          mkdir -p target/release-assets",
            "          gh release upload -p staging",
            // The one that caught the naive substring match out: the *path*
            // contains "cargo", the command is not cargo.
            "          mkdir -p .cargo",
            // Prose describing a command is not a command.
            "        # plain `cargo test -p mvm-hostd` is a no-op on Linux",
        ] {
            assert!(
                cargo_package_flags(line).is_empty(),
                "non-cargo line must yield no packages: {line}"
            );
        }
    }

    #[test]
    fn package_flags_handle_both_spellings_and_quoting() {
        assert_eq!(
            cargo_package_flags("        run: cargo nextest run --package mvm-fs"),
            vec!["mvm-fs".to_string()]
        );
        assert_eq!(
            cargo_package_flags("        run: cargo build --package=mvm-core"),
            vec!["mvm-core".to_string()]
        );
        // Names resolved at run time carry no literal to check, in either
        // GitHub's `${{ }}` or shell `${}` spelling.
        assert!(cargo_package_flags("        run: cargo test -p ${{ matrix.crate }}").is_empty());
        assert!(cargo_package_flags("          cargo publish -p ${CRATE}").is_empty());
    }

    /// Every `cargo -p` across the real workflow tree resolves today. This is
    /// the assertion that would have gone red on the stale reference.
    #[test]
    fn every_workflow_cargo_package_resolves() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let members = workspace_package_names(&root).expect("members");
        let mut stale = Vec::new();
        for path in workflow_files(&root).expect("workflow files") {
            let src = std::fs::read_to_string(&path).expect("read workflow");
            for pkg in cargo_package_flags(&src) {
                if pkg.contains("${{") {
                    continue;
                }
                if !members.contains(&pkg) {
                    stale.push(format!("{}: {pkg}", path.display()));
                }
            }
        }
        assert!(stale.is_empty(), "stale cargo -p references: {stale:?}");
    }
}
