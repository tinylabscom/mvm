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
    let mut problems = Vec::new();
    let mut checked_dirs = 0usize;
    let mut checked_targets = 0usize;

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
        "check-workflow-paths: clean ({} working-directory, {} fuzz target(s) across {} workflow file(s))",
        checked_dirs,
        checked_targets,
        workflows.len()
    );
    Ok(())
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
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join(".github/workflows/ci.yml"),
        )
        .expect("CI workflow must be readable")
    }

    fn ci_job_block<'a>(workflow: &'a str, job: &str) -> &'a str {
        let marker = format!("  {job}:\n");
        let start = workflow
            .find(&marker)
            .unwrap_or_else(|| panic!("CI workflow is missing the {job} job"));
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
        let lint = ci_job_block(&workflow, "lint");
        for unexpected in [
            "cargo nextest run --workspace --features test-support",
            "cargo nextest run -p xtask --features man",
            "uses: actions/cache@v5",
            "uses: ./.github/actions/free-disk",
        ] {
            assert!(
                !lint.contains(unexpected),
                "CI lint job must not contain {unexpected:?}"
            );
        }

        for expected in [
            "cargo nextest run -p mvm-runtime --features test-support --lib",
            "cargo nextest run -p mvm-client --features test-support --lib",
            "cargo nextest run -p mvm-cli --features test-support --lib",
            "cargo nextest run -p mvmctl --features test-support --test audit_emissions_live",
            "cargo check -p mvm-cli --features test-support --example verification_loop",
        ] {
            assert!(
                lint.contains(expected),
                "CI lint job must contain {expected:?}"
            );
        }

        let test = ci_job_block(&workflow, "test");
        assert!(!test.contains("uses: actions/cache@v5"));
        assert!(test.contains("cargo nextest run -p xtask --features man"));
    }

    #[test]
    fn mcp_smoke_reuses_the_test_runner_without_dropping_the_required_check_name() {
        let workflow = ci_workflow();
        let test = ci_job_block(&workflow, "test");
        assert!(test.contains("sudo apt-get install -y attr cryptsetup-bin libcap-ng-dev lld"));
        assert!(test.contains("- name: Install MCP smoke dependency"));
        assert!(test.contains("run: sudo apt-get install -y jq"));
        assert!(test.contains("run: ./scripts/test-mcp-roundtrip.sh"));

        let compatibility = ci_job_block(&workflow, "mcp-server-smoke");
        assert!(compatibility.contains("name: MCP server stdio roundtrip"));
        assert!(compatibility.contains("if: github.event_name == 'mcp-check-compatibility-shim'"));
        assert!(!compatibility.contains("./scripts/test-mcp-roundtrip.sh"));
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
                "crates/mvm-cli/",
                "crates/mvm-client/",
                "crates/mvm-core/",
                "crates/mvm-runtime/",
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
}
