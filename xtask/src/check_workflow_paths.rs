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
//! It also checks one number, for the same reason: the fuzz lane's
//! per-target duration multiplied by its target count must fit inside the
//! job's own timeout. A target is added in one place and the duration is
//! set in another, so the product grew past six hours without either edit
//! looking wrong — and the lane was killed partway down the list every
//! night, with the targets below the cut never running.
//!
//! This is a file-existence check plus arithmetic, so it is cheap enough
//! for the PR lint lane — which matters, because the workflows it guards
//! mostly run on tags and cron, where a break is invisible for days.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::Path;

/// A `cargo fuzz run` invocation resolved against its step's directory.
#[derive(Debug, PartialEq, Eq)]
struct FuzzInvocation {
    crate_dir: String,
    fuzz_dir: String,
    target: String,
}

/// Wall clock one fuzz target costs on top of its own fuzzing time: a
/// sanitizer build of that crate's fuzz harness.
///
/// An allowance, not an average. Measured across a nightly run, the builds
/// cost between a few seconds and five minutes each, so budgeting the mean
/// would put the lane over its timeout on the day several slow ones land
/// together.
const FUZZ_BUILD_ALLOWANCE_SECS: u64 = 120;

/// What the fuzz job says about how long it may take.
#[derive(Debug, PartialEq, Eq)]
struct FuzzBudget {
    /// Seconds of fuzzing per target on the nightly cron — the longest of
    /// the lane's two settings, so the one that has to fit.
    per_target_secs: u64,
    /// The job's own `timeout-minutes`.
    timeout_minutes: u64,
    /// How many targets the job runs.
    targets: usize,
}

impl FuzzBudget {
    /// Wall clock the declared budget implies, in seconds.
    fn projected_secs(&self) -> u64 {
        self.targets as u64 * (self.per_target_secs + FUZZ_BUILD_ALLOWANCE_SECS)
    }

    fn fits(&self) -> bool {
        self.projected_secs() <= self.timeout_minutes * 60
    }
}

/// One version per action, across every workflow.
///
/// Split versions are how an artifact upload and the download meant to
/// consume it drift apart: `publish-npm.yml` and `publish-pypi.yml` paired
/// `upload-artifact@v4` with `download-artifact@v4` while eleven other
/// lanes had moved to v7, so the pair was one major bump away from a
/// handoff that fails only on the release path.
fn action_version_conflicts(workflows: &[(String, String)]) -> Vec<String> {
    let mut seen: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    for (name, src) in workflows {
        for (action, git_ref) in third_party_action_refs(src) {
            seen.entry(action.to_string())
                .or_default()
                .entry(git_ref.to_string())
                .or_default()
                .push(name.clone());
        }
    }
    seen.into_iter()
        .filter(|(action, refs)| {
            // The toolchain action encodes the channel in the ref, so
            // several "versions" of it is the intended usage.
            refs.len() > 1 && !FLOATING_REF_ALLOWED.contains(&action.as_str())
        })
        .map(|(action, refs)| {
            let detail = refs
                .iter()
                .map(|(git_ref, files)| format!("{git_ref} ({})", files.join(", ")))
                .collect::<Vec<_>>()
                .join(" vs ");
            format!("{action} is pinned to more than one version: {detail}")
        })
        .collect()
}

/// Third-party action refs allowed to float, and why.
///
/// `dtolnay/rust-toolchain` publishes no version tags: the channel is the
/// branch name, and `@master` is the documented entry point when the
/// toolchain is supplied as an input instead — which is how the lanes that
/// pin a nightly *date* have to call it. Floating the action to pin the
/// compiler is the trade that action's design forces.
const FLOATING_REF_ALLOWED: [&str; 1] = ["dtolnay/rust-toolchain"];

/// `uses:` refs that move under us.
///
/// `@main` and `@master` re-resolve on every run, so what executes is
/// whatever the upstream default branch holds at that moment. This is not
/// hypothetical distance: when this gate was written, all 18 of this
/// repository's `nix-installer-action` uses floated on `@main`, which was
/// 43 commits ahead of the newest release — 43 unreviewed commits running
/// on the lanes that build and sign what we publish.
fn third_party_action_refs(src: &str) -> impl Iterator<Item = (&str, &str)> {
    src.lines().filter_map(|line| {
        // Both step forms: `uses:` under a `- name:`, and `- uses:` where
        // the step is nothing but its action. Missing the second was worth
        // a test on its own — it is the more common of the two, so a
        // parser that skips it reads a floating ref as clean.
        let trimmed = line.trim();
        let rest = trimmed
            .strip_prefix("- uses:")
            .or_else(|| trimmed.strip_prefix("uses:"))?
            .trim();
        // Local composite actions and reusable workflows are our own code.
        if rest.starts_with("./") {
            return None;
        }
        let (action, git_ref) = rest.split_once('@')?;
        Some((action, git_ref.split_whitespace().next()?))
    })
}

fn floating_action_refs(src: &str) -> Vec<String> {
    third_party_action_refs(src)
        .filter(|(action, git_ref)| {
            matches!(*git_ref, "main" | "master") && !FLOATING_REF_ALLOWED.contains(action)
        })
        .map(|(action, git_ref)| format!("{action}@{git_ref}"))
        .collect()
}

/// Count `setup-uv` steps that would resolve the tool version at runtime.
fn unversioned_setup_uv_steps(src: &str) -> usize {
    let lines = src.lines().collect::<Vec<_>>();
    lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.contains("uses: astral-sh/setup-uv@"))
        .filter(|(index, _)| {
            !lines[index + 1..]
                .iter()
                .take_while(|next| !next.trim_start().starts_with("- "))
                .any(|next| next.trim_start().starts_with("version:"))
        })
        .count()
}

pub fn run(workspace: &Path) -> Result<()> {
    let workflows = workflow_files(workspace)?;
    let members = workspace_package_names(workspace)?;
    let mut problems = Vec::new();
    let mut budgets = Vec::new();
    let mut checked_dirs = 0usize;
    let mut checked_targets = 0usize;
    let mut checked_packages = 0usize;
    let mut checked_actions = 0usize;
    let mut sources: Vec<(String, String)> = Vec::new();

    for path in &workflows {
        let src =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        checked_actions += third_party_action_refs(&src).count();
        sources.push((name.clone(), src.clone()));
        for floating in floating_action_refs(&src) {
            problems.push(format!(
                "{name}: {floating} floats on a branch — pin it to a tag or \
                 commit, or a run executes whatever upstream pushed last"
            ));
        }
        if unversioned_setup_uv_steps(&src) > 0 {
            problems.push(format!(
                "{name}: setup-uv resolves the uv tool version at runtime — pin its `version` input"
            ));
        }

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

        if let Some(budget) = fuzz_budget(&src) {
            budgets.push((name.clone(), budget));
        }
    }

    problems.extend(action_version_conflicts(&sources));

    if !problems.is_empty() {
        bail!(
            "check-workflow-paths: {} unsound workflow reference(s):\n  {}\n\n\
             A step pointing at a path that no longer exists fails before it \
             runs anything — update the workflow in the same change that moves \
             or renames the directory. A step pointing at a branch runs \
             whatever upstream pushed last: pin it to a tag or a commit sha, \
             with the version in a trailing comment.",
            problems.len(),
            problems.join("\n  ")
        );
    }

    let overrun: Vec<&(String, FuzzBudget)> = budgets.iter().filter(|(_, b)| !b.fits()).collect();
    if !overrun.is_empty() {
        let detail: Vec<String> = overrun
            .iter()
            .map(|(name, b)| {
                format!(
                    "{name}: fuzz job budgets {} target(s) × ({}s fuzzing + {FUZZ_BUILD_ALLOWANCE_SECS}s build) \
                     = {} min, past its own timeout-minutes: {}",
                    b.targets,
                    b.per_target_secs,
                    b.projected_secs() / 60,
                    b.timeout_minutes
                )
            })
            .collect();
        bail!(
            "check-workflow-paths: {} fuzz lane(s) cannot finish inside their timeout:\n  {}\n\n\
             The job is killed partway down the target list, and every target below \
             the cut never runs — including ones that witness a numbered claim. \
             Lower the per-target seconds, or raise the timeout if it still fits \
             under the six-hour platform cap.",
            overrun.len(),
            detail.join("\n  ")
        );
    }

    eprintln!(
        "check-workflow-paths: clean ({} working-directory, {} fuzz target(s), {} cargo -p package(s), {} pinned action ref(s) across {} workflow file(s))",
        checked_dirs,
        checked_targets,
        checked_packages,
        checked_actions,
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

/// The body of one top-level job, by name.
///
/// Text-scanned rather than parsed as YAML for the same reason the rest of
/// this gate is: it has to stay a dependency-free file read that the PR
/// lint lane can afford. Jobs sit at two-space indent, so the block ends
/// at the next line with exactly that shape.
fn job_body<'a>(src: &'a str, job: &str) -> Option<&'a str> {
    let header = format!("\n  {job}:\n");
    let start = src.find(&header)? + header.len();
    let rest = &src[start..];
    let end = rest
        .lines()
        .scan(0usize, |offset, line| {
            let at = *offset;
            *offset += line.len() + 1;
            Some((at, line))
        })
        .find(|(_, line)| {
            line.starts_with("  ")
                && !line.starts_with("   ")
                && !line.trim_start().starts_with('#')
                && line.trim_end().ends_with(':')
        })
        .map_or(rest.len(), |(at, _)| at);
    Some(&rest[..end])
}

/// A `key: <integer>` at any indent inside a block.
fn scalar_u64(block: &str, key: &str) -> Option<u64> {
    block.lines().find_map(|line| {
        line.trim()
            .strip_prefix(key)?
            .strip_prefix(':')?
            .split('#')
            .next()?
            .trim()
            .parse()
            .ok()
    })
}

/// The fuzz job's declared budget, if the workflow has one.
fn fuzz_budget(src: &str) -> Option<FuzzBudget> {
    let block = job_body(src, "fuzz")?;
    Some(FuzzBudget {
        per_target_secs: scalar_u64(block, "FUZZ_SECS_SCHEDULE")?,
        timeout_minutes: scalar_u64(block, "timeout-minutes")?,
        targets: fuzz_invocations(block).len(),
    })
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

    fn ci_full_workflow() -> String {
        workflow("ci-full.yml")
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

    /// One job's body, panicking rather than returning `None` — the tests
    /// name jobs that exist, and a rename should say so by name.
    fn job_block<'a>(workflow: &'a str, job: &str) -> &'a str {
        job_body(workflow, job).unwrap_or_else(|| panic!("workflow is missing the {job} job"))
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
        assert!(
            lint_core.contains("./scripts/cargo-stable.sh clippy --all-targets -- -D warnings")
        );
        let lint_policy = job_block(&workflow, "lint-policy");
        assert!(lint_policy.contains("name: Invariant"));
        assert!(lint_policy.contains("bash scripts/check-no-orchestration-server.sh"));
        // The policy gates arrive through the driver, so the lane pins the
        // driver and `check_all`'s own tests pin the table's contents.
        // Asserting a particular gate's step here again would just be the
        // sixty-step list in another file.
        assert!(lint_policy.contains("cargo run -p xtask -- check-all"));
        assert!(lint_policy.contains("Policy gates (check-abi-layout) (single-network-path)"));
        assert!(
            crate::check_all::GATES
                .iter()
                .any(|(name, _)| *name == "check-conformance"),
            "check-conformance must still be one of the gates the lane runs"
        );
        let lint_features = job_block(&workflow, "lint-features");
        // One invocation covering the whole test-support subtree. Selecting a
        // package at a time made cargo resolve features once per package and
        // rebuild most of the same graph each time; the packages are listed
        // together so a single resolution serves all of them.
        for expected in [
            "cargo nextest run --features test-support --lib",
            "-p mvm-backends -p mvm-runtime -p mvm-client -p mvm-cli -p mvm-vmm",
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
                .matches("cargo nextest run --features test-support --lib")
                .count(),
            1,
            "feature coverage must not repeat the test-support run"
        );
        // The per-package shape is what made this lane the critical path, so
        // its return is an error rather than a silent regression.
        for regressed in [
            "cargo nextest run -p mvm-backends --features test-support --lib",
            "cargo nextest run -p mvm-runtime --features test-support --lib",
        ] {
            assert!(
                !lint_features.contains(regressed),
                "feature coverage must not go back to one invocation per package: {regressed:?}"
            );
        }

        let test = job_block(&workflow, "test");
        assert!(test.contains("name: Test"));
        assert!(test.contains(
            "needs: [scope, test-workspace, test-workspace-aarch64, test-linux, \
             test-release-witness, test-ebpf-telemetry, bdd-conformance, kernel]"
        ));

        // Every lane the aggregate names must also be read back in the loop that
        // compares results against the scope decision. A lane in `needs` but not
        // in the loop is gated on nothing but its own scheduling.
        // `bdd-conformance` and `kernel` key off their own narrower scopes, so
        // they are matched against `$SCOPE_BDD` / `$KERNEL_SCOPE` outside the
        // loop rather than folded into it — but they still have to be read back
        // somewhere, which is what this pins.
        for expected in [
            "\"$WORKSPACE_RESULT\"",
            "\"$LINUX_RESULT\"",
            "\"$RELEASE_WITNESS_RESULT\"",
            "\"$EBPF_RESULT\"",
            "\"$BDD_RESULT\"",
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
            "cargo +1.97.1 build -p mvm-contract --target wasm32-unknown-unknown",
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
    fn no_kvm_pipeline_prepares_a_bounded_bundle_then_boots_with_tcg() {
        let workflow = ci_full_workflow();
        let prepare = job_block(&workflow, "no-kvm-prepare");
        let bootstrap = job_block(&workflow, "no-kvm-bootstrap");
        let build = job_block(&workflow, "no-kvm-build");
        let smoke = job_block(&workflow, "no-kvm-smoke");
        let grant = concat!(
            "      - name: Grant QEMU access to vhost-vsock\n",
            "        run: |\n",
            "          test -c /dev/vhost-vsock\n",
            "          sudo chown \"$USER\" /dev/vhost-vsock\n",
            "          sudo chmod 0600 /dev/vhost-vsock",
        );
        for (job, action) in [
            (bootstrap, "Bootstrap source-matched launch artifacts"),
            (smoke, "Install and boot the sealed bundle under QEMU TCG"),
        ] {
            assert!(
                job.contains(grant),
                "each hosted QEMU runner must grant its current user access to vhost-vsock"
            );
            assert!(
                job.find(grant) < job.find(action),
                "vhost-vsock access must be granted before QEMU starts"
            );
        }
        let deny_kvm = "Deny KVM to force QEMU TCG";
        assert!(
            !build.contains("/dev/vhost-vsock")
                && !build.contains("/dev/kvm")
                && !build.contains("machine build --flake examples/exit_code"),
            "bounded bundle preparation must not boot a builder VM"
        );
        assert!(
            build.contains("image boot update --tag boot-image/v0.1.3 --force")
                && bootstrap.contains("mv nix/images/builder-vm.hidden nix/images/builder-vm")
                && bootstrap.contains("sudo chmod 0666 /dev/kvm")
                && bootstrap.contains("sudo chmod a+r")
                && bootstrap.contains("/boot/vmlinuz-$(uname -r)")
                && bootstrap.contains("/boot/initrd.img-$(uname -r)")
                && bootstrap.contains("kernel build --which workload --source compile -v")
                && build.contains(".mvm-ci/cache/kernels/x86_64/workload/bzImage")
                && build.contains("bzImage.sha256")
                && build.contains("write /tmp/exit-code-entrypoint /etc/mvm/entrypoint")
                && build.contains("veritysetup format")
                && build.contains("bundle export \"$slot_hash\""),
            "bundle preparation must combine verified release rootfs bytes with source-matched launch artifacts and exporter"
        );
        // `/etc/mvm/entrypoint` is a marker, not a command line. The agent
        // takes the marker file itself as the program only when it starts
        // with `#!` and is mode 0755 root:root, and `debugfs write` creates
        // 0644. The fixture originally wrote a command line at 0644, which
        // satisfies neither, so the guest refused the entrypoint at boot and
        // the lane exited 1 where it asserts 7 — every night, undetected,
        // because the only thing checking was a guest three jobs downstream.
        // This lane runs nightly; this assertion runs on every pull request.
        assert!(
            build.contains("'#!/bin/sh'") && build.contains("sif /etc/mvm/entrypoint mode 0100755"),
            "the exit-code fixture must bake a shebang marker at mode 0755 — \
             the only shape the guest agent's sealed-marker policy accepts"
        );
        let restore_source_flake = bootstrap
            .find("mv nix/images/builder-vm.hidden nix/images/builder-vm")
            .expect("the source builder flake must be restored after published bootstrap");
        let source_kernel_build = bootstrap
            .find("kernel build --which workload --source compile -v")
            .expect("the source QEMU kernel must be built");
        let restore_kvm = bootstrap
            .find("sudo chmod 0666 /dev/kvm")
            .expect("source artifact compilation must restore KVM acceleration");
        let grant_boot_read = bootstrap
            .find("sudo chmod a+r")
            .expect("source artifact compilation must make the host boot inputs readable");
        assert!(
            restore_source_flake < restore_kvm
                && restore_kvm < grant_boot_read
                && grant_boot_read < source_kernel_build,
            "the source builder flake, KVM acceleration, and readable boot inputs must be restored before source kernel compilation"
        );
        let deny_kvm_position = smoke
            .find(deny_kvm)
            .expect("the hosted boot witness must deny KVM");
        let bundle_boot_position = smoke
            .find("Install and boot the sealed bundle under QEMU TCG")
            .expect("the no-KVM job must install and boot the sealed bundle");
        assert!(
            deny_kvm_position < bundle_boot_position,
            "KVM must be denied before the installed bundle boots"
        );
        let source_build = prepare
            .find("Build source mvmctl and published-builder bootstrap helper")
            .expect("the hosted no-KVM gate must build source-matched mvmctl");
        let source_copy = prepare
            .find("cp target/release/mvmctl /tmp/mvmctl-source-under-test")
            .expect("the source-matched mvmctl must be preserved before helper compilation");
        let workload = smoke
            .find("/tmp/mvmctl-source-under-test machine run")
            .expect("the live workload must run through the source-matched mvmctl");
        assert!(prepare.contains("MVM_EMBED_NO_CACHE: 1"));
        assert!(prepare.contains("timeout-minutes: 45"));
        assert!(
            prepare.contains("cargo build --release -p mvmctl --features user,embed-host-bins")
        );
        assert!(prepare.contains(
            "cargo build --release -p mvmctl --features \
             user,release-artifact-bootstrap,release-channel"
        ));
        assert!(source_build < source_copy);
        assert!(bootstrap.contains("needs: no-kvm-prepare"));
        assert!(build.contains("needs: no-kvm-bootstrap"));
        assert!(smoke.contains("needs: no-kvm-build"));
        assert!(workload > smoke.find(grant).expect("smoke must grant vhost-vsock"));
    }

    #[test]
    fn dedicated_mcp_smoke_lane_stays_out_of_ci() {
        let workflow = ci_workflow();
        for removed in [
            "MCP server stdio roundtrip",
            "mcp-server-smoke",
            "test-mcp-roundtrip.sh",
            "Install MCP smoke dependency",
        ] {
            assert!(
                !workflow.contains(removed),
                "dedicated MCP CI surface must stay absent: {removed}"
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

    /// A branch ref re-resolves on every run, so what executes is whatever
    /// upstream pushed last.
    #[test]
    fn a_branch_ref_is_reported_and_a_pinned_one_is_not() {
        let floating = "\
      - uses: DeterminateSystems/nix-installer-action@main
      - uses: some/other-action@master
";
        let found = floating_action_refs(floating);
        assert_eq!(
            found,
            vec![
                "DeterminateSystems/nix-installer-action@main".to_string(),
                "some/other-action@master".to_string(),
            ]
        );

        let pinned = "\
      - uses: DeterminateSystems/nix-installer-action@ef8a148080ab6020fd15196c2084a2eea5ff2d25 # v22
      - uses: actions/checkout@v6
      - uses: ./.github/actions/rust-cache
      - uses: ./.github/workflows/bdd.yml
";
        assert!(
            floating_action_refs(pinned).is_empty(),
            "a pinned ref, a tag, a local action and a reusable workflow are all fine"
        );

        // The trailing `# v22` comment must not be read as part of the ref.
        assert!(
            third_party_action_refs(pinned)
                .any(|(_, r)| r == "ef8a148080ab6020fd15196c2084a2eea5ff2d25"),
            "the sha must parse without the version comment attached"
        );

        // The documented exception, and only for the action that needs it.
        assert!(floating_action_refs("      - uses: dtolnay/rust-toolchain@master\n").is_empty());
        assert_eq!(
            floating_action_refs("      - uses: dtolnay/other@master\n").len(),
            1,
            "the exception is per-action, not a blanket pass for the owner"
        );
    }

    /// A workflow with no `pull_request` trigger may not cancel itself.
    ///
    /// `cancel-in-progress` exists to keep a PR's check panel free of runs
    /// from superseded SHAs. A workflow that pull requests never trigger has
    /// no such panel, so the only run cancellation can reach is one already
    /// under way — and on the schedule-plus-dispatch workflows those run for
    /// hours. Worse, `github.ref` does not separate them: a nightly cron and
    /// an operator dispatch both carry `refs/heads/main`, so keying the group
    /// on the ref alone put them in the *same* group rather than different
    /// ones. Four consecutive `Extended CI` runs cancelled each other that
    /// way, and each reported `cancelled`, which reads as a red lane rather
    /// than as a lane that was never allowed to finish.
    ///
    /// Derived from the trigger list rather than a filename allow-list, so a
    /// new nightly workflow inherits the rule instead of having to be
    /// remembered.
    #[test]
    fn a_workflow_without_pull_requests_never_cancels_a_run_in_flight() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(".github/workflows");
        let mut checked = 0usize;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "yml") {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            if src.contains("\n  pull_request:") {
                continue;
            }
            checked += 1;
            assert!(
                !src.contains("cancel-in-progress: true"),
                "{}: no pull_request trigger, so cancel-in-progress can only \
                 kill a run already in flight",
                path.display()
            );
        }
        assert!(
            checked >= 3,
            "expected several non-PR workflows; found {checked} — has the \
             trigger spelling this scans for changed?"
        );
    }

    /// No workflow in the tree may float, exception aside.
    #[test]
    fn no_workflow_floats_a_third_party_action() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(".github/workflows");
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "yml") {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            assert!(
                floating_action_refs(&src).is_empty(),
                "{}: {:?}",
                path.display(),
                floating_action_refs(&src)
            );
        }
    }

    #[test]
    fn setup_uv_pins_the_tool_as_well_as_the_action() {
        let unpinned = "\
      - name: Set up uv
        uses: astral-sh/setup-uv@v8.2.0
      - name: Next step
";
        assert_eq!(unversioned_setup_uv_steps(unpinned), 1);

        let pinned = "\
      - name: Set up uv
        uses: astral-sh/setup-uv@v8.2.0
        with:
          version: \"0.12.5\"
      - name: Next step
";
        assert_eq!(unversioned_setup_uv_steps(pinned), 0);
    }

    /// Every security lane runs on a schedule someone will notice.
    ///
    /// This exists because the lanes below were deleted, not weakened:
    /// `sealed-prod-allowlist` and `jailer-property` were removed with
    /// `ci-full.yml` on the reasoning that the workflow had never been
    /// triggered. It hadn't — the run count was zero and that was real —
    /// but a security lane that has never run is one to start running.
    /// Both now sit in `security.yml`, which is what
    /// `security-lane-watch.yml` reports on.
    #[test]
    fn security_lanes_live_where_the_watcher_reads_them() {
        let security = workflow("security.yml");
        for lane in [
            "sealed-prod-allowlist:",
            "jailer-property:",
            "app-deps-audit:",
            "oci-hardening:",
        ] {
            assert!(
                security.contains(lane),
                "{lane} must live in security.yml — that is the workflow \
                 security-lane-watch.yml watches, and these lanes back \
                 numbered claims in ADR-001"
            );
        }

        // Watched, and on a cadence. A lane only reachable by dispatch is
        // one nobody runs; that is how these came to be dead in the first
        // place.
        let watcher = workflow("security-lane-watch.yml");
        for (name, wf) in [
            ("Security", "security.yml"),
            ("Pack signing smoke", "pack-signing-smoke.yml"),
            ("Extended CI", "ci-full.yml"),
        ] {
            assert!(
                watcher.contains(name),
                "security-lane-watch.yml must report on {name}"
            );
            assert!(
                workflow(wf).contains("schedule:"),
                "{wf} must run on a schedule, not dispatch alone"
            );
        }
    }

    #[test]
    fn extended_ci_macos_builds_install_libkrun_from_a_trusted_tap() {
        let extended = workflow("ci-full.yml");
        for job in ["apple", "libkrun-macos"] {
            let body = job_body(&extended, job).expect("extended CI job must exist");
            assert!(
                body.contains("uses: ./.github/actions/install-libkrun"),
                "{job} must use the shared resilient libkrun installer"
            );
        }

        let action = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join(".github/actions/install-libkrun/action.yml"),
        )
        .expect("shared libkrun installer must be readable");
        for command in [
            "brew tap slp/krun",
            "brew trust slp/krun",
            "brew install --build-from-source slp/krun/libkrunfw",
            "brew install slp/krun/libkrun",
            "for attempt in 1 2 3",
        ] {
            assert!(
                action.contains(command),
                "shared libkrun installer must contain `{command}`"
            );
        }

        let apple = job_body(&extended, "apple").expect("Apple job must exist");
        let embedded_toolchain = apple
            .find("uses: ./.github/actions/install-zigbuild")
            .expect("Apple workspace build must install the embedded-host toolchain");
        let build = apple
            .find("      - name: Build")
            .expect("Apple workspace build step must exist");
        assert!(
            embedded_toolchain < build,
            "Apple must install the embedded-host toolchain before building mvm-cli"
        );
    }

    #[test]
    fn extended_ci_builder_image_stubs_every_manifest_binary() {
        let extended = workflow("ci-full.yml");
        let body =
            job_body(&extended, "builder-vm-image-linux").expect("builder VM image job must exist");
        for binary in ["mvm-host-vm-init", "mvm-egress-proxy", "mvm-builderd"] {
            assert!(
                body.contains(&format!("$HOST_BIN_DIR/{binary}")),
                "builder VM image smoke must provide the manifest binary {binary}"
            );
        }
    }

    /// Only one workflow may publish a required check's name.
    ///
    /// Both of these build kernels from the same script, and both once
    /// declared `name: Build kernels (<arch>)` — a required status check.
    /// It resolved unambiguously only because their triggers happen not to
    /// overlap: give `kernel-build.yml` a `pull_request` or `merge_group`
    /// trigger and two runs answer to one required context, with branch
    /// protection reading whichever reported last. The test above pins the
    /// triggers apart; this pins the names apart, so neither half of the
    /// arrangement can quietly go away.
    #[test]
    fn only_one_workflow_claims_the_required_kernel_check_name() {
        const REQUIRED: &str = "name: Build kernels (${{ matrix.arch }})";

        assert!(
            workflow("ci.yml").contains(REQUIRED),
            "ci.yml owns the required kernel check name"
        );
        assert!(
            !workflow("kernel-build.yml").contains(REQUIRED),
            "kernel-build.yml must not publish the same check name as ci.yml — \
             it is the tag-time publisher, not the required PR gate"
        );
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
                "crates/mvm-fs/",
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

    /// A job's body stops where the next job starts, or the fuzz budget
    /// would be read out of whatever job happened to follow.
    #[test]
    fn a_job_body_stops_at_the_next_job() {
        let src = "jobs:\n  first:\n    timeout-minutes: 10\n  # a comment: not a job\n    env:\n      X: 1\n  second:\n    timeout-minutes: 99\n";
        let first = job_body(src, "first").expect("first job");
        assert!(first.contains("timeout-minutes: 10"));
        assert!(
            !first.contains("99"),
            "the next job's settings leaked into this one: {first:?}"
        );
        // A comment at job indent is prose, not a boundary.
        assert!(first.contains("X: 1"));
        assert_eq!(job_body(src, "third"), None);
    }

    #[test]
    fn a_scalar_is_read_without_its_trailing_comment() {
        assert_eq!(
            scalar_u64("    timeout-minutes: 300\n", "timeout-minutes"),
            Some(300)
        );
        assert_eq!(
            scalar_u64(
                "      FUZZ_SECS_SCHEDULE: 720 # why\n",
                "FUZZ_SECS_SCHEDULE"
            ),
            Some(720)
        );
        assert_eq!(
            scalar_u64("    timeout-minutes: soon\n", "timeout-minutes"),
            None
        );
        assert_eq!(scalar_u64("    other: 1\n", "timeout-minutes"), None);
    }

    /// The live assertion. Seventeen targets at half an hour each was nine
    /// hours in a six-hour job, which is what the nightly lane was actually
    /// running: killed partway down the list, every target below the cut
    /// silently never fuzzed.
    ///
    /// The floor below guards against the *parser* failing to resolve targets
    /// and reporting a trivially-fitting budget — it is not a mandate to keep a
    /// given number of them. Deleting a target legitimately lowers it; the FUSE
    /// dispatch target went when the virtio-fs device it fuzzed was deleted,
    /// taking the count from 15 to 14.
    #[test]
    fn the_fuzz_lane_fits_inside_its_own_timeout() {
        let budget =
            fuzz_budget(&workflow("security.yml")).expect("security.yml declares a fuzz budget");
        assert!(
            budget.targets >= 14,
            "the target count did not resolve: {budget:?}"
        );
        assert!(
            budget.fits(),
            "{} targets × {}s + build does not fit in {} min",
            budget.targets,
            budget.per_target_secs,
            budget.timeout_minutes
        );
    }

    /// And it has to be able to say no, or it is decoration.
    #[test]
    fn a_lane_that_cannot_finish_is_rejected() {
        let over = FuzzBudget {
            per_target_secs: 1800,
            timeout_minutes: 300,
            targets: 17,
        };
        assert!(!over.fits());
        // Halving the per-target time is the fix that brings it back.
        assert!(
            FuzzBudget {
                per_target_secs: 720,
                ..over
            }
            .fits()
        );
        // So is dropping targets.
        assert!(FuzzBudget { targets: 4, ..over }.fits());
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
