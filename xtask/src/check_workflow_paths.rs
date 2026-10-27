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

    /// The slow lanes that run after the merge.
    fn main_workflow() -> String {
        workflow("ci-main.yml")
    }

    #[test]
    fn sdk_distribution_evidence_survives_the_release_review_window() {
        for (file, job, step, artifact) in [
            (
                "publish-npm.yml",
                "build",
                "Upload packed artifacts",
                "npm-dist",
            ),
            (
                "publish-pypi.yml",
                "build",
                "Upload built artifacts",
                "pypi-dist-${{ matrix.platform }}",
            ),
        ] {
            let source = workflow(file);
            let upload = job_block(&source, job)
                .split(&format!("      - name: {step}\n"))
                .nth(1)
                .expect("distribution upload step must exist")
                .split("\n      - ")
                .next()
                .unwrap();
            for required in [
                "uses: actions/upload-artifact@",
                &format!("name: {artifact}"),
                "retention-days: 30",
                "if-no-files-found: error",
            ] {
                assert!(upload.contains(required), "{file}: missing {required}");
            }
        }
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

    /// A job's `if:` condition, folded onto one line; empty when it has none.
    fn job_if(block: &str) -> String {
        let mut lines = block
            .lines()
            .skip_while(|line| !line.starts_with("    if:"));
        let Some(first) = lines.next() else {
            return String::new();
        };
        let mut condition = first.trim_start_matches("    if:").trim().to_string();
        for line in lines.take_while(|line| line.starts_with("      ")) {
            condition.push(' ');
            condition.push_str(line.trim());
        }
        condition
    }

    /// Lanes that run on a pull request, in the merge queue and on a push to main.
    const FAST_GATE_LANES: [&str; 2] = ["lint-core", "test-workspace-build"];

    /// Lanes that run on a pull request and a push to main, never in the queue.
    const PR_GATE_LANES: [&str; 4] = [
        "lint-feature-clippy",
        "lint-windows",
        "test-windows-identity",
        "test-workspace",
    ];

    fn step_run(job: &str, name: &str) -> String {
        job.split(&format!("      - name: {name}\n"))
            .nth(1)
            .expect("named step must exist")
            .split("        run: |\n")
            .nth(1)
            .expect("step must have a literal run block")
            .lines()
            .take_while(|line| line.is_empty() || line.starts_with("          "))
            .map(|line| line.strip_prefix("          ").unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n")
            .trim_end()
            .to_string()
    }

    #[test]
    fn docs_scope_matches_the_documented_example_corpus_roots() {
        let source = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../crates/mvm-conformance/src/doc_examples.rs"),
        )
        .unwrap();
        let parsed = syn::parse_file(&source).unwrap();
        let roots = |name: &str| {
            let item = parsed
                .items
                .iter()
                .find_map(|item| match item {
                    syn::Item::Const(item) if item.ident == name => Some(item),
                    _ => None,
                })
                .expect("documentation corpus constant must exist");
            let syn::Expr::Array(array) = item.expr.as_ref() else {
                panic!("documentation corpus must be an explicit array");
            };
            array
                .elems
                .iter()
                .map(|element| {
                    let syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(value),
                        ..
                    }) = element
                    else {
                        panic!("documentation root must be a string");
                    };
                    value.value()
                })
                .collect::<Vec<_>>()
        };
        let patterns = roots("DOCUMENTATION_FILES")
            .iter()
            .map(|root| format!("{}$", regex::escape(root)))
            .chain(
                roots("DOCUMENTATION_TREES")
                    .iter()
                    .map(|root| format!("{root}/")),
            )
            .collect::<Vec<_>>()
            .join("|");
        let ci = ci_workflow();
        assert!(
            job_block(&ci, "scope").contains(&format!("grep -zE '^({patterns})'")),
            "the docs classifier must match documentation_files() roots"
        );
    }

    #[test]
    fn docs_static_is_required_without_reintroducing_queue_bdd() {
        let ci = ci_workflow();
        let lane = job_block(&ci, "docs-static");
        assert!(lane.contains("needs: [scope]"));
        assert_eq!(job_if(lane), "needs.scope.outputs.docs == 'true'");
        for setup in [
            "actions/checkout@v6",
            "dtolnay/rust-toolchain@1.97.1",
            "uses: ./.github/actions/rust-cache",
        ] {
            assert!(lane.contains(setup));
        }
        assert_eq!(
            step_run(lane, "Check static documentation surfaces"),
            "cargo run -p xtask -- check-cli-help-matches-docs\n\
             cargo run -p xtask -- check-doc-links\n\
             cargo run -p xtask -- check-doc-claims"
        );
        for heavy in ["--features", "bdd", "artifact", "cargo build", "sdk build"] {
            assert!(!lane.contains(heavy), "docs static must not add {heavy}");
        }
        let scope = job_block(&ci, "scope");
        for wiring in [
            "docs: ${{ steps.validate.outputs.docs }}",
            "DOCS: ${{ steps.decide.outputs.docs }}",
            "validate docs \"$DOCS\"",
            "for output in code architecture docs; do",
        ] {
            assert!(scope.contains(wiring));
        }
        let aggregate = job_block(&ci, "test");
        assert!(aggregate.contains("needs: [scope, runners, docs-static,"));
        assert!(aggregate.contains("if: ${{ always() }}"));
        assert!(aggregate.contains(
            "BAD: ${{ contains(needs.*.result, 'failure') || contains(needs.*.result, 'cancelled') }}"
        ));
        assert!(aggregate.contains("DOCS: ${{ needs.scope.outputs.docs }}"));
        assert!(aggregate.contains("DOCS_RESULT: ${{ needs.docs-static.result }}"));
        assert!(job_body(&ci, "bdd-conformance").is_none());
        assert!(!ci.contains("uses: ./.github/workflows/bdd.yml"));
        let main = main_workflow();
        assert_eq!(job_if(job_block(&main, "bdd-conformance")), "");
    }

    #[cfg(unix)]
    #[test]
    fn docs_scope_validation_rejects_missing_and_invalid_outputs() {
        use std::process::Command;
        let ci = ci_workflow();
        let script = step_run(job_block(&ci, "scope"), "Validate classification");
        let temp = tempfile::NamedTempFile::new().unwrap();
        for docs in ["true", "false", "", "invalid"] {
            let result = Command::new("bash")
                .args(["-c", &script])
                .env("CODE", "false")
                .env("ARCHITECTURE", "false")
                .env("DOCS", docs)
                .env("GITHUB_OUTPUT", temp.path())
                .output()
                .unwrap();
            assert_eq!(result.status.success(), matches!(docs, "true" | "false"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn aggregate_requires_valid_docs_scope_and_required_lane_success() {
        use std::process::Command;
        let ci = ci_workflow();
        let script = step_run(
            job_block(&ci, "test"),
            "Require every validation lane to pass",
        );
        for docs in ["true", "false", "", "invalid"] {
            for scope in ["success", "skipped", "failure", "cancelled"] {
                for lane in ["success", "skipped", "failure", "cancelled", "", "invalid"] {
                    for other in ["success", "skipped", "failure", "cancelled"] {
                        let bad = [scope, lane, other]
                            .iter()
                            .any(|result| matches!(*result, "failure" | "cancelled"));
                        let verdict = Command::new("bash")
                            .args([
                                "--noprofile",
                                "--norc",
                                "-e",
                                "-o",
                                "pipefail",
                                "-c",
                                &script,
                            ])
                            .env("BAD", bad.to_string())
                            .env("DOCS", docs)
                            .env("DOCS_RESULT", lane)
                            .output()
                            .unwrap();
                        let expected = !bad
                            && match docs {
                                "true" => lane == "success",
                                "false" => matches!(lane, "success" | "skipped"),
                                _ => false,
                            };
                        assert_eq!(
                            verdict.status.success(),
                            expected,
                            "docs={docs:?}, scope={scope}, lane={lane}, other={other}: {verdict:?}"
                        );
                    }
                }
            }
        }
    }

    // Execute the workflow's shell, stubbing only git's external inputs. This
    // covers NUL-delimited paths and failure fallbacks without a real checkout.
    #[cfg(unix)]
    #[test]
    fn docs_classifier_executes_paths_and_fail_closed_events() {
        use std::process::Command;
        let ci = ci_workflow();
        let script = step_run(job_block(&ci, "scope"), "Classify changed paths");
        let temp = tempfile::tempdir().unwrap();
        let changed = temp.path().join("changed");
        let output = temp.path().join("output");
        let cases = [
            ("README.md", true, true),
            ("AGENTS.md", true, true),
            ("public/src/content/docs/guides/new.mdx", true, false),
            (
                "public/src/content/docs/new file\nwith newline.md",
                true,
                false,
            ),
            ("crates/mvm-sdk/sdks/python/README.md", true, true),
            ("examples/new/config.toml", true, true),
            ("public/src/content/docs-extra/page.md", false, false),
            ("README.md.bak", false, false),
            ("docs/README.md", false, false),
            ("public/src/pages/index.astro", false, false),
            ("crates/mvm-core/src/lib.rs", false, true),
        ];
        for event in ["pull_request", "merge_group", "push", "workflow_dispatch"] {
            for failure in ["", "fetch", "merge-base", "diff", "base-ref"] {
                for (path, docs, code) in cases {
                    std::fs::write(&changed, format!("{path}\0")).unwrap();
                    std::fs::write(&output, "").unwrap();
                    let result = Command::new("bash")
                        .arg("-c")
                        .arg(format!(
                            r#"git() {{
  if [ "$1" = "$FAILURE" ]; then return 1; fi
  case "$1" in
    fetch) ;;
    merge-base) printf 'base\n' ;;
    diff) cat "$CHANGED" ;;
    *) return 2 ;;
  esac
}}
{script}"#
                        ))
                        .env("EVENT", event)
                        .env("FAILURE", failure)
                        .env(
                            "MG_BASE_REF",
                            if failure == "base-ref" {
                                "invalid"
                            } else {
                                "refs/heads/main"
                            },
                        )
                        .env("MG_HEAD", "head")
                        .env("PR_BASE", "base")
                        .env("PR_HEAD", "head")
                        .env("CHANGED", &changed)
                        .env("GITHUB_OUTPUT", &output)
                        .output()
                        .unwrap();
                    assert!(
                        result.status.success(),
                        "{event}/{failure}/{path}: {result:?}"
                    );
                    let outputs = std::fs::read_to_string(&output).unwrap();
                    let all = matches!(event, "push" | "workflow_dispatch")
                        || matches!(failure, "merge-base" | "diff")
                        || (event == "merge_group" && matches!(failure, "fetch" | "base-ref"));
                    assert!(
                        outputs.contains(&format!("docs={}", all || docs)),
                        "{event}/{failure}/{path}: {outputs}"
                    );
                    assert!(
                        outputs.contains(&format!("code={}", all || code)),
                        "{event}/{failure}/{path}: {outputs}"
                    );
                    if all {
                        assert!(outputs.contains("architecture=true"));
                    }
                }
            }
        }
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
    fn pull_request_ci_runs_the_required_matrix_without_redundant_caches() {
        let workflow = ci_workflow();
        let main = main_workflow();
        assert!(
            job_body(&workflow, "lint").is_none(),
            "the redundant Lint aggregate must not allocate a second control runner"
        );

        let lint_core = job_block(&workflow, "lint-core");
        assert!(
            lint_core.contains("./scripts/cargo-stable.sh clippy --all-targets -- -D warnings")
        );
        assert!(lint_core.contains("cargo fmt --all -- --check"));
        assert!(lint_core.contains("cargo metadata --locked --format-version 1 --no-deps"));
        let lint_policy = job_block(&workflow, "lint-policy");
        assert!(lint_policy.contains("name: Invariant"));
        assert!(lint_policy.contains("bash scripts/check-no-orchestration-server.sh"));
        // The policy gates arrive through the driver, so the lane pins the
        // driver and `check_all`'s own tests pin the table's contents.
        // Asserting a particular gate's step here again would just be the
        // sixty-step list in another file.
        assert!(lint_policy.contains("cargo run -p xtask -- check-all"));
        assert!(lint_policy.contains("bash scripts/cargo-target-dir-guard.test.sh"));
        assert!(lint_policy.contains("bash scripts/dev-run-guard.test.sh"));
        assert!(lint_policy.contains("Policy gates (check-abi-layout) (single-network-path)"));
        assert!(
            crate::check_all::GATES
                .iter()
                .any(|(name, _)| *name == "check-conformance"),
            "check-conformance must still be one of the gates the lane runs"
        );
        // The test-support subtree is its own job. At 19 minutes inside a
        // 35-minute `lint-features` it was the critical path for every
        // code-touching pull request, and nothing beside it shared a cargo
        // fingerprint to lose by moving it out.
        let lint_features = job_block(&main, "lint-features-test-support");
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
        assert!(test.contains("if: ${{ always() }}"));
        assert!(test.contains("runs-on: ubuntu-slim"));
        assert!(
            !test.contains("actions/checkout") && !test.contains("cargo "),
            "the aggregate must publish the required context without another full runner"
        );
        assert!(test.contains(
            "needs: [scope, runners, docs-static, lint-core, lint-policy, lint-feature-clippy, \
             lint-windows, test-windows-identity, test-workspace-build, test-workspace]"
        ));
        let test_main = job_block(&main, "test-main");
        assert!(test_main.contains("name: Test (main)"));
        assert!(
            test_main.contains(
                "needs: [lint-features, lint-features-test-support, lint-features-embed, \
                 bdd-conformance, test-workspace-extras, test-workspace-aarch64, \
                 test-release-witness, test-musl-confinement, test-linux, \
                 test-ebpf-telemetry, boot-latency, nix-flake-check]"
            ),
            "every post-merge lane must feed the Test (main) aggregate"
        );
        assert!(
            job_body(&workflow, "pr-regressions").is_none(),
            "focused regressions must not allocate a separate PR runner"
        );
        for expected in [
            "github.event_name == 'pull_request'",
            "shellcheck \"${scripts[@]}\"",
            "rustc +1.97.1 --edition=2024 -D warnings --test",
            "git merge-base \"$BASE_SHA\" \"$HEAD_SHA\"",
            "git diff --name-only --diff-filter=A",
            "could not classify added shell scripts",
        ] {
            assert!(
                lint_policy.contains(expected),
                "the policy lane must keep the focused regression {expected:?}"
            );
        }

        // The tier split. Fast-gate lanes run on a pull request and again in
        // the queue; PR-gate lanes run on a pull request and a push but not in
        // the queue. The slow lanes live in ci-main.yml and never see either.
        for lane in FAST_GATE_LANES {
            let job_if = job_if(job_block(&workflow, lane));
            assert!(
                job_if.contains("needs.scope.outputs.code == 'true'")
                    && !job_if.contains("github.event_name"),
                "{lane} is fast-gate: it must run for code on every event, got {job_if:?}"
            );
        }
        for lane in PR_GATE_LANES {
            let job_if = job_if(job_block(&workflow, lane));
            assert!(
                job_if.contains("needs.scope.outputs.code == 'true'")
                    && job_if.contains("github.event_name != 'merge_group'")
                    && !job_if.contains("'pull_request'"),
                "{lane} runs on a pull request and a push but not in the queue, got {job_if:?}"
            );
        }
        assert!(
            !main.contains("pull_request") && !main.contains("merge_group"),
            "ci-main.yml is push and dispatch only"
        );

        // The release-profile lane is the only one that runs with trapping
        // overflow and debug assertions off, i.e. the only one that witnesses
        // what actually ships. A lane that runs but is not in the aggregate's
        // `needs` is a lane that cannot fail the merge, so pin both halves.
        let release_witness = job_block(&main, "test-release-witness");
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

        // The Linux release ships static musl binaries, and the libc decides
        // which syscalls reach a confined role's seccomp filter. Only this
        // lane builds the endpoint the way the release does, so it must cover
        // both shipped musl targets and stay in the aggregate.
        let musl = job_block(&main, "test-musl-confinement");
        for expected in [
            "target: x86_64-unknown-linux-musl",
            "target: aarch64-unknown-linux-musl",
            "uses: ./.github/actions/install-zigbuild",
            "cargo-zigbuild test --profile release-witness --target \"${TARGET}\"",
            "--test confinement_self_test",
            "--test network_endpoint_bin",
            "--test seccomp_property",
        ] {
            assert!(
                musl.contains(expected),
                "musl confinement lane must contain {expected:?}"
            );
        }

        let test_workspace = job_block(&workflow, "test-workspace");
        assert!(!test_workspace.contains("uses: actions/cache@v5"));
        assert_workspace_suite_compiles_once_and_runs_everything(&workflow, &main);
        assert_aarch64_suite_compiles_once_and_runs_everything(&main);
        for expected in [
            "permissions:",
            "actions: read",
            "uses: ./.github/workflows/workspace-shard.yml",
            "commit_sha: ${{ github.sha }}",
            "shard: ${{ matrix.shard }}",
            "runner_kind: ${{ needs.runners.outputs.workspace == 'hetzner' && 'hetzner' || 'github' }}",
        ] {
            assert!(
                test_workspace.contains(expected),
                "workspace matrix must call the shard worker with {expected:?}"
            );
        }
        assert!(!test_workspace.contains("actions: write"));
        assert!(!test_workspace.contains("workflow_dispatch"));
        let workspace_worker = self::workflow("workspace-shard.yml");
        let safe_archive_root = "archive_root=\"$RUNNER_TEMP/mvm-workspace-${ARCHIVE_RUN_ID}\"";
        assert!(
            workflow.contains(safe_archive_root) && workspace_worker.contains(safe_archive_root),
            "archive build and shard must stay outside /tmp, which mvmctl cleanup tests clear"
        );
        assert!(!workflow.contains("archive_root=\"/tmp/mvm-workspace-"));
        assert!(!workspace_worker.contains("/tmp/mvm-workspace-"));
        for expected in [
            "workflow_call:",
            "workflow_dispatch:",
            "fromJSON('[\"self-hosted\",\"Linux\",\"X64\",\"mvm\",\"hetzner\",\"kvm\"]')",
            "if: inputs.runner_kind == 'github' && inputs.archive_run_id == ''",
            "key: ${{ inputs.runner_kind == 'hetzner' && 'hetzner-workspace' || 'workspace' }}",
            "archive_run_id:",
            "--archive-file \"$RUNNER_TEMP/workspace-tests.tar.zst\"",
            "--partition \"hash:${SHARD}/${SHARD_COUNT}\"",
            "SHARD_COUNT: ${{ inputs.shard_count || '2' }}",
            "\"$SHARD\" -le \"$SHARD_COUNT\"",
            "|| 'ubuntu-24.04' }}",
            "name: workspace-tests\n",
            "cargo nextest run --workspace --all-targets --partition \"hash:${SHARD}/${SHARD_COUNT}\"",
            "actions: read",
            "workspace-archive-{0}",
            "workspace-shard-{0}-{1}",
            "if: inputs.archive_run_id == ''",
            "if: inputs.archive_run_id != ''",
            "cp -a \"$GITHUB_WORKSPACE/.\" \"$archive_root/\"",
            "run-id: ${{ inputs.archive_run_id }}",
            "github-token: ${{ secrets.GITHUB_TOKEN }}",
            "--workspace-remap \"$archive_root\"",
            "--extract-to \"$archive_root\"",
        ] {
            assert!(
                workspace_worker.contains(expected),
                "workspace shard worker must contain {expected:?}"
            );
        }
        assert!(!workspace_worker.contains("actions: write"));
        let test_linux = job_block(&main, "test-linux");
        assert!(test_linux.contains("bash scripts/ci-linux-coverage.sh"));
        assert!(!workspace_worker.contains("ci-linux-coverage.sh"));

        let linux_coverage = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("scripts/ci-linux-coverage.sh"),
        )
        .expect("Linux coverage script must be readable");
        for expected in [
            "cargo +1.97.1 build -p mvm-contract --target wasm32-unknown-unknown",
            "cargo test -p mvm-conformance --test meta",
        ] {
            assert!(
                linux_coverage.contains(expected),
                "Linux coverage script must contain {expected:?}"
            );
        }

        // One owner for the Gherkin suite. It ran here *and* in
        // `bdd-conformance`, so every pull request touching `crates/mvm-cli/`
        // paid for 252 scenarios twice — about 16 of this lane's 20 minutes.
        // Pin both halves: gone from here, still present there.
        // Executable lines only. A `#` line naming the suite is the comment
        // explaining why it left, and a gate that cannot tell prose from a
        // command forces that explanation to be written around it.
        let linux_commands = linux_coverage
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !linux_commands.contains("just bdd"),
            "the Gherkin suite belongs to bdd-conformance; running it here too \
             is the duplicate that made this the slowest lane in the workflow"
        );
        let bdd_workflow = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join(".github/workflows/bdd.yml"),
        )
        .expect("BDD workflow must be readable");
        assert!(
            bdd_workflow.contains("just bdd"),
            "bdd-conformance must still run the Gherkin suite"
        );
        // ...and it has to run on every push to main, the Linux lane's tier.
        let bdd = job_block(&main, "bdd-conformance");
        assert!(
            bdd.contains("uses: ./.github/workflows/bdd.yml"),
            "bdd-conformance must call the Gherkin workflow"
        );
    }

    #[test]
    fn workspace_archive_download_is_bounded_and_fails_closed() {
        let worker = workflow("workspace-shard.yml");
        let download = worker
            .split_once("      - name: Download shared workspace test archive\n")
            .expect("workspace shards must download their shared test archive")
            .1
            .split("\n      - ")
            .next()
            .expect("download step body");
        assert!(
            download.contains("\n        timeout-minutes: 10\n"),
            "a stalled artifact transfer must not occupy a runner for the whole job"
        );
        assert!(download.contains("uses: actions/download-artifact@"));
        assert!(download.contains("run-id: ${{ inputs.archive_run_id }}"));
        assert!(
            !download.contains("continue-on-error:"),
            "a failed archive transfer must fail the shard, never skip its tests"
        );
    }

    /// The workspace suite is compiled by one job and run by the shards out of
    /// its archive. Pin the parts whose loss would shrink coverage without
    /// turning anything red: the archive's target selection, the shards'
    /// dependency on it and their partition of all of it, and the suites that
    /// run exactly once.
    fn assert_workspace_suite_compiles_once_and_runs_everything(workflow: &str, main: &str) {
        let build = job_block(workflow, "test-workspace-build");
        assert!(
            build.contains("cargo nextest archive --workspace --all-targets"),
            "the archive must hold the whole workspace's tests, every target"
        );
        assert!(
            !build.contains("check-nextest-groups"),
            "listing the suite once per filter cost eight minutes on the fast gate's critical path"
        );
        assert!(
            job_block(main, "test-workspace-extras")
                .contains("cargo run -p xtask -- check-nextest-groups"),
            "the nextest override filters must still be validated on a push to main"
        );
        let upload = build
            .find("uses: actions/upload-artifact@")
            .expect("the build job must hand the archive on");
        assert!(build[upload..].contains("name: workspace-tests"));

        let shards = job_block(workflow, "test-workspace");
        assert!(
            shards.contains("needs: [scope, runners, test-workspace-build]")
                && shards.contains("needs.scope.outputs.code == 'true'")
                && shards.contains("needs.test-workspace-build.result == 'success'"),
            "the shards must wait for the archive and keep the scope gate"
        );
        assert!(
            build.contains("needs.runners.outputs.workspace != 'hetzner'"),
            "only the hosted suite runs from an archive"
        );
        assert!(
            !shards.contains("cargo build")
                && !shards.contains("cargo nextest archive")
                && !shards.contains("--features"),
            "a shard must run the archive it was handed, not compile its own"
        );
        for expected in [
            "uses: ./.github/workflows/workspace-shard.yml",
            "archive_run_id: ${{ needs.runners.outputs.workspace != 'hetzner' && github.run_id || '' }}",
            "shard: ${{ fromJSON(needs.runners.outputs.workspace == 'hetzner' && '[\"1\"]' || '[\"1\", \"2\"]') }}",
            "shard_count: ${{ needs.runners.outputs.workspace == 'hetzner' && '1' || '2' }}",
        ] {
            assert!(
                shards.contains(expected),
                "the caller must start two archive-backed hosted shards, or one \
                 self-hosted shard that builds its own: missing {expected:?}"
            );
        }

        let extras = job_block(main, "test-workspace-extras");
        for expected in [
            "cargo nextest run -p xtask --features man",
            "cargo nextest run -p mvm-agentd --features addons",
            "cargo test --workspace --doc",
        ] {
            assert!(
                extras.contains(expected),
                "the once-only workspace suites must keep running: missing {expected:?}"
            );
        }
        // The addons suite also runs on the stable toolchain in Lint feature
        // coverage, so only these two are unique to this job.
        for once in [
            "cargo nextest run -p xtask --features man",
            "cargo test --workspace --doc",
        ] {
            assert_eq!(
                workflow.matches(once).count() + main.matches(once).count(),
                1,
                "{once:?} must run exactly once in CI"
            );
        }
    }

    /// The aarch64 suite builds and runs in one job on one arm64 runner: in
    /// the merge queue a hosted arm64 runner costs far more waiting than the
    /// suite costs running, so it is never split into shards or a separate
    /// build. Pin the parts whose loss would shrink aarch64 coverage while
    /// every lane stays green: the target selection (everything but the
    /// `mvm-fs` oracle that cannot build there), the privileged witnesses,
    /// and a run that is the whole suite rather than a partition of it.
    fn assert_aarch64_suite_compiles_once_and_runs_everything(workflow: &str) {
        assert!(
            job_body(workflow, "test-workspace-aarch64-build").is_none(),
            "the aarch64 suite must build where it runs, not hand an archive to another runner"
        );
        let job = job_block(workflow, "test-workspace-aarch64");
        for expected in [
            "name: Test workspace (aarch64)",
            "runs-on: ubuntu-24.04-arm",
            "run: cargo nextest run --workspace --exclude mvm-fs --all-targets\n",
            "MVM_GUEST_PRIVILEGED_TESTS=1",
            "grep -q \"test result: ok. 4 passed\" \"$RUNNER_TEMP/helper.log\"",
            "tool_attribution::tests::egress_identity_alone_receives_live_attribution_over_unix_credentials",
            "printf 'HOME=%s\\nMVM_HOME=%s\\nTMPDIR=%s\\n'",
        ] {
            assert!(
                job.contains(expected),
                "the aarch64 suite job must contain {expected:?}"
            );
        }
        for absent in [
            "--all-targets --no-run",
            "--partition",
            "strategy:",
            "workspace-shard.yml",
            "upload-artifact",
        ] {
            assert!(
                !job.contains(absent),
                "the aarch64 suite must run whole on one runner: found {absent:?}"
            );
        }
    }

    #[test]
    fn short_output_stress_runs_on_native_aarch64_with_prepared_workspace() {
        let workflow = main_workflow();
        let job = job_block(&workflow, "test-workspace-aarch64");
        assert!(job.contains("runs-on: ubuntu-24.04-arm\n"));
        let preparation = job
            .find("run: cargo nextest run --workspace --exclude mvm-fs --all-targets\n")
            .expect("the workspace suite prepares the native test artifacts");
        let stress = job
            .find("run: cargo nextest run --stress-count 200 -E 'test(run_job_matches_streaming_for_short_output)'\n")
            .expect("the exact short-output stress witness must run");
        let restore = job
            .find("- name: Restore HOME")
            .expect("restore runner HOME");
        assert!(preparation < stress && stress < restore);
        let step = &job[job[..stress].rfind("- name:").expect("stress step")..restore];
        assert!(step.contains("working-directory: crates/mvm-builder-guest\n"));
        assert!(!step.contains("if:"));
        assert!(!step.contains("continue-on-error:"));
    }

    #[test]
    fn feature_coverage_tail_uses_existing_test_support_runner() {
        let workflow = main_workflow();
        let core = job_block(&workflow, "lint-features");
        let support = job_block(&workflow, "lint-features-test-support");

        for expected in [
            "name: wasm-backend feature tests (wasmtime tier)",
            "cargo nextest run -p mvm-runtime --features wasm-backend",
            "cargo nextest run -p mvm-hostd --features wasm-backend --test wasm_egress_witness",
            "name: release artifact acquisition contract",
            "cargo check -p mvm-cli --features release-artifact-bootstrap --lib",
            "cargo check -p mvm-cli --features release-artifact-bootstrap,manifest-verify --lib",
            "cargo test -p mvm-build --features release-channel --lib",
            "name: Assert auto-detect still picks libkrun off Linux/HVF",
            "name: In-process pure ext4 materialize tests",
        ] {
            assert!(
                support.contains(expected),
                "test-support must retain {expected:?}"
            );
            assert!(
                !core.contains(expected),
                "core feature lane must not repeat {expected:?}"
            );
            if expected.starts_with("name:") {
                assert_eq!(
                    workflow.matches(expected).count(),
                    1,
                    "feature coverage must run {expected:?} exactly once"
                );
            }
        }
    }

    #[test]
    fn merge_group_and_pull_requests_run_the_fast_gate_and_main_runs_the_full_matrix() {
        let ci = ci_workflow();
        let main = main_workflow();
        let scope = job_block(&ci, "scope");
        for expected in [
            "name: Enforce merge queue policy",
            "bash scripts/check-merge-queue-policy.sh",
            "MG_BASE_REF: ${{ github.event.merge_group.base_ref }}",
            "MG_HEAD: ${{ github.event.merge_group.head_sha }}",
            "PR_BASE: ${{ github.event.pull_request.base.sha }}",
            "PR_HEAD: ${{ github.event.pull_request.head.sha }}",
            "git diff --name-only -z",
            "git merge-base",
            "origin/$TARGET_BRANCH",
            "grep -zE",
            "could not diff $BASE..$HEAD — running every lane to stay safe",
            "invalid or missing ${name} scope",
            "code=true",
            "architecture=true",
            "just/",
            "third_party/",
            "\\.githooks/",
            "uninstall\\.sh",
        ] {
            assert!(
                scope.contains(expected),
                "CI scope must contain fail-closed classifier fragment {expected:?}"
            );
        }

        // What must be caught before the queue: formatting, clippy over the
        // core build and the feature combinations, the policy gates, the
        // compile of every workspace test target (Linux-gated and the BDD
        // runner included) and the unit suite. All of it stays on a PR.
        let core = job_block(&ci, "lint-core");
        for expected in [
            "cargo fmt --all -- --check",
            "./scripts/cargo-stable.sh clippy --all-targets -- -D warnings",
            "./scripts/cargo-stable.sh clippy -p mvm-conformance --tests --features bdd -- -D warnings",
        ] {
            assert!(
                core.contains(expected),
                "the fast gate must run {expected:?}"
            );
        }
        let features = job_block(&ci, "lint-feature-clippy");
        for expected in [
            "MVMCTL_RELEASE_FEATURES",
            "mvm-cli/test-support",
            "mvm-agentd/addons",
            "mvm-hostd/wasm-backend",
            "mvm-sdk/deploy-remote",
            "-p mvm-core -p mvm-build -p mvm-client -- -D warnings",
            "-p mvm-sdk --no-default-features -- -D warnings",
        ] {
            assert!(
                features.contains(expected),
                "the feature-combination clippy must cover {expected:?}"
            );
        }
        assert!(
            job_block(&ci, "test-workspace-build")
                .contains("cargo nextest archive --workspace --all-targets"),
            "the fast gate must compile every workspace test target"
        );

        // `cargo install --locked` pins the installed crate's own dependencies
        // but not which version of that crate is installed, so an upstream
        // release retroactively changes this lane. Now that the lane gates the
        // merge, an unpinned install lets a publish elsewhere block the queue.
        let ebpf = job_block(&main, "test-ebpf-telemetry");
        assert!(
            !ebpf.contains("uses: ./.github/actions/free-disk"),
            "the focused eBPF lane must not spend minutes deleting unrelated runner tools"
        );
        assert!(
            ebpf.contains("cargo +nightly install --locked --version ")
                && ebpf.contains("bpf-linker"),
            "eBPF lane must install a pinned bpf-linker version"
        );

        let policy = job_block(&ci, "lint-policy");
        assert!(policy.contains("needs: [scope]"));
        assert_eq!(
            job_if(policy),
            "github.event_name != 'merge_group'",
            "policy invariants run on a pull request and a push, not in the queue"
        );
        assert!(policy.contains("needs.scope.outputs.architecture == 'true'"));

        let nix = job_block(&main, "nix-flake-check");
        assert!(
            nix.contains("run: sh scripts/check-devshell-tiers.sh"),
            "the dev shell tier check must run in the Nix lane"
        );
        assert!(!nix.contains("Boot the mvm-images-built image"));

        let guest = job_block(&main, "guest-image-boot");
        assert!(guest.contains("if: github.event_name == 'workflow_dispatch'"));
        assert!(
            guest.contains("Boot the pinned base image with the tree's guest runtime"),
            "the guest-image witness must boot the pinned base set"
        );
        for forbidden in [
            "tinylabscom/mvm-images",
            "image-source-ref",
            "nix build",
            "--override-input mvm",
        ] {
            assert!(
                !guest.contains(forbidden),
                "the guest-image witness must not build guest pieces through mvm-images: \
                 found `{forbidden}`"
            );
        }
        assert!(
            guest.contains("./scripts/locked-image-tag.sh") && guest.contains("cosign verify-blob"),
            "the base image must be the signed set images.lock pins"
        );
        assert!(
            guest.contains("MVM_RUNTIME_OVERLAY_ACQUIRE_MODE: build")
                && guest.contains("dev runtime-overlay build --source build"),
            "the guest runtime under test must be assembled from this tree"
        );
        assert!(
            !guest.contains("runtime-overlay-x86_64.tar.gz"),
            "the set's runtime-overlay member must not stand in for the tree's"
        );
        assert!(guest.contains("MVM_RUNTIME_BOOT_READY: guest-agent"));
        assert!(
            guest.contains("dev runtime-overlay build --source build --arch x86_64 --force")
                && guest.contains("cmp \"overlay-staging/$f\" \"$dir/$f\""),
            "the overlay must be reassembled and its bytes compared"
        );

        let website = workflow("website.yml");
        assert!(
            !website.contains("merge_group:"),
            "the non-required Website workflow must not consume every merge-group runner slot"
        );
    }

    #[test]
    fn windows_compile_lane_checks_the_portable_crates_and_gates_the_merge() {
        let ci = ci_workflow();
        let lane = job_block(&ci, "lint-windows");
        assert!(
            lane.contains("rustup target add x86_64-pc-windows-gnu"),
            "the lane must install the Windows GNU target into the pinned toolchain it checks with"
        );
        let check = "cargo check --locked --target x86_64-pc-windows-gnu";
        assert_eq!(
            lane.matches(check).count(),
            2,
            "the lane must check the crate set and the pure-Rust mvm-core features"
        );
        for krate in [
            "mvm-contract",
            "mvm-core",
            "mvm-net",
            "mvm-bundler",
            "mvm-backends",
        ] {
            assert!(
                lane.contains(&format!("-p {krate}")),
                "the Windows compile check must cover {krate}"
            );
        }
        assert!(lane.contains("--features provenance,client,hostd-transport"));

        // A lane outside the aggregate cannot fail the merge.
        assert!(job_block(&ci, "test").contains("lint-windows"));
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
    fn required_workflows_cancel_superseded_pull_requests_and_never_a_sibling_merge_group() {
        // Each merge group has its own ref and the queue builds several at
        // once, so a shared queue key would make one group cancel another.
        let expected_group = "group: ${{ github.workflow }}-${{ github.event_name }}-${{ github.event_name == 'workflow_dispatch' && github.run_id || github.ref }}";
        let expected_cancel = "cancel-in-progress: ${{ github.event_name == 'pull_request' || github.event_name == 'push' }}";

        let ci = ci_workflow();
        assert!(ci.contains(
            "merge_group:\n    types: [checks_requested]\n  push:\n    branches: [main]"
        ));
        assert!(ci.contains(expected_group));
        assert!(ci.contains(expected_cancel));
        assert!(ci.contains("permissions:\n  contents: read"));
        assert!(ci.contains("name: Test"), "required check name drifted");
        assert!(ci.contains("name: Invariant"));
        assert!(main_workflow().contains("name: Nix flake check (Linux eval)"));

        assert!(
            !Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../.github/workflows/architecture.yml")
                .exists(),
            "the duplicate architecture diagnostic workflow must stay retired"
        );
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
        assert!(
            watcher.contains("github.event.workflow_run.event == 'workflow_dispatch'")
                && watcher.contains(
                    r#"[ "$RUN_EVENT" = workflow_dispatch ] && [ "$HEAD_BRANCH" != "$DEFAULT_BRANCH" ]"#
                )
                && !watcher.contains(
                    "github.event.workflow_run.head_branch == github.event.repository.default_branch"
                ),
            "manual recovery must use a case-sensitive default-branch trust check in the shell"
        );
    }

    #[test]
    fn signing_smoke_keeps_pack_inputs_outside_output_directory() {
        let smoke = workflow("pack-signing-smoke.yml").replace("\\\n", " ");
        let mut producers = 0;
        for invocation in smoke.split("cargo run").skip(1) {
            let command = invocation.lines().next().unwrap();
            if !command.contains("mvm-builder-pack-tool") {
                continue;
            }
            producers += 1;
            let args: Vec<_> = command.split_whitespace().collect();
            let output = args.windows(2).find(|pair| pair[0] == "--out-dir").unwrap()[1];
            for flag in ["--vmlinux", "--rootfs", "--verity", "--roothash"] {
                if let Some(pair) = args.windows(2).find(|pair| pair[0] == flag) {
                    assert_ne!(
                        std::path::Path::new(pair[1]).parent(),
                        Some(std::path::Path::new(output)),
                        "{flag} must not copy a pack input onto itself"
                    );
                }
            }
        }
        assert_eq!(producers, 2, "both pack producers must be checked");
    }

    /// Claim 3's `ci:` witness and its no-SSH companion assert properties of
    /// the runtime overlay every microVM attaches. `mvmctl` assembles that
    /// overlay on the host from its guest runtime — a source build's from its
    /// tree, a release binary's from the signed archive its release ships, one
    /// assembler for both — and no launch reads the image set's copy. So each
    /// lane assembles the overlay from this tree, in a home of its own, and
    /// asserts on those bytes; fetching the set's member would witness bytes
    /// no launch attaches. The verity lane also has to check the seal, not
    /// only that three files exist. The merge queue's `boot-latency` lane
    /// boots the same assembled overlay over its published base image.
    #[test]
    fn overlay_witnesses_assert_on_the_cli_assembled_overlay() {
        let security = workflow("security.yml");
        for lane in ["verified-boot-artifacts", "sealed-prod-no-ssh"] {
            let body = job_body(&security, lane)
                .unwrap_or_else(|| panic!("{lane} must stay in security.yml under its name"));
            for assembled in [
                "MVM_RUNTIME_OVERLAY_ACQUIRE_MODE: build",
                "dev runtime-overlay build --source build --arch x86_64",
                "sha256sum -c checksums-sha256.txt",
            ] {
                assert!(
                    body.contains(assembled),
                    "{lane} must assert on the overlay mvmctl assembles: missing {assembled:?}"
                );
            }
            assert!(
                !body.contains("runtime-overlay-x86_64.tar.gz"),
                "{lane} must not assert on the image set's overlay member, which no launch attaches"
            );
            assert!(
                !body.contains("nix build"),
                "{lane} must not build an image through Nix"
            );
        }
        let verity = job_body(&security, "verified-boot-artifacts").expect("checked above");
        assert!(
            verity.contains("veritysetup verify"),
            "the verity witness must check the roothash against the hash tree"
        );
        let no_ssh = job_body(&security, "sealed-prod-no-ssh").expect("checked above");
        assert!(no_ssh.contains("mount -o ro,loop"));

        let ci = main_workflow();
        let latency = job_body(&ci, "boot-latency").expect("boot-latency must stay in ci-main.yml");
        assert!(
            latency.contains("dev runtime-overlay build --source build --arch x86_64")
                && !latency.contains("runtime-overlay-x86_64.tar.gz"),
            "boot-latency must boot the overlay mvmctl assembles, not the set's member"
        );
        assert!(
            latency.contains("./scripts/locked-image-tag.sh")
                && latency.contains("cosign verify-blob"),
            "boot-latency's base image stays the signed set images.lock pins"
        );
    }

    #[test]
    fn test_support_cache_warms_the_exact_primary_consumer_selection() {
        let selection = |job: &str, command: &str| {
            let joined = job.replace("\\\n", " ");
            joined
                .lines()
                .find_map(|line| line.trim().strip_prefix(command))
                .expect("test-support primary command must exist")
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        let warm = workflow("cache-warm.yml");
        let ci = main_workflow();
        assert_eq!(
            selection(
                job_block(&warm, "warm-test-support"),
                "cargo test --no-run ",
            ),
            selection(
                job_block(&ci, "lint-features-test-support"),
                "cargo nextest run ",
            ),
            "the trusted cache must compile the same packages, features and targets as its consumer"
        );
    }

    #[test]
    fn trusted_main_warms_workspace_and_nix_outputs_for_validation() {
        let cache_action = workflow("../actions/rust-cache/action.yml");
        assert!(cache_action.contains("prefix-key: v1-rust"));
        assert!(cache_action.contains("cache-workspace-crates: \"true\""));
        assert!(cache_action.contains("cache-bin: \"true\""));
        assert!(cache_action.contains("save-if: ${{ inputs.save }}"));

        let warm = workflow("cache-warm.yml");
        assert!(warm.contains(
            "uses: nix-community/cache-nix-action@7df957e333c1e5da7721f60227dbba6d06080569"
        ));
        assert!(warm.contains("primary-key: nix-${{ hashFiles("));
        assert!(warm.contains("'crates/**/*.rs'"));
        assert!(warm.contains("'third_party/**'"));
        assert!(warm.contains("--out-link \"$RUNNER_TEMP/nix-cache-warm\""));
        assert!(warm.contains("Build Nix outputs to populate the binary cache"));
        assert!(warm.contains("save: \"true\""));
        assert!(
            job_body(&warm, "warm-hetzner").is_none(),
            "the hosted-only PR shard path must not warm an unused runner pool"
        );
        assert!(warm.contains("key: test-support"));
        assert!(warm.contains("Warm test-support feature tests"));

        let ci = main_workflow();
        let support = job_block(&ci, "lint-features-test-support");
        assert!(support.contains("key: test-support"));
        let support_cache = support
            .find("uses: ./.github/actions/rust-cache")
            .expect("test-support must restore the trusted cache");
        let support_zig = support
            .find("uses: ./.github/actions/install-zigbuild")
            .expect("test-support must install the embedded-host toolchain");
        assert!(
            support_cache < support_zig,
            "test-support must restore cached cargo binaries before installing cargo-zigbuild"
        );
        let embed = job_block(&ci, "lint-features-embed");
        let embed_cache = embed
            .find("uses: ./.github/actions/rust-cache")
            .expect("embed-host-bins must restore the trusted cache");
        let embed_zig = embed
            .find("uses: ./.github/actions/install-zigbuild")
            .expect("embed-host-bins must install the embedded-host toolchain");
        assert!(
            embed_cache < embed_zig,
            "embed-host-bins must restore cached cargo binaries before installing cargo-zigbuild"
        );
        let nix = job_block(&ci, "nix-flake-check");
        assert!(nix.contains(
            "uses: nix-community/cache-nix-action/restore@7df957e333c1e5da7721f60227dbba6d06080569"
        ));
        assert!(
            !nix.contains("magic-nix-cache-action") && !nix.contains("gc-max-store-size"),
            "merge refs must restore the trusted Nix cache without a post-job save"
        );
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
                "crates/mvm-build/",
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
