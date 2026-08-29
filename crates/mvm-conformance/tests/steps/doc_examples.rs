//! Steps proving the documented `mvmctl` examples work.
//!
//! The README and the website docs print commands a reader will paste into a
//! shell. This suite treats each one as an assertion:
//!
//! * **Tier `parse`** — the invocation is parsed by the real clap tree, with
//!   full argument validation. A removed verb, a renamed flag, a value the
//!   parser rejects, or a wrong arity fails here, on every PR, with no VM.
//! * **Tier `exec`** — additionally executed against an isolated `MVM_HOME`.
//!   Only for commands with no side effects outside that home and no network.
//! * **Tier `live`** — additionally boots a real microVM; gated behind `@live`.
//!
//! Every command path the docs use must carry a tier. An unclassified path is
//! a documentation claim with no evidence, and fails the suite by name.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use clap::Command as ClapCommand;
use cucumber::then;
use mvm_conformance::doc_examples::{
    DocExample, ExampleSource, Tier, TierPolicy, doc_examples, documentation_files, is_elided,
    live_scenario_commands, mk_guest_call_attributes, mk_guest_parameters,
    mvmctl_lines_outside_fences,
};

use crate::world::CliWorld;
use mvm_conformance::IsolatedHome;

/// Repo root — two levels above this crate's manifest dir, resolved at compile
/// time so the run does not depend on the process working directory.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// Every documented example, with provenance, across the whole doc set.
fn corpus() -> Vec<DocExample> {
    let root = repo_root();
    let mut all = Vec::new();
    for path in documentation_files(&root) {
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        all.extend(doc_examples(&relative, &body));
    }
    assert!(
        all.len() > 200,
        "extracted only {} documented examples — the extractor has gone blind",
        all.len()
    );
    all
}

/// The tier manifest, which must cover every command path the docs reach.
#[derive(serde::Deserialize)]
struct Manifest {
    #[serde(default)]
    command: Vec<CommandEntry>,
    #[serde(default)]
    planned: Vec<AbsentEntry>,
    #[serde(default)]
    absent: Vec<AbsentEntry>,
    #[serde(default)]
    nix_attribute: Vec<NixAttributeEntry>,
    #[serde(default)]
    prose: Vec<ProseEntry>,
}

/// A `mvmctl …` phrase in a CLI string that is English, not an invocation:
/// "the mvmctl binary", "mvmctl cannot build a boot image locally".
///
/// Declared rather than pattern-matched. Every heuristic I tried for telling
/// prose from a command was wrong in one direction or the other — filtering on
/// "is the first word a real verb" is worst of all, because a string naming a
/// *removed* verb is exactly the defect, and that filter drops precisely those.
/// So the rule is totality: a phrase either resolves against the clap tree or
/// is written down here with a reason.
#[derive(serde::Deserialize)]
struct ProseEntry {
    text: String,
    #[allow(dead_code)]
    reason: String,
}

/// A `mkGuest` attribute the docs teach while its argument set does not accept
/// it. Same contract as [`AbsentEntry`]: declared, and required to stay absent.
#[derive(serde::Deserialize)]
struct NixAttributeEntry {
    name: String,
    #[allow(dead_code)]
    reason: String,
}

#[derive(serde::Deserialize)]
struct CommandEntry {
    path: String,
    tier: String,
    /// Set for a command whose exit status reports on the host rather than on
    /// itself — `doctor` exits nonzero precisely because it found something to
    /// report. Such a command is still executed, and still has to run to
    /// completion without being killed; only the "exited 0" assertion is
    /// dropped.
    #[serde(default)]
    exit_reports_host_state: bool,
    /// Why this path is proven only by parsing. Required for `tier = "parse"`,
    /// which is the weakest tier and the one a path lands in by neglect
    /// rather than by decision. Writing the obstruction down is what keeps
    /// "we could not run this" distinguishable from "nobody tried".
    #[serde(default)]
    reason: Option<String>,
    /// Environment the exec tier sets for this path alone.
    ///
    /// Some commands reach outside `MVM_HOME` by design and ship an explicit
    /// sandbox hook for exactly that reason — `env uninstall` rewrites its
    /// system paths under `MVM_UNINSTALL_PATH_PREFIX`. Without the hook such a
    /// command "passes" only by being cancelled at its confirmation prompt,
    /// which proves nothing and leaves the real path untested.
    #[serde(default)]
    env: BTreeMap<String, String>,
    /// A named fixture staged into the isolated home before this path runs.
    /// Several documented commands are runnable and fail only because the file
    /// they name is not there — a pubkey, a manifest, a bundle archive.
    #[serde(default)]
    fixture: Option<String>,
}

/// A command the docs name while it does not exist — either future syntax the
/// docs mark as planned, or a removed verb the docs correctly describe in the
/// past tense ("the former `mvmctl dev import-image`").
///
/// Declared, not skipped. The suite fails if one quietly becomes real, so a
/// doc that says a command is absent cannot outlive that being true.
#[derive(serde::Deserialize)]
struct AbsentEntry {
    path: String,
    #[allow(dead_code)]
    reason: String,
}

fn manifest() -> Manifest {
    let path = repo_root().join("features/suites/s29_doc_examples/tiers.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read tier manifest {}: {error}", path.display()));
    toml::from_str(&text)
        .unwrap_or_else(|error| panic!("parse tier manifest {}: {error}", path.display()))
}

fn tier_policy() -> TierPolicy {
    TierPolicy::from_entries(manifest().command.into_iter().map(|entry| {
        let tier = entry
            .tier
            .parse::<Tier>()
            .unwrap_or_else(|error| panic!("tier manifest entry {:?}: {error}", entry.path));
        let parts = entry
            .path
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>();
        (parts, tier)
    }))
}

/// Command paths whose exit status describes the host, not the command.
fn host_state_exit_paths() -> BTreeSet<Vec<String>> {
    manifest()
        .command
        .into_iter()
        .filter(|entry| entry.exit_reports_host_state)
        .map(|entry| {
            entry
                .path
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Per-path exec overrides: the environment to set, and the fixture to stage.
type ExecOverride = (BTreeMap<String, String>, Option<String>);

fn exec_overrides() -> BTreeMap<Vec<String>, ExecOverride> {
    manifest()
        .command
        .into_iter()
        .filter(|entry| !entry.env.is_empty() || entry.fixture.is_some())
        .map(|entry| {
            let path = entry
                .path
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>();
            (path, (entry.env, entry.fixture))
        })
        .collect()
}

/// Command paths the docs name as not existing — planned or removed.
fn planned_paths() -> BTreeSet<Vec<String>> {
    let m = manifest();
    m.planned
        .into_iter()
        .chain(m.absent)
        .map(|entry| {
            entry
                .path
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Parse one documented invocation with the real CLI definition.
///
/// Returns the resolved subcommand path on success. The path comes from clap's
/// own parse rather than a token heuristic, so a flag *value* that happens to
/// spell a subcommand (`--image run`) cannot be mistaken for one.
fn parse_example(command: &ClapCommand, example: &DocExample) -> Result<Vec<String>, String> {
    let mut argv = vec!["mvmctl".to_string()];
    argv.extend(example.argv.iter().cloned());

    let matches = command
        .clone()
        .try_get_matches_from(argv)
        .map_err(|error| error.to_string())?;

    let mut path = Vec::new();
    let mut cursor = &matches;
    while let Some((name, sub)) = cursor.subcommand() {
        path.push(name.to_string());
        cursor = sub;
    }
    Ok(path)
}

#[then(expr = "every documented mvmctl example parses against the real CLI")]
fn every_documented_example_parses(_world: &mut CliWorld) {
    let command = mvm_cli::commands::cli_command();
    let mut failures = Vec::new();
    let mut parsed = 0usize;

    for example in corpus() {
        if example.is_template() || example.source != ExampleSource::Fenced {
            continue;
        }
        match parse_example(&command, &example) {
            Ok(_) => parsed += 1,
            Err(error) => {
                let first = error.lines().next().unwrap_or("").trim().to_string();
                failures.push(format!(
                    "  {}\n     $ mvmctl {}\n     {first}",
                    example.location(),
                    example.argv.join(" ")
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} documented example(s) do not parse against the real CLI \
         (parsed {parsed} successfully):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[then(expr = "every documented command path carries a verification tier")]
fn every_documented_path_has_a_tier(_world: &mut CliWorld) {
    let command = mvm_cli::commands::cli_command();
    let policy = tier_policy();
    let mut unclassified: BTreeMap<String, String> = BTreeMap::new();

    for example in corpus() {
        if example.is_template() {
            continue;
        }
        let Ok(path) = parse_example(&command, &example) else {
            // Parse failures are reported by their own scenario; a command that
            // does not parse has no path to classify.
            continue;
        };
        if path.is_empty() {
            continue;
        }
        if policy.tier_for(&path).is_none() {
            unclassified
                .entry(path.join(" "))
                .or_insert_with(|| example.location());
        }
    }

    assert!(
        unclassified.is_empty(),
        "{} documented command path(s) have no tier in \
         features/suites/s29_doc_examples/tiers.toml — decide how each is proven:\n{}",
        unclassified.len(),
        unclassified
            .iter()
            .map(|(path, location)| format!("  mvmctl {path}   (first used at {location})"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[then(expr = "the tier manifest names only real CLI commands")]
fn tier_manifest_names_only_real_commands(_world: &mut CliWorld) {
    let command = mvm_cli::commands::cli_command();
    let mut real = BTreeSet::new();
    collect_paths(&command, &[], &mut real);

    let policy = tier_policy();
    let stale: Vec<String> = policy
        .paths()
        .filter(|path| !real.contains(*path))
        .map(|path| path.join(" "))
        .collect();

    assert!(
        stale.is_empty(),
        "the tier manifest classifies command(s) the CLI no longer has — \
         remove them so the manifest cannot drift into fiction:\n{}",
        stale
            .iter()
            .map(|path| format!("  mvmctl {path}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[then(expr = "no documented command is stranded outside a code fence")]
fn no_command_stranded_outside_a_fence(_world: &mut CliWorld) {
    let command = mvm_cli::commands::cli_command();
    let verbs: Vec<String> = command
        .get_subcommands()
        .map(|sub| sub.get_name().to_string())
        .collect();

    let root = repo_root();
    let mut stranded = Vec::new();
    for path in documentation_files(&root) {
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        for (line, text) in mvmctl_lines_outside_fences(&body, &verbs) {
            stranded.push(format!("  {relative}:{line}\n     {text}"));
        }
    }

    assert!(
        stranded.is_empty(),
        "{} documented command(s) sit outside any code fence — they render as \
         broken prose and are invisible to this harness:\n{}",
        stranded.len(),
        stranded.join("\n")
    );
}

/// Every subcommand path the CLI actually exposes, hidden ones included.
fn collect_paths(command: &ClapCommand, prefix: &[String], out: &mut BTreeSet<Vec<String>>) {
    for sub in command.get_subcommands() {
        let mut path = prefix.to_vec();
        path.push(sub.get_name().to_string());
        out.insert(path.clone());
        collect_paths(sub, &path, out);
    }
}

/// Run one documented example for real against a private `MVM_HOME`.
/// Run a documented example against an isolated home, optionally from a
/// staged working directory and with per-entry environment.
fn execute_in(
    example: &DocExample,
    home: &Path,
    cwd: Option<&Path>,
    env: &BTreeMap<String, String>,
) -> std::process::Output {
    let mut command = crate::steps::cli::mvmctl_command();
    command
        .isolated_home(home)
        // Reconcile-on-entry converges live VM state; a doc example must not
        // reach for the host's real machines just to print its help.
        .env("MVM_SKIP_RECONCILE", "1")
        .args(&example.argv);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    for (key, value) in env {
        // A manifest env value naming a path in this repo is written
        // repo-relative, because that is how a reader would write it. The
        // command runs from a staged fixture directory, so resolve it here
        // rather than leaving a relative path to miss silently.
        let candidate = repo_root().join(value);
        if candidate.exists() {
            command.env(key, candidate);
        } else {
            command.env(key, value);
        }
    }
    command
        .output()
        .unwrap_or_else(|error| panic!("spawn mvmctl for {}: {error}", example.location()))
}

/// Stage the files a documented example names, in a directory of its own.
///
/// A command that fails only because `./publisher.pub` is not there is not
/// un-runnable; it is unstaged. Distinguishing the two is the difference
/// between a tier that reflects the CLI and one that reflects the fixture set.
fn stage_fixture(name: &str, dir: &Path, home: &Path) {
    match name {
        // `manifest info|rm|verify` all resolve a manifest from the working
        // directory, which is what `init` writes.
        "manifest" => {
            let output = crate::steps::cli::mvmctl_command()
                .isolated_home(home)
                .env("MVM_SKIP_RECONCILE", "1")
                .current_dir(dir)
                .args(["init", "."])
                .output()
                .expect("spawn mvmctl init to stage the manifest fixture");
            assert!(
                output.status.success(),
                "staging the manifest fixture failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        // The decorator examples compile a Python source file by path.
        //
        // Deliberately without the README's `source=mvm.local_path(".")`:
        // `local_path` is defined by the Python SDK but absent from the
        // decorator compiler's HELPER_ALLOWLIST, so the README form does not
        // compile. Tracked separately — this fixture proves the command, not
        // that particular kwarg.
        "decorator-script" => {
            let script = "import mvm\n\n\n@mvm.app(\n    name=\"greeter\",\n                    image=mvm.python_image(python=\"3.12\"),\n                    resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),\n)\n                def greet(name: str) -> str:\n    return f\"hello {name}\"\n";
            for file in ["app.py", "script.py"] {
                std::fs::write(dir.join(file), script).expect("write decorator fixture");
            }
        }
        other => panic!("unknown fixture {other:?} in the tier manifest"),
    }
}

#[then(expr = "every side-effect-free documented example executes successfully")]
fn every_exec_tier_example_runs(_world: &mut CliWorld) {
    let command = mvm_cli::commands::cli_command();
    let policy = tier_policy();
    let host_state_exit = host_state_exit_paths();
    let overrides = exec_overrides();
    let home = std::env::temp_dir().join(format!("mvm-doc-exec-{}", std::process::id()));
    std::fs::create_dir_all(&home).expect("create isolated MVM_HOME");

    let mut failures = Vec::new();
    let mut ran = 0usize;
    // One example per command path is enough to prove the path executes; the
    // rest of that path's examples differ only in arguments, which tier
    // `parse` already validates. Running all 600+ would trade a large amount
    // of wall clock for no additional signal.
    let mut seen: BTreeSet<Vec<String>> = BTreeSet::new();

    for example in corpus() {
        if example.is_template() {
            continue;
        }
        let Ok(path) = parse_example(&command, &example) else {
            continue;
        };
        if policy.tier_for(&path) != Some(Tier::Exec) || !seen.insert(path.clone()) {
            continue;
        }

        // Per-entry environment and fixtures, for paths that are runnable
        // but reach outside the home or name a file that has to exist.
        let (env, fixture) = overrides.get(&path).cloned().unwrap_or_default();
        // Always run from a scratch directory, never the repo root. Several
        // documented examples scaffold into a relative path — `mvmctl init
        // ./agent-tool`, `generate template python ./my-python-app` — and at
        // the repo root that drops generated trees into the working copy.
        let dir = home.join("scratch").join(path.join("-"));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        if let Some(name) = fixture.as_deref() {
            stage_fixture(name, &dir, &home);
        }
        let output = execute_in(&example, &home, Some(&dir), &env);
        ran += 1;

        // A command killed by a signal never ran to completion, whatever its
        // tier says about exit codes.
        if output.status.code().is_none() {
            failures.push(format!(
                "  {}\n     $ mvmctl {}\n     terminated by signal",
                example.location(),
                example.argv.join(" ")
            ));
            continue;
        }
        if host_state_exit.contains(&path) {
            continue;
        }
        if !output.status.success() {
            failures.push(format!(
                "  {}\n     $ mvmctl {}\n     exit {:?}\n     {}",
                example.location(),
                example.argv.join(" "),
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
                    .lines()
                    .next()
                    .unwrap_or_default()
            ));
        }
    }

    assert!(ran > 0, "no exec-tier examples were found to run");
    assert!(
        failures.is_empty(),
        "{} exec-tier documented example(s) failed to run (ran {ran}):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[then(expr = "every documented placeholder template names a real or declared command")]
fn every_template_names_a_real_command(_world: &mut CliWorld) {
    let command = mvm_cli::commands::cli_command();
    let planned = planned_paths();

    let mut unknown = Vec::new();
    for example in corpus() {
        if !example.is_template() {
            continue;
        }
        if let Some(bogus) = unknown_subcommand(&command, &example.concrete_prefix()) {
            if planned.contains(&bogus) {
                continue;
            }
            unknown.push(format!(
                "  {}\n     $ mvmctl {}\n     `mvmctl {}` is not a command",
                example.location(),
                example.argv.join(" "),
                bogus.join(" ")
            ));
        }
    }

    assert!(
        unknown.is_empty(),
        "{} placeholder template(s) name a command that does not exist — a \
         template is exempt from parsing, so its verb prefix is what keeps it \
         honest. Fix the docs, or declare it under [[planned]] in \
         features/suites/s29_doc_examples/tiers.toml:\n{}",
        unknown.len(),
        unknown.join("\n")
    );
}

/// Walk `prefix` down the command tree and return the first path that claims to
/// be a subcommand but is not.
///
/// Descent stops harmlessly at a token the current command would read as a
/// positional argument — `machine checkpoint restore agent-sandbox` names a
/// checkpoint id, not a subcommand. A token is only reported when the command
/// it sits under takes no positionals at all, which makes a subcommand the
/// only thing it could have been.
fn unknown_subcommand(root: &ClapCommand, prefix: &[String]) -> Option<Vec<String>> {
    let mut node = root;
    let mut walked: Vec<String> = Vec::new();

    for token in prefix {
        match node.find_subcommand(token.as_str()) {
            Some(child) => {
                walked.push(token.clone());
                node = child;
            }
            None => {
                let takes_positionals = node.get_positionals().next().is_some();
                if takes_positionals {
                    return None;
                }
                walked.push(token.clone());
                return Some(walked);
            }
        }
    }
    None
}

#[then(expr = "no command declared planned has quietly shipped")]
fn no_planned_command_has_shipped(_world: &mut CliWorld) {
    let command = mvm_cli::commands::cli_command();
    let mut real = BTreeSet::new();
    collect_paths(&command, &[], &mut real);

    let shipped: Vec<String> = planned_paths()
        .into_iter()
        .filter(|path| real.contains(path))
        .map(|path| path.join(" "))
        .collect();

    assert!(
        shipped.is_empty(),
        "command(s) declared absent now exist — the docs should present them as \
         available, and the [[planned]]/[[absent]] entry should go:\n{}",
        shipped
            .iter()
            .map(|path| format!("  mvmctl {path}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Command paths carrying a given tier in the manifest.
fn paths_at_tier(wanted: Tier) -> BTreeSet<Vec<String>> {
    manifest()
        .command
        .into_iter()
        .filter(|entry| entry.tier.parse::<Tier>() == Ok(wanted))
        .map(|entry| {
            entry
                .path
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[then(expr = "every live-tier command is exercised by a live scenario")]
fn every_live_tier_command_has_a_live_scenario(_world: &mut CliWorld) {
    let command = mvm_cli::commands::cli_command();
    let suites = repo_root().join("features/suites");

    // The command paths any @live scenario actually drives.
    let mut exercised: BTreeSet<Vec<String>> = BTreeSet::new();
    let mut features = Vec::new();
    collect_features(&suites, &mut features);
    for feature in features {
        let body = std::fs::read_to_string(&feature)
            .unwrap_or_else(|error| panic!("read {}: {error}", feature.display()));
        for argv in live_scenario_commands(&body) {
            let example = DocExample {
                source: ExampleSource::Fenced,
                file: feature.display().to_string(),
                line: 0,
                command: argv.join(" "),
                argv,
            };
            if let Ok(path) = parse_example(&command, &example) {
                // Record the path and every prefix, so a manifest entry for a
                // group is satisfied by a scenario driving one of its leaves.
                for length in 1..=path.len() {
                    exercised.insert(path[..length].to_vec());
                }
            }
        }
    }

    let unbacked: Vec<String> = paths_at_tier(Tier::Live)
        .into_iter()
        .filter(|path| !exercised.contains(path))
        .map(|path| path.join(" "))
        .collect();

    assert!(
        unbacked.is_empty(),
        "{} command(s) are marked tier \"live\" but no @live scenario runs them — \
         a live tier with no live witness is a claim, not evidence. Add a \
         scenario or lower the tier:\n{}",
        unbacked.len(),
        unbacked
            .iter()
            .map(|path| format!("  mvmctl {path}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

fn collect_features(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            collect_features(&path, out);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "feature")
        {
            out.push(path);
        }
    }
}

#[then(expr = "every command named in the docs prose exists")]
fn every_inline_named_command_exists(_world: &mut CliWorld) {
    let command = mvm_cli::commands::cli_command();
    let planned = planned_paths();

    let mut unknown = Vec::new();
    for example in corpus() {
        if example.source != ExampleSource::Inline {
            continue;
        }
        if let Some(bogus) = unknown_subcommand(&command, &example.concrete_prefix()) {
            if planned.contains(&bogus) {
                continue;
            }
            unknown.push(format!(
                "  {}\n     `mvmctl {}`\n     `mvmctl {}` is not a command",
                example.location(),
                example.argv.join(" "),
                bogus.join(" ")
            ));
        }
    }

    assert!(
        unknown.is_empty(),
        "{} command(s) named in tables or prose do not exist. The CLI reference \
         documents most of its surface this way, so a stale spelling here reaches \
         readers exactly like a stale one in a code block:\n{}",
        unknown.len(),
        unknown.join("\n")
    );
}

/// Every fenced block in the documentation set, with provenance.
fn all_code_blocks() -> Vec<mvm_conformance::doc_examples::CodeBlock> {
    let root = repo_root();
    let mut blocks = Vec::new();
    for path in documentation_files(&root) {
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        blocks.extend(mvm_conformance::doc_examples::code_blocks(&relative, &body));
    }
    blocks
}

#[then(expr = "every Rust example that opts out of compiling says why")]
fn every_ignored_rust_block_states_a_reason(_world: &mut CliWorld) {
    let mut unexplained = Vec::new();
    let mut explained = 0usize;

    for block in all_code_blocks() {
        if block.language != "rust" || !block.is_ignored() {
            continue;
        }
        match block.ignore_reason() {
            Some(reason) if !reason.is_empty() => explained += 1,
            _ => unexplained.push(format!(
                "  {}\n     add a first line: // illustrative: <why this cannot compile>",
                block.location()
            )),
        }
    }

    assert!(
        unexplained.is_empty(),
        "{} Rust example(s) opt out of compiling with no stated reason ({explained} \
         do state one). An unexplained opt-out is how a wrong example survives — \
         the marker looks deliberate and nobody can tell whether it still is:\n{}",
        unexplained.len(),
        unexplained.join("\n")
    );
}

#[then(expr = "every documented TOML and JSON block parses")]
fn every_toml_and_json_block_parses(_world: &mut CliWorld) {
    let mut failures = Vec::new();
    let mut checked = 0usize;

    for block in all_code_blocks() {
        // A block carrying placeholder syntax is a shape, not a document.
        let illustrative = block.is_ignored() || is_elided(&block.body);
        if illustrative {
            continue;
        }
        match block.language.as_str() {
            "toml" => {
                checked += 1;
                if let Err(error) = block.body.parse::<toml::Table>() {
                    failures.push(format!("  {}  (toml)\n     {error}", block.location()));
                }
            }
            "json" => {
                checked += 1;
                if let Err(error) = serde_json::from_str::<serde_json::Value>(&block.body) {
                    failures.push(format!("  {}  (json)\n     {error}", block.location()));
                }
            }
            _ => {}
        }
    }

    assert!(checked > 0, "no TOML or JSON blocks were found to check");
    assert!(
        failures.is_empty(),
        "{} documented TOML/JSON block(s) do not parse (checked {checked}). A \
         config a reader pastes has to be syntactically valid:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// A documented code block, in the shape the language checkers read on stdin.
#[derive(serde::Serialize)]
struct BlockPayload {
    file: String,
    line: usize,
    body: String,
}

/// A finding one of the language checkers reported.
#[derive(serde::Deserialize)]
struct Finding {
    file: String,
    line: usize,
    kind: String,
    detail: String,
}

/// Blocks in `language`, skipping the ones that opt out or carry elisions.
fn blocks_in(language: &[&str]) -> Vec<BlockPayload> {
    all_code_blocks()
        .into_iter()
        .filter(|block| language.contains(&block.language.as_str()))
        .filter(|block| !block.is_ignored() && !is_elided(&block.body))
        .map(|block| BlockPayload {
            file: block.file.clone(),
            line: block.line,
            body: block.body.clone(),
        })
        .collect()
}

/// Run a checker fixture over `blocks`, returning what it found.
///
/// The checker resolves names against the real installed SDK, so this is the
/// nearest thing these languages have to the compile step the Rust examples
/// now get.
fn run_checker(program: &str, script: &str, blocks: &[BlockPayload]) -> Vec<Finding> {
    run_checker_with(program, script, blocks, &[])
}

/// As [`run_checker`], with extra environment for the checker process.
fn run_checker_with(
    program: &str,
    script: &str,
    blocks: &[BlockPayload],
    env: &[(&str, std::path::PathBuf)],
) -> Vec<Finding> {
    use std::io::Write as _;
    use std::process::Stdio;

    let root = repo_root();
    let script = root
        .join("features/suites/s29_doc_examples/fixtures")
        .join(script);
    let payload = serde_json::to_vec(blocks).expect("serialize blocks");

    let spawned = std::process::Command::new(program)
        .arg(&script)
        .env("PYTHONPATH", root.join("crates/mvm-sdk/sdks/python"))
        .envs(env.iter().map(|(k, v)| (*k, v.clone())))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // No interpreter here. A host without Node is a real configuration
            // (the KVM witness box is one); failing the suite for it would
            // report a missing toolchain as a documentation defect.
            eprintln!(
                "[bdd] SKIPPED: {program} is not installed — {} did not run",
                script.display()
            );
            return Vec::new();
        }
        Err(error) => panic!("spawn {program} {}: {error}", script.display()),
    };
    child
        .stdin
        .as_mut()
        .expect("checker stdin")
        .write_all(&payload)
        .expect("write blocks to checker");
    let output = child.wait_with_output().expect("checker output");
    assert!(
        output.status.success(),
        "{program} {} failed:\n{}",
        script.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "parse checker findings: {error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn report(findings: &[Finding], language: &str, checked: usize) {
    assert!(
        findings.is_empty(),
        "{} {language} example finding(s) across {checked} block(s). A snippet \
         naming an SDK symbol that does not exist misleads a reader exactly like \
         a stale CLI flag:\n{}",
        findings.len(),
        findings
            .iter()
            .map(|f| format!("  {}:{}  [{}]\n     {}", f.file, f.line, f.kind, f.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[then(expr = "every documented Python example parses and names real SDK symbols")]
fn documented_python_examples_are_valid(_world: &mut CliWorld) {
    let blocks = blocks_in(&["python", "py"]);
    assert!(!blocks.is_empty(), "no Python examples were found to check");
    let findings = run_checker("python3", "check_python_examples.py", &blocks);
    report(&findings, "Python", blocks.len());
}

#[then(expr = "every documented TypeScript example names real SDK exports")]
fn documented_typescript_examples_are_valid(_world: &mut CliWorld) {
    let blocks = blocks_in(&["ts", "typescript"]);
    assert!(
        !blocks.is_empty(),
        "no TypeScript examples were found to check"
    );
    let sdk = repo_root().join("crates/mvm-sdk/sdks/typescript/src");
    let findings = run_checker_with(
        "node",
        "check_typescript_examples.mjs",
        &blocks,
        &[("MVM_TS_SDK_SRC", sdk)],
    );
    report(&findings, "TypeScript", blocks.len());
}

#[then(expr = "every documented mkGuest call names real attributes")]
fn documented_mkguest_calls_are_valid(_world: &mut CliWorld) {
    let root = repo_root();
    let source = std::fs::read_to_string(root.join("nix/lib/mk-guest.nix"))
        .expect("read nix/lib/mk-guest.nix");
    let mut accepted = mk_guest_parameters(&source);
    assert!(
        accepted.len() > 5,
        "read only {} mkGuest parameter(s) — the argument-set walk has gone blind",
        accepted.len()
    );
    // `pkgs` is threaded in by every caller and consumed by the composition
    // layer rather than declared in the inner argument set.
    accepted.insert("pkgs".to_string());

    let declared: BTreeSet<String> = manifest()
        .nix_attribute
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    for name in &declared {
        assert!(
            !accepted.contains(name),
            "`{name}` is declared as an unimplemented mkGuest attribute but the \
             argument set now accepts it — drop the [[nix_attribute]] entry and \
             the docs' not-implemented note"
        );
    }

    let mut failures = Vec::new();
    let mut checked = 0usize;

    for block in all_code_blocks() {
        if block.language != "nix" || block.is_ignored() || is_elided(&block.body) {
            continue;
        }
        let attributes = mk_guest_call_attributes(&block.body);
        if attributes.is_empty() {
            continue;
        }
        checked += 1;
        for (name, offset) in attributes {
            if !accepted.contains(&name) && !declared.contains(&name) {
                failures.push(format!(
                    "  {}:{}\n     `mkGuest` takes no `{name}` attribute",
                    block.file,
                    block.line + offset
                ));
            }
        }
    }

    assert!(
        checked > 0,
        "no documented mkGuest calls were found to check"
    );
    assert!(
        failures.is_empty(),
        "{} documented mkGuest attribute(s) do not exist (checked {checked} call \
         site(s)). The guide teaches mkGuest as the Nix authoring surface, so a \
         renamed attribute silently produces a guest nobody asked for:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Exit status the TypeScript typechecker uses to say its toolchain is absent.
const TOOLCHAIN_ABSENT: i32 = 3;

#[then(expr = "every documented TypeScript example typechecks against the local SDK")]
fn documented_typescript_examples_typecheck(_world: &mut CliWorld) {
    use std::io::Write as _;
    use std::process::Stdio;

    // Typecheck only blocks that import the SDK. A block that does not is an
    // excerpt — a few lines lifted out of a program, using names defined in
    // prose around it — and demanding it compile standalone reports the missing
    // context as 77 findings that are all the same non-problem. Those blocks
    // are still covered by the name-resolution scenario.
    let blocks: Vec<BlockPayload> = blocks_in(&["ts", "typescript"])
        .into_iter()
        .filter(|block| block.body.contains("from \"@runmvm/mvm\""))
        .collect();
    assert!(
        !blocks.is_empty(),
        "no self-contained TypeScript examples were found to typecheck"
    );

    let root = repo_root();
    let sdk = root.join("crates/mvm-sdk/sdks/typescript");
    let script = root
        .join("features/suites/s29_doc_examples/fixtures")
        .join("typecheck_typescript_examples.mjs");

    let child = std::process::Command::new("node")
        .arg(&script)
        .env("MVM_TS_SDK_ROOT", &sdk)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "[bdd] SKIPPED: node is not installed — the TypeScript typecheck did not run"
            );
            return;
        }
        Err(error) => panic!("spawn node {}: {error}", script.display()),
    };
    child
        .stdin
        .as_mut()
        .expect("typechecker stdin")
        .write_all(&serde_json::to_vec(&blocks).expect("serialize blocks"))
        .expect("write blocks");
    let output = child.wait_with_output().expect("typechecker output");

    if output.status.code() == Some(TOOLCHAIN_ABSENT) {
        // The SDK dev toolchain is not installed. Say so loudly rather than
        // passing quietly: the sibling name-resolution scenario still ran, so
        // coverage is reduced here, not absent.
        eprintln!(
            "[bdd] SKIPPED: TypeScript typecheck — no SDK toolchain at {}.\n\
             [bdd]   Run `just sdk-ts-install` to enable it. Name resolution \
             still ran; argument shapes did not.",
            sdk.display()
        );
        return;
    }

    assert!(
        output.status.success(),
        "typechecker failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<Finding> =
        serde_json::from_slice(&output.stdout).expect("parse typecheck findings");
    report(&findings, "TypeScript typecheck", blocks.len());
}

/// Every `*.rs` file under a crate's `src/`.
fn rust_sources(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Resolve a command path against the clap tree, returning the depth matched.
///
/// Only the leading verb chain is judged. Trailing words are arguments, and
/// demanding they parse would let prose through: `machine cp` takes positionals,
/// so "mvmctl cp supports exactly one" *parses* with "supports exactly one"
/// absorbed as arguments — a check built on "does it parse" calls that healthy.
fn resolved_depth(root: &ClapCommand, words: &[String]) -> usize {
    let mut cursor = root;
    let mut depth = 0;
    for word in words {
        let Some(next) = cursor
            .get_subcommands()
            .find(|sub| sub.get_name() == word || sub.get_all_aliases().any(|alias| alias == word))
        else {
            break;
        };
        cursor = next;
        depth += 1;
    }
    depth
}

#[then(expr = "every command named in mvmctl's own output is a real command")]
fn cli_output_names_real_commands(_world: &mut CliWorld) {
    let command = mvm_cli::commands::cli_command();
    let prose: BTreeSet<String> = manifest()
        .prose
        .into_iter()
        .map(|entry| entry.text)
        .collect();

    let mut sources = Vec::new();
    rust_sources(&repo_root().join("crates/mvm-cli/src"), &mut sources);
    assert!(
        sources.len() > 100,
        "found only {} Rust source(s) under crates/mvm-cli/src — the walk went blind",
        sources.len()
    );

    let mut checked = 0usize;
    let mut failures = Vec::new();
    for path in sources {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let relative = path
            .strip_prefix(repo_root())
            .unwrap_or(&path)
            .display()
            .to_string();
        for found in mvm_conformance::source_commands::source_commands(&relative, &text) {
            let rendered = found.rendered();
            if prose.contains(&rendered) {
                continue;
            }
            checked += 1;
            let depth = resolved_depth(&command, &found.words);
            if depth == 0 {
                failures.push(format!(
                    "  {}:{}\n     {rendered}\n     `{}` is not a command",
                    found.file, found.line, found.words[0]
                ));
            } else if depth == 1 && found.words.len() > 1 {
                // The verb resolved but its subcommand did not. Only a failure
                // when the verb actually has subcommands — otherwise the second
                // word is an argument (`mvmctl doctor json`).
                let verb = command
                    .get_subcommands()
                    .find(|sub| {
                        sub.get_name() == found.words[0]
                            || sub.get_all_aliases().any(|a| a == found.words[0])
                    })
                    .expect("depth 1 means the verb resolved");
                if verb.has_subcommands() {
                    failures.push(format!(
                        "  {}:{}\n     {rendered}\n     `{}` has no `{}` subcommand",
                        found.file, found.line, found.words[0], found.words[1]
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} command(s) named in mvmctl's own output do not exist \
         (checked {checked}). Fix the string, or if it is English rather than an \
         invocation add a [[prose]] entry with a reason to \
         features/suites/s29_doc_examples/tiers.toml:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[then(expr = "every parse-tier command path explains why it is only parsed")]
fn every_parse_tier_path_explains_itself(_world: &mut CliWorld) {
    // `parse` is the tier a path reaches by nobody deciding anything: it is
    // the weakest rung and the default landing spot for a newly documented
    // verb. Requiring a written obstruction is what stops the ladder decaying
    // back into "everything parses" — the state this suite exists to leave.
    let unexplained: Vec<String> = manifest()
        .command
        .into_iter()
        .filter(|entry| entry.tier == "parse")
        .filter(|entry| {
            entry
                .reason
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
        })
        .map(|entry| format!("  {}", entry.path))
        .collect();

    assert!(
        unexplained.is_empty(),
        "{} command path(s) sit at tier `parse` with no reason. Either promote \
         them to `exec`/`live`, or record what blocks that:\n{}",
        unexplained.len(),
        unexplained.join("\n")
    );
}

// ── Website-docs coverage ratchet ────────────────────────────────────────────
//
// The README's 38 examples each carry a hand-written witness or exemption
// (`s8_readme_contract/readme_examples.toml`). The website is 461 distinct
// commands across 86 files, and hand-writing 400-odd justifications would
// manufacture the appearance of review rather than perform it — an exemption is
// a claim someone has to be able to disagree with, and nobody can disagree with
// four hundred of them written in an afternoon.
//
// So the website is ratcheted rather than adjudicated. Coverage is computed
// mechanically by the same rule the README gate uses — a scenario driving the
// same verb with at least the same flags — and the partition is checked in.
// From there:
//
//   * a command that is covered today may not become uncovered
//   * a newly documented command must be classified before it merges
//   * the uncovered list is visible debt, and it may only shrink
//
// That gives the website the property the README has (nothing is documented
// without someone deciding how it is proven) without inventing the reasoning.

/// The checked-in partition of documented commands into covered and not.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct DocsCoverage {
    /// Commands a scenario currently exercises. Losing one is a regression.
    covered: Vec<String>,
    /// Commands nothing exercises yet. Visible debt; may only shrink.
    uncovered: Vec<String>,
}

fn docs_coverage_path() -> PathBuf {
    repo_root()
        .join("features")
        .join("suites")
        .join("s29_doc_examples")
        .join("docs_coverage.toml")
}

/// Recompute which documented commands a scenario exercises today.
fn compute_docs_coverage() -> (BTreeSet<String>, BTreeSet<String>) {
    let root = repo_root();
    let command_tree = mvm_cli::commands::cli_command();
    let mut known_paths = Vec::new();
    crate::steps::cli::collect_command_paths(&command_tree, &[], &mut known_paths);

    let scenarios = crate::steps::readme_contract::all_scenario_commands();

    let mut covered = BTreeSet::new();
    let mut uncovered = BTreeSet::new();
    for file in mvm_conformance::doc_examples::documentation_files(&root) {
        let relative = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        // The README has its own per-example ledger; do not double-govern it.
        if relative == "README.md" {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(&file) else {
            continue;
        };
        for example in mvm_conformance::doc_examples::doc_examples(&relative, &contents) {
            if example.is_template()
                || !matches!(
                    example.source,
                    mvm_conformance::doc_examples::ExampleSource::Fenced
                )
            {
                continue;
            }
            let hit = scenarios.values().any(|scenario| {
                scenario.commands.iter().any(|command| {
                    crate::steps::readme_contract::witness_covers_example(
                        &example.argv,
                        command,
                        &known_paths,
                        &command_tree,
                    )
                })
            });
            if hit {
                covered.insert(example.command.clone());
            } else {
                uncovered.insert(example.command.clone());
            }
        }
    }
    // A command printed in two files can be covered via one occurrence.
    for command in &covered {
        uncovered.remove(command);
    }
    (covered, uncovered)
}

#[then(expr = "documented website commands do not lose their coverage")]
fn docs_coverage_ratchet(_world: &mut CliWorld) {
    let (covered, uncovered) = compute_docs_coverage();
    let path = docs_coverage_path();

    if std::env::var_os("MVM_UPDATE_DOCS_COVERAGE").is_some() {
        let ledger = DocsCoverage {
            covered: covered.iter().cloned().collect(),
            uncovered: uncovered.iter().cloned().collect(),
        };
        let header = "# Which documented website commands a scenario exercises.\n\
                      #\n\
                      # Generated, then reviewed. Regenerate with:\n\
                      #   MVM_UPDATE_DOCS_COVERAGE=1 cargo test -p mvm-conformance \\\n\
                      #     --test conformance --features bdd -- -i '<repo>/features/suites/s29_doc_examples/*.feature'\n\
                      #\n\
                      # `covered` may not shrink and `uncovered` may not grow: a documented\n\
                      # command that loses its only scenario is a regression, and a newly\n\
                      # documented one has to be classified before it merges. Moving a line from\n\
                      # `uncovered` to `covered` is the point of the file.\n\n";
        std::fs::write(
            &path,
            format!(
                "{header}{}",
                toml::to_string_pretty(&ledger).expect("serialize docs coverage")
            ),
        )
        .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        return;
    }

    let recorded: DocsCoverage = toml::from_str(
        &std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display())),
    )
    .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));

    let recorded_covered: BTreeSet<String> = recorded.covered.into_iter().collect();
    let recorded_uncovered: BTreeSet<String> = recorded.uncovered.into_iter().collect();

    let regressed: Vec<&String> = recorded_covered.difference(&covered).collect();
    assert!(
        regressed.is_empty(),
        "these documented commands were exercised by a scenario and no longer \
         are. A documented command losing its only witness is how a broken one \
         reaches a release:\n{}",
        regressed
            .iter()
            .map(|c| format!("  {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    let known: BTreeSet<&String> = recorded_covered.union(&recorded_uncovered).collect();
    let unclassified: Vec<&String> = covered
        .union(&uncovered)
        .filter(|command| !known.contains(*command))
        .collect();
    assert!(
        unclassified.is_empty(),
        "these commands are newly documented and are not in the coverage \
         ledger. Regenerate it so the decision about how they are proven is \
         recorded rather than skipped:\n  MVM_UPDATE_DOCS_COVERAGE=1 <this suite>\n{}",
        unclassified
            .iter()
            .map(|c| format!("  {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    let improved: Vec<&String> = recorded_uncovered.intersection(&covered).collect();
    assert!(
        improved.is_empty(),
        "these commands are now exercised and the ledger still lists them as \
         debt. Regenerate it — moving a line out of `uncovered` is the point of \
         the file, and leaving it stale is how the number stops meaning \
         anything:\n  MVM_UPDATE_DOCS_COVERAGE=1 <this suite>\n{}",
        improved
            .iter()
            .map(|c| format!("  {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
