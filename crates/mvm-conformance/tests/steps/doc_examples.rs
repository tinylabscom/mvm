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
    DocExample, ExampleSource, Tier, TierPolicy, doc_examples, documentation_files,
    live_scenario_commands, mk_guest_call_attributes, mk_guest_parameters,
    mvmctl_lines_outside_fences,
};

use crate::world::CliWorld;

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
fn execute(example: &DocExample, home: &Path) -> std::process::Output {
    crate::steps::cli::mvmctl_command()
        .env("HOME", home)
        .env("MVM_HOME", home)
        // Reconcile-on-entry converges live VM state; a doc example must not
        // reach for the host's real machines just to print its help.
        .env("MVM_SKIP_RECONCILE", "1")
        .args(&example.argv)
        .output()
        .unwrap_or_else(|error| panic!("spawn mvmctl for {}: {error}", example.location()))
}

#[then(expr = "every side-effect-free documented example executes successfully")]
fn every_exec_tier_example_runs(_world: &mut CliWorld) {
    let command = mvm_cli::commands::cli_command();
    let policy = tier_policy();
    let host_state_exit = host_state_exit_paths();
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

        let output = execute(&example, &home);
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
        let illustrative = block.is_ignored() || block.body.contains('…');
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
        .filter(|block| !block.is_ignored() && !block.body.contains('…'))
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

    let mut child = std::process::Command::new(program)
        .arg(&script)
        .env("PYTHONPATH", root.join("crates/mvm-sdk/sdks/python"))
        .envs(env.iter().map(|(k, v)| (*k, v.clone())))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| {
            panic!("spawn {program} {}: {error}", script.display());
        });
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
        if block.language != "nix" || block.is_ignored() || block.body.contains('…') {
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
