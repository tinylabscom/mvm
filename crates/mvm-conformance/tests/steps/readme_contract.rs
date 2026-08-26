//! Steps locking the README's user-facing contract to the real `mvmctl`
//! surface — the slice checkable without booting a builder VM or a microVM.
//! Live-boot behaviours (a guest booted to completion, the verified-boot tamper
//! panic, egress enforcement, vsock secret substitution) are proven by the
//! live-KVM smokes, not here.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use clap::Command as ClapCommand;
use cucumber::{then, when};
use serde::Deserialize;

use crate::steps::cli::mvmctl_command;
use crate::world::CliWorld;
use mvm_conformance::IsolatedHome;

/// Repo root — two levels above this crate's manifest dir, resolved at compile
/// time so the run is independent of the process working directory.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// A private, empty `MVM_HOME` for one invocation so a refusal scenario never
/// reads or writes the developer's real `~/.mvm`. Uniqueness comes from the pid
/// plus a monotonic counter, avoiding a temp-dir crate dependency.
fn isolated_mvm_home() -> PathBuf {
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("mvm-readme-contract-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create isolated MVM_HOME");
    dir
}

/// Spawn the built `mvmctl` binary with the given whitespace-split argv,
/// capturing its `Output`. Panics with an actionable hint if the binary is
/// missing, mirroring the sibling `cli` steps.
fn spawn_mvmctl(args: &str, home: Option<PathBuf>) -> std::process::Output {
    let mut cmd = mvmctl_command();
    if let Some(home) = home {
        // Reconcile-on-entry converges live-VM state; disable it so a refusal
        // guard runs against a clean slate with no host side effects.
        cmd.isolated_home(&home).env("MVM_SKIP_RECONCILE", "1");
    }
    cmd.args(args.split_whitespace())
        .output()
        .expect("failed to spawn mvmctl")
}

/// Run the real `mvmctl` against a private, empty `MVM_HOME` so the README's
/// documented refusal/exit-code contracts are exercised hermetically.
#[when(expr = "I run mvmctl in a clean home with {string}")]
fn run_mvmctl_clean_home(world: &mut CliWorld, args: String) {
    world.last_run = Some(spawn_mvmctl(&args, Some(isolated_mvm_home())));
}

/// Verify every shell example in the README against the command tree exposed
/// by the built CLI. The examples are checked through `--help`, so this test
/// validates command and option spelling without booting a VM or contacting a
/// registry.
#[then(expr = "every README CLI example resolves to a command and its options")]
fn readme_cli_examples_resolve(_world: &mut CliWorld) {
    let command_tree = mvm_cli::commands::cli_command();
    let mut command_paths = Vec::new();
    crate::steps::cli::collect_command_paths(&command_tree, &[], &mut command_paths);
    let examples = readme_mvmctl_examples();
    assert!(
        !examples.is_empty(),
        "README.md contains no mvmctl shell examples"
    );

    for example in examples {
        let tokens = shell_tokens(&example);
        let command_tokens = tokens
            .iter()
            .position(|token| token == "mvmctl")
            .map(|index| &tokens[index + 1..])
            .expect("README example must contain mvmctl");
        let path = command_paths
            .iter()
            .filter(|path| path_matches(path, command_tokens))
            .max_by_key(|path| path.len())
            .unwrap_or_else(|| panic!("README command has no CLI match: {example:?}"));

        let output = crate::steps::cli::mvmctl_command()
            .args(path)
            .arg("--help")
            .output()
            .unwrap_or_else(|error| panic!("failed to run README command {example:?}: {error}"));
        assert!(
            output.status.success(),
            "README command `mvmctl {}` has no usable help:\n{}",
            path.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );

        let help = String::from_utf8_lossy(&output.stdout);
        for option in readme_options(command_tokens) {
            assert!(
                help.contains(&option),
                "README option {option:?} is not documented by `mvmctl {}`:\n{help}",
                path.join(" ")
            );
        }
    }
}

/// Exercise every declared CLI option through a help request. Visible options
/// must be present in the real subprocess help. Hidden options are rendered
/// from the same command tree with hiding disabled; they remain covered while
/// retaining their intentionally non-user-facing status in the binary.
#[then(expr = "every CLI command option has a BDD help witness")]
fn every_cli_option_has_help_witness(_world: &mut CliWorld) {
    let command_tree = mvm_cli::commands::cli_command();
    let mut option_count = 0;
    assert_command_options(&command_tree, &[], &mut option_count);
    assert!(option_count > 0, "the CLI command tree declared no options");
}

fn assert_command_options(command: &ClapCommand, path: &[String], option_count: &mut usize) {
    let mut args = path.to_vec();
    args.push("--help".to_string());
    let output = crate::steps::cli::mvmctl_command()
        .args(&args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run `mvmctl {}`: {error}", args.join(" ")));
    assert!(
        output.status.success(),
        "`mvmctl {}` help failed:\n{}",
        args[..args.len() - 1].join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    let visible_help = String::from_utf8_lossy(&output.stdout);
    let all_help = command
        .clone()
        .mut_args(|argument| argument.hide(false))
        .render_help()
        .to_string();

    for argument in command.get_arguments() {
        let Some(option) = argument
            .get_long()
            .map(|long| format!("--{long}"))
            .or_else(|| argument.get_short().map(|short| format!("-{short}")))
        else {
            continue;
        };
        *option_count += 1;
        let help: &str = if argument.is_hide_set() {
            all_help.as_str()
        } else {
            visible_help.as_ref()
        };
        assert!(
            help.contains(&option),
            "option {option:?} is missing from `mvmctl {}` help:\n{help}",
            path.join(" ")
        );
    }

    for subcommand in command.get_subcommands() {
        let mut child_path = path.to_vec();
        child_path.push(subcommand.get_name().to_string());
        assert_command_options(subcommand, &child_path, option_count);
    }
}

#[derive(Debug)]
struct ReadmeCodeBlock {
    language: String,
    body: String,
}

#[derive(Debug, Deserialize)]
struct ReadmeCoverageManifest {
    block: Vec<ReadmeCoverageWitness>,
}

#[derive(Debug, Deserialize)]
struct ReadmeCoverageWitness {
    classification: String,
    language: String,
}

#[then(expr = "every README code block has an explicit coverage witness")]
fn every_readme_code_block_has_a_coverage_witness(_world: &mut CliWorld) {
    let blocks = readme_code_blocks();
    assert!(
        !blocks.is_empty(),
        "README.md contains no fenced code blocks"
    );
    let manifest = readme_coverage_manifest();
    assert_eq!(
        blocks.len(),
        manifest.block.len(),
        "README fenced block count changed; update the test-owned coverage manifest"
    );

    let mut classifications = BTreeSet::new();
    for (index, (block, witness)) in blocks.iter().zip(&manifest.block).enumerate() {
        assert_eq!(
            block.language, witness.language,
            "README code block {index} changed language; update its test-owned coverage witness"
        );
        classifications.insert(witness.classification.as_str());
        match witness.classification.as_str() {
            "cli-bdd" => {
                assert!(
                    matches!(block.language.as_str(), "bash" | "sh" | "shell"),
                    "CLI witness must be a shell block: {block:?}"
                );
                assert!(
                    block.body.contains("mvmctl "),
                    "CLI witness must contain an mvmctl invocation: {block:?}"
                );
            }
            "install-static" => {
                assert_eq!(block.language, "bash", "install witness must be bash");
                for command in ["curl ", "cargo build", "pip install", "npm install"] {
                    assert!(
                        block.body.contains(command),
                        "install witness is missing {command:?}: {block:?}"
                    );
                }
            }
            "sdk-bdd" => {
                assert!(
                    matches!(block.language.as_str(), "python" | "ts" | "typescript"),
                    "SDK witness must be Python or TypeScript: {block:?}"
                );
                assert!(
                    block.body.contains("mvm") || block.body.contains("Sandbox"),
                    "SDK witness must reference the SDK: {block:?}"
                );
            }
            "nix-static" => {
                assert_eq!(block.language, "nix", "Nix witness must be a Nix block");
                for token in ["inputs", "outputs", "mkGuest", "entrypoint"] {
                    assert!(
                        block.body.contains(token),
                        "Nix witness is missing {token:?}: {block:?}"
                    );
                }
            }
            "rust-compile" => {
                assert!(
                    matches!(block.language.as_str(), "rust" | "toml"),
                    "Rust witness must be Rust or Cargo TOML: {block:?}"
                );
                assert!(
                    block.body.contains("mvm") || block.body.contains("Mvm"),
                    "Rust witness must reference an mvm integration: {block:?}"
                );
            }
            "static-only" => {}
            other => panic!("unknown README coverage classification {other:?}"),
        }
    }

    for required in [
        "cli-bdd",
        "install-static",
        "sdk-bdd",
        "nix-static",
        "rust-compile",
        "static-only",
    ] {
        assert!(
            classifications.contains(required),
            "README coverage classification {required:?} has no witness"
        );
    }
}

fn readme_coverage_manifest() -> ReadmeCoverageManifest {
    let path = repo_root()
        .join("features")
        .join("suites")
        .join("s8_readme_contract")
        .join("readme_coverage.toml");
    let manifest = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("read README coverage manifest {}: {error}", path.display())
    });
    toml::from_str(&manifest).unwrap_or_else(|error| {
        panic!("parse README coverage manifest {}: {error}", path.display())
    })
}

fn readme_code_blocks() -> Vec<ReadmeCodeBlock> {
    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("read README.md");
    let mut current: Option<ReadmeCodeBlock> = None;
    let mut blocks = Vec::new();

    for line in readme.lines() {
        let trimmed = line.trim();
        if let Some(block) = current.as_mut() {
            if trimmed == "```" {
                blocks.push(current.take().expect("current README block"));
            } else {
                if !block.body.is_empty() {
                    block.body.push('\n');
                }
                block.body.push_str(line);
            }
            continue;
        }

        if let Some(language) = trimmed.strip_prefix("```") {
            current = Some(ReadmeCodeBlock {
                language: language.to_string(),
                body: String::new(),
            });
        }
    }

    assert!(current.is_none(), "README has an unterminated code block");
    blocks
}

fn readme_mvmctl_examples() -> Vec<String> {
    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("read README.md");
    let mut in_shell_block = false;
    let mut pending: Option<String> = None;
    let mut examples = Vec::new();

    for line in readme.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_shell_block = matches!(trimmed, "```bash" | "```sh" | "```shell");
            pending = None;
            continue;
        }
        if !in_shell_block {
            continue;
        }

        let line = line.split(" #").next().unwrap_or(line).trim_end();
        if let Some(existing) = pending.as_mut() {
            existing.push(' ');
            existing.push_str(line.trim());
        } else if line.contains("mvmctl ") {
            pending = Some(line.trim().to_string());
        } else {
            continue;
        }

        let continued = pending
            .as_deref()
            .is_some_and(|command| command.ends_with('\\'));
        if continued {
            if let Some(command) = pending.as_mut() {
                command.pop();
            }
        } else if let Some(command) = pending.take() {
            examples.extend(split_mvmctl_invocations(&command));
        }
    }

    examples
}

fn split_mvmctl_invocations(line: &str) -> Vec<String> {
    let mut remaining = line;
    let mut invocations = Vec::new();
    while let Some(start) = remaining.find("mvmctl ") {
        let is_command_token = remaining[..start].chars().last().is_none_or(|character| {
            !character.is_ascii_alphanumeric() && character != '/' && character != '.'
        });
        if !is_command_token {
            remaining = &remaining[start + "mvmctl".len()..];
            continue;
        }
        let command = &remaining[start..];
        let end = command.find(['|', ';', '&']).unwrap_or(command.len());
        invocations.push(command[..end].trim().to_string());
        remaining = &command[end..];
        if remaining.is_empty() {
            break;
        }
        remaining = &remaining[1..];
    }
    invocations
}

fn shell_tokens(example: &str) -> Vec<String> {
    example
        .split_whitespace()
        .map(|token| {
            token
                .trim_matches(|character| matches!(character, '"' | '\'' | '\\'))
                .to_string()
        })
        .collect()
}

fn path_matches(path: &[String], tokens: &[String]) -> bool {
    tokens.len() >= path.len()
        && path
            .iter()
            .zip(tokens)
            .all(|(expected, actual)| expected == actual)
}

fn readme_options(tokens: &[String]) -> Vec<String> {
    let mut options = Vec::new();
    for token in tokens {
        if token == "--" {
            break;
        }
        if let Some(long) = token.strip_prefix("--") {
            options.push(format!("--{}", long.split('=').next().unwrap_or(long)));
        } else if token.starts_with('-') && token.len() > 1 && !token.starts_with("--") {
            options.extend(token[1..].chars().map(|short| format!("-{short}")));
        }
    }
    options.sort();
    options.dedup();
    options
}

/// Count the README's enumerated security claims: `N. **…` items inside the
/// `## Security model` section only, so an unrelated numbered list elsewhere
/// cannot inflate the count.
fn readme_enumerated_claims() -> usize {
    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("read README.md");
    let mut in_section = false;
    let mut count = 0;
    for line in readme.lines() {
        if line.starts_with("## Security model") {
            in_section = true;
            continue;
        }
        if in_section && line.starts_with("## ") {
            break;
        }
        if in_section && is_numbered_bold_item(line) {
            count += 1;
        }
    }
    count
}

/// A README claim item opens with `<int>. **`.
fn is_numbered_bold_item(line: &str) -> bool {
    match line.split_once(". ") {
        Some((lead, rest)) => {
            !lead.is_empty() && lead.chars().all(|c| c.is_ascii_digit()) && rest.starts_with("**")
        }
        None => false,
    }
}

/// Count the `Shipped` numbered rows in the conformance claim catalog embedded
/// in the security-posture ADR (the machine-checked claim -> witness table
/// between its begin/end markers).
fn catalog_shipped_claims() -> usize {
    const BEGIN: &str = "<!-- claims-catalog:begin -->";
    const END: &str = "<!-- claims-catalog:end -->";
    let adr =
        std::fs::read_to_string(repo_root().join("specs/adrs/001-microvm-security-posture.md"))
            .expect("read the security-posture ADR");
    let mut in_catalog = false;
    let mut count = 0;
    for line in adr.lines() {
        if line.contains(BEGIN) {
            in_catalog = true;
            continue;
        }
        if line.contains(END) {
            break;
        }
        if in_catalog && is_shipped_claim_row(line) {
            count += 1;
        }
    }
    count
}

/// A catalog table row for a numbered, `Shipped` claim: `| <int> | … | Shipped |`.
fn is_shipped_claim_row(line: &str) -> bool {
    let cells: Vec<&str> = line.split('|').map(str::trim).collect();
    let numbered = cells
        .get(1)
        .is_some_and(|c| !c.is_empty() && c.chars().all(|ch| ch.is_ascii_digit()));
    let shipped = cells
        .iter()
        .rev()
        .find(|c| !c.is_empty())
        .is_some_and(|c| *c == "Shipped");
    numbered && shipped
}

/// Cross-check: the README's enumerated claim count and the catalog's `Shipped`
/// claim count both equal the documented number. Locks the README summary to the
/// machine-checked ledger — either one drifting fails this step.
#[then(expr = "the README and the claim catalog agree on {int} numbered claims")]
fn readme_and_catalog_agree(_world: &mut CliWorld, expected: usize) {
    let readme = readme_enumerated_claims();
    let catalog = catalog_shipped_claims();
    assert_eq!(
        readme, expected,
        "README enumerates {readme} security claims, expected {expected}"
    );
    assert_eq!(
        catalog, expected,
        "conformance catalog lists {catalog} Shipped claims, expected {expected}"
    );
}
