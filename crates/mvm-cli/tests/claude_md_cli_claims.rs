//! Every `mvmctl …` invocation CLAUDE.md shows must resolve against the CLI.
//!
//! CLAUDE.md is loaded as authoritative project instruction on every session, so
//! a command it shows that does not exist is worse than an ordinary stale doc:
//! it is an instruction to type something impossible. When this was first
//! checked it claimed five: `build image`, `console`, `start`, `template build`
//! and `up`, three of which name namespaces that were deliberately deleted.
//!
//! `xtask check-cli-help-matches-docs` covers the published CLI reference, but
//! only at top-level-verb granularity and only for that one file. This runs
//! inside `mvm-cli`, so it can walk the real clap tree and resolve a full
//! subcommand path — which is what `template build` needed.
//!
//! A negated mention is not a claim. CLAUDE.md legitimately discusses retired
//! verbs, so a *paragraph* carrying a negation is skipped. Paragraph, not line:
//! the file's longest such passage quotes a retired claim on one line and
//! refutes it three lines later ("**None of that exists.**"), which a
//! line-scoped check reads as an assertion. That direction is deliberate: the
//! failure mode is a missed check inside a passage that says something does not
//! exist, never a false alarm on one that says it does.

use clap::Command;

/// Words that turn a mention into a statement about something's absence.
const NEGATIONS: &[&str] = &[
    "no ",
    "none of",
    "not ",
    "never",
    "n't",
    "removed",
    "retired",
    "dropped",
    "deleted",
    "gone",
    "does not exist",
    "unreachable",
    "withdrawn",
    "stale",
    "nonexistent",
    "non-existent",
    "was renamed",
    "instead of",
    "rather than",
    "wrong",
];

fn claude_md() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../CLAUDE.md")
        .canonicalize()
        .expect("CLAUDE.md must exist at the workspace root");
    std::fs::read_to_string(path).expect("read CLAUDE.md")
}

/// Pull the command path out of a backticked span that starts with `mvmctl `.
///
/// Stops at the first flag or placeholder: `mvmctl machine run --entrypoint`
/// checks `machine run`, because whether a *flag* exists is a different
/// question with a different answer shape.
fn command_path(span: &str) -> Option<Vec<String>> {
    let rest = span.strip_prefix("mvmctl ")?;
    let path: Vec<String> = rest
        .split_whitespace()
        .take_while(|t| {
            !t.starts_with('-')
                && !t.starts_with('<')
                && !t.starts_with('[')
                && t.chars().all(|c| c.is_ascii_lowercase() || c == '-')
        })
        .map(|t| t.to_string())
        .collect();
    (!path.is_empty()).then_some(path)
}

/// Every backticked span in a paragraph that does not negate.
fn claims_in(paragraph: &str) -> Vec<Vec<String>> {
    let lower = paragraph.to_ascii_lowercase();
    if NEGATIONS.iter().any(|n| lower.contains(n)) {
        return Vec::new();
    }
    paragraph
        .split('`')
        .skip(1)
        .step_by(2)
        .filter_map(command_path)
        .collect()
}

/// Walk `path` down the command tree, hidden subcommands included — hidden is
/// about `--help` clutter, not about existence.
fn resolves(root: &Command, path: &[String]) -> bool {
    let mut cur = root;
    for segment in path {
        match cur
            .get_subcommands()
            .find(|c| c.get_name() == segment || c.get_all_aliases().any(|a| a == segment))
        {
            Some(next) => cur = next,
            None => return false,
        }
    }
    true
}

#[test]
fn every_command_claude_md_shows_resolves() {
    let root = mvm_cli::commands::cli_command();
    let source = claude_md();

    let mut unresolved: Vec<String> = Vec::new();
    let mut paragraph = String::new();
    let mut paragraph_start = 1usize;
    let flush = |paragraph: &mut String, start: usize, out: &mut Vec<String>| {
        for path in claims_in(paragraph) {
            if !resolves(&root, &path) {
                out.push(format!("CLAUDE.md:{start}: `mvmctl {}`", path.join(" ")));
            }
        }
        paragraph.clear();
    };
    for (idx, line) in source.lines().enumerate() {
        if line.trim().is_empty() {
            flush(&mut paragraph, paragraph_start, &mut unresolved);
            paragraph_start = idx + 2;
            continue;
        }
        if paragraph.is_empty() {
            paragraph_start = idx + 1;
        }
        paragraph.push_str(line);
        paragraph.push('\n');
    }
    flush(&mut paragraph, paragraph_start, &mut unresolved);

    assert!(
        unresolved.is_empty(),
        "CLAUDE.md shows {} command(s) that do not exist. It is loaded as \
         authoritative instruction every session, so these are instructions to \
         type something impossible:\n  {}",
        unresolved.len(),
        unresolved.join("\n  ")
    );
}

#[test]
fn the_extractor_sees_claims_and_skips_negations() {
    // Guard the guard: a checker that silently matched nothing would pass
    // forever. These pin both directions on text this file controls.
    assert_eq!(
        claims_in("Run `mvmctl machine run --image alpine` to boot."),
        vec![vec!["machine".to_string(), "run".to_string()]],
        "a plain claim is extracted, and the flag is not part of the path"
    );
    assert!(
        claims_in("There is no `mvmctl up` command.").is_empty(),
        "a negated line is not a claim"
    );
    assert!(
        claims_in("`mvmctl template build` was removed.").is_empty(),
        "a retirement note is not a claim"
    );
    assert!(
        claims_in("This used to claim `mvmctl up` warns.\nNone of that exists.").is_empty(),
        "the refutation may land a line after the quote it refutes"
    );
    assert_eq!(
        command_path("mvmctl run --image <ref>"),
        Some(vec!["run".to_string()]),
        "a placeholder ends the path"
    );
    assert_eq!(command_path("cargo build"), None, "only mvmctl spans count");
}

#[test]
fn the_resolver_accepts_real_commands_and_rejects_invented_ones() {
    let root = mvm_cli::commands::cli_command();
    assert!(resolves(&root, &["machine".into(), "run".into()]));
    assert!(resolves(
        &root,
        &["trust".into(), "audit".into(), "verify".into()]
    ));
    assert!(
        resolves(&root, &["run".into()]),
        "hidden-then-unhidden verbs still resolve"
    );
    assert!(!resolves(&root, &["template".into(), "build".into()]));
    assert!(!resolves(&root, &["definitely-not-a-verb".into()]));
}
