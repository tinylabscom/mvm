//! `xtask check-cli-help-matches-docs`
//!
//! The published CLI reference and `mvmctl --help` must describe the same
//! surface. They had drifted badly in both directions: the reference documented
//! `mvmctl run` as the one-shot flagship and `mvmctl secret` / `mvmctl trust` as
//! the entry points to the substitution and receipt subsystems, while all three
//! carried `hide = true` and could not be found from `--help` at all; and seven
//! visible verbs appeared in no reference row.
//!
//! A user who cannot discover a verb does not have it. This gate holds the two
//! descriptions together:
//!
//! 1. every top-level verb with a reference row is a real, non-hidden variant;
//! 2. every non-hidden variant has a reference row.
//!
//! Hidden verbs are exempt from rule 2 by construction — hiding one is the
//! declaration that it is internal or dev-only. Hiding a verb to dodge writing
//! its row therefore also deletes it from `--help`, which is the cost that
//! keeps the escape honest.
//!
//! Only *command evidence* counts as documentation: a table row opening
//! `` | `mvmctl <verb> `` or a fenced-block line starting `mvmctl <verb>`.
//! Prose is ignored on purpose — the reference discusses retired verbs
//! (`mvmctl security`, `mvmctl flake check`) and explicitly negates others
//! ("not by a public `mvmctl policy` command"), and none of that is a claim
//! that the verb exists.

use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const CLI_REFERENCE: &str = "public/src/content/docs/reference/cli-commands.md";
const COMMANDS_SOURCE: &str = "crates/mvm-cli/src/commands/mod.rs";

/// A top-level clap subcommand as declared in the `Commands` enum.
#[derive(Debug, PartialEq, Eq)]
struct Verb {
    name: String,
    hidden: bool,
    line: usize,
}

pub fn run(workspace: &Path) -> Result<()> {
    let source = read_required(workspace, COMMANDS_SOURCE)?;
    let reference = read_required(workspace, CLI_REFERENCE)?;

    let verbs = parse_commands_enum(&source)?;
    if verbs.is_empty() {
        bail!(
            "{COMMANDS_SOURCE}: parsed no top-level verbs — the enum shape changed and this gate is now blind"
        );
    }
    let documented = parse_documented_verbs(&reference);

    let by_name: BTreeMap<&str, &Verb> = verbs.iter().map(|v| (v.name.as_str(), v)).collect();
    let mut findings: Vec<String> = Vec::new();

    for name in &documented {
        match by_name.get(name.as_str()) {
            None => findings.push(format!(
                "{CLI_REFERENCE} documents `mvmctl {name}`, which is not a top-level command"
            )),
            Some(verb) if verb.hidden => findings.push(format!(
                "{CLI_REFERENCE} documents `mvmctl {name}`, but {COMMANDS_SOURCE}:{} hides it from `--help`",
                verb.line
            )),
            Some(_) => {}
        }
    }

    for verb in &verbs {
        if !verb.hidden && !documented.contains(&verb.name) {
            findings.push(format!(
                "{COMMANDS_SOURCE}:{} exposes `mvmctl {}` in `--help`, but {CLI_REFERENCE} has no row for it",
                verb.line, verb.name
            ));
        }
    }

    if findings.is_empty() {
        eprintln!(
            "check-cli-help-matches-docs: clean ({} verbs, {} visible)",
            verbs.len(),
            verbs.iter().filter(|v| !v.hidden).count()
        );
        return Ok(());
    }

    eprintln!(
        "check-cli-help-matches-docs: {} finding(s) — `mvmctl --help` and the CLI reference disagree",
        findings.len()
    );
    for finding in &findings {
        eprintln!("  {finding}");
    }
    std::process::exit(1);
}

fn read_required(workspace: &Path, rel: &str) -> Result<String> {
    let path = workspace.join(rel);
    if !path.is_file() {
        bail!("required file missing: {}", path.display());
    }
    std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))
}

/// Pull `(name, hidden)` for each variant of the `Commands` enum.
///
/// Deliberately a source scan rather than a link against `mvm-cli`: xtask does
/// not depend on the CLI crate, and building it to read its own help text would
/// put a full workspace build in front of a lint that must stay cheap.
fn parse_commands_enum(source: &str) -> Result<Vec<Verb>> {
    let lines: Vec<&str> = source.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.contains("enum Commands {"))
        .context("could not find `enum Commands {` — the gate cannot parse the CLI surface")?;

    let mut verbs = Vec::new();
    let mut pending_name: Option<String> = None;
    let mut pending_hidden = false;
    let mut depth = 0usize;

    for (offset, line) in lines[start..].iter().enumerate() {
        let trimmed = line.trim();
        depth += line.matches('{').count();
        depth = depth.saturating_sub(line.matches('}').count());
        if depth == 0 && offset > 0 {
            break;
        }

        if trimmed.starts_with("#[command(") || trimmed.starts_with("#[clap(") {
            if trimmed.contains("hide = true") || trimmed.contains("hide=true") {
                pending_hidden = true;
            }
            if let Some(name) = attribute_name(trimmed) {
                pending_name = Some(name);
            }
            continue;
        }
        if trimmed.starts_with("///") || trimmed.starts_with("//") || trimmed.starts_with("#[cfg") {
            continue;
        }

        if let Some(ident) = variant_ident(trimmed) {
            let name = pending_name.take().unwrap_or_else(|| kebab_case(&ident));
            verbs.push(Verb {
                name,
                hidden: pending_hidden,
                line: start + offset + 1,
            });
            pending_hidden = false;
        }
    }

    Ok(verbs)
}

/// `#[command(name = "seccomp-audit", hide = true)]` → `seccomp-audit`.
fn attribute_name(attr: &str) -> Option<String> {
    let rest = attr.split_once("name = \"")?.1;
    let name = rest.split_once('"')?.0;
    Some(name.to_string())
}

/// `Machine(machine::Args),` → `Machine`. Only tuple variants are commands.
fn variant_ident(line: &str) -> Option<String> {
    let ident = line.split_once('(')?.0.trim();
    if ident.is_empty() || !ident.chars().next()?.is_ascii_uppercase() {
        return None;
    }
    if !ident.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(ident.to_string())
}

/// Clap's default renaming for a variant with no explicit `name`.
fn kebab_case(ident: &str) -> String {
    let mut out = String::with_capacity(ident.len() + 2);
    for (idx, ch) in ident.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if idx > 0 {
                out.push('-');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Top-level verbs the reference documents as commands, ignoring prose.
fn parse_documented_verbs(reference: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut in_fence = false;

    for line in reference.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }

        let invocation = if in_fence {
            trimmed.strip_prefix("mvmctl ")
        } else {
            trimmed.strip_prefix("| `mvmctl ")
        };

        if let Some(rest) = invocation
            && let Some(verb) = first_verb(rest)
        {
            found.insert(verb);
        }
    }

    found
}

/// Global flags that take a value. A boolean global (`--verbose`) must not
/// swallow the verb that follows it, so the two kinds cannot share a
/// does-the-next-token-look-like-a-value heuristic.
const VALUED_GLOBAL_FLAGS: &[&str] = &[
    "--log-format",
    "--fc-version",
    "--builder",
    "--kernel-source",
];

/// First bare token of an invocation tail, skipping global flags and their
/// values so `mvmctl --builder qemu machine run` still resolves to `machine`.
fn first_verb(rest: &str) -> Option<String> {
    let mut tokens = rest.split_whitespace().peekable();
    while let Some(token) = tokens.next() {
        if token.starts_with('-') {
            if VALUED_GLOBAL_FLAGS.contains(&token)
                && tokens.peek().is_some_and(|n| !n.starts_with('-'))
            {
                tokens.next();
            }
            continue;
        }
        let verb: String = token
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
            .collect();
        if verb.is_empty() {
            return None;
        }
        return Some(verb);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
enum Commands {
    /// Beginner microVM workflows
    #[command(display_order = 1)]
    Machine(machine::Args),
    /// SDK transport surface
    #[command(hide = true)]
    Run(vm::exec::RunArgs),
    /// Host-side seccomp syscall audit.
    #[command(name = "seccomp-audit", hide = true)]
    SeccompAudit(seccomp_audit::Args),
    /// Print shell configuration
    ShellInit(env::shell_init::Args),
}
"#;

    #[test]
    fn parses_names_hidden_flags_and_clap_renaming() {
        let verbs = parse_commands_enum(SAMPLE).expect("parses");
        let names: Vec<(&str, bool)> = verbs.iter().map(|v| (v.name.as_str(), v.hidden)).collect();
        assert_eq!(
            names,
            vec![
                ("machine", false),
                ("run", true),
                ("seccomp-audit", true),
                ("shell-init", false),
            ]
        );
    }

    #[test]
    fn documentation_evidence_is_rows_and_fences_never_prose() {
        let doc = "\
| `mvmctl machine run --image x` | boot |
Retired: the `mvmctl security` verb folded into doctor.
tenant policy is not exposed by a public `mvmctl policy` command.
```bash
mvmctl trust receipt verify ./r.json
mvmctl --builder qemu machine ls
```
";
        let found = parse_documented_verbs(doc);
        assert!(found.contains("machine"), "table row counts");
        assert!(found.contains("trust"), "fenced invocation counts");
        assert!(!found.contains("security"), "prose must not count");
        assert!(!found.contains("policy"), "negated prose must not count");
    }

    #[test]
    fn global_flags_do_not_shadow_the_verb() {
        assert_eq!(
            first_verb("--builder qemu machine ls").as_deref(),
            Some("machine")
        );
        assert_eq!(first_verb("--verbose doctor").as_deref(), Some("doctor"));
        assert_eq!(
            first_verb("--log-format=json doctor").as_deref(),
            Some("doctor")
        );
        assert_eq!(first_verb("machine run").as_deref(), Some("machine"));
    }

    #[test]
    fn backtick_and_punctuation_terminate_the_verb() {
        assert_eq!(
            first_verb("doctor` | diagnostics |").as_deref(),
            Some("doctor")
        );
    }
}
