//! The justfile is one file with a deliberately small set of recipes; a
//! variant is a recipe's first argument, not another recipe. These guards pin
//! that shape so the surface cannot quietly grow back, and check that what the
//! surface promises can run: every recipe the justfile or a contributor doc
//! names exists, and every recipe body is something the shell can parse.

use std::collections::BTreeSet;
use std::fs;

const JUSTFILE: &str = include_str!("../Justfile");

/// Contributor guidance and source comments that name recipes. A stale name
/// here is a command that fails the first time someone follows it.
const RECIPE_DOCS: &[&str] = &[
    "AGENTS.md",
    "CLAUDE.md",
    "README.md",
    "crates/mvm-agentd/tests/runner_end_to_end.rs",
    "crates/mvm-conformance/README.md",
    "crates/mvm-sdk/src/bin/emit_schema.rs",
    "crates/mvm-compiler/src/orchestrator.rs",
    "nix/wrappers/README.md",
    "public/src/content/docs/contributing/ai-coding-workflow.md",
    "public/src/content/docs/contributing/development.md",
];

/// Calls into another repository's justfile, by doc and recipe. None of the
/// docs above names one today; the image-train release command lives in the
/// releases reference page, which this test does not scan.
const FOREIGN_RECIPES: &[(&str, &str)] = &[];

/// Words that open a shell compound command, and the ones that continue or
/// close it. Without a shebang `just` hands each body line to its own
/// `sh -c`, so a compound command left open on its line is a syntax error.
const COMPOUND_OPENERS: &[&str] = &["if", "case", "for", "while", "until"];
const COMPOUND_CONTINUATIONS: &[&str] = &["then", "else", "elif", "fi", "esac", "do", "done"];
const COMPOUND_CLOSERS: &[&str] = &["fi", "esac", "done"];

struct Recipe<'a> {
    name: &'a str,
    body: Vec<&'a str>,
}

/// Recipe headers sit at column 0; indented body lines may contain ':'
/// (module calls, case arms) and are not headers.
fn recipe_name(line: &str) -> Option<&str> {
    if line.starts_with(char::is_whitespace)
        || line.starts_with('#')
        || line.starts_with("set ")
        || line.starts_with("mod ")
    {
        return None;
    }
    let colon = line.find(':')?;
    if line[colon..].starts_with(":=") {
        return None;
    }
    let name = line[..colon].split_whitespace().next()?;
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        .then_some(name)
}

/// Every recipe in a justfile, with its non-blank body lines trimmed.
fn recipes(text: &str) -> Vec<Recipe<'_>> {
    let mut recipes: Vec<Recipe<'_>> = Vec::new();
    let mut in_body = false;
    for line in text.lines() {
        if let Some(name) = recipe_name(line) {
            recipes.push(Recipe {
                name,
                body: Vec::new(),
            });
            in_body = true;
        } else if line.trim().is_empty() {
            continue;
        } else if !line.starts_with(char::is_whitespace) {
            in_body = false;
        } else if in_body && let Some(recipe) = recipes.last_mut() {
            recipe.body.push(line.trim());
        }
    }
    recipes
}

/// The first body line of a shebang-less recipe that opens a compound command
/// without closing it, or continues one opened on an earlier line.
fn split_compound_line<'a>(recipe: &Recipe<'a>) -> Option<&'a str> {
    if recipe
        .body
        .first()
        .is_some_and(|line| line.starts_with("#!"))
    {
        return None;
    }
    recipe.body.iter().copied().find(|line| {
        let words: Vec<&str> = line
            .trim_start_matches(['@', '-'])
            .split_whitespace()
            .map(|word| word.trim_end_matches(';'))
            .collect();
        let Some(first) = words.first() else {
            return false;
        };
        let closed = words.iter().any(|word| COMPOUND_CLOSERS.contains(word));
        COMPOUND_CONTINUATIONS.contains(first) || (COMPOUND_OPENERS.contains(first) && !closed)
    })
}

/// Why `target` does not name a recipe, or `None` when it does. There are no
/// modules, so a namespaced `module::recipe` never resolves.
fn unresolved(root: &BTreeSet<&str>, target: &str) -> Option<String> {
    if target.contains("::") {
        return Some(
            "there are no modules; the variant is the recipe's first argument".to_string(),
        );
    }
    (!root.contains(target)).then(|| format!("no recipe `{target}`"))
}

fn root_recipes() -> BTreeSet<&'static str> {
    recipes(JUSTFILE).iter().map(|recipe| recipe.name).collect()
}

/// One `just` invocation found in text: the recipe token after it, and
/// whether `just` opened an inline code span.
struct JustCall<'a> {
    target: &'a str,
    backticked: bool,
}

fn just_calls(text: &str) -> Vec<JustCall<'_>> {
    let mut calls = Vec::new();
    let mut from = 0;
    while let Some(offset) = text[from..].find("just") {
        let start = from + offset;
        let end = start + "just".len();
        from = end;
        let before = text[..start].chars().next_back();
        if before.is_some_and(|c| !(c.is_whitespace() || matches!(c, '`' | '@' | '('))) {
            continue;
        }
        let rest = &text[end..];
        let after = rest.trim_start();
        if after.len() == rest.len() {
            continue;
        }
        let token_len = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':')))
            .unwrap_or(after.len());
        let target = after[..token_len].trim_end_matches(':');
        if target.is_empty() || target.starts_with('-') {
            continue;
        }
        calls.push(JustCall {
            target,
            backticked: before == Some('`'),
        });
    }
    calls
}

/// The whole surface is exactly this set — no more, no fewer — and it lives
/// in one file.
#[test]
fn the_recipes_are_exactly_the_contributor_set_in_one_file() {
    assert_eq!(
        root_recipes().into_iter().collect::<Vec<_>>(),
        [
            "build", "check", "ci", "clean", "default", "docs", "e2e", "fmt", "lint", "mem",
            "release", "run", "setup", "test"
        ],
        "the justfile surface changed — update this guard and the docs deliberately"
    );
    assert!(
        !JUSTFILE.lines().any(|line| line.starts_with("mod ")),
        "a variant is a recipe's first argument, not a module"
    );
    assert!(
        !std::path::Path::new("just").exists(),
        "recipes live in the root Justfile, not under just/"
    );
}

/// A multi-line `if` or `case` without a shebang dies on `sh: syntax error:
/// unexpected end of file` on every invocation, because each line runs in its
/// own shell. A compound command spread over lines needs a shebang recipe.
#[test]
fn compound_shell_commands_only_span_lines_in_shebang_recipes() {
    let broken: Vec<String> = recipes(JUSTFILE)
        .iter()
        .filter_map(|recipe| {
            split_compound_line(recipe).map(|line| format!("`{}`: {line}", recipe.name))
        })
        .collect();
    assert!(
        broken.is_empty(),
        "these recipes split a shell compound command across lines without a \
         shebang, so each line runs in its own shell and the first fails to \
         parse:\n{}",
        broken.join("\n")
    );
}

/// A recipe that calls another by a name that does not exist fails only when
/// that arm runs. Resolve every call statically: namespaced calls anywhere in
/// the justfile, bare ones that start a body line or a code span.
#[test]
fn every_just_call_in_the_justfile_names_a_real_recipe() {
    let root = root_recipes();
    let mut stale = Vec::new();
    for line in JUSTFILE.lines() {
        let trimmed = line.trim_start();
        let body_command = line.starts_with(char::is_whitespace)
            && (trimmed.starts_with("just ") || trimmed.starts_with("@just "));
        for call in just_calls(line) {
            if !call.target.contains("::") && !body_command && !call.backticked {
                continue;
            }
            if let Some(reason) = unresolved(&root, call.target) {
                stale.push(format!("`just {}`: {reason}", call.target));
            }
        }
    }
    assert!(
        stale.is_empty(),
        "stale recipe calls:\n{}",
        stale.join("\n")
    );
}

/// The docs kept naming recipes from an earlier layout (`just check-gated`,
/// `just tests::scoped`). A name after `just` must be a recipe.
#[test]
fn contributor_docs_name_real_recipes() {
    let root = root_recipes();
    let mut stale = Vec::new();
    for path in RECIPE_DOCS {
        let text = fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("failed to read {path}: {error}"));
        for call in just_calls(&text) {
            if (!call.target.contains("::") && !call.backticked)
                || FOREIGN_RECIPES.contains(&(path, call.target))
            {
                continue;
            }
            if let Some(reason) = unresolved(&root, call.target) {
                stale.push(format!("{path}: `just {}`: {reason}", call.target));
            }
        }
    }
    assert!(
        stale.is_empty(),
        "stale recipe names:\n{}",
        stale.join("\n")
    );
}

#[test]
fn the_call_scanner_reads_namespaced_bare_and_flag_invocations() {
    let calls = just_calls(
        "run `just lints::fmt`, then just ci; `just --list` and `just\nclippy` and adjust x",
    );
    let targets: Vec<(&str, bool)> = calls
        .iter()
        .map(|call| (call.target, call.backticked))
        .collect();
    assert_eq!(
        targets,
        [("lints::fmt", true), ("ci", false), ("clippy", true)]
    );
}

#[test]
fn a_namespaced_or_misspelled_recipe_is_unresolved() {
    let root: BTreeSet<&str> = ["lint"].into();
    assert_eq!(unresolved(&root, "lint"), None);
    assert!(unresolved(&root, "lints::clippy").is_some());
    assert!(unresolved(&root, "clippy").is_some());
}

#[test]
fn a_split_compound_command_is_reported_only_without_a_shebang() {
    let text = "\
lint SUBSET=\"all\":
    case x in
    a) true ;;
    esac

# a comment ends the body
inline:
    if true; then echo ok; fi

script:
    #!/usr/bin/env bash
    case x in
    esac
";
    let parsed = recipes(text);
    let found: Vec<(&str, Option<&str>)> = parsed
        .iter()
        .map(|recipe| (recipe.name, split_compound_line(recipe)))
        .collect();
    assert_eq!(
        found,
        [
            ("lint", Some("case x in")),
            ("inline", None),
            ("script", None)
        ]
    );
}
