//! The root justfile is a deliberately small, CI-mirroring surface; the
//! modules under `just/` carry everything else. These guards pin that
//! shape so the surface cannot quietly grow back, and check that what the
//! surface promises can run: every recipe a justfile or a contributor doc
//! names exists, and every recipe body is something the shell can parse.

use std::collections::{BTreeMap, BTreeSet};
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
    "crates/mvm-sdk/src/compile/orchestrator.rs",
    "nix/wrappers/README.md",
    "public/src/content/docs/contributing/ai-coding-workflow.md",
    "public/src/content/docs/contributing/development.md",
];

/// Calls into another repository's justfile, by doc and recipe. The release
/// table in the README names the command each train is cut with, and the
/// image train is cut from mvm-images.
const FOREIGN_RECIPES: &[(&str, &str)] = &[("README.md", "release")];

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

/// `mod <name> '<path>'` declarations in the root justfile.
fn declared_modules() -> BTreeMap<&'static str, String> {
    JUSTFILE
        .lines()
        .filter_map(|line| line.strip_prefix("mod "))
        .map(|decl| {
            let mut parts = decl.split_whitespace();
            let name = parts.next().expect("mod name");
            let path = parts
                .next()
                .expect("mod path")
                .trim_matches(|c| c == '\'' || c == '"')
                .to_string();
            (name, path)
        })
        .collect()
}

/// The root justfile and every declared module, keyed by path.
fn justfile_sources() -> Vec<(String, String)> {
    let mut sources = vec![("Justfile".to_string(), JUSTFILE.to_string())];
    for path in declared_modules().into_values() {
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {path}: {error}"));
        sources.push((path, text));
    }
    sources
}

/// The recipes callable as `just <name>`, and as `just <module>::<name>`.
struct Callable {
    root: BTreeSet<String>,
    modules: BTreeMap<String, BTreeSet<String>>,
}

impl Callable {
    fn load() -> Self {
        let names = |text: &str| -> BTreeSet<String> {
            recipes(text)
                .iter()
                .map(|recipe| recipe.name.to_string())
                .collect()
        };
        let modules = declared_modules()
            .into_iter()
            .map(|(module, path)| {
                let text = fs::read_to_string(&path)
                    .unwrap_or_else(|error| panic!("failed to read {path}: {error}"));
                (module.to_string(), names(&text))
            })
            .collect();
        Self {
            root: names(JUSTFILE),
            modules,
        }
    }

    /// Why `target` does not name a recipe, or `None` when it does.
    fn unresolved(&self, target: &str) -> Option<String> {
        match target.split_once("::") {
            Some((module, recipe)) => match self.modules.get(module) {
                None => Some(format!("no module `{module}`")),
                Some(names) if !names.contains(recipe) => {
                    Some(format!("module `{module}` has no recipe `{recipe}`"))
                }
                Some(_) => None,
            },
            None if self.root.contains(target) => None,
            None => Some(format!("no top-level recipe `{target}`")),
        }
    }
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

/// Recipe and module names share one namespace, so the top level is exactly
/// this set — no more, no fewer.
#[test]
fn root_recipes_are_exactly_the_ci_mirror_set() {
    let names: BTreeSet<&str> = recipes(JUSTFILE).iter().map(|recipe| recipe.name).collect();
    assert_eq!(
        names.into_iter().collect::<Vec<_>>(),
        [
            "build",
            "ci",
            "default",
            "docs",
            "embed",
            "lint",
            "release-build",
            "test"
        ],
        "the root justfile surface changed — update this guard and the docs deliberately"
    );
}

/// Every module the root justfile declares. `include_str!` proves each file
/// exists at compile time, so a deleted or renamed module breaks this test
/// target's build rather than failing only at `just --list` time.
#[test]
fn declared_modules_exist() {
    let _audit = include_str!("../just/audit/mod.just");
    let _bdd = include_str!("../just/bdd/mod.just");
    let _check = include_str!("../just/check/mod.just");
    let _e2e = include_str!("../just/e2e/mod.just");
    let _kernel = include_str!("../just/kernel/mod.just");
    let _lab = include_str!("../just/lab/mod.just");
    let _lints = include_str!("../just/lints/mod.just");
    let _maint = include_str!("../just/maint/mod.just");
    let _mem = include_str!("../just/mem/mod.just");
    let _payload = include_str!("../just/payload/mod.just");
    let _release = include_str!("../just/release/mod.just");
    let _sdk = include_str!("../just/sdk/mod.just");
    let _site = include_str!("../just/site/mod.just");
    let _tests = include_str!("../just/tests/mod.just");
}

/// The list above is only a guard if it is the whole list: a module added to
/// the root justfile without a line there would go unchecked.
#[test]
fn declared_modules_are_exactly_the_pinned_set() {
    let declared: Vec<&str> = declared_modules().into_keys().collect();
    assert_eq!(
        declared,
        [
            "audit", "bdd", "check", "e2e", "kernel", "lab", "lints", "maint", "mem", "payload",
            "release", "sdk", "site", "tests"
        ],
        "a module was added or removed — update `declared_modules_exist` to match"
    );
}

/// `lint`, `tests::ci` and `tests::cargo` each shipped a multi-line `if` or
/// `case` without a shebang, so every invocation died on `sh: syntax error:
/// unexpected end of file` — and `ci` depends on `lint`, so the whole local
/// gate did too. A compound command spread over lines needs a shebang recipe.
#[test]
fn compound_shell_commands_only_span_lines_in_shebang_recipes() {
    let mut broken = Vec::new();
    for (path, text) in justfile_sources() {
        for recipe in recipes(&text) {
            if let Some(line) = split_compound_line(&recipe) {
                broken.push(format!("{path}: `{}`: {line}", recipe.name));
            }
        }
    }
    assert!(
        broken.is_empty(),
        "these recipes split a shell compound command across lines without a \
         shebang, so each line runs in its own shell and the first fails to \
         parse:\n{}",
        broken.join("\n")
    );
}

/// `lint` called `just lint::clippy` while the module is `lints`, which fails
/// only when that arm runs. Resolve every call statically: namespaced calls
/// anywhere in the justfiles, bare ones that start a body line or a code span.
#[test]
fn every_just_call_in_the_justfiles_names_a_real_recipe() {
    let callable = Callable::load();
    let mut stale = Vec::new();
    for (path, text) in justfile_sources() {
        for line in text.lines() {
            let trimmed = line.trim_start();
            let body_command = line.starts_with(char::is_whitespace)
                && (trimmed.starts_with("just ") || trimmed.starts_with("@just "));
            for call in just_calls(line) {
                if !call.target.contains("::") && !body_command && !call.backticked {
                    continue;
                }
                if let Some(reason) = callable.unresolved(call.target) {
                    stale.push(format!("{path}: `just {}`: {reason}", call.target));
                }
            }
        }
    }
    assert!(
        stale.is_empty(),
        "stale recipe calls:\n{}",
        stale.join("\n")
    );
}

/// The docs kept naming recipes from before the surface was namespaced
/// (`just fmt`, `just check-gated`, `just bdd`). A bare name must be a
/// top-level recipe; a namespaced one must exist in its module.
#[test]
fn contributor_docs_name_real_recipes() {
    let callable = Callable::load();
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
            if let Some(reason) = callable.unresolved(call.target) {
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
fn a_misspelled_module_or_recipe_is_unresolved() {
    let callable = Callable {
        root: ["lint".to_string()].into(),
        modules: [("lints".to_string(), ["clippy".to_string()].into())].into(),
    };
    assert_eq!(callable.unresolved("lints::clippy"), None);
    assert_eq!(callable.unresolved("lint"), None);
    assert!(callable.unresolved("lint::clippy").is_some());
    assert!(callable.unresolved("lints::fmt").is_some());
    assert!(callable.unresolved("clippy").is_some());
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

#[test]
fn test_module_keeps_scoped_runs_without_the_removed_cache_wrapper() {
    let tests = include_str!("../just/tests/mod.just");
    assert!(tests.contains("scoped CRATE FILTER=\"\""));
    assert!(tests.contains("nextest run -p {{ CRATE }} -E 'test({{ FILTER }})'"));
    assert!(!tests.contains("cached FILTER="));
}
