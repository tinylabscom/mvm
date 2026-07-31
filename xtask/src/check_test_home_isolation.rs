//! `xtask check-test-home-isolation`
//!
//! `MVM_HOME` relocates the whole mvm tree, so a test that points it at a
//! tempdir looks isolated. It isn't. `default_mvm_cache_dir` deliberately
//! ignores `MVM_HOME` and reads `$HOME/.mvm/cache` directly, so an isolated
//! session can seed expensive artifacts — the builder VM image, the runtime
//! overlay — from the host's shared cache instead of rebuilding them. That
//! seed is correct for real use and ruinous under test: a test asserting an
//! artifact is *absent* gets a real one copied in behind its back and passes
//! for the wrong reason. It passes only on a machine that has never built
//! one. CI is such a machine and a contributor's laptop is not, so the suite
//! reads green in CI while the same test is red for everyone else — and a
//! genuine regression in the code under test is masked either way.
//!
//! Three rules keep that class closed:
//!
//! 1. `default-cache-caller` — `default_mvm_cache_dir` is the only resolver
//!    that reads `$HOME` while `MVM_HOME` is set, so it is the only door the
//!    class can grow through. It may be named only from an allowlisted seed
//!    site. Adding an entry is the signal that a new cross-root seed exists,
//!    and it drags that file's tests under rule 2.
//! 2. `test-home-isolation` — in a file that can reach a seed site, a test
//!    that moves `MVM_HOME` must move `HOME` with it.
//!    `TestEnv::isolate_mvm_home` does both; an explicit `HOME` set counts.
//! 3. `subprocess-home-isolation` — in an integration test, a `Command`
//!    handed `MVM_HOME` must be handed `HOME` too.
//!
//! Rule 3 deliberately does no reachability analysis, and that is the point:
//! the child is a whole `mvmctl`, so it reaches *every* seed regardless of
//! what the spawning test file imports. Rule 2 cannot see these at all — such
//! a fixture names none of the seed symbols, and it builds its `Command` in a
//! shared helper rather than inside a `#[test]` body, which is the second
//! thing rule 2 keys on.

use anyhow::{Result, bail};
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Rule {
    DefaultCacheCaller,
    TestHomeIsolation,
    SubprocessHomeIsolation,
}

impl Rule {
    fn label(self) -> &'static str {
        match self {
            Rule::DefaultCacheCaller => "default-cache-caller",
            Rule::TestHomeIsolation => "test-home-isolation",
            Rule::SubprocessHomeIsolation => "subprocess-home-isolation",
        }
    }
}

/// The single resolver that reads `$HOME` even when `MVM_HOME` is set.
const DEFAULT_CACHE_FN: &str = "default_mvm_cache_dir";

/// Files allowed to name [`DEFAULT_CACHE_FN`], with the reason.
const SEED_SITES: &[(&str, &str)] = &[
    (
        "crates/mvm-core/src/config.rs",
        "defines the resolver and owns the deliberate MVM_HOME bypass",
    ),
    (
        "crates/mvm-build/src/cache_install.rs",
        "owns the only cross-root seed: the one derivation of the shared cache root",
    ),
    (
        "xtask/src/check_test_home_isolation.rs",
        "defines the very patterns it scans for",
    ),
];

/// Symbols whose call reaches [`DEFAULT_CACHE_FN`]. A file naming any of
/// them can seed from the real `$HOME`, so its tests must isolate `HOME`.
/// `attach_runtime_overlay` and `attach_universal_initramfs` are matched as
/// prefixes so they also cover the `_if_cached` / `_if_cached_version`
/// wrappers the CLI actually calls.
const SEED_ANCHORS: &[&str] = &[
    DEFAULT_CACHE_FN,
    "default_cache_root",
    "seed_on_miss",
    "ensure_builder_vm_image",
    "resolve_or_seed_from_default_cache",
    "attach_runtime_overlay",
    "attach_universal_initramfs",
];

/// Files exempt from `test-home-isolation`, with the reason.
const ISOLATION_EXEMPT: &[(&str, &str)] = &[(
    "crates/mvm-core/src/config.rs",
    "the resolver's own unit tests assert string derivation and never touch \
     the filesystem; some deliberately diverge HOME from MVM_HOME to pin the \
     ignore-override contract",
)];

pub fn run(workspace: &Path) -> Result<()> {
    let mut hits: Vec<String> = Vec::new();

    for root in ["crates", "src", "xtask", "tests"] {
        walk(&workspace.join(root), &mut |path| {
            scan_file(workspace, path, &mut hits);
        })?;
    }

    if !hits.is_empty() {
        bail!(
            "check-test-home-isolation: {} site(s) can read the developer's real $HOME.\n\
             A test that moves MVM_HOME must move HOME with it — use\n\
             `TestEnv::isolate_mvm_home(root)`, which sets both.\n\
             A genuinely new cross-root seed gets a SEED_SITES entry in\n\
             xtask/src/check_test_home_isolation.rs, with a reason.\n{}",
            hits.len(),
            hits.join("\n")
        );
    }
    eprintln!(
        "check-test-home-isolation: clean (every MVM_HOME test that can reach the default cache also isolates HOME)"
    );
    Ok(())
}

fn scan_file(workspace: &Path, path: &Path, hits: &mut Vec<String>) {
    if path.extension().and_then(|e| e.to_str()) != Some("rs") {
        return;
    }
    let rel = path
        .strip_prefix(workspace)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    let Ok(src) = std::fs::read_to_string(path) else {
        return;
    };
    hits.extend(scan_source(&rel, &src));
}

/// Scan one file's source; returns formatted hit lines. Pure so the unit
/// tests can drive it with fixture text.
fn scan_source(rel: &str, src: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let push = |hits: &mut Vec<String>, line: usize, rule: Rule, detail: String| {
        hits.push(format!("  {rel}:{line}: [{}] {detail}", rule.label()));
    };

    if !SEED_SITES.iter().any(|(path, _)| *path == rel) {
        for (idx, text) in src.lines().enumerate() {
            // A prose mention in a comment is not a call.
            if text.trim_start().starts_with("//") {
                continue;
            }
            if text.contains(DEFAULT_CACHE_FN) {
                push(
                    &mut hits,
                    idx + 1,
                    Rule::DefaultCacheCaller,
                    format!(
                        "{DEFAULT_CACHE_FN} ignores MVM_HOME; declare this seed site: {}",
                        text.trim()
                    ),
                );
            }
        }
    }

    // Rule 3 first: it applies to any integration test, with no dependence on
    // what the file imports, so the seed-anchor early return below must not
    // short-circuit it.
    if is_integration_test(rel) {
        for block in fn_blocks(src) {
            if spawns_with_mvm_home(block.body) && !spawns_with_home(block.body) {
                push(
                    &mut hits,
                    block.line,
                    Rule::SubprocessHomeIsolation,
                    format!(
                        "`{}` gives a subprocess MVM_HOME but not HOME, so the child reads the developer's real cache",
                        block.name
                    ),
                );
            }
        }
    }

    if ISOLATION_EXEMPT.iter().any(|(path, _)| *path == rel) {
        return hits;
    }
    if !SEED_ANCHORS.iter().any(|anchor| src.contains(anchor)) {
        return hits;
    }

    for block in test_blocks(src) {
        if sets_mvm_home(block.body) && !isolates_home(block.body) {
            push(
                &mut hits,
                block.line,
                Rule::TestHomeIsolation,
                format!(
                    "test `{}` moves MVM_HOME but not HOME, and this file can reach the default cache",
                    block.name
                ),
            );
        }
    }
    hits
}

struct TestBlock<'a> {
    line: usize,
    name: &'a str,
    body: &'a str,
}

/// Split `src` into one block per `#[test]`, each running to the next
/// `#[test]` or end of file. Coarse, but a test's env setup always sits
/// between its own attribute and the next one.
fn test_blocks(src: &str) -> Vec<TestBlock<'_>> {
    let starts: Vec<usize> = src.match_indices("#[test]").map(|(at, _)| at).collect();
    starts
        .iter()
        .enumerate()
        .map(|(n, &start)| {
            let end = starts.get(n + 1).copied().unwrap_or(src.len());
            TestBlock {
                line: src[..start].lines().count() + 1,
                name: test_fn_name(&src[start..end]).unwrap_or("<unnamed>"),
                body: &src[start..end],
            }
        })
        .collect()
}

fn test_fn_name(body: &str) -> Option<&str> {
    let at = body.find("fn ")?;
    let rest = &body[at + "fn ".len()..];
    let end = rest.find(|c: char| !c.is_alphanumeric() && c != '_')?;
    Some(&rest[..end])
}

fn sets_mvm_home(body: &str) -> bool {
    [
        "set(\"MVM_HOME\"",
        "set_var(\"MVM_HOME\"",
        "env(\"MVM_HOME\"",
    ]
    .iter()
    .any(|pattern| body.contains(pattern))
}

fn isolates_home(body: &str) -> bool {
    body.contains("isolate_mvm_home")
        || ["set(\"HOME\"", "set_var(\"HOME\"", "env(\"HOME\""]
            .iter()
            .any(|pattern| body.contains(pattern))
}

/// Is this an integration test — a file under a `tests/` directory?
///
/// Those are where subprocess fixtures live. Unit tests inside `src/` drive
/// the code in-process and are rule 2's business.
fn is_integration_test(rel: &str) -> bool {
    rel.starts_with("tests/") || rel.contains("/tests/")
}

/// Split `src` into one block per `fn`, so a fixture that builds its
/// `Command` in a helper is judged as a unit rather than per line.
fn fn_blocks(src: &str) -> Vec<TestBlock<'_>> {
    let starts: Vec<usize> = src.match_indices("fn ").map(|(at, _)| at).collect();
    starts
        .iter()
        .enumerate()
        .map(|(n, &start)| {
            let end = starts.get(n + 1).copied().unwrap_or(src.len());
            TestBlock {
                line: src[..start].lines().count() + 1,
                name: test_fn_name(&src[start..end]).unwrap_or("<unnamed>"),
                body: &src[start..end],
            }
        })
        .collect()
}

fn spawns_with_mvm_home(body: &str) -> bool {
    body.contains("env(\"MVM_HOME\"")
}

fn spawns_with_home(body: &str) -> bool {
    body.contains("env(\"HOME\"") || body.contains("env_clear()")
}

fn walk(dir: &Path, f: &mut dyn FnMut(&Path)) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if matches!(name, "target" | ".git" | "node_modules") {
                continue;
            }
            walk(&path, f)?;
        } else {
            f(&path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANCHORED: &str = "fn helper() { ensure_builder_vm_image() }\n";

    #[test]
    fn flags_mvm_home_without_home_in_a_file_that_reaches_the_seed() {
        let src = format!(
            "{ANCHORED}\
             #[test]\nfn refuses_missing_image() {{\n    env.set(\"MVM_HOME\", d);\n}}\n"
        );
        let hits = scan_source("crates/mvm-build/src/other.rs", &src);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].contains("test-home-isolation"), "{hits:?}");
        assert!(hits[0].contains("refuses_missing_image"), "{hits:?}");
    }

    #[test]
    fn accepts_isolate_mvm_home_helper() {
        let src = format!(
            "{ANCHORED}\
             #[test]\nfn refuses_missing_image() {{\n    env.isolate_mvm_home(d);\n}}\n"
        );
        assert!(scan_source("crates/mvm-build/src/other.rs", &src).is_empty());
    }

    #[test]
    fn accepts_explicit_home_set_alongside_mvm_home() {
        let src = format!(
            "{ANCHORED}\
             #[test]\nfn refuses_missing_image() {{\n    env.set(\"MVM_HOME\", d);\n    env.set(\"HOME\", d);\n}}\n"
        );
        assert!(scan_source("crates/mvm-build/src/other.rs", &src).is_empty());
    }

    #[test]
    fn accepts_subprocess_env_pair() {
        let src = format!(
            "{ANCHORED}\
             #[test]\nfn spawns() {{\n    c.env(\"HOME\", h).env(\"MVM_HOME\", r);\n}}\n"
        );
        assert!(scan_source("crates/mvm-build/src/other.rs", &src).is_empty());
    }

    #[test]
    fn ignores_files_that_cannot_reach_the_seed() {
        let src = "#[test]\nfn unrelated() {\n    env.set(\"MVM_HOME\", d);\n}\n";
        assert!(scan_source("crates/mvm-core/src/domain/session.rs", src).is_empty());
    }

    #[test]
    fn flags_an_undeclared_default_cache_caller() {
        let src = "fn sneak() { let p = default_mvm_cache_dir(); }\n";
        let hits = scan_source("crates/mvm-runtime/src/somewhere.rs", src);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].contains("default-cache-caller"), "{hits:?}");
    }

    #[test]
    fn ignores_a_resolver_mention_in_a_comment() {
        let src =
            "// default_mvm_cache_dir() resolves to ~/.mvm/cache, so point HOME at a tmpdir\n";
        assert!(scan_source("crates/mvm-runtime/src/somewhere.rs", src).is_empty());
    }

    #[test]
    fn allows_declared_seed_sites_to_name_the_resolver() {
        let src = "fn seed() { let p = default_mvm_cache_dir(); }\n";
        assert!(scan_source("crates/mvm-build/src/cache_install.rs", src).is_empty());
    }

    #[test]
    fn exempt_file_skips_the_isolation_rule() {
        let src = format!(
            "{ANCHORED}\
             #[test]\nfn ignores_override() {{\n    env.set(\"MVM_HOME\", d);\n}}\n"
        );
        assert!(scan_source("crates/mvm-core/src/config.rs", &src).is_empty());
    }

    #[test]
    fn flags_a_subprocess_fixture_that_moves_only_mvm_home() {
        let src = "fn mvmctl(&self) -> Command {\n    c.env(\"MVM_HOME\", self.root())\n}\n";
        let hits = scan_source("tests/oci_smoke.rs", src);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].contains("subprocess-home-isolation"), "{hits:?}");
        assert!(hits[0].contains("mvmctl"), "{hits:?}");
    }

    #[test]
    fn subprocess_rule_fires_without_any_seed_anchor_in_the_file() {
        // The whole point of rule 3: the child is a full mvmctl, so the
        // spawning file naming no seed symbol proves nothing.
        let src = "fn spawn() {\n    c.env(\"MVM_HOME\", d);\n}\n";
        assert!(!SEED_ANCHORS.iter().any(|a| src.contains(a)));
        assert_eq!(scan_source("tests/whatever.rs", src).len(), 1);
    }

    #[test]
    fn accepts_a_subprocess_given_both_roots() {
        let src = "fn mvmctl() -> Command {\n    c.env(\"HOME\", h).env(\"MVM_HOME\", r)\n}\n";
        assert!(scan_source("tests/oci_smoke.rs", src).is_empty());
    }

    #[test]
    fn accepts_a_subprocess_with_a_cleared_environment() {
        let src = "fn mvmctl() -> Command {\n    c.env_clear().env(\"MVM_HOME\", r)\n}\n";
        assert!(
            scan_source("tests/oci_smoke.rs", src).is_empty(),
            "env_clear drops the inherited HOME, which is stricter than setting it"
        );
    }

    #[test]
    fn subprocess_rule_covers_crate_local_integration_tests() {
        let src = "fn mvmctl() -> Command {\n    c.env(\"MVM_HOME\", d)\n}\n";
        assert_eq!(scan_source("crates/mvm-cli/tests/cli.rs", src).len(), 1);
    }

    #[test]
    fn subprocess_rule_leaves_in_process_unit_tests_to_rule_two() {
        // A `src/` file driving code in-process is rule 2's business; applying
        // rule 3 there would flag every Command-shaped helper in the tree.
        let src = "fn helper() {\n    c.env(\"MVM_HOME\", d)\n}\n";
        assert!(scan_source("crates/mvm-runtime/src/vm/name_registry.rs", src).is_empty());
    }

    #[test]
    fn test_fn_name_reads_the_first_fn_after_the_attribute() {
        assert_eq!(
            test_fn_name("#[test]\n    fn some_case_name() {\n"),
            Some("some_case_name")
        );
    }

    #[test]
    fn test_blocks_splits_on_each_attribute() {
        let src = "#[test]\nfn a() {}\n#[test]\nfn b() {}\n";
        let blocks = test_blocks(src);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].name, "a");
        assert_eq!(blocks[1].name, "b");
        assert!(blocks[1].line > blocks[0].line);
    }
}
