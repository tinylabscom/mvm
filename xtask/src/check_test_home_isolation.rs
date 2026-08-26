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
//! Four rules keep that class closed:
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
//! 4. `seed-caller-isolation` — a test that *calls* a seeding resolver must
//!    isolate `HOME` even when it never moves `MVM_HOME`. Rule 2 misses that
//!    shape entirely, and it is the shape the initramfs cold-cache assertion
//!    had: it passed a tempdir as the cache root, looked isolated, and seeded
//!    from the real `$HOME` behind its own assertion.
//!
//! Rule 3 deliberately does no reachability analysis, and that is the point:
//! the child is a whole `mvmctl`, so it reaches *every* seed regardless of
//! what the spawning test file imports. Rule 2 cannot see these at all — such
//! a fixture names none of the seed symbols, and it builds its `Command` in a
//! shared helper rather than inside a `#[test]` body, which is the second
//! thing rule 2 keys on.
//!
//! Rules 2 and 4 read test-function bodies, so between them they cover the
//! in-process `TestEnv` patterns the known failures came from — rule 2 the
//! tests that relocate `MVM_HOME`, rule 4 the ones that never touch it and
//! reach a seed anyway. Rule 4 skips `#[ignore]`d live tests, which assert
//! against real host state by construction, and skips seed sites, which drive
//! the seam with roots they pass explicitly.

use anyhow::{Result, bail};
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Rule {
    DefaultCacheCaller,
    TestHomeIsolation,
    SubprocessHomeIsolation,
    SeedCallerIsolation,
}

impl Rule {
    fn label(self) -> &'static str {
        match self {
            Rule::DefaultCacheCaller => "default-cache-caller",
            Rule::TestHomeIsolation => "test-home-isolation",
            Rule::SubprocessHomeIsolation => "subprocess-home-isolation",
            Rule::SeedCallerIsolation => "seed-caller-isolation",
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
    (
        "crates/mvm-conformance/tests/conformance.rs",
        "resolves the prebuilt workload kernel a `@workload_kernel` scenario boots. \
         The seed is the point: the step copies that kernel into the scenario's \
         isolated cache so a volume test does not have to build one. It cannot \
         mask an absence assertion, because the scenarios assert about volume \
         bytes and write refusal, never about whether a kernel is cached",
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

    // A seed site owns the cross-root seam and drives it with roots it passes
    // explicitly, so rule 3 there would only ever flag its own fixtures.
    let is_seed_site = SEED_SITES.iter().any(|(path, _)| *path == rel);

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
            continue;
        }
        if is_seed_site {
            continue;
        }
        // An `#[ignore]`d live test is outside the hermetic suite by
        // construction: it asserts against real host state — a bootstrapped
        // builder image, a running VMM — and isolating HOME would defeat the
        // thing it exists to prove. The rule protects the suite that actually
        // runs on a contributor's machine.
        if block.body.contains("#[ignore") {
            continue;
        }
        if let Some(anchor) = called_seed_anchor(block.body)
            && !isolates_home(block.body)
        {
            push(
                &mut hits,
                block.line,
                Rule::SeedCallerIsolation,
                format!(
                    "test `{}` calls `{anchor}`, which seeds from the real $HOME, without isolating HOME",
                    block.name
                ),
            );
        }
    }
    hits
}

/// The seed anchor a test body names, if any.
///
/// Rule 2 only fires on a test that *moves* `MVM_HOME`. A test that never
/// touches it but calls a seeding resolver directly reads the developer's real
/// `$HOME` just the same — that is the shape the initramfs cold-cache assertion
/// had: green in CI's empty `$HOME`, red on every machine that had ever built
/// the artifact, and blind to the regression it was written to catch.
fn called_seed_anchor(body: &str) -> Option<&'static str> {
    SEED_ANCHORS
        .iter()
        .copied()
        .find(|anchor| body_calls(body, anchor))
}

/// A call, not a mention: skip comment lines so the rule reads code only.
fn body_calls(body: &str, anchor: &str) -> bool {
    body.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .any(|line| line.contains(anchor))
}

struct TestBlock<'a> {
    line: usize,
    name: &'a str,
    body: &'a str,
}

/// Split `src` into one block per test, each bounded by that test function's
/// own body.
///
/// Bounding a block at the *next* test attribute is wrong in a way that is easy
/// to miss: the last test in a `#[cfg(test)]` module then runs on through the
/// production code that follows it and into the next test module. In
/// `mvm-cli/src/exec.rs`, which has two test modules, that made one block 1770
/// lines long and let it "call" any symbol in the file. A two-condition rule
/// rarely trips over that; a single-condition rule reads it as a false positive
/// every time. Brace-matching the function body is the boundary that actually
/// matches what the rules mean by "this test does X".
fn test_blocks(src: &str) -> Vec<TestBlock<'_>> {
    test_attribute_offsets(src)
        .into_iter()
        .filter_map(|start| {
            let body = function_body_from(src, start)?;
            Some(TestBlock {
                line: src[..start].lines().count() + 1,
                name: test_fn_name(&src[start..]).unwrap_or("<unnamed>"),
                body,
            })
        })
        .collect()
}

/// The `fn ... { ... }` that follows the attribute at `start`, as a slice of
/// `src`. Returns `None` when no balanced body follows (a malformed or
/// truncated file), which drops the block rather than over-reading.
fn function_body_from(src: &str, start: usize) -> Option<&str> {
    let open = src[start..].find('{')? + start;
    let bytes = src.as_bytes();
    let mut depth = 0usize;
    let mut idx = open;
    while idx < bytes.len() {
        match bytes[idx] {
            b'/' if bytes.get(idx + 1) == Some(&b'/') => {
                idx = src[idx..].find('\n').map_or(bytes.len(), |n| idx + n);
                continue;
            }
            b'/' if bytes.get(idx + 1) == Some(&b'*') => {
                idx = src[idx + 2..]
                    .find("*/")
                    .map_or(bytes.len(), |n| idx + 2 + n + 2);
                continue;
            }
            b'"' => {
                idx += 1;
                while idx < bytes.len() && bytes[idx] != b'"' {
                    idx += if bytes[idx] == b'\\' { 2 } else { 1 };
                }
            }
            // A char literal, not a lifetime: `'{'` would otherwise unbalance
            // the count. Lifetimes have no closing quote and fall through.
            b'\'' if bytes.get(idx + 2) == Some(&b'\'') => idx += 2,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&src[start..=idx]);
                }
            }
            _ => {}
        }
        idx += 1;
    }
    None
}

fn test_attribute_offsets(src: &str) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut at = 0usize;
    for line in src.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[")
            && trimmed.contains("test")
            && !trimmed.starts_with("#[cfg(test)")
        {
            offsets.push(at + (line.len() - trimmed.len()));
        }
        at += line.len();
    }
    offsets
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

    /// Rule 3's motivating shape: a test that never touches `MVM_HOME` but
    /// calls a seeding resolver still reads the real `$HOME`.
    #[test]
    fn flags_a_seed_caller_that_never_moves_mvm_home() {
        let src = format!(
            "{ANCHORED}\
             #[cfg(test)]\nmod t {{\n    #[test]\n    fn cold() {{\n\
             let dir = tempdir();\n        resolve_or_seed_from_default_cache(&dir);\n    }}\n}}\n"
        );
        let hits = scan_source("crates/mvm-build/src/thing.rs", &src);
        assert!(
            hits.iter().any(|h| h.contains("seed-caller-isolation")),
            "expected a seed-caller hit, got {hits:?}"
        );
    }

    #[test]
    fn accepts_a_seed_caller_that_isolates_home() {
        let src = format!(
            "{ANCHORED}\
             #[cfg(test)]\nmod t {{\n    #[test]\n    fn cold() {{\n\
             env.isolate_mvm_home(dir.path());\n        resolve_or_seed_from_default_cache(&dir);\n    }}\n}}\n"
        );
        assert!(scan_source("crates/mvm-build/src/thing.rs", &src).is_empty());
    }

    /// An `#[ignore]`d live test asserts against real host state on purpose.
    #[test]
    fn skips_an_ignored_live_seed_caller() {
        let src = format!(
            "{ANCHORED}\
             #[cfg(test)]\nmod t {{\n    #[test]\n    #[ignore = \"live\"]\n    fn live() {{\n\
             ensure_builder_vm_image();\n    }}\n}}\n"
        );
        assert!(scan_source("crates/mvm-build/src/thing.rs", &src).is_empty());
    }

    /// A test block stops at its own closing brace. Without that, the last
    /// test in a `#[cfg(test)]` module runs on through the production code
    /// after it and "calls" every symbol there.
    #[test]
    fn a_test_block_does_not_leak_into_the_code_after_its_module() {
        let src = format!(
            "{ANCHORED}\
             #[cfg(test)]\nmod t {{\n    #[test]\n    fn harmless() {{\n        let x = 1;\n    }}\n}}\n\
             fn production() {{\n    ensure_builder_vm_image();\n}}\n"
        );
        let hits = scan_source("crates/mvm-cli/src/thing.rs", &src);
        assert!(
            hits.is_empty(),
            "a test must not be blamed for production code after its module: {hits:?}"
        );
    }

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
