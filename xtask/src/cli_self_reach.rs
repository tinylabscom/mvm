//! The structural half of `check-no-cli-shellout`.
//!
//! The SDK and hostlib trees are scanned for process APIs by name, and the
//! client for a spawn that names `mvmctl` on one line. None of that sees the
//! library crates underneath the client: a spawn in `mvm-build` or `mvm-vmm`
//! that re-runs the current executable, or `mvmctl` through a path variable,
//! has no `mvmctl` beside its constructor. This pass closes that by file
//! rather than by line:
//!
//! - A production file below the CLI that both builds a process and resolves
//!   the CLI (`current_exe()`, `CLI_BIN`, or a hidden `"__verb"` literal) must
//!   route through `refuse_cli_spawn`, `CliSpawn` or `resolve_verified_for`
//!   (which refuses first), so a library embedder refuses instead of running
//!   `mvmctl`.
//! - No crate below the CLI may depend on `mvm-cli` or `mvm-capture`, the two
//!   crates whose job is to run the CLI. Reaching them transitively through
//!   the client would make every guard above moot.
//!
//! `src/bin/` entry points are separate processes with their own role and are
//! not library code an embedder links.

use std::path::Path;
use std::sync::OnceLock;

use anyhow::Result;
use regex::Regex;

use crate::fs_walk::for_each_file;
use crate::rust_source::{
    CommentSyntax, blank_comments, blank_comments_and_strings, blank_ranges, cfg_test_item_ranges,
};

/// Crates whose purpose is to run the CLI, or to test it.
const CLI_SIDE: &[&str] = &["mvm-cli", "mvm-capture", "mvm-conformance"];

/// Crates nothing below the CLI may depend on.
const NOT_LINKABLE: &[&str] = &["mvm-cli", "mvm-capture"];

/// Files that build a process and resolve the CLI today. Some only hold the
/// resolver or run a test binary; the list pins the set, not a verdict. Shrink-only: pay a site down by replacing it
/// with a typed client call and deleting its line here.
const KNOWN_REACHES: &[&str] = &[
    "crates/mvm-backends/src/driver/qemu_process.rs",
    "crates/mvm-build/src/builder_egress_process.rs",
    "crates/mvm-build/src/builder_vm_bootstrap.rs",
    "crates/mvm-capture/src/verify.rs",
    "crates/mvm-cli/src/commands/build/kernel.rs",
    "crates/mvm-cli/src/commands/env/builder_vm/vm_helpers.rs",
    "crates/mvm-cli/src/commands/env/uninstall.rs",
    "crates/mvm-cli/src/commands/pool/refill.rs",
    "crates/mvm-cli/src/test_boot_payload.rs",
    "crates/mvm-cli/src/update.rs",
    "crates/mvm-hostd/src/health_probe.rs",
    "crates/mvm-vmm/src/host/aux_bin.rs",
];

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid static pattern"))
}

fn builds_a_process(code: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    regex(
        &R,
        r"\bhelper_command\w*\s*\(|\bCommand\s*::\s*new\s*\(|\bwrap_checked\s*\(",
    )
    .is_match(code)
}

fn resolves_the_cli(code: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    regex(
        &R,
        r#"\bcurrent_exe\s*\(\s*\)|\bCLI_BIN\b|"__[a-z][a-z-]+""#,
    )
    .is_match(code)
}

fn routes_through_the_refusal(code: &str) -> bool {
    ["refuse_cli_spawn", "CliSpawn::", "resolve_verified_for"]
        .iter()
        .any(|guard| code.contains(guard))
}

/// Production code of `source`: comments and `#[cfg(test)]` items blanked,
/// literals kept.
fn production_code(source: &str) -> String {
    let tests = cfg_test_item_ranges(&blank_comments_and_strings(source));
    blank_ranges(&blank_comments(source, CommentSyntax::Rust), &tests)
}

/// Files the inventory does not read: separate processes, tests and benches.
fn is_test_or_bin(file: &str) -> bool {
    file.contains("/src/bin/")
        || file.contains("/tests/")
        || file.contains("/benches/")
        || file.ends_with("tests.rs")
        || file.ends_with("/test_support.rs")
}

/// Whether production code in `source` both builds a process and resolves the
/// CLI: a place `mvmctl` can be run from.
fn reaches_the_cli(file: &str, source: &str) -> bool {
    if is_test_or_bin(file) {
        return false;
    }
    let code = production_code(source);
    builds_a_process(&code) && resolves_the_cli(&code)
}

/// Every file that reaches the CLI must be listed in [`KNOWN_REACHES`], and
/// every listed file must still reach it: the list only shrinks.
fn inventory_findings(seen: &[String]) -> Vec<String> {
    let new = seen
        .iter()
        .filter(|f| !KNOWN_REACHES.contains(&f.as_str()))
        .map(|f| {
            format!(
                "{f}: builds a process and resolves the CLI but is not in KNOWN_REACHES; \
                 a new CLI-reaching spawn site needs a typed client call instead"
            )
        });
    let stale = KNOWN_REACHES
        .iter()
        .filter(|k| !seen.iter().any(|f| f == *k))
        .map(|k| format!("{k}: listed in KNOWN_REACHES but no longer reaches the CLI; remove it"));
    new.chain(stale).collect()
}

/// `Some(reason)` when `file` is a library file that runs the CLI unguarded.
fn unguarded_cli_reach(file: &str, source: &str) -> Option<String> {
    let crate_name = file.strip_prefix("crates/")?.split('/').next()?;
    if CLI_SIDE.contains(&crate_name) || is_test_or_bin(file) {
        return None;
    }
    let code = production_code(source);
    (builds_a_process(&code) && resolves_the_cli(&code) && !routes_through_the_refusal(&code)).then(
        || {
            format!(
                "{file}: builds a process and resolves the CLI without `refuse_cli_spawn`; \
                 a library embedder would run `mvmctl`"
            )
        },
    )
}

/// A dependency on a crate nothing below the CLI may link, declared in `manifest`.
fn cli_side_dependency(manifest: &str) -> Option<&'static str> {
    manifest.lines().find_map(|line| {
        let name = line.split(['=', '.', ' ']).next()?.trim();
        NOT_LINKABLE.iter().copied().find(|c| *c == name)
    })
}

pub(crate) fn findings(workspace: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut seen = Vec::new();
    // This module is compiled only for tests and the explicit test-support feature.
    // Its current-exe spawn runs the exact test binary, not the application CLI.
    let test_env_is_gated =
        match std::fs::read_to_string(workspace.join("crates/mvm-core/src/util/mod.rs")) {
            Ok(source) => {
                source.contains("#[cfg(any(test, feature = \"test-support\"))]\npub mod test_env;")
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
            Err(err) => return Err(err.into()),
        };
    for_each_file(&workspace.join("crates"), None, &mut |path, text| {
        let rel = path
            .strip_prefix(workspace)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if rel.ends_with(".rs") {
            if rel == "crates/mvm-core/src/util/test_env.rs" && test_env_is_gated {
                return;
            }
            out.extend(unguarded_cli_reach(&rel, text));
            if reaches_the_cli(&rel, text) {
                seen.push(rel);
            }
        } else if rel.ends_with("/Cargo.toml") {
            let owner = rel.split('/').nth(1).unwrap_or_default();
            if !CLI_SIDE.contains(&owner)
                && let Some(dep) = cli_side_dependency(text)
            {
                out.push(format!(
                    "{rel}: depends on `{dep}`, which runs the CLI; nothing below the CLI may link it"
                ));
            }
        }
    })?;
    // The shrink-only list describes the whole workspace, not the partial
    // source trees used by check-no-cli-shellout's fixture tests.
    if workspace.join("Cargo.toml").is_file() {
        seen.sort();
        out.extend(inventory_findings(&seen));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIB: &str = "crates/mvm-build/src/x.rs";

    #[test]
    fn a_self_reexec_without_the_refusal_is_flagged() {
        let src = "fn f() { let p = std::env::current_exe().unwrap(); helper_command(p); }";
        assert!(unguarded_cli_reach(LIB, src).is_some());
    }

    #[test]
    fn the_refusal_clears_the_file() {
        let src =
            "fn f(h: &H) { h.refuse_cli_spawn(CliSpawn::X)?; helper_command(current_exe()?); }";
        assert!(unguarded_cli_reach(LIB, src).is_none());
    }

    #[test]
    fn the_verified_resolver_refuses_first_so_it_clears_the_file() {
        let src = "fn f(h: &H) { let p = resolve_verified_for(&CLI_BIN, h)?; helper_command(p); }";
        assert!(unguarded_cli_reach(LIB, src).is_none());
    }

    #[test]
    fn a_data_literal_naming_mvmctl_is_not_a_reach() {
        let src = "fn f() { helper_command(\"debugfs\"); let tool = \"mvmctl\"; }";
        assert!(unguarded_cli_reach(LIB, src).is_none());
    }

    #[test]
    fn a_hidden_verb_literal_counts_as_resolving_the_cli() {
        let src = "fn f(p: &Path) { helper_command(p).arg(\"__builder-egress-supervisor\"); }";
        assert!(unguarded_cli_reach(LIB, src).is_some());
    }

    #[test]
    fn a_process_without_the_cli_and_the_cli_without_a_process_are_fine() {
        assert!(unguarded_cli_reach(LIB, "fn f() { helper_command(\"mkfs\"); }").is_none());
        assert!(unguarded_cli_reach(LIB, "fn f() { let _ = current_exe(); }").is_none());
    }

    #[test]
    fn comments_and_test_modules_do_not_count() {
        let src = "// helper_command(current_exe())\nfn f() {}\n#[cfg(test)]\nmod t { fn g() { helper_command(current_exe().unwrap()); } }\n";
        assert!(unguarded_cli_reach(LIB, src).is_none());
    }

    #[test]
    fn the_cli_side_bins_and_tests_are_exempt() {
        let src = "fn f() { helper_command(current_exe().unwrap()); }";
        for file in [
            "crates/mvm-cli/src/x.rs",
            "crates/mvm-capture/src/x.rs",
            "crates/mvm-hostd/src/bin/endpoint.rs",
            "crates/mvm-vmm/tests/x.rs",
            "crates/mvm-vmm/src/host/x_tests.rs",
        ] {
            assert!(unguarded_cli_reach(file, src).is_none(), "{file}");
        }
        assert!(
            unguarded_cli_reach("crates/mvm-core/src/util/test_env.rs", src).is_some(),
            "the test-only module must be checked if its feature gate is removed"
        );
    }

    #[test]
    fn linking_the_cli_side_is_flagged() {
        let dep = "[dependencies]\nmvm-capture.workspace = true\n";
        assert_eq!(cli_side_dependency(dep), Some("mvm-capture"));
        assert_eq!(
            cli_side_dependency("mvm-cli = { path = \"x\" }\n"),
            Some("mvm-cli")
        );
        assert_eq!(cli_side_dependency("mvm-client.workspace = true\n"), None);
        assert_eq!(cli_side_dependency("# mvm-cli is the CLI\n"), None);
    }

    #[test]
    fn an_unlisted_reach_and_a_stale_entry_both_fail() {
        let seen = vec!["crates/mvm-build/src/new_site.rs".to_owned()];
        let found = inventory_findings(&seen);
        assert!(
            found
                .iter()
                .any(|f| f.contains("new_site.rs") && f.contains("not in"))
        );
        let listed: Vec<String> = KNOWN_REACHES.iter().map(|s| (*s).to_owned()).collect();
        assert!(inventory_findings(&listed).is_empty());
        if let Some(first) = KNOWN_REACHES.first() {
            let missing: Vec<String> = listed.into_iter().skip(1).collect();
            assert!(
                inventory_findings(&missing)
                    .iter()
                    .any(|f| f.contains(first))
            );
        }
    }

    #[test]
    fn the_inventory_reads_cli_side_crates_but_not_tests() {
        let src = "fn f() { helper_command(current_exe().unwrap()); }";
        assert!(reaches_the_cli("crates/mvm-cli/src/x.rs", src));
        assert!(!reaches_the_cli("crates/mvm-cli/tests/x.rs", src));
        assert!(!reaches_the_cli(
            "crates/mvm-cli/src/x.rs",
            "fn f() { helper_command(\"a\"); }"
        ));
    }

    #[test]
    fn partial_fixtures_skip_the_workspace_inventory_but_not_the_structural_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("crates/mvm-build/src");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("x.rs"),
            "fn f() { helper_command(current_exe()?); }",
        )
        .unwrap();
        let found = findings(tmp.path()).unwrap();
        assert!(
            found
                .iter()
                .any(|f| f.contains("without `refuse_cli_spawn`"))
        );
        assert!(!found.iter().any(|f| f.contains("KNOWN_REACHES")));

        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        let found = findings(tmp.path()).unwrap();
        assert!(found.iter().any(|f| f.contains("KNOWN_REACHES")));
    }

    #[test]
    fn the_workspace_holds_the_rule() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let found = findings(root).unwrap();
        assert!(found.is_empty(), "{found:#?}");
    }
}
