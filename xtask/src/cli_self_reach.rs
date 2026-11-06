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

/// `Some(reason)` when `file` is a library file that runs the CLI unguarded.
fn unguarded_cli_reach(file: &str, source: &str) -> Option<String> {
    let crate_name = file.strip_prefix("crates/")?.split('/').next()?;
    let skipped = CLI_SIDE.contains(&crate_name)
        || file.contains("/src/bin/")
        || file.contains("/tests/")
        || file.contains("/benches/")
        || file.ends_with("tests.rs")
        || file.ends_with("/test_support.rs");
    if skipped {
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
    for_each_file(&workspace.join("crates"), None, &mut |path, text| {
        let rel = path
            .strip_prefix(workspace)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if rel.ends_with(".rs") {
            out.extend(unguarded_cli_reach(&rel, text));
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
    fn the_workspace_holds_the_rule() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let found = findings(root).unwrap();
        assert!(found.is_empty(), "{found:#?}");
    }
}
