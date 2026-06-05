//! `xtask check-core-runtime-free`
//!
//! Assert that `mvm-core`'s **default** feature closure pulls no async
//! runtime (plan 126 B5). This is deliberately *not* part of
//! `check-forbidden-deps`: that check is lockfile-name-based, and `tokio`
//! is legitimately in `Cargo.lock` (mvm-hostd, mvm, and the gated
//! `mvm-core/hostd-transport` + `manifest-verify` features all pull it).
//! What must stay true is narrower — a *default* `mvm-core` build does
//! not link tokio — which is a feature-resolution fact, so we read it
//! from `cargo tree` rather than the lockfile.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

/// Async-runtime crates that must not appear in mvm-core's default tree.
const RUNTIME_CRATES: &[&str] = &["tokio"];

pub fn run(workspace: &Path) -> Result<()> {
    // `-e no-dev` excludes dev-deps (mvm-core keeps a tokio dev-dep so the
    // gated `hostd-transport` tests build); `--prefix none` makes every
    // line start with the crate name. Resolved with the workspace's
    // default features, so if any member enables `hostd-transport` in the
    // default build, tokio surfaces here and the gate trips.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .current_dir(workspace)
        .args([
            "tree", "-p", "mvm-core", "-e", "no-dev", "--prefix", "none", "--locked",
        ])
        .output()
        .context("running `cargo tree -p mvm-core -e no-dev`")?;

    if !output.status.success() {
        bail!(
            "cargo tree failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let tree = String::from_utf8_lossy(&output.stdout);
    let mut found: Vec<&str> = tree
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| RUNTIME_CRATES.contains(name))
        .collect();
    found.sort_unstable();
    found.dedup();

    if !found.is_empty() {
        bail!(
            "check-core-runtime-free: mvm-core's default build pulls an async runtime ({}). \
             The hostd IPC transport must stay behind the `hostd-transport` feature (plan 126 \
             B5) — a workspace member likely enabled it in the default closure, or it crept \
             back into `mvm-core`'s `default`.",
            found.join(", ")
        );
    }

    eprintln!("check-core-runtime-free: clean (mvm-core default closure pulls no tokio)");
    Ok(())
}

#[cfg(test)]
mod tests {
    /// Mirror the parse the gate runs over `cargo tree --prefix none`
    /// output: each line begins with the crate name.
    fn runtime_hits<'a>(tree: &'a str, runtime: &[&str]) -> Vec<&'a str> {
        let mut hits: Vec<&str> = tree
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .filter(|name| runtime.contains(name))
            .collect();
        hits.sort_unstable();
        hits.dedup();
        hits
    }

    #[test]
    fn clean_tree_has_no_runtime() {
        let tree = "mvm-core v0.15.2\nanyhow v1.0.99\nserde v1.0.0\ntar v0.4.45\n";
        assert!(runtime_hits(tree, &["tokio"]).is_empty());
    }

    #[test]
    fn tree_with_tokio_is_flagged() {
        let tree = "mvm-core v0.15.2\ntokio v1.48.0\nserde v1.0.0\n";
        assert_eq!(runtime_hits(tree, &["tokio"]), vec!["tokio"]);
    }

    #[test]
    fn substring_match_does_not_false_positive() {
        // `tokio-util` is not `tokio`; the gate keys on the exact name.
        let tree = "mvm-core v0.15.2\ntokio-util v0.7.0\n";
        assert!(runtime_hits(tree, &["tokio"]).is_empty());
    }
}
