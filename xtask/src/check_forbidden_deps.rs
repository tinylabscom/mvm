//! `xtask check-forbidden-deps`
//!
//! Two complementary supply-chain ratchets:
//!
//! 1. **Lockfile name ban.** Database stacks outside mvm's threat model
//!    (`sea-*`, `mysql`) must never appear in `Cargo.lock` at all — not
//!    even transitively. Lockfile-based so it catches a pull before code
//!    review has to inspect `cargo tree`.
//! 2. **Default-closure ban.** The deliberately-gated heavy deps
//!    (`sigstore`, `opendal`, `pgp`) were cut from the shipped CLI and
//!    are retained only behind off-by-default features. They legitimately
//!    remain in `Cargo.lock` as optional packages, so a lockfile-name
//!    check would false-positive; instead we assert they stay out of
//!    `mvmctl`'s *default-feature* dependency closure (`cargo tree`).
//!
//! `aws-lc-rs` is a deliberate omission from set (2): it is currently in
//! the default closure via `oci-client -> rustls` and cannot be banned
//! until that is unwound upstream. `tokio` staying out of `mvm-core` is
//! covered by the separate `check-core-runtime-free` gate, not here.

use anyhow::{Context, Result, bail};
use std::path::Path;

/// Banned anywhere in `Cargo.lock` (transitive pulls included).
const FORBIDDEN_PREFIXES: &[&str] = &["sea-"];
const FORBIDDEN_SUBSTRINGS: &[&str] = &["mysql"];

/// Banned from `mvmctl`'s default-feature closure. Exact package names —
/// these are off-by-default-feature-only deps that must not ship in the
/// stock CLI. (`aws-lc-rs` is intentionally absent; see module docs.)
const FORBIDDEN_IN_DEFAULT_CLOSURE: &[&str] = &["sigstore", "opendal", "pgp"];

pub fn run(workspace: &Path) -> Result<()> {
    let mut failures: Vec<String> = Vec::new();

    // (1) Lockfile name ban.
    let lock_path = workspace.join("Cargo.lock");
    let lock = std::fs::read_to_string(&lock_path)
        .with_context(|| format!("reading {}", lock_path.display()))?;
    let mut lock_hits: Vec<String> = package_names(&lock)
        .filter(|name| is_forbidden(name))
        .map(str::to_string)
        .collect();
    lock_hits.sort();
    lock_hits.dedup();
    if !lock_hits.is_empty() {
        failures.push(format!(
            "forbidden package(s) in Cargo.lock: {}",
            lock_hits.join(", ")
        ));
    }

    // (2) Default-closure ban.
    let tree = mvmctl_default_closure(workspace)?;
    let names: Vec<&str> = package_names_from_tree(&tree).collect();
    let closure_hits = closure_violations(&names, FORBIDDEN_IN_DEFAULT_CLOSURE);
    if !closure_hits.is_empty() {
        failures.push(format!(
            "deliberately-gated dep(s) re-entered mvmctl's default-feature closure: {} \
             (allowed only behind off-by-default features)",
            closure_hits.join(", ")
        ));
    }

    if !failures.is_empty() {
        bail!("check-forbidden-deps:\n  - {}", failures.join("\n  - "));
    }

    eprintln!(
        "check-forbidden-deps: clean (no sea-*/mysql in Cargo.lock; \
         {} absent from mvmctl's default closure)",
        FORBIDDEN_IN_DEFAULT_CLOSURE.join("/"),
    );
    Ok(())
}

/// Resolve `mvmctl`'s default-feature, normal-edge dependency closure via
/// `cargo tree`. Uses the `CARGO` the parent invocation was launched with
/// so the gate honours the active toolchain in CI.
fn mvmctl_default_closure(workspace: &Path) -> Result<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = std::process::Command::new(&cargo)
        .current_dir(workspace)
        .args([
            "tree", "-p", "mvmctl", "--edges", "normal", "--prefix", "none",
        ])
        .output()
        .with_context(|| format!("running `{cargo} tree` for the mvmctl closure"))?;
    if !output.status.success() {
        bail!(
            "`cargo tree -p mvmctl` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn package_names(lock: &str) -> impl Iterator<Item = &str> {
    lock.lines()
        .filter_map(|line| line.strip_prefix("name = \""))
        .filter_map(|rest| rest.strip_suffix('"'))
}

/// Package names from `cargo tree --prefix none` output: one entry per
/// non-empty line, the leading token (`<name> v<ver> [(*)|(path)]`).
fn package_names_from_tree(tree: &str) -> impl Iterator<Item = &str> {
    tree.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| line.split_whitespace().next())
}

fn is_forbidden(name: &str) -> bool {
    FORBIDDEN_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || FORBIDDEN_SUBSTRINGS
            .iter()
            .any(|needle| name.contains(needle))
}

/// Exact-match the resolved closure against the ban list. Exact (not
/// substring) so siblings like `sigstore-protobuf-specs` don't trip the
/// `sigstore` rule.
fn closure_violations(package_names: &[&str], forbidden: &[&str]) -> Vec<String> {
    let mut hits: Vec<String> = package_names
        .iter()
        .filter(|name| forbidden.contains(name))
        .map(|name| name.to_string())
        .collect();
    hits.sort();
    hits.dedup();
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_names_extracts_lockfile_names() {
        let lock = r#"
[[package]]
name = "mvm"

[[package]]
name = "sea-orm"
"#;
        let names: Vec<_> = package_names(lock).collect();
        assert_eq!(names, vec!["mvm", "sea-orm"]);
    }

    #[test]
    fn forbidden_matches_sea_prefix_and_mysql_substring() {
        assert!(is_forbidden("sea-orm"));
        assert!(is_forbidden("sqlx-mysql"));
        assert!(is_forbidden("mysql_common"));
        assert!(!is_forbidden("sqlx-sqlite"));
        assert!(!is_forbidden("mvm-policy"));
    }

    #[test]
    fn tree_names_parses_prefix_none_lines() {
        let tree = "\
mvmctl v0.16.1 (/repo)
anyhow v1.0.102
aws-lc-rs v1.16.3 (*)

rustls v0.23.37
";
        let names: Vec<_> = package_names_from_tree(tree).collect();
        assert_eq!(
            names,
            vec!["mvmctl", "anyhow", "aws-lc-rs", "rustls"],
            "leading token per non-empty line, dedup marker ignored",
        );
    }

    #[test]
    fn closure_violations_exact_match_no_substring_false_positive() {
        let names = ["mvmctl", "rustls", "sigstore-protobuf-specs", "tokio"];
        // `sigstore-protobuf-specs` must NOT trip the `sigstore` rule.
        assert!(closure_violations(&names, FORBIDDEN_IN_DEFAULT_CLOSURE).is_empty());
    }

    #[test]
    fn closure_violations_flags_exact_banned_names_sorted_deduped() {
        let names = ["pgp", "mvmctl", "opendal", "opendal", "sigstore"];
        assert_eq!(
            closure_violations(&names, FORBIDDEN_IN_DEFAULT_CLOSURE),
            vec!["opendal", "pgp", "sigstore"],
        );
    }

    #[test]
    fn closure_violations_does_not_ban_aws_lc_rs() {
        // aws-lc-rs is in the default closure today (oci-client -> rustls)
        // and must stay un-banned until that is unwound upstream.
        let names = ["mvmctl", "rustls", "aws-lc-rs"];
        assert!(closure_violations(&names, FORBIDDEN_IN_DEFAULT_CLOSURE).is_empty());
    }
}
