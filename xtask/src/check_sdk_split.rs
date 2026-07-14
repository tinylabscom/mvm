//! `xtask check-sdk-split`
//!
//! Guards the crate split introduced for the external SDK release flow:
//!
//! - shared runtime/build crates must stay off `mvm-sdk`;
//! - `mvm-cli` must keep `mvm-sdk` in its normal dependency closure so the
//!   single-CLI authoring surface remains intact.

use anyhow::{Context, Result, bail};
use std::path::Path;

const MUST_EXCLUDE_MVM_SDK: &[&str] = &[
    "mvm",
    "mvm-build",
    "mvm-hostd",
    "mvm-network",
    "mvm-storage",
];
const MUST_INCLUDE_MVM_SDK: &[&str] = &["mvm-cli"];
const SDK_CRATE_NAME: &str = "mvm-sdk";

pub fn run(workspace: &Path) -> Result<()> {
    let mut failures = Vec::new();

    for package in MUST_EXCLUDE_MVM_SDK {
        let closure = package_closure(workspace, package)?;
        if package_names_from_tree(&closure).any(|name| name == SDK_CRATE_NAME) {
            failures.push(format!(
                "{package} unexpectedly depends on {SDK_CRATE_NAME} in its normal closure"
            ));
        }
    }

    for package in MUST_INCLUDE_MVM_SDK {
        let closure = package_closure(workspace, package)?;
        if !package_names_from_tree(&closure).any(|name| name == SDK_CRATE_NAME) {
            failures.push(format!(
                "{package} no longer depends on {SDK_CRATE_NAME}; the single-CLI SDK surface likely regressed"
            ));
        }
    }

    if !failures.is_empty() {
        bail!("check-sdk-split:\n  - {}", failures.join("\n  - "));
    }

    eprintln!(
        "check-sdk-split: clean ({} exclude {SDK_CRATE_NAME}; {} retains it)",
        MUST_EXCLUDE_MVM_SDK.join(", "),
        MUST_INCLUDE_MVM_SDK.join(", "),
    );
    Ok(())
}

fn package_closure(workspace: &Path, package: &str) -> Result<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = std::process::Command::new(&cargo)
        .current_dir(workspace)
        .args([
            "tree", "-p", package, "--edges", "normal", "--prefix", "none",
        ])
        .output()
        .with_context(|| format!("running `{cargo} tree -p {package}`"))?;
    if !output.status.success() {
        bail!(
            "`cargo tree -p {package}` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn package_names_from_tree(tree: &str) -> impl Iterator<Item = &str> {
    tree.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| line.split_whitespace().next())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_names_from_tree_reads_leading_package_token() {
        let tree = "\
mvm-cli v0.18.0 (/repo)
mvm-sdk v0.18.0 (/repo/crates/mvm-sdk)
serde v1.0.228
";
        let names: Vec<_> = package_names_from_tree(tree).collect();
        assert_eq!(names, vec!["mvm-cli", "mvm-sdk", "serde"]);
    }

    #[test]
    fn package_names_from_tree_ignores_blank_lines_and_dedup_markers() {
        let tree = "\
mvm-build v0.18.0 (/repo)

serde v1.0.228
tokio v1.47.1 (*)
";
        let names: Vec<_> = package_names_from_tree(tree).collect();
        assert_eq!(names, vec!["mvm-build", "serde", "tokio"]);
    }
}
