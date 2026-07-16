//! `xtask check-require-grant-token-allowlist`
//!
//! Guards the invariant that `mvm.require_grant=1` is emitted only by the
//! mvm-runtime cmdline builders and matched by the guest vsock reader. A stray
//! emit site in any other crate could brick mvmd sealed workloads — the fleet
//! orchestrator bypasses `VmBackend::start` cmdline assembly and would silently
//! miss or double-emit the token.

use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

/// The literal that only the allowlisted files may contain.
const TOKEN: &str = "mvm.require_grant=1";

/// Files (workspace-relative) that are permitted to contain the token.
const ALLOWLIST: &[&str] = &[
    "crates/mvm-runtime/src/microvm.rs",
    "crates/mvm-runtime/src/qemu.rs",
    "crates/mvm-runtime/src/libkrun.rs",
    "crates/mvm-agentd/src/vsock.rs",
];

pub fn run(workspace: &Path) -> Result<()> {
    let mut rs_files = Vec::new();
    collect_rs_files(&workspace.join("crates"), &mut rs_files)?;

    let mut hits = Vec::new();
    for file in &rs_files {
        let rel = file
            .strip_prefix(workspace)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");

        // Skip files that are explicitly allowlisted.
        if ALLOWLIST.iter().any(|a| rel == *a) {
            continue;
        }

        let text = std::fs::read_to_string(file).unwrap_or_default();
        for (n, line) in text.lines().enumerate() {
            if line.contains(TOKEN) {
                hits.push(format!("{}:{}: {}", rel, n + 1, line.trim()));
            }
        }
    }

    if !hits.is_empty() {
        bail!(
            "check-require-grant-token-allowlist: `{TOKEN}` found outside the allowlist \
             (only mvm-runtime cmdline builders and mvm-agentd/vsock.rs may emit/match it):\n{}",
            hits.join("\n")
        );
    }
    eprintln!(
        "check-require-grant-token-allowlist: clean ({} files scanned; token confined to allowlist)",
        rs_files.len()
    );
    Ok(())
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for (rel_path, content) in files {
            let full = dir.path().join(rel_path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(&full, content).unwrap();
        }
        dir
    }

    #[test]
    fn allowlisted_file_passes() {
        let tree = make_tree(&[(
            "crates/mvm-runtime/src/microvm.rs",
            r#"fn foo() { let _ = "mvm.require_grant=1"; }"#,
        )]);
        run(tree.path()).expect("allowlisted path must pass");
    }

    #[test]
    fn non_allowlisted_file_fails() {
        let tree = make_tree(&[(
            "crates/mvm-core/src/lib.rs",
            r#"fn bad() { let _ = "mvm.require_grant=1"; }"#,
        )]);
        let err = run(tree.path()).expect_err("non-allowlisted path must fail");
        assert!(
            err.to_string().contains("mvm-core/src/lib.rs"),
            "error must name the violating file: {err}"
        );
    }

    #[test]
    fn file_without_token_passes() {
        let tree = make_tree(&[(
            "crates/mvm-core/src/config.rs",
            r#"fn foo() { let _ = "mvm.other_flag=1"; }"#,
        )]);
        run(tree.path()).expect("file without token must pass");
    }
}
