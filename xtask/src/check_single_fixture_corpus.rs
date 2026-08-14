//! `xtask check-single-fixture-corpus`
//!
//! `tests/machine-fixtures/` is the one golden argv corpus binding the CLI and
//! all three SDKs together. The CLI parses every fixture with the real clap
//! parser and the Rust, Python and TypeScript builders each assert they
//! reproduce it — which is what makes a fixture mean "argv `mvmctl` actually
//! accepts".
//!
//! A second directory of the same name silently breaks that. It happened: a
//! copy under `crates/tests/machine-fixtures/` was what the Python and
//! TypeScript suites resolved to, so for two of three languages the corpus was
//! unanchored and drifted — a diverged `run-admission` and a missing
//! `start-image`. Nothing failed, because the shadow was self-consistent.
//!
//! This gate keeps the corpus singular. If you need fixtures for something
//! else, give the directory a different name.

use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

/// The corpus directory name that must be unique across the tree.
const CORPUS_DIR: &str = "machine-fixtures";

/// Where the one legitimate corpus lives, relative to the workspace root.
const CANONICAL: &str = "tests/machine-fixtures";

/// Build output and VCS metadata are never worth descending into. Vendored
/// dependency trees may legitimately ship a same-named directory of their own.
const SKIP_DIRS: [&str; 4] = ["target", ".git", "node_modules", ".venv"];

pub fn run(workspace: &Path) -> Result<()> {
    let mut found = Vec::new();
    collect(workspace, &mut found)?;
    found.sort();

    let canonical = workspace.join(CANONICAL);
    if !canonical.is_dir() {
        bail!(
            "check-single-fixture-corpus: the canonical corpus is missing at {}.\n\
             The CLI and all three SDKs resolve their golden argv fixtures there.",
            canonical.display()
        );
    }

    let shadows: Vec<&PathBuf> = found.iter().filter(|path| **path != canonical).collect();
    if !shadows.is_empty() {
        let list = shadows
            .iter()
            .map(|path| {
                format!(
                    "  {}",
                    path.strip_prefix(workspace).unwrap_or(path).display()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        bail!(
            "check-single-fixture-corpus: found {} shadow {} of `{CORPUS_DIR}`:\n{list}\n\n\
             There must be exactly one, at `{CANONICAL}`. A shadow copy is not \
             parsed by the CLI and not asserted by the Rust SDK, so whichever \
             suite resolves to it silently stops enforcing the argv contract. \
             Delete the copy and point the suite at the canonical corpus.",
            shadows.len(),
            if shadows.len() == 1 { "copy" } else { "copies" }
        );
    }

    println!("check-single-fixture-corpus: ok — one corpus at {CANONICAL}");
    Ok(())
}

/// Recursively collect every directory named [`CORPUS_DIR`] under `dir`.
fn collect(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries.filter_map(std::result::Result::ok) {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if SKIP_DIRS.contains(&name) {
            continue;
        }
        if name == CORPUS_DIR {
            out.push(path);
            // A corpus holds `.argv` files, never a nested corpus.
            continue;
        }
        collect(&path, out)?;
    }
    Ok(())
}
