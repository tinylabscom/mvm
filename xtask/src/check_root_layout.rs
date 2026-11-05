//! Keep the repository root small.
//!
//! Every entry git tracks at the root must be on the allow-list below, and
//! every entry on the list must still be tracked, so the list cannot rot into
//! names that permit nothing. A new top-level file or directory is a decision:
//! add it here in the same change, with a reason in the review.

use crate::check_spec_hygiene::tracked_paths;
use anyhow::{Result, bail};
use std::collections::BTreeSet;
use std::path::Path;

const ALLOWED: &[&str] = &[
    ".cargo",
    ".config",
    ".envrc.example",
    ".githooks",
    ".github",
    ".gitignore",
    "AGENTS.md",
    "AGENTS.md.sigstore.json",
    "CHANGELOG.md",
    "CLAUDE.md",
    "CLAUDE.md.sigstore.json",
    "Cargo.lock",
    "Cargo.toml",
    "Justfile",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "assets",
    "bin",
    "build.rs",
    "cliff.toml",
    "crates",
    "deny.toml",
    "examples",
    "features",
    "flake.lock",
    "flake.nix",
    "install.sh",
    "just",
    "model",
    "nix",
    "public",
    "rust-toolchain.toml",
    "schema",
    "scripts",
    "specs",
    "src",
    "tests",
    "third_party",
    "treefmt.toml",
    "uninstall.sh",
    "web",
    "xtask",
];

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let tracked = tracked_roots(&tracked_paths(workspace, ".")?);
    let violations = violations(&tracked);
    if violations.is_empty() {
        println!(
            "check-root-layout: clean ({} root entries, all allow-listed)",
            tracked.len()
        );
        return Ok(());
    }
    bail!("check-root-layout:\n  {}", violations.join("\n  "))
}

fn tracked_roots(paths: &[String]) -> BTreeSet<String> {
    paths
        .iter()
        .filter_map(|path| path.split('/').next())
        .map(str::to_owned)
        .collect()
}

fn violations(tracked: &BTreeSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    for name in tracked {
        if !ALLOWED.contains(&name.as_str()) {
            out.push(format!(
                "{name}: not on the root allow-list (xtask/src/check_root_layout.rs)"
            ));
        }
    }
    for name in ALLOWED {
        if !tracked.contains(*name) {
            out.push(format!(
                "{name}: on the root allow-list but no longer tracked; remove it"
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn all_allowed() -> BTreeSet<String> {
        roots(ALLOWED)
    }

    #[test]
    fn the_full_allow_list_is_clean() {
        assert!(violations(&all_allowed()).is_empty());
    }

    #[test]
    fn a_new_root_entry_is_refused() {
        let mut tracked = all_allowed();
        tracked.insert("docs".into());
        let found = violations(&tracked);
        assert_eq!(found.len(), 1);
        assert!(found[0].starts_with("docs:"));
    }

    #[test]
    fn a_stale_allow_list_entry_is_refused() {
        let mut tracked = all_allowed();
        tracked.remove("bin");
        let found = violations(&tracked);
        assert_eq!(found.len(), 1);
        assert!(found[0].starts_with("bin:"));
    }

    #[test]
    fn only_the_first_path_component_counts() {
        let paths = vec![
            "crates/mvm-core/src/lib.rs".to_owned(),
            "Cargo.toml".to_owned(),
        ];
        assert_eq!(tracked_roots(&paths), roots(&["Cargo.toml", "crates"]));
    }

    #[test]
    fn the_allow_list_has_no_duplicates() {
        assert_eq!(ALLOWED.iter().collect::<BTreeSet<_>>().len(), ALLOWED.len());
    }
}
