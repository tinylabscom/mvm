//! The cargo-mutants version pin: reading it, reading the installed one,
//! and holding every workflow to installing exactly it.

use super::*;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// The version from `cargo mutants --version`, which prints
/// `cargo-mutants 27.1.0`.
pub fn installed_mutator_version(stdout: &str) -> Option<&str> {
    stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("cargo-mutants "))
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

/// The cargo-mutants version pinned in the root `Cargo.toml`.
pub fn pinned_mutator_version(workspace: &Path) -> Result<String> {
    let manifest = workspace.join("Cargo.toml");
    let raw = std::fs::read_to_string(&manifest)
        .with_context(|| format!("reading {}", manifest.display()))?;
    let doc: toml::Value =
        toml::from_str(&raw).with_context(|| format!("parsing {}", manifest.display()))?;
    doc.get("workspace")
        .and_then(|w| w.get("metadata"))
        .and_then(|m| m.get("mvm"))
        .and_then(|m| m.get("toolchain"))
        .and_then(|t| t.get(MUTATOR_PIN_KEY))
        .and_then(toml::Value::as_str)
        .map(str::to_string)
        .with_context(|| {
            format!(
                "{} has no `{MUTATOR_PIN_KEY}` pin under [workspace.metadata.mvm.toolchain]; \
                 the mutation baseline is only meaningful against one exact mutator version",
                manifest.display()
            )
        })
}

/// Every workflow that installs cargo-mutants must install the pinned one.
pub fn check_mutator_installs_pinned(workspace: &Path, pinned: &str) -> Result<Vec<String>> {
    let dir = workspace.join(WORKFLOWS_REL);
    let mut errors = Vec::new();
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension()
                .is_some_and(|ext| ext == "yml" || ext == "yaml")
        })
        .collect();
    entries.sort();
    for path in entries {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let name = format!(
            "{WORKFLOWS_REL}/{}",
            path.file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default()
        );
        errors.extend(
            unpinned_mutator_installs(&text, pinned)
                .into_iter()
                .map(|e| format!("{name}: {e}")),
        );
    }
    Ok(errors)
}

/// The `cargo install` lines in one workflow that name cargo-mutants
/// without the pin.
///
/// A version is required on every such line. A literal must equal the pin;
/// a variable is accepted, because the lane reads it from the same manifest
/// entry and the run refuses any other installed version.
pub fn unpinned_mutator_installs(workflow: &str, pinned: &str) -> Vec<String> {
    let mut errors = Vec::new();
    for (i, line) in workflow.lines().enumerate() {
        if !line.contains("cargo install") {
            continue;
        }
        for word in line.split_whitespace() {
            let word = word.trim_matches(|c| c == '"' || c == '\'');
            let Some(rest) = word.strip_prefix("cargo-mutants") else {
                continue;
            };
            match rest.strip_prefix('@') {
                None if rest.is_empty() => errors.push(format!(
                    "line {}: installs cargo-mutants unpinned; install `cargo-mutants@{pinned}`",
                    i + 1
                )),
                None => {}
                Some(version) if version.starts_with(|c: char| c.is_ascii_digit()) => {
                    if version != pinned {
                        errors.push(format!(
                            "line {}: installs cargo-mutants@{version}, but \
                             [workspace.metadata.mvm.toolchain] pins {pinned}",
                            i + 1
                        ));
                    }
                }
                Some(_) => {}
            }
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "27.1.0";

    #[test]
    fn the_installed_mutator_version_is_read_from_its_version_line() {
        assert_eq!(
            installed_mutator_version("cargo-mutants 27.1.0\n"),
            Some("27.1.0")
        );
        assert_eq!(installed_mutator_version("something else\n"), None);
        assert_eq!(installed_mutator_version("cargo-mutants \n"), None);
    }

    #[test]
    fn the_mutator_pin_is_read_from_workspace_toolchain_metadata() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[workspace.metadata.mvm.toolchain]\nrust = \"1.91.1\"\ncargo-mutants = \"27.1.0\"\n",
        )
        .unwrap();
        assert_eq!(pinned_mutator_version(dir.path()).unwrap(), "27.1.0");

        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[workspace.metadata.mvm.toolchain]\nrust = \"1.91.1\"\n",
        )
        .unwrap();
        let err = pinned_mutator_version(dir.path()).expect_err("no pin is an error");
        assert!(err.to_string().contains("cargo-mutants"), "{err}");
    }

    /// The workspace itself carries the pin, so the lane and the gate have
    /// one version to agree on.
    #[test]
    fn the_workspace_pins_an_exact_mutator_version() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let pinned = pinned_mutator_version(&workspace).unwrap();
        assert!(
            pinned.split('.').count() == 3 && pinned.split('.').all(|p| p.parse::<u32>().is_ok()),
            "the cargo-mutants pin must be an exact X.Y.Z version, got {pinned:?}"
        );
        assert_eq!(
            check_mutator_installs_pinned(&workspace, &pinned).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn an_unpinned_mutator_install_is_reported() {
        let errors = unpinned_mutator_installs(
            "        run: cargo install --locked cargo-mutants cargo-nextest\n",
            PIN,
        );
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("unpinned"), "{errors:?}");
    }

    #[test]
    fn a_literal_mutator_version_must_match_the_pin() {
        assert!(
            unpinned_mutator_installs("cargo install --locked cargo-mutants@27.1.0\n", PIN)
                .is_empty()
        );
        let errors =
            unpinned_mutator_installs("cargo install --locked cargo-mutants@27.0.0\n", PIN);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("27.0.0"), "{errors:?}");
    }

    #[test]
    fn a_mutator_version_read_from_the_manifest_is_accepted() {
        assert!(
            unpinned_mutator_installs(
                r#"cargo install --locked "cargo-mutants@${CARGO_MUTANTS_VERSION}" cargo-nextest"#,
                PIN
            )
            .is_empty()
        );
    }
}
