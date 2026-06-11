//! `xtask check-runtime-overlay-version`
//!
//! The verity-sealed `/mvm/runtime` overlay is
//! pinned to a single version, and the host-side resolver
//! (`mvm_build::runtime_overlay`) **fails closed on a version mismatch**
//! (`RuntimeOverlayError::VersionMismatch`): it picks the overlay whose
//! `VERSION` equals the running mvmctl's semver, else refuses. So a stale
//! `overlayVersion` pin in the flake doesn't warn — it makes the overlay
//! silently never load on any boot.
//!
//! This gate asserts the flake's `overlayVersion` equals the workspace
//! `[workspace.package].version`, so the lock-step pin (the flake comment
//! calls it hand-maintained) can't drift unnoticed. Source-parse, sibling
//! of the other `check-*` gates.

use anyhow::{Context, Result, bail};
use std::path::Path;

const OVERLAY_FLAKE: &str = "nix/images/runtime-overlay/flake.nix";

pub fn run(workspace: &Path) -> Result<()> {
    let cargo = std::fs::read_to_string(workspace.join("Cargo.toml"))
        .context("reading workspace Cargo.toml")?;
    let flake = std::fs::read_to_string(workspace.join(OVERLAY_FLAKE))
        .with_context(|| format!("reading {OVERLAY_FLAKE}"))?;

    let ws_ver = parse_workspace_version(&cargo)
        .context("could not find [workspace.package] version in Cargo.toml")?;
    let overlay_ver = parse_overlay_version(&flake)
        .with_context(|| format!("could not find `overlayVersion` in {OVERLAY_FLAKE}"))?;

    if ws_ver != overlay_ver {
        bail!(
            "check-runtime-overlay-version: the runtime-overlay flake's overlayVersion \
             ({overlay_ver}) does not match the workspace version ({ws_ver}). The resolver pins \
             the overlay by exact version (ADR-051) and fails closed on a mismatch — a stale pin \
             means the verity overlay silently never loads. Bump `overlayVersion` in \
             {OVERLAY_FLAKE} to {ws_ver}."
        );
    }

    eprintln!(
        "check-runtime-overlay-version: clean (overlay pinned to workspace version {ws_ver})"
    );
    Ok(())
}

/// Extract `version = "X"` from the `[workspace.package]` table. Returns
/// the first `version` key inside that section (TOML one-value-per-key).
fn parse_workspace_version(cargo_toml: &str) -> Option<String> {
    let mut in_workspace_package = false;
    for line in cargo_toml.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_workspace_package = t == "[workspace.package]";
            continue;
        }
        if in_workspace_package
            && let Some(rest) = t.strip_prefix("version")
            && let Some(rest) = rest.trim_start().strip_prefix('=')
        {
            return extract_first_quoted(rest);
        }
    }
    None
}

/// Extract the value of the `overlayVersion = "X";` Nix binding.
fn parse_overlay_version(flake: &str) -> Option<String> {
    for line in flake.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("overlayVersion")
            && let Some(rest) = rest.trim_start().strip_prefix('=')
        {
            return extract_first_quoted(rest);
        }
    }
    None
}

/// The first double-quoted run in `s` (tolerates trailing `;`, commas, or
/// comments after the closing quote).
fn extract_first_quoted(s: &str) -> Option<String> {
    let after = s.trim_start().strip_prefix('"')?;
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_workspace_package_version() {
        let toml = "[workspace]\nmembers = []\n\n[workspace.package]\nedition = \"2024\"\nversion = \"0.16.1\"\n\n[workspace.dependencies]\nversion = \"9.9.9\"\n";
        assert_eq!(parse_workspace_version(toml).as_deref(), Some("0.16.1"));
    }

    #[test]
    fn workspace_version_ignores_other_tables() {
        // A `version` key in `[package]` must not shadow the workspace one.
        let toml = "[package]\nversion = \"1.2.3\"\n\n[workspace.package]\nversion = \"0.16.1\"\n";
        assert_eq!(parse_workspace_version(toml).as_deref(), Some("0.16.1"));
    }

    #[test]
    fn parses_overlay_version_with_trailing_semicolon() {
        let flake = "  let\n      overlayVersion = \"0.16.1\";\n  in {};\n";
        assert_eq!(parse_overlay_version(flake).as_deref(), Some("0.16.1"));
    }

    #[test]
    fn extract_first_quoted_tolerates_trailing_junk() {
        assert_eq!(
            extract_first_quoted(" \"0.16.1\"; # comment").as_deref(),
            Some("0.16.1")
        );
        assert_eq!(extract_first_quoted("no quotes here"), None);
    }
}
