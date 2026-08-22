//! `xtask check-guest-binary-lists`
//!
//! CI lint — the guest runtime binaries baked into an OCI `run --image` rootfs
//! are named in four hand-maintained lists that must stay in lockstep:
//!
//! - `crates/mvm-build/src/guest_agent_build.rs` — the `cargo zigbuild --bin`
//!   invocation that actually builds them (the authoritative list).
//! - `crates/mvm-build/src/oci_runtime_inject.rs` — the `MvmRuntimeBinaries`
//!   struct whose field docs name each bin.
//! - `nix/images/runtime-overlay/flake.nix` — files staged for publication.
//! - `.github/workflows/release-boot-image.yml` — files archived by the release
//!   train.
//!
//! The check asserts those four sets are identical to each other AND that every
//! name is a real `[[bin]]` of `mvm-agentd`. A drift — a
//! renamed bin, a list left behind, or a name that no longer maps to a bin —
//! fails here instead of silently shipping a rootfs missing (or misnaming) a
//! guest binary. It separately asserts that `mvm-cli/build.rs` has no guest
//! `--bin` list: workload binaries belong to the initramfs/runtime artifacts,
//! never the host CLI executable.

use anyhow::{Context, Result, bail};
use regex::Regex;
use std::collections::BTreeSet;
use std::path::Path;

const GUEST_AGENT_BUILD: &str = "crates/mvm-build/src/guest_agent_build.rs";
const CLI_BUILD_RS: &str = "crates/mvm-cli/build.rs";
const OCI_INJECT: &str = "crates/mvm-build/src/oci_runtime_inject.rs";
const RUNTIME_OVERLAY_FLAKE: &str = "nix/images/runtime-overlay/flake.nix";
const RELEASE_BOOT_IMAGE_WORKFLOW: &str = ".github/workflows/release-boot-image.yml";

pub fn run(workspace: &Path) -> Result<()> {
    let universe = guest_bin_universe(workspace)?;

    let lists = [
        (
            "guest_agent_build.rs argv",
            extract_guest_agent_build_argv(workspace, GUEST_AGENT_BUILD)?,
        ),
        (
            "oci_runtime_inject.rs MvmRuntimeBinaries",
            extract_runtime_struct(workspace, OCI_INJECT)?,
        ),
        (
            "runtime-overlay flake guest-runtime output",
            extract_between(
                workspace,
                RUNTIME_OVERLAY_FLAKE,
                "mkdir -p $out/guest-runtime",
                "chmod 0555 $out/guest-runtime/*",
            )?,
        ),
        (
            "release-boot-image.yml guest-runtime archive loop",
            extract_between(
                workspace,
                RELEASE_BOOT_IMAGE_WORKFLOW,
                "for bin in \\",
                "cp -L \"$STORE_PATH/guest-runtime/$bin\"",
            )?,
        ),
    ];

    // Every list must be non-empty — an empty extraction means a refactor moved
    // the list and this check silently stopped guarding it.
    for (label, set) in &lists {
        if set.is_empty() {
            bail!(
                "no guest binary names extracted from {label}; the list moved — update this check"
            );
        }
    }

    // All lists identical.
    let canonical = &lists[0].1;
    for (label, set) in &lists[1..] {
        if set != canonical {
            bail!(
                "guest-binary name lists drift:\n  {} = {:?}\n  {} = {:?}\n\n\
                 Fix: keep every guest runtime binary list identical to {}.",
                lists[0].0,
                canonical,
                label,
                set,
                GUEST_AGENT_BUILD,
            );
        }
    }

    let cli_guest_bins = extract_bin_flags_from_file(workspace, CLI_BUILD_RS)?;
    if !cli_guest_bins.is_empty() {
        bail!(
            "mvm-cli/build.rs embeds workload guest binaries {:?}; build them through the initramfs/runtime artifacts instead",
            cli_guest_bins,
        );
    }

    // Every listed name is a real guest `[[bin]]` — catches an invalid drift.
    let invalid: BTreeSet<&String> = canonical.difference(&universe).collect();
    if !invalid.is_empty() {
        bail!(
            "guest-binary lists reference names that are not `[[bin]]`s of \
             mvm-agentd: {:?}\n  known bins: {:?}",
            invalid,
            universe,
        );
    }

    eprintln!(
        "check-guest-binary-lists: 4 artifact lists agree on {} guest binaries; mvm-cli embeds none",
        canonical.len()
    );
    Ok(())
}

/// The set of every `[[bin]]` name declared by `mvm-agentd` — the universe a
/// listed guest binary must belong to.
fn guest_bin_universe(workspace: &Path) -> Result<BTreeSet<String>> {
    let path = workspace.join("crates/mvm-agentd/Cargo.toml");
    let src = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(parse_bin_names(&src))
}

/// `[[bin]] name = "..."` names in a Cargo.toml. A `name =` line counts only when
/// the most recent section header was `[[bin]]` (skips the `[package] name`).
fn parse_bin_names(manifest: &str) -> BTreeSet<String> {
    let name_re = Regex::new(r#"^\s*name\s*=\s*"([^"]+)""#).unwrap();
    let mut out = BTreeSet::new();
    let mut in_bin = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_bin = t == "[[bin]]";
            continue;
        }
        if in_bin && let Some(c) = name_re.captures(line) {
            out.insert(c[1].to_string());
            in_bin = false;
        }
    }
    out
}

/// Names passed as `--bin <name>` in a `cargo zigbuild` argv. Handles both the
/// plain `"--bin", "name"` (build.rs) and the `"--bin".to_string(),
/// "name".to_string()` (guest_agent_build.rs) forms. Only `mvm-*` literals count
/// — a `--bin <variable>` (host-bin loops) carries no literal and is skipped.
fn extract_bin_flags(src: &str) -> BTreeSet<String> {
    let re = Regex::new(r#""--bin"(?:\.to_string\(\))?\s*,\s*"(mvm-[a-z0-9-]+)""#).unwrap();
    re.captures_iter(src).map(|c| c[1].to_string()).collect()
}

/// The authoritative OCI guest-runtime list in `GuestAgentBuildSpec::argv()`.
/// `guest_agent_build.rs` also contains overlay-only runtime lists for the
/// shared readonly artifact, so this lint must isolate the OCI injection list.
fn extract_guest_agent_build_argv(workspace: &Path, rel: &str) -> Result<BTreeSet<String>> {
    let src = read(workspace, rel)?;
    let start = src
        .find("pub fn argv(&self) -> Vec<String> {")
        .with_context(|| format!("GuestAgentBuildSpec::argv not found in {rel}"))?;
    let rest = &src[start..];
    let end = rest
        .find("\n    }\n")
        .with_context(|| format!("GuestAgentBuildSpec::argv has no closing brace in {rel}"))?;
    Ok(extract_bin_flags(&rest[..end]))
}

fn extract_bin_flags_from_file(workspace: &Path, rel: &str) -> Result<BTreeSet<String>> {
    let src = read(workspace, rel)?;
    Ok(extract_bin_flags(&src))
}

/// Guest binary names named in the `MvmRuntimeBinaries` struct field docs — each
/// field carries exactly one `` `mvm-…` `` backtick reference.
fn extract_runtime_struct(workspace: &Path, rel: &str) -> Result<BTreeSet<String>> {
    let src = read(workspace, rel)?;
    let start = src
        .find("pub struct MvmRuntimeBinaries {")
        .with_context(|| format!("MvmRuntimeBinaries struct not found in {rel}"))?;
    let rest = &src[start..];
    let end = rest
        .find("\n}")
        .with_context(|| format!("MvmRuntimeBinaries struct has no closing brace in {rel}"))?;
    let block = &rest[..end];
    let re = Regex::new(r"`(mvm-[a-z0-9-]+)`").unwrap();
    Ok(re.captures_iter(block).map(|c| c[1].to_string()).collect())
}

fn extract_between(
    workspace: &Path,
    rel: &str,
    start_marker: &str,
    end_marker: &str,
) -> Result<BTreeSet<String>> {
    let src = read(workspace, rel)?;
    let start = src
        .find(start_marker)
        .with_context(|| format!("start marker {start_marker:?} not found in {rel}"))?;
    let rest = &src[start..];
    let end = rest
        .find(end_marker)
        .with_context(|| format!("end marker {end_marker:?} not found in {rel}"))?;
    let re = Regex::new(r"mvm-[a-z0-9-]+").unwrap();
    Ok(re
        .find_iter(&rest[..end])
        .map(|found| found.as_str().to_string())
        .collect())
}

fn read(workspace: &Path, rel: &str) -> Result<String> {
    let path = workspace.join(rel);
    std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn workspace_root() -> PathBuf {
        let manifest = std::env::var("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
        manifest
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or(manifest)
    }

    #[test]
    fn parse_bin_names_skips_package_name() {
        let manifest = r#"
[package]
name = "mvm-agentd"

[[bin]]
name = "mvm-guest-agent"

[[bin]]
name = "mvm-oci-init"
"#;
        let bins = parse_bin_names(manifest);
        assert!(bins.contains("mvm-guest-agent"));
        assert!(bins.contains("mvm-oci-init"));
        assert!(
            !bins.contains("mvm-agentd"),
            "package name must not be a bin"
        );
    }

    #[test]
    fn extract_bin_flags_handles_both_argv_forms() {
        // The plain build.rs form and the `.to_string()` guest_agent_build form.
        let build_rs =
            r#"cmd.args(["zigbuild", "--bin", "mvm-oci-init", "--bin", "mvm-guest-agent"]);"#;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.rs"), build_rs).unwrap();
        let got = extract_bin_flags_from_file(tmp.path(), "a.rs").unwrap();
        assert_eq!(
            got,
            BTreeSet::from(["mvm-oci-init".to_string(), "mvm-guest-agent".to_string()])
        );

        let gab = r#"vec!["--bin".to_string(), "mvm-verity-init".to_string()]"#;
        std::fs::write(tmp.path().join("b.rs"), gab).unwrap();
        let got = extract_bin_flags_from_file(tmp.path(), "b.rs").unwrap();
        assert_eq!(got, BTreeSet::from(["mvm-verity-init".to_string()]));
    }

    #[test]
    fn the_artifact_lists_agree_and_cli_embeds_no_guest_bins() {
        // The real gate over the current tree.
        run(&workspace_root()).expect("guest-binary lists must be in sync");
    }

    #[test]
    fn artifact_extractors_each_find_the_six_runtime_bins() {
        let root = workspace_root();
        let expected = BTreeSet::from([
            "mvm-oci-init".to_string(),
            "mvm-oci-entrypoint".to_string(),
            "mvm-guest-agent".to_string(),
            "mvm-guest-netinit".to_string(),
            "mvm-egress-client".to_string(),
            "mvm-verity-init".to_string(),
        ]);
        assert_eq!(
            extract_guest_agent_build_argv(&root, GUEST_AGENT_BUILD).unwrap(),
            expected
        );
        assert_eq!(extract_runtime_struct(&root, OCI_INJECT).unwrap(), expected);
        assert_eq!(
            extract_between(
                &root,
                RUNTIME_OVERLAY_FLAKE,
                "mkdir -p $out/guest-runtime",
                "chmod 0555 $out/guest-runtime/*",
            )
            .unwrap(),
            expected
        );
        assert_eq!(
            extract_between(
                &root,
                RELEASE_BOOT_IMAGE_WORKFLOW,
                "for bin in \\",
                "cp -L \"$STORE_PATH/guest-runtime/$bin\"",
            )
            .unwrap(),
            expected
        );
        assert!(
            extract_bin_flags_from_file(&root, CLI_BUILD_RS)
                .unwrap()
                .is_empty(),
            "mvm-cli must not cross-compile workload guest binaries"
        );
    }

    #[test]
    fn universe_contains_the_runtime_bins() {
        let universe = guest_bin_universe(&workspace_root()).unwrap();
        for b in [
            "mvm-oci-init",
            "mvm-oci-entrypoint",
            "mvm-guest-agent",
            "mvm-guest-netinit",
            "mvm-egress-client",
            "mvm-verity-init",
        ] {
            assert!(universe.contains(b), "{b} must be a known guest [[bin]]");
        }
    }
}
