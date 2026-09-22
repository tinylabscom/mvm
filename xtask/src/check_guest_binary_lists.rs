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
//!
//! A second section ([`check_overlay_parity`]) holds the runtime overlay's
//! own binary lists — the overlay zigbuild list and `install_one` pairs, the
//! Rust staging array, and the Nix flake's staging `cp` lines — in the same
//! lockstep, and rejects an orphaned `--bin` flag left behind by a removed
//! binary name.

use anyhow::{Context, Result, bail};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const GUEST_AGENT_BUILD: &str = "crates/mvm-build/src/guest_agent_build.rs";
const CLI_BUILD_RS: &str = "crates/mvm-cli/build.rs";
const OCI_INJECT: &str = "crates/mvm-build/src/oci_runtime_inject.rs";
const RUNTIME_OVERLAY_FLAKE: &str = "nix/images/runtime-overlay/flake.nix";
const RUNTIME_OVERLAY_RS: &str = "crates/mvm-build/src/runtime_overlay.rs";
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

    let overlay = check_overlay_parity(workspace, &universe)?;

    eprintln!(
        "check-guest-binary-lists: 4 artifact lists agree on {} guest binaries; overlay lists agree on {overlay}; mvm-cli embeds none",
        canonical.len()
    );
    Ok(())
}

/// The read-only runtime overlay's binary set is maintained in three places:
/// the overlay `cargo zigbuild` bin list plus its `install_one` pairs
/// (`guest_agent_build.rs`), the staging array that writes the overlay root
/// (`runtime_overlay.rs`), and the Nix flake's staging `cp` lines
/// (`runtime-overlay/flake.nix`). They drifted once — the flake shipped
/// `display-bridge` but not `ping` while the Rust builder did the reverse, so
/// `/bin/ping` mediation silently no-oped on Nix-built overlays — and an
/// orphaned `--bin` flag survived a bin removal because cargo happened to
/// absorb the malformed pair. This section keeps the three lists in lockstep
/// and rejects a `--bin` flag not followed by a binary name.
fn check_overlay_parity(workspace: &Path, universe: &BTreeSet<String>) -> Result<usize> {
    let gab = read(workspace, GUEST_AGENT_BUILD)?;
    let orphan = Regex::new(r#""--bin"(?:\.to_string\(\))?\s*,\s*"--bin""#).unwrap();
    if orphan.is_match(&gab) {
        bail!(
            "orphaned `--bin` flag in {GUEST_AGENT_BUILD}: a `\"--bin\"` is immediately \
             followed by another `\"--bin\"`, so a binary name was removed without its flag"
        );
    }

    let argv_block = slice_between(
        &gab,
        "fn build_runtime_overlay_guest_binaries_into_cache",
        "run_zigbuild(&spec, &prod_args)",
        GUEST_AGENT_BUILD,
    )?;
    let overlay_bins = extract_bin_flags(argv_block);

    // `install_one(&output_dir.join("mvm-x"), &layout.field)` — bin ↔ field.
    // Whitespace-tolerant: rustfmt wraps a long call across lines.
    let install_re = Regex::new(
        r#"install_one\(\s*&output_dir\.join\("(mvm-[a-z0-9-]+)"\),\s*&layout\.([a-z_]+),?\s*\)"#,
    )
    .unwrap();
    let bin_to_field: BTreeMap<String, String> = install_re
        .captures_iter(argv_block_to_end(&gab))
        .map(|c| (c[1].to_string(), c[2].to_string()))
        .collect();

    // Rust staging: `(&bins.field, root.join("staged"))` — field ↔ staged name.
    let overlay_rs = read(workspace, RUNTIME_OVERLAY_RS)?;
    let staging_re =
        Regex::new(r#"\(\s*&bins\.([a-z_]+),\s*root\.join\("([a-z0-9-]+)"\),?\s*\)"#).unwrap();
    let field_to_staged: BTreeMap<String, String> = staging_re
        .captures_iter(&overlay_rs)
        .map(|c| (c[1].to_string(), c[2].to_string()))
        .collect();

    // Nix staging: `cp ${pkg}/bin/mvm-x "$staging/staged"` — bin ↔ staged name.
    let flake = read(workspace, RUNTIME_OVERLAY_FLAKE)?;
    let cp_re =
        Regex::new(r#"cp \$\{[A-Za-z0-9]+\}/bin/(mvm-[a-z0-9-]+)\s+"\$staging/([a-z0-9-]+)""#)
            .unwrap();
    let nix_pairs: BTreeMap<String, String> = cp_re
        .captures_iter(&flake)
        .map(|c| (c[1].to_string(), c[2].to_string()))
        .collect();

    for (label, len) in [
        ("overlay zigbuild bin list", overlay_bins.len()),
        ("install_one pairs", bin_to_field.len()),
        ("runtime_overlay.rs staging array", field_to_staged.len()),
        ("runtime-overlay flake staging cp lines", nix_pairs.len()),
    ] {
        if len == 0 {
            bail!(
                "no overlay binary names extracted from the {label}; the list moved — update this check"
            );
        }
    }

    let install_bins: BTreeSet<String> = bin_to_field.keys().cloned().collect();
    let nix_bins: BTreeSet<String> = nix_pairs.keys().cloned().collect();
    let rust_staged: BTreeSet<String> = field_to_staged.values().cloned().collect();
    let nix_staged: BTreeSet<String> = nix_pairs.values().cloned().collect();

    for (label, set) in [
        ("install_one bin set", &install_bins),
        ("runtime-overlay flake bin set", &nix_bins),
    ] {
        if *set != overlay_bins {
            bail!(
                "runtime-overlay binary lists drift:\n  overlay zigbuild list = {overlay_bins:?}\n  {label} = {set:?}"
            );
        }
    }
    if rust_staged != nix_staged {
        bail!(
            "runtime-overlay staged-name sets drift:\n  runtime_overlay.rs = {rust_staged:?}\n  flake = {nix_staged:?}"
        );
    }

    // The three mappings must compose: bin -> field -> staged == bin -> staged.
    for (bin, field) in &bin_to_field {
        let via_rust = field_to_staged.get(field).with_context(|| {
            format!("overlay bin {bin} installs into layout field {field}, which the runtime_overlay.rs staging array never stages")
        })?;
        let via_nix = &nix_pairs[bin];
        if via_rust != via_nix {
            bail!(
                "overlay bin {bin} is staged as {via_rust:?} by runtime_overlay.rs but as {via_nix:?} by the flake"
            );
        }
        if field.replace('_', "-") != *via_rust {
            bail!(
                "overlay layout field {field} stages as {via_rust:?}; field and staged name must correspond"
            );
        }
    }

    let invalid: BTreeSet<&String> = overlay_bins.difference(universe).collect();
    if !invalid.is_empty() {
        bail!(
            "runtime-overlay lists reference names that are not `[[bin]]`s of mvm-agentd: {invalid:?}"
        );
    }

    Ok(overlay_bins.len())
}

/// The tail of `guest_agent_build.rs` from the overlay build function on, so
/// the `install_one` extraction cannot match the unrelated OCI install block.
fn argv_block_to_end(src: &str) -> &str {
    src.find("fn build_runtime_overlay_guest_binaries_into_cache")
        .map(|start| &src[start..])
        .unwrap_or(src)
}

fn slice_between<'a>(
    src: &'a str,
    start_marker: &str,
    end_marker: &str,
    rel: &str,
) -> Result<&'a str> {
    let start = src
        .find(start_marker)
        .with_context(|| format!("start marker {start_marker:?} not found in {rel}"))?;
    let rest = &src[start..];
    let end = rest
        .find(end_marker)
        .with_context(|| format!("end marker {end_marker:?} not found in {rel}"))?;
    Ok(&rest[..end])
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
name = "mvm-oci-entrypoint"
"#;
        let bins = parse_bin_names(manifest);
        assert!(bins.contains("mvm-guest-agent"));
        assert!(bins.contains("mvm-oci-entrypoint"));
        assert!(
            !bins.contains("mvm-agentd"),
            "package name must not be a bin"
        );
    }

    #[test]
    fn extract_bin_flags_handles_both_argv_forms() {
        // The plain build.rs form and the `.to_string()` guest_agent_build form.
        let build_rs =
            r#"cmd.args(["zigbuild", "--bin", "mvm-oci-entrypoint", "--bin", "mvm-guest-agent"]);"#;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.rs"), build_rs).unwrap();
        let got = extract_bin_flags_from_file(tmp.path(), "a.rs").unwrap();
        assert_eq!(
            got,
            BTreeSet::from([
                "mvm-oci-entrypoint".to_string(),
                "mvm-guest-agent".to_string()
            ])
        );

        let gab = r#"vec!["--bin".to_string(), "mvm-seccomp-apply".to_string()]"#;
        std::fs::write(tmp.path().join("b.rs"), gab).unwrap();
        let got = extract_bin_flags_from_file(tmp.path(), "b.rs").unwrap();
        assert_eq!(got, BTreeSet::from(["mvm-seccomp-apply".to_string()]));
    }

    #[test]
    fn the_artifact_lists_agree_and_cli_embeds_no_guest_bins() {
        // The real gate over the current tree.
        run(&workspace_root()).expect("guest-binary lists must be in sync");
    }

    #[test]
    fn artifact_extractors_each_find_the_four_runtime_bins() {
        let root = workspace_root();
        let expected = BTreeSet::from([
            "mvm-oci-entrypoint".to_string(),
            "mvm-guest-agent".to_string(),
            "mvm-guest-netinit".to_string(),
            "mvm-egress-client".to_string(),
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

    fn overlay_fixture(root: &Path, gab_bins: &str, staging: &str, flake_cp: &str) {
        let write = |rel: &str, text: &str| {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write(
            GUEST_AGENT_BUILD,
            &format!(
                "fn build_runtime_overlay_guest_binaries_into_cache() {{\n\
                 let prod_args = vec![{gab_bins}];\n\
                 run_zigbuild(&spec, &prod_args)?;\n\
                 install_one(&output_dir.join(\"mvm-guest-agent\"), &layout.agent)?;\n\
                 install_one(&output_dir.join(\"mvm-ping\"), &layout.ping)?;\n}}\n"
            ),
        );
        write(
            RUNTIME_OVERLAY_RS,
            &format!("let binaries = [{staging}];\n"),
        );
        write(RUNTIME_OVERLAY_FLAKE, flake_cp);
    }

    const FIXTURE_BINS: &str = r#""--bin".to_string(), "mvm-guest-agent".to_string(), "--bin".to_string(), "mvm-ping".to_string()"#;
    const FIXTURE_STAGING: &str =
        r#"(&bins.agent, root.join("agent")), (&bins.ping, root.join("ping"))"#;
    const FIXTURE_FLAKE: &str = "cp ${guest}/bin/mvm-guest-agent \"$staging/agent\"\n\
                                 cp ${guest}/bin/mvm-ping \"$staging/ping\"\n";

    fn fixture_universe() -> BTreeSet<String> {
        BTreeSet::from(["mvm-guest-agent".to_string(), "mvm-ping".to_string()])
    }

    #[test]
    fn rustfmt_wrapped_install_calls_are_still_extracted() {
        let tmp = tempfile::tempdir().unwrap();
        overlay_fixture(tmp.path(), FIXTURE_BINS, FIXTURE_STAGING, FIXTURE_FLAKE);
        // Rewrite the build file with one call wrapped the way rustfmt wraps
        // a long line; extraction must not depend on single-line calls.
        std::fs::write(
            tmp.path().join(GUEST_AGENT_BUILD),
            format!(
                "fn build_runtime_overlay_guest_binaries_into_cache() {{\n\
                 let prod_args = vec![{FIXTURE_BINS}];\n\
                 run_zigbuild(&spec, &prod_args)?;\n\
                 install_one(&output_dir.join(\"mvm-guest-agent\"), &layout.agent)?;\n\
                 install_one(\n    &output_dir.join(\"mvm-ping\"),\n    &layout.ping,\n)?;\n}}\n"
            ),
        )
        .unwrap();
        assert_eq!(
            check_overlay_parity(tmp.path(), &fixture_universe()).unwrap(),
            2
        );
    }

    #[test]
    fn overlay_parity_passes_on_agreeing_lists() {
        let tmp = tempfile::tempdir().unwrap();
        overlay_fixture(tmp.path(), FIXTURE_BINS, FIXTURE_STAGING, FIXTURE_FLAKE);
        assert_eq!(
            check_overlay_parity(tmp.path(), &fixture_universe()).unwrap(),
            2
        );
    }

    #[test]
    fn orphaned_bin_flag_fails_by_name() {
        let tmp = tempfile::tempdir().unwrap();
        let orphaned = r#""--bin".to_string(), "--bin".to_string(), "mvm-ping".to_string()"#;
        overlay_fixture(tmp.path(), orphaned, FIXTURE_STAGING, FIXTURE_FLAKE);
        let error = check_overlay_parity(tmp.path(), &fixture_universe())
            .unwrap_err()
            .to_string();
        assert!(error.contains("orphaned `--bin` flag"), "{error}");
    }

    #[test]
    fn flake_missing_a_bin_is_drift() {
        let tmp = tempfile::tempdir().unwrap();
        overlay_fixture(
            tmp.path(),
            FIXTURE_BINS,
            FIXTURE_STAGING,
            "cp ${guest}/bin/mvm-guest-agent \"$staging/agent\"\n",
        );
        let error = check_overlay_parity(tmp.path(), &fixture_universe())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("runtime-overlay binary lists drift"),
            "{error}"
        );
    }

    #[test]
    fn rust_staging_missing_a_name_is_drift() {
        let tmp = tempfile::tempdir().unwrap();
        overlay_fixture(
            tmp.path(),
            FIXTURE_BINS,
            r#"(&bins.agent, root.join("agent"))"#,
            FIXTURE_FLAKE,
        );
        let error = check_overlay_parity(tmp.path(), &fixture_universe())
            .unwrap_err()
            .to_string();
        assert!(error.contains("staged-name sets drift"), "{error}");
    }

    #[test]
    fn staged_name_disagreement_between_rust_and_flake_fails() {
        let tmp = tempfile::tempdir().unwrap();
        overlay_fixture(
            tmp.path(),
            FIXTURE_BINS,
            r#"(&bins.agent, root.join("agent")), (&bins.ping, root.join("icmp"))"#,
            "cp ${guest}/bin/mvm-guest-agent \"$staging/agent\"\n\
             cp ${guest}/bin/mvm-ping \"$staging/icmp\"\n",
        );
        let error = check_overlay_parity(tmp.path(), &fixture_universe())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("field and staged name must correspond"),
            "{error}"
        );
    }

    #[test]
    fn real_workspace_overlay_lists_agree_on_the_nine_binaries() {
        let root = workspace_root();
        let universe = guest_bin_universe(&root).unwrap();
        assert_eq!(check_overlay_parity(&root, &universe).unwrap(), 9);
        let gab = read(&root, GUEST_AGENT_BUILD).unwrap();
        let argv = slice_between(
            &gab,
            "fn build_runtime_overlay_guest_binaries_into_cache",
            "run_zigbuild(&spec, &prod_args)",
            GUEST_AGENT_BUILD,
        )
        .unwrap();
        let bins = extract_bin_flags(argv);
        for name in ["mvm-ping", "mvm-display-bridge"] {
            assert!(bins.contains(name), "{name} must be an overlay binary");
        }
    }

    #[test]
    fn universe_contains_the_runtime_bins() {
        let universe = guest_bin_universe(&workspace_root()).unwrap();
        for b in [
            "mvm-oci-entrypoint",
            "mvm-guest-agent",
            "mvm-guest-netinit",
            "mvm-egress-client",
        ] {
            assert!(universe.contains(b), "{b} must be a known guest [[bin]]");
        }
    }
}
