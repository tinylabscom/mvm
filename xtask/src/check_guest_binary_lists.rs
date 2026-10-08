//! `xtask check-guest-binary-lists`
//!
//! CI lint — the guest runtime binaries baked into an OCI `run --image` rootfs
//! are named in two hand-maintained lists that must stay in lockstep:
//!
//! - `crates/mvm-build/src/guest_agent_build.rs` — the `cargo zigbuild --bin`
//!   invocation that actually builds them (the authoritative list).
//! - `crates/mvm-build/src/oci_runtime_inject.rs` — the `MvmRuntimeBinaries`
//!   struct whose field docs name each bin.
//!
//! The check asserts those two sets are identical to each other AND that every
//! name is a real `[[bin]]` of `mvm-agentd`. A drift — a
//! renamed bin, a list left behind, or a name that no longer maps to a bin —
//! fails here instead of silently shipping a rootfs missing (or misnaming) a
//! guest binary. It separately asserts that `mvm-cli/build.rs` has no guest
//! `--bin` list: workload binaries belong to the initramfs/runtime artifacts,
//! never the host CLI executable.
//!
//! A second section ([`check_overlay_parity`]) holds the runtime overlay's
//! own binary lists — the two overlay build lists (sealed bins, and the
//! `addons` bins built in their own invocation), the `install_one` pairs, and
//! the Rust staging array — in the same lockstep, and rejects an orphaned
//! `--bin` flag left behind by a removed binary name. It also holds the split
//! itself: the `addons` list must be exactly the overlay bins whose `[[bin]]`
//! requires `addons`, and only that invocation may enable the feature, so
//! cargo's feature unification cannot hand the sealed agent an async runtime.
//! The published overlay is built in mvm-images, which stages from these same
//! bins through its `mvm` input and guards its own flake.

use anyhow::{Context, Result, bail};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const GUEST_AGENT_BUILD: &str = "crates/mvm-build/src/guest_agent_build.rs";
const CLI_BUILD_RS: &str = "crates/mvm-cli/build.rs";
const OCI_INJECT: &str = "crates/mvm-build/src/oci_runtime_inject.rs";
const RUNTIME_OVERLAY_RS: &str = "crates/mvm-build/src/runtime_overlay.rs";

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
        "check-guest-binary-lists: {} artifact lists agree on {} guest binaries; overlay lists agree on {overlay}; mvm-cli embeds none",
        lists.len(),
        canonical.len()
    );
    Ok(())
}

/// The read-only runtime overlay's binary set is maintained in two places:
/// the overlay `cargo zigbuild` bin list plus its `install_one` pairs
/// (`guest_agent_build.rs`), and the staging array that writes the overlay
/// root (`runtime_overlay.rs`). Lists like these drifted once — an image
/// shipped `display-bridge` but not `ping` while the Rust builder did the
/// reverse, so `/bin/ping` mediation silently no-oped — and an orphaned
/// `--bin` flag survived a bin removal because cargo happened to absorb the
/// malformed pair. This section keeps the lists in lockstep and rejects a
/// `--bin` flag not followed by a binary name.
fn check_overlay_parity(workspace: &Path, universe: &BTreeSet<String>) -> Result<usize> {
    let gab = read(workspace, GUEST_AGENT_BUILD)?;
    let orphan = Regex::new(r#""--bin"(?:\.to_string\(\))?\s*,\s*"--bin""#).unwrap();
    if orphan.is_match(&gab) {
        bail!(
            "orphaned `--bin` flag in {GUEST_AGENT_BUILD}: a `\"--bin\"` is immediately \
             followed by another `\"--bin\"`, so a binary name was removed without its flag"
        );
    }

    let sealed_bins = extract_const_names(&gab, SEALED_BINS_CONST)?;
    let addon_bins = extract_const_names(&gab, ADDON_BINS_CONST)?;
    check_overlay_invocations(&gab)?;
    if let Some(both) = sealed_bins.intersection(&addon_bins).next() {
        bail!(
            "{both} is in both {SEALED_BINS_CONST} and {ADDON_BINS_CONST}; it would be built \
             twice, once with `addons`"
        );
    }
    let requires_addons = addon_bin_universe(workspace)?;
    let overlay_bins: BTreeSet<String> = sealed_bins.union(&addon_bins).cloned().collect();
    let expected_addons: BTreeSet<String> = overlay_bins
        .intersection(&requires_addons)
        .cloned()
        .collect();
    if addon_bins != expected_addons {
        bail!(
            "{ADDON_BINS_CONST} = {addon_bins:?}, but the overlay bins whose `[[bin]]` requires \
             `addons` are {expected_addons:?}. Only those may be built with the feature: cargo \
             unifies features across an invocation, so a sealed bin listed there links tokio, \
             and an addon bin listed with the sealed set does not build"
        );
    }

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

    for (label, len) in [
        ("overlay build lists", overlay_bins.len()),
        ("install_one pairs", bin_to_field.len()),
        ("runtime_overlay.rs staging array", field_to_staged.len()),
    ] {
        if len == 0 {
            bail!(
                "no overlay binary names extracted from the {label}; the list moved — update this check"
            );
        }
    }

    let install_bins: BTreeSet<String> = bin_to_field.keys().cloned().collect();
    if install_bins != overlay_bins {
        bail!(
            "runtime-overlay binary lists drift:\n  overlay build lists = {overlay_bins:?}\n  install_one bin set = {install_bins:?}"
        );
    }
    let installed_fields: BTreeSet<&String> = bin_to_field.values().collect();
    let staged_fields: BTreeSet<&String> = field_to_staged.keys().collect();
    if installed_fields != staged_fields {
        bail!(
            "runtime-overlay staged-name sets drift:\n  install_one fields = {installed_fields:?}\n  runtime_overlay.rs stages = {staged_fields:?}"
        );
    }

    // Every installed field must be staged, under the name the field spells.
    for (bin, field) in &bin_to_field {
        let via_rust = field_to_staged.get(field).with_context(|| {
            format!("overlay bin {bin} installs into layout field {field}, which the runtime_overlay.rs staging array never stages")
        })?;
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

const SEALED_BINS_CONST: &str = "RUNTIME_OVERLAY_SEALED_BINS";
const ADDON_BINS_CONST: &str = "RUNTIME_OVERLAY_ADDON_BINS";
const ADDONS_FEATURE_CONST: &str = "MVM_AGENTD_ADDONS_FEATURE";
const OVERLAY_ARGS_FN: &str = "fn runtime_overlay_zigbuild_args";

/// The quoted `mvm-*` names in `pub const <name>: [&str; N] = [ ... ];`.
fn extract_const_names(src: &str, name: &str) -> Result<BTreeSet<String>> {
    let block = slice_between(src, &format!("pub const {name}:"), "];", GUEST_AGENT_BUILD)?;
    let re = Regex::new(r#""(mvm-[a-z0-9-]+)""#).unwrap();
    let names: BTreeSet<String> = re.captures_iter(block).map(|c| c[1].to_string()).collect();
    if names.is_empty() {
        bail!("no binary names extracted from {name}; the list moved — update this check");
    }
    Ok(names)
}

/// The overlay's argument builder must build each list in its own invocation
/// and enable `addons` in exactly one of them; which one is pinned by
/// `mvm-build`'s own test of that function.
fn check_overlay_invocations(src: &str) -> Result<()> {
    let body = slice_between(src, OVERLAY_ARGS_FN, "\n}\n", GUEST_AGENT_BUILD)?;
    for list in [SEALED_BINS_CONST, ADDON_BINS_CONST] {
        if body.matches(&format!("&{list}")).count() != 1 {
            bail!("{OVERLAY_ARGS_FN} must build {list} exactly once, in its own invocation");
        }
    }
    let features = body.matches(ADDONS_FEATURE_CONST).count();
    if features != 1 {
        bail!(
            "{OVERLAY_ARGS_FN} enables {ADDONS_FEATURE_CONST} {features} times; exactly one \
             invocation (the addon bins') may enable it"
        );
    }
    if !src.contains(&format!(
        "for args in {}(",
        OVERLAY_ARGS_FN.trim_start_matches("fn ")
    )) {
        bail!("the overlay build no longer runs every invocation {OVERLAY_ARGS_FN} returns");
    }
    Ok(())
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

/// `mvm-agentd` `[[bin]]`s that declare `required-features` naming `addons`.
fn addon_bin_universe(workspace: &Path) -> Result<BTreeSet<String>> {
    let path = workspace.join("crates/mvm-agentd/Cargo.toml");
    let src = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(parse_bins_requiring(&src, "addons"))
}

/// `[[bin]]` names whose `required-features` list includes `feature`.
fn parse_bins_requiring(manifest: &str, feature: &str) -> BTreeSet<String> {
    let name_re = Regex::new(r#"^\s*name\s*=\s*"([^"]+)""#).unwrap();
    let mut out = BTreeSet::new();
    let mut in_bin = false;
    let mut name: Option<String> = None;
    let quoted = format!("\"{feature}\"");
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_bin = t == "[[bin]]";
            name = None;
            continue;
        }
        if !in_bin {
            continue;
        }
        if let Some(c) = name_re.captures(line) {
            name = Some(c[1].to_string());
        } else if t.starts_with("required-features")
            && t.contains(&quoted)
            && let Some(name) = &name
        {
            out.insert(name.clone());
        }
    }
    out
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
        assert!(
            extract_bin_flags_from_file(&root, CLI_BUILD_RS)
                .unwrap()
                .is_empty(),
            "mvm-cli must not cross-compile workload guest binaries"
        );
    }

    const FIXTURE_MANIFEST: &str = r#"
[package]
name = "mvm-agentd"

[[bin]]
name = "mvm-guest-agent"

[[bin]]
name = "mvm-ping"

[[bin]]
name = "mvm-egress-client"
required-features = ["addons"]
"#;

    const FIXTURE_ARGS_FN: &str = "fn runtime_overlay_zigbuild_args(triple: &str) -> [Vec<String>; 2] {\n\
         let mut addons = package_bin_args(\"mvm-agentd\", &RUNTIME_OVERLAY_ADDON_BINS);\n\
         addons.push(MVM_AGENTD_ADDONS_FEATURE.to_string());\n\
         [release(package_bin_args(\"mvm-agentd\", &RUNTIME_OVERLAY_SEALED_BINS)), release(addons)]\n\
         }\n";

    /// A `guest_agent_build.rs` with the given sealed and addon lists, the
    /// given argument builder, and `installs`; a staging array of `staging`.
    fn overlay_fixture_with(
        root: &Path,
        sealed: &str,
        addons: &str,
        args_fn: &str,
        installs: &str,
        staging: &str,
    ) {
        let write = |rel: &str, text: &str| {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write(
            GUEST_AGENT_BUILD,
            &format!(
                "pub const RUNTIME_OVERLAY_SEALED_BINS: [&str; 2] = [{sealed}];\n\
                 pub const RUNTIME_OVERLAY_ADDON_BINS: [&str; 1] = [{addons}];\n\
                 {args_fn}\
                 fn build_runtime_overlay_guest_binaries_into_cache() {{\n\
                 for args in runtime_overlay_zigbuild_args(spec.target_triple()) {{\n\
                 run_zigbuild(&lock, &spec, &args, &[])?;\n}}\n\
                 {installs}}}\n"
            ),
        );
        write(
            RUNTIME_OVERLAY_RS,
            &format!("let binaries = [{staging}];\n"),
        );
        write("crates/mvm-agentd/Cargo.toml", FIXTURE_MANIFEST);
    }

    const FIXTURE_SEALED: &str = r#""mvm-guest-agent", "mvm-ping""#;
    const FIXTURE_ADDONS: &str = r#""mvm-egress-client""#;
    const FIXTURE_INSTALLS: &str = "install_one(&output_dir.join(\"mvm-guest-agent\"), &layout.agent)?;\n\
         install_one(&output_dir.join(\"mvm-ping\"), &layout.ping)?;\n\
         install_one(&output_dir.join(\"mvm-egress-client\"), &layout.egress_client)?;\n";
    const FIXTURE_STAGING: &str = r#"(&bins.agent, root.join("agent")), (&bins.ping, root.join("ping")), (&bins.egress_client, root.join("egress-client"))"#;

    fn overlay_fixture(root: &Path) {
        overlay_fixture_with(
            root,
            FIXTURE_SEALED,
            FIXTURE_ADDONS,
            FIXTURE_ARGS_FN,
            FIXTURE_INSTALLS,
            FIXTURE_STAGING,
        );
    }

    fn fixture_universe() -> BTreeSet<String> {
        BTreeSet::from([
            "mvm-guest-agent".to_string(),
            "mvm-ping".to_string(),
            "mvm-egress-client".to_string(),
        ])
    }

    fn parity_error(root: &Path) -> String {
        check_overlay_parity(root, &fixture_universe())
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn rustfmt_wrapped_install_calls_are_still_extracted() {
        let tmp = tempfile::tempdir().unwrap();
        overlay_fixture_with(
            tmp.path(),
            FIXTURE_SEALED,
            FIXTURE_ADDONS,
            FIXTURE_ARGS_FN,
            "install_one(&output_dir.join(\"mvm-guest-agent\"), &layout.agent)?;\n\
             install_one(\n    &output_dir.join(\"mvm-ping\"),\n    &layout.ping,\n)?;\n\
             install_one(&output_dir.join(\"mvm-egress-client\"), &layout.egress_client)?;\n",
            FIXTURE_STAGING,
        );
        assert_eq!(
            check_overlay_parity(tmp.path(), &fixture_universe()).unwrap(),
            3
        );
    }

    #[test]
    fn overlay_parity_passes_on_agreeing_lists() {
        let tmp = tempfile::tempdir().unwrap();
        overlay_fixture(tmp.path());
        assert_eq!(
            check_overlay_parity(tmp.path(), &fixture_universe()).unwrap(),
            3
        );
    }

    #[test]
    fn orphaned_bin_flag_fails_by_name() {
        let tmp = tempfile::tempdir().unwrap();
        overlay_fixture(tmp.path());
        let path = tmp.path().join(GUEST_AGENT_BUILD);
        let mut src = std::fs::read_to_string(&path).unwrap();
        src.push_str(r#"vec!["--bin".to_string(), "--bin".to_string(), "mvm-ping".to_string()];"#);
        std::fs::write(&path, src).unwrap();
        assert!(
            parity_error(tmp.path()).contains("orphaned `--bin` flag"),
            "{}",
            parity_error(tmp.path())
        );
    }

    #[test]
    fn a_built_bin_that_is_never_installed_is_drift() {
        let tmp = tempfile::tempdir().unwrap();
        overlay_fixture_with(
            tmp.path(),
            r#""mvm-guest-agent", "mvm-ping", "mvm-extra""#,
            FIXTURE_ADDONS,
            FIXTURE_ARGS_FN,
            FIXTURE_INSTALLS,
            FIXTURE_STAGING,
        );
        let error = parity_error(tmp.path());
        assert!(
            error.contains("runtime-overlay binary lists drift"),
            "{error}"
        );
    }

    /// A sealed bin moved into the addon invocation would link tokio.
    #[test]
    fn a_sealed_bin_built_with_addons_fails() {
        let tmp = tempfile::tempdir().unwrap();
        overlay_fixture_with(
            tmp.path(),
            r#""mvm-ping""#,
            r#""mvm-egress-client", "mvm-guest-agent""#,
            FIXTURE_ARGS_FN,
            FIXTURE_INSTALLS,
            FIXTURE_STAGING,
        );
        let error = parity_error(tmp.path());
        assert!(error.contains("requires `addons`"), "{error}");
    }

    #[test]
    fn an_addon_bin_in_the_sealed_list_fails() {
        let tmp = tempfile::tempdir().unwrap();
        overlay_fixture_with(
            tmp.path(),
            r#""mvm-guest-agent", "mvm-ping", "mvm-egress-client""#,
            r#""mvm-egress-client""#,
            FIXTURE_ARGS_FN,
            FIXTURE_INSTALLS,
            FIXTURE_STAGING,
        );
        let error = parity_error(tmp.path());
        assert!(error.contains("in both"), "{error}");
    }

    /// One invocation building both lists is the unification this guards.
    #[test]
    fn building_both_lists_in_one_invocation_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let merged = "fn runtime_overlay_zigbuild_args(triple: &str) -> [Vec<String>; 1] {\n\
             let mut all = package_bin_args(\"mvm-agentd\", &RUNTIME_OVERLAY_SEALED_BINS);\n\
             all.push(MVM_AGENTD_ADDONS_FEATURE.to_string());\n\
             [release(all)]\n\
             }\n";
        overlay_fixture_with(
            tmp.path(),
            FIXTURE_SEALED,
            FIXTURE_ADDONS,
            merged,
            FIXTURE_INSTALLS,
            FIXTURE_STAGING,
        );
        let error = parity_error(tmp.path());
        assert!(
            error.contains("must build RUNTIME_OVERLAY_ADDON_BINS exactly once"),
            "{error}"
        );
    }

    #[test]
    fn enabling_addons_twice_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let twice = FIXTURE_ARGS_FN.replace(
            "[release(package_bin_args",
            "let _ = MVM_AGENTD_ADDONS_FEATURE;\n[release(package_bin_args",
        );
        overlay_fixture_with(
            tmp.path(),
            FIXTURE_SEALED,
            FIXTURE_ADDONS,
            &twice,
            FIXTURE_INSTALLS,
            FIXTURE_STAGING,
        );
        let error = parity_error(tmp.path());
        assert!(error.contains("2 times"), "{error}");
    }

    #[test]
    fn rust_staging_missing_a_name_is_drift() {
        let tmp = tempfile::tempdir().unwrap();
        overlay_fixture_with(
            tmp.path(),
            FIXTURE_SEALED,
            FIXTURE_ADDONS,
            FIXTURE_ARGS_FN,
            FIXTURE_INSTALLS,
            r#"(&bins.agent, root.join("agent")), (&bins.ping, root.join("ping"))"#,
        );
        let error = parity_error(tmp.path());
        assert!(error.contains("staged-name sets drift"), "{error}");
    }

    #[test]
    fn a_field_staged_under_another_name_fails() {
        let tmp = tempfile::tempdir().unwrap();
        overlay_fixture_with(
            tmp.path(),
            FIXTURE_SEALED,
            FIXTURE_ADDONS,
            FIXTURE_ARGS_FN,
            FIXTURE_INSTALLS,
            r#"(&bins.agent, root.join("agent")), (&bins.ping, root.join("icmp")), (&bins.egress_client, root.join("egress-client"))"#,
        );
        let error = parity_error(tmp.path());
        assert!(
            error.contains("field and staged name must correspond"),
            "{error}"
        );
    }

    #[test]
    fn parse_bins_requiring_reads_required_features() {
        assert_eq!(
            parse_bins_requiring(FIXTURE_MANIFEST, "addons"),
            BTreeSet::from(["mvm-egress-client".to_string()])
        );
    }

    #[test]
    fn real_workspace_overlay_lists_agree_on_the_overlay_binaries() {
        let root = workspace_root();
        let universe = guest_bin_universe(&root).unwrap();
        assert_eq!(check_overlay_parity(&root, &universe).unwrap(), 11);
        let gab = read(&root, GUEST_AGENT_BUILD).unwrap();
        let sealed = extract_const_names(&gab, SEALED_BINS_CONST).unwrap();
        for name in ["mvm-ping", "mvm-display-bridge", "mvm-guest-agent"] {
            assert!(
                sealed.contains(name),
                "{name} must be a sealed overlay binary"
            );
        }
        assert_eq!(
            extract_const_names(&gab, ADDON_BINS_CONST).unwrap(),
            BTreeSet::from(["mvm-egress-client".to_string(), "mvm-addon-dns".to_string()])
        );
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
