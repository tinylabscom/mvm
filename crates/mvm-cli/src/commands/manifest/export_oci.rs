//! `mvmctl manifest export-oci` — copy a slot's OCI tarball to a
//! user-supplied path.
//!
//! The OCI tarball (`image.tar.gz`) is produced by `mkGuest`'s
//! `dockerTools.streamLayeredImage` when the flake opts in. After
//! `template_build_from_manifest` lands a slot, the tarball is
//! copied alongside the kernel and rootfs into the slot's current
//! revision directory. This verb makes that artifact user-facing:
//! `mvmctl manifest export-oci <template> --out ./foo.tar.gz`
//! produces a Docker/Podman-loadable image, extending mvm-built
//! workloads to hosts without KVM.
//!
//! Failure modes (each surfaces with a clear message):
//! - Template doesn't exist → "no slot named X; run mvmctl build"
//! - Slot exists but no current revision → "no current revision"
//! - Revision exists but no image.tar.gz → "this template wasn't
//!   built with the OCI output enabled — rebuild after wiring
//!   `dockerTools.streamLayeredImage` into mkGuest"
//! - Parent directory of `--out` doesn't exist → propagated I/O
//!   error pointing at the bad path

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm::vm::template::lifecycle as tmpl;
use mvm_core::manifest::{
    canonical_key_for_path, is_slot_hash_dirname, resolve_manifest_config_path, slot_dir,
};
use mvm_core::naming::validate_template_name;
use mvm_core::user_config::MvmConfig;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Template — either a 64-char hex slot hash, a manifest path
    /// (file or directory), or a legacy name-keyed template id.
    #[arg(value_name = "TEMPLATE")]
    pub template: String,
    /// Output path for the `image.tar.gz` archive. Parent directory
    /// must exist; the file is overwritten if present.
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    // Resolve the template arg to a slot hash. Three input shapes
    // all collapse to "give me the slot's current revision dir."
    let slot_hash = resolve_to_slot_hash(&args.template)?;

    // Walk into the current revision dir via the lifecycle module.
    // template_artifacts_dispatched already disambiguates slot vs.
    // bundle vs. legacy name; we reuse it so the resolution
    // matches what `mvmctl up` does.
    let (_, _vmlinux, _initrd, rootfs_path, _rev) = tmpl::template_artifacts_dispatched(&slot_hash)
        .with_context(|| format!("resolving template artifacts for {:?}", args.template))?;

    // The OCI tarball lives alongside the rootfs in the revision
    // directory. `template_build_from_manifest` copies it when the
    // flake's mkGuest emits one (via `dockerTools.streamLayeredImage`).
    let rev_dir = std::path::Path::new(&rootfs_path)
        .parent()
        .ok_or_else(|| anyhow::anyhow!("rootfs path has no parent: {rootfs_path}"))?;
    let oci_src = rev_dir.join("image.tar.gz");
    if !oci_src.exists() {
        anyhow::bail!(
            "no OCI tarball at {} — this template wasn't built with the OCI output enabled. \
             Rebuild after wiring `dockerTools.streamLayeredImage` into the flake's mkGuest \
             call, or use `mvmctl bundle export` for a signed .mvmpkg instead.",
            oci_src.display()
        );
    }

    // Ensure parent exists; mirror the bundle-export shape so the
    // CLI handles `--out ./newdir/foo.tar.gz` cleanly.
    if let Some(parent) = args.out.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir {}", parent.display()))?;
    }
    std::fs::copy(&oci_src, &args.out).with_context(|| {
        format!(
            "copying OCI tarball {} -> {}",
            oci_src.display(),
            args.out.display()
        )
    })?;
    let bytes = std::fs::metadata(&args.out).map(|m| m.len()).unwrap_or(0);

    mvm_core::audit_emit!(ImageExportOci, "template={slot_hash},bytes={bytes}");

    println!(
        "Exported OCI tarball to {} ({} bytes)",
        args.out.display(),
        bytes
    );
    println!("Load on a Docker / Podman host with:");
    println!("  docker load -i {}", args.out.display());
    Ok(())
}

/// Resolve a `<TEMPLATE>` arg to a slot hash. Accepts:
///   - a 64-char lowercase-hex slot hash (passed through)
///   - a manifest path (canonicalised + hashed)
///   - a legacy name (looked up via template_load_dispatched)
fn resolve_to_slot_hash(template: &str) -> Result<String> {
    if is_slot_hash_dirname(template) {
        // Caller already supplied a hash. Confirm the slot dir
        // actually exists; otherwise the downstream lookup
        // surfaces a confusing missing-file error.
        let dir = slot_dir(template);
        if std::path::Path::new(&dir).exists() {
            return Ok(template.to_string());
        }
        anyhow::bail!(
            "no slot at {} — run `mvmctl manifest ls` to list available slots",
            dir
        );
    }
    // Try resolving as a manifest path first.
    if let Ok(p) = resolve_manifest_config_path(std::path::Path::new(template)) {
        let canonical = std::fs::canonicalize(&p)
            .with_context(|| format!("canonicalising manifest path {}", p.display()))?;
        return canonical_key_for_path(&canonical)
            .with_context(|| format!("hashing canonical manifest path {}", canonical.display()));
    }
    // Fall back to legacy name lookup — let the lifecycle module
    // tell us whether the name resolves.
    validate_template_name(template)
        .with_context(|| format!("Invalid template name: {template:?}"))?;
    let spec = tmpl::template_load_dispatched(template)
        .with_context(|| format!("looking up template {template:?}"))?;
    Ok(spec.template_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_to_slot_hash_rejects_unknown_slot_hash() {
        // 64-char hex but no slot dir on disk — clear error.
        let bogus = "0".repeat(64);
        let err = resolve_to_slot_hash(&bogus).expect_err("must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no slot at") || msg.contains("manifest ls"),
            "got: {msg}"
        );
    }

    #[test]
    fn resolve_to_slot_hash_rejects_traversal_legacy_name() {
        let err = resolve_to_slot_hash("../../etc/x").expect_err("must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("template name"),
            "expected template-name validation error, got: {msg}"
        );
    }

    #[test]
    fn verb_registered_in_cli_command_tree() {
        // Smoke test that `mvmctl manifest export-oci` is present
        // in the top-level clap tree. Walks the command tree the
        // same way `audit_total_coverage` does so a future rename
        // gets caught here too.
        let root = crate::commands::cli_command();
        let manifest_sub = root
            .find_subcommand("manifest")
            .expect("manifest subcommand present");
        let names: Vec<&str> = manifest_sub
            .get_subcommands()
            .map(|s| s.get_name())
            .collect();
        assert!(
            names.contains(&"export-oci"),
            "export-oci missing from manifest subcommands: {names:?}"
        );
    }
}
