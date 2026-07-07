//! Shared resolver for the per-VM host helper binaries `mvmctl` spawns — the
//! backend supervisors (`mvm-hvf-supervisor`, …) and the substitution endpoint
//! (`mvm-substitution-endpoint`). Each is a separate `[[bin]]` in a workspace
//! crate, so a `cargo run` that builds only `mvmctl` never produces them and a
//! fresh `machine run` would fail with "binary not found".
//!
//! Resolution order: `$<ENV_VAR>` override → alongside the current exe →
//! workspace `target/{release,debug}` → (source checkout only) build it once so
//! the command just works with no manual step. A downloaded release ships these
//! next to `mvmctl` and is resolved by the sibling check before ever building.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Result, bail};

use crate::base::ui;

/// A per-VM helper binary and how to build it from source.
pub(crate) struct AuxBin<'a> {
    /// Binary/file name, e.g. `mvm-hvf-supervisor`.
    pub bin: &'a str,
    /// Workspace package that owns the `[[bin]]`, e.g. `mvm-vm-host`.
    pub package: &'a str,
    /// Path-override env var, e.g. `MVM_HVF_SUPERVISOR_PATH`.
    pub env_var: &'a str,
    /// Cargo features required to build the bin (empty for most).
    pub features: &'a [&'a str],
}

/// Resolve `spec` to an on-disk binary, building it once on a source checkout if
/// it is missing. See the module docs for the resolution order.
pub(crate) fn resolve_or_build(spec: &AuxBin) -> Result<PathBuf> {
    if let Some(p) = std::env::var_os(spec.env_var).map(PathBuf::from) {
        if p.is_file() {
            return Ok(p);
        }
        bail!(
            "{} points at {} which is not a file",
            spec.env_var,
            p.display()
        );
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
    {
        let candidate = dir.join(spec.bin);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(workspace_root) = manifest_dir.parent().and_then(Path::parent) {
        for variant in ["release", "debug"] {
            let candidate = workspace_root.join("target").join(variant).join(spec.bin);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        // Source checkout: build the missing helper once (matching the running
        // profile). The outer `cargo run` has released the build lock by the time
        // this process runs, so the nested build does not contend.
        if workspace_root.join("Cargo.toml").is_file()
            && let Some(built) = build_in_workspace(workspace_root, spec)
        {
            return Ok(built);
        }
    }
    bail!(
        "{} binary not found (looked at ${}, alongside the current exe, and \
         <workspace>/target/{{release,debug}})",
        spec.bin,
        spec.env_var
    )
}

/// One-time on-demand build of a helper for a source checkout. Returns the built
/// binary, or `None` if the build could not run (no cargo, build failed) — the
/// caller then falls through to the bail with the override hint.
fn build_in_workspace(workspace_root: &Path, spec: &AuxBin) -> Option<PathBuf> {
    let release = std::env::current_exe()
        .ok()
        .map(|p| p.components().any(|c| c.as_os_str() == "release"))
        .unwrap_or(false);
    let variant = if release { "release" } else { "debug" };
    ui::info(&format!(
        "building the per-VM helper {} once — `cargo run` builds only mvmctl, not this helper",
        spec.bin
    ));
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(workspace_root)
        .args(["build", "-p", spec.package, "--bin", spec.bin]);
    if release {
        cmd.arg("--release");
    }
    if !spec.features.is_empty() {
        cmd.arg("--features").arg(spec.features.join(","));
    }
    if !cmd.status().map(|s| s.success()).unwrap_or(false) {
        return None;
    }
    let built = workspace_root.join("target").join(variant).join(spec.bin);
    built.is_file().then_some(built)
}
