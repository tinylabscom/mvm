//! Shared resolver for the per-VM host helper binaries `mvmctl` spawns — the
//! backend supervisors (`mvm-hvf-supervisor`, …) and the substitution endpoint
//! (`mvm-substitution-endpoint`). Each is a separate `[[bin]]` in a workspace
//! crate, so a `cargo run` that builds only `mvmctl` never produces them and a
//! fresh `machine run` would fail with "binary not found".
//!
//! Resolution order: `$<ENV_VAR>` override → alongside the current exe →
//! workspace `target/{release,debug}` → (source checkout only) build it so the
//! command just works with no manual step. A downloaded release ships these next
//! to `mvmctl` and is resolved by the sibling check before ever building.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use anyhow::{Context, Result, bail};

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
    /// Workspace-relative files/directories whose mtimes determine whether an
    /// existing source-checkout binary needs to be rebuilt.
    pub input_roots: &'a [&'a str],
}

/// Resolve `spec` to an on-disk binary, building it on a source checkout when it
/// is missing or older than its source inputs. See the module docs for the
/// resolution order.
pub(crate) fn resolve_or_build(spec: &AuxBin) -> Result<PathBuf> {
    let workspace_root = workspace_root_from_manifest_dir();
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
            return existing_source_candidate_or_rebuild(
                candidate,
                workspace_root.as_deref(),
                spec,
            );
        }
    }
    if let Some(workspace_root) = workspace_root.as_deref() {
        for target_dir in source_checkout_target_dirs(workspace_root) {
            for variant in ["release", "debug"] {
                let candidate = target_dir.join(variant).join(spec.bin);
                if candidate.is_file() {
                    return existing_source_candidate_or_rebuild(
                        candidate,
                        Some(workspace_root),
                        spec,
                    );
                }
            }
        }
        // Source checkout: build the missing helper (matching the running
        // profile). The outer `cargo run` has released the build lock by the
        // time this process runs, so the nested build does not contend.
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

fn workspace_root_from_manifest_dir() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.parent()?.parent().map(Path::to_path_buf)
}

fn existing_source_candidate_or_rebuild(
    candidate: PathBuf,
    workspace_root: Option<&Path>,
    spec: &AuxBin,
) -> Result<PathBuf> {
    let Some(workspace_root) = workspace_root else {
        return Ok(candidate);
    };
    if !is_source_checkout_binary(&candidate, workspace_root)
        || !source_candidate_needs_rebuild(&candidate, workspace_root, spec)?
    {
        return Ok(candidate);
    }

    if let Some(built) = build_in_workspace(workspace_root, spec) {
        return Ok(built);
    }
    bail!(
        "{} is older than its source inputs and the automatic rebuild failed. Rebuild it with: {}",
        candidate.display(),
        rebuild_command_for_current_profile(spec)
    );
}

fn is_source_checkout_binary(candidate: &Path, workspace_root: &Path) -> bool {
    is_source_checkout_binary_in_target_dirs(
        candidate,
        &source_checkout_target_dirs(workspace_root),
    )
}

fn is_source_checkout_binary_in_target_dirs(candidate: &Path, target_dirs: &[PathBuf]) -> bool {
    target_dirs
        .iter()
        .any(|target_dir| candidate.starts_with(target_dir))
}

fn source_checkout_target_dirs(workspace_root: &Path) -> Vec<PathBuf> {
    let default_target_dir = workspace_root.join("target");
    let effective_target_dir = effective_cargo_target_dir(workspace_root);
    if effective_target_dir == default_target_dir {
        vec![default_target_dir]
    } else {
        vec![effective_target_dir, default_target_dir]
    }
}

fn effective_cargo_target_dir(workspace_root: &Path) -> PathBuf {
    cargo_target_dir_from_env(workspace_root, std::env::var_os("CARGO_TARGET_DIR"))
}

fn cargo_target_dir_from_env(workspace_root: &Path, target_dir: Option<OsString>) -> PathBuf {
    let Some(target_dir) = target_dir else {
        return workspace_root.join("target");
    };
    if target_dir.is_empty() {
        return workspace_root.join("target");
    }
    let target_dir = PathBuf::from(target_dir);
    if target_dir.is_absolute() {
        target_dir
    } else {
        workspace_root.join(target_dir)
    }
}

fn source_candidate_needs_rebuild(
    candidate: &Path,
    workspace_root: &Path,
    spec: &AuxBin,
) -> Result<bool> {
    let helper_paths = [candidate.to_path_buf()];
    helper_binaries_need_rebuild(&helper_paths, &source_input_roots(workspace_root, spec))
}

fn source_input_roots(workspace_root: &Path, spec: &AuxBin) -> Vec<PathBuf> {
    if !spec.input_roots.is_empty() {
        return spec
            .input_roots
            .iter()
            .map(|root| workspace_root.join(root))
            .collect();
    }
    let package_root = workspace_root.join("crates").join(spec.package);
    [
        workspace_root.join("Cargo.toml"),
        workspace_root.join("Cargo.lock"),
        package_root.join("Cargo.toml"),
        package_root.join("src"),
    ]
    .into()
}

fn rebuild_command_for_current_profile(spec: &AuxBin) -> String {
    let mut cmd = format!("cargo build -p {} --bin {}", spec.package, spec.bin);
    if current_exe_looks_release() {
        cmd.push_str(" --release");
    }
    if !spec.features.is_empty() {
        cmd.push_str(" --features ");
        cmd.push_str(&spec.features.join(","));
    }
    cmd
}

/// On-demand build of a helper for a source checkout. Returns the built binary,
/// or `None` if the build could not run (no cargo, build failed) — the caller
/// then falls through to the bail with the override hint.
fn build_in_workspace(workspace_root: &Path, spec: &AuxBin) -> Option<PathBuf> {
    let release = current_exe_looks_release();
    let variant = if release { "release" } else { "debug" };
    ui::info(&format!(
        "building the per-VM helper {} for this source checkout — `cargo run` builds only mvmctl, not this helper",
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
    let built = effective_cargo_target_dir(workspace_root)
        .join(variant)
        .join(spec.bin);
    built.is_file().then_some(built)
}

fn current_exe_looks_release() -> bool {
    std::env::current_exe()
        .ok()
        .map(|p| p.components().any(|c| c.as_os_str() == "release"))
        .unwrap_or(false)
}

pub(crate) fn helper_binaries_need_rebuild(
    helper_paths: &[PathBuf],
    input_roots: &[PathBuf],
) -> Result<bool> {
    let mut oldest_helper: Option<SystemTime> = None;
    for helper in helper_paths {
        let Ok(meta) = std::fs::metadata(helper) else {
            return Ok(true);
        };
        let modified = meta
            .modified()
            .with_context(|| format!("reading mtime for {}", helper.display()))?;
        oldest_helper = Some(match oldest_helper {
            Some(current) => current.min(modified),
            None => modified,
        });
    }
    let Some(oldest_helper) = oldest_helper else {
        return Ok(true);
    };
    let newest_input = newest_modified_input(input_roots)?;
    Ok(newest_input.is_some_and(|modified| modified > oldest_helper))
}

fn newest_modified_input(input_roots: &[PathBuf]) -> Result<Option<SystemTime>> {
    let mut newest = None;
    for root in input_roots {
        newest = max_system_time(newest, newest_modified_under(root)?);
    }
    Ok(newest)
}

fn newest_modified_under(path: &Path) -> Result<Option<SystemTime>> {
    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(None);
    };
    let mut newest = Some(
        meta.modified()
            .with_context(|| format!("reading mtime for {}", path.display()))?,
    );
    if meta.is_dir() {
        for entry in
            std::fs::read_dir(path).with_context(|| format!("reading dir {}", path.display()))?
        {
            let entry =
                entry.with_context(|| format!("reading dir entry under {}", path.display()))?;
            newest = max_system_time(newest, newest_modified_under(&entry.path())?);
        }
    }
    Ok(newest)
}

fn max_system_time(a: Option<SystemTime>, b: Option<SystemTime>) -> Option<SystemTime> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn source_candidate_check_is_limited_to_workspace_target() {
        let root = Path::new("/repo/mvm");
        assert!(is_source_checkout_binary_in_target_dirs(
            Path::new("/repo/mvm/target/release/mvm-hvf-supervisor"),
            &[root.join("target")]
        ));
        assert!(!is_source_checkout_binary_in_target_dirs(
            Path::new("/usr/local/bin/mvm-hvf-supervisor"),
            &[root.join("target")]
        ));
    }

    #[test]
    fn cargo_target_dir_from_env_honors_absolute_and_relative_overrides() {
        let root = Path::new("/repo/mvm");

        assert_eq!(cargo_target_dir_from_env(root, None), root.join("target"));
        assert_eq!(
            cargo_target_dir_from_env(root, Some(OsString::from("/tmp/mvm-target"))),
            Path::new("/tmp/mvm-target")
        );
        assert_eq!(
            cargo_target_dir_from_env(root, Some(OsString::from("build/target"))),
            root.join("build/target")
        );
    }

    #[test]
    fn source_candidate_check_includes_effective_cargo_target_dir() {
        let helper = Path::new("/tmp/mvm-target/release/mvm-hvf-supervisor");
        assert!(is_source_checkout_binary_in_target_dirs(
            helper,
            &[
                PathBuf::from("/tmp/mvm-target"),
                PathBuf::from("/repo/mvm/target")
            ]
        ));
    }

    #[test]
    fn current_profile_rebuild_command_names_bin_and_package() {
        let spec = AuxBin {
            bin: "mvm-hvf-supervisor",
            package: "mvm-vm-host",
            env_var: "MVM_HVF_SUPERVISOR_PATH",
            features: &[],
            input_roots: &[],
        };
        let cmd = rebuild_command_for_current_profile(&spec);
        assert!(cmd.contains("cargo build"));
        assert!(cmd.contains("mvm-vm-host"));
        assert!(cmd.contains("mvm-hvf-supervisor"));
    }

    #[test]
    fn source_input_roots_use_explicit_roots_when_provided() {
        let spec = AuxBin {
            bin: "mvm-hvf-supervisor",
            package: "mvm-vm-host",
            env_var: "MVM_HVF_SUPERVISOR_PATH",
            features: &[],
            input_roots: &["Cargo.toml", "crates/mvm-vm-host/src"],
        };
        let roots = source_input_roots(Path::new("/repo/mvm"), &spec);
        assert_eq!(roots[0], Path::new("/repo/mvm/Cargo.toml"));
        assert_eq!(roots[1], Path::new("/repo/mvm/crates/mvm-vm-host/src"));
    }

    #[test]
    fn helper_binaries_need_rebuild_when_any_helper_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let helper = tmp.path().join("mvm-hvf-supervisor");
        let missing = tmp.path().join("mvm-substitution-endpoint");
        std::fs::write(&helper, b"helper").unwrap();
        let input = tmp.path().join("Cargo.lock");
        std::fs::write(&input, b"lock").unwrap();

        assert!(
            helper_binaries_need_rebuild(&[helper, missing], &[input])
                .expect("freshness check succeeds")
        );
    }

    #[test]
    fn helper_binaries_skip_rebuild_when_helpers_are_newer_than_inputs() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("Cargo.lock");
        std::fs::write(&input, b"lock").unwrap();
        sleep_for_mtime_tick();
        let helper = tmp.path().join("mvm-hvf-supervisor");
        std::fs::write(&helper, b"helper").unwrap();

        assert!(
            !helper_binaries_need_rebuild(&[helper], &[input]).expect("freshness check succeeds")
        );
    }

    #[test]
    fn helper_binaries_need_rebuild_when_source_input_is_newer() {
        let tmp = tempfile::tempdir().unwrap();
        let helper = tmp.path().join("mvm-hvf-supervisor");
        std::fs::write(&helper, b"helper").unwrap();
        sleep_for_mtime_tick();
        let input_dir = tmp.path().join("crates").join("mvm-vm-host").join("src");
        std::fs::create_dir_all(&input_dir).unwrap();
        let input = input_dir.join("main.rs");
        std::fs::write(&input, b"fn main() {}").unwrap();

        assert!(
            helper_binaries_need_rebuild(&[helper], &[input_dir])
                .expect("freshness check succeeds")
        );
    }

    fn sleep_for_mtime_tick() {
        std::thread::sleep(Duration::from_millis(25));
    }
}
