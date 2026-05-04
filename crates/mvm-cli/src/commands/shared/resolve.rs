//! Environment-aware resolution helpers (running VMs, flake refs, network policy).

use anyhow::{Context, Result};

use crate::bootstrap;

use mvm_runtime::config;
use mvm_runtime::shell;
use mvm_runtime::vm::{firecracker, lima};

/// Resolve a VM name to its absolute directory path inside the Lima VM
/// and verify it is running.
pub fn resolve_running_vm(name: &str) -> Result<String> {
    if bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    let abs_vms = shell::run_in_vm_stdout(&format!("echo {}", config::VMS_DIR))?;
    let abs_dir = format!("{}/{}", abs_vms, name);
    let pid_file = format!("{}/fc.pid", abs_dir);

    if !firecracker::is_vm_running(&pid_file)? {
        anyhow::bail!(
            "VM '{}' is not running. Use 'mvmctl status' to list running VMs.",
            name
        );
    }

    Ok(abs_dir)
}

/// One of two ways to refer to a built template: a legacy name (looked
/// up in the name-keyed registry) or a manifest path that resolves to
/// a slot hash.
///
/// `mvmctl up`/`run`/`exec` accept either form via their `--template`
/// flag during the plan-38 transition. The `Slot` variant is the new
/// path; `Name` will go away with slice 7's namespace removal.
///
/// Callers that need the persisted manifest re-read it via
/// `mvm_runtime::vm::template::lifecycle::template_load_slot(slot_hash)`
/// — keeping the enum lean here avoids the `clippy::large_enum_variant`
/// warning (`PersistedManifest` is ~350 bytes).
#[derive(Debug, Clone)]
pub enum TemplateArgRef {
    /// Legacy name-keyed template (resolves through `template_load`,
    /// `template_artifacts`, etc.).
    Name(String),
    /// Manifest-keyed slot.
    Slot { slot_hash: String },
}

/// Decide whether a `--template` argument refers to a manifest path
/// (file or directory containing one) or a legacy template name.
///
/// Detection rule: if the argument resolves to an existing file or
/// directory on disk, treat it as a manifest path; otherwise it's a
/// name. This lets users transparently use either form during the
/// plan-38 rollout — `mvmctl up --template ./my-app` and
/// `mvmctl up --template openclaw` both work as long as the
/// referenced thing actually exists.
///
/// Returns `Err` only on validation/IO failures; missing-name is
/// handled by the caller's downstream `template_load` lookup.
pub fn resolve_template_arg(arg: &str) -> Result<TemplateArgRef> {
    use mvm_core::manifest::{canonical_key_for_path, resolve_manifest_config_path};

    let path = std::path::Path::new(arg);
    let looks_like_path = arg.contains('/')
        || arg.starts_with('.')
        || arg.ends_with(".toml")
        || path.is_file()
        || path.is_dir();
    if !looks_like_path {
        return Ok(TemplateArgRef::Name(arg.to_string()));
    }

    if !path.exists() {
        anyhow::bail!(
            "Template path '{}' does not exist (expected a manifest file or its directory)",
            arg
        );
    }

    let manifest_path = resolve_manifest_config_path(path)
        .with_context(|| format!("Resolving --template {arg:?}"))?;
    let canonical = std::fs::canonicalize(&manifest_path).with_context(|| {
        format!(
            "Failed to canonicalize manifest path {}",
            manifest_path.display()
        )
    })?;
    let slot_hash = canonical_key_for_path(&canonical)?;

    // Verify the slot exists; surface a clear error otherwise so
    // `mvmctl up` doesn't proceed against a manifest that's never
    // been built. The slot's persisted record is dropped here —
    // callers that need it re-read via `template_load_slot`.
    mvm_runtime::vm::template::lifecycle::template_load_slot(&slot_hash).with_context(|| {
        format!(
            "Manifest at {} has no built slot — run `mvmctl build {}` first",
            canonical.display(),
            canonical.display()
        )
    })?;

    Ok(TemplateArgRef::Slot { slot_hash })
}

/// Resolve a flake reference: relative/absolute paths are canonicalized,
/// remote refs (containing `:`) pass through unchanged.
pub fn resolve_flake_ref(flake_ref: &str) -> Result<String> {
    if flake_ref.contains(':') {
        // Remote ref like "github:user/repo" — pass through
        return Ok(flake_ref.to_string());
    }

    // Local path — canonicalize to absolute
    let path = std::path::Path::new(flake_ref);
    let canonical = path
        .canonicalize()
        .with_context(|| format!("Flake path '{}' does not exist", flake_ref))?;

    Ok(canonical.to_string_lossy().to_string())
}

/// Resolve CLI network flags into a `NetworkPolicy`.
/// `--network-preset` and `--network-allow` are mutually exclusive.
pub fn resolve_network_policy(
    preset: Option<&str>,
    allow: &[String],
) -> Result<mvm_core::network_policy::NetworkPolicy> {
    use mvm_core::network_policy::{HostPort, NetworkPolicy, NetworkPreset};

    match (preset, allow.is_empty()) {
        (Some(_), false) => {
            anyhow::bail!("--network-preset and --network-allow are mutually exclusive")
        }
        (Some(name), true) => {
            let p: NetworkPreset = name.parse()?;
            Ok(NetworkPolicy::preset(p))
        }
        (None, false) => {
            let rules: Vec<HostPort> = allow
                .iter()
                .map(|s| s.parse())
                .collect::<Result<Vec<_>>>()?;
            Ok(NetworkPolicy::allow_list(rules))
        }
        (None, true) => Ok(NetworkPolicy::default()),
    }
}

// Plan 38 §4 (slice 7b): `resolve_optional_network_policy` was used
// by `mvmctl template create --network-preset` to bake a default
// policy into the TemplateSpec. With the `template *` namespace
// gone and `[network]` removed from `mvm.toml` (plan 38 §3),
// runtime policy now lives entirely in `mvmctl up` flags / the
// user-global config / mvmd tenant config. Function deleted; the
// `resolve_network_policy` form (always returns Some) is the only
// remaining helper.
