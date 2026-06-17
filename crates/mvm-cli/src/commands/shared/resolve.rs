//! Environment-aware resolution helpers (running VMs, flake refs, network policy).

use anyhow::{Context, Result};

use mvm::config;
use mvm::shell;
use mvm_backend::firecracker;

/// Resolve a VM name to its absolute directory path and verify the VM
/// is running.
pub fn resolve_running_vm(name: &str) -> Result<String> {
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

/// One of two ways to refer to a built manifest: a legacy name (looked
/// up in the name-keyed registry) or a manifest path that resolves to
/// a slot hash.
///
/// `mvmctl up` / `mvmctl exec` accept either form via their
/// `--manifest` flag. The `Slot` variant is the current path;
/// `Name` is kept only to resolve any pre-existing name-keyed slots.
///
/// Callers that need the persisted manifest re-read it via
/// `mvm::vm::template::lifecycle::template_load_slot(slot_hash)`
/// — keeping the enum lean here avoids the `clippy::large_enum_variant`
/// warning (`PersistedManifest` is ~350 bytes).
#[derive(Debug, Clone)]
pub enum ManifestArgRef {
    /// Legacy name-keyed slot (resolves through `template_load`,
    /// `template_artifacts`, etc.).
    Name(String),
    /// Manifest-keyed slot.
    Slot { slot_hash: String },
}

/// Decide whether a `--manifest` argument refers to a manifest path
/// (file or directory containing one) or a legacy slot name.
///
/// Detection rule: if the argument resolves to an existing file or
/// directory on disk, treat it as a manifest path; otherwise it's a
/// name. Both `mvmctl up --manifest ./my-app` and
/// `mvmctl up --manifest openclaw` work as long as the referenced
/// thing actually exists.
///
/// Returns `Err` only on validation/IO failures; missing-name is
/// handled by the caller's downstream `template_load` lookup.
pub fn resolve_manifest_arg(arg: &str) -> Result<ManifestArgRef> {
    use mvm_core::manifest::{canonical_key_for_path, resolve_manifest_config_path};

    // `<template>@<alias>` form. Aliases live in the
    // template-tags catalog; we resolve them up front so a typo
    // surfaces as "alias not found" rather than booting the
    // current revision silently. Today we validate the alias and
    // log the revision_hash; piping the resolved hash through to
    // skip `current` and boot the aliased revision is a follow-up
    // chunk that needs lifecycle.rs plumbing.
    if let Some((template_id, alias)) = mvm_core::domain::template_tags::split_aliased_ref(arg) {
        match mvm_core::domain::template_tags::resolve_alias(template_id, alias) {
            Some(revision_hash) => {
                tracing::info!(
                    template = template_id,
                    alias,
                    revision_hash,
                    "manifest alias resolved",
                );
                // Boot path still loads `current`; pinning to
                // `revision_hash` is a follow-up. Treat as Name
                // so the existing flow proceeds.
                return Ok(ManifestArgRef::Name(template_id.to_string()));
            }
            None => {
                anyhow::bail!(
                    "manifest alias {alias:?} for template {template_id:?} not found \
                     (run `mvmctl manifest alias ls {template_id}` to see available aliases)"
                );
            }
        }
    }

    let path = std::path::Path::new(arg);
    let looks_like_path = arg.contains('/')
        || arg.starts_with('.')
        || arg.ends_with(".toml")
        || path.is_file()
        || path.is_dir();
    if !looks_like_path {
        return Ok(ManifestArgRef::Name(arg.to_string()));
    }

    if !path.exists() {
        anyhow::bail!(
            "Manifest path '{}' does not exist (expected a manifest file or its directory)",
            arg
        );
    }

    let manifest_path = resolve_manifest_config_path(path)
        .with_context(|| format!("Resolving --manifest {arg:?}"))?;
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
    mvm::vm::template::lifecycle::template_load_slot(&slot_hash).with_context(|| {
        format!(
            "Manifest at {} has no built slot — run `mvmctl build {}` first",
            canonical.display(),
            canonical.display()
        )
    })?;

    Ok(ManifestArgRef::Slot { slot_hash })
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

/// Resolve the transient-run egress flags (`--net` / `--allow-host`) into a
/// single `NetworkPolicy`, identical for every backend.
///
/// Precedence (one tested place so it can't drift):
/// - any `--allow-host` ⇒ allow-list (narrowest intent **wins** over `--net`);
/// - else `--net` ⇒ the `dev` preset (broad outbound + DNS, never
///   `unrestricted`, so it never trips the claim-10 unrestricted ack);
/// - else ⇒ `deny_all` (the safe default).
///
/// `HOST` with no `:PORT` defaults to `443`.
pub fn resolve_run_network_policy(
    net: bool,
    allow_host: &[String],
) -> Result<mvm_core::network_policy::NetworkPolicy> {
    use mvm_core::network_policy::{NetworkPolicy, NetworkPreset};

    if !allow_host.is_empty() {
        let rules = allow_host
            .iter()
            .map(|s| parse_allow_host(s))
            .collect::<Result<Vec<_>>>()?;
        Ok(NetworkPolicy::allow_list(rules))
    } else if net {
        Ok(NetworkPolicy::preset(NetworkPreset::Dev))
    } else {
        Ok(NetworkPolicy::deny_all())
    }
}

/// How faithfully the resolved `backend` enforces `policy` on the transient
/// (no-signed-bundle) run path. Recorded in the signed receipt **alongside**
/// the requested `network_posture` so a verifier never mistakes a requested
/// `host:port` allow-list for port-level enforcement on a backend that only
/// gates the host name.
///
/// - **deny-all** → `flow-drop` and **unrestricted** → `open`: enforced
///   identically on every backend (the flow-open gate / no gate), so the tier
///   is backend-independent.
/// - An **allow-list / preset** is now host **and** port enforced on every
///   backend: Firecracker via nftables (`-d <host> --dport <port>`), libkrun/Vz
///   via the admission-time DNS pin feeding the `L4PolicyScan` (a direct-IP dial
///   to an unlisted address is dropped, not just an unlisted name). The tier is
///   uniformly `<backend>:l4-host-port`; the backend is still named so the
///   receipt records which substrate enforced.
pub fn egress_enforcement_label(
    backend: &str,
    policy: &mvm_core::network_policy::NetworkPolicy,
) -> String {
    if policy.is_unrestricted() {
        return "open".to_string();
    }
    match policy.resolve_rules() {
        // Some(empty) = deny-all: every egress flow dropped at the gate, uniform.
        Some(rules) if rules.is_empty() => "flow-drop".to_string(),
        // Allow-list / preset with rules: host:port L4-enforced on every backend.
        _ => format!("{backend}:l4-host-port"),
    }
}

/// Parse one `--allow-host` entry. `HOST:PORT` is parsed strictly;
/// `HOST` with no port defaults to `443` (https). Fails closed on a
/// malformed port or empty host before any VM work.
fn parse_allow_host(entry: &str) -> Result<mvm_core::network_policy::HostPort> {
    use mvm_core::network_policy::HostPort;
    match entry.rsplit_once(':') {
        // Has an explicit `:PORT` — strict parse (rejects empty host / bad port).
        Some(_) => entry
            .parse()
            .with_context(|| format!("invalid --allow-host {entry:?}")),
        // Bare host — default to the https port.
        None if entry.is_empty() => anyhow::bail!("--allow-host cannot be empty"),
        None => Ok(HostPort::new(entry, 443)),
    }
}

// `resolve_optional_network_policy` was used by `mvmctl template
// create --network-preset` to bake a default policy into the
// TemplateSpec. With the `template *` namespace gone and `[network]`
// removed from `mvm.toml`, runtime policy now lives entirely in
// `mvmctl up` flags / the user-global config / mvmd tenant config.
// Function deleted; the `resolve_network_policy` form (always returns
// Some) is the only remaining helper.

/// Resolve the requested hypervisor to the effective one for this host. `firecracker`
/// (the default `--hypervisor`) auto-detects: KVM → firecracker, macOS 26+ Apple Silicon
/// → vz, macOS 13-25 + libkrun → libkrun, else firecracker (surfaces a clear
/// "not available" error). Any explicit value is returned as-is. Single source of truth,
/// shared by `mvmctl up` and `mvmctl pool` so they agree on the backend.
pub fn resolve_effective_hypervisor(requested: &str) -> String {
    if requested != "firecracker" {
        return requested.to_string();
    }
    let plat = mvm_core::platform::current();
    if plat.has_kvm() {
        "firecracker"
    } else if plat.is_vz_default_tier() {
        "vz"
    } else if plat.has_libkrun() {
        "libkrun"
    } else {
        "firecracker"
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::network_policy::{HostPort, NetworkPolicy, NetworkPreset};

    #[test]
    fn run_net_default_is_deny_all() {
        assert_eq!(
            resolve_run_network_policy(false, &[]).unwrap(),
            NetworkPolicy::deny_all()
        );
    }

    #[test]
    fn run_net_flag_maps_to_dev_preset_not_unrestricted() {
        let p = resolve_run_network_policy(true, &[]).unwrap();
        assert_eq!(p, NetworkPolicy::preset(NetworkPreset::Dev));
        assert!(!p.is_unrestricted(), "--net must never be unrestricted");
    }

    #[test]
    fn allow_host_defaults_to_port_443() {
        let p = resolve_run_network_policy(false, &["api.example.com".to_string()]).unwrap();
        assert_eq!(
            p,
            NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)])
        );
    }

    #[test]
    fn allow_host_honors_explicit_port_and_multiple_hosts() {
        let p = resolve_run_network_policy(false, &["a.com".to_string(), "b.com:8443".to_string()])
            .unwrap();
        assert_eq!(
            p,
            NetworkPolicy::allow_list(vec![
                HostPort::new("a.com", 443),
                HostPort::new("b.com", 8443),
            ])
        );
    }

    #[test]
    fn allow_host_wins_over_net() {
        let p = resolve_run_network_policy(true, &["a.com".to_string()]).unwrap();
        assert_eq!(
            p,
            NetworkPolicy::allow_list(vec![HostPort::new("a.com", 443)]),
            "--allow-host must narrow, winning over --net"
        );
    }

    #[test]
    fn allow_host_rejects_malformed_entries_fail_closed() {
        assert!(resolve_run_network_policy(false, &["host:0notaport".to_string()]).is_err());
        assert!(resolve_run_network_policy(false, &[":443".to_string()]).is_err());
        assert!(resolve_run_network_policy(false, &["".to_string()]).is_err());
    }

    #[test]
    fn enforcement_tier_uniform_for_deny_all_and_unrestricted() {
        // deny-all and unrestricted are enforced the same way on every backend,
        // so the receipt records a backend-independent tier.
        for backend in ["firecracker", "libkrun", "vz"] {
            assert_eq!(
                egress_enforcement_label(backend, &NetworkPolicy::deny_all()),
                "flow-drop"
            );
            assert_eq!(
                egress_enforcement_label(backend, &NetworkPolicy::unrestricted()),
                "open"
            );
        }
    }

    #[test]
    fn enforcement_tier_allow_list_is_uniform_l4_host_port() {
        // host:port is now L4-enforced on every backend (Firecracker nftables;
        // libkrun/Vz via the admission-time DNS pin → L4 scan), so the receipt
        // records `<backend>:l4-host-port` uniformly — no more `dns-name-only`.
        let p = NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]);
        assert_eq!(
            egress_enforcement_label("firecracker", &p),
            "firecracker:l4-host-port"
        );
        assert_eq!(
            egress_enforcement_label("libkrun", &p),
            "libkrun:l4-host-port"
        );
        assert_eq!(egress_enforcement_label("vz", &p), "vz:l4-host-port");
    }
}
