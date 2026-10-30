//! Environment-aware resolution helpers (running VMs, flake refs, network policy).

use anyhow::{Context, Result};
use mvm_client::policy_profiles::{PolicySelection, ProjectPolicy};

pub use mvm_client::launch::manifest_ref::{ManifestArgRef, resolve_manifest_arg};

/// Select launch policy with operator-configured fallbacks.
///
/// # Errors
///
/// A selected policy reference is malformed.
pub(in crate::commands) fn select_launch_policy(
    cli: &[String],
    project: Option<ProjectPolicy>,
    defaults: &[String],
) -> Result<Option<PolicySelection>> {
    let project_selects = project
        .as_ref()
        .is_some_and(|policy| policy.profile.is_some() || !policy.include.is_empty());
    if cli.is_empty() && !project_selects {
        PolicySelection::for_launch(defaults, project)
            .context("selecting configured default_policy")
    } else {
        PolicySelection::for_launch(cli, project).map_err(Into::into)
    }
}

/// True when the launch source selectors resolve to an OCI image boot, whether
/// the image was named directly (`--image`) or indirectly through `--manifest`.
pub(in crate::commands) fn launch_uses_oci_image(
    image_ref: Option<&str>,
    manifest_arg: Option<&str>,
) -> Result<bool> {
    if image_ref.is_some() {
        return Ok(true);
    }
    manifest_arg
        .map(manifest_arg_uses_oci_image)
        .transpose()
        .map(Option::unwrap_or_default)
}

/// True when a `--manifest` argument selects an OCI image source rather than a
/// flake or wasm module.
pub(in crate::commands) fn manifest_arg_uses_oci_image(arg: &str) -> Result<bool> {
    use mvm_core::manifest::{Manifest, is_slot_hash_dirname, resolve_manifest_config_path};

    let path = std::path::Path::new(arg);
    if path.exists() {
        let manifest_path = resolve_manifest_config_path(path)
            .with_context(|| format!("Resolving --manifest {arg:?}"))?;
        let manifest = Manifest::read_file(&manifest_path)
            .with_context(|| format!("Reading manifest {}", manifest_path.display()))?;
        return Ok(manifest.is_image_source());
    }
    if !is_slot_hash_dirname(arg) {
        return Ok(false);
    }
    let persisted = match mvm_runtime::vm::template::lifecycle::template_load_slot(arg) {
        Ok(persisted) => persisted,
        Err(_) => return Ok(false),
    };
    let manifest = match Manifest::read_file(std::path::Path::new(&persisted.manifest_path)) {
        Ok(manifest) => manifest,
        Err(_) => return Ok(false),
    };
    Ok(manifest.is_image_source())
}

pub use mvm_core::domain::manifest::resolve_flake_ref;

/// How faithfully the resolved `backend` enforces `policy` on the transient
/// (no-signed-bundle) run path. Recorded in the signed receipt **alongside**
/// the requested `network_posture` so a verifier never mistakes a requested
/// `host:port` allow-list for port-level enforcement on a backend that only
/// gates the host name.
///
/// - **deny-all** → `flow-drop` and **unrestricted** → `open`: enforced
///   identically on every backend (the flow-open gate / no gate), so the tier
///   is backend-independent.
/// - An **allow-list / preset** is host **and** port enforced on every
///   claim-bearing backend: the per-VM network endpoint's `EgressGate` decides each
///   destination against the admission-time DNS pins (a direct-IP dial to an
///   unlisted address is refused, not just an unlisted name). The tier is
///   uniformly `<backend>:l4-host-port`; the backend is still named so the
///   receipt records which backend ran the workload.
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

// `resolve_optional_network_policy` was used by a since-removed
// template-create flag to bake a default policy into the TemplateSpec.
// With that namespace gone and `[network]` removed from `mvm.toml`,
// runtime policy now lives entirely in `machine run --net` /
// `--allow-host`, the user-global config, and mvmd tenant config.
// Function deleted; the `resolve_network_policy` form (always returns
// Some) is the only remaining helper.

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_client::policy_profiles::{Platform, PolicyRef, PolicyStore, resolve};
    use mvm_core::network_policy::{HostPort, NetworkPolicy};

    fn project(profile: Option<&str>, include: &[&str], hosts: &[&str]) -> ProjectPolicy {
        ProjectPolicy {
            manifest: std::path::PathBuf::from("/p/mvm.toml"),
            profile: profile.map(str::to_string),
            include: include.iter().map(ToString::to_string).collect(),
            allow_hosts: hosts.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn configured_defaults_compose_in_order_with_denies_and_minimum_resources() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.toml");
        let team = dir.path().join("team.toml");
        std::fs::write(
            &base,
            "[overrides.network]\nallow = [\"a.test\"]\n[overrides.resources]\nwall_clock_secs = 20\n",
        )
        .unwrap();
        std::fs::write(
            &team,
            "[overrides.network]\nallow = [\"b.test\"]\ndeny = [\"a.test\"]\n[overrides.resources]\nwall_clock_secs = 60\n",
        )
        .unwrap();
        let defaults = [base.display().to_string(), team.display().to_string()];
        let selection =
            select_launch_policy(&[], Some(project(None, &[], &["project.test"])), &defaults)
                .unwrap()
                .unwrap();
        assert_eq!(
            selection.profiles,
            defaults
                .iter()
                .map(|value| PolicyRef::parse(value).unwrap())
                .collect::<Vec<_>>()
        );
        let resolved = resolve(
            &PolicyStore::at(dir.path()),
            &selection,
            Platform::default(),
        )
        .unwrap();
        assert_eq!(
            resolved.policy.network.allow,
            ["b.test:443", "project.test:443"]
        );
        assert_eq!(resolved.policy.resources.wall_clock_secs, Some(20));
    }

    #[test]
    fn flags_and_project_policy_replace_configured_defaults_but_keep_project_hosts() {
        let dir = tempfile::tempdir().unwrap();
        for (flags, profile, include) in [
            (vec!["agent-apis".into()], None, vec![]),
            (vec![], Some("agent-apis"), vec![]),
            (vec![], None, vec!["llm-apis"]),
        ] {
            let selection = select_launch_policy(
                &flags,
                Some(project(profile, &include, &["project.test"])),
                &["Bad Default".into()],
            )
            .unwrap()
            .unwrap();
            let resolved = resolve(
                &PolicyStore::at(dir.path()),
                &selection,
                Platform::default(),
            )
            .unwrap();
            assert!(
                resolved
                    .policy
                    .network
                    .allow
                    .contains(&"api.openai.com:443".into())
            );
            assert!(
                resolved
                    .policy
                    .network
                    .allow
                    .contains(&"project.test:443".into())
            );
        }
        let error = select_launch_policy(&[], None, &["Bad Default".into()]).unwrap_err();
        assert!(error.to_string().contains("default_policy"), "{error:#}");
        assert!(select_launch_policy(&[], None, &[]).unwrap().is_none());
    }

    #[test]
    fn enforcement_tier_uniform_for_deny_all_and_unrestricted() {
        // deny-all and unrestricted are enforced the same way on every backend,
        // so the receipt records a backend-independent tier.
        for backend in ["firecracker", "libkrun"] {
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
        // libkrun via the admission-time DNS pin → L4 scan), so the receipt
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
    }
}
