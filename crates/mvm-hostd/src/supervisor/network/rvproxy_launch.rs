//! Render + persist the native rvproxy gateway config for a workload.
//!
//! Bridges the admitted policy bundle to [`super::rvproxy_config`]: resolve the
//! tenant's effective egress, lower it, and write the `rvproxy run --config`
//! TOML into the per-VM scratch dir. The supervisor sets the written path as
//! `NetworkingMode::Gvproxy.native_config` so libkrun's gateway spawn launches
//! rvproxy natively instead of in gvproxy-compat mode.
//!
//! [`resolve_egress_and_dns`] is the single resolution the in-line splice also
//! consumes, so the native gateway and the splice enforce byte-identical policy.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use mvm_core::plan::types::TenantId;
use mvm_core::policy::projection::CanonicalEgress;
use mvm_core::policy::resolver::EmergencyDeny;
use mvm_core::policy::{EffectivePolicy, PolicyBundle, canonicalize_l4, resolve};

use super::rvproxy_config::{RvproxyConfigParams, render_rvproxy_config};

/// Upstream resolvers the native gateway forwards allowed lookups to. gvproxy
/// reads the host's resolv.conf implicitly; rvproxy needs them named in
/// `[dns].upstream`. Sourcing these from the host's resolver config is a
/// follow-up — these public anycast resolvers keep the first cut self-contained.
const DEFAULT_UPSTREAM_RESOLVERS: [Ipv4Addr; 2] =
    [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)];

/// Resolve a bundle to the canonical egress + DNS hostname allow-list the
/// gateway enforces. Mirrors the splice's resolution
/// (`gateway_bridge`): an unresolvable L4 spec fails CLOSED to deny-all, and
/// an "open" egress mode adds no DNS sink-hole.
pub fn resolve_egress_and_dns(
    bundle: &PolicyBundle,
    tenant: &TenantId,
    now: DateTime<Utc>,
) -> (CanonicalEgress, Vec<String>) {
    let eff = resolve(bundle, tenant, now, &EmergencyDeny::default());
    egress_and_dns_from_effective(&eff)
}

/// The pure derivation behind [`resolve_egress_and_dns`], taking an already
/// resolved [`EffectivePolicy`]. The in-line splice resolves the bundle once
/// and calls this directly, so the native gateway and the splice never drift.
pub fn egress_and_dns_from_effective(eff: &EffectivePolicy) -> (CanonicalEgress, Vec<String>) {
    let egress = if eff.egress.mode.as_deref() == Some("open") {
        CanonicalEgress::Unrestricted
    } else {
        canonicalize_l4(&eff.network.l4).unwrap_or_else(|_| CanonicalEgress::Rules(Vec::new()))
    };
    let dns_allow: Vec<String> = if eff.egress.mode.as_deref() == Some("open") {
        Vec::new()
    } else {
        eff.egress
            .allow_list
            .iter()
            .map(|(host, _port)| host.clone())
            .collect()
    };
    (egress, dns_allow)
}

/// Render the native rvproxy config for `bundle` and write it to
/// `<scratch_dir>/rvproxy.toml`, returning the path. The transport socket is
/// `<scratch_dir>/gvproxy.sock` — the exact path the gateway spawn polls — so
/// libkrun connects to the socket rvproxy binds. No bundle (Stage 0 / dev) →
/// deny-all egress (the gateway still answers DNS for the dev network).
pub fn write_native_gateway_config(
    bundle: Option<&PolicyBundle>,
    tenant: &TenantId,
    vm_id: &str,
    scratch_dir: &Path,
    now: DateTime<Utc>,
) -> std::io::Result<PathBuf> {
    let (egress, dns_allow) = match bundle {
        Some(b) => resolve_egress_and_dns(b, tenant, now),
        None => (CanonicalEgress::Rules(Vec::new()), Vec::new()),
    };
    let transport_socket = scratch_dir.join("gvproxy.sock");
    let api_socket = scratch_dir.join("rvproxy-api.sock");
    let flow_audit_path = scratch_dir.join("flow-audit.jsonl");
    let toml = render_rvproxy_config(&RvproxyConfigParams {
        id: vm_id,
        transport_socket: &transport_socket,
        api_socket: &api_socket,
        flow_audit_path: &flow_audit_path,
        egress: &egress,
        dns_allow: &dns_allow,
        upstream_resolvers: &DEFAULT_UPSTREAM_RESOLVERS,
    })
    .map_err(std::io::Error::other)?;
    let config_path = scratch_dir.join("rvproxy.toml");
    std::fs::write(&config_path, toml)?;
    Ok(config_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::policy::bundle::{PolicyBundle, PolicyId};

    /// A minimal bundle resolving to the claim-10 deny-all baseline.
    fn deny_all_bundle() -> PolicyBundle {
        PolicyBundle {
            schema_version: 1,
            bundle_id: PolicyId("test".to_string()),
            bundle_version: 1,
            network: Default::default(),
            egress: Default::default(),
            pii: Default::default(),
            tool: Default::default(),
            artifact: Default::default(),
            keys: Default::default(),
            audit: Default::default(),
            wasi: Default::default(),
            tenant_overlays: Default::default(),
        }
    }

    /// A resolved bundle lowers into a written config whose `[policy]` carries
    /// deny-by-default, and whose transport path is the socket the gateway
    /// spawn waits on.
    #[test]
    fn writes_a_deny_by_default_config_from_a_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = deny_all_bundle();
        let tenant = TenantId("acme".to_string());
        let path = write_native_gateway_config(
            Some(&bundle),
            &tenant,
            "vm-1",
            tmp.path(),
            DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
        )
        .expect("write native config");

        assert_eq!(path, tmp.path().join("rvproxy.toml"));
        let toml = std::fs::read_to_string(&path).unwrap();
        assert!(toml.contains("id = \"vm-1\""));
        assert!(toml.contains("default_egress_deny = true"));
        // Transport socket is the spawn-poll path.
        assert!(toml.contains(&format!(
            "path = \"{}\"",
            tmp.path().join("gvproxy.sock").display()
        )));
        // Flow-audit export points where rvproxy_flow_audit tails.
        assert!(toml.contains(&format!(
            "dataplane_audit_jsonl_path = \"{}\"",
            tmp.path().join("flow-audit.jsonl").display()
        )));
        // The whole document round-trips as valid TOML.
        let _: toml::Value = toml.parse().expect("rendered config is valid TOML");
    }

    /// No bundle (Stage 0 / dev) still writes a deny-all config rather than
    /// failing — the gateway needs a valid file to launch.
    #[test]
    fn no_bundle_writes_deny_all() {
        let tmp = tempfile::tempdir().unwrap();
        let tenant = TenantId("dev".to_string());
        let path = write_native_gateway_config(
            None,
            &tenant,
            "vm-dev",
            tmp.path(),
            DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
        )
        .expect("write native config");
        let toml = std::fs::read_to_string(&path).unwrap();
        assert!(toml.contains("default_egress_deny = true"));
        assert!(!toml.contains("[[policy.l4_allowlist]]"));
    }

    #[test]
    fn open_mode_lowers_to_unrestricted_egress() {
        let mut bundle = deny_all_bundle();
        bundle.egress.mode = Some("open".to_string());
        let (egress, dns_allow) = resolve_egress_and_dns(
            &bundle,
            &TenantId("acme".to_string()),
            DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
        );

        assert_eq!(egress, CanonicalEgress::Unrestricted);
        assert!(dns_allow.is_empty());
    }
}
