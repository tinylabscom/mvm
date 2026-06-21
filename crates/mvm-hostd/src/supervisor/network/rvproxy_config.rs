//! Render the full `rvproxy run --config` TOML for a native gateway.
//!
//! Wraps the lowered `[policy]` table ([`super::rvproxy_policy`]) in the rest of
//! the rvproxy config the dataplane needs — the same shape rvproxy's own
//! gvproxy-compat mode builds (`BackendKind::Vfkit` + `TransportKind::Vfkit` over
//! the unixgram socket libkrun connects to, gateway DNS on), plus the `[audit]`
//! section pointing rvproxy's flow-event export at the JSONL file mvm tails (the
//! source for [`super::rvproxy_flow_audit`]).
//!
//! mvm has no rvproxy crate dependency, so the TOML is emitted from mvm-side
//! structs whose field names/spellings match rvproxy's serde exactly. Schema
//! fidelity is validated end-to-end against the real `rvproxy` binary in the
//! parity gate (the emitted config is parsed + `RvproxyConfig::validate()`d);
//! these unit tests cover the structure mvm controls.

use std::net::Ipv4Addr;
use std::path::Path;

use mvm_core::policy::projection::CanonicalEgress;
use serde::Serialize;

use super::rvproxy_policy::{RvproxyPolicy, lower_policy};

/// The dev-network constants mvm's bridge uses (and rvproxy's `single_vm`
/// defaults match): guest `192.168.127.2`, gateway `192.168.127.1`, /24, 1500.
const DEV_CIDR: &str = "192.168.127.0/24";
const DEV_GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 1);
const DEV_GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 2);
const DEV_MTU: u16 = 1500;

/// Per-VM inputs for a native rvproxy gateway config.
pub struct RvproxyConfigParams<'a> {
    /// Stable id for the rvproxy instance (per-VM).
    pub id: &'a str,
    /// Unixgram socket libkrun connects to (the vfkit transport listen path).
    pub transport_socket: &'a Path,
    /// rvproxy's local control API socket.
    pub api_socket: &'a Path,
    /// JSONL file rvproxy exports flow events to; mvm tails it (2c).
    pub flow_audit_path: &'a Path,
    /// The resolved egress projection to enforce.
    pub egress: &'a CanonicalEgress,
    /// DNS hostname allow-list (dotted-suffix); empty = no hostname restriction.
    pub dns_allow: &'a [String],
    /// Upstream DNS resolvers the gateway forwards allowed lookups to.
    pub upstream_resolvers: &'a [Ipv4Addr],
    /// Transparent guest TCP interception for host-side egress termination.
    pub transparent: Option<RvproxyTransparentConfig>,
}

/// Transparent interception target for rvproxy's `[transparent]` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RvproxyTransparentConfig {
    pub terminator_host: Ipv4Addr,
    pub terminator_port: u16,
}

/// Render the complete rvproxy config TOML for `params`.
pub fn render_rvproxy_config(params: &RvproxyConfigParams<'_>) -> Result<String, toml::ser::Error> {
    let doc = RvproxyConfigDoc {
        id: params.id.to_string(),
        mode: "single-vm",
        network: NetworkSection {
            cidr: DEV_CIDR.to_string(),
            gateway_ip: DEV_GATEWAY_IP.to_string(),
            guest_ip: DEV_GUEST_IP.to_string(),
            mtu: DEV_MTU,
        },
        backend: KindSection { kind: "vfkit" },
        transport: TransportSection {
            kind: "vfkit",
            path: params.transport_socket.display().to_string(),
        },
        api: ApiSection {
            listen: format!("unix:{}", params.api_socket.display()),
        },
        dns: DnsSection {
            enabled: true,
            upstream_resolvers: params
                .upstream_resolvers
                .iter()
                .map(|ip| ip.to_string())
                .collect(),
        },
        audit: AuditSection {
            dataplane_audit_jsonl_path: params.flow_audit_path.display().to_string(),
        },
        transparent: params.transparent.map(|transparent| TransparentSection {
            enabled: true,
            intercept_ports: vec![80, 443],
            terminator_host: transparent.terminator_host.to_string(),
            terminator_port: transparent.terminator_port,
        }),
        // `policy` is the last field so its `[[policy.l4_allowlist]]`
        // array-of-tables is the final thing in the document (TOML requires an
        // array-of-tables to follow every scalar/inline value at its level).
        policy: lower_policy(params.egress, params.dns_allow).policy,
    };
    toml::to_string(&doc)
}

#[derive(Serialize)]
struct RvproxyConfigDoc {
    id: String,
    mode: &'static str,
    network: NetworkSection,
    backend: KindSection,
    transport: TransportSection,
    api: ApiSection,
    dns: DnsSection,
    audit: AuditSection,
    #[serde(skip_serializing_if = "Option::is_none")]
    transparent: Option<TransparentSection>,
    policy: RvproxyPolicy,
}

#[derive(Serialize)]
struct NetworkSection {
    cidr: String,
    gateway_ip: String,
    guest_ip: String,
    mtu: u16,
}

#[derive(Serialize)]
struct KindSection {
    kind: &'static str,
}

#[derive(Serialize)]
struct TransportSection {
    kind: &'static str,
    path: String,
}

#[derive(Serialize)]
struct ApiSection {
    listen: String,
}

#[derive(Serialize)]
struct DnsSection {
    enabled: bool,
    // rvproxy's `DnsConfig` renames this field to `upstream` in TOML; emitting
    // `upstream_resolvers` would be silently ignored (no deny_unknown_fields) and
    // fail validation with "no upstream resolver".
    #[serde(rename = "upstream")]
    upstream_resolvers: Vec<String>,
}

#[derive(Serialize)]
struct AuditSection {
    dataplane_audit_jsonl_path: String,
}

#[derive(Serialize)]
struct TransparentSection {
    enabled: bool,
    intercept_ports: Vec<u16>,
    terminator_host: String,
    terminator_port: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::policy::projection::{CanonicalRule, Proto};
    use std::path::PathBuf;

    fn params<'a>(
        egress: &'a CanonicalEgress,
        dns_allow: &'a [String],
        resolvers: &'a [Ipv4Addr],
        sockets: &'a (PathBuf, PathBuf, PathBuf),
    ) -> RvproxyConfigParams<'a> {
        RvproxyConfigParams {
            id: "vm-demo",
            transport_socket: &sockets.0,
            api_socket: &sockets.1,
            flow_audit_path: &sockets.2,
            egress,
            dns_allow,
            upstream_resolvers: resolvers,
            transparent: None,
        }
    }

    fn sockets() -> (PathBuf, PathBuf, PathBuf) {
        (
            PathBuf::from("/run/mvm/vm-demo/gateway.sock"),
            PathBuf::from("/run/mvm/vm-demo/rvproxy.sock"),
            PathBuf::from("/run/mvm/vm-demo/flow-audit.jsonl"),
        )
    }

    #[test]
    fn renders_the_required_sections_for_a_deny_by_default_policy() {
        let egress = CanonicalEgress::Rules(vec![CanonicalRule {
            proto: Proto::Tcp,
            net: "93.184.216.0/24".parse().unwrap(),
            port_lo: 443,
            port_hi: 443,
        }]);
        let resolvers = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)];
        let sk = sockets();
        let toml = render_rvproxy_config(&params(
            &egress,
            &["example.com".to_string()],
            &resolvers,
            &sk,
        ))
        .unwrap();

        // Identity + transport (the proven vfkit/unixgram path).
        assert!(toml.contains("id = \"vm-demo\""));
        assert!(toml.contains("mode = \"single-vm\""));
        assert!(toml.contains("[network]"));
        assert!(toml.contains("cidr = \"192.168.127.0/24\""));
        assert!(toml.contains("[backend]\nkind = \"vfkit\""));
        assert!(toml.contains("[transport]"));
        assert!(toml.contains("kind = \"vfkit\""));
        assert!(toml.contains("path = \"/run/mvm/vm-demo/gateway.sock\""));
        assert!(toml.contains("listen = \"unix:/run/mvm/vm-demo/rvproxy.sock\""));
        // DNS forwarding + flow-event export (2c reads this file).
        assert!(toml.contains("[dns]"));
        assert!(toml.contains("upstream = [\"1.1.1.1\", \"8.8.8.8\"]"));
        assert!(
            toml.contains("dataplane_audit_jsonl_path = \"/run/mvm/vm-demo/flow-audit.jsonl\"")
        );
        // Policy: transport switches on, deny-by-default, L4 + DNS rules.
        assert!(toml.contains("allow_transport_ingress = true"));
        assert!(toml.contains("allow_transport_egress = true"));
        assert!(toml.contains("default_egress_deny = true"));
        assert!(toml.contains("dns_hostname_allowlist = [\"example.com\"]"));
        assert!(toml.contains("[[policy.l4_allowlist]]"));
        assert!(toml.contains("protocol = \"tcp\""));
        assert!(toml.contains("port_lo = 443"));
    }

    #[test]
    fn renders_transparent_interception_when_configured() {
        let egress = CanonicalEgress::Unrestricted;
        let resolvers = [Ipv4Addr::new(1, 1, 1, 1)];
        let sk = sockets();
        let mut p = params(&egress, &[], &resolvers, &sk);
        p.transparent = Some(RvproxyTransparentConfig {
            terminator_host: Ipv4Addr::new(127, 0, 0, 1),
            terminator_port: 18080,
        });

        let toml = render_rvproxy_config(&p).unwrap();

        assert!(toml.contains("[transparent]"));
        assert!(toml.contains("enabled = true"));
        assert!(toml.contains("intercept_ports = [80, 443]"));
        assert!(toml.contains("terminator_host = \"127.0.0.1\""));
        assert!(toml.contains("terminator_port = 18080"));
    }

    #[test]
    fn unrestricted_policy_is_explicit_allowlist_without_ssh() {
        let egress = CanonicalEgress::Unrestricted;
        let resolvers = [Ipv4Addr::new(1, 1, 1, 1)];
        let sk = sockets();
        let toml = render_rvproxy_config(&params(&egress, &[], &resolvers, &sk)).unwrap();
        assert!(toml.contains("default_egress_deny = true"));
        // Mandatory-deny denylist is always present.
        assert!(toml.contains("169.254.169.254/32"));
        // The open posture is still explicit so TCP/22 stays banned.
        assert!(toml.contains("[[policy.l4_allowlist]]"));
        assert!(toml.contains("port_hi = 21"));
        assert!(toml.contains("port_lo = 23"));
        assert!(!toml.contains("port_lo = 22"));
        assert!(!toml.contains("port_hi = 22"));
    }

    /// Print a sample config so it can be fed to the real `rvproxy` binary for
    /// schema-fidelity validation (`cargo test -- --nocapture --ignored`).
    #[test]
    #[ignore]
    fn print_sample_config_for_rvproxy_validation() {
        let egress = CanonicalEgress::Rules(vec![CanonicalRule {
            proto: Proto::Tcp,
            net: "93.184.216.0/24".parse().unwrap(),
            port_lo: 443,
            port_hi: 443,
        }]);
        let resolvers = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)];
        let sk = sockets();
        print!(
            "{}",
            render_rvproxy_config(&params(
                &egress,
                &["example.com".to_string()],
                &resolvers,
                &sk
            ))
            .unwrap()
        );
    }
}
