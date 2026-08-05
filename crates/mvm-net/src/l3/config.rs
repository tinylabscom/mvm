//! The configuration the launch path hands `mvm-netd` on stdin.
//!
//! Everything the gateway needs for one VM boot, resolved by the caller
//! before the VM starts: the host-owned instance identity, the address
//! lease, the canonical egress projection, the bounds, and the declared
//! ingress. The subprocess resolves nothing itself — it is handed an
//! already-admitted contract, which is what keeps the admission decision in
//! one place.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// Marker `mvm-netd` writes to stdout once both listeners are bound and the
/// gateway is ready. The spawner waits for this before starting the VM, so
/// a guest that dials immediately cannot lose the race.
pub const NETD_READY_MARKER: &str = "MVM_NETD_READY";

/// Default bound on frames queued toward the guest.
pub const DEFAULT_QUEUE_DEPTH: usize = 256;

/// Default ceiling on DNS queries per second for one machine.
pub const DEFAULT_DNS_QPS: u32 = 50;

/// Filename of the per-VM pid file, under the VM state directory.
pub const NETD_PID_FILE: &str = "netd.pid";

/// One machine's networking configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetdConfig {
    /// Host-owned identity of this VM boot. Never guest-supplied.
    pub node_id: String,
    pub vm_id: String,
    pub boot_id: String,
    pub plan_digest: String,
    /// Whose audit chain this machine's gateway decisions belong on. Taken
    /// from the signed plan so a refusal lands beside the admission that
    /// authorized the workload, rather than in a stream of its own.
    #[serde(default = "default_tenant")]
    pub tenant: String,

    /// Which socket-directory convention this backend uses.
    pub uds_layout: NetdUdsLayout,

    /// The assigned point-to-point addressing.
    pub gateway_ipv4: Ipv4Addr,
    pub guest_ipv4: Ipv4Addr,
    /// The same pair in IPv6, for a machine issued one. Absent means the
    /// machine has no IPv6 address at all, and admission refuses the family
    /// rather than checking a source against nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_ipv6: Option<Ipv6Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_ipv6: Option<Ipv6Addr>,
    pub mtu: u16,

    /// The canonical egress projection, already resolved. Serialized as the
    /// same rule shape every other enforcement point consumes.
    pub egress: NetdEgress,
    /// Private ranges the plan explicitly opened.
    #[serde(default)]
    pub admitted_private_cidrs: Vec<String>,
    #[serde(default)]
    pub icmp: NetdIcmpPolicy,
    #[serde(default)]
    pub policy_epoch: u64,

    /// Bounds.
    #[serde(default = "default_max_flows")]
    pub max_flows: usize,
    #[serde(default = "default_queue_depth")]
    pub queue_depth: usize,
    #[serde(default = "default_dns_qps")]
    pub dns_qps: u32,

    /// Declared ingress mappings, `"tcp"` or `"udp"`.
    #[serde(default)]
    pub ingress: Vec<NetdIngress>,
}

fn default_tenant() -> String {
    "local".to_string()
}

fn default_max_flows() -> usize {
    crate::l3::flow::DEFAULT_MAX_FLOWS
}

fn default_queue_depth() -> usize {
    DEFAULT_QUEUE_DEPTH
}

fn default_dns_qps() -> u32 {
    DEFAULT_DNS_QPS
}

/// Socket-directory convention, mirrored on the wire so the subprocess does
/// not have to re-derive the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetdUdsLayout {
    /// libkrun / Firecracker per-VM socket directory.
    PerVmDir,
    /// The HVF supervisor's vsock listener directory.
    HvfVsockDir,
}

/// The resolved egress grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetdEgress {
    /// No filtering beyond the unconditional mandatory-deny and address
    /// classes. Still not a bypass: anti-spoofing, flow state, and the
    /// address-class refusals all apply.
    Unrestricted,
    /// An explicit allow-list.
    Rules(Vec<NetdRule>),
}

/// One canonical rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetdRule {
    /// `"tcp"` or `"udp"`.
    pub proto: String,
    pub cidr: String,
    pub port_lo: u16,
    pub port_hi: u16,
}

/// How much ICMP the plan admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetdIcmpPolicy {
    Deny,
    ErrorsOnly,
    #[default]
    EchoAndErrors,
}

/// One declared ingress mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetdIngress {
    pub proto: String,
    pub host_addr: String,
    pub host_port: u16,
    pub guest_port: u16,
}

/// Why a configuration was refused.
#[derive(Debug, thiserror::Error)]
pub enum NetdConfigError {
    #[error("unparseable {field}: {value:?}")]
    Unparseable { field: &'static str, value: String },
    #[error("unknown protocol {0:?} (expected \"tcp\" or \"udp\")")]
    UnknownProto(String),
    #[error("{0}")]
    Ingress(#[from] crate::l3::IngressError),
}

impl NetdConfig {
    /// The host-owned instance identity this configuration is bound to.
    pub fn instance(&self) -> crate::channel::VmInstanceIdentity {
        crate::channel::VmInstanceIdentity::new(
            self.node_id.clone(),
            self.vm_id.clone(),
            self.boot_id.clone(),
            self.plan_digest.clone(),
        )
    }

    /// Lower into the policy core's types, refusing anything unparseable
    /// rather than dropping it. A rule that silently vanished would widen
    /// the grant, so every failure here is fatal to the whole config.
    pub fn to_policy(&self) -> Result<crate::l3::L3PolicyConfig, NetdConfigError> {
        use mvm_core::policy::projection::{CanonicalEgress, CanonicalRule, Proto};

        let egress = match &self.egress {
            NetdEgress::Unrestricted => CanonicalEgress::Unrestricted,
            NetdEgress::Rules(rules) => CanonicalEgress::Rules(
                rules
                    .iter()
                    .map(|r| {
                        let proto = match r.proto.as_str() {
                            "tcp" => Proto::Tcp,
                            "udp" => Proto::Udp,
                            other => {
                                return Err(NetdConfigError::UnknownProto(other.to_string()));
                            }
                        };
                        Ok(CanonicalRule {
                            proto,
                            net: r.cidr.parse().map_err(|_| NetdConfigError::Unparseable {
                                field: "rule cidr",
                                value: r.cidr.clone(),
                            })?,
                            port_lo: r.port_lo,
                            port_hi: r.port_hi,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        };

        let admitted_private = self
            .admitted_private_cidrs
            .iter()
            .map(|c| {
                c.parse().map_err(|_| NetdConfigError::Unparseable {
                    field: "admitted private cidr",
                    value: c.clone(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(crate::l3::L3PolicyConfig {
            egress,
            admitted_private,
            icmp: match self.icmp {
                NetdIcmpPolicy::Deny => crate::l3::IcmpPolicy::Deny,
                NetdIcmpPolicy::ErrorsOnly => crate::l3::IcmpPolicy::ErrorsOnly,
                NetdIcmpPolicy::EchoAndErrors => crate::l3::IcmpPolicy::EchoAndErrors,
            },
            // Version 1 never carries fragments.
            allow_fragments: false,
            mtu: self.mtu,
            policy_epoch: self.policy_epoch,
        })
    }

    /// Lower the declared ingress mappings, refusing a protocol nobody
    /// named rather than guessing one.
    pub fn to_ingress_table(&self) -> Result<crate::l3::IngressTable, NetdConfigError> {
        let mut table = crate::l3::IngressTable::with_defaults();
        for mapping in &self.ingress {
            let host_addr =
                mapping
                    .host_addr
                    .parse()
                    .map_err(|_| NetdConfigError::Unparseable {
                        field: "ingress host address",
                        value: mapping.host_addr.clone(),
                    })?;
            let declared = match mapping.proto.as_str() {
                "tcp" => {
                    crate::l3::IngressMapping::tcp(host_addr, mapping.host_port, mapping.guest_port)
                }
                "udp" => {
                    crate::l3::IngressMapping::udp(host_addr, mapping.host_port, mapping.guest_port)
                }
                other => return Err(NetdConfigError::UnknownProto(other.to_string())),
            };
            table.declare(declared)?;
        }
        Ok(table)
    }

    /// The address lease this configuration assigns.
    pub fn lease(&self) -> crate::l3::AddressLease {
        let lease = crate::l3::AddressLease::for_test(self.gateway_ipv4, self.guest_ipv4);
        match (self.gateway_ipv6, self.guest_ipv6) {
            (Some(gateway), Some(guest)) => lease.with_v6(gateway, guest),
            // A half-configured pair grants nothing: a guest address with no
            // gateway has no resolver to reach, and a gateway with no guest
            // address has nothing anti-spoofing could accept.
            _ => lease,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> NetdConfig {
        NetdConfig {
            node_id: "node-1".into(),
            vm_id: "vm-a".into(),
            boot_id: "boot-1".into(),
            plan_digest: "sha256:plan".into(),
            tenant: "local".into(),
            uds_layout: NetdUdsLayout::PerVmDir,
            gateway_ipv4: Ipv4Addr::new(10, 201, 0, 5),
            guest_ipv4: Ipv4Addr::new(10, 201, 0, 6),
            gateway_ipv6: None,
            guest_ipv6: None,
            mtu: 1500,
            egress: NetdEgress::Rules(vec![NetdRule {
                proto: "tcp".into(),
                cidr: "93.184.216.34/32".into(),
                port_lo: 443,
                port_hi: 443,
            }]),
            admitted_private_cidrs: Vec::new(),
            icmp: NetdIcmpPolicy::default(),
            policy_epoch: 1,
            max_flows: 4096,
            queue_depth: 256,
            dns_qps: 50,
            ingress: Vec::new(),
        }
    }

    #[test]
    fn a_config_roundtrips_through_json() {
        let cfg = config();
        let json = serde_json::to_string(&cfg).unwrap();
        assert_eq!(serde_json::from_str::<NetdConfig>(&json).unwrap(), cfg);
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        let mut value = serde_json::to_value(config()).unwrap();
        value["surprise"] = serde_json::json!("extra");
        assert!(serde_json::from_value::<NetdConfig>(value).is_err());
    }

    #[test]
    fn the_instance_identity_comes_from_the_config_not_the_socket() {
        let instance = config().instance();
        assert_eq!(instance.node_id, "node-1");
        assert_eq!(instance.vm_id, "vm-a");
        assert_eq!(instance.boot_id, "boot-1");
        assert_eq!(instance.plan_digest, "sha256:plan");
    }

    #[test]
    fn rules_lower_into_the_canonical_projection() {
        use mvm_core::policy::projection::CanonicalEgress;
        let policy = config().to_policy().unwrap();
        match policy.egress {
            CanonicalEgress::Rules(rules) => {
                assert_eq!(rules.len(), 1);
                assert_eq!(rules[0].port_lo, 443);
            }
            other => panic!("expected rules, got {other:?}"),
        }
        assert_eq!(policy.mtu, 1500);
        assert!(!policy.allow_fragments, "version 1 never carries fragments");
    }

    #[test]
    fn an_unparseable_cidr_fails_the_whole_config() {
        // A rule that silently vanished would widen the grant.
        let mut cfg = config();
        cfg.egress = NetdEgress::Rules(vec![NetdRule {
            proto: "tcp".into(),
            cidr: "not-a-cidr".into(),
            port_lo: 443,
            port_hi: 443,
        }]);
        assert!(matches!(
            cfg.to_policy(),
            Err(NetdConfigError::Unparseable { .. })
        ));
    }

    #[test]
    fn an_unknown_protocol_fails_the_whole_config() {
        let mut cfg = config();
        cfg.egress = NetdEgress::Rules(vec![NetdRule {
            proto: "sctp".into(),
            cidr: "93.184.216.34/32".into(),
            port_lo: 443,
            port_hi: 443,
        }]);
        assert!(matches!(
            cfg.to_policy(),
            Err(NetdConfigError::UnknownProto(_))
        ));
    }

    #[test]
    fn declared_udp_ingress_lowers_into_the_table() {
        let mut cfg = config();
        cfg.ingress = vec![NetdIngress {
            proto: "udp".into(),
            host_addr: "127.0.0.1".into(),
            host_port: 5353,
            guest_port: 53,
        }];
        let table = cfg.to_ingress_table().unwrap();
        assert!(table.admits(mvm_contract::l3::proto::UDP, 53));
        assert!(
            !table.admits(mvm_contract::l3::proto::TCP, 53),
            "a datagram mapping opens no stream port"
        );
    }

    /// A protocol nobody named is refused rather than defaulted to one.
    #[test]
    fn an_unknown_ingress_protocol_is_refused() {
        let mut cfg = config();
        cfg.ingress = vec![NetdIngress {
            proto: "sctp".into(),
            host_addr: "127.0.0.1".into(),
            host_port: 5353,
            guest_port: 53,
        }];
        assert!(matches!(
            cfg.to_ingress_table(),
            Err(NetdConfigError::UnknownProto(_))
        ));
    }

    #[test]
    fn declared_tcp_ingress_lowers_into_the_table() {
        let mut cfg = config();
        cfg.ingress = vec![NetdIngress {
            proto: "tcp".into(),
            host_addr: "0.0.0.0".into(),
            host_port: 8080,
            guest_port: 80,
        }];
        let table = cfg.to_ingress_table().unwrap();
        assert!(table.admits(mvm_contract::l3::proto::TCP, 80));
    }

    #[test]
    fn an_empty_config_denies_everything() {
        let mut cfg = config();
        cfg.egress = NetdEgress::Rules(Vec::new());
        let policy = cfg.to_policy().unwrap();
        assert!(policy.admitted_private.is_empty());
        match policy.egress {
            mvm_core::policy::projection::CanonicalEgress::Rules(r) => assert!(r.is_empty()),
            other => panic!("expected an empty rule set, got {other:?}"),
        }
    }

    #[test]
    fn the_lease_matches_the_assigned_addresses() {
        let lease = config().lease();
        assert_eq!(lease.gateway, Ipv4Addr::new(10, 201, 0, 5));
        assert_eq!(lease.guest, Ipv4Addr::new(10, 201, 0, 6));
        assert_eq!(lease.prefix_len(), 30);
    }
}
