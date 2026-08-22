use crate::ir::{HostPort, Network, NetworkDns, NetworkEgress, NetworkMode, PortForward};
use mvm_contract::policy::network_policy::AiPolicy;

/// Network policy with the given mode. Use [`NetworkExt`] chained
/// setters to declare ports, egress allowlist, peers, and DNS.
pub fn network(mode: NetworkMode) -> Network {
    Network {
        mode,
        ports: Vec::new(),
        egress: None,
        peers: Vec::new(),
        dns: None,
        ai: None,
    }
}

/// Chained-setter extensions on [`Network`]. Bring into scope via
/// `use mvm_sdk::*;`.
pub trait NetworkExt: Sized {
    fn with_port(self, port: PortForward) -> Self;
    fn with_egress(self, egress: NetworkEgress) -> Self;
    fn with_peers<I, S>(self, peers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>;
    fn with_dns(self, dns: NetworkDns) -> Self;
    fn with_ai(self, ai: AiPolicy) -> Self;
}

impl NetworkExt for Network {
    fn with_port(mut self, port: PortForward) -> Self {
        self.ports.push(port);
        self
    }

    fn with_egress(mut self, egress: NetworkEgress) -> Self {
        self.egress = Some(egress);
        self
    }

    fn with_peers<I, S>(mut self, peers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.peers = peers.into_iter().map(Into::into).collect();
        self
    }

    fn with_dns(mut self, dns: NetworkDns) -> Self {
        self.dns = Some(dns);
        self
    }

    fn with_ai(mut self, ai: AiPolicy) -> Self {
        self.ai = Some(ai);
        self
    }
}

/// Build an egress allowlist from `(host, port)` pairs.
pub fn egress<I>(allowlist: I) -> NetworkEgress
where
    I: IntoIterator<Item = HostPort>,
{
    NetworkEgress {
        allowlist: allowlist.into_iter().collect(),
    }
}

/// Build a host:port pair for an egress allowlist entry.
pub fn host_port(host: impl Into<String>, port: u16) -> HostPort {
    HostPort {
        host: host.into(),
        port,
    }
}

pub fn dns_none() -> NetworkDns {
    NetworkDns::None
}

pub fn dns_system() -> NetworkDns {
    NetworkDns::System
}

pub fn dns_resolver(host: impl Into<String>, port: u16) -> NetworkDns {
    NetworkDns::Resolver {
        host: host.into(),
        port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_ai_attaches_policy() {
        let policy = AiPolicy::metered_with_total_budget(10_000);
        let net = network(NetworkMode::Bridge).with_ai(policy.clone());
        assert_eq!(net.ai, Some(policy));
    }
}
