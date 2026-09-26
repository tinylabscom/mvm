//! The forward leg connects only to the addresses the egress gate admitted.
//!
//! The gate decides a request by resolving its host — against the admission
//! pins for an allow-listed name, or live for an unrestricted policy — and
//! checking every address it gets. The forward leg then opens its own
//! connection, and before this module it resolved the host again through the
//! system resolver. Two lookups are a rebinding window: the name can answer
//! the gate with one address and the connect with another.
//!
//! So the decision's answer is recorded here, keyed by the request's
//! `(host, port)`, and the forward leg's resolver returns exactly that. A host
//! with no recorded answer is decided by the gate on the spot, never resolved
//! around it: the forward leg has no way to reach an address the gate did not
//! admit.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use mvm_runtime::vmm::egress_gate::{EgressGate, EgressVerdict};

/// Most `(host, port)` answers kept. An entry is refreshed by every request
/// to that destination, so the bound only matters for a workload walking
/// many hosts; past it the oldest-inserted half is dropped, and a dropped host
/// is simply decided again by the gate.
const MAX_ADMITTED_ENTRIES: usize = 4096;

/// The addresses the gate admitted for each destination, as last decided.
#[derive(Debug, Default)]
pub(crate) struct AdmittedAddresses {
    entries: Mutex<HashMap<(String, u16), Vec<IpAddr>>>,
}

impl AdmittedAddresses {
    /// Record the gate's answer for `host:port`.
    pub(crate) fn record(&self, host: &str, port: u16, ips: Vec<IpAddr>) {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        if entries.len() >= MAX_ADMITTED_ENTRIES {
            let drop: Vec<(String, u16)> = entries
                .keys()
                .take(MAX_ADMITTED_ENTRIES / 2)
                .cloned()
                .collect();
            for key in drop {
                entries.remove(&key);
            }
        }
        entries.insert((host.to_ascii_lowercase(), port), ips);
    }

    fn get(&self, host: &str, port: u16) -> Option<Vec<IpAddr>> {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&(host.to_ascii_lowercase(), port))
            .cloned()
    }
}

/// A resolver that answers only with gate-admitted addresses.
#[derive(Debug)]
pub(crate) struct GateResolver {
    admitted: Arc<AdmittedAddresses>,
    gate: Arc<EgressGate>,
}

impl GateResolver {
    pub(crate) fn new(admitted: Arc<AdmittedAddresses>, gate: Arc<EgressGate>) -> Self {
        Self { admitted, gate }
    }
}

/// The gate's target form of `host:port`, bracketing a bare IPv6 literal.
fn target_of(host: &str, port: u16) -> String {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
        _ => format!("{bare}:{port}"),
    }
}

impl mvm_http::resolve::Resolve for GateResolver {
    fn resolve(
        &self,
        host: String,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
        if let Some(ips) = self.admitted.get(&host, port) {
            let addrs = ips
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect();
            return Box::pin(async move { Ok(addrs) });
        }
        let gate = Arc::clone(&self.gate);
        Box::pin(async move {
            let target = target_of(&host, port);
            // An unrestricted gate resolves live, which blocks.
            let verdict = tokio::task::spawn_blocking(move || gate.decide_request(&target))
                .await
                .map_err(std::io::Error::other)?;
            match verdict {
                EgressVerdict::Allow { ips, port } => Ok(ips
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect()),
                EgressVerdict::Deny(reason) => Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("not admitted by the egress gate: {reason}"),
                )),
                EgressVerdict::Malformed => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "malformed destination",
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_http::resolve::Resolve;

    use crate::supervisor::network_endpoint_proxy::test_support::gate_admitting;

    #[tokio::test]
    async fn the_forward_leg_gets_the_gate_s_answer_not_a_fresh_lookup() {
        let admitted = Arc::new(AdmittedAddresses::default());
        // A recorded answer wins over anything a live lookup would say; the
        // name here does not resolve at all.
        admitted.record(
            "Api.Pinned.Test",
            443,
            vec!["93.184.216.34".parse().unwrap()],
        );
        let resolver = GateResolver::new(Arc::clone(&admitted), gate_admitting(&[]));
        let addrs = resolver
            .resolve("api.pinned.test".into(), 443)
            .await
            .unwrap();
        assert_eq!(addrs, vec!["93.184.216.34:443".parse().unwrap()]);
    }

    #[tokio::test]
    async fn an_unrecorded_host_is_decided_by_the_gate_and_refused_if_it_denies() {
        let resolver =
            GateResolver::new(Arc::new(AdmittedAddresses::default()), gate_admitting(&[]));
        let err = resolver
            .resolve("10.0.0.5".into(), 443)
            .await
            .expect_err("a deny-all gate admits nothing");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        let err = resolver
            .resolve("[fd00:ec2::254]".into(), 80)
            .await
            .expect_err("metadata is never admitted");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn an_ipv6_literal_is_bracketed_for_the_gate() {
        assert_eq!(target_of("[::1]", 443), "[::1]:443");
        assert_eq!(target_of("::1", 443), "[::1]:443");
        assert_eq!(target_of("api.example.com", 443), "api.example.com:443");
    }
}
