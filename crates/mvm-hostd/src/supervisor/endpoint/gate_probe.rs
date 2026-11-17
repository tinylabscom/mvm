//! The witness-only egress-gate probe.
//!
//! Admission proves the *signed policy* was verified; nothing in that proof
//! shows the gate the endpoint process actually built from it took effect.
//! This module answers a [`GateProbeRequest`] by asking the running
//! [`EgressGate`] to decide each sample — the live gate is the only
//! evaluator, so the probe can witness a gate that silently never took
//! effect. It performs no substitution, opens no forward leg, and writes no
//! audit record: the probe observes the gate; it is not workload egress.

use mvm_contract::peer::PeerName;
use mvm_core::substitution_wire::{
    GateProbeOutcome, GateProbeRequest, GateProbeResponse, GateProbeSample, GateProbeVerdict,
};

use super::network_endpoint_proxy::SubstitutionService;

impl SubstitutionService {
    /// Decide every probe sample against the running egress gate, in request
    /// order, one outcome per sample.
    ///
    /// A peer-shaped sample is refused by name without entering the peer
    /// namespace: peer routes are decided by the flow multiplexer, never by
    /// this endpoint. Everything else — including malformed samples — is
    /// decided by [`Self::decide_probe_sample`]. A request with zero samples
    /// answers with zero results.
    pub(crate) fn process_gate_probe(&self, request: GateProbeRequest) -> GateProbeResponse {
        let results = request
            .samples
            .iter()
            .map(|sample| self.probe_one(sample))
            .collect();
        GateProbeResponse { results }
    }

    fn probe_one(&self, sample: &GateProbeSample) -> GateProbeOutcome {
        if PeerName::is_peer_target(&sample.host) {
            return GateProbeOutcome {
                host: sample.host.clone(),
                port: sample.port,
                verdict: GateProbeVerdict::Deny,
                reason: Some(
                    "peer routes are decided by the flow multiplexer, not by this endpoint".into(),
                ),
            };
        }
        self.decide_probe_sample(sample)
    }
}

#[cfg(test)]
mod tests {
    use mvm_core::substitution_wire::{
        GateProbeExpect, GateProbeRequest, GateProbeSample, GateProbeVerdict,
    };

    use crate::supervisor::endpoint::network_endpoint_proxy::test_support::{
        gate_admitting, service_with_gate,
    };

    fn sample(host: &str, port: u16, expect: GateProbeExpect) -> GateProbeSample {
        GateProbeSample {
            host: host.into(),
            port,
            expect,
        }
    }

    fn probe(
        service: &super::SubstitutionService,
        samples: Vec<GateProbeSample>,
    ) -> Vec<mvm_core::substitution_wire::GateProbeOutcome> {
        service
            .process_gate_probe(GateProbeRequest { samples })
            .results
    }

    /// A gate admitting only `api.example.com:443` (pinned, like the endpoint
    /// builds it), so every verdict below is the gate's own answer.
    fn service() -> std::sync::Arc<super::SubstitutionService> {
        let (service, _placeholder, _forwarder, _dir) = service_with_gate(
            "sk-test",
            &["api.example.com"],
            gate_admitting(&[("api.example.com", 443)]),
        );
        service
    }

    #[test]
    fn a_sample_the_policy_refuses_is_denied_with_the_gates_reason() {
        let outcomes = probe(
            &service(),
            vec![sample("192.0.2.1", 9, GateProbeExpect::Deny)],
        );
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].verdict, GateProbeVerdict::Deny);
        // The gate names the refusal in its own words: the test pin maps
        // `api.example.com` to 192.0.2.1, so probing that address on an
        // unadmitted port reports the port mismatch, not a bare address.
        assert!(
            outcomes[0]
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("not admitted")),
            "the deny carries the gate's explanation: {:?}",
            outcomes[0].reason
        );
    }

    #[test]
    fn a_sample_the_policy_admits_is_admitted() {
        let outcomes = probe(
            &service(),
            vec![sample("api.example.com", 443, GateProbeExpect::Admit)],
        );
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].verdict, GateProbeVerdict::Admit);
        assert_eq!(outcomes[0].reason, None);
    }

    #[test]
    fn a_sample_on_a_refused_port_of_an_admitted_host_is_denied() {
        let outcomes = probe(
            &service(),
            vec![sample("api.example.com", 80, GateProbeExpect::Deny)],
        );
        assert_eq!(outcomes[0].verdict, GateProbeVerdict::Deny);
        assert!(
            outcomes[0]
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("api.example.com:80")),
            "the port mismatch is the gate's own explanation: {:?}",
            outcomes[0].reason
        );
    }

    #[test]
    fn a_malformed_sample_never_reaches_the_gate() {
        for (host, port) in [("", 443), ("api.example.com", 0)] {
            let outcomes = probe(&service(), vec![sample(host, port, GateProbeExpect::Deny)]);
            assert_eq!(outcomes.len(), 1, "one bad sample fails only itself");
            assert_eq!(outcomes[0].verdict, GateProbeVerdict::Malformed);
            assert_eq!(outcomes[0].host, host);
            assert_eq!(outcomes[0].port, port);
        }
    }

    #[test]
    fn a_peer_shaped_sample_is_refused_by_name_without_entering_the_peer_namespace() {
        // The peer suffix is refused by name before any decision: peer routes
        // belong to the flow multiplexer, and this endpoint never resolves
        // through the peer namespace.
        let outcomes = probe(
            &service(),
            vec![sample("db.mvm.peer", 443, GateProbeExpect::Deny)],
        );
        assert_eq!(outcomes[0].verdict, GateProbeVerdict::Deny);
        assert!(
            outcomes[0]
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("flow multiplexer")),
            "the refusal names why: {:?}",
            outcomes[0].reason
        );
    }

    #[test]
    fn zero_samples_answer_with_zero_results() {
        let outcomes = probe(&service(), Vec::new());
        assert!(outcomes.is_empty());
    }

    #[test]
    fn results_come_back_in_request_order() {
        let outcomes = probe(
            &service(),
            vec![
                sample("198.51.100.1", 9, GateProbeExpect::Deny),
                sample("api.example.com", 443, GateProbeExpect::Admit),
                sample("203.0.113.1", 9, GateProbeExpect::Deny),
            ],
        );
        assert_eq!(outcomes.len(), 3);
        assert_eq!(outcomes[0].host, "198.51.100.1");
        assert_eq!(outcomes[0].verdict, GateProbeVerdict::Deny);
        assert_eq!(outcomes[1].host, "api.example.com");
        assert_eq!(outcomes[1].verdict, GateProbeVerdict::Admit);
        assert_eq!(outcomes[2].host, "203.0.113.1");
        assert_eq!(outcomes[2].verdict, GateProbeVerdict::Deny);
    }
}
