//! The witness-only egress-gate probe.
//!
//! Admission proves the *signed policy* was verified; nothing in that proof
//! shows the gate the endpoint process actually built from it took effect.
//! This module answers a [`GateProbeRequest`] by asking the running
//! [`EgressGate`] to decide each sample — the live gate is the only
//! evaluator, so the probe can witness a gate that silently never took
//! effect. It performs no substitution, opens no forward leg, and writes no
//! audit record: the probe observes the gate; it is not workload egress.

use mvm_core::substitution_wire::{
    GateProbeOutcome, GateProbeRequest, GateProbeResponse, GateProbeSample, GateProbeVerdict,
};

use super::SubstitutionService;

impl SubstitutionService {
    /// Decide every probe sample against the running egress gate, in request
    /// order, one outcome per sample.
    ///
    /// A sample the gate would answer is passed to
    /// [`mvm_runtime::vmm::egress_gate::EgressGate::decide_target`] verbatim —
    /// no substitution, no forward leg, no audit recorder write. A malformed
    /// sample (an empty host or port 0) never reaches the gate: it reports a
    /// `Malformed` outcome for that sample, so one bad sample fails only
    /// itself, never the whole probe. A request with zero samples answers
    /// with zero results.
    pub(crate) fn process_gate_probe(&self, request: GateProbeRequest) -> GateProbeResponse {
        let results = request
            .samples
            .iter()
            .map(|sample| self.probe_one(sample))
            .collect();
        GateProbeResponse { results }
    }

    fn probe_one(&self, sample: &GateProbeSample) -> GateProbeOutcome {
        if sample.host.is_empty() || sample.port == 0 {
            return GateProbeOutcome {
                host: sample.host.clone(),
                port: sample.port,
                verdict: GateProbeVerdict::Malformed,
                reason: Some("probe sample needs a non-empty host and a non-zero port".into()),
            };
        }
        let decision = self.egress_gate.decide_target(&sample.host, sample.port);
        let (verdict, reason) = match decision.verdict {
            mvm_runtime::vmm::egress_gate::EgressVerdict::Allow { .. } => {
                (GateProbeVerdict::Admit, None)
            }
            mvm_runtime::vmm::egress_gate::EgressVerdict::Deny(deny) => {
                (GateProbeVerdict::Deny, Some(deny.to_string()))
            }
            mvm_runtime::vmm::egress_gate::EgressVerdict::Malformed => {
                (GateProbeVerdict::Malformed, None)
            }
        };
        GateProbeOutcome {
            host: sample.host.clone(),
            port: sample.port,
            verdict,
            reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use mvm_core::substitution_wire::{
        GateProbeExpect, GateProbeRequest, GateProbeSample, GateProbeVerdict,
    };

    use super::super::test_support::{gate_admitting, service_with_gate};

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
    fn a_peer_shaped_name_the_gate_cannot_parse_is_malformed() {
        // `not a peer!.mvm.peer` carries the peer suffix, so the gate routes
        // it to the peer namespace, where the name fails to parse.
        let outcomes = probe(
            &service(),
            vec![sample("not a peer!.mvm.peer", 443, GateProbeExpect::Deny)],
        );
        assert_eq!(outcomes[0].verdict, GateProbeVerdict::Malformed);
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
