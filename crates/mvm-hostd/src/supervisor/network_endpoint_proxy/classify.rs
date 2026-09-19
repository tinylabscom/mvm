//! Opaque-flow classification: whether a raw flow to a destination must be
//! refused, or can be terminated and substituted, given the admitted secret
//! bindings and transform policies.

use std::sync::Arc;

use super::SubstitutionService;
use super::redaction::redaction_active;

/// Whether the policy's catch-all action explicitly opts every destination
/// into inspection beyond the curated baseline. `RedactionAction::default()`
/// remains compatible with ordinary opaque relay; it is applied when a caller
/// deliberately chooses the typed HTTP class. Non-default detector modes are
/// an admitted requirement and therefore make opaque relay dishonest.
fn explicit_default_redaction(action: &mvm_core::policy::RedactionAction) -> bool {
    !matches!(action.entropy, mvm_core::policy::EntropyMode::Off)
        || !matches!(action.names, mvm_core::policy::NameMode::Off)
        || action.pii.mode.is_some()
        || !matches!(action.secrets, mvm_core::policy::SecretAction::Block)
}

/// How an opaque TCP flow could be terminated and re-forwarded rather than
/// spliced straight through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TerminationMode {
    /// The flow is on port 443. Termination mints a per-SNI leaf under the
    /// per-VM intermediate and decrypts from there.
    Tls,
    /// The flow's bytes are plaintext HTTP. Termination reads and rewrites
    /// the request directly, with no TLS leg.
    Cleartext,
}

impl SubstitutionService {
    /// Explain why an opaque flow to `destination` cannot honestly satisfy the
    /// admitted transformation policy.
    ///
    /// Secret bindings and explicitly enabled replacement/redaction profiles
    /// are destination-bound. Letting the same destination use opaque TCP or
    /// UDP would silently bypass the only path that can inspect, substitute,
    /// or redact its bytes. The caller refuses before DNS resolution or socket
    /// creation. The curated default redaction action does not make every
    /// opaque destination transformed; only an explicit profile/default opt-in
    /// or a bound secret does.
    pub(crate) fn opaque_refusal_reason(&self, destination: &str) -> Option<&'static str> {
        if self.registry.host_is_bound(destination) {
            return Some("destination requires secret substitution over typed HTTP");
        }

        if crate::supervisor::reversible_replacement_resolve::resolve(
            &self.reversible_replacement_policy,
            destination,
        )
        .enabled
        {
            return Some("destination requires reversible replacement over typed HTTP");
        }

        let explicit_redaction = self
            .redaction_policy
            .profiles
            .iter()
            .find(|profile| mvm_contract::ir::host_matches(&profile.host, destination))
            .map(|profile| redaction_active(&profile.action))
            .unwrap_or_else(|| explicit_default_redaction(&self.redaction_policy.default));
        explicit_redaction.then_some("destination requires redaction over typed HTTP")
    }

    /// Whether an opaque TCP flow to `host:port` could be terminated and
    /// substituted rather than refused outright.
    ///
    /// `None` means the existing refusal stands: `host` carries no bound
    /// secret, so there is nothing to substitute, or a secret is bound but
    /// this endpoint has no per-VM TLS intermediate to terminate under. A
    /// bound destination without a terminator fails closed rather than
    /// being spliced through untouched.
    pub(crate) fn terminable(&self, host: &str, port: u16) -> Option<TerminationMode> {
        if !self.registry.host_is_bound(host) {
            return None;
        }
        self.tls_intermediate.as_ref()?;
        match port {
            443 => Some(TerminationMode::Tls),
            80 => Some(TerminationMode::Cleartext),
            _ => None,
        }
    }

    /// The per-VM egress intermediate a terminated flow mints its per-SNI leaf
    /// under. `None` on an endpoint that was never given one, which is what
    /// makes [`Self::terminable`] refuse rather than terminate.
    pub(crate) fn tls_intermediate(&self) -> Option<&Arc<mvm_core::crypto::egress_ca::VmEgressCa>> {
        self.tls_intermediate.as_ref()
    }
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use crate::keyholder::{LocalResolver, SecretResolver, SubstitutionRegistry};
    use crate::supervisor::network_endpoint_proxy::SubstitutionService;
    use crate::supervisor::network_endpoint_proxy::test_support::{
        MockForwarder, bearer_ref, gate_admitting, service_with, service_with_policies,
    };
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use secrecy::SecretBox;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    #[test]
    fn a_secret_bound_destination_requires_the_typed_transform_class() {
        let (service, _placeholder, _forwarder, _dir) =
            service_with("sk-live-zzz", &["api.openai.com"]);

        assert_eq!(
            service.opaque_refusal_reason("api.openai.com"),
            Some("destination requires secret substitution over typed HTTP")
        );
        assert_eq!(service.opaque_refusal_reason("example.com"), None);
    }

    /// Build a service bound to `hosts` via one minted secret, optionally
    /// carrying a per-VM TLS intermediate minted under a fresh host CA.
    fn service_with_termination(
        hosts: &[&str],
        attach_intermediate: bool,
    ) -> (Arc<SubstitutionService>, tempfile::TempDir) {
        let dir = tempdir().expect("create tempdir");
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new("sk-live-zzz".to_string())),
            )
            .expect("seed secret store");
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));
        let mut reg = SubstitutionRegistry::new();
        let _placeholder = reg.mint(bearer_ref("openai", hosts));
        let forwarder = Arc::new(MockForwarder {
            seen: Mutex::new(None),
        });
        let admitted: Vec<(&str, u16)> = hosts.iter().map(|host| (*host, 443)).collect();
        let mut service = SubstitutionService::new(
            Arc::new(reg),
            resolver,
            forwarder,
            gate_admitting(&admitted),
        );
        if attach_intermediate {
            let intermediate = mvm_core::crypto::egress_ca::VmEgressCa::mint(hosts)
                .expect("mint the per-VM egress ca");
            service = service.with_tls_intermediate(intermediate);
        }
        (Arc::new(service), dir)
    }

    #[test]
    fn a_bound_host_with_an_intermediate_is_terminable_as_tls_on_443() {
        let (service, _dir) = service_with_termination(&["api.openai.com"], true);
        assert_eq!(
            service.terminable("api.openai.com", 443),
            Some(TerminationMode::Tls)
        );
    }

    #[test]
    fn a_bound_host_with_an_intermediate_is_terminable_as_cleartext_on_80() {
        let (service, _dir) = service_with_termination(&["api.openai.com"], true);
        assert_eq!(
            service.terminable("api.openai.com", 80),
            Some(TerminationMode::Cleartext)
        );
    }

    #[test]
    fn a_bound_host_without_an_intermediate_stays_refused() {
        let (service, _dir) = service_with_termination(&["api.openai.com"], false);
        assert_eq!(service.terminable("api.openai.com", 443), None);
    }

    #[test]
    fn an_unbound_host_is_not_terminable() {
        let (service, _dir) = service_with_termination(&["api.openai.com"], true);
        assert_eq!(service.terminable("example.com", 443), None);
    }

    #[test]
    fn explicit_redaction_and_replacement_require_the_typed_transform_class() {
        use mvm_core::policy::{
            EntropyMode, RedactionAction, RedactionPolicy, RedactionProfile,
            ReversibleReplacementAction, ReversibleReplacementPolicy, ReversibleReplacementProfile,
        };

        let redaction = RedactionPolicy {
            profiles: vec![RedactionProfile {
                host: "redact.example".into(),
                action: RedactionAction {
                    entropy: EntropyMode::Redact {
                        min_bits_per_char: 4.0,
                        min_run_len: 20,
                    },
                    ..Default::default()
                },
            }],
            ..Default::default()
        };
        let replacement = ReversibleReplacementPolicy {
            profiles: vec![ReversibleReplacementProfile {
                host: "replace.example".into(),
                action: ReversibleReplacementAction {
                    enabled: true,
                    ..Default::default()
                },
            }],
            ..Default::default()
        };
        let (service, _placeholder, _forwarder, _dir) = service_with_policies(
            "sk-live-zzz",
            &["secret.example"],
            Some(redaction),
            Some(replacement),
        );

        assert_eq!(
            service.opaque_refusal_reason("redact.example"),
            Some("destination requires redaction over typed HTTP")
        );
        assert_eq!(
            service.opaque_refusal_reason("replace.example"),
            Some("destination requires reversible replacement over typed HTTP")
        );
        assert_eq!(service.opaque_refusal_reason("opaque.example"), None);
    }

    #[test]
    fn curated_default_redaction_does_not_claim_to_transform_opaque_flows() {
        let (service, _placeholder, _forwarder, _dir) =
            service_with("sk-live-zzz", &["api.openai.com"]);

        assert_eq!(service.opaque_refusal_reason("opaque.example"), None);
    }
}
