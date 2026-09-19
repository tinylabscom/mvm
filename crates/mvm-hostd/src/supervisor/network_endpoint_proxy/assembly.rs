//! Service assembly: the constructor, the builder methods that attach policy
//! and audit state, and `from_plan`, which builds a ready-to-serve service from
//! an admitted plan.

use std::sync::Arc;

use mvm_core::plan::SecretBinding;

use super::SubstitutionService;
use super::forward::{ForwardError, Forwarder, HardenedForwarder};
use crate::keyholder::{
    AssembleError, BindingStore, HandedPlaceholders, SecretResolver, SubstitutionRegistry,
    assemble_registry,
};
use crate::supervisor::ai_meter;
use crate::supervisor::audit_recorder::Recorder;
use crate::supervisor::redactor::RedactingSubstitution;
use crate::supervisor::reversible_replacement::ReplacementEngine;

/// Errors from building a [`SubstitutionService`] from an admitted plan.
#[derive(Debug, thiserror::Error)]
pub enum FromPlanError {
    #[error(transparent)]
    Assemble(#[from] AssembleError),
    #[error(transparent)]
    Forward(#[from] ForwardError),
}

/// Inputs to [`SubstitutionService::from_plan`] — the admitted plan's secret
/// bindings plus the host substrate (stores, redaction, the claim-10 egress
/// gate, optional TLS intermediate, optional audit recorder) the per-VM
/// endpoint assembles from.
pub struct FromPlanInputs<'a> {
    pub plan_secrets: &'a [SecretBinding],
    pub tenant: &'a str,
    /// VM instance identifier used to attribute AI egress metrics and audit
    /// records. An empty string means the endpoint has no instance context.
    pub instance_id: &'a str,
    pub bindings: &'a dyn BindingStore,
    /// The value resolver the service resolves each bound secret through. Built
    /// by the caller (`assemble`) from `EndpointConfig.resolver`: a
    /// [`LocalResolver`] over the host secret store (default), or a
    /// [`crate::keyholder::RemoteResolver`] dialing a fleet-secrets daemon UDS.
    pub resolver: Arc<dyn SecretResolver>,
    pub forward_timeout_secs: u64,
    /// Operator-configured upstream proxy for the forward leg, if the host
    /// force-tunnels its egress. `None` dials destinations directly.
    pub proxy: Option<mvm_http::ProxyConfig>,
    pub redaction: mvm_core::policy::RedactionPolicy,
    pub reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy,
    pub tls_intermediate: Option<mvm_core::crypto::egress_ca::VmEgressCa>,
    pub recorder: Option<Recorder>,
    /// Per-VM AI egress metering/budget policy. `None` means AI egress is not
    /// metered and no budget is enforced.
    pub ai_policy: Option<mvm_contract::policy::network_policy::AiPolicy>,
    /// The claim-10 gate every request is decided against before it is
    /// forwarded. An endpoint with no admitted network policy passes a
    /// default-deny gate; there is no way to pass none.
    pub egress_gate: Arc<mvm_runtime::vmm::egress_gate::EgressGate>,
}

impl SubstitutionService {
    /// Build a service over its registry, resolver, forward leg and claim-10
    /// gate. The gate is a constructor argument rather than a builder step so
    /// that a service which forwards without deciding the destination cannot
    /// be built. It is an `Arc` because the endpoint shares one gate object
    /// across every network surface.
    pub fn new(
        registry: Arc<SubstitutionRegistry>,
        resolver: Arc<dyn SecretResolver>,
        forwarder: Arc<dyn Forwarder>,
        egress_gate: Arc<mvm_runtime::vmm::egress_gate::EgressGate>,
    ) -> Self {
        Self {
            tenant: "local".to_string(),
            registry,
            resolver,
            forwarder,
            redactor: RedactingSubstitution::with_default_rules(),
            recorder: None,
            tls_intermediate: None,
            redaction_policy: mvm_core::policy::RedactionPolicy::default(),
            reversible_replacement_policy: mvm_core::policy::ReversibleReplacementPolicy::default(),
            replacement_engine: ReplacementEngine::new(),
            egress_gate,
            ai_policy: None,
            ai_tracker: None,
            instance_id: None,
            instance_metrics: None,
        }
    }

    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = tenant.into();
        self
    }

    /// Attach a per-destination redaction policy. Default leaves entropy + names
    /// off everywhere (curated-only baseline); a policy opts specific
    /// destinations into entropy/name redaction.
    pub fn with_redaction_policy(mut self, policy: mvm_core::policy::RedactionPolicy) -> Self {
        self.redaction_policy = policy;
        self
    }

    pub fn with_reversible_replacement_policy(
        mut self,
        policy: mvm_core::policy::ReversibleReplacementPolicy,
    ) -> Self {
        self.reversible_replacement_policy = policy;
        self
    }

    /// Attach a chain-signed audit recorder; each substitution then emits a
    /// `secret.substituted` entry (metadata only — claim 13).
    pub fn with_recorder(mut self, recorder: Recorder) -> Self {
        self.recorder = Some(Arc::new(recorder));
        self
    }

    /// Attach the endpoint's shared chain-signed audit sink.
    pub fn with_shared_recorder(mut self, recorder: Arc<Recorder>) -> Self {
        self.recorder = Some(recorder);
        self
    }

    /// Attach the per-VM egress intermediate so the terminator can terminate
    /// bound-host `https`. Absent ⇒ `http`-only.
    pub fn with_tls_intermediate(
        mut self,
        intermediate: mvm_core::crypto::egress_ca::VmEgressCa,
    ) -> Self {
        self.tls_intermediate = Some(Arc::new(intermediate));
        self
    }

    /// Attach the VM instance identifier used to attribute AI egress metrics
    /// and audit records. Empty strings are treated as absent.
    pub fn with_instance_id(mut self, instance_id: impl Into<String>) -> Self {
        let id = instance_id.into();
        self.instance_id = (!id.is_empty()).then_some(id);
        self
    }

    /// Attach a per-VM AI egress metering/budget policy. Metering is only
    /// active when `policy.metering` is `true`.
    pub fn with_ai_policy(
        mut self,
        policy: mvm_contract::policy::network_policy::AiPolicy,
    ) -> Self {
        if policy.metering {
            self.ai_tracker = Some(Arc::new(ai_meter::AiBudgetTracker::new(policy.budget)));
        }
        self.ai_policy = Some(policy);
        self
    }

    /// Override the per-VM metrics registry used for AI counters. When not
    /// set, the process-global registry is used.
    pub fn with_instance_metrics(
        mut self,
        registry: Arc<mvm_core::observability::instance_metrics::InstanceMetricsRegistry>,
    ) -> Self {
        self.instance_metrics = Some(registry);
        self
    }

    /// Assemble a ready-to-serve service from an admitted plan's secret
    /// bindings: build the registry ([`assemble_registry`]) and a
    /// hardened forwarder, and resolve values through the caller-supplied
    /// [`SecretResolver`] (a [`LocalResolver`] over the tenant's secret store by
    /// default, or a remote fleet-secrets resolver). Returns the service plus the
    /// `(guest name, placeholder)` pairs the supervisor injects into the guest.
    /// The caller binds the listener and calls [`Self::serve`].
    pub fn from_plan(
        inputs: FromPlanInputs<'_>,
    ) -> Result<(Arc<Self>, HandedPlaceholders), FromPlanError> {
        let FromPlanInputs {
            plan_secrets,
            tenant,
            instance_id,
            bindings,
            resolver,
            forward_timeout_secs,
            proxy,
            redaction,
            reversible_replacement,
            tls_intermediate,
            recorder,
            ai_policy,
            egress_gate,
        } = inputs;
        let (registry, handed) = assemble_registry(plan_secrets, tenant, bindings)?;
        let forwarder: Arc<dyn Forwarder> =
            Arc::new(HardenedForwarder::new(forward_timeout_secs)?.with_proxy(proxy));
        let mut service = Self::new(Arc::new(registry), resolver, forwarder, egress_gate)
            .with_tenant(tenant)
            .with_instance_id(instance_id);
        service = service.with_redaction_policy(redaction);
        service = service.with_reversible_replacement_policy(reversible_replacement);
        if let Some(intermediate) = tls_intermediate {
            service = service.with_tls_intermediate(intermediate);
        }
        if let Some(recorder) = recorder {
            service = service.with_recorder(recorder);
        }
        if let Some(policy) = ai_policy {
            service = service.with_ai_policy(policy);
        }
        Ok((Arc::new(service), handed))
    }

    /// The attached redaction policy. Test-only: lets the threading tests prove
    /// a policy carried through `from_plan` actually reached the service.
    #[cfg(test)]
    pub(crate) fn redaction_policy(&self) -> &mvm_core::policy::RedactionPolicy {
        &self.redaction_policy
    }

    /// The attached resolver. Test-only: lets `assemble`'s resolver-backend
    /// tests prove which `SecretResolver` (`LocalResolver` vs `RemoteResolver`)
    /// actually reached the service, via an observable `resolve()` call rather
    /// than reaching into a private field.
    #[cfg(test)]
    pub(crate) fn resolver(&self) -> &Arc<dyn SecretResolver> {
        &self.resolver
    }

    /// Run the service's redactor for a destination action. Test-only seam so the
    /// endpoint-config tests can prove the threaded policy fires end-to-end.
    #[cfg(test)]
    pub(crate) fn redactor_redact_bytes_for(
        &self,
        payload: &[u8],
        action: &mvm_core::policy::RedactionAction,
    ) -> Option<(Vec<u8>, crate::supervisor::redactor::RedactionHits)> {
        self.redactor.redact_bytes_for(payload, action)
    }

    #[cfg(test)]
    pub(crate) fn shared_projection_ids(&self) -> (usize, Option<usize>) {
        (
            Arc::as_ptr(&self.egress_gate).cast::<()>() as usize,
            self.recorder
                .as_ref()
                .map(|recorder| Arc::as_ptr(recorder).cast::<()>() as usize),
        )
    }
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use crate::keyholder::{LocalResolver, SecretResolver};
    use crate::supervisor::network_endpoint_proxy::SubstitutionService;
    use mvm_contract::ir::AuthType;
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_runtime::vmm::egress_gate::EgressGate;
    use secrecy::SecretBox;
    use std::sync::Arc;
    use tempfile::tempdir;

    /// A service assembled the way the endpoint assembles one, under the
    /// default-deny gate an endpoint with no admitted policy carries, refuses a
    /// request that carries no placeholder at all. The binding check has nothing
    /// to refuse there, so this is the claim-10 gate alone, and the refusal comes
    /// before the hardened forwarder could dial anything.
    #[tokio::test]
    async fn from_plan_service_refuses_an_unadmitted_destination_without_a_placeholder() {
        use crate::keyholder::FileBindingStore;
        use mvm_core::substitution_wire::{WireRequest, WireResponse};

        let dir = tempdir().unwrap();
        let bindings = FileBindingStore::with_dir(dir.path().join("bindings"));
        let store = FileSecretStore::with_dir(dir.path().join("secrets"));
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));
        let (service, handed) = SubstitutionService::from_plan(FromPlanInputs {
            plan_secrets: &[],
            tenant: "local",
            instance_id: "",
            ai_policy: None,
            bindings: &bindings,
            resolver,
            forward_timeout_secs: 30,
            proxy: None,
            redaction: mvm_core::policy::RedactionPolicy::default(),
            reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
            tls_intermediate: None,
            recorder: None,
            egress_gate: Arc::new(EgressGate::default_deny()),
        })
        .unwrap();
        assert!(handed.is_empty());

        let resp = service
            .process(WireRequest {
                method: "GET".into(),
                url: "https://93.184.216.34/".into(),
                headers: Vec::new(),
                body_b64: String::new(),
            })
            .await;
        match resp {
            WireResponse::Refused { message } => assert_eq!(
                message,
                "egress destination not admitted by network policy (claim-10)"
            ),
            WireResponse::Ok { status, .. } => {
                panic!("an unadmitted destination was forwarded (status {status})")
            }
        }
    }

    #[test]
    fn from_plan_builds_a_service_and_handed_placeholders() {
        use crate::keyholder::{FileBindingStore, SecretBindingMeta};
        use mvm_core::plan::{SecretBinding, SecretSource};

        let dir = tempdir().unwrap();
        // Binding metadata (`secret set`) + the value store.
        let bindings = FileBindingStore::with_dir(dir.path().join("bindings"));
        bindings
            .put(
                "local",
                "openai",
                &SecretBindingMeta {
                    auth_type: AuthType::Bearer,
                    allowed_hosts: vec!["api.openai.com".into()],
                    sigv4: None,
                    provider: None,
                },
            )
            .unwrap();
        let store = FileSecretStore::with_dir(dir.path().join("secrets"));
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new("sk".to_string())),
            )
            .unwrap();
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));

        let plan = [SecretBinding {
            name: "OPENAI_API_KEY".into(),
            source: SecretSource::Keystore {
                address: "openai".into(),
            },
        }];
        let (_service, handed) = SubstitutionService::from_plan(FromPlanInputs {
            plan_secrets: &plan,
            tenant: "local",
            instance_id: "",
            ai_policy: None,
            bindings: &bindings,
            resolver,
            forward_timeout_secs: 30,
            proxy: None,
            redaction: mvm_core::policy::RedactionPolicy::default(),
            reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
            tls_intermediate: None,
            recorder: None,
            egress_gate: Arc::new(EgressGate::default_deny()),
        })
        .unwrap();
        assert_eq!(handed.len(), 1);
        assert_eq!(handed[0].0, "OPENAI_API_KEY");
        assert!(handed[0].1.as_str().starts_with("mvm-secret-"));
    }

    #[test]
    fn from_plan_threads_redaction_policy_onto_the_service() {
        use crate::keyholder::{FileBindingStore, SecretBindingMeta};
        use mvm_core::plan::{SecretBinding, SecretSource};
        use mvm_core::policy::{EntropyMode, RedactionAction, RedactionPolicy, RedactionProfile};

        let dir = tempdir().unwrap();
        let bindings = FileBindingStore::with_dir(dir.path().join("bindings"));
        bindings
            .put(
                "local",
                "openai",
                &SecretBindingMeta {
                    auth_type: AuthType::Bearer,
                    allowed_hosts: vec!["api.openai.com".into()],
                    sigv4: None,
                    provider: None,
                },
            )
            .unwrap();
        let store = FileSecretStore::with_dir(dir.path().join("secrets"));
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new("sk".to_string())),
            )
            .unwrap();
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));

        let plan = [SecretBinding {
            name: "OPENAI_API_KEY".into(),
            source: SecretSource::Keystore {
                address: "openai".into(),
            },
        }];

        // A policy that opts api.openai.com into entropy redaction. After
        // from_plan, resolving that host must yield the opted-in action — proving
        // the policy reached the live service (not just defaulted).
        let policy = RedactionPolicy {
            default: RedactionAction::default(),
            profiles: vec![RedactionProfile {
                host: "api.openai.com".into(),
                action: RedactionAction {
                    entropy: EntropyMode::Redact {
                        min_bits_per_char: 4.0,
                        min_run_len: 20,
                    },
                    ..Default::default()
                },
            }],
        };
        let (service, _handed) = SubstitutionService::from_plan(FromPlanInputs {
            plan_secrets: &plan,
            tenant: "local",
            instance_id: "",
            ai_policy: None,
            bindings: &bindings,
            resolver,
            forward_timeout_secs: 30,
            proxy: None,
            redaction: policy,
            reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
            tls_intermediate: None,
            recorder: None,
            egress_gate: Arc::new(EgressGate::default_deny()),
        })
        .unwrap();
        let resolved = crate::supervisor::redaction_resolve::resolve(
            service.redaction_policy(),
            "api.openai.com",
        );
        assert!(
            matches!(resolved.entropy, EntropyMode::Redact { .. }),
            "redaction policy did not reach the service: {:?}",
            resolved.entropy
        );
    }
}
