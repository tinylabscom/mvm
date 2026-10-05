//! Tool-scoped routes and secrets, decided against a flow's attribution.
//!
//! A route or secret a tool declares belongs to that tool. The egress gate has
//! already admitted the destination when this runs; this narrows who may use
//! it. A flow is attributed to a tool only through a binding this endpoint
//! minted for an admitted invocation and has not yet released, which the guest
//! names only for connections its agent traced to that invocation's session.
//! Every refusal is recorded as `host.tool.scope_refused`, naming the declared
//! route or the secret and the rule that refused it.

use std::net::IpAddr;

use mvm_contract::policy::tool_rules::{RouteScope, ToolRules};
use mvm_contract::protocol::network_flow::attribution::ToolInvocationBinding;

use super::SubstitutionService;
use crate::supervisor::audit_recorder::EventCategory;

/// Fixed refusal reasons, safe for the guest and the audit chain.
pub(crate) const REASON_TOOL_ROUTE: &str = "tool_route_scope";
pub(crate) const REASON_TOOL_SECRET: &str = "tool_secret_scope";

/// The admitted invocation a flow belongs to, if any.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FlowAttribution {
    binding: Option<ToolInvocationBinding>,
    tool: Option<String>,
}

impl FlowAttribution {
    /// The tool the flow is an invocation of.
    pub(crate) fn tool(&self) -> Option<&str> {
        self.tool.as_deref()
    }

    /// The binding the flow named and this endpoint recognised.
    pub(crate) fn binding(&self) -> Option<&ToolInvocationBinding> {
        self.binding.as_ref()
    }
}

/// Every name `host` answers to for tool-route purposes: itself, plus each
/// declared route host whose admitted addresses include it when `host` is a
/// literal address. A workload cannot reach a tool's route by dialling the
/// address its name resolved to.
fn route_hosts(
    gate: &mvm_runtime::vmm::egress_gate::EgressGate,
    rules: &ToolRules,
    host: &str,
    port: u16,
) -> Vec<String> {
    use mvm_runtime::vmm::egress_gate::EgressVerdict;
    let mut hosts = vec![host.to_string()];
    let Ok(dialled) = host.trim_matches(['[', ']']).parse::<IpAddr>() else {
        return hosts;
    };
    for (route_host, route_port) in rules.declared_routes() {
        if route_port.is_some_and(|route_port| route_port != port)
            || route_host.parse::<IpAddr>().is_ok()
        {
            continue;
        }
        if let EgressVerdict::Allow { ips, .. } =
            gate.decide_request(&format!("{route_host}:{port}"))
            && ips.contains(&dialled)
        {
            hosts.push(route_host.to_string());
        }
    }
    hosts
}

impl SubstitutionService {
    /// Resolve the binding a flow named to the invocation it belongs to. A
    /// binding this endpoint did not mint, or has released, attributes the
    /// flow to no tool.
    pub(crate) fn attribute(&self, binding: Option<ToolInvocationBinding>) -> FlowAttribution {
        let Some((gate, binding)) = self.tool_gate.as_ref().zip(binding) else {
            return FlowAttribution::default();
        };
        match gate.tool_for(&binding) {
            Some(tool) => FlowAttribution {
                binding: Some(binding),
                tool: Some(tool),
            },
            None => FlowAttribution::default(),
        }
    }

    /// Whether any tool declares a route, so an unattributed flow can be
    /// refused somewhere.
    pub(crate) fn declares_tool_routes(&self) -> bool {
        self.tool_gate
            .as_ref()
            .is_some_and(|gate| gate.rules().declared_routes().next().is_some())
    }

    /// Refuse a flow to `host:port` the tool rules reserve for another tool,
    /// or that the flow's own tool does not declare.
    pub(crate) async fn enforce_tool_route(
        &self,
        host: &str,
        port: u16,
        attribution: &FlowAttribution,
    ) -> Result<(), &'static str> {
        let Some(gate) = self
            .tool_gate
            .as_ref()
            .filter(|_| self.declares_tool_routes())
        else {
            return Ok(());
        };
        let egress_gate = std::sync::Arc::clone(&self.egress_gate);
        let rules = gate.rules().clone();
        let lookup_host = host.to_string();
        let hosts = tokio::task::spawn_blocking(move || {
            route_hosts(&egress_gate, &rules, &lookup_host, port)
        })
        .await
        .map_err(|_| REASON_TOOL_ROUTE)?;
        let hosts: Vec<&str> = hosts.iter().map(String::as_str).collect();
        match gate.rules().route_scope(attribution.tool(), &hosts, port) {
            RouteScope::Unscoped | RouteScope::Owned { .. } => Ok(()),
            RouteScope::Refused { route, reason } => {
                let mut labels = vec![
                    ("scope".to_string(), "route".to_string()),
                    ("tool_route".to_string(), route.unwrap_or_default()),
                ];
                labels.push(("destination".to_string(), format!("{host}:{port}")));
                self.audit_tool_scope_refused(labels, reason, attribution)
                    .await;
                Err(REASON_TOOL_ROUTE)
            }
        }
    }

    /// Refuse a request carrying a secret the tool rules reserve for another
    /// tool, or that the flow's own tool does not declare.
    pub(crate) async fn enforce_tool_secrets(
        &self,
        secrets: &[String],
        destination: &str,
        attribution: &FlowAttribution,
    ) -> Result<(), &'static str> {
        let Some(gate) = &self.tool_gate else {
            return Ok(());
        };
        for secret in secrets {
            if let Err(reason) = gate.rules().secret_scope(attribution.tool(), secret) {
                let labels = vec![
                    ("scope".to_string(), "secret".to_string()),
                    ("secret".to_string(), secret.clone()),
                    ("destination".to_string(), destination.to_string()),
                ];
                self.audit_tool_scope_refused(labels, reason, attribution)
                    .await;
                return Err(REASON_TOOL_SECRET);
            }
        }
        Ok(())
    }

    async fn audit_tool_scope_refused(
        &self,
        mut labels: Vec<(String, String)>,
        reason: &'static str,
        attribution: &FlowAttribution,
    ) {
        let Some(recorder) = &self.recorder else {
            tracing::warn!(reason, "tool scope refusal with no audit recorder");
            return;
        };
        labels.push(("rule".to_string(), "tool_scope".to_string()));
        labels.push(("reason".to_string(), reason.to_string()));
        if let Some(binding) = attribution.binding() {
            labels.push(("binding".to_string(), binding.to_string()));
        }
        if let Err(error) = recorder
            .record_unbound(EventCategory::Host, "host.tool.scope_refused", labels)
            .await
        {
            tracing::warn!(%error, "tool scope refusal audit failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mvm_contract::policy::tool_rules::ToolRuleDetail;
    use mvm_core::plan::TenantId;

    use super::*;
    use crate::supervisor::audit::CapturingAuditSigner;
    use crate::supervisor::audit_recorder::Recorder;
    use crate::supervisor::network_endpoint_proxy::test_support::service_with_tool_gate;
    use crate::supervisor::runtime_approval::NoApprovalBackend;
    use crate::supervisor::tool_decision::{InvocationVerdict, ToolDecisionGate};

    fn rules() -> ToolRules {
        let mut rules = ToolRules {
            allow: vec!["gh".into(), "plain".into()],
            ..ToolRules::default()
        };
        rules.detail.insert(
            "gh".into(),
            ToolRuleDetail {
                routes: vec!["api.github.com:443".into()],
                secrets: vec!["github".into()],
                ..Default::default()
            },
        );
        rules
    }

    fn scoped_service() -> (
        Arc<SubstitutionService>,
        Arc<ToolDecisionGate>,
        Arc<CapturingAuditSigner>,
        tempfile::TempDir,
    ) {
        let signer = Arc::new(CapturingAuditSigner::new());
        let recorder = Arc::new(Recorder::new(signer.clone(), TenantId("local".into())));
        let gate = Arc::new(ToolDecisionGate::new(
            rules(),
            Arc::new(NoApprovalBackend),
            Arc::clone(&recorder),
        ));
        let (service, dir) = service_with_tool_gate(Arc::clone(&gate));
        let service = Arc::try_unwrap(service)
            .map_err(|_| "shared")
            .expect("unshared service")
            .with_shared_recorder(recorder);
        (Arc::new(service), gate, signer, dir)
    }

    async fn bound(gate: &ToolDecisionGate) -> ToolInvocationBinding {
        match gate.decide_invocation("gh", "gh api").await.expect("audit") {
            InvocationVerdict::Allow {
                binding: Some(binding),
            } => binding,
            other => panic!("expected a bound allow, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_released_or_unknown_binding_attributes_to_no_tool() {
        let (service, gate, _signer, _dir) = scoped_service();
        let binding = bound(&gate).await;
        assert_eq!(service.attribute(Some(binding.clone())).tool(), Some("gh"));
        gate.release(&binding);
        assert_eq!(service.attribute(Some(binding)), FlowAttribution::default());
        assert_eq!(
            service.attribute(Some(ToolInvocationBinding::from_random([1; 16]))),
            FlowAttribution::default()
        );
    }

    #[tokio::test]
    async fn a_tool_route_is_refused_without_the_binding_and_audited() {
        let (service, gate, signer, _dir) = scoped_service();
        let unattributed = FlowAttribution::default();
        assert_eq!(
            service
                .enforce_tool_route("api.github.com", 443, &unattributed)
                .await,
            Err(REASON_TOOL_ROUTE)
        );
        let attributed = service.attribute(Some(bound(&gate).await));
        assert!(
            service
                .enforce_tool_route("api.github.com", 443, &attributed)
                .await
                .is_ok()
        );
        let recorded = serde_json::to_string(&signer.entries()).expect("entries");
        assert!(recorded.contains("host.tool.scope_refused"), "{recorded}");
        assert!(recorded.contains("api.github.com:443"), "{recorded}");
        assert!(recorded.contains("tool_scope"), "{recorded}");
    }

    #[tokio::test]
    async fn a_bound_invocation_reaches_only_its_tools_routes() {
        let (service, gate, _signer, _dir) = scoped_service();
        let attributed = service.attribute(Some(bound(&gate).await));
        assert_eq!(
            service
                .enforce_tool_route("crates.io", 443, &attributed)
                .await,
            Err(REASON_TOOL_ROUTE)
        );
        assert!(
            service
                .enforce_tool_route("crates.io", 443, &FlowAttribution::default())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_tool_secret_is_refused_without_the_binding_and_audited() {
        let (service, gate, signer, _dir) = scoped_service();
        let secrets = vec!["github".to_string()];
        assert_eq!(
            service
                .enforce_tool_secrets(&secrets, "api.github.com", &FlowAttribution::default())
                .await,
            Err(REASON_TOOL_SECRET)
        );
        let attributed = service.attribute(Some(bound(&gate).await));
        assert!(
            service
                .enforce_tool_secrets(&secrets, "api.github.com", &attributed)
                .await
                .is_ok()
        );
        let recorded = serde_json::to_string(&signer.entries()).expect("entries");
        assert!(recorded.contains("\"secret\""), "{recorded}");
        assert!(recorded.contains(REASON_TOOL_SECRET) || recorded.contains("tool_scope"));
    }

    #[test]
    fn a_literal_address_answers_to_a_route_host_that_resolves_to_it() {
        // The fixture gate pins the first named host to 192.0.2.1.
        let gate = crate::supervisor::network_endpoint_proxy::test_support::gate_admitting(&[
            ("api.github.com", 443),
            ("192.0.2.1", 443),
            ("192.0.2.99", 443),
        ]);
        assert_eq!(
            route_hosts(&gate, &rules(), "192.0.2.1", 443),
            ["192.0.2.1", "api.github.com"]
        );
        assert_eq!(
            route_hosts(&gate, &rules(), "192.0.2.99", 443),
            ["192.0.2.99"]
        );
        assert_eq!(route_hosts(&gate, &rules(), "192.0.2.1", 80), ["192.0.2.1"]);
        assert_eq!(
            route_hosts(&gate, &rules(), "example.com", 443),
            ["example.com"]
        );
    }
}
