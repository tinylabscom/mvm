//! Ingress use of the endpoint's admitted material: host-only secrets
//! resolved by signed name, per-connection ingress transformers, and their
//! payload-free audit.

use super::SubstitutionService;
use crate::supervisor::audit_recorder::EventCategory;

/// Failure to resolve host-owned transformation material by its signed plan
/// reference. Errors name only the reference, never the secret bytes.
#[derive(Debug, thiserror::Error)]
pub enum HostMaterialError {
    #[error("host transformation material `{name}` is absent from the admitted plan")]
    NotAdmitted { name: String },
    #[error("host transformation material `{name}` could not be resolved")]
    Unavailable {
        name: String,
        #[source]
        source: crate::keyholder::ResolveError,
    },
}

impl SubstitutionService {
    /// Resolve a host-only transformation secret by its signed plan name.
    /// The returned `SecretBox` zeroizes on drop; callers must parse it in
    /// place and must never serialize or log the exposed bytes.
    pub fn resolve_host_material(
        &self,
        name: &str,
    ) -> Result<secrecy::SecretBox<Vec<u8>>, HostMaterialError> {
        let secret =
            self.registry
                .resolve_name(name)
                .ok_or_else(|| HostMaterialError::NotAdmitted {
                    name: name.to_string(),
                })?;
        self.resolver
            .resolve(secret)
            .map_err(|source| HostMaterialError::Unavailable {
                name: name.to_string(),
                source,
            })
    }

    /// Build per-connection ingress HTTP transformation state from the same
    /// admitted policies used by typed egress. `profile_key` is the signed host
    /// bind address; no peer-controlled Host header selects policy.
    pub fn ingress_transformer(
        &self,
        profile_key: &str,
    ) -> crate::supervisor::ingress_transform::IngressTransformer {
        let redaction =
            crate::supervisor::redaction_resolve::resolve(&self.redaction_policy, profile_key)
                .clone();
        let replacement = crate::supervisor::reversible_replacement_resolve::resolve(
            &self.reversible_replacement_policy,
            profile_key,
        )
        .clone();
        crate::supervisor::ingress_transform::IngressTransformer::new(
            &self.tenant,
            redaction,
            replacement,
        )
    }

    /// Append one payload-free signed audit event for a transformed ingress
    /// exchange. The runtime handle belongs to the endpoint; transform workers
    /// are bounded blocking threads and use it only for the short signer call.
    pub fn audit_ingress_transform(
        &self,
        runtime: &tokio::runtime::Handle,
        mapping_id: u16,
        result: &Result<
            crate::supervisor::ingress_transform::IngressTransformSummary,
            crate::supervisor::ingress_transform::IngressTransformError,
        >,
    ) {
        let Some(recorder) = self.recorder.clone() else {
            return;
        };
        let (event_name, labels) = ingress_transform_audit(mapping_id, result);
        let _ = runtime.block_on(recorder.record_unbound(EventCategory::Host, event_name, labels));
    }
}

fn ingress_transform_audit(
    mapping_id: u16,
    result: &Result<
        crate::supervisor::ingress_transform::IngressTransformSummary,
        crate::supervisor::ingress_transform::IngressTransformError,
    >,
) -> (&'static str, std::collections::BTreeMap<String, String>) {
    match result {
        Ok(summary) => (
            "host.ingress.transformed",
            std::collections::BTreeMap::from([
                ("mapping_id".to_string(), mapping_id.to_string()),
                ("verdict".to_string(), "allowed".to_string()),
                (
                    "request_rewrites".to_string(),
                    summary.request_rewrites.to_string(),
                ),
                (
                    "response_reinjections".to_string(),
                    summary.response_reinjections.to_string(),
                ),
                (
                    "redaction_events".to_string(),
                    summary.redaction_events.to_string(),
                ),
            ]),
        ),
        Err(error) => (
            "host.ingress.transform_refused",
            std::collections::BTreeMap::from([
                ("mapping_id".to_string(), mapping_id.to_string()),
                ("verdict".to_string(), "denied".to_string()),
                ("reason".to_string(), error.audit_reason().to_string()),
            ]),
        ),
    }
}

#[cfg(test)]
#[test]
fn ingress_transform_audit_contains_only_bounded_metadata() {
    let result = Ok(
        crate::supervisor::ingress_transform::IngressTransformSummary {
            request_rewrites: 2,
            response_reinjections: 1,
            redaction_events: 3,
        },
    );
    let (event, labels) = ingress_transform_audit(17, &result);
    let encoded = serde_json::to_string(&labels).unwrap();

    assert_eq!(event, "host.ingress.transformed");
    assert_eq!(labels.get("mapping_id").map(String::as_str), Some("17"));
    assert_eq!(
        labels.get("request_rewrites").map(String::as_str),
        Some("2")
    );
    assert!(!encoded.contains("payload"));
    assert!(!encoded.contains("PRIVATE KEY"));
    assert!(!encoded.contains("sk-"));
}

#[cfg(test)]
#[test]
fn ingress_transform_refusal_audit_contains_only_a_stable_reason() {
    let result = Err(crate::supervisor::ingress_transform::IngressTransformError::BodyTooLarge);
    let (event, labels) = ingress_transform_audit(19, &result);
    let encoded = serde_json::to_string(&labels).unwrap();

    assert_eq!(event, "host.ingress.transform_refused");
    assert_eq!(
        labels,
        std::collections::BTreeMap::from([
            ("mapping_id".to_string(), "19".to_string()),
            ("reason".to_string(), "body_too_large".to_string()),
            ("verdict".to_string(), "denied".to_string()),
        ])
    );
    assert!(!encoded.contains("payload"));
    assert!(!encoded.contains("PRIVATE KEY"));
    assert!(!encoded.contains("sk-"));
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use crate::supervisor::network_endpoint_proxy::test_support::service_with;

    #[test]
    fn host_material_resolves_by_signed_name_without_serializing_its_value() {
        use secrecy::ExposeSecret as _;

        let marker = "-----BEGIN PRIVATE KEY-----\nhost-only";
        let (service, placeholder, _forwarder, _dir) =
            service_with(marker, &["ingress-material.local"]);
        let resolved = service.resolve_host_material("openai").unwrap();
        assert_eq!(resolved.expose_secret().as_slice(), marker.as_bytes());
        assert!(!placeholder.contains(marker));
        assert!(matches!(
            service.resolve_host_material("not-admitted"),
            Err(HostMaterialError::NotAdmitted { .. })
        ));
    }
}
