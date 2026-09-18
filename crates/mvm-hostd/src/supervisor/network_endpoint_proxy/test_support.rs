//! Test doubles shared by the endpoint's per-module suites.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use mvm_contract::ir::{AuthType, SecretMount, SecretRef};
use mvm_contract::substitution::PreparedRequest;
use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
use secrecy::SecretBox;
use tempfile::tempdir;

use super::{ForwardError, ForwardResponse, Forwarder, SubstitutionService};
use crate::keyholder::{LocalResolver, SecretResolver, SubstitutionRegistry};

pub(super) fn resolver_with(name: &str, value: &str) -> (tempfile::TempDir, LocalResolver) {
    let dir = tempdir().unwrap();
    let store = FileSecretStore::with_dir(dir.path());
    store
        .put("local", name, &SecretBox::new(Box::new(value.to_string())))
        .unwrap();
    let store: Arc<dyn SecretStore> = Arc::new(store);
    (dir, LocalResolver::new("local", store))
}

pub(super) fn bearer_ref(name: &str, hosts: &[&str]) -> SecretRef {
    SecretRef {
        name: name.into(),
        mount: SecretMount::Env { var: "K".into() },
        auth_type: AuthType::Bearer,
        allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
        sigv4: None,
    }
}

pub(super) fn sigv4_ref(name: &str, hosts: &[&str], service: &str, region: &str) -> SecretRef {
    use mvm_contract::ir::Sigv4Params;
    SecretRef {
        name: name.into(),
        mount: SecretMount::Env { var: "K".into() },
        auth_type: AuthType::Sigv4,
        allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
        sigv4: Some(Sigv4Params {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            region: region.into(),
            service: service.into(),
        }),
    }
}

pub(super) fn sigv4_ref_no_params(name: &str, hosts: &[&str]) -> SecretRef {
    SecretRef {
        name: name.into(),
        mount: SecretMount::Env { var: "K".into() },
        auth_type: AuthType::Sigv4,
        allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
        sigv4: None,
    }
}

pub(super) fn hmac_ref(name: &str, hosts: &[&str]) -> SecretRef {
    SecretRef {
        name: name.into(),
        mount: SecretMount::Env { var: "K".into() },
        auth_type: AuthType::Hmac,
        allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
        sigv4: None,
    }
}

/// Records the request it was handed so a test can prove the destination
/// (not the guest) received the real credential — without a network call.
pub(super) struct MockForwarder {
    pub(super) seen: Mutex<Option<PreparedRequest>>,
}

pub(super) struct RedirectForwarder {
    pub(super) calls: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl Forwarder for MockForwarder {
    async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
        *self.seen.lock().unwrap() = Some(req);
        Ok(ForwardResponse {
            status: 200,
            headers: vec![("x-mock".into(), "1".into())],
            body: b"pong".to_vec(),
        })
    }
}

#[async_trait]
impl Forwarder for RedirectForwarder {
    async fn forward(&self, _req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(ForwardResponse {
            status: 302,
            headers: vec![("location".into(), "https://unbound.example/steal".into())],
            body: Vec::new(),
        })
    }
}

/// Build a service over a file store seeded with `openai`=value, a registry
/// holding one minted placeholder for `hosts`, and a `MockForwarder`.
/// Returns the service, the minted placeholder string, and the forwarder.
pub(super) fn service_with(
    value: &str,
    hosts: &[&str],
) -> (
    Arc<SubstitutionService>,
    String,
    Arc<MockForwarder>,
    tempfile::TempDir,
) {
    service_with_policies(value, hosts, None, None)
}

pub(super) fn service_with_policies(
    value: &str,
    hosts: &[&str],
    redaction_policy: Option<mvm_core::policy::RedactionPolicy>,
    reversible_policy: Option<mvm_core::policy::ReversibleReplacementPolicy>,
) -> (
    Arc<SubstitutionService>,
    String,
    Arc<MockForwarder>,
    tempfile::TempDir,
) {
    let dir = tempdir().unwrap();
    let store = FileSecretStore::with_dir(dir.path());
    store
        .put(
            "local",
            "openai",
            &SecretBox::new(Box::new(value.to_string())),
        )
        .unwrap();
    let resolver: Arc<dyn SecretResolver> = Arc::new(LocalResolver::new("local", Arc::new(store)));
    let mut reg = SubstitutionRegistry::new();
    let ph = reg.mint(bearer_ref("openai", hosts)).as_str().to_string();
    let forwarder = Arc::new(MockForwarder {
        seen: Mutex::new(None),
    });
    let mut service = SubstitutionService::new(Arc::new(reg), resolver, forwarder.clone());
    if let Some(policy) = redaction_policy {
        service = service.with_redaction_policy(policy);
    }
    if let Some(policy) = reversible_policy {
        service = service.with_reversible_replacement_policy(policy);
    }
    (Arc::new(service), ph, forwarder, dir)
}
