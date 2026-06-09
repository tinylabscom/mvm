//! Plan 129 / ADR-067 — the per-VM substitution endpoint subprocess.
//!
//! The substitution endpoint is the one host process that ever holds a
//! workload's secrets in the clear. It is spawned per-VM as its own process
//! (a moat, sibling to `mvm-broker` / `mvm-host-signer`): the backend hands it
//! the workload's secret bindings on stdin, it opens the host's encrypted
//! secret + binding stores, builds a [`SubstitutionService`], and serves the
//! guest→host substitution channel. Raw secrets exist only in this process's
//! address space and reach the wire via the egress substitution — never the
//! guest (which only ever holds the opaque `mvm-secret-<hex>` placeholder).
//!
//! This module is the bin's library half: the stdin config contract
//! ([`EndpointConfig`]) and [`assemble`] (open stores + build the service).
//! The `mvm-substitution-endpoint` bin is the thin process wrapper that parses
//! the config, reports the minted placeholders, and runs the serve loop.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore, default_secrets_dir};
use mvm_core::plan::SecretBinding;

use crate::keyholder::{FileBindingStore, HandedPlaceholders};
use crate::supervisor::substitution_proxy::SubstitutionService;

/// Default forward-leg timeout (host → real destination) in seconds.
fn default_forward_timeout_secs() -> u64 {
    30
}

/// How the guest reaches this endpoint. Backend-shaped: QEMU's `vhost-vsock`
/// gives a real guest→host AF_VSOCK path, so the host binds an AF_VSOCK
/// listener; Firecracker/libkrun route guest→host through a per-port UDS the
/// in-process VMM proxies, so the host binds that UDS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EndpointTransport {
    /// Host AF_VSOCK listener on this port (QEMU). The guest dials
    /// `connect_host_vsock(SUBSTITUTION_PORT)`.
    Vsock { port: u32 },
    /// Host UDS the per-port vsock proxy forwards to (Firecracker/libkrun).
    Uds { path: PathBuf },
}

/// Config the backend hands the `mvm-substitution-endpoint` subprocess on
/// stdin at spawn. Carries the workload's secret bindings (NOT values — the
/// endpoint resolves values itself from the host store) plus where to listen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointConfig {
    /// Tenant the workload belongs to — the store lookup key.
    pub tenant_id: String,
    /// The admitted plan's `secrets` (name → source). Only
    /// [`mvm_core::plan::SecretSource::Keystore`] entries participate; the
    /// endpoint reconstructs each one's binding from the host binding store.
    pub secrets: Vec<SecretBinding>,
    /// The guest→host transport to listen on.
    pub transport: EndpointTransport,
    /// Forward-leg (host → destination) timeout, seconds.
    #[serde(default = "default_forward_timeout_secs")]
    pub forward_timeout_secs: u64,
    /// Override the value-store base dir. Default: the host's
    /// `~/.mvm/secrets` (honors `MVM_DATA_DIR`).
    #[serde(default)]
    pub secret_store_dir: Option<PathBuf>,
    /// Override the binding-store base dir. Default: `~/.mvm/secret-bindings`.
    #[serde(default)]
    pub binding_store_dir: Option<PathBuf>,
    /// When set, also bind the transparent egress **terminator** TCP listener
    /// (Plan 129 stage 1b) on this host address. The nft `nat` chain REDIRECTs
    /// the guest's outbound TCP here; the endpoint recovers the original
    /// destination, substitutes secrets, and splices to the real host. Linux-
    /// only. `None` (the default) preserves the substitution-channel-only
    /// behaviour — no terminator, no nft redirect.
    #[serde(default)]
    pub terminator_listen: Option<std::net::SocketAddr>,
}

/// Parse an [`EndpointConfig`] from the JSON the backend writes on stdin.
pub fn parse(bytes: &[u8]) -> Result<EndpointConfig, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Open the host's secret + binding stores and build the per-VM
/// [`SubstitutionService`] from the config's bindings. Returns the service
/// plus the `(guest var, placeholder)` pairs the backend hands the guest as
/// launch env (never the values).
///
/// The stores are the same ones `mvmctl secret put` (values) and `mvmctl
/// secret set` (bindings) populate; the endpoint runs as the same host user
/// and opens them by path.
pub fn assemble(
    cfg: &EndpointConfig,
) -> anyhow::Result<(Arc<SubstitutionService>, HandedPlaceholders)> {
    let secret_store: Arc<dyn SecretStore> = Arc::new(match &cfg.secret_store_dir {
        Some(dir) => FileSecretStore::with_dir(dir),
        None => FileSecretStore::with_dir(default_secrets_dir()?),
    });
    let bindings = match &cfg.binding_store_dir {
        Some(dir) => FileBindingStore::with_dir(dir),
        None => FileBindingStore::default_location()?,
    };
    let (service, handed) = SubstitutionService::from_plan(
        &cfg.secrets,
        &cfg.tenant_id,
        &bindings,
        secret_store,
        cfg.forward_timeout_secs,
    )?;
    Ok((service, handed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyholder::{BindingStore, SecretBindingMeta};
    use mvm_core::plan::SecretSource;
    use mvm_sdk::ir::AuthType;
    use secrecy::SecretBox;
    use tempfile::tempdir;

    fn vsock_cfg(secrets: Vec<SecretBinding>, dir: &std::path::Path) -> EndpointConfig {
        EndpointConfig {
            tenant_id: "local".into(),
            secrets,
            transport: EndpointTransport::Vsock { port: 5253 },
            forward_timeout_secs: 30,
            secret_store_dir: Some(dir.join("secrets")),
            binding_store_dir: Some(dir.join("bindings")),
            terminator_listen: None,
        }
    }

    #[test]
    fn config_roundtrips_and_rejects_unknown_fields() {
        let cfg = vsock_cfg(
            vec![SecretBinding {
                name: "OPENAI_API_KEY".into(),
                source: SecretSource::Keystore {
                    address: "openai".into(),
                },
            }],
            std::path::Path::new("/tmp/x"),
        );
        let bytes = serde_json::to_vec(&cfg).unwrap();
        assert_eq!(parse(&bytes).unwrap(), cfg);

        let mut bad: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        bad.as_object_mut()
            .unwrap()
            .insert("smuggled".into(), serde_json::json!("x"));
        let err = parse(&serde_json::to_vec(&bad).unwrap()).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "got {err}");
    }

    #[test]
    fn config_defaults_when_optionals_omitted() {
        let json = serde_json::json!({
            "tenant_id": "local",
            "secrets": [],
            "transport": {"kind": "uds", "path": "/tmp/sub.sock"},
        });
        let cfg = parse(&serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(cfg.forward_timeout_secs, 30);
        assert!(cfg.secret_store_dir.is_none() && cfg.binding_store_dir.is_none());
        // Default: no terminator listener → substitution-channel-only behaviour.
        assert!(cfg.terminator_listen.is_none());
        assert_eq!(
            cfg.transport,
            EndpointTransport::Uds {
                path: "/tmp/sub.sock".into()
            }
        );
    }

    #[test]
    fn config_roundtrips_terminator_listen_when_set() {
        let mut cfg = vsock_cfg(vec![], std::path::Path::new("/tmp/x"));
        cfg.terminator_listen = Some("127.0.0.1:9119".parse().unwrap());
        let bytes = serde_json::to_vec(&cfg).unwrap();
        assert_eq!(parse(&bytes).unwrap(), cfg);
        // SocketAddr serializes as a plain string in the JSON.
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["terminator_listen"], serde_json::json!("127.0.0.1:9119"));
    }

    #[test]
    fn assemble_builds_service_and_hands_placeholder() {
        let dir = tempdir().unwrap();
        FileBindingStore::with_dir(dir.path().join("bindings"))
            .put(
                "local",
                "openai",
                &SecretBindingMeta {
                    auth_type: AuthType::Bearer,
                    allowed_hosts: vec!["api.openai.com".into()],
                },
            )
            .unwrap();
        FileSecretStore::with_dir(dir.path().join("secrets"))
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new("sk-live".to_string())),
            )
            .unwrap();

        let cfg = vsock_cfg(
            vec![SecretBinding {
                name: "OPENAI_API_KEY".into(),
                source: SecretSource::Keystore {
                    address: "openai".into(),
                },
            }],
            dir.path(),
        );
        let (_service, handed) = assemble(&cfg).unwrap();
        assert_eq!(handed.len(), 1);
        assert_eq!(handed[0].0, "OPENAI_API_KEY");
        assert!(handed[0].1.as_str().starts_with("mvm-secret-"));
    }
}
