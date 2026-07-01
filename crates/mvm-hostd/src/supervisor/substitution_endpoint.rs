//! The per-VM substitution endpoint subprocess.
//!
//! The substitution endpoint is the one host process that ever holds a
//! workload's secrets in the clear. It is spawned per-VM as its own process
//! (a moat, sibling to `mvm-broker` / `mvm-host-signer`): the backend hands it
//! the workload's secret bindings on stdin, it opens the host's encrypted
//! secret + binding stores, builds a `SubstitutionService`, and serves the
//! guest→host substitution channel. Raw secrets exist only in this process's
//! address space and reach the wire via the egress substitution — never the
//! guest (which only ever holds the opaque `mvm-secret-<hex>` placeholder).
//!
//! This module is the bin's library half: the stdin config contract
//! (`EndpointConfig`) and `assemble` (open stores + build the service).
//! The `mvm-substitution-endpoint` bin is the thin process wrapper that parses
//! the config, reports the minted placeholders, and runs the serve loop.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;

use serde::{Deserialize, Serialize};

use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore, default_secrets_dir};
use mvm_core::plan::SecretBinding;

use crate::keyholder::{FileBindingStore, HandedPlaceholders};
use crate::supervisor::substitution_proxy::SubstitutionService;

/// Default forward-leg timeout (host → real destination) in seconds.
fn default_forward_timeout_secs() -> u64 {
    30
}

/// Resolve a network policy's host-allowlist entries to IPs (the admission-time
/// DNS pin) so `host:port` rules gate at L4. Literal IPs need no lookup; an
/// unresolvable host pins an empty IP set so the projection fails CLOSED (deny)
/// rather than widening.
fn resolve_dns_pins(
    np: &mvm_core::policy::network_policy::NetworkPolicy,
) -> mvm_core::policy::dns_pin::DnsPinRegistry {
    use std::net::{IpAddr, ToSocketAddrs};
    let mut reg = mvm_core::policy::dns_pin::DnsPinRegistry::new();
    let Some(rules) = np.resolve_rules() else {
        return reg; // unrestricted: no L4 pin set
    };
    for hp in rules {
        let ips: Vec<IpAddr> = if let Ok(ip) = hp.host.parse::<IpAddr>() {
            vec![ip]
        } else {
            (hp.host.as_str(), 0u16)
                .to_socket_addrs()
                .map(|addrs| addrs.map(|sa| sa.ip()).collect())
                .unwrap_or_default()
        };
        reg.add(mvm_core::policy::dns_pin::DnsPin::new(
            hp.host,
            ips,
            chrono::Duration::hours(24),
        ));
    }
    reg
}

/// Build the claim-10 egress gate for a resolved network policy: resolve the
/// host-allowlist DNS pins once (fails closed on an unresolvable host), then
/// project through the shared claim-10 gate every backend agrees on. The
/// WireRequest `assemble` and the raw-egress bin both go through here so the two
/// serve paths gate on byte-identical decisions.
pub fn build_egress_gate(
    policy: &mvm_core::policy::network_policy::NetworkPolicy,
) -> mvm_backend::vmm::egress_gate::EgressGate {
    let pins = resolve_dns_pins(policy);
    let now = chrono::Utc::now().to_rfc3339();
    mvm_backend::vmm::egress_gate::EgressGate::from_network_policy(policy, &pins, &now)
}

/// How the guest reaches this endpoint. Defined in `mvm-backend` (next to the
/// `spawn_substitution_endpoint` writer) and re-exported here so the bin, its
/// tests, and `EndpointConfig` share one wire definition without a dependency
/// cycle (mvm-hostd → mvm-backend, never the reverse).
pub use mvm_backend::EndpointTransport;

/// Which egress protocol the guest speaks on the relayed EGRESS_PORT stream.
/// A VM uses exactly one, fixed at admission (secrets ⇒ WireRequest, else raw),
/// so the endpoint is told the mode rather than sniffing untrusted guest bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    /// Framed WireRequest substitution (claims 12/13) — the default, secret-bearing path.
    #[default]
    Wire,
    /// Raw TCP: first line `host:port`, then a byte splice. No secrets.
    Raw,
}

/// The per-VM name-constrained intermediate the terminator
/// terminates bound-host TLS under. The guest trusts the matching cert (delivered
/// via its secrets drive); the key stays here, in the endpoint process, used only
/// to mint per-SNI leaves during termination. `cert_pem` is also the guest's
/// trust anchor, so it's not secret; `key_pem` is — hence the redacted `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsIntermediate {
    /// The intermediate cert PEM (== the cert the guest trusts).
    pub cert_pem: String,
    /// The intermediate private key PEM — never leaves this process.
    pub key_pem: String,
}

impl std::fmt::Debug for TlsIntermediate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsIntermediate")
            .field("cert_pem", &"<intermediate cert>")
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

/// Config the backend hands the `mvm-substitution-endpoint` subprocess on
/// stdin at spawn. Carries the workload's secret bindings (NOT values — the
/// endpoint resolves values itself from the host store) plus where to listen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Per-destination egress redaction policy, carried from the signed
    /// `ExecutionPlan.redaction`. Default (all-off) preserves the curated-only
    /// baseline; a profile opts a destination into entropy/name redaction.
    #[serde(default)]
    pub redaction: mvm_core::policy::RedactionPolicy,
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
    /// on this host address. The nft `nat` chain REDIRECTs
    /// the guest's outbound TCP here; the endpoint recovers the original
    /// destination, substitutes secrets, and splices to the real host. Linux-
    /// only. `None` (the default) preserves the substitution-channel-only
    /// behaviour — no terminator, no nft redirect.
    #[serde(default)]
    pub terminator_listen: Option<std::net::SocketAddr>,
    /// The per-VM egress intermediate (cert+key) the
    /// transparent `https` terminator terminates bound-host TLS under.
    /// `None` ⇒ `http`-only termination / no TLS leg. Set alongside
    /// `terminator_listen` when the plan has secrets and the backend delivered
    /// the matching cert to the guest's trust bundle.
    #[serde(default)]
    pub tls_intermediate: Option<TlsIntermediate>,
    /// The VM's resolved network policy for claim-10 egress. When set, the endpoint
    /// gates every destination itself (the run loop relays without gating); absent ⇒
    /// the endpoint does not gate (the legacy in-loop gate is still active). Fail
    /// closed when set: an unadmitted destination is refused before any forward.
    #[serde(default)]
    pub network_policy: Option<mvm_core::policy::network_policy::NetworkPolicy>,
    /// Which egress protocol the relayed guest stream carries. `Wire` (default,
    /// secret-bearing) keeps the existing WireRequest substitution serve loop; `Raw`
    /// selects the raw-TCP splice serve loop. Fixed at admission — never sniffed.
    #[serde(default)]
    pub egress_mode: EgressMode,
}

/// Parse an [`EndpointConfig`] from the JSON the backend writes on stdin.
pub fn parse(bytes: &[u8]) -> Result<EndpointConfig, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Resolve the effective `(secret store dir, binding store dir)` for a config,
/// applying the same override-or-default rule [`assemble`] uses. The bin reuses
/// this to build the Landlock confinement spec, so the dirs it grants read on
/// are exactly the dirs the resolver opens per request — no drift between the
/// confinement policy and the runtime behaviour.
pub fn resolve_store_dirs(cfg: &EndpointConfig) -> anyhow::Result<(PathBuf, PathBuf)> {
    let secret_dir = match &cfg.secret_store_dir {
        Some(dir) => dir.clone(),
        None => default_secrets_dir()?,
    };
    let binding_dir = match &cfg.binding_store_dir {
        Some(dir) => dir.clone(),
        None => mvm_core::config::mvm_data_dir_strict()?.join("secret-bindings"),
    };
    Ok((secret_dir, binding_dir))
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
    // Reconstruct the per-VM intermediate minter from the delivered PEMs (the
    // key never left the host) so the terminator can terminate bound-host
    // `https`. Absent ⇒ `http`-only.
    let tls_intermediate = match &cfg.tls_intermediate {
        Some(ti) => Some(
            mvm_core::crypto::egress_ca::VmIntermediate::from_pem(&ti.cert_pem, &ti.key_pem)
                .context("reconstruct per-VM egress intermediate from EndpointConfig")?,
        ),
        None => None,
    };

    // Chain-signed substitution audit. Best-effort: if the host signer key
    // exists at the standard location, attach a Recorder so a live substituting
    // invoke leaves `secret.substituted` / `secret.redacted` entries (metadata
    // only) in the per-tenant audit log; absent ⇒ the endpoint serves without
    // audit rather than refusing (the same optional posture `with_recorder` had).
    let recorder = build_audit_recorder(&cfg.tenant_id);

    let (service, handed) =
        SubstitutionService::from_plan(crate::supervisor::substitution_proxy::FromPlanInputs {
            plan_secrets: &cfg.secrets,
            tenant: &cfg.tenant_id,
            bindings: &bindings,
            secret_store,
            forward_timeout_secs: cfg.forward_timeout_secs,
            redaction: cfg.redaction.clone(),
            tls_intermediate,
            recorder,
        })?;

    // Claim-10: when the backend threaded the VM's resolved network policy, this
    // endpoint becomes the egress gate. Resolve host-allowlist pins once (fails
    // closed on an unresolvable host), build the gate over the same claim-10
    // projection every backend shares, and attach it. Absent ⇒ no gate here.
    let service = match &cfg.network_policy {
        Some(policy) => {
            let gate = build_egress_gate(policy);
            // from_plan just minted this Arc with no other holders, so the unwrap
            // is infallible; attach the gate, then re-wrap.
            let svc = Arc::try_unwrap(service)
                .map_err(|_| anyhow::anyhow!("substitution service Arc unexpectedly shared"))?
                .with_egress_gate(gate);
            Arc::new(svc)
        }
        None => service,
    };

    Ok((service, handed))
}

/// Build a chain-signed audit [`Recorder`] from the standard host paths
/// (`<keys>/host-signer.ed25519` + `<audit>/`), or `None` if the signer key
/// isn't present (the endpoint then serves un-audited, matching the prior
/// optional-recorder posture). The audit dir + the key are inside the
/// endpoint's Landlock grants (see `ConfinementSpec::substitution_endpoint`).
fn build_audit_recorder(tenant: &str) -> Option<crate::supervisor::audit_recorder::Recorder> {
    use crate::supervisor::audit_file::FileAuditSigner;
    use crate::supervisor::audit_recorder::Recorder;
    use ed25519_dalek::SigningKey;
    use mvm_core::plan::TenantId;

    let key_path = mvm_core::config::mvm_keys_dir().join("host-signer.ed25519");
    let bytes = std::fs::read(&key_path).ok()?;
    let key_array: [u8; 32] = bytes.as_slice().try_into().ok()?;
    let signing_key = SigningKey::from_bytes(&key_array);
    let signer = FileAuditSigner::open(signing_key, mvm_core::config::mvm_audit_dir()).ok()?;
    Some(Recorder::new(
        std::sync::Arc::new(signer),
        TenantId(tenant.to_string()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyholder::{BindingStore, SecretBindingMeta};
    use mvm_core::plan::SecretSource;
    use mvm_core::util::test_env::TestEnv;
    use mvm_sdk::ir::AuthType;
    use secrecy::SecretBox;
    use tempfile::tempdir;

    #[test]
    fn build_audit_recorder_attaches_when_signer_key_present() {
        // No host signer key under a fresh data dir → no recorder (best-effort).
        let dir = tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_DATA_DIR", dir.path());
        assert!(
            build_audit_recorder("local").is_none(),
            "no signer key ⇒ no recorder"
        );
        // Drop a 32-byte signer key at the standard location → recorder attaches.
        let keys = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join("host-signer.ed25519"), [7u8; 32]).unwrap();
        assert!(
            build_audit_recorder("local").is_some(),
            "signer key present ⇒ recorder attaches"
        );
    }

    fn vsock_cfg(secrets: Vec<SecretBinding>, dir: &std::path::Path) -> EndpointConfig {
        EndpointConfig {
            tenant_id: "local".into(),
            secrets,
            transport: EndpointTransport::Vsock { port: 5253 },
            redaction: mvm_core::policy::RedactionPolicy::default(),
            forward_timeout_secs: 30,
            secret_store_dir: Some(dir.join("secrets")),
            binding_store_dir: Some(dir.join("bindings")),
            terminator_listen: None,
            tls_intermediate: None,
            network_policy: None,
            egress_mode: EgressMode::Wire,
        }
    }

    #[test]
    fn resolve_store_dirs_uses_overrides_when_set() {
        let cfg = vsock_cfg(vec![], std::path::Path::new("/tmp/x"));
        let (secret, binding) = resolve_store_dirs(&cfg).unwrap();
        assert_eq!(secret, std::path::Path::new("/tmp/x/secrets"));
        assert_eq!(binding, std::path::Path::new("/tmp/x/bindings"));
    }

    #[test]
    fn resolve_store_dirs_falls_back_to_default_store_layout() {
        // With overrides cleared, the resolver must land on the default
        // `~/.mvm` store layout (the dirs the confinement spec grants read on).
        // Assert the trailing components rather than the absolute base so the
        // test stays independent of the host's MVM_DATA_DIR / HOME (no env
        // mutation → no race with parallel readers).
        let mut cfg = vsock_cfg(vec![], std::path::Path::new("/tmp/x"));
        cfg.secret_store_dir = None;
        cfg.binding_store_dir = None;
        let (secret, binding) = resolve_store_dirs(&cfg).unwrap();
        assert_eq!(secret.file_name().unwrap(), "secrets");
        assert_eq!(binding.file_name().unwrap(), "secret-bindings");
        // Both resolve under the same data-dir base.
        assert_eq!(secret.parent(), binding.parent());
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
    fn config_defaults_tls_intermediate_to_none() {
        // Configs without `tls_intermediate` must still parse — the field
        // is `#[serde(default)]`, so http-only termination keeps working.
        let json = serde_json::json!({
            "tenant_id": "local",
            "secrets": [],
            "transport": {"kind": "uds", "path": "/tmp/sub.sock"},
        });
        let cfg = parse(&serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(cfg.tls_intermediate.is_none());
    }

    #[test]
    fn config_defaults_redaction_to_all_off_when_omitted() {
        // A config without a `redaction` block parses (field is
        // `#[serde(default)]`) and defaults to the curated-only baseline.
        let json = serde_json::json!({
            "tenant_id": "local",
            "secrets": [],
            "transport": {"kind": "uds", "path": "/tmp/sub.sock"},
        });
        let cfg = parse(&serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(cfg.redaction, mvm_core::policy::RedactionPolicy::default());
    }

    #[test]
    fn config_redaction_block_roundtrips_and_reaches_the_service() {
        use mvm_core::policy::{EntropyMode, RedactionAction, RedactionProfile};

        let dir = tempdir().unwrap();
        FileBindingStore::with_dir(dir.path().join("bindings"))
            .put(
                "local",
                "openai",
                &SecretBindingMeta {
                    auth_type: AuthType::Bearer,
                    allowed_hosts: vec!["api.openai.com".into()],
                    sigv4: None,
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

        let mut cfg = vsock_cfg(
            vec![SecretBinding {
                name: "OPENAI_API_KEY".into(),
                source: SecretSource::Keystore {
                    address: "openai".into(),
                },
            }],
            dir.path(),
        );
        cfg.redaction.profiles.push(RedactionProfile {
            host: "api.openai.com".into(),
            action: RedactionAction {
                entropy: EntropyMode::Redact {
                    min_bits_per_char: 4.0,
                    min_run_len: 20,
                },
                ..Default::default()
            },
        });

        // The block survives serde (the wire form the backend writes on stdin).
        let bytes = serde_json::to_vec(&cfg).unwrap();
        assert_eq!(parse(&bytes).unwrap(), cfg);

        // And the assembled service carries it: the entropy opt-in for the bound
        // host actually fires on an entropic token (the default would not).
        let (service, _handed) = assemble(&cfg).unwrap();
        let token = "Xa9Kf2pQ7vL0mZ3rT8wB1nC4yH6dJ5sG2eU0iO9";
        let body = format!("k={token} e").into_bytes();
        let action = crate::supervisor::redaction_resolve::resolve(
            // SAFETY: assemble built the service from cfg.redaction; we re-resolve
            // the same policy here to assert the opt-in took effect end-to-end.
            &cfg.redaction,
            "api.openai.com",
        );
        let out = service_redact(&service, &body, action);
        assert!(
            !String::from_utf8_lossy(&out).contains(token),
            "entropy opt-in from EndpointConfig.redaction did not fire"
        );
    }

    /// Drive the service's redactor for a destination action — small helper so the
    /// roundtrip test asserts the policy *fires*, not just that it round-trips.
    fn service_redact(
        service: &SubstitutionService,
        body: &[u8],
        action: &mvm_core::policy::RedactionAction,
    ) -> Vec<u8> {
        service
            .redactor_redact_bytes_for(body, action)
            .map(|(out, _)| out)
            .unwrap_or_else(|| body.to_vec())
    }

    #[test]
    fn config_roundtrips_network_policy_when_set() {
        // The claim-10 policy the backend threads must survive the stdin wire
        // form untouched, so the endpoint gates on exactly what was admitted.
        let mut cfg = vsock_cfg(vec![], std::path::Path::new("/tmp/x"));
        cfg.network_policy = Some(mvm_core::policy::network_policy::NetworkPolicy::deny_all());
        let bytes = serde_json::to_vec(&cfg).unwrap();
        assert_eq!(parse(&bytes).unwrap(), cfg);
        assert!(parse(&bytes).unwrap().network_policy.is_some());
    }

    #[test]
    fn config_defaults_network_policy_to_none() {
        // A config without a `network_policy` block parses (field is
        // `#[serde(default)]`) — the endpoint then does not gate.
        let json = serde_json::json!({
            "tenant_id": "local",
            "secrets": [],
            "transport": {"kind": "uds", "path": "/tmp/sub.sock"},
        });
        let cfg = parse(&serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(cfg.network_policy.is_none());
    }

    #[test]
    fn config_roundtrips_egress_mode_raw() {
        // The raw-egress mode selection must survive the stdin wire form so the
        // bin picks the raw splice loop for exactly the VMs admitted without secrets.
        let mut cfg = vsock_cfg(vec![], std::path::Path::new("/tmp/x"));
        cfg.egress_mode = EgressMode::Raw;
        let bytes = serde_json::to_vec(&cfg).unwrap();
        assert_eq!(parse(&bytes).unwrap(), cfg);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["egress_mode"], serde_json::json!("raw"));
    }

    #[test]
    fn config_defaults_egress_mode_to_wire() {
        // A config without `egress_mode` parses (field is `#[serde(default)]`) and
        // defaults to the secret-bearing WireRequest path — byte-identical to before.
        let json = serde_json::json!({
            "tenant_id": "local",
            "secrets": [],
            "transport": {"kind": "uds", "path": "/tmp/sub.sock"},
        });
        let cfg = parse(&serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(cfg.egress_mode, EgressMode::Wire);
    }

    #[test]
    fn config_roundtrips_tls_intermediate_when_set() {
        let mut cfg = vsock_cfg(vec![], std::path::Path::new("/tmp/x"));
        cfg.tls_intermediate = Some(TlsIntermediate {
            cert_pem: "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nxyz\n-----END PRIVATE KEY-----\n".into(),
        });
        let bytes = serde_json::to_vec(&cfg).unwrap();
        assert_eq!(parse(&bytes).unwrap(), cfg);
    }

    #[test]
    fn tls_intermediate_debug_redacts_key() {
        // The endpoint config's Debug must never print the intermediate key.
        let cfg = EndpointConfig {
            tls_intermediate: Some(TlsIntermediate {
                cert_pem: "CERT".into(),
                key_pem: "-----BEGIN PRIVATE KEY-----SUPERSECRET".into(),
            }),
            ..vsock_cfg(vec![], std::path::Path::new("/tmp/x"))
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("SUPERSECRET"), "key leaked via Debug: {dbg}");
        assert!(dbg.contains("<redacted>"));
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
                    sigv4: None,
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
