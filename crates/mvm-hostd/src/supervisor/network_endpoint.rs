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
//! The `mvm-network-endpoint` bin is the thin process wrapper that parses
//! the config, reports the minted placeholders, and runs the serve loop.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;

use serde::{Deserialize, Serialize};

use mvm_contract::stream::secret_fingerprint::{SecretCategory, SecretFingerprint};
use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore, default_secrets_dir};
use mvm_core::plan::SecretBinding;

use crate::keyholder::{
    FileBindingStore, HandedPlaceholders, LocalResolver, RemoteResolver, SecretResolver,
};
use crate::supervisor::network_endpoint_proxy::SubstitutionService;

/// The endpoint's ready-handshake line. Defined next to
/// [`spawn_network_endpoint`](mvm_runtime::spawn_network_endpoint)'s
/// reader and re-exported here so the bin, its tests and the spawner share one
/// wire definition without a dependency cycle.
pub use mvm_vmm::host::network_endpoint_spawn::EndpointHandshake;

/// Default forward-leg timeout (host → real destination) in seconds.
fn default_forward_timeout_secs() -> u64 {
    30
}

/// Build the claim-10 egress gate for a resolved network policy: resolve the
/// host-allowlist DNS pins once (fails closed on an unresolvable host), then
/// project through the shared claim-10 gate every backend agrees on. The
/// WireRequest `assemble` and the raw-egress bin both go through here so the two
/// serve paths gate on byte-identical decisions.
pub fn build_egress_gate(
    policy: &mvm_core::policy::network_policy::NetworkPolicy,
) -> mvm_runtime::vmm::egress_gate::EgressGate {
    let pins = mvm_core::policy::dns_pin::resolve_network_policy_pins(policy);
    let now = chrono::Utc::now().to_rfc3339();
    mvm_runtime::vmm::egress_gate::EgressGate::from_network_policy(policy, &pins, &now)
}

/// Default remote-resolver round-trip timeout (connect + one request/response
/// over the UDS to the fleet-secrets daemon), in seconds.
fn default_resolve_timeout_secs() -> u64 {
    5
}

/// How `assemble` resolves a bound secret's raw value at request time: on this
/// host's local encrypted secret store (`Local`, the default — the unchanged
/// `mvmctl secret set` flow), or from a remote fleet-secrets daemon over a
/// Unix domain socket (`Remote` — mvmd's tenant vault; see
/// [`crate::keyholder::RemoteResolver`]).
///
/// The registry (which placeholders exist, their `allowed_hosts`/`auth_type`)
/// is always assembled from the local binding store regardless of backend —
/// only *value* resolution moves off-host in `Remote` mode.
///
/// `Local` is a unit variant — deliberately. `EndpointConfig::secret_store_dir`
/// is already the single source of truth for the local store dir (it also
/// drives [`resolve_store_dirs`]'s Landlock confinement grant); a second,
/// per-backend override here would let the two silently drift the moment
/// anyone set it, so there is exactly one place to look.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ResolverBackend {
    /// Resolve locally via [`FileSecretStore`] over
    /// `EndpointConfig::secret_store_dir` (falling back to the host default,
    /// `~/.mvm/secrets`, when unset) — today's exact resolution rule.
    #[default]
    Local,
    /// Resolve remotely over a Unix domain socket to a fleet-secrets daemon.
    Remote {
        /// Path to the daemon's UDS.
        uds_path: PathBuf,
        /// Round-trip timeout, seconds.
        #[serde(default = "default_resolve_timeout_secs")]
        timeout_secs: u64,
    },
}

/// How the guest reaches this endpoint. Defined in `mvm-backend` (next to the
/// `spawn_network_endpoint` writer) and re-exported here so the bin, its
/// tests, and `EndpointConfig` share one wire definition without a dependency
/// cycle (mvm-hostd → mvm-backend, never the reverse).
pub use mvm_vmm::host::network_endpoint_spawn::EndpointTransport;

/// Which egress protocol the guest speaks on the relayed EGRESS_PORT stream.
/// A VM uses exactly one, fixed at admission (secrets ⇒ WireRequest, else raw),
/// so the endpoint is told the mode rather than sniffing untrusted guest bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    /// Framed `WireRequest` substitution over an already-open stream.
    ///
    /// **Not a guest→host transport.** Its one remaining consumer is the wasm
    /// tier, whose `mvm:egress` host import runs on the host and connects to
    /// this endpoint's Unix socket — host-internal IPC between two host
    /// processes. No guest selects it or can speak it.
    #[default]
    Wire,
    /// Authenticated FlowMux session on `GuestService::NetworkFlow`. This is
    /// the converged single networking path, and the only one a guest speaks.
    ///
    /// `Raw` is gone: an unauthenticated `host:port` line followed by a byte
    /// splice, selected by nothing and speakable by no guest.
    FlowMux,
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

/// Identity material for one authenticated FlowMux session.
///
/// The host signing key authenticates the endpoint to the guest; the guest
/// verifying key is the pinned anchor the endpoint accepts. Both are carried
/// as base64 on the stdin wire so no raw bytes escape the spawn boundary in
/// shell-unsafe form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowMuxIdentity {
    /// Unique session identifier, distinct per VM boot.
    pub session_id: String,
    /// Base64-encoded 32-byte Ed25519 host signing key.
    pub host_signing_key_base64: String,
    /// Base64-encoded 32-byte Ed25519 guest verifying key.
    pub guest_verifying_key_base64: String,
}

/// Config the backend hands the `mvm-network-endpoint` subprocess on
/// stdin at spawn. Carries the workload's secret bindings (NOT values — the
/// endpoint resolves values itself from the host store) plus where to listen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointConfig {
    /// Tenant the workload belongs to — the store lookup key.
    pub tenant_id: String,
    /// VM instance identifier. Used to attribute AI egress metrics and audit
    /// records to this workload.
    #[serde(default)]
    pub instance_id: String,
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
    /// Per-destination reversible replacement policy, carried from the signed
    /// `ExecutionPlan.reversible_replacement`. Default (disabled) preserves the
    /// current one-way-only behavior.
    #[serde(default)]
    pub reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy,
    /// Forward-leg (host → destination) timeout, seconds.
    #[serde(default = "default_forward_timeout_secs")]
    pub forward_timeout_secs: u64,
    /// Upstream proxy for the forward leg, as the spawner resolved it from
    /// host configuration. Carried here rather than read from this process's
    /// environment because the endpoint self-confines before serving and is
    /// not the component that owns host configuration.
    ///
    /// Strings rather than a parsed type so the wire format stays inert; the
    /// endpoint parses and reports a bad value instead of silently dialling
    /// direct.
    #[serde(default)]
    pub proxy_https: Option<String>,
    #[serde(default)]
    pub proxy_http: Option<String>,
    #[serde(default)]
    pub no_proxy: Option<String>,
    /// Override the value-store base dir. Default: the host's
    /// `~/.mvm/secrets` (honors `MVM_HOME`).
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
    /// Transport-neutral resource ceilings from the admitted execution plan.
    /// Every FlowMux session for this VM draws from one shared owner of these
    /// limits; the default preserves endpoint configs written before the field
    /// existed.
    #[serde(default)]
    pub network_limits: mvm_core::plan::NetworkLimits,
    /// Exact signed ingress mappings this endpoint owns.
    #[serde(default)]
    pub ingress: Vec<mvm_core::plan::IngressMapping>,
    /// Which egress protocol the relayed guest stream carries. `Wire` (default,
    /// secret-bearing) keeps the existing WireRequest substitution serve loop; `Raw`
    /// selects the raw-TCP splice serve loop. Fixed at admission — never sniffed.
    #[serde(default)]
    pub egress_mode: EgressMode,
    /// Where to record that a guest completed an authenticated session.
    ///
    /// The endpoint binds and prints its handshake line before the guest has
    /// booted, so "ready" at that point means "the placeholders are minted",
    /// not "a guest reached me". This file is the second fact, written when
    /// the first session authenticates, so the launch can tell the difference
    /// between an endpoint that is serving and one that merely started.
    #[serde(default)]
    pub session_marker: Option<std::path::PathBuf>,
    /// Host-local event socket for the first authenticated session.
    ///
    /// The endpoint binds this before its process-ready handshake and wakes
    /// connected launchers after writing `session_marker`. It carries no
    /// identity or secret data; the marker remains the durable evidence.
    #[serde(default)]
    pub session_ready_socket: Option<std::path::PathBuf>,
    /// Host-local typed connector ingress. This listener is owned by the same
    /// endpoint process and uses the same signed policy projection, secret
    /// registry, redaction engine, audit sink, and hardened forwarder as guest
    /// `OpenHttp` flows. Absent on legacy endpoint configs.
    #[serde(default)]
    pub connector_uds_path: Option<std::path::PathBuf>,
    /// How to resolve a bound secret's raw value: this host's local encrypted
    /// store (default), or a remote fleet-secrets daemon over a UDS. See
    /// [`ResolverBackend`].
    #[serde(default)]
    pub resolver: ResolverBackend,
    /// Identity material for the authenticated FlowMux session. Required when
    /// `egress_mode` is `FlowMux`; ignored for `Wire` and `Raw`.
    #[serde(default)]
    pub flowmux_identity: Option<FlowMuxIdentity>,
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
        None => mvm_core::config::mvm_home_strict()?.join("secret-bindings"),
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
/// Endpoint-wide objects projected once from the admitted network fields.
///
/// FlowMux sessions, typed connectors, typed HTTP, ingress transforms, DNS,
/// TCP, and UDP all clone these `Arc`s. Equal reconstructed values are not
/// sufficient here: one object identity is what prevents policy or audit
/// configuration from drifting between surfaces.
#[derive(Clone)]
pub struct EndpointNetworkProjection {
    gate: Option<Arc<mvm_runtime::vmm::egress_gate::EgressGate>>,
    recorder: Option<Arc<crate::supervisor::audit_recorder::Recorder>>,
}

impl EndpointNetworkProjection {
    /// Project the endpoint's admitted policy and audit sink exactly once.
    #[must_use]
    pub fn from_config(cfg: &EndpointConfig) -> Self {
        let gate = cfg
            .network_policy
            .as_ref()
            .map(build_egress_gate)
            .map(Arc::new)
            .or_else(|| {
                (cfg.egress_mode == EgressMode::FlowMux)
                    .then(|| Arc::new(mvm_runtime::vmm::egress_gate::EgressGate::default_deny()))
            });
        Self {
            gate,
            recorder: build_audit_recorder(&cfg.tenant_id).map(Arc::new),
        }
    }

    /// The one claim-10 policy object used by all FlowMux surfaces.
    pub fn flowmux_gate(&self) -> anyhow::Result<Arc<mvm_runtime::vmm::egress_gate::EgressGate>> {
        self.gate
            .as_ref()
            .map(Arc::clone)
            .context("FlowMux endpoint projection has no egress gate")
    }

    /// The endpoint's one optional chain-signed audit sink.
    #[must_use]
    pub fn recorder(&self) -> Option<Arc<crate::supervisor::audit_recorder::Recorder>> {
        self.recorder.as_ref().map(Arc::clone)
    }
}

pub fn assemble(
    cfg: &EndpointConfig,
) -> anyhow::Result<(Arc<SubstitutionService>, HandedPlaceholders)> {
    let projection = EndpointNetworkProjection::from_config(cfg);
    assemble_with_projection(cfg, &projection)
}

/// Assemble the substitution/connector service over the endpoint's already
/// projected policy and audit objects.
pub fn assemble_with_projection(
    cfg: &EndpointConfig,
    projection: &EndpointNetworkProjection,
) -> anyhow::Result<(Arc<SubstitutionService>, HandedPlaceholders)> {
    let bindings = match &cfg.binding_store_dir {
        Some(dir) => FileBindingStore::with_dir(dir),
        None => FileBindingStore::default_location()?,
    };
    // Build the value resolver up front so `from_plan` builds the service
    // over it instead of its hardcoded `LocalResolver`. The registry (which
    // placeholders exist, their allowed_hosts/auth_type) is still assembled
    // inside `from_plan` from the same local binding store — only value
    // resolution moves off-host under `ResolverBackend::Remote`.
    let resolver: Arc<dyn SecretResolver> = match &cfg.resolver {
        ResolverBackend::Local => {
            // The single source of truth for the local store dir is
            // `cfg.secret_store_dir` — the same field `resolve_store_dirs`
            // uses to compute the Landlock confinement grant, so the two
            // can never drift.
            let secret_store: Arc<dyn SecretStore> = Arc::new(match &cfg.secret_store_dir {
                Some(dir) => FileSecretStore::with_dir(dir),
                None => FileSecretStore::with_dir(default_secrets_dir()?),
            });
            Arc::new(LocalResolver::new(&cfg.tenant_id, secret_store))
        }
        ResolverBackend::Remote {
            uds_path,
            timeout_secs,
        } => Arc::new(RemoteResolver::new(
            uds_path.clone(),
            Duration::from_secs(*timeout_secs),
        )),
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

    // Build the service over the resolver assembled above. `from_plan` builds
    // the registry (from the local binding store), the forwarder, and threads
    // the redaction / reversible-replacement / TLS / recorder wiring; passing
    // `resolver` in means it no longer hardcodes a `LocalResolver`, so a
    // `Remote` backend actually reaches its `RemoteResolver`.
    // Resolve the operator's proxy before building the service so a bad value
    // is reported here rather than as an unexplained egress failure later.
    let proxy = cfg.resolve_proxy()?;
    if let Some(p) = proxy.as_ref() {
        tracing::info!(proxy = %p.summary(), "forward leg routed through an upstream proxy");
    }

    let ai_policy = cfg
        .network_policy
        .as_ref()
        .and_then(|policy| policy.ai())
        .cloned();

    let (service, handed) = SubstitutionService::from_plan(
        crate::supervisor::network_endpoint_proxy::FromPlanInputs {
            plan_secrets: &cfg.secrets,
            tenant: &cfg.tenant_id,
            instance_id: &cfg.instance_id,
            bindings: &bindings,
            resolver,
            forward_timeout_secs: cfg.forward_timeout_secs,
            proxy,
            redaction: cfg.redaction.clone(),
            reversible_replacement: cfg.reversible_replacement.clone(),
            tls_intermediate,
            recorder: None,
            ai_policy,
        },
    )?;

    // `from_plan` just minted this Arc with no other holders. Attach both
    // endpoint-wide objects before exposing the service to connector, typed
    // HTTP, terminator, or ingress tasks.
    let mut service = Arc::try_unwrap(service)
        .map_err(|_| anyhow::anyhow!("substitution service Arc unexpectedly shared"))?;
    if let Some(gate) = projection.gate.as_ref() {
        service = service.with_shared_egress_gate(Arc::clone(gate));
    }
    if let Some(recorder) = projection.recorder.as_ref() {
        service = service.with_shared_recorder(Arc::clone(recorder));
    }

    Ok((Arc::new(service), handed))
}

/// Fingerprint every secret this endpoint can resolve, for the host→guest
/// input gate.
///
/// This is the one process that legitimately holds these values, which is why
/// the fingerprints are computed here and not where they are used. Only the
/// fingerprints leave — a length, a rolling hash and a category each — so the
/// process that scans a workload's stdin never has to hold a credential in
/// order to recognise one. What a fingerprint discloses is stated on
/// [`SecretFingerprint`].
///
/// Best effort per secret rather than fail-closed: a `SecretRef` with no value
/// in the store is a secret the workload has no way to receive either, so
/// there is nothing for the gate to recognise and nothing is weakened by
/// skipping it. A resolver failure is logged, not fatal — refusing to boot a
/// VM because one of its credentials is not set yet would be a new failure
/// mode introduced by a backstop.
pub fn fingerprint_bound_secrets(cfg: &EndpointConfig) -> anyhow::Result<Vec<SecretFingerprint>> {
    use crate::keyholder::{LocalResolver, SecretResolver, assemble_registry};
    use secrecy::ExposeSecret;

    let secret_store: Arc<dyn SecretStore> = Arc::new(match &cfg.secret_store_dir {
        Some(dir) => FileSecretStore::with_dir(dir),
        None => FileSecretStore::with_dir(default_secrets_dir()?),
    });
    let bindings = match &cfg.binding_store_dir {
        Some(dir) => FileBindingStore::with_dir(dir),
        None => FileBindingStore::default_location()?,
    };
    let (registry, handed) = assemble_registry(&cfg.secrets, &cfg.tenant_id, &bindings)
        .context("assembling the substitution registry to fingerprint its secrets")?;
    let resolver = LocalResolver::new(cfg.tenant_id.clone(), secret_store);

    let mut out = Vec::with_capacity(handed.len());
    for (_guest_var, placeholder) in &handed {
        let Some(secret_ref) = registry.resolve(placeholder.as_str()) else {
            continue;
        };
        match resolver.resolve(secret_ref) {
            // The exposed bytes are read once, hashed, and dropped with the
            // zeroizing box at the end of this iteration.
            Ok(value) => out.extend(SecretFingerprint::of(
                value.expose_secret().as_slice(),
                SecretCategory::HostSecret,
            )),
            Err(err) => tracing::warn!(
                secret = %secret_ref.name,
                error = %err,
                "secret not resolvable; the input gate will not recognise it"
            ),
        }
    }
    Ok(out)
}

/// Build a chain-signed audit [`Recorder`] from the standard host paths
/// (`<keys>/host-signer.ed25519` + `<audit>/`), or `None` if the signer key
/// isn't present (the endpoint then serves un-audited, matching the prior
/// optional-recorder posture). The audit dir + the key are inside the
/// endpoint's Landlock grants (see `ConfinementSpec::network_endpoint`).
pub fn build_audit_recorder(tenant: &str) -> Option<crate::supervisor::audit_recorder::Recorder> {
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

/// Refuse to boot a workload that will be handed placeholders nothing can
/// resolve.
///
/// A placeholder is minted per secret and injected into the guest's
/// environment. Substituting it back is the whole point: the guest holds
/// `mvm-secret-<hex>` and the host swaps in the real credential when it
/// originates the request. If the endpoint carries secrets but assembled no
/// substitution service, the guest gets the placeholder and sends *that* to a
/// real upstream.
///
/// Fails the launch rather than warning, because the failure is otherwise
/// silent and lands at a third party.
pub fn refuse_secrets_without_substitution(
    cfg: &EndpointConfig,
    assembled: bool,
) -> anyhow::Result<()> {
    if cfg.secrets.is_empty() || assembled {
        return Ok(());
    }
    anyhow::bail!(
        "endpoint carries {} secret(s) but assembled no substitution service: \
         the guest would be handed placeholders with nothing to resolve them",
        cfg.secrets.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyholder::{BindingStore, SecretBindingMeta};
    use mvm_contract::ir::AuthType;
    use mvm_contract::stream::secret_fingerprint::SecretCategory;
    use mvm_core::plan::SecretSource;
    use mvm_core::util::test_env::TestEnv;
    use secrecy::SecretBox;
    use tempfile::tempdir;

    #[test]
    fn build_audit_recorder_attaches_when_signer_key_present() {
        // No host signer key under a fresh data dir → no recorder (best-effort).
        let dir = tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", dir.path());
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

    #[test]
    fn connector_service_uses_the_exact_endpoint_policy_and_audit_objects() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("secrets")).unwrap();
        std::fs::create_dir_all(dir.path().join("bindings")).unwrap();
        let mut cfg = vsock_cfg(vec![], dir.path());
        cfg.egress_mode = EgressMode::FlowMux;
        cfg.network_policy = Some(mvm_core::policy::network_policy::NetworkPolicy::deny_all());

        let gate = Arc::new(mvm_runtime::vmm::egress_gate::EgressGate::default_deny());
        let recorder = Arc::new(crate::supervisor::audit_recorder::Recorder::new(
            Arc::new(crate::supervisor::audit::NoopAuditSigner),
            mvm_core::plan::TenantId("local".into()),
        ));
        let projection = EndpointNetworkProjection {
            gate: Some(Arc::clone(&gate)),
            recorder: Some(Arc::clone(&recorder)),
        };

        let (service, _) = assemble_with_projection(&cfg, &projection).unwrap();
        assert_eq!(
            service.shared_projection_ids(),
            (
                Some(Arc::as_ptr(&gate).cast::<()>() as usize),
                Some(Arc::as_ptr(&recorder).cast::<()>() as usize),
            )
        );
    }

    fn vsock_cfg(secrets: Vec<SecretBinding>, dir: &std::path::Path) -> EndpointConfig {
        EndpointConfig {
            tenant_id: "local".into(),
            instance_id: "test".into(),
            secrets,
            transport: EndpointTransport::Vsock { port: 5253 },
            redaction: mvm_core::policy::RedactionPolicy::default(),
            reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
            forward_timeout_secs: 30,
            proxy_https: None,
            proxy_http: None,
            no_proxy: None,
            secret_store_dir: Some(dir.join("secrets")),
            binding_store_dir: Some(dir.join("bindings")),
            terminator_listen: None,
            tls_intermediate: None,
            network_policy: None,
            network_limits: mvm_core::plan::NetworkLimits::default(),
            ingress: Vec::new(),
            egress_mode: EgressMode::Wire,
            resolver: ResolverBackend::default(),
            flowmux_identity: None,
            session_marker: None,
            session_ready_socket: None,
            connector_uds_path: None,
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
        // test stays independent of the host's MVM_HOME / HOME (no env
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
    fn legacy_config_defaults_network_limits() {
        let parsed = parse(
            br#"{"tenant_id":"t","secrets":[],"transport":{"kind":"uds","path":"/tmp/x.sock"}}"#,
        )
        .unwrap();
        assert_eq!(
            parsed.network_limits,
            mvm_core::plan::NetworkLimits::default()
        );
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
                    provider: None,
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
    fn the_endpoint_fingerprints_what_it_resolved_and_reports_no_value() {
        // Where the plaintext is, is where the fingerprint is computed. This
        // process opens the store; the process that scans a workload's stdin
        // gets a length, a hash and a category, and could not reconstruct the
        // credential from them.
        const SECRET: &str = "sk-live-abcdef0123456789";
        let dir = tempdir().unwrap();
        FileBindingStore::with_dir(dir.path().join("bindings"))
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
        FileSecretStore::with_dir(dir.path().join("secrets"))
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new(SECRET.to_string())),
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
        let fingerprints = fingerprint_bound_secrets(&cfg).unwrap();
        assert_eq!(fingerprints.len(), 1);
        assert_eq!(fingerprints[0].len(), SECRET.len());
        assert_eq!(fingerprints[0].category(), SecretCategory::HostSecret);
        assert!(
            fingerprints[0].matches_window(SECRET.as_bytes()),
            "the fingerprint has to recognise the value it came from, or the \
             gate is scanning for the wrong thing"
        );

        // The handshake this rides on carries no part of the credential.
        let wire = serde_json::to_string(&EndpointHandshake {
            env: Vec::new(),
            input_fingerprints: fingerprints,
        })
        .unwrap();
        assert!(!wire.contains(SECRET), "got {wire}");
        assert!(!wire.contains("sk-live"), "nor any part of it: {wire}");
    }

    #[test]
    fn a_secret_with_no_stored_value_is_skipped_rather_than_fatal() {
        // A credential the operator has bound but not set is one the workload
        // cannot receive either, so there is nothing for the gate to
        // recognise. Refusing to boot over it would be a new failure mode
        // introduced by a backstop.
        let dir = tempdir().unwrap();
        FileBindingStore::with_dir(dir.path().join("bindings"))
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

        let cfg = vsock_cfg(
            vec![SecretBinding {
                name: "OPENAI_API_KEY".into(),
                source: SecretSource::Keystore {
                    address: "openai".into(),
                },
            }],
            dir.path(),
        );
        assert!(fingerprint_bound_secrets(&cfg).unwrap().is_empty());
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
                    provider: None,
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

    #[test]
    fn resolver_backend_defaults_to_local_when_field_omitted() {
        // Back-compat: a config the backend wrote before `resolver` existed
        // (or one that simply omits it) must still parse and land on the
        // local-store behaviour existing `mvmctl secret set` flows rely on.
        let json = serde_json::json!({
            "tenant_id": "local",
            "secrets": [],
            "transport": {"kind": "uds", "path": "/tmp/sub.sock"},
        });
        let cfg = parse(&serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(cfg.resolver, ResolverBackend::Local);
    }

    #[test]
    fn resolver_backend_local_round_trips_as_unit_variant() {
        // `Local` carries no fields — `cfg.secret_store_dir` remains the sole
        // source of truth for the local store dir. Verify the wire shape is
        // just the tag, and that it round-trips through `ResolverBackend`
        // directly as well as inside a full `EndpointConfig`.
        let json = serde_json::json!({ "backend": "local" });
        assert_eq!(
            serde_json::from_value::<ResolverBackend>(json).unwrap(),
            ResolverBackend::Local
        );

        let mut cfg = vsock_cfg(vec![], std::path::Path::new("/tmp/x"));
        cfg.resolver = ResolverBackend::Local;
        let bytes = serde_json::to_vec(&cfg).unwrap();
        assert_eq!(parse(&bytes).unwrap(), cfg);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["resolver"], serde_json::json!({"backend": "local"}));
    }

    #[test]
    fn resolver_backend_remote_round_trips_through_endpoint_config() {
        let mut cfg = vsock_cfg(vec![], std::path::Path::new("/tmp/x"));
        cfg.resolver = ResolverBackend::Remote {
            uds_path: "/run/mvmd/tenant-a.sock".into(),
            timeout_secs: 9,
        };
        let bytes = serde_json::to_vec(&cfg).unwrap();
        assert_eq!(parse(&bytes).unwrap(), cfg);

        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["resolver"]["backend"], serde_json::json!("remote"));
        assert_eq!(
            v["resolver"]["uds_path"],
            serde_json::json!("/run/mvmd/tenant-a.sock")
        );
        assert_eq!(v["resolver"]["timeout_secs"], serde_json::json!(9));
    }

    #[test]
    fn resolver_backend_remote_timeout_defaults_when_omitted() {
        let json = serde_json::json!({
            "backend": "remote",
            "uds_path": "/run/mvmd/tenant-a.sock",
        });
        let backend: ResolverBackend = serde_json::from_value(json).unwrap();
        assert_eq!(
            backend,
            ResolverBackend::Remote {
                uds_path: "/run/mvmd/tenant-a.sock".into(),
                timeout_secs: 5,
            }
        );
    }

    #[test]
    fn resolver_backend_rejects_unknown_fields() {
        let json = serde_json::json!({
            "backend": "remote",
            "uds_path": "/run/mvmd/tenant-a.sock",
            "smuggled": "x",
        });
        let err = serde_json::from_value::<ResolverBackend>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "got {err}");
    }

    /// Spawn a throwaway UDS server standing in for mvmd's tenant vault:
    /// accepts one connection, reads one length-prefixed `ResolveWireRequest`,
    /// replies with `response` framed the same way. Mirrors
    /// `RemoteResolver`'s own test helper (M1) — kept local here rather than
    /// exported since it's a one-shot single-exchange stand-in, not a general
    /// test double.
    fn spawn_resolve_server(response: mvm_core::substitution_wire::ResolveWireResponse) -> PathBuf {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        let dir = tempdir().unwrap();
        let path = dir.path().join("resolver.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let _dir = dir;
            if let Ok((mut stream, _)) = listener.accept() {
                let mut len_buf = [0u8; 4];
                if stream.read_exact(&mut len_buf).is_ok() {
                    let len = u32::from_be_bytes(len_buf) as usize;
                    let mut buf = vec![0u8; len];
                    if stream.read_exact(&mut buf).is_ok() {
                        let _req: Result<mvm_core::substitution_wire::ResolveWireRequest, _> =
                            serde_json::from_slice(&buf);
                        let body = serde_json::to_vec(&response).unwrap();
                        let out_len = (body.len() as u32).to_be_bytes();
                        let _ = stream.write_all(&out_len);
                        let _ = stream.write_all(&body);
                    }
                }
            }
        });
        path
    }

    #[test]
    fn assemble_wires_remote_resolver_backend_to_the_live_uds_server() {
        use base64::Engine;
        use mvm_core::substitution_wire::ResolveWireResponse;
        use mvm_sdk::ir::{AuthType, SecretMount, SecretRef};
        use secrecy::ExposeSecret;

        let value_b64 = base64::engine::general_purpose::STANDARD.encode(b"sk-live-from-vault");
        let uds_path = spawn_resolve_server(ResolveWireResponse::Ok { value_b64 });

        let dir = tempdir().unwrap();
        let mut cfg = vsock_cfg(vec![], dir.path());
        cfg.resolver = ResolverBackend::Remote {
            uds_path: uds_path.clone(),
            timeout_secs: 5,
        };

        // `assemble` must not touch the local secret store at all when the
        // backend is `Remote` — no secret is ever written to `dir/secrets`.
        let (service, handed) = assemble(&cfg).unwrap();
        assert!(handed.is_empty(), "no plan secrets ⇒ nothing handed");

        // Observable-behaviour probe (per the task brief): resolve a
        // `SecretRef` directly through the assembled service's resolver and
        // assert the value came from the live UDS server, not a local store.
        let secret_ref = SecretRef {
            name: "openai".into(),
            mount: SecretMount::Env {
                var: "OPENAI_API_KEY".into(),
            },
            auth_type: AuthType::Bearer,
            allowed_hosts: vec!["api.openai.com".into()],
            sigv4: None,
        };
        let resolved = service.resolver().resolve(&secret_ref).unwrap();
        assert_eq!(resolved.expose_secret().as_slice(), b"sk-live-from-vault");
    }
}

impl EndpointConfig {
    /// Parse the carried proxy strings into a client configuration.
    ///
    /// `Ok(None)` means "dial direct"; an `Err` means the operator configured
    /// something unusable and is reported rather than downgraded to a direct
    /// dial. A host that force-tunnels its egress cannot reach anything
    /// directly, so silently ignoring a typo would turn a fixable
    /// misconfiguration into an unexplained total egress failure.
    pub fn resolve_proxy(&self) -> Result<Option<mvm_http::ProxyConfig>, mvm_http::ProxyError> {
        if self.proxy_https.is_none() && self.proxy_http.is_none() {
            return Ok(None);
        }
        let parse = |s: &Option<String>| -> Result<Option<mvm_http::Proxy>, mvm_http::ProxyError> {
            s.as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(mvm_http::Proxy::parse)
                .transpose()
        };
        let cfg = mvm_http::ProxyConfig {
            https: parse(&self.proxy_https)?,
            http: parse(&self.proxy_http)?,
            no_proxy: self
                .no_proxy
                .as_deref()
                .map(mvm_http::NoProxy::parse)
                .unwrap_or_default(),
        };
        Ok((!cfg.is_empty()).then_some(cfg))
    }
}

#[cfg(test)]
mod proxy_config_tests {
    use super::*;

    fn cfg_with(https: Option<&str>, http: Option<&str>, no_proxy: Option<&str>) -> EndpointConfig {
        let mut cfg: EndpointConfig = serde_json::from_str(
            r#"{"tenant_id":"t","secrets":[],"transport":{"kind":"uds","path":"/tmp/x.sock"}}"#,
        )
        .expect("minimal endpoint config parses");
        cfg.proxy_https = https.map(str::to_string);
        cfg.proxy_http = http.map(str::to_string);
        cfg.no_proxy = no_proxy.map(str::to_string);
        cfg
    }

    #[test]
    fn no_proxy_fields_means_direct() {
        assert!(
            cfg_with(None, None, None)
                .resolve_proxy()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn each_scheme_resolves_independently() {
        let cfg = cfg_with(
            Some("http://secure.corp:3128"),
            Some("socks5://plain.corp:1080"),
            Some("internal.example"),
        );
        let resolved = cfg.resolve_proxy().unwrap().expect("configured");
        assert_eq!(resolved.select("api.example", true).unwrap().port, 3128);
        assert_eq!(
            resolved.select("api.example", false).unwrap().kind,
            mvm_http::ProxyKind::Socks5
        );
        assert!(
            resolved.select("internal.example", true).is_none(),
            "no_proxy still bypasses"
        );
    }

    #[test]
    fn a_malformed_proxy_is_an_error_not_a_silent_direct_dial() {
        let cfg = cfg_with(Some("ftp://nope"), None, None);
        assert!(cfg.resolve_proxy().is_err());
    }
}
