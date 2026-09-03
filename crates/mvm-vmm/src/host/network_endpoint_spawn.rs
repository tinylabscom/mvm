//! Shared per-VM substitution-endpoint spawn/reap helpers.
//!
//! One implementation behind the workload backends that need it, so the
//! endpoint-spawn logic cannot drift between copies. The endpoint is
//! `mvm-network-endpoint` (an `mvm-hostd` bin):
//! when the admitted plan carries secret bindings it runs as a per-VM host
//! process that resolves placeholders for the guest's egress so the real
//! secret never enters the guest. The converged Firecracker, libkrun, and HVF
//! workload paths use the authenticated vsock/UDS endpoint transport.

use crate::host::drive_file::DriveFile;
use anyhow::{Context, Result, anyhow, bail};
use mvm_contract::builder::BuilderError;
use mvm_contract::stream::secret_fingerprint::SecretFingerprint;
use mvm_core::crypto::egress_ca::EgressCa;
use mvm_core::plan::{IngressMapping, SecretBinding};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

/// How the guest reaches the substitution endpoint. Backend-shaped: QEMU's
/// `vhost-vsock` gives a real guest→host AF_VSOCK path, so the host binds an
/// AF_VSOCK listener; Firecracker/libkrun route guest→host through a per-port
/// UDS the in-process VMM proxies, so the host binds that UDS.
///
/// This is the wire contract the `mvm-network-endpoint` bin parses on
/// stdin; mvm-hostd re-exports it so the bin and its tests keep one definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EndpointTransport {
    /// Host AF_VSOCK listener on this port (QEMU). The guest dials
    /// `connect_host_vsock(EGRESS_PORT)`.
    Vsock { port: u32 },
    /// Host UDS the per-port vsock proxy forwards to (Firecracker/libkrun).
    Uds { path: PathBuf },
}

/// The one line the endpoint writes on stdout once it is bound and ready.
///
/// Two things cross here and they are opposites. `env` is what the *guest*
/// gets: opaque placeholders standing in for credentials it must never see.
/// `input_fingerprints` is what the *host* gets: the recognisable shape of
/// each secret this endpoint resolved, so the input gate can refuse bytes
/// heading back into the guest that look like one.
///
/// The fingerprints are computed inside the endpoint because that is the one
/// process that legitimately holds the plaintext. Nothing on this line is a
/// secret value — see `mvm_contract::stream::secret_fingerprint` for what a
/// fingerprint does and does not disclose.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointHandshake {
    /// `(guest var, placeholder)` pairs to inject into the workload's launch
    /// environment.
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// One fingerprint per resolved secret, for the host→guest input gate.
    #[serde(default)]
    pub input_fingerprints: Vec<SecretFingerprint>,
}

/// The fingerprints the endpoint for `vm_name` reported at spawn.
///
/// Process-local and in-memory on purpose. Only the invocation that admits and
/// boots a workload can stream into its stdin — every other entry point holds
/// no plan to write under and refuses — so the process that spawned the
/// endpoint is exactly the process that will later open the input gate.
/// Persisting these would widen a length-and-hash disclosure to every reader
/// of the state dir and buy reachability that nothing uses.
///
/// Empty for a VM this process did not boot, or one whose plan carried no
/// secrets: both mean there is nothing for the gate to recognise.
#[must_use]
pub fn recorded_secret_fingerprints(vm_name: &str) -> Vec<SecretFingerprint> {
    fingerprints().get(vm_name).cloned().unwrap_or_default()
}

/// Record what the endpoint for `vm_name` reported, replacing any earlier set:
/// a restarted VM's secrets are whatever its new endpoint resolved.
///
/// Public so a test can stand in for an endpoint it cannot spawn. Not a
/// privilege boundary — every caller is already inside the process that booted
/// the VM — but the worst case runs the other way from the obvious one.
/// *Adding* a fingerprint only ever makes the gate refuse more. *Replacing* is
/// the sharp edge: this overwrites rather than merges, so an in-process caller
/// passing an empty set leaves the next `open_input` with nothing to scan
/// against, and the gate goes quiet without any refusal to notice. Overwriting
/// is still right — a set that could only grow would outlive the secrets it
/// stood for — so the protection is that the endpoint spawn is the one caller
/// that writes it in production.
pub fn record_secret_fingerprints(vm_name: &str, reported: Vec<SecretFingerprint>) {
    fingerprints().insert(vm_name.to_string(), reported);
}

/// Drop `vm_name`'s fingerprints — the teardown half of the record made at
/// spawn, called wherever the endpoint itself is reaped.
pub fn forget_secret_fingerprints(vm_name: &str) {
    fingerprints().remove(vm_name);
}

/// The per-process fingerprint registry.
///
/// Recovered rather than propagated on poison: a panicking spawn must not take
/// every other VM's input gate down with it, and the map is a plain table a
/// partial update cannot leave inconsistent.
fn fingerprints() -> MutexGuard<'static, HashMap<String, Vec<SecretFingerprint>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Vec<SecretFingerprint>>>> = OnceLock::new();
    REGISTRY
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// The per-VM egress intermediate cert lands in the guest's `mvm-secrets`
/// drive under this filename; the mkGuest boot step appends it to the guest
/// trust bundle before the entrypoint runs.
pub const EGRESS_CERT_DRIVE_NAME: &str = "mvm-egress.crt";

/// The cert/key split the egress CA exists to enforce. The guest receives
/// only `guest_cert` (the intermediate's PEM **cert**, so it can
/// trust host-terminated bound-host TLS); the terminator endpoint receives the
/// cert **and** key (`endpoint_cert_pem` / `endpoint_key_pem`) to mint per-SNI
/// leaves. The intermediate key never enters the guest secrets drive — the same
/// claim-13 "no key on the guest" invariant the substitution channel upholds.
pub struct EgressTlsDelivery {
    /// Cert-only file injected into the guest `mvm-secrets` drive.
    pub guest_cert: DriveFile,
    /// The intermediate cert PEM the endpoint terminates under (== guest cert).
    pub endpoint_cert_pem: String,
    /// The intermediate key PEM — terminator-side only, NEVER to a guest.
    pub endpoint_key_pem: String,
}

// Manual redacted Debug: this struct carries the intermediate private key, so
// its `Debug` must never print key bytes (xtask check-no-display-on-secret-types
// parity with `VmIntermediate`).
impl std::fmt::Debug for EgressTlsDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressTlsDelivery")
            .field("guest_cert", &self.guest_cert.name)
            .field("endpoint_cert_pem", &"<intermediate cert>")
            .field("endpoint_key_pem", &"<redacted>")
            .finish()
    }
}

/// Mint the per-VM name-constrained intermediate (loading/initialising the
/// long-lived host egress CA under `ca_dir`) and split
/// it: cert to the guest secrets drive, cert+key to the terminator endpoint. A
/// pure, unit-testable helper; the boot path calls it when the admitted plan
/// carries secrets and threads the result into `create_dev_secrets_drive` (guest)
/// and the `EndpointConfig` (host). `bound_hosts` are the plan's allowed egress
/// hosts — the intermediate's `nameConstraints permitted` is exactly this set.
pub fn build_egress_tls_delivery(bound_hosts: &[&str], ca_dir: &Path) -> Result<EgressTlsDelivery> {
    let ca = EgressCa::load_or_init_at(ca_dir)
        .map_err(|e| anyhow!("load/init egress CA at {}: {e}", ca_dir.display()))?;
    let inter = ca
        .mint_vm_intermediate(bound_hosts)
        .map_err(|e| anyhow!("mint per-VM egress intermediate: {e}"))?;
    let cert_pem = inter.cert_pem().to_string();
    let key_pem = inter.key_pem();
    Ok(EgressTlsDelivery {
        guest_cert: DriveFile {
            name: EGRESS_CERT_DRIVE_NAME.to_string(),
            content: cert_pem.clone(),
            mode: 0o444,
        },
        endpoint_cert_pem: cert_pem,
        endpoint_key_pem: key_pem,
    })
}

/// PID of the per-VM `mvm-network-endpoint` moat, and the JSON
/// file holding the `(guest var, placeholder)` env pairs it minted (the invoke
/// path reads this to inject `HTTP_PROXY` + placeholder vars). Spawned only when
/// the admitted plan carries secret bindings.
pub const SUBST_PID_FILE: &str = "substitution.pid";

/// Per-VM file the endpoint writes when a guest completes an authenticated
/// session on it.
pub const SUBST_SESSION_FILE: &str = "substitution.session";

/// Per-VM Unix socket that wakes the launcher after the first authenticated
/// FlowMux session. The marker above remains the durable evidence; this socket
/// is only the event that avoids racing a one-shot marker check.
pub const SUBST_SESSION_READY_SOCKET: &str = "substitution-session-ready.sock";

/// Where the session-readiness socket lives.
///
/// Through `vm_socket_dir_at`, not `state_dir` directly: a deep `MVM_HOME`
/// overflows macOS's ~104-byte `sun_path` limit, and that helper falls back to
/// a short hashed `/tmp` namespace. Binding it from the state dir made every
/// launch under a worktree-local home fail with "path must be shorter than
/// SUN_LEN" while the substitution socket — which already used the helper —
/// bound fine.
fn session_ready_socket_path(state_dir: &std::path::Path) -> std::path::PathBuf {
    mvm_core::config::vm_socket_dir_at(state_dir).join(SUBST_SESSION_READY_SOCKET)
}

/// Same treatment for the connector socket, which shares the directory and the
/// same limit.
fn connector_socket_path(state_dir: &std::path::Path) -> std::path::PathBuf {
    mvm_core::config::vm_socket_dir_at(state_dir).join(SUBST_CONNECTOR_SOCKET)
}
/// Host-local typed-connector socket served by the same per-VM endpoint that
/// owns guest FlowMux egress. Broker/tool code may authorize a request, but it
/// reaches the network only by sending that request here.
pub const SUBST_CONNECTOR_SOCKET: &str = "network-endpoint-connector.sock";

/// Bound on the gap between guest-agent readiness and FlowMux authentication.
/// A healthy guest normally authenticates before the launcher connects, so
/// this is a failure deadline rather than launch-path latency.
const DEFAULT_SESSION_READY_TIMEOUT: Duration = Duration::from_secs(5);

/// Wait for the endpoint's first authenticated FlowMux session.
///
/// The endpoint binds its readiness socket before reporting process readiness,
/// then writes one byte only after it has recorded the durable session marker.
/// This gives launch a real happens-before edge without polling or a fixed
/// sleep. A boot with no endpoint remains valid and returns immediately.
pub fn wait_for_endpoint_session(vm_name: &str, state_dir: &Path) -> anyhow::Result<()> {
    wait_for_endpoint_session_with_timeout(vm_name, state_dir, DEFAULT_SESSION_READY_TIMEOUT)
}

fn wait_for_endpoint_session_with_timeout(
    vm_name: &str,
    state_dir: &Path,
    timeout: Duration,
) -> anyhow::Result<()> {
    use std::io::Read as _;

    if endpoint_session_established(state_dir) {
        return Ok(());
    }

    let pid_file = state_dir.join(SUBST_PID_FILE);
    let Some(pid) = read_pid(&pid_file) else {
        return Ok(());
    };
    if !pid_alive(pid) {
        return refuse_launch_without_endpoint_session(vm_name, state_dir);
    }

    let socket = session_ready_socket_path(state_dir);
    let mut stream = std::os::unix::net::UnixStream::connect(&socket).map_err(|e| {
        if pid_alive(pid) {
            anyhow!(
                "VM {vm_name}: connect to network endpoint session readiness socket {}: {e}",
                socket.display()
            )
        } else {
            anyhow!(
                "VM {vm_name}: the network endpoint exited before any guest authenticated \
                 against it — the workload has no network."
            )
        }
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .with_context(|| format!("set network endpoint readiness timeout for VM {vm_name}"))?;

    let mut signal = [0_u8; 1];
    match stream.read_exact(&mut signal) {
        Ok(()) if signal == [1] => {}
        Ok(()) => anyhow::bail!(
            "VM {vm_name}: network endpoint sent an invalid authenticated-session signal"
        ),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            anyhow::bail!(
                "VM {vm_name}: the network endpoint is running but no guest authenticated \
                 within {timeout:?} — the workload has no network. Check that the guest \
                 found its FlowMux identity drive."
            )
        }
        Err(e) => {
            if !pid_alive(pid) {
                return refuse_launch_without_endpoint_session(vm_name, state_dir);
            }
            return Err(anyhow!(
                "VM {vm_name}: waiting for the network endpoint's authenticated session: {e}"
            ));
        }
    }

    // The event is only a wakeup. The marker is the durable source of truth,
    // and final verification keeps a malformed or premature signal fail-closed.
    refuse_launch_without_endpoint_session(vm_name, state_dir)
}

/// Whether a guest has authenticated against this VM's endpoint.
#[must_use]
pub fn endpoint_session_established(state_dir: &std::path::Path) -> bool {
    state_dir.join(SUBST_SESSION_FILE).exists()
}

/// Fail a launch whose endpoint never carried a session.
///
/// Two distinct failures reach the same place. The endpoint may have exited —
/// the pid is gone, so nothing is serving and nothing will. Or it may still be
/// running while no guest ever authenticated against it, which is what a
/// mismatched identity or a guest that cannot find its drive looks like: the
/// endpoint is healthy and the workload has no network.
///
/// **Call this after the guest is activated, never before.** The endpoint binds
/// and prints its handshake line before boot, but a session cannot exist until
/// a guest is running to open one — waiting for it pre-boot deadlocks on an
/// event the wait itself is preventing.
pub fn refuse_launch_without_endpoint_session(
    vm_name: &str,
    state_dir: &std::path::Path,
) -> anyhow::Result<()> {
    if endpoint_session_established(state_dir) {
        return Ok(());
    }
    // No pid file means no endpoint was ever spawned for this VM — a boot with
    // no secrets and a deny-egress policy has nothing to mediate, and has no
    // network by design rather than by failure. Checking those would refuse
    // every one of them.
    let pid_file = state_dir.join(SUBST_PID_FILE);
    let Some(pid) = read_pid(&pid_file) else {
        return Ok(());
    };
    if pid_alive(pid) {
        anyhow::bail!(
            "VM {vm_name}: the network endpoint is running but no guest ever \
             authenticated against it — the workload has no network. Check that the \
             guest found its FlowMux identity drive."
        );
    }
    anyhow::bail!(
        "VM {vm_name}: the network endpoint exited before any guest authenticated \
         against it — the workload has no network."
    )
}
/// Default bound on the endpoint's ready handshake.
///
/// This is not a budget for the endpoint's work — binding a listener and
/// writing one line is microseconds. It is a budget for the process *starting*,
/// and the callers put a lot in front of that: the Stage 0 builder packs a
/// multi-gigabyte, non-sparse `work.ext4` immediately before spawning, so a
/// cold helper binary competes with that flush for I/O and can take tens of
/// seconds to reach `main`. A tight bound turns a slow exec into a spurious
/// "endpoint unresponsive" and sends the operator hunting a hang that is really
/// a queue. Nothing is lost by being generous: an endpoint that dies closes
/// stdout, and that is reported the moment it happens rather than at this bound.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// Env var overriding [`DEFAULT_HANDSHAKE_TIMEOUT`], in whole seconds.
pub const HANDSHAKE_TIMEOUT_ENV: &str = "MVM_ENDPOINT_HANDSHAKE_TIMEOUT_SECS";

/// The handshake bound in force, honouring [`HANDSHAKE_TIMEOUT_ENV`].
pub fn handshake_timeout() -> Duration {
    std::env::var(HANDSHAKE_TIMEOUT_ENV)
        .ok()
        .and_then(|raw| parse_handshake_timeout(&raw))
        .unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT)
}

/// Parse an override. Split out so "junk and zero fall back to the default"
/// is testable without mutating the environment. Zero is rejected rather than
/// honoured: a zero bound fails every spawn before the endpoint can answer.
fn parse_handshake_timeout(raw: &str) -> Option<Duration> {
    let secs: u64 = raw.trim().parse().ok()?;
    (secs > 0).then(|| Duration::from_secs(secs))
}

/// How much of the endpoint's stderr a failed handshake quotes back.
const STDERR_TAIL_BYTES: usize = 2048;

/// What a failed handshake names, so the failure is actionable from the error
/// text alone. Without it the caller reports a bare duration while the
/// endpoint's own stderr — which says exactly what went wrong — sits unread in
/// a file the operator has no reason to know exists.
pub struct HandshakeContext<'a> {
    /// The endpoint binary that was spawned.
    pub endpoint: &'a Path,
    /// Where that process's stderr was redirected, when the caller redirected it.
    pub stderr_log: Option<&'a Path>,
}

impl HandshakeContext<'_> {
    /// Append which binary was run and what it said before it stopped talking.
    fn describe(&self, what: &str) -> String {
        let mut msg = format!("{what} (endpoint {})", self.endpoint.display());
        let Some(log) = self.stderr_log else {
            return msg;
        };
        match stderr_tail(log, STDERR_TAIL_BYTES) {
            Some(tail) => msg.push_str(&format!("; its stderr said: {tail}")),
            None => msg.push_str(&format!("; it wrote nothing to {}", log.display())),
        }
        msg
    }
}

/// Last `max_bytes` of `path`, collapsed onto one line so it survives an error
/// chain. `None` when the file is missing or empty — a silent endpoint is
/// itself a finding, so the caller reports that rather than an empty quote.
fn stderr_tail(path: &Path, max_bytes: usize) -> Option<String> {
    let raw = std::fs::read(path).ok()?;
    let start = raw.len().saturating_sub(max_bytes);
    let collapsed = String::from_utf8_lossy(&raw[start..])
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    (!collapsed.is_empty()).then_some(collapsed)
}

/// Locate the `mvm-network-endpoint` binary and refuse a stale one — the
/// endpoint holds the workload's substituted secrets, so a moved-on config
/// contract failing mid-boot is the worst place to discover the mismatch.
fn resolve_network_endpoint_path() -> Result<PathBuf> {
    crate::host::aux_bin::resolve_verified(&crate::host::aux_bin::AuxBin {
        bin: "mvm-network-endpoint",
        env_var: "MVM_SUBSTITUTION_ENDPOINT_PATH",
        rebuild_package: "mvm-hostd",
    })
}

/// `resolver_remote` config for [`SubstitutionSpawnParams`]: resolve secret
/// *values* over a UDS to a remote fleet-secrets daemon (mvmd's tenant
/// vault) instead of the endpoint's local encrypted secret store. Mirrors
/// `mvm_hostd::supervisor::network_endpoint::ResolverBackend::Remote`'s
/// two fields exactly — but is defined here (not imported from `mvm-hostd`)
/// because `mvm-hostd` depends on `mvm-vmm`, never the reverse; a shared
/// field-shape (not a shared type) is how the two stay in sync without a
/// dependency cycle, the same trick already used for [`EndpointTransport`]
/// (defined here, re-exported by `mvm-hostd`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteResolverSpawnConfig<'a> {
    /// Path to the daemon's UDS.
    pub uds_path: &'a Path,
    /// Round-trip timeout, seconds.
    pub timeout_secs: u64,
}

/// Identity material for an authenticated FlowMux session.
///
/// Mirrors `mvm_hostd::supervisor::network_endpoint::FlowMuxIdentity` field-for-
/// field so the JSON on stdin is identical, without creating a dependency cycle
/// (mvm-hostd depends on mvm-vmm, never the reverse).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowMuxIdentitySpawnConfig {
    /// Unique session identifier, distinct per VM boot.
    pub session_id: String,
    /// Base64-encoded 32-byte Ed25519 host signing key.
    pub host_signing_key_base64: String,
    /// Base64-encoded 32-byte Ed25519 guest verifying key.
    pub guest_verifying_key_base64: String,
}

/// Inputs to [`spawn_network_endpoint`]. Grouped into a struct (rather
/// than threading bare positional args) so the backend-shaped fields —
/// `transport` (vsock vs UDS), `terminator_listen`, `tls_intermediate` — read
/// at the callsite and stay under the argument-count lint.
pub struct SubstitutionSpawnParams<'a> {
    /// VM name; keys the per-VM substitution env path.
    pub vm_name: &'a str,
    /// Per-VM state dir; holds the endpoint PID file.
    pub state_dir: &'a Path,
    /// Tenant id stamped into the endpoint config.
    pub tenant: &'a str,
    /// The admitted plan's secret bindings handed to the endpoint on stdin.
    pub secrets: &'a [SecretBinding],
    /// Per-destination redaction policy from the signed plan.
    pub redaction: &'a mvm_core::policy::RedactionPolicy,
    /// Backend-shaped guest→host channel: `Vsock` (FC/QEMU) or `Uds`
    /// (libkrun/HVF, the per-VM socket the VMM proxies).
    pub transport: EndpointTransport,
    /// `Some(addr)` ⇒ also run the transparent HTTP terminator on that host TCP
    /// addr (FC nft REDIRECT feeds it). `None` on slirp / in-process VMMs.
    pub terminator_listen: Option<SocketAddr>,
    /// The operator's upstream proxy for the endpoint's forward leg, on a host
    /// whose only route out is a proxy.
    ///
    /// `None` means "inherit this host's proxy environment", which
    /// [`spawn_network_endpoint`] resolves once for every backend. Resolving it
    /// there rather than at each call site is deliberate: a backend that forgot
    /// to read the environment would be an egress outage on a force-tunnelled
    /// host, and the forgetting would be invisible.
    pub egress_proxy: Option<EgressProxySpawnConfig>,
    /// Where the endpoint records its first authenticated session. Set by the
    /// spawner; callers leave it `None`.
    pub session_marker: Option<std::path::PathBuf>,
    /// `(cert_pem, key_pem)` of the per-VM intermediate for the `https`
    /// terminator; the key never reaches the guest. `None` ⇒ `http`-only.
    pub tls_intermediate: Option<(String, String)>,
    /// The VM's resolved claim-10 network policy. `Some` ⇒ the endpoint gates
    /// egress itself (the relay path — the run loop no longer gates); `None` ⇒
    /// ungated here (the legacy in-loop gate is the enforcer).
    pub network_policy: Option<&'a mvm_core::policy::network_policy::NetworkPolicy>,
    /// Transport-neutral resource ceilings from the admitted execution plan.
    pub network_limits: mvm_core::plan::NetworkLimits,
    /// Exact signed ingress mappings this endpoint must own.
    pub ingress: &'a [IngressMapping],
    /// `Some` ⇒ the endpoint resolves secret *values* remotely (see
    /// [`RemoteResolverSpawnConfig`]) instead of its local encrypted store.
    /// `None` preserves today's `Local` (unchanged) resolver behavior.
    pub resolver_remote: Option<RemoteResolverSpawnConfig<'a>>,
    /// Override the endpoint's binding-store dir (where `allowed_hosts`/
    /// `auth_type` per secret name are read from at `assemble()` time).
    /// `None` preserves today's host-default dir.
    pub binding_store_dir: Option<&'a Path>,
    /// Identity material for the authenticated FlowMux session. `Some` selects
    /// the converged FlowMux path; `None` keeps the legacy Wire/Raw path.
    pub flowmux_identity: Option<FlowMuxIdentitySpawnConfig>,
}

impl<'a> SubstitutionSpawnParams<'a> {
    /// Start building a [`SubstitutionSpawnParams`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> SubstitutionSpawnParamsBuilder<'a> {
        SubstitutionSpawnParamsBuilder::new()
    }
}

/// Builder for [`SubstitutionSpawnParams`]. Required fields are checked by
/// [`SubstitutionSpawnParamsBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct SubstitutionSpawnParamsBuilder<'a> {
    vm_name: Option<&'a str>,
    state_dir: Option<&'a Path>,
    tenant: Option<&'a str>,
    secrets: Option<&'a [SecretBinding]>,
    redaction: Option<&'a mvm_core::policy::RedactionPolicy>,
    transport: Option<EndpointTransport>,
    terminator_listen: Option<SocketAddr>,
    tls_intermediate: Option<(String, String)>,
    network_policy: Option<&'a mvm_core::policy::network_policy::NetworkPolicy>,
    network_limits: Option<mvm_core::plan::NetworkLimits>,
    ingress: Option<&'a [IngressMapping]>,
    resolver_remote: Option<RemoteResolverSpawnConfig<'a>>,
    binding_store_dir: Option<&'a Path>,
    flowmux_identity: Option<FlowMuxIdentitySpawnConfig>,
    egress_proxy: Option<EgressProxySpawnConfig>,
}

impl<'a> SubstitutionSpawnParamsBuilder<'a> {
    /// An empty builder: nothing set yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            vm_name: None,
            state_dir: None,
            tenant: None,
            secrets: None,
            redaction: None,
            transport: None,
            terminator_listen: None,
            tls_intermediate: None,
            network_policy: None,
            network_limits: None,
            ingress: None,
            resolver_remote: None,
            binding_store_dir: None,
            flowmux_identity: None,
            egress_proxy: None,
        }
    }

    /// Set `vm_name`.
    #[must_use]
    pub fn vm_name(mut self, vm_name: &'a str) -> Self {
        self.vm_name = Some(vm_name);
        self
    }

    /// Set `state_dir`.
    #[must_use]
    pub fn state_dir(mut self, state_dir: &'a Path) -> Self {
        self.state_dir = Some(state_dir);
        self
    }

    /// Set `tenant`.
    #[must_use]
    pub fn tenant(mut self, tenant: &'a str) -> Self {
        self.tenant = Some(tenant);
        self
    }

    /// Set `secrets`.
    #[must_use]
    pub fn secrets(mut self, secrets: &'a [SecretBinding]) -> Self {
        self.secrets = Some(secrets);
        self
    }

    /// Set `redaction`.
    #[must_use]
    pub fn redaction(mut self, redaction: &'a mvm_core::policy::RedactionPolicy) -> Self {
        self.redaction = Some(redaction);
        self
    }

    /// Set `transport`.
    #[must_use]
    pub fn transport(mut self, transport: EndpointTransport) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Set `terminator_listen`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn terminator_listen(mut self, terminator_listen: impl Into<Option<SocketAddr>>) -> Self {
        self.terminator_listen = terminator_listen.into();
        self
    }

    /// Set `tls_intermediate`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn tls_intermediate(
        mut self,
        tls_intermediate: impl Into<Option<(String, String)>>,
    ) -> Self {
        self.tls_intermediate = tls_intermediate.into();
        self
    }

    /// Set `network_policy`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn network_policy(
        mut self,
        network_policy: impl Into<Option<&'a mvm_core::policy::network_policy::NetworkPolicy>>,
    ) -> Self {
        self.network_policy = network_policy.into();
        self
    }

    /// Set the admitted transport-neutral networking ceilings.
    #[must_use]
    pub fn network_limits(mut self, network_limits: mvm_core::plan::NetworkLimits) -> Self {
        self.network_limits = Some(network_limits);
        self
    }

    /// Set the exact signed ingress mappings.
    #[must_use]
    pub fn ingress(mut self, ingress: &'a [IngressMapping]) -> Self {
        self.ingress = Some(ingress);
        self
    }

    /// Set `resolver_remote`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn resolver_remote(
        mut self,
        resolver_remote: impl Into<Option<RemoteResolverSpawnConfig<'a>>>,
    ) -> Self {
        self.resolver_remote = resolver_remote.into();
        self
    }

    /// Set `binding_store_dir`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn binding_store_dir(mut self, binding_store_dir: impl Into<Option<&'a Path>>) -> Self {
        self.binding_store_dir = binding_store_dir.into();
        self
    }

    /// Set `flowmux_identity`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn flowmux_identity(
        mut self,
        flowmux_identity: impl Into<Option<FlowMuxIdentitySpawnConfig>>,
    ) -> Self {
        self.flowmux_identity = flowmux_identity.into();
        self
    }

    /// Set `egress_proxy`. Takes a value or an `Option`; unset means `None`,
    /// which is the endpoint's "dial direct".
    #[must_use]
    pub fn egress_proxy(mut self, egress_proxy: impl Into<Option<EgressProxySpawnConfig>>) -> Self {
        self.egress_proxy = egress_proxy.into();
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<SubstitutionSpawnParams<'a>, BuilderError> {
        Ok(SubstitutionSpawnParams {
            vm_name: self
                .vm_name
                .ok_or(BuilderError::missing("SubstitutionSpawnParams", "vm_name"))?,
            state_dir: self.state_dir.ok_or(BuilderError::missing(
                "SubstitutionSpawnParams",
                "state_dir",
            ))?,
            tenant: self
                .tenant
                .ok_or(BuilderError::missing("SubstitutionSpawnParams", "tenant"))?,
            secrets: self
                .secrets
                .ok_or(BuilderError::missing("SubstitutionSpawnParams", "secrets"))?,
            redaction: self.redaction.ok_or(BuilderError::missing(
                "SubstitutionSpawnParams",
                "redaction",
            ))?,
            transport: self.transport.ok_or(BuilderError::missing(
                "SubstitutionSpawnParams",
                "transport",
            ))?,
            terminator_listen: self.terminator_listen,
            tls_intermediate: self.tls_intermediate,
            network_policy: self.network_policy,
            network_limits: self.network_limits.ok_or(BuilderError::missing(
                "SubstitutionSpawnParams",
                "network_limits",
            ))?,
            ingress: self
                .ingress
                .ok_or(BuilderError::missing("SubstitutionSpawnParams", "ingress"))?,
            resolver_remote: self.resolver_remote,
            binding_store_dir: self.binding_store_dir,
            flowmux_identity: self.flowmux_identity,
            egress_proxy: self.egress_proxy,
            session_marker: None,
        })
    }
}

impl<'a> Default for SubstitutionSpawnParamsBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

/// The upstream proxy, as strings the endpoint parses.
///
/// Strings rather than a parsed type because this only carries a value from
/// host configuration to the endpoint's stdin; the endpoint is where a bad
/// value has to be reported, since it is the process that would otherwise fail
/// to reach anything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressProxySpawnConfig {
    pub https: Option<String>,
    pub http: Option<String>,
    pub no_proxy: Option<String>,
}

impl EgressProxySpawnConfig {
    /// Read the conventional proxy environment of the host process.
    ///
    /// Returns `None` when nothing is configured, so the common case emits no
    /// keys at all and the endpoint's defaults keep meaning "dial direct".
    #[must_use]
    pub fn from_host_env() -> Option<Self> {
        let pick = |names: &[&str]| -> Option<String> {
            names
                .iter()
                .find_map(|n| std::env::var(n).ok())
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let all = pick(&["all_proxy", "ALL_PROXY"]);
        let cfg = Self {
            https: pick(&["https_proxy", "HTTPS_PROXY"]).or_else(|| all.clone()),
            http: pick(&["http_proxy", "HTTP_PROXY"]).or(all),
            no_proxy: pick(&["no_proxy", "NO_PROXY"]),
        };
        (cfg.https.is_some() || cfg.http.is_some()).then_some(cfg)
    }
}

/// The endpoint config a spawn with (or without) a FlowMux identity emits.
///
/// Exposed so the conformance suite can assert the **production** protocol
/// selection rather than a re-implementation of it. The regression this guards
/// against was precisely a guest and a host disagreeing about the protocol
/// while each side's own tests passed.
pub fn endpoint_config_for_identity(
    flowmux_identity: Option<FlowMuxIdentitySpawnConfig>,
) -> serde_json::Value {
    let redaction = mvm_core::policy::RedactionPolicy::default();
    build_endpoint_config_json(&SubstitutionSpawnParams {
        vm_name: "conformance",
        state_dir: Path::new("/nonexistent"),
        tenant: "local",
        secrets: &[],
        redaction: &redaction,
        transport: EndpointTransport::Uds {
            path: PathBuf::from("/nonexistent/vsock-5253.sock"),
        },
        terminator_listen: None,
        egress_proxy: None,
        session_marker: None,
        tls_intermediate: None,
        network_policy: None,
        network_limits: mvm_core::plan::NetworkLimits::default(),
        ingress: &[],
        resolver_remote: None,
        binding_store_dir: None,
        flowmux_identity,
    })
}

/// Build the EndpointConfig JSON the endpoint reads on stdin. Pure (no spawn)
/// so the wire form — including the claim-10 policy + egress mode — is unit-testable.
fn build_endpoint_config_json(params: &SubstitutionSpawnParams<'_>) -> serde_json::Value {
    let mut cfg = serde_json::json!({
        "tenant_id": params.tenant,
        "secrets": params.secrets,
        // Per-destination redaction policy from the signed plan; the endpoint
        // applies it to the cleartext it forwards. Default (all-off) is harmless.
        "redaction": serde_json::to_value(params.redaction)
            .expect("RedactionPolicy serializes to JSON"),
        // Backend-shaped guest→host channel: FC/QEMU dial the per-port vsock
        // (Vsock); libkrun/HVF route through the per-VM UDS the VMM proxies (Uds).
        "transport": serde_json::to_value(&params.transport)
            .expect("EndpointTransport serializes to JSON"),
        // Which egress protocol the relayed stream carries. One authenticated
        // FlowMux session whenever this boot has an identity; "wire" only for
        // the tiers that still speak the substitution protocol directly.
        // "raw" is gone: nothing selects it, and the guest cannot speak it.
        "egress_mode": if params.flowmux_identity.is_some() {
            "flow_mux"
        } else {
            "wire"
        },
        "network_limits": params.network_limits,
        "ingress": params.ingress,
    });
    if let Some(marker) = params.session_marker.as_ref() {
        cfg["session_marker"] = serde_json::json!(marker);
    }
    if params.flowmux_identity.is_some() {
        cfg["session_ready_socket"] =
            serde_json::json!(session_ready_socket_path(params.state_dir));
        cfg["connector_uds_path"] = serde_json::json!(connector_socket_path(params.state_dir));
    }
    if let Some(proxy) = params.egress_proxy.as_ref() {
        // `EndpointConfig.proxy_*`: the operator's upstream proxy for the
        // forward leg. Resolved on the host, where configuration lives, rather
        // than in the endpoint, which self-confines before it serves. Keys are
        // emitted only when set so the endpoint's `#[serde(default)]` fields
        // keep meaning "dial direct".
        if let Some(v) = proxy.https.as_deref() {
            cfg["proxy_https"] = serde_json::Value::String(v.to_string());
        }
        if let Some(v) = proxy.http.as_deref() {
            cfg["proxy_http"] = serde_json::Value::String(v.to_string());
        }
        if let Some(v) = proxy.no_proxy.as_deref() {
            cfg["no_proxy"] = serde_json::Value::String(v.to_string());
        }
    }
    if let Some(addr) = params.terminator_listen {
        // `EndpointConfig.terminator_listen: Option<SocketAddr>`:
        // present ⇒ the endpoint runs the host TCP terminator concurrently with
        // the vsock substitution transport. `SocketAddr`'s Display ("ip:port")
        // is the wire form `serde(SocketAddr)` round-trips.
        cfg["terminator_listen"] = serde_json::Value::String(addr.to_string());
    }
    if let Some((cert_pem, key_pem)) = &params.tls_intermediate {
        // `EndpointConfig.tls_intermediate`: the per-VM name-constrained
        // intermediate the `https` terminator mints per-SNI leaves under. The
        // KEY only ever reaches this host endpoint — never the guest.
        cfg["tls_intermediate"] = serde_json::json!({
            "cert_pem": cert_pem,
            "key_pem": key_pem,
        });
    }
    if let Some(policy) = params.network_policy {
        // `EndpointConfig.network_policy`: present ⇒ the endpoint gates every
        // destination itself. Omitted when `None` so legacy configs are
        // byte-identical to before (the in-loop gate stays the enforcer).
        cfg["network_policy"] =
            serde_json::to_value(policy).expect("NetworkPolicy serializes to JSON");
    }
    if let Some(RemoteResolverSpawnConfig {
        uds_path,
        timeout_secs,
    }) = params.resolver_remote
    {
        // `EndpointConfig.resolver`: internally tagged on `backend` (see
        // `ResolverBackend`'s `#[serde(tag = "backend", rename_all =
        // "snake_case")]`) — `Remote { uds_path, timeout_secs }` becomes
        // `{"backend":"remote","uds_path":...,"timeout_secs":...}`. Built by
        // hand (not by depending on `mvm_hostd::ResolverBackend`) for the same
        // reason `RemoteResolverSpawnConfig` isn't that type: the dependency
        // only runs `mvm-hostd -> mvm-vmm`, never back. Omitted when `None` so
        // legacy configs land on `EndpointConfig`'s `#[serde(default)]` Local.
        cfg["resolver"] = serde_json::json!({
            "backend": "remote",
            "uds_path": uds_path,
            "timeout_secs": timeout_secs,
        });
    }
    if let Some(dir) = params.binding_store_dir {
        cfg["binding_store_dir"] = serde_json::json!(dir);
    }
    if let Some(id) = &params.flowmux_identity {
        cfg["flowmux_identity"] = serde_json::json!({
            "session_id": id.session_id,
            "host_signing_key_base64": id.host_signing_key_base64,
            "guest_verifying_key_base64": id.guest_verifying_key_base64,
        });
    }
    cfg
}

/// Spawn the per-VM `mvm-network-endpoint` moat. Hands it the
/// plan's secret bindings on stdin, reads back the minted `(guest var,
/// placeholder)` handshake line, and persists it to the per-VM substitution env
/// file for the invoke path to inject (`HTTP_PROXY` + placeholder vars). The
/// endpoint serves the guest→host substitution channel over `transport`; when
/// `terminator_listen` is `Some`, it *also* runs the transparent HTTP
/// terminator on that host TCP addr. Detached via `setsid` so it outlives
/// `mvmctl up`; the stop path reaps
/// it via [`SUBST_PID_FILE`]. The real secret values never leave the endpoint's
/// address space — only the opaque placeholders are persisted/handed out.
pub fn spawn_network_endpoint(mut params: SubstitutionSpawnParams<'_>) -> Result<()> {
    use std::io::Write;
    // One resolution point for every backend. A caller that supplied a proxy
    // explicitly keeps it; everyone else inherits the host's environment.
    if params.egress_proxy.is_none() {
        params.egress_proxy = EgressProxySpawnConfig::from_host_env();
    }
    let session_marker = params.state_dir.join(SUBST_SESSION_FILE);
    let session_ready_socket = session_ready_socket_path(params.state_dir);
    // A stale marker from a previous boot would make this launch look ready
    // before any guest had connected, which is the exact failure the check
    // exists to catch.
    let _ = std::fs::remove_file(&session_marker);
    let _ = std::fs::remove_file(&session_ready_socket);
    params.session_marker = Some(session_marker);
    let cfg = build_endpoint_config_json(&params);
    let SubstitutionSpawnParams {
        vm_name, state_dir, ..
    } = params;

    let bin = resolve_network_endpoint_path()?;

    // Capture endpoint diagnostics to /tmp so hangs/refusals are observable.
    // The file is per-VM and truncated each run; stderr was previously /dev/null.
    let stderr_log =
        std::path::PathBuf::from("/tmp").join(format!("mvm-network-endpoint-{vm_name}.log"));
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&stderr_log)
        .map_err(|e| {
            anyhow!(
                "open substitution endpoint stderr log {}: {e}",
                stderr_log.display()
            )
        })?;

    let mut cmd = Command::new(&bin);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(log_file);
    // Detach into its own session so it survives this `mvmctl` process.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            // SAFETY: post-fork, pre-exec; setsid has no preconditions.
            libc::setsid();
            Ok(())
        });
    }
    let pid_file = state_dir.join(SUBST_PID_FILE);
    let env_path = mvm_core::config::vm_substitution_env_path(vm_name);
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("spawn substitution endpoint ({}): {e}", bin.display()))?;
    let mut process_guard = SpawnedEndpointGuard::new(child.id(), &pid_file, &env_path);

    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("substitution endpoint stdin was not piped"))?
        .write_all(cfg.to_string().as_bytes())
        .map_err(|e| anyhow!("pipe EndpointConfig to substitution endpoint: {e}"))?;
    // (stdin writer dropped here → EOF, so the endpoint stops reading config.)

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("substitution endpoint stdout was not piped"))?;
    let handshake = read_handshake_line(
        stdout,
        child.id(),
        handshake_timeout(),
        &HandshakeContext {
            endpoint: &bin,
            stderr_log: Some(&stderr_log),
        },
    )?;

    std::fs::write(&pid_file, child.id().to_string())
        .map_err(|e| anyhow!("write {}: {e}", pid_file.display()))?;
    process_guard.mark_pid_written();
    if let Some(parent) = env_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| anyhow!("create {}: {e}", parent.display()))?;
    }
    // The two halves part company here. Only `env` is persisted, because only
    // the guest launch env needs to survive into a later `mvmctl` invocation;
    // the fingerprints stay in this process, which is the one that will open
    // the input gate.
    let env_json = serde_json::to_vec(&handshake.env)
        .map_err(|e| anyhow!("serialize substitution env for {}: {e}", env_path.display()))?;
    std::fs::write(&env_path, &env_json)
        .map_err(|e| anyhow!("write {}: {e}", env_path.display()))?;
    record_secret_fingerprints(vm_name, handshake.input_fingerprints);
    process_guard.mark_env_written();
    process_guard.defuse();
    // Detach: drop the child handle without killing. The endpoint runs
    // daemonized (setsid) and is reaped by the stop path via SUBST_PID_FILE.
    Ok(())
}

struct SpawnedEndpointGuard {
    pid: libc::pid_t,
    pid_file: PathBuf,
    env_path: PathBuf,
    pid_written: bool,
    env_written: bool,
    armed: bool,
}

impl SpawnedEndpointGuard {
    fn new(pid: u32, pid_file: &Path, env_path: &Path) -> Self {
        Self {
            pid: pid as libc::pid_t,
            pid_file: pid_file.to_path_buf(),
            env_path: env_path.to_path_buf(),
            pid_written: false,
            env_written: false,
            armed: true,
        }
    }

    fn mark_pid_written(&mut self) {
        self.pid_written = true;
    }

    fn mark_env_written(&mut self) {
        self.env_written = true;
    }

    fn defuse(&mut self) {
        self.armed = false;
    }
}

impl Drop for SpawnedEndpointGuard {
    fn drop(&mut self) {
        if self.armed {
            if pid_alive(self.pid) {
                kill(self.pid, libc::SIGTERM);
            }
            if self.pid_written {
                let _ = std::fs::remove_file(&self.pid_file);
            }
            if self.env_written {
                let _ = std::fs::remove_file(&self.env_path);
            }
        }
    }
}

/// Read and parse the endpoint's one-line ready handshake from its stdout
/// within `timeout`. A blocking pipe read can't be timed directly, so read on
/// a helper thread and bound the wait; on timeout / EOF-without-line / a line
/// that is not a handshake, SIGKILL the endpoint and fail (the caller rolls
/// back the VM — fail closed).
///
/// Shared by every spawner of this binary. The builder path used to carry its
/// own copy that accepted *any* non-empty line as a handshake, so stray chrome
/// on a shared stdout read as success there and as a parse failure here.
pub fn read_handshake_line(
    stdout: std::process::ChildStdout,
    pid: u32,
    timeout: Duration,
    ctx: &HandshakeContext<'_>,
) -> Result<EndpointHandshake> {
    use std::io::{BufRead, BufReader};
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let res = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = tx.send(res);
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(line)) if !line.trim().is_empty() => serde_json::from_str(line.trim()).map_err(|e| {
            kill(pid as libc::pid_t, libc::SIGKILL);
            anyhow!(
                "{}",
                ctx.describe(&format!("parse substitution endpoint handshake: {e}"))
            )
        }),
        Ok(Ok(_)) => {
            kill(pid as libc::pid_t, libc::SIGKILL);
            bail!(
                "{}",
                ctx.describe("substitution endpoint closed stdout without a ready handshake")
            )
        }
        Ok(Err(e)) => {
            kill(pid as libc::pid_t, libc::SIGKILL);
            bail!(
                "{}",
                ctx.describe(&format!("read substitution endpoint handshake: {e}"))
            )
        }
        Err(_) => {
            kill(pid as libc::pid_t, libc::SIGKILL);
            bail!(
                "{}",
                ctx.describe(&format!(
                    "substitution endpoint handshake timed out after {timeout:?} \
                     (override with {HANDSHAKE_TIMEOUT_ENV})"
                ))
            )
        }
    }
}

/// RAII reaper for the per-VM substitution endpoint, armed while a backend's
/// `start` is wiring the VM and dropped on any early-return so the
/// decrypted-secret process can't outlive a failed launch. Defused once the VM
/// is fully up (the normal `stop` path then owns teardown). Shared by the
/// libkrun and HVF backends — one definition so the spawn/reap moat can't drift.
pub struct EndpointGuard {
    /// `Some(name)` while armed; `None` once defused. Read by backend tests to
    /// assert the no-secrets path yields a no-op guard.
    pub vm_name: Option<String>,
}

impl EndpointGuard {
    pub fn new(vm_name: &str) -> Self {
        Self {
            vm_name: Some(vm_name.to_string()),
        }
    }
    /// A guard for a VM that spawned no endpoint (no secrets) — Drop is a no-op.
    pub fn defused() -> Self {
        Self { vm_name: None }
    }
    pub fn defuse(&mut self) {
        self.vm_name = None;
    }
}

impl Drop for EndpointGuard {
    fn drop(&mut self) {
        if let Some(ref name) = self.vm_name {
            tracing::warn!(vm = %name, "EndpointGuard: reaping orphaned substitution endpoint");
            reap_network_endpoint(&mvm_core::config::vm_state_dir(name), name);
        }
    }
}

/// Reap the per-VM substitution endpoint (if this VM spawned one) so its
/// decrypted secrets don't outlive the guest, and drop the pid + env sidecars.
/// Best-effort + idempotent: a VM with no endpoint (no secrets) is a no-op. The
/// liveness guard prevents signalling a recycled PID from a stale pidfile.
pub fn reap_network_endpoint(state_dir: &Path, vm_name: &str) {
    if let Some(spid) = read_pid(&state_dir.join(SUBST_PID_FILE))
        && pid_alive(spid)
    {
        kill(spid, libc::SIGTERM);
    }
    let _ = std::fs::remove_file(state_dir.join(SUBST_PID_FILE));
    let _ = std::fs::remove_file(session_ready_socket_path(state_dir));
    let _ = std::fs::remove_file(state_dir.join(SUBST_CONNECTOR_SOCKET));
    let _ = std::fs::remove_file(mvm_core::config::vm_substitution_env_path(vm_name));
    // The endpoint's secrets are gone; the shapes the gate recognised them by
    // go with them, so a recycled VM name cannot inherit them.
    forget_secret_fingerprints(vm_name);
}

// ── pid helpers (local copies — backend modules keep theirs private) ──

fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn pid_alive(pid: libc::pid_t) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

fn kill(pid: libc::pid_t, sig: libc::c_int) {
    unsafe {
        libc::kill(pid, sig);
    }
}

#[cfg(test)]
mod tests {

    /// Stub endpoint scripts run through the verified resolver before they
    /// can play their role, so every stub answers the contract probe first.
    /// Generated from the real response so a contract bump rewrites the
    /// stubs instead of breaking them.
    fn stub_preamble() -> String {
        format!(
            "#!/bin/sh\nif [ \"$1\" = \"{flag}\" ]; then echo '{answer}'; exit 0; fi\n",
            flag = crate::host::helper_contract::CONTRACT_PROBE_FLAG,
            answer =
                crate::host::helper_contract::probe_response("mvm-network-endpoint").trim_end(),
        )
    }

    /// A launch whose endpoint never carried a session must fail, and say
    /// which of the two ways it failed.
    #[test]
    fn a_launch_with_no_endpoint_session_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        // No pid file at all: no endpoint was spawned, so there is nothing to
        // be missing. A boot with nothing to mediate must not be refused.
        assert!(refuse_launch_without_endpoint_session("vm-1", dir.path()).is_ok());

        // A pid that is not running: the endpoint died. Pid 1 is never this
        // endpoint, and a pid that cannot exist reads as dead.
        std::fs::write(dir.path().join(SUBST_PID_FILE), "2147483646").unwrap();
        let err = refuse_launch_without_endpoint_session("vm-1", dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("exited before any guest"),
            "unexpected: {err}"
        );

        // A live pid and still no session: the endpoint is up, the guest never
        // reached it. Our own pid stands in for a live endpoint.
        std::fs::write(
            dir.path().join(SUBST_PID_FILE),
            std::process::id().to_string(),
        )
        .unwrap();
        let err = refuse_launch_without_endpoint_session("vm-1", dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("no guest ever authenticated"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn a_launch_whose_endpoint_carried_a_session_is_admitted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SUBST_SESSION_FILE), b"1").unwrap();
        assert!(endpoint_session_established(dir.path()));
        assert!(refuse_launch_without_endpoint_session("vm-1", dir.path()).is_ok());
    }

    #[test]
    fn a_launch_waits_for_a_delayed_authenticated_session() {
        use std::io::Write as _;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(SUBST_PID_FILE),
            std::process::id().to_string(),
        )
        .unwrap();
        let ready_socket = dir.path().join(SUBST_SESSION_READY_SOCKET);
        let listener = std::os::unix::net::UnixListener::bind(&ready_socket).unwrap();
        let marker = dir.path().join(SUBST_SESSION_FILE);
        let endpoint = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            std::fs::write(marker, b"1").unwrap();
            let _ = stream.write_all(&[1]);
        });

        let result = wait_for_endpoint_session_with_timeout(
            "vm-1",
            dir.path(),
            std::time::Duration::from_secs(1),
        );
        let _ = std::os::unix::net::UnixStream::connect(&ready_socket);
        endpoint.join().unwrap();
        result.expect("the authenticated-session event admits the launch");
    }

    #[test]
    fn a_launch_does_not_wait_when_the_session_is_already_recorded() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SUBST_SESSION_FILE), b"1").unwrap();

        wait_for_endpoint_session_with_timeout("vm-1", dir.path(), std::time::Duration::ZERO)
            .expect("durable session evidence admits immediately");
    }

    #[test]
    fn a_launch_reports_an_endpoint_that_exited_before_authentication() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SUBST_PID_FILE), "2147483646").unwrap();

        let err = wait_for_endpoint_session("vm-1", dir.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("exited before any guest authenticated"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn a_launch_times_out_when_a_live_endpoint_never_authenticates() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(SUBST_PID_FILE),
            std::process::id().to_string(),
        )
        .unwrap();
        let _listener =
            std::os::unix::net::UnixListener::bind(dir.path().join(SUBST_SESSION_READY_SOCKET))
                .unwrap();

        let err = wait_for_endpoint_session_with_timeout(
            "vm-1",
            dir.path(),
            std::time::Duration::from_millis(20),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("no guest authenticated within"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn a_launch_rejects_an_invalid_session_signal_even_when_a_marker_exists() {
        use std::io::Write as _;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(SUBST_PID_FILE),
            std::process::id().to_string(),
        )
        .unwrap();
        let ready_socket = dir.path().join(SUBST_SESSION_READY_SOCKET);
        let listener = std::os::unix::net::UnixListener::bind(&ready_socket).unwrap();
        let marker = dir.path().join(SUBST_SESSION_FILE);
        let endpoint = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            std::fs::write(marker, b"1").unwrap();
            let _ = stream.write_all(&[2]);
        });

        let result = wait_for_endpoint_session_with_timeout(
            "vm-1",
            dir.path(),
            std::time::Duration::from_secs(1),
        );
        if result.is_ok() {
            let _ = std::os::unix::net::UnixStream::connect(&ready_socket);
        }
        endpoint.join().unwrap();
        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid authenticated-session signal"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn a_launch_reports_a_broken_readiness_channel_from_a_live_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(SUBST_PID_FILE),
            std::process::id().to_string(),
        )
        .unwrap();
        let ready_socket = dir.path().join(SUBST_SESSION_READY_SOCKET);
        let listener = std::os::unix::net::UnixListener::bind(&ready_socket).unwrap();
        let endpoint = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            drop(stream);
        });

        let result = wait_for_endpoint_session_with_timeout(
            "vm-1",
            dir.path(),
            std::time::Duration::from_secs(1),
        );
        if result.is_ok() {
            let _ = std::os::unix::net::UnixStream::connect(&ready_socket);
        }
        endpoint.join().unwrap();
        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("waiting for the network endpoint's authenticated session"),
            "unexpected: {err}"
        );
    }

    /// The marker is per-boot. A file left by a previous run would make the
    /// next launch look ready before any guest had connected — the exact
    /// failure this check exists to catch, reintroduced by staleness.
    #[test]
    fn the_session_marker_is_cleared_before_a_new_endpoint_starts() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join(SUBST_SESSION_FILE);
        std::fs::write(&marker, b"1").unwrap();
        // Mirrors what `spawn_network_endpoint` does before handing the path
        // to a fresh endpoint.
        let _ = std::fs::remove_file(&marker);
        assert!(!endpoint_session_established(dir.path()));
    }

    /// The marker path reaches the endpoint's config, or the endpoint has
    /// nothing to write and every launch refuses.
    #[test]
    fn the_config_carries_the_session_marker_when_set() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join(SUBST_SESSION_FILE);
        let redaction = mvm_core::policy::RedactionPolicy::default();
        let mut params = SubstitutionSpawnParamsBuilder::new()
            .vm_name("vm-1")
            .state_dir(dir.path())
            .tenant("local")
            .secrets(&[])
            .redaction(&redaction)
            .network_limits(mvm_contract::plan::NetworkLimits::default())
            .ingress(&[])
            .transport(EndpointTransport::Uds {
                path: dir.path().join("sub.sock"),
            })
            .build()
            .expect("builder");
        params.session_marker = Some(marker.clone());
        let cfg = build_endpoint_config_json(&params);
        assert_eq!(cfg["session_marker"], serde_json::json!(marker));
    }

    #[test]
    fn tls_delivery_debug_redacts_the_private_key() {
        let delivery = EgressTlsDelivery {
            guest_cert: DriveFile {
                name: EGRESS_CERT_DRIVE_NAME.to_string(),
                content: "guest certificate".to_string(),
                mode: 0o444,
            },
            endpoint_cert_pem: "endpoint certificate".to_string(),
            endpoint_key_pem: "never-print-this-private-key".to_string(),
        };

        let rendered = format!("{delivery:?}");
        assert!(rendered.contains(EGRESS_CERT_DRIVE_NAME));
        assert!(rendered.contains("<intermediate cert>"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("never-print-this-private-key"));
    }

    #[test]
    fn substitution_spawn_builder_preserves_every_optional_endpoint_input() {
        let dir = tempfile::tempdir().unwrap();
        let redaction = mvm_core::policy::RedactionPolicy::default();
        let network_policy = mvm_core::policy::network_policy::NetworkPolicy::default();
        let limits = mvm_core::plan::NetworkLimits::default();
        let terminator: SocketAddr = "127.0.0.1:18080".parse().unwrap();
        let tls = ("certificate".to_string(), "private-key".to_string());
        let resolver = RemoteResolverSpawnConfig {
            uds_path: dir.path(),
            timeout_secs: 9,
        };
        let identity = FlowMuxIdentitySpawnConfig {
            session_id: "session-builder".to_string(),
            host_signing_key_base64: "host-key".to_string(),
            guest_verifying_key_base64: "guest-key".to_string(),
        };
        let proxy = EgressProxySpawnConfig {
            https: Some("http://proxy.example:8443".to_string()),
            http: Some("http://proxy.example:8080".to_string()),
            no_proxy: Some("localhost".to_string()),
        };

        let params = SubstitutionSpawnParams::builder()
            .vm_name("vm-builder")
            .state_dir(dir.path())
            .tenant("tenant-builder")
            .secrets(&[])
            .redaction(&redaction)
            .transport(EndpointTransport::Uds {
                path: dir.path().join("endpoint.sock"),
            })
            .network_limits(limits)
            .ingress(&[])
            .terminator_listen(terminator)
            .tls_intermediate(tls.clone())
            .network_policy(&network_policy)
            .resolver_remote(resolver)
            .binding_store_dir(dir.path())
            .flowmux_identity(identity.clone())
            .egress_proxy(proxy.clone())
            .build()
            .expect("every named builder input is retained");

        assert_eq!(params.terminator_listen, Some(terminator));
        assert_eq!(params.tls_intermediate, Some(tls));
        assert_eq!(params.network_policy, Some(&network_policy));
        assert_eq!(params.resolver_remote, Some(resolver));
        assert_eq!(params.binding_store_dir, Some(dir.path()));
        assert_eq!(params.flowmux_identity, Some(identity));
        assert_eq!(params.egress_proxy, Some(proxy));
    }

    #[test]
    fn endpoint_config_for_identity_selects_flowmux_and_carries_the_anchor() {
        let identity = FlowMuxIdentitySpawnConfig {
            session_id: "session-config".to_string(),
            host_signing_key_base64: "host-signing-key".to_string(),
            guest_verifying_key_base64: "guest-verifying-key".to_string(),
        };

        let config = endpoint_config_for_identity(Some(identity));
        assert_eq!(config["egress_mode"], "flow_mux");
        assert_eq!(
            config["flowmux_identity"]["guest_verifying_key_base64"],
            "guest-verifying-key"
        );
    }
    use super::*;
    use mvm_contract::stream::secret_fingerprint::SecretCategory;
    use mvm_core::util::test_env::TestEnv;

    static HOME_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// What a stub endpoint prints as its ready line: a well-formed handshake
    /// with one placeholder and one fingerprint, so the spawn path exercises
    /// the real split rather than a shape it never sees in production.
    const READY_HANDSHAKE: &str = r#"{"env":[["OPENAI_API_KEY","mvm-secret-ab"]],"input_fingerprints":[{"len":7,"hash":42,"category":"host-secret"}]}"#;

    // `stop_vm` reaps the moat BEFORE its not-running early return (so a crashed
    // VM's decrypted-secret endpoint can't outlive the guest). That ordering is
    // only safe because reap is a no-op when nothing exists — assert it here.
    #[test]
    fn reap_is_noop_when_nothing_exists() {
        let dir = std::env::temp_dir().join(format!("mvm-reap-noop-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        reap_network_endpoint(&dir, "nonexistent-vm");
        // Idempotent: a second call on the same empty dir is still clean.
        reap_network_endpoint(&dir, "nonexistent-vm");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spawned_endpoint_guard_cleans_both_sidecars_on_failure() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join(SUBST_PID_FILE);
        let env_file = dir.path().join("substitution.env.json");
        std::fs::write(&pid_file, child.id().to_string()).unwrap();
        std::fs::write(&env_file, b"sidecar").unwrap();

        {
            let mut guard = SpawnedEndpointGuard::new(child.id(), &pid_file, &env_file);
            guard.mark_pid_written();
            guard.mark_env_written();
        }

        assert!(!pid_file.exists());
        assert!(!env_file.exists());
        let _ = child.wait();
    }

    #[test]
    fn defused_spawned_endpoint_guard_does_not_signal_a_live_endpoint() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join(SUBST_PID_FILE);
        let env_file = dir.path().join("substitution.env.json");
        let mut guard = SpawnedEndpointGuard::new(child.id(), &pid_file, &env_file);
        guard.defuse();
        drop(guard);

        assert!(pid_alive(child.id() as libc::pid_t));
        child.kill().unwrap();
        let _ = child.wait();
    }

    #[test]
    fn empty_handshake_line_reports_eof_without_parsing() {
        let mut child = Command::new("sh")
            .args(["-c", "printf '\\n'"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().expect("child stdout is piped");
        let err = read_handshake_line(
            stdout,
            child.id(),
            Duration::from_secs(1),
            &HandshakeContext {
                endpoint: std::path::Path::new("/bin/sh"),
                stderr_log: None,
            },
        )
        .expect_err("an empty handshake line must fail");
        assert!(
            err.to_string()
                .contains("closed stdout without a ready handshake")
        );
        let _ = child.wait();
    }

    #[test]
    fn handshake_timeout_override_rejects_zero_and_junk() {
        assert_eq!(parse_handshake_timeout("90"), Some(Duration::from_secs(90)));
        assert_eq!(
            parse_handshake_timeout("  90 "),
            Some(Duration::from_secs(90))
        );
        // Zero would fail every spawn before the endpoint could answer.
        assert_eq!(parse_handshake_timeout("0"), None);
        assert_eq!(parse_handshake_timeout("soon"), None);
        assert_eq!(parse_handshake_timeout(""), None);
        assert_eq!(parse_handshake_timeout("-5"), None);
    }

    #[test]
    fn handshake_timeout_defaults_well_clear_of_a_cold_exec() {
        // The bound this replaced was 10s, which a cold helper exec behind a
        // multi-gigabyte disk write does not reliably meet.
        assert!(DEFAULT_HANDSHAKE_TIMEOUT >= Duration::from_secs(30));
    }

    #[test]
    fn stderr_tail_reports_none_for_missing_and_empty() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.log");
        assert_eq!(stderr_tail(&missing, 512), None);

        let empty = dir.path().join("empty.log");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(stderr_tail(&empty, 512), None);

        // Whitespace only is "wrote nothing" too — quoting it back is noise.
        let blank = dir.path().join("blank.log");
        std::fs::write(&blank, b"\n\n   \n").unwrap();
        assert_eq!(stderr_tail(&blank, 512), None);
    }

    #[test]
    fn stderr_tail_keeps_the_end_and_collapses_onto_one_line() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("e.log");
        std::fs::write(&log, b"first line\nsecond line\n").unwrap();
        assert_eq!(
            stderr_tail(&log, 4096).as_deref(),
            Some("first line second line")
        );
        // Bounded: the tail is what matters, the head is dropped. `"second
        // line\n"` is the last 12 bytes of the file.
        let tail = stderr_tail(&log, 12).expect("a bounded read still yields the tail");
        assert_eq!(tail, "second line");
    }

    #[test]
    fn timed_out_handshake_names_the_endpoint_and_quotes_its_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("endpoint.stderr.log");
        std::fs::write(&log, b"bind failed: Address already in use\n").unwrap();

        let mut child = Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().expect("child stdout is piped");
        let err = read_handshake_line(
            stdout,
            child.id(),
            Duration::from_millis(200),
            &HandshakeContext {
                endpoint: Path::new("/opt/mvm/mvm-network-endpoint"),
                stderr_log: Some(&log),
            },
        )
        .expect_err("a silent endpoint must time out");
        let msg = err.to_string();
        assert!(msg.contains("timed out"), "{msg}");
        // The three things the operator needs and used to have to guess.
        assert!(msg.contains("/opt/mvm/mvm-network-endpoint"), "{msg}");
        assert!(msg.contains("Address already in use"), "{msg}");
        assert!(msg.contains(HANDSHAKE_TIMEOUT_ENV), "{msg}");
        let _ = child.wait();
    }

    /// Clear every proxy name this reads, so a contributor whose own shell
    /// exports one does not get a different answer from CI.
    fn proxy_env() -> mvm_core::util::test_env::TestEnv {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        for k in [
            "https_proxy",
            "HTTPS_PROXY",
            "http_proxy",
            "HTTP_PROXY",
            "all_proxy",
            "ALL_PROXY",
            "no_proxy",
            "NO_PROXY",
        ] {
            env.remove(k);
        }
        env
    }

    /// Nothing configured is the common case, and it has to stay
    /// distinguishable from "configured with empty values" — the endpoint's
    /// default for absent keys is "dial direct", so a `Some` of all-`None`
    /// would emit keys that say nothing and mean something.
    #[test]
    fn an_unconfigured_host_carries_no_proxy_config() {
        let _env = proxy_env();
        assert_eq!(EgressProxySpawnConfig::from_host_env(), None);
    }

    /// The value has to survive the trip. A `Some` whose fields are all `None`
    /// looks configured and forwards nothing.
    #[test]
    fn a_configured_https_proxy_reaches_the_endpoint_config() {
        let mut env = proxy_env();
        env.set("https_proxy", "http://proxy.internal:3128");

        let cfg = EgressProxySpawnConfig::from_host_env()
            .expect("a host with https_proxy set is proxy-configured");
        assert_eq!(cfg.https.as_deref(), Some("http://proxy.internal:3128"));
        assert_eq!(cfg.http, None);
    }

    /// Either leg alone is a configured host. Requiring both would silently
    /// dial direct on a host that set only one, which is the shape most
    /// http-only and https-only environments actually have.
    #[test]
    fn either_proxy_leg_alone_configures_egress() {
        let mut env = proxy_env();
        env.set("http_proxy", "http://only-http:3128");
        let cfg = EgressProxySpawnConfig::from_host_env()
            .expect("http_proxy alone must configure egress");
        assert_eq!(cfg.http.as_deref(), Some("http://only-http:3128"));
        assert_eq!(cfg.https, None);
        drop(env);

        let mut env = proxy_env();
        env.set("HTTPS_PROXY", "http://only-https:3128");
        let cfg = EgressProxySpawnConfig::from_host_env()
            .expect("HTTPS_PROXY alone must configure egress");
        assert_eq!(cfg.https.as_deref(), Some("http://only-https:3128"));
        assert_eq!(cfg.http, None);
    }

    /// An exported-but-empty proxy var is how a shell spells "unset". Taking
    /// it literally hands the endpoint an empty upstream and every request
    /// fails to reach anything.
    #[test]
    fn an_empty_or_whitespace_proxy_var_reads_as_unset() {
        let mut env = proxy_env();
        env.set("https_proxy", "");
        env.set("http_proxy", "   ");
        assert_eq!(
            EgressProxySpawnConfig::from_host_env(),
            None,
            "an empty proxy value must not count as configured"
        );
    }

    /// `no_proxy` is an exception list, not a proxy. On its own it configures
    /// nothing, or every unproxied host would start emitting proxy keys.
    #[test]
    fn no_proxy_alone_does_not_configure_a_proxy() {
        let mut env = proxy_env();
        env.set("no_proxy", "localhost,127.0.0.1");
        assert_eq!(EgressProxySpawnConfig::from_host_env(), None);
    }

    /// all_proxy is the fallback for both legs, and must not override a
    /// specific one.
    #[test]
    fn all_proxy_fills_both_legs_but_yields_to_a_specific_one() {
        let mut env = proxy_env();
        env.set("all_proxy", "socks5://fallback:1080");
        env.set("https_proxy", "http://specific:3128");

        let cfg = EgressProxySpawnConfig::from_host_env().expect("configured");
        assert_eq!(cfg.https.as_deref(), Some("http://specific:3128"));
        assert_eq!(cfg.http.as_deref(), Some("socks5://fallback:1080"));
    }

    #[test]
    fn a_silent_endpoint_is_reported_as_silent_not_quoted_empty() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("endpoint.stderr.log");
        std::fs::write(&log, b"").unwrap();

        let mut child = Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().expect("child stdout is piped");
        let err = read_handshake_line(
            stdout,
            child.id(),
            Duration::from_millis(200),
            &HandshakeContext {
                endpoint: Path::new("/opt/mvm/mvm-network-endpoint"),
                stderr_log: Some(&log),
            },
        )
        .expect_err("a silent endpoint must time out");
        let msg = err.to_string();
        assert!(msg.contains("wrote nothing to"), "{msg}");
        assert!(msg.contains(&log.display().to_string()), "{msg}");
        let _ = child.wait();
    }

    #[test]
    fn a_non_handshake_line_is_refused() {
        // The builder path used to accept any non-empty line, so stray chrome
        // on a shared stdout read as a successful handshake there.
        let mut child = Command::new("sh")
            .args([
                "-c",
                "printf 'Preparing the builder VM...\\n'; exec sleep 30",
            ])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().expect("child stdout is piped");
        let err = read_handshake_line(
            stdout,
            child.id(),
            Duration::from_secs(5),
            &HandshakeContext {
                endpoint: Path::new("/opt/mvm/mvm-network-endpoint"),
                stderr_log: None,
            },
        )
        .expect_err("chrome is not a handshake");
        let msg = err.to_string();
        assert!(
            msg.contains("parse substitution endpoint handshake"),
            "{msg}"
        );
        assert!(msg.contains("/opt/mvm/mvm-network-endpoint"), "{msg}");
        // `read_handshake_line` already SIGKILLed it; reap so nextest sees no leak.
        let _ = child.wait();
    }

    #[test]
    fn a_well_formed_handshake_line_is_accepted() {
        let mut child = Command::new("sh")
            .args([
                "-c",
                &format!("printf '%s\\n' '{READY_HANDSHAKE}'; exec sleep 30"),
            ])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().expect("child stdout is piped");
        let handshake = read_handshake_line(
            stdout,
            child.id(),
            Duration::from_secs(5),
            &HandshakeContext {
                endpoint: Path::new("/opt/mvm/mvm-network-endpoint"),
                stderr_log: None,
            },
        )
        .expect("a well-formed handshake must parse");
        assert_eq!(handshake.env.len(), 1);
        assert_eq!(handshake.input_fingerprints.len(), 1);
        assert_eq!(
            handshake.input_fingerprints[0].category(),
            SecretCategory::HostSecret
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn endpoint_guard_reaps_armed_endpoint_and_sidecars() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", home.path());
        let vm = "endpoint-guard-armed";
        let state_dir = mvm_core::config::vm_state_dir(vm);
        std::fs::create_dir_all(&state_dir).unwrap();
        let env_path = mvm_core::config::vm_substitution_env_path(vm);
        std::fs::create_dir_all(env_path.parent().unwrap()).unwrap();
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        std::fs::write(state_dir.join(SUBST_PID_FILE), child.id().to_string()).unwrap();
        std::fs::write(&env_path, b"sidecar").unwrap();

        {
            let _guard = EndpointGuard::new(vm);
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut exited = child.try_wait().unwrap().is_some();
        while !exited && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
            exited = child.try_wait().unwrap().is_some();
        }
        if !exited {
            child.kill().unwrap();
            let _ = child.wait();
        }
        assert!(exited, "an armed endpoint guard must terminate its child");
        assert!(!state_dir.join(SUBST_PID_FILE).exists());
        assert!(!env_path.exists());
        let _ = child.wait();
    }

    #[test]
    fn defused_endpoint_guard_leaves_endpoint_and_sidecars_alone() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", home.path());
        let vm = "endpoint-guard-defused";
        let state_dir = mvm_core::config::vm_state_dir(vm);
        std::fs::create_dir_all(&state_dir).unwrap();
        let env_path = mvm_core::config::vm_substitution_env_path(vm);
        std::fs::create_dir_all(env_path.parent().unwrap()).unwrap();
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        std::fs::write(state_dir.join(SUBST_PID_FILE), child.id().to_string()).unwrap();
        std::fs::write(&env_path, b"sidecar").unwrap();

        {
            let mut guard = EndpointGuard::new(vm);
            guard.defuse();
        }

        assert!(pid_alive(child.id() as libc::pid_t));
        assert!(state_dir.join(SUBST_PID_FILE).exists());
        assert!(env_path.exists());
        child.kill().unwrap();
        let _ = child.wait();
    }

    // The libkrun/HVF transport: `spawn_network_endpoint` must serialize the
    // `Uds` variant into the config JSON the endpoint bin parses
    // (`{"kind":"uds","path":...}`). Drive it with a stub bin (via
    // `MVM_SUBSTITUTION_ENDPOINT_PATH`) that copies its stdin config to a file
    // for inspection and prints a one-line ready handshake.
    #[test]
    fn spawn_network_endpoint_emits_uds_transport() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut env = TestEnv::new();
        let dir = std::env::temp_dir().join(format!("mvm-subst-uds-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Route vm_substitution_env_path under a temp MVM_HOME so the write lands
        // somewhere disposable.
        env.set("MVM_HOME", &dir);

        // Stub endpoint: dump stdin (the config JSON) to a file, then emit one
        // handshake line so the spawn helper's read_handshake_line succeeds.
        let cfg_out = dir.join("captured-config.json");
        let stub = dir.join("stub-endpoint.sh");
        std::fs::write(
            &stub,
            format!(
                "{}cat > {}\necho '{}'\n",
                stub_preamble(),
                cfg_out.display(),
                READY_HANDSHAKE
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        env.set("MVM_SUBSTITUTION_ENDPOINT_PATH", &stub);

        // The spawn helper writes the minted (var→placeholder) handshake to
        // `vm_substitution_env_path` — ensure its parent dir exists under the root.
        if let Some(parent) = mvm_core::config::vm_substitution_env_path("uds-xport-vm").parent() {
            std::fs::create_dir_all(parent).unwrap();
        }

        let sock = dir.join("vsock-5253.sock");
        let redaction = mvm_core::policy::RedactionPolicy::default();
        let res = spawn_network_endpoint(SubstitutionSpawnParams {
            vm_name: "uds-xport-vm",
            state_dir: &dir,
            tenant: "tenant-x",
            secrets: &[],
            redaction: &redaction,
            transport: EndpointTransport::Uds { path: sock.clone() },
            terminator_listen: None,
            egress_proxy: None,
            session_marker: None,
            tls_intermediate: None,
            network_policy: None,
            network_limits: mvm_core::plan::NetworkLimits::default(),
            ingress: &[],
            resolver_remote: None,
            binding_store_dir: None,
            flowmux_identity: None,
        });

        res.expect("spawn with stub endpoint should succeed");

        let captured = std::fs::read_to_string(&cfg_out).expect("stub wrote config");
        let v: serde_json::Value = serde_json::from_str(&captured).expect("config is JSON");
        assert_eq!(v["transport"]["kind"], "uds");
        assert_eq!(v["transport"]["path"], sock.to_string_lossy().as_ref());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_handshakes_two_halves_go_to_two_different_places() {
        // The placeholders are the guest's and must survive into a later
        // `mvmctl` invocation, so they are persisted. The fingerprints are the
        // host's and must not, so they stay in this process. Sending either
        // one where the other goes is the whole failure this split prevents:
        // the sidecar would carry a length-and-hash disclosure to every reader
        // of the state dir, and the gate would find nothing to scan for.
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut env = TestEnv::new();
        let dir = std::env::temp_dir().join(format!("mvm-subst-split-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        env.set("MVM_HOME", &dir);

        let stub = dir.join("stub-endpoint.sh");
        std::fs::write(
            &stub,
            format!(
                "{}cat >/dev/null\necho '{READY_HANDSHAKE}'\n",
                stub_preamble()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        env.set("MVM_SUBSTITUTION_ENDPOINT_PATH", &stub);

        let vm = "handshake-split-vm";
        let env_path = mvm_core::config::vm_substitution_env_path(vm);
        if let Some(parent) = env_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let redaction = mvm_core::policy::RedactionPolicy::default();
        spawn_network_endpoint(SubstitutionSpawnParams {
            vm_name: vm,
            state_dir: &dir,
            tenant: "tenant-x",
            secrets: &[],
            redaction: &redaction,
            transport: EndpointTransport::Uds {
                path: dir.join("vsock-5253.sock"),
            },
            terminator_listen: None,
            egress_proxy: None,
            session_marker: None,
            tls_intermediate: None,
            network_policy: None,
            network_limits: mvm_core::plan::NetworkLimits::default(),
            ingress: &[],
            resolver_remote: None,
            binding_store_dir: None,
            flowmux_identity: None,
        })
        .expect("spawn with stub endpoint should succeed");

        let persisted = std::fs::read_to_string(&env_path).expect("the env sidecar");
        let placeholders: Vec<(String, String)> =
            serde_json::from_str(&persisted).expect("the sidecar keeps its array shape");
        assert_eq!(
            placeholders,
            vec![("OPENAI_API_KEY".to_string(), "mvm-secret-ab".to_string())]
        );
        assert!(
            !persisted.contains("input_fingerprints") && !persisted.contains("host-secret"),
            "no fingerprint may be written to disk: {persisted}"
        );

        let recorded = recorded_secret_fingerprints(vm);
        assert_eq!(recorded.len(), 1, "the gate's set came off the handshake");
        assert_eq!(recorded[0].len(), 7);
        assert_eq!(recorded[0].category(), SecretCategory::HostSecret);

        // And the reap that ends the endpoint ends the set with it, so a
        // recycled VM name cannot inherit a dead workload's shapes.
        reap_network_endpoint(&dir, vm);
        assert!(recorded_secret_fingerprints(vm).is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_handshake_that_is_not_a_handshake_fails_the_spawn() {
        // Fail closed. A line the spawner could not parse used to be written
        // to the env sidecar verbatim, so a broken endpoint produced a VM that
        // booted with no placeholders and no fingerprints and said nothing.
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut env = TestEnv::new();
        let dir = std::env::temp_dir().join(format!("mvm-subst-badline-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        env.set("MVM_HOME", &dir);

        let stub = dir.join("stub-endpoint.sh");
        std::fs::write(
            &stub,
            format!(
                "{}cat >/dev/null\necho 'ready handshake'\n",
                stub_preamble()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        env.set("MVM_SUBSTITUTION_ENDPOINT_PATH", &stub);

        let vm = "handshake-garbage-vm";
        let redaction = mvm_core::policy::RedactionPolicy::default();
        let err = spawn_network_endpoint(SubstitutionSpawnParams {
            vm_name: vm,
            state_dir: &dir,
            tenant: "tenant-x",
            secrets: &[],
            redaction: &redaction,
            transport: EndpointTransport::Uds {
                path: dir.join("vsock-5253.sock"),
            },
            terminator_listen: None,
            egress_proxy: None,
            session_marker: None,
            tls_intermediate: None,
            network_policy: None,
            network_limits: mvm_core::plan::NetworkLimits::default(),
            ingress: &[],
            resolver_remote: None,
            binding_store_dir: None,
            flowmux_identity: None,
        })
        .expect_err("an unparseable handshake is not a ready endpoint");
        assert!(
            err.to_string()
                .contains("parse substitution endpoint handshake"),
            "got {err}"
        );
        assert!(recorded_secret_fingerprints(vm).is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spawn_failure_after_pid_write_rolls_back_the_endpoint_sidecar() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut env = TestEnv::new();
        let dir = std::env::temp_dir().join(format!("mvm-subst-rollback-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state_dir = dir.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();

        let invalid_home = dir.join("mvm-home-file");
        std::fs::write(&invalid_home, b"not a directory").unwrap();
        let stub = dir.join("stub-endpoint.sh");
        let stopped = dir.join("stopped");
        let pid_capture = dir.join("endpoint.pid");
        // Arm the TERM trap BEFORE announcing readiness. The spawner only
        // proceeds to the rollback SIGTERM once it reads this handshake line, so
        // if the stub announced "ready" first, the SIGTERM could land in the gap
        // before `trap` runs — default-terminating the stub with no `stopped`
        // sentinel. Arming first makes the sentinel write deterministic instead
        // of racing the trap install under load. Do not reorder these two lines.
        std::fs::write(
            &stub,
            format!(
                "{}cat >/dev/null\necho $$ > {}\ntrap 'echo stopped > {}; exit 0' TERM\necho '{}'\nwhile :; do sleep 1; done\n",
                stub_preamble(),
                pid_capture.display(),
                stopped.display(),
                READY_HANDSHAKE
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        env.set("MVM_HOME", &invalid_home);
        env.set("MVM_SUBSTITUTION_ENDPOINT_PATH", &stub);

        let redaction = mvm_core::policy::RedactionPolicy::default();
        let result = spawn_network_endpoint(SubstitutionSpawnParams {
            vm_name: "rollback-vm",
            state_dir: &state_dir,
            tenant: "tenant-x",
            secrets: &[],
            redaction: &redaction,
            transport: EndpointTransport::Uds {
                path: dir.join("vsock-5253.sock"),
            },
            terminator_listen: None,
            egress_proxy: None,
            session_marker: None,
            tls_intermediate: None,
            network_policy: None,
            network_limits: mvm_core::plan::NetworkLimits::default(),
            ingress: &[],
            resolver_remote: None,
            binding_store_dir: None,
            flowmux_identity: None,
        });

        assert!(result.is_err(), "invalid MVM_HOME must fail sidecar setup");
        assert!(!state_dir.join(SUBST_PID_FILE).exists());

        // The stub is a shell script: it has to take the SIGTERM, run the
        // trap body and write the sentinel. One second of budget for that
        // is not a property of the rollback, it is a bet on how loaded the
        // host is. The deadline here is only a hang guard, so it is
        // generous; the poll interval sets the common-case cost.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !stopped.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let sentinel_written = stopped.exists();

        // Reap the stub whatever happened, but only after reading the
        // sentinel. SIGKILL cannot fire a TERM trap, so killing first
        // turns "the stub was slow" into "the sentinel can never appear"
        // — the previous order did exactly that, then asserted on the
        // outcome it had just foreclosed.
        if let Ok(pid) = std::fs::read_to_string(&pid_capture)
            && let Ok(pid) = pid.trim().parse::<libc::pid_t>()
        {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        std::fs::remove_dir_all(&dir).ok();

        assert!(
            sentinel_written,
            "rollback must terminate the endpoint process"
        );
    }

    // Build a minimal params (empty secrets, default redaction, UDS transport,
    // no terminator/TLS) so the pure JSON builder can be exercised without a spawn.
    fn minimal_params<'a>(
        redaction: &'a mvm_core::policy::RedactionPolicy,
        sock: &Path,
        network_policy: Option<&'a mvm_core::policy::network_policy::NetworkPolicy>,
    ) -> SubstitutionSpawnParams<'a> {
        SubstitutionSpawnParams {
            vm_name: "cfg-vm",
            state_dir: Path::new("/tmp"),
            tenant: "tenant-x",
            secrets: &[],
            redaction,
            transport: EndpointTransport::Uds {
                path: sock.to_path_buf(),
            },
            terminator_listen: None,
            egress_proxy: None,
            session_marker: None,
            tls_intermediate: None,
            network_policy,
            network_limits: mvm_core::plan::NetworkLimits::default(),
            ingress: &[],
            resolver_remote: None,
            binding_store_dir: None,
            flowmux_identity: None,
        }
    }

    // Legacy callers pass `None`/`false`: the config must omit `network_policy`
    // entirely (byte-identical to before) and default the egress mode to `wire`
    // (which equals the endpoint's own default). The base fields still present.
    #[test]
    fn endpoint_config_json_omits_policy_and_defaults_to_wire_when_legacy() {
        let redaction = mvm_core::policy::RedactionPolicy::default();
        let sock = Path::new("/tmp/vsock-5253.sock");
        let cfg = build_endpoint_config_json(&minimal_params(&redaction, sock, None));

        assert!(
            cfg.get("network_policy").is_none(),
            "legacy config must not carry a network_policy key"
        );
        assert_eq!(cfg["egress_mode"], "wire");
        // Base fields carried through the extraction.
        assert_eq!(cfg["tenant_id"], "tenant-x");
        assert_eq!(cfg["secrets"], serde_json::json!([]));
        assert_eq!(cfg["transport"]["kind"], "uds");
        // No remote resolver / binding_store_dir requested ⇒ the keys must be
        // entirely absent (not `null`) so `EndpointConfig`'s `#[serde(default)]`
        // fields fall back to `Local` / host-default, exactly like before these
        // two fields existed.
        assert!(cfg.get("resolver").is_none());
        assert!(cfg.get("binding_store_dir").is_none());
    }

    // A host that force-tunnels its egress reaches nothing without these keys,
    // and the endpoint's `#[serde(default)]` fields mean an omission is
    // indistinguishable from "dial direct" — so assert both directions.
    #[test]
    fn endpoint_config_json_omits_proxy_keys_when_none_is_configured() {
        let redaction = mvm_core::policy::RedactionPolicy::default();
        let sock = Path::new("/tmp/vsock-5253.sock");
        let cfg = build_endpoint_config_json(&minimal_params(&redaction, sock, None));
        for key in ["proxy_https", "proxy_http", "no_proxy"] {
            assert!(
                cfg.get(key).is_none(),
                "{key} must be absent, not null, so the endpoint default applies"
            );
        }
    }

    #[test]
    fn endpoint_config_json_carries_each_configured_proxy_leg() {
        let redaction = mvm_core::policy::RedactionPolicy::default();
        let sock = Path::new("/tmp/vsock-5253.sock");
        let mut params = minimal_params(&redaction, sock, None);
        params.egress_proxy = Some(EgressProxySpawnConfig {
            https: Some("http://secure.corp:3128".into()),
            http: Some("socks5://plain.corp:1080".into()),
            no_proxy: Some("internal.example".into()),
        });
        let cfg = build_endpoint_config_json(&params);
        assert_eq!(cfg["proxy_https"], "http://secure.corp:3128");
        assert_eq!(cfg["proxy_http"], "socks5://plain.corp:1080");
        assert_eq!(cfg["no_proxy"], "internal.example");
    }

    #[test]
    fn a_partially_configured_proxy_emits_only_the_leg_that_is_set() {
        let redaction = mvm_core::policy::RedactionPolicy::default();
        let sock = Path::new("/tmp/vsock-5253.sock");
        let mut params = minimal_params(&redaction, sock, None);
        params.egress_proxy = Some(EgressProxySpawnConfig {
            https: Some("http://secure.corp:3128".into()),
            ..Default::default()
        });
        let cfg = build_endpoint_config_json(&params);
        assert_eq!(cfg["proxy_https"], "http://secure.corp:3128");
        assert!(cfg.get("proxy_http").is_none());
        assert!(cfg.get("no_proxy").is_none());
    }

    // mvmd's tenant-secrets vault (D8 wiring) needs the endpoint to resolve
    // values over a UDS to its per-VM resolver daemon, and to read
    // allowed_hosts/auth_type bindings from a per-VM binding-store dir — not the
    // host defaults. Assert both land in the JSON exactly as
    // `mvm_hostd::supervisor::network_endpoint::EndpointConfig`'s
    // `#[serde(tag = "backend", rename_all = "snake_case")]` `ResolverBackend`
    // and `binding_store_dir` fields expect them shaped. Pure (no subprocess).
    #[test]
    fn endpoint_config_json_emits_remote_resolver_and_binding_store_dir() {
        let redaction = mvm_core::policy::RedactionPolicy::default();
        let sock = Path::new("/tmp/vsock-5253.sock");
        let resolver_uds = Path::new("/run/mvmd/tenant-x/resolver.sock");
        let binding_dir = Path::new("/var/lib/mvm/tenant-x/secret-bindings");
        let mut params = minimal_params(&redaction, sock, None);
        params.resolver_remote = Some(RemoteResolverSpawnConfig {
            uds_path: resolver_uds,
            timeout_secs: 5,
        });
        params.binding_store_dir = Some(binding_dir);
        let cfg = build_endpoint_config_json(&params);

        assert_eq!(cfg["resolver"]["backend"], "remote");
        assert_eq!(
            cfg["resolver"]["uds_path"],
            resolver_uds.to_string_lossy().as_ref()
        );
        assert_eq!(cfg["resolver"]["timeout_secs"], 5);
        assert_eq!(
            cfg["binding_store_dir"],
            binding_dir.to_string_lossy().as_ref()
        );
    }

    // The relay path: `Some(policy)` must land the policy in
    // the config (deserializing back to the same policy) and select `raw` mode.
    #[test]
    fn endpoint_config_json_carries_the_policy_it_was_given() {
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
        let redaction = mvm_core::policy::RedactionPolicy::default();
        let sock = Path::new("/tmp/vsock-5253.sock");
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("api.openai.com", 443)]);
        let cfg = build_endpoint_config_json(&minimal_params(&redaction, sock, Some(&policy)));

        // No identity on this params set, so the endpoint still speaks the
        // substitution protocol. "raw" is gone: nothing selects it and the
        // guest cannot speak it.
        assert_eq!(cfg["egress_mode"], "wire");
        let round: NetworkPolicy = serde_json::from_value(cfg["network_policy"].clone())
            .expect("network_policy deserializes back");
        assert_eq!(round, policy);
    }

    // The converged FlowMux path: identity material must land in the stdin
    // config so the endpoint can authenticate the guest and bind the session to
    // the plan's verifying key.
    #[test]
    fn endpoint_config_json_emits_flowmux_identity() {
        let redaction = mvm_core::policy::RedactionPolicy::default();
        let sock = Path::new("/tmp/vsock-5253.sock");
        let mut params = minimal_params(&redaction, sock, None);
        params.flowmux_identity = Some(FlowMuxIdentitySpawnConfig {
            session_id: "vm-123-boot-456".to_string(),
            host_signing_key_base64: "aG9zdC1rZXktYnl0ZXM".to_string(),
            guest_verifying_key_base64: "Z3Vlc3Qta2V5LWJ5dGVz".to_string(),
        });
        let cfg = build_endpoint_config_json(&params);

        assert_eq!(cfg["egress_mode"], "flow_mux");
        let id = cfg["flowmux_identity"]
            .as_object()
            .expect("flowmux_identity object");
        assert_eq!(id["session_id"], "vm-123-boot-456");
        assert_eq!(id["host_signing_key_base64"], "aG9zdC1rZXktYnl0ZXM");
        assert_eq!(id["guest_verifying_key_base64"], "Z3Vlc3Qta2V5LWJ5dGVz");
        assert_eq!(
            cfg["session_ready_socket"],
            serde_json::json!(Path::new("/tmp").join(SUBST_SESSION_READY_SOCKET))
        );
        assert_eq!(
            cfg["connector_uds_path"],
            serde_json::json!(Path::new("/tmp").join(SUBST_CONNECTOR_SOCKET))
        );
    }

    #[test]
    fn endpoint_config_json_carries_admitted_network_limits() {
        let redaction = mvm_core::policy::RedactionPolicy::default();
        let sock = Path::new("/tmp/vsock-5253.sock");
        let mut params = minimal_params(&redaction, sock, None);
        params.network_limits = mvm_core::plan::NetworkLimits::builder()
            .max_tcp_flows(7)
            .max_udp_associations(5)
            .max_dns_bindings(3)
            .max_ingress_listeners(2)
            .build()
            .unwrap();

        let cfg = build_endpoint_config_json(&params);
        let round: mvm_core::plan::NetworkLimits =
            serde_json::from_value(cfg["network_limits"].clone()).unwrap();
        assert_eq!(round, params.network_limits);
    }

    // ── the cert-to-guest / key-to-endpoint split ──

    // The whole point of the egress CA: the guest may trust the per-VM
    // intermediate cert (to accept host-terminated bound-host TLS), but the
    // intermediate KEY must never reach the guest — same claim-13 "no key on the
    // guest" invariant the substitution channel already upholds. Assert the
    // split holds by construction.
    #[test]
    fn egress_tls_delivery_gives_cert_to_guest_key_to_endpoint() {
        let dir = std::env::temp_dir().join(format!("mvm-egress-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let d = build_egress_tls_delivery(&["api.openai.com"], &dir).unwrap();

        // The guest file is a cert at the fixed drive filename, world-readable.
        assert_eq!(d.guest_cert.name, EGRESS_CERT_DRIVE_NAME);
        assert_eq!(d.guest_cert.mode, 0o444);
        assert!(d.guest_cert.content.contains("BEGIN CERTIFICATE"));

        // The endpoint gets BOTH halves (it serves leaves under this intermediate).
        assert!(d.endpoint_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(d.endpoint_key_pem.contains("PRIVATE KEY"));

        // INVARIANT: no private-key material reaches the guest-delivered file.
        assert!(
            !d.guest_cert.content.contains("PRIVATE KEY"),
            "intermediate key leaked into the guest cert file"
        );
        // The guest must trust exactly the cert the endpoint terminates under.
        assert_eq!(d.guest_cert.content.trim(), d.endpoint_cert_pem.trim());

        std::fs::remove_dir_all(&dir).ok();
    }

    // The key-carrying delivery struct must not expose secret bytes via Debug
    // (xtask check-no-display-on-secret-types parity).
    #[test]
    fn egress_tls_delivery_debug_is_redacted() {
        let dir = std::env::temp_dir().join(format!("mvm-egress-ca-dbg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let d = build_egress_tls_delivery(&["api.openai.com"], &dir).unwrap();
        let dbg = format!("{d:?}");
        assert!(
            !dbg.contains("PRIVATE KEY"),
            "key bytes leaked via Debug: {dbg}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod substitution_spawn_params_builder_tests {
    use super::*;

    /// An empty builder must refuse to finish, naming the first
    /// required field it is missing — never substituting a default.
    #[test]
    fn an_empty_builder_names_the_first_missing_field() {
        let Err(err) = SubstitutionSpawnParams::builder().build() else {
            panic!("an empty SubstitutionSpawnParams builder must not build");
        };
        assert_eq!(
            err,
            BuilderError::missing("SubstitutionSpawnParams", "vm_name")
        );
    }
}
