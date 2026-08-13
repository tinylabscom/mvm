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
use anyhow::{Result, anyhow, bail};
use mvm_contract::stream::secret_fingerprint::SecretFingerprint;
use mvm_core::crypto::egress_ca::EgressCa;
use mvm_core::plan::SecretBinding;
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
/// How long the endpoint gets to bind its listener + write the ready handshake
/// line before the caller declares the spawn failed.
pub const SUBST_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Locate the `mvm-network-endpoint` binary. Compiled by mvmctl's build
/// script; see [`mvm_vmm::host::aux_bin`] for the search order.
fn resolve_network_endpoint_path() -> Result<PathBuf> {
    crate::host::aux_bin::resolve(&crate::host::aux_bin::AuxBin {
        bin: "mvm-network-endpoint",
        env_var: "MVM_SUBSTITUTION_ENDPOINT_PATH",
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
    /// `(cert_pem, key_pem)` of the per-VM intermediate for the `https`
    /// terminator; the key never reaches the guest. `None` ⇒ `http`-only.
    pub tls_intermediate: Option<(String, String)>,
    /// The VM's resolved claim-10 network policy. `Some` ⇒ the endpoint gates
    /// egress itself (the relay path — the run loop no longer gates); `None` ⇒
    /// ungated here (the legacy in-loop gate is the enforcer).
    pub network_policy: Option<&'a mvm_core::policy::network_policy::NetworkPolicy>,
    /// True ⇒ the guest speaks raw TCP egress (`host:port` first line) and the
    /// endpoint serves `egress_mode: "raw"`; false ⇒ the WireRequest substitution
    /// protocol (`"wire"`, the default). A VM's mode is fixed at admission.
    pub raw_egress: bool,
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
        // Which egress protocol the relayed stream carries. Always emit: an
        // explicit "wire" is identical to the endpoint's default, so legacy
        // callers stay backward compatible.
        "egress_mode": if params.flowmux_identity.is_some() {
            "flow_mux"
        } else if params.raw_egress {
            "raw"
        } else {
            "wire"
        },
    });
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
pub fn spawn_network_endpoint(params: SubstitutionSpawnParams<'_>) -> Result<()> {
    use std::io::Write;
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
    let handshake = read_handshake_line(stdout, child.id(), SUBST_HANDSHAKE_TIMEOUT)?;

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
fn read_handshake_line(
    stdout: std::process::ChildStdout,
    pid: u32,
    timeout: Duration,
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
            anyhow!("parse substitution endpoint handshake: {e}")
        }),
        Ok(Ok(_)) => {
            kill(pid as libc::pid_t, libc::SIGKILL);
            bail!("substitution endpoint closed stdout without a ready handshake")
        }
        Ok(Err(e)) => {
            kill(pid as libc::pid_t, libc::SIGKILL);
            bail!("read substitution endpoint handshake: {e}")
        }
        Err(_) => {
            kill(pid as libc::pid_t, libc::SIGKILL);
            bail!("substitution endpoint handshake timed out after {timeout:?}")
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
        let err = read_handshake_line(stdout, child.id(), Duration::from_secs(1))
            .expect_err("an empty handshake line must fail");
        assert!(
            err.to_string()
                .contains("closed stdout without a ready handshake")
        );
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
                "#!/bin/sh\ncat > {}\necho '{}'\n",
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
            tls_intermediate: None,
            network_policy: None,
            raw_egress: false,
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
            format!("#!/bin/sh\ncat >/dev/null\necho '{READY_HANDSHAKE}'\n"),
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
            tls_intermediate: None,
            network_policy: None,
            raw_egress: false,
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
        std::fs::write(&stub, "#!/bin/sh\ncat >/dev/null\necho 'ready handshake'\n").unwrap();
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
            tls_intermediate: None,
            network_policy: None,
            raw_egress: false,
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
                "#!/bin/sh\ncat >/dev/null\necho $$ > {}\ntrap 'echo stopped > {}; exit 0' TERM\necho '{}'\nwhile :; do sleep 1; done\n",
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
            tls_intermediate: None,
            network_policy: None,
            raw_egress: false,
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
        raw_egress: bool,
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
            tls_intermediate: None,
            network_policy,
            raw_egress,
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
        let cfg = build_endpoint_config_json(&minimal_params(&redaction, sock, None, false));

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
        let mut params = minimal_params(&redaction, sock, None, false);
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

    // The relay path: `Some(policy)` + `raw_egress: true` must land the policy in
    // the config (deserializing back to the same policy) and select `raw` mode.
    #[test]
    fn endpoint_config_json_carries_policy_and_raw_when_set() {
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
        let redaction = mvm_core::policy::RedactionPolicy::default();
        let sock = Path::new("/tmp/vsock-5253.sock");
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("api.openai.com", 443)]);
        let cfg =
            build_endpoint_config_json(&minimal_params(&redaction, sock, Some(&policy), true));

        assert_eq!(cfg["egress_mode"], "raw");
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
        let mut params = minimal_params(&redaction, sock, None, false);
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
