//! Shared per-VM substitution-endpoint spawn/reap helpers.
//!
//! One implementation behind the two workload backends that need it (QEMU
//! slirp + Firecracker TAP), so the moat-spawn logic can't drift between
//! copies. The endpoint is `mvm-substitution-endpoint` (an `mvm-hostd` bin):
//! when the admitted plan carries secret bindings it runs as a per-VM host
//! process that resolves placeholders for the guest's egress so the real
//! secret never enters the guest. The QEMU caller passes `terminator_listen:
//! None` (slirp has no TAP to redirect); the FC caller passes `Some(addr)` to
//! turn on the transparent HTTP terminator that the nft TAP REDIRECT feeds.

use crate::microvm::DriveFile;
use anyhow::{Result, anyhow, bail};
use mvm_core::crypto::egress_ca::EgressCa;
use mvm_core::plan::SecretBinding;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// How the guest reaches the substitution endpoint. Backend-shaped: QEMU's
/// `vhost-vsock` gives a real guest→host AF_VSOCK path, so the host binds an
/// AF_VSOCK listener; Firecracker/libkrun route guest→host through a per-port
/// UDS the in-process VMM proxies, so the host binds that UDS.
///
/// This is the wire contract the `mvm-substitution-endpoint` bin parses on
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

/// Read the per-VM egress intermediate (`cert_pem` + `key_pem`) persisted under
/// `<state_dir>/egress-intermediate.json`. Returns `None` when absent.
pub fn read_egress_intermediate(state_dir: &Path) -> Result<Option<(String, String)>> {
    let path = state_dir.join("egress-intermediate.json");
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow!("read {}: {e}", path.display())),
    };
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| anyhow!("parse {}: {e}", path.display()))?;
    let cert = v["cert_pem"].as_str();
    let key = v["key_pem"].as_str();
    match (cert, key) {
        (Some(c), Some(k)) => Ok(Some((c.to_string(), k.to_string()))),
        _ => Err(anyhow!("{} missing cert_pem/key_pem", path.display())),
    }
}

/// PID of the per-VM `mvm-substitution-endpoint` moat, and the JSON
/// file holding the `(guest var, placeholder)` env pairs it minted (the invoke
/// path reads this to inject `HTTP_PROXY` + placeholder vars). Spawned only when
/// the admitted plan carries secret bindings.
pub const SUBST_PID_FILE: &str = "substitution.pid";
/// How long the endpoint gets to bind its listener + write the ready handshake
/// line before the caller declares the spawn failed.
pub const SUBST_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Locate the `mvm-substitution-endpoint` binary: `MVM_SUBSTITUTION_ENDPOINT_PATH`
/// override → sibling of the current exe → workspace `target/{release,debug}`.
/// Mirrors `resolve_vz_drainer_path`.
fn resolve_substitution_endpoint_path() -> Result<PathBuf> {
    const BIN: &str = "mvm-substitution-endpoint";
    if let Some(p) = std::env::var_os("MVM_SUBSTITUTION_ENDPOINT_PATH").map(PathBuf::from) {
        if p.is_file() {
            return Ok(p);
        }
        bail!(
            "MVM_SUBSTITUTION_ENDPOINT_PATH points at {} which is not a file",
            p.display()
        );
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
    {
        let candidate = dir.join(BIN);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(workspace_root) = manifest_dir.parent().and_then(Path::parent) {
        for variant in ["release", "debug"] {
            let candidate = workspace_root.join("target").join(variant).join(BIN);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    bail!("could not locate the {BIN} binary (set MVM_SUBSTITUTION_ENDPOINT_PATH)")
}

/// Inputs to [`spawn_substitution_endpoint`]. Grouped into a struct (rather
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
    /// (libkrun/vz, the per-VM socket the VMM proxies).
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
        // (Vsock); libkrun/vz route through the per-VM UDS the VMM proxies (Uds).
        "transport": serde_json::to_value(&params.transport)
            .expect("EndpointTransport serializes to JSON"),
        // Which egress protocol the relayed stream carries. Always emit: an
        // explicit "wire" is identical to the endpoint's default, so legacy
        // callers stay backward compatible.
        "egress_mode": if params.raw_egress { "raw" } else { "wire" },
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
    cfg
}

/// Spawn the per-VM `mvm-substitution-endpoint` moat. Hands it the
/// plan's secret bindings on stdin, reads back the minted `(guest var,
/// placeholder)` handshake line, and persists it to the per-VM substitution env
/// file for the invoke path to inject (`HTTP_PROXY` + placeholder vars). The
/// endpoint serves the guest→host substitution channel over `transport`; when
/// `terminator_listen` is `Some`, it *also* runs the transparent HTTP
/// terminator on that host TCP addr — the FC nft TAP REDIRECT steers guest :80
/// there. Detached via `setsid` so it outlives `mvmctl up`; the stop path reaps
/// it via [`SUBST_PID_FILE`]. The real secret values never leave the endpoint's
/// address space — only the opaque placeholders are persisted/handed out.
pub fn spawn_substitution_endpoint(params: SubstitutionSpawnParams<'_>) -> Result<()> {
    use std::io::Write;
    let cfg = build_endpoint_config_json(&params);
    let SubstitutionSpawnParams {
        vm_name, state_dir, ..
    } = params;

    let bin = resolve_substitution_endpoint_path()?;

    let mut cmd = Command::new(&bin);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    // Detach into its own session so it survives this `mvmctl` process.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            // SAFETY: post-fork, pre-exec; setsid has no preconditions.
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("spawn substitution endpoint ({}): {e}", bin.display()))?;

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

    let pid_file = state_dir.join(SUBST_PID_FILE);
    std::fs::write(&pid_file, child.id().to_string())
        .map_err(|e| anyhow!("write {}: {e}", pid_file.display()))?;
    let env_path = mvm_core::config::vm_substitution_env_path(vm_name);
    std::fs::write(&env_path, handshake.trim().as_bytes())
        .map_err(|e| anyhow!("write {}: {e}", env_path.display()))?;
    // Detach: drop the child handle without killing. The endpoint runs
    // daemonized (setsid) and is reaped by the stop path via SUBST_PID_FILE.
    Ok(())
}

/// Read the endpoint's one-line ready handshake from its stdout within
/// `timeout`. A blocking pipe read can't be timed directly, so read on a
/// helper thread and bound the wait; on timeout / EOF-without-line, SIGKILL
/// the endpoint and fail (the caller rolls back the VM — fail closed).
fn read_handshake_line(
    stdout: std::process::ChildStdout,
    pid: u32,
    timeout: Duration,
) -> Result<String> {
    use std::io::{BufRead, BufReader};
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let res = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = tx.send(res);
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(line)) if !line.trim().is_empty() => Ok(line),
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
/// libkrun and vz backends — one definition so the spawn/reap moat can't drift.
pub(crate) struct EndpointGuard {
    /// `Some(name)` while armed; `None` once defused. Read by backend tests to
    /// assert the no-secrets path yields a no-op guard.
    pub(crate) vm_name: Option<String>,
}

impl EndpointGuard {
    pub(crate) fn new(vm_name: &str) -> Self {
        Self {
            vm_name: Some(vm_name.to_string()),
        }
    }
    /// A guard for a VM that spawned no endpoint (no secrets) — Drop is a no-op.
    pub(crate) fn defused() -> Self {
        Self { vm_name: None }
    }
    pub(crate) fn defuse(&mut self) {
        self.vm_name = None;
    }
}

impl Drop for EndpointGuard {
    fn drop(&mut self) {
        if let Some(ref name) = self.vm_name {
            tracing::warn!(vm = %name, "EndpointGuard: reaping orphaned substitution endpoint");
            reap_substitution_endpoint(&mvm_core::config::vm_state_dir(name), name);
        }
    }
}

/// Reap the per-VM substitution endpoint (if this VM spawned one) so its
/// decrypted secrets don't outlive the guest, and drop the pid + env sidecars.
/// Best-effort + idempotent: a VM with no endpoint (no secrets) is a no-op. The
/// liveness guard prevents signalling a recycled PID from a stale pidfile.
pub fn reap_substitution_endpoint(state_dir: &Path, vm_name: &str) {
    if let Some(spid) = read_pid(&state_dir.join(SUBST_PID_FILE))
        && pid_alive(spid)
    {
        kill(spid, libc::SIGTERM);
    }
    let _ = std::fs::remove_file(state_dir.join(SUBST_PID_FILE));
    let _ = std::fs::remove_file(mvm_core::config::vm_substitution_env_path(vm_name));
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

    // `stop_vm` reaps the moat BEFORE its not-running early return (so a crashed
    // VM's decrypted-secret endpoint can't outlive the guest). That ordering is
    // only safe because reap is a no-op when nothing exists — assert it here.
    #[test]
    fn reap_is_noop_when_nothing_exists() {
        let dir = std::env::temp_dir().join(format!("mvm-reap-noop-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        reap_substitution_endpoint(&dir, "nonexistent-vm");
        // Idempotent: a second call on the same empty dir is still clean.
        reap_substitution_endpoint(&dir, "nonexistent-vm");
        std::fs::remove_dir_all(&dir).ok();
    }

    // The libkrun/vz transport: `spawn_substitution_endpoint` must serialize the
    // `Uds` variant into the config JSON the endpoint bin parses
    // (`{"kind":"uds","path":...}`). Drive it with a stub bin (via
    // `MVM_SUBSTITUTION_ENDPOINT_PATH`) that copies its stdin config to a file
    // for inspection and prints a one-line ready handshake.
    #[test]
    fn spawn_substitution_endpoint_emits_uds_transport() {
        let _g = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("mvm-subst-uds-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let saved_home = std::env::var_os("HOME");
        // Route vm_substitution_env_path under our temp HOME so the write lands
        // somewhere disposable.
        // SAFETY: serialised by HOME_TEST_LOCK.
        unsafe { std::env::set_var("HOME", &dir) };

        // Stub endpoint: dump stdin (the config JSON) to a file, then emit one
        // handshake line so the spawn helper's read_handshake_line succeeds.
        let cfg_out = dir.join("captured-config.json");
        let stub = dir.join("stub-endpoint.sh");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\ncat > {}\necho 'ready handshake'\n",
                cfg_out.display()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let saved_bin = std::env::var_os("MVM_SUBSTITUTION_ENDPOINT_PATH");
        // SAFETY: serialised by HOME_TEST_LOCK.
        unsafe { std::env::set_var("MVM_SUBSTITUTION_ENDPOINT_PATH", &stub) };

        // The spawn helper writes the minted (var→placeholder) handshake to
        // `vm_substitution_env_path` — ensure its parent dir exists under HOME.
        if let Some(parent) = mvm_core::config::vm_substitution_env_path("uds-xport-vm").parent() {
            std::fs::create_dir_all(parent).unwrap();
        }

        let sock = dir.join("vsock-5253.sock");
        let redaction = mvm_core::policy::RedactionPolicy::default();
        let res = spawn_substitution_endpoint(SubstitutionSpawnParams {
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
        });

        // Restore env before asserting so a failure can't leak it.
        unsafe {
            match saved_bin {
                Some(v) => std::env::set_var("MVM_SUBSTITUTION_ENDPOINT_PATH", v),
                None => std::env::remove_var("MVM_SUBSTITUTION_ENDPOINT_PATH"),
            }
            match saved_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        res.expect("spawn with stub endpoint should succeed");

        let captured = std::fs::read_to_string(&cfg_out).expect("stub wrote config");
        let v: serde_json::Value = serde_json::from_str(&captured).expect("config is JSON");
        assert_eq!(v["transport"]["kind"], "uds");
        assert_eq!(v["transport"]["path"], sock.to_string_lossy().as_ref());

        std::fs::remove_dir_all(&dir).ok();
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
