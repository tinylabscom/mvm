// ============================================================================
// mvm-bridge spawn + watchdog (Linux only), plus the kernel-cmdline token
// builders (egress CA, secret placeholders, verb-grant) every backend reads
// from the per-VM state dir.
//
// An attached-then-detached child-process guard: Drop kills+waits the child on
// early return, `detach()` hands ownership to the caller which records the PID
// in `<state_dir>/fc-bridge.pid` and lets the watchdog thread inherit it.
// The bridge is Linux-only so every helper is `#[cfg(target_os = "linux")]`;
// non-Linux builds compile but never call into this path.
// ============================================================================

#[cfg(target_os = "linux")]
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use tracing::warn;

#[cfg(any(target_os = "linux", test))]
use super::flake_run::FlakeRunConfig;
#[cfg(target_os = "linux")]
use super::guards::EndpointGuard;

/// PID file the bridge watchdog writes inside `<abs_dir>`. Lives next
/// to `fc.pid` so the watchdog (and a future `stop_vm` reaper) can find
/// the bridge with the same `<abs_dir>` it already resolves for the
/// FC VM itself.
#[cfg(target_os = "linux")]
const FC_BRIDGE_PID_FILE_NAME: &str = "fc-bridge.pid";

/// RAII guard for a spawned `mvm-bridge` child: dropping the guard kills +
/// waits the child so an early return / panic between bridge spawn
/// and VM boot completion cleans up the bridge process.
///
/// After successful boot, `detach_and_spawn_bridge_watchdog` takes
/// the `Child` out via `.take()`; the watchdog thread inherits the
/// handle and the OS keeps the bridge alive.
#[cfg(target_os = "linux")]
pub(super) struct AttachedBridgeGuard {
    pub(super) child: Option<std::process::Child>,
}

#[cfg(target_os = "linux")]
impl AttachedBridgeGuard {
    /// Hand off the spawned bridge to the OS — used after the FC VM
    /// boots cleanly so the bridge outlives `run_from_build`'s stack
    /// frame. Returns the `Child` for the caller to record its PID
    /// in the on-disk reaper file before the handle is dropped
    /// without `kill()` firing.
    fn detach(&mut self) -> Option<std::process::Child> {
        self.child.take()
    }
}

#[cfg(target_os = "linux")]
impl Drop for AttachedBridgeGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let pid = c.id();
            if let Err(e) = c.kill() {
                warn!(
                    bridge_pid = pid,
                    error = %e,
                    "AttachedBridgeGuard: kill mvm-bridge failed on drop"
                );
            }
            if let Err(e) = c.wait() {
                warn!(
                    bridge_pid = pid,
                    error = %e,
                    "AttachedBridgeGuard: wait mvm-bridge failed on drop"
                );
            }
        }
    }
}

/// Resolve `MVM_PASST_PATH` (or default `/usr/bin/passt`) without
/// touching std::env in tests. Pure helper so the bridge spawn block
/// stays compact.
#[cfg(target_os = "linux")]
fn passt_path_from_env_or_default() -> std::path::PathBuf {
    std::env::var_os("MVM_PASST_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/bin/passt"))
}

/// Resolve the `mvm-bridge` binary path, checking three
/// sources in order. Pure resolver — exercised directly from tests
/// without touching `std::env`.
#[cfg(target_os = "linux")]
fn resolve_fc_bridge_path_inner(
    env_override: Option<&std::path::Path>,
    current_exe: Option<&std::path::Path>,
    manifest_dir: &std::path::Path,
) -> Result<std::path::PathBuf> {
    if let Some(path) = env_override {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        anyhow::bail!(
            "MVM_BRIDGE_PATH points at {} which is not a file",
            path.display()
        );
    }
    if let Some(exe) = current_exe
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("mvm-bridge");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    // Workspace target dir — `crates/mvm-runtime` → workspace root is
    // two `..` up; the target dir is rooted there.
    if let Some(workspace_root) = manifest_dir.parent().and_then(std::path::Path::parent) {
        for variant in ["release", "debug"] {
            let candidate = workspace_root
                .join("target")
                .join(variant)
                .join("mvm-bridge");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    anyhow::bail!(
        "mvm-bridge binary not found. Looked for: $MVM_BRIDGE_PATH, \
         alongside the current exe, and <workspace>/target/{{release,debug}}/mvm-bridge. \
         Build with `cargo build -p mvm-vm-host --bin mvm-bridge`."
    )
}

/// Production wrapper around `resolve_fc_bridge_path_inner` that
/// reads `std::env` + `current_exe` + `CARGO_MANIFEST_DIR`. Keep the
/// test seam in `_inner` so unit tests don't race on env state.
#[cfg(target_os = "linux")]
fn resolve_fc_bridge_path() -> Result<std::path::PathBuf> {
    let env_override = std::env::var_os("MVM_BRIDGE_PATH").map(std::path::PathBuf::from);
    let current_exe = std::env::current_exe().ok();
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    resolve_fc_bridge_path_inner(
        env_override.as_deref(),
        current_exe.as_deref(),
        &manifest_dir,
    )
}

/// Spawn the per-VM substitution endpoint **before** the guest boots,
/// so the `(var → placeholder)` pairs it mints (and
/// writes to `vm_substitution_env_path`) are available when `boot_args` is built
/// and can ride the cmdline (`mvm.secret_env=`) into a sealed entrypoint. Binds
/// the terminator listener too; the nft REDIRECT that feeds it is installed
/// post-boot by [`install_egress_redirect`] (it needs the guest's TAP). No-op
/// when the plan carries no egress secrets. Returns an armed [`EndpointGuard`]
/// the caller defuses once the VM is fully up.
#[cfg(target_os = "linux")]
pub(super) fn spawn_egress_endpoint(config: &FlakeRunConfig) -> Result<EndpointGuard> {
    use crate::egress_redirect::terminator_port_for;
    use crate::substitution_spawn::spawn_substitution_endpoint;
    use std::net::SocketAddr;

    let name = &config.slot.name;
    let state_dir = mvm_core::config::vm_state_dir(name);
    let Some((secrets, redaction, tenant)) =
        crate::egress_shared::decode_plan_secrets_from_state(&state_dir)?
    else {
        return Ok(EndpointGuard { vm_name: None });
    };

    // Per-slot terminator port so concurrent VMs never collide host-side.
    // 0.0.0.0: a PREROUTING REDIRECT delivers the forwarded packet to a local
    // socket on the host, so the terminator must accept on the host's addrs.
    let term_port = terminator_port_for(config.slot.index);
    let listen = SocketAddr::from(([0, 0, 0, 0], term_port));
    // `mvmctl up` staged the per-VM name-constrained intermediate (cert+key) in
    // the sidecar. Hand the KEY to the endpoint so the `https` terminator can
    // mint per-SNI leaves; it never reaches the guest. Absent ⇒ `http`-only.
    let tls_intermediate = crate::substitution_spawn::read_egress_intermediate(&state_dir)?;
    spawn_substitution_endpoint(crate::substitution_spawn::SubstitutionSpawnParams {
        vm_name: name,
        state_dir: &state_dir,
        tenant: &tenant,
        secrets: &secrets,
        redaction: &redaction,
        transport: crate::substitution_spawn::EndpointTransport::Vsock {
            port: mvm_agentd::vsock::EGRESS_PORT,
        },
        terminator_listen: Some(listen),
        tls_intermediate,
        network_policy: None,
        raw_egress: false,
    })?;
    Ok(EndpointGuard::new(name))
}

/// Install the per-VM nft TAP REDIRECT (`:80`/`:443` → the terminator)
/// **after** the guest boots (the TAP exists). No-op when the plan carries no
/// egress secrets. Persists the table so it outlives this frame; `stop_vm`
/// removes it by name.
#[cfg(target_os = "linux")]
pub(super) fn install_egress_redirect(config: &FlakeRunConfig) -> Result<()> {
    use crate::egress_redirect::{EgressRedirect, terminator_port_for};

    let name = &config.slot.name;
    let state_dir = mvm_core::config::vm_state_dir(name);
    if crate::egress_shared::decode_plan_secrets_from_state(&state_dir)?.is_none() {
        return Ok(());
    }
    let term_port = terminator_port_for(config.slot.index);
    let redirect = EgressRedirect::install(name, &config.slot.tap_dev, term_port)?;
    redirect.persist();
    Ok(())
}

#[cfg(test)]
fn network_tunnel_cmdline_token(config: &FlakeRunConfig) -> Option<String> {
    config
        .network_tunnel
        .as_ref()
        .and_then(mvm_core::vm_backend::encode_network_tunnel_cmdline)
}

/// The `mvm.egress_ca=<hex>` kernel-cmdline token for `vm_name`,
/// or `None` when the VM has no staged intermediate (no secrets / no https leg).
/// Reads the **cert** from the per-VM `egress-intermediate.json` sidecar (the key
/// is never put on the cmdline / in the guest). Best-effort: a malformed/missing
/// sidecar yields `None` rather than blocking boot — the worst case is the guest
/// can't trust host-terminated TLS, and the claim-12 host allow-list still holds.
pub(super) fn egress_ca_cmdline_token(vm_name: &str) -> Option<String> {
    let path = mvm_core::config::vm_state_dir(vm_name).join("egress-intermediate.json");
    let bytes = std::fs::read(&path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let cert = v["cert_pem"].as_str()?;
    mvm_core::vm_backend::encode_egress_ca_cmdline(cert)
}

/// The `mvm.secret_env=<hex>` cmdline token for `vm_name`, or `None`
/// when the VM has no secrets. Reads the `(var, placeholder)`
/// pairs the pre-boot substitution endpoint minted into `vm_substitution_env_path`
/// (a JSON array of `[var, placeholder]`) and encodes them — **placeholders only**,
/// never values (claim 13). Best-effort: a missing/malformed handshake yields
/// `None` rather than blocking boot.
pub(super) fn secret_env_cmdline_token(vm_name: &str) -> Option<String> {
    let path = mvm_core::config::vm_substitution_env_path(vm_name);
    let bytes = std::fs::read(&path).ok()?;
    let pairs: Vec<(String, String)> = serde_json::from_slice(&bytes).ok()?;
    mvm_core::vm_backend::encode_secret_env_cmdline(&pairs)
}

/// The `mvm.verb_grant=<hex>` cmdline token for `vm_name`, or `None` when
/// no verb-grant sidecar was minted (plan carried no `agent_verbs`). Reads
/// the envelope the admission path wrote to `<vm_state_dir>/verb-grant.json`
/// and encodes it. Best-effort: a missing or malformed sidecar yields `None`
/// (grant-less boot), mirroring `secret_env_cmdline_token`.
///
/// Exported as `pub(crate)` so the libkrun, HVF, and QEMU cmdline builders
/// can append the same token without duplicating the sidecar-read logic.
pub(crate) fn verb_grant_cmdline_token(vm_name: &str) -> Option<String> {
    let path = mvm_core::config::vm_state_dir(vm_name).join("verb-grant.json");
    let bytes = std::fs::read(&path).ok()?;
    let envelope: mvm_core::protocol::vm_backend::VerbGrantEnvelope =
        serde_json::from_slice(&bytes).ok()?;
    mvm_core::vm_backend::encode_verb_grant_cmdline(&envelope)
}

/// The `mvm.require_grant=1` cmdline token for `vm_name`, or `None` when no
/// verb-grant sidecar was minted. Keyed on the sidecar file EXISTING (not a
/// successful decode): a launcher that minted a grant asserts enforcement even
/// if the grant token fails to encode (corrupt sidecar), so the guest fails
/// closed rather than running grant-less. Bypassed entirely by direct-launch
/// paths that never build this cmdline (e.g. the fleet orchestrator), so those
/// instances never assert enforcement.
pub(crate) fn require_grant_cmdline_token(vm_name: &str) -> Option<String> {
    let path = mvm_core::config::vm_state_dir(vm_name).join("verb-grant.json");
    path.exists().then(|| "mvm.require_grant=1".to_string())
}

/// Filename of the host-signer public verifying key under the keys dir. The raw
/// 32-byte Ed25519 public key the grant is verified against.
const HOST_SIGNER_PUBKEY_FILENAME: &str = "host-signer.pub";

/// The `mvm.host_signer_pub=<hex>` cmdline token for `vm_name`, or `None` when
/// no verb-grant sidecar was minted (plan carried no `agent_verbs`).
///
/// Delivers the host-signer public verifying key — the grant trust anchor — out
/// of band on the kernel cmdline. On the block backends the anchor rides the
/// config drive, but a sealed vsock-only guest has no config drive, so the
/// cmdline is its only per-VM channel. This is a public key, safe on
/// `/proc/cmdline`. Keyed on the same sidecar the grant token reads, so the
/// anchor is present exactly when a grant is. Best-effort: a missing or
/// wrong-sized key file yields `None`, degrading to a grant-less boot rather
/// than blocking.
pub(crate) fn host_signer_pub_cmdline_token(vm_name: &str) -> Option<String> {
    let sidecar = mvm_core::config::vm_state_dir(vm_name).join("verb-grant.json");
    if !sidecar.exists() {
        return None;
    }
    let pubkey_path = mvm_core::config::mvm_keys_dir().join(HOST_SIGNER_PUBKEY_FILENAME);
    let bytes = std::fs::read(&pubkey_path).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Some(format!("mvm.host_signer_pub={hex}"))
}

/// Spawn the `mvm-bridge` sibling. Creates a UNIX
/// socketpair, clears `O_CLOEXEC` on both halves in the child via
/// `CommandExt::pre_exec` so they survive `execve`, then pipes the
/// `BridgeConfigJson` document to the child's stdin. Both fds stay
/// owned by the child; the parent closes its handles via
/// `libc::close` after spawn so the supervisor process doesn't leak
/// an fd per VM boot.
///
/// Reads `plan.json` (required) + `bundle.json` (optional) from the
/// per-VM state dir `~/.mvm/vms/<vm_name>/` where the producer
/// (`stash_plan_for_bridge` in `mvm-cli`) wrote them at mode 0600.
///
/// Returns an [`AttachedBridgeGuard`] still holding the `Child`; the
/// caller either lets it fall out of scope on early-return (the Drop
/// impl kills + waits the child) or calls
/// [`detach_and_spawn_bridge_watchdog`] after the FC VM confirms boot
/// to detach the handle and start the watchdog.
///
/// `vm_name` labels the bridge thread + audit chain `vm` field;
/// `abs_dir` is the FC VM's state dir inside the host's filesystem
/// (where `fc.pid` lands so the watchdog can find it).
#[cfg(target_os = "linux")]
pub(super) fn spawn_fc_bridge(vm_name: &str, abs_dir: &str) -> Result<AttachedBridgeGuard> {
    use std::io::Write;
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::os::unix::process::CommandExt;

    // ── Step 1: locate the bridge binary + verify producer stashed
    //            plan.json. The bridge is the trust boundary for the
    //            envelope (it parses but doesn't re-verify); the
    //            producer side (`mvm-cli::stash_plan_for_bridge`) is
    //            responsible for putting a freshly-admitted plan
    //            here. A missing file means a non-admitted boot —
    //            legacy path, no bridge.
    let bridge_bin =
        resolve_fc_bridge_path().with_context(|| "locate mvm-bridge binary".to_string())?;

    let state_dir = mvm_core::config::vm_state_dir(vm_name);
    let plan_path = state_dir.join("plan.json");
    let bundle_path = state_dir.join("bundle.json");
    let plan_json = match std::fs::read_to_string(&plan_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!(
                vm = %vm_name,
                "no plan.json at {}; skipping mvm-bridge (legacy path)",
                plan_path.display()
            );
            return Ok(AttachedBridgeGuard { child: None });
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "read plan.json at {} (Plan 113 §Task 13 producer): {e}",
                plan_path.display()
            ));
        }
    };
    let bundle_json = match std::fs::read_to_string(&bundle_path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "read bundle.json at {}: {e}",
                bundle_path.display()
            ));
        }
    };

    // ── Step 2: substrate paths the bridge needs to bind/read. All
    //            relative to `mvm_home()` so an `MVM_HOME`
    //            override (tests, mvmd) transparently re-roots the
    //            whole tree.
    let audit_dir = mvm_core::config::mvm_audit_dir();
    let audit_socket = audit_dir.join(format!("gateway-{vm_name}.sock"));
    let keys_dir = mvm_core::config::mvm_keys_dir();
    let signing_key_path = keys_dir.join("host-signer.ed25519");
    let passt_path = passt_path_from_env_or_default();
    let passt_hashes_path =
        std::path::PathBuf::from(mvm_core::config::mvm_home()).join("passt-hashes.toml");

    // ── Step 3: create the socketpair. Both halves go to the child
    //            (one feeds passt, one feeds the supervisor's gateway
    //            loop — see `mvm_hostd::supervisor::gateway_bridge::
    //            BridgeEndpoints::Passt`). We use stdlib pairs which
    //            arrive with FD_CLOEXEC set; the `pre_exec` block
    //            clears CLOEXEC in the child before `execve` so the
    //            kernel preserves both fds.
    let (gateway_socket, supervisor_socket) = std::os::unix::net::UnixStream::pair()
        .map_err(|e| anyhow::anyhow!("create passt/supervisor socketpair: {e}"))?;
    let gateway_raw = gateway_socket.as_raw_fd();
    let supervisor_raw = supervisor_socket.as_raw_fd();

    // Unified `mvm_hostd::bridge::parse::BridgeConfigJson` shape (built as raw
    // JSON because mvm-backend cannot depend on the leaf bin crate). The passt
    // binary + hashes + inherited fds live under the `passt` endpoint variant.
    // `network_policy_json` carries `unrestricted` so the bridge's flow gate
    // DEFERS to Firecracker's authoritative kernel nftables moat (claim 10
    // leg 1) instead of double-gating — the old `mvm-firecracker-bridge`
    // hardcoded this internally; it is now producer-supplied.
    let network_policy_json = serde_json::to_string(
        &mvm_core::network_policy::NetworkPolicy::unrestricted(),
    )
    .map_err(|e| anyhow::anyhow!("serialize unrestricted NetworkPolicy for FC bridge: {e}"))?;
    let bridge_cfg = serde_json::json!({
        "vm_name": vm_name,
        "audit_dir": audit_dir,
        "audit_socket": audit_socket,
        "keys_dir": keys_dir,
        "signing_key_path": signing_key_path,
        "plan_json": plan_json,
        "bundle_json": bundle_json,
        "network_policy_json": network_policy_json,
        "endpoint": {
            "passt": {
                "passt_path": passt_path,
                "passt_hashes_path": passt_hashes_path,
                "gateway_fd_raw": gateway_raw,
                "supervisor_fd_raw": supervisor_raw,
            }
        },
    });

    tracing::info!(
        vm = %vm_name,
        bridge = %bridge_bin.display(),
        gateway_fd = gateway_raw,
        supervisor_fd = supervisor_raw,
        "spawning mvm-bridge with inherited socketpair fds"
    );

    let mut cmd = std::process::Command::new(&bridge_bin);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit());

    // SAFETY: `pre_exec` runs in the child between fork and exec.
    // Both raw fds (`gateway_raw`, `supervisor_raw`) are valid in the
    // child's fd table because the child inherits the parent's table
    // post-fork; clearing FD_CLOEXEC via `fcntl(F_SETFD)` is a
    // syscall wrapper with no side effects beyond the fd flag. We
    // only call libc; no allocation, no Rust runtime entry-points
    // are invoked. The closure captures `gateway_raw` and
    // `supervisor_raw` (Copy `i32`s); no shared state.
    unsafe {
        cmd.pre_exec(move || {
            for raw in [gateway_raw, supervisor_raw] {
                let flags = libc::fcntl(raw, libc::F_GETFD);
                if flags < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let new_flags = flags & !libc::FD_CLOEXEC;
                if libc::fcntl(raw, libc::F_SETFD, new_flags) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn {}: {e}", bridge_bin.display()))?;

    // ── Step 4: parent-side fd hygiene. The child inherited both
    //            socketpair fds (CLOEXEC cleared via pre_exec); the
    //            parent's copies are still open. Without closing
    //            them here the supervisor leaks two fds per VM boot.
    //            We give up Rust ownership via `into_raw_fd` (skipping
    //            the stdlib's Drop close) and then `libc::close`
    //            explicitly so the error path is auditable.
    //
    //            CRITICAL: close BEFORE the stdin write below. The
    //            `fork+execve` has already happened by the time
    //            `spawn()` returns, so the child holds its own fd
    //            table entries via the inherited dup. If the
    //            following `.stdin.take().ok_or_else(...)?` or
    //            `write_all(...)?` returns `Err`, an early-return
    //            after this point would otherwise leak both fds in
    //            the parent (the raw fd is not owned by Rust drop
    //            once `into_raw_fd` has been called).
    let parent_gateway_fd = gateway_socket.into_raw_fd();
    let parent_supervisor_fd = supervisor_socket.into_raw_fd();
    // SAFETY: both raw fds came from `UnixStream::pair` + `into_raw_fd`
    // immediately above. They are valid, owned by this process, and
    // no other code path in this function reads them. After
    // `libc::close` they MUST NOT be referenced again — we don't.
    // Closing the parent's copies does not affect the child: the
    // child's fd table received its own dup of each fd during the
    // post-spawn fork+execve, so the kernel keeps the underlying
    // socket endpoints alive on the child side.
    unsafe {
        libc::close(parent_gateway_fd);
        libc::close(parent_supervisor_fd);
    }

    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("mvm-bridge stdin was not piped"))?
        .write_all(bridge_cfg.to_string().as_bytes())
        .map_err(|e| anyhow::anyhow!("pipe BridgeConfigJson to stdin: {e}"))?;

    // Reference `abs_dir` here so the parent layer doesn't get a
    // dead-arg lint when the bridge contract evolves to consume it
    // (planned: read fc.pid path from the host paths struct rather
    // than reconstructing it in the watchdog). Today the watchdog
    // builds its own path from `abs_dir` so this is just keeping the
    // signature wired.
    let _ = abs_dir;

    Ok(AttachedBridgeGuard { child: Some(child) })
}

/// Atomically write the bridge PID file at mode 0600 — tmp + rename so a
/// concurrent reader (a future `stop_vm` reaper) never sees a partial value.
#[cfg(target_os = "linux")]
fn write_fc_bridge_pid_file(path: &std::path::Path, pid: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("bridge pid path has no parent: {}", path.display()))?;
    let tmp = parent.join(format!("{FC_BRIDGE_PID_FILE_NAME}.tmp"));
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| anyhow::anyhow!("open {} for write: {e}", tmp.display()))?;
        writeln!(f, "{pid}").map_err(|e| anyhow::anyhow!("write bridge pid: {e}"))?;
        let _ = f.sync_all();
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| anyhow::anyhow!("rename {} -> {}: {e}", tmp.display(), path.display()))?;
    Ok(())
}

/// Once the FC VM is healthy, take the bridge `Child` out of its
/// guard, persist its PID under `<abs_dir>/fc-bridge.pid` (mode 0600),
/// then spawn the watchdog thread that observes the child via
/// `wait()`. On bridge death the watchdog SIGTERMs the FC VM via
/// `<abs_dir>/fc.pid` (hard-fail bridge crash policy).
///
/// No-op when the guard is empty (legacy path with no admitted plan).
#[cfg(target_os = "linux")]
pub(super) fn detach_and_spawn_bridge_watchdog(
    vm_name: &str,
    abs_dir: &str,
    guard: &mut AttachedBridgeGuard,
) -> Result<()> {
    let Some(mut child) = guard.detach() else {
        return Ok(());
    };
    let pid = child.id();
    let pid_path = std::path::PathBuf::from(abs_dir).join(FC_BRIDGE_PID_FILE_NAME);
    write_fc_bridge_pid_file(&pid_path, pid)?;

    let fc_pid_path = format!("{abs_dir}/fc.pid");
    let vm = vm_name.to_string();
    std::thread::spawn(move || {
        let exit = child.wait();
        warn!(
            vm = %vm,
            bridge_pid = pid,
            ?exit,
            "mvm-bridge exited; SIGTERM'ing Firecracker VM (hard-fail policy)"
        );
        match std::fs::read_to_string(&fc_pid_path) {
            Ok(pid_str) => match pid_str.trim().parse::<libc::pid_t>() {
                Ok(fc_pid) => {
                    // SAFETY: `libc::kill(pid, SIGTERM)` is a syscall
                    // wrapper. SIGTERM to an arbitrary pid_t is well-
                    // defined (kernel resolves or returns ESRCH); no
                    // Rust invariants are touched.
                    let rc = unsafe { libc::kill(fc_pid, libc::SIGTERM) };
                    if rc != 0 {
                        let err = std::io::Error::last_os_error();
                        warn!(
                            vm = %vm,
                            fc_pid,
                            error = %err,
                            "watchdog: SIGTERM to Firecracker VM failed"
                        );
                    }
                }
                Err(e) => warn!(
                    vm = %vm,
                    fc_pid_path = %fc_pid_path,
                    error = %e,
                    "watchdog: parse fc.pid failed; VM may already be gone"
                ),
            },
            Err(e) => warn!(
                vm = %vm,
                fc_pid_path = %fc_pid_path,
                error = %e,
                "watchdog: read fc.pid failed; VM may already be gone"
            ),
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::config::VmSlot;

    fn baseline_run_config(mem_initial: Option<u32>) -> FlakeRunConfig {
        FlakeRunConfig {
            name: "v".to_string(),
            slot: VmSlot::new("v", 0),
            vmlinux_path: "/k/vmlinux".to_string(),
            initrd_path: None,
            rootfs_path: "/k/rootfs.ext4".to_string(),
            verity_path: None,
            roothash: None,
            runtime_overlay_path: None,
            runtime_overlay_verity_path: None,
            runtime_overlay_roothash: None,
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
            revision_hash: "abc".to_string(),
            flake_ref: "/p".to_string(),
            profile: None,
            cpus: 2,
            memory: 1024,
            mem_initial,
            volumes: Vec::new(),
            config_files: Vec::new(),
            secret_files: Vec::new(),
            ports: Vec::new(),
            network_policy: mvm_core::network_policy::NetworkPolicy::default(),
            network_tunnel: None,
        }
    }

    #[test]
    fn network_tunnel_cmdline_token_round_trips_shared_config() {
        let mut config = baseline_run_config(None);
        config.network_tunnel = Some(mvm_core::protocol::network_tunnel::TunnelRuntimeConfig {
            guest_port: 5302,
            session: mvm_core::protocol::network_tunnel::TunnelSessionConfig {
                tenant_id: "tenant-a".to_string(),
                vm_id: "vm-1".to_string(),
                boot_id: "boot-1".to_string(),
                session_nonce: "nonce-1".to_string(),
                requested_features: mvm_core::protocol::network_tunnel::TunnelFeatures {
                    ipv4: true,
                    ..mvm_core::protocol::network_tunnel::TunnelFeatures::default()
                },
                maximum_frame_size: 4096,
            },
        });

        let token = network_tunnel_cmdline_token(&config).expect("valid tunnel config encodes");
        let hex = token
            .strip_prefix("mvm.network_tunnel=")
            .expect("cmdline token prefix");
        let decoded = mvm_core::vm_backend::decode_network_tunnel_cmdline(hex).unwrap();
        assert_eq!(decoded, config.network_tunnel.unwrap());
    }

    // ───────────────────────────────────────────────────────────────
    // mvm-bridge spawn helpers
    // ───────────────────────────────────────────────────────────────

    #[test]
    #[cfg(target_os = "linux")]
    fn resolve_fc_bridge_path_inner_honors_env_var() {
        // Pure resolver — exercised without touching process env. The
        // override must point at a real file or the call errors.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let manifest_dir = std::path::PathBuf::from("/nonexistent/manifest");
        let resolved = resolve_fc_bridge_path_inner(Some(tmp.path()), None, &manifest_dir)
            .expect("env override resolves");
        assert_eq!(resolved, tmp.path());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn resolve_fc_bridge_path_inner_env_pointing_at_missing_file_errors() {
        let manifest_dir = std::path::PathBuf::from("/nonexistent/manifest");
        let bogus = std::path::Path::new("/definitely/not/there/mvm-bridge");
        let err = resolve_fc_bridge_path_inner(Some(bogus), None, &manifest_dir)
            .expect_err("missing file must error");
        assert!(
            err.to_string().contains("not a file"),
            "error explains why: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn resolve_fc_bridge_path_inner_missing_env_falls_back_to_adjacent() {
        // No env override, but a sibling binary exists next to the
        // current exe → resolver returns it.
        let tmp_dir = tempfile::tempdir().unwrap();
        let exe = tmp_dir.path().join("mvmctl");
        std::fs::write(&exe, b"#!fake").unwrap();
        let bridge = tmp_dir.path().join("mvm-bridge");
        std::fs::write(&bridge, b"#!fake").unwrap();
        let manifest_dir = std::path::PathBuf::from("/nonexistent/manifest");
        let resolved =
            resolve_fc_bridge_path_inner(None, Some(&exe), &manifest_dir).expect("adjacent hit");
        assert_eq!(resolved, bridge);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn resolve_fc_bridge_path_inner_errors_when_nothing_found() {
        // All three sources miss → actionable error naming the binary
        // + the override env var so operators know how to fix it.
        let manifest_dir = std::path::PathBuf::from("/nonexistent/manifest");
        let err = resolve_fc_bridge_path_inner(None, None, &manifest_dir)
            .expect_err("no candidate must error");
        let msg = err.to_string();
        assert!(
            msg.contains("mvm-bridge") && msg.contains("MVM_BRIDGE_PATH"),
            "error names the binary + override env var: {msg}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn attached_bridge_guard_kills_child_on_drop() {
        // Spawn a long-lived `sleep` and wrap it; dropping the guard
        // must kill the process. Poll `kill(pid, 0)` after drop to
        // assert the child is reaped.
        let child = std::process::Command::new("sleep")
            .arg("60")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as libc::pid_t;
        {
            let _guard = AttachedBridgeGuard { child: Some(child) };
            // SAFETY: kill(pid, 0) is a syscall wrapper that returns
            // 0 if the process exists. No UB.
            assert_eq!(
                unsafe { libc::kill(pid, 0) },
                0,
                "sleep should be alive while guard owns it"
            );
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while std::time::Instant::now() < deadline {
            // SAFETY: see above.
            if unsafe { libc::kill(pid, 0) } != 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        // SAFETY: see above.
        assert_ne!(
            unsafe { libc::kill(pid, 0) },
            0,
            "sleep must be dead after guard drop"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn attached_bridge_guard_detach_leaves_child_running() {
        // `detach` takes the Child out so dropping the guard does NOT
        // kill the process. The test reaps the detached child manually
        // to avoid leaking it past the test boundary.
        let child = std::process::Command::new("sleep")
            .arg("60")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as libc::pid_t;
        let mut guard = AttachedBridgeGuard { child: Some(child) };
        let detached = guard.detach().expect("detach yields the child");
        drop(guard);
        // SAFETY: kill(pid, 0) is the standard liveness probe.
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            0,
            "sleep must still be alive after detach"
        );
        // Clean up so the test doesn't leak the process.
        // SAFETY: SIGKILL to a pid we just verified is ours.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let mut detached = detached;
        let _ = detached.wait();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn attached_bridge_guard_empty_drop_is_noop() {
        // Legacy / no-admission path returns an empty guard. Dropping
        // it must not panic and must not attempt any process ops.
        let guard = AttachedBridgeGuard { child: None };
        drop(guard);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn write_fc_bridge_pid_file_creates_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fc-bridge.pid");
        write_fc_bridge_pid_file(&path, 12345).expect("write");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "bridge pid file must be mode 0600 (got {mode:o})"
        );
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.trim(), "12345");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn passt_path_default_when_env_unset() {
        // Production resolver — touches std::env. We test the unset
        // path which yields /usr/bin/passt; the set path is exercised
        // implicitly by `mvmctl up` integration tests.
        let saved = std::env::var_os("MVM_PASST_PATH");
        // SAFETY: scoped env var swap restored below.
        unsafe { std::env::remove_var("MVM_PASST_PATH") };
        let p = passt_path_from_env_or_default();
        assert_eq!(p, std::path::PathBuf::from("/usr/bin/passt"));
        // SAFETY: restore prior value (or remove).
        unsafe {
            match saved {
                Some(v) => std::env::set_var("MVM_PASST_PATH", v),
                None => std::env::remove_var("MVM_PASST_PATH"),
            }
        }
    }

    // ---- verb_grant_cmdline_token ----

    #[test]
    fn verb_grant_cmdline_token_some_when_sidecar_present() {
        use mvm_core::plan::{Nonce, VerbGrant, VerbId};
        use mvm_core::protocol::vm_backend::{VerbGrantEnvelope, decode_verb_grant_cmdline};

        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());

        let vm_name = "verb-grant-token-test";
        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();

        // Construct a plausible envelope. The token builder reads and
        // re-encodes; it does not verify the signature, so a stub sig
        // is sufficient here. Signature correctness is exercised in the
        // plan_admission mint test.
        let nonce = Nonce::from_bytes([5u8; 16]);
        // Use a far-future not_after to avoid expiry: 2099-01-01T00:00:00Z.
        let not_after = mvm_core::time::parse_iso8601("2099-01-01T00:00:00Z").unwrap();
        let grant = VerbGrant {
            session_id: vm_name.to_string(),
            plan_nonce: nonce.clone(),
            not_after,
            verbs: vec![VerbId::new("run-entrypoint").unwrap()],
            sig: vec![0u8; 64],
        };
        // pubkey_hex must be non-empty for encode_verb_grant_cmdline to return Some.
        let pubkey_hex = "aa".repeat(32);
        let envelope = VerbGrantEnvelope {
            pubkey_hex,
            plan_nonce_hex: nonce.as_hex().to_string(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant,
        };
        let json = serde_json::to_vec(&envelope).unwrap();
        std::fs::write(state_dir.join("verb-grant.json"), &json).unwrap();

        let token = verb_grant_cmdline_token(vm_name).expect("token must be Some");
        assert!(
            token.starts_with("mvm.verb_grant="),
            "token must start with mvm.verb_grant="
        );
        let hex_part = token.trim_start_matches("mvm.verb_grant=");
        let roundtrip = decode_verb_grant_cmdline(hex_part).unwrap();
        assert_eq!(roundtrip.plan_nonce_hex, nonce.as_hex());
    }

    #[test]
    fn verb_grant_cmdline_token_none_when_sidecar_absent() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());

        let vm_name = "no-grant-vm";
        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();

        assert!(
            verb_grant_cmdline_token(vm_name).is_none(),
            "absent sidecar must yield None"
        );
    }

    // ---- require_grant_cmdline_token ----

    #[test]
    fn require_grant_cmdline_token_some_when_sidecar_present() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());

        let vm_name = "require-grant-present-test";
        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();

        // Write garbage content: the function is keyed on file existence,
        // not on successful JSON decode.
        std::fs::write(state_dir.join("verb-grant.json"), b"not-valid-json").unwrap();

        let token =
            require_grant_cmdline_token(vm_name).expect("token must be Some when sidecar exists");
        assert_eq!(
            token, "mvm.require_grant=1",
            "token must be mvm.require_grant=1"
        );
    }

    #[test]
    fn require_grant_cmdline_token_none_when_no_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());

        let vm_name = "require-grant-absent-test";
        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();

        assert!(
            require_grant_cmdline_token(vm_name).is_none(),
            "absent sidecar must yield None"
        );
    }

    // ---- host_signer_pub_cmdline_token ----

    /// Write both the verb-grant sidecar (its content is irrelevant here — the
    /// token is keyed on existence) and a raw 32-byte host-signer pubkey under
    /// the data dir keys/ directory.
    fn seed_grant_and_pubkey(vm_name: &str, pubkey: &[u8; 32]) {
        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(state_dir.join("verb-grant.json"), b"{}").unwrap();
        let keys_dir = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys_dir).unwrap();
        std::fs::write(keys_dir.join("host-signer.pub"), pubkey).unwrap();
    }

    #[test]
    fn host_signer_pub_cmdline_token_some_when_grant_and_key_present() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());

        let vm_name = "host-signer-pub-present";
        let pubkey = [0xABu8; 32];
        seed_grant_and_pubkey(vm_name, &pubkey);

        let token = host_signer_pub_cmdline_token(vm_name).expect("token must be Some");
        let expected_hex = "ab".repeat(32);
        assert_eq!(token, format!("mvm.host_signer_pub={expected_hex}"));

        // Round-trip: the value decodes back to the exact key bytes.
        let hex_part = token.trim_start_matches("mvm.host_signer_pub=");
        let decoded: Vec<u8> = (0..hex_part.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_part[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(decoded, pubkey.to_vec());
    }

    #[test]
    fn host_signer_pub_cmdline_token_none_when_grant_absent() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());

        // Key present, but no verb-grant sidecar (plan carried no agent_verbs).
        let keys_dir = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys_dir).unwrap();
        std::fs::write(keys_dir.join("host-signer.pub"), [0u8; 32]).unwrap();

        let vm_name = "host-signer-pub-no-grant";
        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();

        assert!(
            host_signer_pub_cmdline_token(vm_name).is_none(),
            "no grant sidecar must yield None even when the key exists"
        );
    }

    #[test]
    fn host_signer_pub_cmdline_token_none_when_key_wrong_size() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());

        let vm_name = "host-signer-pub-bad-key";
        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(state_dir.join("verb-grant.json"), b"{}").unwrap();
        let keys_dir = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys_dir).unwrap();
        // 31 bytes: not a valid Ed25519 public key length.
        std::fs::write(keys_dir.join("host-signer.pub"), [1u8; 31]).unwrap();

        assert!(
            host_signer_pub_cmdline_token(vm_name).is_none(),
            "a wrong-sized key must yield None (best-effort, no boot block)"
        );
    }
}
