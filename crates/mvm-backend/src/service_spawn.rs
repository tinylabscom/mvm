//! Shared per-VM host-service subprocess spawn primitives (the audit-signer and
//! the broker ride these). Each such service is a detached subprocess that reads
//! a JSON config on stdin and binds a per-VM UDS; the spawn pattern — resolve
//! the binary, `setsid`-detach, pipe the config, wait for the bind, persist a
//! PID, reap on teardown — is identical, so it lives here once.
//!
//! Mirrors the shape of [`crate::substitution_spawn`] (which predates this and
//! keeps its own copy for the FC/QEMU-shaped transport fields). New host
//! services should build on these helpers rather than fork the spawn logic.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};

/// How long a service gets to bind its UDS before the spawn is declared failed.
const BIND_TIMEOUT: Duration = Duration::from_secs(10);
/// Poll interval while waiting for the UDS to appear.
const BIND_POLL: Duration = Duration::from_millis(25);

/// Locate a host-service binary: `<env_var>` override (must be a file) →
/// sibling of the current exe → workspace `target/{release,debug}`. The
/// release artifacts must ship the binary beside `mvmctl` (like
/// `mvm-substitution-endpoint`); dev resolves it from `target/`.
pub(crate) fn resolve_service_binary(bin: &str, env_var: &str) -> Result<PathBuf> {
    if let Some(p) = std::env::var_os(env_var).map(PathBuf::from) {
        if p.is_file() {
            return Ok(p);
        }
        bail!("{env_var} points at {} which is not a file", p.display());
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
    {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(workspace_root) = manifest_dir.parent().and_then(Path::parent) {
        for variant in ["release", "debug"] {
            let candidate = workspace_root.join("target").join(variant).join(bin);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    bail!("could not locate the {bin} binary (set {env_var})")
}

/// Inputs to [`spawn_detached_uds_service`].
pub(crate) struct UdsServiceSpec<'a> {
    /// The resolved service binary.
    pub bin: &'a Path,
    /// The JSON config piped on stdin (the service parses it, then EOF).
    pub config_json: &'a serde_json::Value,
    /// The UDS the service is expected to bind — spawn succeeds once it appears.
    pub listen_uds: &'a Path,
    /// Where to persist the child PID for the reap path.
    pub pid_file: &'a Path,
}

/// Spawn a host-service subprocess: ensure the UDS parent dir exists, clear any
/// stale socket, hand the config on stdin, detach via `setsid`, wait for the
/// service to bind its UDS, persist the PID. Fail-closed: a spawn error, an
/// early child exit, or a bind timeout SIGKILLs the child and returns `Err` so
/// the caller rolls the launch back. The service is daemonized and is reaped by
/// the stop path via the PID file.
pub(crate) fn spawn_detached_uds_service(spec: UdsServiceSpec<'_>) -> Result<()> {
    use std::io::Write;
    let UdsServiceSpec {
        bin,
        config_json,
        listen_uds,
        pid_file,
    } = spec;

    if let Some(parent) = listen_uds.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    // A stale socket from a prior run would fail the new bind; clear it.
    let _ = std::fs::remove_file(listen_uds);

    let mut cmd = Command::new(bin);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
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
        .map_err(|e| anyhow!("spawn {}: {e}", bin.display()))?;

    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("{} stdin was not piped", bin.display()))?
        .write_all(config_json.to_string().as_bytes())
        .map_err(|e| anyhow!("pipe config to {}: {e}", bin.display()))?;
    // (stdin writer dropped here → EOF, so the service stops reading config.)

    wait_for_uds_bind(&mut child, listen_uds, bin)?;

    std::fs::write(pid_file, child.id().to_string())
        .map_err(|e| anyhow!("write {}: {e}", pid_file.display()))?;
    // Detach: drop the child handle without killing (std `Child` drop doesn't
    // signal). The service is daemonized and reaped via the PID file.
    Ok(())
}

/// Poll until `listen_uds` exists (the service bound) or the bind times out / the
/// child exits early. SIGKILL + bail on failure.
fn wait_for_uds_bind(child: &mut Child, listen_uds: &Path, bin: &Path) -> Result<()> {
    let start = Instant::now();
    loop {
        if listen_uds.exists() {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|e| anyhow!("waiting on {}: {e}", bin.display()))?
        {
            bail!(
                "{} exited before binding its UDS (status {status})",
                bin.display()
            );
        }
        if start.elapsed() > BIND_TIMEOUT {
            let _ = child.kill();
            bail!(
                "{} did not bind {} within {:?}",
                bin.display(),
                listen_uds.display(),
                BIND_TIMEOUT
            );
        }
        std::thread::sleep(BIND_POLL);
    }
}

/// Reap a service: SIGTERM the live PID from `pid_file`, then drop the PID file
/// and any `sockets` it left behind. Best-effort + idempotent: a service that
/// was never spawned is a no-op. The liveness check avoids signalling a recycled
/// PID from a stale pidfile.
pub(crate) fn reap_service(pid_file: &Path, sockets: &[PathBuf]) {
    if let Some(pid) = read_pid(pid_file)
        && pid_alive(pid)
    {
        kill(pid, libc::SIGTERM);
    }
    let _ = std::fs::remove_file(pid_file);
    for socket in sockets {
        let _ = std::fs::remove_file(socket);
    }
}

/// RAII reaper for a per-VM host service, armed while a backend's `start` is
/// wiring the VM and dropped on any early-return so the service can't outlive a
/// failed launch. Defused once the VM is up (the `stop` path then owns
/// teardown). The `reap` fn pointer lets one guard type serve every service —
/// each module supplies its own `reap_*(state_dir)`.
pub struct ServiceGuard {
    /// `Some(name)` while armed; `None` once defused.
    vm_name: Option<String>,
    /// Per-service reaper, invoked with the VM state dir on an armed drop.
    reap: fn(&Path),
}

impl ServiceGuard {
    pub(crate) fn armed(vm_name: &str, reap: fn(&Path)) -> Self {
        Self {
            vm_name: Some(vm_name.to_string()),
            reap,
        }
    }
    /// A guard for a VM that spawned no service — Drop is a no-op.
    pub(crate) fn defused(reap: fn(&Path)) -> Self {
        Self {
            vm_name: None,
            reap,
        }
    }
    pub fn defuse(&mut self) {
        self.vm_name = None;
    }
}

impl Drop for ServiceGuard {
    fn drop(&mut self) {
        if let Some(ref name) = self.vm_name {
            tracing::warn!(vm = %name, "ServiceGuard: reaping orphaned host service");
            (self.reap)(&mvm_core::config::vm_state_dir(name));
        }
    }
}

/// Create `dir` (and parents) at mode 0700, idempotently.
pub(crate) fn ensure_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let mut perms = std::fs::metadata(dir)
        .with_context(|| format!("stat {}", dir.display()))?
        .permissions();
    if perms.mode() & 0o777 != 0o700 {
        perms.set_mode(0o700);
        std::fs::set_permissions(dir, perms)
            .with_context(|| format!("chmod 0700 {}", dir.display()))?;
    }
    Ok(())
}

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

    #[test]
    fn resolve_rejects_bad_env_override() {
        // SAFETY: single-threaded test; restored before return.
        unsafe { std::env::set_var("MVM_TEST_SVC_PATH", "/nonexistent/mvm-test-svc") };
        let err = resolve_service_binary("mvm-test-svc", "MVM_TEST_SVC_PATH").unwrap_err();
        unsafe { std::env::remove_var("MVM_TEST_SVC_PATH") };
        assert!(err.to_string().contains("is not a file"), "{err}");
    }

    #[test]
    fn reap_is_idempotent_noop_without_pidfile() {
        let tmp = tempfile::tempdir().unwrap();
        reap_service(&tmp.path().join("absent.pid"), &[]);
        reap_service(
            &tmp.path().join("absent.pid"),
            &[tmp.path().join("absent.sock")],
        );
    }

    #[test]
    fn ensure_private_dir_creates_at_0700() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("svc");
        ensure_private_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
}
