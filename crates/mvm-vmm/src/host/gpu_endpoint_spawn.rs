//! Per-VM GPU endpoint spawn/reap.
//!
//! A launch that asks for the GPU remoting plane (`VmStartConfig.gpu`) gets
//! one `mvm-gpu-endpoint` process, spawned beside the network endpoint and
//! reaped with the VM. The endpoint binds the host side of the guest's GPU
//! vsock channel ([`mvm_contract::protocol::gpu::GPU_RPC_PORT`]) and serves
//! the guest shim libraries' RPCs against the real driver or the
//! deterministic stub.
//!
//! Unlike the network endpoint there is no stdin config and no ready
//! handshake on stdout: the guest only dials after its workload starts, so
//! readiness is proven by the bound socket itself. The spawner still waits
//! for that bind so a dead endpoint fails the launch at boot, not inside the
//! workload's first CUDA call.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::host::network_endpoint_spawn::EndpointTransport;

/// Per-VM file recording the endpoint's pid, inside the VM state dir.
pub const GPU_ENDPOINT_PID_FILE: &str = "gpu-endpoint.pid";
/// The endpoint's stderr/stdout capture, inside the VM state dir.
pub const GPU_ENDPOINT_LOG_FILE: &str = "gpu-endpoint.log";

/// Bound on waiting for the endpoint's socket to appear after spawn. Binding
/// a UDS is milliseconds of work; the bound covers process startup on a busy
/// host, the same reasoning as the network endpoint's handshake timeout.
const BIND_WAIT: Duration = Duration::from_secs(30);
const BIND_POLL: Duration = Duration::from_millis(20);

fn resolve_gpu_endpoint_path() -> Result<PathBuf> {
    crate::host::aux_bin::resolve_verified(&crate::host::aux_bin::AuxBin {
        bin: "mvm-gpu-endpoint",
        env_var: "MVM_GPU_ENDPOINT_PATH",
        rebuild_package: "mvm-gpu",
    })
}

/// Where the endpoint proves readiness: the UDS path it must bind. A vsock
/// transport has no filesystem proof, so readiness is the spawn succeeding.
fn bind_proof(transport: &EndpointTransport) -> Option<PathBuf> {
    match transport {
        EndpointTransport::Uds { path } => Some(path.clone()),
        EndpointTransport::Vsock { .. } => None,
    }
}

/// Spawn this VM's GPU endpoint and wait until its listener is bound.
///
/// `transport` is backend-shaped exactly like the network endpoint's:
/// Firecracker/libkrun/HVF proxy the guest dial to a per-VM UDS; QEMU's
/// vhost-vsock lets the endpoint bind the real port.
pub fn spawn_gpu_endpoint(
    vm_name: &str,
    state_dir: &Path,
    transport: EndpointTransport,
) -> Result<()> {
    let endpoint = resolve_gpu_endpoint_path()?;
    let listen = match &transport {
        EndpointTransport::Uds { path } => format!("unix:{}", path.display()),
        EndpointTransport::Vsock { port } => format!("vsock:{port}"),
    };
    let log_path = state_dir.join(GPU_ENDPOINT_LOG_FILE);
    let log = std::fs::File::create(&log_path)
        .with_context(|| format!("creating {}", log_path.display()))?;
    let mut child = Command::new(&endpoint)
        .arg("--listen")
        .arg(&listen)
        .arg("--backend")
        .arg("auto")
        .arg("--vm")
        .arg(vm_name)
        .stdin(Stdio::null())
        .stdout(log.try_clone().context("cloning the GPU endpoint log")?)
        .stderr(log)
        .spawn()
        .with_context(|| format!("spawning {}", endpoint.display()))?;
    let pid = child.id();
    std::fs::write(state_dir.join(GPU_ENDPOINT_PID_FILE), format!("{pid}\n"))
        .with_context(|| format!("writing {GPU_ENDPOINT_PID_FILE} for VM {vm_name}"))?;

    if let Some(proof) = bind_proof(&transport) {
        let deadline = Instant::now() + BIND_WAIT;
        loop {
            // Existence is not readiness: the socket file appears at bind(),
            // and a guest dial before listen() is ECONNREFUSED. Probe with a
            // real connect so the VM only boots once the endpoint serves.
            let serving = proof.exists() && std::os::unix::net::UnixStream::connect(&proof).is_ok();
            if serving {
                break;
            }
            // A dead endpoint never binds: reap it and fail the launch with
            // its log rather than burning the whole wait.
            if let Some(status) = child.try_wait().context("polling GPU endpoint")? {
                let _ = child.wait();
                bail!(
                    "GPU endpoint for VM {vm_name} exited with {status} before binding {}; \
                     see {}",
                    proof.display(),
                    log_path.display()
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!(
                    "GPU endpoint for VM {vm_name} did not bind {} within {BIND_WAIT:?}; see {}",
                    proof.display(),
                    log_path.display()
                );
            }
            std::thread::sleep(BIND_POLL);
        }
    }
    // The child outlives this handle deliberately: it is reaped by pid file
    // when the VM stops, exactly like the network endpoint.
    Ok(())
}

/// Reap this VM's GPU endpoint, if one was spawned. Idempotent.
pub fn reap_gpu_endpoint(state_dir: &Path) {
    let pid_path = state_dir.join(GPU_ENDPOINT_PID_FILE);
    let Ok(raw) = std::fs::read_to_string(&pid_path) else {
        return;
    };
    let Ok(pid) = raw.trim().parse::<i32>() else {
        let _ = std::fs::remove_file(&pid_path);
        return;
    };
    // SIGTERM first: the endpoint arms a flag for a clean accept-loop exit.
    // SAFETY: `kill` only signals the pid; the pid came from this VM's own
    // pid file, written by this process family at spawn.
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        // SAFETY: `kill(pid, 0)` probes existence only.
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        if !alive {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // SAFETY: same probe-and-then-signal pattern; after the grace window the
    // endpoint has had its chance to exit cleanly.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let _ = std::fs::remove_file(&pid_path);
}

/// Parse a bind proof path from a `--listen unix:...` value, for tests and
/// for callers that need to know the socket without re-deriving it.
#[must_use]
pub fn uds_bind_path(listen: &str) -> Option<PathBuf> {
    listen
        .strip_prefix("unix:")
        .map(std::path::Path::new)
        .map(std::path::Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_proof_is_the_uds_path_and_nothing_for_vsock() {
        let uds = EndpointTransport::Uds {
            path: "/run/gpu.sock".into(),
        };
        assert_eq!(bind_proof(&uds), Some(PathBuf::from("/run/gpu.sock")));
        let vsock = EndpointTransport::Vsock { port: 5256 };
        assert_eq!(bind_proof(&vsock), None);
    }

    #[test]
    fn reaping_without_a_pid_file_is_a_no_op() {
        let dir = tempfile::tempdir().expect("tempdir");
        // No pid file → no panic, no error.
        reap_gpu_endpoint(dir.path());
    }

    #[test]
    fn reaping_a_garbage_pid_file_cleans_it_up() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(GPU_ENDPOINT_PID_FILE), "not-a-pid\n").expect("write");
        reap_gpu_endpoint(dir.path());
        assert!(!dir.path().join(GPU_ENDPOINT_PID_FILE).exists());
    }

    #[test]
    fn reaping_kills_a_live_child_and_removes_the_pid_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A child that ignores nothing and sleeps: SIGTERM's flag does not
        // exist in this process, so the graceful window then SIGKILL is the
        // path being exercised.
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 60")
            .spawn()
            .expect("spawn sleeper");
        let pid = child.id();
        std::fs::write(dir.path().join(GPU_ENDPOINT_PID_FILE), format!("{pid}\n"))
            .expect("write pid");
        reap_gpu_endpoint(dir.path());
        assert!(!dir.path().join(GPU_ENDPOINT_PID_FILE).exists());
        // The child is gone: try_wait reports a status (killed).
        let status = child.wait().expect("reaped child");
        assert!(!status.success());
        // SAFETY: signal 0 probes existence only; the pid was reaped above,
        // so the probe must fail.
        let probe = unsafe { libc::kill(i32::try_from(pid).expect("pid fits i32"), 0) };
        assert_ne!(probe, 0, "a reaped child must not answer a liveness probe");
    }

    #[test]
    fn uds_bind_path_parses_the_listen_value() {
        assert_eq!(
            uds_bind_path("unix:/run/gpu.sock"),
            Some(PathBuf::from("/run/gpu.sock"))
        );
        assert_eq!(uds_bind_path("vsock:5256"), None);
    }
}
