//! Host-side client for the persistent builder VM's control socket.
//!
//! The Vz supervisor binds `<vm_state_dir>/control.sock` (mode 0700) and
//! accepts newline-framed text commands — the same protocol as
//! `mvm-backend::vz_control`. This module reimplements the minimal client
//! inside `mvm-build` so the crate stays off `mvm-backend` in the dep graph
//! (mvm-backend depends on mvm-build, not the other way around).
//!
//! `send_builder_control_command` is the only public surface; everything else
//! is a test helper or a private sub-function.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::builder_vm::BuilderVmError;
use crate::vz::{StartupMode, SupervisorConfig};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Send one newline-framed command to the builder VM's control socket and
/// return the response line (without the trailing newline).
///
/// Rejects commands that contain embedded newlines — they would split into
/// multiple protocol frames, corrupting the command stream. Maps I/O errors
/// to [`BuilderVmError::ExtractionFailed`] with the socket path and operation
/// in the message.
pub fn send_builder_control_command(
    socket_path: &Path,
    command: &str,
) -> Result<String, BuilderVmError> {
    if command.contains('\n') {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "builder control command must not contain a newline: {command:?}"
        )));
    }

    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("connect {}: {e}", socket_path.display()))
    })?;
    stream
        .set_read_timeout(Some(DEFAULT_TIMEOUT))
        .map_err(|e| BuilderVmError::ExtractionFailed(format!("set_read_timeout: {e}")))?;
    stream
        .set_write_timeout(Some(DEFAULT_TIMEOUT))
        .map_err(|e| BuilderVmError::ExtractionFailed(format!("set_write_timeout: {e}")))?;

    let mut payload = command.as_bytes().to_vec();
    payload.push(b'\n');
    stream
        .write_all(&payload)
        .map_err(|e| BuilderVmError::ExtractionFailed(format!("write command {command:?}: {e}")))?;

    // Read byte-by-byte until a newline or EOF — one response per command.
    let mut response = Vec::with_capacity(64);
    let mut buf = [0u8; 1];
    loop {
        let n = stream
            .read(&mut buf)
            .map_err(|e| BuilderVmError::ExtractionFailed(format!("read response: {e}")))?;
        if n == 0 {
            break;
        }
        if buf[0] == b'\n' {
            break;
        }
        response.push(buf[0]);
    }

    String::from_utf8(response)
        .map_err(|e| BuilderVmError::ExtractionFailed(format!("response was not UTF-8: {e}")))
}

/// Return a copy of `persisted` with `startup_mode` set to
/// [`StartupMode::Restore`] pointing at `snapshot_path`.
///
/// All other fields — name, disks, resources, vsock, virtio-fs shares,
/// console, network, balloon, control socket, tenant/plan/audit substrate —
/// are preserved byte-identically. The caller is responsible for persisting
/// the returned config before the next boot.
///
/// Returns `Err` when `snapshot_path` is not absolute (the Vz API requires
/// an absolute path for `restoreMachineState(from:)`).
pub fn builder_restore_config(
    persisted: SupervisorConfig,
    snapshot_path: &Path,
    machine_id_path: Option<&Path>,
) -> Result<SupervisorConfig, BuilderVmError> {
    if !snapshot_path.is_absolute() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "snapshot_path must be absolute, got: {}",
            snapshot_path.display()
        )));
    }
    Ok(SupervisorConfig {
        startup_mode: StartupMode::Restore {
            snapshot_path: snapshot_path.to_string_lossy().into_owned(),
            machine_id_path: machine_id_path.map(|p| p.to_string_lossy().into_owned()),
        },
        ..persisted
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vz::{DiskConfig, KernelConfig, ResourceConfig, VirtioFsShare, VsockConfig};
    use std::os::unix::net::UnixListener;
    use std::thread;

    // ── helpers ─────────────────────────────────────────────────────────────

    /// Spawn a one-shot fake supervisor on `path` that accepts a single
    /// connection, reads one line (drains the command), and replies
    /// `response\n`.
    fn fake_supervisor(path: std::path::PathBuf, response: String) -> thread::JoinHandle<()> {
        let listener = UnixListener::bind(&path).expect("bind fake supervisor");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf);
                let mut payload = response.into_bytes();
                payload.push(b'\n');
                let _ = stream.write_all(&payload);
            }
        })
    }

    fn minimal_config() -> SupervisorConfig {
        SupervisorConfig {
            name: "test-builder".into(),
            vm_state_dir: "/tmp/builder".into(),
            pid_file_name: Some("vz.pid".into()),
            kernel: KernelConfig {
                path: "/tmp/vmlinux".into(),
                cmdline: "console=hvc0 root=/dev/vda rw init=/init".into(),
                initrd_path: None,
            },
            resources: ResourceConfig {
                cpu_count: 2,
                memory_mib: 4096,
            },
            disks: vec![DiskConfig {
                id: "rootfs".into(),
                path: "/tmp/rootfs.ext4".into(),
                read_only: true,
            }],
            virtio_fs: vec![VirtioFsShare {
                tag: "work".into(),
                host_path: "/work".into(),
                read_only: false,
            }],
            vsock: VsockConfig {
                ports: vec![5252],
                socket_dir: "/tmp/builder/vsock".into(),
                host_listen_ports: vec![],
            },
            console_output_path: None,
            network: None,
            balloon: None,
            control_socket_path: Some("/tmp/builder/control.sock".into()),
            startup_mode: StartupMode::Boot,
            tenant_id: None,
            plan: None,
            bundle: None,
            network_policy: None,
            audit_dir: None,
            gateway_audit_socket: None,
            signing_key_path: None,
        }
    }

    // ── Task 2 tests: send_builder_control_command ───────────────────────────

    #[test]
    fn builder_control_newline_in_command_rejected() {
        // Must fail without connecting (before socket dial).
        let err =
            send_builder_control_command(Path::new("/nonexistent.sock"), "SAVE /tmp/x\nINJECT")
                .expect_err("newline must be rejected");
        assert!(
            err.to_string().contains("must not contain a newline"),
            "error: {err}"
        );
    }

    #[test]
    fn builder_control_round_trip_via_echo_server() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("control.sock");

        let h = fake_supervisor(sock.clone(), "OK".to_string());
        let response = send_builder_control_command(&sock, "SAVE /tmp/x").expect("round-trip");
        assert_eq!(response, "OK");
        h.join().unwrap();
    }

    #[test]
    fn builder_control_missing_socket_errors_with_path() {
        let err = send_builder_control_command(Path::new("/nonexistent/control.sock"), "STATUS")
            .expect_err("missing socket should error");
        assert!(
            err.to_string().contains("/nonexistent/control.sock"),
            "error includes path: {err}"
        );
    }

    // ── Task 3 tests: builder_restore_config ────────────────────────────────

    #[test]
    fn builder_restore_config_sets_restore_mode_with_paths() {
        let cfg = minimal_config();
        let snap = Path::new("/abs/snap.vzsnap");
        let mid = Path::new("/abs/snap.vzsnap.machine-id");

        let result = builder_restore_config(cfg, snap, Some(mid)).expect("absolute path accepted");

        match result.startup_mode {
            StartupMode::Restore {
                snapshot_path,
                machine_id_path,
            } => {
                assert_eq!(snapshot_path, "/abs/snap.vzsnap");
                assert_eq!(
                    machine_id_path.as_deref(),
                    Some("/abs/snap.vzsnap.machine-id")
                );
            }
            other => panic!("expected Restore, got {other:?}"),
        }
    }

    #[test]
    fn builder_restore_config_preserves_all_other_fields() {
        let cfg = minimal_config();
        let snap = Path::new("/abs/snap.vzsnap");

        let result =
            builder_restore_config(cfg.clone(), snap, None).expect("absolute path accepted");

        assert_eq!(result.name, cfg.name);
        assert_eq!(result.disks.len(), cfg.disks.len());
        assert_eq!(result.control_socket_path, cfg.control_socket_path);
        assert_eq!(result.vm_state_dir, cfg.vm_state_dir);
        assert_eq!(result.resources.cpu_count, cfg.resources.cpu_count);
        assert_eq!(result.virtio_fs.len(), cfg.virtio_fs.len());
    }

    #[test]
    fn builder_restore_config_relative_path_rejected() {
        let cfg = minimal_config();
        let err = builder_restore_config(cfg, Path::new("relative/snap.vzsnap"), None)
            .expect_err("relative path must be rejected");
        assert!(err.to_string().contains("must be absolute"), "error: {err}");
    }
}
