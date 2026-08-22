//! Host-facing convenience API: dial the guest agent (by instance
//! directory or by a direct UDS path) and issue a single request,
//! mapping the typed response into a plain `Result`.

use std::os::unix::net::UnixStream;

use anyhow::{Result, bail};

use super::connection::connect;
use super::*;

/// Query worker status from the guest vsock agent.
pub fn query_worker_status(instance_dir: &str) -> Result<GuestResponse> {
    let mut stream = connect(instance_dir, DEFAULT_TIMEOUT_SECS)?;
    send_request(&mut stream, &GuestRequest::WorkerStatus)
}

/// Request sleep preparation via vsock.
///
/// Returns Ok(true) if guest ACKed (OpenClaw idle, data flushed),
/// Ok(false) if guest NAKed or timed out.
pub fn request_sleep_prep(instance_dir: &str, drain_timeout_secs: u64) -> Result<bool> {
    let mut stream = connect(instance_dir, drain_timeout_secs)?;
    let resp = send_request(&mut stream, &GuestRequest::SleepPrep { drain_timeout_secs })?;

    match resp {
        GuestResponse::SleepPrepAck { success, .. } => Ok(success),
        GuestResponse::Error { message } => {
            bail!("Guest sleep prep error: {}", message);
        }
        _ => bail!("Unexpected response to SleepPrep"),
    }
}

/// Signal wake to the guest vsock agent.
///
/// Returns Ok(true) if guest ACKed (connections reinitialized, secrets refreshed),
/// Ok(false) if guest NAKed.
pub fn signal_wake(instance_dir: &str) -> Result<bool> {
    let mut stream = connect(instance_dir, DEFAULT_TIMEOUT_SECS)?;
    let resp = send_request(&mut stream, &GuestRequest::Wake)?;

    match resp {
        GuestResponse::WakeAck { success } => Ok(success),
        GuestResponse::Error { message } => {
            bail!("Guest wake error: {}", message);
        }
        _ => bail!("Unexpected response to Wake"),
    }
}

/// Ping the guest vsock agent (health check).
pub fn ping(instance_dir: &str) -> Result<bool> {
    let mut stream = connect(instance_dir, DEFAULT_TIMEOUT_SECS)?;
    let resp = send_request(&mut stream, &GuestRequest::Ping)?;
    Ok(matches!(resp, GuestResponse::Pong))
}

/// Query the guest agent process's current RSS in bytes.
pub fn query_resource_usage(instance_dir: &str) -> Result<u64> {
    let mut stream = connect(instance_dir, DEFAULT_TIMEOUT_SECS)?;
    resource_usage_response(send_request(&mut stream, &GuestRequest::ResourceUsage)?)
}

/// Query integration status from the guest agent.
pub fn query_integration_status(
    instance_dir: &str,
) -> Result<Vec<crate::integrations::IntegrationStateReport>> {
    let mut stream = connect(instance_dir, DEFAULT_TIMEOUT_SECS)?;
    let resp = send_request(&mut stream, &GuestRequest::IntegrationStatus)?;

    match resp {
        GuestResponse::IntegrationStatusReport { integrations } => Ok(integrations),
        GuestResponse::Error { message } => {
            bail!("Guest integration status error: {}", message);
        }
        _ => bail!("Unexpected response to IntegrationStatus"),
    }
}

/// Request the guest to checkpoint named integrations before sleep.
///
/// Returns Ok(true) if all integrations checkpointed successfully,
/// Ok(false) if any failed.
pub fn checkpoint_integrations(
    instance_dir: &str,
    integrations: Vec<String>,
    timeout_secs: u64,
) -> Result<bool> {
    let mut stream = connect(instance_dir, timeout_secs)?;
    let resp = send_request(
        &mut stream,
        &GuestRequest::CheckpointIntegrations { integrations },
    )?;

    match resp {
        GuestResponse::CheckpointResult { success, .. } => Ok(success),
        GuestResponse::Error { message } => {
            bail!("Guest checkpoint error: {}", message);
        }
        _ => bail!("Unexpected response to CheckpointIntegrations"),
    }
}
/// Ping the guest vsock agent at a specific UDS path.
pub fn ping_at(vsock_uds_path: &str) -> Result<bool> {
    let mut stream = connect_to(vsock_uds_path, DEFAULT_TIMEOUT_SECS)?;
    let resp = send_request(&mut stream, &GuestRequest::Ping)?;
    Ok(matches!(resp, GuestResponse::Pong))
}

/// Query the guest agent process's current RSS through a direct UDS path.
pub fn query_resource_usage_at(vsock_uds_path: &str) -> Result<u64> {
    let mut stream = connect_to(vsock_uds_path, DEFAULT_TIMEOUT_SECS)?;
    resource_usage_response(send_request(&mut stream, &GuestRequest::ResourceUsage)?)
}

fn resource_usage_response(response: GuestResponse) -> Result<u64> {
    match response {
        GuestResponse::ResourceUsageReport { rss_bytes } => Ok(rss_bytes),
        GuestResponse::Error { message } => bail!("Guest resource usage error: {message}"),
        _ => bail!("Unexpected response to ResourceUsage"),
    }
}

/// Query worker status from the guest vsock agent at a specific UDS path.
pub fn query_worker_status_at(vsock_uds_path: &str) -> Result<GuestResponse> {
    let mut stream = connect_to(vsock_uds_path, DEFAULT_TIMEOUT_SECS)?;
    send_request(&mut stream, &GuestRequest::WorkerStatus)
}

/// Query integration status from the guest agent at a specific UDS path.
pub fn query_integration_status_at(
    vsock_uds_path: &str,
) -> Result<Vec<crate::integrations::IntegrationStateReport>> {
    let mut stream = connect_to(vsock_uds_path, DEFAULT_TIMEOUT_SECS)?;
    let resp = send_request(&mut stream, &GuestRequest::IntegrationStatus)?;

    match resp {
        GuestResponse::IntegrationStatusReport { integrations } => Ok(integrations),
        GuestResponse::Error { message } => {
            bail!("Guest integration status error: {}", message);
        }
        _ => bail!("Unexpected response to IntegrationStatus"),
    }
}

/// Query probe status from the guest agent.
pub fn query_probe_status(instance_dir: &str) -> Result<Vec<crate::probes::ProbeResult>> {
    let mut stream = connect(instance_dir, DEFAULT_TIMEOUT_SECS)?;
    let resp = send_request(&mut stream, &GuestRequest::ProbeStatus)?;

    match resp {
        GuestResponse::ProbeStatusReport { probes } => Ok(probes),
        GuestResponse::Error { message } => {
            bail!("Guest probe status error: {}", message);
        }
        _ => bail!("Unexpected response to ProbeStatus"),
    }
}

/// Query probe status from the guest agent at a specific UDS path.
pub fn query_probe_status_at(vsock_uds_path: &str) -> Result<Vec<crate::probes::ProbeResult>> {
    let mut stream = connect_to(vsock_uds_path, DEFAULT_TIMEOUT_SECS)?;
    let resp = send_request(&mut stream, &GuestRequest::ProbeStatus)?;

    match resp {
        GuestResponse::ProbeStatusReport { probes } => Ok(probes),
        GuestResponse::Error { message } => {
            bail!("Guest probe status error: {}", message);
        }
        _ => bail!("Unexpected response to ProbeStatus"),
    }
}

/// Outcome of a `PostRestore` signal: whether the guest acknowledged the
/// signal, rotated its VMGenID, and applied the host wall-clock epoch.
///
/// `reseeded` is the load-bearing field for the warm-start verb's honesty —
/// `acknowledged` only says the guest answered, `reseeded` says it rotated,
/// and `clock_resynced` says the restore clock was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostRestoreReply {
    /// The guest acknowledged the post-restore signal with success.
    pub acknowledged: bool,
    /// The guest rotated its VMGenID from the delivered token.
    pub reseeded: bool,
    /// The guest applied the host-provided wall-clock epoch.
    pub clock_resynced: bool,
}

/// Interpret a guest's response to `PostRestore` into the host-facing reply.
/// Pure so the success/reseeded mapping is unit-tested without a live agent.
fn interpret_post_restore(resp: GuestResponse) -> Result<PostRestoreReply> {
    match resp {
        GuestResponse::PostRestoreAck {
            success,
            reseeded,
            clock_resynced,
            ..
        } => Ok(PostRestoreReply {
            acknowledged: success,
            reseeded,
            clock_resynced,
        }),
        GuestResponse::Error { message } => {
            bail!("Guest post-restore error: {}", message);
        }
        _ => bail!("Unexpected response to PostRestore"),
    }
}

/// Signal post-restore to the guest agent at a specific UDS path.
///
/// After snapshot restore, tells the guest to rotate its VMGenID with the
/// host-minted `token` (so two clones of one snapshot diverge), then remount
/// config/secrets drives and restart services. An all-zero `token` is a
/// no-rotation restore. Returns the guest's [`PostRestoreReply`] so the caller
/// can surface whether the guest actually reseeded.
pub fn post_restore_at(
    vsock_uds_path: &str,
    token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
) -> Result<PostRestoreReply> {
    let mut stream = connect_to(vsock_uds_path, DEFAULT_TIMEOUT_SECS)?;
    let resp = send_request(
        &mut stream,
        &GuestRequest::PostRestore {
            token,
            host_epoch_secs: None,
            grant_envelope: None,
        },
    )?;
    interpret_post_restore(resp)
}

/// Like [`post_restore_at`] but carries an optional verb-grant envelope so
/// the guest re-pins its grant without a reboot. `None` degrades to the
/// same behaviour as [`post_restore_at`].
pub fn post_restore_with_grant_at(
    vsock_uds_path: &str,
    token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
    grant_envelope: Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>,
) -> Result<PostRestoreReply> {
    post_restore_with_grant_and_clock_at(vsock_uds_path, token, grant_envelope, None)
}

/// Like [`post_restore_with_grant_at`] but also asks the guest to synchronize
/// its wall clock before restarting init-owned services.
pub fn post_restore_with_grant_and_clock_at(
    vsock_uds_path: &str,
    token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
    grant_envelope: Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>,
    host_epoch_secs: Option<u64>,
) -> Result<PostRestoreReply> {
    let mut stream = connect_to(vsock_uds_path, DEFAULT_TIMEOUT_SECS)?;
    let resp = send_request(
        &mut stream,
        &GuestRequest::PostRestore {
            token,
            host_epoch_secs,
            grant_envelope,
        },
    )?;
    interpret_post_restore(resp)
}

/// Filesystem marker a workload creates to signal it has finished warming
/// (caches/JITs/model load done). The guest agent reports its presence on a
/// `PrimedStatus` query; the host's warm-snapshot barrier waits for it before
/// sealing. A tmpfs path the workload can write with no extra privilege.
pub const PRIMED_MARKER_PATH: &str = "/run/mvm/primed";

/// Whether the workload has signalled "primed": the marker exists. Pure so the
/// agent-side check is unit-testable without a live guest.
pub fn workload_is_primed_at(marker: &std::path::Path) -> bool {
    marker.exists()
}

/// Interpret a guest's response to `PrimedStatus`. Pure so the mapping is
/// unit-tested without a live agent.
pub fn interpret_primed_status(resp: GuestResponse) -> Result<bool> {
    match resp {
        GuestResponse::PrimedStatusReport { primed } => Ok(primed),
        GuestResponse::Error { message } => bail!("Guest primed-status error: {}", message),
        _ => bail!("Unexpected response to PrimedStatus"),
    }
}

/// Query whether the workload has signalled "primed" via the guest agent at a
/// specific UDS path. One-shot; the host barrier polls this until primed or it
/// times out.
pub fn query_primed_at(vsock_uds_path: &str) -> Result<bool> {
    let mut stream = connect_to(vsock_uds_path, DEFAULT_TIMEOUT_SECS)?;
    let resp = send_request(&mut stream, &GuestRequest::PrimedStatus)?;
    interpret_primed_status(resp)
}

/// Query filesystem diff from the guest agent at a specific UDS path.
///
/// Returns the list of filesystem changes since boot (created, modified,
/// deleted files). The guest agent walks the overlay filesystem to compute
/// the diff.
pub fn query_fs_diff(instance_dir: &str) -> Result<Vec<FsChange>> {
    let mut stream = connect(instance_dir, DEFAULT_TIMEOUT_SECS)?;
    query_fs_diff_on(&mut stream)
}

/// Query filesystem diff at a specific UDS path.
pub fn query_fs_diff_at(vsock_uds_path: &str) -> Result<Vec<FsChange>> {
    let mut stream = connect_to(vsock_uds_path, DEFAULT_TIMEOUT_SECS)?;
    query_fs_diff_on(&mut stream)
}

/// Query filesystem diff on an already-connected stream. Backend-agnostic
/// entry point for `mvmctl diff` — the stream comes from
/// `mvm_runtime::vsock_transport::for_vm(name)` so the verb works against any VMM.
/// `FsDiff` is part of the filesystem RPC surface, so this drives
/// the hello prelude requiring `FilesystemRpc` exactly like
/// [`send_fs_request_on`] — the dir-based wrappers used to skip the hello,
/// which a hard-cutover agent would reject.
pub fn query_fs_diff_on(stream: &mut UnixStream) -> Result<Vec<FsChange>> {
    require_capabilities(stream, &[GuestCapability::FilesystemRpc])?;
    let resp = send_request(stream, &GuestRequest::FsDiff)?;
    match resp {
        GuestResponse::FsDiffResult { changes } => Ok(changes),
        GuestResponse::Error { message } => {
            bail!("Guest fs-diff error: {}", message);
        }
        _ => bail!("Unexpected response to FsDiff"),
    }
}

/// Dispatch a non-streaming process-control request to a running
/// VM and return the `ProcResult`. Single-frame surface — the
/// streaming `ProcWait` verb has its own helper below. Dir-based
/// wrapper over [`send_proc_request_on`] for callers that still pass
/// an instance dir (mvmd, mock).
pub fn send_proc_request(instance_dir: &str, req: GuestRequest) -> Result<ProcResult> {
    let mut stream = connect(instance_dir, DEFAULT_TIMEOUT_SECS)?;
    send_proc_request_on(&mut stream, req)
}

/// Dispatch a non-streaming process-control verb on an already-connected
/// stream and return the `ProcResult`. The backend-agnostic entry point:
/// the host CLI obtains the stream from `mvm_runtime::vsock_transport::for_vm(name)`
/// so `mvmctl proc` works regardless of which VMM launched the VM.
/// `send_proc_request` is the dir-based wrapper over this.
pub fn send_proc_request_on(stream: &mut UnixStream, req: GuestRequest) -> Result<ProcResult> {
    debug_assert!(matches!(
        req,
        GuestRequest::ProcStart { .. }
            | GuestRequest::ProcList
            | GuestRequest::ProcSignal { .. }
            | GuestRequest::ProcSendInput { .. }
            | GuestRequest::ProcKill { .. }
    ));
    require_capabilities(stream, &[GuestCapability::ProcessRpc])?;
    let resp = send_request(stream, &req)?;
    match resp {
        GuestResponse::ProcResult(r) => Ok(r),
        GuestResponse::Error { message } => {
            bail!("Guest proc-control transport error: {}", message)
        }
        _ => bail!("Unexpected response to proc-control verb"),
    }
}

/// Stream `ProcWait` events for `pid_token`. Calls `on_event` for
/// every non-terminal frame and returns the terminal event. Mirrors
/// the host shape of `send_run_entrypoint`. Dir-based wrapper over
/// [`send_proc_wait_on`].
pub fn send_proc_wait<F: FnMut(&ProcWaitEvent)>(
    instance_dir: &str,
    pid_token: &str,
    timeout_secs: Option<u64>,
    on_event: F,
) -> Result<ProcWaitEvent> {
    let mut stream = connect(instance_dir, DEFAULT_TIMEOUT_SECS)?;
    send_proc_wait_on(&mut stream, pid_token, timeout_secs, on_event)
}

/// Stream `ProcWait` events on an already-connected stream. Backend-agnostic
/// entry point for `mvmctl proc wait` — the stream comes from
/// `mvm_runtime::vsock_transport::for_vm(name)` so the verb works against any VMM.
/// Mirrors the host shape of [`send_run_entrypoint`].
pub fn send_proc_wait_on<F: FnMut(&ProcWaitEvent)>(
    stream: &mut UnixStream,
    pid_token: &str,
    timeout_secs: Option<u64>,
    mut on_event: F,
) -> Result<ProcWaitEvent> {
    require_capabilities(stream, &[GuestCapability::ProcessRpc])?;
    let req = GuestRequest::ProcWait {
        pid_token: pid_token.to_string(),
        timeout_secs,
    };
    let mut session = super::connection::open_authenticated_session(stream)?;
    session.write(stream, &req)?;
    loop {
        let resp: GuestResponse = session.read(stream)?;
        match resp {
            GuestResponse::ProcWaitEvent(ev) => {
                if ev.is_terminal() {
                    return Ok(ev);
                }
                on_event(&ev);
            }
            GuestResponse::Error { message } => {
                bail!("Guest proc-wait transport error: {}", message)
            }
            _ => bail!("Unexpected response in proc-wait stream"),
        }
    }
}

/// Dispatch a single FS RPC request to a running VM and return the
/// `FsResult`. Wraps `connect` + `send_request` for `mvmctl fs *`
/// callers — the host CLI doesn't need to thread a `UnixStream`
/// around.
pub fn send_fs_request(instance_dir: &str, req: GuestRequest) -> Result<FsResult> {
    debug_assert!(matches!(
        req,
        GuestRequest::FsRead { .. }
            | GuestRequest::FsWrite { .. }
            | GuestRequest::FsList { .. }
            | GuestRequest::FsStat { .. }
            | GuestRequest::FsMkdir { .. }
            | GuestRequest::FsRemove { .. }
            | GuestRequest::FsMove { .. }
    ));
    let mut stream = connect(instance_dir, DEFAULT_TIMEOUT_SECS)?;
    send_fs_request_on(&mut stream, req)
}

/// Dispatch a single FS RPC on an already-connected stream and return the
/// `FsResult`. The backend-agnostic entry point: the host CLI obtains the
/// stream from `mvm_runtime::vsock_transport::for_vm(name)` (which resolves the
/// right socket per backend — Firecracker's `v.sock`, or the per-port UNIX
/// socket libkrun/QEMU expose), so `fs`/`cp` work regardless of which VMM
/// launched the VM. `send_fs_request` is the dir-based wrapper
/// over this for callers that still pass an instance dir (mvmd, mock).
pub fn send_fs_request_on(stream: &mut UnixStream, req: GuestRequest) -> Result<FsResult> {
    require_capabilities(stream, &[GuestCapability::FilesystemRpc])?;
    let resp = send_request(stream, &req)?;
    match resp {
        GuestResponse::FsResult(r) => Ok(r),
        GuestResponse::Error { message } => bail!("Guest FS RPC transport error: {}", message),
        _ => bail!("Unexpected response to FS RPC verb"),
    }
}

/// Host-side helper: ask the guest agent to mount an already-attached
/// virtio-fs volume at `guest_path`. `volume_name` is the virtio-fs tag
/// the host registered (`uvol{idx}`). Returns the guest's canonical
/// mount path on success. The guest validates `guest_path` against its
/// `MountPathPolicy` (allow-roots `/mnt`, `/data`, `/work`); a denied
/// path surfaces here as an error rather than a silent no-mount.
pub fn mount_volume_on(
    stream: &mut UnixStream,
    volume_name: &str,
    guest_path: &str,
    read_only: bool,
) -> Result<String> {
    let _ = negotiate_protocol(stream, Vec::new())?;
    let resp = send_request(
        stream,
        &GuestRequest::MountVolume {
            volume_name: volume_name.to_string(),
            guest_path: guest_path.to_string(),
            read_only,
        },
    )?;
    match resp {
        GuestResponse::VolumeMountResult(VolumeMountResult::Mounted { canonical_path }) => {
            Ok(canonical_path)
        }
        GuestResponse::VolumeMountResult(VolumeMountResult::Error { kind, message }) => {
            bail!("guest refused volume '{volume_name}' -> {guest_path} ({kind:?}): {message}")
        }
        GuestResponse::VolumeMountResult(other) => {
            bail!("unexpected volume-mount result for '{volume_name}': {other:?}")
        }
        GuestResponse::Error { message } => {
            bail!("guest error mounting '{volume_name}': {message}")
        }
        _ => bail!("unexpected response to MountVolume for '{volume_name}'"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_is_primed_reflects_marker_presence() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("primed");
        assert!(
            !workload_is_primed_at(&marker),
            "absent marker → not primed"
        );
        std::fs::write(&marker, b"").unwrap();
        assert!(workload_is_primed_at(&marker), "present marker → primed");
    }

    #[test]
    fn interpret_primed_status_maps_report_and_errors() {
        assert!(
            interpret_primed_status(GuestResponse::PrimedStatusReport { primed: true }).unwrap()
        );
        assert!(
            !interpret_primed_status(GuestResponse::PrimedStatusReport { primed: false }).unwrap()
        );
        assert!(
            interpret_primed_status(GuestResponse::Error {
                message: "x".into()
            })
            .is_err()
        );
    }

    #[test]
    fn resource_usage_response_maps_report_and_rejects_other_variants() {
        assert_eq!(
            resource_usage_response(GuestResponse::ResourceUsageReport { rss_bytes: 4096 })
                .unwrap(),
            4096
        );
        assert!(
            resource_usage_response(GuestResponse::Error {
                message: "unavailable".into()
            })
            .is_err()
        );
        assert!(resource_usage_response(GuestResponse::Pong).is_err());
    }

    #[test]
    fn interpret_post_restore_maps_ack_reseeded_and_errors() {
        // Positive ack with rotation.
        let r = interpret_post_restore(GuestResponse::PostRestoreAck {
            success: true,
            detail: None,
            reseeded: true,
            clock_resynced: true,
        })
        .unwrap();
        assert!(r.acknowledged && r.reseeded && r.clock_resynced);
        // Acknowledged but the guest did not rotate (e.g. a zero/no-op token).
        let r = interpret_post_restore(GuestResponse::PostRestoreAck {
            success: true,
            detail: None,
            reseeded: false,
            clock_resynced: false,
        })
        .unwrap();
        assert!(r.acknowledged && !r.reseeded);
        // A guest-reported failure ack is surfaced as acknowledged=false.
        let r = interpret_post_restore(GuestResponse::PostRestoreAck {
            success: false,
            detail: Some("kill failed".into()),
            reseeded: false,
            clock_resynced: false,
        })
        .unwrap();
        assert!(!r.acknowledged && !r.reseeded);
        // A transport-level error / off-contract response is an Err.
        assert!(
            interpret_post_restore(GuestResponse::Error {
                message: "boom".into()
            })
            .is_err()
        );
    }

    #[test]
    fn test_ping_at_nonexistent_path() {
        let result = ping_at("/nonexistent/v.sock");
        assert!(result.is_err());
    }

    #[test]
    fn test_query_worker_status_at_nonexistent_path() {
        let result = query_worker_status_at("/nonexistent/v.sock");
        assert!(result.is_err());
    }

    #[test]
    fn test_query_integration_status_at_nonexistent_path() {
        let result = query_integration_status_at("/nonexistent/v.sock");
        assert!(result.is_err());
    }

    #[test]
    fn test_query_probe_status_at_nonexistent_path() {
        let result = query_probe_status_at("/nonexistent/v.sock");
        assert!(result.is_err());
    }
}
