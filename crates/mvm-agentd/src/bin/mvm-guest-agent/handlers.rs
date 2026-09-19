//! The always-compiled per-verb request handlers, plus the `RunEntrypoint`
//! execution machinery (validated-entrypoint dispatch, warm-pool routing,
//! and the per-call TMPDIR). DevOnly handlers live in the sibling
//! `interactive` module and are admitted by the request dispatcher only after
//! runtime profile and signed-grant checks.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mvm_agentd::entrypoint::{CallCaps, CancellationToken, EntrypointCall, ProcessResourceLimits};
use mvm_agentd::entrypoint_stream::stream_call;
use mvm_agentd::stream_input::InputDesk;
use mvm_agentd::stream_pump::{CapturedOutput, StreamGap};
use mvm_agentd::vsock::{
    ComponentState, DriveFileOperation, DriveRefusal, EntrypointEvent, ExtensionCancellation,
    ExtensionDispatch, FsChange, FsChangeKind, GuestResponse, RunEntrypointError,
};
use mvm_agentd::worker_pool::{DispatchError, DispatchOutcome, WorkerPool};
use mvm_agentd::worker_protocol::WorkerOutcome;
use mvm_contract::stream::input::{CloseInput, InputFrame};

use crate::HandlerCtx;
use crate::globals::{
    RUN_ENTRYPOINT_LOCK, VALIDATED_ENTRYPOINT, VALIDATED_EXTENSIONS, WARM_POOL,
    reseed_on_post_restore,
};
use crate::health::build_integration_reports;
use crate::port_forward::start_unix_socket_forwarder;
use crate::probe::build_probe_reports;
use crate::socket::write_response;

/// Sync filesystems and drop page cache.
fn do_sleep_prep() -> (bool, String) {
    do_sleep_prep_with(mvm_agentd::filesystem_sync::flush_filesystems, || {
        std::fs::write("/proc/sys/vm/drop_caches", "3").is_ok()
    })
}

fn do_sleep_prep_with(
    flush_filesystems: impl FnOnce(),
    drop_page_cache: impl FnOnce() -> bool,
) -> (bool, String) {
    // The direct syscall is part of the runtime agent, so even a scratch OCI
    // image with no `sync` executable can acknowledge durable teardown.
    flush_filesystems();
    let drop_ok = drop_page_cache();

    if drop_ok {
        (true, "filesystems synced, page cache dropped".to_string())
    } else {
        (
            true,
            "filesystems synced, page cache drop failed (non-root?)".to_string(),
        )
    }
}

/// Generate a per-call TMPDIR path under /tmp. The mutex guarantees only
/// one in-flight call per VM, so a name collision is exceedingly unlikely
/// — but use pid + nanos anyway to survive any post-crash leftovers.
fn make_call_tmpdir() -> std::io::Result<CallTmpdir> {
    use std::os::unix::fs::DirBuilderExt;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let path = PathBuf::from(format!("/tmp/mvm-call-{pid}-{nanos:x}"));
    std::fs::DirBuilder::new().mode(0o700).create(&path)?;
    Ok(CallTmpdir { path })
}

/// RAII wrapper that removes the TMPDIR on drop. The cleanup runs from the
/// agent — robust to wrapper crashes, kills, and any panic on the agent's
/// own side.
struct CallTmpdir {
    path: PathBuf,
}

impl CallTmpdir {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CallTmpdir {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.path) {
            eprintln!(
                "mvm-guest-agent: TMPDIR cleanup failed for {}: {e}",
                self.path.display()
            );
        }
    }
}

/// Wrap an `EntrypointEvent` in a `GuestResponse` for vsock framing.
fn evt(e: EntrypointEvent) -> GuestResponse {
    GuestResponse::EntrypointEvent(e)
}

fn drive_evt(e: EntrypointEvent) -> GuestResponse {
    GuestResponse::DriveEvent(e)
}

fn emit_entrypoint_bytes(file: &mut dyn Write, bytes: &[u8], stdout: bool) {
    for chunk in bytes.chunks(mvm_agentd::vsock::MAX_DATA_CHUNK_SIZE) {
        let event = if stdout {
            EntrypointEvent::Stdout {
                chunk: chunk.to_vec(),
            }
        } else {
            EntrypointEvent::Stderr {
                chunk: chunk.to_vec(),
            }
        };
        write_response(file, &evt(event));
    }
}

/// Replay one call's captured output onto the response stream: stdout, then
/// stderr, then every control record. A retention gap is appended to the
/// control records rather than written inline, so the host learns output was
/// dropped without the notice landing in the middle of the workload's own
/// bytes.
///
/// The warm path only. A warm worker answers with one buffered frame, so
/// replay is all there is to do with it; the cold path streams each event as
/// the pump produces it and never assembles a buffer to replay.
fn emit_captured_output(file: &mut dyn Write, output: CapturedOutput) {
    emit_entrypoint_bytes(file, &output.stdout, true);
    emit_entrypoint_bytes(file, &output.stderr, false);
    let mut records = output.controls;
    records.extend(output.gaps.iter().map(StreamGap::control_record));
    emit_controls(file, records);
}

/// Handle a `RunEntrypoint` request. Writes streaming events directly via
/// `write_response` and returns the terminal event for the dispatcher to
/// send through the existing `match` arm pattern.
///
#[inline(never)]
fn handle_run_entrypoint(
    file: &mut dyn Write,
    stdin: Vec<u8>,
    timeout_secs: u64,
    env: Vec<(String, String)>,
    stream_input: bool,
) -> GuestResponse {
    // When a warm-process pool is active, route through it instead
    // of the cold-respawn path. The host wire is identical;
    // the pool's `dispatch` synthesizes the same `EntrypointEvent`
    // stream (Stdout / Stderr / Exit | Error) we'd produce below.
    if let Some(Some(pool)) = WARM_POOL.get() {
        // A warm worker's stdin belongs to the pool, not to this call, so
        // there is no pipe to hand the input desk. Refusing is the only honest
        // answer: accepting and quietly ignoring the flag would leave the host
        // holding an input lease, and the writer offering frames, for a stdin
        // that closed before the workload ever ran.
        if stream_input {
            return evt(EntrypointEvent::Error {
                kind: RunEntrypointError::InternalError,
                message: "streamed stdin is not available while a warm process pool is active"
                    .into(),
            });
        }
        return dispatch_via_warm_pool(file, pool, stdin, timeout_secs, env);
    }

    let _guard = match RUN_ENTRYPOINT_LOCK.try_lock() {
        Ok(g) => g,
        Err(_) => {
            return evt(EntrypointEvent::Error {
                kind: RunEntrypointError::Busy,
                message: "another RunEntrypoint call is in flight".into(),
            });
        }
    };

    let entrypoint = match VALIDATED_ENTRYPOINT.get() {
        Some(Ok(e)) => e,
        Some(Err(msg)) => {
            return evt(EntrypointEvent::Error {
                kind: RunEntrypointError::EntrypointInvalid,
                message: msg.clone(),
            });
        }
        None => {
            return evt(EntrypointEvent::Error {
                kind: RunEntrypointError::EntrypointInvalid,
                message: "entrypoint validation never ran".into(),
            });
        }
    };

    let tmpdir = match make_call_tmpdir() {
        Ok(t) => t,
        Err(e) => {
            return evt(EntrypointEvent::Error {
                kind: RunEntrypointError::InternalError,
                message: format!("create per-call TMPDIR: {e}"),
            });
        }
    };

    let call = EntrypointCall {
        entrypoint,
        cwd: tmpdir.path(),
        stdin: &stdin,
        timeout: Duration::from_secs(timeout_secs),
        caps: CallCaps::v1(),
        resource_limits: None,
        cancellation: None,
        env,
        stream_input,
    };

    // Each event is framed the moment it arrives, so the host sees a
    // long-running workload's output while it is still running. Nothing is
    // held back to be replayed after the child exits — that replay is what
    // made a streaming pump look silent from the outside. A `Control` here is
    // either the agent's own (a retention gap, constructed in-process) or one
    // that came off fd 3 through the reserved-kind gate, so a workload still
    // cannot mint an agent-authored record.
    //
    // tmpdir drops at end of scope and runs its `Drop` cleanup.
    let terminal = stream_call(call, &mut |event| {
        write_response(&mut *file, &evt(event));
    });
    evt(terminal)
}

/// Execute one boot-validated optional extension with no program-selection
/// surface. Every identity is compared before a process exists.
pub(crate) fn handle_run_extension(
    file: &mut dyn Write,
    dispatch: ExtensionDispatch,
) -> GuestResponse {
    let extensions = match VALIDATED_EXTENSIONS.get() {
        Some(Ok(extensions)) => extensions,
        Some(Err(message)) => {
            return evt(EntrypointEvent::Error {
                kind: RunEntrypointError::EntrypointInvalid,
                message: message.clone(),
            });
        }
        None => {
            return evt(EntrypointEvent::Error {
                kind: RunEntrypointError::EntrypointInvalid,
                message: "optional extensions were not activated".to_string(),
            });
        }
    };
    let Some(extension) = extensions.iter().find(|candidate| {
        candidate.config.binding.extension_id == dispatch.extension_id
            && candidate.config.binding.pack_digest == dispatch.pack_digest
            && candidate.config.binding.contract_digest == dispatch.contract_digest
    }) else {
        return evt(EntrypointEvent::Error {
            kind: RunEntrypointError::EntrypointInvalid,
            message: "extension identity was not admitted".to_string(),
        });
    };
    if extension.config.plan_id != dispatch.plan_id {
        return evt(EntrypointEvent::Error {
            kind: RunEntrypointError::EntrypointInvalid,
            message: "extension plan identity mismatch".to_string(),
        });
    }
    let budgets = extension.config.binding.budgets;
    if dispatch.input.len() > usize::try_from(budgets.max_payload_bytes).expect("u32 fits in usize")
    {
        return evt(EntrypointEvent::Error {
            kind: RunEntrypointError::InternalError,
            message: "extension input exceeds its admitted budget".to_string(),
        });
    }
    let _guard = match extension.call_lock.try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            return evt(EntrypointEvent::Error {
                kind: RunEntrypointError::Busy,
                message: "extension concurrency budget is exhausted".to_string(),
            });
        }
    };
    let active_call = match extension.cancellation.begin(dispatch.cancellation()) {
        Ok(active) => active,
        Err(message) => {
            return evt(EntrypointEvent::Error {
                kind: RunEntrypointError::Busy,
                message,
            });
        }
    };
    let tmpdir = match make_call_tmpdir() {
        Ok(tmpdir) => tmpdir,
        Err(error) => {
            return evt(EntrypointEvent::Error {
                kind: RunEntrypointError::InternalError,
                message: format!("create extension TMPDIR: {error}"),
            });
        }
    };
    let output_max = usize::try_from(budgets.max_output_bytes).expect("u32 fits in usize");
    let call = EntrypointCall {
        entrypoint: &extension.entrypoint,
        cwd: tmpdir.path(),
        stdin: &dispatch.input,
        timeout: Duration::from_millis(budgets.duration_ms),
        caps: CallCaps {
            stdin_max: usize::try_from(budgets.max_payload_bytes).expect("u32 fits in usize"),
            stdout_max: output_max,
            stderr_max: output_max,
            fd3_max: 0,
            ..CallCaps::v1()
        },
        resource_limits: Some(ProcessResourceLimits {
            address_space_bytes: budgets.memory_bytes,
            cpu_millis: budgets.cpu_millis,
        }),
        cancellation: Some(active_call.token()),
        env: Vec::new(),
        stream_input: false,
    };
    let mut emitted = 0usize;
    let terminal = stream_call(call, &mut |event| {
        let bytes = match &event {
            EntrypointEvent::Stdout { chunk } | EntrypointEvent::Stderr { chunk } => chunk.len(),
            _ => 0,
        };
        if emitted.saturating_add(bytes) <= output_max {
            emitted = emitted.saturating_add(bytes);
            write_response(&mut *file, &evt(event));
        }
    });
    evt(terminal)
}

/// Cancel only the active call whose complete admitted identity matches.
pub(crate) fn handle_cancel_extension(cancellation: ExtensionCancellation) -> GuestResponse {
    let extensions = match VALIDATED_EXTENSIONS.get() {
        Some(Ok(extensions)) => extensions,
        _ => {
            return GuestResponse::Error {
                message: "extension cancellation did not match an active call".to_string(),
            };
        }
    };
    let Some(extension) = extensions.iter().find(|candidate| {
        candidate.config.binding.extension_id == cancellation.extension_id
            && candidate.config.binding.pack_digest == cancellation.pack_digest
            && candidate.config.binding.contract_digest == cancellation.contract_digest
            && candidate.config.plan_id == cancellation.plan_id
    }) else {
        return GuestResponse::Error {
            message: "extension cancellation did not match an active call".to_string(),
        };
    };
    match extension
        .cancellation
        .request_and_wait(&cancellation, Duration::from_secs(5))
    {
        Ok(()) => GuestResponse::ExtensionCancellationAck,
        Err(message) => GuestResponse::Error { message },
    }
}

/// Emit each control record a warm worker returned as one
/// `EntrypointEvent::Control` frame on the response stream. Records go out
/// after stdout and stderr, which the worker's single buffered response frame
/// leaves no way to improve on; the host accepts non-terminal events in any
/// order before the terminal `Exit` / `Error`.
///
/// Every record here has already passed the reserved-kind gate at the pool's
/// ingest, so this writes agent-authored records and workload records that do
/// not claim to be one.
fn emit_controls(file: &mut dyn Write, records: Vec<mvm_agentd::entrypoint::ControlRecord>) {
    for record in records {
        // The conversion is also where the frame budget applies, so a record
        // too wide to frame becomes a bounded notice instead of an oversized
        // frame the writer would replace with a fatal error response.
        write_response(file, &evt(record.into()));
    }
}

/// Route a `RunEntrypoint` request through the warm-process worker
/// pool. The pool's `dispatch` returns a single
/// `DispatchOutcome` per call (one buffered frame), which we
/// translate back into the existing host-facing `EntrypointEvent`
/// stream — same wire shape as the cold path so `mvmctl invoke` is
/// unaffected.
///
#[inline(never)]
fn dispatch_via_warm_pool(
    file: &mut dyn Write,
    pool: &Arc<WorkerPool>,
    stdin: Vec<u8>,
    timeout_secs: u64,
    env: Vec<(String, String)>,
) -> GuestResponse {
    match pool.dispatch(stdin, timeout_secs, env) {
        Ok(DispatchOutcome {
            stdout,
            stderr,
            controls,
            outcome,
        }) => {
            // The pool answers with buffers rather than a pump, so it can
            // never report a gap — but it goes out the one emission path.
            emit_captured_output(
                file,
                CapturedOutput {
                    stdout,
                    stderr,
                    controls,
                    gaps: Vec::new(),
                },
            );
            match outcome {
                WorkerOutcome::Exit { code } => evt(EntrypointEvent::Exit { code }),
                WorkerOutcome::Error { kind, message } => evt(EntrypointEvent::Error {
                    kind: map_worker_error_kind(&kind),
                    message,
                }),
            }
        }
        Err(DispatchError::QueueFull) => evt(EntrypointEvent::Error {
            kind: RunEntrypointError::Busy,
            message: "warm-process pool queue is full".into(),
        }),
        Err(DispatchError::ShuttingDown) => evt(EntrypointEvent::Error {
            kind: RunEntrypointError::InternalError,
            message: "warm-process pool is shutting down".into(),
        }),
        Err(DispatchError::NoLiveWorkers) => evt(EntrypointEvent::Error {
            kind: RunEntrypointError::InternalError,
            message: "warm-process pool has no live workers".into(),
        }),
        // after_start readiness probe has not yet succeeded —
        // workload is still warming up. Surface as Busy
        // so the host's retry semantics apply (same as queue-full);
        // the message distinguishes the cause for operators.
        Err(DispatchError::NotReady) => evt(EntrypointEvent::Error {
            kind: RunEntrypointError::Busy,
            message: "warm-process pool warming up (after_start probe not yet ready)".into(),
        }),
    }
}

fn map_worker_error_kind(kind: &str) -> RunEntrypointError {
    match kind {
        "wrapper_crash" => RunEntrypointError::WrapperCrashed,
        "timeout" => RunEntrypointError::Timeout,
        _ => RunEntrypointError::InternalError,
    }
}

/// Collect filesystem changes by walking the overlay upper directory.
///
/// When the rootfs is mounted read-only with an overlay (squashfs + tmpfs),
/// all writes go to the upper dir (typically /overlay/upper). Walking it
/// reveals every file created or modified since boot.
///
/// Falls back to an empty list if the overlay dir doesn't exist (non-overlay
/// rootfs or unrestricted mode).
fn collect_fs_diff() -> Vec<FsChange> {
    // Common overlay upper dir paths
    let upper_dirs = ["/overlay/upper", "/run/overlay/upper", "/tmp/overlay/upper"];
    let upper = upper_dirs.iter().find(|p| std::path::Path::new(p).is_dir());

    let Some(upper_dir) = upper else {
        return Vec::new();
    };

    let mut changes = Vec::new();
    walk_dir(std::path::Path::new(upper_dir), upper_dir, &mut changes);
    changes.sort_by(|a, b| a.path.cmp(&b.path));
    changes
}

fn walk_dir(dir: &std::path::Path, strip_prefix: &str, changes: &mut Vec<FsChange>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let rel = path
            .to_str()
            .unwrap_or("")
            .strip_prefix(strip_prefix)
            .unwrap_or("")
            .to_string();

        if rel.is_empty() {
            continue;
        }

        if path.is_dir() {
            walk_dir(&path, strip_prefix, changes);
        } else {
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            // In overlay upper dir, whiteout files (.wh.*) indicate deletion
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if let Some(deleted_name) = filename.strip_prefix(".wh.") {
                let parent = path.parent().unwrap_or(&path);
                let del_rel = parent
                    .to_str()
                    .unwrap_or("")
                    .strip_prefix(strip_prefix)
                    .unwrap_or("");
                changes.push(FsChange {
                    path: format!("{}/{}", del_rel, deleted_name),
                    kind: FsChangeKind::Deleted,
                    size: 0,
                });
            } else {
                // File exists in upper = created or modified
                changes.push(FsChange {
                    path: rel,
                    kind: FsChangeKind::Created, // can't distinguish create vs modify from overlay alone
                    size,
                });
            }
        }
    }
}

pub(crate) fn handle_ping() -> GuestResponse {
    GuestResponse::Pong
}

pub(crate) fn handle_resource_usage() -> GuestResponse {
    match mvm_agentd::worker_pool::process_rss_bytes(std::process::id()) {
        Some(rss_bytes) => GuestResponse::ResourceUsageReport { rss_bytes },
        None => GuestResponse::Error {
            message: "guest agent RSS is unavailable".to_string(),
        },
    }
}

pub(crate) fn handle_worker_status(ctx: &mut HandlerCtx) -> GuestResponse {
    let (status, last_busy_at) = match ctx.state.lock() {
        Ok(s) => (s.status.clone(), s.last_busy_at.clone()),
        Err(_) => ("unknown".to_string(), None),
    };
    GuestResponse::WorkerStatus {
        status,
        last_busy_at,
    }
}

pub(crate) fn handle_sleep_prep(_drain_timeout_secs: u64) -> GuestResponse {
    let (success, detail) = do_sleep_prep();
    GuestResponse::SleepPrepAck {
        success,
        detail: Some(detail),
    }
}

pub(crate) fn handle_wake(ctx: &mut HandlerCtx) -> GuestResponse {
    // Reset monitoring state after wake from snapshot.
    if let Ok(mut s) = ctx.state.lock() {
        s.status = "idle".to_string();
        s.last_busy_at = None;
    }
    GuestResponse::WakeAck { success: true }
}

pub(crate) fn handle_integration_status(ctx: &mut HandlerCtx) -> GuestResponse {
    GuestResponse::IntegrationStatusReport {
        integrations: build_integration_reports(ctx.integration_state, ctx.boot_state.boot_at),
    }
}

pub(crate) fn handle_checkpoint_integrations(_integrations: Vec<String>) -> GuestResponse {
    GuestResponse::CheckpointResult {
        success: true,
        failed: vec![],
        detail: None,
    }
}

pub(crate) fn handle_probe_status(ctx: &mut HandlerCtx) -> GuestResponse {
    GuestResponse::ProbeStatusReport {
        probes: build_probe_reports(ctx.probe_state),
    }
}

pub(crate) fn handle_primed_status() -> GuestResponse {
    GuestResponse::PrimedStatusReport {
        primed: mvm_agentd::vsock::workload_is_primed_at(std::path::Path::new(
            mvm_agentd::vsock::PRIMED_MARKER_PATH,
        )),
    }
}

pub(crate) fn handle_post_restore(
    ctx: &mut HandlerCtx,
    token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
    hostname: Option<&str>,
    host_epoch_secs: Option<u64>,
    grant_envelope: Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>,
) -> GuestResponse {
    // First, rotate the generation token: feed the host-minted token to the
    // process-resident reseeder. Its state is captured in the snapshot,
    // so two clones of one snapshot both diverge from the captured
    // value when the host delivers each a distinct fresh token. A
    // zero token (no-rotation restore) is a no-op.
    let reseed = reseed_on_post_restore(token);
    let (clock_resynced, clock_error) = match host_epoch_secs {
        None => (false, None),
        Some(epoch_secs) => match mvm_agentd::restore_clock::resync(epoch_secs) {
            Ok(()) => (true, None),
            Err(error) => (false, Some(format!("clock resync failed: {error}"))),
        },
    };
    let hostname_error = hostname.and_then(|value| {
        mvm_agentd::guest_hostname::provision(value)
            .err()
            .map(|error| format!("hostname provisioning failed: {error}"))
    });
    // Re-pin the verb grant if the host sent a fresh envelope. This
    // covers restore across a plan change (a fork mints a fresh
    // host-signed grant with the child's new session_id/plan_nonce and
    // may widen the verb set). The envelope is verified against the
    // boot-pinned host-signer anchor — NOT the self-attested key inside
    // the envelope, which any caller able to deliver a PostRestore could
    // forge. With no boot anchor there is nothing to trust the envelope
    // against, so the re-pin is refused (fail closed).
    if let Some(env) = grant_envelope.as_ref() {
        match ctx.boot_state.host_signer_key() {
            Some(anchor) => {
                let (_, current_grant) = ctx.boot_state.grant_state();
                if let Some(g) = mvm_agentd::vsock::re_pin_verb_grant(
                    env,
                    current_grant.as_ref(),
                    &anchor,
                    chrono::Utc::now(),
                ) {
                    ctx.boot_state.set_verb_grant(g);
                }
            }
            None => eprintln!(
                "mvm-guest-agent: PostRestore re-pin refused — no boot-pinned host-signer anchor"
            ),
        }
    }
    // Then send SIGUSR1 to PID 1 to trigger drive remount + service restart.
    let mut command = std::process::Command::new("kill");
    command.args(["-USR1", "1"]);
    mvm_agentd::fd_hygiene::configure_close_fds(&mut command, 3, None);
    let result = command.output();
    let signal_detail = match result {
        Ok(out) if out.status.success() => None,
        Ok(out) => Some(format!(
            "kill failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )),
        Err(e) => Some(format!("failed to send signal: {}", e)),
    };
    post_restore_ack(PostRestoreSteps {
        reseed,
        hostname_requested: hostname.is_some(),
        hostname_error,
        clock_requested: host_epoch_secs.is_some(),
        clock_resynced,
        clock_error,
        signal_error: signal_detail,
    })
}

/// What each post-restore step did, gathered so the acknowledgement is decided
/// in one place that can be tested without a guest.
struct PostRestoreSteps {
    reseed: mvm_agentd::genid::GenIdAction,
    hostname_requested: bool,
    hostname_error: Option<String>,
    clock_requested: bool,
    clock_resynced: bool,
    clock_error: Option<String>,
    signal_error: Option<String>,
}

/// Build the `PostRestoreAck`.
///
/// `success` covers the steps that finish bringing the guest back — hostname,
/// clock, the init signal. The reseed is reported on its own, as `reseeded`
/// plus a shortfall and a reason in `detail`, so a guest that could not reseed
/// is not mistaken for one whose drives are still unmounted.
fn post_restore_ack(steps: PostRestoreSteps) -> GuestResponse {
    let reseeded = steps.reseed.reseeded();
    let (reseed_shortfall, reseed_note) = match steps.reseed {
        mvm_agentd::genid::GenIdAction::ReseedFailed(failure) => {
            let label = match failure.shortfall {
                mvm_agentd::vsock::ReseedShortfall::HelperMissing => "restore reseed unavailable",
                mvm_agentd::vsock::ReseedShortfall::Failed => "restore reseed failed",
            };
            (
                Some(failure.shortfall),
                Some(format!("{label}: {}", failure.reason)),
            )
        }
        mvm_agentd::genid::GenIdAction::Unchanged | mvm_agentd::genid::GenIdAction::Reseeded => {
            (None, None)
        }
    };
    let errors = [steps.hostname_error, steps.clock_error, steps.signal_error]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let success = errors.is_empty();
    let summary = if success {
        match (steps.hostname_requested, steps.clock_requested) {
            (true, true) => "post-restore hostname, clock sync, and init signal completed",
            (true, false) => "post-restore hostname and init signal completed",
            (false, true) => "post-restore clock sync and init signal completed",
            (false, false) => "post-restore signal sent to init",
        }
        .to_string()
    } else {
        errors.join("; ")
    };
    let detail = match reseed_note {
        Some(note) => format!("{summary}; {note}"),
        None => summary,
    };
    GuestResponse::PostRestoreAck {
        success,
        detail: Some(detail),
        reseeded,
        clock_resynced: steps.clock_resynced,
        reseed_shortfall,
    }
}

/// `RunEntrypoint` arm: distinguish "validation hasn't completed yet"
/// (Starting → NotReady, transient) from "validation failed"
/// (Failed → EntrypointInvalid, terminal) before delegating to the
/// real handler. Snapshot once so the decision is consistent even if
/// a concurrent background-thread update flips state mid-handler.
pub(crate) fn handle_run_entrypoint_request(
    ctx: &mut HandlerCtx,
    stdin: Vec<u8>,
    timeout_secs: u64,
    env: Vec<(String, String)>,
    stream_input: bool,
) -> GuestResponse {
    if matches!(
        ctx.boot_state.snapshot().entrypoint,
        ComponentState::Starting
    ) {
        GuestResponse::EntrypointEvent(EntrypointEvent::Error {
            kind: RunEntrypointError::NotReady,
            message: "entrypoint validation in progress; poll ReadinessStatus and retry"
                .to_string(),
        })
    } else {
        handle_run_entrypoint(ctx.file, stdin, timeout_secs, env, stream_input)
    }
}

/// Start the boot-validated entrypoint under the pinned drive authority. The
/// program identity has already been compared by the dispatcher gate; this
/// handler independently canonicalizes the working directory against the
/// granted roots before spawning and derives every cap from the grant.
pub(crate) fn handle_drive_open(
    ctx: &mut HandlerCtx,
    cwd: &str,
    env: Vec<(String, String)>,
    grant: Option<&mvm_contract::grants::DriveGrant>,
) -> GuestResponse {
    let Some(grant) = grant else {
        return GuestResponse::DriveRefused {
            reason: DriveRefusal::NotGranted,
        };
    };
    if matches!(
        ctx.boot_state.snapshot().entrypoint,
        ComponentState::Starting
    ) {
        return drive_evt(EntrypointEvent::Error {
            kind: RunEntrypointError::NotReady,
            message: "entrypoint validation in progress; poll ReadinessStatus and retry".into(),
        });
    }
    let policy = mvm_core::crypto::policy::PathPolicy::default().with_allow_roots(
        grant
            .workspace_roots
            .iter()
            .map(mvm_contract::grants::WorkspaceRoot::as_str),
    );
    let canonical = match policy.validate(
        &mvm_core::crypto::policy::OsCanonicalizer,
        cwd,
        mvm_core::crypto::policy::PathOp::Read,
    ) {
        Ok(path) => path,
        Err(_) => {
            return GuestResponse::DriveRefused {
                reason: DriveRefusal::OutsideWorkspaceRoots,
            };
        }
    };
    let _guard = match RUN_ENTRYPOINT_LOCK.try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            return drive_evt(EntrypointEvent::Error {
                kind: RunEntrypointError::Busy,
                message: "another driven program is in flight".into(),
            });
        }
    };
    let entrypoint = match VALIDATED_ENTRYPOINT.get() {
        Some(Ok(entrypoint)) => entrypoint,
        Some(Err(message)) => {
            return drive_evt(EntrypointEvent::Error {
                kind: RunEntrypointError::EntrypointInvalid,
                message: message.clone(),
            });
        }
        None => {
            return drive_evt(EntrypointEvent::Error {
                kind: RunEntrypointError::EntrypointInvalid,
                message: "entrypoint validation never ran".into(),
            });
        }
    };
    let mut caps = CallCaps::v1();
    caps.stdin_max = usize::try_from(grant.max_bytes_in.get()).unwrap_or(usize::MAX);
    let output_max = usize::try_from(grant.max_bytes_out.get()).unwrap_or(usize::MAX);
    caps.stdout_max = output_max;
    caps.stderr_max = output_max;
    let cancellation = CancellationToken::default();
    let call = EntrypointCall {
        entrypoint,
        cwd: canonical.as_path(),
        stdin: &[],
        timeout: Duration::from_secs(u64::from(grant.ttl.get())),
        caps,
        resource_limits: None,
        cancellation: Some(cancellation.clone()),
        env,
        stream_input: true,
    };
    let mut output_bytes = 0u64;
    let mut output_exceeded = false;
    let terminal = stream_call(call, &mut |event| {
        let chunk_len = match &event {
            EntrypointEvent::Stdout { chunk } | EntrypointEvent::Stderr { chunk } => {
                u64::try_from(chunk.len()).unwrap_or(u64::MAX)
            }
            EntrypointEvent::Control { .. }
            | EntrypointEvent::Exit { .. }
            | EntrypointEvent::Error { .. } => 0,
        };
        output_bytes = output_bytes.saturating_add(chunk_len);
        if output_bytes > grant.max_bytes_out.get() {
            output_exceeded = true;
            cancellation.request();
            return;
        }
        write_response(&mut *ctx.file, &drive_evt(event));
    });
    if output_exceeded {
        drive_evt(EntrypointEvent::Error {
            kind: RunEntrypointError::PayloadCap,
            message: "drive output exceeded max_bytes_out".into(),
        })
    } else {
        drive_evt(terminal)
    }
}

pub(crate) fn handle_drive_file(
    operation: &DriveFileOperation,
    grant: Option<&mvm_contract::grants::DriveGrant>,
) -> GuestResponse {
    let Some(grant) = grant else {
        return GuestResponse::DriveRefused {
            reason: DriveRefusal::NotGranted,
        };
    };
    GuestResponse::FsResult(mvm_agentd::fs_rpc::handle_drive_with_defaults(
        operation, grant,
    ))
}

/// Deliver one host-admitted input frame to the running workload's stdin.
///
/// Nothing here re-decides whether the writer was allowed to send it: that is
/// the host gate's job, and it is the only place with the signed plan, the
/// lease and the secret set to decide it with. The desk's own refusals are
/// about *delivery* — no workload, a frame out of order, a queue at its
/// budget — and none of them wait on the workload to read.
pub(crate) fn handle_stream_input(frame: InputFrame) -> GuestResponse {
    GuestResponse::StreamInputResult(InputDesk::write_frame(frame))
}

/// Deliver the withheld tail, then close the workload's stdin.
pub(crate) fn handle_close_stream_input(close: CloseInput) -> GuestResponse {
    GuestResponse::StreamInputResult(InputDesk::close(close))
}

pub(crate) fn handle_fs_diff() -> GuestResponse {
    // Walk the overlay upper dir to find changes since boot.
    // The overlay upper dir is typically at /overlay/upper when
    // the rootfs is mounted read-only with an overlay.
    let changes = collect_fs_diff();
    GuestResponse::FsDiffResult { changes }
}

pub(crate) fn handle_start_unix_socket_forward(
    guest_path: String,
    host_vsock_port: u32,
    socket_mode: u32,
) -> GuestResponse {
    match start_unix_socket_forwarder(&guest_path, host_vsock_port, socket_mode) {
        Ok(()) => GuestResponse::UnixSocketForwardStarted {
            guest_path,
            host_vsock_port,
        },
        Err(err) => GuestResponse::Error {
            message: format!("unix socket forward failed: {err}"),
        },
    }
}

pub(crate) fn handle_entrypoint_status() -> GuestResponse {
    match VALIDATED_ENTRYPOINT.get() {
        Some(Ok(v)) => GuestResponse::EntrypointStatusReport {
            ok: true,
            path: Some(v.resolved.display().to_string()),
            detail: None,
        },
        Some(Err(msg)) => GuestResponse::EntrypointStatusReport {
            ok: false,
            path: None,
            detail: Some(msg.clone()),
        },
        // With background init, `None` means validation is still
        // running, not "never ran".
        None => GuestResponse::EntrypointStatusReport {
            ok: false,
            path: None,
            detail: Some("entrypoint validation in progress".to_string()),
        },
    }
}

pub(crate) fn handle_readiness_status(ctx: &mut HandlerCtx) -> GuestResponse {
    GuestResponse::ReadinessStatusReport(ctx.boot_state.snapshot())
}

pub(crate) fn handle_fs_read(path: String, offset: Option<u64>, length: u64) -> GuestResponse {
    GuestResponse::FsResult(mvm_agentd::fs_rpc::handle_with_defaults(
        mvm_agentd::fs_rpc::FsRequest::Read {
            path: &path,
            offset,
            length,
        },
    ))
}

pub(crate) fn handle_fs_write(
    path: String,
    content: Vec<u8>,
    mode: u32,
    create_parents: bool,
    offset: u64,
    truncate: bool,
) -> GuestResponse {
    GuestResponse::FsResult(mvm_agentd::fs_rpc::handle_with_defaults(
        mvm_agentd::fs_rpc::FsRequest::Write {
            path: &path,
            content: &content,
            mode,
            create_parents,
            offset,
            truncate,
        },
    ))
}

pub(crate) fn handle_fs_list(path: String) -> GuestResponse {
    GuestResponse::FsResult(mvm_agentd::fs_rpc::handle_with_defaults(
        mvm_agentd::fs_rpc::FsRequest::List { path: &path },
    ))
}

pub(crate) fn handle_fs_stat(path: String, follow_symlinks: bool) -> GuestResponse {
    GuestResponse::FsResult(mvm_agentd::fs_rpc::handle_with_defaults(
        mvm_agentd::fs_rpc::FsRequest::Stat {
            path: &path,
            follow_symlinks,
        },
    ))
}

pub(crate) fn handle_fs_mkdir(path: String, mode: u32, parents: bool) -> GuestResponse {
    GuestResponse::FsResult(mvm_agentd::fs_rpc::handle_with_defaults(
        mvm_agentd::fs_rpc::FsRequest::Mkdir {
            path: &path,
            mode,
            parents,
        },
    ))
}

pub(crate) fn handle_fs_remove(path: String, recursive: bool) -> GuestResponse {
    GuestResponse::FsResult(mvm_agentd::fs_rpc::handle_with_defaults(
        mvm_agentd::fs_rpc::FsRequest::Remove {
            path: &path,
            recursive,
        },
    ))
}

pub(crate) fn handle_fs_move(from: String, to: String) -> GuestResponse {
    GuestResponse::FsResult(mvm_agentd::fs_rpc::handle_with_defaults(
        mvm_agentd::fs_rpc::FsRequest::Move {
            from: &from,
            to: &to,
        },
    ))
}

pub(crate) fn handle_proc_start(
    argv: Vec<String>,
    env: std::collections::BTreeMap<String, String>,
    cwd: Option<String>,
    stdin: Vec<u8>,
) -> GuestResponse {
    let caps = mvm_agentd::process_rpc::Caps::production();
    GuestResponse::ProcResult(mvm_agentd::process_rpc::handle_proc_start(
        crate::interactive::proc_registry(),
        &caps,
        &argv,
        &env,
        cwd.as_deref(),
        &stdin,
    ))
}

pub(crate) fn handle_proc_list() -> GuestResponse {
    GuestResponse::ProcResult(mvm_agentd::process_rpc::handle_proc_list(
        crate::interactive::proc_registry(),
    ))
}

pub(crate) fn handle_proc_signal(pid_token: String, signum: i32) -> GuestResponse {
    GuestResponse::ProcResult(mvm_agentd::process_rpc::handle_proc_signal(
        crate::interactive::proc_registry(),
        &pid_token,
        signum,
    ))
}

pub(crate) fn handle_proc_send_input(pid_token: String, bytes: Vec<u8>) -> GuestResponse {
    let caps = mvm_agentd::process_rpc::Caps::production();
    GuestResponse::ProcResult(mvm_agentd::process_rpc::handle_proc_send_input(
        crate::interactive::proc_registry(),
        &caps,
        &pid_token,
        &bytes,
    ))
}

pub(crate) fn handle_proc_kill(pid_token: String) -> GuestResponse {
    GuestResponse::ProcResult(mvm_agentd::process_rpc::handle_proc_kill(
        crate::interactive::proc_registry(),
        &pid_token,
    ))
}

pub(crate) fn handle_proc_wait(
    ctx: &mut HandlerCtx,
    pid_token: String,
    timeout_secs: Option<u64>,
) -> GuestResponse {
    let terminal =
        crate::interactive::handle_proc_wait_streaming(ctx.file, &pid_token, timeout_secs);
    GuestResponse::ProcWaitEvent(terminal)
}

pub(crate) fn handle_mount_volume(
    volume_name: String,
    guest_path: String,
    read_only: bool,
) -> GuestResponse {
    GuestResponse::VolumeMountResult(mvm_agentd::volume::handle_mount(
        &volume_name,
        &guest_path,
        read_only,
    ))
}

pub(crate) fn handle_unmount_volume(guest_path: String, force: bool) -> GuestResponse {
    GuestResponse::VolumeMountResult(mvm_agentd::volume::handle_unmount(&guest_path, force))
}

pub(crate) fn handle_update_idle_timeout(secs: u64) -> GuestResponse {
    match WARM_POOL.get() {
        Some(Some(pool)) => {
            let previous = pool.set_idle_timeout(secs);
            GuestResponse::UpdateIdleTimeoutAck {
                previous_secs: previous,
                applied_secs: secs,
            }
        }
        _ => GuestResponse::UpdateIdleTimeoutAck {
            previous_secs: 0,
            applied_secs: 0,
        },
    }
}

#[cfg(test)]
mod post_restore_ack_tests {
    use mvm_agentd::genid::{GenIdAction, ReseedFailure};
    use mvm_agentd::vsock::ReseedShortfall;

    use super::*;

    fn steps(reseed: GenIdAction) -> PostRestoreSteps {
        PostRestoreSteps {
            reseed,
            hostname_requested: true,
            hostname_error: None,
            clock_requested: true,
            clock_resynced: true,
            clock_error: None,
            signal_error: None,
        }
    }

    fn failed(shortfall: ReseedShortfall, reason: &str) -> GenIdAction {
        GenIdAction::ReseedFailed(ReseedFailure {
            shortfall,
            reason: reason.to_string(),
        })
    }

    #[test]
    fn a_failed_reseed_is_reported_as_not_reseeded_and_names_the_reason() {
        let GuestResponse::PostRestoreAck {
            success,
            detail,
            reseeded,
            clock_resynced,
            reseed_shortfall,
        } = post_restore_ack(steps(failed(
            ReseedShortfall::Failed,
            "forcing the kernel generator to rekey failed: EPERM",
        )))
        else {
            panic!("post-restore must answer with a PostRestoreAck");
        };
        assert!(!reseeded, "a failed reseed must never be reported as done");
        assert_eq!(reseed_shortfall, Some(ReseedShortfall::Failed));
        assert!(
            success,
            "the restore steps themselves completed; the reseed is reported on its own"
        );
        let detail = detail.expect("a failure carries its reason");
        assert!(
            detail.contains("restore reseed failed") && detail.contains("EPERM"),
            "{detail}"
        );
        assert!(clock_resynced);
    }

    #[test]
    fn a_guest_without_a_helper_says_so_distinctly() {
        let GuestResponse::PostRestoreAck {
            reseeded,
            reseed_shortfall,
            detail,
            ..
        } = post_restore_ack(steps(failed(
            ReseedShortfall::HelperMissing,
            "no CRNG reseed helper is running in this guest",
        )))
        else {
            panic!("post-restore must answer with a PostRestoreAck");
        };
        assert!(!reseeded);
        assert_eq!(reseed_shortfall, Some(ReseedShortfall::HelperMissing));
        assert!(
            detail.is_some_and(|d| d.contains("restore reseed unavailable")),
            "an image without a helper is not reported as a failed reseed"
        );
    }

    #[test]
    fn a_failed_restore_step_and_a_failed_reseed_are_both_reported() {
        let mut both = steps(failed(ReseedShortfall::Failed, "EPERM"));
        both.signal_error = Some("kill failed".to_string());
        let GuestResponse::PostRestoreAck {
            success, detail, ..
        } = post_restore_ack(both)
        else {
            panic!("post-restore must answer with a PostRestoreAck");
        };
        assert!(!success);
        let detail = detail.unwrap_or_default();
        assert!(
            detail.contains("kill failed") && detail.contains("restore reseed failed"),
            "{detail}"
        );
    }

    #[test]
    fn a_completed_reseed_is_reported_as_reseeded() {
        let GuestResponse::PostRestoreAck {
            success,
            reseeded,
            reseed_shortfall,
            ..
        } = post_restore_ack(steps(GenIdAction::Reseeded))
        else {
            panic!("post-restore must answer with a PostRestoreAck");
        };
        assert!(success && reseeded);
        assert_eq!(reseed_shortfall, None);
    }

    #[test]
    fn a_no_rotation_restore_succeeds_without_claiming_a_reseed() {
        let GuestResponse::PostRestoreAck {
            success,
            reseeded,
            reseed_shortfall,
            ..
        } = post_restore_ack(steps(GenIdAction::Unchanged))
        else {
            panic!("post-restore must answer with a PostRestoreAck");
        };
        assert!(success && !reseeded);
        assert_eq!(reseed_shortfall, None);
    }
}

#[cfg(test)]
mod sleep_prep_tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn sleep_prep_flushes_before_dropping_cache_and_acknowledging() {
        let flushed = Cell::new(false);
        let (success, detail) = do_sleep_prep_with(
            || flushed.set(true),
            || {
                assert!(flushed.get(), "cache drop must follow the filesystem flush");
                true
            },
        );

        assert!(success);
        assert_eq!(detail, "filesystems synced, page cache dropped");
    }

    #[test]
    fn cache_drop_failure_does_not_downgrade_a_completed_flush() {
        let (success, detail) = do_sleep_prep_with(|| {}, || false);

        assert!(success);
        assert!(detail.contains("filesystems synced"), "{detail}");
        assert!(detail.contains("cache drop failed"), "{detail}");
    }
}
