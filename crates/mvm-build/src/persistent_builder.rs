//! Host-side scaffold for the persistent builder VM's dispatch
//! supervisor.
//!
//! `PersistentBuilderSupervisor` owns the host end of the
//! dispatch socket libkrun creates at
//! `<vm_state_dir>/vsock-<BUILDER_DISPATCH_PORT>.sock` once the
//! persistent VM is up. Callers — eventually `mvmctl build` from
//! inside an active persistent-builder session — submit a
//! [`crate::builder_vm::BuilderJob`] via `Self::submit`; the
//! supervisor serializes it to a
//! [`crate::builder_protocol::HostVmRequest::Run`], writes the
//! frame over the socket, then reads back streamed
//! [`crate::builder_protocol::HostVmResponse::StderrChunk`] frames
//! followed by a terminating
//! [`crate::builder_protocol::HostVmResponse::Result`].
//!
//! ## Why serialize V1
//!
//! V1 is one in-flight dispatch per
//! supervisor. The dispatch mutex guards the socket so two
//! concurrent submits don't interleave their `HostVmRequest` /
//! `HostVmResponse` frames on the same connection. V2+ parallel
//! dispatch (per-job overlay namespaces + per-job vsock conns) is
//! an explicit non-goal of this plan.

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::builder_protocol::{
    BootTimingsWire, HostVmRequest, HostVmResponse, JobId, JobTimings, WorkloadId,
};
use crate::builder_vm::BuilderJob;
use mvm_contract::builder::BuilderError;

/// Host-side hook the persistent dispatch
/// supervisor calls at the boundaries of each dispatched job so a
/// production adapter can extend the chain-signed audit log
/// (`~/.mvm/audit/<tenant>.jsonl`) without `mvm-build` depending
/// on `mvm-supervisor`.
///
/// Why a trait instead of a direct call to
/// `mvm_hostd::supervisor::FileAuditSigner`:
///
/// - `mvm-build` sits below `mvm-supervisor` in the workspace
///   dependency graph (the supervisor uses `mvm-build`'s
///   `BuilderJob` shape, not the other way around). A direct
///   call would invert the graph.
/// - The persistent-builder dev verb (`mvmctl persistent-builder
///   submit`) doesn't have a parent ExecutionPlan to bind to; it
///   passes `None` and the supervisor skips the emit. The trait
///   gives that opt-out a typed shape.
/// - Tests want a recording fake. `RecordingBuilderAuditSink`
///   below ships as a `#[cfg(any(test, feature = "test-fakes"))]`
///   util.
///
/// The three methods correspond to three event kinds:
///
/// - [`Self::dispatched`] — fires after the supervisor writes
///   the `HostVmRequest::Run` frame and before it starts
///   collecting responses. Records the start of the
///   `job_id`-tagged sub-chain.
/// - [`Self::completed`] — fires after a successful
///   `HostVmResponse::Result` (exit_code is whatever the build
///   produced; non-zero exits are still "completed" from the
///   dispatch supervisor's POV).
/// - [`Self::failed`] — fires when the supervisor surfaces a
///   [`PersistentBuilderError`] (PrematureEof, JobIdMismatch,
///   SocketUnreachable, framing I/O). Distinct from a non-zero
///   build exit code, which the host wraps in `completed`.
///
/// All three methods are best-effort from the supervisor's POV:
/// the trait returns `()` rather than `Result` so an audit-emit
/// failure can't fail-close the dispatch. The production adapter
/// is expected to log emit failures itself (a corrupted audit
/// chain is a separate alarm).
pub trait BuilderAuditSink: Send + Sync {
    /// `dispatched` fires after the request was written to the
    /// guest, *before* reading the first response. The supervisor
    /// passes the request's `job_id`, the `BuilderJob` (for hash
    /// derivation), and `job_dir_relpath` so the entry can be
    /// reproduced later from the audit row alone.
    fn dispatched(&self, job_id: JobId, job: &BuilderJob, job_dir_relpath: &str);

    /// `completed` fires after a terminating `Result` frame
    /// arrived. `exit_code` is the build's process exit;
    /// non-zero is still "completed" (the dispatch round
    /// terminated normally).
    fn completed(&self, job_id: JobId, exit_code: i32, job_timings: JobTimings);

    /// `failed` fires when the dispatch round itself errored
    /// (premature EOF, job-id mismatch, socket unreachable,
    /// framing I/O). The error's `Display` is stable enough to
    /// store in the entry; callers should *also* log the
    /// underlying error with full chain.
    fn failed(&self, job_id: JobId, reason: &str);
}

/// Default timeout for the entire dispatch round (write request +
/// drain stderr stream + read terminating Result). Generous because
/// real builds can take minutes; callers that want a hard upper
/// bound should wrap their own timeout above [`Self::submit`].
const DEFAULT_DISPATCH_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Per-frame read timeout. Bounds how long the supervisor blocks
/// waiting for the next StderrChunk / Result if the guest's
/// dispatch loop is wedged. The chosen 30 s is large enough that a
/// busy nix-build with quiet stderr stretches don't trip it, while
/// being small enough that a crashed guest doesn't pin the host
/// thread for the full `DEFAULT_DISPATCH_TIMEOUT`.
const DEFAULT_FRAME_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The completed outcome of one dispatched job. Mirrors the wire
/// shape of [`HostVmResponse::Result`] plus an in-process
/// accumulation of the stderr chunks that streamed in before the
/// terminating Result.
#[derive(Debug, Clone)]
pub struct DispatchOutcome {
    pub job_id: JobId,
    pub exit_code: i32,
    pub stderr_tail: String,
    pub stderr_chunks: Vec<String>,
    pub boot_timings: Option<Box<BootTimingsWire>>,
    pub job_timings: JobTimings,
}

/// The spawn config for a nested workload microVM,
/// the host-side input to [`HostVmRequest::WorkloadStart`]. All
/// paths are resolved *inside the host VM* (see the protocol doc);
/// the backend branch stages the artifacts into a host-VM share and
/// fills these with the guest-visible paths.
#[derive(Debug, Clone)]
pub struct WorkloadStartParams {
    pub kernel_path: String,
    pub rootfs_path: String,
    pub vsock_socket_dir: String,
    pub vcpus: u32,
    pub memory_mib: u32,
    pub kernel_cmdline_extras: String,
}

impl WorkloadStartParams {
    /// Start building a [`WorkloadStartParams`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> WorkloadStartParamsBuilder {
        WorkloadStartParamsBuilder::new()
    }
}

/// Builder for [`WorkloadStartParams`]. Required fields are checked by
/// [`WorkloadStartParamsBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct WorkloadStartParamsBuilder {
    kernel_path: Option<String>,
    rootfs_path: Option<String>,
    vsock_socket_dir: Option<String>,
    vcpus: Option<u32>,
    memory_mib: Option<u32>,
    kernel_cmdline_extras: Option<String>,
}

impl WorkloadStartParamsBuilder {
    /// An empty builder: nothing set yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            kernel_path: None,
            rootfs_path: None,
            vsock_socket_dir: None,
            vcpus: None,
            memory_mib: None,
            kernel_cmdline_extras: None,
        }
    }

    /// Set `kernel_path`.
    #[must_use]
    pub fn kernel_path(mut self, kernel_path: String) -> Self {
        self.kernel_path = Some(kernel_path);
        self
    }

    /// Set `rootfs_path`.
    #[must_use]
    pub fn rootfs_path(mut self, rootfs_path: String) -> Self {
        self.rootfs_path = Some(rootfs_path);
        self
    }

    /// Set `vsock_socket_dir`.
    #[must_use]
    pub fn vsock_socket_dir(mut self, vsock_socket_dir: String) -> Self {
        self.vsock_socket_dir = Some(vsock_socket_dir);
        self
    }

    /// Set `vcpus`.
    #[must_use]
    pub fn vcpus(mut self, vcpus: u32) -> Self {
        self.vcpus = Some(vcpus);
        self
    }

    /// Set `memory_mib`.
    #[must_use]
    pub fn memory_mib(mut self, memory_mib: u32) -> Self {
        self.memory_mib = Some(memory_mib);
        self
    }

    /// Set `kernel_cmdline_extras`.
    #[must_use]
    pub fn kernel_cmdline_extras(mut self, kernel_cmdline_extras: String) -> Self {
        self.kernel_cmdline_extras = Some(kernel_cmdline_extras);
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<WorkloadStartParams, BuilderError> {
        Ok(WorkloadStartParams {
            kernel_path: self
                .kernel_path
                .ok_or(BuilderError::missing("WorkloadStartParams", "kernel_path"))?,
            rootfs_path: self
                .rootfs_path
                .ok_or(BuilderError::missing("WorkloadStartParams", "rootfs_path"))?,
            vsock_socket_dir: self.vsock_socket_dir.ok_or(BuilderError::missing(
                "WorkloadStartParams",
                "vsock_socket_dir",
            ))?,
            vcpus: self
                .vcpus
                .ok_or(BuilderError::missing("WorkloadStartParams", "vcpus"))?,
            memory_mib: self
                .memory_mib
                .ok_or(BuilderError::missing("WorkloadStartParams", "memory_mib"))?,
            kernel_cmdline_extras: self.kernel_cmdline_extras.ok_or(BuilderError::missing(
                "WorkloadStartParams",
                "kernel_cmdline_extras",
            ))?,
        })
    }
}

impl Default for WorkloadStartParamsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of a successful `WorkloadStart` dispatch:
/// the host-minted id the guest echoed and the spawned VMM pid
/// (inside the host VM) the host tracks for lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadStartOutcome {
    pub workload_id: WorkloadId,
    pub pid: u32,
}

/// Typed error surface for [`PersistentBuilderSupervisor`].
#[derive(Debug, Error)]
pub enum PersistentBuilderError {
    /// The dispatch socket was unreachable at submit time. Usually
    /// means the persistent VM is down or libkrun hasn't yet
    /// created the proxy socket. Caller may want to fall back to
    /// the single-shot [`crate::libkrun_builder::LibkrunBuilderVm`]
    /// path.
    #[error("dispatch socket {socket} unreachable: {source}")]
    SocketUnreachable {
        socket: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Reading or writing a frame failed mid-dispatch. The guest
    /// most likely crashed; subsequent submits will hit
    /// [`Self::SocketUnreachable`] until the supervisor restarts
    /// the VM.
    #[error("dispatch frame I/O error: {0}")]
    Frame(#[from] std::io::Error),

    /// Guest sent a frame whose `job_id` didn't match the
    /// request's. Hard failure — V1's serialized dispatch means
    /// every response should belong to the one in-flight job, so a
    /// mismatch means the guest's dispatch loop is corrupted.
    #[error("job_id mismatch: request {request:?}, response {response:?}")]
    JobIdMismatch { request: JobId, response: JobId },

    /// Guest closed the connection before sending a terminating
    /// [`HostVmResponse::Result`]. Could mean kernel panic, OOM
    /// kill of the build process, or a logic bug in the dispatch
    /// loop. Distinguished from [`Self::SocketUnreachable`] because
    /// the *connection* was established and partial output was
    /// received.
    #[error("dispatch ended without Result frame after {chunks} stderr chunks")]
    PrematureEof { chunks: usize },

    /// Internal: dispatch mutex poisoned (a previous submit panicked
    /// mid-flight). Caller should rebuild the supervisor.
    #[error("dispatch mutex poisoned — caller must restart the supervisor")]
    MutexPoisoned,

    /// The guest returned [`HostVmResponse::WorkloadFailed`]
    /// for a workload lifecycle request (spawn / stop). Carries the
    /// guest's failure reason.
    #[error("workload {workload_id} failed in host VM: {error}")]
    WorkloadFailed {
        workload_id: WorkloadId,
        error: String,
    },

    /// The guest answered a workload request with a
    /// frame of the wrong kind (e.g. a `WorkloadStopped` for a
    /// `WorkloadStart`). A protocol violation — the dispatch loop is
    /// corrupted or out of sync.
    #[error("unexpected response to {expected}: got {got}")]
    UnexpectedResponse {
        expected: &'static str,
        got: &'static str,
    },
}

/// Persistent builder VM dispatch supervisor.
///
/// `socket_path` is `<vm_state_dir>/vsock-<BUILDER_DISPATCH_PORT>.sock`
/// — the libkrun-managed Unix socket that proxies to AF_VSOCK port
/// [`mvm_agentd::builder_agent::BUILDER_DISPATCH_PORT`] inside the
/// guest. The owner of the persistent VM (`LibkrunPersistentHostVm`)
/// constructs this supervisor once the VM is up, then hands the
/// result to whatever submits jobs (`mvmctl build` from inside a dev
/// session).
pub struct PersistentBuilderSupervisor {
    socket_path: PathBuf,
    dispatch_mutex: Mutex<()>,
    frame_read_timeout: Duration,
    dispatch_timeout: Duration,
    /// Optional audit sink. `None` means
    /// the supervisor doesn't emit chain entries (matches the
    /// dev-only `mvmctl persistent-builder` verb, which doesn't
    /// run under an ExecutionPlan). `Some(_)` means every
    /// dispatch round emits `dispatched` then `completed` or
    /// `failed`.
    audit_sink: Option<Arc<dyn BuilderAuditSink>>,
}

impl PersistentBuilderSupervisor {
    /// Construct a supervisor against the given dispatch socket.
    /// Doesn't actually connect — connection is per-submit so a
    /// crashed-then-restarted VM doesn't require restarting the
    /// supervisor. The socket is opportunistically probed
    /// (`std::path::Path::exists`) so callers get a clean
    /// `SocketUnreachable` immediately for the obvious case.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            dispatch_mutex: Mutex::new(()),
            frame_read_timeout: DEFAULT_FRAME_READ_TIMEOUT,
            dispatch_timeout: DEFAULT_DISPATCH_TIMEOUT,
            audit_sink: None,
        }
    }

    /// Wire a [`BuilderAuditSink`] in so the
    /// supervisor emits `builder.job.dispatched` /
    /// `builder.job.completed` / `builder.job.failed` events on
    /// the chain-signed audit log around each dispatch round.
    /// `None` (the default) means no audit emission — used by
    /// the dev-only `mvmctl persistent-builder` verb.
    pub fn with_audit_sink(mut self, sink: Arc<dyn BuilderAuditSink>) -> Self {
        self.audit_sink = Some(sink);
        self
    }

    /// Override the per-frame read timeout. Useful for tests that
    /// want fast fail; production callers should stick with the
    /// default.
    pub fn with_frame_read_timeout(mut self, timeout: Duration) -> Self {
        self.frame_read_timeout = timeout;
        self
    }

    /// Override the whole-dispatch timeout. Same caveat as
    /// [`Self::with_frame_read_timeout`].
    pub fn with_dispatch_timeout(mut self, timeout: Duration) -> Self {
        self.dispatch_timeout = timeout;
        self
    }

    /// Dispatch one [`BuilderJob`] into the persistent VM and
    /// block until the guest sends back a terminating
    /// [`HostVmResponse::Result`]. Holds the dispatch mutex for
    /// the duration (V1 = serialized).
    ///
    /// `job_dir_relpath` is the path inside the `/job` virtio-fs
    /// share where the host has already staged this job's
    /// artifacts (cmd.sh / install_spec.json / etc.). The guest's
    /// dispatch loop resolves it as `/job/<job_dir_relpath>`.
    pub fn submit(
        &self,
        job: BuilderJob,
        job_dir_relpath: String,
    ) -> Result<DispatchOutcome, PersistentBuilderError> {
        let _guard = self
            .dispatch_mutex
            .lock()
            .map_err(|_| PersistentBuilderError::MutexPoisoned)?;

        let job_id = JobId::new();
        // Snapshot the job + relpath for the audit emit before
        // moving them into the HostVmRequest::Run variant; the
        // dispatch loop then consumes the request.
        let job_for_audit = job.clone();
        let relpath_for_audit = job_dir_relpath.clone();
        let request = HostVmRequest::Run {
            job_id,
            job,
            job_dir_relpath,
        };

        // The generic shell-job channel has no typed mvm-builderd equivalent
        // yet, so this dispatch always resolves to the legacy route. Emit the
        // structured diagnostic so the remaining shell surface stays visible
        // and shrinkable; per-operation typed routing (BuildGuestImage /
        // FlakeCheck via BuilderdClient) lands in the callers behind the
        // opt-in flag, flipping this resolution one operation at a time.
        let route = crate::builder_route::resolve_route(
            false,
            crate::builder_route::typed_opt_in(|k| std::env::var(k).ok()),
        );
        if route == crate::builder_route::BuilderRoute::LegacyShell {
            tracing::debug!(
                target: "mvm::builder",
                "{}",
                crate::builder_route::legacy_shell_diagnostic(&job_id.to_string())
            );
        }

        // Emit `dispatched` before the round begins. Reasons:
        //
        // 1. If the dispatch round itself errors, the host still
        //    records that a job was attempted (and the matching
        //    `failed` emit closes the pair).
        // 2. The audit chain is append-only; we want the
        //    `dispatched` row written before `completed`/`failed`
        //    so a reader walking the chain in order sees the
        //    natural lifecycle.
        if let Some(sink) = &self.audit_sink {
            sink.dispatched(job_id, &job_for_audit, &relpath_for_audit);
        }

        match self.dispatch(&request, job_id) {
            Ok(outcome) => {
                if let Some(sink) = &self.audit_sink {
                    sink.completed(job_id, outcome.exit_code, outcome.job_timings);
                }
                Ok(outcome)
            }
            Err(e) => {
                if let Some(sink) = &self.audit_sink {
                    sink.failed(job_id, &e.to_string());
                }
                Err(e)
            }
        }
    }

    /// Dispatch a [`HostVmRequest::WorkloadStart`] to
    /// the host VM, which spawns the workload microVM (Firecracker)
    /// inside itself. Mints a fresh [`WorkloadId`], returns the
    /// echoed id + spawned VMM pid on success, or
    /// [`PersistentBuilderError::WorkloadFailed`] if the guest
    /// refused. Workload requests get a single reply (no streaming),
    /// so this uses `Self::dispatch_single_response` rather than the
    /// build-job `Self::dispatch` streaming loop.
    pub fn submit_workload_start(
        &self,
        params: WorkloadStartParams,
    ) -> Result<WorkloadStartOutcome, PersistentBuilderError> {
        let _guard = self
            .dispatch_mutex
            .lock()
            .map_err(|_| PersistentBuilderError::MutexPoisoned)?;
        let workload_id = WorkloadId::new();
        let request = HostVmRequest::WorkloadStart {
            workload_id,
            kernel_path: params.kernel_path,
            rootfs_path: params.rootfs_path,
            vsock_socket_dir: params.vsock_socket_dir,
            vcpus: params.vcpus,
            memory_mib: params.memory_mib,
            kernel_cmdline_extras: params.kernel_cmdline_extras,
        };
        match self.dispatch_single_response(&request)? {
            HostVmResponse::WorkloadStarted {
                workload_id: got,
                pid,
            } => Ok(WorkloadStartOutcome {
                workload_id: got,
                pid,
            }),
            HostVmResponse::WorkloadFailed { workload_id, error } => {
                Err(PersistentBuilderError::WorkloadFailed { workload_id, error })
            }
            other => Err(PersistentBuilderError::UnexpectedResponse {
                expected: "workload_started",
                got: response_kind(&other),
            }),
        }
    }

    /// Dispatch a [`HostVmRequest::WorkloadStop`] and
    /// confirm the guest tore the workload down.
    pub fn submit_workload_stop(
        &self,
        workload_id: WorkloadId,
    ) -> Result<(), PersistentBuilderError> {
        let _guard = self
            .dispatch_mutex
            .lock()
            .map_err(|_| PersistentBuilderError::MutexPoisoned)?;
        let request = HostVmRequest::WorkloadStop { workload_id };
        match self.dispatch_single_response(&request)? {
            HostVmResponse::WorkloadStopped { .. } => Ok(()),
            HostVmResponse::WorkloadFailed { workload_id, error } => {
                Err(PersistentBuilderError::WorkloadFailed { workload_id, error })
            }
            other => Err(PersistentBuilderError::UnexpectedResponse {
                expected: "workload_stopped",
                got: response_kind(&other),
            }),
        }
    }

    /// Dispatch a [`HostVmRequest::WorkloadStatus`].
    /// Returns the guest's status string (`"running"` / `"stopped"`
    /// / `"not_found"`).
    pub fn submit_workload_status(
        &self,
        workload_id: WorkloadId,
    ) -> Result<String, PersistentBuilderError> {
        let _guard = self
            .dispatch_mutex
            .lock()
            .map_err(|_| PersistentBuilderError::MutexPoisoned)?;
        let request = HostVmRequest::WorkloadStatus { workload_id };
        match self.dispatch_single_response(&request)? {
            HostVmResponse::WorkloadStatusReport { status, .. } => Ok(status),
            HostVmResponse::WorkloadFailed { workload_id, error } => {
                Err(PersistentBuilderError::WorkloadFailed { workload_id, error })
            }
            other => Err(PersistentBuilderError::UnexpectedResponse {
                expected: "workload_status_report",
                got: response_kind(&other),
            }),
        }
    }

    /// Connect, write `request`, and read exactly one response frame.
    /// Used by the workload lifecycle calls, which (unlike build-job
    /// dispatch) expect a single reply rather than a stderr stream +
    /// terminating Result. A clean EOF before any frame is a
    /// [`PersistentBuilderError::PrematureEof`] (guest crashed).
    fn dispatch_single_response(
        &self,
        request: &HostVmRequest,
    ) -> Result<HostVmResponse, PersistentBuilderError> {
        let mut stream = self.connect()?;
        let _ = stream.set_read_timeout(Some(self.frame_read_timeout));
        let _ = stream.set_write_timeout(Some(self.frame_read_timeout));
        mvm_agentd::vsock::write_frame(&mut stream, request)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        match read_next_response(&mut stream, self.frame_read_timeout)? {
            Some(resp) => Ok(resp),
            None => Err(PersistentBuilderError::PrematureEof { chunks: 0 }),
        }
    }

    /// Send a [`HostVmRequest::Shutdown`] to the guest's dispatch
    /// loop and wait for the matching [`HostVmResponse::Bye`].
    /// Consumes `self` because the supervisor is one-shot after
    /// shutdown — the VM will power off and the socket goes away.
    pub fn shutdown(self) -> Result<(), PersistentBuilderError> {
        let _guard = self
            .dispatch_mutex
            .lock()
            .map_err(|_| PersistentBuilderError::MutexPoisoned)?;

        let request = HostVmRequest::Shutdown {};
        let mut stream = self.connect()?;
        mvm_agentd::vsock::write_frame(&mut stream, &request)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        // Expect Bye. Any other frame is a protocol violation but
        // we already asked for shutdown — log via the error chain
        // and let the caller treat it as success.
        let _ = read_next_response(&mut stream, self.frame_read_timeout);
        Ok(())
    }

    fn connect(&self) -> Result<UnixStream, PersistentBuilderError> {
        UnixStream::connect(&self.socket_path).map_err(|source| {
            PersistentBuilderError::SocketUnreachable {
                socket: self.socket_path.clone(),
                source,
            }
        })
    }

    fn dispatch(
        &self,
        request: &HostVmRequest,
        request_job_id: JobId,
    ) -> Result<DispatchOutcome, PersistentBuilderError> {
        let started = std::time::Instant::now();
        let mut stream = self.connect()?;
        let _ = stream.set_read_timeout(Some(self.frame_read_timeout));
        let _ = stream.set_write_timeout(Some(self.frame_read_timeout));

        mvm_agentd::vsock::write_frame(&mut stream, request)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        let mut stderr_chunks = Vec::new();
        loop {
            if started.elapsed() > self.dispatch_timeout {
                return Err(PersistentBuilderError::PrematureEof {
                    chunks: stderr_chunks.len(),
                });
            }
            let response = read_next_response(&mut stream, self.frame_read_timeout)?;
            match response {
                Some(HostVmResponse::StderrChunk { job_id, line }) => {
                    if job_id != request_job_id {
                        return Err(PersistentBuilderError::JobIdMismatch {
                            request: request_job_id,
                            response: job_id,
                        });
                    }
                    stderr_chunks.push(line);
                }
                Some(HostVmResponse::Result {
                    job_id,
                    exit_code,
                    stderr_tail,
                    boot_timings,
                    job_timings,
                }) => {
                    if job_id != request_job_id {
                        return Err(PersistentBuilderError::JobIdMismatch {
                            request: request_job_id,
                            response: job_id,
                        });
                    }
                    return Ok(DispatchOutcome {
                        job_id,
                        exit_code,
                        stderr_tail,
                        stderr_chunks,
                        boot_timings,
                        job_timings,
                    });
                }
                Some(HostVmResponse::Bye {}) => {
                    // Bye in the middle of a dispatch is unexpected —
                    // treat as premature EOF.
                    return Err(PersistentBuilderError::PrematureEof {
                        chunks: stderr_chunks.len(),
                    });
                }
                Some(HostVmResponse::WorkloadStarted { .. })
                | Some(HostVmResponse::WorkloadStopped { .. })
                | Some(HostVmResponse::WorkloadStatusReport { .. })
                | Some(HostVmResponse::WorkloadFailed { .. }) => {
                    // Workload responses on the build-job dispatch
                    // path are a protocol violation. Workload
                    // lifecycle responses flow on a dedicated channel
                    // (a vsock-proxy hop), not this build-dispatch
                    // conn. Treat as premature EOF — the host can't
                    // recover from a wire mismatch.
                    return Err(PersistentBuilderError::PrematureEof {
                        chunks: stderr_chunks.len(),
                    });
                }
                None => {
                    // Clean EOF before a Result arrived.
                    return Err(PersistentBuilderError::PrematureEof {
                        chunks: stderr_chunks.len(),
                    });
                }
            }
        }
    }
}

/// The wire `kind` tag of a response, for `UnexpectedResponse`
/// diagnostics. Mirrors the serde `rename_all = "snake_case"` tags.
fn response_kind(resp: &HostVmResponse) -> &'static str {
    match resp {
        HostVmResponse::StderrChunk { .. } => "stderr_chunk",
        HostVmResponse::Result { .. } => "result",
        HostVmResponse::Bye {} => "bye",
        HostVmResponse::WorkloadStarted { .. } => "workload_started",
        HostVmResponse::WorkloadStopped { .. } => "workload_stopped",
        HostVmResponse::WorkloadStatusReport { .. } => "workload_status_report",
        HostVmResponse::WorkloadFailed { .. } => "workload_failed",
    }
}

/// Read the next [`HostVmResponse`] from `stream`. Returns
/// `Ok(None)` on clean EOF and `Err(_)` on any I/O or framing
/// failure. Module-private because the supervisor is the only
/// caller that needs the "Option-on-EOF" semantics.
fn read_next_response(
    stream: &mut UnixStream,
    _read_timeout: Duration,
) -> Result<Option<HostVmResponse>, PersistentBuilderError> {
    match mvm_agentd::vsock::read_frame::<HostVmResponse>(stream) {
        Ok(resp) => Ok(Some(resp)),
        Err(e) => {
            let src = e.source();
            if let Some(io_err) = src.and_then(|s| s.downcast_ref::<std::io::Error>())
                && io_err.kind() == std::io::ErrorKind::UnexpectedEof
            {
                return Ok(None);
            }
            Err(PersistentBuilderError::Frame(std::io::Error::other(
                e.to_string(),
            )))
        }
    }
}

/// Path of the dispatch socket libkrun creates for a builder VM
/// rooted at `vm_state_dir`. Mirrors the convention
/// `libkrun_sys::KrunContext` uses when
/// `add_vsock_port(BUILDER_DISPATCH_PORT)` is configured.
pub fn dispatch_socket_path(vm_state_dir: &Path) -> PathBuf {
    mvm_core::config::vm_vsock_port_socket_at(
        vm_state_dir,
        mvm_agentd::builder_agent::BUILDER_DISPATCH_PORT,
    )
}

// ============================================================
// session record + PersistentBuilderVm
// ============================================================
//
// `mvmctl persistent-builder start` writes the session record at
// `~/.mvm/run/persistent-builder.json` and leaves the supervisor
// child running. `mvm_build::pipeline::dev_build` reads the record
// on every build and routes through `PersistentBuilderVm` (which
// implements `BuilderVm` via the wire) when a session is alive.

/// Session record format mirroring
/// `mvm_cli::commands::build::persistent_builder::SessionRecord`.
/// Duplicated here to keep mvm-build off the mvm-cli direction in
/// the dep graph; the `session_record_serde_matches_mvm_cli` test
/// pins the two shapes together via shared JSON fixtures.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionRecord {
    /// Opaque session ID from the live `PersistentVmHandle`.
    pub session_id: String,
    /// libkrun-managed Unix socket the supervisor connects to.
    pub dispatch_socket_path: PathBuf,
    /// Per-session job dir (bound at `/job` in the guest). Hosts
    /// stage per-dispatch artifacts here before submitting.
    pub job_dir: PathBuf,
    /// Workspace bound at `/work`. Recorded for `mvmctl
    /// persistent-builder status`; not load-bearing here.
    pub workspace_root: PathBuf,
    /// PID of the libkrun supervisor child. Used to check the
    /// session is alive before routing through it.
    pub supervisor_pid: u32,
    /// Last known successful host-side activity against the session.
    ///
    /// Optional for backward compatibility with session records written before
    /// the invocation-driven keeper. Missing means "unknown", and the keeper
    /// treats it as active at the current observation time rather than tearing
    /// down an upgraded user's existing builder immediately.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_activity_unix_secs: Option<u64>,
}

/// Why the invocation-driven keeper should stop the persistent builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderSessionTeardownReason {
    /// `MVM_RESIDENCY=cold` means no resident builder should remain alive.
    ColdPolicy,
    /// Policy requested a parked snapshot after idle, but this libkrun-backed
    /// persistent-builder session has no memory snapshot primitive.
    SnapshotUnavailable,
}

/// Pure decision for a live persistent-builder session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderSessionPolicyDecision {
    Keep,
    Teardown(BuilderSessionTeardownReason),
}

/// Decide what the keeper should do with a live persistent-builder session.
///
/// A real snapshot path for the HVF dev-builder is not wired yet; this hidden
/// `persistent-builder` session is currently libkrun-backed, so a policy-level
/// `Park` decision degrades to teardown rather than pretending a snapshot was
/// captured.
pub fn decide_builder_session_policy(
    record: &SessionRecord,
    policy: &mvm_core::residency::ResidencyPolicy,
    now_unix_secs: u64,
) -> BuilderSessionPolicyDecision {
    if matches!(policy.kind(), mvm_core::residency::ResidencyKind::Cold) {
        return BuilderSessionPolicyDecision::Teardown(BuilderSessionTeardownReason::ColdPolicy);
    }

    let Some(threshold) = builder_session_idle_threshold(policy) else {
        return BuilderSessionPolicyDecision::Keep;
    };
    let idle = session_idle_duration(record, now_unix_secs);
    match mvm_core::residency::decide_builder_residency_action(policy.kind(), idle, threshold) {
        mvm_core::residency::BuilderResidencyAction::Keep => BuilderSessionPolicyDecision::Keep,
        mvm_core::residency::BuilderResidencyAction::Park => {
            BuilderSessionPolicyDecision::Teardown(
                BuilderSessionTeardownReason::SnapshotUnavailable,
            )
        }
        mvm_core::residency::BuilderResidencyAction::Teardown => {
            BuilderSessionPolicyDecision::Teardown(BuilderSessionTeardownReason::ColdPolicy)
        }
    }
}

fn builder_session_idle_threshold(
    policy: &mvm_core::residency::ResidencyPolicy,
) -> Option<Duration> {
    match policy.kind() {
        mvm_core::residency::ResidencyKind::Cold => Some(Duration::ZERO),
        mvm_core::residency::ResidencyKind::Parked => Some(Duration::ZERO),
        mvm_core::residency::ResidencyKind::Warm => policy.idle_timeout(),
    }
}

fn session_idle_duration(record: &SessionRecord, now_unix_secs: u64) -> Duration {
    let last = record.last_activity_unix_secs.unwrap_or(now_unix_secs);
    Duration::from_secs(now_unix_secs.saturating_sub(last))
}

/// On-disk location of the session record. Returns `None` only if
/// `$HOME` isn't set, which would be a misconfigured environment.
pub fn session_record_path() -> Option<PathBuf> {
    mvm_core::config::mvm_home_strict()
        .ok()
        .map(|d| d.join("run").join("persistent-builder.json"))
}

/// Starts a persistent builder session and returns its record.
///
/// Registered by `mvm-cli`, which owns what a start needs — host-binary
/// extraction, builder-image resolution, writing the session record — none of
/// which this crate can reach without inverting the dependency direction. Same
/// arrangement as `builder_backend_select::register_hvf_builder`.
pub type SessionStarter = Box<dyn Fn() -> anyhow::Result<SessionRecord> + Send + Sync>;

static SESSION_STARTER: std::sync::OnceLock<SessionStarter> = std::sync::OnceLock::new();

/// Register the session starter. Called once at CLI startup; later calls are
/// ignored.
pub fn register_session_starter(starter: SessionStarter) {
    let _ = SESSION_STARTER.set(starter);
}

/// Marker naming the process currently starting a session.
///
/// Created with `create_new`, so exactly one racing builder wins it. Two builds
/// hitting a contended store image at the same moment would otherwise both
/// boot a VM, and the loser's supervisor would fail to take the store lock and
/// exit — safe, but a wasted boot and a confusing error.
fn session_start_marker_path() -> Option<PathBuf> {
    session_record_path().map(|p| p.with_extension("starting"))
}

/// How long a build that lost the start race waits for the winner's record.
/// Covers a cold builder boot, which formats and seeds the store disk; the
/// alternative is falling through to queue for the image anyway.
const SESSION_START_WAIT: Duration = Duration::from_secs(180);

/// Outcome of trying to obtain a session to dispatch into.
#[derive(Debug)]
pub enum SessionAcquisition {
    /// A session to dispatch this build into.
    Ready(SessionRecord),
    /// No session, and none was started. The caller falls back to the
    /// single-shot builder, which queues for the store image.
    Unavailable,
}

/// Get a session to share, starting one if nobody has.
///
/// Called when the store image is already held: this build cannot have the
/// image to itself, so its options are to queue for it or to join the VM that
/// holds it. This is the second option.
///
/// Losing the start race is not a failure — the loser waits for the winner's
/// record and dispatches into that same session, which is the point.
pub fn adopt_or_start_session() -> SessionAcquisition {
    if let Some(record) = read_active_session() {
        return SessionAcquisition::Ready(record);
    }
    let Some(starter) = SESSION_STARTER.get() else {
        // Nothing registered (mvmd, tests): adoption only, never auto-start.
        return SessionAcquisition::Unavailable;
    };
    let Some(marker) = session_start_marker_path() else {
        return SessionAcquisition::Unavailable;
    };
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
    {
        Ok(_) => {
            let started = starter();
            // The marker arbitrates the race; it is not a lock. Remove it as
            // soon as the outcome is known, win or lose, so a failed start
            // cannot wedge every later build into the waiting branch.
            let _ = std::fs::remove_file(&marker);
            match started {
                Ok(record) => SessionAcquisition::Ready(record),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "starting a persistent builder for the contended store image failed; \
                         falling back to the single-shot builder"
                    );
                    SessionAcquisition::Unavailable
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            wait_for_started_session(&marker)
        }
        Err(_) => SessionAcquisition::Unavailable,
    }
}

/// Wait for whoever won the start race to publish a session record.
fn wait_for_started_session(marker: &Path) -> SessionAcquisition {
    let deadline = std::time::Instant::now() + SESSION_START_WAIT;
    while std::time::Instant::now() < deadline {
        if let Some(record) = read_active_session() {
            return SessionAcquisition::Ready(record);
        }
        if !marker.exists() {
            // The winner finished or gave up. One more read closes the gap
            // between it writing the record and removing the marker.
            return match read_active_session() {
                Some(record) => SessionAcquisition::Ready(record),
                None => SessionAcquisition::Unavailable,
            };
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    SessionAcquisition::Unavailable
}

/// Read the session record and verify the supervisor is alive.
/// Returns `None` if the record is missing, malformed, or the
/// recorded PID isn't a live process — all of which are "no
/// active session, fall back to single-shot" signals as far as
/// the routing layer is concerned. Never errors: a stale record
/// shouldn't break the user's build.
pub fn read_active_session() -> Option<SessionRecord> {
    let path = session_record_path()?;
    let body = std::fs::read(&path).ok()?;
    let record: SessionRecord = serde_json::from_slice(&body).ok()?;
    if !supervisor_alive(record.supervisor_pid) {
        return None;
    }
    Some(record)
}

/// Mark the active session as used. Best-effort: a failed touch should not make
/// a build fail, but it gives the invocation-driven keeper a durable activity
/// signal on the next command.
pub fn touch_active_session(now_unix_secs: u64) -> std::io::Result<bool> {
    let Some(path) = session_record_path() else {
        return Ok(false);
    };
    let body = match std::fs::read(&path) {
        Ok(body) => body,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let mut record: SessionRecord = serde_json::from_slice(&body).map_err(std::io::Error::other)?;
    if !supervisor_alive(record.supervisor_pid) {
        return Ok(false);
    }
    record.last_activity_unix_secs = Some(now_unix_secs);
    let body = serde_json::to_vec_pretty(&record).map_err(std::io::Error::other)?;
    std::fs::write(path, body)?;
    Ok(true)
}

/// Apply the resolved residency policy to any active libkrun persistent-builder
/// session. Returns the teardown reason when it stopped a session. Errors are
/// intentionally swallowed by the caller-facing API: residency enforcement must
/// not make the single-shot fallback unavailable.
pub fn enforce_active_session_policy(
    policy: &mvm_core::residency::ResidencyPolicy,
    now_unix_secs: u64,
) -> Option<BuilderSessionTeardownReason> {
    let record = read_active_session()?;
    let BuilderSessionPolicyDecision::Teardown(reason) =
        decide_builder_session_policy(&record, policy, now_unix_secs)
    else {
        return None;
    };

    let supervisor = PersistentBuilderSupervisor::new(&record.dispatch_socket_path);
    let _ = supervisor.shutdown();
    terminate_supervisor(record.supervisor_pid);
    if let Some(path) = session_record_path() {
        let _ = std::fs::remove_file(path);
    }
    Some(reason)
}

fn terminate_supervisor(pid: u32) {
    #[cfg(unix)]
    unsafe {
        // SAFETY: `kill(SIGTERM)` targets the PID recorded in the session file.
        // It does not dereference pointers or share memory with Rust.
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

pub fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// `kill(pid, 0)` — checks the process exists without signalling.
fn supervisor_alive(pid: u32) -> bool {
    crate::builder_vm_runtime::pid_alive(pid)
}

/// Sidecar filename inside `<job_dir>/<job_id>/out/` carrying the
/// nix store path. The host parses it after a successful dispatch
/// to recover the revision hash (mirror of single-shot's
/// `read_revision_hash` in `libkrun_builder.rs`).
pub const STORE_PATH_SIDECAR: &str = "store-path.txt";

/// Subdir name inside a dispatch's job dir where the cmd.sh
/// copies build artifacts (`vmlinux`, `rootfs.ext4`, optional
/// `manifest.json`, and the [`STORE_PATH_SIDECAR`]).
pub const ARTIFACT_SUBDIR: &str = "out";

/// Path on the host where a dispatch's artifacts land.
pub fn artifact_dir_for(session_job_dir: &Path, job_id: &str) -> PathBuf {
    session_job_dir.join(job_id).join(ARTIFACT_SUBDIR)
}

/// Stage a per-dispatch cmd.sh + output subdir under
/// `<session_job_dir>/<job_id>/`. Returns the relative path
/// (just `<job_id>`) that the host passes as
/// `HostVmRequest::Run::job_dir_relpath` and the guest dispatch
/// loop resolves under `/job/`. cmd.sh:
///
/// 1. Runs `nix build` against `<flake_ref>#<attr>`, captures the
///    store path.
/// 2. Validates `$STORE_PATH/vmlinux` and `$STORE_PATH/rootfs.ext4`
///    (mkGuest layout contract); exits 4 with stderr message on
///    miss.
/// 3. `cp -L`s vmlinux + rootfs.ext4 (+ optional manifest.json)
///    to `/job/<job_id>/out/`.
/// 4. Writes the store path to `/job/<job_id>/out/store-path.txt`
///    so the host can recover the revision hash post-dispatch.
pub fn stage_flake_dispatch_job(
    session_job_dir: &Path,
    flake_ref: &str,
    attr: &str,
) -> std::io::Result<String> {
    let job_id = uuid::Uuid::new_v4().to_string();
    let sub = session_job_dir.join(&job_id);
    let artifact_dir = sub.join(ARTIFACT_SUBDIR);
    std::fs::create_dir_all(&artifact_dir)?;
    let script = format!(
        "#!/bin/sh\n\
         set -eu\n\
         OUT_DIR='/job/{job_id}/{artifact_subdir}'\n\
         mkdir -p \"$OUT_DIR\"\n\
         STORE_PATH=$(nix --extra-experimental-features 'nix-command flakes' \\\n\
             build --no-link --print-out-paths \\\n\
             {flake_ref}#{attr})\n\
         echo \"store-path=$STORE_PATH\"\n\
         printf '%s\\n' \"$STORE_PATH\" > \"$OUT_DIR/{store_path_sidecar}\"\n\
         if [ ! -f \"$STORE_PATH/vmlinux\" ]; then\n\
             echo 'mvm-host-vm-init: nix output missing vmlinux' >&2\n\
             exit 4\n\
         fi\n\
         if [ ! -f \"$STORE_PATH/rootfs.ext4\" ]; then\n\
             echo 'mvm-host-vm-init: nix output missing rootfs.ext4' >&2\n\
             exit 4\n\
         fi\n\
         cp -L \"$STORE_PATH/vmlinux\" \"$OUT_DIR/vmlinux\"\n\
         BUILD_HOOK_ROOTFS=\"/tmp/mvm-rootfs-before-build.ext4\"\n\
         cp -L \"$STORE_PATH/rootfs.ext4\" \"$BUILD_HOOK_ROOTFS\"\n\
         echo 'mvm-host-vm-init: running before_build hook' >&2\n\
         set +e\n\
         /sbin/mvm-host-vm-init run-before-build-hook \"$BUILD_HOOK_ROOTFS\"\n\
         hook_rc=$?\n\
         set -e\n\
         if [ \"$hook_rc\" -ne 0 ]; then\n\
             echo \"mvm-host-vm-init: before_build hook failed (exit $hook_rc)\" >&2\n\
             rm -f \"$BUILD_HOOK_ROOTFS\"\n\
             exit $hook_rc\n\
         fi\n\
         cp -L \"$BUILD_HOOK_ROOTFS\" \"$OUT_DIR/rootfs.ext4\"\n\
         {seal_rootfs_journal_sh}\n\
         sync\n\
         rm -f \"$BUILD_HOOK_ROOTFS\"\n\
         if [ -f \"$STORE_PATH/manifest.json\" ]; then\n\
             cp -L \"$STORE_PATH/manifest.json\" \"$OUT_DIR/manifest.json\"\n\
         fi\n",
        artifact_subdir = ARTIFACT_SUBDIR,
        store_path_sidecar = STORE_PATH_SIDECAR,
        flake_ref = shell_single_quote(flake_ref),
        attr = shell_single_quote(attr),
        seal_rootfs_journal_sh =
            crate::builder_vm_runtime::seal_rootfs_journal_sh("\"$OUT_DIR/rootfs.ext4\""),
    );
    let cmd_path = sub.join("cmd.sh");
    std::fs::write(&cmd_path, script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&cmd_path, std::fs::Permissions::from_mode(0o755));
    }
    Ok(job_id)
}

fn shell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str(r"'\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Extract the leading hash from a Nix store path. Mirror of the
/// single-shot helper in `libkrun_builder.rs`. Shared with the typed
/// builder-dispatch path in `pipeline::dev_build`, which derives a
/// build's revision hash from the daemon-reported store out-path.
/// Gated on the `builder-vm` feature to keep no-feature builds free of
/// dead-code warnings.
#[cfg(any(test, feature = "builder-vm"))]
pub(crate) fn extract_nix_store_hash(store_path: &str) -> Option<&str> {
    let name = store_path.strip_prefix("/nix/store/")?;
    let (hash, _rest) = name.split_once('-')?;
    if hash.is_empty() { None } else { Some(hash) }
}

/// `BuilderVm` impl that routes builds through the live persistent
/// VM via [`PersistentBuilderSupervisor`]. Constructed from a
/// [`SessionRecord`] read by [`read_active_session`].
///
/// On `run_build`:
/// 1. Stages cmd.sh + output dir under the session's `job_dir`.
/// 2. Submits a `BuilderJob::Flake` via the supervisor.
/// 3. On success: reads `store-path.txt`, derives the revision
///    hash, copies artifacts from the session's output dir into
///    `mounts.artifact_out` so callers see the same paths the
///    single-shot path produces.
/// 4. Returns `BuilderArtifacts::Image` mirroring the single-shot
///    shape so downstream `dev_build` post-processing is
///    unchanged.
///
/// Install variant (`BuilderJob::Install`) returns
/// `BuilderVmError::NotYetImplemented` — reconciling the sealed-volume
/// invariants with persistent-mode is follow-up work.
#[cfg(feature = "builder-vm")]
pub struct PersistentBuilderVm {
    session: SessionRecord,
}

#[cfg(feature = "builder-vm")]
impl PersistentBuilderVm {
    pub fn new(session: SessionRecord) -> Self {
        Self { session }
    }
}

#[cfg(feature = "builder-vm")]
impl crate::builder_vm::BuilderVm for PersistentBuilderVm {
    fn run_build(
        &self,
        job: &crate::builder_vm::BuilderJob,
        mounts: &crate::builder_vm::BuilderMounts,
    ) -> Result<crate::builder_vm::BuilderArtifacts, crate::builder_vm::BuilderVmError> {
        use crate::builder_vm::{BuilderArtifacts, BuilderJob, BuilderVmError};

        // Install variant routes through the
        // same dispatch wire but stages the install spec instead
        // of a cmd.sh, and the guest's run_install_job_at writes
        // sealed-volume sidecars (result.json + content/ + sbom +
        // fetch.log + cve.json) into the per-dispatch out/ dir.
        // Host reads them back via finalize_install_dispatch.
        if let BuilderJob::Install { spec_path } = job {
            return self.run_install_dispatch(spec_path, mounts);
        }

        let (flake_ref, attr_path) = match job {
            BuilderJob::Flake {
                flake_ref,
                attr_path,
            } => (flake_ref.as_str(), attr_path.as_str()),
            BuilderJob::Install { .. } => unreachable!("handled above"),
        };

        let _ = touch_active_session(current_unix_secs());
        let job_id = stage_flake_dispatch_job(&self.session.job_dir, flake_ref, attr_path)
            .map_err(|e| {
                BuilderVmError::ExtractionFailed(format!("staging persistent dispatch job: {e}"))
            })?;

        let supervisor = PersistentBuilderSupervisor::new(&self.session.dispatch_socket_path)
            .with_frame_read_timeout(Duration::from_secs(60));
        let outcome = supervisor
            .submit(job.clone(), job_id.clone())
            .map_err(|e| BuilderVmError::NixBuildFailed(format!("persistent dispatch: {e}")))?;
        let _ = touch_active_session(current_unix_secs());
        if outcome.exit_code != 0 {
            return Err(BuilderVmError::NixBuildFailed(format!(
                "persistent dispatch exit {} — stderr tail:\n{}",
                outcome.exit_code, outcome.stderr_tail
            )));
        }

        let artifact_dir = artifact_dir_for(&self.session.job_dir, &job_id);
        let store_path_body = std::fs::read_to_string(artifact_dir.join(STORE_PATH_SIDECAR))
            .map_err(|e| {
                BuilderVmError::ExtractionFailed(format!(
                    "reading {}: {e}",
                    artifact_dir.join(STORE_PATH_SIDECAR).display()
                ))
            })?;
        let revision_hash = extract_nix_store_hash(store_path_body.trim())
            .ok_or_else(|| {
                BuilderVmError::ExtractionFailed(format!(
                    "malformed store path in sidecar: {store_path_body:?}"
                ))
            })?
            .to_string();

        std::fs::create_dir_all(&mounts.artifact_out).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating {}: {e}",
                mounts.artifact_out.display()
            ))
        })?;
        let dst_vmlinux = mounts.artifact_out.join("vmlinux");
        std::fs::copy(artifact_dir.join("vmlinux"), &dst_vmlinux)
            .map_err(|e| BuilderVmError::ExtractionFailed(format!("copying vmlinux: {e}")))?;
        let dst_rootfs = mounts.artifact_out.join("rootfs.ext4");
        std::fs::copy(artifact_dir.join("rootfs.ext4"), &dst_rootfs)
            .map_err(|e| BuilderVmError::ExtractionFailed(format!("copying rootfs.ext4: {e}")))?;

        Ok(BuilderArtifacts::Image {
            rootfs_path: dst_rootfs,
            kernel_path: Some(dst_vmlinux),
            revision_hash,
            lock_hash: None,
            accessible: None,
        })
    }
}

#[cfg(feature = "builder-vm")]
impl PersistentBuilderVm {
    /// `BuilderJob::Install` arm of
    /// [`BuilderVm::run_build`]. Copies the host-side install spec
    /// into a per-dispatch dir under `<session.job_dir>/<job_id>/`,
    /// submits a `BuilderJob::Install` with the in-guest path, then
    /// — on a clean dispatch — hands `mounts.artifact_out` to
    /// `finalize_install_job` so the caller sees the same
    /// `BuilderArtifacts::InstallVolume` shape the single-shot path
    /// returns.
    fn run_install_dispatch(
        &self,
        host_spec_path: &Path,
        mounts: &crate::builder_vm::BuilderMounts,
    ) -> Result<crate::builder_vm::BuilderArtifacts, crate::builder_vm::BuilderVmError> {
        use crate::builder_vm::{BuilderArtifacts, BuilderJob, BuilderVmError};

        let job_id =
            stage_install_dispatch_job(&self.session.job_dir, host_spec_path).map_err(|e| {
                BuilderVmError::ExtractionFailed(format!(
                    "staging persistent install dispatch job: {e}"
                ))
            })?;

        // The in-guest spec path the dispatch loop reads.
        // `<JOB_DIR>/<job_id>/install_spec.json` where JOB_DIR=`/job`
        // is the convention `mvm-host-vm-init`'s dispatch loop
        // resolves against.
        let in_guest_spec_path = PathBuf::from(format!("/job/{}/install_spec.json", job_id));

        let supervisor = PersistentBuilderSupervisor::new(&self.session.dispatch_socket_path)
            .with_frame_read_timeout(Duration::from_secs(60));
        let outcome = supervisor
            .submit(
                BuilderJob::Install {
                    spec_path: in_guest_spec_path,
                },
                job_id.clone(),
            )
            .map_err(|e| BuilderVmError::NixBuildFailed(format!("persistent dispatch: {e}")))?;
        if outcome.exit_code != 0 {
            return Err(BuilderVmError::NixBuildFailed(format!(
                "persistent install dispatch exit {} — stderr tail:\n{}",
                outcome.exit_code, outcome.stderr_tail
            )));
        }

        // The guest wrote result.json + sealed-volume sidecars into
        // <session.job_dir>/<job_id>/out/. Copy the whole dir into
        // mounts.artifact_out so the downstream finalize_install_job
        // reads from the canonical path the single-shot caller hands it.
        let dispatch_out_dir = artifact_dir_for(&self.session.job_dir, &job_id);
        std::fs::create_dir_all(&mounts.artifact_out).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating {}: {e}",
                mounts.artifact_out.display()
            ))
        })?;
        copy_dir_recursive(&dispatch_out_dir, &mounts.artifact_out).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "copying install artifacts {} → {}: {e}",
                dispatch_out_dir.display(),
                mounts.artifact_out.display()
            ))
        })?;

        Ok(BuilderArtifacts::InstallVolume {
            volume_dir: mounts.artifact_out.clone(),
            result_json_path: mounts.artifact_out.join("result.json"),
        })
    }
}

/// Stage a per-dispatch install job under `<session_job_dir>/<job_id>/`:
/// create the out/ subdir (mirror of [`stage_flake_dispatch_job`]'s
/// convention) and copy the caller's install spec into
/// `<job_id>/install_spec.json`. Returns the `job_id` the host passes
/// as `HostVmRequest::Run::job_dir_relpath`.
#[cfg(feature = "builder-vm")]
fn stage_install_dispatch_job(
    session_job_dir: &Path,
    host_spec_path: &Path,
) -> std::io::Result<String> {
    let job_id = uuid::Uuid::new_v4().to_string();
    let sub = session_job_dir.join(&job_id);
    let artifact_dir = sub.join(ARTIFACT_SUBDIR);
    std::fs::create_dir_all(&artifact_dir)?;
    let dst_spec = sub.join("install_spec.json");
    std::fs::copy(host_spec_path, &dst_spec)?;
    Ok(job_id)
}

/// Cheap recursive copy. Used by the install dispatch to move the
/// per-dispatch out/ contents into the caller's
/// `mounts.artifact_out` so the downstream `finalize_install_job`
/// (single-shot path) sees the same shape it would for a fresh-
/// VM build. Doesn't try to be clever about symlinks — the install
/// pipeline emits plain files + dirs.
#[cfg(feature = "builder-vm")]
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let entry_dst = dst.join(entry.file_name());
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &entry_dst)?;
        } else if ty.is_file() {
            std::fs::copy(entry.path(), &entry_dst)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn dispatch_socket_path_uses_builder_dispatch_port_constant() {
        let p = dispatch_socket_path(Path::new("/var/lib/mvm/vm-foo"));
        assert!(
            p.to_string_lossy().ends_with(&format!(
                "vsock-{}.sock",
                mvm_agentd::builder_agent::BUILDER_DISPATCH_PORT
            )),
            "got: {}",
            p.display()
        );
    }

    #[test]
    fn submit_against_missing_socket_returns_socket_unreachable() {
        let supervisor = PersistentBuilderSupervisor::new("/no/such/socket.sock");
        let result = supervisor.submit(
            BuilderJob::Flake {
                flake_ref: "path:/x".to_string(),
                attr_path: "packages.aarch64-linux.default".to_string(),
            },
            "00000000".to_string(),
        );
        match result {
            Err(PersistentBuilderError::SocketUnreachable { socket, .. }) => {
                assert!(socket.to_string_lossy().contains("/no/such/socket.sock"));
            }
            other => panic!("expected SocketUnreachable, got {other:?}"),
        }
    }

    // -----------------------------------------------------------
    // session record + PersistentBuilderVm
    // -----------------------------------------------------------

    #[test]
    fn session_record_roundtrips_through_json() {
        let record = SessionRecord {
            session_id: "abc".to_string(),
            dispatch_socket_path: PathBuf::from("/tmp/sock"),
            job_dir: PathBuf::from("/tmp/jobs"),
            workspace_root: PathBuf::from("/work"),
            supervisor_pid: 4242,
            last_activity_unix_secs: Some(1234567890),
        };
        let json = serde_json::to_vec(&record).unwrap();
        let back: SessionRecord = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.session_id, "abc");
        assert_eq!(back.supervisor_pid, 4242);
        assert_eq!(back.last_activity_unix_secs, Some(1234567890));
    }

    #[test]
    fn session_record_parses_mvm_cli_emitted_shape() {
        // Cross-validation: mvm-cli writes the same JSON. If
        // either side renames a field, this test fails — the
        // JSON below is the exact body
        // `mvm_cli::commands::build::persistent_builder` emits.
        let json = r#"{
            "session_id": "abc123",
            "dispatch_socket_path": "/home/u/mvm-home/vms/foo/vsock-21471.sock",
            "job_dir": "/home/u/mvm-home/jobs/foo",
            "workspace_root": "/work",
            "supervisor_pid": 7777,
            "last_activity_unix_secs": 1234567890
        }"#;
        let record: SessionRecord = serde_json::from_str(json).expect("parse mvm-cli shape");
        assert_eq!(record.session_id, "abc123");
        assert_eq!(record.supervisor_pid, 7777);
        assert_eq!(record.last_activity_unix_secs, Some(1234567890));
    }

    #[test]
    fn session_record_defaults_missing_last_activity_to_none() {
        let json = r#"{
            "session_id": "abc123",
            "dispatch_socket_path": "/home/u/mvm-home/vms/foo/vsock-21471.sock",
            "job_dir": "/home/u/mvm-home/jobs/foo",
            "workspace_root": "/work",
            "supervisor_pid": 7777
        }"#;
        let record: SessionRecord = serde_json::from_str(json).expect("parse old shape");
        assert_eq!(record.last_activity_unix_secs, None);
        assert_eq!(
            decide_builder_session_policy(
                &record,
                &mvm_core::residency::ResidencyPolicy::always_warm(),
                1234567890 + 3600,
            ),
            BuilderSessionPolicyDecision::Keep,
            "old records must not be torn down immediately after upgrade"
        );
    }

    #[test]
    fn builder_session_policy_keeps_fresh_warm_session() {
        let record = SessionRecord {
            session_id: "abc".to_string(),
            dispatch_socket_path: PathBuf::from("/tmp/sock"),
            job_dir: PathBuf::from("/tmp/jobs"),
            workspace_root: PathBuf::from("/work"),
            supervisor_pid: 4242,
            last_activity_unix_secs: Some(1000),
        };
        assert_eq!(
            decide_builder_session_policy(
                &record,
                &mvm_core::residency::ResidencyPolicy::always_warm(),
                1000 + 60,
            ),
            BuilderSessionPolicyDecision::Keep,
        );
    }

    #[test]
    fn builder_session_policy_tears_down_cold_immediately() {
        let record = SessionRecord {
            session_id: "abc".to_string(),
            dispatch_socket_path: PathBuf::from("/tmp/sock"),
            job_dir: PathBuf::from("/tmp/jobs"),
            workspace_root: PathBuf::from("/work"),
            supervisor_pid: 4242,
            last_activity_unix_secs: Some(1000),
        };
        assert_eq!(
            decide_builder_session_policy(
                &record,
                &mvm_core::residency::ResidencyPolicy::cold(),
                1001,
            ),
            BuilderSessionPolicyDecision::Teardown(BuilderSessionTeardownReason::ColdPolicy),
        );
    }

    #[test]
    fn builder_session_policy_tears_down_when_snapshot_unavailable() {
        let record = SessionRecord {
            session_id: "abc".to_string(),
            dispatch_socket_path: PathBuf::from("/tmp/sock"),
            job_dir: PathBuf::from("/tmp/jobs"),
            workspace_root: PathBuf::from("/work"),
            supervisor_pid: 4242,
            last_activity_unix_secs: Some(1000),
        };
        assert_eq!(
            decide_builder_session_policy(
                &record,
                &mvm_core::residency::ResidencyPolicy::always_warm(),
                1000 + 20 * 60 + 1,
            ),
            BuilderSessionPolicyDecision::Teardown(
                BuilderSessionTeardownReason::SnapshotUnavailable
            ),
        );
    }

    #[test]
    fn touch_active_session_updates_live_record_timestamp() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let data_dir = scratch.path().join("mvm-home");
        let run_dir = data_dir.join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let record = SessionRecord {
            session_id: "x".to_string(),
            dispatch_socket_path: PathBuf::from("/dev/null"),
            job_dir: PathBuf::from("/tmp"),
            workspace_root: PathBuf::from("/tmp"),
            supervisor_pid: std::process::id(),
            last_activity_unix_secs: Some(1),
        };
        std::fs::write(
            run_dir.join("persistent-builder.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", &data_dir);
        let touched = touch_active_session(55).expect("touch active session");
        assert!(touched);
        let body = std::fs::read(run_dir.join("persistent-builder.json")).unwrap();
        let back: SessionRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(back.last_activity_unix_secs, Some(55));
    }

    #[test]
    fn adoption_prefers_a_live_session_over_starting_another() {
        // A build that finds the image busy and a session already serving it
        // must join that session, not boot a second builder.
        let scratch = tempfile::tempdir().expect("tempdir");
        let run_dir = scratch.path().join("mvm-home").join("run");
        std::fs::create_dir_all(&run_dir).expect("run dir");
        let record = SessionRecord {
            session_id: "live".into(),
            dispatch_socket_path: run_dir.join("dispatch.sock"),
            job_dir: run_dir.join("jobs"),
            workspace_root: scratch.path().to_path_buf(),
            // This process: alive by construction.
            supervisor_pid: std::process::id(),
            last_activity_unix_secs: None,
        };
        std::fs::write(
            run_dir.join("persistent-builder.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .expect("write record");

        let mut env = TestEnv::new();
        env.set("MVM_HOME", scratch.path().join("mvm-home"));

        match adopt_or_start_session() {
            SessionAcquisition::Ready(got) => assert_eq!(got.session_id, "live"),
            other => panic!("expected the live session, got {other:?}"),
        }
    }

    #[test]
    fn without_a_registered_starter_there_is_nothing_to_adopt_or_start() {
        // mvmd and the unit suite register no starter: adoption only, and
        // never an auto-start behind the caller's back.
        let scratch = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_HOME", scratch.path().join("mvm-home"));

        assert!(matches!(
            adopt_or_start_session(),
            SessionAcquisition::Unavailable
        ));
        // And no marker was left behind to wedge a later build into waiting.
        assert!(
            !scratch
                .path()
                .join("mvm-home")
                .join("run")
                .join("persistent-builder.starting")
                .exists()
        );
    }

    #[test]
    fn the_start_marker_sits_beside_the_session_record() {
        // The two must share a directory: the loser of the race polls for the
        // record while watching the marker, so a mismatch would make it wait
        // the full window every time.
        let scratch = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_HOME", scratch.path().join("mvm-home"));

        let record = session_record_path().expect("record path");
        let marker = session_start_marker_path().expect("marker path");
        assert_eq!(record.parent(), marker.parent());
        assert_ne!(record, marker);
    }

    #[test]
    fn read_active_session_returns_none_when_record_missing() {
        // Point MVM_HOME at a tempdir with no run/persistent-
        // builder.json; the read should silently return None rather
        // than error.
        let scratch = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_HOME", scratch.path().join("mvm-home"));
        let result = read_active_session();
        assert!(result.is_none());
    }

    #[test]
    fn read_active_session_returns_none_when_pid_is_dead() {
        // Picked far above /proc/sys/kernel/pid_max defaults
        // (typically 4194304) but inside i32 range — kill(pid, 0)
        // returns ESRCH for any nonexistent PID. PID 0 on Unix
        // means "send to caller's process group" so it's a poor
        // sentinel; this one is safely unallocated.
        const DEFINITELY_DEAD_PID: u32 = 2_000_000_000;
        let scratch = tempfile::tempdir().expect("tempdir");
        let run_dir = scratch.path().join("mvm-home").join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let record = SessionRecord {
            session_id: "x".to_string(),
            dispatch_socket_path: PathBuf::from("/dev/null"),
            job_dir: PathBuf::from("/tmp"),
            workspace_root: PathBuf::from("/tmp"),
            supervisor_pid: DEFINITELY_DEAD_PID,
            last_activity_unix_secs: Some(1234567890),
        };
        std::fs::write(
            run_dir.join("persistent-builder.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", scratch.path().join("mvm-home"));
        let result = read_active_session();
        assert!(
            result.is_none(),
            "dead PID {DEFINITELY_DEAD_PID} must be classified as not-alive"
        );
    }

    #[test]
    fn stage_flake_dispatch_job_writes_cmd_sh_and_store_path_sidecar_dir() {
        // Cross-platform: only checks file layout + content, no
        // actual VM dispatch.
        let scratch = tempfile::tempdir().expect("tempdir");
        let job_dir = scratch.path().to_path_buf();
        let job_id =
            stage_flake_dispatch_job(&job_dir, "path:/work", "packages.aarch64-linux.default")
                .expect("stage");
        let cmd_path = job_dir.join(&job_id).join("cmd.sh");
        assert!(cmd_path.is_file(), "{}", cmd_path.display());
        let body = std::fs::read_to_string(&cmd_path).expect("read");
        assert!(body.contains("'path:/work'"), "{body}");
        assert!(body.contains("'packages.aarch64-linux.default'"), "{body}");
        assert!(body.contains(STORE_PATH_SIDECAR), "{body}");
        assert!(body.contains("cp -L"), "{body}");
        let artifact_dir = artifact_dir_for(&job_dir, &job_id);
        assert!(
            artifact_dir.is_dir(),
            "expected pre-staged artifact dir at {}",
            artifact_dir.display()
        );
    }

    #[test]
    fn stage_flake_dispatch_job_seals_final_artifact_without_a_new_builder_subcommand() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let job_dir = scratch.path().to_path_buf();
        let job_id =
            stage_flake_dispatch_job(&job_dir, "path:/work", "packages.aarch64-linux.default")
                .expect("stage");
        let body = std::fs::read_to_string(job_dir.join(&job_id).join("cmd.sh")).expect("read");
        assert!(
            body.contains("/sbin/mvm-host-vm-init run-before-build-hook"),
            "missing before_build hook runner invocation in:\n{body}"
        );
        assert!(
            body.contains("/tmp/mvm-rootfs-before-build.ext4"),
            "missing writable temp rootfs path in:\n{body}"
        );
        let hook_idx = body
            .find("/sbin/mvm-host-vm-init run-before-build-hook")
            .expect("hook runner present");
        let journal_idx = body
            .find("/sbin/e2fsck -p -f \"$OUT_DIR/rootfs.ext4\"")
            .expect("offline rootfs journal check present");
        let writable_idx = body
            .find("chmod 0644 \"$OUT_DIR/rootfs.ext4\"")
            .expect("final rootfs permission normalization present");
        let out_copy_idx = body
            .find("cp -L \"$BUILD_HOOK_ROOTFS\" \"$OUT_DIR/rootfs.ext4\"")
            .expect("final rootfs copy present");
        assert!(
            hook_idx < out_copy_idx && out_copy_idx < writable_idx && writable_idx < journal_idx,
            "the exported rootfs must be checked after the hook and final copy"
        );
        let sync_idx = body
            .find("sync\nrm -f \"$BUILD_HOOK_ROOTFS\"")
            .expect("artifact sync present");
        assert!(
            out_copy_idx < sync_idx,
            "the exported rootfs must be flushed before the temporary image is removed"
        );
        assert!(
            out_copy_idx < journal_idx && journal_idx < sync_idx,
            "the final copied rootfs must be sealed before it is published"
        );
        assert!(
            body.contains("mvm-host-vm-init: before_build hook failed"),
            "missing hook failure message in:\n{body}"
        );
        assert!(
            body.contains(
                "set +e\n/sbin/mvm-host-vm-init run-before-build-hook \"$BUILD_HOOK_ROOTFS\"\nhook_rc=$?\nset -e"
            ),
            "the hook's real exit status must be captured before testing it in:\n{body}"
        );
        assert!(
            !body.contains("if ! /sbin/mvm-host-vm-init run-before-build-hook"),
            "negating the hook command loses its real exit status in:\n{body}"
        );
        assert!(
            body.contains("0|1) ;;"),
            "the offline checker must accept clean and repaired exit codes in:\n{body}"
        );
        assert!(
            body.contains("rootfs journal check failed (exit $fsck_rc)"),
            "the offline checker must fail closed for every other exit code in:\n{body}"
        );
        assert!(
            body.contains("rootfs permission normalization failed")
                && body.contains("rm -f \"$OUT_DIR/rootfs.ext4\""),
            "an artifact that cannot be made writable for repair must be removed in:\n{body}"
        );
        assert!(
            !body.contains("/sbin/mvm-host-vm-init seal-rootfs-journal"),
            "source-rendered jobs must remain compatible with published builder binaries that predate the seal subcommand"
        );
    }

    #[test]
    fn extract_nix_store_hash_recovers_leading_hash() {
        assert_eq!(
            extract_nix_store_hash("/nix/store/abc123-foo-bar"),
            Some("abc123")
        );
        assert_eq!(extract_nix_store_hash("/nix/store/-bad"), None);
        assert_eq!(extract_nix_store_hash("not-a-store-path"), None);
    }

    // -----------------------------------------------------------
    // install dispatch helpers
    // -----------------------------------------------------------

    #[cfg(feature = "builder-vm")]
    #[test]
    fn stage_install_dispatch_job_copies_spec_and_creates_out_dir() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let session_job_dir = scratch.path().join("session");
        std::fs::create_dir_all(&session_job_dir).unwrap();

        // Caller's host-side spec: pin the bytes so we can assert
        // the copy is byte-identical.
        let host_spec_path = scratch.path().join("source-spec.json");
        let spec_body = br#"{"language":"python","lockfile_relative_path":"uv.lock","source_mount":"/work","gate":"prod"}"#;
        std::fs::write(&host_spec_path, spec_body).unwrap();

        let job_id = stage_install_dispatch_job(&session_job_dir, &host_spec_path).expect("stage");

        let staged_spec = session_job_dir.join(&job_id).join("install_spec.json");
        assert!(staged_spec.is_file(), "{}", staged_spec.display());
        let staged_body = std::fs::read(&staged_spec).unwrap();
        assert_eq!(&staged_body, spec_body);

        let out_dir = artifact_dir_for(&session_job_dir, &job_id);
        assert!(out_dir.is_dir(), "expected out/ at {}", out_dir.display());
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn copy_dir_recursive_copies_files_and_subdirs() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let src = scratch.path().join("src");
        let dst = scratch.path().join("dst");
        std::fs::create_dir_all(src.join("nested")).unwrap();
        std::fs::write(src.join("a.txt"), b"alpha").unwrap();
        std::fs::write(src.join("nested/b.txt"), b"beta").unwrap();

        copy_dir_recursive(&src, &dst).expect("copy");

        assert_eq!(std::fs::read(dst.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(std::fs::read(dst.join("nested/b.txt")).unwrap(), b"beta");
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn copy_dir_recursive_rejects_missing_src() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let src = scratch.path().join("does-not-exist");
        let dst = scratch.path().join("dst");
        let err = copy_dir_recursive(&src, &dst).expect_err("missing src");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }
}

#[cfg(test)]
mod workload_start_params_builder_tests {
    use super::*;

    /// An empty builder must refuse to finish, naming the first
    /// required field it is missing — never substituting a default.
    #[test]
    fn an_empty_builder_names_the_first_missing_field() {
        let Err(err) = WorkloadStartParams::builder().build() else {
            panic!("an empty WorkloadStartParams builder must not build");
        };
        assert_eq!(
            err,
            BuilderError::missing("WorkloadStartParams", "kernel_path")
        );
    }
}
