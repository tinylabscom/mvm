//! Wire response type: `GuestResponse`, the machine-readable
//! request/response contract (`Verb`, `ResponseVariant`,
//! `ResponseContract`), guest-agent capability negotiation, and the
//! readiness/volume-mount payload types that ride directly on
//! `GuestResponse`.

use super::*;

fn is_false(value: &bool) -> bool {
    !*value
}
use mvm_core::security::AgentProfile;
use serde::{Deserialize, Serialize};

/// State of a single guest subsystem during boot.
///
/// `Disabled` is distinct from `Ready` — a missing optional subsystem
/// (no integrations declared, no warm pool configured, no probes
/// registered) reports `Disabled`, while a present-and-warmed
/// subsystem reports `Ready`. This lets the host UX distinguish
/// "the workload doesn't use X" from "X is still warming".
///
/// `Default` is `Disabled` — the most-conservative semantically
/// correct value (= "this subsystem isn't configured"). Lets
/// constructors of `ReadinessReport` use `..Default::default()` to
/// elide subsystems they don't care about in tests / fixtures.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ComponentState {
    /// Subsystem is not configured for this image (no policy → no
    /// state machine to advance). Wire-stable distinct from `Ready`.
    #[default]
    Disabled,
    /// Subsystem is initializing in the background.
    Starting,
    /// Subsystem is up and accepting work.
    Ready,
    /// Subsystem failed to initialize. `message` is a short human-
    /// readable reason; no secrets / paths beyond what the host
    /// already knows.
    Failed {
        /// Short human-readable failure reason. Stable enough for an
        /// operator to recognise, not a structured cause — pair with
        /// stderr logs for diagnosis.
        message: String,
    },
}

/// Per-phase monotonic boot timings in milliseconds since the agent
/// process started.
///
/// `agent_started_ms`, `vsock_bound_ms`, `first_accept_ms`, and
/// `entrypoint_ready_ms` are wired so callers can already display the
/// cold-path timing breakdown. The remaining fields
/// (`warm_pool_ready_ms`, `integrations_ready_ms`, `probes_ready_ms`)
/// are reserved and stay `None` for now.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct BootTimingReport {
    /// Milliseconds from agent process start to vsock bind/listen.
    /// Always present once the agent has bound — this number is the
    /// dominant signal for early-readiness regressions.
    pub agent_started_ms: Option<u64>,
    /// Milliseconds from agent start to a successful `bind+listen`
    /// pair on the control port. Same anchor as `agent_started_ms`
    /// today; reserved for diverging if a future refactor
    /// splits "process started" from "socket created".
    pub vsock_bound_ms: Option<u64>,
    /// Milliseconds from agent start to the first accepted host
    /// connection. `None` until the first `accept()` returns.
    pub first_accept_ms: Option<u64>,
    /// Milliseconds from agent start to `entrypoint = Ready` (or
    /// `Failed`). `None` while still `Starting`.
    pub entrypoint_ready_ms: Option<u64>,
    /// Reserved; not yet populated, so `None` for now.
    pub warm_pool_ready_ms: Option<u64>,
    /// Reserved; not yet populated, so `None` for now.
    pub integrations_ready_ms: Option<u64>,
    /// Reserved; not yet populated, so `None` for now.
    pub probes_ready_ms: Option<u64>,
}

/// Snapshot of agent readiness at the moment of a `ReadinessStatus`
/// call.
///
/// Used by host
/// callers (`mvmctl wait`, `mvmctl up --timings`, `mvmctl doctor`)
/// to distinguish:
///
/// - "control plane is up, workload not yet warm" → invoke would
///   block; the host can stream progress to the user
/// - "entrypoint validation failed" → invoke would fail fast with
///   a typed error; the host can surface the validation message
/// - "optional subsystem failed" → invoke is still safe; the host
///   surfaces a warning
///
/// `Default` composes the `Default` impls of each field — every
/// component is `Disabled`, the profile is `SealedProd`, all
/// timings are `None`. Tests and fixtures can construct partial
/// reports with `..Default::default()`.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ReadinessReport {
    /// Vsock listener bound and accepting. Always `Ready` if the
    /// agent could respond at all.
    pub control_plane: ComponentState,
    /// `/etc/mvm/entrypoint` validation result. Gates `RunEntrypoint`
    /// — a request submitted while `Starting` returns
    /// `RunEntrypointError::NotReady`.
    pub entrypoint: ComponentState,
    /// Warm-process pool readiness. `Disabled` for cold-tier images;
    /// `Ready` once the `after_start.sh` probe passes.
    pub warm_pool: ComponentState,
    /// Drop-in integration scan + health loop. `Disabled` if no
    /// `/etc/mvm/integrations.d/*.json` files present.
    pub integrations: ComponentState,
    /// Drop-in probe scan + probe loop. `Disabled` if no
    /// `/etc/mvm/probes.d/*.json` files present.
    pub probes: ComponentState,
    /// Volume-mount state — wire-stable placeholder. `Disabled` because
    /// mount/unmount are on-demand verbs, not boot state.
    pub volumes: ComponentState,
    /// Active agent profile. Same value the dispatcher uses for the
    /// `allowed_in` gate.
    pub profile: AgentProfile,
    /// Per-phase monotonic timings.
    pub boot_millis: BootTimingReport,
}
/// Response from guest vsock agent to host.
///
/// Same `deny_unknown_fields` discipline as `GuestRequest` — a
/// compromised guest must not be able to slip extra fields past the
/// host's deserializer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum GuestResponse {
    /// Guest-agent protocol negotiation succeeded.
    ProtocolHelloAck {
        agent_protocol_version: u32,
        min_supported_version: u32,
        agent_version: String,
        capabilities: Vec<GuestCapability>,
    },
    /// Guest-agent protocol negotiation failed before dispatch.
    ProtocolMismatch {
        host_protocol_version: u32,
        agent_protocol_version: u32,
        required_action: ProtocolUpgradeAction,
        message: String,
    },
    /// Activation acknowledgement for PID-1 initramfs boot.  Sent after
    /// the agent has successfully mounted the rootfs, runtime overlay,
    /// and any custom volumes.
    ActivateEnvironmentAck,
    /// Activation failed.  The agent is still in the `Awaiting` boot
    /// state and will not serve operational RPCs until a valid
    /// activation arrives.
    ActivateEnvironmentError { message: String },
    /// The agent is running in PID-1 initramfs mode and has not yet
    /// received a valid `ActivateEnvironment`.  Only
    /// `ActivateEnvironment` is accepted until then.
    NotActivated,
    /// Worker status with optional last-busy timestamp.
    WorkerStatus {
        status: String,
        last_busy_at: Option<String>,
    },
    /// Sleep preparation acknowledgement.
    SleepPrepAck {
        success: bool,
        detail: Option<String>,
    },
    /// Wake acknowledgement.
    WakeAck { success: bool },
    /// Pong.
    Pong,
    /// Current guest-agent process resource usage.
    ResourceUsageReport { rss_bytes: u64 },
    /// Error from guest agent.
    Error { message: String },
    /// The dispatcher refused this verb because the active
    /// `AgentProfile` does not allow it. Distinct
    /// from `Error { message }` so SDK callers can branch on
    /// capability without parsing message text — analogous to
    /// `ProcErrorKind::UnsupportedInProduction` for process RPC,
    /// but at the protocol layer rather than per-handler.
    UnsupportedInProfile {
        /// Active profile on the agent that rejected the call.
        profile: AgentProfile,
        /// `verb_name()` of the rejected request. Wire-stable.
        verb: String,
    },
    /// The pinned verb grant does not authorize this verb for the
    /// workload. Wire-stable. Universal — may answer any request.
    VerbNotAuthorized { verb: String },
    /// The agent refused to spawn workload code because it is still running as
    /// uid 0. Carries the offending verb and the live uid so the refusal is
    /// self-diagnosing rather than needing a console-log hunt.
    WorkloadPrivilegeRefused { verb: String, uid: u32 },
    /// Per-integration status report.
    IntegrationStatusReport {
        integrations: Vec<crate::integrations::IntegrationStateReport>,
    },
    /// Result of checkpointing integrations before sleep.
    CheckpointResult {
        success: bool,
        /// Names of integrations that failed to checkpoint.
        failed: Vec<String>,
        detail: Option<String>,
    },
    /// Per-probe status report.
    ProbeStatusReport {
        probes: Vec<crate::probes::ProbeResult>,
    },
    /// Whether the workload has signalled "primed" (the primed marker is
    /// present). Answers `PrimedStatus`.
    PrimedStatusReport { primed: bool },
    /// One event in the response stream of a `RunEntrypoint` call.
    ///
    /// The agent emits a sequence of these in response to a single
    /// `RunEntrypoint` request, terminated by an `EntrypointEvent`
    /// whose `is_terminal` returns true (`Exit` or `Error`). The
    /// host reads frames in a loop until terminal.
    EntrypointEvent(EntrypointEvent),
    /// The exact active extension invocation accepted cancellation.
    ExtensionCancellationAck,
    /// One event in the streaming response of a DevOnly `Exec` call.
    /// Terminated by `ExecEvent::Exit`.
    ExecEvent(ExecEvent),
    /// Buffered outcomes of a DevOnly `ExecBatch` call, one per
    /// command in request order (truncated at the first non-zero exit).
    ExecBatchResult { outcomes: Vec<ExecOutcomeWire> },
    /// Ack for a `RunDetached` call: the detached workload was spawned
    /// with the given guest PID. The workload runs independently of this
    /// request's connection; its exit is later reported to the host's
    /// workload-exit port by the agent's reaper.
    DetachedStarted { pid: i32 },
    /// Post-restore acknowledgement.
    PostRestoreAck {
        success: bool,
        detail: Option<String>,
        /// `true` iff the delivered generation token changed and the guest
        /// reseeded its CSPRNG (a fresh clone). `false` for an unchanged/zero
        /// token (a plain wake or no-rotation restore). Defaults to `false`
        /// on the wire for forward-compat with a pre-rotation ack.
        #[serde(default)]
        reseeded: bool,
        /// `true` iff the guest applied the host-provided restore epoch before
        /// signaling init. Defaults to `false` for older agents.
        #[serde(default, skip_serializing_if = "is_false")]
        clock_resynced: bool,
    },
    /// Filesystem diff result.
    FsDiffResult { changes: Vec<FsChange> },
    /// Guest Unix socket forward started successfully.
    UnixSocketForwardStarted {
        guest_path: String,
        host_vsock_port: u32,
    },
    /// Console PTY session opened. Connect to `data_port` for raw I/O.
    ConsoleOpened { session_id: u32, data_port: u32 },
    /// Console PTY session ended (shell exited).
    ConsoleExited { session_id: u32, exit_code: i32 },
    /// Console resize acknowledged.
    ConsoleResized { session_id: u32 },
    /// Result of an `EntrypointStatus` query.
    ///
    /// `ok = true` means the agent successfully validated
    /// `/etc/mvm/entrypoint` at boot and will serve `RunEntrypoint`.
    /// `ok = false` means validation failed — `path` carries the
    /// resolved path attempt (or the marker contents if resolution
    /// itself failed) and `detail` carries a human-readable reason.
    EntrypointStatusReport {
        ok: bool,
        path: Option<String>,
        detail: Option<String>,
    },

    /// Result of a `ReadinessStatus` query.
    /// Snapshot of every component plus per-phase timings.
    ReadinessStatusReport(ReadinessReport),

    /// Result of a filesystem RPC call. The single top-level variant
    /// keeps `GuestResponse` from sprawling — the `FsResult` sub-enum
    /// carries the per-verb shapes.
    FsResult(FsResult),

    /// Result of a non-streaming process-control verb (`ProcStart`,
    /// `ProcList`, `ProcSignal`, `ProcSendInput`, `ProcKill`).
    ProcResult(ProcResult),

    /// One event in the streaming response of a `ProcWait` call.
    /// Mirrors the `EntrypointEvent` shape — the agent emits
    /// `Stdout`/`Stderr` chunks (capped per chunk by the wire frame
    /// limit) terminated by exactly one of `Exit` / `Killed` /
    /// `TimedOut` / `Error`.
    ProcWaitEvent(ProcWaitEvent),

    /// Result of a `MountVolume` / `UnmountVolume` call. Single-frame
    /// surface; closed sub-enum carries the per-verb shape.
    /// (Renamed from `ShareResult`.)
    VolumeMountResult(VolumeMountResult),

    /// Acknowledgement for `UpdateIdleTimeout`. `applied_secs` is the
    /// value the agent is now enforcing — `0` means the warm-process
    /// pool isn't active on this guest (cold-path-only build), so
    /// the host reaper is the only enforcement.
    UpdateIdleTimeoutAck {
        previous_secs: u64,
        applied_secs: u64,
    },

    /// Outcome of one `StreamInput` frame or one `CloseStreamInput`.
    StreamInputResult(StreamInputResult),
}
/// Declares a unit enum that is the name-only projection of a wire enum,
/// with a `ALL` slice (every variant, declaration order) and a `name()`
/// returning the variant's identifier. `ALL` is generated from the same
/// variant list as the enum, so the two can't drift.
macro_rules! name_enum {
    ($(#[$m:meta])* $vis:vis enum $name:ident { $($v:ident),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        $vis enum $name { $($v),+ }

        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: &'static [$name] = &[$($name::$v),+];

            /// The variant's wire-stable identifier (its Rust ident).
            pub fn name(self) -> &'static str {
                match self { $($name::$v => stringify!($v)),+ }
            }
        }
    };
}

name_enum! {
    /// Typed projection of every `GuestRequest` verb. Enumerable (`ALL`) so
    /// the contract can be iterated; `GuestRequest::verb()` keeps it in
    /// lockstep with the wire enum (exhaustive match).
    pub enum Verb {
        ActivateEnvironment, ProtocolHello, WorkerStatus, SleepPrep, Wake, Ping, ResourceUsage,
        IntegrationStatus,
        CheckpointIntegrations, ProbeStatus, PrimedStatus, Exec, ExecBatch, RunEntrypoint, RunExtension,
        CancelExtension,
        RunDetached,
        PostRestore,
        FsDiff, StartUnixSocketForward, ConsoleOpen,
        ConsoleClose, ConsoleResize, EntrypointStatus, ReadinessStatus, FsRead,
        FsWrite, FsList, FsStat, FsMkdir, FsRemove, FsMove, ProcStart,
        ProcList, ProcSignal, ProcSendInput, ProcWait, ProcKill, MountVolume,
        UnmountVolume, UpdateIdleTimeout, RunCode, StreamInput, CloseStreamInput,
    }
}

name_enum! {
    /// Typed projection of every `GuestResponse` variant.
    /// `GuestResponse::variant()` keeps it in lockstep with the wire enum
    /// (exhaustive match).
    pub enum ResponseVariant {
        ActivateEnvironmentAck, ActivateEnvironmentError, NotActivated,
        ProtocolHelloAck, ProtocolMismatch, WorkerStatus, SleepPrepAck, WakeAck,
        Pong, ResourceUsageReport, Error, UnsupportedInProfile, VerbNotAuthorized, WorkloadPrivilegeRefused, IntegrationStatusReport,
        CheckpointResult, ProbeStatusReport, PrimedStatusReport, EntrypointEvent, ExtensionCancellationAck, ExecEvent,
        ExecBatchResult, DetachedStarted,
        PostRestoreAck, FsDiffResult,
        UnixSocketForwardStarted, ConsoleOpened, ConsoleExited, ConsoleResized,
        EntrypointStatusReport,
        ReadinessStatusReport, FsResult, ProcResult, ProcWaitEvent,
        VolumeMountResult, UpdateIdleTimeoutAck, StreamInputResult,
    }
}

impl ResponseVariant {
    /// Universal responses any request may receive instead of its
    /// request-specific answer: a protocol-layer profile rejection
    /// (`UnsupportedInProfile`) or a generic agent `Error`. Excluded from
    /// per-request contracts — a typed client handles them globally.
    pub fn is_universal(self) -> bool {
        matches!(
            self,
            ResponseVariant::Error
                | ResponseVariant::UnsupportedInProfile
                | ResponseVariant::VerbNotAuthorized
                | ResponseVariant::WorkloadPrivilegeRefused
        )
    }
}

/// Whether a request is answered by a single response frame, or by a stream
/// of frames terminated by a terminal event (`is_terminal()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseKind {
    /// Exactly one `GuestResponse` frame.
    Unary,
    /// A sequence of `GuestResponse` frames, read until terminal.
    Stream,
}

/// Whether a verb carries bounded orchestration metadata or user-controlled
/// payload bytes. The distinction drives dispatch capacity and audit handling;
/// it is independent of the prod/dev profile gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrafficPlane {
    Control,
    Data,
}

/// The declared response contract for a request verb: which `GuestResponse`
/// variant(s) answer it, and whether the answer is a single frame or a
/// terminal-terminated stream. The universal responses (`Error`,
/// `UnsupportedInProfile`) are not listed — they may answer any request.
#[derive(Debug, Clone, Copy)]
pub struct ResponseContract {
    /// The request-specific response variant(s) this verb may produce.
    pub responses: &'static [ResponseVariant],
    /// Single-frame vs streamed.
    pub kind: ResponseKind,
}

impl Verb {
    /// Exhaustive control/data-plane classification for this wire verb.
    pub fn traffic_plane(self) -> TrafficPlane {
        use TrafficPlane::{Control, Data};
        match self {
            Self::Exec
            | Self::ExecBatch
            | Self::RunEntrypoint
            | Self::RunExtension
            | Self::FsDiff
            | Self::FsRead
            | Self::FsWrite
            | Self::FsList
            | Self::ProcSendInput
            | Self::ProcWait
            | Self::RunCode
            | Self::StreamInput
            | Self::CloseStreamInput => Data,
            Self::ActivateEnvironment
            | Self::ProtocolHello
            | Self::WorkerStatus
            | Self::SleepPrep
            | Self::Wake
            | Self::Ping
            | Self::ResourceUsage
            | Self::IntegrationStatus
            | Self::CheckpointIntegrations
            | Self::ProbeStatus
            | Self::PrimedStatus
            | Self::CancelExtension
            | Self::RunDetached
            | Self::PostRestore
            | Self::StartUnixSocketForward
            | Self::ConsoleOpen
            | Self::ConsoleClose
            | Self::ConsoleResize
            | Self::EntrypointStatus
            | Self::ReadinessStatus
            | Self::FsStat
            | Self::FsMkdir
            | Self::FsRemove
            | Self::FsMove
            | Self::ProcStart
            | Self::ProcList
            | Self::ProcSignal
            | Self::ProcKill
            | Self::MountVolume
            | Self::UnmountVolume
            | Self::UpdateIdleTimeout => Control,
        }
    }

    /// Whether serving this verb creates a process running workload code.
    ///
    /// Exhaustive on purpose: a new verb cannot be added without someone
    /// deciding which side of this line it falls on, the same discipline
    /// `traffic_plane` and `RequestClass::class` already impose.
    ///
    /// This exists because the agent has five distinct workload-spawn sites
    /// (`entrypoint.rs`, `exec_stream.rs`, `console.rs`, `lifecycle_hooks.rs`,
    /// `worker_pool.rs`) and **none of them sets a uid** — every one inherits
    /// the agent's identity. Guarding each site would therefore be guarding the
    /// symptom. The property that matters is that the agent is not root when it
    /// serves one of these, which is a single check over this classification.
    pub fn spawns_workload_process(self) -> bool {
        match self {
            // Each of these ends in a process executing image or user code.
            Self::Exec
            | Self::ExecBatch
            | Self::RunEntrypoint
            | Self::RunExtension
            | Self::RunDetached
            | Self::RunCode
            | Self::ProcStart
            | Self::ConsoleOpen => true,

            // Agent-internal: these answer from agent state, mutate mounts or
            // forwarding, or manage a process the verbs above already created.
            // `ActivateEnvironment` is the important one — it runs the mounts
            // and the pivot, so it legitimately executes while still root and
            // must never be caught by this gate.
            Self::ActivateEnvironment
            | Self::ProtocolHello
            | Self::WorkerStatus
            | Self::SleepPrep
            | Self::Wake
            | Self::Ping
            | Self::ResourceUsage
            | Self::IntegrationStatus
            | Self::CheckpointIntegrations
            | Self::ProbeStatus
            | Self::PrimedStatus
            | Self::CancelExtension
            | Self::PostRestore
            | Self::FsDiff
            | Self::StartUnixSocketForward
            | Self::ConsoleClose
            | Self::ConsoleResize
            | Self::EntrypointStatus
            | Self::ReadinessStatus
            | Self::FsRead
            | Self::FsWrite
            | Self::FsList
            | Self::FsStat
            | Self::FsMkdir
            | Self::FsRemove
            | Self::FsMove
            | Self::ProcList
            | Self::ProcSignal
            | Self::ProcSendInput
            | Self::ProcWait
            | Self::ProcKill
            | Self::MountVolume
            | Self::UnmountVolume
            // Both hand bytes to, or close, the stdin of a process
            // `RunEntrypoint` already created. Neither can name a program and
            // neither reaches a spawn site, so the gate must not treat them as
            // workload-spawning.
            | Self::StreamInput
            | Self::CloseStreamInput
            | Self::UpdateIdleTimeout => false,
        }
    }

    /// The declared host↔guest response contract for this verb — the
    /// machine-readable pairing previously implicit in the agent dispatch.
    pub fn response_contract(self) -> ResponseContract {
        use ResponseKind::{Stream, Unary};
        use ResponseVariant as R;
        let unary = |responses: &'static [R]| ResponseContract {
            responses,
            kind: Unary,
        };
        let stream = |responses: &'static [R]| ResponseContract {
            responses,
            kind: Stream,
        };
        match self {
            Verb::ActivateEnvironment => unary(&[
                R::ActivateEnvironmentAck,
                R::ActivateEnvironmentError,
                R::NotActivated,
            ]),
            Verb::ProtocolHello => unary(&[R::ProtocolHelloAck, R::ProtocolMismatch]),
            Verb::WorkerStatus => unary(&[R::WorkerStatus]),
            Verb::SleepPrep => unary(&[R::SleepPrepAck]),
            Verb::Wake => unary(&[R::WakeAck]),
            Verb::Ping => unary(&[R::Pong]),
            Verb::ResourceUsage => unary(&[R::ResourceUsageReport]),
            Verb::IntegrationStatus => unary(&[R::IntegrationStatusReport]),
            Verb::CheckpointIntegrations => unary(&[R::CheckpointResult]),
            Verb::ProbeStatus => unary(&[R::ProbeStatusReport]),
            Verb::PrimedStatus => unary(&[R::PrimedStatusReport]),
            Verb::Exec => stream(&[R::ExecEvent]),
            Verb::ExecBatch => unary(&[R::ExecBatchResult]),
            Verb::RunEntrypoint => stream(&[R::EntrypointEvent]),
            Verb::RunExtension => stream(&[R::EntrypointEvent]),
            Verb::CancelExtension => unary(&[R::ExtensionCancellationAck]),
            Verb::RunDetached => unary(&[R::DetachedStarted]),
            Verb::PostRestore => unary(&[R::PostRestoreAck]),
            Verb::FsDiff => unary(&[R::FsDiffResult]),
            Verb::StartUnixSocketForward => unary(&[R::UnixSocketForwardStarted]),
            Verb::ConsoleOpen => unary(&[R::ConsoleOpened]),
            Verb::ConsoleClose => unary(&[R::ConsoleExited]),
            Verb::ConsoleResize => unary(&[R::ConsoleResized]),
            Verb::EntrypointStatus => unary(&[R::EntrypointStatusReport]),
            Verb::ReadinessStatus => unary(&[R::ReadinessStatusReport]),
            Verb::FsRead
            | Verb::FsWrite
            | Verb::FsList
            | Verb::FsStat
            | Verb::FsMkdir
            | Verb::FsRemove
            | Verb::FsMove => unary(&[R::FsResult]),
            Verb::ProcStart
            | Verb::ProcList
            | Verb::ProcSignal
            | Verb::ProcSendInput
            | Verb::ProcKill => unary(&[R::ProcResult]),
            Verb::ProcWait => stream(&[R::ProcWaitEvent]),
            Verb::MountVolume | Verb::UnmountVolume => unary(&[R::VolumeMountResult]),
            Verb::UpdateIdleTimeout => unary(&[R::UpdateIdleTimeoutAck]),
            Verb::RunCode => stream(&[R::ExecEvent]),
            Verb::StreamInput | Verb::CloseStreamInput => unary(&[R::StreamInputResult]),
        }
    }
}

impl GuestResponse {
    /// Name-only projection. Exhaustive — adding a `GuestResponse` variant
    /// fails to compile until mapped here, keeping `ResponseVariant` in
    /// lockstep with the wire enum.
    pub fn variant(&self) -> ResponseVariant {
        match self {
            GuestResponse::ActivateEnvironmentAck => ResponseVariant::ActivateEnvironmentAck,
            GuestResponse::ActivateEnvironmentError { .. } => {
                ResponseVariant::ActivateEnvironmentError
            }
            GuestResponse::NotActivated => ResponseVariant::NotActivated,
            GuestResponse::ProtocolHelloAck { .. } => ResponseVariant::ProtocolHelloAck,
            GuestResponse::ProtocolMismatch { .. } => ResponseVariant::ProtocolMismatch,
            GuestResponse::WorkerStatus { .. } => ResponseVariant::WorkerStatus,
            GuestResponse::SleepPrepAck { .. } => ResponseVariant::SleepPrepAck,
            GuestResponse::WakeAck { .. } => ResponseVariant::WakeAck,
            GuestResponse::Pong => ResponseVariant::Pong,
            GuestResponse::ResourceUsageReport { .. } => ResponseVariant::ResourceUsageReport,
            GuestResponse::Error { .. } => ResponseVariant::Error,
            GuestResponse::UnsupportedInProfile { .. } => ResponseVariant::UnsupportedInProfile,
            GuestResponse::VerbNotAuthorized { .. } => ResponseVariant::VerbNotAuthorized,
            GuestResponse::WorkloadPrivilegeRefused { .. } => {
                ResponseVariant::WorkloadPrivilegeRefused
            }
            GuestResponse::IntegrationStatusReport { .. } => {
                ResponseVariant::IntegrationStatusReport
            }
            GuestResponse::CheckpointResult { .. } => ResponseVariant::CheckpointResult,
            GuestResponse::ProbeStatusReport { .. } => ResponseVariant::ProbeStatusReport,
            GuestResponse::PrimedStatusReport { .. } => ResponseVariant::PrimedStatusReport,
            GuestResponse::EntrypointEvent(_) => ResponseVariant::EntrypointEvent,
            GuestResponse::ExtensionCancellationAck => ResponseVariant::ExtensionCancellationAck,
            GuestResponse::ExecEvent(_) => ResponseVariant::ExecEvent,
            GuestResponse::ExecBatchResult { .. } => ResponseVariant::ExecBatchResult,
            GuestResponse::DetachedStarted { .. } => ResponseVariant::DetachedStarted,
            GuestResponse::PostRestoreAck { .. } => ResponseVariant::PostRestoreAck,
            GuestResponse::FsDiffResult { .. } => ResponseVariant::FsDiffResult,
            GuestResponse::UnixSocketForwardStarted { .. } => {
                ResponseVariant::UnixSocketForwardStarted
            }
            GuestResponse::ConsoleOpened { .. } => ResponseVariant::ConsoleOpened,
            GuestResponse::ConsoleExited { .. } => ResponseVariant::ConsoleExited,
            GuestResponse::ConsoleResized { .. } => ResponseVariant::ConsoleResized,
            GuestResponse::EntrypointStatusReport { .. } => ResponseVariant::EntrypointStatusReport,
            GuestResponse::ReadinessStatusReport(_) => ResponseVariant::ReadinessStatusReport,
            GuestResponse::FsResult(_) => ResponseVariant::FsResult,
            GuestResponse::ProcResult(_) => ResponseVariant::ProcResult,
            GuestResponse::StreamInputResult(_) => ResponseVariant::StreamInputResult,
            GuestResponse::ProcWaitEvent(_) => ResponseVariant::ProcWaitEvent,
            GuestResponse::VolumeMountResult(_) => ResponseVariant::VolumeMountResult,
            GuestResponse::UpdateIdleTimeoutAck { .. } => ResponseVariant::UpdateIdleTimeoutAck,
        }
    }
}
impl GuestResponse {
    /// Whether this frame ends a streaming response. Only the streaming
    /// variants can be non-terminal (their inner event decides); any other
    /// frame is a complete answer and ends the read.
    pub fn is_stream_terminal(&self) -> bool {
        match self {
            GuestResponse::EntrypointEvent(e) => e.is_terminal(),
            GuestResponse::ExecEvent(e) => e.is_terminal(),
            GuestResponse::ProcWaitEvent(e) => e.is_terminal(),
            _ => true,
        }
    }
}
/// Guest-agent control protocol capability. Closed enum so host and
/// guest fail loudly on drift instead of accepting arbitrary strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum GuestCapability {
    Ping,
    ResourceUsage,
    IntegrationStatus,
    EntrypointStatus,
    RunEntrypoint,
    RunExtension,
    FilesystemRpc,
    ProcessRpc,
    Console,
    /// Unix-domain socket forwarding (`StartUnixSocketForward`). Not an SSH
    /// session capability — no SSH client/server or key material crosses the
    /// guest boundary.
    UnixSocketForward,
    VolumeMount,
    UpdateIdleTimeout,
    /// `ReadinessStatus` returns
    /// `GuestResponse::ReadinessStatusReport(ReadinessReport)`.
    /// `mvmctl wait` / `mvmctl boot-report` require this capability.
    Readiness,
}

/// Required remediation for a host/guest protocol mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ProtocolUpgradeAction {
    UpgradeHost,
    RebuildGuest,
    DowngradeHost,
}

/// Protocol negotiation result returned by [`negotiate_protocol`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolNegotiation {
    pub agent_protocol_version: u32,
    pub min_supported_version: u32,
    pub agent_version: String,
    pub capabilities: Vec<GuestCapability>,
}

/// Capabilities served by this agent build.
pub fn supported_capabilities() -> Vec<GuestCapability> {
    vec![
        GuestCapability::Ping,
        GuestCapability::ResourceUsage,
        GuestCapability::IntegrationStatus,
        GuestCapability::EntrypointStatus,
        GuestCapability::RunEntrypoint,
        GuestCapability::RunExtension,
        GuestCapability::FilesystemRpc,
        GuestCapability::ProcessRpc,
        GuestCapability::Console,
        GuestCapability::UnixSocketForward,
        GuestCapability::VolumeMount,
        GuestCapability::UpdateIdleTimeout,
        GuestCapability::Readiness,
    ]
}

/// Return `true` when `[a_min, a_max]` overlaps `[b_min, b_max]`.
fn protocol_ranges_overlap(a_min: u32, a_max: u32, b_min: u32, b_max: u32) -> bool {
    a_min <= b_max && b_min <= a_max
}

/// Build the guest side response for a protocol hello request.
pub fn protocol_hello_response(
    host_protocol_version: u32,
    host_min_supported_version: u32,
    _host_version: &str,
    requested_capabilities: &[GuestCapability],
) -> GuestResponse {
    if !protocol_ranges_overlap(
        host_min_supported_version,
        host_protocol_version,
        MIN_SUPPORTED_PROTOCOL_VERSION,
        PROTOCOL_VERSION,
    ) {
        let required_action = if host_protocol_version < MIN_SUPPORTED_PROTOCOL_VERSION {
            ProtocolUpgradeAction::UpgradeHost
        } else {
            ProtocolUpgradeAction::RebuildGuest
        };

        return GuestResponse::ProtocolMismatch {
            host_protocol_version,
            agent_protocol_version: PROTOCOL_VERSION,
            required_action,
            message: format!(
                "guest-agent protocol mismatch: host supports {}..={}, agent supports {}..={}",
                host_min_supported_version,
                host_protocol_version,
                MIN_SUPPORTED_PROTOCOL_VERSION,
                PROTOCOL_VERSION
            ),
        };
    }

    let supported = supported_capabilities();
    let capabilities = requested_capabilities
        .iter()
        .copied()
        .filter(|cap| supported.contains(cap))
        .collect();

    GuestResponse::ProtocolHelloAck {
        agent_protocol_version: PROTOCOL_VERSION,
        min_supported_version: MIN_SUPPORTED_PROTOCOL_VERSION,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities,
    }
}
/// Result of a virtio-fs volume mount operation.
/// (Renamed from `ShareResult`.)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum VolumeMountResult {
    /// `MountVolume` succeeded. `canonical_path` is the
    /// post-validation path the agent actually mounted at — same
    /// shape as input but with trailing slashes normalised.
    Mounted { canonical_path: String },
    /// `UnmountVolume` succeeded.
    Unmounted,
    /// Verb-specific error.
    Error {
        kind: VolumeMountErrorKind,
        message: String,
    },
}

/// Class of error returned in `VolumeMountResult::Error`. Closed enum
/// so the host can branch on `kind` without parsing message text.
/// (Renamed from `ShareErrorKind`.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum VolumeMountErrorKind {
    /// `guest_path` is empty / not absolute / contains `..` /
    /// embedded NUL.
    BadPath,
    /// `guest_path` resolved to a deny-prefix or fell outside the
    /// allow-roots configured for this image.
    PolicyDenied,
    /// `volume_name` is empty, too long, or contains characters
    /// virtio-fs won't accept as a tag.
    BadVolumeName,
    /// `mount(2)` returned a non-EBUSY error (no virtiofsd, kernel
    /// missing virtio_fs module, etc.).
    MountFailed,
    /// `umount(2)` returned EBUSY and `force = false` — caller
    /// must retry with `force = true` to lazy-detach.
    Busy,
    /// Underlying I/O error not mapped above.
    IoError,
    /// Any other unclassified failure.
    Other,
}
/// Kind of agent-side error reported via `EntrypointEvent::Error`.
///
/// The variants are deliberately coarse — the host correlates by
/// `kind` and surfaces the human-readable `message` to the operator.
/// Adding a variant is a wire change; renaming or removing is a
/// breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum RunEntrypointError {
    /// Inbound stdin or buffered stdout/stderr exceeded the cap
    /// configured for the call.
    PayloadCap,
    /// The wrapper exceeded `timeout_secs`. Agent killed the
    /// process group.
    Timeout,
    /// The admitted controller canceled the call and the agent killed its
    /// process group.
    Canceled,
    /// Another `RunEntrypoint` is in flight on this VM. M12: agents
    /// serialize per-VM; concurrency comes from pool growth.
    Busy,
    /// The wrapper process died unexpectedly (signal, OOM, etc.).
    WrapperCrashed,
    /// Entrypoint validation has not yet completed:
    /// the agent binds vsock early and validates entrypoint in the
    /// background, so a host that races `RunEntrypoint` ahead of
    /// `ReadinessStatus { entrypoint: Ready }` gets this back rather
    /// than `EntrypointInvalid` (which would imply a permanent
    /// failure). Hosts should poll readiness, not retry blindly.
    NotReady,
    /// `/etc/mvm/entrypoint` is missing, fails validation
    /// (symlink crossing FS, wrong perms, off the verity
    /// partition), or otherwise can't be loaded. Reported per-call
    /// even though the validation runs at agent boot.
    EntrypointInvalid,
    /// The session backing this call was killed externally (host
    /// invoked `mvmctl session kill <id>`) while the call was in
    /// flight. Synthesized host-side by `mvmctl invoke` /
    /// `session attach` after detecting a transport-level connection
    /// drop coincident with a session record marked `Killed`. The
    /// agent itself does not emit this — it would be torn down with
    /// the VM before it could.
    SessionKilled,
    /// Other agent-internal failure — file I/O, vsock framing,
    /// inter-process plumbing. Look at `message` for detail.
    InternalError,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn post_restore_ack_carries_reseeded_flag() {
        let ack = GuestResponse::PostRestoreAck {
            success: true,
            detail: None,
            reseeded: true,
            clock_resynced: true,
        };
        let json = serde_json::to_string(&ack).unwrap();
        match serde_json::from_str::<GuestResponse>(&json).unwrap() {
            GuestResponse::PostRestoreAck { reseeded, .. } => assert!(reseeded),
            other => panic!("expected PostRestoreAck, got {other:?}"),
        }
        // A pre-rotation ack without the field defaults `reseeded` to false.
        match serde_json::from_str::<GuestResponse>(
            r#"{"PostRestoreAck":{"success":true,"detail":null}}"#,
        )
        .unwrap()
        {
            GuestResponse::PostRestoreAck {
                reseeded,
                clock_resynced,
                ..
            } => {
                assert!(!reseeded);
                assert!(!clock_resynced);
            }
            other => panic!("expected PostRestoreAck, got {other:?}"),
        }
    }

    #[test]
    fn primed_status_wire_roundtrips_and_rejects_unknown_fields() {
        // Request roundtrip.
        let json = serde_json::to_string(&GuestRequest::PrimedStatus).unwrap();
        assert!(matches!(
            serde_json::from_str::<GuestRequest>(&json).unwrap(),
            GuestRequest::PrimedStatus
        ));
        // Response roundtrip.
        let report = GuestResponse::PrimedStatusReport { primed: true };
        let json = serde_json::to_string(&report).unwrap();
        match serde_json::from_str::<GuestResponse>(&json).unwrap() {
            GuestResponse::PrimedStatusReport { primed } => assert!(primed),
            other => panic!("expected PrimedStatusReport, got {other:?}"),
        }
        // The verb maps to the contracted unary response.
        assert!(matches!(
            GuestRequest::PrimedStatus.verb().response_contract().kind,
            ResponseKind::Unary
        ));
    }

    #[test]
    fn test_guest_response_roundtrip() {
        use crate::integrations::{IntegrationStateReport, IntegrationStatus};

        let variants: Vec<GuestResponse> = vec![
            GuestResponse::ProtocolHelloAck {
                agent_protocol_version: PROTOCOL_VERSION,
                min_supported_version: MIN_SUPPORTED_PROTOCOL_VERSION,
                agent_version: "0.1.0".to_string(),
                capabilities: vec![GuestCapability::Ping],
            },
            GuestResponse::ProtocolMismatch {
                host_protocol_version: 0,
                agent_protocol_version: PROTOCOL_VERSION,
                required_action: ProtocolUpgradeAction::UpgradeHost,
                message: "host too old".to_string(),
            },
            GuestResponse::WorkerStatus {
                status: "idle".to_string(),
                last_busy_at: Some("2025-01-01T00:00:00Z".to_string()),
            },
            GuestResponse::SleepPrepAck {
                success: true,
                detail: Some("flushed".to_string()),
            },
            GuestResponse::WakeAck { success: true },
            GuestResponse::Pong,
            GuestResponse::ResourceUsageReport { rss_bytes: 4096 },
            GuestResponse::Error {
                message: "oops".to_string(),
            },
            GuestResponse::UnsupportedInProfile {
                profile: AgentProfile::SealedProd,
                verb: "Exec".to_string(),
            },
            GuestResponse::ReadinessStatusReport(ReadinessReport {
                control_plane: ComponentState::Ready,
                entrypoint: ComponentState::Starting,
                warm_pool: ComponentState::Disabled,
                integrations: ComponentState::Disabled,
                probes: ComponentState::Disabled,
                volumes: ComponentState::Disabled,
                profile: AgentProfile::SealedProd,
                boot_millis: BootTimingReport {
                    agent_started_ms: Some(5),
                    vsock_bound_ms: Some(5),
                    first_accept_ms: Some(8),
                    entrypoint_ready_ms: None,
                    warm_pool_ready_ms: None,
                    integrations_ready_ms: None,
                    probes_ready_ms: None,
                },
            }),
            GuestResponse::IntegrationStatusReport {
                integrations: vec![IntegrationStateReport {
                    name: "whatsapp".to_string(),
                    status: IntegrationStatus::Active,
                    last_checkpoint_at: Some("2025-06-01T12:00:00Z".to_string()),
                    state_size_bytes: 8192,
                    health: None,
                }],
            },
            GuestResponse::CheckpointResult {
                success: true,
                failed: vec![],
                detail: Some("all checkpointed".to_string()),
            },
            GuestResponse::ProbeStatusReport {
                probes: vec![crate::probes::ProbeResult {
                    name: "disk-usage".to_string(),
                    healthy: true,
                    detail: "ok".to_string(),
                    output: Some(serde_json::json!({"usage_pct": 42})),
                    checked_at: "2026-02-26T12:00:00Z".to_string(),
                }],
            },
            GuestResponse::PostRestoreAck {
                success: true,
                detail: Some("post-restore signal sent to init".to_string()),
                reseeded: false,
                clock_resynced: false,
            },
            GuestResponse::FsDiffResult {
                changes: vec![
                    FsChange {
                        path: "/app/output.txt".to_string(),
                        kind: FsChangeKind::Created,
                        size: 1234,
                    },
                    FsChange {
                        path: "/etc/hosts".to_string(),
                        kind: FsChangeKind::Modified,
                        size: 89,
                    },
                    FsChange {
                        path: "/tmp/scratch".to_string(),
                        kind: FsChangeKind::Deleted,
                        size: 0,
                    },
                ],
            },
            GuestResponse::ConsoleOpened {
                session_id: 1,
                data_port: 20001,
            },
            GuestResponse::ConsoleExited {
                session_id: 1,
                exit_code: 0,
            },
            GuestResponse::ConsoleResized { session_id: 1 },
            GuestResponse::FsResult(FsResult::Read {
                content: vec![1, 2, 3],
                total_size: 3,
            }),
            GuestResponse::FsResult(FsResult::Write { bytes_written: 4 }),
            GuestResponse::FsResult(FsResult::List {
                entries: vec![FsEntry {
                    name: "data.csv".to_string(),
                    kind: FsEntryKind::File,
                    size: 1024,
                }],
                truncated: false,
            }),
            GuestResponse::FsResult(FsResult::Stat(FsStat {
                canonical_path: "/data/data.csv".to_string(),
                kind: FsEntryKind::File,
                size: 1024,
                mode: 0o100644,
                mtime: Some("2026-05-05T10:00:00Z".to_string()),
            })),
            GuestResponse::FsResult(FsResult::Mkdir),
            GuestResponse::FsResult(FsResult::Remove { entries_removed: 7 }),
            GuestResponse::FsResult(FsResult::Move),
            GuestResponse::FsResult(FsResult::Error {
                kind: FsErrorKind::PolicyDenied,
                message: "path under /etc/mvm/* is denied".to_string(),
            }),
            GuestResponse::ProcResult(ProcResult::Started {
                pid_token: "tok-1".to_string(),
            }),
            GuestResponse::ProcResult(ProcResult::List {
                processes: vec![ProcInfo {
                    pid_token: "tok-1".to_string(),
                    started_at: "2026-05-05T10:00:00Z".to_string(),
                    argv0: "/usr/bin/sleep".to_string(),
                    state: ProcState::Running,
                }],
            }),
            GuestResponse::ProcResult(ProcResult::Signaled),
            GuestResponse::ProcResult(ProcResult::InputAccepted { bytes_accepted: 3 }),
            GuestResponse::ProcResult(ProcResult::Killed),
            GuestResponse::ProcResult(ProcResult::Error {
                kind: ProcErrorKind::UnknownToken,
                message: "no such pid_token".to_string(),
            }),
            GuestResponse::ProcWaitEvent(ProcWaitEvent::Stdout { chunk: vec![1, 2] }),
            GuestResponse::ProcWaitEvent(ProcWaitEvent::Stderr { chunk: vec![3, 4] }),
            GuestResponse::ProcWaitEvent(ProcWaitEvent::Exit { code: 0 }),
            GuestResponse::ProcWaitEvent(ProcWaitEvent::Killed { signal: 15 }),
            GuestResponse::ProcWaitEvent(ProcWaitEvent::TimedOut),
            GuestResponse::ProcWaitEvent(ProcWaitEvent::Error {
                kind: ProcErrorKind::UnsupportedInProduction,
                message: "stripped from prod".to_string(),
            }),
            GuestResponse::VolumeMountResult(VolumeMountResult::Mounted {
                canonical_path: "/data/foo".to_string(),
            }),
            GuestResponse::VolumeMountResult(VolumeMountResult::Unmounted),
            GuestResponse::VolumeMountResult(VolumeMountResult::Error {
                kind: VolumeMountErrorKind::PolicyDenied,
                message: "/etc/x is on the deny list".to_string(),
            }),
            GuestResponse::VolumeMountResult(VolumeMountResult::Error {
                kind: VolumeMountErrorKind::Busy,
                message: "target busy; pass force=true".to_string(),
            }),
            GuestResponse::UpdateIdleTimeoutAck {
                previous_secs: 300,
                applied_secs: 600,
            },
            GuestResponse::UpdateIdleTimeoutAck {
                previous_secs: 0,
                applied_secs: 0,
            },
        ];

        for resp in &variants {
            let json = serde_json::to_string(resp).unwrap();
            let parsed: GuestResponse = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn test_protocol_hello_response_ack_filters_capabilities() {
        let resp = protocol_hello_response(
            PROTOCOL_VERSION,
            MIN_SUPPORTED_PROTOCOL_VERSION,
            "host-test",
            &[GuestCapability::Ping, GuestCapability::RunEntrypoint],
        );

        match resp {
            GuestResponse::ProtocolHelloAck {
                agent_protocol_version,
                min_supported_version,
                capabilities,
                ..
            } => {
                assert_eq!(agent_protocol_version, PROTOCOL_VERSION);
                assert_eq!(min_supported_version, MIN_SUPPORTED_PROTOCOL_VERSION);
                assert_eq!(
                    capabilities,
                    vec![GuestCapability::Ping, GuestCapability::RunEntrypoint]
                );
            }
            other => panic!("expected ProtocolHelloAck, got {other:?}"),
        }
    }

    #[test]
    fn test_supported_capabilities_include_unix_socket_forward() {
        assert!(supported_capabilities().contains(&GuestCapability::UnixSocketForward));
    }

    #[test]
    fn resource_usage_is_capability_negotiated_and_unary() {
        assert!(supported_capabilities().contains(&GuestCapability::ResourceUsage));
        let contract = Verb::ResourceUsage.response_contract();
        assert_eq!(contract.kind, ResponseKind::Unary);
        assert_eq!(contract.responses, &[ResponseVariant::ResourceUsageReport]);
    }

    #[test]
    fn test_protocol_hello_response_upgrade_host_when_host_too_old() {
        let resp = protocol_hello_response(0, 0, "host-test", &[GuestCapability::Ping]);

        match resp {
            GuestResponse::ProtocolMismatch {
                host_protocol_version,
                agent_protocol_version,
                required_action,
                message,
            } => {
                assert_eq!(host_protocol_version, 0);
                assert_eq!(agent_protocol_version, PROTOCOL_VERSION);
                assert_eq!(required_action, ProtocolUpgradeAction::UpgradeHost);
                assert!(message.contains("protocol mismatch"));
            }
            other => panic!("expected ProtocolMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_protocol_hello_response_rebuild_guest_when_agent_too_old() {
        let resp = protocol_hello_response(
            PROTOCOL_VERSION + 10,
            PROTOCOL_VERSION + 10,
            "host-test",
            &[GuestCapability::Ping],
        );

        match resp {
            GuestResponse::ProtocolMismatch {
                host_protocol_version,
                agent_protocol_version,
                required_action,
                ..
            } => {
                assert_eq!(host_protocol_version, PROTOCOL_VERSION + 10);
                assert_eq!(agent_protocol_version, PROTOCOL_VERSION);
                assert_eq!(required_action, ProtocolUpgradeAction::RebuildGuest);
            }
            other => panic!("expected ProtocolMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_protocol_unknown_field_rejected() {
        let req_json = r#"{"ProtocolHello":{"host_protocol_version":1,"min_supported_version":1,"host_version":"0.1.0","requested_capabilities":["ping"],"extra":true}}"#;
        let req: Result<GuestRequest, _> = serde_json::from_str(req_json);
        assert!(req.is_err(), "ProtocolHello extra field must reject");

        let resp_json = r#"{"ProtocolHelloAck":{"agent_protocol_version":1,"min_supported_version":1,"agent_version":"0.1.0","capabilities":["ping"],"extra":true}}"#;
        let resp: Result<GuestResponse, _> = serde_json::from_str(resp_json);
        assert!(resp.is_err(), "ProtocolHelloAck extra field must reject");
    }

    /// `VolumeMountResult` sub-variants reachable through
    /// `GuestResponse` also need deny-unknown-fields, since they land
    /// on the host's deserializer.
    #[test]
    fn test_volume_response_subtypes_reject_unknown_fields() {
        let cases = [
            r#"{"VolumeMountResult":{"Mounted":{"canonical_path":"/data/x","smuggled":1}}}"#,
            r#"{"VolumeMountResult":{"Error":{"kind":"PolicyDenied","message":"x","smuggled":1}}}"#,
        ];
        for json in cases {
            let err = serde_json::from_str::<GuestResponse>(json).unwrap_err();
            assert!(
                err.to_string().contains("unknown field"),
                "expected unknown-field rejection for {json}, got: {err}"
            );
        }
    }

    /// `VolumeMountResult::Unmounted` is a unit variant; verify the
    /// wire shape is just the variant name.
    #[test]
    fn test_volume_unmounted_unit_variant_roundtrip() {
        let resp = GuestResponse::VolumeMountResult(VolumeMountResult::Unmounted);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""VolumeMountResult":"Unmounted""#));
        let parsed: GuestResponse = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            parsed,
            GuestResponse::VolumeMountResult(VolumeMountResult::Unmounted)
        ));
    }

    #[test]
    fn test_guest_response_rejects_unknown_field_inside_variant() {
        let json = r#"{"WorkerStatus":{"status":"idle","last_busy_at":null,"x":1}}"#;
        let err = serde_json::from_str::<GuestResponse>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn test_detached_started_response_roundtrip() {
        let resp = GuestResponse::DetachedStarted { pid: 4242 };
        let json = serde_json::to_string(&resp).expect("serialize");
        let decoded: GuestResponse = serde_json::from_str(&json).expect("deserialize");
        match decoded {
            GuestResponse::DetachedStarted { pid } => assert_eq!(pid, 4242),
            other => panic!("expected DetachedStarted, got {other:?}"),
        }
    }

    #[test]
    fn test_run_entrypoint_error_all_variants_roundtrip() {
        // Every error variant must serialize and deserialize back
        // to itself. Adding a variant without updating this list is
        // intentional friction.
        let variants = [
            RunEntrypointError::PayloadCap,
            RunEntrypointError::Timeout,
            RunEntrypointError::Busy,
            RunEntrypointError::WrapperCrashed,
            RunEntrypointError::EntrypointInvalid,
            RunEntrypointError::SessionKilled,
            RunEntrypointError::InternalError,
        ];
        for v in variants {
            let json = serde_json::to_string(&v).expect("serialize");
            let decoded: RunEntrypointError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded, v, "variant {v:?} did not roundtrip");
        }
    }

    #[test]
    fn test_run_entrypoint_error_rejects_unknown_variant() {
        let json = r#""SomeNewError""#;
        let err = serde_json::from_str::<RunEntrypointError>(json).unwrap_err();
        assert!(
            err.to_string().contains("unknown variant"),
            "expected 'unknown variant', got: {err}"
        );
    }

    #[test]
    fn test_entrypoint_status_report_ok_roundtrip() {
        let resp = GuestResponse::EntrypointStatusReport {
            ok: true,
            path: Some("/usr/lib/mvm/wrappers/python-runner".into()),
            detail: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: GuestResponse = serde_json::from_str(&json).unwrap();
        match decoded {
            GuestResponse::EntrypointStatusReport { ok, path, detail } => {
                assert!(ok);
                assert_eq!(path.as_deref(), Some("/usr/lib/mvm/wrappers/python-runner"));
                assert!(detail.is_none());
            }
            other => panic!("expected EntrypointStatusReport, got {other:?}"),
        }
    }

    #[test]
    fn test_entrypoint_status_report_failed_roundtrip() {
        let resp = GuestResponse::EntrypointStatusReport {
            ok: false,
            path: None,
            detail: Some("entrypoint validation never ran".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: GuestResponse = serde_json::from_str(&json).unwrap();
        match decoded {
            GuestResponse::EntrypointStatusReport { ok, path, detail } => {
                assert!(!ok);
                assert!(path.is_none());
                assert!(detail.unwrap().contains("never ran"));
            }
            other => panic!("expected EntrypointStatusReport, got {other:?}"),
        }
    }

    #[test]
    fn test_entrypoint_status_report_rejects_unknown_field() {
        let json =
            r#"{"EntrypointStatusReport":{"ok":true,"path":null,"detail":null,"smuggled":1}}"#;
        let err = serde_json::from_str::<GuestResponse>(json).unwrap_err();
        assert!(
            err.to_string().contains("unknown field") && err.to_string().contains("smuggled"),
            "expected 'unknown field smuggled', got: {err}"
        );
    }

    #[test]
    fn test_guest_response_worker_status_fields() {
        let resp = GuestResponse::WorkerStatus {
            status: "busy".to_string(),
            last_busy_at: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"status\":\"busy\""));
    }

    #[test]
    fn test_checkpoint_result_failure() {
        let resp = GuestResponse::CheckpointResult {
            success: false,
            failed: vec!["whatsapp".to_string()],
            detail: Some("session locked".to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: GuestResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            GuestResponse::CheckpointResult {
                success, failed, ..
            } => {
                assert!(!success);
                assert_eq!(failed, vec!["whatsapp"]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_unsupported_in_profile_response_roundtrip() {
        let resp = GuestResponse::UnsupportedInProfile {
            profile: AgentProfile::SealedProd,
            verb: "Exec".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        // kebab-case profile wire format keeps user-facing JSON tidy.
        assert!(json.contains("\"sealed-prod\""), "got {json}");
        assert!(json.contains("\"Exec\""), "got {json}");

        let parsed: GuestResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            GuestResponse::UnsupportedInProfile { profile, verb } => {
                assert_eq!(profile, AgentProfile::SealedProd);
                assert_eq!(verb, "Exec");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn test_component_state_wire_format_is_snake_case() {
        // Wire format keeps JSON ergonomic for hand-written
        // policies / mock fixtures.
        assert_eq!(
            serde_json::to_string(&ComponentState::Starting).unwrap(),
            "\"starting\""
        );
        assert_eq!(
            serde_json::to_string(&ComponentState::Ready).unwrap(),
            "\"ready\""
        );
        assert_eq!(
            serde_json::to_string(&ComponentState::Disabled).unwrap(),
            "\"disabled\""
        );
        let failed_json = serde_json::to_string(&ComponentState::Failed {
            message: "boom".into(),
        })
        .unwrap();
        assert!(failed_json.contains("\"failed\""), "got {failed_json}");
        assert!(failed_json.contains("\"boom\""), "got {failed_json}");

        let parsed: ComponentState = serde_json::from_str(&failed_json).unwrap();
        assert!(matches!(
            parsed,
            ComponentState::Failed { ref message } if message == "boom"
        ));
    }

    #[test]
    fn test_readiness_report_roundtrip_with_disabled_subsystems() {
        // A cold-tier image's readiness snapshot mid-boot: control
        // plane ready, entrypoint still validating, everything
        // else `Disabled` (no warm pool, no integrations, no
        // probes) by virtue of `Default`.
        let report = ReadinessReport {
            control_plane: ComponentState::Ready,
            entrypoint: ComponentState::Starting,
            boot_millis: BootTimingReport {
                agent_started_ms: Some(3),
                vsock_bound_ms: Some(3),
                first_accept_ms: Some(7),
                ..Default::default()
            },
            ..Default::default()
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: ReadinessReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, report);
    }

    #[test]
    fn test_readiness_report_rejects_unknown_fields() {
        // Every host↔guest type must deny unknown
        // fields. Verify the outer report shape; ComponentState +
        // BootTimingReport carry their own `deny_unknown_fields`.
        let json = r#"{
            "control_plane": "ready",
            "entrypoint": "starting",
            "warm_pool": "disabled",
            "integrations": "disabled",
            "probes": "disabled",
            "volumes": "disabled",
            "profile": "sealed-prod",
            "boot_millis": {
                "agent_started_ms": null,
                "vsock_bound_ms": null,
                "first_accept_ms": null,
                "entrypoint_ready_ms": null,
                "warm_pool_ready_ms": null,
                "integrations_ready_ms": null,
                "probes_ready_ms": null
            },
            "smuggled": 1
        }"#;
        let err = serde_json::from_str::<ReadinessReport>(json).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "expected unknown-field rejection, got: {err}"
        );
    }

    #[test]
    fn test_run_entrypoint_error_not_ready_roundtrip() {
        // The typed variant returned when a host
        // races `RunEntrypoint` ahead of `entrypoint=Ready`.
        let err = RunEntrypointError::NotReady;
        let json = serde_json::to_string(&err).unwrap();
        assert_eq!(json, "\"NotReady\"");
        let parsed: RunEntrypointError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, err);
    }

    #[test]
    fn test_boot_timing_report_default_is_all_none() {
        // The skeleton ships with all-`None` so later work can fill
        // the remaining fields without breaking the wire shape.
        let t = BootTimingReport::default();
        assert!(t.agent_started_ms.is_none());
        assert!(t.vsock_bound_ms.is_none());
        assert!(t.first_accept_ms.is_none());
        assert!(t.entrypoint_ready_ms.is_none());
        assert!(t.warm_pool_ready_ms.is_none());
        assert!(t.integrations_ready_ms.is_none());
        assert!(t.probes_ready_ms.is_none());
    }

    #[test]
    fn test_component_state_default_is_disabled() {
        // "Not configured" is the semantically conservative default.
        // A subsystem we haven't heard anything about must NOT
        // accidentally read as `Ready` — that would short-circuit a
        // host's readiness gate.
        assert_eq!(ComponentState::default(), ComponentState::Disabled);
    }

    #[test]
    fn test_readiness_report_default_is_all_disabled_sealed_prod() {
        // A bare `ReadinessReport::default()` is what an unconfigured
        // sealed-prod agent would report. Tests / fixtures that only
        // care about one or two components can use this + struct-
        // update syntax instead of listing every field.
        let r = ReadinessReport::default();
        assert_eq!(r.control_plane, ComponentState::Disabled);
        assert_eq!(r.entrypoint, ComponentState::Disabled);
        assert_eq!(r.warm_pool, ComponentState::Disabled);
        assert_eq!(r.integrations, ComponentState::Disabled);
        assert_eq!(r.probes, ComponentState::Disabled);
        assert_eq!(r.volumes, ComponentState::Disabled);
        assert_eq!(r.profile, AgentProfile::SealedProd);
        assert_eq!(r.boot_millis, BootTimingReport::default());
    }

    #[test]
    fn test_readiness_report_default_struct_update_ergonomics() {
        // Demonstrates the intended call-site shape: change one or
        // two components, default the rest. If the type ever grows a
        // field this test still compiles — that's the whole point.
        let r = ReadinessReport {
            control_plane: ComponentState::Ready,
            entrypoint: ComponentState::Starting,
            boot_millis: BootTimingReport {
                vsock_bound_ms: Some(7),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(r.control_plane, ComponentState::Ready);
        assert_eq!(r.entrypoint, ComponentState::Starting);
        assert_eq!(r.warm_pool, ComponentState::Disabled);
        assert_eq!(r.boot_millis.vsock_bound_ms, Some(7));
        assert!(r.boot_millis.first_accept_ms.is_none());
    }
    #[test]
    fn ping_is_unary_pong() {
        let c = Verb::Ping.response_contract();
        assert_eq!(c.kind, ResponseKind::Unary);
        assert_eq!(c.responses, &[ResponseVariant::Pong]);
    }

    #[test]
    fn run_entrypoint_streams_entrypoint_event() {
        let c = Verb::RunEntrypoint.response_contract();
        assert_eq!(c.kind, ResponseKind::Stream);
        assert_eq!(c.responses, &[ResponseVariant::EntrypointEvent]);
    }

    #[test]
    fn protocol_hello_lists_both_outcomes() {
        let c = Verb::ProtocolHello.response_contract();
        assert_eq!(c.kind, ResponseKind::Unary);
        let got: BTreeSet<_> = c.responses.iter().map(|r| r.name()).collect();
        assert_eq!(
            got,
            BTreeSet::from(["ProtocolHelloAck", "ProtocolMismatch"])
        );
    }

    #[test]
    fn streaming_verbs_are_the_closed_expected_set() {
        let streaming: BTreeSet<_> = Verb::ALL
            .iter()
            .filter(|v| v.response_contract().kind == ResponseKind::Stream)
            .map(|v| v.name())
            .collect();
        assert_eq!(
            streaming,
            BTreeSet::from([
                "Exec",
                "ProcWait",
                "RunCode",
                "RunEntrypoint",
                "RunExtension",
            ])
        );
    }

    #[test]
    fn every_streaming_verb_is_data_plane() {
        for verb in Verb::ALL {
            if verb.response_contract().kind == ResponseKind::Stream {
                assert_eq!(verb.traffic_plane(), TrafficPlane::Data, "{}", verb.name());
            }
        }
    }

    #[test]
    fn representative_verbs_have_expected_traffic_planes() {
        assert_eq!(Verb::Ping.traffic_plane(), TrafficPlane::Control);
        assert_eq!(Verb::ReadinessStatus.traffic_plane(), TrafficPlane::Control);
        assert_eq!(Verb::RunEntrypoint.traffic_plane(), TrafficPlane::Data);
        assert_eq!(Verb::FsRead.traffic_plane(), TrafficPlane::Data);
        assert_eq!(Verb::ConsoleOpen.traffic_plane(), TrafficPlane::Control);
    }

    // Drift guard: every GuestResponse variant must be answered by some
    // request's contract, or be a universal (Error / UnsupportedInProfile).
    // Adding a GuestResponse variant without wiring it fails this test.
    #[test]
    fn every_response_variant_is_contracted_or_universal() {
        let mut covered: BTreeSet<&'static str> = BTreeSet::new();
        for v in Verb::ALL {
            for r in v.response_contract().responses {
                covered.insert(r.name());
            }
        }
        for r in ResponseVariant::ALL.iter().filter(|r| r.is_universal()) {
            covered.insert(r.name());
        }
        let all: BTreeSet<_> = ResponseVariant::ALL.iter().map(|r| r.name()).collect();
        assert_eq!(covered, all);
    }

    #[test]
    fn contracts_never_list_universal_responses() {
        for v in Verb::ALL {
            for r in v.response_contract().responses {
                assert!(
                    !r.is_universal(),
                    "{} lists universal response {}",
                    v.name(),
                    r.name()
                );
            }
        }
    }

    #[test]
    fn response_variant_projection_round_trips() {
        assert_eq!(GuestResponse::Pong.variant(), ResponseVariant::Pong);
        assert_eq!(GuestResponse::Pong.variant().name(), "Pong");
    }

    // ---- is_stream_terminal ----

    #[test]
    fn entrypoint_exit_is_stream_terminal_but_stdout_is_not() {
        let term = GuestResponse::EntrypointEvent(EntrypointEvent::Exit { code: 0 });
        let mid = GuestResponse::EntrypointEvent(EntrypointEvent::Stdout {
            chunk: b"x".to_vec(),
        });
        assert!(term.is_stream_terminal());
        assert!(!mid.is_stream_terminal());
    }

    #[test]
    fn activate_environment_response_contract_is_unary() {
        let contract = Verb::ActivateEnvironment.response_contract();
        assert_eq!(contract.kind, ResponseKind::Unary);
        assert!(
            contract
                .responses
                .contains(&ResponseVariant::ActivateEnvironmentAck)
        );
        assert!(
            contract
                .responses
                .contains(&ResponseVariant::ActivateEnvironmentError)
        );
        assert!(contract.responses.contains(&ResponseVariant::NotActivated));
    }

    #[test]
    fn activate_environment_response_variants_project() {
        assert_eq!(
            GuestResponse::ActivateEnvironmentAck.variant(),
            ResponseVariant::ActivateEnvironmentAck
        );
        assert_eq!(
            GuestResponse::ActivateEnvironmentError {
                message: "x".to_string()
            }
            .variant(),
            ResponseVariant::ActivateEnvironmentError
        );
        assert_eq!(
            GuestResponse::NotActivated.variant(),
            ResponseVariant::NotActivated
        );
    }
}
