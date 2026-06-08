use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mvm_core::security::{
    AgentProfile, AuthenticatedFrame, PROTOCOL_VERSION_AUTHENTICATED, SIG_ALG_ED25519,
    SessionHello, SessionHelloAck,
};
use mvm_core::signing::SignedPayload;
use serde::{Deserialize, Serialize};

/// Default vsock guest CID (Firecracker convention).
pub const GUEST_CID: u32 = 3;

/// Port the guest vsock agent listens on.
///
/// **Why 5252 (and why not <1024).** Linux gates `bind(2)` on AF_VSOCK
/// ports ≤ 1023 behind `CAP_NET_BIND_SERVICE` — the same way it gates
/// AF_INET. The agent runs as uid 901 with `--bounding-set=-all`
/// (ADR-002 §W4.5), so it has no caps to spend on a privileged port.
/// Any port < 1024 would force us to either grant the agent
/// `CAP_NET_BIND_SERVICE` (weakening W4.5 to work around port choice)
/// or bind in init and pass the fd in (extra surface for no
/// architectural benefit). Port 52 was picked when the agent ran as
/// root and the codebase incorrectly assumed vsock binds were
/// unprivileged on Linux — see the corrected comment in
/// `nix/lib/minimal-init/default.nix::guestAgentBlock`.
///
/// 5252 sits clearly above 1023 and below the port-forward range
/// (`PORT_FORWARD_BASE` = 10_000) and the console-data range
/// (`CONSOLE_PORT_BASE` = 20_000), so the host-side proxy allowlist
/// (ADR-002 §W1.3) keeps its disjoint-union shape. The "52" tail is a
/// callback to the historical port for grep-ability.
///
/// **Single source of truth.** `mvm-apple-container` and
/// `mvm::vm::vminitd_client` re-declare this value because
/// they cannot depend on `mvm-guest`. If you change this, update those
/// duplicates in the same commit; the workspace tests catch drift.
pub const GUEST_AGENT_PORT: u32 = 5252;

/// Control vsock port the guest's `/init` connects to (host side) to
/// report a one-shot workload's exit code before `poweroff -f`. The host
/// supervisor binds the listener (`add_vsock_port2(listen=false)`). Wire
/// format: a single 4-byte little-endian `i32`. Plan 152 WS-A.
pub const WORKLOAD_EXIT_PORT: u32 = 5251;

/// vsock port the host substitution endpoint (Plan 129 / ADR-067 §1) is exposed
/// on. The in-guest forward proxy connects here; the host bin maps it to the
/// UDS where `SubstitutionService` listens. Distinct from the removed 5300/5301
/// secrets channel (ADR-062). NOTE: exposing this port end-to-end needs the
/// host-side proxy port-allowlist (W1.3) to admit it — part of the bin glue.
pub const SUBSTITUTION_PORT: u32 = 5253;

/// Base vsock port for TCP port forwarding.
/// The forwarded vsock port = `PORT_FORWARD_BASE + guest_tcp_port`.
pub const PORT_FORWARD_BASE: u32 = 10000;

/// Base vsock port for interactive console PTY sessions.
pub const CONSOLE_PORT_BASE: u32 = 20000;

/// Default connect/read timeout in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Current guest-agent control protocol version.
///
/// This is distinct from `PROTOCOL_VERSION_AUTHENTICATED`, which
/// versions the signed envelope used by authenticated frame wrappers.
/// `PROTOCOL_VERSION` versions the `GuestRequest` / `GuestResponse`
/// control surface served by `mvm-guest-agent`.
pub const PROTOCOL_VERSION: u32 = 1;

/// Oldest guest-agent control protocol this host can speak.
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 1;

/// Maximum response frame size (256 KiB).
const MAX_FRAME_SIZE: usize = 256 * 1024;

/// Number of CONNECT handshake retries before giving up.
const CONNECT_RETRIES: u32 = 3;

/// Delay between CONNECT handshake retries.
const CONNECT_RETRY_DELAY_MS: u64 = 500;

/// Base delay for the adaptive readiness-poll backoff (Plan 93 Phase 2
/// Lever 2). The first poll after a failed attempt waits this long.
const ADAPTIVE_BACKOFF_BASE_MS: u64 = 20;

/// Cap for the adaptive readiness-poll backoff — the historical fixed
/// poll interval. Backoff grows from [`ADAPTIVE_BACKOFF_BASE_MS`] up to
/// this ceiling so a slow guest still polls at the old steady cadence.
const ADAPTIVE_BACKOFF_CAP_MS: u64 = 500;

/// Adaptive backoff delay for the `mvmctl up` readiness poll
/// (Plan 93 Phase 2 Lever 2). `attempt` is 0-based: attempt 0 waits the
/// base, each subsequent attempt doubles, capped at
/// [`ADAPTIVE_BACKOFF_CAP_MS`]. This replaces a fixed 500 ms sleep that
/// cost up to ~480 ms of dead time after a fast-binding guest was
/// already reachable; the cap preserves the old steady-state cadence
/// for a slow guest. Pure — the schedule is unit-tested. This changes
/// *timing only*; it never reorders or skips the protocol/auth steps a
/// caller performs between polls.
pub fn adaptive_backoff(attempt: u32) -> Duration {
    // Saturating shift so a large `attempt` can't overflow; it clamps
    // to the cap well before the shift would wrap.
    let scaled = ADAPTIVE_BACKOFF_BASE_MS.saturating_mul(1u64 << attempt.min(16));
    Duration::from_millis(scaled.min(ADAPTIVE_BACKOFF_CAP_MS))
}

// ============================================================================
// Guest agent protocol (JSON over vsock)
// ============================================================================

/// Request sent from host to guest vsock agent.
///
/// `#[serde(deny_unknown_fields)]` is load-bearing: ADR-002 §W4.1
/// requires the guest agent to refuse frames whose JSON contains
/// fields the deserializer doesn't recognise, on the principle that
/// silent acceptance of unknown fields is a deserialization-bug
/// gadget waiting to happen. Today every variant is a struct or
/// unit, so the attribute applies cleanly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum GuestRequest {
    /// Negotiate guest-agent protocol compatibility and capabilities
    /// before dispatching capability-dependent requests. ADR-053 /
    /// plan 74 W1.
    ProtocolHello {
        host_protocol_version: u32,
        min_supported_version: u32,
        host_version: String,
        requested_capabilities: Vec<GuestCapability>,
    },
    /// Query current worker status.
    WorkerStatus,
    /// Request sleep preparation. Guest should:
    /// 1. Finish/checkpoint in-flight OpenClaw work
    /// 2. Flush data to disk
    /// 3. Drop page cache
    /// 4. ACK with SleepPrepAck
    SleepPrep { drain_timeout_secs: u64 },
    /// Signal wake — guest should reinitialize connections and refresh secrets.
    Wake,
    /// Health probe.
    Ping,
    /// Query status of all managed integrations.
    IntegrationStatus,
    /// Checkpoint named integrations before sleep.
    /// Sent before SleepPrep so integrations can persist session state.
    CheckpointIntegrations { integrations: Vec<String> },
    /// Query status of all loaded probes.
    ProbeStatus,
    /// Run a command inside the guest (dev-only, requires dev-shell feature + SecurityPolicy).
    Exec {
        command: String,
        stdin: Option<String>,
        timeout_secs: Option<u64>,
    },
    /// Run the image's baked entrypoint program with the given stdin
    /// piped in and stdout/stderr captured. ADR-007 / plan 41 W1.
    ///
    /// This is the production-safe call surface. The agent reads the
    /// entrypoint path from `/etc/mvm/entrypoint` at boot, validates
    /// it (verity-partition, mode, ownership), and that resolved
    /// path is the only program `RunEntrypoint` will spawn. There is
    /// no argv override, no shell, no env injection beyond what the
    /// wrapper template defines at image build time.
    ///
    /// The response is a stream of `EntrypointEvent` frames
    /// terminated by `EntrypointEvent::Exit` or
    /// `EntrypointEvent::Error`. v1 emits one `Stdout` chunk + one
    /// `Stderr` chunk + a terminal event (buffered up to caps); v2
    /// may chunk progressively without changing the wire shape.
    ///
    /// Caps and timeouts are enforced agent-side (W2). The wire
    /// frame size is bounded by `MAX_FRAME_SIZE`.
    RunEntrypoint {
        /// Bytes piped to the wrapper's stdin.
        stdin: Vec<u8>,
        /// Wall-clock timeout for the call, in seconds. The agent
        /// kills the wrapper on overrun and emits
        /// `EntrypointEvent::Error { kind: Timeout }`.
        timeout_secs: u64,
        /// Env vars injected into the workload after `env_clear()`
        /// (Plan 129: `HTTP_PROXY` + secret placeholder vars). Empty for
        /// a plain call; omitted on the wire defaults to empty.
        #[serde(default)]
        env: Vec<(String, String)>,
    },
    /// Signal post-restore: remount drives and restart services.
    PostRestore,
    /// Request filesystem diff (changes since boot, from overlay or snapshot).
    FsDiff,
    /// Start a vsock→TCP port forwarder for the given guest port.
    /// The agent binds vsock port `PORT_FORWARD_BASE + guest_port` and
    /// forwards each connection to `localhost:guest_port`.
    StartPortForward { guest_port: u16 },
    /// Open an interactive PTY console session (dev-mode only).
    /// The guest allocates a PTY, spawns a shell, and listens on a
    /// dedicated vsock data port for raw byte streaming.
    ConsoleOpen { cols: u16, rows: u16 },
    /// Close an active console session.
    ConsoleClose { session_id: u32 },
    /// Resize the PTY window for an active console session.
    ConsoleResize {
        session_id: u32,
        cols: u16,
        rows: u16,
    },
    /// Query whether the agent's boot-time entrypoint validation
    /// succeeded. Used by `mvmctl doctor` to confirm a running guest
    /// can actually serve `RunEntrypoint`. ADR-007 / plan 41 W5.
    /// Prod-safe — reveals no secrets, takes no inputs.
    EntrypointStatus,

    /// Query structured readiness across every guest subsystem
    /// (control plane, entrypoint, warm pool, integrations, probes,
    /// volumes) plus per-phase boot timings. Plan 76 Phase 2.
    ///
    /// Prod-safe — the response carries no secrets and reveals only
    /// state the host already chose to provision (via image config /
    /// drop-in files). Designed to be the verb that responds first
    /// after vsock bind, so a host can begin streaming progress UX
    /// before entrypoint validation or warm-pool warmup finish.
    ///
    /// Distinct from `EntrypointStatus` (which is entrypoint-only and
    /// returns a flat `EntrypointStatusReport`): `ReadinessStatus`
    /// reports the *full* boot phase set with `ComponentState` per
    /// component, and is intended to be polled (`mvmctl wait`).
    ReadinessStatus,

    // ========================================================================
    // Filesystem RPC (W1 / A1 of the filesystem-volumes plan).
    //
    // Production-safe (unlike `Exec`): every verb is constrained by
    // the agent's uid 901 + W2 read-only bind mounts + the
    // `mvm-security::policy::path` deny-list. Extending the
    // `prod-agent-runentry-contract` CI lane to assert handler
    // symbols PRESENT in prod builds is part of the per-verb landing.
    // ========================================================================
    /// Read up to `length` bytes from `path`, optionally starting at
    /// `offset`. The agent enforces `length` ≤ a hard cap (default
    /// 16 MiB); callers wanting larger reads must use the streaming
    /// surface (lands in W2).
    FsRead {
        path: String,
        offset: Option<u64>,
        length: u64,
        /// `true` to follow symlinks during canonicalization. Default
        /// `true` for read; the host CLI may toggle to `false` for
        /// TOCTOU-resistant audits.
        #[serde(default = "default_true")]
        follow_symlinks: bool,
    },
    /// Write `content` to `path`. Small-content path; large writes
    /// must use the streaming surface (W2).
    FsWrite {
        path: String,
        content: Vec<u8>,
        /// File mode for newly-created files (e.g. `0o644`). Ignored
        /// when overwriting an existing file (existing perms kept).
        mode: u32,
        /// Create parent directories if missing.
        #[serde(default)]
        create_parents: bool,
        /// Defaults to `false` for write — TOCTOU-safe default since
        /// a malicious symlink could redirect the write.
        #[serde(default)]
        follow_symlinks: bool,
    },
    /// List entries in `path`. Cap: 4096 entries; truncated flag set
    /// in the response when exceeded.
    FsList {
        path: String,
        #[serde(default = "default_true")]
        follow_symlinks: bool,
    },
    /// Stat `path`. `follow_symlinks=false` returns metadata about
    /// the symlink itself (`lstat`).
    FsStat {
        path: String,
        #[serde(default = "default_true")]
        follow_symlinks: bool,
    },
    /// Create directory at `path`. With `parents=true` the call
    /// behaves like `mkdir -p`.
    FsMkdir {
        path: String,
        mode: u32,
        #[serde(default)]
        parents: bool,
    },
    /// Remove `path`. With `recursive=true` the call walks subtrees;
    /// the agent caps the walked-entry count to bound work.
    FsRemove {
        path: String,
        #[serde(default)]
        recursive: bool,
        /// Defaults to `false` for remove; symlink-following on
        /// remove is a known footgun.
        #[serde(default)]
        follow_symlinks: bool,
    },
    /// Rename `from` to `to`. Refuses to cross filesystem boundaries
    /// (returns `Errno::XDEV` rather than copy-then-delete).
    FsMove {
        from: String,
        to: String,
        #[serde(default)]
        follow_symlinks: bool,
    },

    // ========================================================================
    // Process control RPC (W1 / A2 of the filesystem-volumes plan).
    //
    // **Dev-only.** These verbs are the closest analog to the
    // established sandbox-runtime
    // `commands.start/list/signal/sendInput/wait/kill` API; they
    // exist for development and agent-driven workflows where the
    // user wants to launch arbitrary processes interactively.
    //
    // The wire types are compiled into every `mvm-guest` build so a
    // host caller against a prod agent gets a typed
    // `ProcErrorKind::UnsupportedInProduction` rather than a
    // transport error. The agent-side **handler** lives in
    // `crate::process_rpc`, gated behind the `dev-shell` feature —
    // which means the function symbols are absent from prod builds.
    // The combined `prod-agent-runentry-contract` CI gate asserts
    // this symbol contract per ADR-002 §W4.3 + ADR-007 §W5.
    //
    // Distinct from `Exec` (single-shot, blocking) and from
    // `RunEntrypoint` (production-safe baked program). Process
    // verbs offer sandbox-runtime-shaped fan-out: spawn many, list them, send
    // signals, stream output, send more stdin.
    // ========================================================================
    /// Spawn a new process. Returns a `pid_token` string the host
    /// uses to refer to the process for the rest of its lifetime —
    /// the token is opaque to the host so a buggy or malicious
    /// caller can never address a process it didn't start.
    ///
    /// Children spawned this way inherit the agent's bounding-set
    /// (`--bounding-set=-all --no-new-privs` per ADR-002 §W4.5);
    /// the handler additionally `process_group(0)`s and sets
    /// `RLIMIT_CORE=0` to avoid coredump exfil. argv is validated
    /// against an allowlist before exec.
    ProcStart {
        /// Argument vector. `argv[0]` is the executable to spawn.
        argv: Vec<String>,
        /// Environment variables. Replaces (does not extend) the
        /// agent's environment.
        #[serde(default)]
        env: std::collections::BTreeMap<String, String>,
        /// Working directory inside the guest. `None` = process
        /// inherits the agent's cwd.
        #[serde(default)]
        cwd: Option<String>,
        /// Initial stdin bytes. Further input goes via
        /// `ProcSendInput`.
        #[serde(default)]
        stdin: Vec<u8>,
        /// Optional wall-clock kill on overrun. `None` = no agent-
        /// imposed timeout; the caller can still send SIGTERM via
        /// `ProcSignal` or `ProcKill`.
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
    /// List processes currently tracked by the agent's PID-token
    /// map. Includes still-running and recently-exited entries
    /// until the agent reaps them (default: keep for 60 s after
    /// exit).
    ProcList,
    /// Send `signum` to the process named by `pid_token`. Common
    /// signals are 15 (SIGTERM) and 2 (SIGINT); for SIGKILL use
    /// the dedicated `ProcKill` verb so the audit chain captures
    /// the explicit-force semantics.
    ProcSignal { pid_token: String, signum: i32 },
    /// Append `bytes` to the process's stdin. Capped per call by
    /// the agent (default 1 MiB) and per process (default 16 MiB
    /// ring buffer); `ProcResult::InputAccepted` reports actual
    /// bytes written.
    ProcSendInput { pid_token: String, bytes: Vec<u8> },
    /// Wait for the process named by `pid_token` to exit, with an
    /// optional timeout. Response is a stream of `ProcWaitEvent`
    /// frames (stdout/stderr chunks) terminated by an `Exit`,
    /// `Killed`, `TimedOut`, or `Error` event.
    ProcWait {
        pid_token: String,
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
    /// Send SIGKILL to the process named by `pid_token`. Distinct
    /// from `ProcSignal { signum: 9 }` so the audit emit can be
    /// typed `ProcKilled` instead of a generic signal event.
    ProcKill { pid_token: String },

    // ========================================================================
    // virtio-fs share mount control (W1 / D of the filesystem-volumes plan).
    //
    // The host launches a `virtiofsd` process exposing a host
    // directory under a virtio-fs `tag`; the agent then runs the
    // in-guest `mount -t virtiofs <tag> <guest_path>`. Mount paths
    // are validated against `mvm_core::crypto::policy::MountPathPolicy`
    // (default allow-roots `/mnt`, `/data`, `/work`; deny anything
    // under `/etc`, `/usr`, `/proc`, etc.) so a host can't shadow
    // verity-protected files post-boot. Production-safe.
    // ========================================================================
    /// Mount a virtio-fs volume inside the guest. The host has
    /// already attached the device and the agent only needs to
    /// run the in-guest mount(2) call. `volume_name` is the
    /// virtio-fs tag string the device was created with — named
    /// per plan 45 to align with the `Volume` wire type.
    /// (Replaces the former `MountShare` per plan 45 §D5.)
    MountVolume {
        volume_name: String,
        guest_path: String,
        read_only: bool,
    },
    /// Unmount a previously-mounted volume. `force = false`
    /// returns `EBUSY` when the kernel reports active fds; the
    /// caller passes `force = true` to demand a lazy detach.
    /// (Replaces the former `UnmountShare` per plan 45 §D5.)
    UnmountVolume { guest_path: String, force: bool },

    /// Update the warm-process pool's idle-recycle timeout. Workers
    /// that have been idle (no in-flight call) longer than
    /// `secs` are recycled at the next sweep. `secs == 0` disables
    /// idle-based recycling — only `max_calls_per_worker` and
    /// `max_rss_mb` triggers remain.
    ///
    /// This is the substrate-side mirror of `mvmctl session
    /// set-timeout <id> <secs>`: the host writes the new value into
    /// the session record, then dispatches this verb so the agent's
    /// pool sees the same value. A best-effort dispatch — if the
    /// agent is unreachable the host record still wins on the next
    /// `mvmctl session reap`.
    UpdateIdleTimeout { secs: u64 },
    /// Run user-supplied source code in the wrapper's native
    /// interpreter. Dev-only — gated behind the agent's `dev-shell`
    /// feature flag, same fence as `Exec`. The host
    /// (`mvmctl session run-code`) provides additional gating: the
    /// session must be `mode=Dev`.
    ///
    /// The interpreter is selected by reading `/etc/mvm/wrapper.json`
    /// at dispatch time:
    ///   - `language = "python"` → `python3 -c <code>`
    ///   - `language = "node"`   → `node -e <code>`
    ///
    /// Other values, or a missing/unparseable wrapper.json, refuse
    /// with a wire-stable error message.
    ///
    /// **v1 is stateless** — each call spawns a fresh interpreter
    /// process, so `from foo import bar` in call 1 isn't visible in
    /// call 2. A future v2 (Plan-0010 §run-code Choice A) routes
    /// through the warm-process pool's wrapper for stateful eval
    /// across calls; the wire shape stays identical, the dispatch
    /// flips inside the agent.
    RunCode { code: String, timeout_secs: Option<u64> },
}

impl GuestRequest {
    /// Stable kebab-case verb name for this request — the value
    /// host-side audit emitters write into the
    /// `LocalAuditKind::NetworkPolicyAllow` detail format under
    /// `verb=<name>`. Plan 51 W6 / Plan 37 §6 invariant: every
    /// vsock RPC from host to guest emits one audit record so a
    /// forensic pass can reconstruct what the host asked the
    /// guest to do.
    ///
    /// The strings are wire-stable — a rename here is also a
    /// detail-format wire-format change. Pinned by
    /// [`tests::kind_name_covers_every_variant`].
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::ProtocolHello { .. } => "protocol-hello",
            Self::WorkerStatus => "worker-status",
            Self::SleepPrep { .. } => "sleep-prep",
            Self::Wake => "wake",
            Self::Ping => "ping",
            Self::IntegrationStatus => "integration-status",
            Self::CheckpointIntegrations { .. } => "checkpoint-integrations",
            Self::ProbeStatus => "probe-status",
            Self::Exec { .. } => "exec",
            Self::RunEntrypoint { .. } => "run-entrypoint",
            Self::PostRestore => "post-restore",
            Self::FsDiff => "fs-diff",
            Self::StartPortForward { .. } => "start-port-forward",
            Self::ConsoleOpen { .. } => "console-open",
            Self::ConsoleClose { .. } => "console-close",
            Self::ConsoleResize { .. } => "console-resize",
            Self::EntrypointStatus => "entrypoint-status",
            Self::ReadinessStatus => "readiness-status",
            Self::FsRead { .. } => "fs-read",
            Self::FsWrite { .. } => "fs-write",
            Self::FsList { .. } => "fs-list",
            Self::FsStat { .. } => "fs-stat",
            Self::FsMkdir { .. } => "fs-mkdir",
            Self::FsRemove { .. } => "fs-remove",
            Self::FsMove { .. } => "fs-move",
            Self::ProcStart { .. } => "proc-start",
            Self::ProcList => "proc-list",
            Self::ProcSignal { .. } => "proc-signal",
            Self::ProcSendInput { .. } => "proc-send-input",
            Self::ProcWait { .. } => "proc-wait",
            Self::ProcKill { .. } => "proc-kill",
            Self::MountVolume { .. } => "mount-volume",
            Self::UnmountVolume { .. } => "unmount-volume",
            Self::UpdateIdleTimeout { .. } => "update-idle-timeout",
            Self::RunCode { .. } => "run-code",
        }
    }
}

/// Helper for `#[serde(default = "...")]` on `bool` fields where
/// `true` is the desired default (serde's `Default` trait yields
/// `false`).
fn default_true() -> bool {
    true
}

// ============================================================================
// Readiness model (plan 76 Phase 2)
// ============================================================================

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
/// Plan 76 Phase 4 fills in the full per-phase set. Phase 2 wires
/// `agent_started_ms`, `vsock_bound_ms`, `first_accept_ms`, and
/// `entrypoint_ready_ms` so callers can already display the cold-path
/// timing breakdown. Fields populated by Phase 4 (`warm_pool_ready_ms`,
/// `integrations_ready_ms`, `probes_ready_ms`) stay `None` for now.
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
    /// today; reserved for diverging if a future Phase 4 refactor
    /// splits "process started" from "socket created".
    pub vsock_bound_ms: Option<u64>,
    /// Milliseconds from agent start to the first accepted host
    /// connection. `None` until the first `accept()` returns.
    pub first_accept_ms: Option<u64>,
    /// Milliseconds from agent start to `entrypoint = Ready` (or
    /// `Failed`). `None` while still `Starting`.
    pub entrypoint_ready_ms: Option<u64>,
    /// Filled in by Phase 4. `None` for now.
    pub warm_pool_ready_ms: Option<u64>,
    /// Filled in by Phase 4. `None` for now.
    pub integrations_ready_ms: Option<u64>,
    /// Filled in by Phase 4. `None` for now.
    pub probes_ready_ms: Option<u64>,
}

/// Snapshot of agent readiness at the moment of a `ReadinessStatus`
/// call.
///
/// Plan 76 Phase 2 §"Early control-plane readiness". Used by host
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
    /// Volume-mount state — wire-stable placeholder. `Disabled` in
    /// v1 (mount/unmount are on-demand verbs, not boot state).
    pub volumes: ComponentState,
    /// Active agent profile. Same value the dispatcher uses for the
    /// `allowed_in` gate.
    pub profile: AgentProfile,
    /// Per-phase monotonic timings.
    pub boot_millis: BootTimingReport,
}

// ============================================================================
// Profile classifier (plan 76 Phase 1)
// ============================================================================

/// Coarse profile-eligibility class for each `GuestRequest` variant.
///
/// Wire types are compiled into every agent build; this classifier
/// is the dispatcher-side gate that rejects out-of-profile verbs
/// *before* the per-variant handler runs. See ADR-002 §W4.3 for the
/// complementary compile-time symbol-absence story (`do_exec`,
/// `do_run_code`, process RPC handlers gated by `dev-shell`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestClass {
    /// Allowed under `SealedProd` and `Dev` profiles. Includes the
    /// lifecycle, entrypoint-status, sleep/wake, mount-volume, and
    /// idle-timeout verbs. Sub-policies (mount path, idle timeout
    /// scope) are enforced inside the handler.
    ProdSafe,
    /// Allowed only under `Dev`. Process RPC, filesystem RPC, console,
    /// port forwarding, shell exec, code eval.
    DevOnly,
    /// Allowed only under `Builder`. No current `GuestRequest`
    /// variant is `BuilderOnly`; the variant is reserved for forward
    /// compatibility when builder-specific verbs land on the tenant
    /// wire.
    BuilderOnly,
}

impl GuestRequest {
    /// Stable string name for the verb, used in audit logs and the
    /// `UnsupportedInProfile` rejection response. Wire-stable —
    /// renaming a verb is a breaking change.
    pub fn verb_name(&self) -> &'static str {
        match self {
            GuestRequest::ProtocolHello { .. } => "ProtocolHello",
            GuestRequest::WorkerStatus => "WorkerStatus",
            GuestRequest::SleepPrep { .. } => "SleepPrep",
            GuestRequest::Wake => "Wake",
            GuestRequest::Ping => "Ping",
            GuestRequest::IntegrationStatus => "IntegrationStatus",
            GuestRequest::CheckpointIntegrations { .. } => "CheckpointIntegrations",
            GuestRequest::ProbeStatus => "ProbeStatus",
            GuestRequest::Exec { .. } => "Exec",
            GuestRequest::RunEntrypoint { .. } => "RunEntrypoint",
            GuestRequest::PostRestore => "PostRestore",
            GuestRequest::FsDiff => "FsDiff",
            GuestRequest::StartPortForward { .. } => "StartPortForward",
            GuestRequest::ConsoleOpen { .. } => "ConsoleOpen",
            GuestRequest::ConsoleClose { .. } => "ConsoleClose",
            GuestRequest::ConsoleResize { .. } => "ConsoleResize",
            GuestRequest::EntrypointStatus => "EntrypointStatus",
            GuestRequest::ReadinessStatus => "ReadinessStatus",
            GuestRequest::FsRead { .. } => "FsRead",
            GuestRequest::FsWrite { .. } => "FsWrite",
            GuestRequest::FsList { .. } => "FsList",
            GuestRequest::FsStat { .. } => "FsStat",
            GuestRequest::FsMkdir { .. } => "FsMkdir",
            GuestRequest::FsRemove { .. } => "FsRemove",
            GuestRequest::FsMove { .. } => "FsMove",
            GuestRequest::ProcStart { .. } => "ProcStart",
            GuestRequest::ProcList => "ProcList",
            GuestRequest::ProcSignal { .. } => "ProcSignal",
            GuestRequest::ProcSendInput { .. } => "ProcSendInput",
            GuestRequest::ProcWait { .. } => "ProcWait",
            GuestRequest::ProcKill { .. } => "ProcKill",
            GuestRequest::MountVolume { .. } => "MountVolume",
            GuestRequest::UnmountVolume { .. } => "UnmountVolume",
            GuestRequest::UpdateIdleTimeout { .. } => "UpdateIdleTimeout",
            GuestRequest::RunCode { .. } => "RunCode",
        }
    }

    /// Profile class of this request. Exhaustive match — adding a new
    /// `GuestRequest` variant fails to compile until it is classified.
    pub fn class(&self) -> RequestClass {
        match self {
            // ProdSafe: handshake + lifecycle + status + entrypoint
            // + sleep/wake + mount-volume + idle-timeout. Volume
            // mounts are additionally constrained by
            // `MountPathPolicy` inside the handler — the gate just
            // lets the verb reach it. `ProtocolHello` MUST be
            // prod-safe; it's the negotiation that runs before
            // every other request and a sealed-prod agent that
            // refuses it would never see another verb.
            GuestRequest::ProtocolHello { .. }
            | GuestRequest::WorkerStatus
            | GuestRequest::SleepPrep { .. }
            | GuestRequest::Wake
            | GuestRequest::Ping
            | GuestRequest::IntegrationStatus
            | GuestRequest::CheckpointIntegrations { .. }
            | GuestRequest::ProbeStatus
            | GuestRequest::RunEntrypoint { .. }
            | GuestRequest::PostRestore
            | GuestRequest::EntrypointStatus
            | GuestRequest::ReadinessStatus
            | GuestRequest::MountVolume { .. }
            | GuestRequest::UnmountVolume { .. }
            | GuestRequest::UpdateIdleTimeout { .. } => RequestClass::ProdSafe,

            // DevOnly: shell exec, process RPC, filesystem RPC,
            // console, port forwarding, code eval, filesystem diff.
            // Filesystem reads look benign but can leak secrets and
            // mounted-volume contents (plan 76 "Read-only filesystem
            // access can leak secrets"), so the entire filesystem
            // RPC surface is DevOnly in v1.
            GuestRequest::Exec { .. }
            | GuestRequest::FsDiff
            | GuestRequest::StartPortForward { .. }
            | GuestRequest::ConsoleOpen { .. }
            | GuestRequest::ConsoleClose { .. }
            | GuestRequest::ConsoleResize { .. }
            | GuestRequest::FsRead { .. }
            | GuestRequest::FsWrite { .. }
            | GuestRequest::FsList { .. }
            | GuestRequest::FsStat { .. }
            | GuestRequest::FsMkdir { .. }
            | GuestRequest::FsRemove { .. }
            | GuestRequest::FsMove { .. }
            | GuestRequest::ProcStart { .. }
            | GuestRequest::ProcList
            | GuestRequest::ProcSignal { .. }
            | GuestRequest::ProcSendInput { .. }
            | GuestRequest::ProcWait { .. }
            | GuestRequest::ProcKill { .. }
            | GuestRequest::RunCode { .. } => RequestClass::DevOnly,
        }
    }

    /// Whether this request is allowed under `profile`.
    ///
    /// Profile rules:
    /// - `SealedProd` allows only `ProdSafe`.
    /// - `Dev` allows `ProdSafe` and `DevOnly` (a superset).
    /// - `Builder` allows only `BuilderOnly` — today the builder
    ///   agent speaks `HostVmRequest`, so `GuestRequest` reaching
    ///   a `Builder`-profile agent is a configuration error.
    pub fn allowed_in(&self, profile: AgentProfile) -> bool {
        matches!(
            (self.class(), profile),
            (
                RequestClass::ProdSafe,
                AgentProfile::SealedProd | AgentProfile::Dev
            ) | (RequestClass::DevOnly, AgentProfile::Dev)
                | (RequestClass::BuilderOnly, AgentProfile::Builder)
        )
    }
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
    /// Guest-agent protocol negotiation succeeded. ADR-053 / plan 74 W1.
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
    /// Error from guest agent.
    Error { message: String },
    /// The dispatcher refused this verb because the active
    /// `AgentProfile` does not allow it (plan 76 Phase 1). Distinct
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
    /// One event in the response stream of a `RunEntrypoint` call.
    /// ADR-007 / plan 41 W1.
    ///
    /// The agent emits a sequence of these in response to a single
    /// `RunEntrypoint` request, terminated by an `EntrypointEvent`
    /// whose `is_terminal` returns true (`Exit` or `Error`). The
    /// host reads frames in a loop until terminal.
    EntrypointEvent(EntrypointEvent),
    /// One event in the streaming response of an `Exec` call (dev-shell
    /// only). Terminated by `ExecEvent::Exit`. Plan 159 WS-5 E.
    ExecEvent(ExecEvent),
    /// Post-restore acknowledgement.
    PostRestoreAck {
        success: bool,
        detail: Option<String>,
    },
    /// Filesystem diff result.
    FsDiffResult { changes: Vec<FsChange> },
    /// Port forward started successfully.
    PortForwardStarted { guest_port: u16, vsock_port: u32 },
    /// Console PTY session opened. Connect to `data_port` for raw I/O.
    ConsoleOpened { session_id: u32, data_port: u32 },
    /// Console PTY session ended (shell exited).
    ConsoleExited { session_id: u32, exit_code: i32 },
    /// Console resize acknowledged.
    ConsoleResized { session_id: u32 },
    /// Result of an `EntrypointStatus` query. ADR-007 / plan 41 W5.
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

    /// Result of a `ReadinessStatus` query. Plan 76 Phase 2.
    /// Snapshot of every component plus per-phase timings.
    ReadinessStatusReport(ReadinessReport),

    /// Result of a filesystem RPC call. The single top-level variant
    /// keeps `GuestResponse` from sprawling — the `FsResult` sub-enum
    /// carries the per-verb shapes. W1 / A1.
    FsResult(FsResult),

    /// Result of a non-streaming process-control verb (`ProcStart`,
    /// `ProcList`, `ProcSignal`, `ProcSendInput`, `ProcKill`). W1 / A2.
    ProcResult(ProcResult),

    /// One event in the streaming response of a `ProcWait` call.
    /// Mirrors the `EntrypointEvent` shape — the agent emits
    /// `Stdout`/`Stderr` chunks (capped per chunk by the wire frame
    /// limit) terminated by exactly one of `Exit` / `Killed` /
    /// `TimedOut` / `Error`.
    ProcWaitEvent(ProcWaitEvent),

    /// Result of a `MountVolume` / `UnmountVolume` call. Single-frame
    /// surface; closed sub-enum carries the per-verb shape.
    /// (Renamed from `ShareResult` per plan 45 §D5.)
    VolumeMountResult(VolumeMountResult),

    /// Acknowledgement for `UpdateIdleTimeout`. `applied_secs` is the
    /// value the agent is now enforcing — `0` means the warm-process
    /// pool isn't active on this guest (cold-path-only build), so
    /// the host reaper is the only enforcement.
    UpdateIdleTimeoutAck {
        previous_secs: u64,
        applied_secs: u64,
    },
}

/// Guest-agent control protocol capability. Closed enum so host and
/// guest fail loudly on drift instead of accepting arbitrary strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum GuestCapability {
    Ping,
    IntegrationStatus,
    EntrypointStatus,
    RunEntrypoint,
    FilesystemRpc,
    ProcessRpc,
    Console,
    VolumeMount,
    UpdateIdleTimeout,
    /// Plan 76 Phase 2 — `ReadinessStatus` returns
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
        GuestCapability::IntegrationStatus,
        GuestCapability::EntrypointStatus,
        GuestCapability::RunEntrypoint,
        GuestCapability::FilesystemRpc,
        GuestCapability::ProcessRpc,
        GuestCapability::Console,
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
/// (Renamed from `ShareResult` per plan 45 §D5.)
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
/// (Renamed from `ShareErrorKind` per plan 45 §D5.)
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

/// Result of a non-streaming process-control verb. Closed enum with
/// `deny_unknown_fields` so a compromised agent can't smuggle extra
/// fields past the host's deserializer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ProcResult {
    /// `ProcStart` succeeded — `pid_token` is the opaque handle the
    /// host uses for the rest of the process's lifetime.
    Started { pid_token: String },
    /// `ProcList` snapshot. Order is agent-defined (typically by
    /// `started_at`).
    List { processes: Vec<ProcInfo> },
    /// `ProcSignal` delivered.
    Signaled,
    /// `ProcSendInput` accepted some/all of the bytes.
    /// `bytes_accepted` may be less than the request's `bytes.len()`
    /// if the per-process input ring buffer would overflow.
    InputAccepted { bytes_accepted: u64 },
    /// `ProcKill` issued SIGKILL.
    Killed,
    /// Verb-specific error. Distinct from `GuestResponse::Error`,
    /// which is reserved for transport-layer failures.
    Error {
        kind: ProcErrorKind,
        message: String,
    },
}

/// Per-process metadata returned by `ProcList`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProcInfo {
    pub pid_token: String,
    /// RFC 3339 timestamp.
    pub started_at: String,
    /// argv\[0\] for display only — the agent does not expose the
    /// full argv over the wire (it could echo secrets the caller
    /// passed in via env / stdin).
    pub argv0: String,
    pub state: ProcState,
}

/// Lifecycle state of a tracked process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ProcState {
    Running,
    Exited(i32),
    /// Process was killed by signal `i32`.
    Killed(i32),
    /// Process exceeded its `timeout_secs`; agent killed the pgroup.
    TimedOut,
}

/// Class of error returned in `ProcResult::Error` and
/// `ProcWaitEvent::Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ProcErrorKind {
    /// `pid_token` doesn't match any known process. Either the
    /// host fabricated it or the agent reaped the process record.
    UnknownToken,
    /// The agent failed to spawn the child (executable missing,
    /// EACCES, ENOMEM, etc.).
    SpawnFailed,
    /// Per-child seccomp / setpriv envelope failed to apply.
    /// Agent refuses to spawn an un-confined child.
    SecurityEnvelopeFailed,
    /// argv was empty, argv\[0\] was empty / not absolute / on a
    /// disallowed path.
    InvalidArgv,
    /// One or more env keys / values failed validation (charset,
    /// length).
    InvalidEnv,
    /// `cwd` failed canonicalization or hit the deny-list.
    BadCwd,
    /// Per-VM concurrent-process cap or per-call byte cap
    /// exceeded.
    CapExceeded,
    /// Returned by prod builds whose handler module was stripped
    /// per ADR-002 §W4.3. Lets SDK callers branch on capability.
    UnsupportedInProduction,
    /// Other / unclassified.
    Other,
}

/// One event in the streaming response of a `ProcWait` call.
/// Terminal events end the stream — the host loops on
/// `is_terminal()` just like for `EntrypointEvent`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ProcWaitEvent {
    /// Bytes from the process's stdout.
    Stdout { chunk: Vec<u8> },
    /// Bytes from the process's stderr.
    Stderr { chunk: Vec<u8> },
    /// Process exited with the given code. Terminal.
    Exit { code: i32 },
    /// Process was killed by signal. Terminal.
    Killed { signal: i32 },
    /// `timeout_secs` elapsed; agent killed the process group.
    /// Terminal.
    TimedOut,
    /// Agent-side condition prevented the wait (unknown token,
    /// internal failure, prod-stripped). Terminal.
    Error {
        kind: ProcErrorKind,
        message: String,
    },
    /// A streaming resource is throttled (ADR-053 §5 / plan 74 W4).
    /// **Non-terminal.** The agent emits this on the rising edge of
    /// a backpressure condition — typically the host-side stdout/
    /// stderr buffer crossing its high-water mark. The wait loop
    /// continues; subsequent `Stdout` / `Stderr` / terminal events
    /// signal that flow has resumed.
    ///
    /// `detail` is a bounded, redacted human-readable hint
    /// (operator-facing). It **never** carries argv, env, stdin,
    /// stdout, stderr, or filesystem paths — see ADR-053's payload
    /// invariant.
    Backpressure {
        reason: mvm_core::domain::instance::BackpressureReason,
        detail: String,
    },
}

impl ProcWaitEvent {
    /// Returns true if this event terminates the response stream
    /// for one `ProcWait` call. `Backpressure` is non-terminal —
    /// the wait loop continues after the agent emits it.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ProcWaitEvent::Exit { .. }
                | ProcWaitEvent::Killed { .. }
                | ProcWaitEvent::TimedOut
                | ProcWaitEvent::Error { .. }
        )
    }
}

/// Result of a filesystem RPC call. Closed enum with
/// `deny_unknown_fields` so a compromised agent can't smuggle extra
/// data past the host's deserializer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum FsResult {
    /// Bytes read. `total_size` is the on-disk size at read time so
    /// callers can detect short reads even when `content.len() <
    /// requested length`.
    Read { content: Vec<u8>, total_size: u64 },
    /// Bytes successfully written.
    Write { bytes_written: u64 },
    /// Directory listing. `truncated` is `true` when the entry count
    /// exceeded the agent's per-call cap.
    List {
        entries: Vec<FsEntry>,
        truncated: bool,
    },
    /// File / directory metadata.
    Stat(FsStat),
    /// Directory created (no payload).
    Mkdir,
    /// Removed `entries_removed` filesystem entries (1 for a single
    /// file/dir, more under `recursive=true`).
    Remove { entries_removed: u64 },
    /// Move / rename completed.
    Move,
    /// Verb-specific error. Distinct from `GuestResponse::Error`,
    /// which is reserved for transport-layer failures the agent
    /// can't attribute to a specific verb.
    Error { kind: FsErrorKind, message: String },
}

/// One entry in an `FsList` response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsEntry {
    /// Bare entry name (no leading directory component).
    pub name: String,
    /// File type. `Other` covers sockets, FIFOs, devices.
    pub kind: FsEntryKind,
    /// Size in bytes, or `0` for non-files.
    pub size: u64,
}

/// Type of a filesystem entry returned by `FsList` / `FsStat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum FsEntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

/// Stat metadata for a single filesystem entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsStat {
    /// Canonical (post-`realpath`) path the agent operated on. Lets
    /// the host detect when a symlink resolution surprised it.
    pub canonical_path: String,
    pub kind: FsEntryKind,
    pub size: u64,
    /// Unix mode bits (e.g. `0o100644`). Always present; on backends
    /// without a unix mode the agent reports a best-effort
    /// equivalent.
    pub mode: u32,
    /// Modification timestamp as RFC 3339, or `None` if the
    /// underlying fs doesn't expose mtime.
    pub mtime: Option<String>,
}

/// Class of error returned in `FsResult::Error`. Closed enum so the
/// host can branch on `kind` without parsing message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum FsErrorKind {
    /// Path was rejected by the agent's policy (deny-list,
    /// canonicalization failed, symlink crossed the deny-list).
    PolicyDenied,
    /// Path doesn't exist.
    NotFound,
    /// Caller does not have permission for this op (uid 901 EPERM).
    PermissionDenied,
    /// Target already exists where the verb required absence.
    AlreadyExists,
    /// Size / count cap exceeded (e.g. `length > 16 MiB`,
    /// `recursive` walk would exceed cap).
    CapExceeded,
    /// Tried to rename across filesystems (`EXDEV`).
    CrossDevice,
    /// `recursive=false` on a non-empty directory.
    DirectoryNotEmpty,
    /// Underlying I/O error (look at `message` for detail).
    IoError,
    /// Path canonicalization succeeded but produced a path the agent
    /// refuses to operate on (e.g. `/proc/self`).
    BadPath,
    /// Other / unclassified.
    Other,
}

/// A single filesystem change detected since boot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FsChange {
    /// Path relative to the filesystem root.
    pub path: String,
    /// Type of change.
    pub kind: FsChangeKind,
    /// File size in bytes (0 for deleted files).
    pub size: u64,
}

/// Kind of filesystem change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum FsChangeKind {
    Created,
    Modified,
    Deleted,
}

/// One event in the streaming response of a `RunEntrypoint` call.
/// ADR-007 / plan 41 W1.
///
/// `Stdout` / `Stderr` carry bytes from the wrapper's respective
/// streams. `Exit` and `Error` are terminal — they end the response
/// stream for one call. The agent emits exactly one terminal event
/// per call.
///
/// v1 buffers each stream fully before sending one `Stdout` and one
/// `Stderr` event (sizes bounded by agent caps). v2 may chunk
/// progressively without changing the type or the protocol shape:
/// the host already reads frames in a loop until terminal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum EntrypointEvent {
    /// Bytes from the wrapper's stdout.
    Stdout { chunk: Vec<u8> },
    /// Bytes from the wrapper's stderr.
    Stderr { chunk: Vec<u8> },
    /// One control-channel record from the wrapper's fd-3 (Plan-0010
    /// §B4 / phase 4 of the upstream-mvm coordination work in
    /// `specs/upstream-mvm-prompt.md`).
    ///
    /// fd-3 is a separate stream the wrapper writes structured
    /// records to — error envelopes, captured logs when capture is
    /// on, etc. — that user code cannot spoof by writing to stderr.
    /// stdout / stderr keep streaming user-visible bytes verbatim.
    ///
    /// The on-the-fd-3-wire frame format is:
    ///
    /// ```text
    ///   header_len:  u32 LE   (4 bytes; max 64 KiB)
    ///   header_json: bytes    (header_len bytes; UTF-8 JSON object)
    ///   payload_len: u32 LE   (4 bytes; max bounded by call caps)
    ///   payload:     bytes    (payload_len bytes; opaque)
    /// ```
    ///
    /// `header_json` is a JSON object with at minimum `{"kind": "<str>"}`.
    /// The agent re-emits the header as `header_json: String` and the
    /// payload bytes as `payload: Vec<u8>` — no agent-side parsing
    /// beyond the framing. The host (`mvmctl invoke` and downstream
    /// SDKs) decides what to do with each record kind.
    ///
    /// **Wiring status (phase 4a):** the variant ships ahead of any
    /// emitter. Agents at this version do not yet open fd-3 in the
    /// child or emit `Control` events; phase 4b lands fd-3 wiring in
    /// the cold path (`execute()`), phase 4c in the warm-process
    /// pool, and the wrapper templates flip from stderr-envelope to
    /// fd-3-envelope at the same time. Hosts that see a `Control`
    /// event must already know how to consume it, so this variant is
    /// added eagerly to keep host/guest deserializers in lockstep.
    Control {
        /// JSON-encoded record header (deserialized by the host into a
        /// kind-specific struct). Agent does not parse beyond UTF-8
        /// validation.
        header_json: String,
        /// Opaque per-record payload. Empty for envelope-style records;
        /// used for raw bytes on log-style records.
        payload: Vec<u8>,
    },
    /// Wrapper exited with the given code. Terminal.
    Exit { code: i32 },
    /// Agent-side condition that prevented or interrupted the
    /// call (cap breach, timeout, busy session, missing entrypoint,
    /// crashed wrapper, internal failure). Terminal.
    Error {
        kind: RunEntrypointError,
        message: String,
    },
}

impl EntrypointEvent {
    /// Returns true if this event terminates the response stream
    /// for one `RunEntrypoint` call.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            EntrypointEvent::Exit { .. } | EntrypointEvent::Error { .. }
        )
    }
}

/// One event in the response stream of an `Exec` call (dev-shell only).
/// The agent emits a sequence of these for a single `Exec` request,
/// terminated by `Exit`. The host reads frames in a loop until terminal.
/// Plan 159 WS-5 E.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ExecEvent {
    /// Bytes from the command's stdout, as they arrive.
    Stdout { chunk: Vec<u8> },
    /// Bytes from the command's stderr, as they arrive.
    Stderr { chunk: Vec<u8> },
    /// Command exited with this code. Terminal.
    Exit { code: i32 },
    /// `timeout_secs` elapsed; the agent killed the command's process
    /// group. Terminal. Mirrors `ProcWaitEvent::TimedOut`. The host maps
    /// this to exit code 124 (GNU `timeout(1)` convention) for user
    /// commands. Plan 173.
    TimedOut,
}

impl ExecEvent {
    /// True if this event terminates the `Exec` response stream.
    pub fn is_terminal(&self) -> bool {
        matches!(self, ExecEvent::Exit { .. } | ExecEvent::TimedOut)
    }
}

/// Kind of agent-side error reported via `EntrypointEvent::Error`.
/// ADR-007 / plan 41 W1.
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
    /// Another `RunEntrypoint` is in flight on this VM. M12: agents
    /// serialize per-VM; concurrency comes from pool growth.
    Busy,
    /// The wrapper process died unexpectedly (signal, OOM, etc.).
    WrapperCrashed,
    /// Entrypoint validation has not yet completed. Plan 76 Phase 2:
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

// ============================================================================
// Host-bound protocol (guest → host, reverse direction)
// ============================================================================

/// Port the host listens on for host-bound requests from gateway VMs.
pub const HOST_BOUND_PORT: u32 = 53;

/// Request FROM a guest VM (gateway) TO the host agent.
/// Used for wake-on-demand: the gateway VM asks the host to wake a worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum HostBoundRequest {
    /// Wake a sleeping instance.
    WakeInstance {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
    },
    /// Query current status of an instance.
    QueryInstanceStatus {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
    },
    /// Query host wall-clock time. Plan 37 Addendum B11.
    ///
    /// The guest agent calls this at boot (and after snapshot
    /// restore / wake) to set its own clock against host-trusted
    /// time. Without it, a guest with a broken clock could
    /// silently bypass TLS certificate-validity checks, JWT
    /// `exp` checks, and any `expires_at` field in plans /
    /// secrets / attestation reports.
    QueryHostTime,
}

/// Response from host agent to a guest VM's host-bound request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum HostBoundResponse {
    /// Result of a wake request.
    WakeResult {
        success: bool,
        detail: Option<String>,
    },
    /// Status of queried instance.
    InstanceStatus {
        status: String,
        guest_ip: Option<String>,
    },
    /// Host wall-clock time. Plan 37 Addendum B11. Reported as
    /// (unix_seconds, unix_nanos) so the response is
    /// representation-stable across host clock crates and
    /// language runtimes — the guest reconstructs the
    /// `chrono::DateTime<Utc>` (or platform equivalent) locally.
    /// `unix_nanos` is the sub-second component, in `[0, 1_000_000_000)`.
    HostTime { unix_seconds: i64, unix_nanos: u32 },
    /// Error from host agent.
    Error { message: String },
}

/// Read a single length-prefixed JSON frame from a stream.
/// Returns the deserialized value.
pub fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .with_context(|| "Failed to read frame length")?;
    let frame_len = u32::from_be_bytes(len_buf) as usize;

    if frame_len > MAX_FRAME_SIZE {
        bail!(
            "Frame too large: {} bytes (max {})",
            frame_len,
            MAX_FRAME_SIZE
        );
    }

    let mut buf = vec![0u8; frame_len];
    stream
        .read_exact(&mut buf)
        .with_context(|| "Failed to read frame body")?;

    serde_json::from_slice(&buf).with_context(|| "Failed to deserialize frame")
}

/// Write a single length-prefixed JSON frame to a stream.
pub fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let data = serde_json::to_vec(value).with_context(|| "Failed to serialize frame")?;
    let len = (data.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .with_context(|| "Failed to write frame length")?;
    stream
        .write_all(&data)
        .with_context(|| "Failed to write frame body")?;
    stream.flush()?;
    Ok(())
}

// ============================================================================
// Authenticated frame wrappers
// ============================================================================

/// Write an authenticated, Ed25519-signed frame to a stream.
///
/// Serializes `value` as JSON, signs it with the given key, wraps it in an
/// `AuthenticatedFrame` envelope, then writes it as a length-prefixed JSON frame.
pub fn write_authenticated_frame<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    signing_key: &SigningKey,
    signer_id: &str,
    session_id: &str,
    sequence: u64,
) -> Result<()> {
    let payload = serde_json::to_vec(value).with_context(|| "Failed to serialize inner payload")?;

    let signature = signing_key.sign(&payload);
    let signed = SignedPayload {
        payload,
        signature: signature.to_bytes().to_vec(),
        signer_id: signer_id.to_string(),
    };

    let frame = AuthenticatedFrame {
        version: PROTOCOL_VERSION_AUTHENTICATED,
        sig_alg: SIG_ALG_ED25519,
        session_id: session_id.to_string(),
        sequence,
        timestamp: chrono::Utc::now().to_rfc3339(),
        signed,
    };

    write_frame(stream, &frame)
}

/// Read an authenticated frame from a stream and verify its Ed25519 signature.
///
/// Reads a length-prefixed `AuthenticatedFrame`, verifies the signature against
/// the provided verifying key, checks session ID and sequence number, then
/// deserializes the inner payload as `T`.
pub fn read_authenticated_frame<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
    verifying_key: &VerifyingKey,
    expected_session_id: &str,
    expected_min_sequence: u64,
) -> Result<(T, u64)> {
    let frame: AuthenticatedFrame = read_frame(stream)?;
    verify_authenticated_frame(
        &frame,
        verifying_key,
        expected_session_id,
        expected_min_sequence,
    )
}

/// Verify an already-deserialized `AuthenticatedFrame` and extract its
/// inner payload.
///
/// Same checks as [`read_authenticated_frame`] minus the wire read:
/// version → session ID → sequence (replay) → 64-byte signature length
/// → Ed25519 signature over `signed.payload` → deserialize as `T`.
/// Each step short-circuits with `Err`; the inner deserializer is
/// reached only after the signature check passes, which is the
/// load-bearing property the fuzz harness exercises.
///
/// Public so `crates/mvm-guest/fuzz/fuzz_targets/fuzz_authed_path.rs`
/// can drive the verification path without a real `UnixStream`.
pub fn verify_authenticated_frame<T: serde::de::DeserializeOwned>(
    frame: &AuthenticatedFrame,
    verifying_key: &VerifyingKey,
    expected_session_id: &str,
    expected_min_sequence: u64,
) -> Result<(T, u64)> {
    if frame.version != PROTOCOL_VERSION_AUTHENTICATED {
        bail!(
            "Unexpected protocol version: {} (expected {})",
            frame.version,
            PROTOCOL_VERSION_AUTHENTICATED
        );
    }

    if frame.session_id != expected_session_id {
        bail!(
            "Session ID mismatch: got '{}', expected '{}'",
            frame.session_id,
            expected_session_id
        );
    }

    if frame.sequence < expected_min_sequence {
        bail!(
            "Replay detected: sequence {} < expected minimum {}",
            frame.sequence,
            expected_min_sequence
        );
    }

    let signed = &frame.signed;
    if signed.signature.len() != 64 {
        bail!(
            "Invalid signature length: {} (expected 64)",
            signed.signature.len()
        );
    }

    let sig_bytes: [u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .with_context(|| "Signature must be exactly 64 bytes")?;

    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(&signed.payload, &signature)
        .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))?;

    let value: T = serde_json::from_slice(&signed.payload)
        .with_context(|| "Failed to deserialize verified payload")?;

    Ok((value, frame.sequence))
}

/// Perform the host side of the session handshake.
///
/// After CONNECT/OK, the host sends `SessionHello` with a random challenge
/// and its public key. The guest responds with `SessionHelloAck` containing
/// the signed challenge and its public key.
///
/// Returns the guest's verifying key on success.
pub fn handshake_as_host(
    stream: &mut UnixStream,
    session_id: &str,
    host_signing_key: &SigningKey,
) -> Result<VerifyingKey> {
    let _span = tracing::info_span!("vsock_handshake").entered();
    let t = std::time::Instant::now();
    let challenge: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let host_pubkey = host_signing_key.verifying_key().to_bytes().to_vec();

    let hello = SessionHello {
        version: PROTOCOL_VERSION_AUTHENTICATED,
        session_id: session_id.to_string(),
        challenge: challenge.clone(),
        host_pubkey,
    };

    write_frame(stream, &hello)?;

    let ack: SessionHelloAck = read_frame(stream)?;

    // Verify session ID echoed back
    if ack.session_id != session_id {
        bail!(
            "Session ID mismatch in HelloAck: got '{}', expected '{}'",
            ack.session_id,
            session_id
        );
    }

    // Extract guest public key
    if ack.guest_pubkey.len() != 32 {
        bail!(
            "Invalid guest public key length: {} (expected 32)",
            ack.guest_pubkey.len()
        );
    }
    let guest_key_bytes: [u8; 32] = ack
        .guest_pubkey
        .as_slice()
        .try_into()
        .with_context(|| "Guest public key must be 32 bytes")?;

    let guest_verifying_key = VerifyingKey::from_bytes(&guest_key_bytes)
        .with_context(|| "Invalid guest Ed25519 public key")?;

    // Verify guest signed the challenge
    if ack.challenge_response.len() != 64 {
        bail!(
            "Invalid challenge response length: {} (expected 64)",
            ack.challenge_response.len()
        );
    }
    let sig_bytes: [u8; 64] = ack
        .challenge_response
        .as_slice()
        .try_into()
        .with_context(|| "Challenge response must be 64 bytes")?;

    let sig = Signature::from_bytes(&sig_bytes);
    guest_verifying_key
        .verify(&challenge, &sig)
        .map_err(|e| anyhow::anyhow!("Challenge verification failed: {}", e))?;

    mvm_core::observability::metrics::global()
        .vsock_handshake_rtt_ms
        .store(
            t.elapsed().as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

    Ok(guest_verifying_key)
}

/// Perform the guest side of the session handshake.
///
/// Reads `SessionHello` from the host, signs the challenge with the guest's
/// key, and sends back `SessionHelloAck`.
///
/// Returns the host's verifying key and session ID on success.
pub fn handshake_as_guest(
    stream: &mut UnixStream,
    guest_signing_key: &SigningKey,
) -> Result<(VerifyingKey, String)> {
    let hello: SessionHello = read_frame(stream)?;

    // Extract host public key
    if hello.host_pubkey.len() != 32 {
        bail!(
            "Invalid host public key length: {} (expected 32)",
            hello.host_pubkey.len()
        );
    }
    let host_key_bytes: [u8; 32] = hello
        .host_pubkey
        .as_slice()
        .try_into()
        .with_context(|| "Host public key must be 32 bytes")?;

    let host_verifying_key = VerifyingKey::from_bytes(&host_key_bytes)
        .with_context(|| "Invalid host Ed25519 public key")?;

    // Sign the challenge to prove we hold the session key
    let challenge_sig = guest_signing_key.sign(&hello.challenge);
    let guest_pubkey = guest_signing_key.verifying_key().to_bytes().to_vec();

    let ack = SessionHelloAck {
        version: hello.version,
        session_id: hello.session_id.clone(),
        challenge_response: challenge_sig.to_bytes().to_vec(),
        guest_pubkey,
    };

    write_frame(stream, &ack)?;

    Ok((host_verifying_key, hello.session_id))
}

// ============================================================================
// Vsock UDS connection
// ============================================================================

/// Path to the Firecracker vsock UDS for an instance.
pub fn vsock_uds_path(instance_dir: &str) -> String {
    format!("{}/runtime/v.sock", instance_dir)
}

/// Check if an IO error is a timeout (EAGAIN/EWOULDBLOCK or TimedOut).
fn is_timeout_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Single attempt to connect and perform the Firecracker CONNECT handshake.
fn try_connect_once(uds_path: &str, port: u32, timeout_secs: u64) -> Result<UnixStream> {
    let timeout = Duration::from_secs(timeout_secs);

    // Pre-flight: verify the socket file exists and is actually a socket.
    match std::fs::symlink_metadata(uds_path) {
        Err(e) => bail!("Vsock socket not found at {}: {}", uds_path, e),
        Ok(m) if !m.file_type().is_socket() => {
            bail!(
                "Path {} exists but is not a socket (type: {:?})",
                uds_path,
                m.file_type()
            )
        }
        Ok(_) => {}
    }

    let stream = UnixStream::connect(uds_path)
        .with_context(|| format!("Failed to connect to vsock UDS at {}", uds_path))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut stream = stream;
    writeln!(stream, "CONNECT {}", port).with_context(|| "Failed to send CONNECT")?;
    stream.flush()?;

    // Read response line: "OK <port>\n"
    let mut reader = BufReader::new(&stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).map_err(|e| {
        if is_timeout_error(&e) {
            anyhow::anyhow!(
                "Guest agent did not respond within {}s \
                 (the agent may not be running or the microVM may be unhealthy)",
                timeout_secs
            )
        } else {
            anyhow::anyhow!("Failed to read CONNECT response: {}", e)
        }
    })?;

    if !response_line.starts_with("OK ") {
        bail!(
            "Vsock CONNECT failed: expected 'OK {}', got '{}'",
            GUEST_AGENT_PORT,
            response_line.trim()
        );
    }

    Ok(stream)
}

/// Connect to a specific vsock port via the Firecracker UDS multiplexer.
///
/// The Firecracker vsock device exposes a single host-side UDS for
/// host→guest connections; the destination port is selected by the
/// `CONNECT <port>\n` handshake line, not by the UDS path. This entry
/// point lets the caller pick that port — needed for things like the
/// console data port, which is allocated by the agent at runtime.
///
/// Connect protocol:
/// 1. Open Unix stream to the given UDS path.
/// 2. Write `CONNECT <port>\n`.
/// 3. Read `OK <port>\n`.
/// 4. Then exchange length-prefixed JSON frames.
///
/// Retries up to [`CONNECT_RETRIES`] times on timeout errors, skipping retries
/// for definitive failures (connection refused, socket not found).
pub fn connect_to_port(uds_path: &str, port: u32, timeout_secs: u64) -> Result<UnixStream> {
    let mut last_err = None;

    for attempt in 1..=CONNECT_RETRIES {
        match try_connect_once(uds_path, port, timeout_secs) {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                let is_timeout = e.to_string().contains("did not respond within");

                // Don't retry definitive failures (VM not running at all)
                if !is_timeout {
                    return Err(e);
                }

                last_err = Some(e);

                if attempt < CONNECT_RETRIES {
                    std::thread::sleep(Duration::from_millis(CONNECT_RETRY_DELAY_MS));
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        anyhow::anyhow!(
            "Failed to connect to guest agent on port {} after {} attempts",
            port,
            CONNECT_RETRIES
        )
    }))
}

/// Connect to the guest agent control port ([`GUEST_AGENT_PORT`]) via
/// a direct UDS path. Backward-compatible thin wrapper over
/// [`connect_to_port`] that all existing callers (control-plane RPCs,
/// health probes, integration queries) target.
pub fn connect_to(uds_path: &str, timeout_secs: u64) -> Result<UnixStream> {
    connect_to_port(uds_path, GUEST_AGENT_PORT, timeout_secs)
}

/// The vsock CID of the host, from the guest's perspective (`VMADDR_CID_HOST`).
pub const HOST_CID: u32 = 2;

/// Open a **guest→host** vsock stream to the host on `port` (AF_VSOCK to
/// [`HOST_CID`]). This is the direction the substitution forward proxy needs —
/// the opposite of [`connect_to_port`], which is the host→guest Firecracker
/// UDS-multiplexer path. Backend-agnostic on the guest side: both QEMU
/// (`vhost-vsock`) and Firecracker forward a guest AF_VSOCK connect to CID 2 to
/// the host's listener (real AF_VSOCK for QEMU, a per-port UDS for Firecracker).
///
/// The returned fd is a `SOCK_STREAM` socket wrapped as a [`UnixStream`] — a
/// thin SOCK_STREAM wrapper whose read/write are the same syscalls — so the
/// length-prefixed frame helpers ([`read_frame`]/[`write_frame`]) work over it
/// unchanged.
pub fn connect_host_vsock(port: u32, timeout_secs: u64) -> Result<UnixStream> {
    use std::os::fd::FromRawFd;

    const AF_VSOCK: libc::c_int = 40;
    // Kernel uapi `struct sockaddr_vm`: family u16 + reserved u16 + port u32 +
    // cid u32 + 4-byte pad = 16 (== sizeof(struct sockaddr)).
    #[repr(C)]
    struct SockaddrVm {
        svm_family: libc::sa_family_t,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }
    const _: () = assert!(std::mem::size_of::<SockaddrVm>() == 16);

    // SAFETY: standard socket(2)/connect(2) on AF_VSOCK; `addr` is fully
    // initialized and sized exactly. The fd is adopted by `UnixStream` on
    // success (closed on its drop) or closed explicitly on the error paths.
    let stream = unsafe {
        let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(
                anyhow::Error::from(std::io::Error::last_os_error()).context("AF_VSOCK socket()")
            );
        }
        let addr = SockaddrVm {
            svm_family: AF_VSOCK as libc::sa_family_t,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: HOST_CID,
            svm_zero: [0; 4],
        };
        let rc = libc::connect(
            fd,
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
        );
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(anyhow::Error::from(err).context(format!(
                "AF_VSOCK connect to host CID {HOST_CID} port {port}"
            )));
        }
        UnixStream::from_raw_fd(fd)
    };
    let timeout = Duration::from_secs(timeout_secs);
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    Ok(stream)
}

/// Connect to the guest vsock agent via the fleet-mode instance directory convention.
///
/// Resolves the UDS path as `<instance_dir>/runtime/v.sock`.
fn connect(instance_dir: &str, timeout_secs: u64) -> Result<UnixStream> {
    connect_to(&vsock_uds_path(instance_dir), timeout_secs)
}

/// Send a request and receive a response over a vsock connection.
///
/// Uses 4-byte big-endian length prefix + JSON body (same pattern as hostd).
pub fn send_request(stream: &mut UnixStream, req: &GuestRequest) -> Result<GuestResponse> {
    let data = serde_json::to_vec(req).with_context(|| "Failed to serialize request")?;

    // Write length-prefixed frame
    let len = (data.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .with_context(|| "Failed to write frame length")?;
    stream
        .write_all(&data)
        .with_context(|| "Failed to write frame body")?;
    stream.flush()?;

    // Read response length
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| {
        if is_timeout_error(&e) {
            anyhow::anyhow!("Guest agent timed out while waiting for response")
        } else {
            anyhow::anyhow!("Failed to read response length: {}", e)
        }
    })?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    if resp_len > MAX_FRAME_SIZE {
        bail!(
            "Response frame too large: {} bytes (max {})",
            resp_len,
            MAX_FRAME_SIZE
        );
    }

    // Read response body
    let mut buf = vec![0u8; resp_len];
    stream.read_exact(&mut buf).map_err(|e| {
        if is_timeout_error(&e) {
            anyhow::anyhow!("Guest agent timed out while reading response body")
        } else {
            anyhow::anyhow!("Failed to read response body: {}", e)
        }
    })?;

    serde_json::from_slice(&buf).with_context(|| "Failed to deserialize response")
}

/// Negotiate guest-agent protocol version and capabilities on an
/// already-connected control stream.
///
/// This helper is intentionally stream-level so it works with both the
/// Firecracker UDS multiplexer path and Apple Container's direct vsock
/// stream. Hard cutover (ADR-053 / plan 74 W1): every fresh session
/// must call this before issuing any operational request, including a
/// bare `Ping` reachability probe. Pre-hello guest agents receive
/// `ProtocolMismatch` and the connection is closed; this helper
/// surfaces that as an error so callers can prompt the user to
/// rebuild their dev VM.
pub fn negotiate_protocol(
    stream: &mut UnixStream,
    requested_capabilities: Vec<GuestCapability>,
) -> Result<ProtocolNegotiation> {
    let resp = send_request(
        stream,
        &GuestRequest::ProtocolHello {
            host_protocol_version: PROTOCOL_VERSION,
            min_supported_version: MIN_SUPPORTED_PROTOCOL_VERSION,
            host_version: env!("CARGO_PKG_VERSION").to_string(),
            requested_capabilities,
        },
    )?;

    match resp {
        GuestResponse::ProtocolHelloAck {
            agent_protocol_version,
            min_supported_version,
            agent_version,
            capabilities,
        } => Ok(ProtocolNegotiation {
            agent_protocol_version,
            min_supported_version,
            agent_version,
            capabilities,
        }),
        GuestResponse::ProtocolMismatch {
            required_action,
            message,
            ..
        } => bail!("guest-agent protocol mismatch ({required_action:?}): {message}"),
        GuestResponse::Error { message } => {
            bail!("guest-agent protocol negotiation error: {message}")
        }
        other => bail!("unexpected response to ProtocolHello: {other:?}"),
    }
}

/// Negotiate the guest-agent protocol and fail if any mandatory
/// capability is missing.
pub fn require_capabilities(
    stream: &mut UnixStream,
    required_capabilities: &[GuestCapability],
) -> Result<ProtocolNegotiation> {
    let negotiated = negotiate_protocol(stream, required_capabilities.to_vec())?;
    let missing: Vec<_> = required_capabilities
        .iter()
        .copied()
        .filter(|cap| !negotiated.capabilities.contains(cap))
        .collect();

    if !missing.is_empty() {
        bail!("guest-agent missing required capabilities: {missing:?}");
    }

    Ok(negotiated)
}

/// Send a `RunEntrypoint` request and consume the streaming
/// `EntrypointEvent` response. ADR-007 / plan 41 W3.
///
/// `on_event` is invoked for each non-terminal event (`Stdout` /
/// `Stderr` chunk) as it arrives — callers can stream output to their
/// own stdout/stderr without buffering. Returns the terminal event
/// (`Exit` or `Error`) for the caller to inspect.
///
/// The wire format is the same length-prefixed JSON envelope as every
/// other vsock verb. v1 emits exactly three frames per call: one
/// `Stdout`, one `Stderr`, and one terminal event. v2 may chunk
/// progressively without changing this consumer — termination is
/// detected via [`EntrypointEvent::is_terminal`], not frame count.
pub fn send_run_entrypoint<F>(
    stream: &mut UnixStream,
    stdin: Vec<u8>,
    timeout_secs: u64,
    env: Vec<(String, String)>,
    mut on_event: F,
) -> Result<EntrypointEvent>
where
    F: FnMut(&EntrypointEvent),
{
    require_capabilities(stream, &[GuestCapability::RunEntrypoint])?;
    let req = GuestRequest::RunEntrypoint {
        stdin,
        timeout_secs,
        env,
    };
    write_frame(stream, &req)?;

    loop {
        let resp: GuestResponse = read_frame(stream)?;
        let event = match resp {
            GuestResponse::EntrypointEvent(e) => e,
            GuestResponse::Error { message } => bail!("guest agent error: {message}"),
            other => bail!("expected EntrypointEvent during RunEntrypoint stream, got {other:?}"),
        };
        if event.is_terminal() {
            return Ok(event);
        }
        on_event(&event);
    }
}

/// Send an `Exec` request and stream its response. Invokes `on_event`
/// for each `Stdout`/`Stderr` chunk as it arrives; returns the terminal
/// `Exit` or `TimedOut`. Exec carries no `GuestCapability` — the agent
/// gates it at compile time via the `dev-shell` feature — so this does
/// a plain protocol hello (no capability requirement). Plan 159 WS-5 E.
pub fn send_exec_streaming<F>(
    stream: &mut UnixStream,
    command: &str,
    stdin: Option<String>,
    timeout_secs: Option<u64>,
    on_event: F,
) -> Result<ExecEvent>
where
    F: FnMut(&ExecEvent),
{
    let _ = negotiate_protocol(stream, Vec::new())?;
    let req = GuestRequest::Exec {
        command: command.to_string(),
        stdin,
        timeout_secs,
    };
    write_frame(stream, &req)?;
    read_exec_stream(stream, on_event)
}

/// Read an `ExecEvent` response stream from `stream`: invoke `on_event`
/// for each non-terminal chunk, return the terminal `Exit`. The caller
/// must have already done the protocol hello and written the request
/// frame (`Exec` or `RunCode` — both stream `ExecEvent`). Plan 159 WS-5 E.
pub fn read_exec_stream<F>(stream: &mut UnixStream, mut on_event: F) -> Result<ExecEvent>
where
    F: FnMut(&ExecEvent),
{
    loop {
        let resp: GuestResponse = read_frame(stream)?;
        let event = match resp {
            GuestResponse::ExecEvent(e) => e,
            GuestResponse::Error { message } => bail!("guest exec error: {message}"),
            other => bail!("expected ExecEvent during exec stream, got {other:?}"),
        };
        if event.is_terminal() {
            return Ok(event);
        }
        on_event(&event);
    }
}

// ============================================================================
// High-level API
// ============================================================================

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

// ============================================================================
// Direct-path API (for dev-mode VMs where v.sock is not under runtime/)
// ============================================================================

/// Ping the guest vsock agent at a specific UDS path.
pub fn ping_at(vsock_uds_path: &str) -> Result<bool> {
    let mut stream = connect_to(vsock_uds_path, DEFAULT_TIMEOUT_SECS)?;
    let resp = send_request(&mut stream, &GuestRequest::Ping)?;
    Ok(matches!(resp, GuestResponse::Pong))
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

/// Signal post-restore to the guest agent at a specific UDS path.
///
/// After snapshot restore, tells the guest to remount config/secrets drives
/// and restart services. Returns Ok(true) if the guest acknowledged success.
pub fn post_restore_at(vsock_uds_path: &str) -> Result<bool> {
    let mut stream = connect_to(vsock_uds_path, DEFAULT_TIMEOUT_SECS)?;
    let resp = send_request(&mut stream, &GuestRequest::PostRestore)?;

    match resp {
        GuestResponse::PostRestoreAck { success, .. } => Ok(success),
        GuestResponse::Error { message } => {
            bail!("Guest post-restore error: {}", message);
        }
        _ => bail!("Unexpected response to PostRestore"),
    }
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
/// `mvm::vsock_transport::for_vm(name)` so the verb works against any VMM
/// (Plan 169). `FsDiff` is part of the filesystem RPC surface, so this drives
/// the plan 74 W1 hello prelude requiring `FilesystemRpc` exactly like
/// [`send_fs_request_on`] — the dir-based wrappers used to skip the hello,
/// which a hard-cutover agent (ADR-053) would reject.
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
/// the host CLI obtains the stream from `mvm::vsock_transport::for_vm(name)`
/// so `mvmctl proc` works regardless of which VMM launched the VM
/// (Plan 169). `send_proc_request` is the dir-based wrapper over this.
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
/// `mvm::vsock_transport::for_vm(name)` so the verb works against any VMM
/// (Plan 169). Mirrors the host shape of [`send_run_entrypoint`].
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
    write_frame(stream, &req)?;
    loop {
        let resp: GuestResponse = read_frame(stream)?;
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
/// stream from `mvm::vsock_transport::for_vm(name)` (which resolves the
/// right socket per backend — Firecracker's `v.sock`, or the per-port UNIX
/// socket libkrun/QEMU expose), so `fs`/`cp` work regardless of which VMM
/// launched the VM (Plan 169). `send_fs_request` is the dir-based wrapper
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

/// Send a `StartPortForward` request on an already-connected stream.
///
/// Used by the Apple Container backend where the vsock connection is
/// established via `VZVirtioSocketDevice` rather than a UDS path.
///
/// Performs the ADR-053 / plan 74 W1 hello prelude internally so
/// callers don't have to. `StartPortForward` is not a capability-gated
/// operation, so an empty capability list is requested — the hello
/// alone satisfies the agent's "no operational request before hello"
/// rule.
pub fn start_port_forward_on(stream: &mut UnixStream, guest_port: u16) -> Result<u32> {
    let _ = negotiate_protocol(stream, Vec::new())?;
    let resp = send_request(stream, &GuestRequest::StartPortForward { guest_port })?;
    match resp {
        GuestResponse::PortForwardStarted { vsock_port, .. } => Ok(vsock_port),
        GuestResponse::Error { message } => {
            bail!("Guest port-forward error: {}", message);
        }
        _ => bail!("Unexpected response to StartPortForward"),
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_backoff_grows_then_caps_and_is_never_zero() {
        // Doubles from the 20ms base.
        assert_eq!(adaptive_backoff(0), Duration::from_millis(20));
        assert_eq!(adaptive_backoff(1), Duration::from_millis(40));
        assert_eq!(adaptive_backoff(2), Duration::from_millis(80));
        assert_eq!(adaptive_backoff(3), Duration::from_millis(160));
        assert_eq!(adaptive_backoff(4), Duration::from_millis(320));
        // Caps at the historical fixed interval and stays there.
        assert_eq!(adaptive_backoff(5), Duration::from_millis(500));
        assert_eq!(adaptive_backoff(6), Duration::from_millis(500));
        // Large attempt counts can't overflow or drop to zero.
        assert_eq!(adaptive_backoff(64), Duration::from_millis(500));
        assert_eq!(adaptive_backoff(u32::MAX), Duration::from_millis(500));
        // Never busy-spins.
        for a in 0..40 {
            assert!(adaptive_backoff(a) >= Duration::from_millis(ADAPTIVE_BACKOFF_BASE_MS));
        }
    }

    #[test]
    fn test_guest_request_roundtrip() {
        let variants: Vec<GuestRequest> = vec![
            GuestRequest::ProtocolHello {
                host_protocol_version: PROTOCOL_VERSION,
                min_supported_version: MIN_SUPPORTED_PROTOCOL_VERSION,
                host_version: "0.1.0".to_string(),
                requested_capabilities: vec![GuestCapability::Ping, GuestCapability::RunEntrypoint],
            },
            GuestRequest::WorkerStatus,
            GuestRequest::SleepPrep {
                drain_timeout_secs: 30,
            },
            GuestRequest::Wake,
            GuestRequest::Ping,
            GuestRequest::IntegrationStatus,
            GuestRequest::CheckpointIntegrations {
                integrations: vec!["whatsapp".to_string(), "telegram".to_string()],
            },
            GuestRequest::ProbeStatus,
            GuestRequest::Exec {
                command: "uname -a".to_string(),
                stdin: Some("hello".to_string()),
                timeout_secs: Some(10),
            },
            GuestRequest::PostRestore,
            GuestRequest::FsDiff,
            GuestRequest::StartPortForward { guest_port: 8080 },
            GuestRequest::ConsoleOpen {
                cols: 120,
                rows: 40,
            },
            GuestRequest::ConsoleClose { session_id: 1 },
            GuestRequest::ConsoleResize {
                session_id: 1,
                cols: 80,
                rows: 24,
            },
            GuestRequest::FsRead {
                path: "/data/file.txt".to_string(),
                offset: Some(1024),
                length: 4096,
                follow_symlinks: true,
            },
            GuestRequest::FsWrite {
                path: "/tmp/out.bin".to_string(),
                content: vec![0xde, 0xad, 0xbe, 0xef],
                mode: 0o644,
                create_parents: true,
                follow_symlinks: false,
            },
            GuestRequest::FsList {
                path: "/work".to_string(),
                follow_symlinks: true,
            },
            GuestRequest::FsStat {
                path: "/etc/hostname".to_string(),
                follow_symlinks: false,
            },
            GuestRequest::FsMkdir {
                path: "/work/new".to_string(),
                mode: 0o755,
                parents: true,
            },
            GuestRequest::FsRemove {
                path: "/tmp/scratch".to_string(),
                recursive: true,
                follow_symlinks: false,
            },
            GuestRequest::FsMove {
                from: "/tmp/a".to_string(),
                to: "/tmp/b".to_string(),
                follow_symlinks: false,
            },
            GuestRequest::ProcStart {
                argv: vec!["/usr/bin/echo".to_string(), "hello".to_string()],
                env: {
                    let mut m = std::collections::BTreeMap::new();
                    m.insert("LANG".to_string(), "C".to_string());
                    m
                },
                cwd: Some("/tmp".to_string()),
                stdin: vec![],
                timeout_secs: Some(30),
            },
            GuestRequest::ProcList,
            GuestRequest::ProcSignal {
                pid_token: "tok-abc".to_string(),
                signum: 15,
            },
            GuestRequest::ProcSendInput {
                pid_token: "tok-abc".to_string(),
                bytes: vec![1, 2, 3],
            },
            GuestRequest::ProcWait {
                pid_token: "tok-abc".to_string(),
                timeout_secs: Some(60),
            },
            GuestRequest::ProcKill {
                pid_token: "tok-abc".to_string(),
            },
            GuestRequest::MountVolume {
                volume_name: "data-volume".to_string(),
                guest_path: "/data/foo".to_string(),
                read_only: true,
            },
            GuestRequest::UnmountVolume {
                guest_path: "/data/foo".to_string(),
                force: false,
            },
            GuestRequest::UpdateIdleTimeout { secs: 600 },
            GuestRequest::UpdateIdleTimeout { secs: 0 },
            GuestRequest::RunCode {
                code: "print('hello')".into(),
                timeout_secs: Some(30),
            },
            GuestRequest::ReadinessStatus,
        ];

        for req in &variants {
            let json = serde_json::to_string(req).unwrap();
            let parsed: GuestRequest = serde_json::from_str(&json).unwrap();
            // Verify round-trip produces valid JSON
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
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
            GuestResponse::PortForwardStarted {
                guest_port: 8080,
                vsock_port: 18080,
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

    #[test]
    fn test_negotiate_protocol_round_trip_on_stream() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();

        let guest_thread = std::thread::spawn(move || {
            let req: GuestRequest = read_frame(&mut guest).unwrap();
            match req {
                GuestRequest::ProtocolHello {
                    host_protocol_version,
                    min_supported_version,
                    host_version,
                    requested_capabilities,
                } => {
                    let resp = protocol_hello_response(
                        host_protocol_version,
                        min_supported_version,
                        &host_version,
                        &requested_capabilities,
                    );
                    write_frame(&mut guest, &resp).unwrap();
                }
                other => panic!("expected ProtocolHello, got {other:?}"),
            }
        });

        let negotiated = negotiate_protocol(
            &mut host,
            vec![GuestCapability::Ping, GuestCapability::FilesystemRpc],
        )
        .unwrap();

        guest_thread.join().unwrap();
        assert_eq!(negotiated.agent_protocol_version, PROTOCOL_VERSION);
        assert_eq!(
            negotiated.capabilities,
            vec![GuestCapability::Ping, GuestCapability::FilesystemRpc]
        );
    }

    #[test]
    fn test_negotiate_protocol_mismatch_is_error() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();

        let guest_thread = std::thread::spawn(move || {
            let _req: GuestRequest = read_frame(&mut guest).unwrap();
            write_frame(
                &mut guest,
                &GuestResponse::ProtocolMismatch {
                    host_protocol_version: PROTOCOL_VERSION + 1,
                    agent_protocol_version: PROTOCOL_VERSION,
                    required_action: ProtocolUpgradeAction::RebuildGuest,
                    message: "rebuild guest image".to_string(),
                },
            )
            .unwrap();
        });

        let err = negotiate_protocol(&mut host, vec![GuestCapability::Ping]).unwrap_err();
        guest_thread.join().unwrap();
        assert!(err.to_string().contains("protocol mismatch"));
        assert!(err.to_string().contains("rebuild guest image"));
    }

    #[test]
    fn test_require_capabilities_accepts_present_capability() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();

        let guest_thread = std::thread::spawn(move || {
            let req: GuestRequest = read_frame(&mut guest).unwrap();
            match req {
                GuestRequest::ProtocolHello {
                    host_protocol_version,
                    min_supported_version,
                    host_version,
                    requested_capabilities,
                } => {
                    let resp = protocol_hello_response(
                        host_protocol_version,
                        min_supported_version,
                        &host_version,
                        &requested_capabilities,
                    );
                    write_frame(&mut guest, &resp).unwrap();
                }
                other => panic!("expected ProtocolHello, got {other:?}"),
            }
        });

        let negotiated =
            require_capabilities(&mut host, &[GuestCapability::FilesystemRpc]).unwrap();

        guest_thread.join().unwrap();
        assert_eq!(
            negotiated.capabilities,
            vec![GuestCapability::FilesystemRpc]
        );
    }

    #[test]
    fn test_require_capabilities_rejects_missing_capability() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();

        let guest_thread = std::thread::spawn(move || {
            let _req: GuestRequest = read_frame(&mut guest).unwrap();
            write_frame(
                &mut guest,
                &GuestResponse::ProtocolHelloAck {
                    agent_protocol_version: PROTOCOL_VERSION,
                    min_supported_version: MIN_SUPPORTED_PROTOCOL_VERSION,
                    agent_version: "0.1.0".to_string(),
                    capabilities: vec![GuestCapability::Ping],
                },
            )
            .unwrap();
        });

        let err = require_capabilities(&mut host, &[GuestCapability::FilesystemRpc]).unwrap_err();

        guest_thread.join().unwrap();
        assert!(err.to_string().contains("missing required capabilities"));
        assert!(err.to_string().contains("FilesystemRpc"));
    }

    #[test]
    fn test_require_capabilities_surfaces_protocol_mismatch() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();

        let guest_thread = std::thread::spawn(move || {
            let _req: GuestRequest = read_frame(&mut guest).unwrap();
            write_frame(
                &mut guest,
                &GuestResponse::ProtocolMismatch {
                    host_protocol_version: PROTOCOL_VERSION + 1,
                    agent_protocol_version: PROTOCOL_VERSION,
                    required_action: ProtocolUpgradeAction::RebuildGuest,
                    message: "guest image is stale".to_string(),
                },
            )
            .unwrap();
        });

        let err = require_capabilities(&mut host, &[GuestCapability::FilesystemRpc]).unwrap_err();

        guest_thread.join().unwrap();
        assert!(err.to_string().contains("protocol mismatch"));
        assert!(err.to_string().contains("guest image is stale"));
    }

    /// W4.1 + A1 regression: every new FS variant rejects unknown
    /// fields. Repeats the smuggling discipline from
    /// `test_guest_request_rejects_unknown_field_inside_variant` for
    /// each verb so a reviewer adding an FS field without the
    /// `#[serde(...)]` attributes can't ship a regression.
    #[test]
    fn test_fs_request_variants_reject_unknown_fields() {
        let cases = [
            r#"{"FsRead":{"path":"/x","length":1,"follow_symlinks":true,"smuggled":1}}"#,
            r#"{"FsWrite":{"path":"/x","content":[],"mode":420,"create_parents":false,"follow_symlinks":false,"smuggled":1}}"#,
            r#"{"FsList":{"path":"/x","follow_symlinks":true,"smuggled":1}}"#,
            r#"{"FsStat":{"path":"/x","follow_symlinks":true,"smuggled":1}}"#,
            r#"{"FsMkdir":{"path":"/x","mode":493,"parents":true,"smuggled":1}}"#,
            r#"{"FsRemove":{"path":"/x","recursive":false,"follow_symlinks":false,"smuggled":1}}"#,
            r#"{"FsMove":{"from":"/x","to":"/y","follow_symlinks":false,"smuggled":1}}"#,
        ];
        for json in cases {
            let err = serde_json::from_str::<GuestRequest>(json).unwrap_err();
            assert!(
                err.to_string().contains("unknown field"),
                "expected unknown-field rejection for {json}, got: {err}"
            );
        }
    }

    /// FS sub-types that don't live inside `GuestRequest` directly
    /// (`FsResult`, `FsEntry`, `FsStat`, `FsErrorKind`, `FsEntryKind`)
    /// also need the deny-unknown-fields discipline because they
    /// surface through `GuestResponse::FsResult(...)` on the host's
    /// deserializer. Cover each in turn.
    #[test]
    fn test_fs_response_subtypes_reject_unknown_fields() {
        let cases = [
            // FsResult variant smuggling.
            r#"{"FsResult":{"Read":{"content":[],"total_size":0,"smuggled":1}}}"#,
            r#"{"FsResult":{"Write":{"bytes_written":0,"smuggled":1}}}"#,
            r#"{"FsResult":{"List":{"entries":[],"truncated":false,"smuggled":1}}}"#,
            r#"{"FsResult":{"Remove":{"entries_removed":0,"smuggled":1}}}"#,
            r#"{"FsResult":{"Error":{"kind":"NotFound","message":"x","smuggled":1}}}"#,
            // FsStat field smuggling (transports inside FsResult::Stat).
            r#"{"FsResult":{"Stat":{"canonical_path":"/x","kind":"file","size":0,"mode":0,"mtime":null,"smuggled":1}}}"#,
            // FsEntry field smuggling (transports inside FsResult::List).
            r#"{"FsResult":{"List":{"entries":[{"name":"x","kind":"file","size":0,"smuggled":1}],"truncated":false}}}"#,
        ];
        for json in cases {
            let err = serde_json::from_str::<GuestResponse>(json).unwrap_err();
            assert!(
                err.to_string().contains("unknown field"),
                "expected unknown-field rejection for {json}, got: {err}"
            );
        }
    }

    /// W4.1 + A2 regression: every new Proc variant rejects unknown
    /// fields. Mirrors `test_fs_request_variants_reject_unknown_fields`
    /// for the dev-only process surface.
    #[test]
    fn test_proc_request_variants_reject_unknown_fields() {
        let cases = [
            r#"{"ProcStart":{"argv":["/x"],"env":{},"cwd":null,"stdin":[],"timeout_secs":null,"smuggled":1}}"#,
            r#"{"ProcSignal":{"pid_token":"t","signum":15,"smuggled":1}}"#,
            r#"{"ProcSendInput":{"pid_token":"t","bytes":[],"smuggled":1}}"#,
            r#"{"ProcWait":{"pid_token":"t","timeout_secs":null,"smuggled":1}}"#,
            r#"{"ProcKill":{"pid_token":"t","smuggled":1}}"#,
        ];
        for json in cases {
            let err = serde_json::from_str::<GuestRequest>(json).unwrap_err();
            assert!(
                err.to_string().contains("unknown field"),
                "expected unknown-field rejection for {json}, got: {err}"
            );
        }
    }

    /// `ProcList` is a unit variant in the wire enum. JSON encoding
    /// is just the variant name as a string. Verify roundtrip.
    #[test]
    fn test_proc_list_unit_variant_roundtrip() {
        let req = GuestRequest::ProcList;
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#""ProcList""#);
        let parsed: GuestRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, GuestRequest::ProcList));
    }

    /// FS-style: sub-types reachable through `ProcResult` and
    /// `ProcWaitEvent` also need deny-unknown-fields, since they
    /// land in `GuestResponse` on the *host's* deserializer.
    #[test]
    fn test_proc_response_subtypes_reject_unknown_fields() {
        let cases = [
            r#"{"ProcResult":{"Started":{"pid_token":"t","smuggled":1}}}"#,
            r#"{"ProcResult":{"List":{"processes":[{"pid_token":"t","started_at":"now","argv0":"/x","state":"running","smuggled":1}]}}}"#,
            r#"{"ProcResult":{"InputAccepted":{"bytes_accepted":0,"smuggled":1}}}"#,
            r#"{"ProcResult":{"Error":{"kind":"UnknownToken","message":"x","smuggled":1}}}"#,
            r#"{"ProcWaitEvent":{"Stdout":{"chunk":[],"smuggled":1}}}"#,
            r#"{"ProcWaitEvent":{"Exit":{"code":0,"smuggled":1}}}"#,
            r#"{"ProcWaitEvent":{"Killed":{"signal":15,"smuggled":1}}}"#,
            r#"{"ProcWaitEvent":{"Error":{"kind":"Other","message":"x","smuggled":1}}}"#,
        ];
        for json in cases {
            let err = serde_json::from_str::<GuestResponse>(json).unwrap_err();
            assert!(
                err.to_string().contains("unknown field"),
                "expected unknown-field rejection for {json}, got: {err}"
            );
        }
    }

    /// `ProcWaitEvent::is_terminal` is load-bearing for the host
    /// streaming loop. Make sure every terminal variant says
    /// terminal and no non-terminal one does.
    #[test]
    fn test_proc_wait_event_terminal_classification() {
        assert!(!ProcWaitEvent::Stdout { chunk: vec![] }.is_terminal());
        assert!(!ProcWaitEvent::Stderr { chunk: vec![] }.is_terminal());
        assert!(ProcWaitEvent::Exit { code: 0 }.is_terminal());
        assert!(ProcWaitEvent::Killed { signal: 9 }.is_terminal());
        assert!(ProcWaitEvent::TimedOut.is_terminal());
        assert!(
            ProcWaitEvent::Error {
                kind: ProcErrorKind::Other,
                message: String::new(),
            }
            .is_terminal()
        );
        // ADR-053 §5 / plan 74 W4: `Backpressure` is non-terminal.
        // The wait loop continues after the agent emits it.
        assert!(
            !ProcWaitEvent::Backpressure {
                reason: mvm_core::domain::instance::BackpressureReason::OutputConsumerSlow,
                detail: "captured output 12345 bytes ≥ 12288 byte high-water (cap 16384 bytes)"
                    .to_string(),
            }
            .is_terminal()
        );
    }

    /// ADR-053 §5 / plan 74 W4: the `Backpressure` variant
    /// roundtrips through serde with its full nested shape and
    /// `BackpressureReason` snake-case discriminant intact, and
    /// rejects unknown fields like every other host↔guest type.
    #[test]
    fn test_proc_wait_event_backpressure_serde_roundtrip() {
        let ev = ProcWaitEvent::Backpressure {
            reason: mvm_core::domain::instance::BackpressureReason::OutputConsumerSlow,
            detail: "captured output 12345 bytes ≥ 12288 byte high-water (cap 16384 bytes)"
                .to_string(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let parsed: ProcWaitEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ev);
        // The reason discriminant ships snake_case on the wire so
        // CLI / Studio / MCP renderers can pattern-match on string
        // form without taking a typed dependency on mvm-core.
        assert!(
            json.contains("\"output_consumer_slow\""),
            "wire payload missing snake_case reason: {json}"
        );

        let smuggled =
            r#"{"Backpressure":{"reason":"output_consumer_slow","detail":"x","extra":1}}"#;
        assert!(
            serde_json::from_str::<ProcWaitEvent>(smuggled).is_err(),
            "Backpressure must reject unknown fields"
        );
    }

    /// W4.1 + D regression: every new Volume variant rejects unknown
    /// fields. Mirrors the FS / Proc deny-unknown-fields tests for
    /// the virtio-fs volume surface.
    #[test]
    fn test_volume_request_variants_reject_unknown_fields() {
        let cases = [
            r#"{"MountVolume":{"volume_name":"v","guest_path":"/data/x","read_only":true,"smuggled":1}}"#,
            r#"{"UnmountVolume":{"guest_path":"/data/x","force":false,"smuggled":1}}"#,
        ];
        for json in cases {
            let err = serde_json::from_str::<GuestRequest>(json).unwrap_err();
            assert!(
                err.to_string().contains("unknown field"),
                "expected unknown-field rejection for {json}, got: {err}"
            );
        }
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

    /// Every committed fuzz seed must deserialize cleanly under the
    /// production `GuestRequest` schema. Without this guard, a typo
    /// in a seed (or a future field rename) could silently exclude
    /// the seed from the fuzz coverage and the corpus would shrink
    /// without anyone noticing.
    #[test]
    fn test_fuzz_corpus_seeds_parse() {
        let seeds = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/corpus/fuzz_guest_request");
        if !seeds.is_dir() {
            // The fuzz crate is excluded from some sparse checkouts;
            // skip silently rather than failing in those.
            return;
        }
        let mut count = 0usize;
        for entry in std::fs::read_dir(&seeds).expect("read corpus dir") {
            let entry = entry.expect("read corpus entry");
            if !entry.file_type().expect("file type").is_file() {
                continue;
            }
            let path = entry.path();
            let bytes = std::fs::read(&path).expect("read seed");
            // Tolerate an optional trailing newline editors add.
            let trimmed = bytes.trim_ascii_end().to_vec();
            serde_json::from_slice::<GuestRequest>(&trimmed)
                .unwrap_or_else(|e| panic!("seed {} failed to parse: {e}", path.display()));
            count += 1;
        }
        // 5 baseline (ping, port-fwd, run-entrypoint, sleep-prep,
        // worker-status) + 7 fs-* (A1) + 6 proc-* (A2) + 2 share-*
        // (D) = 20.
        assert!(count >= 20, "expected ≥20 corpus seeds, got {count}");
    }

    /// `follow_symlinks` defaults to `true` for read-shaped verbs and
    /// `false` for mutation verbs. The asymmetric default is
    /// load-bearing for TOCTOU resistance — if a future reviewer
    /// flips a default, this test catches it.
    #[test]
    fn test_fs_follow_symlinks_defaults() {
        let read =
            serde_json::from_str::<GuestRequest>(r#"{"FsRead":{"path":"/x","length":1}}"#).unwrap();
        match read {
            GuestRequest::FsRead {
                follow_symlinks, ..
            } => assert!(follow_symlinks, "FsRead should follow symlinks by default"),
            _ => panic!("expected FsRead"),
        }

        let write = serde_json::from_str::<GuestRequest>(
            r#"{"FsWrite":{"path":"/x","content":[],"mode":420}}"#,
        )
        .unwrap();
        match write {
            GuestRequest::FsWrite {
                follow_symlinks,
                create_parents,
                ..
            } => {
                assert!(
                    !follow_symlinks,
                    "FsWrite must NOT follow symlinks by default"
                );
                assert!(!create_parents, "create_parents defaults to false");
            }
            _ => panic!("expected FsWrite"),
        }

        let remove = serde_json::from_str::<GuestRequest>(r#"{"FsRemove":{"path":"/x"}}"#).unwrap();
        match remove {
            GuestRequest::FsRemove {
                follow_symlinks,
                recursive,
                ..
            } => {
                assert!(
                    !follow_symlinks,
                    "FsRemove must NOT follow symlinks by default"
                );
                assert!(!recursive, "recursive defaults to false");
            }
            _ => panic!("expected FsRemove"),
        }
    }

    /// W4.1 regression: unknown fields in a `GuestRequest` JSON frame must be
    /// rejected outright. Without `deny_unknown_fields`, an attacker could
    /// smuggle extra keys past serde to (a) trip up downstream consumers that
    /// re-parse the same blob, (b) probe for upcoming variants, or (c) create
    /// drift between versions of the agent and host. ADR-002 §W4.1.
    #[test]
    fn test_guest_request_rejects_unknown_field_inside_variant() {
        let json = r#"{"SleepPrep":{"drain_timeout_secs":30,"smuggled":1}}"#;
        let err = serde_json::from_str::<GuestRequest>(json).unwrap_err();
        assert!(
            err.to_string().contains("unknown field") && err.to_string().contains("smuggled"),
            "expected 'unknown field `smuggled`', got: {err}"
        );
    }

    #[test]
    fn test_guest_request_rejects_unknown_top_level_variant() {
        let json = r#"{"NotARealVariant":{}}"#;
        let err = serde_json::from_str::<GuestRequest>(json).unwrap_err();
        assert!(
            err.to_string().contains("unknown variant"),
            "expected 'unknown variant', got: {err}"
        );
    }

    #[test]
    fn test_guest_response_rejects_unknown_field_inside_variant() {
        let json = r#"{"WorkerStatus":{"status":"idle","last_busy_at":null,"x":1}}"#;
        let err = serde_json::from_str::<GuestResponse>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn test_host_bound_request_rejects_unknown_field() {
        let json =
            r#"{"WakeInstance":{"tenant_id":"a","pool_id":"b","instance_id":"c","extra":true}}"#;
        let err = serde_json::from_str::<HostBoundRequest>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn test_host_bound_response_rejects_unknown_field() {
        let json = r#"{"WakeResult":{"success":true,"detail":null,"oops":1}}"#;
        let err = serde_json::from_str::<HostBoundResponse>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn test_fs_change_rejects_unknown_field() {
        let json = r#"{"path":"/x","kind":"created","size":0,"hidden":42}"#;
        let err = serde_json::from_str::<FsChange>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    // -------------------------------------------------------------------
    // ADR-007 / plan 41 W1 — RunEntrypoint wire protocol
    // -------------------------------------------------------------------

    #[test]
    fn test_run_entrypoint_request_roundtrip() {
        let req = GuestRequest::RunEntrypoint {
            stdin: vec![1, 2, 3, 4, 5],
            timeout_secs: 30,
            env: vec![("HTTP_PROXY".into(), "http://127.0.0.1:18080".into())],
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let decoded: GuestRequest = serde_json::from_str(&json).expect("deserialize");
        match decoded {
            GuestRequest::RunEntrypoint {
                stdin,
                timeout_secs,
                env,
            } => {
                assert_eq!(stdin, vec![1, 2, 3, 4, 5]);
                assert_eq!(timeout_secs, 30);
                assert_eq!(
                    env,
                    vec![("HTTP_PROXY".into(), "http://127.0.0.1:18080".into())]
                );
            }
            other => panic!("expected RunEntrypoint, got {other:?}"),
        }
    }

    #[test]
    fn test_run_entrypoint_request_env_defaults_empty_when_omitted() {
        // `env` is `#[serde(default)]`: a wire frame without it decodes to an
        // empty env (a plain call), so callers that never inject stay valid.
        let json = r#"{"RunEntrypoint":{"stdin":[1,2,3],"timeout_secs":10}}"#;
        let decoded: GuestRequest = serde_json::from_str(json).expect("deserialize");
        match decoded {
            GuestRequest::RunEntrypoint { env, .. } => assert!(env.is_empty()),
            other => panic!("expected RunEntrypoint, got {other:?}"),
        }
    }

    #[test]
    fn test_run_entrypoint_request_empty_stdin_roundtrip() {
        let req = GuestRequest::RunEntrypoint {
            stdin: vec![],
            timeout_secs: 5,
            env: vec![],
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let decoded: GuestRequest = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(
            decoded,
            GuestRequest::RunEntrypoint {
                stdin,
                timeout_secs: 5,
                ..
            } if stdin.is_empty()
        ));
    }

    #[test]
    fn test_run_entrypoint_request_rejects_unknown_field() {
        // Unknown fields inside the request must not slip past the
        // deserializer (ADR-002 §W4.1).
        let json = r#"{"RunEntrypoint":{"stdin":[1,2,3],"timeout_secs":10,"smuggled":"x"}}"#;
        let err = serde_json::from_str::<GuestRequest>(json).unwrap_err();
        assert!(
            err.to_string().contains("unknown field") && err.to_string().contains("smuggled"),
            "expected 'unknown field `smuggled`', got: {err}"
        );
    }

    #[test]
    fn test_entrypoint_event_stdout_roundtrip() {
        let evt = EntrypointEvent::Stdout {
            chunk: b"hello".to_vec(),
        };
        let json = serde_json::to_string(&evt).expect("serialize");
        let decoded: EntrypointEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, evt);
        assert!(!decoded.is_terminal());
    }

    #[test]
    fn test_entrypoint_event_stderr_roundtrip() {
        let evt = EntrypointEvent::Stderr {
            chunk: b"warn".to_vec(),
        };
        let json = serde_json::to_string(&evt).expect("serialize");
        let decoded: EntrypointEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, evt);
        assert!(!decoded.is_terminal());
    }

    #[test]
    fn test_entrypoint_event_control_roundtrip() {
        // Control events are non-terminal — the host streams them
        // through alongside Stdout/Stderr until a terminal Exit/Error
        // arrives. Phase 4a wire-shape lock-in.
        let evt = EntrypointEvent::Control {
            header_json: r#"{"kind":"envelope","envelope_kind":"ValueError","error_id":"abc","message":"negative input"}"#.into(),
            payload: b"".to_vec(),
        };
        let json = serde_json::to_string(&evt).expect("serialize");
        let decoded: EntrypointEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, evt);
        assert!(!decoded.is_terminal());
    }

    #[test]
    fn test_entrypoint_event_control_with_payload_roundtrip() {
        // Log-style records carry raw bytes alongside a header.
        let evt = EntrypointEvent::Control {
            header_json: r#"{"kind":"log","stream":"stderr","ts_ms":12345}"#.into(),
            payload: b"DEBUG: warmup complete\n".to_vec(),
        };
        let json = serde_json::to_string(&evt).expect("serialize");
        let decoded: EntrypointEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, evt);
        assert!(!decoded.is_terminal());
    }

    #[test]
    fn test_entrypoint_event_exit_is_terminal() {
        let evt = EntrypointEvent::Exit { code: 0 };
        assert!(evt.is_terminal());
        let json = serde_json::to_string(&evt).expect("serialize");
        let decoded: EntrypointEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, evt);

        let nonzero = EntrypointEvent::Exit { code: 42 };
        assert!(nonzero.is_terminal());
    }

    #[test]
    fn test_entrypoint_event_error_is_terminal() {
        let evt = EntrypointEvent::Error {
            kind: RunEntrypointError::Timeout,
            message: "killed after 30s".into(),
        };
        assert!(evt.is_terminal());
        let json = serde_json::to_string(&evt).expect("serialize");
        let decoded: EntrypointEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, evt);
    }

    #[test]
    fn test_entrypoint_event_rejects_unknown_field() {
        let json = r#"{"Stdout":{"chunk":[1,2,3],"length":3}}"#;
        let err = serde_json::from_str::<EntrypointEvent>(json).unwrap_err();
        assert!(
            err.to_string().contains("unknown field") && err.to_string().contains("length"),
            "expected 'unknown field `length`', got: {err}"
        );
    }

    #[test]
    fn test_entrypoint_event_rejects_unknown_variant() {
        let json = r#"{"Aborted":{"reason":"x"}}"#;
        let err = serde_json::from_str::<EntrypointEvent>(json).unwrap_err();
        assert!(
            err.to_string().contains("unknown variant"),
            "expected 'unknown variant', got: {err}"
        );
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
    fn test_guest_response_entrypoint_event_roundtrip() {
        // Wrap an EntrypointEvent in GuestResponse and roundtrip
        // through the same JSON discipline as every other variant.
        let resp = GuestResponse::EntrypointEvent(EntrypointEvent::Exit { code: 0 });
        let json = serde_json::to_string(&resp).expect("serialize");
        let decoded: GuestResponse = serde_json::from_str(&json).expect("deserialize");
        match decoded {
            GuestResponse::EntrypointEvent(EntrypointEvent::Exit { code }) => {
                assert_eq!(code, 0);
            }
            other => panic!("expected EntrypointEvent(Exit), got {other:?}"),
        }
    }

    #[test]
    fn test_run_entrypoint_response_stream_terminates_on_exit() {
        // Simulate a v1 response stream and assert the host's read
        // loop discipline: read events until is_terminal returns
        // true. This is the contract W2's agent handler must
        // satisfy and W3's CLI consumes.
        let stream = vec![
            EntrypointEvent::Stdout {
                chunk: b"out".to_vec(),
            },
            EntrypointEvent::Stderr {
                chunk: b"err".to_vec(),
            },
            EntrypointEvent::Exit { code: 0 },
        ];

        let mut seen = 0;
        for evt in &stream {
            seen += 1;
            if evt.is_terminal() {
                break;
            }
        }
        assert_eq!(seen, 3);
        assert!(stream[2].is_terminal());
    }

    #[test]
    fn test_run_entrypoint_response_stream_terminates_on_error() {
        // Same shape as the Exit case but with Error as the
        // terminal event — the host loop must stop equally cleanly
        // either way.
        let stream = vec![
            EntrypointEvent::Stdout {
                chunk: b"partial".to_vec(),
            },
            EntrypointEvent::Error {
                kind: RunEntrypointError::Timeout,
                message: "killed after 30s".into(),
            },
        ];

        let mut seen = 0;
        for evt in &stream {
            seen += 1;
            if evt.is_terminal() {
                break;
            }
        }
        assert_eq!(seen, 2);
        assert!(stream[1].is_terminal());
    }

    #[test]
    fn test_run_entrypoint_request_well_formed_accepted() {
        // Sanity: the W1 wire types must continue to parse cleanly
        // with `deny_unknown_fields` applied.
        let json = r#"{"RunEntrypoint":{"stdin":[],"timeout_secs":15}}"#;
        let req: GuestRequest = serde_json::from_str(json).expect("deserialize");
        assert!(matches!(
            req,
            GuestRequest::RunEntrypoint {
                stdin,
                timeout_secs: 15,
                ..
            } if stdin.is_empty()
        ));
    }

    // -------------------------------------------------------------------
    // ADR-007 / plan 41 W5 — EntrypointStatus query
    // -------------------------------------------------------------------

    #[test]
    fn test_entrypoint_status_request_roundtrip() {
        let req = GuestRequest::EntrypointStatus;
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#""EntrypointStatus""#);
        let decoded: GuestRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, GuestRequest::EntrypointStatus));
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

    /// Sanity check: the well-formed frames the same tests cover above must
    /// still parse cleanly with the attribute applied.
    #[test]
    fn test_guest_request_well_formed_still_accepted() {
        let json = r#"{"SleepPrep":{"drain_timeout_secs":30}}"#;
        let req: GuestRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(
            req,
            GuestRequest::SleepPrep {
                drain_timeout_secs: 30
            }
        ));
    }

    #[test]
    fn test_vsock_uds_path() {
        assert_eq!(
            vsock_uds_path("/var/lib/mvm/tenants/acme/pools/workers/instances/i-abc"),
            "/var/lib/mvm/tenants/acme/pools/workers/instances/i-abc/runtime/v.sock"
        );
    }

    #[test]
    fn test_guest_request_sleep_prep_fields() {
        let req = GuestRequest::SleepPrep {
            drain_timeout_secs: 45,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("45"));
        assert!(json.contains("SleepPrep"));
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
    fn test_constants() {
        assert_eq!(GUEST_CID, 3);
        // Must stay > 1023 — vsock binds <= 1023 require
        // CAP_NET_BIND_SERVICE, which the agent (uid 901) doesn't have
        // (ADR-002 §W4.5). See the doc comment on GUEST_AGENT_PORT.
        const _: () = assert!(GUEST_AGENT_PORT > 1023);
        assert_eq!(GUEST_AGENT_PORT, 5252);
        assert_eq!(DEFAULT_TIMEOUT_SECS, 10);
    }

    #[test]
    fn test_max_frame_size() {
        assert_eq!(MAX_FRAME_SIZE, 256 * 1024);
    }

    #[test]
    fn test_checkpoint_request_serde() {
        let req = GuestRequest::CheckpointIntegrations {
            integrations: vec!["whatsapp".to_string(), "signal".to_string()],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("CheckpointIntegrations"));
        assert!(json.contains("whatsapp"));
        assert!(json.contains("signal"));
        let parsed: GuestRequest = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&parsed).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn test_host_bound_request_roundtrip() {
        let variants: Vec<HostBoundRequest> = vec![
            HostBoundRequest::WakeInstance {
                tenant_id: "alice".to_string(),
                pool_id: "workers".to_string(),
                instance_id: "i-abc123".to_string(),
            },
            HostBoundRequest::QueryInstanceStatus {
                tenant_id: "alice".to_string(),
                pool_id: "workers".to_string(),
                instance_id: "i-abc123".to_string(),
            },
            HostBoundRequest::QueryHostTime,
        ];

        for req in &variants {
            let json = serde_json::to_string(req).unwrap();
            let parsed: HostBoundRequest = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn test_query_host_time_serialises_as_bare_variant() {
        // QueryHostTime is unit-shaped — make sure it serialises
        // as the bare string form rather than picking up an empty
        // object body, so the wire format is forward-compatible
        // with other unit variants in the enum.
        let req = HostBoundRequest::QueryHostTime;
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, "\"QueryHostTime\"");
    }

    #[test]
    fn test_host_time_response_roundtrip() {
        let resp = HostBoundResponse::HostTime {
            unix_seconds: 1_777_372_800,
            unix_nanos: 123_456_789,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: HostBoundResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            HostBoundResponse::HostTime {
                unix_seconds,
                unix_nanos,
            } => {
                assert_eq!(unix_seconds, 1_777_372_800);
                assert_eq!(unix_nanos, 123_456_789);
            }
            other => panic!("expected HostTime, got {other:?}"),
        }
    }

    #[test]
    fn test_host_time_response_unknown_field_rejected() {
        // deny_unknown_fields must reject an extra field even on a
        // successful-looking variant — defends against a future
        // host accidentally emitting a richer HostTime that older
        // guests don't understand.
        let json = r#"{"HostTime":{"unix_seconds":0,"unix_nanos":0,"timezone":"UTC"}}"#;
        let result: Result<HostBoundResponse, _> = serde_json::from_str(json);
        assert!(result.is_err(), "extra field must be rejected");
    }

    #[test]
    fn test_host_bound_response_roundtrip() {
        let variants: Vec<HostBoundResponse> = vec![
            HostBoundResponse::WakeResult {
                success: true,
                detail: Some("woke i-abc123".to_string()),
            },
            HostBoundResponse::InstanceStatus {
                status: "Running".to_string(),
                guest_ip: Some("10.240.1.5".to_string()),
            },
            HostBoundResponse::Error {
                message: "instance not found".to_string(),
            },
        ];

        for resp in &variants {
            let json = serde_json::to_string(resp).unwrap();
            let parsed: HostBoundResponse = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
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

    #[test]
    fn test_is_timeout_error_would_block() {
        let err = std::io::Error::new(std::io::ErrorKind::WouldBlock, "would block");
        assert!(is_timeout_error(&err));
    }

    #[test]
    fn test_is_timeout_error_timed_out() {
        let err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        assert!(is_timeout_error(&err));
    }

    #[test]
    fn test_is_timeout_error_other() {
        let err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        assert!(!is_timeout_error(&err));
    }

    #[test]
    fn test_try_connect_once_nonexistent_path() {
        let result = try_connect_once("/nonexistent/v.sock", GUEST_AGENT_PORT, 1);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Vsock socket not found at"),
            "Error was: {}",
            err_msg
        );
    }

    #[test]
    fn test_connect_to_nonexistent_no_retry_delay() {
        // Definitive failure (socket not found) should fail fast without retries
        let start = std::time::Instant::now();
        let result = connect_to("/nonexistent/v.sock", 1);
        let elapsed = start.elapsed();
        assert!(result.is_err());
        assert!(
            elapsed.as_secs() < 2,
            "connect_to took {:?}, suggesting unnecessary retries",
            elapsed
        );
    }

    #[test]
    fn test_host_bound_port_constant() {
        assert_eq!(HOST_BOUND_PORT, 53);
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

    // ========================================================================
    // Authenticated frame tests
    // ========================================================================

    fn test_keypair() -> SigningKey {
        SigningKey::generate(&mut rand::rngs::OsRng)
    }

    #[test]
    fn test_authenticated_frame_write_read_roundtrip() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let key = test_keypair();
        let verifying = key.verifying_key();
        let session_id = "test-session-001";

        let request = GuestRequest::Ping;

        write_authenticated_frame(&mut writer, &request, &key, "test-key", session_id, 1).unwrap();

        let (parsed, seq): (GuestRequest, u64) =
            read_authenticated_frame(&mut reader, &verifying, session_id, 0).unwrap();

        assert_eq!(seq, 1);
        assert!(matches!(parsed, GuestRequest::Ping));
    }

    #[test]
    fn test_authenticated_frame_complex_payload() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let key = test_keypair();
        let verifying = key.verifying_key();
        let session_id = "complex-session";

        let response = GuestResponse::WorkerStatus {
            status: "busy".to_string(),
            last_busy_at: Some("2026-02-25T10:00:00Z".to_string()),
        };

        write_authenticated_frame(&mut writer, &response, &key, "guest", session_id, 42).unwrap();

        let (parsed, seq): (GuestResponse, u64) =
            read_authenticated_frame(&mut reader, &verifying, session_id, 0).unwrap();

        assert_eq!(seq, 42);
        match parsed {
            GuestResponse::WorkerStatus {
                status,
                last_busy_at,
            } => {
                assert_eq!(status, "busy");
                assert_eq!(last_busy_at.unwrap(), "2026-02-25T10:00:00Z");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_authenticated_frame_tampered_payload_rejected() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let key = test_keypair();
        let verifying = key.verifying_key();

        // Write a valid authenticated frame
        let request = GuestRequest::Ping;
        write_authenticated_frame(&mut writer, &request, &key, "test", "sess", 1).unwrap();

        // Read the raw bytes and tamper with the payload
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).unwrap();
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; frame_len];
        reader.read_exact(&mut buf).unwrap();

        // Tamper: change a byte in the payload
        let mut frame: AuthenticatedFrame = serde_json::from_slice(&buf).unwrap();
        if !frame.signed.payload.is_empty() {
            frame.signed.payload[0] ^= 0xFF;
        }

        // Write tampered frame to a new stream
        let (mut w2, mut r2) = UnixStream::pair().unwrap();
        r2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write_frame(&mut w2, &frame).unwrap();

        let result: Result<(GuestRequest, u64)> =
            read_authenticated_frame(&mut r2, &verifying, "sess", 0);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Signature verification failed") || err_msg.contains("deserialize"),
            "Unexpected error: {}",
            err_msg
        );
    }

    #[test]
    fn test_authenticated_frame_wrong_key_rejected() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let key_a = test_keypair();
        let key_b = test_keypair();

        write_authenticated_frame(&mut writer, &GuestRequest::Ping, &key_a, "a", "sess", 1)
            .unwrap();

        // Try to verify with wrong key
        let result: Result<(GuestRequest, u64)> =
            read_authenticated_frame(&mut reader, &key_b.verifying_key(), "sess", 0);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Signature verification failed")
        );
    }

    #[test]
    fn test_authenticated_frame_replay_detection() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let key = test_keypair();
        let verifying = key.verifying_key();

        // Write frame with sequence 5
        write_authenticated_frame(&mut writer, &GuestRequest::Ping, &key, "test", "sess", 5)
            .unwrap();

        // Try to read expecting minimum sequence 10 — should be rejected
        let result: Result<(GuestRequest, u64)> =
            read_authenticated_frame(&mut reader, &verifying, "sess", 10);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Replay detected"));
    }

    #[test]
    fn test_authenticated_frame_session_id_mismatch() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let key = test_keypair();
        let verifying = key.verifying_key();

        write_authenticated_frame(
            &mut writer,
            &GuestRequest::Ping,
            &key,
            "test",
            "session-A",
            1,
        )
        .unwrap();

        let result: Result<(GuestRequest, u64)> =
            read_authenticated_frame(&mut reader, &verifying, "session-B", 0);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Session ID mismatch")
        );
    }

    // ========================================================================
    // Handshake tests
    // ========================================================================

    #[test]
    fn test_handshake_roundtrip() {
        let (mut host_stream, mut guest_stream) = UnixStream::pair().unwrap();
        host_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        guest_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let host_key = test_keypair();
        let guest_key = test_keypair();
        let host_vk_expected = host_key.verifying_key();
        let guest_vk_expected = guest_key.verifying_key();
        let session_id = "handshake-test-001";

        // Run handshake in separate threads since both sides block on I/O
        let host_handle =
            std::thread::spawn(move || handshake_as_host(&mut host_stream, session_id, &host_key));

        let guest_handle =
            std::thread::spawn(move || handshake_as_guest(&mut guest_stream, &guest_key));

        let guest_vk = host_handle.join().unwrap().unwrap();
        let (host_vk, received_session_id) = guest_handle.join().unwrap().unwrap();

        // Host got guest's public key
        assert_eq!(guest_vk.as_bytes(), guest_vk_expected.as_bytes());
        // Guest got host's public key
        assert_eq!(host_vk.as_bytes(), host_vk_expected.as_bytes());
        // Session ID was echoed correctly
        assert_eq!(received_session_id, session_id);
    }

    #[test]
    fn test_handshake_then_authenticated_exchange() {
        let (mut host_stream, mut guest_stream) = UnixStream::pair().unwrap();
        host_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        guest_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let host_key = test_keypair();
        let guest_key = test_keypair();
        let session_id = "full-exchange-test";

        // Handshake
        let host_handle = {
            let hk = SigningKey::from_bytes(&host_key.to_bytes());
            std::thread::spawn(move || {
                handshake_as_host(&mut host_stream, session_id, &hk).map(|gvk| (host_stream, gvk))
            })
        };

        let guest_handle = {
            let gk = SigningKey::from_bytes(&guest_key.to_bytes());
            std::thread::spawn(move || {
                handshake_as_guest(&mut guest_stream, &gk)
                    .map(|(hvk, sid)| (guest_stream, hvk, sid))
            })
        };

        let (mut host_stream, guest_vk) = host_handle.join().unwrap().unwrap();
        let (mut guest_stream, host_vk, _sid) = guest_handle.join().unwrap().unwrap();

        // Host sends authenticated request
        write_authenticated_frame(
            &mut host_stream,
            &GuestRequest::Ping,
            &host_key,
            "host",
            session_id,
            1,
        )
        .unwrap();

        // Guest reads and verifies
        let (req, seq): (GuestRequest, u64) =
            read_authenticated_frame(&mut guest_stream, &host_vk, session_id, 0).unwrap();
        assert!(matches!(req, GuestRequest::Ping));
        assert_eq!(seq, 1);

        // Guest sends authenticated response
        write_authenticated_frame(
            &mut guest_stream,
            &GuestResponse::Pong,
            &guest_key,
            "guest",
            session_id,
            1,
        )
        .unwrap();

        // Host reads and verifies
        let (resp, seq): (GuestResponse, u64) =
            read_authenticated_frame(&mut host_stream, &guest_vk, session_id, 0).unwrap();
        assert!(matches!(resp, GuestResponse::Pong));
        assert_eq!(seq, 1);
    }

    // -------------------------------------------------------------------
    // ADR-007 / plan 41 W3 — send_run_entrypoint streaming consumer
    // -------------------------------------------------------------------

    fn write_event_frame(stream: &mut UnixStream, event: &EntrypointEvent) {
        write_frame(stream, &GuestResponse::EntrypointEvent(event.clone())).unwrap();
    }

    fn answer_run_entrypoint_protocol_hello(stream: &mut UnixStream) {
        let req: GuestRequest = read_frame(stream).unwrap();
        match req {
            GuestRequest::ProtocolHello {
                requested_capabilities,
                ..
            } => assert_eq!(requested_capabilities, vec![GuestCapability::RunEntrypoint]),
            other => panic!("expected ProtocolHello, got {other:?}"),
        }
        write_frame(
            stream,
            &GuestResponse::ProtocolHelloAck {
                agent_protocol_version: PROTOCOL_VERSION,
                min_supported_version: MIN_SUPPORTED_PROTOCOL_VERSION,
                agent_version: "test-agent".to_string(),
                capabilities: vec![GuestCapability::RunEntrypoint],
            },
        )
        .unwrap();
    }

    #[test]
    fn test_send_run_entrypoint_collects_events_until_terminal() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // Guest side: read the request, emit Stdout, Stderr, Exit.
        let guest_handle = std::thread::spawn(move || {
            answer_run_entrypoint_protocol_hello(&mut guest);
            let req: GuestRequest = read_frame(&mut guest).unwrap();
            assert!(matches!(
                req,
                GuestRequest::RunEntrypoint {
                    timeout_secs: 30,
                    ..
                }
            ));
            write_event_frame(
                &mut guest,
                &EntrypointEvent::Stdout {
                    chunk: b"out".to_vec(),
                },
            );
            write_event_frame(
                &mut guest,
                &EntrypointEvent::Stderr {
                    chunk: b"err".to_vec(),
                },
            );
            write_event_frame(&mut guest, &EntrypointEvent::Exit { code: 0 });
        });

        let mut received: Vec<EntrypointEvent> = Vec::new();
        let terminal = send_run_entrypoint(&mut host, b"in".to_vec(), 30, Vec::new(), |evt| {
            received.push(evt.clone())
        })
        .expect("send_run_entrypoint");

        guest_handle.join().unwrap();

        assert_eq!(received.len(), 2);
        assert!(matches!(
            received[0],
            EntrypointEvent::Stdout { ref chunk } if chunk == b"out"
        ));
        assert!(matches!(
            received[1],
            EntrypointEvent::Stderr { ref chunk } if chunk == b"err"
        ));
        assert!(matches!(terminal, EntrypointEvent::Exit { code: 0 }));
    }

    #[test]
    fn test_send_run_entrypoint_terminates_on_error() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // Guest side: emit one Stdout chunk, then a terminal Error.
        // The handler must observe the Stdout but stop reading after
        // Error.
        let guest_handle = std::thread::spawn(move || {
            answer_run_entrypoint_protocol_hello(&mut guest);
            let _req: GuestRequest = read_frame(&mut guest).unwrap();
            write_event_frame(
                &mut guest,
                &EntrypointEvent::Stdout {
                    chunk: b"partial".to_vec(),
                },
            );
            write_event_frame(
                &mut guest,
                &EntrypointEvent::Error {
                    kind: RunEntrypointError::Timeout,
                    message: "killed at 30s".into(),
                },
            );
            // Write a bogus extra frame after the terminal — the
            // consumer must not read it.
            write_event_frame(
                &mut guest,
                &EntrypointEvent::Stdout {
                    chunk: b"should-not-be-read".to_vec(),
                },
            );
        });

        let mut received: Vec<EntrypointEvent> = Vec::new();
        let terminal = send_run_entrypoint(&mut host, b"".to_vec(), 30, Vec::new(), |evt| {
            received.push(evt.clone())
        })
        .expect("send_run_entrypoint");

        guest_handle.join().unwrap();

        assert_eq!(received.len(), 1);
        assert!(matches!(
            received[0],
            EntrypointEvent::Stdout { ref chunk } if chunk == b"partial"
        ));
        assert!(matches!(
            terminal,
            EntrypointEvent::Error {
                kind: RunEntrypointError::Timeout,
                ..
            }
        ));
    }

    #[test]
    fn test_send_run_entrypoint_rejects_unexpected_response() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // Guest writes a Pong instead of an EntrypointEvent.
        let guest_handle = std::thread::spawn(move || {
            answer_run_entrypoint_protocol_hello(&mut guest);
            let _req: GuestRequest = read_frame(&mut guest).unwrap();
            write_frame(&mut guest, &GuestResponse::Pong).unwrap();
        });

        let result = send_run_entrypoint(&mut host, b"".to_vec(), 30, Vec::new(), |_| {});
        guest_handle.join().unwrap();

        let err = result.expect_err("should reject Pong");
        assert!(
            err.to_string().contains("expected EntrypointEvent"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn test_send_run_entrypoint_surfaces_guest_error() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // Guest writes a generic Error (not an EntrypointEvent::Error).
        // This shouldn't normally happen for RunEntrypoint, but the
        // host-side consumer should map it to a clear Result error.
        let guest_handle = std::thread::spawn(move || {
            answer_run_entrypoint_protocol_hello(&mut guest);
            let _req: GuestRequest = read_frame(&mut guest).unwrap();
            write_frame(
                &mut guest,
                &GuestResponse::Error {
                    message: "agent panicked before dispatch".into(),
                },
            )
            .unwrap();
        });

        let result = send_run_entrypoint(&mut host, b"".to_vec(), 30, Vec::new(), |_| {});
        guest_handle.join().unwrap();

        let err = result.expect_err("should surface guest error");
        assert!(
            err.to_string().contains("agent panicked"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_handshake_with_wrong_challenge_response() {
        let (mut host_stream, mut guest_stream) = UnixStream::pair().unwrap();
        host_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        guest_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let host_key = test_keypair();
        let wrong_key = test_keypair(); // Guest uses wrong key

        let host_handle = std::thread::spawn(move || {
            handshake_as_host(&mut host_stream, "bad-handshake", &host_key)
        });

        // Guest side: read hello, but sign with wrong key
        let hello: SessionHello = read_frame(&mut guest_stream).unwrap();
        let bad_sig = wrong_key.sign(&hello.challenge);
        let ack = SessionHelloAck {
            version: hello.version,
            session_id: hello.session_id,
            challenge_response: bad_sig.to_bytes().to_vec(),
            // Send the correct guest pubkey for the wrong key
            guest_pubkey: wrong_key.verifying_key().to_bytes().to_vec(),
        };
        write_frame(&mut guest_stream, &ack).unwrap();

        // Host should succeed because the guest signed with wrong_key
        // but sent wrong_key's pubkey — the challenge was signed by the
        // key whose pubkey was provided, so verification passes.
        // This is correct: we verify the guest controls the key it claims.
        let result = host_handle.join().unwrap();
        assert!(result.is_ok());
    }

    // ========================================================================
    // Plan 76 Phase 1 — profile classifier
    // ========================================================================

    /// Every `GuestRequest` variant must classify as either `ProdSafe`
    /// or `DevOnly` today. Compile-fail when a new variant is added
    /// without being classified — the exhaustive match inside
    /// `class()` guarantees that, and this test fails closed if the
    /// variant ever lands in an unexpected class.
    #[test]
    fn test_request_class_coverage_matches_sealed_prod_allowlist() {
        let prod_safe_verbs: &[&str] = &[
            "ProtocolHello",
            "WorkerStatus",
            "SleepPrep",
            "Wake",
            "Ping",
            "IntegrationStatus",
            "CheckpointIntegrations",
            "ProbeStatus",
            "RunEntrypoint",
            "PostRestore",
            "EntrypointStatus",
            "ReadinessStatus",
            "MountVolume",
            "UnmountVolume",
            "UpdateIdleTimeout",
        ];

        // One representative `GuestRequest` value per variant. Used to
        // exercise `class()` + `verb_name()` together.
        let all: Vec<GuestRequest> = vec![
            GuestRequest::ProtocolHello {
                host_protocol_version: 1,
                min_supported_version: 1,
                host_version: "test".into(),
                requested_capabilities: vec![],
            },
            GuestRequest::WorkerStatus,
            GuestRequest::SleepPrep {
                drain_timeout_secs: 0,
            },
            GuestRequest::Wake,
            GuestRequest::Ping,
            GuestRequest::IntegrationStatus,
            GuestRequest::CheckpointIntegrations {
                integrations: vec![],
            },
            GuestRequest::ProbeStatus,
            GuestRequest::Exec {
                command: "x".into(),
                stdin: None,
                timeout_secs: None,
            },
            GuestRequest::RunEntrypoint {
                stdin: vec![],
                timeout_secs: 1,
                env: vec![],
            },
            GuestRequest::PostRestore,
            GuestRequest::FsDiff,
            GuestRequest::StartPortForward { guest_port: 1 },
            GuestRequest::ConsoleOpen { cols: 1, rows: 1 },
            GuestRequest::ConsoleClose { session_id: 1 },
            GuestRequest::ConsoleResize {
                session_id: 1,
                cols: 1,
                rows: 1,
            },
            GuestRequest::EntrypointStatus,
            GuestRequest::ReadinessStatus,
            GuestRequest::FsRead {
                path: "/x".into(),
                offset: None,
                length: 1,
                follow_symlinks: true,
            },
            GuestRequest::FsWrite {
                path: "/x".into(),
                content: vec![],
                mode: 0,
                create_parents: false,
                follow_symlinks: false,
            },
            GuestRequest::FsList {
                path: "/x".into(),
                follow_symlinks: true,
            },
            GuestRequest::FsStat {
                path: "/x".into(),
                follow_symlinks: true,
            },
            GuestRequest::FsMkdir {
                path: "/x".into(),
                mode: 0,
                parents: false,
            },
            GuestRequest::FsRemove {
                path: "/x".into(),
                recursive: false,
                follow_symlinks: false,
            },
            GuestRequest::FsMove {
                from: "/x".into(),
                to: "/y".into(),
                follow_symlinks: false,
            },
            GuestRequest::ProcStart {
                argv: vec!["/x".into()],
                env: Default::default(),
                cwd: None,
                stdin: vec![],
                timeout_secs: None,
            },
            GuestRequest::ProcList,
            GuestRequest::ProcSignal {
                pid_token: "t".into(),
                signum: 15,
            },
            GuestRequest::ProcSendInput {
                pid_token: "t".into(),
                bytes: vec![],
            },
            GuestRequest::ProcWait {
                pid_token: "t".into(),
                timeout_secs: None,
            },
            GuestRequest::ProcKill {
                pid_token: "t".into(),
            },
            GuestRequest::MountVolume {
                volume_name: "v".into(),
                guest_path: "/x".into(),
                read_only: true,
            },
            GuestRequest::UnmountVolume {
                guest_path: "/x".into(),
                force: false,
            },
            GuestRequest::UpdateIdleTimeout { secs: 0 },
            GuestRequest::RunCode {
                code: "x".into(),
                timeout_secs: Some(1),
            },
        ];

        // Every variant has a stable verb_name; that name appears in
        // exactly one of the two classification buckets.
        for req in &all {
            let name = req.verb_name();
            let in_prod = prod_safe_verbs.contains(&name);
            match req.class() {
                RequestClass::ProdSafe => assert!(
                    in_prod,
                    "{name}: classified ProdSafe but missing from SealedProd allowlist"
                ),
                RequestClass::DevOnly => assert!(
                    !in_prod,
                    "{name}: classified DevOnly but present in SealedProd allowlist"
                ),
                RequestClass::BuilderOnly => {
                    panic!("{name}: no GuestRequest variant should be BuilderOnly yet")
                }
            }
        }

        // The allowlist itself stays anchored: every prod-safe verb
        // shows up in `all` above, so renaming a variant trips this
        // assertion too.
        let names: Vec<&'static str> = all.iter().map(|r| r.verb_name()).collect();
        for v in prod_safe_verbs {
            assert!(
                names.contains(v),
                "SealedProd verb {v} missing from coverage"
            );
        }
    }

    #[test]
    fn test_sealed_prod_rejects_dev_only_verbs() {
        let dev_only_samples = [
            GuestRequest::Exec {
                command: "x".into(),
                stdin: None,
                timeout_secs: None,
            },
            GuestRequest::ConsoleOpen { cols: 80, rows: 24 },
            GuestRequest::ProcStart {
                argv: vec!["/x".into()],
                env: Default::default(),
                cwd: None,
                stdin: vec![],
                timeout_secs: None,
            },
            GuestRequest::RunCode {
                code: "print(1)".into(),
                timeout_secs: Some(1),
            },
            GuestRequest::FsWrite {
                path: "/x".into(),
                content: vec![],
                mode: 0,
                create_parents: false,
                follow_symlinks: false,
            },
            GuestRequest::FsRead {
                path: "/x".into(),
                offset: None,
                length: 1,
                follow_symlinks: true,
            },
            GuestRequest::StartPortForward { guest_port: 8080 },
        ];

        for req in &dev_only_samples {
            assert!(
                !req.allowed_in(AgentProfile::SealedProd),
                "{} should be rejected in SealedProd",
                req.verb_name()
            );
            assert!(
                req.allowed_in(AgentProfile::Dev),
                "{} should be allowed in Dev",
                req.verb_name()
            );
            assert!(
                !req.allowed_in(AgentProfile::Builder),
                "{} should not be allowed in Builder",
                req.verb_name()
            );
        }
    }

    #[test]
    fn test_sealed_prod_accepts_prod_safe_verbs() {
        let prod_safe_samples = [
            GuestRequest::Ping,
            GuestRequest::WorkerStatus,
            GuestRequest::EntrypointStatus,
            GuestRequest::RunEntrypoint {
                stdin: vec![],
                timeout_secs: 60,
                env: vec![],
            },
            GuestRequest::SleepPrep {
                drain_timeout_secs: 5,
            },
            GuestRequest::Wake,
            GuestRequest::PostRestore,
            GuestRequest::UpdateIdleTimeout { secs: 600 },
            GuestRequest::MountVolume {
                volume_name: "v".into(),
                guest_path: "/data".into(),
                read_only: true,
            },
            GuestRequest::UnmountVolume {
                guest_path: "/data".into(),
                force: false,
            },
        ];

        for req in &prod_safe_samples {
            assert!(
                req.allowed_in(AgentProfile::SealedProd),
                "{} should be allowed in SealedProd",
                req.verb_name()
            );
            assert!(
                req.allowed_in(AgentProfile::Dev),
                "{} should be allowed in Dev (Dev ⊃ SealedProd)",
                req.verb_name()
            );
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

    // ========================================================================
    // Plan 76 Phase 2 — readiness model
    // ========================================================================

    #[test]
    fn test_readiness_status_classifies_prod_safe() {
        // `ReadinessStatus` must respond from sealed-prod images
        // even before entrypoint validation completes — that's the
        // whole point of the verb. If a future refactor downgrades
        // it to DevOnly, this test fails loud.
        let req = GuestRequest::ReadinessStatus;
        assert_eq!(req.class(), RequestClass::ProdSafe);
        assert!(req.allowed_in(AgentProfile::SealedProd));
        assert!(req.allowed_in(AgentProfile::Dev));
        assert!(!req.allowed_in(AgentProfile::Builder));
        assert_eq!(req.verb_name(), "ReadinessStatus");
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
        // ADR-002 §W4.1: every host↔guest type must deny unknown
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
        // Plan 76 Phase 2: the typed variant returned when a host
        // races `RunEntrypoint` ahead of `entrypoint=Ready`.
        let err = RunEntrypointError::NotReady;
        let json = serde_json::to_string(&err).unwrap();
        assert_eq!(json, "\"NotReady\"");
        let parsed: RunEntrypointError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, err);
    }

    #[test]
    fn test_boot_timing_report_default_is_all_none() {
        // The skeleton ships with all-`None` so Phase 4 can fill
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

    // ========================================================================
    // Plan 74 W2 / Plan 51 W6 — `GuestRequest::kind_name` for vsock RPC audit
    // ========================================================================

    /// Every `GuestRequest` variant must produce a kebab-case
    /// verb name. The check is exhaustive: a new variant added
    /// without updating `kind_name` panics here because the
    /// constructor list is hand-maintained, not derived.
    ///
    /// Pin the wire-stable strings: a rename is a detail-format
    /// wire-format change, so the audit consumer reading old
    /// logs sees the same `verb=<name>` tokens.
    #[test]
    fn kind_name_covers_every_variant() {
        // Hand-roll one of each variant. A new variant requires
        // a new row here — the match in `kind_name` is exhaustive
        // so the compiler catches it on the implementation side,
        // and this test catches it on the wire-format side.
        let cases: &[(GuestRequest, &str)] = &[
            (
                GuestRequest::ProtocolHello {
                    host_protocol_version: 0,
                    min_supported_version: 0,
                    host_version: String::new(),
                    requested_capabilities: Vec::new(),
                },
                "protocol-hello",
            ),
            (GuestRequest::WorkerStatus, "worker-status"),
            (
                GuestRequest::SleepPrep {
                    drain_timeout_secs: 0,
                },
                "sleep-prep",
            ),
            (GuestRequest::Wake, "wake"),
            (GuestRequest::Ping, "ping"),
            (GuestRequest::IntegrationStatus, "integration-status"),
            (
                GuestRequest::CheckpointIntegrations {
                    integrations: Vec::new(),
                },
                "checkpoint-integrations",
            ),
            (GuestRequest::ProbeStatus, "probe-status"),
            (
                GuestRequest::Exec {
                    command: String::new(),
                    stdin: None,
                    timeout_secs: None,
                },
                "exec",
            ),
            (
                GuestRequest::RunEntrypoint {
                    stdin: Vec::new(),
                    timeout_secs: 0,
                    env: Vec::new(),
                },
                "run-entrypoint",
            ),
            (GuestRequest::PostRestore, "post-restore"),
            (GuestRequest::FsDiff, "fs-diff"),
            (
                GuestRequest::StartPortForward { guest_port: 0 },
                "start-port-forward",
            ),
            (
                GuestRequest::ConsoleOpen { cols: 0, rows: 0 },
                "console-open",
            ),
            (
                GuestRequest::ConsoleClose { session_id: 0 },
                "console-close",
            ),
            (
                GuestRequest::ConsoleResize {
                    session_id: 0,
                    cols: 0,
                    rows: 0,
                },
                "console-resize",
            ),
            (GuestRequest::EntrypointStatus, "entrypoint-status"),
            (GuestRequest::ReadinessStatus, "readiness-status"),
            (
                GuestRequest::FsRead {
                    path: String::new(),
                    offset: None,
                    length: 0,
                    follow_symlinks: true,
                },
                "fs-read",
            ),
            (
                GuestRequest::FsWrite {
                    path: String::new(),
                    content: Vec::new(),
                    mode: 0,
                    create_parents: false,
                    follow_symlinks: false,
                },
                "fs-write",
            ),
        ];
        for (req, expected) in cases {
            assert_eq!(req.kind_name(), *expected, "verb name for {req:?}");
        }
    }

    #[test]
    fn workload_exit_port_is_distinct_and_reserved() {
        assert_eq!(WORKLOAD_EXIT_PORT, 5251);
        assert_ne!(WORKLOAD_EXIT_PORT, GUEST_AGENT_PORT);
        const { assert!(WORKLOAD_EXIT_PORT < PORT_FORWARD_BASE) }
    }

    /// Sanity: the verb names are all kebab-case (lowercase
    /// ASCII letters + `-`). A future variant accidentally
    /// emitting `snake_case` or `CamelCase` would break log
    /// parsers that split on `-`.
    #[test]
    fn kind_name_strings_are_kebab_case() {
        let samples = [
            GuestRequest::Ping,
            GuestRequest::EntrypointStatus,
            GuestRequest::ReadinessStatus,
            GuestRequest::FsDiff,
            GuestRequest::StartPortForward { guest_port: 0 },
            GuestRequest::CheckpointIntegrations {
                integrations: vec![],
            },
        ];
        for req in samples {
            let s = req.kind_name();
            for c in s.chars() {
                assert!(
                    c.is_ascii_lowercase() || c == '-',
                    "verb '{s}' contains non-kebab-case char {c:?}"
                );
            }
            assert!(!s.is_empty(), "verb name must not be empty");
            assert!(!s.starts_with('-'), "verb must not start with hyphen: {s}");
            assert!(!s.ends_with('-'), "verb must not end with hyphen: {s}");
        }
    }

    #[test]
    fn exec_event_exit_and_timedout_are_terminal() {
        assert!(ExecEvent::Exit { code: 0 }.is_terminal());
        assert!(ExecEvent::TimedOut.is_terminal());
        assert!(
            !ExecEvent::Stdout {
                chunk: b"x".to_vec()
            }
            .is_terminal()
        );
        assert!(
            !ExecEvent::Stderr {
                chunk: b"y".to_vec()
            }
            .is_terminal()
        );
    }

    #[test]
    fn guest_response_exec_event_roundtrips() {
        let r = GuestResponse::ExecEvent(ExecEvent::Stdout {
            chunk: b"hi".to_vec(),
        });
        let j = serde_json::to_vec(&r).unwrap();
        let back: GuestResponse = serde_json::from_slice(&j).unwrap();
        assert!(
            matches!(back, GuestResponse::ExecEvent(ExecEvent::Stdout { ref chunk }) if chunk == b"hi")
        );
    }

    // Plan 159 WS-5 E — send_exec_streaming host reader
    // -------------------------------------------------------------------

    fn answer_exec_protocol_hello(stream: &mut UnixStream) {
        let req: GuestRequest = read_frame(stream).unwrap();
        match req {
            GuestRequest::ProtocolHello {
                requested_capabilities,
                ..
            } => assert_eq!(requested_capabilities, vec![]),
            other => panic!("expected ProtocolHello, got {other:?}"),
        }
        write_frame(
            stream,
            &GuestResponse::ProtocolHelloAck {
                agent_protocol_version: PROTOCOL_VERSION,
                min_supported_version: MIN_SUPPORTED_PROTOCOL_VERSION,
                agent_version: "test-agent".to_string(),
                capabilities: vec![],
            },
        )
        .unwrap();
    }

    #[test]
    fn send_exec_streaming_collects_chunks_until_exit() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let guest_handle = std::thread::spawn(move || {
            answer_exec_protocol_hello(&mut guest);
            let req: GuestRequest = read_frame(&mut guest).unwrap();
            assert!(matches!(req, GuestRequest::Exec { ref command, .. } if command == "echo hi"));
            write_frame(
                &mut guest,
                &GuestResponse::ExecEvent(ExecEvent::Stdout {
                    chunk: b"hi\n".to_vec(),
                }),
            )
            .unwrap();
            write_frame(
                &mut guest,
                &GuestResponse::ExecEvent(ExecEvent::Exit { code: 0 }),
            )
            .unwrap();
        });

        let mut got: Vec<ExecEvent> = Vec::new();
        let terminal = send_exec_streaming(&mut host, "echo hi", None, Some(30), |e| got.push(e.clone()))
            .expect("send_exec_streaming");
        guest_handle.join().unwrap();

        assert_eq!(got.len(), 1);
        assert!(matches!(got[0], ExecEvent::Stdout { ref chunk } if chunk == b"hi\n"));
        assert!(matches!(terminal, ExecEvent::Exit { code: 0 }));
    }

    #[test]
    fn read_exec_stream_collects_until_exit() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let guest_handle = std::thread::spawn(move || {
            write_frame(
                &mut guest,
                &GuestResponse::ExecEvent(ExecEvent::Stderr {
                    chunk: b"e".to_vec(),
                }),
            )
            .unwrap();
            write_frame(
                &mut guest,
                &GuestResponse::ExecEvent(ExecEvent::Exit { code: 2 }),
            )
            .unwrap();
        });
        let mut got = Vec::new();
        let term = read_exec_stream(&mut host, |e| got.push(e.clone())).unwrap();
        guest_handle.join().unwrap();
        assert_eq!(got.len(), 1);
        assert!(matches!(got[0], ExecEvent::Stderr { ref chunk } if chunk == b"e"));
        assert!(matches!(term, ExecEvent::Exit { code: 2 }));
    }
}
