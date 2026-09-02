//! Wire request type: `GuestRequest`, the per-verb payload structs the
//! host issues over the vsock control channel, and its `kind_name()`
//! audit projection. Profile classification lives in `request_policy`.

use super::*;
use mvm_contract::stream::input::{CloseInput, InputFrame};
use serde::{Deserialize, Serialize};

/// Request sent from host to guest vsock agent.
///
/// `#[serde(deny_unknown_fields)]` is load-bearing: the guest agent
/// must refuse frames whose JSON contains
/// fields the deserializer doesn't recognise, on the principle that
/// silent acceptance of unknown fields is a deserialization-bug
/// gadget waiting to happen. Today every variant is a struct or
/// unit, so the attribute applies cleanly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum GuestRequest {
    /// Activation message for PID-1 initramfs boot.  Carries the
    /// dm-verity rootfs/runtime-overlay parameters and any custom
    /// volumes.  This is the only operational verb accepted before
    /// privilege drop in initramfs mode; every other request returns
    /// `NotActivated` until the agent has mounted the environment.
    ActivateEnvironment(ActivateEnvironment),

    /// Negotiate guest-agent protocol compatibility and capabilities
    /// before dispatching capability-dependent requests.
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
    /// Query the guest agent process's current resident memory.
    ResourceUsage,
    /// Query status of all managed integrations.
    IntegrationStatus,
    /// Checkpoint named integrations before sleep.
    /// Sent before SleepPrep so integrations can persist session state.
    CheckpointIntegrations { integrations: Vec<String> },
    /// Query status of all loaded probes.
    ProbeStatus,
    /// Query whether the workload has signalled "primed" (caches/JITs/model
    /// load done). The workload asserts it by creating the primed marker
    /// (`PRIMED_MARKER_PATH`); the agent reports its presence. Used by the
    /// host's warm-snapshot barrier to seal a deterministic, fully-warmed base.
    PrimedStatus,
    /// Run a command inside the guest (DevOnly, requires the runtime profile,
    /// signed verb grant, and SecurityPolicy).
    Exec {
        command: String,
        stdin: Option<String>,
        timeout_secs: Option<u64>,
    },
    /// Tier-2 batched exec (DevOnly): stage files, then run a sequence of
    /// argv commands in-guest in a single round-trip, returning one buffered
    /// outcome per command. The chain stops at the first non-zero exit. This is
    /// the one-round-trip counterpart to the host driving `FsWrite` + `Exec`
    /// frames itself; `peak_rss_kib` is agent-measured here. Answered by a
    /// single `ExecBatchResult` frame.
    ExecBatch {
        stages: Vec<StageFile>,
        commands: Vec<Vec<String>>,
        timeout_secs: Option<u64>,
    },
    /// Run the image's baked entrypoint program with the given stdin
    /// piped in and stdout/stderr captured.
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
    /// `EntrypointEvent::Error`. Output events carry bounded chunks;
    /// callers consume frames until the terminal event.
    ///
    /// Caps and timeouts are enforced agent-side. The wire
    /// frame size is bounded by `MAX_FRAME_SIZE`.
    RunEntrypoint {
        /// Bytes piped to the wrapper's stdin.
        stdin: Vec<u8>,
        /// Wall-clock timeout for the call, in seconds. The agent
        /// kills the wrapper on overrun and emits
        /// `EntrypointEvent::Error { kind: Timeout }`.
        timeout_secs: u64,
        /// Env vars injected into the workload after `env_clear()`
        /// (`HTTP_PROXY` + secret placeholder vars). Empty for
        /// a plain call; omitted on the wire defaults to empty.
        #[serde(default)]
        env: Vec<(String, String)>,
        /// Keep the workload's stdin open after `stdin` is written, so
        /// `StreamInput` frames can keep feeding it until `CloseStreamInput`.
        ///
        /// Off by default, and the host only turns it on for a plan that
        /// carries the input grant. It has to be a per-call decision rather
        /// than the agent's default: an entrypoint whose stdin stays open
        /// never sees EOF, so a `cat`-shaped workload under a host that
        /// forgot to close would run to its timeout instead of exiting.
        #[serde(default)]
        stream_input: bool,
    },
    /// Run one exact optional extension admitted and mounted at activation.
    /// The request carries identities and bounded stdin only; the executable,
    /// mount, environment, and resource ceilings are fixed by admission.
    RunExtension { dispatch: ExtensionDispatch },
    /// Cancel one exact active optional-extension invocation. There is no PID,
    /// signal, command, or cleanup selector on this surface.
    CancelExtension { cancellation: ExtensionCancellation },
    /// Run an arbitrary argv as a detached workload (dev-only).
    ///
    /// Mirrors how the image's `/init` runs its baked entrypoint, but
    /// driven from the agent and non-blocking: the agent spawns the
    /// program in its own session (`setsid`), with stdin from
    /// `/dev/null` and stdout/stderr on the guest console (which the
    /// host backend captures to `console.log`), returns an immediate
    /// `DetachedStarted { pid }` ack, and a reaper reports the
    /// workload's exit code to the host's workload-exit port when it
    /// finishes — so the VM powers off once the workload exits
    /// (docker `-d` semantics). Unlike `Exec`, the workload's lifetime
    /// is not bound to this request's connection.
    RunDetached {
        /// The program and its arguments. `argv[0]` is the program;
        /// resolved via PATH when not absolute.
        argv: Vec<String>,
        /// Env vars injected after `env_clear()` (plus a minimal safe
        /// base). Empty when omitted on the wire.
        #[serde(default)]
        env: Vec<(String, String)>,
    },
    /// Signal post-restore: rotate the VMGenID, then remount drives and
    /// restart services. `token` is the host-minted generation token for this
    /// resume; the guest feeds it to its `GenIdReseeder` so two clones of one
    /// snapshot reseed their CSPRNG to distinct state. An all-zero token (the
    /// `serde` default, used by no-rotation callers like template restore)
    /// means "no rotation" — the remount/restart still runs.
    PostRestore {
        #[serde(default)]
        token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
        /// Workload identity to install as the kernel hostname after a warm
        /// parent is restored into a named child. Legacy resume callers omit
        /// it and leave the current hostname unchanged.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        /// Host wall-clock epoch seconds to apply before the init restart
        /// hook. Omitted by legacy callers that do not request clock sync.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host_epoch_secs: Option<u64>,
        /// Host-minted verb-grant envelope to re-pin after restore. When
        /// the plan changes across a snapshot boundary the host delivers a
        /// fresh envelope here so the guest updates its pinned grant without
        /// a reboot. Absent on callers that do not rotate grants.
        #[serde(default)]
        grant_envelope: Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>,
    },
    /// Request filesystem diff (changes since boot, from overlay or snapshot).
    FsDiff,
    /// Bind a guest Unix socket and forward each accepted connection to a host
    /// vsock port. The guest path must live under `/run/mvm/` (see
    /// `validate_unix_forward_guest_path`).
    StartUnixSocketForward {
        guest_path: String,
        host_vsock_port: u32,
        socket_mode: u32,
    },
    /// Open an interactive PTY console session (dev-mode only).
    /// The guest allocates a PTY, spawns a shell, and listens on a
    /// dedicated vsock data port for raw byte streaming.
    ConsoleOpen {
        cols: u16,
        rows: u16,
        #[serde(default)]
        env: Vec<(String, String)>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        argv: Vec<String>,
    },
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
    /// can actually serve `RunEntrypoint`.
    /// Prod-safe — reveals no secrets, takes no inputs.
    EntrypointStatus,

    /// Query structured readiness across every guest subsystem
    /// (control plane, entrypoint, warm pool, integrations, probes,
    /// volumes) plus per-phase boot timings.
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
    // Filesystem RPC.
    //
    // Production-safe (unlike `Exec`): every verb is constrained by
    // the agent's uid 901 + read-only bind mounts + the
    // `mvm-core::crypto::policy::path` deny-list. Extending the
    // Filesystem paths remain constrained by the agent uid, read-only mounts,
    // and the path deny-list.
    // ========================================================================
    /// Read one bounded chunk from `path`, optionally starting at `offset`.
    /// Callers transfer larger files through repeated offset-addressed calls.
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
    /// Write one bounded chunk to `path`. Callers transfer larger files through
    /// repeated offset-addressed calls; only the first chunk truncates.
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
        /// Byte offset at which this chunk is written. Defaults to the start.
        #[serde(default)]
        offset: Option<u64>,
        /// Truncate before writing. Defaults to the original one-shot behavior.
        #[serde(default = "default_true")]
        truncate: bool,
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
    // Process control RPC.
    //
    // **Dev-only.** These verbs are the closest analog to the
    // established sandbox-runtime
    // `commands.start/list/signal/sendInput/wait/kill` API; they
    // exist for development and agent-driven workflows where the
    // user wants to launch arbitrary processes interactively.
    //
    // The wire types are compiled into every `mvm-agentd` build so a
    // host caller against a prod agent gets a typed
    // `ProcErrorKind::UnsupportedInProduction` rather than a
    // transport error. The agent-side handler lives in `crate::process_rpc`;
    // the dispatcher admits these requests only for a runtime profile and
    // signed grant that authorize DevOnly process control.
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
    /// (`--bounding-set=-all --no-new-privs`);
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
    // virtio-fs share mount control.
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
    /// virtio-fs tag string the device was created with — named to
    /// align with the `Volume` wire type.
    /// (Replaces the former `MountShare`.)
    MountVolume {
        volume_name: String,
        guest_path: String,
        read_only: bool,
    },
    /// Unmount a previously-mounted volume. `force = false`
    /// returns `EBUSY` when the kernel reports active fds; the
    /// caller passes `force = true` to demand a lazy detach.
    /// (Replaces the former `UnmountShare`.)
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
    /// interpreter. DevOnly — gated by the agent's runtime profile and
    /// signed grant, same fence as `Exec`. The host
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
    /// This call is stateless: each request spawns a fresh interpreter
    /// process, so `from foo import bar` in call 1 isn't visible in
    /// call 2.
    RunCode {
        code: String,
        timeout_secs: Option<u64>,
    },

    /// Deliver one host-admitted chunk of bytes to the running workload's
    /// stdin.
    ///
    /// Production-safe, and default-deny at the *host* end: these bytes have
    /// already passed the host's input gate, which refuses unless the signed
    /// `ExecutionPlan` carries the input grant, arbitrates a single-writer
    /// lease, and scans for the host's own secret material across frame
    /// boundaries. The guest cannot re-derive any of that, so it checks the
    /// one thing it can see locally — that `seq` advances past the last frame
    /// it delivered — and otherwise queues the bytes without waiting for the
    /// workload to read them.
    ///
    /// Only a call that opted into streamed input (`RunEntrypoint`'s
    /// `stream_input`) keeps its child's stdin open; anything else answers
    /// `StreamInputResult::Refused { kind: NoWorkload }`.
    StreamInput(InputFrame),

    /// End the workload's input stream: deliver the tail the host's gate
    /// withheld, then close the stdin fd.
    ///
    /// Closing the fd *is* the EOF — a flag or a sentinel byte would leave a
    /// read-to-EOF workload blocked on a `read` that never returns. The
    /// trailing bytes go first, because they are the writer's last ones and
    /// the close is what proved they were only ever a prefix of a secret.
    CloseStreamInput(CloseInput),
}

impl GuestRequest {
    /// Stable kebab-case verb name for this request — the value
    /// host-side audit emitters write into the
    /// `LocalAuditKind::NetworkPolicyAllow` detail format under
    /// `verb=<name>`. Invariant: every vsock RPC from host to guest
    /// emits one audit record so a forensic pass can reconstruct
    /// what the host asked the guest to do.
    ///
    /// The strings are wire-stable — a rename here is also a
    /// detail-format wire-format change. Pinned by
    /// `tests::kind_name_covers_every_variant`.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::ActivateEnvironment { .. } => "activate-environment",
            Self::ProtocolHello { .. } => "protocol-hello",
            Self::WorkerStatus => "worker-status",
            Self::SleepPrep { .. } => "sleep-prep",
            Self::Wake => "wake",
            Self::Ping => "ping",
            Self::ResourceUsage => "resource-usage",
            Self::IntegrationStatus => "integration-status",
            Self::CheckpointIntegrations { .. } => "checkpoint-integrations",
            Self::ProbeStatus => "probe-status",
            Self::PrimedStatus => "primed-status",
            Self::Exec { .. } => "exec",
            Self::ExecBatch { .. } => "exec-batch",
            Self::RunEntrypoint { .. } => "run-entrypoint",
            Self::RunExtension { .. } => "run-extension",
            Self::CancelExtension { .. } => "cancel-extension",
            Self::RunDetached { .. } => "run-detached",
            Self::PostRestore { .. } => "post-restore",
            Self::FsDiff => "fs-diff",
            Self::StartUnixSocketForward { .. } => "start-unix-socket-forward",
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
            Self::StreamInput(_) => "stream-input",
            Self::CloseStreamInput(_) => "close-stream-input",
        }
    }
}

/// Helper for `#[serde(default = "...")]` on `bool` fields where
/// `true` is the desired default (serde's `Default` trait yields
/// `false`).
fn default_true() -> bool {
    true
}
/// A file to stage into the guest before an [`GuestRequest::ExecBatch`] runs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct StageFile {
    pub path: String,
    pub content: Vec<u8>,
    pub mode: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

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
            GuestRequest::ResourceUsage,
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
            GuestRequest::PostRestore {
                token: [0u8; mvm_core::crypto::vmgenid::GENID_BYTES],
                hostname: None,
                host_epoch_secs: None,
                grant_envelope: None,
            },
            GuestRequest::FsDiff,
            GuestRequest::StartUnixSocketForward {
                guest_path: "/run/mvm/forward.sock".to_string(),
                host_vsock_port: BROKER_PORT,
                socket_mode: 0o600,
            },
            GuestRequest::ConsoleOpen {
                cols: 120,
                rows: 40,
                env: Vec::new(),
                argv: Vec::new(),
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
                offset: None,
                truncate: true,
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
    fn post_restore_token_roundtrips_and_defaults_to_zero() {
        use mvm_core::crypto::vmgenid::GENID_BYTES;

        // A non-zero generation token survives the JSON round-trip intact.
        let req = GuestRequest::PostRestore {
            token: [9u8; GENID_BYTES],
            hostname: Some("worker-9".to_string()),
            host_epoch_secs: Some(1_717_000_000),
            grant_envelope: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        match serde_json::from_str::<GuestRequest>(&json).unwrap() {
            GuestRequest::PostRestore {
                token,
                hostname,
                host_epoch_secs,
                ..
            } => {
                assert_eq!(token, [9u8; GENID_BYTES]);
                assert_eq!(hostname.as_deref(), Some("worker-9"));
                assert_eq!(host_epoch_secs, Some(1_717_000_000));
            }
            other => panic!("expected PostRestore, got {other:?}"),
        }

        // An omitted token (no-rotation caller / template restore) defaults to
        // the all-zero "no rotation" token rather than failing to parse.
        match serde_json::from_str::<GuestRequest>(r#"{"PostRestore":{}}"#).unwrap() {
            GuestRequest::PostRestore { token, .. } => assert_eq!(token, [0u8; GENID_BYTES]),
            other => panic!("expected PostRestore, got {other:?}"),
        }

        // `deny_unknown_fields` is load-bearing: an unexpected field fails closed.
        assert!(
            serde_json::from_str::<GuestRequest>(r#"{"PostRestore":{"bogus":1}}"#).is_err(),
            "unknown field must be rejected"
        );
    }

    /// Regression: every new FS variant rejects unknown
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

    /// Regression: every new Proc variant rejects unknown
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

    /// Regression: every new Volume variant rejects unknown
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
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if file_name.starts_with('.') {
                continue;
            }
            let bytes = std::fs::read(&path).expect("read seed");
            // Tolerate an optional trailing newline editors add.
            let trimmed = bytes.trim_ascii_end().to_vec();
            serde_json::from_slice::<GuestRequest>(&trimmed)
                .unwrap_or_else(|e| panic!("seed {} failed to parse: {e}", path.display()));
            count += 1;
        }
        // 4 baseline (ping, run-entrypoint, sleep-prep, worker-status) +
        // 7 fs-* + 6 proc-* + 2 share-* = 19.
        assert!(count >= 19, "expected ≥19 corpus seeds, got {count}");
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
                offset,
                truncate,
                ..
            } => {
                assert!(
                    !follow_symlinks,
                    "FsWrite must NOT follow symlinks by default"
                );
                assert!(!create_parents, "create_parents defaults to false");
                assert_eq!(offset, None, "offset defaults to the beginning of the file");
                assert!(truncate, "legacy one-shot writes truncate by default");
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

    /// Regression: unknown fields in a `GuestRequest` JSON frame must be
    /// rejected outright. Without `deny_unknown_fields`, an attacker could
    /// smuggle extra keys past serde to (a) trip up downstream consumers that
    /// re-parse the same blob, (b) probe for upcoming variants, or (c) create
    /// drift between versions of the agent and host.
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

    // -------------------------------------------------------------------
    // RunEntrypoint wire protocol
    // -------------------------------------------------------------------

    #[test]
    fn test_run_entrypoint_request_roundtrip() {
        let req = GuestRequest::RunEntrypoint {
            stdin: vec![1, 2, 3, 4, 5],
            timeout_secs: 30,
            env: vec![("HTTP_PROXY".into(), "http://127.0.0.1:18080".into())],
            stream_input: false,
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let decoded: GuestRequest = serde_json::from_str(&json).expect("deserialize");
        match decoded {
            GuestRequest::RunEntrypoint {
                stdin,
                timeout_secs,
                env,
                stream_input,
            } => {
                assert!(!stream_input, "the default call closes stdin");
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

    // -------------------------------------------------------------------
    // RunDetached wire protocol
    // -------------------------------------------------------------------

    #[test]
    fn test_run_detached_request_roundtrip() {
        let req = GuestRequest::RunDetached {
            argv: vec!["/bin/sh".into(), "-lc".into(), "true".into()],
            env: vec![("FOO".into(), "bar".into())],
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let decoded: GuestRequest = serde_json::from_str(&json).expect("deserialize");
        match decoded {
            GuestRequest::RunDetached { argv, env } => {
                assert_eq!(argv, vec!["/bin/sh", "-lc", "true"]);
                assert_eq!(env, vec![("FOO".into(), "bar".into())]);
            }
            other => panic!("expected RunDetached, got {other:?}"),
        }
    }

    #[test]
    fn test_run_detached_request_env_defaults_empty_when_omitted() {
        // `env` is `#[serde(default)]`: a frame without it decodes to an
        // empty env, matching the fuzz-seed shape.
        let json = r#"{"RunDetached":{"argv":["/bin/sh","-lc","true"]}}"#;
        let decoded: GuestRequest = serde_json::from_str(json).expect("deserialize");
        match decoded {
            GuestRequest::RunDetached { argv, env } => {
                assert_eq!(argv, vec!["/bin/sh", "-lc", "true"]);
                assert!(env.is_empty());
            }
            other => panic!("expected RunDetached, got {other:?}"),
        }
    }

    #[test]
    fn test_run_detached_request_rejects_unknown_field() {
        let json = r#"{"RunDetached":{"argv":["/bin/true"],"env":[],"oops":1}}"#;
        let err = serde_json::from_str::<GuestRequest>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
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
            stream_input: false,
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
        // deserializer.
        let json = r#"{"RunEntrypoint":{"stdin":[1,2,3],"timeout_secs":10,"smuggled":"x"}}"#;
        let err = serde_json::from_str::<GuestRequest>(json).unwrap_err();
        assert!(
            err.to_string().contains("unknown field") && err.to_string().contains("smuggled"),
            "expected 'unknown field `smuggled`', got: {err}"
        );
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
    // EntrypointStatus query
    // -------------------------------------------------------------------

    #[test]
    fn test_entrypoint_status_request_roundtrip() {
        let req = GuestRequest::EntrypointStatus;
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#""EntrypointStatus""#);
        let decoded: GuestRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, GuestRequest::EntrypointStatus));
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
    fn test_guest_request_sleep_prep_fields() {
        let req = GuestRequest::SleepPrep {
            drain_timeout_secs: 45,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("45"));
        assert!(json.contains("SleepPrep"));
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

    // ========================================================================
    // `GuestRequest::kind_name` for vsock RPC audit
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
            (GuestRequest::ResourceUsage, "resource-usage"),
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
                    stream_input: false,
                },
                "run-entrypoint",
            ),
            (
                GuestRequest::StreamInput(InputFrame {
                    seq: 0,
                    payload: Vec::new(),
                }),
                "stream-input",
            ),
            (
                GuestRequest::CloseStreamInput(CloseInput::default()),
                "close-stream-input",
            ),
            (
                GuestRequest::PostRestore {
                    token: [0u8; mvm_core::crypto::vmgenid::GENID_BYTES],
                    hostname: None,
                    host_epoch_secs: None,
                    grant_envelope: None,
                },
                "post-restore",
            ),
            (GuestRequest::FsDiff, "fs-diff"),
            (
                GuestRequest::StartUnixSocketForward {
                    guest_path: "/run/mvm/forward.sock".to_string(),
                    host_vsock_port: BROKER_PORT,
                    socket_mode: 0o600,
                },
                "start-unix-socket-forward",
            ),
            (
                GuestRequest::ConsoleOpen {
                    cols: 0,
                    rows: 0,
                    env: Vec::new(),
                    argv: Vec::new(),
                },
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
                    offset: None,
                    truncate: true,
                },
                "fs-write",
            ),
        ];
        for (req, expected) in cases {
            assert_eq!(req.kind_name(), *expected, "verb name for {req:?}");
        }
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
    fn exec_batch_wire_types_deny_unknown_fields() {
        // StageFile + ExecOutcomeWire fail closed on a smuggled extra field.
        assert!(
            serde_json::from_str::<StageFile>(r#"{"path":"/a","content":[],"mode":420,"x":1}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<ExecOutcomeWire>(
                r#"{"status":0,"stdout":[],"stderr":[],"duration_ms":0,"peak_rss_kib":null,"x":1}"#
            )
            .is_err()
        );
    }

    #[test]
    fn console_open_missing_argv_defaults_empty() {
        let req: GuestRequest =
            serde_json::from_str(r#"{"ConsoleOpen":{"cols":80,"rows":24,"env":[]}}"#)
                .expect("legacy console-open request should deserialize");
        match req {
            GuestRequest::ConsoleOpen { argv, .. } => assert!(argv.is_empty()),
            other => panic!("expected ConsoleOpen, got {other:?}"),
        }
    }

    #[test]
    fn console_open_preserves_explicit_argv() {
        let req = GuestRequest::ConsoleOpen {
            cols: 80,
            rows: 24,
            env: Vec::new(),
            argv: vec!["/bin/sh".to_string()],
        };
        let json = serde_json::to_string(&req).expect("serialize console-open");
        assert!(
            json.contains(r#""argv":["/bin/sh"]"#),
            "serialized request should carry argv: {json}"
        );
        let parsed: GuestRequest = serde_json::from_str(&json).expect("deserialize console-open");
        match parsed {
            GuestRequest::ConsoleOpen { argv, .. } => {
                assert_eq!(argv, vec!["/bin/sh".to_string()]);
            }
            other => panic!("expected ConsoleOpen, got {other:?}"),
        }
    }

    #[test]
    fn activate_environment_kind_name_is_kebab_case() {
        use crate::vsock::{ActivateEnvironment, RootfsConfig, RuntimeOverlayConfig};
        let req = GuestRequest::ActivateEnvironment(ActivateEnvironment {
            rootfs: RootfsConfig {
                data_dev: "/dev/vda".to_string(),
                hash_dev: Some("/dev/vdb".to_string()),
                roothash: Some("a".repeat(64)),
                virtiofs_tag: None,
                in_place: false,
            },
            runtime: Some(RuntimeOverlayConfig {
                data_dev: "/dev/vdc".to_string(),
                hash_dev: "/dev/vdd".to_string(),
                roothash: "b".repeat(64),
            }),
            volumes: Vec::new(),
            extensions: Vec::new(),
            verb_grant_envelope: None,
        });
        assert_eq!(req.kind_name(), "activate-environment");
    }

    #[test]
    fn run_extension_has_no_command_or_host_authority() {
        let request = serde_json::json!({
            "RunExtension": { "dispatch": {
                "extension_id": "org.example.extension",
                "pack_digest": vec![1; 32],
                "contract_digest": vec![2; 32],
                "request_id": "mvm-request-1",
                "session_id": "session-1",
                "campaign_id": "campaign-1",
                "trial_id": "trial-1",
                "plan_id": "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "idempotency_key": "trial-key-1",
                "grant_digest": format!("sha256:{}", "b".repeat(64)),
                "nonce": "nonce-1",
                "input": [123, 125]
            }}
        });
        let parsed: GuestRequest = serde_json::from_value(request.clone()).expect("strict request");
        assert_eq!(parsed.kind_name(), "run-extension");
        assert_eq!(parsed.class(), RequestClass::ProdSafe);
        let encoded = serde_json::to_string(&parsed).expect("encode");
        for forbidden in ["command", "argv", "env", "host_path", "destination"] {
            assert!(!encoded.contains(forbidden), "{encoded}");
        }

        let mut forged = request;
        forged["RunExtension"]["dispatch"]["command"] = serde_json::json!("/bin/sh");
        assert!(serde_json::from_value::<GuestRequest>(forged).is_err());
    }

    #[test]
    fn cancel_extension_is_identity_only_and_rejects_process_authority() {
        let request = serde_json::json!({
            "CancelExtension": { "cancellation": {
                "extension_id": "org.example.extension",
                "pack_digest": vec![1; 32],
                "contract_digest": vec![2; 32],
                "request_id": "mvm-request-1",
                "session_id": "session-1",
                "campaign_id": "campaign-1",
                "trial_id": "trial-1",
                "plan_id": "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "idempotency_key": "trial-key-1",
                "grant_digest": format!("sha256:{}", "b".repeat(64)),
                "nonce": "nonce-1"
            }}
        });
        let parsed: GuestRequest = serde_json::from_value(request.clone()).expect("strict request");
        assert_eq!(parsed.kind_name(), "cancel-extension");
        assert_eq!(parsed.class(), RequestClass::ProdSafe);
        let encoded = serde_json::to_string(&parsed).expect("encode");
        for forbidden in ["pid", "signal", "command", "path", "cleanup"] {
            assert!(!encoded.contains(forbidden), "{encoded}");
        }

        let mut forged = request;
        forged["CancelExtension"]["cancellation"]["signal"] = serde_json::json!(9);
        assert!(serde_json::from_value::<GuestRequest>(forged).is_err());
    }
}
