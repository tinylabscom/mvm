//! Per-verb-family response payload types: process control, filesystem
//! RPC, and entrypoint/exec event streams.

use super::*;
use serde::{Deserialize, Serialize};

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
    /// Returned by prod builds whose handler module was stripped.
    /// Lets SDK callers branch on capability.
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
    /// A streaming resource is throttled.
    /// **Non-terminal.** The agent emits this on the rising edge of
    /// a backpressure condition — typically the host-side stdout/
    /// stderr buffer crossing its high-water mark. The wait loop
    /// continues; subsequent `Stdout` / `Stderr` / terminal events
    /// signal that flow has resumed.
    ///
    /// `detail` is a bounded, redacted human-readable hint
    /// (operator-facing). It **never** carries argv, env, stdin,
    /// stdout, stderr, or filesystem paths — that's the payload
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
///
/// `Stdout` / `Stderr` carry bytes from the wrapper's respective
/// streams. `Exit` and `Error` are terminal — they end the response
/// stream for one call. The agent emits exactly one terminal event
/// per call.
///
/// Buffered output is split into bounded `Stdout` and `Stderr` events without
/// changing the protocol shape: the host reads frames until terminal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum EntrypointEvent {
    /// Bytes from the wrapper's stdout.
    Stdout { chunk: Vec<u8> },
    /// Bytes from the wrapper's stderr.
    Stderr { chunk: Vec<u8> },
    /// One control-channel record from the wrapper's fd-3.
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
    /// **Wiring status:** the variant ships ahead of any
    /// emitter. Agents at this version do not yet open fd-3 in the
    /// child or emit `Control` events; later work lands fd-3 wiring in
    /// the cold path (`execute()`), then the warm-process
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
/// One command's buffered outcome from an [`GuestRequest::ExecBatch`]. Agent-
/// measured: `duration_ms` is the in-guest wall-clock and `peak_rss_kib` the
/// `getrusage` high-water mark when the guest can report it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ExecOutcomeWire {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_ms: u64,
    pub peak_rss_kib: Option<u64>,
}
/// One event in the response stream of an `Exec` call (interactive only).
/// The agent emits a sequence of these for a single `Exec` request,
/// terminated by `Exit`. The host reads frames in a loop until terminal.
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
    /// commands.
    TimedOut,
}

impl ExecEvent {
    /// True if this event terminates the `Exec` response stream.
    pub fn is_terminal(&self) -> bool {
        matches!(self, ExecEvent::Exit { .. } | ExecEvent::TimedOut)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // `Backpressure` is non-terminal.
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

    /// The `Backpressure` variant
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

    #[test]
    fn test_fs_change_rejects_unknown_field() {
        let json = r#"{"path":"/x","kind":"created","size":0,"hidden":42}"#;
        let err = serde_json::from_str::<FsChange>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
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
        // arrives. Wire-shape lock-in.
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

    #[test]
    fn exec_batch_result_roundtrips_and_maps_to_variant() {
        let r = GuestResponse::ExecBatchResult {
            outcomes: vec![ExecOutcomeWire {
                status: 0,
                stdout: b"ok".to_vec(),
                stderr: Vec::new(),
                duration_ms: 12,
                peak_rss_kib: Some(2048),
            }],
        };
        let back: GuestResponse = serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
        assert!(matches!(
            back,
            GuestResponse::ExecBatchResult { ref outcomes }
                if outcomes.len() == 1 && outcomes[0].duration_ms == 12
                    && outcomes[0].peak_rss_kib == Some(2048)
        ));
        assert_eq!(r.variant(), ResponseVariant::ExecBatchResult);
    }
}
