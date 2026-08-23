//! Guest agent vsock protocol: wire types (`GuestRequest`/`GuestResponse`),
//! framing, verb-grant enforcement, and the RPC helpers every host-side
//! caller (and the in-guest agent) use to talk over the control channel.
//!
//! Submodules mirror the protocol's layers: `request`/`response` are the
//! wire types, `response_payloads` holds the per-verb-family payload
//! structs, `framing` is the length-prefixed + authenticated envelope,
//! `connection` is the vsock UDS dial path, `rpc` is the contract-checked
//! call layer, `verb_grant` is grant verification/enforcement, and `api`
//! is the host-facing convenience surface built on all of the above.

use std::time::Duration;

mod activation;
mod api;
mod connection;
mod framing;
mod request;
mod request_policy;
mod response;
mod response_payloads;
mod rpc;
/// AF_VSOCK socket primitives shared by the guest's synchronous vsock sites
/// (forward-proxy dial, exit reporter, builder-agent listener). Linux-only;
/// an empty module elsewhere. Public so the one-shot guest bins can reach it.
pub mod sys;
mod verb_grant;
mod workload_privilege;

pub use activation::{
    ActivateEnvironment, ExtensionCancellation, ExtensionConfig, ExtensionDispatch, RootfsConfig,
    RuntimeOverlayConfig, VolumeConfig, VolumeConfigKind,
};
pub use api::{
    PRIMED_MARKER_PATH, PostRestoreReply, checkpoint_integrations, interpret_primed_status,
    mount_volume_on, ping, ping_at, post_restore_at, post_restore_with_grant_and_clock_at,
    post_restore_with_grant_at, query_fs_diff, query_fs_diff_at, query_fs_diff_on,
    query_integration_status, query_integration_status_at, query_primed_at, query_probe_status,
    query_probe_status_at, query_resource_usage, query_resource_usage_at, query_worker_status,
    query_worker_status_at, request_sleep_prep, send_fs_request, send_fs_request_on,
    send_proc_request, send_proc_request_on, send_proc_wait, send_proc_wait_on, signal_wake,
    workload_is_primed_at,
};
pub use connection::{
    HOST_CID, connect_host_vsock, connect_to, connect_to_port, connect_to_port_once, send_request,
    send_request_stream, vsock_uds_path,
};
pub use framing::{
    AuthenticatedSession, handshake_as_guest, handshake_as_host, read_authenticated_frame,
    read_frame, verify_authenticated_frame, write_authenticated_frame, write_frame,
};
pub use request::{GuestRequest, StageFile};
pub use request_policy::RequestClass;
pub use response::{
    BootTimingReport, ComponentState, GuestCapability, GuestResponse, ProtocolNegotiation,
    ProtocolUpgradeAction, ReadinessReport, ResponseContract, ResponseKind, ResponseVariant,
    RunEntrypointError, TrafficPlane, Verb, VolumeMountErrorKind, VolumeMountResult,
    protocol_hello_response, supported_capabilities,
};
pub use response_payloads::{
    EntrypointEvent, ExecEvent, ExecOutcomeWire, FsChange, FsChangeKind, FsEntry, FsEntryKind,
    FsErrorKind, FsResult, FsStat, ProcErrorKind, ProcInfo, ProcResult, ProcState, ProcWaitEvent,
    StreamInputRefusal, StreamInputResult,
};
pub use rpc::{
    ControlSession, RpcError, RunEntrypointCall, call_streaming, call_unary, check_response,
    negotiate_protocol, probe_agent_ready, read_exec_stream, require_capabilities,
    send_cancel_extension, send_close_stream_input, send_exec_streaming, send_run_code_streaming,
    send_run_detached, send_run_entrypoint, send_run_extension, send_stream_input,
};
pub use verb_grant::{
    HOST_SIGNER_PUB_CMDLINE_KEY, HOST_SIGNER_PUBKEY_PATH, TrustDecision, VERB_TRUST_POLICY_PATH,
    enforce_verb_grant, host_signer_pub_token, is_verb_trust_baseline, launch_requires_grant,
    load_host_signer_verifying_key, load_pinned_verb_grant, load_verb_trust_policy,
    parse_require_grant_cmdline, pin_verb_grant, provision_host_signer_anchor_from_cmdline,
    re_pin_verb_grant, trust_decision, verifying_key_from_hex, write_host_signer_anchor,
};
pub use workload_privilege::{current_uid, workload_privilege_refusal};

/// Default vsock guest CID (Firecracker convention).
pub const GUEST_CID: u32 = 3;

/// Port the guest vsock agent listens on.
///
/// **Why 5252 (and why not <1024).** Linux gates `bind(2)` on AF_VSOCK
/// ports ≤ 1023 behind `CAP_NET_BIND_SERVICE` — the same way it gates
/// AF_INET. The agent runs as uid 901 with `--bounding-set=-all`,
/// so it has no caps to spend on a privileged port.
/// Any port < 1024 would force us to either grant the agent
/// `CAP_NET_BIND_SERVICE` (weakening the no-caps posture to work around
/// port choice) or bind in init and pass the fd in (extra surface for no
/// architectural benefit). Port 52 was picked when the agent ran as
/// root and the codebase incorrectly assumed vsock binds were
/// unprivileged on Linux — see the corrected comment in
/// `nix/lib/minimal-init/default.nix::guestAgentBlock`.
///
/// 5252 sits clearly above 1023 and below the console-data range
/// (`CONSOLE_PORT_BASE` = 20_000), so the host-side proxy allowlist
/// keeps its disjoint-union shape. The "52" tail is a
/// callback to the historical port for grep-ability.
///
/// **Single source of truth.** All host-side code refers to this constant
/// (`mvm-runtime` depends on `mvm-agentd`, so no duplicate is needed).
pub const GUEST_AGENT_PORT: u32 = 5252;

/// Control vsock port the guest's `/init` connects to (host side) to
/// report a one-shot workload's exit code before `poweroff -f`. The host
/// supervisor binds the listener (`add_vsock_port2(listen=false)`). Wire
/// format: a single 4-byte little-endian `i32`.
pub const WORKLOAD_EXIT_PORT: u32 = 5251;

/// vsock port of the **host egress gateway**  — the single host-mediated
/// egress chokepoint. The in-guest egress client connects here; the host's per-VM
/// gateway makes the claim-10 allow/deny decision and proxies the flow, and for a
/// bound-secret destination performs the claims-12/13 credential substitution (a
/// *behavior* of this one gateway, not a separate channel — this port was always
/// host-mediated egress, formerly named `EGRESS_PORT`). Each microVM has its
/// own vsock; this is a fixed well-known service number reused per VM, not a secret.
/// NOTE: exposing it end-to-end needs the host-side proxy port-allowlist to admit it.
pub const EGRESS_PORT: u32 = mvm_contract::protocol::network_flow::NETWORK_FLOW_PORT;

// A compile-time proof rather than a test: the guest dials this port and the
// host binds it from `mvm_net::GuestService::NetworkFlow`. Both derive from the
// contract constant, so drift is not expressible — this pins the value the
// derivation must land on.
const _: () = assert!(EGRESS_PORT == 5253);

/// vsock port the host-services broker is exposed on. The in-guest broker
/// client ([`crate::broker_client`]) dials this to reach the supervisor's
/// guest-facing broker listener, which derives the workload identity from the
/// connection, enforces the `ExecutionPlan.services` binding, and proxies the
/// `ServiceCall` to the `mvm-broker` subprocess. The host admits it via its
/// `host_listen_ports` allowlist — a one-port, audited widening, the same
/// mechanism [`EGRESS_PORT`] uses.
///
/// 5300 sits above the privileged range and above 5251/5252/5253, and below
/// the console-data range ([`CONSOLE_PORT_BASE`] = 20_000), so the host-side proxy
/// allowlist keeps its disjoint-union shape. It reuses the number the
/// pre-broker secrets channel once held (that channel was removed), so there
/// is no live collision.
pub const BROKER_PORT: u32 = 5300;

/// Base vsock port for interactive console PTY sessions.
pub const CONSOLE_PORT_BASE: u32 = 20000;

/// How many interactive-console data ports a dev-accessible VM pre-opens.
/// The guest agent allocates `CONSOLE_PORT_BASE + session_id` per
/// `ConsoleOpen`, with `session_id` incrementing monotonically over the VM's
/// life (one active session at a time), so this bounds the number of console
/// attaches before the pre-opened range is exhausted.
pub const DEV_CONSOLE_DATA_PORT_COUNT: u32 = 128;

/// The host-side console data-port range a dev-accessible VM pre-opens so an
/// interactive PTY (`machine run -t`, `machine shell`, `up --console`) can
/// reach the agent-allocated `CONSOLE_PORT_BASE + session_id` data channel.
///
/// The per-port-UDS backends (libkrun, HVF) bind a *static* vsock port list at
/// start, so a dynamic data port is unreachable unless it was pre-declared;
/// Firecracker multiplexes every port over one UDS and ignores this range.
pub fn dev_console_data_ports() -> impl Iterator<Item = u32> {
    (1..=DEV_CONSOLE_DATA_PORT_COUNT).map(|offset| CONSOLE_PORT_BASE + offset)
}

/// Default connect/read timeout in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Current guest-agent control protocol version.
///
/// This is distinct from `PROTOCOL_VERSION_AUTHENTICATED`, which
/// versions the signed envelope used by authenticated frame wrappers.
/// `PROTOCOL_VERSION` versions the `GuestRequest` / `GuestResponse`
/// control surface served by `mvm-guest-agent`.
pub const PROTOCOL_VERSION: u32 = 2;

/// Oldest guest-agent control protocol this host can speak.
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 2;

/// Maximum response frame size (256 KiB).
pub const MAX_FRAME_SIZE: usize = 256 * 1024;

/// Worst-case bytes one payload byte costs once `serde_json` has written it as
/// a decimal element of a `Vec<u8>` array: `255,`.
const JSON_BYTE_ARRAY_WORST_CASE: usize = 4;

/// How far a payload byte expands between the handler and the wire.
///
/// One hop: the `GuestRequest` / `GuestResponse` body, where content is a
/// `Vec<u8>` and `serde_json` writes it as an integer array. The envelope
/// around that body is binary — `SealedFrame::encode` — so the ciphertext
/// crosses no second JSON encoding.
///
/// It used to. When the envelope was JSON as well, this was `4 * 4` and the
/// cap below was a quarter of what it is now, because a `Vec<u8>` ciphertext
/// was itself re-encoded as an integer array. Sizing against a single hop
/// while the wire charged for two is what let a stdout chunk pass the
/// handler's own [`MAX_FRAME_SIZE`] check and then fail the identical check on
/// the envelope.
const SEALED_ENVELOPE_EXPANSION: usize = JSON_BYTE_ARRAY_WORST_CASE;

/// Room reserved for everything in the frame that is not content: the body's
/// own variant tags and field names, and the binary envelope's fixed header —
/// session id, sequence, timestamp, signer id, signature — plus the GCM tag.
/// Generous on purpose: over-reserving costs a slightly smaller chunk, and
/// under-reserving costs a dead session.
const SEALED_ENVELOPE_OVERHEAD: usize = 8 * 1024;

/// Maximum raw user-content bytes placed in one data-plane frame.
///
/// Derived from what the wire can actually carry rather than picked: a chunk
/// this size fits under [`MAX_FRAME_SIZE`] after the body encoding.
/// `sealed_worst_case_chunk_fits_the_frame_cap` exercises it against the real
/// envelope.
pub const MAX_DATA_CHUNK_SIZE: usize =
    (MAX_FRAME_SIZE - SEALED_ENVELOPE_OVERHEAD) / SEALED_ENVELOPE_EXPANSION;

// A chunk must survive the body encoding with the envelope still inside the
// cap. Stated as a build-time assertion so a future edit to either constant
// cannot silently reintroduce a chunk size the wire will not carry.
const _: () = assert!(
    MAX_DATA_CHUNK_SIZE * SEALED_ENVELOPE_EXPANSION + SEALED_ENVELOPE_OVERHEAD <= MAX_FRAME_SIZE
);

/// Largest encoded sealed frame the control plane accepts off the wire.
///
/// Bounds the binary envelope, not the plaintext inside it: [`MAX_FRAME_SIZE`]
/// caps the `GuestRequest` / `GuestResponse` body, and the envelope adds the
/// GCM tag and its fixed header on top of that.
pub const MAX_SEALED_FRAME_SIZE: usize = MAX_FRAME_SIZE + SEALED_ENVELOPE_OVERHEAD;

/// Number of transport reconnect attempts before giving up.
const CONNECT_RETRIES: u32 = 4;

/// Base delay for exponential reconnect backoff.
const CONNECT_RETRY_BASE_DELAY_MS: u64 = 100;

/// Cap for exponential reconnect backoff.
const CONNECT_RETRY_CAP_DELAY_MS: u64 = 500;

/// Base delay for the adaptive readiness-poll backoff. The first poll
/// after a failed attempt waits this long.
const ADAPTIVE_BACKOFF_BASE_MS: u64 = 20;

/// Cap for the adaptive readiness-poll backoff — the historical fixed
/// poll interval. Backoff grows from [`ADAPTIVE_BACKOFF_BASE_MS`] up to
/// this ceiling so a slow guest still polls at the old steady cadence.
const ADAPTIVE_BACKOFF_CAP_MS: u64 = 500;

/// Adaptive backoff delay for the `mvmctl up` readiness poll.
/// `attempt` is 0-based: attempt 0 waits the
/// base, each subsequent attempt doubles, capped at
/// `ADAPTIVE_BACKOFF_CAP_MS`. This replaces a fixed 500 ms sleep that
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_console_data_ports_cover_the_expected_range() {
        let ports: Vec<u32> = dev_console_data_ports().collect();
        assert_eq!(ports.len(), DEV_CONSOLE_DATA_PORT_COUNT as usize);
        assert_eq!(ports.first().copied(), Some(CONSOLE_PORT_BASE + 1));
        assert_eq!(
            ports.last().copied(),
            Some(CONSOLE_PORT_BASE + DEV_CONSOLE_DATA_PORT_COUNT)
        );
        // Disjoint from the agent + control ports (no allowlist overlap).
        assert!(!ports.contains(&GUEST_AGENT_PORT));
        assert!(!ports.contains(&CONSOLE_PORT_BASE));
    }

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
    fn test_constants() {
        assert_eq!(GUEST_CID, 3);
        // Must stay > 1023 — vsock binds <= 1023 require
        // CAP_NET_BIND_SERVICE, which the agent (uid 901) doesn't have.
        // See the doc comment on GUEST_AGENT_PORT.
        const _: () = assert!(GUEST_AGENT_PORT > 1023);
        assert_eq!(GUEST_AGENT_PORT, 5252);
        assert_eq!(DEFAULT_TIMEOUT_SECS, 10);
    }

    #[test]
    fn test_max_frame_size() {
        assert_eq!(MAX_FRAME_SIZE, 256 * 1024);
    }

    #[test]
    fn workload_exit_port_is_distinct_and_reserved() {
        assert_eq!(WORKLOAD_EXIT_PORT, 5251);
        assert_ne!(WORKLOAD_EXIT_PORT, GUEST_AGENT_PORT);
        const { assert!(WORKLOAD_EXIT_PORT < CONSOLE_PORT_BASE) }
    }
}
