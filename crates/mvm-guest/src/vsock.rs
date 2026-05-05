use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mvm_core::security::{
    AuthenticatedFrame, PROTOCOL_VERSION_AUTHENTICATED, SessionHello, SessionHelloAck,
};
use mvm_core::signing::SignedPayload;
use serde::{Deserialize, Serialize};

/// Default vsock guest CID (Firecracker convention).
pub const GUEST_CID: u32 = 3;

/// Port the guest vsock agent listens on.
pub const GUEST_AGENT_PORT: u32 = 52;

/// Base vsock port for TCP port forwarding.
/// The forwarded vsock port = `PORT_FORWARD_BASE + guest_tcp_port`.
pub const PORT_FORWARD_BASE: u32 = 10000;

/// Base vsock port for interactive console PTY sessions.
pub const CONSOLE_PORT_BASE: u32 = 20000;

/// Default connect/read timeout in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Maximum response frame size (256 KiB).
const MAX_FRAME_SIZE: usize = 256 * 1024;

/// Number of CONNECT handshake retries before giving up.
const CONNECT_RETRIES: u32 = 3;

/// Delay between CONNECT handshake retries.
const CONNECT_RETRY_DELAY_MS: u64 = 500;

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
pub enum GuestRequest {
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
}

/// Response from guest vsock agent to host.
///
/// Same `deny_unknown_fields` discipline as `GuestRequest` — a
/// compromised guest must not be able to slip extra fields past the
/// host's deserializer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum GuestResponse {
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
    /// Result of an Exec request.
    ExecResult {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    /// One event in the response stream of a `RunEntrypoint` call.
    /// ADR-007 / plan 41 W1.
    ///
    /// The agent emits a sequence of these in response to a single
    /// `RunEntrypoint` request, terminated by an `EntrypointEvent`
    /// whose `is_terminal` returns true (`Exit` or `Error`). The
    /// host reads frames in a loop until terminal.
    EntrypointEvent(EntrypointEvent),
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
}

/// A single filesystem change detected since boot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
pub enum EntrypointEvent {
    /// Bytes from the wrapper's stdout.
    Stdout { chunk: Vec<u8> },
    /// Bytes from the wrapper's stderr.
    Stderr { chunk: Vec<u8> },
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

/// Kind of agent-side error reported via `EntrypointEvent::Error`.
/// ADR-007 / plan 41 W1.
///
/// The variants are deliberately coarse — the host correlates by
/// `kind` and surfaces the human-readable `message` to the operator.
/// Adding a variant is a wire change; renaming or removing is a
/// breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// `/etc/mvm/entrypoint` is missing, fails validation
    /// (symlink crossing FS, wrong perms, off the verity
    /// partition), or otherwise can't be loaded. Reported per-call
    /// even though the validation runs at agent boot.
    EntrypointInvalid,
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
    mut on_event: F,
) -> Result<EntrypointEvent>
where
    F: FnMut(&EntrypointEvent),
{
    let req = GuestRequest::RunEntrypoint {
        stdin,
        timeout_secs,
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

/// Execute a command inside the guest via vsock at a specific UDS path (dev-only).
pub fn exec_at(
    vsock_uds_path: &str,
    command: &str,
    stdin: Option<String>,
    timeout_secs: u64,
) -> Result<GuestResponse> {
    let mut stream = connect_to(vsock_uds_path, timeout_secs)?;
    send_request(
        &mut stream,
        &GuestRequest::Exec {
            command: command.to_string(),
            stdin,
            timeout_secs: Some(timeout_secs),
        },
    )
}

/// Query filesystem diff from the guest agent at a specific UDS path.
///
/// Returns the list of filesystem changes since boot (created, modified,
/// deleted files). The guest agent walks the overlay filesystem to compute
/// the diff.
pub fn query_fs_diff(instance_dir: &str) -> Result<Vec<FsChange>> {
    let mut stream = connect(instance_dir, DEFAULT_TIMEOUT_SECS)?;
    let resp = send_request(&mut stream, &GuestRequest::FsDiff)?;

    match resp {
        GuestResponse::FsDiffResult { changes } => Ok(changes),
        GuestResponse::Error { message } => {
            bail!("Guest fs-diff error: {}", message);
        }
        _ => bail!("Unexpected response to FsDiff"),
    }
}

/// Query filesystem diff at a specific UDS path.
pub fn query_fs_diff_at(vsock_uds_path: &str) -> Result<Vec<FsChange>> {
    let mut stream = connect_to(vsock_uds_path, DEFAULT_TIMEOUT_SECS)?;
    let resp = send_request(&mut stream, &GuestRequest::FsDiff)?;

    match resp {
        GuestResponse::FsDiffResult { changes } => Ok(changes),
        GuestResponse::Error { message } => {
            bail!("Guest fs-diff error: {}", message);
        }
        _ => bail!("Unexpected response to FsDiff"),
    }
}

/// Send a `StartPortForward` request on an already-connected stream.
///
/// Used by the Apple Container backend where the vsock connection is
/// established via `VZVirtioSocketDevice` rather than a UDS path.
pub fn start_port_forward_on(stream: &mut UnixStream, guest_port: u16) -> Result<u32> {
    let resp = send_request(stream, &GuestRequest::StartPortForward { guest_port })?;
    match resp {
        GuestResponse::PortForwardStarted { vsock_port, .. } => Ok(vsock_port),
        GuestResponse::Error { message } => {
            bail!("Guest port-forward error: {}", message);
        }
        _ => bail!("Unexpected response to StartPortForward"),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guest_request_roundtrip() {
        let variants: Vec<GuestRequest> = vec![
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
            GuestResponse::ExecResult {
                exit_code: 0,
                stdout: "Linux\n".to_string(),
                stderr: String::new(),
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
        ];

        for resp in &variants {
            let json = serde_json::to_string(resp).unwrap();
            let parsed: GuestResponse = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
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
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let decoded: GuestRequest = serde_json::from_str(&json).expect("deserialize");
        match decoded {
            GuestRequest::RunEntrypoint {
                stdin,
                timeout_secs,
            } => {
                assert_eq!(stdin, vec![1, 2, 3, 4, 5]);
                assert_eq!(timeout_secs, 30);
            }
            other => panic!("expected RunEntrypoint, got {other:?}"),
        }
    }

    #[test]
    fn test_run_entrypoint_request_empty_stdin_roundtrip() {
        let req = GuestRequest::RunEntrypoint {
            stdin: vec![],
            timeout_secs: 5,
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let decoded: GuestRequest = serde_json::from_str(&json).expect("deserialize");
        assert!(matches!(
            decoded,
            GuestRequest::RunEntrypoint {
                stdin,
                timeout_secs: 5,
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
        assert_eq!(GUEST_AGENT_PORT, 52);
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

    #[test]
    fn test_send_run_entrypoint_collects_events_until_terminal() {
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // Guest side: read the request, emit Stdout, Stderr, Exit.
        let guest_handle = std::thread::spawn(move || {
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
        let terminal = send_run_entrypoint(&mut host, b"in".to_vec(), 30, |evt| {
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
        let terminal = send_run_entrypoint(&mut host, b"".to_vec(), 30, |evt| {
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
            let _req: GuestRequest = read_frame(&mut guest).unwrap();
            write_frame(&mut guest, &GuestResponse::Pong).unwrap();
        });

        let result = send_run_entrypoint(&mut host, b"".to_vec(), 30, |_| {});
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
            let _req: GuestRequest = read_frame(&mut guest).unwrap();
            write_frame(
                &mut guest,
                &GuestResponse::Error {
                    message: "agent panicked before dispatch".into(),
                },
            )
            .unwrap();
        });

        let result = send_run_entrypoint(&mut host, b"".to_vec(), 30, |_| {});
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
}
