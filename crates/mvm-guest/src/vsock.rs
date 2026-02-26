use std::io::{BufRead, BufReader, Read, Write};
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

/// Default connect/read timeout in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Maximum response frame size (256 KiB).
const MAX_FRAME_SIZE: usize = 256 * 1024;

// ============================================================================
// Guest agent protocol (JSON over vsock)
// ============================================================================

/// Request sent from host to guest vsock agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// Response from guest vsock agent to host.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

// ============================================================================
// Host-bound protocol (guest → host, reverse direction)
// ============================================================================

/// Port the host listens on for host-bound requests from gateway VMs.
pub const HOST_BOUND_PORT: u32 = 53;

/// Request FROM a guest VM (gateway) TO the host agent.
/// Used for wake-on-demand: the gateway VM asks the host to wake a worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// Response from host agent to a guest VM's host-bound request.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    // Verify protocol version
    if frame.version != PROTOCOL_VERSION_AUTHENTICATED {
        bail!(
            "Unexpected protocol version: {} (expected {})",
            frame.version,
            PROTOCOL_VERSION_AUTHENTICATED
        );
    }

    // Verify session ID
    if frame.session_id != expected_session_id {
        bail!(
            "Session ID mismatch: got '{}', expected '{}'",
            frame.session_id,
            expected_session_id
        );
    }

    // Replay detection: sequence must be >= expected minimum
    if frame.sequence < expected_min_sequence {
        bail!(
            "Replay detected: sequence {} < expected minimum {}",
            frame.sequence,
            expected_min_sequence
        );
    }

    // Verify Ed25519 signature
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

    // Deserialize the verified inner payload
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

/// Connect to the guest vsock agent via a direct UDS path.
///
/// Firecracker exposes guest vsock as a Unix domain socket. The connect protocol:
/// 1. Open Unix stream to the given UDS path
/// 2. Write `CONNECT <port>\n`
/// 3. Read `OK <port>\n`
/// 4. Then use length-prefixed JSON frames
fn connect_to(uds_path: &str, timeout_secs: u64) -> Result<UnixStream> {
    let timeout = Duration::from_secs(timeout_secs);

    let stream = UnixStream::connect(uds_path)
        .with_context(|| format!("Failed to connect to vsock UDS at {}", uds_path))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    // Firecracker vsock connect handshake
    let mut stream = stream;
    writeln!(stream, "CONNECT {}", GUEST_AGENT_PORT).with_context(|| "Failed to send CONNECT")?;
    stream.flush()?;

    // Read response line: "OK <port>\n"
    let mut reader = BufReader::new(&stream);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .with_context(|| "Failed to read CONNECT response")?;

    if !response_line.starts_with("OK ") {
        bail!(
            "Vsock CONNECT failed: expected 'OK {}', got '{}'",
            GUEST_AGENT_PORT,
            response_line.trim()
        );
    }

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
fn send_request(stream: &mut UnixStream, req: &GuestRequest) -> Result<GuestResponse> {
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
    stream
        .read_exact(&mut len_buf)
        .with_context(|| "Failed to read response length")?;
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
    stream
        .read_exact(&mut buf)
        .with_context(|| "Failed to read response body")?;

    serde_json::from_slice(&buf).with_context(|| "Failed to deserialize response")
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
        ];

        for resp in &variants {
            let json = serde_json::to_string(resp).unwrap();
            let parsed: GuestResponse = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
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
        ];

        for req in &variants {
            let json = serde_json::to_string(req).unwrap();
            let parsed: HostBoundRequest = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, json2);
        }
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
