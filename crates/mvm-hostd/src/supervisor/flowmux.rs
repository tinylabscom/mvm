//! FlowMux session acceptor for the single workload networking endpoint.
//!
//! This module owns the host side of one authenticated FlowMux session:
//! handshake, frame I/O, and dispatch to the per-flow handlers. The current
//! implementation accepts one session, completes the handshake, and runs a
//! minimal TCP data relay for guest-initiated `OpenTcp` flows. UDP (`OpenUdp`)
//! and DNS (`Resolve`) frames are admitted into the registry but not yet
//! connected; everything else fails closed with `GoAway`.

pub mod registry;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::network_flow::{
    Direction, FrameError, HEADER_LEN, LENGTH_PREFIX_LEN, Opcode, SessionValidator, decode,
};
use mvm_core::net::session::Session;
use mvm_vmm::vsock_egress_bridge::egress_gate::{EgressGate, EgressVerdict};
use tracing::{info, warn};

use self::registry::{RegistryLimits, StreamRegistry, class_for_open};

/// Per-address connect budget when trying an admitted set: small so an
/// unreachable address (e.g. an AAAA with no host IPv6 egress) fails over to
/// the next candidate quickly.
const PER_IP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Why the FlowMux session ended.
#[derive(Debug, thiserror::Error)]
pub enum FlowMuxError {
    /// Handshake with the guest failed.
    #[error("handshake failed: {0}")]
    Handshake(String),
    /// A frame from the guest violated the protocol or session state.
    #[error("frame refused: {0}")]
    FrameRefused(String),
    /// An I/O error occurred on the transport.
    #[error("transport error: {0}")]
    Transport(#[from] std::io::Error),
}

/// Host-owned context for one authenticated FlowMux session.
pub struct FlowMuxSession {
    /// The read half of the underlying authenticated stream. Only the main
    /// session thread reads from this fd.
    reader: UnixStream,
    /// The write half, shared with per-stream relay threads so they can send
    /// `Data`/`HalfClose`/`Reset` frames back to the guest.
    writer: Arc<Mutex<UnixStream>>,
    session: Session,
    validator: SessionValidator,
    registry: Arc<Mutex<StreamRegistry>>,
    /// Active guest-initiated TCP streams and their upstream sockets. The host
    /// half of each stream lives in a dedicated thread.
    streams: BTreeMap<u32, TcpStreamHandle>,
    gate: EgressGate,
    read_buf: Vec<u8>,
    connect_timeout: Duration,
}

impl std::fmt::Debug for FlowMuxSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowMuxSession")
            .field("session_id", &self.session_id())
            .field("streams", &self.streams.len())
            .finish_non_exhaustive()
    }
}

/// The host-side handle for one active TCP flow. The relay thread owns a
/// clone of `upstream`; this half lets the main thread forward guest data and
/// shut the socket down when the guest closes or resets.
struct TcpStreamHandle {
    upstream: TcpStream,
    /// Set by the relay thread when the upstream socket reaches EOF.
    host_half_closed: Arc<AtomicBool>,
}

impl FlowMuxSession {
    /// Return the session identifier for logging and correlation.
    pub fn session_id(&self) -> &str {
        self.session.session_id()
    }

    /// Accept one authenticated FlowMux session on `stream`.
    ///
    /// `session_id` must be unique per VM boot. `host_key` signs the
    /// handshake; `guest_anchor` is the only guest identity this endpoint
    /// will accept. A mismatch fails closed.
    pub fn accept(
        mut stream: UnixStream,
        session_id: &str,
        host_key: SigningKey,
        guest_anchor: &VerifyingKey,
        limits: RegistryLimits,
        gate: EgressGate,
    ) -> Result<Self, FlowMuxError> {
        // Split the socket into independent read/write descriptors so the
        // main thread can block on guest frames while relay threads emit
        // upstream data back to the guest.
        let writer = stream.try_clone()?;
        let (session, _peer_key) = Session::host(&mut stream, session_id, host_key)
            .map_err(|e| FlowMuxError::Handshake(e.to_string()))?;

        if session.peer_verifying_key() != guest_anchor {
            return Err(FlowMuxError::Handshake(
                "guest identity does not match pinned anchor".to_string(),
            ));
        }

        info!(session_id, "FlowMux handshake complete");

        Ok(Self {
            reader: stream,
            writer: Arc::new(Mutex::new(writer)),
            session,
            validator: SessionValidator::default(),
            registry: Arc::new(Mutex::new(StreamRegistry::new(limits))),
            streams: BTreeMap::new(),
            gate,
            read_buf: Vec::with_capacity(4096),
            connect_timeout: Duration::from_secs(30),
        })
    }

    /// Serve the session until it closes or errors.
    ///
    /// The implementation completes the FlowMux `Hello`/`HelloAck` exchange,
    /// then dispatches flow frames. `OpenTcp` flows that pass the shared
    /// [`EgressGate`] are connected on the host and relayed; everything else
    /// is refused or terminated with `GoAway`.
    pub fn serve(&mut self) -> Result<(), FlowMuxError> {
        // Wait for the guest's Hello, then acknowledge. The authenticated
        // session is already established; this is the FlowMux session opening.
        match self.read_frame()? {
            Some((Opcode::Hello, 0, 0)) => {}
            Some((opcode, _, _)) => {
                return Err(FlowMuxError::FrameRefused(format!(
                    "expected Hello as first FlowMux frame, got {opcode:?}"
                )));
            }
            None => {
                return Err(FlowMuxError::FrameRefused(
                    "peer closed before Hello".to_string(),
                ));
            }
        }

        self.validator
            .admit(&mvm_contract::protocol::network_flow::FrameFacts::new(
                Direction::GuestToHost,
                Opcode::Hello,
                0,
            ))
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;

        self.send_hello_ack()?;
        self.validator
            .mark_hello_ack_sent()
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;

        loop {
            let (opcode, stream_id, payload_len) = match self.read_frame()? {
                Some(facts) => facts,
                None => {
                    info!("FlowMux peer closed session");
                    return Ok(());
                }
            };

            if let Err(e) = self.validator.admit(
                &mvm_contract::protocol::network_flow::FrameFacts::new(
                    Direction::GuestToHost,
                    opcode,
                    stream_id,
                )
                .with_payload(payload_len),
            ) {
                warn!(error = %e, "FlowMux frame refused by session validator");
                self.send_goaway(&e.to_string())?;
                return Ok(());
            }

            match opcode {
                Opcode::Hello => {
                    // A second Hello is illegal after the session is established;
                    // the validator already refuses it.
                }
                Opcode::OpenTcp => {
                    if let Err(e) = self.handle_open_tcp(stream_id, payload_len) {
                        warn!(error = %e, stream_id, "FlowMux TCP open failed");
                        self.send_reset(stream_id, "host error")?;
                    }
                }
                Opcode::Data => {
                    if let Err(e) = self.handle_guest_data(stream_id, payload_len) {
                        warn!(error = %e, stream_id, "FlowMux data forwarding failed");
                        let _ = self.reset_stream(stream_id);
                    }
                }
                Opcode::HalfClose => {
                    if let Err(e) = self.handle_guest_half_close(stream_id) {
                        warn!(error = %e, stream_id, "FlowMux half-close failed");
                        let _ = self.reset_stream(stream_id);
                    }
                }
                Opcode::Reset => {
                    self.reset_stream(stream_id)?;
                }
                Opcode::WindowUpdate => {
                    if let Err(e) = self.handle_window_update(stream_id, payload_len) {
                        warn!(error = %e, stream_id, "FlowMux window update failed");
                        let _ = self.reset_stream(stream_id);
                    }
                }
                Opcode::OpenUdp => {
                    // Record the guest-initiated stream so the registry tracks
                    // ceilings and parity; UDP association relay is still TODO.
                    if let Some(class) = class_for_open(opcode)
                        && let Err(e) = lock_registry(&self.registry).open_guest(stream_id, class)
                    {
                        warn!(error = %e, stream_id, "FlowMux refusing UDP open");
                        self.send_refused(stream_id, &e.to_string())?;
                    } else {
                        warn!(
                            stream_id,
                            "FlowMux UDP open admitted; relay not yet implemented"
                        );
                        self.send_goaway("UDP relay not yet implemented")?;
                        return Ok(());
                    }
                }
                Opcode::CloseUdp => {
                    if lock_registry(&self.registry).get(stream_id).is_some() {
                        let _ = lock_registry(&self.registry).retire(stream_id);
                    }
                    warn!(stream_id, "FlowMux skeleton rejects CloseUdp");
                    self.send_goaway("UDP relay not yet implemented")?;
                    return Ok(());
                }
                _ => {
                    if lock_registry(&self.registry).get(stream_id).is_some() {
                        warn!(?opcode, stream_id, "FlowMux skeleton rejects flow frame");
                        self.send_goaway("flow frames not yet implemented")?;
                    } else {
                        warn!(?opcode, stream_id, "FlowMux frame on unknown stream");
                        self.send_goaway("unknown stream")?;
                    }
                    return Ok(());
                }
            }
        }
    }

    fn handle_open_tcp(&mut self, stream_id: u32, payload_len: u32) -> Result<(), FlowMuxError> {
        if payload_len == 0 || payload_len > 256 {
            self.send_refused(stream_id, "OpenTcp target missing or too long")?;
            return Ok(());
        }

        let payload_start = LENGTH_PREFIX_LEN + HEADER_LEN;
        let payload_end = payload_start + payload_len as usize;
        let target = match std::str::from_utf8(&self.read_buf[payload_start..payload_end]) {
            Ok(s) => s,
            Err(_) => {
                self.send_refused(stream_id, "OpenTcp target is not UTF-8")?;
                return Ok(());
            }
        };

        let (host, port) = match parse_host_port(target) {
            Ok(pair) => pair,
            Err(e) => {
                self.send_refused(stream_id, &format!("invalid OpenTcp target: {e}"))?;
                return Ok(());
            }
        };

        let (ips, port) = match self.gate.decide_request(&format!("{host}:{port}")) {
            EgressVerdict::Allow { ips, port } => (ips, port),
            EgressVerdict::Deny(reason) => {
                self.send_refused(stream_id, &reason.to_string())?;
                return Ok(());
            }
            EgressVerdict::Malformed => {
                self.send_refused(stream_id, "malformed destination")?;
                return Ok(());
            }
        };

        if let Err(e) =
            lock_registry(&self.registry).open_guest(stream_id, registry::FlowClass::Tcp)
        {
            self.send_refused(stream_id, &e.to_string())?;
            return Ok(());
        }

        let upstream = match connect_first_admitted(&ips, port, self.connect_timeout) {
            Some(stream) => stream,
            None => {
                warn!(stream_id, %target, "FlowMux TCP connect failed");
                let _ = lock_registry(&self.registry).retire(stream_id);
                self.send_refused(stream_id, "connection failed")?;
                return Ok(());
            }
        };

        if let Err(e) = lock_registry(&self.registry).confirm(stream_id) {
            let _ = lock_registry(&self.registry).retire(stream_id);
            self.send_refused(stream_id, &e.to_string())?;
            return Ok(());
        }

        self.send_opened(stream_id)?;
        self.spawn_tcp_relay(stream_id, upstream)?;
        Ok(())
    }

    fn spawn_tcp_relay(&mut self, stream_id: u32, upstream: TcpStream) -> Result<(), FlowMuxError> {
        let upstream_read = upstream.try_clone()?;
        let host_half_closed = Arc::new(AtomicBool::new(false));
        let relay_flag = Arc::clone(&host_half_closed);
        let writer = Arc::clone(&self.writer);
        let registry = Arc::clone(&self.registry);

        std::thread::Builder::new()
            .name(format!("flowmux-tcp-{stream_id}"))
            .spawn(move || run_tcp_relay(stream_id, upstream_read, writer, registry, relay_flag))
            .map_err(FlowMuxError::Transport)?;

        self.streams.insert(
            stream_id,
            TcpStreamHandle {
                upstream,
                host_half_closed,
            },
        );
        Ok(())
    }

    fn handle_guest_data(&mut self, stream_id: u32, payload_len: u32) -> Result<(), FlowMuxError> {
        let payload_start = LENGTH_PREFIX_LEN + HEADER_LEN;
        let payload_end = payload_start + payload_len as usize;
        let payload = &self.read_buf[payload_start..payload_end];

        let handle = match self.streams.get_mut(&stream_id) {
            Some(h) => h,
            None => {
                warn!(stream_id, "Data frame on unknown stream");
                self.send_goaway("unknown stream")?;
                return Ok(());
            }
        };

        if handle.host_half_closed.load(Ordering::Relaxed) {
            self.send_reset(stream_id, "data after host half-close")?;
            self.remove_stream(stream_id);
            return Ok(());
        }

        {
            let mut reg = lock_registry(&self.registry);
            if let Err(e) = reg.consume_guest_credit(stream_id, payload_len) {
                warn!(error = %e, stream_id, "guest credit exhausted");
                drop(reg);
                self.send_reset(stream_id, "credit exhausted")?;
                self.remove_stream(stream_id);
                return Ok(());
            }
        }

        if let Err(e) = handle
            .upstream
            .write_all(payload)
            .and_then(|_| handle.upstream.flush())
        {
            warn!(error = %e, stream_id, "write to upstream failed");
            self.send_reset(stream_id, "upstream write failed")?;
            self.remove_stream(stream_id);
            return Ok(());
        }

        // Replenish the consumed credit so the guest can keep sending.
        {
            let mut reg = lock_registry(&self.registry);
            let _ = reg.grant_guest_credit(stream_id, payload_len);
        }
        self.send_window_update(stream_id, payload_len)?;
        Ok(())
    }

    fn handle_guest_half_close(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        let handle = match self.streams.get_mut(&stream_id) {
            Some(h) => h,
            None => {
                warn!(stream_id, "HalfClose on unknown stream");
                self.send_goaway("unknown stream")?;
                return Ok(());
            }
        };

        let _ = handle.upstream.shutdown(std::net::Shutdown::Write);

        if handle.host_half_closed.load(Ordering::Relaxed) {
            // Both directions are now done.
            self.send_reset(stream_id, "stream complete")?;
            self.remove_stream(stream_id);
        } else {
            let _ = lock_registry(&self.registry).half_close(stream_id);
        }
        Ok(())
    }

    fn handle_window_update(
        &mut self,
        stream_id: u32,
        payload_len: u32,
    ) -> Result<(), FlowMuxError> {
        if payload_len != 4 {
            return Err(FlowMuxError::FrameRefused(
                "WindowUpdate payload must be 4 bytes".to_string(),
            ));
        }
        let payload_start = LENGTH_PREFIX_LEN + HEADER_LEN;
        let payload_end = payload_start + payload_len as usize;
        let payload = &self.read_buf[payload_start..payload_end];
        let delta = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let reg = lock_registry(&self.registry);
        if reg.get(stream_id).is_none() {
            return Err(FlowMuxError::FrameRefused(format!(
                "WindowUpdate on unknown stream {stream_id}"
            )));
        }
        // The registry currently tracks only guest credit. Host credit grants
        // from the guest are accepted and ignored until per-direction host
        // accounting is wired in.
        let _ = delta;
        Ok(())
    }

    fn reset_stream(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        if let Some(handle) = self.streams.remove(&stream_id) {
            let _ = handle.upstream.shutdown(std::net::Shutdown::Both);
        }
        let _ = lock_registry(&self.registry).retire(stream_id);
        self.send_reset(stream_id, "reset by peer")?;
        Ok(())
    }

    fn remove_stream(&mut self, stream_id: u32) {
        if let Some(handle) = self.streams.remove(&stream_id) {
            let _ = handle.upstream.shutdown(std::net::Shutdown::Both);
        }
        let _ = lock_registry(&self.registry).retire(stream_id);
    }

    fn send_hello_ack(&self) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::HelloAck, 0, b"")
    }

    fn send_goaway(&self, reason: &str) -> Result<(), FlowMuxError> {
        warn!(%reason, "FlowMux sending GoAway");
        self.write_frame(Opcode::GoAway, 0, reason.as_bytes())
    }

    fn send_opened(&self, stream_id: u32) -> Result<(), FlowMuxError> {
        info!(stream_id, "FlowMux sending Opened");
        self.write_frame(Opcode::Opened, stream_id, b"")
    }

    fn send_refused(&self, stream_id: u32, reason: &str) -> Result<(), FlowMuxError> {
        warn!(stream_id, %reason, "FlowMux sending Refused");
        self.write_frame(Opcode::Refused, stream_id, reason.as_bytes())
    }

    fn send_reset(&self, stream_id: u32, reason: &str) -> Result<(), FlowMuxError> {
        warn!(stream_id, %reason, "FlowMux sending Reset");
        self.write_frame(Opcode::Reset, stream_id, reason.as_bytes())
    }

    fn send_window_update(&self, stream_id: u32, delta: u32) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::WindowUpdate, stream_id, &delta.to_be_bytes())
    }

    fn write_frame(
        &self,
        opcode: Opcode,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<(), FlowMuxError> {
        write_frame_to(&self.writer, opcode, stream_id, payload)
    }

    /// Read one decrypted FlowMux frame from the peer, returning the opcode,
    /// stream id, and payload length, or `None` on clean close.
    ///
    /// The session layer encrypts each frame; this helper reads the encrypted
    /// envelope, opens it, and decodes the inner FlowMux header. The skeleton
    /// currently sends plaintext FlowMux frames, so this reads the length
    /// prefix that `encode_into` produces and decodes the frame directly.
    fn read_frame(&mut self) -> Result<Option<(Opcode, u32, u32)>, FlowMuxError> {
        let mut len_buf = [0u8; 4];
        match self.reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        if frame_len == 0 {
            return Ok(None);
        }
        if frame_len > 1 << 20 {
            return Err(FlowMuxError::FrameRefused(format!(
                "FlowMux frame length {frame_len} exceeds 1 MiB"
            )));
        }
        self.read_buf.resize(4 + frame_len, 0);
        self.read_buf[..4].copy_from_slice(&len_buf);
        self.reader.read_exact(&mut self.read_buf[4..])?;

        // TODO: decrypt `self.read_buf` with `self.session.open(...)` once
        // the encrypted wire format for `SealedFrame` is defined.

        let frame = match decode(&self.read_buf) {
            Ok(frame) => frame,
            Err(FrameError::Incomplete { have: 0, .. }) => return Ok(None),
            Err(e) => return Err(FlowMuxError::FrameRefused(e.to_string())),
        };

        Ok(Some((
            frame.header.opcode,
            frame.header.stream_id,
            frame.header.payload_len,
        )))
    }
}

/// Lock the shared writer, recovering from poison so a crashed relay thread
/// does not silence the whole session.
fn lock_writer(writer: &Mutex<UnixStream>) -> std::sync::MutexGuard<'_, UnixStream> {
    writer.lock().unwrap_or_else(|e| e.into_inner())
}

/// Lock the shared registry, recovering from poison.
fn lock_registry(registry: &Mutex<StreamRegistry>) -> std::sync::MutexGuard<'_, StreamRegistry> {
    registry.lock().unwrap_or_else(|e| e.into_inner())
}

/// Serialize and send one frame through a shared writer.
fn write_frame_to(
    writer: &Mutex<UnixStream>,
    opcode: Opcode,
    stream_id: u32,
    payload: &[u8],
) -> Result<(), FlowMuxError> {
    let mut wire = Vec::new();
    mvm_contract::protocol::network_flow::encode_into(&mut wire, opcode, stream_id, payload)
        .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
    let mut w = lock_writer(writer);
    w.write_all(&wire)?;
    w.flush()?;
    Ok(())
}

/// Try each admitted address in order, first success wins, bounded overall by
/// `overall_timeout` and per-address by [`PER_IP_CONNECT_TIMEOUT`]. This is
/// the happy-eyeballs fallover used by the raw egress path, expressed
/// synchronously because the FlowMux session runs in `spawn_blocking`.
fn connect_first_admitted(
    ips: &[IpAddr],
    port: u16,
    overall_timeout: Duration,
) -> Option<TcpStream> {
    let deadline = std::time::Instant::now() + overall_timeout;
    for ip in ips {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let budget = remaining.min(PER_IP_CONNECT_TIMEOUT);
        match TcpStream::connect_timeout(&std::net::SocketAddr::new(*ip, port), budget) {
            Ok(stream) => return Some(stream),
            Err(e) => warn!(%ip, %port, error = %e, "FlowMux TCP connect attempt failed"),
        }
    }
    None
}

/// Per-stream relay thread: read from the upstream TCP socket and forward
/// each chunk to the guest as a `Data` frame. EOF becomes a `HalfClose`;
/// errors become a `Reset`.
fn run_tcp_relay(
    stream_id: u32,
    mut upstream: TcpStream,
    writer: Arc<Mutex<UnixStream>>,
    registry: Arc<Mutex<StreamRegistry>>,
    host_half_closed: Arc<AtomicBool>,
) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match upstream.read(&mut buf) {
            Ok(0) => {
                host_half_closed.store(true, Ordering::Relaxed);
                if write_frame_to(&writer, Opcode::HalfClose, stream_id, &[]).is_err() {
                    warn!(stream_id, "FlowMux relay failed to send HalfClose");
                }
                break;
            }
            Ok(n) => {
                if write_frame_to(&writer, Opcode::Data, stream_id, &buf[..n]).is_err() {
                    warn!(stream_id, "FlowMux relay failed to send Data");
                    break;
                }
            }
            Err(e) => {
                warn!(stream_id, error = %e, "FlowMux upstream read failed");
                let reason = format!("upstream error: {e}");
                let _ = write_frame_to(&writer, Opcode::Reset, stream_id, reason.as_bytes());
                host_half_closed.store(true, Ordering::Relaxed);
                break;
            }
        }
    }
    // The stream remains in the registry until the main thread observes the
    // half-close/reset and retires it, so we do not race with in-flight guest
    // frames here.
    let _ = registry;
}

fn parse_host_port(target: &str) -> Result<(&str, u16), String> {
    let (host, port_str) = target
        .rsplit_once(':')
        .ok_or_else(|| "target must be host:port".to_string())?;
    if host.is_empty() {
        return Err("host must not be empty".to_string());
    }
    let port = port_str
        .parse::<u16>()
        .map_err(|_| format!("port must be a 16-bit integer: {port_str}"))?;
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::thread;

    use ed25519_dalek::SigningKey;
    use mvm_contract::protocol::network_flow::{Opcode, encode_into};
    use mvm_core::net::session::Session;
    use rand::RngCore;

    use super::*;

    fn fresh_keys() -> (SigningKey, VerifyingKey) {
        let mut seed = [0u8; 32];
        RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        let key = SigningKey::from_bytes(&seed);
        let verify = key.verifying_key();
        (key, verify)
    }

    #[test]
    fn accept_rejects_wrong_guest_anchor() {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, _guest_verify) = fresh_keys();
        let (_wrong_key, wrong_verify) = fresh_keys();

        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();

        let gate = EgressGate::default_deny();
        let host_handle = thread::spawn(move || {
            FlowMuxSession::accept(
                host_stream,
                "test-session",
                host_key,
                &wrong_verify,
                RegistryLimits::default(),
                gate,
            )
            .map(|_| ())
        });

        // Drive the guest side of the handshake with the *correct* guest key;
        // the host must still reject because the anchor does not match.
        let (_guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        let result = host_handle.join().unwrap();
        assert!(
            matches!(result, Err(FlowMuxError::Handshake(_))),
            "expected handshake failure due to anchor mismatch, got {result:?}"
        );
    }

    fn read_flowmux_frame(stream: &mut UnixStream) -> (Opcode, Vec<u8>) {
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) => panic!("read len failed: {e:?}"),
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = Vec::with_capacity(4 + len);
        buf.extend_from_slice(&len_buf);
        buf.resize(4 + len, 0);
        stream.read_exact(&mut buf[4..]).unwrap();
        let parsed = mvm_contract::protocol::network_flow::decode(&buf).unwrap();
        (parsed.header.opcode, parsed.payload.to_vec())
    }

    #[test]
    fn accept_succeeds_and_sends_hello_ack() {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, guest_verify) = fresh_keys();

        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();

        let gate = EgressGate::default_deny();
        let host_handle = thread::spawn(move || {
            let mut session = FlowMuxSession::accept(
                host_stream,
                "test-session",
                host_key,
                &guest_verify,
                RegistryLimits::default(),
                gate,
            )
            .unwrap();
            session.serve()
        });

        let (_guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        // The guest must send Hello to open the FlowMux session.
        let mut hello = Vec::new();
        encode_into(&mut hello, Opcode::Hello, 0, b"").unwrap();
        guest_stream.write_all(&hello).unwrap();
        guest_stream.flush().unwrap();

        // Read the HelloAck from the host.
        let (opcode, _payload) = read_flowmux_frame(&mut guest_stream);
        assert_eq!(opcode, Opcode::HelloAck);

        // Send a flow frame on an unknown stream and expect a GoAway.
        let mut payload = Vec::new();
        encode_into(&mut payload, Opcode::Data, 1, b"hello").unwrap();
        guest_stream.write_all(&payload).unwrap();
        guest_stream.flush().unwrap();

        let (opcode, goaway_payload) = read_flowmux_frame(&mut guest_stream);
        assert_eq!(opcode, Opcode::GoAway);
        assert!(!goaway_payload.is_empty());

        // Close the guest side; the host serve loop should end cleanly.
        drop(guest_stream);
        host_handle.join().unwrap().unwrap();
    }

    #[test]
    fn open_tcp_to_unknown_host_is_refused_by_default_deny_gate() {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, guest_verify) = fresh_keys();

        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();

        let gate = EgressGate::default_deny();
        let host_handle = thread::spawn(move || {
            let mut session = FlowMuxSession::accept(
                host_stream,
                "test-session",
                host_key,
                &guest_verify,
                RegistryLimits::default(),
                gate,
            )
            .unwrap();
            session.serve()
        });

        let (_guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        let mut hello = Vec::new();
        encode_into(&mut hello, Opcode::Hello, 0, b"").unwrap();
        guest_stream.write_all(&hello).unwrap();
        guest_stream.flush().unwrap();

        let (opcode, _payload) = read_flowmux_frame(&mut guest_stream);
        assert_eq!(opcode, Opcode::HelloAck);

        let mut open = Vec::new();
        encode_into(&mut open, Opcode::OpenTcp, 1, b"example.com:443").unwrap();
        guest_stream.write_all(&open).unwrap();
        guest_stream.flush().unwrap();

        let (opcode, payload) = read_flowmux_frame(&mut guest_stream);
        assert_eq!(opcode, Opcode::Refused);
        assert!(!payload.is_empty());

        // The session stays alive; an unknown-stream frame afterward still
        // receives a GoAway rather than dropping the connection.
        let mut data = Vec::new();
        encode_into(&mut data, Opcode::Data, 3, b"?").unwrap();
        guest_stream.write_all(&data).unwrap();
        guest_stream.flush().unwrap();

        let (opcode, _payload) = read_flowmux_frame(&mut guest_stream);
        assert_eq!(opcode, Opcode::GoAway);

        drop(guest_stream);
        host_handle.join().unwrap().unwrap();
    }

    #[test]
    fn parse_host_port_accepts_ipv4_and_names() {
        assert_eq!(
            parse_host_port("127.0.0.1:443").unwrap(),
            ("127.0.0.1", 443)
        );
        assert_eq!(
            parse_host_port("example.com:80").unwrap(),
            ("example.com", 80)
        );
    }

    #[test]
    fn parse_host_port_rejects_missing_port_and_empty_host() {
        assert!(parse_host_port("example.com").is_err());
        assert!(parse_host_port(":443").is_err());
        assert!(parse_host_port("example.com:99999").is_err());
    }
}
