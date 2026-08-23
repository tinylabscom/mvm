//! Per-stream TCP relay: the host half of one `OpenTcp` flow.
//!
//! One admitted flow becomes one thread that owns the upstream socket, reads
//! from it, and frames each chunk back to the guest as `Data`. EOF becomes a
//! `HalfClose`; an error becomes a `Reset`.
//!
//! The interesting part is the window. An exhausted send window is
//! backpressure, not a failure: the guest returns credit as it consumes, so a
//! full window means "slow down". Resetting instead truncates a transfer that
//! was working, and surfaces to the caller as a corrupt download rather than as
//! flow control — which is exactly how it presented before it was diagnosed.
//!
//! Split out of `flowmux.rs` alongside `udp_relay`, which is the same shape for
//! datagrams.

use std::io::Read;
use std::net::{IpAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mvm_contract::protocol::network_flow::Opcode;
use mvm_contract::protocol::network_flow::{Direction, SessionValidator};
use mvm_core::net::session::Session;
use tracing::warn;

use super::registry::{RegistryError, StreamRegistry};
use super::{PER_IP_CONNECT_TIMEOUT, lock_registry, lock_validator, write_frame_to};

/// How often the wait re-checks. The relay thread is blocked either way, so
/// this trades a little latency for not needing a condvar in the registry.
const HOST_CREDIT_POLL: Duration = Duration::from_millis(2);

/// Reserve `len` bytes of host credit on `stream_id`, waiting for the guest to
/// replenish if the window is currently full.
///
/// An exhausted window is **backpressure, not an error**. The guest returns
/// credit as it consumes, so a full window means "slow down" — resetting the
/// stream instead truncates a transfer that was working, which surfaces to the
/// caller as a corrupt download rather than as flow control. Only two things
/// end the wait: the stream going away, or a peer that has stopped reading for
/// `wait`, which comes from `RegistryLimits::credit_wait`.
fn await_host_credit(
    registry: &Mutex<StreamRegistry>,
    stream_id: u32,
    len: u32,
    retired: &AtomicBool,
    wait: Duration,
) -> Result<(), RegistryError> {
    let deadline = Instant::now() + wait;
    loop {
        let err = match lock_registry(registry).consume_host_credit(stream_id, len) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        // `NotLive` means the stream is gone — waiting cannot fix that, and
        // only `IllegalState` is the window-full case worth retrying.
        if !matches!(err, RegistryError::IllegalState { .. })
            || retired.load(Ordering::Relaxed)
            || Instant::now() >= deadline
        {
            return Err(err);
        }
        std::thread::sleep(HOST_CREDIT_POLL);
    }
}

/// Try each admitted address in order, first success wins, bounded overall by
/// `overall_timeout` and per-address by [`PER_IP_CONNECT_TIMEOUT`].
///
/// Happy-eyeballs fallover, expressed synchronously because the FlowMux
/// session runs in `spawn_blocking`.
pub(super) fn connect_first_admitted(
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
            Ok(stream) => {
                if let Err(error) = stream.set_nodelay(true) {
                    warn!(%ip, %port, %error, "FlowMux TCP_NODELAY setup failed");
                }
                return Some(stream);
            }
            Err(e) => warn!(%ip, %port, error = %e, "FlowMux TCP connect attempt failed"),
        }
    }
    None
}

/// Per-stream relay thread: read from the upstream TCP socket and forward
/// each chunk to the guest as a `Data` frame. EOF becomes a `HalfClose`;
/// errors become a `Reset`.
/// Parameters for the per-stream TCP relay thread.
pub(super) struct TcpRelayParams {
    pub(super) stream_id: u32,
    pub(super) upstream: TcpStream,
    pub(super) session: Arc<Mutex<Session>>,
    pub(super) writer: Arc<Mutex<UnixStream>>,
    pub(super) registry: Arc<Mutex<StreamRegistry>>,
    pub(super) validator: Arc<Mutex<SessionValidator>>,
    pub(super) host_half_closed: Arc<AtomicBool>,
    pub(super) retired: Arc<AtomicBool>,
    /// How long to wait for the guest to return credit before giving up.
    pub(super) credit_wait: Duration,
}

pub(super) fn run_tcp_relay(params: TcpRelayParams) {
    let TcpRelayParams {
        stream_id,
        mut upstream,
        session,
        writer,
        registry,
        validator,
        host_half_closed,
        retired,
        credit_wait,
    } = params;
    let mut buf = [0u8; 16 * 1024];
    loop {
        match upstream.read(&mut buf) {
            Ok(0) => {
                host_half_closed.store(true, Ordering::Relaxed);
                if !retired.load(Ordering::Relaxed)
                    && write_frame_to(&session, &writer, Opcode::HalfClose, stream_id, &[]).is_err()
                {
                    warn!(stream_id, "FlowMux relay failed to send HalfClose");
                }
                break;
            }
            Ok(n) => {
                if let Err(e) =
                    await_host_credit(&registry, stream_id, n as u32, &retired, credit_wait)
                {
                    warn!(stream_id, error = %e, "FlowMux host credit exhausted");
                    let _ = write_frame_to(
                        &session,
                        &writer,
                        Opcode::Reset,
                        stream_id,
                        b"host credit exhausted",
                    );
                    host_half_closed.store(true, Ordering::Relaxed);
                    break;
                }
                // Spend the window on this side's validator too. It is
                // credited by every guest `WindowUpdate` it admits, so a send
                // that never debits it leaves the counter climbing until a
                // legitimate grant overflows the cap and the session goes
                // away — a few megabytes in, which is why only a large
                // transfer finds it.
                if let Err(e) = lock_validator(&validator).admit(
                    &mvm_contract::protocol::network_flow::FrameFacts::new(
                        Direction::HostToGuest,
                        Opcode::Data,
                        stream_id,
                    )
                    .with_payload(n as u32),
                ) {
                    warn!(stream_id, error = %e, "FlowMux relay data refused by validator");
                    break;
                }
                if write_frame_to(&session, &writer, Opcode::Data, stream_id, &buf[..n]).is_err() {
                    warn!(stream_id, "FlowMux relay failed to send Data");
                    break;
                }
            }
            Err(e) => {
                warn!(stream_id, error = %e, "FlowMux upstream read failed");
                if !retired.load(Ordering::Relaxed) {
                    let reason = format!("upstream error: {e}");
                    let _ = write_frame_to(
                        &session,
                        &writer,
                        Opcode::Reset,
                        stream_id,
                        reason.as_bytes(),
                    );
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admitted_connections_disable_nagle() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let accept = std::thread::spawn(move || listener.accept().unwrap());

        let stream =
            connect_first_admitted(&[address.ip()], address.port(), Duration::from_secs(1))
                .expect("loopback listener accepts an admitted connection");
        assert!(stream.nodelay().unwrap());

        drop(stream);
        let _ = accept.join().unwrap();
    }
}
