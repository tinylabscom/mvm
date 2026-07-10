//! Guest-side blocking session helpers for the shared network tunnel contract.
//!
//! This is the `mvm-guest` side of the backend-agnostic tunnel seam:
//! - dial the host over AF_VSOCK,
//! - negotiate the shared `HELLO` / `HELLO_ACK`,
//! - exchange typed control frames and raw packet frames.
//!
//! The actual TUN device plumbing lands in a later slice. This module keeps the
//! transport and framing reusable so Firecracker, HVF, libkrun, and future
//! backends can share the same guest-side protocol logic.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result, bail};
use mvm_core::protocol::network_tunnel::{
    BorrowedTunnelFrame, DecodeError, FrameType, OwnedTunnelFrame, PACKET_FRAME_HEADER_LEN,
    PacketFrameHeader, TunnelControlMessage, TunnelCreditUpdate, TunnelHello, TunnelHelloAck,
    TunnelNetworkConfig, TunnelRuntimeConfig,
};

/// Production tunnel session from guest to host.
pub struct GuestNetworkTunnelSession {
    stream: UnixStream,
}

impl GuestNetworkTunnelSession {
    /// Dial the host's network-tunnel AF_VSOCK port.
    pub fn connect(port: u32, timeout_secs: u64) -> Result<Self> {
        Ok(Self {
            stream: crate::vsock::connect_host_vsock(port, timeout_secs)?,
        })
    }

    /// Wrap an already-connected stream.
    pub fn from_stream(stream: UnixStream) -> Self {
        Self { stream }
    }

    /// Recover the underlying stream.
    pub fn into_inner(self) -> UnixStream {
        self.stream
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    /// Send the guest hello and validate the host acknowledgement.
    pub fn negotiate(&mut self, hello: TunnelHello, sequence: u64) -> Result<TunnelHelloAck> {
        self.send_control(TunnelControlMessage::Hello(hello.clone()), 0, 0, sequence)?;
        let ack = self.recv_control()?;
        match ack {
            TunnelControlMessage::HelloAck(ack) => {
                ack.validate_against(&hello)
                    .with_context(|| "host tunnel hello acknowledgement failed validation")?;
                Ok(ack)
            }
            other => bail!("expected tunnel hello acknowledgement, got {other:?}"),
        }
    }

    /// Send one typed control frame.
    pub fn send_control(
        &mut self,
        message: TunnelControlMessage,
        flags: u16,
        flow_id: u32,
        sequence: u64,
    ) -> Result<()> {
        let frame = message
            .encode_frame(flags, flow_id, sequence)
            .with_context(|| "encode network-tunnel control frame")?;
        self.write_owned_frame(&frame)
    }

    /// Receive and decode one typed control frame.
    pub fn recv_control(&mut self) -> Result<TunnelControlMessage> {
        let frame = self.read_frame()?;
        TunnelControlMessage::decode(frame.header.frame_type, &frame.payload)
            .with_context(|| "decode network-tunnel control frame")
    }

    /// Receive the host-authored tunnel network configuration frame.
    pub fn recv_network_config(&mut self) -> Result<TunnelNetworkConfig> {
        match self.recv_control()? {
            TunnelControlMessage::Config(config) => Ok(config),
            other => bail!("expected tunnel network config, got {other:?}"),
        }
    }

    /// Receive the first host credit grant for the session.
    pub fn recv_credit_update(&mut self) -> Result<TunnelCreditUpdate> {
        match self.recv_control()? {
            TunnelControlMessage::Credit(credit) => Ok(credit),
            other => bail!("expected tunnel credit update, got {other:?}"),
        }
    }

    /// Send one raw packet frame.
    pub fn send_packet(
        &mut self,
        flags: u16,
        flow_id: u32,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Result<()> {
        let frame = OwnedTunnelFrame::new(FrameType::Packet, flags, flow_id, sequence, payload)
            .with_context(|| "encode network-tunnel packet frame")?;
        self.write_owned_frame(&frame)
    }

    /// Receive one packet frame. Control frames are refused so callers do not
    /// accidentally treat a policy/error message as packet data.
    pub fn recv_packet(&mut self) -> Result<OwnedTunnelFrame> {
        let frame = self.read_frame()?;
        if frame.header.frame_type != FrameType::Packet {
            bail!(
                "expected network-tunnel packet frame, got {:?}",
                frame.header.frame_type
            );
        }
        Ok(frame)
    }

    fn write_owned_frame(&mut self, frame: &OwnedTunnelFrame) -> Result<()> {
        self.stream
            .write_all(&frame.encode())
            .with_context(|| "write network-tunnel frame")?;
        self.stream
            .flush()
            .with_context(|| "flush network-tunnel frame")?;
        Ok(())
    }

    fn read_frame(&mut self) -> Result<OwnedTunnelFrame> {
        let mut header_buf = [0_u8; PACKET_FRAME_HEADER_LEN];
        self.stream
            .read_exact(&mut header_buf)
            .with_context(|| "read network-tunnel frame header")?;
        let header = PacketFrameHeader::decode(&header_buf)
            .map_err(|err| decode_to_anyhow("decode network-tunnel frame header", err))?;

        let mut payload = vec![0_u8; header.payload_len as usize];
        self.stream
            .read_exact(&mut payload)
            .with_context(|| "read network-tunnel frame payload")?;

        // Re-run whole-frame validation against the concatenated bytes so any
        // future header/payload invariant added in mvm-core is enforced here too.
        let mut full = Vec::with_capacity(PACKET_FRAME_HEADER_LEN + payload.len());
        full.extend_from_slice(&header_buf);
        full.extend_from_slice(&payload);
        let borrowed = BorrowedTunnelFrame::decode(&full)
            .map_err(|err| decode_to_anyhow("decode complete network-tunnel frame", err))?;

        Ok(OwnedTunnelFrame {
            header: borrowed.header,
            payload: borrowed.payload.to_vec(),
        })
    }
}

/// Extract the optional tunnel runtime config from a kernel cmdline.
pub fn runtime_config_from_cmdline(cmdline: &str) -> Result<Option<TunnelRuntimeConfig>> {
    let Some(hex) = cmdline_token_value(cmdline, "mvm.network_tunnel") else {
        return Ok(None);
    };
    Ok(Some(mvm_core::vm_backend::decode_network_tunnel_cmdline(
        &hex,
    )?))
}

/// Build a validated guest `HELLO` from the shared runtime config. This keeps
/// the boot metadata → wire-message mapping in one place before the real TUN
/// device plumbing lands.
pub fn hello_from_runtime_config(
    config: &TunnelRuntimeConfig,
    guest_agent_version: &str,
) -> Result<TunnelHello> {
    config.validate()?;
    config
        .session
        .hello(guest_agent_version)
        .with_context(|| "build tunnel hello from runtime config")
}

/// Recover the optional tunnel runtime config from a kernel cmdline and turn it
/// into the validated guest `HELLO` for the handshake.
pub fn bootstrap_hello_from_cmdline(
    cmdline: &str,
    guest_agent_version: &str,
) -> Result<Option<(TunnelRuntimeConfig, TunnelHello)>> {
    let Some(config) = runtime_config_from_cmdline(cmdline)? else {
        return Ok(None);
    };
    let hello = hello_from_runtime_config(&config, guest_agent_version)?;
    Ok(Some((config, hello)))
}

/// Result of the shared tunnel bootstrap exchange before the packet pump starts.
pub struct BootstrappedGuestTunnel {
    pub runtime_config: TunnelRuntimeConfig,
    pub hello_ack: TunnelHelloAck,
    pub network_config: TunnelNetworkConfig,
    pub send_credit: SendCreditBudget,
    pub session: GuestNetworkTunnelSession,
    pending_guest_packet: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PumpProgress {
    pub guest_packets: usize,
    pub host_packets: usize,
    pub host_shutdown: Option<mvm_core::protocol::network_tunnel::TunnelShutdownReason>,
}

impl BootstrappedGuestTunnel {
    /// Apply the host-authored guest network config.
    pub fn apply_network_config(&self) -> Result<()> {
        apply_network_config(&self.network_config)
    }

    /// Open the guest's TUN device and apply the host-authored interface
    /// settings so the packet loop can start.
    pub fn prepare_tun_device(&self) -> Result<crate::guest_tun::GuestTunDevice> {
        let tun = crate::guest_tun::GuestTunDevice::open_named(&self.network_config.interface_name)
            .with_context(|| "open guest tunnel device")?;
        self.apply_network_config()?;
        Ok(tun)
    }

    /// Maximum admitted packet/frame size for this negotiated session.
    pub fn negotiated_frame_size(&self) -> usize {
        usize::try_from(self.hello_ack.maximum_frame_size)
            .expect("u32 frame size always fits usize on supported targets")
    }

    fn flush_pending_guest_packet(&mut self, flow_id: u32, sequence: u64) -> Result<bool> {
        let Some(packet) = self.pending_guest_packet.take() else {
            return Ok(false);
        };
        if !self.send_credit.can_send(packet.len()) {
            self.pending_guest_packet = Some(packet);
            return Ok(false);
        }
        let packet_len = packet.len();
        self.session
            .send_packet(0, flow_id, sequence, packet)
            .with_context(|| "forward guest packet to host tunnel session")?;
        self.send_credit.consume(packet_len)?;
        Ok(true)
    }

    fn queue_guest_packet<D: crate::guest_tun::PacketDevice>(
        &mut self,
        tun: &mut D,
    ) -> Result<usize> {
        let max_len = self.negotiated_frame_size();
        let mut packet = vec![0_u8; max_len + 1];
        let read = tun
            .read_packet(&mut packet)
            .with_context(|| format!("read guest packet from {}", tun.interface_name()))?;
        if read == 0 {
            bail!(
                "guest tunnel device {} returned an empty packet",
                tun.interface_name()
            );
        }
        if read > max_len {
            bail!(
                "guest packet from {} exceeds negotiated frame size {}",
                tun.interface_name(),
                max_len
            );
        }
        packet.truncate(read);
        self.pending_guest_packet = Some(packet);
        Ok(read)
    }

    /// Read one packet from the guest TUN and send it to the host tunnel
    /// session, refusing anything larger than the negotiated frame size.
    pub fn pump_one_tun_to_session<D: crate::guest_tun::PacketDevice>(
        &mut self,
        tun: &mut D,
        flow_id: u32,
        sequence: u64,
    ) -> Result<usize> {
        let read = self.queue_guest_packet(tun)?;
        let sent = self.flush_pending_guest_packet(flow_id, sequence)?;
        if !sent {
            bail!("guest tunnel send credit exhausted before packet could be forwarded");
        }
        Ok(read)
    }

    /// Receive one packet from the host tunnel session and write it to the
    /// guest TUN device, refusing payloads larger than the negotiated frame
    /// size or partial writes back into the guest stack.
    pub fn pump_one_session_to_tun<D: crate::guest_tun::PacketDevice>(
        &mut self,
        tun: &mut D,
    ) -> Result<usize> {
        match self.pump_one_session_event(tun)? {
            SessionPumpOutcome::Packet { bytes } => Ok(bytes),
            SessionPumpOutcome::IgnoredControl => Ok(0),
            SessionPumpOutcome::Shutdown { reason } => {
                bail!("host requested tunnel shutdown: {reason:?}")
            }
        }
    }

    fn pump_one_session_event<D: crate::guest_tun::PacketDevice>(
        &mut self,
        tun: &mut D,
    ) -> Result<SessionPumpOutcome> {
        let max_len = self.negotiated_frame_size();
        let frame = self
            .session
            .read_frame()
            .with_context(|| "receive host frame from tunnel session")?;
        if frame.header.frame_type != FrameType::Packet {
            let control = TunnelControlMessage::decode(frame.header.frame_type, &frame.payload)
                .with_context(|| "decode host control frame during guest packet loop")?;
            return match control {
                TunnelControlMessage::Heartbeat => Ok(SessionPumpOutcome::IgnoredControl),
                TunnelControlMessage::Credit(credit) => {
                    self.send_credit.add(credit);
                    Ok(SessionPumpOutcome::IgnoredControl)
                }
                TunnelControlMessage::Shutdown(reason) => {
                    Ok(SessionPumpOutcome::Shutdown { reason })
                }
                TunnelControlMessage::Error(error) => Err(anyhow::anyhow!(
                    "host tunnel error {:?}: {}",
                    error.code,
                    error.detail
                )),
                TunnelControlMessage::Hello(_)
                | TunnelControlMessage::HelloAck(_)
                | TunnelControlMessage::Config(_) => Err(anyhow::anyhow!(
                    "unexpected host control frame {:?} during guest packet loop",
                    frame.header.frame_type
                )),
            };
        }
        if frame.payload.len() > max_len {
            bail!(
                "host packet for {} exceeds negotiated frame size {}",
                tun.interface_name(),
                max_len
            );
        }
        let wrote = tun
            .write_packet(&frame.payload)
            .with_context(|| format!("write host packet into {}", tun.interface_name()))?;
        if wrote != frame.payload.len() {
            bail!(
                "short write into {}: wrote {} of {} bytes",
                tun.interface_name(),
                wrote,
                frame.payload.len()
            );
        }
        Ok(SessionPumpOutcome::Packet { bytes: wrote })
    }

    /// Pump at most one guest-originated packet and at most one host-originated
    /// packet for the current readiness edge. `next_sequence` advances only for
    /// guest→host packet frames because host→guest packets already carry their
    /// own session framing from the authority.
    pub fn pump_ready<D: crate::guest_tun::PacketDevice>(
        &mut self,
        tun: &mut D,
        flow_id: u32,
        next_sequence: &mut u64,
        guest_ready: bool,
        host_ready: bool,
    ) -> Result<PumpProgress> {
        let mut progress = PumpProgress {
            guest_packets: 0,
            host_packets: 0,
            host_shutdown: None,
        };
        if self.flush_pending_guest_packet(flow_id, *next_sequence)? {
            *next_sequence = next_sequence.saturating_add(1);
            progress.guest_packets = 1;
        } else if guest_ready && self.pending_guest_packet.is_none() {
            self.queue_guest_packet(tun)?;
            if self.flush_pending_guest_packet(flow_id, *next_sequence)? {
                *next_sequence = next_sequence.saturating_add(1);
                progress.guest_packets = 1;
            }
        }
        if host_ready {
            match self.pump_one_session_event(tun)? {
                SessionPumpOutcome::Packet { .. } => {
                    progress.host_packets = 1;
                }
                SessionPumpOutcome::IgnoredControl => {}
                SessionPumpOutcome::Shutdown { reason } => {
                    progress.host_shutdown = Some(reason);
                }
            }
        }
        if progress.guest_packets == 0
            && self.flush_pending_guest_packet(flow_id, *next_sequence)?
        {
            *next_sequence = next_sequence.saturating_add(1);
            progress.guest_packets = 1;
        }
        Ok(progress)
    }

    /// Run the blocking guest-side packet loop over the tunnel session and the
    /// opened TUN device. This is the first real runtime substrate for a future
    /// `mvm-guest-netd`-style worker.
    #[cfg(target_os = "linux")]
    pub fn run_blocking_packet_loop(
        &mut self,
        tun: &mut crate::guest_tun::GuestTunDevice,
        flow_id: u32,
        mut next_sequence: u64,
    ) -> Result<()> {
        loop {
            if self.flush_pending_guest_packet(flow_id, next_sequence)? {
                next_sequence = next_sequence.saturating_add(1);
                continue;
            }
            let mut fds = [
                libc::pollfd {
                    fd: tun.as_raw_fd(),
                    events: if self.pending_guest_packet.is_none() {
                        libc::POLLIN
                    } else {
                        0
                    },
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.session.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: `fds` points to valid pollfd storage for exactly two fds,
            // and timeout -1 intentionally blocks until one side is ready.
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
            if rc < 0 {
                return Err(anyhow::Error::new(std::io::Error::last_os_error()))
                    .context("poll guest tunnel device and tunnel session");
            }
            let guest_ready = (fds[0].revents & libc::POLLIN) != 0;
            let host_ready = (fds[1].revents & libc::POLLIN) != 0;
            if (fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                bail!(
                    "guest tunnel device poll failed with revents=0x{:x}",
                    fds[0].revents
                );
            }
            if (fds[1].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                bail!(
                    "guest tunnel session poll failed with revents=0x{:x}",
                    fds[1].revents
                );
            }
            let progress =
                self.pump_ready(tun, flow_id, &mut next_sequence, guest_ready, host_ready)?;
            if progress.host_shutdown.is_some() {
                return Ok(());
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionPumpOutcome {
    Packet {
        bytes: usize,
    },
    IgnoredControl,
    Shutdown {
        reason: mvm_core::protocol::network_tunnel::TunnelShutdownReason,
    },
}

/// Perform the shared guest bootstrap over an already-connected stream:
/// validate boot metadata, send `HELLO`, receive `HELLO_ACK`, then receive the
/// host-authored `CONFIG`.
pub fn bootstrap_over_stream(
    stream: UnixStream,
    runtime_config: TunnelRuntimeConfig,
    guest_agent_version: &str,
    hello_sequence: u64,
) -> Result<BootstrappedGuestTunnel> {
    let hello = hello_from_runtime_config(&runtime_config, guest_agent_version)?;
    let mut session = GuestNetworkTunnelSession::from_stream(stream);
    let hello_ack = session
        .negotiate(hello, hello_sequence)
        .with_context(|| "negotiate tunnel hello/ack")?;
    let network_config = session
        .recv_network_config()
        .with_context(|| "receive tunnel network config")?;
    let send_credit = SendCreditBudget::from_update(
        session
            .recv_credit_update()
            .with_context(|| "receive initial tunnel credit update")?,
    );
    Ok(BootstrappedGuestTunnel {
        runtime_config,
        hello_ack,
        network_config,
        send_credit,
        session,
        pending_guest_packet: None,
    })
}

/// Recover the optional runtime config from `/proc/cmdline`, dial the host
/// tunnel port, and complete the shared bootstrap exchange.
pub fn bootstrap_from_cmdline(
    cmdline: &str,
    guest_agent_version: &str,
    timeout_secs: u64,
    hello_sequence: u64,
) -> Result<Option<BootstrappedGuestTunnel>> {
    let Some((runtime_config, _hello)) =
        bootstrap_hello_from_cmdline(cmdline, guest_agent_version)?
    else {
        return Ok(None);
    };
    let session = GuestNetworkTunnelSession::connect(runtime_config.guest_port, timeout_secs)
        .with_context(|| "connect guest tunnel session")?;
    Ok(Some(bootstrap_over_stream(
        session.into_inner(),
        runtime_config,
        guest_agent_version,
        hello_sequence,
    )?))
}

/// Apply the host-authored guest interface settings for the packet tunnel.
pub fn apply_network_config(config: &TunnelNetworkConfig) -> Result<()> {
    crate::guest_net::configure_tunnel_guest_network(config)
        .map_err(anyhow::Error::msg)
        .with_context(|| "apply tunnel guest network config")
}

fn decode_to_anyhow(context: &'static str, err: DecodeError) -> anyhow::Error {
    anyhow::Error::new(err).context(context)
}

fn cmdline_token_value(cmdline: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    cmdline
        .split_whitespace()
        .find_map(|part| part.strip_prefix(&prefix).map(ToOwned::to_owned))
}

pub fn cmdline_requests_network_tunnel(cmdline: &str) -> bool {
    cmdline_token_value(cmdline, "mvm.network_tunnel").is_some()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendCreditBudget {
    remaining_bytes: u64,
    remaining_packets: u64,
}

impl SendCreditBudget {
    pub fn from_update(update: TunnelCreditUpdate) -> Self {
        Self {
            remaining_bytes: u64::from(update.bytes),
            remaining_packets: u64::from(update.packets),
        }
    }

    pub fn add(&mut self, update: TunnelCreditUpdate) {
        self.remaining_bytes = self.remaining_bytes.saturating_add(u64::from(update.bytes));
        self.remaining_packets = self
            .remaining_packets
            .saturating_add(u64::from(update.packets));
    }

    pub fn can_send(&self, packet_len: usize) -> bool {
        self.remaining_packets > 0
            && self.remaining_bytes >= u64::try_from(packet_len).expect("packet len fits u64")
    }

    pub fn consume(&mut self, packet_len: usize) -> Result<()> {
        let packet_len = u64::try_from(packet_len).expect("packet len fits u64");
        if !self.can_send(packet_len as usize) {
            bail!("guest tunnel send credit exhausted");
        }
        self.remaining_packets -= 1;
        self.remaining_bytes -= packet_len;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_tun::PacketDevice;
    use mvm_core::protocol::network_tunnel::{
        NETWORK_TUNNEL_VERSION, TunnelCreditUpdate, TunnelFeatures, TunnelNetworkConfig,
        TunnelSessionConfig,
    };

    fn hello() -> TunnelHello {
        TunnelHello {
            protocol_version: NETWORK_TUNNEL_VERSION,
            tenant_id: "tenant-a".to_string(),
            vm_id: "vm-1".to_string(),
            boot_id: "boot-1".to_string(),
            session_nonce: "nonce-1".to_string(),
            guest_agent_version: "guest-netd/1".to_string(),
            requested_features: TunnelFeatures {
                ipv4: true,
                split_control_stream: true,
                ..TunnelFeatures::default()
            },
            maximum_frame_size: 4096,
        }
    }

    fn ack() -> TunnelHelloAck {
        TunnelHelloAck {
            protocol_version: NETWORK_TUNNEL_VERSION,
            vm_id: "vm-1".to_string(),
            boot_id: "boot-1".to_string(),
            session_nonce: "nonce-1".to_string(),
            accepted_features: TunnelFeatures {
                ipv4: true,
                split_control_stream: true,
                ..TunnelFeatures::default()
            },
            maximum_frame_size: 4096,
        }
    }

    fn initial_credit() -> TunnelCreditUpdate {
        TunnelCreditUpdate {
            flow_id: 0,
            bytes: 64,
            packets: 4,
        }
    }

    #[derive(Default)]
    struct FakePacketDevice {
        interface_name: String,
        reads: std::collections::VecDeque<Vec<u8>>,
        writes: Vec<Vec<u8>>,
        short_write_len: Option<usize>,
    }

    impl FakePacketDevice {
        fn named(name: &str) -> Self {
            Self {
                interface_name: name.to_string(),
                ..Self::default()
            }
        }
    }

    impl PacketDevice for FakePacketDevice {
        fn interface_name(&self) -> &str {
            &self.interface_name
        }

        fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
            let packet = self.reads.pop_front().expect("test packet queued");
            let len = packet.len();
            buf[..len].copy_from_slice(&packet);
            Ok(len)
        }

        fn write_packet(&mut self, packet: &[u8]) -> Result<usize> {
            self.writes.push(packet.to_vec());
            Ok(self.short_write_len.unwrap_or(packet.len()))
        }
    }

    fn bootstrapped_guest(stream: UnixStream, maximum_frame_size: u32) -> BootstrappedGuestTunnel {
        BootstrappedGuestTunnel {
            runtime_config: TunnelRuntimeConfig {
                guest_port: 5302,
                session: TunnelSessionConfig {
                    tenant_id: "tenant-a".to_string(),
                    vm_id: "vm-1".to_string(),
                    boot_id: "boot-1".to_string(),
                    session_nonce: "nonce-1".to_string(),
                    requested_features: TunnelFeatures {
                        ipv4: true,
                        split_control_stream: true,
                        ..TunnelFeatures::default()
                    },
                    maximum_frame_size,
                },
            },
            hello_ack: TunnelHelloAck {
                protocol_version: NETWORK_TUNNEL_VERSION,
                vm_id: "vm-1".to_string(),
                boot_id: "boot-1".to_string(),
                session_nonce: "nonce-1".to_string(),
                accepted_features: TunnelFeatures {
                    ipv4: true,
                    split_control_stream: true,
                    ..TunnelFeatures::default()
                },
                maximum_frame_size,
            },
            network_config: TunnelNetworkConfig {
                interface_name: "mvm-net0".to_string(),
                guest_ipv4: "10.240.0.2".parse().expect("ip"),
                prefix_len: 24,
                gateway_ipv4: "10.240.0.1".parse().expect("ip"),
                dns_servers: vec!["1.1.1.1".parse().expect("ip")],
                mtu: 1500,
                host_entries: Vec::new(),
            },
            send_credit: SendCreditBudget::from_update(initial_credit()),
            session: GuestNetworkTunnelSession::from_stream(stream),
            pending_guest_packet: None,
        }
    }

    #[test]
    fn negotiate_roundtrips_hello_and_ack() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut host = GuestNetworkTunnelSession::from_stream(host);
            let message = host.recv_control().unwrap();
            assert_eq!(message, TunnelControlMessage::Hello(hello()));
            host.send_control(TunnelControlMessage::HelloAck(ack()), 0, 0, 1)
                .unwrap();
        });

        let mut guest = GuestNetworkTunnelSession::from_stream(guest);
        let negotiated = guest.negotiate(hello(), 1).unwrap();
        assert_eq!(negotiated, ack());
        host_thread.join().unwrap();
    }

    #[test]
    fn control_frame_roundtrips_config_message() {
        let (guest, host) = UnixStream::pair().unwrap();
        let config = TunnelNetworkConfig {
            interface_name: "mvm-net0".to_string(),
            guest_ipv4: "10.240.0.2".parse().unwrap(),
            prefix_len: 24,
            gateway_ipv4: "10.240.0.1".parse().unwrap(),
            dns_servers: vec!["1.1.1.1".parse().unwrap()],
            mtu: 1500,
            host_entries: Vec::new(),
        };
        let host_config = config.clone();
        let host_thread = std::thread::spawn(move || {
            let mut host = GuestNetworkTunnelSession::from_stream(host);
            let message = host.recv_network_config().unwrap();
            assert_eq!(message, host_config);
        });

        let mut guest = GuestNetworkTunnelSession::from_stream(guest);
        guest
            .send_control(TunnelControlMessage::Config(config.clone()), 0, 0, 2)
            .unwrap();
        host_thread.join().unwrap();
    }

    #[test]
    fn recv_network_config_rejects_non_config_control_message() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut host = GuestNetworkTunnelSession::from_stream(host);
            host.send_control(TunnelControlMessage::Heartbeat, 0, 0, 3)
                .unwrap();
        });

        let mut guest = GuestNetworkTunnelSession::from_stream(guest);
        let err = guest.recv_network_config().expect_err("heartbeat rejected");
        assert!(err.to_string().contains("expected tunnel network config"));
        host_thread.join().unwrap();
    }

    #[test]
    fn recv_credit_update_rejects_non_credit_control_message() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut host = GuestNetworkTunnelSession::from_stream(host);
            host.send_control(TunnelControlMessage::Heartbeat, 0, 0, 3)
                .unwrap();
        });

        let mut guest = GuestNetworkTunnelSession::from_stream(guest);
        let err = guest.recv_credit_update().expect_err("heartbeat rejected");
        assert!(err.to_string().contains("expected tunnel credit update"));
        host_thread.join().unwrap();
    }

    #[test]
    fn packet_frame_roundtrips_payload() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut host = GuestNetworkTunnelSession::from_stream(host);
            let frame = host.recv_packet().unwrap();
            assert_eq!(frame.header.flow_id, 77);
            assert_eq!(frame.header.sequence, 8);
            assert_eq!(frame.payload, vec![1, 2, 3, 4]);
        });

        let mut guest = GuestNetworkTunnelSession::from_stream(guest);
        guest.send_packet(0, 77, 8, vec![1, 2, 3, 4]).unwrap();
        host_thread.join().unwrap();
    }

    #[test]
    fn recv_packet_rejects_control_frames() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut host = GuestNetworkTunnelSession::from_stream(host);
            host.send_control(TunnelControlMessage::Heartbeat, 0, 0, 3)
                .unwrap();
        });

        let mut guest = GuestNetworkTunnelSession::from_stream(guest);
        let err = guest.recv_packet().expect_err("control frame rejected");
        assert!(
            err.to_string()
                .contains("expected network-tunnel packet frame")
        );
        host_thread.join().unwrap();
    }

    #[test]
    fn runtime_config_from_cmdline_round_trips_shared_token() {
        let runtime = TunnelRuntimeConfig {
            guest_port: 5302,
            session: TunnelSessionConfig {
                tenant_id: "tenant-a".to_string(),
                vm_id: "vm-1".to_string(),
                boot_id: "boot-1".to_string(),
                session_nonce: "nonce-1".to_string(),
                requested_features: TunnelFeatures {
                    ipv4: true,
                    ..TunnelFeatures::default()
                },
                maximum_frame_size: 4096,
            },
        };
        let token = mvm_core::vm_backend::encode_network_tunnel_cmdline(&runtime).unwrap();
        let cmdline = format!("console=hvc0 {token} root=/dev/vda");

        let parsed = runtime_config_from_cmdline(&cmdline).unwrap();
        assert_eq!(parsed, Some(runtime));
    }

    #[test]
    fn bootstrap_hello_from_cmdline_builds_guest_hello() {
        let runtime = TunnelRuntimeConfig {
            guest_port: 5302,
            session: TunnelSessionConfig {
                tenant_id: "tenant-a".to_string(),
                vm_id: "vm-1".to_string(),
                boot_id: "boot-1".to_string(),
                session_nonce: "nonce-1".to_string(),
                requested_features: TunnelFeatures {
                    ipv4: true,
                    split_control_stream: true,
                    ..TunnelFeatures::default()
                },
                maximum_frame_size: 4096,
            },
        };
        let token = mvm_core::vm_backend::encode_network_tunnel_cmdline(&runtime).unwrap();
        let cmdline = format!("{token} root=/dev/vda");

        let (parsed, built_hello) = bootstrap_hello_from_cmdline(&cmdline, "guest-netd/1")
            .unwrap()
            .expect("runtime config present");
        assert_eq!(parsed, runtime);
        assert_eq!(built_hello, hello());
    }

    #[test]
    fn bootstrap_hello_from_cmdline_is_none_without_token() {
        assert!(
            bootstrap_hello_from_cmdline("console=hvc0 root=/dev/vda", "guest-netd/1")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn bootstrap_over_stream_completes_hello_and_receives_network_config() {
        let (guest, host) = UnixStream::pair().unwrap();
        let runtime = TunnelRuntimeConfig {
            guest_port: 5302,
            session: TunnelSessionConfig {
                tenant_id: "tenant-a".to_string(),
                vm_id: "vm-1".to_string(),
                boot_id: "boot-1".to_string(),
                session_nonce: "nonce-1".to_string(),
                requested_features: TunnelFeatures {
                    ipv4: true,
                    split_control_stream: true,
                    ..TunnelFeatures::default()
                },
                maximum_frame_size: 4096,
            },
        };
        let network_config = TunnelNetworkConfig {
            interface_name: "mvm-net0".to_string(),
            guest_ipv4: "10.240.0.2".parse().expect("ip"),
            prefix_len: 24,
            gateway_ipv4: "10.240.0.1".parse().expect("ip"),
            dns_servers: vec!["1.1.1.1".parse().expect("ip")],
            mtu: 1500,
            host_entries: Vec::new(),
        };
        let host_config = network_config.clone();

        let host_thread = std::thread::spawn(move || {
            let mut host = GuestNetworkTunnelSession::from_stream(host);
            let got = host.recv_control().expect("hello");
            assert_eq!(got, TunnelControlMessage::Hello(hello()));
            host.send_control(TunnelControlMessage::HelloAck(ack()), 0, 0, 7)
                .expect("ack");
            host.send_control(TunnelControlMessage::Config(host_config), 0, 0, 8)
                .expect("config");
            host.send_control(TunnelControlMessage::Credit(initial_credit()), 0, 0, 9)
                .expect("credit");
        });

        let bootstrapped = bootstrap_over_stream(guest, runtime.clone(), "guest-netd/1", 1)
            .expect("bootstrap succeeds");
        assert_eq!(bootstrapped.runtime_config, runtime);
        assert_eq!(bootstrapped.hello_ack, ack());
        assert_eq!(bootstrapped.network_config, network_config);
        assert_eq!(
            bootstrapped.send_credit,
            SendCreditBudget::from_update(initial_credit())
        );
        host_thread.join().unwrap();
    }

    #[test]
    fn pump_one_tun_to_session_forwards_one_packet() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut host = GuestNetworkTunnelSession::from_stream(host);
            let frame = host.recv_packet().expect("packet");
            assert_eq!(frame.header.flow_id, 55);
            assert_eq!(frame.header.sequence, 9);
            assert_eq!(frame.payload, vec![1, 2, 3, 4]);
        });

        let mut bootstrapped = bootstrapped_guest(guest, 4096);
        let mut tun = FakePacketDevice::named("mvm-net0");
        tun.reads.push_back(vec![1, 2, 3, 4]);

        let read = bootstrapped
            .pump_one_tun_to_session(&mut tun, 55, 9)
            .expect("forwarded");
        assert_eq!(read, 4);
        host_thread.join().unwrap();
    }

    #[test]
    fn pump_one_session_to_tun_writes_one_packet() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut host = GuestNetworkTunnelSession::from_stream(host);
            host.send_packet(0, 77, 4, vec![9, 8, 7]).expect("send");
        });

        let mut bootstrapped = bootstrapped_guest(guest, 4096);
        let mut tun = FakePacketDevice::named("mvm-net0");

        let wrote = bootstrapped
            .pump_one_session_to_tun(&mut tun)
            .expect("written");
        assert_eq!(wrote, 3);
        assert_eq!(tun.writes, vec![vec![9, 8, 7]]);
        host_thread.join().unwrap();
    }

    #[test]
    fn pump_one_session_to_tun_rejects_short_writes() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut host = GuestNetworkTunnelSession::from_stream(host);
            host.send_packet(0, 77, 4, vec![9, 8, 7]).expect("send");
        });

        let mut bootstrapped = bootstrapped_guest(guest, 4096);
        let mut tun = FakePacketDevice::named("mvm-net0");
        tun.short_write_len = Some(2);

        let err = bootstrapped
            .pump_one_session_to_tun(&mut tun)
            .expect_err("short write rejected");
        assert!(err.to_string().contains("short write"));
        host_thread.join().unwrap();
    }

    #[test]
    fn pump_one_tun_to_session_rejects_packets_over_negotiated_frame_size() {
        let (guest, _host) = UnixStream::pair().unwrap();
        let mut bootstrapped = bootstrapped_guest(guest, 4);
        let mut tun = FakePacketDevice::named("mvm-net0");
        tun.reads.push_back(vec![1, 2, 3, 4, 5]);

        let err = bootstrapped
            .pump_one_tun_to_session(&mut tun, 55, 9)
            .expect_err("oversize rejected");
        assert!(err.to_string().contains("exceeds negotiated frame size"));
    }

    #[test]
    fn pump_ready_can_forward_both_directions_in_one_tick() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut host = GuestNetworkTunnelSession::from_stream(host);
            let frame = host.recv_packet().expect("guest packet");
            assert_eq!(frame.payload, vec![1, 2, 3]);
            host.send_packet(0, 77, 4, vec![9, 8, 7]).expect("send");
        });

        let mut bootstrapped = bootstrapped_guest(guest, 4096);
        let mut tun = FakePacketDevice::named("mvm-net0");
        tun.reads.push_back(vec![1, 2, 3]);
        let mut next_sequence = 10;

        let progress = bootstrapped
            .pump_ready(&mut tun, 55, &mut next_sequence, true, true)
            .expect("tick succeeds");
        assert_eq!(
            progress,
            PumpProgress {
                guest_packets: 1,
                host_packets: 1,
                host_shutdown: None,
            }
        );
        assert_eq!(next_sequence, 11);
        assert_eq!(tun.writes, vec![vec![9, 8, 7]]);
        host_thread.join().unwrap();
    }

    #[test]
    fn pump_ready_leaves_packet_pending_when_credit_is_exhausted() {
        let (guest, _host) = UnixStream::pair().unwrap();
        let mut bootstrapped = bootstrapped_guest(guest, 4096);
        bootstrapped.send_credit = SendCreditBudget::from_update(TunnelCreditUpdate {
            flow_id: 0,
            bytes: 0,
            packets: 0,
        });
        let mut tun = FakePacketDevice::named("mvm-net0");
        tun.reads.push_back(vec![1, 2, 3]);
        let mut next_sequence = 10;

        let progress = bootstrapped
            .pump_ready(&mut tun, 55, &mut next_sequence, true, false)
            .expect("tick succeeds");
        assert_eq!(
            progress,
            PumpProgress {
                guest_packets: 0,
                host_packets: 0,
                host_shutdown: None,
            }
        );
        assert_eq!(next_sequence, 10);
        assert_eq!(bootstrapped.pending_guest_packet, Some(vec![1, 2, 3]));
    }

    #[test]
    fn pump_ready_flushes_pending_packet_after_credit_update() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut host = GuestNetworkTunnelSession::from_stream(host);
            host.send_control(
                TunnelControlMessage::Credit(TunnelCreditUpdate {
                    flow_id: 0,
                    bytes: 3,
                    packets: 1,
                }),
                0,
                0,
                4,
            )
            .expect("send credit");
            let frame = host.recv_packet().expect("guest packet");
            assert_eq!(frame.payload, vec![1, 2, 3]);
            assert_eq!(frame.header.sequence, 10);
        });

        let mut bootstrapped = bootstrapped_guest(guest, 4096);
        bootstrapped.send_credit = SendCreditBudget::from_update(TunnelCreditUpdate {
            flow_id: 0,
            bytes: 0,
            packets: 0,
        });
        bootstrapped.pending_guest_packet = Some(vec![1, 2, 3]);
        let mut tun = FakePacketDevice::named("mvm-net0");
        let mut next_sequence = 10;

        let progress = bootstrapped
            .pump_ready(&mut tun, 55, &mut next_sequence, false, true)
            .expect("tick succeeds");
        assert_eq!(
            progress,
            PumpProgress {
                guest_packets: 1,
                host_packets: 0,
                host_shutdown: None,
            }
        );
        assert_eq!(next_sequence, 11);
        assert_eq!(bootstrapped.pending_guest_packet, None);
        host_thread.join().unwrap();
    }

    #[test]
    fn pump_ready_ignores_host_heartbeat_control_frames() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut host = GuestNetworkTunnelSession::from_stream(host);
            host.send_control(TunnelControlMessage::Heartbeat, 0, 0, 4)
                .expect("send heartbeat");
        });

        let mut bootstrapped = bootstrapped_guest(guest, 4096);
        let mut tun = FakePacketDevice::named("mvm-net0");
        let mut next_sequence = 10;

        let progress = bootstrapped
            .pump_ready(&mut tun, 55, &mut next_sequence, false, true)
            .expect("tick succeeds");
        assert_eq!(
            progress,
            PumpProgress {
                guest_packets: 0,
                host_packets: 0,
                host_shutdown: None,
            }
        );
        assert_eq!(tun.writes, Vec::<Vec<u8>>::new());
        host_thread.join().unwrap();
    }

    #[test]
    fn pump_ready_reports_host_shutdown_without_crashing() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut host = GuestNetworkTunnelSession::from_stream(host);
            host.send_control(
                TunnelControlMessage::Shutdown(
                    mvm_core::protocol::network_tunnel::TunnelShutdownReason::PolicyDenied,
                ),
                0,
                0,
                4,
            )
            .expect("send shutdown");
        });

        let mut bootstrapped = bootstrapped_guest(guest, 4096);
        let mut tun = FakePacketDevice::named("mvm-net0");
        let mut next_sequence = 10;

        let progress = bootstrapped
            .pump_ready(&mut tun, 55, &mut next_sequence, false, true)
            .expect("tick succeeds");
        assert_eq!(
            progress,
            PumpProgress {
                guest_packets: 0,
                host_packets: 0,
                host_shutdown: Some(
                    mvm_core::protocol::network_tunnel::TunnelShutdownReason::PolicyDenied
                ),
            }
        );
        host_thread.join().unwrap();
    }

    #[test]
    fn cmdline_requests_network_tunnel_detects_token() {
        assert!(cmdline_requests_network_tunnel(
            "console=ttyS0 mvm.network_tunnel=abcd root=/dev/vda"
        ));
        assert!(!cmdline_requests_network_tunnel(
            "console=ttyS0 root=/dev/vda"
        ));
    }
}
