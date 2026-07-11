//! Host-side session validation helpers for the shared network tunnel contract.
//!
//! This module is intentionally transport-agnostic: it validates one guest
//! `HELLO` against host-owned VM/session state, emits a matching `HELLO_ACK`,
//! and exchanges framed control/packet messages over any blocking stream.
//!
//! Backend adapters (Firecracker UDS, HVF/libkrun host listeners, future WHP
//! transport shims) should reuse this logic rather than reimplementing tunnel
//! identity checks per backend.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;

use anyhow::{Context, Result, bail};
use mvm_core::policy::dns_pin::DnsPinRegistry;
use mvm_core::protocol::network_tunnel::{
    BorrowedTunnelFrame, DecodeError, FrameType, MAX_HOST_ENTRIES, OwnedTunnelFrame,
    PACKET_FRAME_HEADER_LEN, PacketFrameHeader, TunnelControlMessage, TunnelCreditUpdate,
    TunnelErrorCode, TunnelErrorFrame, TunnelFeatures, TunnelHello, TunnelHelloAck,
    TunnelHostEntry, TunnelNetworkConfig, TunnelSessionConfig, TunnelShutdownReason,
};
use serde::{Deserialize, Serialize};

use std::net::{IpAddr, Ipv4Addr};

use crate::host_tun;
use crate::net_l3::{L3Decision, L3DropReason, L3ForwardPolicy, parse_ipv4_dst_and_l4};

/// Host-owned expected session identity for one VM boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedTunnelSession {
    pub tenant_id: String,
    pub vm_id: String,
    pub boot_id: String,
    pub session_nonce: String,
    pub maximum_frame_size: u32,
    pub accepted_features: TunnelFeatures,
}

impl ExpectedTunnelSession {
    pub fn from_session_config(
        session: &TunnelSessionConfig,
        accepted_features: TunnelFeatures,
    ) -> Result<Self, TunnelSessionError> {
        session
            .validate()
            .map_err(TunnelSessionError::InvalidHello)?;
        Ok(Self {
            tenant_id: session.tenant_id.clone(),
            vm_id: session.vm_id.clone(),
            boot_id: session.boot_id.clone(),
            session_nonce: session.session_nonce.clone(),
            maximum_frame_size: session.maximum_frame_size,
            accepted_features,
        })
    }

    pub fn validate_hello(&self, hello: &TunnelHello) -> Result<(), TunnelSessionError> {
        hello.validate().map_err(TunnelSessionError::InvalidHello)?;

        if hello.tenant_id != self.tenant_id {
            return Err(TunnelSessionError::TenantMismatch);
        }
        if hello.vm_id != self.vm_id {
            return Err(TunnelSessionError::VmMismatch);
        }
        if hello.boot_id != self.boot_id {
            return Err(TunnelSessionError::BootMismatch);
        }
        if hello.session_nonce != self.session_nonce {
            return Err(TunnelSessionError::SessionNonceMismatch);
        }
        if hello.maximum_frame_size == 0 || hello.maximum_frame_size < self.maximum_frame_size {
            return Err(TunnelSessionError::FrameSizeTooSmall {
                guest: hello.maximum_frame_size,
                host_minimum: self.maximum_frame_size,
            });
        }

        Ok(())
    }

    pub fn hello_ack(&self) -> TunnelHelloAck {
        TunnelHelloAck {
            protocol_version: mvm_core::protocol::network_tunnel::NETWORK_TUNNEL_VERSION,
            vm_id: self.vm_id.clone(),
            boot_id: self.boot_id.clone(),
            session_nonce: self.session_nonce.clone(),
            accepted_features: self.accepted_features.clone(),
            maximum_frame_size: self.maximum_frame_size,
        }
    }
}

/// Blocking host-side session over a backend-provided stream.
pub struct HostNetworkTunnelSession<S> {
    stream: S,
}

impl<S> HostNetworkTunnelSession<S>
where
    S: Read + Write,
{
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Receive the guest hello, validate it against host-owned state, and send
    /// the matching host acknowledgement.
    pub fn accept_hello(
        &mut self,
        expected: &ExpectedTunnelSession,
        sequence: u64,
    ) -> Result<TunnelHello, TunnelSessionError> {
        let hello = match self.recv_control().map_err(TunnelSessionError::transport)? {
            TunnelControlMessage::Hello(hello) => hello,
            other => return Err(TunnelSessionError::UnexpectedFirstFrame(other.frame_type())),
        };

        expected.validate_hello(&hello)?;
        self.send_control(
            TunnelControlMessage::HelloAck(expected.hello_ack()),
            0,
            0,
            sequence,
        )
        .map_err(TunnelSessionError::transport)?;
        Ok(hello)
    }

    pub fn send_control(
        &mut self,
        message: TunnelControlMessage,
        flags: u16,
        flow_id: u32,
        sequence: u64,
    ) -> Result<()> {
        let frame = message
            .encode_frame(flags, flow_id, sequence)
            .with_context(|| "encode network-tunnel host control frame")?;
        self.write_owned_frame(&frame)
    }

    pub fn recv_control(&mut self) -> Result<TunnelControlMessage> {
        let frame = self.read_frame()?;
        TunnelControlMessage::decode(frame.header.frame_type, &frame.payload)
            .with_context(|| "decode network-tunnel host control frame")
    }

    pub fn send_network_config(
        &mut self,
        config: TunnelNetworkConfig,
        sequence: u64,
    ) -> Result<()> {
        self.send_control(TunnelControlMessage::Config(config), 0, 0, sequence)
    }

    /// Validate the guest hello, send the host acknowledgement, then send the
    /// host-authored guest network config on the same session.
    pub fn accept_bootstrap(
        &mut self,
        expected: &ExpectedTunnelSession,
        network_config: TunnelNetworkConfig,
        hello_ack_sequence: u64,
        config_sequence: u64,
    ) -> Result<TunnelHello, TunnelSessionError> {
        let hello = self.accept_hello(expected, hello_ack_sequence)?;
        self.send_network_config(network_config, config_sequence)
            .map_err(TunnelSessionError::transport)?;
        Ok(hello)
    }

    pub fn send_packet(
        &mut self,
        flags: u16,
        flow_id: u32,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Result<()> {
        let frame = OwnedTunnelFrame::new(FrameType::Packet, flags, flow_id, sequence, payload)
            .with_context(|| "encode network-tunnel host packet frame")?;
        self.write_owned_frame(&frame)
    }

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
            .with_context(|| "write network-tunnel host frame")?;
        self.stream
            .flush()
            .with_context(|| "flush network-tunnel host frame")?;
        Ok(())
    }

    fn read_frame(&mut self) -> Result<OwnedTunnelFrame> {
        let mut header_buf = [0_u8; PACKET_FRAME_HEADER_LEN];
        self.stream
            .read_exact(&mut header_buf)
            .with_context(|| "read network-tunnel host frame header")?;
        let header = PacketFrameHeader::decode(&header_buf)
            .map_err(|err| decode_to_anyhow("decode network-tunnel host frame header", err))?;

        let mut payload = vec![0_u8; header.payload_len as usize];
        self.stream
            .read_exact(&mut payload)
            .with_context(|| "read network-tunnel host frame payload")?;

        let mut full = Vec::with_capacity(PACKET_FRAME_HEADER_LEN + payload.len());
        full.extend_from_slice(&header_buf);
        full.extend_from_slice(&payload);
        let borrowed = BorrowedTunnelFrame::decode(&full)
            .map_err(|err| decode_to_anyhow("decode complete network-tunnel host frame", err))?;

        Ok(OwnedTunnelFrame {
            header: borrowed.header,
            payload: borrowed.payload.to_vec(),
        })
    }
}

/// What the first host-owned packet worker should do with guest packets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TunnelPacketPolicy {
    /// Production default-deny until a later slice wires an admitted forwarder.
    DropAll,
    /// Inspect each guest IPv4 packet, decide allow/drop against the admitted
    /// policy + DNS pins, and audit the outcome. With no `interface_name` the
    /// gate only decides + drops; with one, admitted packets forward out the
    /// named host TUN and replies frame back to the guest via the bidirectional
    /// [`HostTunnelWorker::run_blocking_l3_relay_loop`].
    L3Forward {
        gate: L3ForwardPolicy,
        #[serde(default)]
        interface_name: Option<String>,
    },
    /// Relay packets through a host-owned Linux TUN device.
    HostTun { interface_name: String },
}

/// Per-session packet limits enforced by the host worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelWorkerLimits {
    pub max_packets: u64,
    pub max_bytes: u64,
}

impl Default for TunnelWorkerLimits {
    fn default() -> Self {
        Self {
            max_packets: 1024,
            max_bytes: 8 * 1024 * 1024,
        }
    }
}

impl TunnelWorkerLimits {
    fn validate(self) -> Result<Self, TunnelWorkerError> {
        if self.max_packets == 0 {
            return Err(TunnelWorkerError::InvalidConfig(
                "max_packets must be non-zero",
            ));
        }
        if self.max_bytes == 0 {
            return Err(TunnelWorkerError::InvalidConfig(
                "max_bytes must be non-zero",
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelWorkerConfig {
    pub expected_session: ExpectedTunnelSession,
    pub network_config: TunnelNetworkConfig,
    pub initial_credit: TunnelCreditUpdate,
    pub packet_policy: TunnelPacketPolicy,
    pub limits: TunnelWorkerLimits,
}

impl TunnelWorkerConfig {
    pub fn validate(&self) -> Result<(), TunnelWorkerError> {
        self.network_config
            .validate()
            .map_err(TunnelWorkerError::InvalidNetworkConfig)?;
        self.initial_credit
            .validate()
            .map_err(TunnelWorkerError::InvalidInitialCredit)?;
        match &self.packet_policy {
            TunnelPacketPolicy::DropAll => {}
            TunnelPacketPolicy::L3Forward { interface_name, .. } => {
                if let Some(interface_name) = interface_name {
                    crate::host_tun::validate_interface_name(interface_name)
                        .map_err(TunnelWorkerError::InvalidPacketPolicy)?;
                }
            }
            TunnelPacketPolicy::HostTun { interface_name } => {
                crate::host_tun::validate_interface_name(interface_name)
                    .map_err(TunnelWorkerError::InvalidPacketPolicy)?;
            }
        }
        self.limits.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum TunnelAuditEvent {
    SessionBootstrapped {
        vm_id: String,
        maximum_frame_size: u32,
    },
    PacketDropped {
        flow_id: u32,
        sequence: u64,
        bytes: usize,
    },
    /// The L3 gate admitted this packet's destination. Egress isn't wired yet,
    /// so the packet is still dropped — this records the allow decision.
    PacketL3Allowed {
        flow_id: u32,
        sequence: u64,
        bytes: usize,
        dst: Ipv4Addr,
        dst_port: Option<u16>,
    },
    /// The L3 gate denied this packet's destination.
    PacketL3Dropped {
        flow_id: u32,
        sequence: u64,
        bytes: usize,
        reason: L3DropReason,
    },
    PacketForwarded {
        flow_id: u32,
        sequence: u64,
        bytes: usize,
        interface_name: String,
    },
    PacketDeliveredToGuest {
        flow_id: u32,
        sequence: u64,
        bytes: usize,
        interface_name: String,
    },
    /// A userspace TCP flow to an admitted destination was accepted and bridged
    /// to a host socket (the macOS userspace-stack egress path).
    TcpFlowOpened {
        flow_id: u32,
        dst: Ipv4Addr,
        dst_port: u16,
    },
    /// A bridged userspace TCP flow closed, with the byte counts spliced each
    /// way.
    TcpFlowClosed {
        flow_id: u32,
        dst: Ipv4Addr,
        dst_port: u16,
        guest_to_host_bytes: u64,
        host_to_guest_bytes: u64,
    },
    /// A userspace TCP connection was refused before any host socket opened
    /// because the gate denied its destination.
    TcpFlowDenied {
        dst: Ipv4Addr,
        dst_port: u16,
        reason: L3DropReason,
    },
    SessionClosed {
        outcome: TunnelWorkerOutcome,
        stats: TunnelWorkerStats,
    },
}

pub trait TunnelAuditSink {
    type Error: std::fmt::Display;

    fn record(&mut self, event: TunnelAuditEvent) -> Result<(), Self::Error>;
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NoopTunnelAuditSink;

impl TunnelAuditSink for NoopTunnelAuditSink {
    type Error = std::convert::Infallible;

    fn record(&mut self, _event: TunnelAuditEvent) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelWorkerStats {
    pub guest_packets_seen: u64,
    pub guest_bytes_seen: u64,
    pub guest_packets_dropped: u64,
    pub guest_bytes_dropped: u64,
    /// Packets the L3 gate admitted. Still counted under
    /// `guest_packets_dropped` too until egress forwarding is wired.
    pub guest_packets_l3_allowed: u64,
    pub guest_bytes_l3_allowed: u64,
    pub guest_packets_forwarded: u64,
    pub guest_bytes_forwarded: u64,
    pub host_packets_delivered: u64,
    pub host_bytes_delivered: u64,
    pub host_control_frames_sent: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelWorkerOutcome {
    GuestShutdown(TunnelShutdownReason),
    QuotaExceeded,
    PacketPathFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPacketAction {
    Dropped,
    Forwarded { interface_name: String },
}

pub trait HostPacketPath {
    fn handle_guest_packet(
        &mut self,
        flow_id: u32,
        sequence: u64,
        packet: &[u8],
    ) -> std::result::Result<HostPacketAction, String>;
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DropAllPacketPath;

impl HostPacketPath for DropAllPacketPath {
    fn handle_guest_packet(
        &mut self,
        _flow_id: u32,
        _sequence: u64,
        _packet: &[u8],
    ) -> std::result::Result<HostPacketAction, String> {
        Ok(HostPacketAction::Dropped)
    }
}

#[derive(Debug)]
pub struct HostTunPacketPath<D> {
    device: D,
}

impl<D> HostTunPacketPath<D> {
    pub fn new(device: D) -> Self {
        Self { device }
    }

    pub fn device(&self) -> &D {
        &self.device
    }

    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }
}

impl<D> AsRawFd for HostTunPacketPath<D>
where
    D: AsRawFd,
{
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.device.as_raw_fd()
    }
}

impl<D> HostPacketPath for HostTunPacketPath<D>
where
    D: host_tun::PacketDevice,
{
    fn handle_guest_packet(
        &mut self,
        _flow_id: u32,
        _sequence: u64,
        packet: &[u8],
    ) -> std::result::Result<HostPacketAction, String> {
        let written = self
            .device
            .write_packet(packet)
            .map_err(|err| err.to_string())?;
        if written != packet.len() {
            return Err(format!(
                "host packet path short write on {}: wrote {written} of {} bytes",
                self.device.interface_name(),
                packet.len()
            ));
        }
        Ok(HostPacketAction::Forwarded {
            interface_name: self.device.interface_name().to_string(),
        })
    }
}

/// Derive guest `/etc/hosts` entries from the admission DNS pins.
///
/// IPv4 pins only (IPv6 pins are skipped — the L3 forward path is IPv4-only),
/// one `(name, ip)` per pinned IPv4, exact duplicates removed, capped at
/// [`MAX_HOST_ENTRIES`]. The host already resolved every allowlisted name at
/// admission and gates guest packets by dst IP against these same pins; handing
/// the guest the pairs makes in-guest resolution pin-consistent by
/// construction. A name with no IPv4 pin contributes nothing, so it can't
/// resolve in the guest — default-deny.
pub fn host_entries_from_pins(pins: &DnsPinRegistry) -> Vec<TunnelHostEntry> {
    let mut entries = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (dest, pin) in pins.iter() {
        for ip in &pin.ips {
            let IpAddr::V4(v4) = ip else { continue };
            if !seen.insert((dest.clone(), *v4)) {
                continue;
            }
            entries.push(TunnelHostEntry {
                name: dest.clone(),
                ip: *v4,
            });
            if entries.len() >= MAX_HOST_ENTRIES {
                return entries;
            }
        }
    }
    entries
}

pub struct HostTunnelWorker<S, A> {
    session: HostNetworkTunnelSession<S>,
    audit: A,
    config: TunnelWorkerConfig,
    stats: TunnelWorkerStats,
}

impl<S, A> HostTunnelWorker<S, A>
where
    S: Read + Write,
    A: TunnelAuditSink,
{
    pub fn new(
        stream: S,
        audit: A,
        mut config: TunnelWorkerConfig,
    ) -> Result<Self, TunnelWorkerError> {
        // Populate the guest hosts entries from the admitted gate's pins so the
        // config the guest receives resolves each allowlisted name to exactly an
        // IP the gate admits. Done before validate() so a malformed pinned name
        // fails the whole session closed rather than reaching the guest.
        if let TunnelPacketPolicy::L3Forward { gate, .. } = &config.packet_policy {
            config.network_config.host_entries = host_entries_from_pins(gate.pins());
        }
        config.validate()?;
        Ok(Self {
            session: HostNetworkTunnelSession::new(stream),
            audit,
            config,
            stats: TunnelWorkerStats::default(),
        })
    }

    pub fn stats(&self) -> &TunnelWorkerStats {
        &self.stats
    }

    pub fn audit(&self) -> &A {
        &self.audit
    }

    /// The negotiated maximum frame size — the upper bound on a single packet
    /// this session will carry in either direction.
    pub fn negotiated_frame_size(&self) -> usize {
        usize::try_from(self.config.expected_session.maximum_frame_size)
            .expect("u32 frame size always fits usize on supported targets")
    }

    pub fn bootstrap(
        &mut self,
        hello_ack_sequence: u64,
        config_sequence: u64,
        credit_sequence: u64,
    ) -> Result<TunnelHello, TunnelWorkerError> {
        let hello = self
            .session
            .accept_bootstrap(
                &self.config.expected_session,
                self.config.network_config.clone(),
                hello_ack_sequence,
                config_sequence,
            )
            .map_err(TunnelWorkerError::Session)?;
        self.record_audit(TunnelAuditEvent::SessionBootstrapped {
            vm_id: hello.vm_id.clone(),
            maximum_frame_size: hello.maximum_frame_size,
        })?;
        self.send_control(
            TunnelControlMessage::Credit(self.config.initial_credit),
            credit_sequence,
        )?;
        Ok(hello)
    }

    pub fn run_until_shutdown(&mut self) -> Result<TunnelWorkerOutcome, TunnelWorkerError> {
        let mut packet_path = DropAllPacketPath;
        self.run_until_shutdown_with_packet_path(&mut packet_path)
    }

    pub fn run_until_shutdown_with_packet_path<P>(
        &mut self,
        packet_path: &mut P,
    ) -> Result<TunnelWorkerOutcome, TunnelWorkerError>
    where
        P: HostPacketPath,
    {
        loop {
            let frame = self
                .session
                .read_frame()
                .map_err(TunnelWorkerError::transport)?;
            match frame.header.frame_type {
                FrameType::Packet => {
                    if let Some(outcome) = self.handle_packet(frame, packet_path)? {
                        self.record_audit(TunnelAuditEvent::SessionClosed {
                            outcome: outcome.clone(),
                            stats: self.stats,
                        })?;
                        return Ok(outcome);
                    }
                }
                other => {
                    let outcome = self.handle_control(other, &frame.payload)?;
                    if let Some(outcome) = outcome {
                        self.record_audit(TunnelAuditEvent::SessionClosed {
                            outcome: outcome.clone(),
                            stats: self.stats,
                        })?;
                        return Ok(outcome);
                    }
                }
            }
        }
    }

    /// Run the raw-L3 decision gate: inspect each guest IPv4 packet, decide
    /// allow/drop against the admitted policy + DNS pins, audit the outcome,
    /// and still drop every packet (egress forwarding lands in a later slice).
    /// Requires the worker's `packet_policy` to be [`TunnelPacketPolicy::L3Forward`].
    pub fn run_until_shutdown_l3_gate(&mut self) -> Result<TunnelWorkerOutcome, TunnelWorkerError> {
        let gate = match &self.config.packet_policy {
            TunnelPacketPolicy::L3Forward { gate, .. } => gate.clone(),
            _ => {
                return Err(TunnelWorkerError::InvalidConfig(
                    "run_until_shutdown_l3_gate requires an l3_forward packet policy",
                ));
            }
        };
        loop {
            let frame = self
                .session
                .read_frame()
                .map_err(TunnelWorkerError::transport)?;
            match frame.header.frame_type {
                FrameType::Packet => {
                    if let Some(outcome) = self.handle_l3_gate_packet(frame, &gate)? {
                        self.record_audit(TunnelAuditEvent::SessionClosed {
                            outcome: outcome.clone(),
                            stats: self.stats,
                        })?;
                        return Ok(outcome);
                    }
                }
                other => {
                    if let Some(outcome) = self.handle_control(other, &frame.payload)? {
                        self.record_audit(TunnelAuditEvent::SessionClosed {
                            outcome: outcome.clone(),
                            stats: self.stats,
                        })?;
                        return Ok(outcome);
                    }
                }
            }
        }
    }

    /// Run the raw-L3 forward loop: inspect each guest IPv4 packet, decide
    /// allow/drop against the admitted policy + DNS pins, and forward only the
    /// admitted packets into `packet_path` (a real host TUN in production). A
    /// denied packet is audited and dropped and never touches the packet path.
    /// Requires the worker's `packet_policy` to be [`TunnelPacketPolicy::L3Forward`].
    pub fn run_until_shutdown_l3_forward_with_packet_path<P>(
        &mut self,
        packet_path: &mut P,
    ) -> Result<TunnelWorkerOutcome, TunnelWorkerError>
    where
        P: HostPacketPath,
    {
        let gate = match &self.config.packet_policy {
            TunnelPacketPolicy::L3Forward { gate, .. } => gate.clone(),
            _ => {
                return Err(TunnelWorkerError::InvalidConfig(
                    "run_until_shutdown_l3_forward_with_packet_path requires an l3_forward packet policy",
                ));
            }
        };
        loop {
            let frame = self
                .session
                .read_frame()
                .map_err(TunnelWorkerError::transport)?;
            match frame.header.frame_type {
                FrameType::Packet => {
                    if let Some(outcome) =
                        self.handle_l3_forward_packet(frame, &gate, packet_path)?
                    {
                        self.record_audit(TunnelAuditEvent::SessionClosed {
                            outcome: outcome.clone(),
                            stats: self.stats,
                        })?;
                        return Ok(outcome);
                    }
                }
                other => {
                    if let Some(outcome) = self.handle_control(other, &frame.payload)? {
                        self.record_audit(TunnelAuditEvent::SessionClosed {
                            outcome: outcome.clone(),
                            stats: self.stats,
                        })?;
                        return Ok(outcome);
                    }
                }
            }
        }
    }

    fn handle_l3_forward_packet<P>(
        &mut self,
        frame: OwnedTunnelFrame,
        gate: &L3ForwardPolicy,
        packet_path: &mut P,
    ) -> Result<Option<TunnelWorkerOutcome>, TunnelWorkerError>
    where
        P: HostPacketPath,
    {
        let payload_len =
            u64::try_from(frame.payload.len()).expect("packet length always fits u64");
        if let Some(outcome) = self.account_and_check_quota(frame.header.sequence, payload_len)? {
            return Ok(Some(outcome));
        }

        let flow_id = frame.header.flow_id;
        let sequence = frame.header.sequence;
        let bytes = frame.payload.len();
        match gate.decide_packet(&frame.payload) {
            L3Decision::Allow => {
                self.stats.guest_packets_l3_allowed =
                    self.stats.guest_packets_l3_allowed.saturating_add(1);
                self.stats.guest_bytes_l3_allowed = self
                    .stats
                    .guest_bytes_l3_allowed
                    .saturating_add(payload_len);
                // Only admitted packets reach the packet path; the gate decides
                // before any byte is written to the host TUN.
                self.forward_via_packet_path(frame, payload_len, packet_path)
            }
            L3Decision::Drop(reason) => {
                self.stats.guest_packets_dropped =
                    self.stats.guest_packets_dropped.saturating_add(1);
                self.stats.guest_bytes_dropped =
                    self.stats.guest_bytes_dropped.saturating_add(payload_len);
                self.record_audit(TunnelAuditEvent::PacketL3Dropped {
                    flow_id,
                    sequence,
                    bytes,
                    reason,
                })?;
                Ok(None)
            }
        }
    }

    fn handle_packet(
        &mut self,
        frame: OwnedTunnelFrame,
        packet_path: &mut impl HostPacketPath,
    ) -> Result<Option<TunnelWorkerOutcome>, TunnelWorkerError> {
        let payload_len =
            u64::try_from(frame.payload.len()).expect("packet length always fits u64");
        if let Some(outcome) = self.account_and_check_quota(frame.header.sequence, payload_len)? {
            return Ok(Some(outcome));
        }
        self.forward_via_packet_path(frame, payload_len, packet_path)
    }

    /// Count one guest packet against the per-session quota. Returns
    /// `Some(QuotaExceeded)` — after telling the guest to stop — when the packet
    /// or byte budget is spent, so callers fail closed before touching egress.
    fn account_and_check_quota(
        &mut self,
        frame_sequence: u64,
        payload_len: u64,
    ) -> Result<Option<TunnelWorkerOutcome>, TunnelWorkerError> {
        self.stats.guest_packets_seen = self.stats.guest_packets_seen.saturating_add(1);
        self.stats.guest_bytes_seen = self.stats.guest_bytes_seen.saturating_add(payload_len);

        if self.stats.guest_packets_seen > self.config.limits.max_packets
            || self.stats.guest_bytes_seen > self.config.limits.max_bytes
        {
            self.send_control(
                TunnelControlMessage::Error(TunnelErrorFrame {
                    code: TunnelErrorCode::QuotaExceeded,
                    detail: "network tunnel packet quota exceeded".to_string(),
                }),
                frame_sequence.saturating_add(1),
            )?;
            self.send_control(
                TunnelControlMessage::Shutdown(TunnelShutdownReason::PolicyDenied),
                frame_sequence.saturating_add(2),
            )?;
            return Ok(Some(TunnelWorkerOutcome::QuotaExceeded));
        }
        Ok(None)
    }

    /// Hand one guest packet to a host packet path, updating stats + audit and
    /// failing closed on a path error. Shared by the plain forward loop and the
    /// L3-gated forward loop, which reach this only after the gate admits the
    /// packet.
    fn forward_via_packet_path(
        &mut self,
        frame: OwnedTunnelFrame,
        payload_len: u64,
        packet_path: &mut impl HostPacketPath,
    ) -> Result<Option<TunnelWorkerOutcome>, TunnelWorkerError> {
        match packet_path.handle_guest_packet(
            frame.header.flow_id,
            frame.header.sequence,
            &frame.payload,
        ) {
            Ok(HostPacketAction::Dropped) => {
                self.stats.guest_packets_dropped =
                    self.stats.guest_packets_dropped.saturating_add(1);
                self.stats.guest_bytes_dropped =
                    self.stats.guest_bytes_dropped.saturating_add(payload_len);
                self.record_audit(TunnelAuditEvent::PacketDropped {
                    flow_id: frame.header.flow_id,
                    sequence: frame.header.sequence,
                    bytes: frame.payload.len(),
                })?;
                Ok(None)
            }
            Ok(HostPacketAction::Forwarded { interface_name }) => {
                self.stats.guest_packets_forwarded =
                    self.stats.guest_packets_forwarded.saturating_add(1);
                self.stats.guest_bytes_forwarded =
                    self.stats.guest_bytes_forwarded.saturating_add(payload_len);
                self.record_audit(TunnelAuditEvent::PacketForwarded {
                    flow_id: frame.header.flow_id,
                    sequence: frame.header.sequence,
                    bytes: frame.payload.len(),
                    interface_name,
                })?;
                Ok(None)
            }
            Err(detail) => {
                self.send_control(
                    TunnelControlMessage::Error(TunnelErrorFrame {
                        code: TunnelErrorCode::Internal,
                        detail: format!("host packet path failed: {detail}"),
                    }),
                    frame.header.sequence.saturating_add(1),
                )?;
                self.send_control(
                    TunnelControlMessage::Shutdown(TunnelShutdownReason::HostError),
                    frame.header.sequence.saturating_add(2),
                )?;
                Ok(Some(TunnelWorkerOutcome::PacketPathFailed))
            }
        }
    }

    fn handle_l3_gate_packet(
        &mut self,
        frame: OwnedTunnelFrame,
        gate: &L3ForwardPolicy,
    ) -> Result<Option<TunnelWorkerOutcome>, TunnelWorkerError> {
        let payload_len =
            u64::try_from(frame.payload.len()).expect("packet length always fits u64");
        if let Some(outcome) = self.account_and_check_quota(frame.header.sequence, payload_len)? {
            return Ok(Some(outcome));
        }

        // Every packet is still dropped in this decision-only loop; the gate
        // decision only distinguishes allow (audited + counted) from drop.
        self.stats.guest_packets_dropped = self.stats.guest_packets_dropped.saturating_add(1);
        self.stats.guest_bytes_dropped = self.stats.guest_bytes_dropped.saturating_add(payload_len);

        let flow_id = frame.header.flow_id;
        let sequence = frame.header.sequence;
        let bytes = frame.payload.len();
        match parse_ipv4_dst_and_l4(&frame.payload) {
            Some((dst, proto, dst_port)) => match gate.decide(dst, proto, dst_port) {
                L3Decision::Allow => {
                    self.stats.guest_packets_l3_allowed =
                        self.stats.guest_packets_l3_allowed.saturating_add(1);
                    self.stats.guest_bytes_l3_allowed = self
                        .stats
                        .guest_bytes_l3_allowed
                        .saturating_add(payload_len);
                    self.record_audit(TunnelAuditEvent::PacketL3Allowed {
                        flow_id,
                        sequence,
                        bytes,
                        dst,
                        dst_port,
                    })?;
                }
                L3Decision::Drop(reason) => {
                    self.record_audit(TunnelAuditEvent::PacketL3Dropped {
                        flow_id,
                        sequence,
                        bytes,
                        reason,
                    })?;
                }
            },
            None => {
                self.record_audit(TunnelAuditEvent::PacketL3Dropped {
                    flow_id,
                    sequence,
                    bytes,
                    reason: L3DropReason::Unparseable,
                })?;
            }
        }
        Ok(None)
    }

    fn handle_control(
        &mut self,
        frame_type: FrameType,
        payload: &[u8],
    ) -> Result<Option<TunnelWorkerOutcome>, TunnelWorkerError> {
        let message = TunnelControlMessage::decode(frame_type, payload)
            .map_err(|err| TunnelWorkerError::Control(err.to_string()))?;
        match message {
            TunnelControlMessage::Heartbeat | TunnelControlMessage::Credit(_) => Ok(None),
            TunnelControlMessage::Shutdown(reason) => {
                Ok(Some(TunnelWorkerOutcome::GuestShutdown(reason)))
            }
            TunnelControlMessage::Hello(_)
            | TunnelControlMessage::HelloAck(_)
            | TunnelControlMessage::Config(_)
            | TunnelControlMessage::Error(_) => {
                self.send_control(
                    TunnelControlMessage::Error(TunnelErrorFrame {
                        code: TunnelErrorCode::MalformedFrame,
                        detail: format!("unexpected post-bootstrap control frame: {frame_type:?}"),
                    }),
                    0,
                )?;
                self.send_control(
                    TunnelControlMessage::Shutdown(TunnelShutdownReason::ProtocolError),
                    1,
                )?;
                Err(TunnelWorkerError::UnexpectedControlFrame(frame_type))
            }
        }
    }

    fn send_control(
        &mut self,
        message: TunnelControlMessage,
        sequence: u64,
    ) -> Result<(), TunnelWorkerError> {
        self.session
            .send_control(message, 0, 0, sequence)
            .map_err(TunnelWorkerError::transport)?;
        self.stats.host_control_frames_sent = self.stats.host_control_frames_sent.saturating_add(1);
        Ok(())
    }

    fn record_audit(&mut self, event: TunnelAuditEvent) -> Result<(), TunnelWorkerError> {
        self.audit
            .record(event)
            .map_err(|err| TunnelWorkerError::Audit(err.to_string()))
    }
}

impl<S, A> HostTunnelWorker<S, A>
where
    S: Read + Write + AsRawFd,
    A: TunnelAuditSink,
{
    /// Read one reply packet off the host TUN and frame it back to the guest.
    /// Returns `Ok(None)` on a delivered packet, `Ok(Some(outcome))` when this
    /// reply spends the shared per-session quota (fail closed), and a
    /// `PacketPath` error on an empty or oversize device read.
    fn pump_one_host_tun_to_guest<D>(
        &mut self,
        packet_path: &mut HostTunPacketPath<D>,
        flow_id: u32,
        sequence: u64,
    ) -> Result<Option<TunnelWorkerOutcome>, TunnelWorkerError>
    where
        D: host_tun::PacketDevice,
    {
        let max_len = usize::try_from(self.config.expected_session.maximum_frame_size)
            .expect("u32 frame size always fits usize on supported targets");
        let mut packet = vec![0_u8; max_len + 1];
        let read = packet_path
            .device_mut()
            .read_packet(&mut packet)
            .map_err(|err| TunnelWorkerError::PacketPath(err.to_string()))?;
        if read == 0 {
            return Err(TunnelWorkerError::PacketPath(format!(
                "host packet path {} returned an empty packet",
                packet_path.device().interface_name()
            )));
        }
        if read > max_len {
            return Err(TunnelWorkerError::PacketPath(format!(
                "host packet path {} exceeded negotiated frame size {}",
                packet_path.device().interface_name(),
                max_len
            )));
        }
        let read_len = u64::try_from(read).expect("packet len fits u64");
        // Reverse-direction bytes count against the same per-session budget as
        // guest egress; fail closed before delivering once the budget is spent.
        if let Some(outcome) = self.account_and_check_quota(sequence, read_len)? {
            return Ok(Some(outcome));
        }
        packet.truncate(read);
        self.session
            .send_packet(0, flow_id, sequence, packet)
            .map_err(TunnelWorkerError::transport)?;
        self.stats.host_packets_delivered = self.stats.host_packets_delivered.saturating_add(1);
        self.stats.host_bytes_delivered = self.stats.host_bytes_delivered.saturating_add(read_len);
        self.record_audit(TunnelAuditEvent::PacketDeliveredToGuest {
            flow_id,
            sequence,
            bytes: read,
            interface_name: packet_path.device().interface_name().to_string(),
        })?;
        Ok(None)
    }

    /// Service one poll wakeup on either the guest session fd or the host TUN
    /// fd. A `gate` gates the guest→device direction (admitted packets forward,
    /// denied packets audit + drop); with no gate the guest→device direction is
    /// an unconditional forward. The device→guest reverse direction is always
    /// ungated — the host kernel only produces replies for admitted flows.
    pub fn pump_tun_relay_ready<D>(
        &mut self,
        packet_path: &mut HostTunPacketPath<D>,
        flow_id: u32,
        next_sequence: &mut u64,
        guest_ready: bool,
        host_ready: bool,
        gate: Option<&L3ForwardPolicy>,
    ) -> Result<HostRelayProgress, TunnelWorkerError>
    where
        D: host_tun::PacketDevice,
    {
        let mut progress = HostRelayProgress::default();
        if guest_ready {
            let frame = self
                .session
                .read_frame()
                .map_err(TunnelWorkerError::transport)?;
            match frame.header.frame_type {
                FrameType::Packet => {
                    let handled = match gate {
                        Some(gate) => self.handle_l3_forward_packet(frame, gate, packet_path)?,
                        None => self.handle_packet(frame, packet_path)?,
                    };
                    if let Some(outcome) = handled {
                        progress.outcome = Some(outcome);
                        return Ok(progress);
                    }
                    progress.guest_packets = 1;
                }
                other => {
                    if let Some(outcome) = self.handle_control(other, &frame.payload)? {
                        progress.outcome = Some(outcome);
                        return Ok(progress);
                    }
                }
            }
        }
        if host_ready {
            match self.pump_one_host_tun_to_guest(packet_path, flow_id, *next_sequence) {
                Ok(None) => {
                    *next_sequence = next_sequence.saturating_add(1);
                    progress.host_packets = 1;
                }
                Ok(Some(outcome)) => {
                    progress.outcome = Some(outcome);
                    return Ok(progress);
                }
                Err(TunnelWorkerError::PacketPath(detail)) => {
                    progress.outcome = Some(self.close_for_packet_path_failure(detail)?);
                    return Ok(progress);
                }
                Err(other) => return Err(other),
            }
        }
        Ok(progress)
    }

    /// Bidirectional relay with no egress gate: every guest packet forwards
    /// straight to the host TUN and every host reply frames back to the guest.
    pub fn run_blocking_tun_relay_loop<D>(
        &mut self,
        packet_path: &mut HostTunPacketPath<D>,
        flow_id: u32,
        next_sequence: u64,
    ) -> Result<TunnelWorkerOutcome, TunnelWorkerError>
    where
        D: host_tun::PacketDevice + AsRawFd,
    {
        self.run_blocking_relay_loop_gated(packet_path, flow_id, next_sequence, None)
    }

    /// Bidirectional relay with the admitted raw-L3 gate on the guest→device
    /// direction: only admitted packets reach the host TUN, replies frame back
    /// ungated, and both directions share the per-session quota. Requires the
    /// worker's `packet_policy` to be [`TunnelPacketPolicy::L3Forward`].
    pub fn run_blocking_l3_relay_loop<D>(
        &mut self,
        packet_path: &mut HostTunPacketPath<D>,
        flow_id: u32,
        next_sequence: u64,
    ) -> Result<TunnelWorkerOutcome, TunnelWorkerError>
    where
        D: host_tun::PacketDevice + AsRawFd,
    {
        let gate = match &self.config.packet_policy {
            TunnelPacketPolicy::L3Forward { gate, .. } => gate.clone(),
            _ => {
                return Err(TunnelWorkerError::InvalidConfig(
                    "run_blocking_l3_relay_loop requires an l3_forward packet policy",
                ));
            }
        };
        self.run_blocking_relay_loop_gated(packet_path, flow_id, next_sequence, Some(&gate))
    }

    fn run_blocking_relay_loop_gated<D>(
        &mut self,
        packet_path: &mut HostTunPacketPath<D>,
        flow_id: u32,
        mut next_sequence: u64,
        gate: Option<&L3ForwardPolicy>,
    ) -> Result<TunnelWorkerOutcome, TunnelWorkerError>
    where
        D: host_tun::PacketDevice + AsRawFd,
    {
        loop {
            let mut fds = [
                libc::pollfd {
                    fd: self.session.stream.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: packet_path.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: `fds` points to valid pollfd storage for exactly two fds,
            // and timeout -1 intentionally blocks until one side is ready.
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
            if rc < 0 {
                return Err(TunnelWorkerError::transport(anyhow::Error::new(
                    std::io::Error::last_os_error(),
                )));
            }
            if (fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                return Err(TunnelWorkerError::Transport(format!(
                    "guest tunnel session poll failed with revents=0x{:x}",
                    fds[0].revents
                )));
            }
            if (fds[1].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                let outcome = self.close_for_packet_path_failure(format!(
                    "host packet path poll failed with revents=0x{:x}",
                    fds[1].revents
                ))?;
                self.record_audit(TunnelAuditEvent::SessionClosed {
                    outcome: outcome.clone(),
                    stats: self.stats,
                })?;
                return Ok(outcome);
            }
            let progress = self.pump_tun_relay_ready(
                packet_path,
                flow_id,
                &mut next_sequence,
                (fds[0].revents & libc::POLLIN) != 0,
                (fds[1].revents & libc::POLLIN) != 0,
                gate,
            )?;
            if let Some(outcome) = progress.outcome {
                self.record_audit(TunnelAuditEvent::SessionClosed {
                    outcome: outcome.clone(),
                    stats: self.stats,
                })?;
                return Ok(outcome);
            }
        }
    }

    fn close_for_packet_path_failure(
        &mut self,
        detail: String,
    ) -> Result<TunnelWorkerOutcome, TunnelWorkerError> {
        self.send_control(
            TunnelControlMessage::Error(TunnelErrorFrame {
                code: TunnelErrorCode::Internal,
                detail: format!("host packet path failed: {detail}"),
            }),
            0,
        )?;
        self.send_control(
            TunnelControlMessage::Shutdown(TunnelShutdownReason::HostError),
            1,
        )?;
        Ok(TunnelWorkerOutcome::PacketPathFailed)
    }

    /// Block up to `timeout_ms` for the guest session fd to become readable. A
    /// negative timeout blocks indefinitely. A poll-driven egress loop (the
    /// macOS userspace stack) uses this so its own timers still fire while no
    /// guest frame is pending.
    pub fn poll_guest_readable(&self, timeout_ms: i32) -> Result<bool, TunnelWorkerError> {
        let mut fds = [libc::pollfd {
            fd: self.session.stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        // SAFETY: `fds` is one valid pollfd for the lifetime of the call.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 1, timeout_ms) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(TunnelWorkerError::transport(anyhow::Error::new(err)));
        }
        if (fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
            return Err(TunnelWorkerError::Transport(format!(
                "guest tunnel session poll failed with revents=0x{:x}",
                fds[0].revents
            )));
        }
        Ok((fds[0].revents & libc::POLLIN) != 0)
    }

    /// Read exactly one frame from the guest session and classify it for a
    /// poll-driven egress loop. Callers must confirm readability first
    /// (`poll_guest_readable`) so this doesn't block mid-loop.
    ///
    /// A packet frame is accounted against the per-session quota; a spent quota
    /// tells the guest to stop (fail closed) and yields
    /// [`GuestSessionEvent::Closed`]. A shutdown control frame also yields
    /// `Closed`; benign control frames yield [`GuestSessionEvent::Control`].
    pub fn read_guest_session_event(&mut self) -> Result<GuestSessionEvent, TunnelWorkerError> {
        let frame = self
            .session
            .read_frame()
            .map_err(TunnelWorkerError::transport)?;
        match frame.header.frame_type {
            FrameType::Packet => {
                let payload_len =
                    u64::try_from(frame.payload.len()).expect("packet length always fits u64");
                if let Some(outcome) =
                    self.account_and_check_quota(frame.header.sequence, payload_len)?
                {
                    return Ok(GuestSessionEvent::Closed(outcome));
                }
                Ok(GuestSessionEvent::Packet {
                    flow_id: frame.header.flow_id,
                    sequence: frame.header.sequence,
                    payload: frame.payload,
                })
            }
            other => match self.handle_control(other, &frame.payload)? {
                Some(outcome) => Ok(GuestSessionEvent::Closed(outcome)),
                None => Ok(GuestSessionEvent::Control),
            },
        }
    }

    /// Frame one host-origin IPv4 packet back to the guest. Reverse bytes count
    /// against the same per-session quota as guest egress; a spent quota tells
    /// the guest to stop and returns the outcome without delivering the packet.
    pub fn send_guest_packet(
        &mut self,
        flow_id: u32,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Result<Option<TunnelWorkerOutcome>, TunnelWorkerError> {
        let payload_len = u64::try_from(payload.len()).expect("packet length always fits u64");
        if let Some(outcome) = self.account_and_check_quota(sequence, payload_len)? {
            return Ok(Some(outcome));
        }
        let bytes = payload.len();
        self.session
            .send_packet(0, flow_id, sequence, payload)
            .map_err(TunnelWorkerError::transport)?;
        self.stats.host_packets_delivered = self.stats.host_packets_delivered.saturating_add(1);
        self.stats.host_bytes_delivered =
            self.stats.host_bytes_delivered.saturating_add(payload_len);
        self.record_audit(TunnelAuditEvent::PacketDeliveredToGuest {
            flow_id,
            sequence,
            bytes,
            interface_name: "mvm-smoltcp".to_string(),
        })?;
        Ok(None)
    }

    /// Record one tunnel audit event from a poll-driven egress loop.
    pub fn record_tunnel_audit(
        &mut self,
        event: TunnelAuditEvent,
    ) -> Result<(), TunnelWorkerError> {
        self.record_audit(event)
    }

    /// Tell the guest to stop on a host-side egress failure (Error + Shutdown),
    /// yielding [`TunnelWorkerOutcome::PacketPathFailed`].
    pub fn close_for_host_error(
        &mut self,
        detail: String,
    ) -> Result<TunnelWorkerOutcome, TunnelWorkerError> {
        self.close_for_packet_path_failure(detail)
    }

    /// Record the terminal `SessionClosed` audit event with final stats.
    pub fn record_session_closed(
        &mut self,
        outcome: TunnelWorkerOutcome,
    ) -> Result<(), TunnelWorkerError> {
        self.record_audit(TunnelAuditEvent::SessionClosed {
            outcome,
            stats: self.stats,
        })
    }
}

/// One event pulled from the guest session inside a poll-driven egress loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestSessionEvent {
    /// A raw guest IPv4 packet payload, with its framing coordinates.
    Packet {
        flow_id: u32,
        sequence: u64,
        payload: Vec<u8>,
    },
    /// The session ended (guest shutdown or a spent quota); stop with this
    /// outcome.
    Closed(TunnelWorkerOutcome),
    /// A benign control frame (heartbeat/credit) — keep looping.
    Control,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HostRelayProgress {
    pub guest_packets: u64,
    pub host_packets: u64,
    pub outcome: Option<TunnelWorkerOutcome>,
}

fn decode_to_anyhow(context: &'static str, err: DecodeError) -> anyhow::Error {
    anyhow::Error::new(err).context(context)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TunnelSessionError {
    #[error("transport failure: {0}")]
    Transport(String),
    #[error("guest hello is invalid: {0}")]
    InvalidHello(mvm_core::protocol::network_tunnel::ControlMessageError),
    #[error("guest hello tenant_id does not match host-owned session")]
    TenantMismatch,
    #[error("guest hello vm_id does not match host-owned session")]
    VmMismatch,
    #[error("guest hello boot_id does not match host-owned session")]
    BootMismatch,
    #[error("guest hello session_nonce does not match host-owned session")]
    SessionNonceMismatch,
    #[error("guest hello maximum_frame_size {guest} is smaller than host-required {host_minimum}")]
    FrameSizeTooSmall { guest: u32, host_minimum: u32 },
    #[error("expected guest hello as the first tunnel control frame, got {0:?}")]
    UnexpectedFirstFrame(FrameType),
}

impl TunnelSessionError {
    fn transport(err: anyhow::Error) -> Self {
        Self::Transport(err.to_string())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TunnelWorkerError {
    #[error("tunnel worker config is invalid: {0}")]
    InvalidConfig(&'static str),
    #[error("host-authored network config is invalid: {0}")]
    InvalidNetworkConfig(mvm_core::protocol::network_tunnel::ControlMessageError),
    #[error("host-authored initial credit is invalid: {0}")]
    InvalidInitialCredit(mvm_core::protocol::network_tunnel::ControlMessageError),
    #[error("host-authored packet policy is invalid: {0}")]
    InvalidPacketPolicy(String),
    #[error("tunnel session bootstrap failed: {0}")]
    Session(TunnelSessionError),
    #[error("transport failure: {0}")]
    Transport(String),
    #[error("control-plane failure: {0}")]
    Control(String),
    #[error("audit sink failure: {0}")]
    Audit(String),
    #[error("host packet path failure: {0}")]
    PacketPath(String),
    #[error("unexpected post-bootstrap control frame: {0:?}")]
    UnexpectedControlFrame(FrameType),
}

impl TunnelWorkerError {
    fn transport(err: anyhow::Error) -> Self {
        Self::Transport(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_l3::L3ForwardPolicy;
    use mvm_core::policy::dns_pin::DnsPin;
    use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
    use mvm_core::protocol::network_tunnel::NETWORK_TUNNEL_VERSION;
    use std::os::unix::net::UnixStream;

    fn pin_at(dest: &str, ips: &[&str]) -> DnsPin {
        DnsPin::at(
            dest,
            ips.iter().map(|s| s.parse().expect("ip")).collect(),
            "2026-05-15T12:00:00Z",
            "2026-05-15T13:00:00Z",
        )
    }

    #[test]
    fn host_entries_from_pins_maps_ipv4_pins_and_skips_ipv6() {
        let mut pins = DnsPinRegistry::new();
        // Mixed v4/v6 pin: only the v4 addresses become entries.
        pins.add(pin_at(
            "api.openai.com",
            &["104.18.7.42", "2606:4700::1111", "104.18.32.1"],
        ));
        pins.add(pin_at("example.com", &["93.184.216.34"]));
        // Pure-IPv6 pin contributes nothing.
        pins.add(pin_at("dns.google", &["2001:4860:4860::8888"]));

        let entries = host_entries_from_pins(&pins);
        // Sorted by dest (registry iteration order): api.openai.com (2 v4),
        // then example.com (1 v4); dns.google skipped entirely.
        assert_eq!(
            entries,
            vec![
                TunnelHostEntry {
                    name: "api.openai.com".to_string(),
                    ip: "104.18.7.42".parse().unwrap(),
                },
                TunnelHostEntry {
                    name: "api.openai.com".to_string(),
                    ip: "104.18.32.1".parse().unwrap(),
                },
                TunnelHostEntry {
                    name: "example.com".to_string(),
                    ip: "93.184.216.34".parse().unwrap(),
                },
            ]
        );
    }

    #[test]
    fn host_entries_from_pins_dedupes_and_caps() {
        let mut pins = DnsPinRegistry::new();
        // Duplicate v4 in one pin's set is collapsed to one entry.
        pins.add(pin_at("dup.example.com", &["1.2.3.4", "1.2.3.4"]));
        let deduped = host_entries_from_pins(&pins);
        assert_eq!(deduped.len(), 1);

        // Cap: many distinct (name, ip) pairs are truncated to MAX_HOST_ENTRIES.
        let mut big = DnsPinRegistry::new();
        for i in 0..(MAX_HOST_ENTRIES + 10) {
            big.add(pin_at(&format!("h{i:04}.example.com"), &["10.0.0.1"]));
        }
        let capped = host_entries_from_pins(&big);
        assert_eq!(capped.len(), MAX_HOST_ENTRIES);
    }

    #[test]
    fn worker_new_populates_host_entries_from_l3_gate_pins() {
        let (_guest, host) = UnixStream::pair().unwrap();
        let mut pins = DnsPinRegistry::new();
        pins.add(pin_at("api.example.com", &["93.184.216.34"]));
        let gate = L3ForwardPolicy::new(
            NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]),
            pins,
        );
        let config = TunnelWorkerConfig {
            expected_session: expected(),
            network_config: network_config(),
            initial_credit: initial_credit(),
            packet_policy: TunnelPacketPolicy::L3Forward {
                gate,
                interface_name: None,
            },
            limits: TunnelWorkerLimits::default(),
        };
        let worker = HostTunnelWorker::new(host, NoopTunnelAuditSink, config).unwrap();
        assert_eq!(
            worker.config.network_config.host_entries,
            vec![TunnelHostEntry {
                name: "api.example.com".to_string(),
                ip: "93.184.216.34".parse().unwrap(),
            }]
        );
    }

    fn expected() -> ExpectedTunnelSession {
        ExpectedTunnelSession {
            tenant_id: "tenant-a".to_string(),
            vm_id: "vm-1".to_string(),
            boot_id: "boot-1".to_string(),
            session_nonce: "nonce-1".to_string(),
            maximum_frame_size: 4096,
            accepted_features: TunnelFeatures {
                ipv4: true,
                split_control_stream: true,
                ..TunnelFeatures::default()
            },
        }
    }

    #[test]
    fn expected_session_can_build_from_shared_session_config() {
        let got = ExpectedTunnelSession::from_session_config(
            &TunnelSessionConfig {
                tenant_id: "tenant-a".to_string(),
                vm_id: "vm-1".to_string(),
                boot_id: "boot-1".to_string(),
                session_nonce: "nonce-1".to_string(),
                requested_features: TunnelFeatures::default(),
                maximum_frame_size: 4096,
            },
            TunnelFeatures {
                ipv4: true,
                split_control_stream: true,
                ..TunnelFeatures::default()
            },
        )
        .unwrap();

        assert_eq!(got, expected());
    }

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

    fn network_config() -> TunnelNetworkConfig {
        TunnelNetworkConfig {
            interface_name: "mvm-net0".to_string(),
            guest_ipv4: "10.240.0.2".parse().expect("ip"),
            prefix_len: 24,
            gateway_ipv4: "10.240.0.1".parse().expect("ip"),
            dns_servers: vec!["1.1.1.1".parse().expect("ip")],
            mtu: 1500,
            host_entries: Vec::new(),
        }
    }

    fn initial_credit() -> TunnelCreditUpdate {
        TunnelCreditUpdate {
            flow_id: 0,
            bytes: 64,
            packets: 4,
        }
    }

    #[test]
    fn accept_hello_validates_and_replies_with_ack() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut host = HostNetworkTunnelSession::new(host);
            let got = host.accept_hello(&expected(), 7).unwrap();
            assert_eq!(got, hello());
        });

        let mut guest = mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest);
        let ack = guest.negotiate(hello(), 1).unwrap();
        assert_eq!(ack, expected().hello_ack());
        host_thread.join().unwrap();
    }

    #[test]
    fn accept_hello_rejects_mismatched_vm_identity() {
        let (mut guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut host = HostNetworkTunnelSession::new(host);
            let err = host.accept_hello(&expected(), 7).unwrap_err();
            assert_eq!(err, TunnelSessionError::VmMismatch);
        });

        let bad = TunnelControlMessage::Hello(TunnelHello {
            vm_id: "vm-2".to_string(),
            ..hello()
        });
        let frame = bad.encode_frame(0, 0, 1).unwrap().encode();
        guest.write_all(&frame).unwrap();
        guest.flush().unwrap();
        host_thread.join().unwrap();
    }

    #[test]
    fn accept_hello_rejects_non_hello_first_frame() {
        let (mut guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut host = HostNetworkTunnelSession::new(host);
            let err = host.accept_hello(&expected(), 7).unwrap_err();
            assert_eq!(
                err,
                TunnelSessionError::UnexpectedFirstFrame(FrameType::Heartbeat)
            );
        });

        let frame = TunnelControlMessage::Heartbeat
            .encode_frame(0, 0, 1)
            .unwrap()
            .encode();
        guest.write_all(&frame).unwrap();
        guest.flush().unwrap();
        host_thread.join().unwrap();
    }

    #[test]
    fn packet_roundtrip_uses_shared_frame_shape() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut host = HostNetworkTunnelSession::new(host);
            let frame = host.recv_packet().unwrap();
            assert_eq!(frame.header.flow_id, 55);
            assert_eq!(frame.payload, vec![9, 8, 7]);
            host.send_packet(0, 56, 3, vec![1, 2, 3]).unwrap();
        });

        let mut guest = mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest);
        guest.send_packet(0, 55, 2, vec![9, 8, 7]).unwrap();
        let frame = guest.recv_packet().unwrap();
        assert_eq!(frame.header.flow_id, 56);
        assert_eq!(frame.payload, vec![1, 2, 3]);
        host_thread.join().unwrap();
    }

    #[test]
    fn accept_bootstrap_sends_host_network_config_after_ack() {
        let (guest, host) = UnixStream::pair().unwrap();
        let network_config = network_config();
        let host_config = network_config.clone();
        let host_thread = std::thread::spawn(move || {
            let mut host = HostNetworkTunnelSession::new(host);
            let got = host
                .accept_bootstrap(&expected(), host_config, 7, 8)
                .unwrap();
            assert_eq!(got, hello());
        });

        let mut guest = mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest);
        let ack = guest.negotiate(hello(), 1).unwrap();
        assert_eq!(ack, expected().hello_ack());
        let got = guest.recv_network_config().unwrap();
        assert_eq!(got, network_config);
        host_thread.join().unwrap();
    }

    #[derive(Debug, Default)]
    struct RecordingAuditSink {
        events: Vec<TunnelAuditEvent>,
    }

    #[derive(Debug)]
    struct FakePacketPath {
        interface_name: String,
        writes: Vec<Vec<u8>>,
        short_write_to: Option<usize>,
    }

    impl FakePacketPath {
        fn forwarding(interface_name: &str) -> Self {
            Self {
                interface_name: interface_name.to_string(),
                writes: Vec::new(),
                short_write_to: None,
            }
        }

        fn short_write(interface_name: &str, bytes: usize) -> Self {
            Self {
                interface_name: interface_name.to_string(),
                writes: Vec::new(),
                short_write_to: Some(bytes),
            }
        }
    }

    impl host_tun::PacketDevice for FakePacketPath {
        fn interface_name(&self) -> &str {
            &self.interface_name
        }

        fn read_packet(&mut self, _buf: &mut [u8]) -> Result<usize> {
            bail!("read_packet is not used in this test helper")
        }

        fn write_packet(&mut self, packet: &[u8]) -> Result<usize> {
            self.writes.push(packet.to_vec());
            Ok(self.short_write_to.unwrap_or(packet.len()))
        }
    }

    #[derive(Debug)]
    struct StreamPacketDevice {
        interface_name: String,
        stream: UnixStream,
    }

    impl StreamPacketDevice {
        fn new(interface_name: &str, stream: UnixStream) -> Self {
            Self {
                interface_name: interface_name.to_string(),
                stream,
            }
        }
    }

    impl host_tun::PacketDevice for StreamPacketDevice {
        fn interface_name(&self) -> &str {
            &self.interface_name
        }

        fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
            self.stream.read(buf).map_err(anyhow::Error::new)
        }

        fn write_packet(&mut self, packet: &[u8]) -> Result<usize> {
            self.stream.write(packet).map_err(anyhow::Error::new)
        }
    }

    impl AsRawFd for StreamPacketDevice {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            self.stream.as_raw_fd()
        }
    }

    impl TunnelAuditSink for RecordingAuditSink {
        type Error = std::convert::Infallible;

        fn record(&mut self, event: TunnelAuditEvent) -> Result<(), Self::Error> {
            self.events.push(event);
            Ok(())
        }
    }

    #[test]
    fn worker_bootstraps_and_drops_guest_packets_under_default_deny() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut worker = HostTunnelWorker::new(
                host,
                RecordingAuditSink::default(),
                TunnelWorkerConfig {
                    expected_session: expected(),
                    network_config: network_config(),
                    initial_credit: initial_credit(),
                    packet_policy: TunnelPacketPolicy::DropAll,
                    limits: TunnelWorkerLimits::default(),
                },
            )
            .unwrap();
            let guest_hello = worker.bootstrap(7, 8, 9).unwrap();
            assert_eq!(guest_hello, hello());
            let outcome = worker.run_until_shutdown().unwrap();
            assert_eq!(
                outcome,
                TunnelWorkerOutcome::GuestShutdown(TunnelShutdownReason::GuestStopping)
            );
            assert_eq!(
                *worker.stats(),
                TunnelWorkerStats {
                    guest_packets_seen: 1,
                    guest_bytes_seen: 3,
                    guest_packets_dropped: 1,
                    guest_bytes_dropped: 3,
                    guest_packets_l3_allowed: 0,
                    guest_bytes_l3_allowed: 0,
                    guest_packets_forwarded: 0,
                    guest_bytes_forwarded: 0,
                    host_packets_delivered: 0,
                    host_bytes_delivered: 0,
                    host_control_frames_sent: 1,
                }
            );
            assert_eq!(worker.audit().events.len(), 3);
            assert!(matches!(
                worker.audit().events[0],
                TunnelAuditEvent::SessionBootstrapped { .. }
            ));
            assert!(matches!(
                worker.audit().events[1],
                TunnelAuditEvent::PacketDropped {
                    flow_id: 55,
                    sequence: 2,
                    bytes: 3
                }
            ));
            assert!(matches!(
                worker.audit().events[2],
                TunnelAuditEvent::SessionClosed {
                    outcome: TunnelWorkerOutcome::GuestShutdown(
                        TunnelShutdownReason::GuestStopping
                    ),
                    ..
                }
            ));
        });

        let mut guest = mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest);
        let ack = guest.negotiate(hello(), 1).unwrap();
        assert_eq!(ack, expected().hello_ack());
        assert_eq!(guest.recv_network_config().unwrap(), network_config());
        assert_eq!(
            guest.recv_control().unwrap(),
            TunnelControlMessage::Credit(initial_credit())
        );
        guest.send_packet(0, 55, 2, vec![9, 8, 7]).unwrap();
        guest
            .send_control(
                TunnelControlMessage::Shutdown(TunnelShutdownReason::GuestStopping),
                0,
                0,
                3,
            )
            .unwrap();
        host_thread.join().unwrap();
    }

    #[test]
    fn worker_enforces_packet_quota_and_sends_shutdown() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut worker = HostTunnelWorker::new(
                host,
                RecordingAuditSink::default(),
                TunnelWorkerConfig {
                    expected_session: expected(),
                    network_config: network_config(),
                    initial_credit: initial_credit(),
                    packet_policy: TunnelPacketPolicy::DropAll,
                    limits: TunnelWorkerLimits {
                        max_packets: 1,
                        max_bytes: 64,
                    },
                },
            )
            .unwrap();
            worker.bootstrap(7, 8, 9).unwrap();
            let outcome = worker.run_until_shutdown().unwrap();
            assert_eq!(outcome, TunnelWorkerOutcome::QuotaExceeded);
            assert_eq!(worker.stats().guest_packets_seen, 2);
            assert_eq!(worker.stats().guest_packets_dropped, 1);
            assert_eq!(worker.stats().guest_packets_forwarded, 0);
            assert_eq!(worker.stats().host_control_frames_sent, 3);
        });

        let mut guest = mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest);
        let _ack = guest.negotiate(hello(), 1).unwrap();
        let _config = guest.recv_network_config().unwrap();
        let _credit = guest.recv_control().unwrap();
        guest.send_packet(0, 55, 2, vec![1, 2, 3]).unwrap();
        guest.send_packet(0, 55, 3, vec![4, 5, 6]).unwrap();
        let error = guest.recv_control().unwrap();
        assert!(matches!(
            error,
            TunnelControlMessage::Error(TunnelErrorFrame {
                code: TunnelErrorCode::QuotaExceeded,
                ..
            })
        ));
        let shutdown = guest.recv_control().unwrap();
        assert_eq!(
            shutdown,
            TunnelControlMessage::Shutdown(TunnelShutdownReason::PolicyDenied)
        );
        host_thread.join().unwrap();
    }

    #[test]
    fn worker_can_forward_guest_packets_into_host_packet_path() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut worker = HostTunnelWorker::new(
                host,
                RecordingAuditSink::default(),
                TunnelWorkerConfig {
                    expected_session: expected(),
                    network_config: network_config(),
                    initial_credit: initial_credit(),
                    packet_policy: TunnelPacketPolicy::DropAll,
                    limits: TunnelWorkerLimits::default(),
                },
            )
            .unwrap();
            let mut packet_path = HostTunPacketPath::new(FakePacketPath::forwarding("mvmht0"));
            worker.bootstrap(7, 8, 9).unwrap();
            let outcome = worker
                .run_until_shutdown_with_packet_path(&mut packet_path)
                .unwrap();
            assert_eq!(
                outcome,
                TunnelWorkerOutcome::GuestShutdown(TunnelShutdownReason::GuestStopping)
            );
            assert_eq!(packet_path.device().writes, vec![vec![9, 8, 7]]);
            assert_eq!(worker.stats().guest_packets_forwarded, 1);
            assert_eq!(worker.stats().guest_bytes_forwarded, 3);
            assert!(matches!(
                worker.audit().events[1],
                TunnelAuditEvent::PacketForwarded {
                    flow_id: 55,
                    sequence: 2,
                    bytes: 3,
                    ref interface_name,
                } if interface_name == "mvmht0"
            ));
        });

        let mut guest = mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest);
        let _ack = guest.negotiate(hello(), 1).unwrap();
        let _config = guest.recv_network_config().unwrap();
        let _credit = guest.recv_control().unwrap();
        guest.send_packet(0, 55, 2, vec![9, 8, 7]).unwrap();
        guest
            .send_control(
                TunnelControlMessage::Shutdown(TunnelShutdownReason::GuestStopping),
                0,
                0,
                3,
            )
            .unwrap();
        host_thread.join().unwrap();
    }

    #[test]
    fn worker_fails_closed_when_host_packet_path_short_writes() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut worker = HostTunnelWorker::new(
                host,
                RecordingAuditSink::default(),
                TunnelWorkerConfig {
                    expected_session: expected(),
                    network_config: network_config(),
                    initial_credit: initial_credit(),
                    packet_policy: TunnelPacketPolicy::DropAll,
                    limits: TunnelWorkerLimits::default(),
                },
            )
            .unwrap();
            let mut packet_path = HostTunPacketPath::new(FakePacketPath::short_write("mvmht0", 2));
            worker.bootstrap(7, 8, 9).unwrap();
            let outcome = worker
                .run_until_shutdown_with_packet_path(&mut packet_path)
                .unwrap();
            assert_eq!(outcome, TunnelWorkerOutcome::PacketPathFailed);
            assert_eq!(worker.stats().host_control_frames_sent, 3);
            assert!(matches!(
                worker.audit().events[1],
                TunnelAuditEvent::SessionClosed {
                    outcome: TunnelWorkerOutcome::PacketPathFailed,
                    ..
                }
            ));
        });

        let mut guest = mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest);
        let _ack = guest.negotiate(hello(), 1).unwrap();
        let _config = guest.recv_network_config().unwrap();
        let _credit = guest.recv_control().unwrap();
        guest.send_packet(0, 55, 2, vec![9, 8, 7]).unwrap();
        let error = guest.recv_control().unwrap();
        assert!(matches!(
            error,
            TunnelControlMessage::Error(TunnelErrorFrame {
                code: TunnelErrorCode::Internal,
                ..
            })
        ));
        let shutdown = guest.recv_control().unwrap();
        assert_eq!(
            shutdown,
            TunnelControlMessage::Shutdown(TunnelShutdownReason::HostError)
        );
        host_thread.join().unwrap();
    }

    fn l3_gate(host: &str, port: u16, pinned_ips: &[&str]) -> crate::net_l3::L3ForwardPolicy {
        use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
        let policy = NetworkPolicy::allow_list(vec![HostPort::new(host, port)]);
        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            host,
            pinned_ips.iter().map(|s| s.parse().expect("ip")).collect(),
            "2026-05-15T12:00:00Z",
            "2026-05-15T13:00:00Z",
        ));
        crate::net_l3::L3ForwardPolicy::new(policy, pins)
    }

    /// A minimal IPv4/TCP packet targeting `dst:dst_port`.
    fn ipv4_tcp_packet(dst: &str, dst_port: u16) -> Vec<u8> {
        let octets: std::net::Ipv4Addr = dst.parse().expect("ipv4");
        let mut p = vec![0_u8; 24];
        p[0] = 0x45; // version 4, IHL 5
        p[9] = 6; // TCP
        p[16..20].copy_from_slice(&octets.octets());
        p[22..24].copy_from_slice(&dst_port.to_be_bytes());
        p
    }

    #[test]
    fn l3_gate_drops_unparseable_packet_and_audits() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut worker = HostTunnelWorker::new(
                host,
                RecordingAuditSink::default(),
                TunnelWorkerConfig {
                    expected_session: expected(),
                    network_config: network_config(),
                    initial_credit: initial_credit(),
                    packet_policy: TunnelPacketPolicy::L3Forward {
                        gate: l3_gate("api.example.com", 443, &["93.184.216.34"]),
                        interface_name: None,
                    },
                    limits: TunnelWorkerLimits::default(),
                },
            )
            .unwrap();
            worker.bootstrap(7, 8, 9).unwrap();
            let outcome = worker.run_until_shutdown_l3_gate().unwrap();
            assert_eq!(
                outcome,
                TunnelWorkerOutcome::GuestShutdown(TunnelShutdownReason::GuestStopping)
            );
            // Everything is still dropped until egress is wired.
            assert_eq!(worker.stats().guest_packets_dropped, 1);
            assert_eq!(worker.stats().guest_packets_l3_allowed, 0);
            assert!(worker.audit().events.iter().any(|event| matches!(
                event,
                TunnelAuditEvent::PacketL3Dropped {
                    reason: crate::net_l3::L3DropReason::Unparseable,
                    ..
                }
            )));
        });

        let mut guest = mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest);
        let _ack = guest.negotiate(hello(), 1).unwrap();
        let _config = guest.recv_network_config().unwrap();
        let _credit = guest.recv_control().unwrap();
        // Too short to be an IPv4 header → Unparseable.
        guest.send_packet(0, 55, 2, vec![1, 2, 3]).unwrap();
        guest
            .send_control(
                TunnelControlMessage::Shutdown(TunnelShutdownReason::GuestStopping),
                0,
                0,
                3,
            )
            .unwrap();
        host_thread.join().unwrap();
    }

    #[test]
    fn l3_gate_allows_pinned_packet_and_audits_but_still_drops() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut worker = HostTunnelWorker::new(
                host,
                RecordingAuditSink::default(),
                TunnelWorkerConfig {
                    expected_session: expected(),
                    network_config: network_config(),
                    initial_credit: initial_credit(),
                    packet_policy: TunnelPacketPolicy::L3Forward {
                        gate: l3_gate("api.example.com", 443, &["93.184.216.34"]),
                        interface_name: None,
                    },
                    limits: TunnelWorkerLimits::default(),
                },
            )
            .unwrap();
            worker.bootstrap(7, 8, 9).unwrap();
            let outcome = worker.run_until_shutdown_l3_gate().unwrap();
            assert_eq!(
                outcome,
                TunnelWorkerOutcome::GuestShutdown(TunnelShutdownReason::GuestStopping)
            );
            assert_eq!(worker.stats().guest_packets_l3_allowed, 1);
            // Allowed, but egress isn't wired yet — nothing is forwarded.
            assert_eq!(worker.stats().guest_packets_forwarded, 0);
            assert_eq!(worker.stats().guest_packets_dropped, 1);
            assert!(worker.audit().events.iter().any(|event| matches!(
                event,
                TunnelAuditEvent::PacketL3Allowed {
                    flow_id: 55,
                    dst_port: Some(443),
                    ..
                }
            )));
        });

        let mut guest = mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest);
        let _ack = guest.negotiate(hello(), 1).unwrap();
        let _config = guest.recv_network_config().unwrap();
        let _credit = guest.recv_control().unwrap();
        guest
            .send_packet(0, 55, 2, ipv4_tcp_packet("93.184.216.34", 443))
            .unwrap();
        guest
            .send_control(
                TunnelControlMessage::Shutdown(TunnelShutdownReason::GuestStopping),
                0,
                0,
                3,
            )
            .unwrap();
        host_thread.join().unwrap();
    }

    #[test]
    fn host_tun_forward_injects_only_admitted_packets() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut worker = HostTunnelWorker::new(
                host,
                RecordingAuditSink::default(),
                TunnelWorkerConfig {
                    expected_session: expected(),
                    network_config: network_config(),
                    initial_credit: initial_credit(),
                    packet_policy: TunnelPacketPolicy::L3Forward {
                        gate: l3_gate("api.example.com", 443, &["93.184.216.34"]),
                        interface_name: Some("mvmht0".to_string()),
                    },
                    limits: TunnelWorkerLimits::default(),
                },
            )
            .unwrap();
            let mut packet_path = HostTunPacketPath::new(FakePacketPath::forwarding("mvmht0"));
            worker.bootstrap(7, 8, 9).unwrap();
            let outcome = worker
                .run_until_shutdown_l3_forward_with_packet_path(&mut packet_path)
                .unwrap();
            assert_eq!(
                outcome,
                TunnelWorkerOutcome::GuestShutdown(TunnelShutdownReason::GuestStopping)
            );
            // Exactly the admitted packet is written to the device; the denied
            // one never reaches it.
            assert_eq!(
                packet_path.device().writes,
                vec![ipv4_tcp_packet("93.184.216.34", 443)]
            );
            assert_eq!(worker.stats().guest_packets_forwarded, 1);
            assert_eq!(worker.stats().guest_packets_l3_allowed, 1);
            // The denied packet is counted as dropped, not forwarded.
            assert_eq!(worker.stats().guest_packets_dropped, 1);
            assert!(worker.audit().events.iter().any(|event| matches!(
                event,
                TunnelAuditEvent::PacketForwarded { interface_name, .. }
                    if interface_name == "mvmht0"
            )));
        });

        let mut guest = mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest);
        let _ack = guest.negotiate(hello(), 1).unwrap();
        let _config = guest.recv_network_config().unwrap();
        let _credit = guest.recv_control().unwrap();
        // Admitted destination — forwarded to the device.
        guest
            .send_packet(0, 55, 2, ipv4_tcp_packet("93.184.216.34", 443))
            .unwrap();
        // Unpinned destination — dropped, never written to the device.
        guest
            .send_packet(0, 55, 3, ipv4_tcp_packet("203.0.113.7", 443))
            .unwrap();
        guest
            .send_control(
                TunnelControlMessage::Shutdown(TunnelShutdownReason::GuestStopping),
                0,
                0,
                4,
            )
            .unwrap();
        host_thread.join().unwrap();
    }

    #[test]
    fn denied_packet_never_reaches_host_tun() {
        let (guest, host) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut worker = HostTunnelWorker::new(
                host,
                RecordingAuditSink::default(),
                TunnelWorkerConfig {
                    expected_session: expected(),
                    network_config: network_config(),
                    initial_credit: initial_credit(),
                    packet_policy: TunnelPacketPolicy::L3Forward {
                        gate: l3_gate("api.example.com", 443, &["93.184.216.34"]),
                        interface_name: Some("mvmht0".to_string()),
                    },
                    limits: TunnelWorkerLimits::default(),
                },
            )
            .unwrap();
            let mut packet_path = HostTunPacketPath::new(FakePacketPath::forwarding("mvmht0"));
            worker.bootstrap(7, 8, 9).unwrap();
            let outcome = worker
                .run_until_shutdown_l3_forward_with_packet_path(&mut packet_path)
                .unwrap();
            assert_eq!(
                outcome,
                TunnelWorkerOutcome::GuestShutdown(TunnelShutdownReason::GuestStopping)
            );
            // The denied packet produced zero device writes.
            assert!(packet_path.device().writes.is_empty());
            assert_eq!(worker.stats().guest_packets_forwarded, 0);
            assert_eq!(worker.stats().guest_packets_dropped, 1);
            assert!(worker.audit().events.iter().any(|event| matches!(
                event,
                TunnelAuditEvent::PacketL3Dropped {
                    reason: crate::net_l3::L3DropReason::UnpinnedDst,
                    ..
                }
            )));
        });

        let mut guest = mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest);
        let _ack = guest.negotiate(hello(), 1).unwrap();
        let _config = guest.recv_network_config().unwrap();
        let _credit = guest.recv_control().unwrap();
        guest
            .send_packet(0, 55, 2, ipv4_tcp_packet("203.0.113.7", 443))
            .unwrap();
        guest
            .send_control(
                TunnelControlMessage::Shutdown(TunnelShutdownReason::GuestStopping),
                0,
                0,
                3,
            )
            .unwrap();
        host_thread.join().unwrap();
    }

    #[test]
    fn worker_run_blocking_tun_relay_loop_relays_both_directions() {
        let (guest, host) = UnixStream::pair().unwrap();
        let (device_host, mut device_peer) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut worker = HostTunnelWorker::new(
                host,
                RecordingAuditSink::default(),
                TunnelWorkerConfig {
                    expected_session: expected(),
                    network_config: network_config(),
                    initial_credit: initial_credit(),
                    packet_policy: TunnelPacketPolicy::DropAll,
                    limits: TunnelWorkerLimits::default(),
                },
            )
            .unwrap();
            let mut packet_path =
                HostTunPacketPath::new(StreamPacketDevice::new("mvmht0", device_host));
            worker.bootstrap(7, 8, 9).unwrap();
            let outcome = worker
                .run_blocking_tun_relay_loop(&mut packet_path, 0, 10)
                .unwrap();
            assert_eq!(
                outcome,
                TunnelWorkerOutcome::GuestShutdown(TunnelShutdownReason::GuestStopping)
            );
            assert_eq!(worker.stats().guest_packets_forwarded, 1);
            assert_eq!(worker.stats().host_packets_delivered, 1);
            assert!(worker.audit().events.iter().any(|event| matches!(
                event,
                TunnelAuditEvent::PacketForwarded { flow_id: 55, sequence: 2, bytes: 3, interface_name }
                    if interface_name == "mvmht0"
            )));
            assert!(worker.audit().events.iter().any(|event| matches!(
                event,
                TunnelAuditEvent::PacketDeliveredToGuest { flow_id: 0, sequence: 10, bytes: 3, interface_name }
                    if interface_name == "mvmht0"
            )));
        });

        let mut guest = mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest);
        let _ack = guest.negotiate(hello(), 1).unwrap();
        let _config = guest.recv_network_config().unwrap();
        let _credit = guest.recv_control().unwrap();

        guest.send_packet(0, 55, 2, vec![1, 2, 3]).unwrap();
        let mut guest_packet = [0_u8; 3];
        device_peer.read_exact(&mut guest_packet).unwrap();
        assert_eq!(&guest_packet, &[1, 2, 3]);

        device_peer.write_all(&[4, 5, 6]).unwrap();
        let frame = guest.recv_packet().unwrap();
        assert_eq!(frame.header.flow_id, 0);
        assert_eq!(frame.header.sequence, 10);
        assert_eq!(frame.payload, vec![4, 5, 6]);

        guest
            .send_control(
                TunnelControlMessage::Shutdown(TunnelShutdownReason::GuestStopping),
                0,
                0,
                3,
            )
            .unwrap();
        host_thread.join().unwrap();
    }

    #[test]
    fn host_tun_reply_packets_frame_back_to_guest() {
        let (guest, host) = UnixStream::pair().unwrap();
        let (device_host, mut device_peer) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut worker = HostTunnelWorker::new(
                host,
                RecordingAuditSink::default(),
                TunnelWorkerConfig {
                    expected_session: expected(),
                    network_config: network_config(),
                    initial_credit: initial_credit(),
                    packet_policy: TunnelPacketPolicy::L3Forward {
                        gate: l3_gate("api.example.com", 443, &["93.184.216.34"]),
                        interface_name: Some("mvmht0".to_string()),
                    },
                    limits: TunnelWorkerLimits::default(),
                },
            )
            .unwrap();
            let mut packet_path =
                HostTunPacketPath::new(StreamPacketDevice::new("mvmht0", device_host));
            worker.bootstrap(7, 8, 9).unwrap();
            let outcome = worker
                .run_blocking_l3_relay_loop(&mut packet_path, 0, 10)
                .unwrap();
            assert_eq!(
                outcome,
                TunnelWorkerOutcome::GuestShutdown(TunnelShutdownReason::GuestStopping)
            );
            assert_eq!(worker.stats().host_packets_delivered, 1);
            assert_eq!(worker.stats().host_bytes_delivered, 3);
            assert!(worker.audit().events.iter().any(|event| matches!(
                event,
                TunnelAuditEvent::PacketDeliveredToGuest {
                    flow_id: 0,
                    sequence: 10,
                    bytes: 3,
                    interface_name,
                } if interface_name == "mvmht0"
            )));
        });

        let mut guest = mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest);
        let _ack = guest.negotiate(hello(), 1).unwrap();
        let _config = guest.recv_network_config().unwrap();
        let _credit = guest.recv_control().unwrap();

        // A reply arrives on the host TUN and is framed back to the guest.
        device_peer.write_all(&[4, 5, 6]).unwrap();
        let frame = guest.recv_packet().unwrap();
        assert_eq!(frame.header.flow_id, 0);
        assert_eq!(frame.header.sequence, 10);
        assert_eq!(frame.payload, vec![4, 5, 6]);

        guest
            .send_control(
                TunnelControlMessage::Shutdown(TunnelShutdownReason::GuestStopping),
                0,
                0,
                3,
            )
            .unwrap();
        host_thread.join().unwrap();
    }

    #[test]
    fn l3_relay_loop_gates_guest_forward_direction() {
        let (guest, host) = UnixStream::pair().unwrap();
        let (device_host, mut device_peer) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut worker = HostTunnelWorker::new(
                host,
                RecordingAuditSink::default(),
                TunnelWorkerConfig {
                    expected_session: expected(),
                    network_config: network_config(),
                    initial_credit: initial_credit(),
                    packet_policy: TunnelPacketPolicy::L3Forward {
                        gate: l3_gate("api.example.com", 443, &["93.184.216.34"]),
                        interface_name: Some("mvmht0".to_string()),
                    },
                    limits: TunnelWorkerLimits::default(),
                },
            )
            .unwrap();
            let mut packet_path =
                HostTunPacketPath::new(StreamPacketDevice::new("mvmht0", device_host));
            worker.bootstrap(7, 8, 9).unwrap();
            let outcome = worker
                .run_blocking_l3_relay_loop(&mut packet_path, 0, 10)
                .unwrap();
            assert_eq!(
                outcome,
                TunnelWorkerOutcome::GuestShutdown(TunnelShutdownReason::GuestStopping)
            );
            // Only the admitted guest packet reached the device; the denied one
            // was dropped by the gate before any byte was written.
            assert_eq!(worker.stats().guest_packets_forwarded, 1);
            assert_eq!(worker.stats().guest_packets_dropped, 1);
            assert_eq!(worker.stats().host_packets_delivered, 1);
        });

        let mut guest = mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest);
        let _ack = guest.negotiate(hello(), 1).unwrap();
        let _config = guest.recv_network_config().unwrap();
        let _credit = guest.recv_control().unwrap();

        // Admitted destination is forwarded to the device.
        guest
            .send_packet(0, 55, 2, ipv4_tcp_packet("93.184.216.34", 443))
            .unwrap();
        let mut admitted = [0_u8; 24];
        device_peer.read_exact(&mut admitted).unwrap();
        assert_eq!(admitted.to_vec(), ipv4_tcp_packet("93.184.216.34", 443));

        // Denied destination is dropped by the gate, never written to the device.
        guest
            .send_packet(0, 55, 3, ipv4_tcp_packet("203.0.113.7", 443))
            .unwrap();

        // A reply still frames back to the guest, proving the reverse path runs
        // alongside the gated forward path.
        device_peer.write_all(&[4, 5, 6]).unwrap();
        let reply = guest.recv_packet().unwrap();
        assert_eq!(reply.header.sequence, 10);
        assert_eq!(reply.payload, vec![4, 5, 6]);

        guest
            .send_control(
                TunnelControlMessage::Shutdown(TunnelShutdownReason::GuestStopping),
                0,
                0,
                4,
            )
            .unwrap();
        host_thread.join().unwrap();
    }

    #[test]
    fn reverse_path_respects_worker_limits() {
        let (guest, host) = UnixStream::pair().unwrap();
        let (device_host, mut device_peer) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut worker = HostTunnelWorker::new(
                host,
                RecordingAuditSink::default(),
                TunnelWorkerConfig {
                    expected_session: expected(),
                    network_config: network_config(),
                    initial_credit: initial_credit(),
                    packet_policy: TunnelPacketPolicy::L3Forward {
                        gate: l3_gate("api.example.com", 443, &["93.184.216.34"]),
                        interface_name: Some("mvmht0".to_string()),
                    },
                    // One packet of reverse budget: the second reply must fail closed.
                    limits: TunnelWorkerLimits {
                        max_packets: 1,
                        max_bytes: 1024,
                    },
                },
            )
            .unwrap();
            let mut packet_path =
                HostTunPacketPath::new(StreamPacketDevice::new("mvmht0", device_host));
            worker.bootstrap(7, 8, 9).unwrap();
            let outcome = worker
                .run_blocking_l3_relay_loop(&mut packet_path, 0, 10)
                .unwrap();
            assert_eq!(outcome, TunnelWorkerOutcome::QuotaExceeded);
            // The first reply was delivered; the second spent the quota and was
            // never framed back.
            assert_eq!(worker.stats().host_packets_delivered, 1);
            assert_eq!(worker.stats().guest_packets_seen, 2);
        });

        let mut guest = mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest);
        let _ack = guest.negotiate(hello(), 1).unwrap();
        let _config = guest.recv_network_config().unwrap();
        let _credit = guest.recv_control().unwrap();

        // First reply is delivered; wait for it before sending the second so the
        // stream device doesn't coalesce both into one read.
        device_peer.write_all(&[4, 5, 6]).unwrap();
        let frame = guest.recv_packet().unwrap();
        assert_eq!(frame.payload, vec![4, 5, 6]);

        // Second reply exceeds the packet budget and fails closed.
        device_peer.write_all(&[7, 8, 9]).unwrap();
        let error = guest.recv_control().unwrap();
        assert!(matches!(
            error,
            TunnelControlMessage::Error(TunnelErrorFrame {
                code: TunnelErrorCode::QuotaExceeded,
                ..
            })
        ));
        let shutdown = guest.recv_control().unwrap();
        assert_eq!(
            shutdown,
            TunnelControlMessage::Shutdown(TunnelShutdownReason::PolicyDenied)
        );
        host_thread.join().unwrap();
    }

    #[test]
    fn reverse_path_quota_exhaustion_shuts_down() {
        let (guest, host) = UnixStream::pair().unwrap();
        let (device_host, mut device_peer) = UnixStream::pair().unwrap();
        let host_thread = std::thread::spawn(move || {
            let mut worker = HostTunnelWorker::new(
                host,
                RecordingAuditSink::default(),
                TunnelWorkerConfig {
                    expected_session: expected(),
                    network_config: network_config(),
                    initial_credit: initial_credit(),
                    packet_policy: TunnelPacketPolicy::L3Forward {
                        gate: l3_gate("api.example.com", 443, &["93.184.216.34"]),
                        interface_name: Some("mvmht0".to_string()),
                    },
                    // Two-byte reverse byte budget: a single 3-byte reply blows it.
                    limits: TunnelWorkerLimits {
                        max_packets: 10,
                        max_bytes: 2,
                    },
                },
            )
            .unwrap();
            let mut packet_path =
                HostTunPacketPath::new(StreamPacketDevice::new("mvmht0", device_host));
            worker.bootstrap(7, 8, 9).unwrap();
            let outcome = worker
                .run_blocking_l3_relay_loop(&mut packet_path, 0, 10)
                .unwrap();
            assert_eq!(outcome, TunnelWorkerOutcome::QuotaExceeded);
            // The reply's bytes spent the budget before delivery, so nothing was
            // framed back to the guest.
            assert_eq!(worker.stats().host_packets_delivered, 0);
            assert_eq!(worker.stats().guest_bytes_seen, 3);
            assert!(worker.audit().events.iter().any(|event| matches!(
                event,
                TunnelAuditEvent::SessionClosed {
                    outcome: TunnelWorkerOutcome::QuotaExceeded,
                    ..
                }
            )));
        });

        let mut guest = mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest);
        let _ack = guest.negotiate(hello(), 1).unwrap();
        let _config = guest.recv_network_config().unwrap();
        let _credit = guest.recv_control().unwrap();

        // One oversize-for-quota reply arrives; the loop fails closed with the
        // shared ERROR + SHUTDOWN control frames.
        device_peer.write_all(&[4, 5, 6]).unwrap();
        let error = guest.recv_control().unwrap();
        assert!(matches!(
            error,
            TunnelControlMessage::Error(TunnelErrorFrame {
                code: TunnelErrorCode::QuotaExceeded,
                ..
            })
        ));
        let shutdown = guest.recv_control().unwrap();
        assert_eq!(
            shutdown,
            TunnelControlMessage::Shutdown(TunnelShutdownReason::PolicyDenied)
        );
        host_thread.join().unwrap();
    }
}
