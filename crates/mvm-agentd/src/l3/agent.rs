//! The in-guest tunnel agent.
//!
//! Generic over the transport (`Read + Write`), the TUN device, and the
//! interface configurator, so the entire lifecycle — handshake, apply
//! config, pump packets, fail closed — runs in ordinary unprivileged tests.
//! Only the ioctl and capability bodies are platform-gated.
//!
//! Steady state allocates nothing: one MTU-sized read buffer, one framing
//! buffer, one accumulator, all sized at construction and reused.

use std::io::{Read, Write};

use mvm_contract::l3::{
    Config, ErrorCode, ErrorMessage, Heartbeat, Hello, MessageType, Ready, Shutdown,
    ShutdownReason, frame, limits, message,
};

use super::netcfg::{InterfaceConfigurator, InterfacePlan};
use super::privdrop::{PrivilegeDropper, SystemPrivilegeDropper};
use super::tun::{TunDevice, TunError};

/// Where the agent is in its lifecycle. A workload supervisor reads this to
/// decide whether networking is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    /// Nothing opened yet.
    Init,
    /// `HELLO` sent, waiting for `CONFIG`.
    Handshaking,
    /// Interface configured, `READY` sent. Packets may flow.
    Ready,
    /// Networking is unavailable and will not come back under this session.
    Unavailable,
}

impl AgentState {
    /// Whether the workload has networking right now. The supervisor gates
    /// a network-requiring workload on this.
    pub fn network_available(&self) -> bool {
        *self == AgentState::Ready
    }
}

/// Bounded counters. Exposed as metrics; never a log line per packet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AgentCounters {
    pub packets_out: u64,
    pub packets_in: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub oversized_dropped: u64,
    pub malformed_dropped: u64,
    pub stale_session_dropped: u64,
    pub tun_write_failed: u64,
}

/// Why the agent could not proceed.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// Transport I/O failed.
    #[error("tunnel transport failed: {0}")]
    Transport(#[from] std::io::Error),
    /// The host sent something the protocol does not permit.
    #[error("protocol violation: {0}")]
    Protocol(String),
    /// A control message payload was malformed.
    #[error(transparent)]
    Message(#[from] message::MessageError),
    /// The interface could not be created or configured.
    #[error(transparent)]
    Interface(#[from] TunError),
    /// The host refused to admit the tunnel.
    #[error("host refused the tunnel: {code:?}: {detail}")]
    Refused { code: ErrorCode, detail: String },
    /// Privileges could not be fully dropped, so the pump must not start.
    #[error("privilege drop incomplete: {}", .0.join(", "))]
    PrivilegeDropIncomplete(Vec<&'static str>),
}

/// The guest-side tunnel agent.
pub struct NetAgent<T: TunDevice, C: InterfaceConfigurator> {
    tun: T,
    configurator: C,
    /// Injected because the drop is a process-global, one-way side effect:
    /// a test that performed the real one would disarm its own runner.
    privileges: Box<dyn PrivilegeDropper>,
    state: AgentState,
    session_id: u64,
    plan: Option<InterfacePlan>,
    negotiated_mtu: u16,
    policy_epoch: u64,
    resolver_configured: bool,
    counters: AgentCounters,
    heartbeat_counter: u64,
    /// Preallocated: one MTU-sized packet read buffer.
    packet_buf: Vec<u8>,
    /// Preallocated: one framing buffer, reused per send.
    frame_buf: Vec<u8>,
    /// Preallocated: the partial-frame accumulator for the data connection.
    rx_buf: Vec<u8>,
}

impl<T: TunDevice, C: InterfaceConfigurator> NetAgent<T, C> {
    /// Build an agent over an already-created device.
    pub fn new(tun: T, configurator: C) -> Self {
        Self {
            tun,
            configurator,
            privileges: Box::new(SystemPrivilegeDropper),
            state: AgentState::Init,
            session_id: 0,
            plan: None,
            negotiated_mtu: limits::MTU_V1,
            policy_epoch: 0,
            resolver_configured: false,
            counters: AgentCounters::default(),
            heartbeat_counter: 0,
            packet_buf: vec![0u8; limits::MAX_PAYLOAD_LEN],
            frame_buf: Vec::with_capacity(limits::MAX_WIRE_LEN),
            rx_buf: Vec::with_capacity(limits::MAX_WIRE_LEN * 2),
        }
    }

    /// Replace the privilege dropper. Tests use this; the production agent
    /// keeps the default, which performs the real drop.
    pub fn with_privilege_dropper(mut self, dropper: Box<dyn PrivilegeDropper>) -> Self {
        self.privileges = dropper;
        self
    }

    pub fn state(&self) -> AgentState {
        self.state
    }

    pub fn counters(&self) -> AgentCounters {
        self.counters
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn interface_plan(&self) -> Option<&InterfacePlan> {
        self.plan.as_ref()
    }

    pub fn tun(&self) -> &T {
        &self.tun
    }

    pub fn tun_mut(&mut self) -> &mut T {
        &mut self.tun
    }

    pub fn configurator(&self) -> &C {
        &self.configurator
    }

    /// Run the control handshake: `HELLO` → `CONFIG` → configure → `READY`.
    ///
    /// On any failure the agent lands in [`AgentState::Unavailable`] and the
    /// interface is marked down. There is no partial success: either the
    /// tunnel is up under a host-assigned configuration, or the workload has
    /// no network.
    pub fn handshake<S: Read + Write>(&mut self, control: &mut S) -> Result<(), AgentError> {
        match self.handshake_inner(control) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.fail_closed();
                Err(err)
            }
        }
    }

    fn handshake_inner<S: Read + Write>(&mut self, control: &mut S) -> Result<(), AgentError> {
        self.state = AgentState::Handshaking;
        let hello = Hello::v1();
        self.send(control, MessageType::Hello, 0, &hello.encode())?;

        let (header, payload) = self.read_message(control)?;
        match header.msg_type {
            MessageType::Config => {}
            MessageType::Error => {
                let err = ErrorMessage::decode(&payload)?;
                return Err(AgentError::Refused {
                    code: err.code,
                    detail: err.detail,
                });
            }
            other => {
                return Err(AgentError::Protocol(format!(
                    "expected CONFIG, got {other:?}"
                )));
            }
        }
        if header.session_id == 0 {
            return Err(AgentError::Protocol(
                "host assigned session id 0, which is reserved".into(),
            ));
        }
        let config = Config::decode(&payload)?;
        let v4 = config.v4.ok_or_else(|| {
            AgentError::Protocol("this build carries IPv4 only; CONFIG assigned none".into())
        })?;
        if config.queue_count != limits::QUEUE_COUNT_V1 {
            return Err(AgentError::Protocol(format!(
                "this build runs {} data queue, host assigned {}",
                limits::QUEUE_COUNT_V1,
                config.queue_count
            )));
        }

        self.session_id = header.session_id;
        self.negotiated_mtu = config.mtu;
        self.policy_epoch = config.policy_epoch;
        let plan = InterfacePlan {
            iface: self.tun.name().to_string(),
            address: v4.address.into(),
            peer: v4.peer.into(),
            prefix_len: v4.prefix_len,
            mtu: config.mtu,
            dns: v4.dns.into(),
        };
        self.configurator.apply(&plan)?;
        self.resolver_configured = self.configurator.write_resolv_conf(&plan);
        self.plan = Some(plan);

        // Privileges bought the interface; they are not needed to move
        // packets across an fd that is already open. Refuse to continue on a
        // partial drop rather than pumping with CAP_NET_ADMIN still held.
        let report = self.privileges.drop_privileges();
        if !report.is_complete() {
            return Err(AgentError::PrivilegeDropIncomplete(report.shortfall()));
        }

        let ready = Ready {
            policy_epoch: self.policy_epoch,
            mtu: self.negotiated_mtu,
            resolver_configured: self.resolver_configured,
        };
        self.send(
            control,
            MessageType::Ready,
            self.session_id,
            &ready.encode(),
        )?;
        self.state = AgentState::Ready;
        Ok(())
    }

    /// Drain every packet the guest stack has queued on the TUN and frame
    /// each onto the data connection. Returns how many were forwarded.
    ///
    /// One packet per frame. The IP version nibble decides v4 vs v6; no
    /// Ethernet header is ever added.
    pub fn pump_tun_to_transport<S: Write>(&mut self, data: &mut S) -> Result<usize, AgentError> {
        if self.state != AgentState::Ready {
            return Ok(0);
        }
        let mut forwarded = 0usize;
        loop {
            let n = match self.tun.read_packet(&mut self.packet_buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(AgentError::Transport(err)),
            };
            if n > self.negotiated_mtu as usize {
                // The guest stack should never exceed the MTU we set on the
                // interface; if it does, the host would refuse the frame
                // anyway, so drop it here and count it.
                self.counters.oversized_dropped += 1;
                continue;
            }
            if !is_plausible_ip_packet(&self.packet_buf[..n]) {
                self.counters.malformed_dropped += 1;
                continue;
            }
            self.frame_buf.clear();
            frame::encode_into(
                &mut self.frame_buf,
                MessageType::Packet,
                self.session_id,
                0,
                &self.packet_buf[..n],
            )
            .map_err(|e| AgentError::Protocol(e.to_string()))?;
            data.write_all(&self.frame_buf)?;
            self.counters.packets_out += 1;
            self.counters.bytes_out += n as u64;
            forwarded += 1;
        }
        if forwarded > 0 {
            data.flush()?;
        }
        Ok(forwarded)
    }

    /// Feed bytes read from the data connection into the agent. Complete
    /// frames are validated and their packets written to the TUN; a partial
    /// tail is retained for the next call.
    ///
    /// Returns how many packets reached the guest stack.
    pub fn ingest_transport_bytes(&mut self, bytes: &[u8]) -> Result<usize, AgentError> {
        self.rx_buf.extend_from_slice(bytes);
        let mut delivered = 0usize;
        loop {
            let (consumed, packet_range) = match frame::decode(&self.rx_buf) {
                Ok(parsed) => {
                    let consumed = parsed.consumed;
                    // A frame on the data connection must be a packet and
                    // must carry the live session. Anything else is a
                    // protocol violation, not a recoverable drop.
                    if parsed.header.msg_type == MessageType::Shutdown {
                        self.fail_closed();
                        return Ok(delivered);
                    }
                    if parsed.header.msg_type != MessageType::Packet {
                        return Err(AgentError::Protocol(format!(
                            "{:?} is not a data-plane message",
                            parsed.header.msg_type
                        )));
                    }
                    if parsed.header.session_id != self.session_id {
                        self.counters.stale_session_dropped += 1;
                        (consumed, None)
                    } else if parsed.payload.len() > self.negotiated_mtu as usize {
                        self.counters.oversized_dropped += 1;
                        (consumed, None)
                    } else if !is_plausible_ip_packet(parsed.payload) {
                        self.counters.malformed_dropped += 1;
                        (consumed, None)
                    } else {
                        let start = frame::LENGTH_PREFIX_LEN + limits::HEADER_LEN;
                        (consumed, Some(start..start + parsed.payload.len()))
                    }
                }
                Err(frame::FrameError::Incomplete { .. }) => break,
                Err(err) => {
                    self.fail_closed();
                    return Err(AgentError::Protocol(err.to_string()));
                }
            };
            if let Some(range) = packet_range {
                // Copy out of `rx_buf` so the borrow ends before the drain.
                // The packet buffer is preallocated, so this is a memcpy,
                // not an allocation.
                let len = range.len();
                self.packet_buf[..len].copy_from_slice(&self.rx_buf[range]);
                match self.tun.write_packet(&self.packet_buf[..len]) {
                    Ok(()) => {
                        self.counters.packets_in += 1;
                        self.counters.bytes_in += len as u64;
                        delivered += 1;
                    }
                    Err(_) => self.counters.tun_write_failed += 1,
                }
            }
            self.rx_buf.drain(..consumed);
        }
        Ok(delivered)
    }

    /// Handle one complete control message the host sent after the
    /// handshake.
    ///
    /// Kept separate from the data path so bulk packet traffic can never
    /// delay or be delayed by a shutdown: the two ride different
    /// connections and are read from different poll slots.
    pub fn handle_control_frame(&mut self, bytes: &[u8]) -> Result<(), AgentError> {
        let parsed = match frame::decode(bytes) {
            Ok(parsed) => parsed,
            Err(err) => {
                self.fail_closed();
                return Err(AgentError::Protocol(err.to_string()));
            }
        };
        match parsed.header.msg_type {
            // Liveness from the host needs no reply: the agent's own
            // heartbeat is what the host watches.
            MessageType::Heartbeat => Ok(()),
            MessageType::Shutdown => {
                self.fail_closed();
                Ok(())
            }
            MessageType::Error => {
                let err = ErrorMessage::decode(parsed.payload)?;
                self.fail_closed();
                Err(AgentError::Refused {
                    code: err.code,
                    detail: err.detail,
                })
            }
            other => {
                self.fail_closed();
                Err(AgentError::Protocol(format!(
                    "{other:?} is not valid on the control channel after the handshake"
                )))
            }
        }
    }

    /// Send a liveness message on the control connection.
    pub fn send_heartbeat<S: Write>(&mut self, control: &mut S) -> Result<(), AgentError> {
        self.heartbeat_counter += 1;
        let hb = Heartbeat {
            counter: self.heartbeat_counter,
        };
        let session = self.session_id;
        self.send(control, MessageType::Heartbeat, session, &hb.encode())
    }

    /// Tell the host this side is going away, then fail closed locally.
    pub fn shutdown<S: Write>(&mut self, control: &mut S) -> Result<(), AgentError> {
        let msg = Shutdown {
            reason: ShutdownReason::GuestExiting,
        };
        let session = self.session_id;
        let result = self.send(control, MessageType::Shutdown, session, &msg.encode());
        self.fail_closed();
        result
    }

    /// Mark networking unavailable: the interface goes down and the session
    /// is finished.
    ///
    /// There is no fallback here — not to a NIC, not to host networking, not
    /// to the brokered mode. A workload that had networking now has an
    /// interface with no route, which is a visible failure rather than a
    /// silent one.
    pub fn fail_closed(&mut self) {
        if self.state != AgentState::Unavailable {
            let _ = self.configurator.set_down(self.tun.name());
        }
        self.state = AgentState::Unavailable;
        self.session_id = 0;
        self.rx_buf.clear();
    }

    fn send<S: Write>(
        &mut self,
        sink: &mut S,
        msg_type: MessageType,
        session_id: u64,
        payload: &[u8],
    ) -> Result<(), AgentError> {
        self.frame_buf.clear();
        frame::encode_into(&mut self.frame_buf, msg_type, session_id, 0, payload)
            .map_err(|e| AgentError::Protocol(e.to_string()))?;
        sink.write_all(&self.frame_buf)?;
        sink.flush()?;
        Ok(())
    }

    /// Read exactly one control message, refusing an oversized announcement
    /// before allocating for it.
    fn read_message<S: Read>(
        &mut self,
        source: &mut S,
    ) -> Result<(frame::FrameHeader, Vec<u8>), AgentError> {
        let mut prefix = [0u8; frame::LENGTH_PREFIX_LEN];
        source.read_exact(&mut prefix)?;
        let frame_len =
            frame::peek_frame_len(&prefix).map_err(|e| AgentError::Protocol(e.to_string()))?;
        let mut buf = vec![0u8; frame::LENGTH_PREFIX_LEN + frame_len];
        buf[..frame::LENGTH_PREFIX_LEN].copy_from_slice(&prefix);
        source.read_exact(&mut buf[frame::LENGTH_PREFIX_LEN..])?;
        let parsed = frame::decode(&buf).map_err(|e| AgentError::Protocol(e.to_string()))?;
        Ok((parsed.header, parsed.payload.to_vec()))
    }
}

/// Cheap structural screen before framing: the version nibble must be 4 or
/// 6, and the buffer must hold at least that family's header.
///
/// This is not the policy check — the host does that, on every packet,
/// because the guest is not trusted. It exists so the tunnel does not spend
/// a frame carrying something that cannot possibly be admitted.
fn is_plausible_ip_packet(packet: &[u8]) -> bool {
    match packet.first().map(|b| b >> 4) {
        Some(4) => packet.len() >= limits::MIN_IPV4_HEADER,
        Some(6) => packet.len() >= limits::IPV6_HEADER_LEN,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l3::netcfg::RecordingConfigurator;
    use crate::l3::tun::MemoryTun;
    use mvm_contract::l3::{Ipv4Config, features};
    use std::io::Cursor;

    const SESSION: u64 = 0xABCD_EF01_2345_6789;

    fn agent() -> NetAgent<MemoryTun, RecordingConfigurator> {
        NetAgent::new(MemoryTun::new("mvm0"), RecordingConfigurator::default())
            .with_privilege_dropper(Box::new(
                crate::l3::privdrop::RecordingPrivilegeDropper::default(),
            ))
    }

    fn config() -> Config {
        Config {
            v4: Some(Ipv4Config {
                address: [10, 201, 0, 6],
                prefix_len: 30,
                peer: [10, 201, 0, 5],
                dns: [10, 201, 0, 5],
            }),
            v6: None,
            mtu: limits::MTU_V1,
            queue_count: 1,
            features: features::GRANTED_V1,
            policy_epoch: 7,
        }
    }

    /// A control channel that replays a scripted host response and records
    /// whatever the agent wrote.
    struct ScriptedControl {
        inbound: Cursor<Vec<u8>>,
        outbound: Vec<u8>,
    }

    impl ScriptedControl {
        fn new(host_says: Vec<u8>) -> Self {
            Self {
                inbound: Cursor::new(host_says),
                outbound: Vec::new(),
            }
        }

        fn with_config(cfg: &Config, session: u64) -> Self {
            Self::new(frame::encode(MessageType::Config, session, 0, &cfg.encode()).unwrap())
        }

        /// Every frame the agent sent, in order.
        fn sent(&self) -> Vec<(MessageType, Vec<u8>, u64)> {
            let mut out = Vec::new();
            let mut buf = self.outbound.as_slice();
            while let Ok(parsed) = frame::decode(buf) {
                out.push((
                    parsed.header.msg_type,
                    parsed.payload.to_vec(),
                    parsed.header.session_id,
                ));
                buf = &buf[parsed.consumed..];
            }
            out
        }
    }

    impl Read for ScriptedControl {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inbound.read(buf)
        }
    }

    impl Write for ScriptedControl {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.outbound.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn v4_packet(payload_len: usize) -> Vec<u8> {
        let total = 20 + payload_len;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 201, 0, 6]);
        p[16..20].copy_from_slice(&[93, 184, 216, 34]);
        p
    }

    #[test]
    fn a_fresh_agent_has_no_network() {
        let agent = agent();
        assert_eq!(agent.state(), AgentState::Init);
        assert!(!agent.state().network_available());
    }

    #[test]
    fn the_handshake_configures_the_interface_and_reports_ready() {
        let mut agent = agent();
        let mut control = ScriptedControl::with_config(&config(), SESSION);
        agent.handshake(&mut control).unwrap();

        assert_eq!(agent.state(), AgentState::Ready);
        assert!(agent.state().network_available());
        assert_eq!(agent.session_id(), SESSION);

        let plan = agent.interface_plan().unwrap();
        assert_eq!(plan.iface, "mvm0");
        assert_eq!(plan.address, std::net::Ipv4Addr::new(10, 201, 0, 6));
        assert_eq!(plan.peer, std::net::Ipv4Addr::new(10, 201, 0, 5));
        assert_eq!(plan.dns, std::net::Ipv4Addr::new(10, 201, 0, 5));
        assert_eq!(plan.mtu, 1500);
        assert_eq!(plan.prefix_len, 30);

        // The host's configuration was applied verbatim.
        assert_eq!(agent.configurator().applied.len(), 1);
        assert_eq!(&agent.configurator().applied[0], plan);
    }

    #[test]
    fn the_handshake_sends_hello_then_ready_in_order() {
        let mut agent = agent();
        let mut control = ScriptedControl::with_config(&config(), SESSION);
        agent.handshake(&mut control).unwrap();
        let sent = control.sent();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].0, MessageType::Hello);
        assert_eq!(sent[0].2, 0, "HELLO carries no session yet");
        assert_eq!(sent[1].0, MessageType::Ready);
        assert_eq!(sent[1].2, SESSION, "READY echoes the assigned session");
        let ready = Ready::decode(&sent[1].1).unwrap();
        assert_eq!(ready.policy_epoch, 7);
        assert_eq!(ready.mtu, 1500);
        assert!(ready.resolver_configured);
    }

    #[test]
    fn hello_carries_no_machine_identity() {
        let mut agent = agent();
        let mut control = ScriptedControl::with_config(&config(), SESSION);
        agent.handshake(&mut control).unwrap();
        let hello_payload = &control.sent()[0].1;
        // Version, features, max_queues — and nothing that names a machine.
        assert_eq!(hello_payload.len(), message::HELLO_LEN);
        let hello = Hello::decode(hello_payload).unwrap();
        assert_eq!(hello, Hello::v1());
    }

    #[test]
    fn a_sealed_resolv_conf_is_reported_but_does_not_fail_the_tunnel() {
        let mut agent = NetAgent::new(
            MemoryTun::new("mvm0"),
            RecordingConfigurator {
                fail_resolv: true,
                ..Default::default()
            },
        )
        .with_privilege_dropper(Box::new(
            crate::l3::privdrop::RecordingPrivilegeDropper::default(),
        ));
        let mut control = ScriptedControl::with_config(&config(), SESSION);
        agent.handshake(&mut control).unwrap();
        assert_eq!(agent.state(), AgentState::Ready);
        let ready = Ready::decode(&control.sent()[1].1).unwrap();
        assert!(
            !ready.resolver_configured,
            "the host must be told the guest could not point its resolver"
        );
    }

    #[test]
    fn a_failed_interface_configuration_fails_closed() {
        let mut agent = NetAgent::new(
            MemoryTun::new("mvm0"),
            RecordingConfigurator {
                fail_apply: true,
                ..Default::default()
            },
        )
        .with_privilege_dropper(Box::new(
            crate::l3::privdrop::RecordingPrivilegeDropper::default(),
        ));
        let mut control = ScriptedControl::with_config(&config(), SESSION);
        let err = agent.handshake(&mut control).unwrap_err();
        assert!(matches!(err, AgentError::Interface(_)));
        assert_eq!(agent.state(), AgentState::Unavailable);
        assert!(!agent.state().network_available());
    }

    #[test]
    fn a_host_refusal_surfaces_the_reason_and_fails_closed() {
        let refusal = ErrorMessage::new(ErrorCode::NotAdmitted, "plan does not admit l3");
        let mut control = ScriptedControl::new(
            frame::encode(MessageType::Error, 0, 0, &refusal.encode()).unwrap(),
        );
        let mut agent = agent();
        let err = agent.handshake(&mut control).unwrap_err();
        assert!(matches!(
            err,
            AgentError::Refused {
                code: ErrorCode::NotAdmitted,
                ..
            }
        ));
        assert_eq!(agent.state(), AgentState::Unavailable);
    }

    #[test]
    fn a_session_id_of_zero_is_refused_because_it_is_reserved() {
        let mut control = ScriptedControl::with_config(&config(), 0);
        let mut agent = agent();
        let err = agent.handshake(&mut control).unwrap_err();
        assert!(matches!(err, AgentError::Protocol(msg) if msg.contains("session id 0")));
        assert_eq!(agent.state(), AgentState::Unavailable);
    }

    #[test]
    fn an_unexpected_control_message_is_a_protocol_violation() {
        let mut control = ScriptedControl::new(
            frame::encode(
                MessageType::Heartbeat,
                1,
                0,
                &Heartbeat { counter: 1 }.encode(),
            )
            .unwrap(),
        );
        let mut agent = agent();
        assert!(matches!(
            agent.handshake(&mut control),
            Err(AgentError::Protocol(_))
        ));
        assert_eq!(agent.state(), AgentState::Unavailable);
    }

    #[test]
    fn a_config_assigning_more_queues_than_this_build_runs_is_refused() {
        let mut cfg = config();
        cfg.queue_count = 4;
        let mut control = ScriptedControl::with_config(&cfg, SESSION);
        let mut agent = agent();
        assert!(matches!(
            agent.handshake(&mut control),
            Err(AgentError::Protocol(_))
        ));
    }

    #[test]
    fn a_config_with_no_v4_assignment_is_refused() {
        // Encode a v6-only CONFIG directly: `Config::decode` accepts it, and
        // the refusal must come from the agent knowing it carries v4 only.
        let cfg = Config {
            v4: None,
            v6: Some(mvm_contract::l3::Ipv6Config {
                address: [0x20; 16],
                prefix_len: 127,
                peer: [0x21; 16],
                dns: [0x22; 16],
            }),
            features: features::IPV6,
            ..config()
        };
        let mut control = ScriptedControl::with_config(&cfg, SESSION);
        let mut agent = agent();
        assert!(matches!(
            agent.handshake(&mut control),
            Err(AgentError::Protocol(msg)) if msg.contains("IPv4 only")
        ));
    }

    #[test]
    fn a_truncated_control_stream_fails_closed() {
        let full = frame::encode(MessageType::Config, SESSION, 0, &config().encode()).unwrap();
        let mut control = ScriptedControl::new(full[..full.len() - 4].to_vec());
        let mut agent = agent();
        assert!(agent.handshake(&mut control).is_err());
        assert_eq!(agent.state(), AgentState::Unavailable);
    }

    /// Handshake helper for the pump tests.
    fn ready_agent() -> NetAgent<MemoryTun, RecordingConfigurator> {
        let mut agent = agent();
        let mut control = ScriptedControl::with_config(&config(), SESSION);
        agent.handshake(&mut control).unwrap();
        agent
    }

    #[test]
    fn every_tun_packet_becomes_one_framed_message() {
        let mut agent = ready_agent();
        for _ in 0..3 {
            agent.tun_mut().push_outbound(v4_packet(10));
        }
        let mut wire = Vec::new();
        assert_eq!(agent.pump_tun_to_transport(&mut wire).unwrap(), 3);

        let mut buf = wire.as_slice();
        let mut seen = 0;
        while let Ok(parsed) = frame::decode(buf) {
            assert_eq!(parsed.header.msg_type, MessageType::Packet);
            assert_eq!(parsed.header.session_id, SESSION);
            assert_eq!(parsed.header.queue_id, 0);
            assert_eq!(parsed.payload.len(), 30);
            assert_eq!(parsed.payload[0] >> 4, 4, "no ethernet header was added");
            buf = &buf[parsed.consumed..];
            seen += 1;
        }
        assert_eq!(seen, 3);
        assert_eq!(agent.counters().packets_out, 3);
        assert_eq!(agent.counters().bytes_out, 90);
    }

    #[test]
    fn the_pump_is_inert_before_the_handshake_completes() {
        let mut agent = agent();
        agent.tun_mut().push_outbound(v4_packet(10));
        let mut wire = Vec::new();
        assert_eq!(agent.pump_tun_to_transport(&mut wire).unwrap(), 0);
        assert!(wire.is_empty(), "no packet may leave before READY");
    }

    #[test]
    fn an_oversized_tun_packet_is_dropped_and_counted() {
        let mut agent = ready_agent();
        agent.tun_mut().push_outbound(v4_packet(2000));
        let mut wire = Vec::new();
        assert_eq!(agent.pump_tun_to_transport(&mut wire).unwrap(), 0);
        assert_eq!(agent.counters().oversized_dropped, 1);
        assert!(wire.is_empty());
    }

    #[test]
    fn a_structurally_impossible_tun_packet_is_dropped_and_counted() {
        let mut agent = ready_agent();
        agent.tun_mut().push_outbound(vec![0x00, 0x01, 0x02]);
        agent.tun_mut().push_outbound(vec![0x45, 0x00]);
        let mut wire = Vec::new();
        assert_eq!(agent.pump_tun_to_transport(&mut wire).unwrap(), 0);
        assert_eq!(agent.counters().malformed_dropped, 2);
    }

    #[test]
    fn an_inbound_packet_frame_reaches_the_guest_stack() {
        let mut agent = ready_agent();
        let packet = v4_packet(40);
        let wire = frame::encode(MessageType::Packet, SESSION, 0, &packet).unwrap();
        assert_eq!(agent.ingest_transport_bytes(&wire).unwrap(), 1);
        assert_eq!(agent.tun().delivered(), &[packet]);
        assert_eq!(agent.counters().packets_in, 1);
    }

    #[test]
    fn a_frame_bearing_a_stale_session_is_dropped_not_delivered() {
        let mut agent = ready_agent();
        let wire = frame::encode(MessageType::Packet, SESSION ^ 0xff, 0, &v4_packet(10)).unwrap();
        assert_eq!(agent.ingest_transport_bytes(&wire).unwrap(), 0);
        assert!(agent.tun().delivered().is_empty());
        assert_eq!(agent.counters().stale_session_dropped, 1);
        assert_eq!(
            agent.state(),
            AgentState::Ready,
            "one stale frame is not fatal"
        );
    }

    #[test]
    fn a_frame_split_across_reads_is_reassembled() {
        let mut agent = ready_agent();
        let packet = v4_packet(40);
        let wire = frame::encode(MessageType::Packet, SESSION, 0, &packet).unwrap();
        let (head, tail) = wire.split_at(10);
        assert_eq!(agent.ingest_transport_bytes(head).unwrap(), 0);
        assert_eq!(agent.ingest_transport_bytes(tail).unwrap(), 1);
        assert_eq!(agent.tun().delivered(), &[packet]);
    }

    #[test]
    fn several_frames_in_one_read_are_all_delivered() {
        let mut agent = ready_agent();
        let mut wire = Vec::new();
        for _ in 0..4 {
            frame::encode_into(&mut wire, MessageType::Packet, SESSION, 0, &v4_packet(8)).unwrap();
        }
        assert_eq!(agent.ingest_transport_bytes(&wire).unwrap(), 4);
        assert_eq!(agent.tun().delivered().len(), 4);
    }

    #[test]
    fn a_malformed_inbound_frame_fails_closed() {
        let mut agent = ready_agent();
        // Announce a frame larger than the protocol permits.
        let bogus = ((limits::MAX_FRAME_LEN + 1) as u32).to_be_bytes();
        assert!(agent.ingest_transport_bytes(&bogus).is_err());
        assert_eq!(agent.state(), AgentState::Unavailable);
    }

    #[test]
    fn a_control_message_on_the_data_connection_is_a_protocol_violation() {
        let mut agent = ready_agent();
        let wire = frame::encode(
            MessageType::Ready,
            SESSION,
            0,
            &Ready {
                policy_epoch: 1,
                mtu: 1500,
                resolver_configured: true,
            }
            .encode(),
        )
        .unwrap();
        assert!(matches!(
            agent.ingest_transport_bytes(&wire),
            Err(AgentError::Protocol(_))
        ));
    }

    #[test]
    fn a_shutdown_frame_marks_networking_unavailable() {
        let mut agent = ready_agent();
        let wire = frame::encode(
            MessageType::Shutdown,
            SESSION,
            0,
            &Shutdown {
                reason: ShutdownReason::MachineStopping,
            }
            .encode(),
        )
        .unwrap();
        agent.ingest_transport_bytes(&wire).unwrap();
        assert_eq!(agent.state(), AgentState::Unavailable);
    }

    #[test]
    fn failing_closed_marks_the_interface_down_and_forgets_the_session() {
        let mut agent = ready_agent();
        agent.fail_closed();
        assert_eq!(agent.state(), AgentState::Unavailable);
        assert!(!agent.state().network_available());
        assert_eq!(agent.session_id(), 0);
        assert_eq!(agent.configurator().downed, vec!["mvm0".to_string()]);
    }

    #[test]
    fn a_disconnected_agent_forwards_nothing_further() {
        let mut agent = ready_agent();
        agent.fail_closed();
        agent.tun_mut().push_outbound(v4_packet(10));
        let mut wire = Vec::new();
        assert_eq!(agent.pump_tun_to_transport(&mut wire).unwrap(), 0);
        assert!(
            wire.is_empty(),
            "there is no fallback path once the tunnel is gone"
        );
    }

    #[test]
    fn failing_closed_twice_only_downs_the_interface_once() {
        let mut agent = ready_agent();
        agent.fail_closed();
        agent.fail_closed();
        assert_eq!(agent.configurator().downed.len(), 1);
    }

    #[test]
    fn shutdown_tells_the_host_and_then_fails_closed() {
        let mut agent = ready_agent();
        let mut control = ScriptedControl::new(Vec::new());
        agent.shutdown(&mut control).unwrap();
        let sent = control.sent();
        assert_eq!(sent[0].0, MessageType::Shutdown);
        assert_eq!(
            Shutdown::decode(&sent[0].1).unwrap().reason,
            ShutdownReason::GuestExiting
        );
        assert_eq!(agent.state(), AgentState::Unavailable);
    }

    #[test]
    fn a_host_shutdown_on_the_control_channel_fails_closed() {
        let mut agent = ready_agent();
        let wire = frame::encode(
            MessageType::Shutdown,
            SESSION,
            0,
            &Shutdown {
                reason: ShutdownReason::MachineStopping,
            }
            .encode(),
        )
        .unwrap();
        agent.handle_control_frame(&wire).unwrap();
        assert_eq!(agent.state(), AgentState::Unavailable);
    }

    #[test]
    fn a_host_heartbeat_is_accepted_without_changing_state() {
        let mut agent = ready_agent();
        let wire = frame::encode(
            MessageType::Heartbeat,
            SESSION,
            0,
            &Heartbeat { counter: 9 }.encode(),
        )
        .unwrap();
        agent.handle_control_frame(&wire).unwrap();
        assert_eq!(agent.state(), AgentState::Ready);
    }

    #[test]
    fn a_host_error_on_the_control_channel_fails_closed_with_the_reason() {
        let mut agent = ready_agent();
        let msg = ErrorMessage::new(ErrorCode::StaleSession, "session revoked");
        let wire = frame::encode(MessageType::Error, SESSION, 0, &msg.encode()).unwrap();
        let err = agent.handle_control_frame(&wire).unwrap_err();
        assert!(matches!(
            err,
            AgentError::Refused {
                code: ErrorCode::StaleSession,
                ..
            }
        ));
        assert_eq!(agent.state(), AgentState::Unavailable);
    }

    #[test]
    fn a_packet_on_the_control_channel_is_refused() {
        // Bulk traffic must never appear on the control connection; if it
        // does, something is multiplexing the two and the separation the
        // design rests on is gone.
        let mut agent = ready_agent();
        let wire = frame::encode(MessageType::Packet, SESSION, 0, &v4_packet(10)).unwrap();
        assert!(matches!(
            agent.handle_control_frame(&wire),
            Err(AgentError::Protocol(_))
        ));
        assert_eq!(agent.state(), AgentState::Unavailable);
    }

    #[test]
    fn heartbeats_carry_a_monotonic_counter() {
        let mut agent = ready_agent();
        let mut control = ScriptedControl::new(Vec::new());
        agent.send_heartbeat(&mut control).unwrap();
        agent.send_heartbeat(&mut control).unwrap();
        let sent = control.sent();
        assert_eq!(Heartbeat::decode(&sent[0].1).unwrap().counter, 1);
        assert_eq!(Heartbeat::decode(&sent[1].1).unwrap().counter, 2);
    }

    #[test]
    fn arbitrary_transport_bytes_never_panic() {
        let mut state = 0x5DEE_CE66_D1B5_4A32u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for len in 0..300usize {
            let mut agent = ready_agent();
            let mut buf = vec![0u8; len];
            for byte in buf.iter_mut() {
                *byte = (next() & 0xff) as u8;
            }
            let _ = agent.ingest_transport_bytes(&buf);
        }
    }
}
