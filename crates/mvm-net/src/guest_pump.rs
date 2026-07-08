//! Guest bridge pump seam between TUN packets and the host authority.
//!
//! This module wires the dependency-light packet translator to generic
//! authority and packet-sink traits. It does not choose a serialization format,
//! async runtime, or concrete fd type; the Linux executor can provide those
//! without forcing dependencies into the default crate build.

use std::fmt;

use crate::guest_packet::{GuestPacketError, GuestPacketTranslator};
use crate::proto::NetMessage;

pub const DEFAULT_MAX_TUN_PACKET_BYTES: usize = 65_535;
pub const DEFAULT_MAX_AUTHORITY_MESSAGES_PER_TICK: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestPumpError {
    Packet(GuestPacketError),
    PacketSource(String),
    Authority(String),
    PacketSink(String),
    Wait(String),
    InvalidLoopConfig(&'static str),
    InvalidPacketRead { bytes: usize, capacity: usize },
    UnsupportedAuthorityMessage(&'static str),
}

impl fmt::Display for GuestPumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packet(err) => write!(f, "{err}"),
            Self::PacketSource(err) => write!(f, "guest packet source failed: {err}"),
            Self::Authority(err) => write!(f, "authority transport failed: {err}"),
            Self::PacketSink(err) => write!(f, "guest packet sink failed: {err}"),
            Self::Wait(err) => write!(f, "guest pump wait failed: {err}"),
            Self::InvalidLoopConfig(reason) => {
                write!(f, "invalid guest pump loop config: {reason}")
            }
            Self::InvalidPacketRead { bytes, capacity } => write!(
                f,
                "guest packet source returned invalid read size {bytes}; buffer capacity is {capacity}"
            ),
            Self::UnsupportedAuthorityMessage(message) => {
                write!(
                    f,
                    "authority message {message} is not supported by this pump"
                )
            }
        }
    }
}

impl std::error::Error for GuestPumpError {}

impl From<GuestPacketError> for GuestPumpError {
    fn from(value: GuestPacketError) -> Self {
        Self::Packet(value)
    }
}

pub trait GuestAuthority {
    type Error: fmt::Display;

    fn send_message(&mut self, message: NetMessage) -> Result<(), Self::Error>;
}

pub trait GuestAuthorityReceiver: GuestAuthority {
    fn receive_message(&mut self) -> Result<AuthorityRead, Self::Error>;
}

pub trait GuestPacketSink {
    type Error: fmt::Display;

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), Self::Error>;
}

pub trait GuestPacketSource {
    type Error: fmt::Display;

    fn read_packet(&mut self, buffer: &mut [u8]) -> Result<GuestPacketRead, Self::Error>;
}

pub trait GuestPumpWait {
    type Error: fmt::Display;

    fn wait_for_activity(&mut self) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityRead {
    Message(NetMessage),
    WouldBlock,
    Closed,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum GuestPacketRead {
    Packet { bytes: usize },
    WouldBlock,
    Closed,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AuthorityMessageOutcome {
    WrotePacket { bytes: usize },
    DroppedWithoutPacket,
    IgnoredControl,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestPumpLoopConfig {
    max_tun_packet_bytes: usize,
    max_authority_messages_per_tick: usize,
}

impl GuestPumpLoopConfig {
    pub fn builder() -> GuestPumpLoopConfigBuilder {
        GuestPumpLoopConfigBuilder::default()
    }

    pub const fn max_tun_packet_bytes(&self) -> usize {
        self.max_tun_packet_bytes
    }

    pub const fn max_authority_messages_per_tick(&self) -> usize {
        self.max_authority_messages_per_tick
    }
}

impl Default for GuestPumpLoopConfig {
    fn default() -> Self {
        Self::builder()
            .build()
            .expect("default guest pump loop config is valid")
    }
}

#[derive(Debug, Clone)]
pub struct GuestPumpLoopConfigBuilder {
    max_tun_packet_bytes: usize,
    max_authority_messages_per_tick: usize,
}

impl Default for GuestPumpLoopConfigBuilder {
    fn default() -> Self {
        Self {
            max_tun_packet_bytes: DEFAULT_MAX_TUN_PACKET_BYTES,
            max_authority_messages_per_tick: DEFAULT_MAX_AUTHORITY_MESSAGES_PER_TICK,
        }
    }
}

impl GuestPumpLoopConfigBuilder {
    pub fn max_tun_packet_bytes(mut self, max_tun_packet_bytes: usize) -> Self {
        self.max_tun_packet_bytes = max_tun_packet_bytes;
        self
    }

    pub fn max_authority_messages_per_tick(
        mut self,
        max_authority_messages_per_tick: usize,
    ) -> Self {
        self.max_authority_messages_per_tick = max_authority_messages_per_tick;
        self
    }

    pub fn build(self) -> Result<GuestPumpLoopConfig, GuestPumpError> {
        if self.max_tun_packet_bytes == 0 {
            return Err(GuestPumpError::InvalidLoopConfig(
                "max_tun_packet_bytes must be non-zero",
            ));
        }
        if self.max_tun_packet_bytes > DEFAULT_MAX_TUN_PACKET_BYTES {
            return Err(GuestPumpError::InvalidLoopConfig(
                "max_tun_packet_bytes cannot exceed the IPv4 packet size limit",
            ));
        }
        if self.max_authority_messages_per_tick == 0 {
            return Err(GuestPumpError::InvalidLoopConfig(
                "max_authority_messages_per_tick must be non-zero",
            ));
        }
        Ok(GuestPumpLoopConfig {
            max_tun_packet_bytes: self.max_tun_packet_bytes,
            max_authority_messages_per_tick: self.max_authority_messages_per_tick,
        })
    }
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct GuestPumpTick {
    pub guest_packets_read: usize,
    pub outbound_messages_sent: usize,
    pub authority_messages_read: usize,
    pub guest_packets_written: usize,
    pub guest_closed: bool,
    pub authority_closed: bool,
}

impl GuestPumpTick {
    pub const fn is_idle(&self) -> bool {
        self.guest_packets_read == 0
            && self.outbound_messages_sent == 0
            && self.authority_messages_read == 0
            && self.guest_packets_written == 0
            && !self.guest_closed
            && !self.authority_closed
    }

    pub const fn should_stop(&self) -> bool {
        self.guest_closed || self.authority_closed
    }
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct GuestPumpRunStats {
    pub ticks: usize,
    pub idle_waits: usize,
    pub guest_packets_read: usize,
    pub outbound_messages_sent: usize,
    pub authority_messages_read: usize,
    pub guest_packets_written: usize,
}

impl GuestPumpRunStats {
    fn record_tick(&mut self, tick: GuestPumpTick) {
        self.ticks += 1;
        self.guest_packets_read += tick.guest_packets_read;
        self.outbound_messages_sent += tick.outbound_messages_sent;
        self.authority_messages_read += tick.authority_messages_read;
        self.guest_packets_written += tick.guest_packets_written;
    }
}

#[derive(Debug)]
pub struct GuestPumpLoop {
    config: GuestPumpLoopConfig,
    packet_buffer: Vec<u8>,
}

impl GuestPumpLoop {
    pub fn new(config: GuestPumpLoopConfig) -> Self {
        let packet_buffer = vec![0; config.max_tun_packet_bytes];
        Self {
            config,
            packet_buffer,
        }
    }

    pub fn config(&self) -> &GuestPumpLoopConfig {
        &self.config
    }

    pub fn tick<A, Source, Sink>(
        &mut self,
        pump: &mut GuestBridgePump<A>,
        source: &mut Source,
        sink: &mut Sink,
    ) -> Result<GuestPumpTick, GuestPumpError>
    where
        A: GuestAuthorityReceiver,
        Source: GuestPacketSource,
        Sink: GuestPacketSink,
    {
        let mut tick = GuestPumpTick::default();
        match source
            .read_packet(&mut self.packet_buffer)
            .map_err(|err| GuestPumpError::PacketSource(err.to_string()))?
        {
            GuestPacketRead::Packet { bytes } => {
                if bytes == 0 || bytes > self.packet_buffer.len() {
                    return Err(GuestPumpError::InvalidPacketRead {
                        bytes,
                        capacity: self.packet_buffer.len(),
                    });
                }
                tick.guest_packets_read = 1;
                tick.outbound_messages_sent =
                    pump.send_outbound_packet(&self.packet_buffer[..bytes])?;
            }
            GuestPacketRead::WouldBlock => {}
            GuestPacketRead::Closed => {
                tick.guest_closed = true;
            }
        }

        for _ in 0..self.config.max_authority_messages_per_tick {
            match pump
                .authority_mut()
                .receive_message()
                .map_err(|err| GuestPumpError::Authority(err.to_string()))?
            {
                AuthorityRead::Message(message) => {
                    tick.authority_messages_read += 1;
                    if matches!(
                        pump.apply_authority_message(sink, message)?,
                        AuthorityMessageOutcome::WrotePacket { .. }
                    ) {
                        tick.guest_packets_written += 1;
                    }
                }
                AuthorityRead::WouldBlock => break,
                AuthorityRead::Closed => {
                    tick.authority_closed = true;
                    break;
                }
            }
        }

        Ok(tick)
    }
}

impl Default for GuestPumpLoop {
    fn default() -> Self {
        Self::new(GuestPumpLoopConfig::default())
    }
}

pub fn run_guest_pump_loop<A, Source, Sink, Wait>(
    pump_loop: &mut GuestPumpLoop,
    pump: &mut GuestBridgePump<A>,
    source: &mut Source,
    sink: &mut Sink,
    wait: &mut Wait,
) -> Result<GuestPumpRunStats, GuestPumpError>
where
    A: GuestAuthorityReceiver,
    Source: GuestPacketSource,
    Sink: GuestPacketSink,
    Wait: GuestPumpWait,
{
    let mut stats = GuestPumpRunStats::default();
    loop {
        let tick = pump_loop.tick(pump, source, sink)?;
        let should_stop = tick.should_stop();
        let is_idle = tick.is_idle();
        stats.record_tick(tick);

        if should_stop {
            return Ok(stats);
        }
        if is_idle {
            wait.wait_for_activity()
                .map_err(|err| GuestPumpError::Wait(err.to_string()))?;
            stats.idle_waits += 1;
        }
    }
}

#[derive(Debug)]
pub struct GuestBridgePump<A> {
    translator: GuestPacketTranslator,
    authority: A,
}

impl<A> GuestBridgePump<A> {
    pub fn new(translator: GuestPacketTranslator, authority: A) -> Self {
        Self {
            translator,
            authority,
        }
    }

    pub fn translator(&self) -> &GuestPacketTranslator {
        &self.translator
    }

    pub fn translator_mut(&mut self) -> &mut GuestPacketTranslator {
        &mut self.translator
    }

    pub fn authority(&self) -> &A {
        &self.authority
    }

    pub fn authority_mut(&mut self) -> &mut A {
        &mut self.authority
    }

    pub fn into_authority(self) -> A {
        self.authority
    }
}

impl<A> GuestBridgePump<A>
where
    A: GuestAuthority,
{
    pub fn send_outbound_packet(&mut self, packet: &[u8]) -> Result<usize, GuestPumpError> {
        let events = self.translator.translate_outbound_ipv4(packet)?;
        let mut sent = 0usize;
        for event in events {
            self.authority
                .send_message(event.into_message())
                .map_err(|err| GuestPumpError::Authority(err.to_string()))?;
            sent += 1;
        }
        Ok(sent)
    }

    pub fn apply_authority_message<S>(
        &mut self,
        sink: &mut S,
        message: NetMessage,
    ) -> Result<AuthorityMessageOutcome, GuestPumpError>
    where
        S: GuestPacketSink,
    {
        match message {
            NetMessage::DnsResponse(response) => {
                let packet = self.translator.synthesize_dns_response(&response)?;
                let bytes = packet.len();
                sink.write_packet(&packet)
                    .map_err(|err| GuestPumpError::PacketSink(err.to_string()))?;
                Ok(AuthorityMessageOutcome::WrotePacket { bytes })
            }
            NetMessage::IcmpEchoResponse(response) => {
                if let Some(packet) = self.translator.synthesize_icmp_echo_response(&response)? {
                    let bytes = packet.len();
                    sink.write_packet(&packet)
                        .map_err(|err| GuestPumpError::PacketSink(err.to_string()))?;
                    return Ok(AuthorityMessageOutcome::WrotePacket { bytes });
                }
                Ok(AuthorityMessageOutcome::DroppedWithoutPacket)
            }
            NetMessage::Hello(_) | NetMessage::HelloAck(_) => {
                Ok(AuthorityMessageOutcome::IgnoredControl)
            }
            NetMessage::TcpOpenResult(result) => {
                let packet = self.translator.synthesize_tcp_open_result(&result)?;
                let bytes = packet.len();
                sink.write_packet(&packet)
                    .map_err(|err| GuestPumpError::PacketSink(err.to_string()))?;
                Ok(AuthorityMessageOutcome::WrotePacket { bytes })
            }
            NetMessage::TcpData(chunk) => {
                if let Some(packet) = self.translator.synthesize_tcp_data(&chunk)? {
                    let bytes = packet.len();
                    sink.write_packet(&packet)
                        .map_err(|err| GuestPumpError::PacketSink(err.to_string()))?;
                    return Ok(AuthorityMessageOutcome::WrotePacket { bytes });
                }
                Ok(AuthorityMessageOutcome::DroppedWithoutPacket)
            }
            NetMessage::CloseFlow(close) => {
                let packet = self.translator.synthesize_tcp_close(&close)?;
                let bytes = packet.len();
                sink.write_packet(&packet)
                    .map_err(|err| GuestPumpError::PacketSink(err.to_string()))?;
                Ok(AuthorityMessageOutcome::WrotePacket { bytes })
            }
            NetMessage::UdpDelivery(_) => {
                Err(GuestPumpError::UnsupportedAuthorityMessage("UdpDelivery"))
            }
            NetMessage::OpenTcp(_)
            | NetMessage::DnsQuery(_)
            | NetMessage::UdpDatagram(_)
            | NetMessage::IcmpEchoRequest(_) => Err(GuestPumpError::UnsupportedAuthorityMessage(
                "guest-to-host message received from authority",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::guest::{DEFAULT_GUEST_ADDRESS, DEFAULT_HOST_GATEWAY};
    use crate::guest_packet::{GuestPacketTranslator, GuestPacketTranslatorConfig};
    #[cfg(feature = "host")]
    use crate::host::{
        AllowAllHostPolicy, DenyAllHostPolicy, HostAuthority, HostRoute, HostTcpConnector,
        NoopHostAuditSink,
    };
    use crate::proto::{
        CloseReason, DnsAnswer, DnsName, DnsRecordData, DnsRecordType, DnsResponse,
        DnsResponseCode, EndpointRole, FlowDirection, FlowId, Hello, IcmpEchoResponse,
        IcmpEchoStatus, StreamChunk, Target, TcpOpenResult, TransportError,
    };

    const DNS_PORT: u16 = 53;
    const UDP_HEADER_LEN: usize = 8;
    const IPV4_MIN_HEADER_LEN: usize = 20;
    const IPPROTO_ICMP: u8 = 1;
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_UDP: u8 = 17;
    const IPV4_TTL: u8 = 64;
    const TCP_RST_ACK: u8 = 0x14;

    #[derive(Debug, Default)]
    struct MockAuthority {
        sent: Vec<NetMessage>,
        incoming: VecDeque<AuthorityRead>,
        fail: Option<&'static str>,
        receive_fail: Option<&'static str>,
    }

    impl GuestAuthority for MockAuthority {
        type Error = &'static str;

        fn send_message(&mut self, message: NetMessage) -> Result<(), Self::Error> {
            if let Some(err) = self.fail {
                return Err(err);
            }
            self.sent.push(message);
            Ok(())
        }
    }

    impl GuestAuthorityReceiver for MockAuthority {
        fn receive_message(&mut self) -> Result<AuthorityRead, Self::Error> {
            if let Some(err) = self.receive_fail {
                return Err(err);
            }
            Ok(self
                .incoming
                .pop_front()
                .unwrap_or(AuthorityRead::WouldBlock))
        }
    }

    #[derive(Debug, Default)]
    struct MockSink {
        packets: Vec<Vec<u8>>,
        fail: Option<&'static str>,
    }

    impl GuestPacketSink for MockSink {
        type Error = &'static str;

        fn write_packet(&mut self, packet: &[u8]) -> Result<(), Self::Error> {
            if let Some(err) = self.fail {
                return Err(err);
            }
            self.packets.push(packet.to_vec());
            Ok(())
        }
    }

    #[cfg(feature = "host")]
    #[derive(Debug, Default)]
    struct RecordingConnector {
        opens: Vec<(FlowId, String, u16, HostRoute)>,
        sends: Vec<(FlowId, Vec<u8>, bool)>,
        closes: Vec<(FlowId, CloseReason)>,
    }

    #[cfg(feature = "host")]
    impl HostTcpConnector for RecordingConnector {
        fn open(
            &mut self,
            flow_id: FlowId,
            target: &Target,
            route: &HostRoute,
        ) -> Result<(), TransportError> {
            self.opens
                .push((flow_id, target.host().to_string(), target.port(), *route));
            Ok(())
        }

        fn send(&mut self, chunk: &StreamChunk) -> Result<(), TransportError> {
            self.sends
                .push((chunk.flow_id, chunk.bytes.clone(), chunk.end_stream));
            Ok(())
        }

        fn close(&mut self, flow_id: FlowId, reason: CloseReason) -> Result<(), TransportError> {
            self.closes.push((flow_id, reason));
            Ok(())
        }
    }

    #[derive(Debug)]
    enum MockSourceRead {
        Packet(Vec<u8>),
        InvalidSize(usize),
        WouldBlock,
        Closed,
        Fail(&'static str),
    }

    #[derive(Debug, Default)]
    struct MockSource {
        reads: VecDeque<MockSourceRead>,
    }

    impl MockSource {
        fn with_reads(reads: impl IntoIterator<Item = MockSourceRead>) -> Self {
            Self {
                reads: reads.into_iter().collect(),
            }
        }
    }

    impl GuestPacketSource for MockSource {
        type Error = &'static str;

        fn read_packet(&mut self, buffer: &mut [u8]) -> Result<GuestPacketRead, Self::Error> {
            match self.reads.pop_front().unwrap_or(MockSourceRead::WouldBlock) {
                MockSourceRead::Packet(packet) => {
                    if packet.len() > buffer.len() {
                        return Err("packet larger than buffer");
                    }
                    buffer[..packet.len()].copy_from_slice(&packet);
                    Ok(GuestPacketRead::Packet {
                        bytes: packet.len(),
                    })
                }
                MockSourceRead::InvalidSize(bytes) => Ok(GuestPacketRead::Packet { bytes }),
                MockSourceRead::WouldBlock => Ok(GuestPacketRead::WouldBlock),
                MockSourceRead::Closed => Ok(GuestPacketRead::Closed),
                MockSourceRead::Fail(err) => Err(err),
            }
        }
    }

    #[derive(Debug, Default)]
    struct MockWait {
        waits: usize,
        fail: Option<&'static str>,
    }

    impl GuestPumpWait for MockWait {
        type Error = &'static str;

        fn wait_for_activity(&mut self) -> Result<(), Self::Error> {
            if let Some(err) = self.fail {
                return Err(err);
            }
            self.waits += 1;
            Ok(())
        }
    }

    fn pump() -> GuestBridgePump<MockAuthority> {
        GuestBridgePump::new(
            GuestPacketTranslator::new(GuestPacketTranslatorConfig::default()),
            MockAuthority::default(),
        )
    }

    fn dns_query_payload(tx_id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&tx_id.to_be_bytes());
        payload.extend_from_slice(&0x0100u16.to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&encode_dns_name(name));
        payload.extend_from_slice(&qtype.to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload
    }

    fn encode_dns_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn udp_ipv4_packet(src_port: u16, dst_ip: Ipv4Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        build_ipv4_packet(
            DEFAULT_GUEST_ADDRESS,
            dst_ip,
            IPPROTO_UDP,
            build_udp_packet(src_port, dst_port, payload).as_slice(),
        )
    }

    fn icmp_echo_ipv4_packet(dst_ip: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let mut icmp = Vec::new();
        icmp.push(8);
        icmp.push(0);
        icmp.extend_from_slice(&0u16.to_be_bytes());
        icmp.extend_from_slice(&7u16.to_be_bytes());
        icmp.extend_from_slice(&1u16.to_be_bytes());
        icmp.extend_from_slice(payload);
        let checksum = internet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
        build_ipv4_packet(DEFAULT_GUEST_ADDRESS, dst_ip, IPPROTO_ICMP, &icmp)
    }

    fn tcp_ipv4_packet(dst_ip: Ipv4Addr, dst_port: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&49152u16.to_be_bytes());
        tcp.extend_from_slice(&dst_port.to_be_bytes());
        tcp.extend_from_slice(&7u32.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes());
        tcp.push(5 << 4);
        tcp.push(flags);
        tcp.extend_from_slice(&1024u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(payload);
        build_ipv4_packet(DEFAULT_GUEST_ADDRESS, dst_ip, IPPROTO_TCP, &tcp)
    }

    fn build_udp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let length = (UDP_HEADER_LEN + payload.len()) as u16;
        let mut packet = Vec::new();
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    fn build_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total_len = (IPV4_MIN_HEADER_LEN + payload.len()) as u16;
        let mut packet = vec![0u8; IPV4_MIN_HEADER_LEN];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[8] = IPV4_TTL;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        let checksum = internet_checksum(&packet);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    fn internet_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut chunks = bytes.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        if let Some(byte) = chunks.remainder().first() {
            sum += u16::from_be_bytes([*byte, 0]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn dns_response_rcode(packet: &[u8]) -> u8 {
        let dns = IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN;
        packet[dns + 3] & 0x0f
    }

    fn dns_answer_count(packet: &[u8]) -> u16 {
        let dns = IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN;
        u16::from_be_bytes([packet[dns + 6], packet[dns + 7]])
    }

    fn tcp_response_flags(packet: &[u8]) -> u8 {
        packet[IPV4_MIN_HEADER_LEN + 13]
    }

    fn query_id_from_last_dns(pump: &GuestBridgePump<MockAuthority>) -> crate::proto::QueryId {
        match pump.authority().sent.last() {
            Some(NetMessage::DnsQuery(query)) => query.query_id,
            other => panic!("unexpected authority message: {other:?}"),
        }
    }

    fn query_id_from_last_icmp(pump: &GuestBridgePump<MockAuthority>) -> crate::proto::QueryId {
        match pump.authority().sent.last() {
            Some(NetMessage::IcmpEchoRequest(request)) => request.query_id,
            other => panic!("unexpected authority message: {other:?}"),
        }
    }

    fn flow_id_from_last_tcp_open(pump: &GuestBridgePump<MockAuthority>) -> FlowId {
        match pump.authority().sent.last() {
            Some(NetMessage::OpenTcp(open)) => open.flow_id,
            other => panic!("unexpected authority message: {other:?}"),
        }
    }

    #[cfg(feature = "host")]
    fn pop_sent_message(pump: &mut GuestBridgePump<MockAuthority>) -> NetMessage {
        assert_eq!(
            pump.authority().sent.len(),
            1,
            "acceptance harness processes one guest-to-host message at a time"
        );
        pump.authority_mut().sent.remove(0)
    }

    #[cfg(feature = "host")]
    fn synthetic_ip_from_dns_response(messages: &[NetMessage]) -> Ipv4Addr {
        match messages {
            [NetMessage::DnsResponse(response)] => match response.answers.as_slice() {
                [
                    DnsAnswer {
                        data: DnsRecordData::Ip(IpAddr::V4(ip)),
                        ..
                    },
                ] => *ip,
                other => panic!("unexpected DNS answers: {other:?}"),
            },
            other => panic!("unexpected DNS response messages: {other:?}"),
        }
    }

    #[test]
    fn outbound_dns_packet_is_sent_to_authority() {
        let mut pump = pump();
        let packet = udp_ipv4_packet(
            40000,
            DEFAULT_HOST_GATEWAY,
            DNS_PORT,
            &dns_query_payload(0x1234, "example.com", 1),
        );

        assert_eq!(pump.send_outbound_packet(&packet), Ok(1));
        assert!(matches!(
            pump.authority().sent.first(),
            Some(NetMessage::DnsQuery(query))
                if query.name.as_str() == "example.com" && query.record_type == DnsRecordType::A
        ));
    }

    #[test]
    fn loop_tick_reads_guest_packet_and_sends_authority_message() {
        let packet = udp_ipv4_packet(
            40000,
            DEFAULT_HOST_GATEWAY,
            DNS_PORT,
            &dns_query_payload(0x1234, "example.com", 1),
        );
        let mut source = MockSource::with_reads([MockSourceRead::Packet(packet)]);
        let mut sink = MockSink::default();
        let mut pump = pump();
        let mut pump_loop = GuestPumpLoop::default();

        let tick = pump_loop.tick(&mut pump, &mut source, &mut sink).unwrap();

        assert_eq!(tick.guest_packets_read, 1);
        assert_eq!(tick.outbound_messages_sent, 1);
        assert_eq!(tick.authority_messages_read, 0);
        assert_eq!(tick.guest_packets_written, 0);
        assert!(!tick.is_idle());
        assert!(!tick.should_stop());
        assert!(matches!(
            pump.authority().sent.first(),
            Some(NetMessage::DnsQuery(query)) if query.name.as_str() == "example.com"
        ));
        assert!(sink.packets.is_empty());
    }

    #[test]
    fn loop_tick_applies_bounded_authority_messages() {
        let mut pump = pump();
        pump.authority_mut()
            .incoming
            .push_back(AuthorityRead::Message(NetMessage::Hello(Hello::new(
                EndpointRole::Host,
                Vec::new(),
            ))));
        pump.authority_mut()
            .incoming
            .push_back(AuthorityRead::Message(NetMessage::Hello(Hello::new(
                EndpointRole::Host,
                Vec::new(),
            ))));
        pump.authority_mut()
            .incoming
            .push_back(AuthorityRead::Message(NetMessage::Hello(Hello::new(
                EndpointRole::Host,
                Vec::new(),
            ))));
        let config = GuestPumpLoopConfig::builder()
            .max_authority_messages_per_tick(2)
            .build()
            .unwrap();
        let mut pump_loop = GuestPumpLoop::new(config);
        let mut source = MockSource::with_reads([MockSourceRead::WouldBlock]);
        let mut sink = MockSink::default();

        let tick = pump_loop.tick(&mut pump, &mut source, &mut sink).unwrap();

        assert_eq!(tick.authority_messages_read, 2);
        assert_eq!(pump.authority().incoming.len(), 1);
        assert_eq!(tick.guest_packets_written, 0);
        assert!(!tick.is_idle());
    }

    #[test]
    fn loop_tick_writes_authority_response_packets() {
        let mut pump = pump();
        let packet = udp_ipv4_packet(
            40000,
            DEFAULT_HOST_GATEWAY,
            DNS_PORT,
            &dns_query_payload(0x1234, "example.com", 1),
        );
        pump.send_outbound_packet(&packet).unwrap();
        let query_id = query_id_from_last_dns(&pump);
        pump.authority_mut()
            .incoming
            .push_back(AuthorityRead::Message(NetMessage::DnsResponse(
                DnsResponse {
                    query_id,
                    code: DnsResponseCode::Ok,
                    answers: vec![DnsAnswer {
                        name: DnsName::new("example.com").unwrap(),
                        record_type: DnsRecordType::A,
                        data: DnsRecordData::Ip(IpAddr::V4(Ipv4Addr::new(198, 19, 0, 2))),
                        ttl_seconds: 60,
                    }],
                    denial: None,
                },
            )));
        let mut source = MockSource::with_reads([MockSourceRead::WouldBlock]);
        let mut sink = MockSink::default();
        let mut pump_loop = GuestPumpLoop::default();

        let tick = pump_loop.tick(&mut pump, &mut source, &mut sink).unwrap();

        assert_eq!(tick.authority_messages_read, 1);
        assert_eq!(tick.guest_packets_written, 1);
        assert_eq!(sink.packets.len(), 1);
    }

    #[test]
    fn loop_tick_reports_closed_edges() {
        let mut pump = pump();
        pump.authority_mut()
            .incoming
            .push_back(AuthorityRead::Closed);
        let mut source = MockSource::with_reads([MockSourceRead::Closed]);
        let mut sink = MockSink::default();
        let mut pump_loop = GuestPumpLoop::default();

        let tick = pump_loop.tick(&mut pump, &mut source, &mut sink).unwrap();

        assert!(tick.guest_closed);
        assert!(tick.authority_closed);
        assert!(tick.should_stop());
    }

    #[test]
    fn run_loop_waits_on_idle_and_stops_on_closed_source() {
        let mut pump = pump();
        let mut source =
            MockSource::with_reads([MockSourceRead::WouldBlock, MockSourceRead::Closed]);
        let mut sink = MockSink::default();
        let mut wait = MockWait::default();
        let mut pump_loop = GuestPumpLoop::default();

        let stats =
            run_guest_pump_loop(&mut pump_loop, &mut pump, &mut source, &mut sink, &mut wait)
                .unwrap();

        assert_eq!(stats.ticks, 2);
        assert_eq!(stats.idle_waits, 1);
        assert_eq!(wait.waits, 1);
        assert_eq!(stats.guest_packets_read, 0);
        assert_eq!(stats.authority_messages_read, 0);
    }

    #[test]
    fn run_loop_fails_closed_on_wait_error() {
        let mut pump = pump();
        let mut source = MockSource::with_reads([MockSourceRead::WouldBlock]);
        let mut sink = MockSink::default();
        let mut wait = MockWait {
            waits: 0,
            fail: Some("poll failed"),
        };
        let mut pump_loop = GuestPumpLoop::default();

        assert_eq!(
            run_guest_pump_loop(&mut pump_loop, &mut pump, &mut source, &mut sink, &mut wait),
            Err(GuestPumpError::Wait("poll failed".to_string()))
        );
    }

    #[test]
    fn loop_tick_fails_closed_on_source_errors_and_invalid_sizes() {
        let mut pump = pump();
        let mut source = MockSource::with_reads([MockSourceRead::Fail("read failed")]);
        let mut sink = MockSink::default();
        let mut pump_loop = GuestPumpLoop::default();

        assert_eq!(
            pump_loop.tick(&mut pump, &mut source, &mut sink),
            Err(GuestPumpError::PacketSource("read failed".to_string()))
        );

        let mut source = MockSource::with_reads([MockSourceRead::InvalidSize(0)]);
        assert_eq!(
            pump_loop.tick(&mut pump, &mut source, &mut sink),
            Err(GuestPumpError::InvalidPacketRead {
                bytes: 0,
                capacity: DEFAULT_MAX_TUN_PACKET_BYTES,
            })
        );
    }

    #[test]
    fn loop_config_rejects_unbounded_or_zero_values() {
        assert!(matches!(
            GuestPumpLoopConfig::builder()
                .max_tun_packet_bytes(0)
                .build(),
            Err(GuestPumpError::InvalidLoopConfig(_))
        ));
        assert!(matches!(
            GuestPumpLoopConfig::builder()
                .max_tun_packet_bytes(DEFAULT_MAX_TUN_PACKET_BYTES + 1)
                .build(),
            Err(GuestPumpError::InvalidLoopConfig(_))
        ));
        assert!(matches!(
            GuestPumpLoopConfig::builder()
                .max_authority_messages_per_tick(0)
                .build(),
            Err(GuestPumpError::InvalidLoopConfig(_))
        ));
    }

    #[test]
    fn dns_response_from_authority_writes_guest_packet() {
        let mut pump = pump();
        let packet = udp_ipv4_packet(
            40000,
            DEFAULT_HOST_GATEWAY,
            DNS_PORT,
            &dns_query_payload(0x1234, "example.com", 1),
        );
        pump.send_outbound_packet(&packet).unwrap();
        let query_id = query_id_from_last_dns(&pump);
        let mut sink = MockSink::default();

        let outcome = pump
            .apply_authority_message(
                &mut sink,
                NetMessage::DnsResponse(DnsResponse {
                    query_id,
                    code: DnsResponseCode::Ok,
                    answers: vec![DnsAnswer {
                        name: DnsName::new("example.com").unwrap(),
                        record_type: DnsRecordType::A,
                        data: DnsRecordData::Ip(IpAddr::V4(Ipv4Addr::new(198, 19, 0, 2))),
                        ttl_seconds: 60,
                    }],
                    denial: None,
                }),
            )
            .unwrap();

        assert!(matches!(
            outcome,
            AuthorityMessageOutcome::WrotePacket { bytes } if bytes == sink.packets[0].len()
        ));
        assert_eq!(sink.packets.len(), 1);
        assert_eq!(&sink.packets[0][16..20], &DEFAULT_GUEST_ADDRESS.octets());
    }

    #[test]
    fn icmp_denial_drops_without_guest_packet() {
        let mut pump = pump();
        let target = Ipv4Addr::new(198, 19, 0, 9);
        pump.translator_mut()
            .remember_synthetic_host(target, DnsName::new("ping.example.com").unwrap());
        pump.send_outbound_packet(&icmp_echo_ipv4_packet(target, b"hello"))
            .unwrap();
        let query_id = query_id_from_last_icmp(&pump);
        let mut sink = MockSink::default();

        let outcome = pump
            .apply_authority_message(
                &mut sink,
                NetMessage::IcmpEchoResponse(IcmpEchoResponse {
                    query_id,
                    status: IcmpEchoStatus::Denied,
                    round_trip_micros: None,
                    denial: None,
                }),
            )
            .unwrap();

        assert_eq!(outcome, AuthorityMessageOutcome::DroppedWithoutPacket);
        assert!(sink.packets.is_empty());
    }

    #[test]
    fn authority_transport_errors_are_reported_without_panic() {
        let mut pump = GuestBridgePump::new(
            GuestPacketTranslator::default(),
            MockAuthority {
                sent: Vec::new(),
                incoming: VecDeque::new(),
                fail: Some("closed"),
                receive_fail: None,
            },
        );
        let packet = udp_ipv4_packet(
            40000,
            DEFAULT_HOST_GATEWAY,
            DNS_PORT,
            &dns_query_payload(0x1234, "example.com", 1),
        );

        assert_eq!(
            pump.send_outbound_packet(&packet),
            Err(GuestPumpError::Authority("closed".to_string()))
        );
    }

    #[test]
    fn tcp_authority_open_and_data_write_guest_packets() {
        let mut pump = pump();
        let target = Ipv4Addr::new(198, 19, 0, 12);
        pump.translator_mut()
            .remember_synthetic_host(target, DnsName::new("tcp.example.com").unwrap());
        pump.send_outbound_packet(&tcp_ipv4_packet(target, 443, 0x02, &[]))
            .unwrap();
        let flow_id = flow_id_from_last_tcp_open(&pump);
        let mut sink = MockSink::default();

        let outcome = pump
            .apply_authority_message(
                &mut sink,
                NetMessage::TcpOpenResult(TcpOpenResult::opened(flow_id)),
            )
            .unwrap();
        assert!(matches!(
            outcome,
            AuthorityMessageOutcome::WrotePacket { bytes } if bytes == sink.packets[0].len()
        ));
        assert_eq!(sink.packets[0][9], IPPROTO_TCP);
        assert_eq!(&sink.packets[0][12..16], &target.octets());
        assert_eq!(&sink.packets[0][16..20], &DEFAULT_GUEST_ADDRESS.octets());

        let outcome = pump
            .apply_authority_message(
                &mut sink,
                NetMessage::TcpData(StreamChunk::new(
                    flow_id,
                    FlowDirection::HostToGuest,
                    0,
                    b"hello".to_vec(),
                )),
            )
            .unwrap();

        assert!(matches!(
            outcome,
            AuthorityMessageOutcome::WrotePacket { bytes } if bytes == sink.packets[1].len()
        ));
        assert_eq!(sink.packets.len(), 2);
    }

    #[cfg(feature = "host")]
    #[test]
    fn guest_dns_then_tcp_packets_reach_host_authority_and_connector() {
        let mut pump = pump();
        let mut sink = MockSink::default();
        let mut authority = HostAuthority::new(
            AllowAllHostPolicy,
            NoopHostAuditSink,
            RecordingConnector::default(),
        );

        let dns_packet = udp_ipv4_packet(
            40000,
            DEFAULT_HOST_GATEWAY,
            DNS_PORT,
            &dns_query_payload(0x1234, "Example.COM", 1),
        );
        assert_eq!(pump.send_outbound_packet(&dns_packet), Ok(1));
        let dns_responses = authority
            .handle_message(pop_sent_message(&mut pump))
            .expect("host authority accepts guest DNS");
        let synthetic_ip = synthetic_ip_from_dns_response(&dns_responses);
        for message in dns_responses {
            pump.apply_authority_message(&mut sink, message)
                .expect("guest pump applies DNS response");
        }
        assert_eq!(
            sink.packets.len(),
            1,
            "DNS response must be written back to the guest"
        );

        let syn_packet = tcp_ipv4_packet(synthetic_ip, 80, 0x02, &[]);
        assert_eq!(pump.send_outbound_packet(&syn_packet), Ok(1));
        let open_message = pop_sent_message(&mut pump);
        let flow_id = match &open_message {
            NetMessage::OpenTcp(open) => {
                assert_eq!(open.target.host(), "example.com");
                assert_eq!(open.target.port(), 80);
                open.flow_id
            }
            other => panic!("unexpected TCP open message: {other:?}"),
        };
        let open_responses = authority
            .handle_message(open_message)
            .expect("host authority opens admitted TCP flow");
        for message in open_responses {
            pump.apply_authority_message(&mut sink, message)
                .expect("guest pump applies TCP open response");
        }
        assert_eq!(
            authority.tcp_connector_mut().opens,
            vec![(
                flow_id,
                "example.com".to_string(),
                80,
                HostRoute::unresolved()
            )]
        );
        assert_eq!(
            sink.packets.len(),
            2,
            "TCP SYN-ACK must be written back to the guest"
        );

        let request = b"GET / HTTP/1.0\r\n\r\n";
        let data_packet = tcp_ipv4_packet(synthetic_ip, 80, 0x18, request);
        assert_eq!(pump.send_outbound_packet(&data_packet), Ok(1));
        let data_message = pop_sent_message(&mut pump);
        match &data_message {
            NetMessage::TcpData(chunk) => {
                assert_eq!(chunk.flow_id, flow_id);
                assert_eq!(chunk.direction, FlowDirection::GuestToHost);
                assert_eq!(chunk.bytes.as_slice(), request);
            }
            other => panic!("unexpected TCP data message: {other:?}"),
        }
        let data_responses = authority
            .handle_message(data_message)
            .expect("host authority forwards guest TCP data");
        assert!(
            data_responses.is_empty(),
            "guest-to-host TCP data does not synthesize an immediate response"
        );
        assert_eq!(
            authority.tcp_connector_mut().sends,
            vec![(flow_id, request.to_vec(), false)]
        );
    }

    #[cfg(feature = "host")]
    #[test]
    fn guest_dns_denial_returns_refused_packet_without_synthetic_mapping() {
        let mut pump = pump();
        let mut sink = MockSink::default();
        let mut authority = HostAuthority::new(
            DenyAllHostPolicy,
            NoopHostAuditSink,
            RecordingConnector::default(),
        );

        let dns_packet = udp_ipv4_packet(
            40000,
            DEFAULT_HOST_GATEWAY,
            DNS_PORT,
            &dns_query_payload(0x1234, "blocked.example", 1),
        );
        assert_eq!(pump.send_outbound_packet(&dns_packet), Ok(1));
        let dns_responses = authority
            .handle_message(pop_sent_message(&mut pump))
            .expect("deny-all DNS produces a refusal response");
        assert!(
            authority.dns_map().is_empty(),
            "denied DNS must not allocate a synthetic address"
        );
        for message in dns_responses {
            pump.apply_authority_message(&mut sink, message)
                .expect("guest pump applies refused DNS response");
        }

        assert_eq!(sink.packets.len(), 1);
        assert_eq!(
            dns_response_rcode(&sink.packets[0]),
            5,
            "DNS response code must be REFUSED"
        );
        assert_eq!(dns_answer_count(&sink.packets[0]), 0);
    }

    #[cfg(feature = "host")]
    #[test]
    fn guest_denied_tcp_open_receives_rst_without_connector_open() {
        let mut pump = pump();
        let mut sink = MockSink::default();
        let target = Ipv4Addr::new(198, 19, 0, 44);
        pump.translator_mut()
            .remember_synthetic_host(target, DnsName::new("blocked.example").unwrap());
        let mut authority = HostAuthority::new(
            DenyAllHostPolicy,
            NoopHostAuditSink,
            RecordingConnector::default(),
        );

        let syn_packet = tcp_ipv4_packet(target, 443, 0x02, &[]);
        assert_eq!(pump.send_outbound_packet(&syn_packet), Ok(1));
        let open_responses = authority
            .handle_message(pop_sent_message(&mut pump))
            .expect("deny-all TCP produces a denied open response");
        assert!(
            authority.tcp_connector_mut().opens.is_empty(),
            "denied TCP must not invoke the host connector"
        );
        for message in open_responses {
            pump.apply_authority_message(&mut sink, message)
                .expect("guest pump applies denied TCP response");
        }

        assert_eq!(sink.packets.len(), 1);
        assert_eq!(sink.packets[0][9], IPPROTO_TCP);
        assert_eq!(&sink.packets[0][12..16], &target.octets());
        assert_eq!(&sink.packets[0][16..20], &DEFAULT_GUEST_ADDRESS.octets());
        assert_eq!(tcp_response_flags(&sink.packets[0]), TCP_RST_ACK);
    }

    #[test]
    fn unknown_tcp_authority_response_fails_closed() {
        let mut pump = pump();
        let mut sink = MockSink::default();

        assert!(matches!(
            pump.apply_authority_message(
                &mut sink,
                NetMessage::TcpData(StreamChunk::new(
                    FlowId::new(1).unwrap(),
                    FlowDirection::HostToGuest,
                    0,
                    b"hello".to_vec(),
                )),
            ),
            Err(GuestPumpError::Packet(GuestPacketError::UnknownTcpFlow))
        ));
        assert!(sink.packets.is_empty());
    }
}
