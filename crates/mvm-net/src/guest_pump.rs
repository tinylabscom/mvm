//! Guest bridge pump seam between TUN packets and the host authority.
//!
//! This module wires the dependency-light packet translator to generic
//! authority and packet-sink traits. It does not choose a serialization format,
//! async runtime, or concrete fd type; the Linux executor can provide those
//! without forcing dependencies into the default crate build.

use std::fmt;

use crate::guest_packet::{GuestPacketError, GuestPacketTranslator};
use crate::proto::NetMessage;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestPumpError {
    Packet(GuestPacketError),
    Authority(String),
    PacketSink(String),
    UnsupportedAuthorityMessage(&'static str),
}

impl fmt::Display for GuestPumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packet(err) => write!(f, "{err}"),
            Self::Authority(err) => write!(f, "authority transport failed: {err}"),
            Self::PacketSink(err) => write!(f, "guest packet sink failed: {err}"),
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

pub trait GuestPacketSink {
    type Error: fmt::Display;

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AuthorityMessageOutcome {
    WrotePacket { bytes: usize },
    DroppedWithoutPacket,
    IgnoredControl,
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
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::guest::{DEFAULT_GUEST_ADDRESS, DEFAULT_HOST_GATEWAY};
    use crate::guest_packet::{GuestPacketTranslator, GuestPacketTranslatorConfig};
    use crate::proto::{
        DnsAnswer, DnsName, DnsRecordData, DnsRecordType, DnsResponse, DnsResponseCode,
        FlowDirection, FlowId, IcmpEchoResponse, IcmpEchoStatus, StreamChunk, TcpOpenResult,
    };

    const DNS_PORT: u16 = 53;
    const UDP_HEADER_LEN: usize = 8;
    const IPV4_MIN_HEADER_LEN: usize = 20;
    const IPPROTO_ICMP: u8 = 1;
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_UDP: u8 = 17;
    const IPV4_TTL: u8 = 64;

    #[derive(Debug, Default)]
    struct MockAuthority {
        sent: Vec<NetMessage>,
        fail: Option<&'static str>,
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
                fail: Some("closed"),
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
