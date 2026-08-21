//! Hermetic driver for measuring the retired userspace L3 datapath.
//!
//! This module exists only in tests and explicit `network-perf` builds. It
//! drives the real admission gate, smoltcp termination, and host socket
//! re-origination while keeping the authority surface high level: callers can
//! run loopback TCP/UDP exchanges, but cannot inject an unadmitted packet.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use mvm_contract::l3::MTU_V1;
use mvm_core::policy::projection::{CanonicalEgress, CanonicalRule, Proto};
use mvm_net::l3::{
    AddressLease, DnsBindingStore, FlowTable, IngressTable, L3Admitter, L3PolicyConfig,
    OutboundVerdict,
};
use smoltcp::wire::{TcpControl, TcpRepr, TcpSeqNumber};

use super::tcp::emit_v4_segment;
use super::{UserspaceHandle, UserspaceSocketDatapath};
use crate::netd::packet::{build_udp_v4, udp_v4_payload};
use crate::netd::{DatapathHandle, DatapathRequest};

const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 201, 0, 5);
const GUEST: Ipv4Addr = Ipv4Addr::new(10, 201, 0, 6);
const FIRST_GUEST_PORT: u16 = 40_000;
const GUEST_ISN: u32 = 10_000;
const MAX_DRIVE_PASSES: usize = 100_000;
const TCP_CHUNK_BYTES: usize = 1_200;

/// One actual userspace-L3 fixture with policy and socket state isolated from
/// every other measured case.
pub struct LegacyL3Fixture {
    handle: UserspaceHandle,
    admitter: L3Admitter,
    next_guest_port: u16,
    now_millis: u64,
}

impl LegacyL3Fixture {
    /// Admit TCP and UDP to one loopback fixture address and open the real
    /// smoltcp-backed userspace datapath.
    pub fn for_target(target: SocketAddr, proto: Proto) -> Result<Self> {
        let IpAddr::V4(target_ip) = target.ip() else {
            bail!("the legacy benchmark fixture currently requires IPv4");
        };
        let lease = AddressLease::for_test(GATEWAY, GUEST);
        let network = ipnet::Ipv4Net::new(target_ip, 32).context("target /32")?;
        let policy = L3PolicyConfig {
            egress: CanonicalEgress::Rules(vec![CanonicalRule {
                proto,
                net: network.into(),
                port_lo: target.port(),
                port_hi: target.port(),
            }]),
            admitted_private: vec![network.into()],
            mtu: MTU_V1,
            ..L3PolicyConfig::default()
        };
        let request = DatapathRequest {
            machine_id: "network-perf".into(),
            gateway: lease.gateway,
            guest: lease.guest,
            prefix_len: lease.prefix_len(),
            v6: None,
            mtu: MTU_V1,
            ingress: Vec::new(),
        };
        let handle = UserspaceSocketDatapath::new().open_handle(&request)?;
        let mut admitter = L3Admitter::new(
            lease,
            policy,
            FlowTable::with_defaults(),
            DnsBindingStore::with_defaults(),
            IngressTable::with_defaults(),
        );
        admitter.set_ready(true);
        Ok(Self {
            handle,
            admitter,
            next_guest_port: FIRST_GUEST_PORT,
            now_millis: 0,
        })
    }

    /// Complete one TCP connect and echo through admission and smoltcp.
    pub fn tcp_echo(&mut self, target: SocketAddr, payload: &[u8]) -> Result<(Duration, Duration)> {
        let guest_port = self.take_guest_port()?;
        let connect_started = Instant::now();
        self.send_tcp(
            target,
            GuestTcpSegment {
                guest_port,
                control: TcpControl::Syn,
                seq: GUEST_ISN,
                ack: None,
                payload: &[],
            },
        )?;
        let host_isn = self.wait_for_tcp(target, guest_port, |packet| {
            (packet.flags & 0x12 == 0x12).then_some(packet.seq)
        })?;
        let connect = connect_started.elapsed();
        let host_ack = host_isn.wrapping_add(1);
        self.send_tcp(
            target,
            GuestTcpSegment {
                guest_port,
                control: TcpControl::None,
                seq: GUEST_ISN.wrapping_add(1),
                ack: Some(host_ack),
                payload: &[],
            },
        )?;

        let request_started = Instant::now();
        let mut guest_seq = GUEST_ISN.wrapping_add(1);
        for chunk in payload.chunks(TCP_CHUNK_BYTES) {
            self.send_tcp(
                target,
                GuestTcpSegment {
                    guest_port,
                    control: TcpControl::Psh,
                    seq: guest_seq,
                    ack: Some(host_ack),
                    payload: chunk,
                },
            )?;
            guest_seq = guest_seq.wrapping_add(u32::try_from(chunk.len())?);
            self.drive_once()?;
        }

        let mut response = Vec::with_capacity(payload.len());
        let mut final_ack = host_ack;
        for _ in 0..MAX_DRIVE_PASSES {
            self.drive_once()?;
            while let Some(packet) = self.next_tcp_packet(guest_port)? {
                if !packet.payload.is_empty() {
                    response.extend_from_slice(&packet.payload);
                    final_ack = packet
                        .seq
                        .wrapping_add(u32::try_from(packet.payload.len())?);
                }
            }
            if response.len() >= payload.len() {
                self.send_tcp(
                    target,
                    GuestTcpSegment {
                        guest_port,
                        control: TcpControl::None,
                        seq: guest_seq,
                        ack: Some(final_ack),
                        payload: &[],
                    },
                )?;
                if response != payload {
                    bail!("legacy L3 TCP echo changed the payload");
                }
                return Ok((connect, request_started.elapsed()));
            }
            thread::yield_now();
        }
        bail!("legacy L3 TCP echo did not complete within the drive bound")
    }

    /// Complete one UDP echo through admission and the socket association.
    pub fn udp_echo(&mut self, target: SocketAddr, payload: &[u8]) -> Result<Duration> {
        let IpAddr::V4(target_ip) = target.ip() else {
            bail!("the legacy benchmark fixture currently requires IPv4");
        };
        let guest_port = self.take_guest_port()?;
        let packet = build_udp_v4(
            GUEST,
            target_ip,
            guest_port,
            target.port(),
            payload,
            64,
            guest_port,
        );
        let started = Instant::now();
        self.send_packet(&packet)?;
        for _ in 0..MAX_DRIVE_PASSES {
            self.drive_once()?;
            let mut buffer = vec![0_u8; MTU_V1 as usize];
            loop {
                match self.handle.recv_from_network(&mut buffer) {
                    Ok(length) => {
                        if let Some(body) = udp_v4_payload(&buffer[..length])
                            && body == payload
                        {
                            return Ok(started.elapsed());
                        }
                    }
                    Err(error) if datapath_would_block(&error) => break,
                    Err(error) => return Err(error.into()),
                }
            }
            thread::yield_now();
        }
        bail!("legacy L3 UDP echo did not complete within the drive bound")
    }

    fn take_guest_port(&mut self) -> Result<u16> {
        let port = self.next_guest_port;
        self.next_guest_port = self
            .next_guest_port
            .checked_add(1)
            .context("legacy benchmark exhausted guest ports")?;
        Ok(port)
    }

    fn send_tcp(&mut self, target: SocketAddr, guest: GuestTcpSegment<'_>) -> Result<()> {
        let IpAddr::V4(target_ip) = target.ip() else {
            bail!("the legacy benchmark fixture currently requires IPv4");
        };
        let segment = TcpRepr {
            src_port: guest.guest_port,
            dst_port: target.port(),
            control: guest.control,
            seq_number: TcpSeqNumber(guest.seq.cast_signed()),
            ack_number: guest.ack.map(|number| TcpSeqNumber(number.cast_signed())),
            window_len: u16::MAX,
            window_scale: None,
            max_seg_size: matches!(guest.control, TcpControl::Syn).then_some(1_400),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: guest.payload,
        };
        self.send_packet(&emit_v4_segment(GUEST, target_ip, &segment))
    }

    fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        match self.admitter.admit_outbound(packet, self.now_millis) {
            OutboundVerdict::Forward(admitted) => self.handle.send_to_network(&admitted)?,
            OutboundVerdict::Deny(reason) => bail!("legacy L3 admission refused: {reason:?}"),
            OutboundVerdict::Gateway(_, _) => bail!("legacy L3 fixture reached a host service"),
        }
        Ok(())
    }

    fn drive_once(&mut self) -> Result<()> {
        self.now_millis = self.now_millis.saturating_add(1);
        self.handle.service(self.now_millis)?;
        Ok(())
    }

    fn wait_for_tcp<T>(
        &mut self,
        target: SocketAddr,
        guest_port: u16,
        mut accept: impl FnMut(&TcpPacket) -> Option<T>,
    ) -> Result<T> {
        for _ in 0..MAX_DRIVE_PASSES {
            self.drive_once()?;
            while let Some(packet) = self.next_tcp_packet(guest_port)? {
                if let Some(value) = accept(&packet) {
                    return Ok(value);
                }
            }
            thread::yield_now();
        }
        bail!("legacy L3 TCP flow to {target} did not advance within the drive bound")
    }

    fn next_tcp_packet(&mut self, guest_port: u16) -> Result<Option<TcpPacket>> {
        let mut buffer = vec![0_u8; MTU_V1 as usize];
        loop {
            match self.handle.recv_from_network(&mut buffer) {
                Ok(length) => {
                    if let Some(packet) = parse_tcp_packet(&buffer[..length])
                        && packet.dst_port == guest_port
                    {
                        return Ok(Some(packet));
                    }
                }
                Err(error) if datapath_would_block(&error) => return Ok(None),
                Err(error) => return Err(error.into()),
            }
        }
    }
}

struct GuestTcpSegment<'a> {
    guest_port: u16,
    control: TcpControl,
    seq: u32,
    ack: Option<u32>,
    payload: &'a [u8],
}

struct TcpPacket {
    seq: u32,
    flags: u8,
    payload: Vec<u8>,
    dst_port: u16,
}

fn parse_tcp_packet(packet: &[u8]) -> Option<TcpPacket> {
    let ihl = usize::from(packet.first()? & 0x0f) * 4;
    let tcp = packet.get(ihl..)?;
    let header = usize::from(*tcp.get(12)? >> 4) * 4;
    Some(TcpPacket {
        seq: u32::from_be_bytes(tcp.get(4..8)?.try_into().ok()?),
        flags: *tcp.get(13)?,
        payload: tcp.get(header..)?.to_vec(),
        dst_port: u16::from_be_bytes(tcp.get(2..4)?.try_into().ok()?),
    })
}

fn datapath_would_block(error: &crate::netd::DatapathError) -> bool {
    matches!(error, crate::netd::DatapathError::Io(source) if source.kind() == std::io::ErrorKind::WouldBlock)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};

    use super::*;

    #[test]
    fn real_legacy_l3_tcp_and_udp_echo_round_trip() {
        let tcp = TcpListener::bind("0.0.0.0:0").unwrap();
        let target = SocketAddr::new(local_test_ip(), tcp.local_addr().unwrap().port());
        let server = thread::spawn(move || {
            let (mut peer, _) = tcp.accept().unwrap();
            let mut body = [0; 5];
            peer.read_exact(&mut body).unwrap();
            peer.write_all(&body).unwrap();
        });
        let mut fixture = LegacyL3Fixture::for_target(target, Proto::Tcp).unwrap();
        fixture.tcp_echo(target, b"hello").unwrap();
        server.join().unwrap();

        let udp = UdpSocket::bind("0.0.0.0:0").unwrap();
        let target = SocketAddr::new(local_test_ip(), udp.local_addr().unwrap().port());
        let server = thread::spawn(move || {
            let mut body = [0; 5];
            let (length, peer) = udp.recv_from(&mut body).unwrap();
            udp.send_to(&body[..length], peer).unwrap();
        });
        let mut fixture = LegacyL3Fixture::for_target(target, Proto::Udp).unwrap();
        fixture.udp_echo(target, b"hello").unwrap();
        server.join().unwrap();
    }

    fn local_test_ip() -> IpAddr {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.connect("1.1.1.1:80").unwrap();
        socket.local_addr().unwrap().ip()
    }
}
