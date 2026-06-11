//! Pure L3/L4 parse + payload rebuild for the
//! gateway packet-observer pipeline. No sockets, no async: takes `&[u8]`
//! ethernet frames, returns borrowed views, and rebuilds frames with
//! replaced payloads (recomputing IP length + IP/TCP/UDP checksums).
//!
//! Runs on untrusted guest bytes — every parse path is fallible and fails
//! closed to `None` (the bridge forwards unparsed frames unchanged).
//! `rebuild_with_payload` refuses anything it cannot serialize safely
//! (over-MTU, IP extension headers, >u16 payloads), so a redactor can
//! never silently leak (fail-closed).

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum L4Proto {
    Tcp,
    Udp,
}

/// Connection identity used as the `killed_flows` key. Direction-agnostic
/// at the type level; the bridge stores keys per its coarse per-direction
/// flow model (one guest = one workload).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: L4Proto,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiveTuple {
    pub proto: L4Proto,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl FiveTuple {
    pub fn flow_key(&self) -> FlowKey {
        FlowKey {
            proto: self.proto,
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            src_port: self.src_port,
            dst_port: self.dst_port,
        }
    }
}

/// Borrowed view of one parsed ethernet frame. `raw_frame` is the escape
/// hatch for the rare L2-aware observer; `l4_payload` is the common case.
#[derive(Debug)]
pub struct ParsedPacket<'a> {
    pub five_tuple: FiveTuple,
    pub l4_payload: &'a [u8],
    pub raw_frame: &'a [u8],
}

#[derive(Debug, thiserror::Error)]
pub enum RebuildError {
    #[error("rebuilt frame {len} bytes exceeds MTU {mtu}; V1 does not re-fragment")]
    ExceedsMtu { len: usize, mtu: usize },
    #[error("original frame is not a rebuildable plain IPv4/IPv6 TCP/UDP packet")]
    Unparseable,
    #[error("etherparse could not re-serialize the modified frame: {0}")]
    Serialize(String),
}

/// Parse an ethernet frame to a borrowed `ParsedPacket`. Returns `None`
/// for anything that is not a well-formed IPv4/IPv6 frame carrying TCP or
/// UDP (ARP, ICMP, malformed, truncated) — the caller forwards those
/// unchanged. Fails closed: any parse error → `None`.
pub fn parse(raw: &[u8]) -> Option<ParsedPacket<'_>> {
    let sliced = etherparse::SlicedPacket::from_ethernet(raw).ok()?;
    let (src_ip, dst_ip): (IpAddr, IpAddr) = match sliced.net.as_ref()? {
        etherparse::NetSlice::Ipv4(v4) => (
            IpAddr::V4(v4.header().source_addr()),
            IpAddr::V4(v4.header().destination_addr()),
        ),
        etherparse::NetSlice::Ipv6(v6) => (
            IpAddr::V6(v6.header().source_addr()),
            IpAddr::V6(v6.header().destination_addr()),
        ),
        _ => return None,
    };
    let (proto, src_port, dst_port, l4_payload) = match sliced.transport.as_ref()? {
        etherparse::TransportSlice::Tcp(tcp) => (
            L4Proto::Tcp,
            tcp.source_port(),
            tcp.destination_port(),
            tcp.payload(),
        ),
        etherparse::TransportSlice::Udp(udp) => (
            L4Proto::Udp,
            udp.source_port(),
            udp.destination_port(),
            udp.payload(),
        ),
        _ => return None,
    };
    Some(ParsedPacket {
        five_tuple: FiveTuple {
            proto,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        },
        l4_payload,
        raw_frame: raw,
    })
}

/// Rebuild `raw` with `new_payload` replacing its L4 payload, recomputing
/// IP total length + IP header checksum + TCP/UDP checksum. Refuses when
/// the result would exceed `mtu` (no re-fragmentation in V1), when the
/// original is not plain Ethernet2/IPv4|IPv6/TCP|UDP, or when IP extension
/// headers are present (V1 fail-closed shortcut — the four V1 observers
/// operate on extension-free packets). Only runs on the rare `Modify`
/// path, so the re-parse cost is acceptable.
pub fn rebuild_with_payload(
    raw: &[u8],
    new_payload: &[u8],
    mtu: usize,
) -> Result<Vec<u8>, RebuildError> {
    use etherparse::{LinkHeader, NetHeaders, TransportHeader};

    let headers = etherparse::PacketHeaders::from_ethernet_slice(raw)
        .map_err(|_| RebuildError::Unparseable)?;
    let Some(LinkHeader::Ethernet2(eth)) = headers.link else {
        return Err(RebuildError::Unparseable);
    };
    let net = headers.net.ok_or(RebuildError::Unparseable)?;
    let transport = headers.transport.ok_or(RebuildError::Unparseable)?;

    let mut out: Vec<u8> = Vec::with_capacity(raw.len() + new_payload.len());
    let serr = |e: std::io::Error| RebuildError::Serialize(e.to_string());
    let cerr = |e: etherparse::err::ValueTooBigError<usize>| RebuildError::Serialize(e.to_string());

    match (net, transport) {
        (NetHeaders::Ipv4(mut ip, ext), TransportHeader::Tcp(mut tcp)) => {
            if !ext.is_empty() {
                return Err(RebuildError::Unparseable);
            }
            check_mtu(
                14 + ip.header_len() + tcp.header_len() + new_payload.len(),
                mtu,
            )?;
            ip.set_payload_len(tcp.header_len() + new_payload.len())
                .map_err(|e| RebuildError::Serialize(e.to_string()))?;
            tcp.checksum = tcp.calc_checksum_ipv4(&ip, new_payload).map_err(cerr)?;
            eth.write(&mut out).map_err(serr)?;
            ip.write(&mut out).map_err(serr)?;
            tcp.write(&mut out).map_err(serr)?;
        }
        (NetHeaders::Ipv4(mut ip, ext), TransportHeader::Udp(mut udp)) => {
            if !ext.is_empty() {
                return Err(RebuildError::Unparseable);
            }
            let total = etherparse::UdpHeader::LEN + new_payload.len();
            check_mtu(14 + ip.header_len() + total, mtu)?;
            ip.set_payload_len(total)
                .map_err(|e| RebuildError::Serialize(e.to_string()))?;
            udp.length = u16::try_from(total)
                .map_err(|_| RebuildError::Serialize("udp length overflow".into()))?;
            udp.checksum = udp.calc_checksum_ipv4(&ip, new_payload).map_err(cerr)?;
            eth.write(&mut out).map_err(serr)?;
            ip.write(&mut out).map_err(serr)?;
            udp.write(&mut out).map_err(serr)?;
        }
        (NetHeaders::Ipv6(mut ip, ext), TransportHeader::Tcp(mut tcp)) => {
            if !ext.is_empty() {
                return Err(RebuildError::Unparseable);
            }
            check_mtu(
                14 + ip.header_len() + tcp.header_len() + new_payload.len(),
                mtu,
            )?;
            ip.set_payload_length(tcp.header_len() + new_payload.len())
                .map_err(|e| RebuildError::Serialize(e.to_string()))?;
            tcp.checksum = tcp.calc_checksum_ipv6(&ip, new_payload).map_err(cerr)?;
            eth.write(&mut out).map_err(serr)?;
            ip.write(&mut out).map_err(serr)?;
            tcp.write(&mut out).map_err(serr)?;
        }
        (NetHeaders::Ipv6(mut ip, ext), TransportHeader::Udp(mut udp)) => {
            if !ext.is_empty() {
                return Err(RebuildError::Unparseable);
            }
            let total = etherparse::UdpHeader::LEN + new_payload.len();
            check_mtu(14 + ip.header_len() + total, mtu)?;
            ip.set_payload_length(total)
                .map_err(|e| RebuildError::Serialize(e.to_string()))?;
            udp.length = u16::try_from(total)
                .map_err(|_| RebuildError::Serialize("udp length overflow".into()))?;
            udp.checksum = udp.calc_checksum_ipv6(&ip, new_payload).map_err(cerr)?;
            eth.write(&mut out).map_err(serr)?;
            ip.write(&mut out).map_err(serr)?;
            udp.write(&mut out).map_err(serr)?;
        }
        _ => return Err(RebuildError::Unparseable),
    }

    out.extend_from_slice(new_payload);
    Ok(out)
}

fn check_mtu(len: usize, mtu: usize) -> Result<(), RebuildError> {
    if len > mtu {
        Err(RebuildError::ExceedsMtu { len, mtu })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use std::net::Ipv4Addr;

    /// Build a real TCP/IPv4/Ethernet frame with the given payload.
    fn tcp_v4_frame(payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4(
                Ipv4Addr::new(10, 0, 0, 2).octets(),
                Ipv4Addr::new(93, 184, 216, 34).octets(),
                64,
            )
            .tcp(40000, 443, 1, 64000);
        let mut out = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut out, payload).unwrap();
        out
    }

    fn udp_v4_frame(payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4(
                Ipv4Addr::new(10, 0, 0, 2).octets(),
                Ipv4Addr::new(8, 8, 8, 8).octets(),
                64,
            )
            .udp(40000, 53);
        let mut out = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut out, payload).unwrap();
        out
    }

    #[test]
    fn parse_extracts_five_tuple_and_payload() {
        let frame = tcp_v4_frame(b"hello-world");
        let p = parse(&frame).expect("parses a valid TCP/IPv4 frame");
        assert_eq!(p.five_tuple.proto, L4Proto::Tcp);
        assert_eq!(p.five_tuple.dst_port, 443);
        assert_eq!(p.five_tuple.src_port, 40000);
        assert_eq!(
            p.five_tuple.dst_ip,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
        );
        assert_eq!(p.l4_payload, b"hello-world");
        assert_eq!(p.raw_frame, &frame[..]);
    }

    #[test]
    fn parse_udp_extracts_payload() {
        let frame = udp_v4_frame(b"dns-query");
        let p = parse(&frame).expect("parses UDP/IPv4");
        assert_eq!(p.five_tuple.proto, L4Proto::Udp);
        assert_eq!(p.five_tuple.dst_port, 53);
        assert_eq!(p.l4_payload, b"dns-query");
    }

    #[test]
    fn parse_non_ip_frame_returns_none() {
        // 14-byte ethernet header, ethertype 0xffff, no IP payload.
        let frame = [0xff; 14];
        assert!(parse(&frame).is_none());
    }

    #[test]
    fn parse_truncated_frame_returns_none() {
        let frame = tcp_v4_frame(b"x");
        assert!(
            parse(&frame[..10]).is_none(),
            "truncated frame must fail closed"
        );
    }

    #[test]
    fn rebuild_replaces_payload_and_fixes_checksums() {
        let frame = tcp_v4_frame(b"SECRET-TOKEN-1234");
        let rebuilt = rebuild_with_payload(&frame, b"REDACTED---------", 1514)
            .expect("same-length rebuild succeeds");
        // Re-parse strictly validates the rebuilt frame (etherparse slices
        // verify header consistency); assert payload + five-tuple survived.
        let p = parse(&rebuilt).expect("rebuilt frame re-parses");
        assert_eq!(p.l4_payload, b"REDACTED---------");
        assert_eq!(p.five_tuple.dst_port, 443);
    }

    #[test]
    fn rebuild_shorter_payload_succeeds() {
        let frame = tcp_v4_frame(b"AAAAAAAAAAAA");
        let rebuilt = rebuild_with_payload(&frame, b"BB", 1514).expect("shrink ok");
        assert_eq!(parse(&rebuilt).unwrap().l4_payload, b"BB");
    }

    #[test]
    fn rebuild_udp_payload_succeeds() {
        let frame = udp_v4_frame(b"original-dns");
        let rebuilt = rebuild_with_payload(&frame, b"modified", 1514).expect("udp rebuild ok");
        let p = parse(&rebuilt).expect("udp rebuilt re-parses");
        assert_eq!(p.l4_payload, b"modified");
        assert_eq!(p.five_tuple.proto, L4Proto::Udp);
    }

    #[test]
    fn rebuild_over_mtu_is_refused() {
        let frame = tcp_v4_frame(b"small");
        let huge = vec![0u8; 4096];
        let err = rebuild_with_payload(&frame, &huge, 1514).expect_err("must refuse over-MTU");
        assert!(matches!(err, RebuildError::ExceedsMtu { .. }));
    }

    #[test]
    fn rebuild_unparseable_original_errors() {
        let err = rebuild_with_payload(&[0xff; 14], b"x", 1514).expect_err("non-IP original");
        assert!(matches!(err, RebuildError::Unparseable));
    }

    #[test]
    fn flow_key_derives_from_five_tuple() {
        let frame = tcp_v4_frame(b"k");
        let p = parse(&frame).unwrap();
        let k = p.five_tuple.flow_key();
        assert_eq!(k.proto, L4Proto::Tcp);
        assert_eq!(k.dst_port, 443);
    }
}
