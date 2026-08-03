//! Bounded IPv4/IPv6 packet validation.
//!
//! Runs on bytes a hostile guest wrote. Every path is fallible, every walk
//! is bounded, and nothing is trusted twice: the declared total length is
//! checked against the buffer, the declared header length is checked
//! against the total, and extension-header traversal is capped in both
//! chain length and total bytes.
//!
//! This module answers "what is this packet, and is it structurally
//! sane" — it does not answer "may it go". Policy lives in `mvm-net`.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::limits::{IPV6_HEADER_LEN, MAX_IPV6_EXT_BYTES, MAX_IPV6_EXT_HEADERS, MIN_IPV4_HEADER};

/// IANA transport protocol numbers this validator understands well enough
/// to extract ports or message types from.
pub mod proto {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ICMPV6: u8 = 58;
}

/// IPv6 extension-header next-header values.
mod ext {
    pub const HOP_BY_HOP: u8 = 0;
    pub const ROUTING: u8 = 43;
    pub const FRAGMENT: u8 = 44;
    pub const ESP: u8 = 50;
    pub const AUTH: u8 = 51;
    pub const NO_NEXT_HEADER: u8 = 59;
    pub const DESTINATION_OPTIONS: u8 = 60;

    /// Whether `n` names an extension header rather than a transport
    /// protocol. ESP is deliberately excluded: its payload is opaque, so
    /// the walk must stop there rather than pretend to keep parsing.
    pub fn is_extension(n: u8) -> bool {
        matches!(
            n,
            HOP_BY_HOP | ROUTING | FRAGMENT | AUTH | DESTINATION_OPTIONS
        )
    }
}

/// Why a packet was refused. Each variant is a distinct counter on the
/// gateway, so an operator can tell "guest is buggy" from "guest is
/// probing".
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IpParseError {
    /// Fewer bytes than the smallest possible header.
    #[error("packet of {len} bytes is shorter than the {min}-byte minimum header")]
    TooShort { len: usize, min: usize },
    /// The version nibble was neither 4 nor 6.
    #[error("unsupported IP version {0}")]
    UnsupportedVersion(u8),
    /// IPv4 IHL named a header shorter than 20 bytes or longer than the
    /// packet.
    #[error("invalid IPv4 header length {0}")]
    InvalidHeaderLen(usize),
    /// The declared total length disagreed with the bytes present, or was
    /// smaller than the header it declared.
    #[error("declared total length {declared} inconsistent with {available} bytes available")]
    InconsistentTotalLength { declared: usize, available: usize },
    /// The transport header was truncated.
    #[error("truncated {proto} header")]
    TruncatedTransport { proto: &'static str },
    /// The IPv6 extension-header chain exceeded its bound.
    #[error("IPv6 extension header chain exceeded bounds ({headers} headers, {bytes} bytes)")]
    ExtensionChainTooLong { headers: usize, bytes: usize },
    /// An extension header declared a length that ran off the packet.
    #[error("malformed IPv6 extension header")]
    MalformedExtensionHeader,
}

/// A structurally validated packet, reduced to what policy needs. No
/// borrowed payload: every consumer of this type makes an
/// address/port/protocol decision, and handing them the bytes would
/// invite payload inspection this mode explicitly does not do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedIpPacket {
    /// 4 or 6.
    pub version: u8,
    /// Transport protocol number after any extension headers.
    pub protocol: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    /// Source port for TCP/UDP; `None` otherwise.
    pub src_port: Option<u16>,
    /// Destination port for TCP/UDP; `None` otherwise.
    pub dst_port: Option<u16>,
    /// ICMP/ICMPv6 (type, code); `None` otherwise.
    pub icmp: Option<(u8, u8)>,
    /// Whether this is a fragment (IPv4 MF set or non-zero offset; IPv6
    /// fragment extension header present). Version 1 refuses these rather
    /// than reassembling.
    pub fragment: bool,
    /// Bytes the packet declares itself to be.
    pub total_len: usize,
}

impl ParsedIpPacket {
    /// TCP SYN without ACK — a flow's first packet. The gateway uses this
    /// to decide whether it is looking at a new flow or a stray segment.
    pub fn is_tcp_syn_only(&self, flags: u8) -> bool {
        self.protocol == proto::TCP && (flags & TCP_SYN) != 0 && (flags & TCP_ACK) == 0
    }
}

/// TCP flag bits the gateway cares about.
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

/// Parse and structurally validate one IP packet.
///
/// `buf` must contain exactly one packet. Extra trailing bytes beyond the
/// declared total length are tolerated for IPv4 (link padding is normal),
/// but the declared length is what everything downstream uses.
pub fn parse(buf: &[u8]) -> Result<ParsedIpPacket, IpParseError> {
    let first = *buf.first().ok_or(IpParseError::TooShort {
        len: 0,
        min: MIN_IPV4_HEADER,
    })?;
    match first >> 4 {
        4 => parse_v4(buf),
        6 => parse_v6(buf),
        other => Err(IpParseError::UnsupportedVersion(other)),
    }
}

fn parse_v4(buf: &[u8]) -> Result<ParsedIpPacket, IpParseError> {
    if buf.len() < MIN_IPV4_HEADER {
        return Err(IpParseError::TooShort {
            len: buf.len(),
            min: MIN_IPV4_HEADER,
        });
    }
    let ihl = ((buf[0] & 0x0f) as usize) * 4;
    if ihl < MIN_IPV4_HEADER || ihl > buf.len() {
        return Err(IpParseError::InvalidHeaderLen(ihl));
    }
    let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if total_len < ihl || total_len > buf.len() {
        return Err(IpParseError::InconsistentTotalLength {
            declared: total_len,
            available: buf.len(),
        });
    }

    let flags_frag = u16::from_be_bytes([buf[6], buf[7]]);
    let more_fragments = flags_frag & 0x2000 != 0;
    let fragment_offset = flags_frag & 0x1fff;
    let fragment = more_fragments || fragment_offset != 0;

    let protocol = buf[9];
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);

    // A non-initial fragment carries no transport header to read. Version
    // 1 refuses fragments anyway, but the parse must not read past the
    // header to discover that.
    let transport = if fragment_offset != 0 {
        Transport::default()
    } else {
        parse_transport(protocol, &buf[ihl..total_len])?
    };

    Ok(ParsedIpPacket {
        version: 4,
        protocol,
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        src_port: transport.src_port,
        dst_port: transport.dst_port,
        icmp: transport.icmp,
        fragment,
        total_len,
    })
}

fn parse_v6(buf: &[u8]) -> Result<ParsedIpPacket, IpParseError> {
    if buf.len() < IPV6_HEADER_LEN {
        return Err(IpParseError::TooShort {
            len: buf.len(),
            min: IPV6_HEADER_LEN,
        });
    }
    let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let total_len = IPV6_HEADER_LEN + payload_len;
    if total_len > buf.len() {
        return Err(IpParseError::InconsistentTotalLength {
            declared: total_len,
            available: buf.len(),
        });
    }

    let mut src = [0u8; 16];
    src.copy_from_slice(&buf[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&buf[24..40]);

    let (protocol, offset, fragment) = walk_v6_extensions(buf[6], &buf[..total_len])?;
    let transport = if fragment {
        // A fragmented IPv6 packet is refused by policy; do not attempt to
        // read a transport header that may belong to another fragment.
        Transport::default()
    } else {
        parse_transport(protocol, &buf[offset..total_len])?
    };

    Ok(ParsedIpPacket {
        version: 6,
        protocol,
        src: IpAddr::V6(Ipv6Addr::from(src)),
        dst: IpAddr::V6(Ipv6Addr::from(dst)),
        src_port: transport.src_port,
        dst_port: transport.dst_port,
        icmp: transport.icmp,
        fragment,
        total_len,
    })
}

/// Walk the IPv6 extension-header chain, bounded in both header count and
/// total bytes traversed. Returns the final next-header value, the offset
/// of the transport header, and whether a fragment header was seen.
fn walk_v6_extensions(mut next_header: u8, buf: &[u8]) -> Result<(u8, usize, bool), IpParseError> {
    let mut offset = IPV6_HEADER_LEN;
    let mut headers = 0usize;
    let mut bytes = 0usize;
    let mut fragment = false;

    while ext::is_extension(next_header) {
        headers += 1;
        if headers > MAX_IPV6_EXT_HEADERS || bytes > MAX_IPV6_EXT_BYTES {
            return Err(IpParseError::ExtensionChainTooLong { headers, bytes });
        }
        if offset + 2 > buf.len() {
            return Err(IpParseError::MalformedExtensionHeader);
        }
        let this = next_header;
        next_header = buf[offset];
        // Fragment headers are a fixed 8 bytes; every other extension
        // header encodes its length in 8-octet units excluding the first.
        // AH is the exception: 4-octet units, excluding two.
        let ext_len = match this {
            ext::FRAGMENT => 8,
            ext::AUTH => (buf[offset + 1] as usize + 2) * 4,
            _ => (buf[offset + 1] as usize + 1) * 8,
        };
        if this == ext::FRAGMENT {
            fragment = true;
        }
        if ext_len == 0 || offset + ext_len > buf.len() {
            return Err(IpParseError::MalformedExtensionHeader);
        }
        offset += ext_len;
        bytes += ext_len;
        if bytes > MAX_IPV6_EXT_BYTES {
            return Err(IpParseError::ExtensionChainTooLong { headers, bytes });
        }
    }

    if next_header == ext::NO_NEXT_HEADER || next_header == ext::ESP {
        // Nothing further is parseable. Report the offset at the end so
        // callers do not read past what we validated.
        return Ok((next_header, buf.len(), fragment));
    }
    Ok((next_header, offset, fragment))
}

/// Ports / ICMP identity extracted from a transport header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Transport {
    src_port: Option<u16>,
    dst_port: Option<u16>,
    icmp: Option<(u8, u8)>,
}

fn parse_transport(protocol: u8, buf: &[u8]) -> Result<Transport, IpParseError> {
    match protocol {
        proto::TCP => {
            if buf.len() < 20 {
                return Err(IpParseError::TruncatedTransport { proto: "TCP" });
            }
            Ok(Transport {
                src_port: Some(u16::from_be_bytes([buf[0], buf[1]])),
                dst_port: Some(u16::from_be_bytes([buf[2], buf[3]])),
                icmp: None,
            })
        }
        proto::UDP => {
            if buf.len() < 8 {
                return Err(IpParseError::TruncatedTransport { proto: "UDP" });
            }
            Ok(Transport {
                src_port: Some(u16::from_be_bytes([buf[0], buf[1]])),
                dst_port: Some(u16::from_be_bytes([buf[2], buf[3]])),
                icmp: None,
            })
        }
        proto::ICMP | proto::ICMPV6 => {
            if buf.len() < 4 {
                return Err(IpParseError::TruncatedTransport { proto: "ICMP" });
            }
            Ok(Transport {
                src_port: None,
                dst_port: None,
                icmp: Some((buf[0], buf[1])),
            })
        }
        // Any other protocol is structurally fine; policy decides whether
        // it may go. We extract nothing rather than guessing a layout.
        _ => Ok(Transport::default()),
    }
}

/// Where a validated packet's TCP header starts, for the readers below.
///
/// One definition of the offset rather than one per field: the IPv6 arm
/// walks an extension chain, and a second copy of that walk is a second
/// place for it to be wrong.
fn tcp_header_offset(buf: &[u8], packet: &ParsedIpPacket) -> Option<usize> {
    if packet.protocol != proto::TCP || packet.fragment {
        return None;
    }
    match packet.version {
        4 => Some(((*buf.first()? & 0x0f) as usize) * 4),
        6 => Some(
            walk_v6_extensions(*buf.get(6)?, buf.get(..packet.total_len)?)
                .ok()?
                .1,
        ),
        _ => None,
    }
}

/// Read the TCP flag byte from a validated packet's buffer, if it has one.
/// Separate from [`parse`] because only the flow tracker needs it.
pub fn tcp_flags(buf: &[u8], packet: &ParsedIpPacket) -> Option<u8> {
    buf.get(tcp_header_offset(buf, packet)? + 13).copied()
}

/// Read the TCP sequence number from a validated packet's buffer.
///
/// Read at its fixed offset within the TCP header rather than through a
/// parser that first honours the data-offset nibble. The nibble is
/// guest-written and can declare a header longer than the bytes present;
/// a reader that validates it first would refuse packets whose sequence
/// number is right there, and a guest could use that to suppress a reset
/// the host owes it. The sequence number sits at bytes 4..8, and [`parse`]
/// has already guaranteed a TCP packet carries at least 20 transport
/// bytes, so those four are always present.
pub fn tcp_sequence(buf: &[u8], packet: &ParsedIpPacket) -> Option<u32> {
    let offset = tcp_header_offset(buf, packet)?;
    let seq = buf.get(offset + 4..offset + 8)?;
    Some(u32::from_be_bytes(seq.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Build a minimal IPv4 packet. `payload` follows the 20-byte header.
    fn v4(protocol: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[9] = protocol;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p.extend_from_slice(payload);
        p
    }

    fn tcp_payload(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&src_port.to_be_bytes());
        t[2..4].copy_from_slice(&dst_port.to_be_bytes());
        t[12] = 0x50;
        t[13] = flags;
        t
    }

    fn udp_payload(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut u = vec![0u8; 8];
        u[0..2].copy_from_slice(&src_port.to_be_bytes());
        u[2..4].copy_from_slice(&dst_port.to_be_bytes());
        u
    }

    /// Build a minimal IPv6 packet with an explicit next-header chain.
    fn v6(next_header: u8, src: [u8; 16], dst: [u8; 16], rest: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(rest.len() as u16).to_be_bytes());
        p[6] = next_header;
        p[7] = 64;
        p[8..24].copy_from_slice(&src);
        p[24..40].copy_from_slice(&dst);
        p.extend_from_slice(rest);
        p
    }

    #[test]
    fn parses_an_ipv4_tcp_packet() {
        let pkt = v4(
            proto::TCP,
            [10, 0, 0, 2],
            [93, 184, 216, 34],
            &tcp_payload(50000, 443, TCP_SYN),
        );
        let parsed = parse(&pkt).unwrap();
        assert_eq!(parsed.version, 4);
        assert_eq!(parsed.protocol, proto::TCP);
        assert_eq!(parsed.src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(parsed.dst, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(parsed.src_port, Some(50000));
        assert_eq!(parsed.dst_port, Some(443));
        assert!(!parsed.fragment);
        assert_eq!(parsed.total_len, 40);
        assert_eq!(tcp_flags(&pkt, &parsed), Some(TCP_SYN));
        assert!(parsed.is_tcp_syn_only(TCP_SYN));
        assert!(!parsed.is_tcp_syn_only(TCP_SYN | TCP_ACK));
    }

    #[test]
    fn parses_an_ipv4_udp_packet() {
        let pkt = v4(
            proto::UDP,
            [10, 0, 0, 2],
            [1, 1, 1, 1],
            &udp_payload(1234, 53),
        );
        let parsed = parse(&pkt).unwrap();
        assert_eq!(parsed.protocol, proto::UDP);
        assert_eq!(parsed.dst_port, Some(53));
        assert!(parsed.icmp.is_none());
    }

    #[test]
    fn parses_an_ipv4_icmp_packet() {
        let pkt = v4(proto::ICMP, [10, 0, 0, 2], [8, 8, 8, 8], &[8, 0, 0, 0]);
        let parsed = parse(&pkt).unwrap();
        assert_eq!(parsed.icmp, Some((8, 0)));
        assert_eq!(parsed.src_port, None);
    }

    #[test]
    fn parses_an_ipv4_header_with_options() {
        let mut pkt = v4(proto::UDP, [10, 0, 0, 2], [1, 1, 1, 1], &[]);
        // Widen the header to 24 bytes and append the UDP header after it.
        pkt[0] = 0x46;
        pkt.extend_from_slice(&[0u8; 4]);
        pkt.extend_from_slice(&udp_payload(7, 9));
        let total = pkt.len();
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        let parsed = parse(&pkt).unwrap();
        assert_eq!(parsed.dst_port, Some(9));
    }

    #[test]
    fn rejects_an_empty_buffer() {
        assert!(matches!(parse(&[]), Err(IpParseError::TooShort { .. })));
    }

    #[test]
    fn rejects_a_bad_version_nibble() {
        for v in [0u8, 1, 2, 3, 5, 7, 8, 15] {
            let mut pkt = vec![0u8; 40];
            pkt[0] = v << 4;
            assert!(matches!(
                parse(&pkt),
                Err(IpParseError::UnsupportedVersion(got)) if got == v
            ));
        }
    }

    #[test]
    fn rejects_a_short_ipv4_packet() {
        let pkt = vec![0x45u8; MIN_IPV4_HEADER - 1];
        assert!(matches!(parse(&pkt), Err(IpParseError::TooShort { .. })));
    }

    #[test]
    fn rejects_an_ipv4_ihl_below_the_minimum() {
        let mut pkt = v4(proto::UDP, [10, 0, 0, 2], [1, 1, 1, 1], &udp_payload(1, 2));
        pkt[0] = 0x44; // IHL 4 → 16 bytes
        assert!(matches!(
            parse(&pkt),
            Err(IpParseError::InvalidHeaderLen(16))
        ));
    }

    #[test]
    fn rejects_an_ipv4_ihl_beyond_the_buffer() {
        let mut pkt = v4(proto::UDP, [10, 0, 0, 2], [1, 1, 1, 1], &[]);
        pkt[0] = 0x4f; // IHL 15 → 60 bytes, buffer is 20
        assert!(matches!(
            parse(&pkt),
            Err(IpParseError::InvalidHeaderLen(60))
        ));
    }

    #[test]
    fn rejects_a_total_length_that_overruns_the_buffer() {
        let mut pkt = v4(proto::UDP, [10, 0, 0, 2], [1, 1, 1, 1], &udp_payload(1, 2));
        pkt[2..4].copy_from_slice(&9000u16.to_be_bytes());
        assert!(matches!(
            parse(&pkt),
            Err(IpParseError::InconsistentTotalLength { .. })
        ));
    }

    #[test]
    fn rejects_a_total_length_below_its_own_header() {
        let mut pkt = v4(proto::UDP, [10, 0, 0, 2], [1, 1, 1, 1], &udp_payload(1, 2));
        pkt[2..4].copy_from_slice(&10u16.to_be_bytes());
        assert!(matches!(
            parse(&pkt),
            Err(IpParseError::InconsistentTotalLength { .. })
        ));
    }

    #[test]
    fn rejects_a_truncated_tcp_header() {
        let pkt = v4(proto::TCP, [10, 0, 0, 2], [1, 1, 1, 1], &[0u8; 8]);
        assert!(matches!(
            parse(&pkt),
            Err(IpParseError::TruncatedTransport { proto: "TCP" })
        ));
    }

    #[test]
    fn rejects_a_truncated_udp_header() {
        let pkt = v4(proto::UDP, [10, 0, 0, 2], [1, 1, 1, 1], &[0u8; 4]);
        assert!(matches!(
            parse(&pkt),
            Err(IpParseError::TruncatedTransport { proto: "UDP" })
        ));
    }

    #[test]
    fn detects_ipv4_fragments_both_ways() {
        // More-fragments set on the first fragment.
        let mut first = v4(proto::UDP, [10, 0, 0, 2], [1, 1, 1, 1], &udp_payload(1, 2));
        first[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(parse(&first).unwrap().fragment);

        // A non-initial fragment has an offset and no readable transport
        // header — the parse must succeed without reading one.
        let mut later = v4(proto::UDP, [10, 0, 0, 2], [1, 1, 1, 1], &[0u8; 2]);
        later[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
        let parsed = parse(&later).unwrap();
        assert!(parsed.fragment);
        assert_eq!(parsed.src_port, None);
    }

    #[test]
    fn parses_an_ipv6_tcp_packet() {
        let pkt = v6(
            proto::TCP,
            [0x20; 16],
            [0x30; 16],
            &tcp_payload(1000, 443, TCP_SYN),
        );
        let parsed = parse(&pkt).unwrap();
        assert_eq!(parsed.version, 6);
        assert_eq!(parsed.protocol, proto::TCP);
        assert_eq!(parsed.dst_port, Some(443));
        assert_eq!(tcp_flags(&pkt, &parsed), Some(TCP_SYN));
    }

    #[test]
    fn rejects_a_short_ipv6_packet() {
        let pkt = vec![0x60u8; IPV6_HEADER_LEN - 1];
        assert!(matches!(parse(&pkt), Err(IpParseError::TooShort { .. })));
    }

    #[test]
    fn rejects_an_ipv6_payload_length_that_overruns_the_buffer() {
        let mut pkt = v6(proto::UDP, [1; 16], [2; 16], &udp_payload(1, 2));
        pkt[4..6].copy_from_slice(&4000u16.to_be_bytes());
        assert!(matches!(
            parse(&pkt),
            Err(IpParseError::InconsistentTotalLength { .. })
        ));
    }

    #[test]
    fn walks_a_single_ipv6_extension_header() {
        // Hop-by-hop: next=UDP, len=0 → 8 bytes.
        let mut rest = vec![proto::UDP, 0, 0, 0, 0, 0, 0, 0];
        rest.extend_from_slice(&udp_payload(53, 5353));
        let pkt = v6(0, [1; 16], [2; 16], &rest);
        let parsed = parse(&pkt).unwrap();
        assert_eq!(parsed.protocol, proto::UDP);
        assert_eq!(parsed.dst_port, Some(5353));
    }

    #[test]
    fn detects_an_ipv6_fragment_header() {
        let mut rest = vec![proto::UDP, 0, 0, 0, 0, 0, 0, 0];
        rest.extend_from_slice(&udp_payload(1, 2));
        let pkt = v6(44, [1; 16], [2; 16], &rest);
        let parsed = parse(&pkt).unwrap();
        assert!(parsed.fragment);
    }

    #[test]
    fn rejects_an_excessive_ipv6_extension_chain() {
        // A chain of minimum-size destination-options headers, one more
        // than the cap allows.
        let mut rest = Vec::new();
        for _ in 0..=MAX_IPV6_EXT_HEADERS {
            rest.extend_from_slice(&[ext::DESTINATION_OPTIONS, 0, 0, 0, 0, 0, 0, 0]);
        }
        let tail = rest.len() - 8;
        rest[tail] = proto::UDP;
        rest.extend_from_slice(&udp_payload(1, 2));
        let pkt = v6(ext::DESTINATION_OPTIONS, [1; 16], [2; 16], &rest);
        assert!(matches!(
            parse(&pkt),
            Err(IpParseError::ExtensionChainTooLong { .. })
        ));
    }

    #[test]
    fn rejects_an_extension_header_that_runs_off_the_packet() {
        // Declares 8 * (200 + 1) bytes inside a much smaller packet.
        let rest = vec![proto::UDP, 200, 0, 0, 0, 0, 0, 0];
        let pkt = v6(ext::DESTINATION_OPTIONS, [1; 16], [2; 16], &rest);
        assert!(matches!(
            parse(&pkt),
            Err(IpParseError::MalformedExtensionHeader)
        ));
    }

    #[test]
    fn rejects_a_truncated_extension_header() {
        let rest = vec![proto::UDP];
        let pkt = v6(ext::DESTINATION_OPTIONS, [1; 16], [2; 16], &rest);
        assert!(matches!(
            parse(&pkt),
            Err(IpParseError::MalformedExtensionHeader)
        ));
    }

    #[test]
    fn stops_at_an_opaque_esp_payload_without_guessing_a_layout() {
        let pkt = v6(ext::ESP, [1; 16], [2; 16], &[0u8; 16]);
        let parsed = parse(&pkt).unwrap();
        assert_eq!(parsed.protocol, ext::ESP);
        assert_eq!(parsed.src_port, None);
        assert_eq!(parsed.dst_port, None);
    }

    #[test]
    fn an_unknown_transport_protocol_parses_without_ports() {
        let pkt = v4(89, [10, 0, 0, 2], [1, 1, 1, 1], &[0u8; 8]); // OSPF
        let parsed = parse(&pkt).unwrap();
        assert_eq!(parsed.protocol, 89);
        assert_eq!(parsed.src_port, None);
        assert_eq!(parsed.icmp, None);
    }

    #[test]
    fn tcp_flags_returns_none_for_non_tcp() {
        let pkt = v4(proto::UDP, [10, 0, 0, 2], [1, 1, 1, 1], &udp_payload(1, 2));
        let parsed = parse(&pkt).unwrap();
        assert_eq!(tcp_flags(&pkt, &parsed), None);
    }

    #[test]
    fn tcp_sequence_reads_the_sequence_number() {
        let mut payload = tcp_payload(50_000, 443, TCP_SYN);
        payload[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        let pkt = v4(proto::TCP, [10, 0, 0, 2], [1, 1, 1, 1], &payload);
        let parsed = parse(&pkt).unwrap();
        assert_eq!(tcp_sequence(&pkt, &parsed), Some(0xDEAD_BEEF));
    }

    #[test]
    fn tcp_sequence_returns_none_for_non_tcp() {
        let pkt = v4(proto::UDP, [10, 0, 0, 2], [1, 1, 1, 1], &udp_payload(1, 2));
        let parsed = parse(&pkt).unwrap();
        assert_eq!(tcp_sequence(&pkt, &parsed), None);
    }

    /// The data-offset nibble is guest-written and can declare a header
    /// longer than the bytes present. A reader that honoured it first would
    /// refuse a sequence number sitting right there at bytes 4..8, which
    /// hands a guest a way to suppress a reset the host owes it.
    #[test]
    fn a_lying_data_offset_does_not_hide_the_sequence_number() {
        let mut payload = tcp_payload(50_000, 443, TCP_SYN);
        payload[4..8].copy_from_slice(&7u32.to_be_bytes());
        // 15 words = a 60-byte header declared inside 20 bytes.
        payload[12] = 0xF0;
        let pkt = v4(proto::TCP, [10, 0, 0, 2], [1, 1, 1, 1], &payload);
        let parsed = parse(&pkt).unwrap();
        assert_eq!(tcp_sequence(&pkt, &parsed), Some(7));
        assert_eq!(tcp_flags(&pkt, &parsed), Some(TCP_SYN));
    }

    /// Every packet that reaches a sequence-number reader has been through
    /// [`parse`], which refuses a TCP packet carrying fewer than 20
    /// transport bytes — so the four the reader wants are always present.
    #[test]
    fn a_truncated_tcp_header_never_reaches_the_sequence_reader() {
        let pkt = v4(proto::TCP, [10, 0, 0, 2], [1, 1, 1, 1], &[0u8; 12]);
        assert!(matches!(
            parse(&pkt),
            Err(IpParseError::TruncatedTransport { proto: "TCP" })
        ));
    }

    #[test]
    fn tcp_sequence_reads_past_an_ipv6_extension_chain() {
        let mut payload = tcp_payload(50_000, 443, TCP_SYN);
        payload[4..8].copy_from_slice(&99u32.to_be_bytes());
        let mut inner = vec![proto::TCP, 0, 0, 0, 0, 0, 0, 0];
        inner.extend_from_slice(&payload);
        let pkt = v6(ext::HOP_BY_HOP, [1; 16], [2; 16], &inner);
        let parsed = parse(&pkt).unwrap();
        assert_eq!(parsed.protocol, proto::TCP);
        assert_eq!(tcp_sequence(&pkt, &parsed), Some(99));
    }

    #[test]
    fn arbitrary_input_never_panics() {
        let mut state = 0xD1B5_4A32_D192_ED03u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for len in 0..300usize {
            let mut buf = vec![0u8; len];
            for byte in buf.iter_mut() {
                *byte = (next() & 0xff) as u8;
            }
            if let Ok(parsed) = parse(&buf) {
                let _ = tcp_flags(&buf, &parsed);
                let _ = tcp_sequence(&buf, &parsed);
            }
            // Force the version nibble so the deep paths get exercised
            // rather than bouncing off UnsupportedVersion.
            if !buf.is_empty() {
                buf[0] = 0x45;
                if let Ok(parsed) = parse(&buf) {
                    let _ = tcp_flags(&buf, &parsed);
                    let _ = tcp_sequence(&buf, &parsed);
                }
                buf[0] = 0x60;
                if let Ok(parsed) = parse(&buf) {
                    let _ = tcp_flags(&buf, &parsed);
                    let _ = tcp_sequence(&buf, &parsed);
                }
            }
        }
    }
}
