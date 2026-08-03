//! Building the IPv4 packets the gateway originates.
//!
//! The synthetic resolver answers the guest from the gateway address, which
//! means the gateway has to emit a well-formed IPv4/UDP packet — the guest's
//! stack will drop anything whose checksums do not verify. Kept pure and
//! separate so the arithmetic is testable without a socket.

use std::net::Ipv4Addr;

use mvm_protocol::l3::proto;

/// Sizes of the headers this module writes.
const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

/// Build an IPv4/UDP packet.
///
/// `payload` must fit the MTU once headers are added; the caller checks
/// that, because it knows the negotiated MTU and this function does not.
pub fn build_udp_v4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    ttl: u8,
    ip_id: u16,
) -> Vec<u8> {
    let total_len = IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
    let mut pkt = vec![0u8; total_len];

    pkt[0] = 0x45; // version 4, IHL 5
    pkt[1] = 0; // DSCP/ECN
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&ip_id.to_be_bytes());
    // Don't Fragment. The tunnel refuses fragments, so an oversized reply
    // must fail visibly rather than arrive in pieces that get dropped.
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = ttl;
    pkt[9] = proto::UDP;
    // checksum left zero while it is computed
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let ip_checksum = ones_complement(&pkt[..IPV4_HEADER_LEN]);
    pkt[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp = IPV4_HEADER_LEN;
    pkt[udp..udp + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[udp + 2..udp + 4].copy_from_slice(&dst_port.to_be_bytes());
    let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
    pkt[udp + 4..udp + 6].copy_from_slice(&udp_len.to_be_bytes());
    pkt[udp + 8..].copy_from_slice(payload);
    let udp_checksum = udp_v4_checksum(src, dst, &pkt[udp..]);
    pkt[udp + 6..udp + 8].copy_from_slice(&udp_checksum.to_be_bytes());

    pkt
}

/// Extract the UDP payload of a validated IPv4 packet.
///
/// Returns `None` for anything that is not IPv4/UDP or whose declared
/// lengths do not agree — the packet has already been structurally
/// validated by the protocol crate, so this is a narrowing, not a re-parse.
pub fn udp_v4_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < IPV4_HEADER_LEN || packet[0] >> 4 != 4 || packet[9] != proto::UDP {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if ihl < IPV4_HEADER_LEN || total_len > packet.len() || ihl + UDP_HEADER_LEN > total_len {
        return None;
    }
    let udp_len = u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]) as usize;
    if udp_len < UDP_HEADER_LEN || ihl + udp_len > total_len {
        return None;
    }
    Some(&packet[ihl + UDP_HEADER_LEN..ihl + udp_len])
}

/// Standard internet checksum over a byte range.
fn ones_complement(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }
    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// UDP checksum over the IPv4 pseudo-header plus the datagram.
fn udp_v4_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in src.octets().chunks(2).chain(dst.octets().chunks(2)) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += proto::UDP as u32;
    sum += udp.len() as u32;
    let mut i = 0;
    while i + 1 < udp.len() {
        sum += u16::from_be_bytes([udp[i], udp[i + 1]]) as u32;
        i += 2;
    }
    if i < udp.len() {
        sum += (udp[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    // RFC 768: a computed zero is transmitted as all-ones, because zero
    // means "no checksum" on the wire.
    if checksum == 0 { 0xffff } else { checksum }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_protocol::l3::ip;

    const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 201, 0, 5);
    const GUEST: Ipv4Addr = Ipv4Addr::new(10, 201, 0, 6);

    #[test]
    fn a_built_packet_parses_back_to_what_was_asked_for() {
        let pkt = build_udp_v4(GATEWAY, GUEST, 53, 40000, b"answer-bytes", 64, 1);
        let parsed = ip::parse(&pkt).unwrap();
        assert_eq!(parsed.version, 4);
        assert_eq!(parsed.protocol, proto::UDP);
        assert_eq!(parsed.src, std::net::IpAddr::V4(GATEWAY));
        assert_eq!(parsed.dst, std::net::IpAddr::V4(GUEST));
        assert_eq!(parsed.src_port, Some(53));
        assert_eq!(parsed.dst_port, Some(40000));
        assert!(!parsed.fragment);
        assert_eq!(parsed.total_len, pkt.len());
    }

    #[test]
    fn the_ip_header_checksum_verifies() {
        let pkt = build_udp_v4(GATEWAY, GUEST, 53, 40000, b"x", 64, 7);
        // Summing a correct header including its checksum yields zero.
        assert_eq!(ones_complement(&pkt[..20]), 0);
    }

    #[test]
    fn the_udp_checksum_verifies() {
        let pkt = build_udp_v4(GATEWAY, GUEST, 53, 40000, b"payload", 64, 7);
        let mut probe = pkt.clone();
        probe[26..28].copy_from_slice(&[0, 0]);
        let recomputed = udp_v4_checksum(GATEWAY, GUEST, &probe[20..]);
        assert_eq!(u16::from_be_bytes([pkt[26], pkt[27]]), recomputed);
    }

    #[test]
    fn an_odd_length_payload_checksums_correctly() {
        for len in [0usize, 1, 2, 3, 15, 16, 17] {
            let payload = vec![0xABu8; len];
            let pkt = build_udp_v4(GATEWAY, GUEST, 53, 40000, &payload, 64, 1);
            assert_eq!(ones_complement(&pkt[..20]), 0, "len {len}");
            assert_eq!(udp_v4_payload(&pkt), Some(payload.as_slice()), "len {len}");
        }
    }

    #[test]
    fn the_dont_fragment_bit_is_set() {
        let pkt = build_udp_v4(GATEWAY, GUEST, 53, 40000, b"x", 64, 1);
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]) & 0x4000, 0x4000);
    }

    #[test]
    fn the_udp_payload_round_trips() {
        let pkt = build_udp_v4(GATEWAY, GUEST, 53, 40000, b"round-trip", 64, 1);
        assert_eq!(udp_v4_payload(&pkt), Some(&b"round-trip"[..]));
    }

    #[test]
    fn payload_extraction_refuses_non_udp_and_malformed_input() {
        let mut tcp = build_udp_v4(GATEWAY, GUEST, 53, 40000, b"x", 64, 1);
        tcp[9] = proto::TCP;
        assert_eq!(udp_v4_payload(&tcp), None);

        assert_eq!(udp_v4_payload(&[]), None);
        assert_eq!(udp_v4_payload(&[0x45u8; 10]), None);

        // A UDP length running past the IP total length.
        let mut bad = build_udp_v4(GATEWAY, GUEST, 53, 40000, b"x", 64, 1);
        bad[24..26].copy_from_slice(&9000u16.to_be_bytes());
        assert_eq!(udp_v4_payload(&bad), None);
    }

    #[test]
    fn payload_extraction_never_panics_on_arbitrary_bytes() {
        let mut state = 0x8765_4321_ABCD_EF01u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for len in 0..200usize {
            let mut buf = vec![0u8; len];
            for byte in buf.iter_mut() {
                *byte = (next() & 0xff) as u8;
            }
            let _ = udp_v4_payload(&buf);
            if !buf.is_empty() {
                buf[0] = 0x45;
                if buf.len() > 9 {
                    buf[9] = proto::UDP;
                }
                let _ = udp_v4_payload(&buf);
            }
        }
    }
}
