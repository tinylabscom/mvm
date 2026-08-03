//! IPv4 + TCP builders shared by the netd test modules.
//!
//! One definition of the header offsets rather than one per test module: a
//! hand-rolled copy in each module is a copy that can quietly disagree
//! about, say, the data-offset nibble and still look plausible.

use std::net::Ipv4Addr;

/// A minimal well-formed IPv4 packet carrying `payload`.
///
/// The header checksum is left zero — every consumer of these builders
/// parses the header rather than verifying it, and a wrong-but-present
/// checksum would be worse than an absent one.
pub(crate) fn v4_packet(protocol: u8, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    // A zero TTL is a packet every real forwarder drops; these stand in for
    // packets a guest actually sent.
    p[8] = 64;
    p[9] = protocol;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}

/// A 20-byte TCP header with no options and no payload.
pub(crate) fn tcp(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&src_port.to_be_bytes());
    t[2..4].copy_from_slice(&dst_port.to_be_bytes());
    // Data offset 5 words, i.e. a 20-byte header, in the high nibble.
    t[12] = 0x50;
    t[13] = flags;
    t
}
