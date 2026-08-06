//! TCP segment construction helpers for the userspace socket datapath.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use mvm_net::l3::flow::FlowKey;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpControl, TcpPacket, TcpRepr,
    TcpSeqNumber,
};

/// TTL on a synthesized reset. The guest is one hop away over the stack's
/// own interface, so this is only ever decremented by the guest's own
/// receive path; the conventional 64 keeps the packet indistinguishable
/// from one a real peer sent.
const RESET_HOP_LIMIT: u8 = 64;

/// Build the reset a guest is owed when the host side of its flow will
/// never come up, so its `connect()` fails as it would on a real path
/// instead of hanging until the guest's own timeout.
///
/// `key` supplies the admitted flow identity the reset must appear to come
/// from, `guest` the leased address it is sent to, and `acknowledging` the
/// sequence number of the SYN being answered. RFC 793's answer to a SYN is
/// `RST|ACK` with sequence zero acknowledging the SYN's sequence plus one —
/// a reset outside that window is discarded by the guest's stack and is no
/// reset at all.
///
/// `None` only when the session leased the guest no address in the flow's
/// family. It is not a statement about which families are supported — both
/// are emitted.
pub fn synthesize_rst(key: &FlowKey, guest: IpAddr, acknowledging: u32) -> Option<Vec<u8>> {
    let tcp = TcpRepr {
        src_port: key.remote_port,
        dst_port: key.guest_port,
        control: TcpControl::Rst,
        seq_number: TcpSeqNumber(0),
        // `as i32` is the wrap TCP sequence arithmetic is defined on: the
        // space is modulo 2^32, and smoltcp carries it signed.
        ack_number: Some(TcpSeqNumber(acknowledging as i32) + 1),
        window_len: 0,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    match (key.remote, guest) {
        (IpAddr::V4(remote), IpAddr::V4(guest)) => Some(emit_v4_segment(remote, guest, &tcp)),
        (IpAddr::V6(remote), IpAddr::V6(guest)) => Some(emit_v6_segment(remote, guest, &tcp)),
        _ => None,
    }
}

/// Emit `tcp` inside an IPv4 header. The header checksum is written by
/// `emit` and covers only the header, so writing the segment afterwards
/// does not invalidate it.
///
/// Named by direction rather than by role: this datapath emits segments
/// both ways — host-originated resets toward the guest, and, in the test
/// fixtures, guest segments toward a destination — and a signature that
/// said `remote, guest` would read as an argument order the second use
/// violates.
pub fn emit_v4_segment(src: Ipv4Addr, dst: Ipv4Addr, tcp: &TcpRepr<'_>) -> Vec<u8> {
    let ip = Ipv4Repr {
        src_addr: src,
        dst_addr: dst,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: RESET_HOP_LIMIT,
    };
    let checksums = ChecksumCapabilities::default();
    let mut bytes = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
    let mut packet = Ipv4Packet::new_unchecked(&mut bytes);
    ip.emit(&mut packet, &checksums);
    tcp.emit(
        &mut TcpPacket::new_unchecked(packet.payload_mut()),
        &src.into(),
        &dst.into(),
        &checksums,
    );
    bytes
}

/// Emit `tcp` inside an IPv6 header. IPv6 has no header checksum, but the
/// TCP checksum is computed over a different pseudo-header from IPv4's, so
/// the two cannot share an emitter.
///
/// Named by direction rather than by role, for the reason
/// [`emit_v4_segment`] gives.
pub fn emit_v6_segment(src: Ipv6Addr, dst: Ipv6Addr, tcp: &TcpRepr<'_>) -> Vec<u8> {
    let ip = Ipv6Repr {
        src_addr: src,
        dst_addr: dst,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: RESET_HOP_LIMIT,
    };
    let mut bytes = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
    let mut packet = Ipv6Packet::new_unchecked(&mut bytes);
    ip.emit(&mut packet);
    tcp.emit(
        &mut TcpPacket::new_unchecked(packet.payload_mut()),
        &src.into(),
        &dst.into(),
        &ChecksumCapabilities::default(),
    );
    bytes
}
