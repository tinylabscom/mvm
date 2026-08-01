//! The L3-over-vsock wire protocol: framing, control messages, and
//! bounded IP validation.
//!
//! Shared verbatim by the in-guest agent (`mvm-agentd`) and the host
//! gateway (`mvm-hostd::netd`), so there is exactly one implementation of
//! the bytes on the wire and one place to fuzz.
//!
//! This is an mvm protocol assembled from standard TUN and AF_VSOCK
//! primitives. It is **not** virtio-net: there is no virtio ring, no
//! virtio-net header, no offload metadata, and no Ethernet frame. A
//! `PACKET` message carries one complete IP packet and nothing else.
//!
//! See `specs/adrs/035-l3-tun-over-vsock.md`.

pub mod frame;
pub mod ip;
pub mod limits;
pub mod message;

pub use frame::{
    FrameError, FrameHeader, MAGIC, MessageType, ParsedFrame, decode, encode, encode_into,
    peek_frame_len,
};
pub use ip::{IpParseError, ParsedIpPacket, parse as parse_ip, proto, tcp_flags};
pub use limits::{
    HEADER_LEN, MAX_FRAME_LEN, MAX_PAYLOAD_LEN, MAX_WIRE_LEN, MTU_V1, PROTOCOL_VERSION,
    QUEUE_COUNT_V1,
};
pub use message::{
    Config, ErrorCode, ErrorMessage, Heartbeat, Hello, Ipv4Config, Ipv6Config, MessageError, Ready,
    Shutdown, ShutdownReason, features,
};

/// Vsock port carrying the **control** connection: handshake,
/// configuration, liveness, and shutdown. One connection per session.
///
/// Deliberately distinct from the machine-control RPC port
/// (`mvm_agentd::vsock::GUEST_AGENT_PORT`): bulk packet traffic must never
/// share a stream with machine control, or a saturated uplink starves the
/// guest's own health checks and the host's shutdown path.
pub const L3_CONTROL_PORT: u32 = 5254;

/// Base vsock port for **data** connections. Queue `q` uses
/// `L3_DATA_PORT_BASE + q`. Version 1 opens queue 0 only; the base exists
/// so multi-queue is a negotiation, not a re-numbering.
pub const L3_DATA_PORT_BASE: u32 = 5260;

/// Vsock port for data queue `queue_id`.
pub fn data_port(queue_id: u16) -> u32 {
    L3_DATA_PORT_BASE + u32::from(queue_id)
}

/// Kernel-cmdline flag the host sets when a boot is admitted for the L3
/// tunnel. The guest init keys off this to start the agent — and to refuse
/// to start the workload if the agent cannot come up.
///
/// A cmdline token rather than a file or an env var because it is the one
/// channel that already exists before any guest userspace runs, and because
/// the host writes it as part of the boot the plan admitted.
pub const GUEST_CMDLINE_FLAG: &str = "mvm.l3=1";

/// Path the guest agent creates once `mvm0` is configured and the tunnel is
/// carrying packets.
///
/// This is the readiness signal the workload supervisor waits on. Its
/// absence is meaningful: a workload admitted for networking must not start
/// without it, or it runs believing it has a network it does not have.
pub const GUEST_READY_FILE: &str = "/run/mvm/l3-ready";

/// Interface name the guest agent creates. Fixed so host-side diagnostics
/// and guest-side expectations cannot drift, and short enough for
/// `IFNAMSIZ`.
pub const GUEST_INTERFACE: &str = "mvm0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_and_data_ports_do_not_collide_with_existing_services() {
        // 5251 exit-report, 5252 guest agent, 5253 egress gateway,
        // 5300 host-services broker, 10000+ port-forward, 20000+ console.
        for taken in [5251u32, 5252, 5253, 5300] {
            assert_ne!(L3_CONTROL_PORT, taken);
            assert_ne!(L3_DATA_PORT_BASE, taken);
        }
        const { assert!(L3_CONTROL_PORT > 1023, "must not need CAP_NET_BIND_SERVICE") };
        const { assert!(L3_DATA_PORT_BASE > L3_CONTROL_PORT) };
        assert!(
            L3_DATA_PORT_BASE + u32::from(limits::MAX_QUEUES) < 10_000,
            "the whole queue range must stay below the port-forward base"
        );
    }

    #[test]
    fn queue_ports_are_contiguous_from_the_base() {
        assert_eq!(data_port(0), L3_DATA_PORT_BASE);
        assert_eq!(data_port(3), L3_DATA_PORT_BASE + 3);
    }

    #[test]
    fn the_guest_interface_name_fits_ifnamsiz() {
        assert!(GUEST_INTERFACE.len() < 16);
        assert_eq!(GUEST_INTERFACE, "mvm0");
    }
}
