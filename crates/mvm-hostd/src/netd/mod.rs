//! `mvm-netd` — the host-side L3 tunnel gateway.
//!
//! One gateway per machine, not a general packet forwarder. A packet may
//! reach a host forwarding mechanism only after it has crossed vsock, been
//! bound to a host-owned machine session, passed frame and IP validation,
//! and passed the signed plan's policy. The inverse holds for inbound
//! traffic: nothing enters a guest except through this gateway, an admitted
//! session, a framed vsock data connection, and the guest agent.
//!
//! Host TUN devices, network namespaces, routes, and nftables rules live
//! strictly *after* that boundary. None of them is ever attached to a guest
//! or exposed as a hypervisor network device.
//!
//! See `specs/adrs/036-l3-tun-over-vsock.md`.

/// The already-admitted configuration the launch path hands `mvm-netd`.
/// Defined in `mvm-net` so the launch path can build one without depending
/// on this crate; re-exported here because this is where it is consumed.
pub mod config {
    pub use mvm_net::l3::config::*;

    /// Map the wire layout onto this crate's provider layout. The
    /// conversion lives here, not in the policy core, so the core does not
    /// have to know the daemon's types.
    pub fn uds_layout(value: NetdUdsLayout) -> super::UdsLayout {
        match value {
            NetdUdsLayout::PerVmDir => super::UdsLayout::PerVmDir,
            NetdUdsLayout::HvfVsockDir => super::UdsLayout::HvfVsockDir,
        }
    }
}
pub mod datapath;
pub mod gateway;
pub mod metrics;
pub mod packet;
/// IPv4/TCP builders shared by this module tree's tests.
#[cfg(test)]
pub(crate) mod test_packets;
/// The per-port Unix-socket guest channel — the concrete transport behind
/// the backend-neutral abstraction for every VMM whose host-facing endpoint
/// is a per-VM socket.
pub mod uds_channel;
/// The userspace socket datapath: terminates guest TCP/UDP and
/// re-originates each admitted flow on a host socket.
pub mod userspace;

#[cfg(target_os = "linux")]
pub mod linux;

pub use datapath::{
    DatapathError, DatapathHandle, DatapathRequest, ForwardingCapabilities, L3Datapath,
    LoopbackDatapath, LoopbackHandle, MacosUserspaceGateway, UnsupportedDatapath,
};
pub use gateway::{
    Direction, Gateway, GatewayConfig, GatewayError, GatewayEvent, GatewayState, HostResolver,
    ResolveError, StaticResolver,
};
pub use metrics::GatewayMetrics;
pub use uds_channel::{UdsGuestChannelProvider, UdsLayout};

/// The datapath for the host this build runs on.
///
/// Linux gets the real host-TUN/netns/nftables path. Every other platform
/// gets a datapath that refuses, so `l3-vsock` is rejected at admission with
/// a stated reason instead of coming up and dropping everything. There is
/// deliberately no interim path through a general-purpose proxy runtime.
pub fn host_datapath() -> Box<dyn L3Datapath> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxDatapath::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(datapath::MacosUserspaceGateway)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Box::new(UnsupportedDatapath::new("this platform"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_datapath_availability_matches_the_platform() {
        let available = host_datapath().is_available();
        if cfg!(target_os = "linux") {
            // On Linux availability depends on privileges and /dev/net/tun,
            // so the assertion is only that the answer is stated rather than
            // guessed: an error must name what is missing.
            if let Err(err) = available {
                let msg = err.to_string();
                assert!(!msg.is_empty());
            }
        } else {
            let err = available.expect_err("only Linux ships a datapath");
            assert!(matches!(err, DatapathError::Unsupported { .. }));
        }
    }
}
