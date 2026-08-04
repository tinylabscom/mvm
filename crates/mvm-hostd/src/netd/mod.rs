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
    LoopbackDatapath, LoopbackHandle, UnsupportedDatapath,
};
pub use gateway::{
    Direction, Gateway, GatewayConfig, GatewayError, GatewayEvent, GatewayState, HostResolver,
    ResolveError, StaticResolver,
};
pub use metrics::GatewayMetrics;
pub use uds_channel::{UdsGuestChannelProvider, UdsLayout};

/// What probing this host for a packet-level datapath found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunProbe {
    /// A host tunnel device exists and this process may configure it.
    Available,
    /// The device or the privilege to configure it is missing.
    Unavailable,
    /// This platform ships no host tunnel datapath at all.
    Unsupported,
}

/// The datapath this host will use, and — when it is not the packet-level
/// one — why it is not.
pub struct DatapathSelection {
    pub datapath: Box<dyn L3Datapath>,
    /// `None` only when the host got the packet-level datapath. Otherwise
    /// the operator-facing explanation from [`fallback_reason`], with
    /// whatever the probe itself said appended.
    pub fallback_reason: Option<String>,
}

/// The operator-facing explanation for forwarding through host sockets
/// rather than a host tunnel device.
///
/// Names the cause and the consequence together, because either half alone
/// is a trap. Without the cause, a later refusal reading `missing: ["icmp"]`
/// sends the operator hunting a bug in a plan that is fine. Without the
/// consequence, they know a substitution happened but not what it cost them.
fn fallback_reason(probe: TunProbe) -> Option<String> {
    let cause = match probe {
        TunProbe::Available => return None,
        TunProbe::Unavailable => {
            "this host has no usable tunnel device: forwarding whole packets needs \
             /dev/net/tun plus root or CAP_NET_ADMIN, and this process has neither"
        }
        TunProbe::Unsupported => {
            "this platform ships no host tunnel datapath: a tunnel device, its routes, and \
             a firewall anchor all need root, and mvm runs no privileged host helper"
        }
    };
    Some(format!(
        "{cause}. Forwarding has fallen back to userspace socket translation, which \
         re-originates each admitted guest TCP connection and UDP flow on a host socket. \
         It carries no ICMP, no raw IP protocols, and no arbitrary-IPv4 forwarding, so a \
         plan needing any of those is refused rather than quietly degraded."
    ))
}

/// The packet-level datapath, when this host can actually serve one.
///
/// Returns the datapath only when the probe passed, so no caller can hold
/// one that would fail at open time.
fn probe_host_tun() -> Result<Box<dyn L3Datapath>, (TunProbe, Option<String>)> {
    #[cfg(target_os = "linux")]
    {
        let tun = linux::LinuxDatapath::new();
        match tun.is_available() {
            Ok(()) => Ok(Box::new(tun)),
            Err(err) => Err((TunProbe::Unavailable, Some(err.to_string()))),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err((TunProbe::Unsupported, None))
    }
}

/// The datapath for the host this build runs on, and why.
///
/// Linux gets the real host-TUN/netns/nftables path whenever its probe
/// passes. Everywhere else — including a Linux host that lost the privilege
/// — forwarding falls back to userspace socket translation, which needs no
/// privileges at all. The fallback is never silent: the reason travels with
/// the datapath so that whatever refuses later can say what substituted for
/// what.
pub fn select_host_datapath() -> DatapathSelection {
    match probe_host_tun() {
        Ok(datapath) => DatapathSelection {
            datapath,
            fallback_reason: None,
        },
        Err((probe, detail)) => {
            let reason = fallback_reason(probe).map(|reason| match detail {
                Some(detail) => format!("{reason} The probe reported: {detail}"),
                None => reason,
            });
            DatapathSelection {
                datapath: Box::new(userspace::UserspaceSocketDatapath::new()),
                fallback_reason: reason,
            }
        }
    }
}

/// The datapath alone, for callers that only ask whether this host can serve
/// one. A caller that reports a failure to a human wants
/// [`select_host_datapath`] instead, so the fallback reason reaches them.
pub fn host_datapath() -> Box<dyn L3Datapath> {
    select_host_datapath().datapath
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn macos_selects_the_userspace_datapath() {
        let dp = host_datapath();
        assert!(dp.is_available().is_ok());
        assert!(dp.capabilities().userspace_socket_translation);
    }

    /// An operator who lost CAP_NET_ADMIN would otherwise see a plan refused
    /// for `missing: ["icmp"]` with nothing saying the fallback caused it.
    #[test]
    fn the_linux_fallback_explains_itself() {
        let reason =
            fallback_reason(TunProbe::Unavailable).expect("a fallback must state its reason");
        assert!(reason.contains("CAP_NET_ADMIN"), "{reason}");
        assert!(reason.contains("userspace socket translation"), "{reason}");
    }

    #[test]
    fn a_host_on_its_own_datapath_has_nothing_to_explain() {
        assert_eq!(fallback_reason(TunProbe::Available), None);
    }

    #[test]
    fn a_platform_without_a_tunnel_datapath_says_so_without_blaming_privileges_it_could_hold() {
        let reason = fallback_reason(TunProbe::Unsupported).expect("a fallback must state itself");
        assert!(reason.contains("no host tunnel datapath"), "{reason}");
        assert!(reason.contains("userspace socket translation"), "{reason}");
        assert!(
            !reason.contains("CAP_NET_ADMIN"),
            "a platform that has no such capability must not be told to go and get it: {reason}"
        );
    }

    #[test]
    fn the_selected_datapath_is_serveable_and_its_reason_matches_what_it_can_carry() {
        let selection = select_host_datapath();
        selection
            .datapath
            .is_available()
            .expect("selection must not hand back a datapath this host cannot serve");
        // The two have to agree. A fallback with no reason is the silent
        // substitution this task exists to remove; a reason on the
        // packet-level path would name a substitution that never happened.
        assert_eq!(
            selection.fallback_reason.is_some(),
            !selection.datapath.capabilities().full_packet_forwarding,
        );
    }
}
