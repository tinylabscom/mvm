//! Bringing `mvm0` up from the host-assigned configuration.
//!
//! Everything the interface needs — address, point-to-point peer, MTU,
//! default route, resolver — comes from the host's `CONFIG` message. The
//! guest chooses none of it.
//!
//! No in-guest networking utility is used or required. `ip`, `ifconfig`,
//! `ethtool`, NetworkManager, and systemd-networkd are all absent from a
//! minimal, distroless, or scratch image, so configuration goes straight to
//! the kernel.
//!
//! The two address families take different roads there, because the kernel
//! offers no single one. IPv4 goes through `SIOCSIF*` ioctls on an
//! `AF_INET` socket — the same mechanism the existing guest bring-up
//! already uses. IPv6 goes through rtnetlink: its address ioctl needs a
//! second `ifreq` shape, and its route ioctl needs an `in6_rtmsg` whose
//! fields `libc` does not expose, so the ioctl road runs out halfway.
//! rtnetlink carries both halves, and this crate already speaks it for the
//! boot-time blackhole routes.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::tun::TunError;

/// The IPv6 half of an [`InterfacePlan`].
///
/// Additive: a v4-only assignment leaves it `None` and the interface is
/// configured exactly as it was before IPv6 existed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Plan {
    pub address: Ipv6Addr,
    /// Point-to-point peer: the synthetic gateway and default route.
    pub peer: Ipv6Addr,
    pub prefix_len: u8,
    /// Synthetic resolver the guest must use. Unspecified (`::`) is how a
    /// fixed-layout wire message says "no v6 resolver".
    pub dns: Ipv6Addr,
}

/// The interface state the host asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfacePlan {
    pub iface: String,
    pub address: Ipv4Addr,
    /// Point-to-point peer: the synthetic gateway and default route.
    pub peer: Ipv4Addr,
    pub prefix_len: u8,
    pub mtu: u16,
    /// Synthetic resolver the guest must use.
    pub dns: Ipv4Addr,
    /// Present only when the host assigned an IPv6 pair as well.
    pub v6: Option<Ipv6Plan>,
}

impl InterfacePlan {
    /// The netmask implied by `prefix_len`.
    pub fn netmask(&self) -> Ipv4Addr {
        if self.prefix_len == 0 {
            return Ipv4Addr::UNSPECIFIED;
        }
        let bits = u32::MAX << (32 - u32::from(self.prefix_len.min(32)));
        Ipv4Addr::from(bits)
    }

    /// Every resolver the host assigned, in the order the guest should try
    /// them: the v4 one first, then the v6 one when there is one.
    ///
    /// An unspecified v6 resolver is dropped rather than written out — the
    /// wire message has a fixed layout, so `::` is the only way it can say
    /// a v6 assignment carries no resolver, and a `nameserver ::` line
    /// would send every lookup somewhere that cannot answer.
    pub fn resolvers(&self) -> Vec<std::net::IpAddr> {
        let mut out = vec![std::net::IpAddr::V4(self.dns)];
        if let Some(v6) = &self.v6
            && !v6.dns.is_unspecified()
        {
            out.push(std::net::IpAddr::V6(v6.dns));
        }
        out
    }

    /// `resolv.conf` body pointing at the assigned resolvers, and nothing
    /// else — the guest must not retain an inherited nameserver that the
    /// gateway would refuse to reach anyway.
    pub fn resolv_conf(&self) -> Vec<u8> {
        crate::guest_net::render_resolv_conf(&self.resolvers())
    }
}

/// Applies an [`InterfacePlan`] to a real or simulated interface.
///
/// A trait so the agent's configure step is exercised in unprivileged
/// tests: the assertion is that the agent asks for the right thing, which
/// is separable from whether the kernel accepted it.
pub trait InterfaceConfigurator: Send {
    /// Assign addresses, MTU, routes, and bring the link up.
    fn apply(&mut self, plan: &InterfacePlan) -> Result<(), TunError>;

    /// Point the system resolver at the assigned address.
    ///
    /// Returns `false` when the file could not be written — a read-only or
    /// sealed `/etc` is common and is not fatal: the tunnel still carries
    /// traffic, and applications that resolve through the file (rather than
    /// being told the address directly) are the ones affected. The outcome
    /// is reported in `READY` so it is visible rather than silent.
    fn write_resolv_conf(&mut self, plan: &InterfacePlan) -> bool;

    /// Mark the interface down. Called when the transport fails, so a
    /// workload sees an interface with no route instead of a black hole
    /// that looks operational.
    fn set_down(&mut self, iface: &str) -> Result<(), TunError>;
}

/// Records what was asked for, applies nothing. Used by tests and by the
/// dry-run path.
#[derive(Debug, Default)]
pub struct RecordingConfigurator {
    pub applied: Vec<InterfacePlan>,
    pub resolv_written: Vec<InterfacePlan>,
    pub downed: Vec<String>,
    /// Make `apply` fail, to exercise the fail-closed path.
    pub fail_apply: bool,
    /// Make `write_resolv_conf` report failure, as a sealed `/etc` would.
    pub fail_resolv: bool,
}

impl InterfaceConfigurator for RecordingConfigurator {
    fn apply(&mut self, plan: &InterfacePlan) -> Result<(), TunError> {
        if self.fail_apply {
            return Err(TunError::ConfigureFailed {
                what: "address",
                name: plan.iface.clone(),
                source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            });
        }
        self.applied.push(plan.clone());
        Ok(())
    }

    fn write_resolv_conf(&mut self, plan: &InterfacePlan) -> bool {
        if self.fail_resolv {
            return false;
        }
        self.resolv_written.push(plan.clone());
        true
    }

    fn set_down(&mut self, iface: &str) -> Result<(), TunError> {
        self.downed.push(iface.to_string());
        Ok(())
    }
}

/// The rtnetlink requests that bring the IPv6 half of a plan up.
///
/// Pure — the bytes, their order, and the label each failure carries are
/// decided here and nowhere else, so the whole v6 decision surface is
/// asserted without a socket, a privileged host, or a Linux one. All the
/// platform-gated code does is hand these to the kernel in order.
#[cfg(any(target_os = "linux", test))]
pub(crate) mod wire6 {
    use super::Ipv6Plan;
    use crate::netlink::wire::*;
    use std::net::Ipv6Addr;

    /// One request, and the name its failure is reported under.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Ipv6Request {
        pub what: &'static str,
        pub bytes: Vec<u8>,
    }

    /// Bring the v6 half up, in the only order that works: the address
    /// first, then the point-to-point peer as an on-link destination, then
    /// the default route through it.
    ///
    /// The middle request is the v6 analogue of `SIOCSIFDSTADDR` on the v4
    /// side. Without it the default route is accepted only when the peer
    /// happens to fall inside the assigned prefix; with it the peer is
    /// reachable on the device however the host chose to size that prefix.
    pub fn bringup_requests(v6: &Ipv6Plan, ifindex: u32, seqs: [u32; 3]) -> [Ipv6Request; 3] {
        [
            Ipv6Request {
                what: "ipv6 address",
                bytes: encode_newaddr(v6.address, v6.prefix_len, ifindex, seqs[0]),
            },
            Ipv6Request {
                what: "ipv6 peer route",
                bytes: encode_peer_route(v6.peer, ifindex, seqs[1]),
            },
            Ipv6Request {
                what: "ipv6 default route",
                bytes: encode_default_route(v6.peer, ifindex, seqs[2]),
            },
        ]
    }

    /// `RTM_NEWADDR` assigning `address/prefix_len` to the interface.
    ///
    /// Duplicate Address Detection is skipped: the address is host-assigned
    /// on a point-to-point link whose only other end is the gateway, so
    /// there is no neighbour to collide with, and DAD would leave the
    /// address unusable for the second it takes to find that out.
    fn encode_newaddr(address: Ipv6Addr, prefix_len: u8, ifindex: u32, seq: u32) -> Vec<u8> {
        let mut msg = Vec::new();
        push_nlmsghdr(
            &mut msg,
            RTM_NEWADDR,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK,
            seq,
        );
        // struct ifaddrmsg — single-byte fields need no endian handling.
        msg.push(AF_INET6_U8); // ifa_family
        msg.push(prefix_len); // ifa_prefixlen
        msg.push(IFA_F_NODAD); // ifa_flags
        msg.push(RT_SCOPE_UNIVERSE); // ifa_scope
        msg.extend_from_slice(&ifindex.to_ne_bytes()); // ifa_index
        // The v6 address handler prefers IFA_LOCAL over IFA_ADDRESS, and
        // sending only IFA_LOCAL is what asks for an address with no peer
        // attribute — the peer is expressed as a route below instead.
        push_rtattr(&mut msg, IFA_LOCAL, &address.octets());
        finish(&mut msg);
        msg
    }

    /// `RTM_NEWROUTE` making `peer/128` directly reachable on the device.
    fn encode_peer_route(peer: Ipv6Addr, ifindex: u32, seq: u32) -> Vec<u8> {
        let mut msg = Vec::new();
        push_nlmsghdr(
            &mut msg,
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK,
            seq,
        );
        push_rtmsg(&mut msg, 128, RT_SCOPE_LINK);
        push_rtattr(&mut msg, RTA_DST, &peer.octets());
        push_rtattr(&mut msg, RTA_OIF, &ifindex.to_ne_bytes());
        finish(&mut msg);
        msg
    }

    /// `RTM_NEWROUTE` sending everything else through the peer.
    fn encode_default_route(peer: Ipv6Addr, ifindex: u32, seq: u32) -> Vec<u8> {
        let mut msg = Vec::new();
        push_nlmsghdr(
            &mut msg,
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK,
            seq,
        );
        // A zero destination length with no RTA_DST is how ::/0 is spelled.
        push_rtmsg(&mut msg, 0, RT_SCOPE_UNIVERSE);
        push_rtattr(&mut msg, RTA_GATEWAY, &peer.octets());
        // Naming the device explicitly: a gateway the kernel would have to
        // resolve against the whole table is a gateway it can resolve to
        // the wrong device.
        push_rtattr(&mut msg, RTA_OIF, &ifindex.to_ne_bytes());
        finish(&mut msg);
        msg
    }

    /// The `struct rtmsg` both route requests share.
    fn push_rtmsg(msg: &mut Vec<u8>, dst_len: u8, scope: u8) {
        msg.push(AF_INET6_U8); // rtm_family
        msg.push(dst_len); // rtm_dst_len
        msg.push(0); // rtm_src_len
        msg.push(0); // rtm_tos
        msg.push(RT_TABLE_MAIN); // rtm_table
        msg.push(RTPROT_BOOT); // rtm_protocol
        msg.push(scope); // rtm_scope
        msg.push(RTN_UNICAST); // rtm_type
        msg.extend_from_slice(&0u32.to_ne_bytes()); // rtm_flags
    }
}

#[cfg(target_os = "linux")]
pub use linux::KernelConfigurator;

#[cfg(target_os = "linux")]
mod linux {
    use super::wire6;
    use super::{InterfaceConfigurator, InterfacePlan, Ipv6Plan};
    use crate::guest_net::{
        SIOCADDRT_REQUEST, SIOCGIFFLAGS_REQUEST, SIOCSIFADDR_REQUEST, SIOCSIFFLAGS_REQUEST,
        ifreq_for, set_sockaddr_in, target_ioctl_request,
    };
    use crate::l3::tun::TunError;
    use crate::netlink::NetlinkSocket;
    use std::io;

    const SIOCSIFDSTADDR_REQUEST: libc::Ioctl = target_ioctl_request(libc::SIOCSIFDSTADDR);
    const SIOCSIFMTU_REQUEST: libc::Ioctl = target_ioctl_request(libc::SIOCSIFMTU);
    const SIOCSIFNETMASK_REQUEST: libc::Ioctl = target_ioctl_request(libc::SIOCSIFNETMASK);

    /// Configures the interface by talking to the kernel directly.
    #[derive(Debug, Default)]
    pub struct KernelConfigurator;

    impl KernelConfigurator {
        fn with_socket<T>(
            iface: &str,
            what: &'static str,
            body: impl FnOnce(libc::c_int) -> Result<T, io::Error>,
        ) -> Result<T, TunError> {
            // SAFETY: socket(2) returns -1 on error (checked) or an fd we own
            // and close on every path.
            let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            if sock < 0 {
                return Err(TunError::ConfigureFailed {
                    what,
                    name: iface.to_string(),
                    source: io::Error::last_os_error(),
                });
            }
            let result = body(sock);
            // SAFETY: `sock` is the fd we just opened and still own.
            unsafe { libc::close(sock) };
            result.map_err(|source| TunError::ConfigureFailed {
                what,
                name: iface.to_string(),
                source,
            })
        }

        /// Apply the IPv6 half over rtnetlink, after the v4 sequence has
        /// brought the link up: an address on a down interface stays
        /// unusable, and a route through it is refused.
        fn apply_v6(iface: &str, v6: &Ipv6Plan) -> Result<(), TunError> {
            let failed = |what: &'static str, source: io::Error| TunError::ConfigureFailed {
                what,
                name: iface.to_string(),
                source,
            };
            let ifindex =
                Self::if_index(iface).map_err(|source| failed("ipv6 interface index", source))?;
            let sock =
                NetlinkSocket::open().map_err(|source| failed("ipv6 netlink socket", source))?;
            let seqs = [sock.next_seq(), sock.next_seq(), sock.next_seq()];
            for request in wire6::bringup_requests(v6, ifindex, seqs) {
                match sock.send_and_ack(&request.bytes) {
                    Ok(0) => {}
                    // The address and its routes are desired state, not
                    // write-once operations: finding them already there is
                    // the outcome we asked for.
                    Ok(errno) if errno == libc::EEXIST => {}
                    Ok(errno) => {
                        return Err(failed(request.what, io::Error::from_raw_os_error(errno)));
                    }
                    Err(source) => return Err(failed(request.what, source)),
                }
            }
            Ok(())
        }

        fn if_index(iface: &str) -> Result<u32, io::Error> {
            let name = std::ffi::CString::new(iface)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            // SAFETY: `name` is a valid NUL-terminated C string that
            // outlives the call, which is all if_nametoindex reads.
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if index == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(index)
        }
    }

    impl InterfaceConfigurator for KernelConfigurator {
        fn apply(&mut self, plan: &InterfacePlan) -> Result<(), TunError> {
            let iface = plan.iface.as_str();
            let address = plan.address.octets();
            let peer = plan.peer.octets();
            let netmask = plan.netmask().octets();
            let mtu = plan.mtu;

            Self::with_socket(iface, "address", |sock| {
                // SAFETY: each `ifreq` is zero-initialized by `ifreq_for`,
                // fully owned here, and passed to an ioctl that reads it by
                // the layout `linux/if.h` defines.
                unsafe {
                    let mut ifr = ifreq_for(iface);
                    set_sockaddr_in(&mut ifr.ifr_ifru.ifru_addr, address);
                    if libc::ioctl(sock, SIOCSIFADDR_REQUEST, &ifr) < 0 {
                        return Err(io::Error::last_os_error());
                    }

                    // The point-to-point peer. This is what makes the link
                    // routed rather than broadcast: the guest's only on-link
                    // neighbour is the gateway, so no ARP and no broadcast
                    // domain exist to police.
                    let mut ifr = ifreq_for(iface);
                    set_sockaddr_in(&mut ifr.ifr_ifru.ifru_dstaddr, peer);
                    if libc::ioctl(sock, SIOCSIFDSTADDR_REQUEST, &ifr) < 0 {
                        return Err(io::Error::last_os_error());
                    }

                    let mut ifr = ifreq_for(iface);
                    set_sockaddr_in(&mut ifr.ifr_ifru.ifru_netmask, netmask);
                    if libc::ioctl(sock, SIOCSIFNETMASK_REQUEST, &ifr) < 0 {
                        return Err(io::Error::last_os_error());
                    }

                    let mut ifr = ifreq_for(iface);
                    ifr.ifr_ifru.ifru_mtu = libc::c_int::from(mtu);
                    if libc::ioctl(sock, SIOCSIFMTU_REQUEST, &ifr) < 0 {
                        return Err(io::Error::last_os_error());
                    }

                    let mut ifr = ifreq_for(iface);
                    if libc::ioctl(sock, SIOCGIFFLAGS_REQUEST, &mut ifr) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    ifr.ifr_ifru.ifru_flags |=
                        (libc::IFF_UP | libc::IFF_RUNNING | libc::IFF_POINTOPOINT) as libc::c_short;
                    if libc::ioctl(sock, SIOCSIFFLAGS_REQUEST, &ifr) < 0 {
                        return Err(io::Error::last_os_error());
                    }

                    // Default route via the peer.
                    let mut rt: libc::rtentry = std::mem::zeroed();
                    set_sockaddr_in(&mut rt.rt_dst, [0, 0, 0, 0]);
                    set_sockaddr_in(&mut rt.rt_genmask, [0, 0, 0, 0]);
                    set_sockaddr_in(&mut rt.rt_gateway, peer);
                    rt.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as libc::c_ushort;
                    if libc::ioctl(sock, SIOCADDRT_REQUEST, &rt) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                }
            })?;

            match &plan.v6 {
                Some(v6) => Self::apply_v6(iface, v6),
                None => Ok(()),
            }
        }

        fn write_resolv_conf(&mut self, plan: &InterfacePlan) -> bool {
            crate::guest_net::seed_resolv_conf_bytes(&plan.resolv_conf()).is_ok()
        }

        fn set_down(&mut self, iface: &str) -> Result<(), TunError> {
            Self::with_socket(iface, "link down", |sock| {
                // SAFETY: as above — a zeroed, owned `ifreq` handed to the
                // flags ioctls.
                unsafe {
                    let mut ifr = ifreq_for(iface);
                    if libc::ioctl(sock, SIOCGIFFLAGS_REQUEST, &mut ifr) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    ifr.ifr_ifru.ifru_flags &=
                        !((libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short);
                    if libc::ioctl(sock, SIOCSIFFLAGS_REQUEST, &ifr) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::wire6;
    use crate::netlink::wire::*;

    fn plan() -> InterfacePlan {
        InterfacePlan {
            iface: "mvm0".into(),
            address: Ipv4Addr::new(10, 201, 0, 6),
            peer: Ipv4Addr::new(10, 201, 0, 5),
            prefix_len: 30,
            mtu: 1500,
            dns: Ipv4Addr::new(10, 201, 0, 5),
            v6: None,
        }
    }

    fn v6_plan() -> Ipv6Plan {
        Ipv6Plan {
            address: "2001:db8::6".parse().unwrap(),
            peer: "2001:db8::5".parse().unwrap(),
            prefix_len: 126,
            dns: "2001:db8::5".parse().unwrap(),
        }
    }

    fn dual_stack_plan() -> InterfacePlan {
        InterfacePlan {
            v6: Some(v6_plan()),
            ..plan()
        }
    }

    #[test]
    fn a_slash_30_prefix_becomes_the_right_netmask() {
        assert_eq!(plan().netmask(), Ipv4Addr::new(255, 255, 255, 252));
    }

    #[test]
    fn prefix_lengths_map_to_masks_across_the_range() {
        for (prefix, expected) in [
            (0u8, Ipv4Addr::UNSPECIFIED),
            (8, Ipv4Addr::new(255, 0, 0, 0)),
            (16, Ipv4Addr::new(255, 255, 0, 0)),
            (24, Ipv4Addr::new(255, 255, 255, 0)),
            (32, Ipv4Addr::new(255, 255, 255, 255)),
        ] {
            let p = InterfacePlan {
                prefix_len: prefix,
                ..plan()
            };
            assert_eq!(p.netmask(), expected, "prefix /{prefix}");
        }
    }

    #[test]
    fn resolv_conf_names_only_the_assigned_resolver() {
        let body = String::from_utf8(plan().resolv_conf()).unwrap();
        assert!(body.contains("nameserver 10.201.0.5"), "{body}");
        assert_eq!(
            body.lines().filter(|l| l.starts_with("nameserver")).count(),
            1,
            "an inherited nameserver would be unreachable and misleading: {body}"
        );
    }

    #[test]
    fn the_recording_configurator_captures_what_was_asked_for() {
        let mut cfg = RecordingConfigurator::default();
        let p = plan();
        cfg.apply(&p).unwrap();
        assert!(cfg.write_resolv_conf(&p));
        cfg.set_down("mvm0").unwrap();
        assert_eq!(cfg.applied, vec![p.clone()]);
        assert_eq!(cfg.resolv_written, vec![p]);
        assert_eq!(cfg.downed, vec!["mvm0".to_string()]);
    }

    #[test]
    fn a_sealed_etc_reports_resolver_failure_without_erroring() {
        let mut cfg = RecordingConfigurator {
            fail_resolv: true,
            ..Default::default()
        };
        assert!(!cfg.write_resolv_conf(&plan()));
        assert!(cfg.resolv_written.is_empty());
    }

    #[test]
    fn a_failed_apply_surfaces_as_a_named_configure_error() {
        let mut cfg = RecordingConfigurator {
            fail_apply: true,
            ..Default::default()
        };
        let err = cfg.apply(&plan()).unwrap_err();
        assert!(matches!(err, TunError::ConfigureFailed { name, .. } if name == "mvm0"));
    }

    // ────────────────────────────────────────────────────────────
    // The IPv6 half
    // ────────────────────────────────────────────────────────────

    #[test]
    fn resolv_conf_names_both_resolvers_when_both_were_assigned() {
        let body = String::from_utf8(dual_stack_plan().resolv_conf()).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(
            lines,
            vec!["nameserver 10.201.0.5", "nameserver 2001:db8::5"],
            "a dual-stack guest resolves through both assigned resolvers, v4 first"
        );
    }

    #[test]
    fn an_unspecified_v6_resolver_is_dropped_rather_than_written_out() {
        // The wire message has a fixed layout, so `::` is the only way it
        // can say a v6 assignment carries no resolver. Writing it out would
        // point every lookup at an address that cannot answer.
        let p = InterfacePlan {
            v6: Some(Ipv6Plan {
                dns: Ipv6Addr::UNSPECIFIED,
                ..v6_plan()
            }),
            ..plan()
        };
        assert_eq!(p.resolvers(), vec![std::net::IpAddr::V4(p.dns)]);
        let body = String::from_utf8(p.resolv_conf()).unwrap();
        assert!(!body.contains("::"), "{body}");
    }

    #[test]
    fn a_v4_only_plan_resolves_exactly_as_it_did_before() {
        assert_eq!(
            plan().resolvers(),
            vec![std::net::IpAddr::V4(Ipv4Addr::new(10, 201, 0, 5))]
        );
    }

    #[test]
    fn the_recording_configurator_captures_the_v6_half_too() {
        // A double that dropped the v6 assignment would make every test
        // above it vacuous: the agent could stop asking for v6 entirely and
        // nothing would notice.
        let mut cfg = RecordingConfigurator::default();
        let p = dual_stack_plan();
        cfg.apply(&p).unwrap();
        assert_eq!(cfg.applied[0].v6, Some(v6_plan()));
    }

    #[test]
    fn v6_bringup_asks_for_the_address_then_the_peer_then_the_default() {
        let reqs = wire6::bringup_requests(&v6_plan(), 7, [1, 2, 3]);
        assert_eq!(
            reqs.iter().map(|r| r.what).collect::<Vec<_>>(),
            vec!["ipv6 address", "ipv6 peer route", "ipv6 default route"],
            "an address must exist before a route can point through it"
        );
        for (i, req) in reqs.iter().enumerate() {
            assert_eq!(
                u32::from_ne_bytes(req.bytes[0..4].try_into().unwrap()),
                req.bytes.len() as u32,
                "{}: nlmsg_len must equal the message length",
                req.what
            );
            assert_eq!(
                u32::from_ne_bytes(req.bytes[8..12].try_into().unwrap()),
                (i + 1) as u32,
                "{}: each request carries its own sequence number",
                req.what
            );
            assert_eq!(
                u16::from_ne_bytes(req.bytes[6..8].try_into().unwrap()),
                NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK,
                "{}: every request asks for an ACK, so a refusal is seen",
                req.what
            );
        }
    }

    #[test]
    fn the_address_request_assigns_exactly_what_the_host_chose() {
        let v6 = v6_plan();
        let msg = &wire6::bringup_requests(&v6, 7, [1, 2, 3])[0].bytes;

        assert_eq!(
            msg.len(),
            44,
            "nlmsghdr(16)+ifaddrmsg(8)+rtattr(4)+addr(16)"
        );
        assert_eq!(
            u16::from_ne_bytes(msg[4..6].try_into().unwrap()),
            RTM_NEWADDR
        );

        // struct ifaddrmsg
        assert_eq!(msg[16], AF_INET6_U8, "ifa_family");
        assert_eq!(msg[17], 126, "ifa_prefixlen is the host's, not a default");
        assert_eq!(
            msg[18], IFA_F_NODAD,
            "DAD on a point-to-point link has no neighbour to find, and delays the address"
        );
        assert_eq!(msg[19], RT_SCOPE_UNIVERSE, "ifa_scope");
        assert_eq!(
            u32::from_ne_bytes(msg[20..24].try_into().unwrap()),
            7,
            "ifa_index"
        );

        // rtattr IFA_LOCAL
        assert_eq!(u16::from_ne_bytes(msg[24..26].try_into().unwrap()), 20);
        assert_eq!(
            u16::from_ne_bytes(msg[26..28].try_into().unwrap()),
            IFA_LOCAL
        );
        assert_eq!(
            &msg[28..44],
            &v6.address.octets(),
            "the assigned address, in network byte order"
        );
    }

    #[test]
    fn the_peer_route_puts_the_gateway_on_link_whatever_the_prefix() {
        // The v6 analogue of SIOCSIFDSTADDR. A host that assigns a /128
        // leaves the peer outside the prefix, and without this request the
        // default route through it is refused.
        let v6 = Ipv6Plan {
            prefix_len: 128,
            ..v6_plan()
        };
        let msg = &wire6::bringup_requests(&v6, 7, [1, 2, 3])[1].bytes;

        assert_eq!(msg.len(), 56, "nlmsghdr(16)+rtmsg(12)+dst(20)+oif(8)");
        assert_eq!(
            u16::from_ne_bytes(msg[4..6].try_into().unwrap()),
            RTM_NEWROUTE
        );
        assert_eq!(msg[16], AF_INET6_U8, "rtm_family");
        assert_eq!(msg[17], 128, "rtm_dst_len — the peer, exactly");
        assert_eq!(msg[20], RT_TABLE_MAIN, "rtm_table");
        assert_eq!(msg[21], RTPROT_BOOT, "rtm_protocol");
        assert_eq!(
            msg[22], RT_SCOPE_LINK,
            "on-link is what makes the peer reachable with no gateway of its own"
        );
        assert_eq!(msg[23], RTN_UNICAST, "rtm_type");

        assert_eq!(u16::from_ne_bytes(msg[30..32].try_into().unwrap()), RTA_DST);
        assert_eq!(
            &msg[32..48],
            &v6.peer.octets(),
            "the peer is the destination"
        );
        assert_eq!(u16::from_ne_bytes(msg[50..52].try_into().unwrap()), RTA_OIF);
        assert_eq!(u32::from_ne_bytes(msg[52..56].try_into().unwrap()), 7);
    }

    #[test]
    fn the_default_route_sends_everything_else_through_the_peer() {
        let v6 = v6_plan();
        let msg = &wire6::bringup_requests(&v6, 7, [1, 2, 3])[2].bytes;

        assert_eq!(msg.len(), 56, "nlmsghdr(16)+rtmsg(12)+gateway(20)+oif(8)");
        assert_eq!(msg[16], AF_INET6_U8, "rtm_family");
        assert_eq!(
            msg[17], 0,
            "a zero destination length with no RTA_DST is how ::/0 is spelled"
        );
        assert_eq!(msg[22], RT_SCOPE_UNIVERSE, "rtm_scope");
        assert_eq!(msg[23], RTN_UNICAST, "rtm_type");
        assert_eq!(
            u16::from_ne_bytes(msg[30..32].try_into().unwrap()),
            RTA_GATEWAY,
            "the peer is the next hop, not the destination"
        );
        assert_eq!(&msg[32..48], &v6.peer.octets());
        assert_eq!(u16::from_ne_bytes(msg[50..52].try_into().unwrap()), RTA_OIF);
        assert_eq!(
            u32::from_ne_bytes(msg[52..56].try_into().unwrap()),
            7,
            "naming the device keeps the kernel from resolving the gateway elsewhere"
        );
    }

    #[test]
    fn every_v6_request_names_the_v6_family_and_the_assigned_device() {
        // A transposed family or a zero ifindex surfaces as an opaque
        // EINVAL on a host no unit test can boot, so pin both here.
        let reqs = wire6::bringup_requests(&v6_plan(), 3, [9, 10, 11]);
        for req in &reqs {
            assert_eq!(req.bytes[16], AF_INET6_U8, "{}: family", req.what);
            assert!(
                req.bytes.windows(4).any(|w| w == 3u32.to_ne_bytes()),
                "{}: no request may be applied to a device it did not name",
                req.what
            );
        }
    }

    #[test]
    fn the_routes_point_at_the_peer_and_never_at_the_interface_address() {
        // Swapping the two is the mistake that produces a route to
        // yourself: it installs cleanly and black-holes every packet.
        let v6 = v6_plan();
        let reqs = wire6::bringup_requests(&v6, 7, [1, 2, 3]);
        for req in reqs.iter().skip(1) {
            assert!(
                req.bytes.windows(16).any(|w| w == v6.peer.octets()),
                "{}: must carry the peer",
                req.what
            );
            assert!(
                !req.bytes.windows(16).any(|w| w == v6.address.octets()),
                "{}: a route through our own address is a route to nowhere",
                req.what
            );
        }
    }
}
