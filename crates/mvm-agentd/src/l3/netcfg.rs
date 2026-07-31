//! Bringing `mvm0` up from the host-assigned configuration.
//!
//! Everything the interface needs — address, point-to-point peer, MTU,
//! default route, resolver — comes from the host's `CONFIG` message. The
//! guest chooses none of it.
//!
//! No in-guest networking utility is used or required. `ip`, `ifconfig`,
//! `ethtool`, NetworkManager, and systemd-networkd are all absent from a
//! minimal, distroless, or scratch image, so configuration goes straight to
//! the kernel through `SIOCSIF*` ioctls on an `AF_INET` socket — the same
//! mechanism the existing guest bring-up already uses.

use std::net::Ipv4Addr;

use super::tun::TunError;

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

    /// `resolv.conf` body pointing at the assigned resolver, and nothing
    /// else — the guest must not retain an inherited nameserver that the
    /// gateway would refuse to reach anyway.
    pub fn resolv_conf(&self) -> Vec<u8> {
        crate::guest_net::render_resolv_conf(&[std::net::IpAddr::V4(self.dns)])
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

#[cfg(target_os = "linux")]
pub use linux::KernelConfigurator;

#[cfg(target_os = "linux")]
mod linux {
    use super::{InterfaceConfigurator, InterfacePlan};
    use crate::guest_net::{
        SIOCADDRT_REQUEST, SIOCGIFFLAGS_REQUEST, SIOCSIFADDR_REQUEST, SIOCSIFFLAGS_REQUEST,
        ifreq_for, set_sockaddr_in, target_ioctl_request,
    };
    use crate::l3::tun::TunError;
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
            })
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

    fn plan() -> InterfacePlan {
        InterfacePlan {
            iface: "mvm0".into(),
            address: Ipv4Addr::new(10, 201, 0, 6),
            peer: Ipv4Addr::new(10, 201, 0, 5),
            prefix_len: 30,
            mtu: 1500,
            dns: Ipv4Addr::new(10, 201, 0, 5),
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
}
