//! Synchronous rtnetlink: the kernel ABI constants, the request framing,
//! and the socket that carries one request and reads its ACK.
//!
//! Two callers in this crate talk to the routing kernel — the boot-time
//! blackhole installer and the L3 agent's IPv6 bring-up. Both need the same
//! 16-byte `nlmsghdr`, the same attribute framing, and the same
//! send-then-wait exchange. One copy, so the two cannot drift apart against
//! an ABI that never moves.
//!
//! Constants are transcribed from `<linux/netlink.h>`,
//! `<linux/rtnetlink.h>`, and `<linux/if_addr.h>` rather than pulled from a
//! netlink crate: the guest closure would carry the dependency to build a
//! few dozen bytes a handful of times per boot. `constants_match_libc`
//! pins every one libc exposes, so a transcription typo fails on CI rather
//! than as an opaque `EINVAL` on a host no test can boot.
//!
//! The framing lives off the `cfg(linux)` socket code so its byte layout is
//! unit-tested on any host, and the module is gated `linux`-or-`test` so a
//! macOS production build does not carry it as dead code.

#[cfg(any(target_os = "linux", test))]
pub mod wire {
    /// `NLM_F_REQUEST` — this message is a request.
    pub const NLM_F_REQUEST: u16 = 0x01;
    /// `NLM_F_ACK` — ask the kernel for an explicit reply (an `nlmsgerr`
    /// with `error == 0`), so a caller can confirm the change landed
    /// instead of firing and forgetting.
    pub const NLM_F_ACK: u16 = 0x04;
    /// `NLM_F_CREATE` — create the object if it does not exist.
    pub const NLM_F_CREATE: u16 = 0x400;

    /// `RTM_NEWADDR` — assign an address to an interface.
    pub const RTM_NEWADDR: u16 = 20;
    /// `RTM_NEWROUTE` — create or modify a routing table entry.
    pub const RTM_NEWROUTE: u16 = 24;

    /// `AF_INET` — `rtm_family` / `ifa_family` for IPv4.
    pub const AF_INET_U8: u8 = 2;
    /// `AF_INET6` — `rtm_family` / `ifa_family` for IPv6.
    pub const AF_INET6_U8: u8 = 10;

    /// `RT_TABLE_MAIN` — the main routing table.
    pub const RT_TABLE_MAIN: u8 = 254;
    /// `RTPROT_BOOT` — installed by the boot process rather than a daemon.
    pub const RTPROT_BOOT: u8 = 3;
    /// `RT_SCOPE_UNIVERSE` — global scope: the destination is not confined
    /// to this link.
    pub const RT_SCOPE_UNIVERSE: u8 = 0;
    /// `RT_SCOPE_LINK` — the destination is directly reachable on the
    /// device, with no gateway in between.
    pub const RT_SCOPE_LINK: u8 = 253;

    /// `RTN_UNICAST` — an ordinary forwarding entry.
    pub const RTN_UNICAST: u8 = 1;
    /// `RTN_BLACKHOLE` — drop matching packets, no ICMP unreachable.
    pub const RTN_BLACKHOLE: u8 = 6;

    /// `RTA_DST` — the route's destination prefix.
    pub const RTA_DST: u16 = 1;
    /// `RTA_OIF` — the outgoing interface index.
    pub const RTA_OIF: u16 = 4;
    /// `RTA_GATEWAY` — the next hop.
    pub const RTA_GATEWAY: u16 = 5;

    /// `IFA_LOCAL` — the local address being assigned. The v6 address
    /// handler takes this in preference to `IFA_ADDRESS`.
    pub const IFA_LOCAL: u16 = 2;
    /// `IFA_F_NODAD` — skip Duplicate Address Detection.
    pub const IFA_F_NODAD: u8 = 0x02;

    /// Wire size of `struct nlmsghdr`.
    pub const NLMSGHDR_LEN: usize = 16;

    /// Start a request: a 16-byte `nlmsghdr` whose length is a placeholder
    /// until [`finish`] stamps it.
    ///
    /// Header fields are native-endian; that is the netlink ABI, not an
    /// oversight.
    pub fn push_nlmsghdr(msg: &mut Vec<u8>, msg_type: u16, flags: u16, seq: u32) {
        msg.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len — patched by finish()
        msg.extend_from_slice(&msg_type.to_ne_bytes());
        msg.extend_from_slice(&flags.to_ne_bytes());
        msg.extend_from_slice(&seq.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid — 0: the kernel fills it
    }

    /// Append one `struct rtattr` and its payload, padded to the 4-byte
    /// alignment the kernel's attribute walker assumes. `rta_len` counts
    /// the header and the payload but not the padding, which is what
    /// `RTA_LENGTH` means.
    pub fn push_rtattr(msg: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
        let rta_len = 4 + payload.len();
        msg.extend_from_slice(&(rta_len as u16).to_ne_bytes());
        msg.extend_from_slice(&attr_type.to_ne_bytes());
        msg.extend_from_slice(payload);
        msg.resize(msg.len() + rta_len.next_multiple_of(4) - rta_len, 0);
    }

    /// Stamp `nlmsg_len` now that the body is complete. A request whose
    /// declared length disagrees with its actual one is discarded by the
    /// kernel without an error a caller could read.
    pub fn finish(msg: &mut [u8]) {
        let len = msg.len() as u32;
        msg[0..4].copy_from_slice(&len.to_ne_bytes());
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::mem::zeroed;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// `NLMSG_ERROR` — the kernel's ACK/error reply type. Carries an `i32`
    /// error immediately after its `nlmsghdr`: `0` = success ACK, `-errno`
    /// = failure.
    const NLMSG_ERROR: u16 = 2;

    /// A bound `NETLINK_ROUTE` socket, used synchronously: one request out,
    /// one ACK back, no runtime.
    ///
    /// Requires `CAP_NET_ADMIN` in the current user namespace. Both callers
    /// run before the agent drops privileges.
    ///
    /// Owns the fd for its lifetime (`OwnedFd` closes it on drop). `seq`
    /// numbers requests so each ACK can be matched to its send on a socket
    /// this type owns exclusively.
    pub struct NetlinkSocket {
        fd: OwnedFd,
        seq: AtomicU32,
    }

    impl NetlinkSocket {
        /// Open and bind a `NETLINK_ROUTE` socket.
        ///
        /// Fallible: the open fails on a kernel built without netlink —
        /// rare, but possible on a stripped-down embedded kernel — which a
        /// caller may want to distinguish from a per-request failure.
        pub fn open() -> Result<Self, io::Error> {
            // SAFETY: socket() with constant args; the return is checked.
            let raw =
                unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: raw is a fresh, owned, valid fd (checked >= 0).
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };

            // Bind with nl_pid = 0 so the kernel assigns a unique port id;
            // nl_groups = 0 because these are unicast requests wanting no
            // multicast. zeroed() gives nl_pad = 0 as required.
            // SAFETY: sockaddr_nl is a plain-data struct of integer fields, so
            // an all-zero bit pattern is a valid, fully-initialized value.
            let mut addr: libc::sockaddr_nl = unsafe { zeroed() };
            addr.nl_family = libc::AF_NETLINK as u16;
            // SAFETY: addr is a valid sockaddr_nl for the bind's len.
            let rc = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                    size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                fd,
                seq: AtomicU32::new(0),
            })
        }

        /// The next request sequence number. Starts at 1: 0 reads as "no
        /// sequence" in most netlink tooling.
        pub fn next_seq(&self) -> u32 {
            self.seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
        }

        /// Send one encoded request to the kernel (nl_pid = 0) and wait for
        /// its ACK. Returns the kernel's verdict as a positive errno, `0`
        /// for success.
        pub fn send_and_ack(&self, msg: &[u8]) -> Result<i32, io::Error> {
            let fd = self.fd.as_raw_fd();
            // SAFETY: sockaddr_nl is a plain-data struct of integer fields, so
            // an all-zero bit pattern is a valid, fully-initialized value.
            let mut dst: libc::sockaddr_nl = unsafe { zeroed() };
            dst.nl_family = libc::AF_NETLINK as u16; // nl_pid = 0 → the kernel
            // SAFETY: msg is a valid slice; dst is a valid sockaddr_nl.
            let sent = unsafe {
                libc::sendto(
                    fd,
                    msg.as_ptr() as *const libc::c_void,
                    msg.len(),
                    0,
                    &dst as *const libc::sockaddr_nl as *const libc::sockaddr,
                    size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if sent < 0 {
                return Err(io::Error::last_os_error());
            }

            // The ACK is a single NLMSG_ERROR: nlmsghdr(16) + i32 error +
            // the echoed request header. 1 KiB is ample.
            let mut buf = [0u8; 1024];
            // SAFETY: buf is a valid, sized destination.
            let r = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if r < 0 {
                return Err(io::Error::last_os_error());
            }
            let r = r as usize;
            // Need at least nlmsghdr(16) + error(4) to read the verdict.
            if r < 20 {
                return Err(io::Error::other(format!("short netlink ACK: {r} bytes")));
            }
            let nlmsg_type = u16::from_ne_bytes([buf[4], buf[5]]);
            if nlmsg_type != NLMSG_ERROR {
                return Err(io::Error::other(format!(
                    "unexpected netlink reply type {nlmsg_type}"
                )));
            }
            // nlmsgerr.error sits right after the 16-byte nlmsghdr.
            let err = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
            Ok(-err) // kernel reports -errno; flip to a positive errno (0 = ACK)
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::NetlinkSocket;

#[cfg(test)]
mod tests {
    use super::wire::*;

    #[test]
    fn a_finished_header_declares_the_whole_message() {
        let mut msg = Vec::new();
        push_nlmsghdr(&mut msg, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK, 3);
        push_rtattr(&mut msg, RTA_OIF, &7u32.to_ne_bytes());
        finish(&mut msg);

        assert_eq!(msg.len(), NLMSGHDR_LEN + 8);
        assert_eq!(
            u32::from_ne_bytes(msg[0..4].try_into().unwrap()),
            msg.len() as u32,
            "a request whose declared length disagrees with its body is dropped silently"
        );
        assert_eq!(
            u16::from_ne_bytes(msg[4..6].try_into().unwrap()),
            RTM_NEWROUTE
        );
        assert_eq!(
            u16::from_ne_bytes(msg[6..8].try_into().unwrap()),
            NLM_F_REQUEST | NLM_F_ACK
        );
        assert_eq!(u32::from_ne_bytes(msg[8..12].try_into().unwrap()), 3, "seq");
        assert_eq!(
            u32::from_ne_bytes(msg[12..16].try_into().unwrap()),
            0,
            "nlmsg_pid is left for the kernel to fill"
        );
    }

    #[test]
    fn an_attribute_declares_its_unpadded_length_and_pads_after_it() {
        // A 1-byte payload is the case that distinguishes RTA_LENGTH from
        // RTA_SPACE: rta_len counts 5, the buffer advances 8.
        let mut msg = Vec::new();
        push_rtattr(&mut msg, RTA_DST, &[0xAB]);
        assert_eq!(u16::from_ne_bytes(msg[0..2].try_into().unwrap()), 5);
        assert_eq!(u16::from_ne_bytes(msg[2..4].try_into().unwrap()), RTA_DST);
        assert_eq!(msg[4], 0xAB);
        assert_eq!(msg.len(), 8, "the walker assumes 4-byte alignment");
        assert_eq!(&msg[5..], &[0, 0, 0], "padding is zeroed, not left stale");
    }

    #[test]
    fn an_aligned_attribute_gets_no_padding() {
        let mut msg = Vec::new();
        push_rtattr(&mut msg, RTA_GATEWAY, &[0u8; 16]);
        assert_eq!(msg.len(), 20);
        assert_eq!(u16::from_ne_bytes(msg[0..2].try_into().unwrap()), 20);
    }

    /// The constants are transcribed rather than pulled from a netlink
    /// crate, so this Linux-only test pins each to libc's value. A typo
    /// would otherwise reach the kernel as an opaque EINVAL.
    #[cfg(target_os = "linux")]
    #[test]
    fn constants_match_libc() {
        assert_eq!(NLM_F_REQUEST, libc::NLM_F_REQUEST as u16);
        assert_eq!(NLM_F_ACK, libc::NLM_F_ACK as u16);
        assert_eq!(NLM_F_CREATE, libc::NLM_F_CREATE as u16);
        assert_eq!(RTM_NEWADDR, libc::RTM_NEWADDR);
        assert_eq!(RTM_NEWROUTE, libc::RTM_NEWROUTE);
        assert_eq!(AF_INET_U8, libc::AF_INET as u8);
        assert_eq!(AF_INET6_U8, libc::AF_INET6 as u8);
        assert_eq!(RT_TABLE_MAIN, libc::RT_TABLE_MAIN);
        assert_eq!(RTPROT_BOOT, libc::RTPROT_BOOT);
        assert_eq!(RT_SCOPE_UNIVERSE, libc::RT_SCOPE_UNIVERSE);
        assert_eq!(RT_SCOPE_LINK, libc::RT_SCOPE_LINK);
        assert_eq!(RTN_UNICAST, libc::RTN_UNICAST);
        assert_eq!(RTN_BLACKHOLE, libc::RTN_BLACKHOLE);
        assert_eq!(RTA_DST, libc::RTA_DST);
        assert_eq!(RTA_OIF, libc::RTA_OIF);
        assert_eq!(RTA_GATEWAY, libc::RTA_GATEWAY);
        assert_eq!(IFA_LOCAL, libc::IFA_LOCAL);
        assert_eq!(NLMSGHDR_LEN, size_of::<libc::nlmsghdr>());
        // `rtmsg` and `ifaddrmsg` have no libc bindings to check against;
        // the encoders that lay them out assert their own total length.
    }
}
