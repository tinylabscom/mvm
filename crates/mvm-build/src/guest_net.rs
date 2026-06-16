//! Shared in-guest network configuration helpers.
//!
//! Factored out of `stage0-init` so both builder init binaries
//! (`stage0-init` and `mvm-host-vm-init`) share one implementation of
//! the static-IP ioctl sequence instead of two diverging copies.
//!
//! The ioctl bodies are gated `#[cfg(target_os = "linux")]`; the pure
//! address-parsing helpers compile and are unit-tested on every host.

/// Parse a dotted-decimal IPv4 string into a 4-byte array.
///
/// Returns `None` if the string is not exactly four decimal octets
/// separated by dots, or if any octet exceeds 255.
pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut parts = s.splitn(5, '.');
    let a = parts.next()?.parse::<u8>().ok()?;
    let b = parts.next()?.parse::<u8>().ok()?;
    let c = parts.next()?.parse::<u8>().ok()?;
    let d = parts.next()?.parse::<u8>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some([a, b, c, d])
}

/// Encode an interface name into a NUL-padded `[c_char; IFNAMSIZ]` buffer.
///
/// Returns `Err` if the name is too long for Linux's `IFNAMSIZ` limit
/// (15 bytes of name + 1 NUL terminator = 16 bytes total).
pub fn encode_iface_name(iface: &str) -> Result<[libc::c_char; libc::IFNAMSIZ], String> {
    let bytes = iface.as_bytes();
    if bytes.len() >= libc::IFNAMSIZ {
        return Err(format!(
            "interface name '{iface}' is {} bytes; Linux IFNAMSIZ caps it at {}",
            bytes.len(),
            libc::IFNAMSIZ - 1,
        ));
    }
    let mut buf = [0 as libc::c_char; libc::IFNAMSIZ];
    for (i, &b) in bytes.iter().enumerate() {
        buf[i] = b as libc::c_char;
    }
    Ok(buf)
}

/// Statically configure a guest NIC: assign `addr/netmask` and install a
/// default route via `gateway`.
///
/// Applies the standard `SIOCSIFADDR` / `SIOCSIFNETMASK` / `SIOCSIFFLAGS`
/// (UP|RUNNING) / `SIOCADDRT` ioctl sequence on an `AF_INET/SOCK_DGRAM`
/// socket. The gvproxy virtual subnet is fixed (`192.168.127.0/24`, gateway
/// `.1`, first DHCP client `.3`), and each builder VM gets its own gvproxy
/// instance, so a static address cannot collide across VMs.
#[cfg(target_os = "linux")]
pub fn configure_static(
    iface: &str,
    addr: &str,
    netmask: &str,
    gateway: &str,
) -> Result<(), String> {
    let addr_b = parse_ipv4(addr).ok_or_else(|| format!("bad addr: {addr}"))?;
    let mask_b = parse_ipv4(netmask).ok_or_else(|| format!("bad netmask: {netmask}"))?;
    let gw_b = parse_ipv4(gateway).ok_or_else(|| format!("bad gateway: {gateway}"))?;

    // SAFETY: socket(2) returns -1 on error (checked below) or a valid fd.
    // We close it on every return path.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(format!(
            "socket(AF_INET, SOCK_DGRAM) for {iface}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let res = apply_ioctls(sock, iface, addr_b, mask_b, gw_b);
    // SAFETY: sock is valid, we own it.
    unsafe { libc::close(sock) };
    res
}

/// Run the SIOCSIF* / SIOCADDRT sequence on an already-opened socket.
///
/// Separated so the socket lifetime is clear and the helper stays testable
/// in isolation (the caller owns open + close).
#[cfg(target_os = "linux")]
fn apply_ioctls(
    sock: libc::c_int,
    iface: &str,
    addr: [u8; 4],
    netmask: [u8; 4],
    gateway: [u8; 4],
) -> Result<(), String> {
    unsafe {
        // address
        let mut ifr = ifreq_for(iface);
        set_sockaddr_in(&mut ifr.ifr_ifru.ifru_addr, addr);
        if libc::ioctl(sock, libc::SIOCSIFADDR as _, &ifr) < 0 {
            return Err(format!(
                "SIOCSIFADDR {iface}: {}",
                std::io::Error::last_os_error()
            ));
        }
        // netmask
        let mut ifr = ifreq_for(iface);
        set_sockaddr_in(&mut ifr.ifr_ifru.ifru_netmask, netmask);
        if libc::ioctl(sock, libc::SIOCSIFNETMASK as _, &ifr) < 0 {
            return Err(format!(
                "SIOCSIFNETMASK {iface}: {}",
                std::io::Error::last_os_error()
            ));
        }
        // flags: read current then OR in UP|RUNNING
        let mut ifr = ifreq_for(iface);
        if libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) < 0 {
            return Err(format!(
                "SIOCGIFFLAGS {iface}: {}",
                std::io::Error::last_os_error()
            ));
        }
        ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        if libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) < 0 {
            return Err(format!(
                "SIOCSIFFLAGS {iface}: {}",
                std::io::Error::last_os_error()
            ));
        }
        // default route
        let mut rt: libc::rtentry = std::mem::zeroed();
        set_sockaddr_in(&mut rt.rt_dst, [0, 0, 0, 0]);
        set_sockaddr_in(&mut rt.rt_genmask, [0, 0, 0, 0]);
        set_sockaddr_in(&mut rt.rt_gateway, gateway);
        rt.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as libc::c_ushort;
        if libc::ioctl(sock, libc::SIOCADDRT as _, &rt) < 0 {
            return Err(format!("SIOCADDRT: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

/// Build an `ifreq` with the interface name pre-filled and all other fields
/// zeroed. Truncates at `IFNAMSIZ - 1` bytes (the kernel enforces the same
/// limit; `encode_iface_name` validates it before this function is called).
#[cfg(target_os = "linux")]
fn ifreq_for(iface: &str) -> libc::ifreq {
    // SAFETY: ifreq is a plain C struct; zeroed is a valid empty request.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in iface.bytes().enumerate().take(libc::IFNAMSIZ - 1) {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    ifr
}

/// Write an IPv4 `sockaddr_in` into a `sockaddr`-typed ioctl field in-place.
#[cfg(target_os = "linux")]
fn set_sockaddr_in(dst: *mut libc::sockaddr, addr: [u8; 4]) {
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: `dst` points at a `sockaddr`-sized field inside an `ifreq` or
    // `rtentry` that the caller zeroed and owns. `sockaddr_in` is the same
    // 16 bytes on all Linux ABI targets.
    unsafe {
        std::ptr::copy_nonoverlapping(
            &sin as *const libc::sockaddr_in as *const u8,
            dst as *mut u8,
            std::mem::size_of::<libc::sockaddr_in>(),
        );
    }
}

/// The persistent builder VM's last network-bootstrap outcome, as
/// recovered from its host-readable `console.log`.
///
/// The builder guest's init brings `eth0` up, runs busybox `udhcpc`, and
/// on a failed lease falls back to the fixed gvproxy static address. Each
/// path emits a distinct console line; this enum is the classification of
/// the *last* such line (a VM can reboot, so later lines win).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderNetBootstrap {
    /// busybox udhcpc obtained a DHCP lease for `ip`.
    Lease { ip: String },
    /// udhcpc failed and init applied the fixed gvproxy static address.
    /// Degraded but reachable.
    StaticFallback { ip: String },
    /// udhcpc failed and no static fallback was applied — the builder VM
    /// has no IP and inner builds can't fetch.
    Failed,
    /// No recognizable outcome in the log yet.
    Unknown,
}

/// The fixed gvproxy static address init falls back to when DHCP fails.
/// gvproxy's virtual subnet is `192.168.127.0/24` (gateway+DNS at `.1`,
/// first DHCP client at `.3`); each builder VM gets its own gvproxy
/// instance, so this address can't collide across VMs.
const GVPROXY_STATIC_FALLBACK_IP: &str = "192.168.127.3";

/// Classify a persistent builder VM's network-bootstrap outcome from its
/// `console.log` contents.
///
/// Scans every line and returns the *last* recognizable outcome, so a VM
/// that rebooted reports its most recent boot rather than a stale one.
/// Robust to interleaved log noise: only the three known markers are
/// matched, anything else is ignored.
///
/// Markers (in `setup_network`'s emission order on a single boot):
/// - DHCP lease: busybox prints `udhcpc: lease of <ip> obtained from ...`.
/// - Static fallback: init prints `... falling back to static gvproxy
///   addressing` after a non-zero udhcpc exit.
/// - Failure: init prints `setup_network warning (non-fatal): ...` carrying
///   `udhcpc exit <N>` with neither a lease nor a fallback line after it.
pub fn classify_builder_net_bootstrap(console_log: &str) -> BuilderNetBootstrap {
    let mut outcome = BuilderNetBootstrap::Unknown;
    for line in console_log.lines() {
        if let Some(ip) = parse_udhcpc_lease_ip(line) {
            outcome = BuilderNetBootstrap::Lease { ip };
        } else if line.contains("falling back to static gvproxy addressing") {
            outcome = BuilderNetBootstrap::StaticFallback {
                ip: GVPROXY_STATIC_FALLBACK_IP.to_string(),
            };
        } else if line.contains("setup_network warning (non-fatal)") && line.contains("udhcpc exit")
        {
            outcome = BuilderNetBootstrap::Failed;
        }
    }
    outcome
}

/// Extract the leased IP from a busybox udhcpc lease line, if this is one.
///
/// Matches `udhcpc: lease of <ip> obtained from ...` and returns `<ip>`.
/// Returns `None` for any other line. The address itself is validated
/// through [`parse_ipv4`] so a malformed token isn't reported as a lease.
fn parse_udhcpc_lease_ip(line: &str) -> Option<String> {
    let after = line.split("lease of ").nth(1)?;
    let ip = after.split_whitespace().next()?;
    parse_ipv4(ip)?;
    Some(ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_valid_addresses() {
        assert_eq!(parse_ipv4("192.168.127.1"), Some([192, 168, 127, 1]));
        assert_eq!(parse_ipv4("10.0.2.15"), Some([10, 0, 2, 15]));
        assert_eq!(parse_ipv4("0.0.0.0"), Some([0, 0, 0, 0]));
        assert_eq!(parse_ipv4("255.255.255.0"), Some([255, 255, 255, 0]));
    }

    #[test]
    fn parse_ipv4_rejects_malformed() {
        assert_eq!(parse_ipv4(""), None);
        assert_eq!(parse_ipv4("192.168.1"), None);
        assert_eq!(parse_ipv4("192.168.1.1.1"), None);
        assert_eq!(parse_ipv4("256.0.0.1"), None);
        assert_eq!(parse_ipv4("notanip"), None);
        assert_eq!(parse_ipv4("192.168.1.abc"), None);
    }

    #[test]
    fn encode_iface_name_eth0_pads_with_nul() {
        let buf = encode_iface_name("eth0").expect("eth0 fits");
        assert_eq!(buf[0] as u8, b'e');
        assert_eq!(buf[1] as u8, b't');
        assert_eq!(buf[2] as u8, b'h');
        assert_eq!(buf[3] as u8, b'0');
        assert_eq!(buf[4] as u8, 0, "remainder NUL-padded");
        assert_eq!(buf[libc::IFNAMSIZ - 1] as u8, 0);
    }

    #[test]
    fn encode_iface_name_max_length_succeeds() {
        let max = "a".repeat(libc::IFNAMSIZ - 1);
        let buf = encode_iface_name(&max).expect("15-byte name fits");
        for byte in buf.iter().take(libc::IFNAMSIZ - 1) {
            assert_eq!(*byte as u8, b'a');
        }
        assert_eq!(buf[libc::IFNAMSIZ - 1] as u8, 0, "NUL terminator");
    }

    #[test]
    fn encode_iface_name_too_long_errors() {
        let over = "a".repeat(libc::IFNAMSIZ);
        let err = encode_iface_name(&over).expect_err("IFNAMSIZ-byte name rejected");
        assert!(err.contains("IFNAMSIZ"), "err mentions limit: {err}");
    }

    #[test]
    fn classify_lease_from_real_busybox_line() {
        let log = "udhcpc: lease of 192.168.127.3 obtained from 192.168.127.1, lease time 3600";
        assert_eq!(
            classify_builder_net_bootstrap(log),
            BuilderNetBootstrap::Lease {
                ip: "192.168.127.3".to_string()
            }
        );
    }

    #[test]
    fn classify_lease_amid_noise() {
        let log = "\
booting...
mvm-host-vm-init: bring_iface_up eth0
udhcpc: sending discover
udhcpc: lease of 10.0.2.15 obtained from 10.0.2.2, lease time 86400
some-service: ready";
        assert_eq!(
            classify_builder_net_bootstrap(log),
            BuilderNetBootstrap::Lease {
                ip: "10.0.2.15".to_string()
            }
        );
    }

    #[test]
    fn classify_static_fallback() {
        let log = "\
udhcpc: no lease, failing
mvm-host-vm-init: udhcpc exit 1 — falling back to static gvproxy addressing";
        assert_eq!(
            classify_builder_net_bootstrap(log),
            BuilderNetBootstrap::StaticFallback {
                ip: "192.168.127.3".to_string()
            }
        );
    }

    #[test]
    fn classify_failed_when_warning_without_lease_or_fallback() {
        let log = "\
udhcpc: sending discover
mvm-host-vm-init: setup_network warning (non-fatal): spawn /bin/udhcpc: udhcpc exit 1";
        assert_eq!(
            classify_builder_net_bootstrap(log),
            BuilderNetBootstrap::Failed
        );
    }

    #[test]
    fn classify_unknown_on_empty() {
        assert_eq!(
            classify_builder_net_bootstrap(""),
            BuilderNetBootstrap::Unknown
        );
    }

    #[test]
    fn classify_unknown_on_unrelated_noise() {
        let log = "boot ok\nservice up\nready";
        assert_eq!(
            classify_builder_net_bootstrap(log),
            BuilderNetBootstrap::Unknown
        );
    }

    #[test]
    fn classify_takes_last_outcome_across_reboot() {
        // A reboot: first boot leased, second boot fell back to static.
        // The later outcome wins.
        let log = "\
udhcpc: lease of 192.168.127.3 obtained from 192.168.127.1, lease time 3600
--- reboot ---
mvm-host-vm-init: udhcpc exit 1 — falling back to static gvproxy addressing";
        assert_eq!(
            classify_builder_net_bootstrap(log),
            BuilderNetBootstrap::StaticFallback {
                ip: "192.168.127.3".to_string()
            }
        );
    }

    #[test]
    fn classify_fallback_supersedes_earlier_failure_warning() {
        // On one boot the warning and the fallback both appear; the
        // fallback is the real outcome (reachable), so it must win.
        let log = "\
mvm-host-vm-init: setup_network warning (non-fatal): udhcpc exit 1
mvm-host-vm-init: udhcpc exit 1 — falling back to static gvproxy addressing";
        assert_eq!(
            classify_builder_net_bootstrap(log),
            BuilderNetBootstrap::StaticFallback {
                ip: "192.168.127.3".to_string()
            }
        );
    }

    #[test]
    fn classify_rejects_malformed_lease_ip() {
        let log = "udhcpc: lease of not.an.ip.addr obtained from 192.168.127.1";
        assert_eq!(
            classify_builder_net_bootstrap(log),
            BuilderNetBootstrap::Unknown
        );
    }
}
