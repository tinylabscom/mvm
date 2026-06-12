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
}
