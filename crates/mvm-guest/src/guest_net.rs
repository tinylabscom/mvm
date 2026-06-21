//! Shared in-guest network configuration.
//!
//! One implementation of the guest-side network bring-up used by **both** the
//! builder VM init (`mvm-host-vm-init`, via `mvm-build`) and the workload guest
//! netinit (`mvm-guest-netinit`). Before this was shared, only the builder
//! brought `eth0` up + ran DHCP; workload guests relied on libkrun's
//! `NET_FLAG_DHCP_CLIENT`, which does not configure the interface here — so a
//! workload guest got no network at all. [`configure_guest_network`] is the
//! single bring-up both now call.
//!
//! The ioctl/`udhcpc` bodies are gated `#[cfg(target_os = "linux")]`; the pure
//! address-parsing + policy helpers compile and are unit-tested on every host.

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

/// The gateway-local resolver line for the active VMM's virtual network.
///
/// QEMU user-mode networking serves DNS at 10.0.2.3; the gvproxy backends
/// (libkrun, Vz) at 192.168.127.1. Host-side resolution through the gateway
/// works on any network — baked public resolvers only work where the local
/// network permits direct external UDP/53.
pub fn resolver_seed(cmdline: &str) -> &'static [u8] {
    if cmdline.split_whitespace().any(|t| t == "mvm.backend=qemu") {
        b"nameserver 10.0.2.3\n"
    } else {
        b"nameserver 192.168.127.1\n"
    }
}

/// True when a DHCP failure should trigger the static gvproxy fallback.
///
/// The QEMU/slirp backend uses a different subnet (10.0.2.x) with its own
/// `ip=` kernel autoconfig, so applying the gvproxy static address there would
/// be wrong — only fall back to static on the gvproxy backends.
pub fn dhcp_fallback_applies(cmdline: &str, udhcpc_success: bool) -> bool {
    if udhcpc_success {
        return false;
    }
    !cmdline.split_whitespace().any(|t| t == "mvm.backend=qemu")
}

/// Statically configure a guest NIC: assign `addr/netmask` and install a
/// default route via `gateway`.
///
/// Applies the standard `SIOCSIFADDR` / `SIOCSIFNETMASK` / `SIOCSIFFLAGS`
/// (UP|RUNNING) / `SIOCADDRT` ioctl sequence on an `AF_INET/SOCK_DGRAM`
/// socket. The gvproxy virtual subnet is fixed (`192.168.127.0/24`, gateway
/// `.1`), and each VM gets its own gateway instance, so a static address
/// cannot collide across VMs.
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
/// zeroed.
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

/// Bring a network interface administratively up via
/// `ioctl(SIOCSIFFLAGS, IFF_UP)`. Equivalent to `ip link set dev <iface> up`,
/// issued directly so we don't pin a path-dependency in the rootfs and the
/// error names the failing ioctl. Must run before `udhcpc` (busybox udhcpc
/// binds a `PF_PACKET` socket that needs the link already up).
#[cfg(target_os = "linux")]
pub fn bring_iface_up(iface: &str) -> Result<(), String> {
    let name = encode_iface_name(iface)?;
    // SAFETY: socket(2) returns -1 on error (checked) or a valid fd; closed below.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(format!(
            "socket(AF_INET, SOCK_DGRAM) for {iface}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let result = (|| {
        // SAFETY: `ifreq` is repr(C); zero-init + per-variant union assignment
        // is the standard pattern. `ifru_flags` is read only after SIOCGIFFLAGS.
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        ifr.ifr_name = name;
        if unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as libc::Ioctl, &mut ifr) } < 0 {
            return Err(format!(
                "SIOCGIFFLAGS {iface}: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: SIOCGIFFLAGS populated ifru_flags; OR-in IFF_UP through the
        // same Copy union variant.
        unsafe {
            let flags = ifr.ifr_ifru.ifru_flags;
            ifr.ifr_ifru.ifru_flags = flags | (libc::IFF_UP as libc::c_short);
        }
        if unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as libc::Ioctl, &ifr) } < 0 {
            return Err(format!(
                "SIOCSIFFLAGS {iface} IFF_UP: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    })();
    // SAFETY: sock is owned by this function until close.
    unsafe { libc::close(sock) };
    result
}

/// Stage the gateway-resolver seed on tmpfs and bind-mount it over the baked
/// read-only `/etc/resolv.conf` so udhcpc's script (and the lease it carries)
/// can write DNS config through the mount.
#[cfg(target_os = "linux")]
pub fn seed_resolv_conf(cmdline: &str) -> Result<(), String> {
    let seed = resolver_seed(cmdline);
    std::fs::create_dir_all("/run/mvm").map_err(|e| format!("mkdir /run/mvm: {e}"))?;
    std::fs::write("/run/mvm/resolv.conf", seed)
        .map_err(|e| format!("seed /run/mvm/resolv.conf: {e}"))?;
    // Prefer a bind-mount so the image's own /etc/resolv.conf stays pristine.
    // A minimal OCI rootfs may have no bind target or no /bin/busybox, so on
    // any failure fall back to writing /etc/resolv.conf directly — DNS is what
    // matters, not the mechanism.
    if std::path::Path::new("/etc/resolv.conf").exists() {
        let bound = std::process::Command::new("/bin/busybox")
            .args([
                "mount",
                "--bind",
                "/run/mvm/resolv.conf",
                "/etc/resolv.conf",
            ])
            .status()
            .map(|st| st.success())
            .unwrap_or(false);
        if bound {
            return Ok(());
        }
    }
    std::fs::write("/etc/resolv.conf", seed)
        .map_err(|e| format!("write /etc/resolv.conf: {e}"))?;
    Ok(())
}

/// Bring `iface` up, seed `/etc/resolv.conf` to the gateway resolver, obtain a
/// lease via busybox `udhcpc`, and on a failed lease apply the static
/// `fallback_ip` (gvproxy subnet only — see [`dhcp_fallback_applies`]).
///
/// Shared by the builder VM init and the workload guest netinit so both bring
/// the guest network up identically. `cmdline` is `/proc/cmdline`; it selects
/// the resolver + whether the static fallback applies. Returns `Ok` when the
/// interface ends up configured (lease or fallback); `Err` on a hard udhcpc
/// failure where no fallback applies. resolv.conf seeding is best-effort (a
/// failure degrades DNS but never blocks the link/DHCP).
#[cfg(target_os = "linux")]
pub fn configure_guest_network(
    iface: &str,
    cmdline: &str,
    fallback_ip: &str,
) -> Result<(), String> {
    bring_iface_up(iface)?;

    if let Err(e) = seed_resolv_conf(cmdline) {
        eprintln!("guest-net: resolv.conf seed skipped: {e} (continuing — DNS degraded)");
    }

    // `/bin/udhcpc` — busybox applet symlink. `-n` exit if lease fails, `-q`
    // quit after obtaining a lease. The `-s` script applies the lease (IP +
    // route + DNS) when present. An arbitrary OCI rootfs (e.g. a minimal
    // alpine) need not ship udhcpc at this path; a spawn failure is treated as
    // "no lease" so the static fallback still runs, rather than hard-failing
    // the guest with no address. `configure_static` uses ioctls directly, so it
    // needs no in-guest networking tools.
    let script = "/etc/udhcpc/default.script";
    let mut cmd = std::process::Command::new("/bin/udhcpc");
    cmd.args(["-i", iface, "-n", "-q"]);
    if std::path::Path::new(script).is_file() {
        cmd.args(["-s", script]);
    }
    let udhcpc_success = match cmd.status() {
        Ok(status) => status.success(),
        Err(e) => {
            eprintln!("guest-net: /bin/udhcpc unavailable ({e}); treating as no lease");
            false
        }
    };

    if dhcp_fallback_applies(cmdline, udhcpc_success) {
        eprintln!(
            "guest-net: no DHCP lease — falling back to static gvproxy addressing ({fallback_ip})"
        );
        configure_static(iface, fallback_ip, "255.255.255.0", "192.168.127.1")?;
    } else if !udhcpc_success {
        return Err("udhcpc obtained no lease and no static fallback applies".to_string());
    }
    Ok(())
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
        assert_eq!(buf[3] as u8, b'0');
        assert_eq!(buf[4] as u8, 0, "remainder NUL-padded");
        assert_eq!(buf[libc::IFNAMSIZ - 1] as u8, 0);
    }

    #[test]
    fn encode_iface_name_too_long_errors() {
        let over = "a".repeat(libc::IFNAMSIZ);
        let err = encode_iface_name(&over).expect_err("IFNAMSIZ-byte name rejected");
        assert!(err.contains("IFNAMSIZ"), "err mentions limit: {err}");
    }

    #[test]
    fn resolver_seed_picks_gateway_per_backend() {
        assert_eq!(
            resolver_seed("console=hvc0 root=/dev/vda"),
            b"nameserver 192.168.127.1\n"
        );
        assert_eq!(
            resolver_seed("mvm.backend=qemu ip=dhcp"),
            b"nameserver 10.0.2.3\n"
        );
    }

    #[test]
    fn dhcp_fallback_only_on_gvproxy_failure() {
        // success → never fall back
        assert!(!dhcp_fallback_applies("anything", true));
        // gvproxy failure → fall back
        assert!(dhcp_fallback_applies("console=hvc0", false));
        // QEMU failure → do NOT apply the gvproxy static (QEMU uses ip= autoconfig)
        assert!(!dhcp_fallback_applies("mvm.backend=qemu", false));
    }
}
