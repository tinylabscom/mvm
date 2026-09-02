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

#[cfg(target_os = "linux")]
const SHARED_GATEWAY_ADDR: &str = "192.168.127.1";
#[cfg(target_os = "linux")]
const SHARED_GATEWAY_NETMASK: &str = "255.255.255.0";
#[cfg(target_os = "linux")]
pub(crate) const SIOCSIFADDR_REQUEST: libc::Ioctl = target_ioctl_request(libc::SIOCSIFADDR);
#[cfg(target_os = "linux")]
const SIOCSIFNETMASK_REQUEST: libc::Ioctl = target_ioctl_request(libc::SIOCSIFNETMASK);
#[cfg(target_os = "linux")]
pub(crate) const SIOCGIFFLAGS_REQUEST: libc::Ioctl = target_ioctl_request(libc::SIOCGIFFLAGS);
#[cfg(target_os = "linux")]
pub(crate) const SIOCSIFFLAGS_REQUEST: libc::Ioctl = target_ioctl_request(libc::SIOCSIFFLAGS);
#[cfg(target_os = "linux")]
pub(crate) const SIOCADDRT_REQUEST: libc::Ioctl = target_ioctl_request(libc::SIOCADDRT);
const RESOLVER_CMDLINE_PREFIX: &str = "mvm.resolver=";

#[cfg(any(target_os = "linux", test))]
const fn loopback_ipv4_config() -> ([u8; 4], [u8; 4]) {
    ([127, 0, 0, 1], [255, 0, 0, 0])
}

#[cfg(target_os = "linux")]
pub(crate) const fn target_ioctl_request(request: u64) -> libc::Ioctl {
    assert!(request <= target_ioctl_request_max());
    request as libc::Ioctl
}

#[cfg(all(target_os = "linux", target_env = "musl"))]
const fn target_ioctl_request_max() -> u64 {
    libc::Ioctl::MAX as u64
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
const fn target_ioctl_request_max() -> u64 {
    libc::Ioctl::MAX
}

/// Parse the first usable `nameserver` entry from a resolv.conf body.
///
/// Comments, blank lines, and malformed addresses are ignored. Returns the
/// first valid IPv4 resolver because the Linux host flow exposes a
/// single DNS-forward target to the guest.
pub fn first_nameserver_from_resolv_conf(body: &str) -> Option<String> {
    body.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next(), parts.next()) {
            (Some("nameserver"), Some(ip), None) if parse_ipv4(ip).is_some() => {
                Some(ip.to_string())
            }
            _ => None,
        }
    })
}

/// Render a kernel-cmdline token that tells the guest which resolver IP to
/// seed when the host's gateway path does not answer DNS at the virtual
/// gateway address.
pub fn resolver_cmdline_token_from_resolv_conf(body: &str) -> Option<String> {
    first_nameserver_from_resolv_conf(body).map(|ip| format!("{RESOLVER_CMDLINE_PREFIX}{ip}"))
}

/// Parse the host-supplied resolver override out of the kernel cmdline.
pub fn resolver_override_from_cmdline(cmdline: &str) -> Option<&str> {
    cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix(RESOLVER_CMDLINE_PREFIX))
        .filter(|ip| parse_ipv4(ip).is_some())
}

/// The gateway-local resolver line for the active VMM's virtual network.
///
/// QEMU user-mode networking serves DNS at 10.0.2.3. The libkrun/HVF path
/// defaults to the shared virtual gateway at 192.168.127.1, but a host-supplied
/// `mvm.resolver=` token can override that when the active gateway only answers
/// DNS for a forwarded upstream address. Host-side resolution through the
/// gateway works on any network; baked public resolvers only work where the
/// local network permits direct external UDP/53.
pub fn resolver_seed(cmdline: &str) -> Vec<u8> {
    if let Some(resolver) = resolver_override_from_cmdline(cmdline) {
        return format!("nameserver {resolver}\n").into_bytes();
    }
    if cmdline.split_whitespace().any(|t| t == "mvm.backend=qemu") {
        b"nameserver 10.0.2.3\n".to_vec()
    } else {
        b"nameserver 192.168.127.1\n".to_vec()
    }
}

/// Render a resolv.conf body from an explicit list of DNS servers.
pub fn render_resolv_conf(nameservers: &[std::net::IpAddr]) -> Vec<u8> {
    nameservers
        .iter()
        .map(|addr| format!("nameserver {addr}\n"))
        .collect::<String>()
        .into_bytes()
}

/// Resolver address exposed by the in-guest vsock DNS stub.
pub const LOOPBACK_STUB_RESOLVER: std::net::Ipv4Addr = std::net::Ipv4Addr::LOCALHOST;

#[cfg(any(target_os = "linux", test))]
fn loopback_stub_resolver_body() -> Vec<u8> {
    render_resolv_conf(&[LOOPBACK_STUB_RESOLVER.into()])
}

/// True when a DHCP failure should trigger the static shared-gateway fallback.
///
/// The QEMU/slirp backend uses a different subnet (10.0.2.x) with its own
/// `ip=` kernel autoconfig, so applying the shared-gateway static address there
/// would be wrong — only fall back to static on the gateway-backed backends.
pub fn gateway_static_fallback_applies(cmdline: &str, udhcpc_success: bool) -> bool {
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
/// socket. The shared gateway subnet is fixed (`192.168.127.0/24`, gateway
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

/// Assign the canonical IPv4 loopback address and bring `lo` up without
/// installing any route outside `127.0.0.0/8`.
#[cfg(target_os = "linux")]
pub fn configure_loopback() -> Result<(), String> {
    let (addr, netmask) = loopback_ipv4_config();
    // SAFETY: socket(2) returns -1 on error (checked below) or a valid fd.
    // We close it on every return path.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(format!(
            "socket(AF_INET, SOCK_DGRAM) for lo: {}",
            std::io::Error::last_os_error()
        ));
    }
    let result = apply_interface_address(sock, "lo", addr, netmask);
    // SAFETY: sock is valid, and this function owns it.
    unsafe { libc::close(sock) };
    result
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
    apply_interface_address(sock, iface, addr, netmask)?;
    unsafe {
        // default route
        let mut rt: libc::rtentry = std::mem::zeroed();
        set_sockaddr_in(&mut rt.rt_dst, [0, 0, 0, 0]);
        set_sockaddr_in(&mut rt.rt_genmask, [0, 0, 0, 0]);
        set_sockaddr_in(&mut rt.rt_gateway, gateway);
        rt.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as libc::c_ushort;
        if libc::ioctl(sock, SIOCADDRT_REQUEST, &rt) < 0 {
            return Err(format!("SIOCADDRT: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn apply_interface_address(
    sock: libc::c_int,
    iface: &str,
    addr: [u8; 4],
    netmask: [u8; 4],
) -> Result<(), String> {
    unsafe {
        let mut ifr = ifreq_for(iface);
        set_sockaddr_in(&mut ifr.ifr_ifru.ifru_addr, addr);
        if libc::ioctl(sock, SIOCSIFADDR_REQUEST, &ifr) < 0 {
            return Err(format!(
                "SIOCSIFADDR {iface}: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut ifr = ifreq_for(iface);
        set_sockaddr_in(&mut ifr.ifr_ifru.ifru_netmask, netmask);
        if libc::ioctl(sock, SIOCSIFNETMASK_REQUEST, &ifr) < 0 {
            return Err(format!(
                "SIOCSIFNETMASK {iface}: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut ifr = ifreq_for(iface);
        if libc::ioctl(sock, SIOCGIFFLAGS_REQUEST, &mut ifr) < 0 {
            return Err(format!(
                "SIOCGIFFLAGS {iface}: {}",
                std::io::Error::last_os_error()
            ));
        }
        ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        if libc::ioctl(sock, SIOCSIFFLAGS_REQUEST, &ifr) < 0 {
            return Err(format!(
                "SIOCSIFFLAGS {iface}: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

/// Build an `ifreq` with the interface name pre-filled and all other fields
/// zeroed.
#[cfg(target_os = "linux")]
pub(crate) fn ifreq_for(iface: &str) -> libc::ifreq {
    // SAFETY: ifreq is a plain C struct; zeroed is a valid empty request.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in iface.bytes().enumerate().take(libc::IFNAMSIZ - 1) {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    ifr
}

/// Write an IPv4 `sockaddr_in` into a `sockaddr`-typed ioctl field in-place.
#[cfg(target_os = "linux")]
pub(crate) fn set_sockaddr_in(dst: *mut libc::sockaddr, addr: [u8; 4]) {
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
/// What bringing the guest network up actually found.
///
/// A workload microVM boots with a virtio-vsock device and **no NIC at all** —
/// that is the vsock-only invariant behind claims 10 and 13, and
/// `xtask check-vsock-only-egress` enforces it. `eth0` being absent there is
/// the designed configuration, not a fault, and the two cases have to be
/// distinguishable at the call site: the builder VM does have a NIC, so a
/// missing interface there is a real failure. Returning `Ok` for both and
/// letting each caller decide beats a shared error string neither can act on.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestNetwork {
    /// The interface exists and is configured (lease or static fallback).
    Configured,
    /// There is no such interface on this guest.
    NoInterface,
}

/// binds a `PF_PACKET` socket that needs the link already up).
#[cfg(target_os = "linux")]
pub fn bring_iface_up(iface: &str) -> Result<GuestNetwork, String> {
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
        if unsafe { libc::ioctl(sock, SIOCGIFFLAGS_REQUEST, &mut ifr) } < 0 {
            let err = std::io::Error::last_os_error();
            // ENODEV is the kernel saying the interface does not exist, which
            // is not the same as failing to configure one that does. Every
            // other errno stays a hard error.
            if err.raw_os_error() == Some(libc::ENODEV) {
                return Ok(GuestNetwork::NoInterface);
            }
            return Err(format!("SIOCGIFFLAGS {iface}: {err}"));
        }
        // SAFETY: SIOCGIFFLAGS populated ifru_flags; OR-in IFF_UP through the
        // same Copy union variant.
        unsafe {
            let flags = ifr.ifr_ifru.ifru_flags;
            ifr.ifr_ifru.ifru_flags = flags | (libc::IFF_UP as libc::c_short);
        }
        if unsafe { libc::ioctl(sock, SIOCSIFFLAGS_REQUEST, &ifr) } < 0 {
            return Err(format!(
                "SIOCSIFFLAGS {iface} IFF_UP: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(GuestNetwork::Configured)
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
    seed_resolv_conf_bytes(&seed)
}

/// Stage a concrete resolv.conf body for the guest.
#[cfg(target_os = "linux")]
pub fn seed_resolv_conf_bytes(seed: &[u8]) -> Result<(), String> {
    std::fs::create_dir_all("/etc").map_err(|e| format!("mkdir /etc: {e}"))?;
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
    std::fs::write("/etc/resolv.conf", seed).map_err(|e| format!("write /etc/resolv.conf: {e}"))?;
    Ok(())
}

/// Point guest name resolution at the loopback stub served by the egress client.
#[cfg(target_os = "linux")]
pub fn seed_loopback_resolver() -> Result<(), String> {
    seed_resolv_conf_bytes(&loopback_stub_resolver_body())
}

/// Bring `iface` up, seed `/etc/resolv.conf` to the gateway resolver, obtain a
/// lease via busybox `udhcpc`, and on a failed lease apply the static
/// `fallback_ip` (shared gateway subnet only — see
/// [`gateway_static_fallback_applies`]).
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
) -> Result<GuestNetwork, String> {
    if bring_iface_up(iface)? == GuestNetwork::NoInterface {
        // Nothing downstream — DHCP, the static fallback, the default route —
        // has an interface to act on. Returning here keeps the caller's log
        // line the single statement about this guest's network.
        return Ok(GuestNetwork::NoInterface);
    }

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

    if gateway_static_fallback_applies(cmdline, udhcpc_success) {
        eprintln!(
            "guest-net: no DHCP lease — falling back to static gateway addressing ({fallback_ip})"
        );
        configure_static(
            iface,
            fallback_ip,
            SHARED_GATEWAY_NETMASK,
            SHARED_GATEWAY_ADDR,
        )?;
    } else if !udhcpc_success {
        return Err("udhcpc obtained no lease and no static fallback applies".to_string());
    }
    Ok(GuestNetwork::Configured)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_configuration_assigns_ipv4_localhost_over_eight() {
        assert_eq!(loopback_ipv4_config(), ([127, 0, 0, 1], [255, 0, 0, 0]));
    }

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
        let byte = |value: libc::c_char| u8::from_ne_bytes(value.to_ne_bytes());
        assert_eq!(byte(buf[0]), b'e');
        assert_eq!(byte(buf[3]), b'0');
        assert_eq!(byte(buf[4]), 0, "remainder NUL-padded");
        assert_eq!(byte(buf[libc::IFNAMSIZ - 1]), 0);
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
            b"nameserver 192.168.127.1\n".to_vec()
        );
        assert_eq!(
            resolver_seed("mvm.backend=qemu ip=dhcp"),
            b"nameserver 10.0.2.3\n".to_vec()
        );
    }

    #[test]
    fn resolver_seed_prefers_cmdline_override() {
        assert_eq!(
            resolver_seed("console=hvc0 mvm.resolver=1.1.1.1"),
            b"nameserver 1.1.1.1\n".to_vec()
        );
    }

    #[test]
    fn resolver_override_from_cmdline_ignores_malformed_values() {
        assert_eq!(resolver_override_from_cmdline("mvm.resolver=bad.ip"), None);
        assert_eq!(resolver_override_from_cmdline("console=hvc0"), None);
    }

    #[test]
    fn first_nameserver_from_resolv_conf_ignores_comments_and_invalid_lines() {
        let body = "\
# comment
search example.internal
nameserver invalid
nameserver 10.0.0.2
nameserver 10.0.0.3
";
        assert_eq!(
            first_nameserver_from_resolv_conf(body).as_deref(),
            Some("10.0.0.2")
        );
        assert_eq!(
            resolver_cmdline_token_from_resolv_conf(body).as_deref(),
            Some("mvm.resolver=10.0.0.2")
        );
    }

    #[test]
    fn gateway_static_fallback_only_on_gateway_backend_failure() {
        // success → never fall back
        assert!(!gateway_static_fallback_applies("anything", true));
        // gateway-backed libkrun/HVF failure → fall back
        assert!(gateway_static_fallback_applies("console=hvc0", false));
        // QEMU failure → do NOT apply the shared-gateway static (QEMU uses ip= autoconfig)
        assert!(!gateway_static_fallback_applies("mvm.backend=qemu", false));
    }

    #[test]
    fn render_resolv_conf_lists_every_nameserver() {
        let rendered = render_resolv_conf(&[
            "1.1.1.1".parse().expect("ipv4"),
            "2606:4700:4700::1111".parse().expect("ipv6"),
        ]);
        assert_eq!(
            String::from_utf8(rendered).expect("utf8"),
            "nameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\n"
        );
    }

    #[test]
    fn loopback_stub_resolver_body_points_at_localhost() {
        assert_eq!(
            loopback_stub_resolver_body(),
            b"nameserver 127.0.0.1\n".to_vec()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::unnecessary_cast)]
    fn network_ioctl_requests_fit_target_request_type() {
        assert_eq!(SIOCSIFADDR_REQUEST as u64, libc::SIOCSIFADDR as u64);
        assert_eq!(SIOCSIFNETMASK_REQUEST as u64, libc::SIOCSIFNETMASK as u64);
        assert_eq!(SIOCGIFFLAGS_REQUEST as u64, libc::SIOCGIFFLAGS as u64);
        assert_eq!(SIOCSIFFLAGS_REQUEST as u64, libc::SIOCSIFFLAGS as u64);
        assert_eq!(SIOCADDRT_REQUEST as u64, libc::SIOCADDRT as u64);
    }

    /// The distinction this split exists for, at the syscall that draws it.
    ///
    /// A name no guest has yields ENODEV from SIOCGIFFLAGS — the same errno a
    /// NIC-less workload guest gets for `eth0` — and that must read as "there
    /// is no such interface", not as a bring-up failure. Reading interface
    /// flags needs no privileges, so this runs anywhere Linux does.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_nonexistent_interface_is_reported_as_absent_not_as_a_failure() {
        // 15 chars max (IFNAMSIZ - 1), and nothing plausibly present.
        let outcome = bring_iface_up("mvmnodev0");
        assert_eq!(
            outcome,
            Ok(GuestNetwork::NoInterface),
            "ENODEV must be the absent-interface outcome, not an error"
        );
    }

    /// The other half: an interface that cannot even be named is a caller
    /// error, and must not be laundered into "this guest has no NIC" — that
    /// would turn a typo into a silently networkless guest.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unencodable_interface_name_stays_an_error() {
        let too_long = "x".repeat(libc::IFNAMSIZ + 4);
        assert!(
            bring_iface_up(&too_long).is_err(),
            "an unusable name is an error, not an absent interface"
        );
    }
}
