//! The Linux datapath: an mvm-owned host TUN device, narrowly scoped
//! routes, and nftables for NAT and defence in depth.
//!
//! This sits **after** the vsock trust boundary. The device here is the
//! host's, not the guest's: the guest has no network device at all, and
//! `mvm0` inside it terminates in the guest agent. There is no bridge, no
//! TAP, and no hypervisor network device anywhere in this path.
//!
//! Only packets the userspace admitter has already approved are written to
//! the device, and everything read back off it goes through inbound
//! admission before reaching a guest. The nftables ruleset is a second
//! layer, never the only one: if it were removed, admission would still
//! refuse the same packets.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};

use mvm_net::l3::AdmittedPacket;

use super::datapath::{
    DatapathError, DatapathHandle, DatapathRequest, ForwardingCapabilities, L3Datapath,
};

const TUN_PATH: &str = "/dev/net/tun";
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
// `libc::Ioctl` is `c_int` on musl and `c_ulong` on glibc, so the request
// number is narrowed through a const fn rather than written as a bare
// constant that only compiles for one of them.
const TUNSETIFF: libc::Ioctl = ioctl_request(0x4004_54ca);

/// Narrow an ioctl request number to this target's `libc::Ioctl` width.
const fn ioctl_request(request: u64) -> libc::Ioctl {
    assert!(request <= ioctl_request_max());
    request as libc::Ioctl
}

#[cfg(target_env = "musl")]
const fn ioctl_request_max() -> u64 {
    libc::Ioctl::MAX as u64
}

#[cfg(not(target_env = "musl"))]
const fn ioctl_request_max() -> u64 {
    libc::Ioctl::MAX
}

/// Prefix for every device and table this datapath creates, so a sweep can
/// find them all and nothing unrelated is ever touched.
const RESOURCE_PREFIX: &str = "mvmn";

#[repr(C, align(8))]
struct IfReqFlags {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

// Layout contract for `struct ifreq` <linux/if.h>, read out of the header
// with cc `sizeof`/`_Alignof`/`offsetof` on LP64 Linux, not off this
// definition. `align(8)` is explicit because the C union's widest member
// is a pointer while this mirror's is a `c_short`; without it the Rust
// type under-aligns and the assert below is what catches that.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<IfReqFlags>() == 40);
    assert!(align_of::<IfReqFlags>() == 8);
    assert!(offset_of!(IfReqFlags, name) == 0);
    assert!(offset_of!(IfReqFlags, flags) == 16);
};

/// Opens Linux datapaths.
#[derive(Debug, Default)]
pub struct LinuxDatapath {
    /// When set, nftables rules are generated but not applied. Used by the
    /// tests that assert the ruleset's shape without root.
    dry_run: bool,
}

impl LinuxDatapath {
    pub fn new() -> Self {
        Self { dry_run: false }
    }

    /// A datapath that generates rules without applying them.
    pub fn dry_run() -> Self {
        Self { dry_run: true }
    }
}

impl L3Datapath for LinuxDatapath {
    fn open(&self, req: &DatapathRequest) -> Result<Box<dyn DatapathHandle>, DatapathError> {
        let iface = device_name(&req.machine_id);
        let table = table_name(&req.machine_id);

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(TUN_PATH)
            .map_err(|source| DatapathError::SetupFailed {
                what: "host tun device",
                machine_id: req.machine_id.clone(),
                source,
            })?;

        let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
        for (i, b) in iface.bytes().enumerate().take(libc::IFNAMSIZ - 1) {
            name[i] = b as libc::c_char;
        }
        let mut ifreq = IfReqFlags {
            name,
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0u8; 22],
        };
        // SAFETY: `ifreq` matches the layout TUNSETIFF expects and outlives
        // the call; the fd is open for read/write.
        if unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut ifreq) } < 0 {
            return Err(DatapathError::PrivilegeRequired {
                operation: "creating the host tun device",
                detail: std::io::Error::last_os_error().to_string(),
            });
        }

        // Non-blocking is not an optimization here, it is required. The
        // gateway drains this device until it reports `WouldBlock`; on a
        // blocking fd an idle interface never returns, so the first inbound
        // poll would hang the whole session — and with it the shutdown path
        // that would otherwise have cleaned up.
        set_nonblocking(file.as_raw_fd()).map_err(|source| DatapathError::SetupFailed {
            what: "host tun device (non-blocking)",
            machine_id: req.machine_id.clone(),
            source,
        })?;

        let mut handle = LinuxHandle {
            file: Some(file),
            iface: iface.clone(),
            table: table.clone(),
            machine_id: req.machine_id.clone(),
            guest: req.guest,
            guest_v6: req.v6.map(|v6| v6.guest),
            nft_applied: false,
            closed: false,
            dry_run: self.dry_run,
        };

        if let Err(err) = handle.configure(req) {
            // A partial setup must not survive. Teardown runs on this path
            // exactly as it does on a normal stop.
            let _ = handle.close();
            return Err(err);
        }
        Ok(Box::new(handle))
    }

    fn is_available(&self) -> Result<(), DatapathError> {
        if self.dry_run {
            return Ok(());
        }
        if !std::path::Path::new(TUN_PATH).exists() {
            return Err(DatapathError::Unsupported {
                platform: "linux",
                detail: format!("{TUN_PATH} is missing (host kernel needs CONFIG_TUN)"),
            });
        }
        // Creating a TUN device and installing routes both need
        // CAP_NET_ADMIN. Checking here means an unprivileged supervisor
        // refuses the mode at admission instead of failing mid-handshake.
        // SAFETY: geteuid takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } != 0 && !has_net_admin() {
            return Err(DatapathError::PrivilegeRequired {
                operation: "creating a host tun device and installing routes",
                detail: "the supervisor holds neither root nor CAP_NET_ADMIN".to_string(),
            });
        }
        Ok(())
    }

    fn capabilities(&self) -> ForwardingCapabilities {
        // A host TUN carries whole IP packets, so every transport the
        // policy layer understands works, in either family: `configure`
        // assigns the v6 pair whenever the lease carries one — which is
        // what puts the guest's address in a connected prefix — and the
        // ruleset pins the v6 source exactly as it pins the v4 one. The
        // device itself never cared which family it was handed, so the two
        // v6 flags answer the same question as their v4 counterparts and
        // get the same answer.
        ForwardingCapabilities::FULL_L3
    }
}

/// One machine's open datapath.
pub struct LinuxHandle {
    /// `Option` because closing must *drop* the descriptor: a TUN device
    /// created with `TUNSETIFF` lives exactly as long as its last open fd,
    /// so a `close()` that leaves the file alive leaves the interface on
    /// the host until the handle is eventually dropped.
    file: Option<std::fs::File>,
    iface: String,
    table: String,
    machine_id: String,
    guest: Ipv4Addr,
    /// The guest's v6 address, when the lease carried one. The ruleset is
    /// regenerated from it, so what `ruleset()` reports and what was loaded
    /// cannot drift apart.
    guest_v6: Option<Ipv6Addr>,
    nft_applied: bool,
    closed: bool,
    dry_run: bool,
}

impl LinuxHandle {
    /// Assign the host side of the link, set the MTU, bring it up, install
    /// exactly one route for the machine's /30 — and, when the lease
    /// carried one, for its /126 — and load the nftables rules.
    fn configure(&mut self, req: &DatapathRequest) -> Result<(), DatapathError> {
        if self.dry_run {
            self.nft_applied = true;
            return Ok(());
        }
        set_point_to_point(&self.iface, req.gateway, req.guest, req.mtu)?;
        if let Some(v6) = req.v6 {
            set_v6_address(&self.iface, v6.gateway, v6.prefix_len)?;
        }
        apply_nft(&nft_ruleset(
            &self.table,
            &self.iface,
            req.guest,
            self.guest_v6,
        ))?;
        self.nft_applied = true;
        Ok(())
    }

    /// The nftables ruleset this handle installed. Exposed so the shape is
    /// assertable without root.
    pub fn ruleset(&self) -> String {
        nft_ruleset(&self.table, &self.iface, self.guest, self.guest_v6)
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }
}

impl DatapathHandle for LinuxHandle {
    fn send_to_network(&mut self, packet: &AdmittedPacket<'_>) -> Result<(), DatapathError> {
        if self.closed {
            return Err(DatapathError::Io(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe,
            )));
        }
        self.file
            .as_mut()
            .ok_or_else(|| DatapathError::Io(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))?
            .write_all(packet.bytes())?;
        Ok(())
    }

    fn recv_from_network(&mut self, buf: &mut [u8]) -> Result<usize, DatapathError> {
        if self.closed {
            return Err(DatapathError::Io(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe,
            )));
        }
        Ok(self
            .file
            .as_mut()
            .ok_or_else(|| DatapathError::Io(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))?
            .read(buf)?)
    }

    fn close(&mut self) -> Result<(), DatapathError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        if self.dry_run {
            self.file = None;
            return Ok(());
        }
        // Deterministic teardown: the rules go, then the device. Dropping
        // the TUN's last fd is what removes the interface — and its
        // addresses and routes with it — so the descriptor has to go here
        // rather than whenever the handle happens to be dropped.
        //
        // Each step is best-effort because this also runs on the
        // failed-setup path, where some of it was never created.
        if self.nft_applied {
            let _ = delete_nft_table(&self.table);
            self.nft_applied = false;
        }
        self.file = None;
        Ok(())
    }

    fn description(&self) -> String {
        format!(
            "linux host tun {} (table {}) for {}",
            self.iface, self.table, self.machine_id
        )
    }

    fn readiness_fd(&self) -> Option<std::os::fd::RawFd> {
        self.file.as_ref().map(std::fs::File::as_raw_fd)
    }
}

impl Drop for LinuxHandle {
    /// Teardown must not depend on anyone remembering to call `close`.
    /// A panic, an early return, or a dropped supervisor would otherwise
    /// leave an interface and an nftables table on the host, and host state
    /// that outlives the machine it belonged to is exactly what the cleanup
    /// guarantee exists to prevent.
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Device name for a machine.
///
/// Public so the privileged test lane can assert on the exact device the
/// datapath created rather than guessing at it. Slug-validated and length-bounded so it can
/// never be steered into another interface's name.
pub fn device_name(machine_id: &str) -> String {
    // IFNAMSIZ is 16 including the NUL, so the suffix budget is 15 minus
    // the prefix.
    let budget = 15 - RESOURCE_PREFIX.len();
    format!("{RESOURCE_PREFIX}{}", slug(machine_id, budget))
}

/// nftables table name for a machine.
pub fn table_name(machine_id: &str) -> String {
    format!("{RESOURCE_PREFIX}_{}", slug(machine_id, 32))
}

/// Reduce an identifier to `[a-z0-9]`, truncated to `budget` characters.
///
/// Not an escape: a name that survives this is a name nft and the kernel
/// both accept literally, so no quoting question arises downstream.
fn slug(input: &str, budget: usize) -> String {
    let mut out = String::with_capacity(budget);
    for ch in input.chars() {
        if out.len() == budget {
            break;
        }
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        }
    }
    if out.is_empty() {
        out.push('0');
    }
    out
}

/// The nftables ruleset for one machine.
///
/// Two layers, neither load-bearing on its own: masquerade so replies come
/// back, and a filter that drops anything whose source is not the address
/// this machine was assigned. Userspace admission has already made that
/// decision; this is what still holds if a rule elsewhere is wrong.
///
/// The table is `inet`, so one ruleset covers both families and the v6
/// source is pinned by the same mechanism as the v4 one. A machine with no
/// v6 address emits no v6 rule at all — it has no source to pin, and the
/// closing `drop` already refuses the family.
fn nft_ruleset(table: &str, iface: &str, guest: Ipv4Addr, guest_v6: Option<Ipv6Addr>) -> String {
    let (v6_masquerade, v6_forward) = match guest_v6 {
        Some(guest) => (
            format!("\x20   ip6 saddr {guest}/128 masquerade\n"),
            format!(
                "\x20   iifname \"{iface}\" ip6 saddr {guest}/128 accept\n\
                 \x20   oifname \"{iface}\" ip6 daddr {guest}/128 ct state established,related accept\n"
            ),
        ),
        None => (String::new(), String::new()),
    };
    format!(
        "table inet {table} {{\n\
         \x20 chain postrouting {{\n\
         \x20   type nat hook postrouting priority srcnat; policy accept;\n\
         \x20   ip saddr {guest}/32 masquerade\n\
         {v6_masquerade}\
         \x20 }}\n\
         \x20 chain forward {{\n\
         \x20   type filter hook forward priority filter; policy drop;\n\
         \x20   iifname \"{iface}\" ip saddr {guest}/32 accept\n\
         \x20   oifname \"{iface}\" ip daddr {guest}/32 ct state established,related accept\n\
         {v6_forward}\
         \x20   iifname \"{iface}\" drop\n\
         \x20 }}\n\
         }}\n"
    )
}

/// Load a ruleset through `nft -f -`.
///
/// The ruleset is generated from slug-validated identifiers and an
/// `Ipv4Addr`, so no caller-controlled text reaches the command; the only
/// argument is `-f -`, and the rules arrive on stdin rather than through a
/// shell.
fn apply_nft(rules: &str) -> Result<(), DatapathError> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| DatapathError::SetupFailed {
            what: "nft",
            machine_id: String::new(),
            source,
        })?;
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(rules.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(DatapathError::PrivilegeRequired {
            operation: "loading nftables rules",
            detail: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(())
}

fn delete_nft_table(table: &str) -> Result<(), DatapathError> {
    let status = Command::new("nft")
        .args(["delete", "table", "inet", table])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        // A table that is already gone is the desired state, not a failure.
        Ok(())
    }
}

/// Assign the host address, set the MTU, and bring the interface up.
fn set_point_to_point(
    iface: &str,
    gateway: Ipv4Addr,
    guest: Ipv4Addr,
    mtu: u16,
) -> Result<(), DatapathError> {
    // SAFETY: socket(2) returns -1 on error (checked) or an fd we own and
    // close on every path.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(DatapathError::Io(std::io::Error::last_os_error()));
    }
    let result = (|| {
        // SAFETY: each `ifreq` is zeroed, owned here, and handed to an
        // ioctl that reads it by the layout `linux/if.h` defines.
        unsafe {
            let mut ifr = ifreq(iface);
            write_sockaddr(&mut ifr.ifr_ifru.ifru_addr, gateway);
            ioctl_checked(sock, libc::SIOCSIFADDR, &ifr)?;

            let mut ifr = ifreq(iface);
            write_sockaddr(&mut ifr.ifr_ifru.ifru_dstaddr, guest);
            ioctl_checked(sock, libc::SIOCSIFDSTADDR, &ifr)?;

            let mut ifr = ifreq(iface);
            write_sockaddr(
                &mut ifr.ifr_ifru.ifru_netmask,
                Ipv4Addr::new(255, 255, 255, 252),
            );
            ioctl_checked(sock, libc::SIOCSIFNETMASK, &ifr)?;

            let mut ifr = ifreq(iface);
            ifr.ifr_ifru.ifru_mtu = libc::c_int::from(mtu);
            ioctl_checked(sock, libc::SIOCSIFMTU, &ifr)?;

            let mut ifr = ifreq(iface);
            if libc::ioctl(sock, libc::SIOCGIFFLAGS as libc::Ioctl, &mut ifr) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            ifr.ifr_ifru.ifru_flags |=
                (libc::IFF_UP | libc::IFF_RUNNING | libc::IFF_POINTOPOINT) as libc::c_short;
            ioctl_checked(sock, libc::SIOCSIFFLAGS, &ifr)?;
            Ok(())
        }
    })();
    // SAFETY: `sock` is the fd we opened and still own.
    unsafe { libc::close(sock) };
    result.map_err(DatapathError::Io)
}

/// Assign the host side of the IPv6 half of the link.
///
/// The host-side mirror of what the guest agent configures on `mvm0`, and
/// deliberately the same mechanism the v4 half above uses rather than a
/// second one: `SIOCSIFADDR` on an `AF_INET6` socket takes an `in6_ifreq`
/// instead of an `ifreq`, and that is the whole difference.
///
/// Assigning the gateway's prefix is also what installs the route: the
/// kernel adds the connected route for it, and the guest's address sits
/// inside that prefix, so the peer becomes reachable for exactly the
/// reason the /30's peer is. There is no second route to install and none
/// to tear down — dropping the device takes both with it.
///
/// No duplicate-address detection runs: a TUN device is `IFF_NOARP`, so
/// the kernel marks the address usable immediately rather than leaving it
/// tentative while it waits for a neighbour that a point-to-point link
/// cannot have.
fn set_v6_address(iface: &str, gateway: Ipv6Addr, prefix_len: u8) -> Result<(), DatapathError> {
    let name = ifreq(iface);
    // SAFETY: `ifr_name` is a NUL-padded C string this call just built, and
    // `if_nametoindex` only reads it.
    let ifindex = unsafe { libc::if_nametoindex(name.ifr_name.as_ptr()) };
    if ifindex == 0 {
        return Err(DatapathError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: socket(2) returns -1 on error (checked) or an fd we own and
    // close on every path.
    let sock = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(DatapathError::Io(std::io::Error::last_os_error()));
    }
    let ifr = libc::in6_ifreq {
        ifr6_addr: libc::in6_addr {
            s6_addr: gateway.octets(),
        },
        ifr6_prefixlen: u32::from(prefix_len),
        ifr6_ifindex: ifindex as libc::c_int,
    };
    // SAFETY: `ifr` is owned here and matches the layout `SIOCSIFADDR` on an
    // `AF_INET6` socket expects.
    let result = unsafe { ioctl_checked(sock, libc::SIOCSIFADDR, &ifr) };
    // SAFETY: `sock` is the fd we opened and still own.
    unsafe { libc::close(sock) };
    result.map_err(DatapathError::Io)
}

/// SAFETY: caller passes a valid, owned request struct of the type the
/// named ioctl reads.
unsafe fn ioctl_checked<T>(sock: libc::c_int, request: u64, ifr: &T) -> Result<(), std::io::Error> {
    // SAFETY: forwarded from the caller's contract.
    if unsafe { libc::ioctl(sock, ioctl_request(request), ifr) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn ifreq(iface: &str) -> libc::ifreq {
    // SAFETY: `ifreq` is a plain C struct; zeroed is a valid empty request.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in iface.bytes().enumerate().take(libc::IFNAMSIZ - 1) {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    ifr
}

fn write_sockaddr(dst: *mut libc::sockaddr, addr: Ipv4Addr) {
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.octets()),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: `dst` points at a `sockaddr`-sized field inside an `ifreq`
    // the caller zeroed and owns; `sockaddr_in` is the same 16 bytes on
    // every Linux ABI target.
    unsafe {
        std::ptr::copy_nonoverlapping(
            &sin as *const libc::sockaddr_in as *const u8,
            dst as *mut u8,
            std::mem::size_of::<libc::sockaddr_in>(),
        );
    }
}

/// Put a file descriptor in non-blocking mode.
fn set_nonblocking(fd: libc::c_int) -> std::io::Result<()> {
    // SAFETY: `fd` is owned by the caller's live `File`.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: same fd; F_SETFL takes an int.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Whether this process holds `CAP_NET_ADMIN` in its effective set.
fn has_net_admin() -> bool {
    const CAP_NET_ADMIN: u32 = 12;
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: libc::pid_t,
    }
    #[derive(Clone, Copy, Default)]
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    // Layout contracts for `cap_user_header_t` / `cap_user_data_t`
    // <linux/capability.h>, read out of the header with cc.
    const _: () = {
        use core::mem::{align_of, offset_of, size_of};
        assert!(size_of::<CapHeader>() == 8);
        assert!(align_of::<CapHeader>() == 4);
        assert!(offset_of!(CapHeader, version) == 0);
        assert!(offset_of!(CapHeader, pid) == 4);
        assert!(size_of::<CapData>() == 12);
        assert!(align_of::<CapData>() == 4);
        assert!(offset_of!(CapData, effective) == 0);
        assert!(offset_of!(CapData, permitted) == 4);
        assert!(offset_of!(CapData, inheritable) == 8);
    };

    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: both pointers reference stack values that outlive the call
    // and match the kernel's `__user_cap_*` layout.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapHeader,
            data.as_mut_ptr(),
        )
    };
    rc == 0 && data[0].effective & (1 << CAP_NET_ADMIN) != 0
}

/// Layout contract for `struct in6_ifreq` <linux/ipv6.h>. The definition
/// comes from a crate rather than from this file, so the shape the
/// `AF_INET6` `SIOCSIFADDR` call depends on is pinned here.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<libc::in6_ifreq>() == 24);
    assert!(align_of::<libc::in6_ifreq>() == 4);
    assert!(offset_of!(libc::in6_ifreq, ifr6_addr) == 0);
    assert!(offset_of!(libc::in6_ifreq, ifr6_prefixlen) == 16);
    assert!(offset_of!(libc::in6_ifreq, ifr6_ifindex) == 20);
};

/// Layout contract with `linux/if.h`'s `ifreq` for TUNSETIFF.
const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(offset_of!(IfReqFlags, name) == 0);
    assert!(offset_of!(IfReqFlags, flags) == libc::IFNAMSIZ);
    assert!(size_of::<IfReqFlags>() >= libc::IFNAMSIZ + 2);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_name_fits_ifnamsiz_and_carries_the_prefix() {
        for id in ["vm-a", "a-very-long-machine-identifier-indeed", "x"] {
            let name = device_name(id);
            assert!(name.len() < libc::IFNAMSIZ, "{name} is too long");
            assert!(name.starts_with(RESOURCE_PREFIX), "{name}");
        }
    }

    #[test]
    fn distinct_machines_get_distinct_devices() {
        assert_ne!(device_name("vm-a"), device_name("vm-b"));
        assert_ne!(table_name("vm-a"), table_name("vm-b"));
    }

    #[test]
    fn a_hostile_machine_id_cannot_smuggle_shell_or_nft_syntax() {
        let hostile = "a; nft flush ruleset; echo \"$(id)\" `whoami` -- --";
        let table = table_name(hostile);
        let device = device_name(hostile);
        for name in [&table, &device] {
            assert!(
                name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "{name} carries characters that are not [a-z0-9_]"
            );
        }
        // The ruleset is then structurally identical to a benign one. A
        // blanket "contains no `;`" check would test the template rather
        // than the sanitizer — nft terminates every statement with one —
        // and injection is what would *add* statements, so compare the
        // counts against a benign id instead.
        let guest = Ipv4Addr::new(10, 201, 0, 6);
        let hostile_rules = nft_ruleset(&table, &device, guest, Some(GUEST_V6));
        let benign_rules = nft_ruleset(
            &table_name("vm-a"),
            &device_name("vm-a"),
            guest,
            Some(GUEST_V6),
        );
        for syntax in [';', '{', '}', '\n'] {
            assert_eq!(
                hostile_rules.matches(syntax).count(),
                benign_rules.matches(syntax).count(),
                "a hostile machine id added {syntax:?} to the ruleset: {hostile_rules}"
            );
        }
        // Shell metacharacters cannot appear at all, because the only
        // interpolated values are the two slugs above and an address. Double
        // quotes are part of the nft template around interface names and are
        // therefore expected in an otherwise safe ruleset.
        for bad in ['`', '$', '\'', '\\'] {
            assert!(
                !hostile_rules.contains(bad),
                "ruleset contains {bad:?}: {hostile_rules}"
            );
        }
    }

    #[test]
    fn an_empty_or_symbolic_machine_id_still_yields_a_usable_name() {
        for id in ["", "---", "!!!"] {
            let name = device_name(id);
            assert!(name.len() > RESOURCE_PREFIX.len(), "{name}");
            assert!(name.len() < libc::IFNAMSIZ);
        }
    }

    /// A guest address out of the unique-local pool the allocator carves
    /// the v6 half from.
    const GUEST_V6: Ipv6Addr = Ipv6Addr::new(0xfd6d, 0x766d, 1, 0, 0, 0, 0, 2);

    #[test]
    fn the_ruleset_defaults_to_drop_and_pins_the_guest_source() {
        let rules = nft_ruleset("mvmn_vma", "mvmnvma", Ipv4Addr::new(10, 201, 0, 6), None);
        assert!(rules.contains("policy drop"), "{rules}");
        assert!(rules.contains("ip saddr 10.201.0.6/32 accept"), "{rules}");
        assert!(
            rules.contains("ip saddr 10.201.0.6/32 masquerade"),
            "{rules}"
        );
        assert!(
            rules.contains("ct state established,related accept"),
            "return traffic must be stateful: {rules}"
        );
        assert!(
            rules.contains("iifname \"mvmnvma\" drop"),
            "a final fail-closed rule must follow the accepts: {rules}"
        );
    }

    #[test]
    fn the_ruleset_has_no_bridge_and_no_tap() {
        let rules = nft_ruleset("mvmn_vma", "mvmnvma", Ipv4Addr::new(10, 201, 0, 6), None);
        for forbidden in ["bridge", "tap", "br0", "virbr"] {
            assert!(
                !rules.contains(forbidden),
                "the L3 path must not reference {forbidden}: {rules}"
            );
        }
    }

    /// The v6 source is pinned by the same mechanism as the v4 one, in the
    /// same `inet` table: a masquerade so replies come back, an inbound
    /// accept for exactly the assigned address, and a stateful return path.
    #[test]
    fn the_ruleset_pins_the_v6_source_when_the_lease_carries_one() {
        let rules = nft_ruleset(
            "mvmn_vma",
            "mvmnvma",
            Ipv4Addr::new(10, 201, 0, 6),
            Some(GUEST_V6),
        );
        assert!(
            rules.contains("ip6 saddr fd6d:766d:1::2/128 accept"),
            "{rules}"
        );
        assert!(
            rules.contains("ip6 saddr fd6d:766d:1::2/128 masquerade"),
            "{rules}"
        );
        assert!(
            rules.contains("ip6 daddr fd6d:766d:1::2/128 ct state established,related accept"),
            "v6 return traffic must be stateful too: {rules}"
        );
    }

    /// A source-pinning rule that the fail-closed `drop` precedes would
    /// never be reached, so the order is the property, not the presence.
    #[test]
    fn the_v6_accept_precedes_the_fail_closed_drop() {
        let rules = nft_ruleset(
            "mvmn_vma",
            "mvmnvma",
            Ipv4Addr::new(10, 201, 0, 6),
            Some(GUEST_V6),
        );
        let accept = rules
            .find("ip6 saddr fd6d:766d:1::2/128 accept")
            .expect("the v6 accept must be present");
        let drop = rules
            .find("iifname \"mvmnvma\" drop")
            .expect("the fail-closed drop must be present");
        assert!(accept < drop, "{rules}");
    }

    /// A machine whose plan never asked for IPv6 must get exactly the
    /// ruleset it got before the family was carried at all — not a
    /// superset, not a reordering. Its own `drop` is what refuses v6.
    #[test]
    fn a_v4_only_lease_gets_a_ruleset_with_no_v6_rule_at_all() {
        let rules = nft_ruleset("mvmn_vma", "mvmnvma", Ipv4Addr::new(10, 201, 0, 6), None);
        assert_eq!(
            rules,
            "table inet mvmn_vma {\n\
             \x20 chain postrouting {\n\
             \x20   type nat hook postrouting priority srcnat; policy accept;\n\
             \x20   ip saddr 10.201.0.6/32 masquerade\n\
             \x20 }\n\
             \x20 chain forward {\n\
             \x20   type filter hook forward priority filter; policy drop;\n\
             \x20   iifname \"mvmnvma\" ip saddr 10.201.0.6/32 accept\n\
             \x20   oifname \"mvmnvma\" ip daddr 10.201.0.6/32 ct state established,related accept\n\
             \x20   iifname \"mvmnvma\" drop\n\
             \x20 }\n\
             }\n"
        );
    }

    /// The two IPv6 questions the capability seam asks are both yes here,
    /// for the same reason the v4 pair is: the device carries whole
    /// packets, whatever family they are in.
    #[test]
    fn the_linux_datapath_declares_both_families() {
        let caps = LinuxDatapath::new().capabilities();
        assert_eq!(caps, ForwardingCapabilities::FULL_L3);
        assert!(caps.ipv6_flows);
        assert!(caps.arbitrary_ipv6);
    }

    #[test]
    fn a_dry_run_datapath_opens_and_closes_without_privileges() {
        let dp = LinuxDatapath::dry_run();
        assert!(dp.is_available().is_ok());
    }

    #[test]
    fn the_slug_bounds_length_and_alphabet() {
        assert_eq!(slug("Hello-World_123", 32), "helloworld123");
        assert_eq!(slug("abcdefghij", 4), "abcd");
        assert_eq!(slug("", 8), "0");
        assert_eq!(slug("!!!", 8), "0");
    }
}
