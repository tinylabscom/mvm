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
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::path::Path;
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
const NFT_TABLE: &str = "mvmn";
const NFT_FORWARD_CHAIN: &str = "forward";
const NFT_POSTROUTING_CHAIN: &str = "postrouting";

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
        // policy layer understands works. IPv6 stays off until the workload
        // kernel enables it — claiming it would be claiming a datapath that
        // has no guest address to talk to.
        ForwardingCapabilities::FULL_L3_V4
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
    nft_applied: bool,
    closed: bool,
    dry_run: bool,
}

impl LinuxHandle {
    /// Assign the host side of the link, set the MTU, bring it up, install
    /// exactly one route for the machine's /30, and load the nftables rules.
    fn configure(&mut self, req: &DatapathRequest) -> Result<(), DatapathError> {
        if self.dry_run {
            self.nft_applied = true;
            return Ok(());
        }
        set_point_to_point(&self.iface, req.gateway, req.guest, req.mtu)?;
        let _lock = nft_lock()?;
        if let Err(error) = install_nft(&self.table, &self.iface, &self.machine_id, req.guest) {
            let _ = remove_shared_table_if_empty(&self.table);
            return Err(error);
        }
        self.nft_applied = true;
        Ok(())
    }

    /// The nftables ruleset this handle installed. Exposed so the shape is
    /// assertable without root.
    pub fn ruleset(&self) -> String {
        nft_ruleset(&self.table, &self.iface, self.guest)
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
        if self.dry_run {
            self.closed = true;
            self.file = None;
            return Ok(());
        }
        // Deterministic teardown: the rules go, then the device. Dropping
        // the TUN's last fd is what removes the interface — and its
        // addresses and routes with it — so the descriptor has to go here
        // rather than whenever the handle happens to be dropped.
        //
        // Cleanup also runs on the failed-setup path, where some of the
        // resources were never created. Surface a lock or nft failure to an
        // explicit close caller; Drop still makes a best-effort attempt.
        let result = if self.nft_applied {
            match nft_lock() {
                Ok(lock) => {
                    let result = delete_machine_nft(&self.table, &self.iface, &self.machine_id);
                    drop(lock);
                    result
                }
                Err(error) => Err(error),
            }
        } else {
            Ok(())
        };
        self.file = None;
        if result.is_ok() {
            self.nft_applied = false;
            self.closed = true;
        }
        result
    }

    fn description(&self) -> String {
        format!(
            "linux host tun {} (table {}) for {}",
            self.iface, self.table, self.machine_id
        )
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

/// nftables table shared by all machine-scoped chains.
pub fn table_name(_machine_id: &str) -> String {
    NFT_TABLE.to_string()
}

/// Filter chain for one machine inside the shared nftables table.
pub fn forward_chain_name(machine_id: &str) -> String {
    format!("{RESOURCE_PREFIX}_f_{}", slug(machine_id, 32))
}

/// NAT chain for one machine inside the shared nftables table.
pub fn nat_chain_name(machine_id: &str) -> String {
    format!("{RESOURCE_PREFIX}_n_{}", slug(machine_id, 32))
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

/// A complete shared-table ruleset containing the first machine's chains.
///
/// The shared forward base chain owns the host-wide default drop. Each
/// machine gets regular chains reached only by interface-scoped jumps, so a
/// machine's rules cannot drop packets belonging to another machine.
fn nft_ruleset(table: &str, iface: &str, guest: Ipv4Addr) -> String {
    let forward_chain = forward_chain_name(iface);
    let nat_chain = nat_chain_name(iface);
    format!(
        "add table inet {table}\n\
         add chain inet {table} {NFT_POSTROUTING_CHAIN} {{ type nat hook postrouting priority srcnat; policy accept; }}\n\
         add chain inet {table} {NFT_FORWARD_CHAIN} {{ type filter hook forward priority filter; policy drop; }}\n\
         {machine_rules}",
        machine_rules = machine_ruleset(table, iface, guest, &forward_chain, &nat_chain,)
    )
}

fn shared_table_ruleset(table: &str) -> String {
    format!(
        "add table inet {table}\n\
         add chain inet {table} {NFT_POSTROUTING_CHAIN} {{ type nat hook postrouting priority srcnat; policy accept; }}\n\
         add chain inet {table} {NFT_FORWARD_CHAIN} {{ type filter hook forward priority filter; policy drop; }}\n"
    )
}

fn machine_ruleset(
    table: &str,
    iface: &str,
    guest: Ipv4Addr,
    forward_chain: &str,
    nat_chain: &str,
) -> String {
    format!(
        "add chain inet {table} {forward_chain}\n\
         add chain inet {table} {nat_chain}\n\
         add rule inet {table} {NFT_FORWARD_CHAIN} iifname \"{iface}\" jump {forward_chain}\n\
         add rule inet {table} {NFT_FORWARD_CHAIN} oifname \"{iface}\" jump {forward_chain}\n\
         add rule inet {table} {NFT_POSTROUTING_CHAIN} iifname \"{iface}\" jump {nat_chain}\n\
         add rule inet {table} {forward_chain} iifname \"{iface}\" ip saddr {guest}/32 counter accept\n\
         add rule inet {table} {forward_chain} iifname \"{iface}\" drop\n\
         add rule inet {table} {forward_chain} oifname \"{iface}\" ip daddr {guest}/32 ct state established,related counter accept\n\
         add rule inet {table} {forward_chain} oifname \"{iface}\" drop\n\
         add rule inet {table} {nat_chain} iifname \"{iface}\" ip saddr {guest}/32 masquerade\n"
    )
}

fn install_nft(
    table: &str,
    iface: &str,
    machine_id: &str,
    guest: Ipv4Addr,
) -> Result<(), DatapathError> {
    ensure_shared_table(table)?;
    let forward_chain = forward_chain_name(machine_id);
    let nat_chain = nat_chain_name(machine_id);
    apply_nft(&machine_ruleset(
        table,
        iface,
        guest,
        &forward_chain,
        &nat_chain,
    ))
}

fn ensure_shared_table(table: &str) -> Result<(), DatapathError> {
    if !nft_table_exists_for_runtime(table)? {
        apply_nft(&shared_table_ruleset(table))?;
    }
    let forward = list_nft_chain(table, NFT_FORWARD_CHAIN)?;
    if !forward.contains("type filter hook forward") || !forward.contains("policy drop") {
        return Err(DatapathError::PrivilegeRequired {
            operation: "validating the shared nftables forward policy",
            detail: "the mvm-owned forward chain is missing its default drop policy".to_string(),
        });
    }
    let postrouting = list_nft_chain(table, NFT_POSTROUTING_CHAIN)?;
    if !postrouting.contains("type nat hook postrouting") || !postrouting.contains("policy accept")
    {
        return Err(DatapathError::PrivilegeRequired {
            operation: "validating the shared nftables NAT policy",
            detail: "the mvm-owned postrouting chain is missing its accept policy".to_string(),
        });
    }
    Ok(())
}

fn nft_lock() -> Result<mvm_core::util::atomic_io::FileLock, DatapathError> {
    let runtime =
        mvm_core::config::ensure_runtime_dir().map_err(|source| DatapathError::SetupFailed {
            what: "nftables lock directory",
            machine_id: String::new(),
            source,
        })?;
    mvm_core::util::atomic_io::FileLock::acquire(&Path::new(&runtime).join("netd-nftables"))
        .map_err(|error| DatapathError::SetupFailed {
            what: "nftables lock",
            machine_id: String::new(),
            source: std::io::Error::other(error.to_string()),
        })
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

fn nft_table_exists_for_runtime(table: &str) -> Result<bool, DatapathError> {
    let output = Command::new("nft")
        .args(["list", "table", "inet", table])
        .output()
        .map_err(|source| DatapathError::SetupFailed {
            what: "nft",
            machine_id: String::new(),
            source,
        })?;
    Ok(output.status.success())
}

fn list_nft_chain(table: &str, chain: &str) -> Result<String, DatapathError> {
    let output = Command::new("nft")
        .args(["-a", "list", "chain", "inet", table, chain])
        .output()
        .map_err(|source| DatapathError::SetupFailed {
            what: "nft",
            machine_id: String::new(),
            source,
        })?;
    if !output.status.success() {
        return Err(DatapathError::PrivilegeRequired {
            operation: "listing nftables rules",
            detail: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn delete_machine_nft(table: &str, iface: &str, machine_id: &str) -> Result<(), DatapathError> {
    if !nft_table_exists_for_runtime(table)? {
        return Ok(());
    }
    let forward_chain = forward_chain_name(machine_id);
    let nat_chain = nat_chain_name(machine_id);
    let forward = list_nft_chain(table, NFT_FORWARD_CHAIN)?;
    let postrouting = list_nft_chain(table, NFT_POSTROUTING_CHAIN)?;
    let mut rules = String::new();
    for handle in jump_handles(&forward, &forward_chain, iface)? {
        rules.push_str(&format!(
            "delete rule inet {table} {NFT_FORWARD_CHAIN} handle {handle}\n"
        ));
    }
    for handle in jump_handles(&postrouting, &nat_chain, iface)? {
        rules.push_str(&format!(
            "delete rule inet {table} {NFT_POSTROUTING_CHAIN} handle {handle}\n"
        ));
    }
    rules.push_str(&format!(
        "delete chain inet {table} {forward_chain}\n\
         delete chain inet {table} {nat_chain}\n"
    ));
    apply_nft(&rules)?;
    remove_shared_table_if_empty(table)
}

fn jump_handles(
    chain_listing: &str,
    target_chain: &str,
    iface: &str,
) -> Result<Vec<u64>, DatapathError> {
    let target = format!("jump {target_chain}");
    let interface = format!("\"{iface}\"");
    let mut handles = Vec::new();
    for line in chain_listing.lines() {
        if !line.contains(&target) || !line.contains(&interface) {
            continue;
        }
        let handle = line
            .split("# handle ")
            .nth(1)
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| DatapathError::PrivilegeRequired {
                operation: "identifying nftables teardown rules",
                detail: format!("rule for {iface} has no nft handle"),
            })?;
        handles.push(handle);
    }
    Ok(handles)
}

fn remove_shared_table_if_empty(table: &str) -> Result<(), DatapathError> {
    if !nft_table_exists_for_runtime(table)? {
        return Ok(());
    }
    let listing = {
        let output = Command::new("nft")
            .args(["list", "table", "inet", table])
            .output()
            .map_err(|source| DatapathError::SetupFailed {
                what: "nft",
                machine_id: String::new(),
                source,
            })?;
        if !output.status.success() {
            return Ok(());
        }
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let has_machine_chain = listing.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with("chain mvmn_f_") || trimmed.starts_with("chain mvmn_n_")
    });
    if !has_machine_chain {
        let rules = format!("delete table inet {table}\n");
        apply_nft(&rules)?;
    }
    Ok(())
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

/// SAFETY: caller passes a valid, owned `ifreq` for the named request.
unsafe fn ioctl_checked(
    sock: libc::c_int,
    request: u64,
    ifr: &libc::ifreq,
) -> Result<(), std::io::Error> {
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
        assert_eq!(table_name("vm-a"), table_name("vm-b"));
        assert_ne!(forward_chain_name("vm-a"), forward_chain_name("vm-b"));
        assert_ne!(nat_chain_name("vm-a"), nat_chain_name("vm-b"));
    }

    #[test]
    fn a_hostile_machine_id_cannot_smuggle_shell_or_nft_syntax() {
        let hostile = "a; nft flush ruleset; echo \"$(id)\" `whoami` -- --";
        let device = device_name(hostile);
        let forward = forward_chain_name(hostile);
        let nat = nat_chain_name(hostile);
        for name in [&forward, &nat, &device] {
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
        let hostile_rules = nft_ruleset(&table_name(hostile), &device, guest);
        let benign_rules = nft_ruleset(&table_name("vm-a"), &device_name("vm-a"), guest);
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

    #[test]
    fn the_ruleset_keeps_one_shared_default_drop_and_pins_the_guest_source() {
        let rules = nft_ruleset("mvmn_vma", "mvmnvma", Ipv4Addr::new(10, 201, 0, 6));
        assert!(rules.contains("policy drop"), "{rules}");
        assert!(
            rules.contains("ip saddr 10.201.0.6/32 counter accept"),
            "{rules}"
        );
        assert!(
            rules.contains("ip saddr 10.201.0.6/32 masquerade"),
            "{rules}"
        );
        assert!(
            rules.contains("ct state established,related counter accept"),
            "return traffic must be stateful: {rules}"
        );
        assert!(
            rules.contains("iifname \"mvmnvma\" drop"),
            "a final fail-closed rule must follow the accepts: {rules}"
        );
        assert!(rules.contains("jump mvmn_f_mvmnvma"), "{rules}");
        assert!(rules.contains("jump mvmn_n_mvmnvma"), "{rules}");
        assert_eq!(
            rules.matches("type filter hook forward").count(),
            1,
            "the shared table must own exactly one forward base chain: {rules}"
        );
    }

    #[test]
    fn the_ruleset_has_no_bridge_and_no_tap() {
        let rules = nft_ruleset("mvmn_vma", "mvmnvma", Ipv4Addr::new(10, 201, 0, 6));
        for forbidden in ["bridge", "tap", "br0", "virbr"] {
            assert!(
                !rules.contains(forbidden),
                "the L3 path must not reference {forbidden}: {rules}"
            );
        }
    }

    #[test]
    fn jump_handles_only_select_the_named_machine_interface() {
        let listing = r#"
            iifname "mvmna" jump mvmn_f_a # handle 11
            iifname "mvmnb" jump mvmn_f_b # handle 12
            oifname "mvmna" jump mvmn_f_a # handle 13
        "#;
        assert_eq!(
            jump_handles(listing, "mvmn_f_a", "mvmna").expect("handles"),
            vec![11, 13]
        );
        assert!(
            jump_handles(listing, "mvmn_f_a", "mvmnb")
                .expect("matching interface has no malformed handles")
                .is_empty()
        );
    }

    #[test]
    fn jump_handles_reject_a_matching_rule_without_a_kernel_handle() {
        let listing = r#"iifname "mvmna" jump mvmn_f_a"#;
        assert!(jump_handles(listing, "mvmn_f_a", "mvmna").is_err());
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
