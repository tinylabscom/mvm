//! Host-side TUN device helpers for the shared network tunnel.
//!
//! This mirrors the guest-side packet-device seam, but keeps host packet I/O
//! explicitly host-owned. Later slices can hand a real host TUN into the tunnel
//! worker without changing backend transport or session-validation code.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};

#[cfg(not(target_os = "linux"))]
use anyhow::bail;
use anyhow::{Context, Result};
use mvm_core::protocol::network_tunnel::host_tun_nat_table_name;

/// Blocking packet device abstraction used by host-side tunnel forwarding.
pub trait PacketDevice {
    fn interface_name(&self) -> &str;
    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn write_packet(&mut self, packet: &[u8]) -> Result<usize>;
}

/// Blocking host TUN device.
#[derive(Debug)]
pub struct HostTunDevice {
    interface_name: String,
    file: File,
}

impl HostTunDevice {
    /// Open `/dev/net/tun` and bind it to the given interface name.
    #[cfg(target_os = "linux")]
    pub fn open_named(interface_name: &str) -> Result<Self> {
        let name = encode_iface_name(interface_name)
            .map_err(anyhow::Error::msg)
            .with_context(|| "validate tunnel interface name")?;
        let file = File::options()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .with_context(|| "open /dev/net/tun")?;

        bind_named_tun(&file, name)
            .with_context(|| format!("bind host tunnel interface {interface_name}"))?;
        Ok(Self {
            interface_name: interface_name.to_string(),
            file,
        })
    }

    /// Non-Linux hosts compile the workspace but cannot create host TUNs.
    #[cfg(not(target_os = "linux"))]
    pub fn open_named(interface_name: &str) -> Result<Self> {
        encode_iface_name(interface_name)
            .map_err(anyhow::Error::msg)
            .with_context(|| "validate tunnel interface name")?;
        bail!("host tunnel devices are only supported on Linux")
    }

    pub fn into_file(self) -> File {
        self.file
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl AsRawFd for HostTunDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl PacketDevice for HostTunDevice {
    fn interface_name(&self) -> &str {
        &self.interface_name
    }

    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.file
            .read(buf)
            .with_context(|| format!("read packet from {}", self.interface_name))
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<usize> {
        self.file
            .write(packet)
            .with_context(|| format!("write packet to {}", self.interface_name))
    }
}

pub fn validate_interface_name(interface_name: &str) -> Result<(), String> {
    encode_iface_name(interface_name).map(|_| ())
}

/// Address assigned to the host TUN gateway endpoint. The guest's admitted
/// packets egress via this link, then get source-NATed onto the real network.
pub const HOST_TUN_GATEWAY_CIDR: &str = "10.240.0.1/30";
/// Source subnet masqueraded out the host's egress interface. Matches the
/// `/30` the gateway address lives in, so only tunnel-originated traffic is
/// rewritten.
pub const HOST_TUN_LINK_CIDR: &str = "10.240.0.0/30";

/// Errors composing or applying the host TUN egress link + NAT.
#[derive(Debug, thiserror::Error)]
pub enum TunnelNatError {
    #[error("invalid interface name {value:?}: only [A-Za-z0-9_.-] permitted, under IFNAMSIZ")]
    InvalidInterface { value: String },
    #[error("egress interface discovery failed: {0}")]
    EgressDiscovery(String),
    #[error("host TUN egress link + NAT is only supported on Linux")]
    LinuxOnly,
    #[error("{context}: {detail}")]
    Command { context: String, detail: String },
}

/// Reject anything that isn't a safe interface slug before it reaches an `nft`
/// or `ip` invocation, so a crafted name can't inject a second command.
fn validate_nat_interface(interface_name: &str) -> Result<(), TunnelNatError> {
    let ok = !interface_name.is_empty()
        && interface_name.len() < libc::IFNAMSIZ
        && interface_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if ok {
        Ok(())
    } else {
        Err(TunnelNatError::InvalidInterface {
            value: interface_name.to_string(),
        })
    }
}

/// Compose the nftables masquerade ruleset that source-NATs tunnel-link
/// traffic out `egress_iface`. Pure: returns the script text so callers can
/// assert the rule shape without touching the kernel. The table is scoped to
/// `link_iface` so teardown removes exactly what setup added.
pub fn build_tunnel_masquerade_rules(
    link_iface: &str,
    egress_iface: &str,
) -> Result<String, TunnelNatError> {
    validate_nat_interface(link_iface)?;
    validate_nat_interface(egress_iface)?;
    let table = host_tun_nat_table_name(link_iface);
    Ok(format!(
        "table ip {table} {{\n\
         \tchain postrouting {{\n\
         \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
         \t\tip saddr {HOST_TUN_LINK_CIDR} oifname \"{egress_iface}\" masquerade\n\
         \t}}\n\
         }}\n"
    ))
}

/// Compose the teardown script removing the per-link NAT table. Idempotent on
/// the `nft` side only if the table exists; callers tolerate the not-found
/// error on a double teardown.
pub fn build_tunnel_masquerade_teardown(link_iface: &str) -> Result<String, TunnelNatError> {
    validate_nat_interface(link_iface)?;
    Ok(format!(
        "delete table ip {}\n",
        host_tun_nat_table_name(link_iface)
    ))
}

/// Parse the default-route interface out of `/proc/net/route` contents. The
/// default route is the row whose destination and mask are both `00000000`;
/// its first column is the interface name. Pure so it can be unit-tested
/// without `/proc`.
pub fn parse_default_route_iface(proc_net_route: &str) -> Option<String> {
    for line in proc_net_route.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let iface = cols.next()?;
        let destination = cols.next()?;
        if destination.eq_ignore_ascii_case("00000000") {
            return Some(iface.to_string());
        }
    }
    None
}

/// Discover the host's default egress interface. Linux-only: reads
/// `/proc/net/route`.
#[cfg(target_os = "linux")]
pub fn default_egress_interface() -> Result<String, TunnelNatError> {
    let contents = std::fs::read_to_string("/proc/net/route")
        .map_err(|e| TunnelNatError::EgressDiscovery(format!("read /proc/net/route: {e}")))?;
    parse_default_route_iface(&contents).ok_or_else(|| {
        TunnelNatError::EgressDiscovery("no default route in /proc/net/route".into())
    })
}

/// Bring the host TUN up with the gateway address and install the masquerade
/// NAT rule out the discovered default egress interface. Linux-only; the guest
/// TUN must already be open (the worker owns its fd) before the address is
/// assigned.
#[cfg(target_os = "linux")]
pub fn setup_host_tun_egress(link_iface: &str) -> Result<(), TunnelNatError> {
    validate_nat_interface(link_iface)?;
    let egress = default_egress_interface()?;
    run_ip(
        &["addr", "add", HOST_TUN_GATEWAY_CIDR, "dev", link_iface],
        true,
    )?;
    run_ip(&["link", "set", "dev", link_iface, "up"], false)?;
    let rules = build_tunnel_masquerade_rules(link_iface, &egress)?;
    apply_nft_rules(&rules)?;
    Ok(())
}

/// Non-Linux hosts compile but cannot install the egress link + NAT.
#[cfg(not(target_os = "linux"))]
pub fn setup_host_tun_egress(link_iface: &str) -> Result<(), TunnelNatError> {
    validate_nat_interface(link_iface)?;
    Err(TunnelNatError::LinuxOnly)
}

/// Remove the masquerade NAT table and gateway address for `link_iface`.
/// Best-effort: a missing table or address is not an error.
#[cfg(target_os = "linux")]
pub fn teardown_host_tun_egress(link_iface: &str) -> Result<(), TunnelNatError> {
    validate_nat_interface(link_iface)?;
    let rules = build_tunnel_masquerade_teardown(link_iface)?;
    // Tolerate a missing table (already torn down) but surface other failures.
    if let Err(err) = apply_nft_rules(&rules) {
        tracing::debug!(%link_iface, error = %err, "host TUN NAT teardown: nft delete tolerated");
    }
    let _ = run_ip(
        &["addr", "del", HOST_TUN_GATEWAY_CIDR, "dev", link_iface],
        true,
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn teardown_host_tun_egress(link_iface: &str) -> Result<(), TunnelNatError> {
    validate_nat_interface(link_iface)?;
    Err(TunnelNatError::LinuxOnly)
}

/// Convert a graceful stop signal (`SIGTERM`/`SIGINT`) into an egress teardown
/// for `interface_name` before the process exits. Defense in depth: a caught
/// stop still removes the per-VM NAT table a hard `SIGKILL` would otherwise
/// leak (the backend reap sweep covers the uncatchable `SIGKILL` path).
///
/// The stop signals are blocked process-wide and consumed by one dedicated
/// thread via `sigwait`, so teardown runs on a normal stack — `nft`/`ip` exec is
/// not async-signal-safe and must never run inside a signal handler. Call this
/// only on the forwarding path, after the NAT is installed: a worker with no NAT
/// must keep the default terminate-on-`SIGTERM` disposition so a normal reap
/// stops it without escalating to `SIGKILL`.
#[cfg(target_os = "linux")]
pub fn install_egress_teardown_on_stop_signal(interface_name: String) {
    let set = stop_signal_set();
    // SAFETY: `set` is a fully initialised sigset; blocking these signals in the
    // current (main) thread makes every later-spawned thread inherit the block,
    // so only the sigwait thread below observes them.
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
    let _ = std::thread::Builder::new()
        .name("tunnel-egress-teardown".into())
        .spawn(move || {
            let set = stop_signal_set();
            let mut sig: libc::c_int = 0;
            // SAFETY: `set` and `sig` are valid; sigwait blocks until one of the
            // blocked stop signals is delivered, returning its number in `sig`.
            let rc = unsafe { libc::sigwait(&set, &mut sig) };
            if rc == 0
                && let Err(err) = teardown_host_tun_egress(&interface_name)
            {
                tracing::warn!(%interface_name, error = %err, "stop-signal host TUN egress teardown failed");
            }
            // Whatever stopped us is going away; a clean status keeps a waiter
            // from treating the graceful stop as a crash.
            std::process::exit(0);
        });
}

/// Non-Linux hosts never install the host TUN egress, so there is nothing to
/// tear down on a stop signal.
#[cfg(not(target_os = "linux"))]
pub fn install_egress_teardown_on_stop_signal(_interface_name: String) {}

/// The stop signals converted into a graceful egress teardown. Shared by the
/// process-wide mask and the sigwait so both always agree on the set.
#[cfg(target_os = "linux")]
fn stop_signal_set() -> libc::sigset_t {
    // SAFETY: zero-init then populate via the libc sigset helpers, the standard
    // construction pattern; the value is fully initialised on return.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        set
    }
}

/// Run `ip <args>`. When `tolerate_exists` is set, an `EEXIST`-style failure
/// (address already present) is treated as success so setup stays idempotent.
#[cfg(target_os = "linux")]
fn run_ip(args: &[&str], tolerate_exists: bool) -> Result<(), TunnelNatError> {
    let output = std::process::Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| TunnelNatError::Command {
            context: format!("spawn ip {}", args.join(" ")),
            detail: e.to_string(),
        })?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if tolerate_exists && stderr.to_ascii_lowercase().contains("exists") {
        return Ok(());
    }
    Err(TunnelNatError::Command {
        context: format!("ip {}", args.join(" ")),
        detail: stderr.trim().to_string(),
    })
}

/// Apply an nftables script, reusing the host firewall's `nft -f -` boundary.
#[cfg(target_os = "linux")]
fn apply_nft_rules(rules: &str) -> Result<(), TunnelNatError> {
    crate::supervisor::firewall::linux_nft::apply(rules).map_err(|e| TunnelNatError::Command {
        context: "apply host TUN NAT rules".to_string(),
        detail: e.to_string(),
    })
}

fn encode_iface_name(iface: &str) -> Result<[libc::c_char; libc::IFNAMSIZ], String> {
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

// `libc::TUNSETIFF` is `Ioctl`-typed, which is `u64` on gnu/64-bit but `i32`
// on musl — the `as u64` normalizes it and is not redundant on every target.
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_cast)]
const TUNSETIFF_REQUEST: libc::Ioctl = target_ioctl_request(libc::TUNSETIFF as u64);

#[cfg(target_os = "linux")]
const fn target_ioctl_request(request: u64) -> libc::Ioctl {
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

#[cfg(target_os = "linux")]
fn bind_named_tun(file: &File, interface_name: [libc::c_char; libc::IFNAMSIZ]) -> Result<()> {
    // SAFETY: `ifreq` is repr(C); zero-init + union assignment is the standard
    // tuntap ioctl pattern, and the fd comes from an owned open of /dev/net/tun.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_name = interface_name;
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    let fd = file.as_raw_fd();
    // SAFETY: `fd` is a valid tun device fd and `ifr` points to initialized storage.
    let rc = unsafe { libc::ioctl(fd, TUNSETIFF_REQUEST, &ifr) };
    if rc < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_named_rejects_oversize_interface_names_before_os_work() {
        let over = "a".repeat(libc::IFNAMSIZ);
        let err = HostTunDevice::open_named(&over).expect_err("oversize name rejected");
        assert!(err.to_string().contains("interface name"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::unnecessary_cast)]
    fn tun_ioctl_request_fits_target_request_type() {
        assert_eq!(TUNSETIFF_REQUEST as u64, libc::TUNSETIFF as u64);
    }

    #[test]
    fn nat_rule_shape_masquerades_tunnel_link() {
        let rules = build_tunnel_masquerade_rules("mvmht0", "eth0").expect("compose rules");
        assert!(
            rules.contains("table ip mvm_tun_nat_mvmht0"),
            "missing scoped table: {rules}"
        );
        assert!(
            rules.contains("type nat hook postrouting priority srcnat"),
            "missing srcnat hook: {rules}"
        );
        assert!(
            rules.contains("ip saddr 10.240.0.0/30 oifname \"eth0\" masquerade"),
            "missing masquerade rule: {rules}"
        );
    }

    #[test]
    fn nat_teardown_scopes_to_the_link_table() {
        let rules = build_tunnel_masquerade_teardown("mvmht0").expect("compose teardown");
        assert_eq!(rules, "delete table ip mvm_tun_nat_mvmht0\n");
    }

    #[test]
    fn host_tun_nat_table_name_is_stable_and_matches_composed_rule() {
        // The shared name fn is the one source of truth: the setup rule and the
        // teardown script must both embed exactly what it returns for an iface.
        let iface = "mvmht0";
        let table = host_tun_nat_table_name(iface);
        assert_eq!(table, "mvm_tun_nat_mvmht0");

        let rules = build_tunnel_masquerade_rules(iface, "eth0").expect("compose rules");
        assert!(
            rules.contains(&format!("table ip {table} {{")),
            "setup rule must embed the shared table name: {rules}"
        );

        let teardown = build_tunnel_masquerade_teardown(iface).expect("compose teardown");
        assert_eq!(teardown, format!("delete table ip {table}\n"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stop_signal_set_covers_term_and_int_only() {
        let set = stop_signal_set();
        // SAFETY: `set` is a valid sigset; sigismember only reads it.
        assert_eq!(unsafe { libc::sigismember(&set, libc::SIGTERM) }, 1);
        assert_eq!(unsafe { libc::sigismember(&set, libc::SIGINT) }, 1);
        // The uncatchable signals are never in the graceful-stop set.
        assert_eq!(unsafe { libc::sigismember(&set, libc::SIGKILL) }, 0);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn install_egress_teardown_is_noop_off_linux() {
        // Off Linux there is no host TUN egress; the installer must simply
        // return without blocking signals or spawning a consumer thread.
        install_egress_teardown_on_stop_signal("mvmht0".to_string());
    }

    #[test]
    fn nat_rules_reject_unsafe_interface_names() {
        assert!(matches!(
            build_tunnel_masquerade_rules("mvmht0; rm -rf /", "eth0"),
            Err(TunnelNatError::InvalidInterface { .. })
        ));
        assert!(matches!(
            build_tunnel_masquerade_rules("mvmht0", "eth0\"drop"),
            Err(TunnelNatError::InvalidInterface { .. })
        ));
        assert!(matches!(
            build_tunnel_masquerade_rules("", "eth0"),
            Err(TunnelNatError::InvalidInterface { .. })
        ));
    }

    #[test]
    fn parse_default_route_iface_picks_the_zero_destination_row() {
        let route = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
eth0\t00000000\t0102000A\t0003\t0\t0\t100\t00000000\n\
eth0\t0002000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\n";
        assert_eq!(parse_default_route_iface(route).as_deref(), Some("eth0"));
    }

    #[test]
    fn parse_default_route_iface_returns_none_without_default() {
        let route = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
eth0\t0002000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\n";
        assert!(parse_default_route_iface(route).is_none());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn setup_and_teardown_egress_are_linux_only_off_linux() {
        assert!(matches!(
            setup_host_tun_egress("mvmht0"),
            Err(TunnelNatError::LinuxOnly)
        ));
        assert!(matches!(
            teardown_host_tun_egress("mvmht0"),
            Err(TunnelNatError::LinuxOnly)
        ));
    }
}
