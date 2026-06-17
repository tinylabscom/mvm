//! Host-side classification of a builder VM's network-bootstrap outcome.
//!
//! The guest-side network bring-up (ioctls, udhcpc, static config) now lives in
//! [`mvm_guest::guest_net`] — shared by the builder init and the workload
//! netinit. What remains here is host-only: parsing the builder VM's
//! `console.log` to report how its network came up (DHCP lease vs static
//! fallback vs failure), surfaced by `mvmctl doctor`.

use mvm_guest::guest_net::parse_ipv4;

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
/// Robust to interleaved log noise: only the known markers are matched,
/// anything else is ignored.
pub fn classify_builder_net_bootstrap(console_log: &str) -> BuilderNetBootstrap {
    let mut outcome = BuilderNetBootstrap::Unknown;
    for line in console_log.lines() {
        if let Some(ip) = parse_udhcpc_lease_ip(line) {
            outcome = BuilderNetBootstrap::Lease { ip };
        } else if line.contains("falling back to static gvproxy addressing") {
            outcome = BuilderNetBootstrap::StaticFallback {
                ip: GVPROXY_STATIC_FALLBACK_IP.to_string(),
            };
        } else if (line.contains("setup_network warning (non-fatal)")
            || line.contains("guest-net:"))
            && line.contains("udhcpc exit")
            && !line.contains("falling back")
        {
            outcome = BuilderNetBootstrap::Failed;
        }
    }
    outcome
}

/// Extract the leased IP from a busybox udhcpc lease line, if this is one.
///
/// Matches `udhcpc: lease of <ip> obtained from ...` and returns `<ip>`.
/// The address is validated through [`parse_ipv4`] so a malformed token
/// isn't reported as a lease.
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
guest-net: udhcpc exit 1 — falling back to static gvproxy addressing (192.168.127.3)";
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
guest-net: spawn /bin/udhcpc: udhcpc exit 1";
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
        let log = "\
udhcpc: lease of 192.168.127.3 obtained from 192.168.127.1, lease time 3600
--- reboot ---
guest-net: udhcpc exit 1 — falling back to static gvproxy addressing (192.168.127.3)";
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
