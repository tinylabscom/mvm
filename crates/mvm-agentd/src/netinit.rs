//! Guest-side network defense.
//!
//! Installs kernel **blackhole routes** for every IPv4 entry in
//! [`mvm_core::network_policy::MANDATORY_DENY_RANGES`] inside the
//! microVM at boot, before the workload entrypoint forks.
//!
//! ## Why kernel routes (not nftables / iptables)
//!
//! The microVM's rootfs is user-controlled. Nix-built rootfs has
//! busybox (no `nft`, no `iptables`); OCI-imported rootfs might be
//! `alpine` (has both), `python:3.12-slim` (neither), `distroless`
//! (neither), or anything else. A defense layer that depends on a
//! userspace tool inside the guest fails on most images.
//!
//! Kernel-side blackhole routes are universal — every Linux kernel
//! supports `RTN_BLACKHOLE` since 2.0, no userspace tool required.
//! We talk directly to the kernel over a synchronous `AF_NETLINK`
//! socket; the only dependency is a Linux kernel.
//!
//! ## Why this is defense-in-depth, not the sole defense
//!
//! A workload that gains root inside the guest can `ip route del`
//! the blackhole routes (CAP_NET_ADMIN inside the guest's netns).
//! That's why this layer pairs with host-side enforcement (mvm
//! iptables on Linux-direct; mvmd nftables on fleet). The
//! guest-side floor catches:
//!
//! - the macOS Apple Container path where mvm has no host firewall;
//! - the legitimate uid-0 dev workload that doesn't actively try to
//!   defeat the routes;
//! - any workload that doesn't gain root.
//!
//! The two layers together make IMDS-style exfil substantially
//! harder regardless of which platform the microVM runs on.
//!
//! ## Audit emission
//!
//! `install_mandatory_deny` returns a `Report` describing what
//! was installed (and what failed). The caller — typically the
//! `mvm-guest-netinit` binary running from `/init` — writes the
//! report as a single JSON line to stdout, which the kernel
//! console forwards to the host. A future slice wires the agent
//! to forward the report as a `LocalAuditKind::NetworkMandatoryDeny`
//! audit event via vsock; for v1 the console-scrape path is
//! sufficient to surface install failures.
//!
//! ## Failure semantics
//!
//! Any per-route failure is recorded in the report but does NOT
//! abort the install loop — we want every successful route to
//! land even if one fails. The binary exits non-zero when the
//! report carries any failures, so `/init` can fail-closed
//! (refuse to fork the workload entrypoint).

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Canonical line marker that the `mvm-guest-netinit` binary
/// prefixes to its JSON output line. The host-side console
/// scrape greps for this to extract the [`Report`] from the
/// VM's console log (firecracker.log on FC, libkrun console
/// output on libkrun). Keeping the marker as a public const here
/// — not duplicated in both the binary and the host parser —
/// means a future rename surfaces immediately as a compile
/// failure on both sides.
///
/// The marker is deliberately distinctive: a sequence the
/// kernel and busybox both stay away from. Underscores +
/// uppercase + double-underscore framing puts it well outside
/// any reasonable log message.
pub const REPORT_MARKER: &str = "__MVM_NETINIT_REPORT__";

/// Parse a console log buffer for the netinit report.
///
/// Scans `log` line-by-line for [`REPORT_MARKER`]; the *last*
/// matching line wins (a workload might restart and re-run
/// netinit, in which case the latest report reflects the live
/// kernel route state). Returns `None` if no marker is present
/// or every marker line carries unparseable JSON.
///
/// Pure function: no I/O, no allocation beyond the parsed
/// `Report`. Tests construct synthetic console buffers; the
/// live host-side caller reads the console log into a `String`
/// and hands it here.
pub fn parse_report_from_console(log: &str) -> Option<Report> {
    let mut last: Option<Report> = None;
    for line in log.lines() {
        // The marker can appear anywhere on the line — the kernel
        // sometimes prefixes timestamps or `[mvm-init]` tags. We
        // match by substring and then take everything after the
        // marker + one space.
        if let Some(idx) = line.find(REPORT_MARKER) {
            let json_start = idx + REPORT_MARKER.len();
            let json = line[json_start..].trim_start();
            // A malformed line is silently skipped rather than
            // aborting the scan — partial console capture is a
            // real failure mode and we'd rather emit nothing
            // than wedge the host start path on garbage.
            if let Ok(parsed) = serde_json::from_str::<Report>(json) {
                last = Some(parsed);
            }
        }
    }
    last
}

/// What was installed for a single CIDR.
///
/// `category` is owned `String` (not `&'static str`) so the
/// Deserialize impl works for round-trip from an audit-log
/// reader. Construction at install time still uses string
/// literals — `categorize_v4` returns `&'static str` and we
/// `.to_string()` on insertion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteInstalled {
    pub cidr: IpNet,
    /// The mvm category this CIDR belongs to. Mirrors the audit
    /// detail format in `LocalAuditKind::NetworkMandatoryDeny`:
    /// `cloud-metadata` | `link-local` | `cgnat` | `loopback`.
    pub category: String,
}

/// Failure to install one route. The loop continues past this so
/// other routes still land; the caller branches on
/// `report.failed.is_empty()` to decide overall success.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteFailed {
    pub cidr: IpNet,
    pub category: String,
    /// Stringified error. Kept opaque so the JSON shape is stable
    /// even if the underlying netlink error representation changes.
    pub reason: String,
}

/// Cumulative outcome of one `install_mandatory_deny` run.
///
/// Serializes to a stable JSON shape so the
/// `mvm-guest-netinit` binary can write `serde_json::to_string`
/// of this directly to stdout. A future audit consumer parses
/// the same shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Report {
    pub installed: Vec<RouteInstalled>,
    pub failed: Vec<RouteFailed>,
    /// IPv6 entries from the const are intentionally skipped (the
    /// guest's bridge / TAP is IPv4-only on every backend today).
    /// Reported here so an operator parsing the JSON sees that the
    /// v6 entries were deliberately not attempted, not silently
    /// missing.
    pub skipped_ipv6: Vec<IpNet>,
    /// Loopback ranges (`127.0.0.0/8`) are intentionally **not**
    /// blackholed inside the guest: a blackhole route is
    /// interface-agnostic, so it would also kill the guest's own `lo`
    /// — breaking the forward proxy on `127.0.0.1` and any local
    /// service. The host-loopback-via-bridge threat
    /// `MANDATORY_DENY_RANGES` guards against is enforced host-side
    /// (the L4 / nft egress enforcers on the bridge), which still
    /// carry the full range list. Reported so the skip is observable,
    /// not silent. `#[serde(default)]` keeps older report JSON
    /// (without this field) parseable.
    #[serde(default)]
    pub skipped_loopback: Vec<IpNet>,
}

impl Report {
    pub fn empty() -> Self {
        Self {
            installed: Vec::new(),
            failed: Vec::new(),
            skipped_ipv6: Vec::new(),
            skipped_loopback: Vec::new(),
        }
    }

    /// `true` when at least one route failed to install. The
    /// `mvm-guest-netinit` binary exits non-zero on
    /// `has_failures()` so `/init` can fail-closed.
    pub fn has_failures(&self) -> bool {
        !self.failed.is_empty()
    }
}

/// Abstraction over the actual netlink call so tests can use a
/// `MockInstaller` without a real `AF_NETLINK` socket. Production
/// uses [`RawNetlinkInstaller`].
///
/// Synchronous: the previous `rtnetlink`-backed impl was
/// `async`, which forced `#[async_trait]` here and dragged `tokio` into
/// the guest closure for a one-shot, fire-and-wait netlink exchange that
/// never needed a runtime. The raw installer does a blocking
/// `send`/`recv` on a socket it owns.
pub trait RouteInstaller: Send + Sync {
    /// Add a blackhole route for `cidr`. Idempotent at the kernel
    /// level — if the route already exists, returning `Ok(())` is
    /// the correct semantics (the entry is the desired state, not
    /// a write-once operation).
    fn install_blackhole(&self, cidr: IpNet) -> Result<(), String>;
}

/// Categorize a CIDR for the audit category field. Pure function;
/// returns the same string keys as
/// `LocalAuditKind::NetworkMandatoryDeny`'s detail format.
fn categorize(cidr: &IpNet) -> &'static str {
    // The match order mirrors the const's ordering in
    // `mvm-core::policy::network_policy`. A future const edit that
    // shifts categories should update this function in lock-step.
    match cidr.to_string().as_str() {
        "169.254.169.254/32" | "169.254.0.0/16" => "link-local",
        // Note: cloud-metadata is the /32 specifically. We keep
        // both /32 and /16 in `link-local` here for simplicity —
        // a future audit slice that needs to distinguish IMDS
        // from generic link-local can pivot on the CIDR prefix
        // length.
        "100.64.0.0/10" => "cgnat",
        "127.0.0.0/8" | "::1/128" => "loopback",
        "fe80::/10" => "link-local-v6",
        _ => "other",
    }
}

/// Cloud metadata `/32` gets its own category for the audit detail
/// so a security dashboard can alert on IMDS exfil attempts
/// distinctly from generic link-local probes.
fn categorize_v4(cidr: &IpNet) -> &'static str {
    if cidr.to_string() == "169.254.169.254/32" {
        "cloud-metadata"
    } else {
        categorize(cidr)
    }
}

/// Install blackhole routes for every IPv4 entry in
/// `MANDATORY_DENY_RANGES`. IPv6 entries are skipped (the guest
/// network stack is v4-only on every backend today) and reported
/// in `report.skipped_ipv6` so an operator can see they were
/// deliberately not attempted.
///
/// The loop is fault-tolerant: a per-route failure is recorded in
/// `report.failed` but doesn't abort. Callers branch on
/// `report.has_failures()` for the overall verdict.
pub fn install_mandatory_deny<I: RouteInstaller>(installer: &I) -> Report {
    let mut report = Report::empty();
    for cidr in mvm_core::network_policy::mandatory_deny_ranges() {
        if !cidr.network().is_ipv4() {
            report.skipped_ipv6.push(cidr);
            continue;
        }
        // Never blackhole the guest's own loopback. A blackhole route matches
        // by destination regardless of interface, so blackholing 127.0.0.0/8
        // kills guest-internal loopback (the forward proxy on
        // 127.0.0.1:18080, and any local service) — not just host loopback
        // reached via a misconfigured bridge. That host-side threat is the
        // host bridge / L4 enforcer's job; they still carry the full
        // `MANDATORY_DENY_RANGES`. Skip-and-report, never silently.
        if categorize(&cidr) == "loopback" {
            report.skipped_loopback.push(cidr);
            continue;
        }
        let category = categorize_v4(&cidr).to_string();
        match installer.install_blackhole(cidr) {
            Ok(()) => report.installed.push(RouteInstalled { cidr, category }),
            Err(reason) => report.failed.push(RouteFailed {
                cidr,
                category,
                reason,
            }),
        }
    }
    report
}

// ============================================================================
// Raw netlink wire format (cross-platform — no socket, pure bytes)
// ============================================================================

/// Netlink `RTM_NEWROUTE` wire encoding for blackhole routes.
///
/// We replaced the async `rtnetlink` crate (which dragged `tokio` and
/// `async-trait` into the guest closure) with a hand-rolled message over a
/// synchronous `AF_NETLINK` socket. The message is 36 bytes of stable
/// kernel UAPI; building it needs no dependency. The encoding lives off the
/// `cfg(linux)` socket code so its byte layout is unit-tested on any host —
/// and the module is gated to `linux`-or-`test` so a macOS production build
/// (where only the Linux installer would call it) doesn't carry it as dead
/// code.
///
/// The constants and the framing come from `crate::netlink`, which the L3
/// agent's IPv6 bring-up shares.
#[cfg(any(target_os = "linux", test))]
mod wire {
    pub use crate::netlink::wire::*;
    use std::net::Ipv4Addr;

    /// Encode an `RTM_NEWROUTE` netlink message installing a blackhole
    /// route for `addr/prefix_len`. Pure: returns the exact wire bytes
    /// the kernel expects on an `AF_NETLINK`/`NETLINK_ROUTE` socket, no
    /// I/O.
    ///
    /// Layout (all multi-byte header fields native-endian per the
    /// netlink ABI; the `RTA_DST` payload is the address in network
    /// order): `nlmsghdr`(16) + `rtmsg`(12) + `rtattr`(4) + dst(4) = 36.
    ///
    /// `seq` is echoed back in the ACK so the caller can match request
    /// to reply on a socket it owns exclusively.
    pub fn encode_blackhole_route_v4(addr: Ipv4Addr, prefix_len: u8, seq: u32) -> Vec<u8> {
        let mut msg = Vec::with_capacity(36);
        push_nlmsghdr(
            &mut msg,
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK,
            seq,
        );

        // struct rtmsg — single-byte fields need no endian handling.
        msg.push(AF_INET_U8); // rtm_family
        msg.push(prefix_len); // rtm_dst_len — the prefix being blackholed
        msg.push(0); // rtm_src_len
        msg.push(0); // rtm_tos
        msg.push(RT_TABLE_MAIN); // rtm_table
        msg.push(RTPROT_BOOT); // rtm_protocol
        msg.push(RT_SCOPE_UNIVERSE); // rtm_scope
        msg.push(RTN_BLACKHOLE); // rtm_type — drop, no ICMP unreachable
        msg.extend_from_slice(&0u32.to_ne_bytes()); // rtm_flags

        // The address is already network-order in `octets()`, which is
        // what the kernel wants in RTA_DST.
        push_rtattr(&mut msg, RTA_DST, &addr.octets());

        finish(&mut msg);
        debug_assert_eq!(msg.len(), 36);
        msg
    }
}

#[cfg(any(target_os = "linux", test))]
use wire::*;

// ============================================================================
// Production installer — raw netlink (Linux-only)
// ============================================================================

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    use crate::netlink::NetlinkSocket;
    use std::io;

    /// Production [`RouteInstaller`] that talks to the kernel directly
    /// over a `NETLINK_ROUTE` socket — synchronous `sendto`/`recv`, no
    /// runtime. Requires CAP_NET_ADMIN in the current
    /// user namespace; the binary runs as root from `/init` BEFORE the
    /// agent setpriv's down to uid 901.
    pub struct RawNetlinkInstaller {
        sock: NetlinkSocket,
    }

    impl RawNetlinkInstaller {
        /// Open and bind a `NETLINK_ROUTE` socket. Fallible: the socket
        /// open can fail on a kernel built without netlink (rare, but
        /// possible on stripped-down embedded kernels) — the binary
        /// maps this to a distinct exit code so `/init` can tell a
        /// systemic netlink failure from a per-route one.
        pub fn open() -> Result<Self, String> {
            let sock = NetlinkSocket::open().map_err(|e| format!("open AF_NETLINK socket: {e}"))?;
            Ok(Self { sock })
        }
    }

    impl RouteInstaller for RawNetlinkInstaller {
        fn install_blackhole(&self, cidr: IpNet) -> Result<(), String> {
            let IpNet::V4(v4) = cidr else {
                // `install_mandatory_deny` skips v6 before calling us;
                // this defends against a future refactor.
                return Err(format!(
                    "internal: install_blackhole called with IPv6 cidr {cidr} (v6 not supported yet)"
                ));
            };
            let msg =
                encode_blackhole_route_v4(v4.network(), v4.prefix_len(), self.sock.next_seq());
            match self
                .sock
                .send_and_ack(&msg)
                .map_err(|e| format!("netlink exchange: {e}"))?
            {
                0 => Ok(()),
                // EEXIST: the blackhole is already installed. The route
                // is desired state, not a write-once op — idempotent Ok.
                e if e == libc::EEXIST => Ok(()),
                e => Err(format!(
                    "route add {cidr}: {}",
                    io::Error::from_raw_os_error(e)
                )),
            }
        }
    }

    /// Convenience: open the netlink socket and run the full install.
    /// The `mvm-guest-netinit` binary uses this.
    pub fn install_mandatory_deny_via_netlink() -> Result<Report, String> {
        let installer = RawNetlinkInstaller::open()?;
        Ok(install_mandatory_deny(&installer))
    }
}

#[cfg(target_os = "linux")]
pub use linux::{RawNetlinkInstaller, install_mandatory_deny_via_netlink};

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    /// In-memory mock that records every `install_blackhole` call.
    /// Tests inspect the recorded CIDRs to verify which entries
    /// the loop attempted; an injected `fail_on` set forces specific
    /// CIDRs to return an error so failure aggregation is tested too.
    struct MockInstaller {
        calls: Mutex<Vec<IpNet>>,
        fail_on: HashSet<IpNet>,
    }

    impl MockInstaller {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail_on: HashSet::new(),
            }
        }

        fn fail_on(mut self, cidrs: &[&str]) -> Self {
            for s in cidrs {
                self.fail_on.insert(s.parse().unwrap());
            }
            self
        }

        fn recorded(&self) -> Vec<IpNet> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl RouteInstaller for MockInstaller {
        fn install_blackhole(&self, cidr: IpNet) -> Result<(), String> {
            self.calls.lock().unwrap().push(cidr);
            if self.fail_on.contains(&cidr) {
                Err(format!("forced failure for {cidr}"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn install_calls_installer_for_every_ipv4_entry_except_loopback() {
        let mock = MockInstaller::new();
        let report = install_mandatory_deny(&mock);
        // Every IPv4 entry in `MANDATORY_DENY_RANGES` is blackholed except
        // loopback (skipped so the guest's own `lo` survives — see
        // `install_skips_loopback_*`). Mirror the const's count so a future
        // edit that adds a v4 entry also has to update this test.
        let v4_installable = mvm_core::network_policy::mandatory_deny_ranges()
            .iter()
            .filter(|n| n.network().is_ipv4() && categorize(n) != "loopback")
            .count();
        assert_eq!(mock.recorded().len(), v4_installable);
        assert_eq!(report.installed.len(), v4_installable);
        assert!(report.failed.is_empty());
    }

    #[test]
    fn install_skips_ipv6_entries_and_reports_them() {
        let mock = MockInstaller::new();
        let report = install_mandatory_deny(&mock);
        let v6_count = mvm_core::network_policy::mandatory_deny_ranges()
            .iter()
            .filter(|n| !n.network().is_ipv4())
            .count();
        assert_eq!(report.skipped_ipv6.len(), v6_count);
        // The installer was never called for any v6 entry.
        for recorded in mock.recorded() {
            assert!(
                recorded.network().is_ipv4(),
                "installer was called with non-v4 CIDR {recorded}"
            );
        }
    }

    #[test]
    fn install_skips_loopback_so_guest_internal_loopback_survives() {
        // A guest must not blackhole its own loopback: a blackhole route for
        // 127.0.0.0/8 is interface-agnostic and kills guest-internal loopback,
        // including the forward proxy on 127.0.0.1. The host-loopback
        // threat stays handled host-side with the full range list.
        let mock = MockInstaller::new();
        let report = install_mandatory_deny(&mock);
        let loopback: IpNet = "127.0.0.0/8".parse().unwrap();
        assert!(
            !mock.recorded().contains(&loopback),
            "guest installed a blackhole for its own loopback (breaks the forward proxy)"
        );
        assert!(
            !report.installed.iter().any(|r| r.cidr == loopback),
            "loopback must not appear in installed routes"
        );
        assert!(
            report.skipped_loopback.contains(&loopback),
            "the loopback skip must be reported"
        );
    }

    #[test]
    fn install_records_cloud_metadata_explicitly() {
        // The metadata `/32` is the highest-stakes entry. Asserting
        // it shows up in `installed` with category=cloud-metadata
        // means a regression that drops the entry from the const,
        // or skips it in the install loop, fails loudly here.
        let mock = MockInstaller::new();
        let report = install_mandatory_deny(&mock);
        let metadata: IpNet = "169.254.169.254/32".parse().unwrap();
        let entry = report
            .installed
            .iter()
            .find(|r| r.cidr == metadata)
            .expect("cloud metadata /32 must be in the installed set");
        assert_eq!(entry.category, "cloud-metadata");
    }

    #[test]
    fn install_continues_past_failures_and_records_them() {
        // Force one specific CIDR to fail. The loop must still
        // attempt every other entry; the failed CIDR lands in
        // `report.failed`, the rest in `report.installed`.
        let mock = MockInstaller::new().fail_on(&["100.64.0.0/10"]);
        let report = install_mandatory_deny(&mock);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].cidr.to_string(), "100.64.0.0/10");
        assert!(report.failed[0].reason.contains("forced failure"));
        // Other installs still happened.
        assert!(!report.installed.is_empty());
        // `has_failures()` reports the right state for the caller.
        assert!(report.has_failures());
    }

    #[test]
    fn install_marks_clean_run_no_failures() {
        let mock = MockInstaller::new();
        let report = install_mandatory_deny(&mock);
        assert!(!report.has_failures());
    }

    #[test]
    fn install_serializes_to_stable_json_shape() {
        // The binary's stdout is `serde_json::to_string(&report)`.
        // Pin the load-bearing field names so a downstream audit
        // consumer can deserialize across mvmctl versions.
        let mock = MockInstaller::new();
        let report = install_mandatory_deny(&mock);
        let json = serde_json::to_value(&report).unwrap();
        let obj = json.as_object().unwrap();
        for key in ["installed", "failed", "skipped_ipv6"] {
            assert!(obj.contains_key(key), "report JSON missing key {key}");
        }
        // Each installed entry has the documented field set.
        let first = obj["installed"]
            .as_array()
            .and_then(|a| a.first())
            .expect("at least one installed entry in clean run");
        assert!(first.get("cidr").is_some());
        assert!(first.get("category").is_some());
    }

    // ────────────────────────────────────────────────────────────
    // Raw netlink wire-format tests (no socket — pure bytes)
    // ────────────────────────────────────────────────────────────

    #[test]
    fn encode_blackhole_route_v4_produces_exact_netlink_bytes() {
        // The cloud-metadata /32 — highest-stakes entry. Pin every
        // load-bearing field of the RTM_NEWROUTE message so a wrong
        // offset, constant, or endianness surfaces here, not as a
        // silent kernel EINVAL on a host we can't boot in this test.
        let msg = encode_blackhole_route_v4(Ipv4Addr::new(169, 254, 169, 254), 32, 1);

        assert_eq!(msg.len(), 36, "nlmsghdr(16)+rtmsg(12)+rtattr(4)+dst(4)");

        // nlmsghdr (offsets 0..16)
        assert_eq!(
            u32::from_ne_bytes(msg[0..4].try_into().unwrap()),
            36,
            "nlmsg_len must equal total message length"
        );
        assert_eq!(
            u16::from_ne_bytes(msg[4..6].try_into().unwrap()),
            RTM_NEWROUTE,
            "nlmsg_type"
        );
        assert_eq!(
            u16::from_ne_bytes(msg[6..8].try_into().unwrap()),
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK,
            "nlmsg_flags"
        );
        assert_eq!(
            u32::from_ne_bytes(msg[8..12].try_into().unwrap()),
            1,
            "nlmsg_seq is echoed in the ACK"
        );

        // rtmsg (offsets 16..28)
        assert_eq!(msg[16], AF_INET_U8, "rtm_family");
        assert_eq!(msg[17], 32, "rtm_dst_len = prefix");
        assert_eq!(msg[18], 0, "rtm_src_len");
        assert_eq!(msg[20], RT_TABLE_MAIN, "rtm_table");
        assert_eq!(msg[21], RTPROT_BOOT, "rtm_protocol");
        assert_eq!(msg[22], RT_SCOPE_UNIVERSE, "rtm_scope");
        assert_eq!(msg[23], RTN_BLACKHOLE, "rtm_type — the blackhole");

        // rtattr RTA_DST (offsets 28..36)
        assert_eq!(
            u16::from_ne_bytes(msg[28..30].try_into().unwrap()),
            8,
            "rta_len = 4 (header) + 4 (addr)"
        );
        assert_eq!(
            u16::from_ne_bytes(msg[30..32].try_into().unwrap()),
            RTA_DST,
            "rta_type"
        );
        assert_eq!(
            &msg[32..36],
            &[169, 254, 169, 254],
            "destination address in network byte order"
        );
    }

    #[test]
    fn encode_blackhole_route_v4_carries_prefix_and_addr() {
        // A /10 (the CGNAT range) — different prefix + address, to prove
        // the encoder isn't hardcoded to the metadata /32.
        let msg = encode_blackhole_route_v4(Ipv4Addr::new(100, 64, 0, 0), 10, 7);
        assert_eq!(msg[17], 10, "rtm_dst_len tracks the supplied prefix");
        assert_eq!(&msg[32..36], &[100, 64, 0, 0], "destination address");
        assert_eq!(u32::from_ne_bytes(msg[8..12].try_into().unwrap()), 7, "seq");
    }

    // The netlink constants this encoder uses are pinned to libc's values
    // in `crate::netlink`, where they now live.

    // ────────────────────────────────────────────────────────────
    // Console-scrape parser tests
    // ────────────────────────────────────────────────────────────

    fn fake_report_json() -> String {
        // A minimal Report shape — one installed, one failed,
        // one skipped — that exercises every field path on the
        // parser side.
        r#"{"installed":[{"cidr":"169.254.169.254/32","category":"cloud-metadata"}],"failed":[{"cidr":"127.0.0.0/8","category":"loopback","reason":"forced"}],"skipped_ipv6":["::1/128"]}"#.to_string()
    }

    #[test]
    fn parse_report_extracts_from_clean_line() {
        let log = format!("__MVM_NETINIT_REPORT__ {}", fake_report_json());
        let report = parse_report_from_console(&log).expect("parser must extract");
        assert_eq!(report.installed.len(), 1);
        assert_eq!(report.installed[0].category, "cloud-metadata");
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.skipped_ipv6.len(), 1);
    }

    #[test]
    fn parse_report_ignores_unrelated_console_lines() {
        let report_line = fake_report_json();
        let log = format!(
            "[    0.000000] Booting Linux...\n\
             [    0.123456] random: crng init done\n\
             [mvm-init] mounted /proc /sys /dev\n\
             __MVM_NETINIT_REPORT__ {report_line}\n\
             [mvm-agent] starting on vsock port 5252\n"
        );
        let report = parse_report_from_console(&log).expect("must find the one marker line");
        assert_eq!(report.installed.len(), 1);
    }

    #[test]
    fn parse_report_returns_none_when_no_marker() {
        let log = "kernel boot ... busybox ... agent up ... no report here";
        assert!(parse_report_from_console(log).is_none());
    }

    #[test]
    fn parse_report_returns_none_when_marker_present_but_json_malformed() {
        let log = "__MVM_NETINIT_REPORT__ {this is not json}";
        assert!(parse_report_from_console(log).is_none());
    }

    #[test]
    fn parse_report_returns_last_marker_when_multiple() {
        // Multi-boot or restart scenario: two markers on the
        // console, the LATER one reflects live state.
        let log = format!(
            "__MVM_NETINIT_REPORT__ {{\"installed\":[],\"failed\":[],\"skipped_ipv6\":[]}}\n\
             other stuff\n\
             __MVM_NETINIT_REPORT__ {}\n",
            fake_report_json()
        );
        let report = parse_report_from_console(&log).expect("parser must extract last");
        // The last marker is the one with cloud-metadata installed;
        // a returned empty report would mean we kept the FIRST.
        assert_eq!(report.installed.len(), 1);
    }

    #[test]
    fn parse_report_handles_kernel_timestamp_prefix() {
        // Kernel console output frequently prefixes lines with
        // `[    1.234567]` timestamps. The marker should be
        // findable mid-line, not only at start.
        let log = format!(
            "[    1.234567] __MVM_NETINIT_REPORT__ {}",
            fake_report_json()
        );
        let report = parse_report_from_console(&log).expect("marker mid-line must parse");
        assert_eq!(report.installed.len(), 1);
    }

    #[test]
    fn report_marker_is_distinctive_enough() {
        // Defensive: the marker must not appear in obvious
        // kernel/busybox/agent log patterns. A future rename to
        // something kernel-message-shaped would break console
        // grep silently; pin the current value here so a refactor
        // has to update the test.
        assert_eq!(REPORT_MARKER, "__MVM_NETINIT_REPORT__");
        for noise in [
            "[    0.000000] Booting Linux",
            "[mvm-init] mounted /proc",
            "[mvm-agent] starting on vsock port 5252",
            "kernel: AF_VSOCK ready",
        ] {
            assert!(
                !noise.contains(REPORT_MARKER),
                "marker collides with kernel/agent log: {noise}"
            );
        }
    }

    #[test]
    fn categorize_v4_handles_known_entries() {
        let cases = [
            ("169.254.169.254/32", "cloud-metadata"),
            ("169.254.0.0/16", "link-local"),
            ("100.64.0.0/10", "cgnat"),
            ("127.0.0.0/8", "loopback"),
        ];
        for (s, expected) in cases {
            let cidr: IpNet = s.parse().unwrap();
            assert_eq!(categorize_v4(&cidr), expected, "category for {s}");
        }
    }
}
