//! Egress-policy logic — iptables script generation and the
//! `ipnet`/`std::net` mandatory-deny enforcement.
//!
//! The DTO half (`HostPort`, `NetworkPreset`, `EgressMode`,
//! `NetworkPolicy`, the `BANNED_SSH_PORT`/`MANDATORY_DENY_RANGES`
//! consts, `is_banned_ssh_port`, and every pure constructor/accessor)
//! lives in `mvm_protocol::policy::network_policy` and is re-exported
//! below so every existing `crate::policy::network_policy::X` /
//! `mvm_core::policy::network_policy::X` path keeps resolving unchanged.

pub use mvm_protocol::policy::network_policy::{
    BANNED_SSH_PORT, EgressMode, HostPort, MANDATORY_DENY_RANGES, NetworkPolicy,
    NetworkPolicyParseError, NetworkPreset, is_banned_ssh_port,
};

const SSH_BANNER_HEX_PREFIX: &str = "|5353482d|";

/// Generate the iptables shell script fragment for `policy`.
/// Returns `None` if unrestricted (no rules needed).
///
/// The script assumes it runs on the Linux host with sudo and that
/// the bridge device and FORWARD chain are already set up.
///
/// A free function rather than an inherent method on [`NetworkPolicy`]:
/// that type now lives in `mvm-protocol`, and the orphan rule forbids
/// `mvm-core` from adding inherent `impl`s to a foreign type.
pub fn iptables_script(policy: &NetworkPolicy, bridge_dev: &str, guest_ip: &str) -> Option<String> {
    let rules = policy.resolve_rules()?;

    let mut script = String::new();
    script.push_str(&format!(
        "# Network policy: drop all outbound from {} except allowed hosts\n",
        guest_ip
    ));

    // Drop all FORWARD from this guest by default
    script.push_str(&format!(
        "sudo iptables -I FORWARD -i {br} -s {ip} -j DROP\n",
        br = bridge_dev,
        ip = guest_ip,
    ));

    // Allow ESTABLISHED/RELATED (return traffic)
    script.push_str(&format!(
        "sudo iptables -I FORWARD -i {br} -s {ip} -m state --state ESTABLISHED,RELATED -j ACCEPT\n",
        br = bridge_dev,
        ip = guest_ip,
    ));

    // Allow DNS (UDP + TCP port 53) so domain resolution works
    script.push_str(&format!(
        "sudo iptables -I FORWARD -i {br} -s {ip} -p udp --dport 53 -j ACCEPT\n",
        br = bridge_dev,
        ip = guest_ip,
    ));
    script.push_str(&format!(
        "sudo iptables -I FORWARD -i {br} -s {ip} -p tcp --dport 53 -j ACCEPT\n",
        br = bridge_dev,
        ip = guest_ip,
    ));

    // Allow each specific host:port
    for rule in &rules {
        script.push_str(&format!(
            "sudo iptables -I FORWARD -i {br} -s {ip} -d {host} -p tcp --dport {port} -j ACCEPT\n",
            br = bridge_dev,
            ip = guest_ip,
            host = rule.host,
            port = rule.port,
        ));
    }

    Some(script)
}

/// Generate the iptables cleanup script for `policy`.
/// Returns `None` if unrestricted (nothing to clean up).
///
/// A free function rather than an inherent method on [`NetworkPolicy`] —
/// see [`iptables_script`] for why.
pub fn iptables_cleanup_script(
    policy: &NetworkPolicy,
    bridge_dev: &str,
    guest_ip: &str,
) -> Option<String> {
    if policy.is_unrestricted() {
        return None;
    }

    Some(format!(
        "# Clean up network policy rules for {ip}\n\
         while sudo iptables -D FORWARD -i {br} -s {ip} -j DROP 2>/dev/null; do :; done\n\
         while sudo iptables -D FORWARD -i {br} -s {ip} -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do :; done\n\
         while sudo iptables -D FORWARD -i {br} -s {ip} -p udp --dport 53 -j ACCEPT 2>/dev/null; do :; done\n\
         while sudo iptables -D FORWARD -i {br} -s {ip} -p tcp --dport 53 -j ACCEPT 2>/dev/null; do :; done\n",
        br = bridge_dev,
        ip = guest_ip,
    ))
}

// ============================================================================
// Mandatory deny ranges
// ============================================================================

/// Parse [`MANDATORY_DENY_RANGES`] into typed [`ipnet::IpNet`]s.
/// Done at call time (no `lazy_static` / `OnceLock`) — the list
/// is small (<10 entries) and parse cost is dominated by the
/// `Vec` allocation. A malformed entry is a programmer bug, not
/// a runtime failure; the `mandatory_deny_ranges_const_parses`
/// test catches typos before they ship.
///
/// Note: panics if any entry fails to parse. The single test
/// guards the const, so a panic here can only happen if a future
/// edit slips both the const review and CI — caller doesn't need
/// to handle the error path.
pub fn mandatory_deny_ranges() -> Vec<ipnet::IpNet> {
    MANDATORY_DENY_RANGES
        .iter()
        .map(|s| {
            s.parse().unwrap_or_else(|_| {
                panic!("MANDATORY_DENY_RANGES contains invalid CIDR {s:?} — fix the const")
            })
        })
        .collect()
}

/// Returns `true` if `ip` falls within any of the mandatory
/// deny ranges. The defense-in-depth check every egress
/// enforcer (iptables setup, `CanonicalEgress::permits`, the L7
/// proxy) should run *before* consulting the user's allow-list — a
/// hit here means the destination is forbidden full stop, no matter
/// how permissive the allow-list is.
///
/// Allocates a small `Vec` per call today; the call site is
/// admission-path or per-flow, neither of which is hot enough to
/// justify cached parsing. A perf-sensitive consumer can hoist
/// [`mandatory_deny_ranges`] outside its loop.
pub fn is_mandatory_deny(ip: std::net::IpAddr) -> bool {
    let ip = unmap_v4_mapped(ip);
    mandatory_deny_ranges().iter().any(|net| net.contains(&ip))
}

/// Collapse an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its embedded
/// IPv4 address, leaving every other address unchanged.
///
/// A dual-stack socket (the Linux default, without `IPV6_V6ONLY`) connecting
/// to the mapped form is routed by the kernel to the embedded IPv4
/// destination, so an egress range check that inspects the IPv6 form sees an
/// opaque address and misses IPv4-only deny ranges — a `::ffff:169.254.169.254`
/// would otherwise slip past the metadata deny. Normalizing here forces the
/// check onto the address the kernel will actually reach. `::1`, `::`,
/// `fe80::/10` and `fc00::/7` are not mapped forms, so they stay IPv6 and are
/// classified by the IPv6 rules.
#[must_use]
pub fn unmap_v4_mapped(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => std::net::IpAddr::V4(v4),
            None => std::net::IpAddr::V6(v6),
        },
        std::net::IpAddr::V4(_) => ip,
    }
}

/// Emit the iptables shell fragment that drops outbound from
/// `guest_ip` on `bridge_dev` to every IPv4 entry in
/// [`MANDATORY_DENY_RANGES`]. Always returns a non-empty
/// script — the deny posture applies regardless of the user's
/// [`NetworkPolicy`].
///
/// **Order matters.** The script uses `iptables -I FORWARD`,
/// which inserts at chain position 1, so a rule emitted *later*
/// in the script ends up *earlier* in the chain (and is checked
/// first by the kernel). Callers run this script *after* a
/// policy's [`iptables_script`] output so the
/// deny rules end up at the TOP of FORWARD — they fire before
/// any per-policy allow rule. Without that ordering, a
/// `--network-preset unrestricted` workload (no allow-list,
/// nothing scoped to it in FORWARD today) would still hit the
/// metadata endpoint.
///
/// IPv6 entries from the const are intentionally skipped here —
/// today's bridge wiring is IPv4-only, so a v6 packet from the
/// guest doesn't have a route to leave anyway. The v6
/// enforcement lands when the bridge gains v6.
pub fn mandatory_deny_iptables_script(bridge_dev: &str, guest_ip: &str) -> String {
    let mut script = String::from(
        "# Mandatory deny ranges (cloud metadata, link-local, CGNAT, host\n\
         # loopback). These rules sit at the top of FORWARD via `-I` so\n\
         # they're checked before any per-policy allow rule — even an\n\
         # `unrestricted` workload cannot reach 169.254.169.254 (AWS IMDS /\n\
         # GCP / Azure metadata).\n",
    );
    for net in mandatory_deny_ranges() {
        if !net.network().is_ipv4() {
            continue;
        }
        script.push_str(&format!(
            "sudo iptables -I FORWARD -i {br} -s {ip} -d {cidr} -j DROP\n",
            br = bridge_dev,
            ip = guest_ip,
            cidr = net,
        ));
    }
    script.push_str(&format!(
        "sudo iptables -I FORWARD -i {br} -s {ip} -p tcp --dport {port} -j DROP\n",
        br = bridge_dev,
        ip = guest_ip,
        port = BANNED_SSH_PORT,
    ));
    script.push_str(&format!(
        "sudo iptables -I FORWARD -o {br} -d {ip} -p tcp -m string --algo bm --hex-string '{banner}' -j DROP\n",
        br = bridge_dev,
        ip = guest_ip,
        banner = SSH_BANNER_HEX_PREFIX,
    ));
    script
}

/// Cleanup counterpart of [`mandatory_deny_iptables_script`].
/// `iptables -D` removes one matching rule; the
/// `while … 2>/dev/null; do :; done` form drains *all* matching
/// rules so a previously-leaked duplicate (from a prior crashed
/// `apply_network_policy`) doesn't strand a deny rule on the
/// chain. Mirrors the pattern used by [`iptables_cleanup_script`].
pub fn mandatory_deny_iptables_cleanup_script(bridge_dev: &str, guest_ip: &str) -> String {
    let mut script = String::from("# Clean up mandatory-deny rules\n");
    for net in mandatory_deny_ranges() {
        if !net.network().is_ipv4() {
            continue;
        }
        script.push_str(&format!(
            "while sudo iptables -D FORWARD -i {br} -s {ip} -d {cidr} -j DROP 2>/dev/null; do :; done\n",
            br = bridge_dev,
            ip = guest_ip,
            cidr = net,
        ));
    }
    script.push_str(&format!(
        "while sudo iptables -D FORWARD -i {br} -s {ip} -p tcp --dport {port} -j DROP 2>/dev/null; do :; done\n",
        br = bridge_dev,
        ip = guest_ip,
        port = BANNED_SSH_PORT,
    ));
    script.push_str(&format!(
        "while sudo iptables -D FORWARD -o {br} -d {ip} -p tcp -m string --algo bm --hex-string '{banner}' -j DROP 2>/dev/null; do :; done\n",
        br = bridge_dev,
        ip = guest_ip,
        banner = SSH_BANNER_HEX_PREFIX,
    ));
    script
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iptables_script_unrestricted_is_none() {
        let policy = NetworkPolicy::unrestricted();
        assert!(iptables_script(&policy, "br-mvm", "172.16.0.2").is_none());
    }

    #[test]
    fn iptables_script_deny_all_has_drop_no_host_rules() {
        let policy = NetworkPolicy::deny_all();
        let script = iptables_script(&policy, "br-mvm", "172.16.0.2").unwrap();
        assert!(script.contains("-j DROP"));
        assert!(script.contains("--dport 53")); // DNS allowed
        // No host-specific ACCEPT rules (only DNS + ESTABLISHED)
        let accept_lines: Vec<&str> = script
            .lines()
            .filter(|l| {
                l.contains("-j ACCEPT") && !l.contains("--dport 53") && !l.contains("ESTABLISHED")
            })
            .collect();
        assert!(
            accept_lines.is_empty(),
            "deny-all should have no host ACCEPT rules"
        );
    }

    #[test]
    fn iptables_script_allow_list_has_host_rules() {
        let policy = NetworkPolicy::allow_list(vec![
            HostPort::new("github.com", 443),
            HostPort::new("api.openai.com", 443),
        ]);
        let script = iptables_script(&policy, "br-mvm", "172.16.0.3").unwrap();
        assert!(script.contains("-d github.com"));
        assert!(script.contains("-d api.openai.com"));
        assert!(script.contains("--dport 443"));
        assert!(script.contains("-s 172.16.0.3"));
        assert!(script.contains("-i br-mvm"));
    }

    #[test]
    fn nic_policy_behind_tunnel_collapses_to_denying_iptables_script() {
        // A tunnel-carried workload's NIC policy collapses to
        // deny-all; confirm the rendered script actually
        // default-denies rather than just checking the DTO shape
        // (that check lives with the DTO in mvm-protocol).
        let allow = NetworkPolicy::allow_list(vec![HostPort::new("1.1.1.1", 443)]);
        let behind = allow.nic_policy_behind_tunnel(true);
        assert!(
            iptables_script(&behind, "br-mvm", "172.16.0.2")
                .unwrap()
                .contains("-j DROP"),
            "the NIC firewall default-denies"
        );
    }

    #[test]
    fn iptables_cleanup_unrestricted_is_none() {
        let policy = NetworkPolicy::unrestricted();
        assert!(iptables_cleanup_script(&policy, "br-mvm", "172.16.0.2").is_none());
    }

    #[test]
    fn iptables_cleanup_deny_all_has_commands() {
        let policy = NetworkPolicy::deny_all();
        let script = iptables_cleanup_script(&policy, "br-mvm", "172.16.0.2").unwrap();
        assert!(script.contains("iptables -D FORWARD"));
    }

    // =====================================================================
    // Mandatory deny ranges
    // =====================================================================

    /// Every entry in [`MANDATORY_DENY_RANGES`] must parse cleanly.
    /// A typo here panics every consumer at runtime — catch it at
    /// build time instead.
    #[test]
    fn mandatory_deny_ranges_const_parses() {
        // `mandatory_deny_ranges()` itself panics on a parse
        // failure, so calling it inside the test surfaces a typo
        // as a test failure rather than a release-time panic.
        let nets = mandatory_deny_ranges();
        assert_eq!(
            nets.len(),
            MANDATORY_DENY_RANGES.len(),
            "every constant entry should produce one IpNet"
        );
    }

    /// The cloud metadata endpoint is the highest-stakes single
    /// IP in the list. Asserting it directly (not just via the
    /// containing `/16`) keeps the test loud if a future edit
    /// removes the specific `/32` entry.
    #[test]
    fn cloud_metadata_endpoint_is_denied() {
        let metadata: std::net::IpAddr = "169.254.169.254".parse().unwrap();
        assert!(
            is_mandatory_deny(metadata),
            "AWS/GCP/Azure IMDS at 169.254.169.254 must be in the default-deny set"
        );
    }

    #[test]
    fn link_local_ipv4_is_denied() {
        // Other points within the /16 must also fall in the deny
        // set (the metadata `/32` is a subset of this `/16`).
        for addr in ["169.254.0.1", "169.254.42.42", "169.254.255.254"] {
            let ip: std::net::IpAddr = addr.parse().unwrap();
            assert!(
                is_mandatory_deny(ip),
                "link-local IPv4 {addr} must be denied"
            );
        }
    }

    #[test]
    fn link_local_ipv6_is_denied() {
        for addr in ["fe80::1", "fe80::abcd:ef12:3456:7890"] {
            let ip: std::net::IpAddr = addr.parse().unwrap();
            assert!(
                is_mandatory_deny(ip),
                "link-local IPv6 {addr} must be denied"
            );
        }
    }

    #[test]
    fn cgnat_range_is_denied() {
        // 100.64.0.0/10 = 100.64.0.0 through 100.127.255.255.
        for addr in ["100.64.0.1", "100.127.255.254"] {
            let ip: std::net::IpAddr = addr.parse().unwrap();
            assert!(is_mandatory_deny(ip), "CGNAT {addr} must be denied");
        }
        // Just outside the CGNAT range must NOT be denied.
        let outside: std::net::IpAddr = "100.63.255.255".parse().unwrap();
        assert!(
            !is_mandatory_deny(outside),
            "100.63.255.255 is one below CGNAT and should NOT be denied"
        );
        let above: std::net::IpAddr = "100.128.0.0".parse().unwrap();
        assert!(
            !is_mandatory_deny(above),
            "100.128.0.0 is one above CGNAT and should NOT be denied"
        );
    }

    #[test]
    fn host_loopback_v4_and_v6_are_denied() {
        let v4: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let v6: std::net::IpAddr = "::1".parse().unwrap();
        assert!(is_mandatory_deny(v4), "127.0.0.1 must be denied");
        assert!(is_mandatory_deny(v6), "::1 must be denied");
        // Anywhere inside 127.0.0.0/8 must be denied too.
        let nested: std::net::IpAddr = "127.42.99.7".parse().unwrap();
        assert!(is_mandatory_deny(nested), "127.42.99.7 must be denied");
    }

    #[test]
    fn ipv4_mapped_forms_do_not_bypass_mandatory_deny() {
        // The IPv4-only deny ranges must still catch the IPv4-mapped IPv6
        // spelling — a dual-stack connect to `::ffff:a.b.c.d` reaches `a.b.c.d`.
        for addr in [
            "::ffff:169.254.169.254", // metadata
            "::ffff:127.0.0.1",       // loopback
            "::ffff:100.64.0.1",      // CGNAT
        ] {
            let ip: std::net::IpAddr = addr.parse().unwrap();
            assert!(is_mandatory_deny(ip), "mapped {addr} must be denied");
        }
        // A mapped *public* address is not mandatory-deny.
        let public: std::net::IpAddr = "::ffff:93.184.216.34".parse().unwrap();
        assert!(
            !is_mandatory_deny(public),
            "mapped public must not be denied"
        );
    }

    /// Legitimate public IPs must pass through cleanly so a
    /// future regression that overzealously expands the deny
    /// set (e.g. blocking all RFC1918) surfaces here.
    #[test]
    fn legitimate_public_ips_are_not_denied() {
        let cases = [
            "8.8.8.8",              // Google DNS
            "1.1.1.1",              // Cloudflare DNS
            "104.16.0.1",           // arbitrary Cloudflare anycast
            "2001:4860:4860::8888", // Google DNS IPv6
            "2606:4700:4700::1111", // Cloudflare DNS IPv6
        ];
        for addr in cases {
            let ip: std::net::IpAddr = addr.parse().unwrap();
            assert!(
                !is_mandatory_deny(ip),
                "{addr} must NOT be denied (legitimate public dest)"
            );
        }
    }

    /// RFC1918 ranges are deliberately NOT in the default-deny
    /// set — corporate VPNs, home labs, and k8s pod networks live
    /// here and breaking them would be a UX regression. If a
    /// future edit accidentally adds RFC1918 to the const, this
    /// test fails loudly and the maintainer reads the comment
    /// above MANDATORY_DENY_RANGES that says why.
    #[test]
    fn rfc1918_is_not_in_default_deny() {
        let cases = ["10.0.0.1", "172.16.0.1", "192.168.1.1"];
        for addr in cases {
            let ip: std::net::IpAddr = addr.parse().unwrap();
            assert!(
                !is_mandatory_deny(ip),
                "{addr} is RFC1918 — must NOT be in default-deny (legitimate corp/VPN use)"
            );
        }
    }

    /// The first entry in the list is the cloud metadata `/32`.
    /// Pinning the order matters: a maintainer scanning the
    /// const should hit the most consequential entry first and
    /// think twice before removing it. If a future PR rearranges
    /// the entries, this assertion forces a conscious decision
    /// rather than a silent reordering.
    #[test]
    fn cloud_metadata_is_first_entry_in_const() {
        assert_eq!(
            MANDATORY_DENY_RANGES[0], "169.254.169.254/32",
            "cloud metadata /32 should be the first entry — it's the most \
             consequential single address and a maintainer scanning the \
             list should see it before anything else"
        );
    }

    // =====================================================================
    // iptables wiring for mandatory deny ranges
    // =====================================================================

    /// The most consequential assertion: the rendered script
    /// must DROP traffic destined for the cloud metadata
    /// endpoint. If this fails, AWS IMDS / GCP / Azure metadata
    /// is reachable from the guest — defeating the entire
    /// purpose of this slice.
    #[test]
    fn mandatory_deny_iptables_script_drops_cloud_metadata() {
        let script = mandatory_deny_iptables_script("br-mvm", "172.16.0.2");
        assert!(
            script.contains("-d 169.254.169.254/32 -j DROP"),
            "script must drop cloud metadata endpoint; got: {script}"
        );
    }

    #[test]
    fn mandatory_deny_iptables_script_drops_ssh_port() {
        let script = mandatory_deny_iptables_script("br-mvm", "172.16.0.2");
        assert!(
            script.contains("-p tcp --dport 22 -j DROP"),
            "script must drop TCP/22 so SSH sessions cannot be established; got: {script}"
        );
    }

    #[test]
    fn mandatory_deny_iptables_script_drops_inbound_ssh_banner() {
        let script = mandatory_deny_iptables_script("br-mvm", "172.16.0.2");
        assert!(
            script.contains("-o br-mvm -d 172.16.0.2 -p tcp -m string --algo bm --hex-string '|5353482d|' -j DROP"),
            "script must drop inbound SSH identification banners on any TCP port; got: {script}"
        );
    }

    #[test]
    fn mandatory_deny_iptables_script_scopes_to_guest_endpoint() {
        let script = mandatory_deny_iptables_script("br-mvm", "172.16.0.2");
        // Every line that adds a rule must be scoped to this guest as either
        // source (egress) or destination (inbound server banners), otherwise a
        // sibling guest's traffic could be affected by cleanup of this one.
        for line in script.lines().filter(|l| l.contains("iptables -I")) {
            assert!(
                line.contains("-s 172.16.0.2") || line.contains("-d 172.16.0.2"),
                "deny rule line must scope to the guest endpoint: {line}"
            );
        }
    }

    #[test]
    fn mandatory_deny_iptables_script_uses_minus_i_for_top_of_chain() {
        // `-I FORWARD` inserts at chain position 1 (top). A
        // future PR that switches to `-A` would silently bury
        // the deny rules below any pre-existing allow rules —
        // catastrophic. Catch the regression at the unit level.
        let script = mandatory_deny_iptables_script("br-mvm", "172.16.0.2");
        for line in script.lines().filter(|l| l.contains("iptables")) {
            assert!(
                line.contains("-I FORWARD"),
                "rule must use `-I FORWARD` (top-insert); got: {line}"
            );
            assert!(
                !line.contains("-A FORWARD"),
                "rule must NOT use `-A FORWARD` (would bury below allow rules): {line}"
            );
        }
    }

    #[test]
    fn mandatory_deny_iptables_script_skips_ipv6_entries() {
        let script = mandatory_deny_iptables_script("br-mvm", "172.16.0.2");
        // v6 enforcement lands when the bridge gains v6
        // routing; until then the v6 deny rules belong in a
        // future PR, not in this script.
        assert!(
            !script.contains("ip6tables"),
            "ip6tables must not appear; v6 wiring is deferred. got: {script}"
        );
        assert!(
            !script.contains("::1/128"),
            "IPv6 entries must not appear in v4 script: {script}"
        );
        assert!(
            !script.contains("fe80::"),
            "IPv6 entries must not appear in v4 script: {script}"
        );
    }

    #[test]
    fn mandatory_deny_iptables_script_covers_every_ipv4_const_entry() {
        let script = mandatory_deny_iptables_script("br-mvm", "172.16.0.2");
        for raw in MANDATORY_DENY_RANGES {
            let net: ipnet::IpNet = raw.parse().unwrap();
            if !net.network().is_ipv4() {
                continue;
            }
            assert!(
                script.contains(&format!("-d {net} -j DROP")),
                "expected a DROP for {net} but it's missing from script: {script}"
            );
        }
    }

    /// Apply emits a DROP per IPv4 entry; cleanup must emit a
    /// matching `-D` for every one of them. Drift between the
    /// two scripts strands stale rules on the bridge after a
    /// VM teardown.
    #[test]
    fn mandatory_deny_cleanup_matches_apply_line_for_line() {
        let apply = mandatory_deny_iptables_script("br-mvm", "172.16.0.2");
        let cleanup = mandatory_deny_iptables_cleanup_script("br-mvm", "172.16.0.2");
        // For every `-I` rule in apply, expect a `-D` rule in
        // cleanup with the same `-d <cidr>` token.
        let apply_cidrs: Vec<&str> = apply
            .lines()
            .filter(|l| l.contains("iptables -I"))
            .filter_map(|l| l.split("-d ").nth(1))
            .filter_map(|tail| tail.split(' ').next())
            .collect();
        let cleanup_cidrs: Vec<&str> = cleanup
            .lines()
            .filter(|l| l.contains("iptables -D"))
            .filter_map(|l| l.split("-d ").nth(1))
            .filter_map(|tail| tail.split(' ').next())
            .collect();
        assert_eq!(
            apply_cidrs, cleanup_cidrs,
            "apply and cleanup must reference identical CIDRs in identical order"
        );
        assert!(!apply_cidrs.is_empty(), "apply must emit at least one rule");
    }

    #[test]
    fn mandatory_deny_cleanup_uses_drain_loop() {
        let cleanup = mandatory_deny_iptables_cleanup_script("br-mvm", "172.16.0.2");
        // A single `-D` removes exactly one matching rule. The
        // `while … do :; done` form drains all matches so a
        // leaked duplicate (from a prior crashed apply) doesn't
        // strand a deny rule. Matches the pattern used by the
        // cleanup script in `mvm-backend::network`.
        for line in cleanup.lines().filter(|l| l.contains("iptables -D")) {
            assert!(
                line.starts_with("while sudo "),
                "cleanup must use `while sudo … do :; done` drain loop: {line}"
            );
            assert!(
                line.ends_with("done"),
                "cleanup must close the `while … done` block: {line}"
            );
        }
    }
}
