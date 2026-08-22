//! Egress-policy logic — iptables script generation.
//!
//! The DTO half (`HostPort`, `NetworkPreset`, `EgressMode`,
//! `NetworkPolicy`, the `BANNED_SSH_PORT`/`MANDATORY_DENY_RANGES`
//! consts, `is_banned_ssh_port`, every pure constructor/accessor, and
//! the `ipnet`-typed mandatory-deny predicates the egress projection
//! decides with) lives in `mvm_contract::policy::network_policy` and is
//! re-exported below so every existing `crate::policy::network_policy::X`
//! / `mvm_core::policy::network_policy::X` path keeps resolving unchanged.

pub use mvm_contract::policy::network_policy::{
    AiBudget, AiPolicy, BANNED_SSH_PORT, EgressMode, HostPort, MANDATORY_DENY_RANGES,
    NetworkPolicy, NetworkPolicyParseError, NetworkPreset, is_banned_ssh_port, is_mandatory_deny,
    mandatory_deny_ranges, unmap_v4_mapped,
};

const SSH_BANNER_HEX_PREFIX: &str = "|5353482d|";

/// Generate the iptables shell script fragment for `policy`.
/// Returns `None` if unrestricted (no rules needed).
///
/// The script assumes it runs on the Linux host with sudo and that
/// the bridge device and FORWARD chain are already set up.
///
/// A free function rather than an inherent method on [`NetworkPolicy`]:
/// that type now lives in `mvm-contract`, and the orphan rule forbids
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
