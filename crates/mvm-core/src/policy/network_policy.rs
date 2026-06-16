use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A host:port pair for network allowlist rules.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

impl HostPort {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl FromStr for HostPort {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("expected host:port, got {:?}", s))?;
        if host.is_empty() {
            anyhow::bail!("host cannot be empty in {:?}", s);
        }
        let port: u16 = port
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid port in {:?}", s))?;
        Ok(Self::new(host, port))
    }
}

/// Built-in network presets for common workloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkPreset {
    /// Full internet access (no filtering). Default for backward compatibility.
    Unrestricted,
    /// No outbound network (FORWARD DROP, DNS only).
    None,
    /// Package registries only (npm, crates.io, PyPI).
    Registries,
    /// Developer preset: registries + GitHub + OpenAI + Anthropic APIs.
    Dev,
    /// LLM-agent preset: the LLM inference APIs an agent typically
    /// calls (Anthropic, OpenAI), plus GitHub for source operations.
    /// Minimum surface for `nix/images/examples/llm-agent/`'s
    /// `claude-code-vm`. Strictly smaller than `dev` — does NOT include
    /// package registries,
    /// because an agent VM is meant to run trusted closures, not
    /// re-resolve npm/PyPI on the fly.
    Agent,
}

impl NetworkPreset {
    /// Expand a preset into its constituent host:port rules.
    pub fn rules(&self) -> Vec<HostPort> {
        match self {
            Self::Unrestricted => vec![], // empty = no filtering
            Self::None => vec![],         // empty + applied as deny-all
            Self::Registries => registry_rules(),
            Self::Dev => {
                let mut rules = registry_rules();
                rules.extend(dev_extra_rules());
                rules
            }
            Self::Agent => agent_rules(),
        }
    }

    /// Whether this preset means "allow everything" (no iptables filtering).
    pub fn is_unrestricted(&self) -> bool {
        matches!(self, Self::Unrestricted)
    }

    /// Whether this preset means "deny everything" (no allowlist entries).
    pub fn is_deny_all(&self) -> bool {
        matches!(self, Self::None)
    }
}

impl FromStr for NetworkPreset {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unrestricted" => Ok(Self::Unrestricted),
            "none" => Ok(Self::None),
            "registries" => Ok(Self::Registries),
            "dev" => Ok(Self::Dev),
            "agent" => Ok(Self::Agent),
            _ => anyhow::bail!(
                "unknown network preset {:?} (expected: unrestricted, none, registries, dev, agent)",
                s
            ),
        }
    }
}

impl fmt::Display for NetworkPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unrestricted => write!(f, "unrestricted"),
            Self::None => write!(f, "none"),
            Self::Registries => write!(f, "registries"),
            Self::Dev => write!(f, "dev"),
            Self::Agent => write!(f, "agent"),
        }
    }
}

/// Egress enforcement layer.
///
/// This enum lets callers pick which layers apply. v1 wires only L3;
/// v2 (deferred) adds the L7 SNI/Host proxy + DNS pinning.
///
/// `Open` is the implicit mode for any `NetworkPolicy` that resolves
/// to an unrestricted preset. `L3Only` and `L3PlusL7` apply when
/// the policy resolves to a non-empty allowlist.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EgressMode {
    /// No filtering — guest gets full outbound. Implied by an
    /// unrestricted policy.
    #[default]
    Open,
    /// L3 only: iptables `FORWARD` allowlist on the bridge. Catches
    /// raw-IP exfil; doesn't catch DNS rotation or SNI/Host abuse
    /// over a permitted destination.
    L3Only,
    /// L3 + L7 stack: iptables allowlist plus an HTTPS proxy on the
    /// host that enforces SNI for HTTPS (CONNECT) and Host header
    /// for HTTP. The runtime impl isn't wired yet — today this variant
    /// returns "egress proxy not implemented" at `tap_create` time so
    /// callers see a clear error rather than a silent downgrade.
    L3PlusL7,
}

impl EgressMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::L3Only => "l3-only",
            Self::L3PlusL7 => "l3-plus-l7",
        }
    }
}

impl FromStr for EgressMode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(Self::Open),
            "l3-only" | "l3" => Ok(Self::L3Only),
            "l3-plus-l7" | "l3+l7" | "l7" => Ok(Self::L3PlusL7),
            other => anyhow::bail!(
                "unknown egress mode {:?} (expected: open, l3-only, l3-plus-l7)",
                other
            ),
        }
    }
}

impl fmt::Display for EgressMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Network policy for a microVM, controlling outbound traffic.
///
/// The optional `egress_mode` enrichment is a per-policy override. When
/// present, it pins the L3/L7 enforcement tier for the policy at
/// apply-time; when `None`, callers fall back to the host-wide default
/// (today: `EgressMode::Open`). The field is deliberately co-located on
/// each variant rather than as a sibling field so a `Preset` and a
/// hand-rolled `AllowList` can both attach a mode without forcing every
/// consumer to re-thread a separate parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum NetworkPolicy {
    /// Use a built-in preset.
    Preset {
        preset: NetworkPreset,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        egress_mode: Option<EgressMode>,
    },
    /// Explicit allowlist of host:port pairs.
    AllowList {
        rules: Vec<HostPort>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        egress_mode: Option<EgressMode>,
    },
}

impl NetworkPolicy {
    pub fn unrestricted() -> Self {
        Self::Preset {
            preset: NetworkPreset::Unrestricted,
            egress_mode: None,
        }
    }

    pub fn deny_all() -> Self {
        Self::Preset {
            preset: NetworkPreset::None,
            egress_mode: None,
        }
    }

    pub fn preset(preset: NetworkPreset) -> Self {
        Self::Preset {
            preset,
            egress_mode: None,
        }
    }

    /// Construct a preset policy with an explicit `egress_mode`. Used
    /// by callers that want to bake an L7 tier into a template's
    /// `default_network_policy`.
    pub fn preset_with_mode(preset: NetworkPreset, mode: EgressMode) -> Self {
        Self::Preset {
            preset,
            egress_mode: Some(mode),
        }
    }

    pub fn allow_list(rules: Vec<HostPort>) -> Self {
        Self::AllowList {
            rules,
            egress_mode: None,
        }
    }

    /// Construct an allow-list policy with an explicit `egress_mode`.
    pub fn allow_list_with_mode(rules: Vec<HostPort>, mode: EgressMode) -> Self {
        Self::AllowList {
            rules,
            egress_mode: Some(mode),
        }
    }

    /// The baked-in egress mode override, if any. `None` means "fall
    /// back to the host-wide default" — callers should not interpret
    /// `None` as `EgressMode::Open` directly because the host default
    /// can change.
    pub fn egress_mode(&self) -> Option<EgressMode> {
        match self {
            Self::Preset { egress_mode, .. } | Self::AllowList { egress_mode, .. } => *egress_mode,
        }
    }

    /// Whether this policy allows all traffic (no filtering).
    pub fn is_unrestricted(&self) -> bool {
        matches!(
            self,
            Self::Preset {
                preset: NetworkPreset::Unrestricted,
                ..
            }
        )
    }

    /// Resolve to the concrete list of allowed host:port pairs.
    /// Returns `None` if the policy is unrestricted (no filtering needed).
    pub fn resolve_rules(&self) -> Option<Vec<HostPort>> {
        match self {
            Self::Preset { preset, .. } if preset.is_unrestricted() => None,
            Self::Preset { preset, .. } => Some(preset.rules()),
            Self::AllowList { rules, .. } => Some(rules.clone()),
        }
    }

    /// Generate the iptables shell script fragment for this policy.
    /// Returns `None` if unrestricted (no rules needed).
    ///
    /// The script assumes it runs inside the Lima VM with sudo and that
    /// the bridge device and FORWARD chain are already set up.
    pub fn iptables_script(&self, bridge_dev: &str, guest_ip: &str) -> Option<String> {
        let rules = self.resolve_rules()?;

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

    /// Generate the iptables cleanup script for this policy.
    /// Returns `None` if unrestricted (nothing to clean up).
    pub fn iptables_cleanup_script(&self, bridge_dev: &str, guest_ip: &str) -> Option<String> {
        if self.is_unrestricted() {
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
}

impl Default for NetworkPolicy {
    /// Deny-all is the safe default.
    ///
    /// An earlier `Default` returned `unrestricted()`. That posture
    /// contradicted the rest of the security model (the guest is
    /// confined at every other layer; an unrestricted egress default
    /// undermined the claim that untrusted code can't reach arbitrary
    /// network destinations). The default is now `deny_all` so the safe
    /// posture is the one workloads get without opting in.
    ///
    /// Migration shape: `mvmctl up` callers who relied on the old
    /// default get a warning if they explicitly pass
    /// `--network-preset unrestricted`. Template authors who want
    /// open egress declare it in the template's
    /// `default_network_policy`. The escape hatch is named, never
    /// silent.
    fn default() -> Self {
        Self::deny_all()
    }
}

fn registry_rules() -> Vec<HostPort> {
    vec![
        HostPort::new("registry.npmjs.org", 443),
        HostPort::new("crates.io", 443),
        HostPort::new("static.crates.io", 443),
        HostPort::new("index.crates.io", 443),
        HostPort::new("pypi.org", 443),
        HostPort::new("files.pythonhosted.org", 443),
    ]
}

fn dev_extra_rules() -> Vec<HostPort> {
    vec![
        HostPort::new("github.com", 443),
        HostPort::new("github.com", 22),
        HostPort::new("api.github.com", 443),
        HostPort::new("api.openai.com", 443),
        HostPort::new("api.anthropic.com", 443),
    ]
}

/// LLM-agent preset rules.
///
/// Strictly smaller than `dev` — agent VMs are meant to run trusted
/// closures (claude-code, opencode, …) against an inference endpoint
/// plus a code host, not pull arbitrary packages on the fly.
fn agent_rules() -> Vec<HostPort> {
    vec![
        HostPort::new("api.anthropic.com", 443),
        HostPort::new("api.openai.com", 443),
        HostPort::new("github.com", 443),
        HostPort::new("github.com", 22),
        HostPort::new("api.github.com", 443),
    ]
}

// ============================================================================
// Mandatory deny ranges
// ============================================================================

/// CIDR ranges that mvm always denies as egress destinations,
/// regardless of any user-supplied allow-list — blocks metadata
/// endpoints and local control-plane ranges by default.
///
/// Categories represented:
///
/// - **Cloud metadata endpoint** (`169.254.169.254/32`): AWS IMDS,
///   GCP, and Azure all serve instance metadata at this magic
///   address. A microVM with unrestricted egress can read the
///   host's IAM credentials by hitting this endpoint; default-
///   denying it closes the most consequential single-line escape.
/// - **Link-local IPv4** (`169.254.0.0/16`) and **link-local IPv6**
///   (`fe80::/10`): the metadata endpoint plus other host-only
///   services that should never be addressable from a guest. The
///   IPv4 range is the superset of the metadata `/32` — listing
///   both is intentional, so a single-line tamper has to remove
///   two entries (defense in depth).
/// - **CGNAT** (`100.64.0.0/10`): commonly the host's "shared
///   provider" address space on cloud / mobile networks. Often
///   reachable internal services live here.
/// - **Host loopback** (`127.0.0.0/8`, `::1/128`): the host's own
///   services. VM-level isolation should already make these
///   unreachable; the rule is a belt-and-braces guard against a
///   misconfigured bridge.
///
/// Deliberately **NOT** in the list:
///
/// - RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) —
///   commonly legitimate (corporate VPN, home lab, k8s pod
///   network). Operators who want them blocked can add their
///   own deny rules; defaulting to deny would break too many
///   real-world workloads.
/// - Unspecified (`0.0.0.0/32`, `::/128`) — doesn't route.
/// - Multicast (`224.0.0.0/4`, `ff00::/8`) — doesn't reach the
///   public internet; out of scope for egress policy.
/// - IPv6 ULA (`fc00::/7`) — analogous to RFC1918 above.
///
/// Every enforcer (iptables/nft on Linux, `CanonicalEgress::permits`,
/// the L7 egress proxy) should consult this list *before* the user's
/// allow-list.
pub const MANDATORY_DENY_RANGES: &[&str] = &[
    // Cloud metadata first — the most consequential entry. A
    // future operator who edits this list should think twice
    // before touching this line specifically.
    "169.254.169.254/32",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "::1/128",
    "fe80::/10",
];

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
    mandatory_deny_ranges().iter().any(|net| net.contains(&ip))
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
/// policy's [`NetworkPolicy::iptables_script`] output so the
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
        "# Plan 74 W2 §item 4 — mandatory deny ranges (cloud metadata,\n\
         # link-local, CGNAT, host loopback). These rules sit at the top\n\
         # of FORWARD via `-I` so they're checked before any per-policy\n\
         # allow rule — even an `unrestricted` workload cannot reach\n\
         # 169.254.169.254 (AWS IMDS / GCP / Azure metadata).\n",
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
    script
}

/// Cleanup counterpart of [`mandatory_deny_iptables_script`].
/// `iptables -D` removes one matching rule; the
/// `while … 2>/dev/null; do :; done` form drains *all* matching
/// rules so a previously-leaked duplicate (from a prior crashed
/// `apply_network_policy`) doesn't strand a deny rule on the
/// chain. Mirrors the pattern used by
/// [`NetworkPolicy::iptables_cleanup_script`].
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
    script
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_parse() {
        let hp: HostPort = "github.com:443".parse().unwrap();
        assert_eq!(hp.host, "github.com");
        assert_eq!(hp.port, 443);
    }

    #[test]
    fn host_port_parse_missing_port() {
        assert!("github.com".parse::<HostPort>().is_err());
    }

    #[test]
    fn host_port_parse_empty_host() {
        assert!(":443".parse::<HostPort>().is_err());
    }

    #[test]
    fn host_port_parse_invalid_port() {
        assert!("github.com:abc".parse::<HostPort>().is_err());
    }

    #[test]
    fn host_port_display() {
        let hp = HostPort::new("github.com", 443);
        assert_eq!(hp.to_string(), "github.com:443");
    }

    #[test]
    fn host_port_serde_roundtrip() {
        let hp = HostPort::new("api.openai.com", 443);
        let json = serde_json::to_string(&hp).unwrap();
        let parsed: HostPort = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, hp);
    }

    #[test]
    fn preset_parse() {
        assert_eq!("dev".parse::<NetworkPreset>().unwrap(), NetworkPreset::Dev);
        assert_eq!(
            "none".parse::<NetworkPreset>().unwrap(),
            NetworkPreset::None
        );
        assert_eq!(
            "registries".parse::<NetworkPreset>().unwrap(),
            NetworkPreset::Registries
        );
        assert_eq!(
            "unrestricted".parse::<NetworkPreset>().unwrap(),
            NetworkPreset::Unrestricted
        );
    }

    #[test]
    fn preset_parse_invalid() {
        assert!("foo".parse::<NetworkPreset>().is_err());
    }

    #[test]
    fn preset_display_roundtrip() {
        for preset in [
            NetworkPreset::Unrestricted,
            NetworkPreset::None,
            NetworkPreset::Registries,
            NetworkPreset::Dev,
        ] {
            let s = preset.to_string();
            let parsed: NetworkPreset = s.parse().unwrap();
            assert_eq!(parsed, preset);
        }
    }

    #[test]
    fn preset_rules_dev_includes_registries() {
        let dev_rules = NetworkPreset::Dev.rules();
        let reg_rules = NetworkPreset::Registries.rules();
        for reg in &reg_rules {
            assert!(
                dev_rules.contains(reg),
                "dev preset should include registry rule {}",
                reg
            );
        }
    }

    #[test]
    fn preset_rules_dev_has_github_and_ai() {
        let rules = NetworkPreset::Dev.rules();
        let hosts: Vec<&str> = rules.iter().map(|r| r.host.as_str()).collect();
        assert!(hosts.contains(&"github.com"));
        assert!(hosts.contains(&"api.openai.com"));
        assert!(hosts.contains(&"api.anthropic.com"));
    }

    #[test]
    fn preset_agent_parses_and_displays() {
        assert_eq!(
            "agent".parse::<NetworkPreset>().unwrap(),
            NetworkPreset::Agent
        );
        assert_eq!(NetworkPreset::Agent.to_string(), "agent");
    }

    #[test]
    fn preset_agent_has_inference_apis_and_github() {
        let rules = NetworkPreset::Agent.rules();
        let hosts: Vec<&str> = rules.iter().map(|r| r.host.as_str()).collect();
        assert!(
            hosts.contains(&"api.anthropic.com"),
            "agent preset must include Anthropic"
        );
        assert!(
            hosts.contains(&"api.openai.com"),
            "agent preset must include OpenAI"
        );
        assert!(
            hosts.contains(&"github.com"),
            "agent preset must include GitHub"
        );
    }

    #[test]
    fn preset_agent_excludes_package_registries() {
        // Agent preset is strictly smaller than dev.
        // No npm, no PyPI, no crates.io — agents are meant to run
        // pre-resolved closures, not pull packages at runtime.
        let rules = NetworkPreset::Agent.rules();
        let hosts: Vec<&str> = rules.iter().map(|r| r.host.as_str()).collect();
        assert!(!hosts.contains(&"registry.npmjs.org"));
        assert!(!hosts.contains(&"crates.io"));
        assert!(!hosts.contains(&"pypi.org"));
    }

    #[test]
    fn egress_mode_default_is_open() {
        assert_eq!(EgressMode::default(), EgressMode::Open);
    }

    #[test]
    fn egress_mode_parse_canonical() {
        assert_eq!("open".parse::<EgressMode>().unwrap(), EgressMode::Open);
        assert_eq!("l3-only".parse::<EgressMode>().unwrap(), EgressMode::L3Only);
        assert_eq!(
            "l3-plus-l7".parse::<EgressMode>().unwrap(),
            EgressMode::L3PlusL7
        );
    }

    #[test]
    fn egress_mode_parse_aliases() {
        assert_eq!("l3".parse::<EgressMode>().unwrap(), EgressMode::L3Only);
        assert_eq!("l7".parse::<EgressMode>().unwrap(), EgressMode::L3PlusL7);
        assert_eq!("l3+l7".parse::<EgressMode>().unwrap(), EgressMode::L3PlusL7);
    }

    #[test]
    fn egress_mode_parse_unknown_errors() {
        assert!("bogus".parse::<EgressMode>().is_err());
    }

    #[test]
    fn egress_mode_display_roundtrip() {
        for mode in [EgressMode::Open, EgressMode::L3Only, EgressMode::L3PlusL7] {
            let s = mode.to_string();
            assert_eq!(s.parse::<EgressMode>().unwrap(), mode);
        }
    }

    #[test]
    fn egress_mode_serde_roundtrip() {
        for mode in [EgressMode::Open, EgressMode::L3Only, EgressMode::L3PlusL7] {
            let json = serde_json::to_string(&mode).unwrap();
            let parsed: EgressMode = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, mode);
        }
    }

    #[test]
    fn preset_rules_none_is_empty() {
        assert!(NetworkPreset::None.rules().is_empty());
    }

    #[test]
    fn preset_rules_unrestricted_is_empty() {
        assert!(NetworkPreset::Unrestricted.rules().is_empty());
    }

    #[test]
    fn policy_default_is_deny_all() {
        // claim 10: the safe default is deny-all. Workloads
        // that need network access opt in explicitly via
        // `--network-preset` or a template's
        // `default_network_policy`. The escape hatch is
        // `--network-preset unrestricted`, which mvmctl warns about
        // at launch.
        let default = NetworkPolicy::default();
        assert!(!default.is_unrestricted());
        let rules = default
            .resolve_rules()
            .expect("default resolves to a concrete rule set");
        assert!(rules.is_empty(), "deny-all should yield no allow rules");
    }

    #[test]
    fn policy_unrestricted_no_rules() {
        assert!(NetworkPolicy::unrestricted().resolve_rules().is_none());
    }

    #[test]
    fn policy_deny_all_empty_rules() {
        let rules = NetworkPolicy::deny_all().resolve_rules().unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn policy_preset_dev_resolves() {
        let policy = NetworkPolicy::preset(NetworkPreset::Dev);
        let rules = policy.resolve_rules().unwrap();
        assert!(!rules.is_empty());
        assert!(rules.iter().any(|r| r.host == "github.com"));
    }

    #[test]
    fn policy_allow_list_resolves() {
        let policy = NetworkPolicy::allow_list(vec![
            HostPort::new("example.com", 443),
            HostPort::new("example.com", 80),
        ]);
        let rules = policy.resolve_rules().unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn policy_serde_roundtrip_preset() {
        let policy = NetworkPolicy::preset(NetworkPreset::Dev);
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: NetworkPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, policy);
    }

    #[test]
    fn policy_serde_roundtrip_allow_list() {
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("example.com", 443)]);
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: NetworkPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, policy);
    }

    #[test]
    fn iptables_script_unrestricted_is_none() {
        let policy = NetworkPolicy::unrestricted();
        assert!(policy.iptables_script("br-mvm", "172.16.0.2").is_none());
    }

    #[test]
    fn iptables_script_deny_all_has_drop_no_host_rules() {
        let policy = NetworkPolicy::deny_all();
        let script = policy.iptables_script("br-mvm", "172.16.0.2").unwrap();
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
        let script = policy.iptables_script("br-mvm", "172.16.0.3").unwrap();
        assert!(script.contains("-d github.com"));
        assert!(script.contains("-d api.openai.com"));
        assert!(script.contains("--dport 443"));
        assert!(script.contains("-s 172.16.0.3"));
        assert!(script.contains("-i br-mvm"));
    }

    #[test]
    fn iptables_cleanup_unrestricted_is_none() {
        let policy = NetworkPolicy::unrestricted();
        assert!(
            policy
                .iptables_cleanup_script("br-mvm", "172.16.0.2")
                .is_none()
        );
    }

    #[test]
    fn iptables_cleanup_deny_all_has_commands() {
        let policy = NetworkPolicy::deny_all();
        let script = policy
            .iptables_cleanup_script("br-mvm", "172.16.0.2")
            .unwrap();
        assert!(script.contains("iptables -D FORWARD"));
    }

    // --- egress_mode enrichment ---

    #[test]
    fn egress_mode_default_is_none_on_constructors() {
        // The base constructors leave the field unset so behaviour
        // matches the host-wide default; this is the back-compat path.
        assert!(NetworkPolicy::unrestricted().egress_mode().is_none());
        assert!(NetworkPolicy::deny_all().egress_mode().is_none());
        assert!(
            NetworkPolicy::preset(NetworkPreset::Dev)
                .egress_mode()
                .is_none()
        );
        assert!(
            NetworkPolicy::allow_list(vec![HostPort::new("example.com", 443)])
                .egress_mode()
                .is_none()
        );
    }

    #[test]
    fn egress_mode_with_explicit_mode_constructors() {
        let p = NetworkPolicy::preset_with_mode(NetworkPreset::Agent, EgressMode::L3PlusL7);
        assert_eq!(p.egress_mode(), Some(EgressMode::L3PlusL7));

        let a = NetworkPolicy::allow_list_with_mode(
            vec![HostPort::new("api.anthropic.com", 443)],
            EgressMode::L3Only,
        );
        assert_eq!(a.egress_mode(), Some(EgressMode::L3Only));
    }

    #[test]
    fn egress_mode_serde_roundtrip_with_mode() {
        let original = NetworkPolicy::preset_with_mode(NetworkPreset::Agent, EgressMode::L3PlusL7);
        let json = serde_json::to_string(&original).unwrap();
        // Field must be present on the wire when set.
        assert!(json.contains("egress_mode"));
        assert!(json.contains("l3-plus-l7"));
        let parsed: NetworkPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn egress_mode_serde_omits_field_when_none() {
        // skip_serializing_if must elide the field for back-compat
        // with consumers that don't know about egress_mode yet.
        let policy = NetworkPolicy::preset(NetworkPreset::Dev);
        let json = serde_json::to_string(&policy).unwrap();
        assert!(
            !json.contains("egress_mode"),
            "egress_mode must not appear when None: {json}"
        );
    }

    #[test]
    fn pre_plan_34_serialised_form_still_parses() {
        // A NetworkPolicy serialised before `egress_mode` existed has
        // no such field. `#[serde(default)]` must accept it.
        let preset_json = r#"{"type":"preset","preset":"dev"}"#;
        let parsed: NetworkPolicy = serde_json::from_str(preset_json).unwrap();
        assert_eq!(parsed, NetworkPolicy::preset(NetworkPreset::Dev));
        assert!(parsed.egress_mode().is_none());

        let allowlist_json = r#"{"type":"allowlist","rules":[{"host":"example.com","port":443}]}"#;
        let parsed_al: NetworkPolicy = serde_json::from_str(allowlist_json).unwrap();
        assert_eq!(
            parsed_al,
            NetworkPolicy::allow_list(vec![HostPort::new("example.com", 443)])
        );
        assert!(parsed_al.egress_mode().is_none());
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
    fn mandatory_deny_iptables_script_scopes_to_guest_source() {
        let script = mandatory_deny_iptables_script("br-mvm", "172.16.0.2");
        // Every line that adds a rule must be scoped to the
        // guest's source IP — otherwise a sibling guest's
        // traffic could be affected by cleanup of this one.
        for line in script.lines().filter(|l| l.contains("iptables -I")) {
            assert!(
                line.contains("-s 172.16.0.2"),
                "deny rule line must scope to the guest IP: {line}"
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
