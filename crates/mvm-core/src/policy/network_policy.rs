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
    /// LLM-agent preset (plan 32 / Proposal D / ADR-004): the LLM
    /// inference APIs an agent typically calls (Anthropic, OpenAI),
    /// plus GitHub for source operations. Minimum surface for
    /// `nix/images/examples/llm-agent/`'s `claude-code-vm`. Strictly
    /// smaller than `dev` — does NOT include package registries,
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

/// Egress enforcement layer (plan 32 / Proposal D / ADR-004).
///
/// The three-layer model lives in ADR-004; this enum lets callers
/// pick which layers apply. v1 (D shipped) wires only L3; v2
/// (plan 34, deferred) adds the L7 SNI/Host proxy + DNS pinning.
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
    /// for HTTP. Plan 34 / ADR-004 §"L7" covers the runtime impl;
    /// today this variant returns "egress proxy not implemented" at
    /// `tap_create` time so callers see a clear error rather than a
    /// silent downgrade.
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
/// The optional `egress_mode` enrichment is plan 34's per-policy
/// override. When present, it pins the L3/L7 enforcement tier for the
/// policy at apply-time; when `None`, callers fall back to the
/// host-wide default (today: `EgressMode::Open`, equivalent to the
/// pre-plan-34 behaviour). The field is deliberately co-located on
/// each variant rather than as a sibling field so a `Preset` and a
/// hand-rolled `AllowList` can both attach a mode without forcing
/// every consumer to re-thread a separate parameter — see plan 34
/// §"Per-template default_network_policy interaction".
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
    /// by plan 34 callers that want to bake an L7 tier into a
    /// template's `default_network_policy`.
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
    fn default() -> Self {
        Self::unrestricted()
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

/// LLM-agent preset rules (plan 32 / Proposal D / ADR-004).
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
        // Plan 32 / Proposal D: agent preset is strictly smaller than dev.
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
    fn policy_default_is_unrestricted() {
        assert!(NetworkPolicy::default().is_unrestricted());
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

    // --- Plan 34 / ADR-006 egress_mode enrichment ---

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
        // with consumers that don't know about plan 34 yet.
        let policy = NetworkPolicy::preset(NetworkPreset::Dev);
        let json = serde_json::to_string(&policy).unwrap();
        assert!(
            !json.contains("egress_mode"),
            "egress_mode must not appear when None: {json}"
        );
    }

    #[test]
    fn pre_plan_34_serialised_form_still_parses() {
        // A NetworkPolicy serialised before plan 34 has no
        // `egress_mode` field. `#[serde(default)]` must accept it.
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
}
