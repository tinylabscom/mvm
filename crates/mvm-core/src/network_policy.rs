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
            _ => anyhow::bail!(
                "unknown network preset {:?} (expected: unrestricted, none, registries, dev)",
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
        }
    }
}

/// Network policy for a microVM, controlling outbound traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum NetworkPolicy {
    /// Use a built-in preset.
    Preset { preset: NetworkPreset },
    /// Explicit allowlist of host:port pairs.
    AllowList { rules: Vec<HostPort> },
}

impl NetworkPolicy {
    pub fn unrestricted() -> Self {
        Self::Preset {
            preset: NetworkPreset::Unrestricted,
        }
    }

    pub fn deny_all() -> Self {
        Self::Preset {
            preset: NetworkPreset::None,
        }
    }

    pub fn preset(preset: NetworkPreset) -> Self {
        Self::Preset { preset }
    }

    pub fn allow_list(rules: Vec<HostPort>) -> Self {
        Self::AllowList { rules }
    }

    /// Whether this policy allows all traffic (no filtering).
    pub fn is_unrestricted(&self) -> bool {
        matches!(
            self,
            Self::Preset {
                preset: NetworkPreset::Unrestricted
            }
        )
    }

    /// Resolve to the concrete list of allowed host:port pairs.
    /// Returns `None` if the policy is unrestricted (no filtering needed).
    pub fn resolve_rules(&self) -> Option<Vec<HostPort>> {
        match self {
            Self::Preset { preset } if preset.is_unrestricted() => None,
            Self::Preset { preset } => Some(preset.rules()),
            Self::AllowList { rules } => Some(rules.clone()),
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
}
