//! Egress-policy DTOs — the pure, wire-shape half of `NetworkPolicy`.
//!
//! `HostPort`, `NetworkPreset`, `EgressMode`, `NetworkPolicy`, the
//! `BANNED_SSH_PORT`/`MANDATORY_DENY_RANGES` consts, and every pure
//! constructor/accessor live here. The `ipnet`/`std::net` mandatory-deny
//! logic and the iptables script generators (which need a concrete
//! `NetworkPolicy` plus host networking types) stay in
//! `mvm_core::policy::network_policy`, which re-exports every type in
//! this module at its existing path.

use core::fmt;
use core::str::FromStr;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

// ============================================================================
// Errors
// ============================================================================

/// Errors from parsing the string forms of [`HostPort`], [`NetworkPreset`],
/// or [`EgressMode`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetworkPolicyParseError {
    /// A `HostPort` string had no `:PORT` suffix.
    #[error("expected host:port, got {0:?}")]
    MissingPort(String),
    /// A `HostPort` string's host component was empty.
    #[error("host cannot be empty in {0:?}")]
    EmptyHost(String),
    /// A `HostPort` string's port component didn't parse as a `u16`.
    #[error("invalid port in {0:?}")]
    InvalidPort(String),
    /// Not one of the named [`NetworkPreset`] variants.
    #[error("unknown network preset {0:?} (expected: unrestricted, none, registries, dev, agent)")]
    UnknownPreset(String),
    /// Not one of the named [`EgressMode`] variants (or their aliases).
    #[error("unknown egress mode {0:?} (expected: open, l3-only, l3-plus-l7)")]
    UnknownEgressMode(String),
}

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
    type Err = NetworkPolicyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| NetworkPolicyParseError::MissingPort(s.to_string()))?;
        if host.is_empty() {
            return Err(NetworkPolicyParseError::EmptyHost(s.to_string()));
        }
        let port: u16 = port
            .parse()
            .map_err(|_| NetworkPolicyParseError::InvalidPort(s.to_string()))?;
        Ok(Self::new(host, port))
    }
}

/// TCP/22 is reserved for SSH and is never an admitted guest egress target.
///
/// This is deliberately separate from the CIDR mandatory-deny list: SSH is a
/// protocol/port ban, not an address range. Runtime gates still enforce it in
/// the shared L4 projection path so an open policy cannot override it.
pub const BANNED_SSH_PORT: u16 = 22;

pub fn is_banned_ssh_port(port: u16) -> bool {
    port == BANNED_SSH_PORT
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
            Self::Unrestricted => Vec::new(), // empty = no filtering
            Self::None => Vec::new(),         // empty + applied as deny-all
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
    type Err = NetworkPolicyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unrestricted" => Ok(Self::Unrestricted),
            "none" => Ok(Self::None),
            "registries" => Ok(Self::Registries),
            "dev" => Ok(Self::Dev),
            "agent" => Ok(Self::Agent),
            _ => Err(NetworkPolicyParseError::UnknownPreset(s.to_string())),
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
    type Err = NetworkPolicyParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(Self::Open),
            "l3-only" | "l3" => Ok(Self::L3Only),
            "l3-plus-l7" | "l3+l7" | "l7" => Ok(Self::L3PlusL7),
            other => Err(NetworkPolicyParseError::UnknownEgressMode(
                other.to_string(),
            )),
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

    /// Egress grant for **trusted build/dev infrastructure** only — the
    /// Stage-0 builder VM and dev shells, which fetch from arbitrary Nix
    /// substituters/forges and so can't use a tight allow-list yet. This
    /// is unrestricted egress, but cloud-metadata + link-local stay blocked
    /// by the always-on mandatory-deny. It exists as one named, greppable
    /// constructor so every broad-egress grant is auditable and can never
    /// be confused with a workload policy. **Never** use it for a workload
    /// (`mvmctl run`/`up`/`invoke`): those default to `deny_all`.
    pub fn trusted_build_egress() -> Self {
        Self::unrestricted()
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

    /// Whether this policy grants any outbound egress at all.
    ///
    /// `unrestricted` obviously does; allow-lists and named presets do iff
    /// they expand to at least one host:port rule. Both the explicit
    /// deny-all preset and an empty allow-list return `false`.
    pub fn allows_egress(&self) -> bool {
        self.is_unrestricted() || self.resolve_rules().is_some_and(|rules| !rules.is_empty())
    }

    /// Short, non-sensitive, human-readable summary of the effective
    /// egress posture for admission/audit/dry-run/receipt surfaces.
    ///
    /// Carries only the preset name or the declared host:port allow-list
    /// (user-supplied destinations, classified non-sensitive like the
    /// run profile) — never credentials. `deny-all` and `unrestricted`
    /// are spelled out so a reader never has to know that the deny-all
    /// default is internally `Preset { None }`.
    pub fn posture_label(&self) -> String {
        match self {
            Self::Preset {
                preset: NetworkPreset::None,
                ..
            } => "deny-all".to_string(),
            Self::Preset {
                preset: NetworkPreset::Unrestricted,
                ..
            } => "unrestricted".to_string(),
            Self::Preset { preset, .. } => format!("preset:{preset}"),
            Self::AllowList { rules, .. } if rules.is_empty() => "deny-all".to_string(),
            Self::AllowList { rules, .. } => {
                let mut hosts: Vec<String> = rules.iter().map(HostPort::to_string).collect();
                hosts.sort();
                hosts.dedup();
                format!("allow-list:{}", hosts.join(","))
            }
        }
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
    alloc::vec![
        HostPort::new("registry.npmjs.org", 443),
        HostPort::new("crates.io", 443),
        HostPort::new("static.crates.io", 443),
        HostPort::new("index.crates.io", 443),
        HostPort::new("pypi.org", 443),
        HostPort::new("files.pythonhosted.org", 443),
    ]
}

fn dev_extra_rules() -> Vec<HostPort> {
    alloc::vec![
        HostPort::new("github.com", 443),
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
    alloc::vec![
        HostPort::new("api.anthropic.com", 443),
        HostPort::new("api.openai.com", 443),
        HostPort::new("github.com", 443),
        HostPort::new("api.github.com", 443),
    ]
}

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

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn host_port_parse() {
        let hp: HostPort = "github.com:443".parse().unwrap();
        assert_eq!(hp.host, "github.com");
        assert_eq!(hp.port, 443);
    }

    #[test]
    fn posture_label_covers_every_shape() {
        assert_eq!(NetworkPolicy::deny_all().posture_label(), "deny-all");
        assert_eq!(
            NetworkPolicy::unrestricted().posture_label(),
            "unrestricted"
        );
        assert_eq!(
            NetworkPolicy::preset(NetworkPreset::Dev).posture_label(),
            "preset:dev"
        );
        // An empty allow-list is deny-all, not an empty "allow-list:".
        assert_eq!(
            NetworkPolicy::allow_list(vec![]).posture_label(),
            "deny-all"
        );
        // Hosts are sorted + deduped so the label is stable and non-sensitive.
        assert_eq!(
            NetworkPolicy::allow_list(vec![
                HostPort::new("b.com", 8443),
                HostPort::new("a.com", 443),
                HostPort::new("a.com", 443),
            ])
            .posture_label(),
            "allow-list:a.com:443,b.com:8443"
        );
    }

    #[test]
    fn allows_egress_covers_every_shape() {
        assert!(!NetworkPolicy::deny_all().allows_egress());
        assert!(!NetworkPolicy::allow_list(vec![]).allows_egress());
        assert!(NetworkPolicy::unrestricted().allows_egress());
        assert!(NetworkPolicy::preset(NetworkPreset::Dev).allows_egress());
        assert!(NetworkPolicy::allow_list(vec![HostPort::new("a.com", 443)]).allows_egress());
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
    fn built_in_presets_do_not_grant_ssh_port() {
        for preset in [
            NetworkPreset::Registries,
            NetworkPreset::Dev,
            NetworkPreset::Agent,
        ] {
            let offenders: Vec<_> = preset
                .rules()
                .into_iter()
                .filter(|rule| is_banned_ssh_port(rule.port))
                .collect();
            assert!(
                offenders.is_empty(),
                "{preset} must not authorize SSH port 22: {offenders:?}"
            );
        }
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
}
