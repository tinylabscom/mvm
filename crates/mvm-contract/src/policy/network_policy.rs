//! Egress-policy DTOs — the pure, wire-shape half of `NetworkPolicy`.
//!
//! `HostPort`, `NetworkPreset`, `EgressMode`, `NetworkPolicy`, the
//! `BANNED_SSH_PORT`/`MANDATORY_DENY_RANGES` consts, every pure
//! constructor/accessor, and the mandatory-deny predicates the egress
//! projection decides with live here. The iptables script generators
//! (host-only shell emission) stay in `mvm_core::policy::network_policy`,
//! which re-exports everything in this module at its existing path.

use core::fmt;
use core::net::IpAddr;
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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

/// AI-specific egress policy attached to a network grant.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AiPolicy {
    /// Whether to record AI token usage for this workload.
    #[serde(default)]
    pub metering: bool,
    /// Optional token budget. `None` means no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<AiBudget>,
}

impl AiPolicy {
    /// A policy with metering off and no budget.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// A policy with metering on and no budget.
    pub fn metered() -> Self {
        Self {
            metering: true,
            budget: None,
        }
    }

    /// A policy with metering on and a total-token budget.
    pub fn metered_with_total_budget(max_total_tokens: u64) -> Self {
        Self {
            metering: true,
            budget: Some(AiBudget {
                max_input_tokens: None,
                max_output_tokens: None,
                max_total_tokens: Some(max_total_tokens),
            }),
        }
    }
}

/// Token budget for AI egress. A `None` field means no limit for that category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AiBudget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_input_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_tokens: Option<u64>,
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum NetworkPolicy {
    /// Use a built-in preset.
    Preset {
        preset: NetworkPreset,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        egress_mode: Option<EgressMode>,
        /// Optional AI egress metering and budget policy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ai: Option<AiPolicy>,
    },
    /// Explicit allowlist of host:port pairs.
    AllowList {
        rules: Vec<HostPort>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        egress_mode: Option<EgressMode>,
        /// Optional AI egress metering and budget policy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ai: Option<AiPolicy>,
    },
}

impl NetworkPolicy {
    pub fn unrestricted() -> Self {
        Self::Preset {
            preset: NetworkPreset::Unrestricted,
            egress_mode: None,
            ai: None,
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
            ai: None,
        }
    }

    pub fn preset(preset: NetworkPreset) -> Self {
        Self::Preset {
            preset,
            egress_mode: None,
            ai: None,
        }
    }

    /// Construct a preset policy with an explicit `egress_mode`. Used
    /// by callers that want to bake an L7 tier into a template's
    /// `default_network_policy`.
    pub fn preset_with_mode(preset: NetworkPreset, mode: EgressMode) -> Self {
        Self::Preset {
            preset,
            egress_mode: Some(mode),
            ai: None,
        }
    }

    pub fn allow_list(rules: Vec<HostPort>) -> Self {
        Self::AllowList {
            rules,
            egress_mode: None,
            ai: None,
        }
    }

    /// Construct an allow-list policy with an explicit `egress_mode`.
    pub fn allow_list_with_mode(rules: Vec<HostPort>, mode: EgressMode) -> Self {
        Self::AllowList {
            rules,
            egress_mode: Some(mode),
            ai: None,
        }
    }

    /// Construct a preset policy with an AI metering/budget attachment.
    pub fn preset_with_ai(preset: NetworkPreset, ai: Option<AiPolicy>) -> Self {
        Self::Preset {
            preset,
            egress_mode: None,
            ai,
        }
    }

    /// Construct an allow-list policy with an AI metering/budget attachment.
    pub fn allow_list_with_ai(rules: Vec<HostPort>, ai: Option<AiPolicy>) -> Self {
        Self::AllowList {
            rules,
            egress_mode: None,
            ai,
        }
    }

    /// Return this policy with the AI attachment replaced.
    pub fn with_ai(self, ai: Option<AiPolicy>) -> Self {
        match self {
            Self::Preset {
                preset,
                egress_mode,
                ..
            } => Self::Preset {
                preset,
                egress_mode,
                ai,
            },
            Self::AllowList {
                rules, egress_mode, ..
            } => Self::AllowList {
                rules,
                egress_mode,
                ai,
            },
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

    /// The AI egress metering/budget policy, if any. `None` means no AI
    /// metering and no budget.
    pub fn ai(&self) -> Option<&AiPolicy> {
        match self {
            Self::Preset { ai, .. } | Self::AllowList { ai, .. } => ai.as_ref(),
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
pub fn is_mandatory_deny(ip: IpAddr) -> bool {
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
pub fn unmap_v4_mapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(_) => ip,
    }
}

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

    /// The SSH ban has production callers in the L4 projection and the CLI
    /// resolver, but this crate only ever asserted the negative direction
    /// — so pinning the predicate to `false` disarmed the ban here without
    /// failing anything.
    #[test]
    fn ssh_port_is_banned_and_its_neighbours_are_not() {
        assert!(is_banned_ssh_port(BANNED_SSH_PORT));
        assert!(is_banned_ssh_port(22));
        assert!(!is_banned_ssh_port(21));
        assert!(!is_banned_ssh_port(23));
        assert!(!is_banned_ssh_port(2222));
        assert!(!is_banned_ssh_port(0));
    }

    /// Both directions of both preset predicates. Asserting only that a
    /// preset *is* deny-all leaves a constant-`true` predicate — one that
    /// calls every preset deny-all, including `Unrestricted` — passing.
    #[test]
    fn preset_predicates_hold_only_for_their_own_preset() {
        assert!(NetworkPreset::None.is_deny_all());
        assert!(!NetworkPreset::Unrestricted.is_deny_all());
        assert!(!NetworkPreset::Dev.is_deny_all());

        assert!(NetworkPreset::Unrestricted.is_unrestricted());
        assert!(!NetworkPreset::None.is_unrestricted());
        assert!(!NetworkPreset::Dev.is_unrestricted());
    }

    /// The one named broad-egress grant. The builder VM and dev shells
    /// depend on it actually being unrestricted; substituting the deny-all
    /// default breaks every Nix fetch, and nothing here noticed.
    #[test]
    fn trusted_build_egress_is_unrestricted_not_the_deny_all_default() {
        let policy = NetworkPolicy::trusted_build_egress();
        assert_eq!(policy, NetworkPolicy::unrestricted());
        assert_ne!(policy, NetworkPolicy::deny_all());
        assert_ne!(policy, NetworkPolicy::default());
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

    #[test]
    fn ai_policy_roundtrips_through_json() {
        let policy = AiPolicy {
            metering: true,
            budget: Some(AiBudget {
                max_input_tokens: Some(100),
                max_output_tokens: Some(200),
                max_total_tokens: Some(300),
            }),
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: AiPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn ai_policy_constructors_preserve_metering_intent() {
        assert_eq!(AiPolicy::disabled(), AiPolicy::default());

        let policy = AiPolicy::metered();
        assert!(policy.metering);
        assert_eq!(policy.budget, None);
        assert_ne!(policy, AiPolicy::default());
    }

    #[test]
    fn network_policy_with_ai_roundtrips() {
        let policy = NetworkPolicy::AllowList {
            rules: vec![HostPort::new("api.openai.com", 443)],
            egress_mode: None,
            ai: Some(AiPolicy::metered_with_total_budget(1_000_000)),
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: NetworkPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
        assert!(back.ai().is_some());
        assert!(back.ai().unwrap().metering);
        assert_eq!(
            back.ai().unwrap().budget.unwrap().max_total_tokens,
            Some(1_000_000)
        );
    }

    #[test]
    fn network_policy_default_has_no_ai() {
        let policy = NetworkPolicy::deny_all();
        assert!(policy.ai().is_none());
    }
}
