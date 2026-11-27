//! Sub-policy shapes carried by [`EffectivePolicy`].
//!
//! No field here is enforced. The workload actor lifecycle carries an
//! `EffectivePolicy` in its manifest, requires the default value, and
//! compares a child's with its parent's. Egress is enforced from the
//! launch's [`NetworkPolicy`], not from these types. `PiiPolicy` is also the
//! shape the stream plane's redactor reads from its own configuration.
//!
//! [`EffectivePolicy`]: crate::policy::resolver::EffectivePolicy
//! [`NetworkPolicy`]: crate::policy::network_policy::NetworkPolicy
//!
//! Every type uses `#[serde(deny_unknown_fields)]` so a future
//! field addition is a fail-closed schema bump for older verifiers,
//! and every type derives `Default`.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Network policy shape. Not enforced: the egress gate is built from the
/// launch's `NetworkPolicy`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleNetworkPolicy {
    /// Network preset name.
    pub preset: Option<String>,
    /// L4 rows (`proto`, `dst_cidr`, port range).
    #[serde(default)]
    pub l4: Vec<L4RuleSpec>,
    /// Observer names.
    #[serde(default)]
    pub observers: Vec<String>,
    /// Flow-byte log settings. Nothing writes a flow-byte log from it.
    #[serde(default)]
    pub flow_byte_log: Option<FlowByteLogSpec>,
}

/// Retention + scope for the opt-in flow-byte log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowByteLogSpec {
    /// Hard cap on bytes-on-disk per VM before rotation drops oldest.
    pub max_disk_bytes: u64,
    /// Records older than this are swept by `mvmctl cache prune`.
    pub max_age_days: u32,
    /// Which directions to log.
    pub directions: FlowByteLogDirections,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowByteLogDirections {
    Egress,
    Ingress,
    Both,
}

/// L4 rule row shape inside `[[network.l4]]`. Not parsed into a gate
/// rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L4RuleSpec {
    /// `"tcp"` or `"udp"`.
    pub proto: String,
    /// Destination CIDR.
    pub dst_cidr: String,
    /// Inclusive low bound of the destination port range.
    pub port_lo: u16,
    /// Inclusive high bound. `port_lo == 0 && port_hi == 0` is the
    /// "any port for this (proto, cidr)" wildcard.
    pub port_hi: u16,
}

/// Egress policy shape. Not enforced: the egress gate is built from the
/// launch's `NetworkPolicy`, and a plan's redaction and reversible
/// replacement come from the launch, not from here.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressPolicy {
    /// Egress mode name.
    pub mode: Option<String>,
    /// (host, port) allowlist.
    #[serde(default)]
    pub allow_list: Vec<(String, u16)>,
    /// Whether plain HTTP (not just CONNECT/HTTPS) is permitted. No
    /// code reads it today.
    #[serde(default)]
    pub allow_plain_http: bool,
    /// Body read cap for plain-HTTP (bytes). No code reads it today; the
    /// endpoint's redaction applies [`DEFAULT_BODY_CAP_BYTES`].
    #[serde(default)]
    pub body_cap_bytes: u64,
    /// Per-name inspector opt-out. Admission accepts only the names
    /// `destination_policy`, `ssrf_guard`, `secrets_scanner`,
    /// `injection_guard` and `pii_redactor`; no inspector chain reads
    /// the field today.
    #[serde(default)]
    pub disabled_inspectors: Vec<String>,
    /// Per-destination egress redaction.
    #[serde(default)]
    pub redaction: crate::policy::redaction::RedactionPolicy,
    /// Per-destination reversible replacement / reinjection.
    #[serde(default)]
    pub reversible_replacement: crate::policy::reversible_replacement::ReversibleReplacementPolicy,
}

/// Body cap the endpoint's redaction applies. 16 MiB — matches
/// AI-provider request sizes (long contexts + image uploads).
pub const DEFAULT_BODY_CAP_BYTES: u64 = 16 * 1024 * 1024;

/// One filesystem-preopen grant in a policy bound. `access` is the
/// wire string `"ro"` / `"rw"`; anything else refuses at projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsGrantSpec {
    pub guest_path: String,
    pub access: String,
}

/// The tenant bound on a wasm-component's WASI capabilities: which
/// filesystem preopens and env-var names it may receive. Deny-by-
/// default — an empty policy grants nothing.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasiCapPolicy {
    #[serde(default)]
    pub fs: Vec<FsGrantSpec>,
    #[serde(default)]
    pub env: Vec<String>,
}

/// PII redaction policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PiiPolicy {
    /// `disabled` / `detect` / `redact` / `refuse`. Stub.
    pub mode: Option<String>,
    /// Categories to act on (`email`, `cc_number`, `ssn`, ...).
    /// Empty means all categories the redactor knows about.
    #[serde(default)]
    pub categories: Vec<String>,
}

/// Artifact policy shape. Distinct from `mvm-core::plan::ArtifactPolicy`,
/// the per-run plan field. Nothing collects artifacts from it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ArtifactPolicy {
    pub capture_paths: Vec<String>,
    pub retention_days: u32,
}

/// Key policy. Parsed and validated; nothing reads it at runtime today.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KeyPolicy {
    /// 0 = no rotation; supervisor warns but accepts.
    pub rotation_interval_days: u32,
}

/// Audit policy shape. Nothing configures an emitter from it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuditPolicy {
    /// Whether the supervisor should chain-sign each entry into the
    /// previous's hash for tamper-evidence.
    pub chain_signing: bool,
    /// Audit-stream destinations.
    pub stream_destinations: Vec<String>,
}

#[cfg(test)]
mod plan_113_observer_tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    #[test]
    fn network_policy_parses_observers_chain() {
        let toml = r#"
preset = "deny-by-default"
observers = ["flow-count-metrics"]
"#;
        let p: BundleNetworkPolicy = toml::from_str(toml).expect("parse");
        assert_eq!(p.observers, vec!["flow-count-metrics".to_string()]);
    }

    #[test]
    fn network_policy_missing_observers_defaults_empty() {
        let toml = r#"
preset = "deny-by-default"
"#;
        let p: BundleNetworkPolicy = toml::from_str(toml).expect("parse");
        assert!(p.observers.is_empty());
    }

    #[test]
    fn network_policy_backward_compat_with_v1_bundle() {
        // A bundle file written before the observer chain existed has no
        // `observers` field; it must still parse and behave like an empty chain.
        // L4RuleSpec uses `proto` / `dst_cidr` / `port_lo` / `port_hi`
        // (see definition above) — the v1 bundle row matches that
        // shape exactly.
        let toml = r#"
preset = "deny-by-default"

[[l4]]
proto    = "tcp"
dst_cidr = "10.0.0.0/24"
port_lo  = 443
port_hi  = 443
"#;
        let p: BundleNetworkPolicy = toml::from_str(toml).expect("parse v1 bundle");
        assert_eq!(p.l4.len(), 1);
        assert!(p.observers.is_empty());
    }

    #[test]
    fn network_policy_flow_byte_log_defaults_off() {
        // A bundle without the field still parses and logging is off.
        let np = BundleNetworkPolicy::default();
        assert!(np.flow_byte_log.is_none());
        let p: BundleNetworkPolicy =
            toml::from_str("preset = \"open\"\n").expect("parse without field");
        assert!(p.flow_byte_log.is_none());
    }

    #[test]
    fn flow_byte_log_spec_serde_roundtrip() {
        let spec = FlowByteLogSpec {
            max_disk_bytes: 1_000_000,
            max_age_days: 7,
            directions: FlowByteLogDirections::Egress,
        };
        let toml_str = toml::to_string(&spec).unwrap();
        let back: FlowByteLogSpec = toml::from_str(&toml_str).unwrap();
        assert_eq!(spec, back);
        assert!(toml_str.contains("directions = \"egress\""));
    }
}
