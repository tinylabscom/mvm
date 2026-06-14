//! Sub-policy types referenced by `PolicyBundle`.
//!
//! Each sub-policy starts as a minimal shape placeholder; real
//! enforcement contracts are filled in incrementally:
//!
//! - `EgressPolicy` (L7 rules), `PiiPolicy` (detect / redact / refuse
//!   modes), and `ToolPolicy` (RPC allowlist).
//! - `KeyPolicy` (per-run secret grants) and `AuditPolicy` (chain
//!   signing, per-tenant streams).
//! - `NetworkPolicy` (per-tenant netns) and `ArtifactPolicy` retention
//!   sweeps.
//!
//! Every type uses `#[serde(deny_unknown_fields)]` so a future
//! field addition is a fail-closed schema bump for older verifiers,
//! and every type derives `Default` so `TenantOverlay`'s
//! `Option<T>` semantics ("None inherits from base") compose
//! cleanly with the bundle's resolution algorithm.

use serde::{Deserialize, Serialize};

/// Network policy. `l4` is the L4 allow-list the supervisor's `L4Gate`
/// consults at flow-establishment time. `preset` is a stub kept for
/// forward compat with the `mvm-core::policy::network_policy` shape that
/// older bundles may still carry.
///
/// `l4` is `#[serde(default)]` so bundles authored without
/// `[[network.l4]]` rows continue to parse — they evaluate as
/// **default-deny** at the gate, matching the fail-closed posture. To
/// allow outbound traffic, add explicit rows.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    /// Name of the network preset
    /// (`open` / `agent` / `tenant-isolated` / etc.). Stub.
    pub preset: Option<String>,
    /// L4 allow-list (`proto`, `dst_cidr`, port range) evaluated by
    /// the supervisor's `L4Gate` at flow-establishment time. Empty =
    /// default-deny.
    #[serde(default)]
    pub l4: Vec<L4RuleSpec>,
    /// Observer chain. Each entry is a name resolved against the host's
    /// `ObserverAllowlist` (`~/.mvm/observers/allowlist.toml`). Empty Vec
    /// = no observers (only the always-on chain signer fires).
    ///
    /// Default is empty for backward compatibility: claim-10 v1 bundles
    /// that don't have this field still parse and behave identically
    /// (no fan-out, chain entries unchanged).
    #[serde(default)]
    pub observers: Vec<String>,
    /// Opt-in per-VM flow-byte log. `None` (default) = off. When set, the
    /// bridge appends length-prefixed payload records
    /// to `~/.mvm/audit/flow-bytes/<tenant>/<vm>-<utc>.bin`; the signed
    /// chain references each record by `(file, record_id, sha256)` without
    /// inlining payload bytes.
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

/// Wire-format L4 rule row inside `[[network.l4]]`. The supervisor's
/// `canonicalize_l4` (in `mvm_core::policy`) parses `dst_cidr` via
/// `ipnet::IpNet` and lowers the rows into a `CanonicalEgress`; this
/// crate stays free of `ipnet` so the policy schema doesn't take a
/// hard dep on the address-family crate.
///
/// Example TOML:
///
/// ```toml
/// [[network.l4]]
/// proto    = "tcp"
/// dst_cidr = "10.0.0.0/24"
/// port_lo  = 443
/// port_hi  = 443
///
/// [[network.l4]]
/// proto    = "udp"
/// dst_cidr = "8.8.8.8/32"
/// port_lo  = 0
/// port_hi  = 0   # any-port wildcard
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L4RuleSpec {
    /// `"tcp"` or `"udp"`. `canonicalize_l4` refuses unknown protocols
    /// at translate time (loud failure at admission, not silent drop at
    /// runtime).
    pub proto: String,
    /// Destination CIDR — parsed by `ipnet::IpNet`; both v4 and v6
    /// supported. The supervisor refuses unparseable CIDRs at
    /// translate time.
    pub dst_cidr: String,
    /// Inclusive low bound of the destination port range.
    pub port_lo: u16,
    /// Inclusive high bound. `port_lo == 0 && port_hi == 0` is the
    /// "any port for this (proto, cidr)" wildcard.
    pub port_hi: u16,
}

/// L7 egress policy. The fields the `L7EgressProxy` consumes:
/// - `allow_list` is the (host, port) destination policy.
/// - `allow_plain_http` opens the plain-HTTP code path; **the
///   supervisor refuses to honour `true` for `Variant::Prod`** so
///   production workloads can never accidentally egress unencrypted.
/// - `body_cap_bytes` bounds the body read for plain-HTTP. `0` means
///   "use default" ([`DEFAULT_BODY_CAP_BYTES`], 16 MiB) — matches
///   AI-provider request sizes (long contexts + image uploads).
/// - `disabled_inspectors` lets operators turn off specific
///   inspectors by name (e.g., disable `pii_redactor` for an
///   analytics workload that scrubs upstream).
///
/// `mode` is retained for compatibility with the earlier stub; the
/// supervisor honours `mode = Some("open")` as a kill-switch that
/// skips the proxy entirely. New fields are `#[serde(default)]` so
/// older bundles continue to parse.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressPolicy {
    /// `open` — no proxy. Anything else routes through the L7 chain.
    pub mode: Option<String>,
    /// (host, port) allowlist consumed by `DestinationPolicy`.
    /// `port = 0` is the explicit "any port for this host" wildcard.
    #[serde(default)]
    pub allow_list: Vec<(String, u16)>,
    /// Whether plain HTTP (not just CONNECT/HTTPS) is permitted.
    /// **Forbidden for `Variant::Prod`** — the supervisor's
    /// `with_l7_egress` builder rejects this combination at policy
    /// load.
    #[serde(default)]
    pub allow_plain_http: bool,
    /// Body read cap for plain-HTTP (bytes). `0` means "use default"
    /// ([`DEFAULT_BODY_CAP_BYTES`]).
    #[serde(default)]
    pub body_cap_bytes: u64,
    /// Per-name inspector opt-out. Empty == every inspector enabled.
    /// Names match `Inspector::name()` strings: `destination_policy`,
    /// `ssrf_guard`, `secrets_scanner`, `injection_guard`,
    /// `pii_redactor`.
    #[serde(default)]
    pub disabled_inspectors: Vec<String>,
    /// Per-destination egress redaction. Synthesized into the signed
    /// `ExecutionPlan.redaction` at admission. Default = all-off.
    #[serde(default)]
    pub redaction: crate::policy::RedactionPolicy,
}

/// Default body cap when `EgressPolicy::body_cap_bytes` is 0.
/// 16 MiB — matches AI-provider request sizes (long contexts +
/// image uploads). Configurable per workload via the policy field.
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

/// Tool-call allowlist. Wires the supervisor's vsock RPC `ToolGate`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPolicy {
    /// Names of tools the workload is allowed to invoke. Stub.
    #[serde(default)]
    pub allowed: Vec<String>,
}

/// Artifact policy. Distinct from `mvm-core::plan::ArtifactPolicy` —
/// the plan field is a per-run snapshot; this is the bundle-side
/// source of truth that the supervisor's `ArtifactCollector`
/// consults at workload exit.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ArtifactPolicy {
    pub capture_paths: Vec<String>,
    pub retention_days: u32,
}

/// Key policy. Wires `KeystoreReleaser`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KeyPolicy {
    /// 0 = no rotation; supervisor warns but accepts.
    pub rotation_interval_days: u32,
}

/// Audit policy. Wires chain signing + per-tenant streams.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuditPolicy {
    /// Whether the supervisor should chain-sign each entry into the
    /// previous's hash for tamper-evidence.
    pub chain_signing: bool,
    /// Per-tenant audit-stream destinations. Resolved by
    /// `AuditSigner`.
    pub stream_destinations: Vec<String>,
}

#[cfg(test)]
mod plan_113_observer_tests {
    use super::*;

    #[test]
    fn network_policy_parses_observers_chain() {
        let toml = r#"
preset = "deny-by-default"
observers = ["flow-count-metrics"]
"#;
        let p: NetworkPolicy = toml::from_str(toml).expect("parse");
        assert_eq!(p.observers, vec!["flow-count-metrics".to_string()]);
    }

    #[test]
    fn network_policy_missing_observers_defaults_empty() {
        let toml = r#"
preset = "deny-by-default"
"#;
        let p: NetworkPolicy = toml::from_str(toml).expect("parse");
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
        let p: NetworkPolicy = toml::from_str(toml).expect("parse v1 bundle");
        assert_eq!(p.l4.len(), 1);
        assert!(p.observers.is_empty());
    }

    #[test]
    fn network_policy_flow_byte_log_defaults_off() {
        // A bundle without the field still parses and logging is off.
        let np = NetworkPolicy::default();
        assert!(np.flow_byte_log.is_none());
        let p: NetworkPolicy = toml::from_str("preset = \"open\"\n").expect("parse without field");
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
