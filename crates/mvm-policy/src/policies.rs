//! Sub-policy types referenced by `PolicyBundle`.
//!
//! Plan 37 Wave 1.2 lands the *shape* of each sub-policy as a
//! minimal placeholder. Real enforcement contracts arrive in later
//! waves:
//!
//! - Wave 2 fills `EgressPolicy` (L7 rules), `PiiPolicy` (detect /
//!   redact / refuse modes), and `ToolPolicy` (RPC allowlist).
//! - Wave 3 fills `KeyPolicy` (per-run secret grants) and
//!   `AuditPolicy` (chain signing, per-tenant streams).
//! - Wave 4 fills `NetworkPolicy` (per-tenant netns) and
//!   `ArtifactPolicy` retention sweeps.
//!
//! Every type uses `#[serde(deny_unknown_fields)]` so a future
//! field addition is a fail-closed schema bump for older verifiers,
//! and every type derives `Default` so `TenantOverlay`'s
//! `Option<T>` semantics ("None inherits from base") compose
//! cleanly with the bundle's resolution algorithm.

use serde::{Deserialize, Serialize};

/// Network policy. Wave 4 introduces per-tenant netns + bridge
/// allocation. Today: name-only stub matching the existing
/// `mvm-core::policy::network_policy` shape.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    /// Name of the network preset
    /// (`open` / `agent` / `tenant-isolated` / etc.). Stub.
    pub preset: Option<String>,
}

/// L7 egress policy. Plan 37 §15 differentiator. Wave 2 fills:
///   - inspector chain (SecretsScanner, SsrfGuard, InjectionGuard,
///     DestinationPolicy)
///   - AiProviderRouter
///   - allowed destinations / SNI pin set
///
/// Today: a stub flag indicating whether the egress proxy is on at
/// all. The proxy itself is plan 32 / PR #23 (foundation only).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressPolicy {
    /// `open` — no proxy. `l3` — drop-on-deny IP allowlist (plan 32).
    /// `l3_plus_l7` — Wave 2 differentiator. Stub today.
    pub mode: Option<String>,
}

/// PII redaction policy. Plan 37 §15.1.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PiiPolicy {
    /// `disabled` / `detect` / `redact` / `refuse`. Stub.
    pub mode: Option<String>,
    /// Categories to act on (`email`, `cc_number`, `ssn`, ...).
    /// Empty means all categories the redactor knows about.
    pub categories: Vec<String>,
}

/// Tool-call allowlist. Plan 37 §2.2. Wave 2 wires the supervisor's
/// vsock RPC `ToolGate`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPolicy {
    /// Names of tools the workload is allowed to invoke. Stub.
    pub allowed: Vec<String>,
}

/// Artifact policy. Distinct from `mvm-plan::ArtifactPolicy` —
/// the plan field is a per-run snapshot; this is the bundle-side
/// source of truth that the supervisor's `ArtifactCollector` (Wave 3)
/// consults at workload exit.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPolicy {
    pub capture_paths: Vec<String>,
    pub retention_days: u32,
}

/// Key policy. Plan 37 §12. Wave 3 wires `KeystoreReleaser`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPolicy {
    /// 0 = no rotation; supervisor warns but accepts.
    pub rotation_interval_days: u32,
}

/// Audit policy. Plan 37 §22. Wave 3 wires chain signing + per-tenant
/// streams.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPolicy {
    /// Whether the supervisor should chain-sign each entry into the
    /// previous's hash for tamper-evidence.
    pub chain_signing: bool,
    /// Per-tenant audit-stream destinations. Resolved by
    /// `AuditSigner` per Wave 3.
    pub stream_destinations: Vec<String>,
}
