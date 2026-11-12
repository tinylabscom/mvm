//! `PolicyBundle` — the bundle of policies a workload boots under.

use alloc::collections::BTreeMap;
use alloc::string::String;

use crate::plan::types::TenantId;
use serde::{Deserialize, Serialize};

use crate::policy::policies::{
    ArtifactPolicy, AuditPolicy, BundleNetworkPolicy, EgressPolicy, KeyPolicy, PiiPolicy,
    WasiCapPolicy,
};

/// Wire-format version. Same fail-closed semantics as
/// `mvm-core::plan::SCHEMA_VERSION` — older verifiers reject unknown
/// future bundle versions before any per-field deserialisation.
pub const SCHEMA_VERSION: u32 = 1;

/// Stable identifier for a `PolicyBundle`. Audit entries reference
/// `(bundle_id, bundle_version)` alongside the plan's `plan_id` and its
/// stable `(tenant, workload)` identity so a runbook can answer "which
/// policy was in force when this audit entry was written?" in O(1).
/// Correlate across a workload's revisions by `(tenant, workload)`; pin
/// one concrete execution by the per-execution `plan_id` content-address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyId(pub String);

/// A bundle of every policy a workload boots under. Resolved from a
/// `PolicyRef` on `ExecutionPlan`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundle {
    pub schema_version: u32,
    pub bundle_id: PolicyId,
    /// Monotonic per-`bundle_id` revision counter.
    pub bundle_version: u32,

    pub network: BundleNetworkPolicy,
    pub egress: EgressPolicy,
    pub pii: PiiPolicy,
    pub artifact: ArtifactPolicy,
    pub keys: KeyPolicy,
    pub audit: AuditPolicy,
    #[serde(default)]
    pub wasi: WasiCapPolicy,

    /// Per-tenant overlays. Resolved by composing the bundle's
    /// base policy with the matching tenant overlay (overlay wins
    /// on conflict). Empty map means no per-tenant variation.
    #[serde(default)]
    pub tenant_overlays: BTreeMap<TenantId, TenantOverlay>,
}

/// Per-tenant overlay. Each field is optional — `None` means
/// "inherit from the bundle base"; `Some(_)` overrides.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantOverlay {
    pub network: Option<BundleNetworkPolicy>,
    pub egress: Option<EgressPolicy>,
    pub pii: Option<PiiPolicy>,
    pub artifact: Option<ArtifactPolicy>,
    pub keys: Option<KeyPolicy>,
    pub audit: Option<AuditPolicy>,
    #[serde(default)]
    pub wasi: Option<WasiCapPolicy>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_tool_fields_are_rejected_in_wire_bundles() {
        let base = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "bundle_id": "tenant/workload",
            "bundle_version": 1,
            "network": {},
            "egress": {},
            "pii": {},
            "artifact": {},
            "keys": {},
            "audit": {}
        });
        assert!(serde_json::from_value::<PolicyBundle>(base.clone()).is_ok());
        for legacy in [
            serde_json::json!({"tool": {"allowed": ["shell"]}}),
            serde_json::json!({"tenant_overlays": {"tenant": {"tool": {"allowed": ["shell"]}}}}),
        ] {
            let mut value = base.clone();
            value
                .as_object_mut()
                .unwrap()
                .extend(legacy.as_object().unwrap().clone());
            assert!(
                serde_json::from_value::<PolicyBundle>(value).is_err(),
                "legacy tool policy must not be silently dropped"
            );
        }
    }
}
