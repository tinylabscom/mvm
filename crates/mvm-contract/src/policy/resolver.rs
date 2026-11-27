//! `EffectivePolicy` — a flattened policy shape the workload actor
//! lifecycle carries and compares between parent and child. Nothing
//! resolves it from a policy bundle: the actor lifecycle requires the
//! default value.

use serde::{Deserialize, Serialize};

use crate::policy::policies::{
    ArtifactPolicy, AuditPolicy, BundleNetworkPolicy, EgressPolicy, KeyPolicy, PiiPolicy,
    WasiCapPolicy,
};

/// A flattened policy shape. The actor lifecycle refuses anything but
/// [`EffectivePolicy::default`] and compares a child's value with its
/// parent's; no field is enforced on its own.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectivePolicy {
    pub network: BundleNetworkPolicy,
    pub egress: EgressPolicy,
    pub pii: PiiPolicy,
    pub artifact: ArtifactPolicy,
    pub keys: KeyPolicy,
    pub audit: AuditPolicy,
    #[serde(default)]
    pub wasi: WasiCapPolicy,
}
