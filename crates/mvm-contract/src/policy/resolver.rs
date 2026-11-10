//! `EffectivePolicy` — the wire DTO the policy resolver produces.
//!
//! - `EffectivePolicy` is the fully-resolved policy a workload boots
//!   under: same shape as `PolicyBundle`'s sub-policies, but
//!   flattened — no `Option<T>`, no overlays.
//!
//! The merge algorithm that produces an `EffectivePolicy` from a
//! `PolicyBundle` + tenant (`resolve()`, plus its
//! `pick()` helper) stays in `mvm_core::policy::resolver` — it isn't
//! itself a wire type, just the pure function that builds one.

use serde::{Deserialize, Serialize};

use crate::policy::policies::{
    ArtifactPolicy, AuditPolicy, BundleNetworkPolicy, EgressPolicy, KeyPolicy, PiiPolicy,
    WasiCapPolicy,
};

/// The fully-resolved policy a workload boots under. Same shape as
/// `PolicyBundle`'s sub-policies, but flattened: no `Option<T>`,
/// no overlays. Every field is the value the supervisor should
/// enforce.
///
/// The supervisor consumes this; `mvmctl plan inspect <plan>` can
/// also print it for operator review.
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
