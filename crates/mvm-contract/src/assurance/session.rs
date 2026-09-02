//! The admitted session as it crosses to the process that serves probes.
//!
//! These types live here, rather than beside the ledger in `mvm-hostd`,
//! because the carrier does. `RegisterVm` is declared in this crate and its
//! production constructor sits in `mvm-vmm`, which is *below* `mvm-hostd` —
//! so a session type defined up there could not be named at either end of the
//! hop it has to make.
//!
//! Everything here is a decision already taken. The supervisor holds the plan:
//! it verifies it, mints the binding, intersects the authority, and resolves
//! the operator's declared destinations. What travels is the result, so the
//! receiving process gains no new judgement — the same shape as
//! `services_bindings`, which is also decided elsewhere and merely enforced.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::authority::EffectiveAuthority;
use super::binding::MvmBinding;
use super::ids::AssuranceId;
use super::ids::Sha256Digest;
use super::input::SessionRef;
use crate::plan::types::{PlanId, TenantId};
use crate::policy::network_policy::NetworkPolicy;

/// The only part of an admitted plan an assurance record quotes.
///
/// Exactly the fields a `PlanAuditEntry` carries, so a record written on
/// either side of the process boundary is identical — without the receiving
/// process ever being handed a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PlanIdentity {
    pub tenant: TenantId,
    pub plan_id: PlanId,
    pub plan_version: u32,
    pub image_name: String,
    pub image_sha256: String,
    /// Opaque caller commitment copied from the admitted plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_commitment: Option<crate::plan::CallerCommitment>,
    /// Labels the plan asks to be copied onto every entry it generates.
    #[serde(default)]
    pub audit_labels: BTreeMap<String, String>,
}

/// A destination an operator declared for one campaign, already resolved.
///
/// The workload only ever names the label. What it resolves to is settled
/// host-side before this crosses, so the probe path has nothing to look up and
/// nothing to be steered by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct DeclaredEdge {
    pub label: AssuranceId,
    pub host: String,
    pub port: u16,
}

/// An assurance session the supervisor already admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AdmittedAssuranceSession {
    /// The workload session id the supervisor will report in the call context.
    pub workload_session_id: String,
    pub binding: MvmBinding,
    /// Authority after every intersection. The receiver narrows nothing.
    pub authority: EffectiveAuthority,
    pub trial_id: AssuranceId,
    pub identity: PlanIdentity,
    /// Provider/campaign identity, when this registration came from the
    /// admission-bound provider path. Legacy registrations omit it and are
    /// refused by the daemon rather than opened with guessed identity.
    #[serde(default)]
    pub session: Option<SessionRef>,
    /// Source digest joined by the provider path. Legacy registrations omit
    /// it and cannot open an assurance session.
    #[serde(default)]
    pub source_digest: Option<Sha256Digest>,
    /// The workload's admitted egress policy, which the probe consults.
    pub policy: NetworkPolicy,
    pub destinations: Vec<DeclaredEdge>,
}
