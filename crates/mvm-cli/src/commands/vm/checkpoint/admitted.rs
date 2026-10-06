//! The admitted state a checkpoint capture seals: the permission set a restore
//! bounds its children against, and the key domain the captured chunks are
//! filed under.

use anyhow::{Context, Result};

use mvm_contract::grants::Grants;
use mvm_core::checkpoint::CheckpointKeyDomain;
use mvm_core::plan::ExecutionPlan;

/// What a capture of `name` seals from the plan it was admitted under.
pub(super) struct AdmittedCapture {
    /// The permission set, so a later restore can bound a child against it.
    pub(super) grants: Option<Grants>,
    /// The admitted tenant's key domain, or the host's for a VM with no plan.
    pub(super) key_domain: CheckpointKeyDomain,
}

impl AdmittedCapture {
    fn from_plan(plan: Option<ExecutionPlan>) -> Result<Self> {
        let Some(plan) = plan else {
            return Ok(Self {
                grants: None,
                key_domain: CheckpointKeyDomain::host(),
            });
        };
        let key_domain = CheckpointKeyDomain::tenant(plan.tenant.0.clone()).with_context(|| {
            format!(
                "plan {} names no tenant to key the checkpoint's chunks to",
                plan.plan_id.0
            )
        })?;
        Ok(Self {
            grants: plan.grants,
            key_domain,
        })
    }
}

/// The admitted state a capture of `name` seals, read off its persisted plan.
///
/// Degrades the same way [`bind_checkpoint_created`](super::bind_checkpoint_created) does, and safely for the
/// same reason: a VM with no readable plan also gets no chain-signed
/// `checkpoint.created` entry, so the record it produces has nothing to anchor
/// its content-address and every fork of it is refused before the grants are
/// consulted at all.
pub(super) fn admitted_capture_for(name: &str) -> Result<AdmittedCapture> {
    let path = super::super::plan_persist::plan_path(name)?;
    // A VM that never had a plan legitimately has no grant to seal, and that is
    // the only tolerated absence. Every other failure — a corrupt plan, one at
    // loose permissions, one that will not parse — is refused rather than
    // resolved to `None`, because `None` is not "unknown" here: for CPU and wall
    // clock it means *unbounded*, so swallowing the error would widen the record
    // silently and hand every child restored from it that widening. It would
    // also file the tenant's memory under the host's key domain.
    if !path.exists() {
        return AdmittedCapture::from_plan(None);
    }
    let plan = super::super::plan_persist::read_plan_at(&path).with_context(|| {
        format!(
            "reading {name}'s admitted plan to seal its grants into the checkpoint; \
             refusing to seal a checkpoint whose permission set cannot be determined"
        )
    })?;
    AdmittedCapture::from_plan(Some(plan))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_capture_without_a_plan_is_keyed_to_the_host() {
        let admitted = AdmittedCapture::from_plan(None).unwrap();
        assert!(admitted.key_domain.is_host());
        assert!(admitted.grants.is_none());
    }

    #[test]
    fn a_capture_under_a_plan_is_keyed_to_the_plans_tenant() {
        let grants = Grants {
            cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 500 }),
            ..Default::default()
        };
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("acme")
            .grants(Some(grants.clone()))
            .build();

        let admitted = AdmittedCapture::from_plan(Some(plan)).unwrap();

        assert_eq!(
            admitted.key_domain,
            CheckpointKeyDomain::tenant("acme").unwrap()
        );
        assert_eq!(admitted.grants, Some(grants));
    }

    #[test]
    fn a_plan_with_an_empty_tenant_is_refused_rather_than_filed_under_the_host() {
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("")
            .build();
        assert!(AdmittedCapture::from_plan(Some(plan)).is_err());
    }
}
