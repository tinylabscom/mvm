//! The admission check that a unit's liveness deadline has an owner.
//!
//! A unit whose topology declares a liveness period is fenced, once its
//! deadline passes, by the per-VM supervisor that owns its guest. Topology
//! admission decided that for the backend it was asked about, but the record
//! it sealed names no backend, and a host may boot the same unit on another.
//! A launch on a backend with no such process would leave the period declared
//! and enforced by nothing, so it is refused here, before the nonce is spent.

use std::num::NonZeroU32;
use std::path::Path;

use anyhow::Result;
use mvm_contract::plan::topology::Unit;
use mvm_contract::protocol::resource_controls::{LivenessControl, ResourceControls};
use mvm_contract::protocol::vm_backend::BackendKind;
use mvm_core::plan::{ExecutionPlan, WorkloadId};

/// Why a unit with a liveness period may not launch.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LivenessOwnerRefusal {
    #[error(
        "unit {} declares a {period_ms} ms liveness period, and a {} launch has no \
         process that holds its deadline",
        .unit.0,
        .backend.as_str()
    )]
    BackendHoldsNoDeadline {
        unit: WorkloadId,
        period_ms: NonZeroU32,
        backend: BackendKind,
    },
    #[error(
        "unit {} declares a {period_ms} ms liveness period, and this launch was admitted \
         without the backend that will boot it, so no owner of its deadline can be named",
        .unit.0
    )]
    NoBackend {
        unit: WorkloadId,
        period_ms: NonZeroU32,
    },
}

/// Whether a launch of `unit` on `backend` has an owner for its liveness
/// deadline. A plan bound to no unit, or a unit declaring no period, has no
/// deadline to own.
pub(super) fn check_liveness_owner(
    unit: Option<&Unit>,
    backend: Option<BackendKind>,
) -> Result<(), LivenessOwnerRefusal> {
    let Some((unit, period_ms)) = unit.and_then(|u| Some((u, u.liveness_period_ms?))) else {
        return Ok(());
    };
    let unit = unit.workload.clone();
    let Some(backend) = backend else {
        return Err(LivenessOwnerRefusal::NoBackend { unit, period_ms });
    };
    match ResourceControls::for_backend(backend).liveness {
        LivenessControl::HostDeadline => Ok(()),
        LivenessControl::None => Err(LivenessOwnerRefusal::BackendHoldsNoDeadline {
            unit,
            period_ms,
            backend,
        }),
    }
}

/// [`check_liveness_owner`], with a refusal written to the plan's chain once,
/// as the topology binding check writes its own.
///
/// # Errors
///
/// A [`LivenessOwnerRefusal`], carrying the audited marker when the refusal
/// was recorded.
pub(super) fn admit_liveness_owner(
    home: &Path,
    plan: &ExecutionPlan,
    unit: Option<&Unit>,
    backend: Option<BackendKind>,
    host_signer_keys_dir: Option<&Path>,
) -> Result<()> {
    check_liveness_owner(unit, backend).map_err(|refusal| {
        super::topology_binding::audit_refusal(
            home,
            plan,
            host_signer_keys_dir,
            super::topology_binding::AuditedRefusal::LIVENESS_OWNER,
            refusal.into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use mvm_contract::assurance::Sha256Digest;
    use mvm_contract::plan::topology::{CorePlacement, SealedTransitions, UnitResources, UnitRole};

    use super::*;

    fn unit(period_ms: Option<u32>) -> Unit {
        Unit {
            workload: WorkloadId("controller".into()),
            role: UnitRole::Worker,
            recipe: Sha256Digest::from_bytes(&[7; 32]),
            resources: UnitResources {
                cpus: 1,
                mem_mib: 64,
                disk_mib: 64,
            },
            placement: CorePlacement::Floating,
            min_isolation: None,
            permits: SealedTransitions::default(),
            liveness_period_ms: period_ms.and_then(NonZeroU32::new),
            require_isolated_cores: false,
        }
    }

    #[test]
    fn a_unit_with_a_period_launches_only_where_a_supervisor_holds_the_deadline() {
        let watched = unit(Some(5_000));
        for &kind in BackendKind::ALL {
            let decided = check_liveness_owner(Some(&watched), Some(kind));
            match kind {
                BackendKind::Libkrun
                | BackendKind::Hvf
                | BackendKind::AppleContainer
                | BackendKind::Mock => assert_eq!(decided, Ok(()), "{kind:?}"),
                BackendKind::Firecracker
                | BackendKind::Qemu
                | BackendKind::Wasm
                | BackendKind::WebLinux => assert_eq!(
                    decided,
                    Err(LivenessOwnerRefusal::BackendHoldsNoDeadline {
                        unit: watched.workload.clone(),
                        period_ms: NonZeroU32::new(5_000).unwrap(),
                        backend: kind,
                    }),
                    "{kind:?}"
                ),
            }
        }
    }

    #[test]
    fn a_unit_with_a_period_is_refused_when_no_backend_is_named() {
        let watched = unit(Some(5_000));
        let refusal = check_liveness_owner(Some(&watched), None).unwrap_err();
        assert!(matches!(refusal, LivenessOwnerRefusal::NoBackend { .. }));
        assert!(refusal.to_string().contains("controller"), "{refusal}");
    }

    #[test]
    fn a_unit_without_a_period_and_an_unbound_plan_launch_anywhere() {
        for &kind in BackendKind::ALL {
            assert_eq!(check_liveness_owner(Some(&unit(None)), Some(kind)), Ok(()));
            assert_eq!(check_liveness_owner(None, Some(kind)), Ok(()));
        }
        assert_eq!(check_liveness_owner(Some(&unit(None)), None), Ok(()));
        assert_eq!(check_liveness_owner(None, None), Ok(()));
    }
}
