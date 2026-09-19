//! Whether one permission set sits inside another.
//!
//! Distinct from [`GrantCeiling`](crate::grants::ceiling::GrantCeiling), which
//! bounds a grant against host or fleet configuration. This bounds a grant
//! against *another grant* — the one a running VM was already admitted under.
//! Snapshot/restore needs it: a child plan is independently signed and
//! internally consistent, so signature, plan id, tenant and validity all pass
//! for a child that simply asks for more than its parent had. Without a
//! containment check, restore launders a permission set.
//!
//! Absence does not mean the same thing in every dimension, and treating it
//! uniformly is the way to get this wrong. An absent CPU or wall-clock grant is
//! *unbounded*, so a child that drops one its parent carried has widened. An
//! absent egress grant is deny-all, so a child that drops one has narrowed.

use crate::grants::{
    CpuGrant, DriveGrant, DriveProgramId, EgressGrant, Grants, WallClockGrant, WorkspaceRoot,
};
use crate::policy::network_policy::HostPort;

/// The dimension in which a child asked for more than its parent held.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantWidening {
    #[error("child drops the parent's CPU bound, and an absent CPU grant is unbounded")]
    CpuBoundDropped,
    #[error("child CPU share {child} millicores exceeds the parent's {parent}")]
    CpuShareExceeded { child: u32, parent: u32 },
    #[error("child CPU fuel {child} instructions exceeds the parent's {parent}")]
    CpuFuelExceeded { child: u64, parent: u64 },
    #[error(
        "child and parent CPU grants are in different units; a share is a fraction of host CPU \
         and fuel is an instruction count, and no conversion between them exists"
    )]
    CpuUnitMismatch,
    #[error(
        "child drops the parent's wall-clock bound, and an absent wall-clock grant is unbounded"
    )]
    WallClockBoundDropped,
    #[error("child asks for an unbounded wall clock under a parent bounded to {parent} seconds")]
    WallClockUnbounded { parent: u32 },
    #[error("child wall clock of {child} seconds exceeds the parent's {parent}")]
    WallClockExceeded { child: u32, parent: u32 },
    #[error("child egress destination {0} was not admitted for the parent")]
    EgressNotAdmitted(HostPort),
    #[error("child carries a drive grant, but the parent carried none")]
    DriveNotAdmitted,
    #[error("child drive program {child} differs from the parent's {parent}")]
    DriveProgramMismatch {
        child: DriveProgramId,
        parent: DriveProgramId,
    },
    #[error("child drive workspace root {0} is outside the parent's admitted roots")]
    DriveWorkspaceRootNotAdmitted(WorkspaceRoot),
    #[error("child drive input bound {child} bytes exceeds the parent's {parent}")]
    DriveInputExceeded { child: u64, parent: u64 },
    #[error("child drive output bound {child} bytes exceeds the parent's {parent}")]
    DriveOutputExceeded { child: u64, parent: u64 },
    #[error("child drive lifetime {child} seconds exceeds the parent's {parent}")]
    DriveTtlExceeded { child: u32, parent: u32 },
}

/// Whether `child` asks for no more than `parent` holds, in every dimension.
///
/// Dimensions are checked in a fixed order — CPU, wall clock, egress, drive —
/// so a child that widens in more than one reports a stable reason rather than
/// one that depends on evaluation order.
pub fn grants_are_subset(child: &Grants, parent: &Grants) -> Result<(), GrantWidening> {
    cpu_is_subset(child.cpu, parent.cpu)?;
    wall_clock_is_subset(child.wall_clock, parent.wall_clock)?;
    egress_is_subset(child.egress.as_ref(), parent.egress.as_ref())?;
    drive_is_subset(child.drive.as_ref(), parent.drive.as_ref())
}

fn cpu_is_subset(child: Option<CpuGrant>, parent: Option<CpuGrant>) -> Result<(), GrantWidening> {
    let (Some(parent), child) = (parent, child) else {
        // An unbounded parent bounds nothing, so any child sits inside it.
        return Ok(());
    };
    let Some(child) = child else {
        return Err(GrantWidening::CpuBoundDropped);
    };
    match (child, parent) {
        (CpuGrant::Share { millicores: c }, CpuGrant::Share { millicores: p }) => {
            if c > p {
                return Err(GrantWidening::CpuShareExceeded {
                    child: c,
                    parent: p,
                });
            }
            Ok(())
        }
        (CpuGrant::Fuel { instructions: c }, CpuGrant::Fuel { instructions: p }) => {
            if c > p {
                return Err(GrantWidening::CpuFuelExceeded {
                    child: c,
                    parent: p,
                });
            }
            Ok(())
        }
        // Refusing beats inventing an exchange rate: any conversion would be a
        // host-specific guess, and guessing high is a silent widening.
        (CpuGrant::Share { .. }, CpuGrant::Fuel { .. })
        | (CpuGrant::Fuel { .. }, CpuGrant::Share { .. }) => Err(GrantWidening::CpuUnitMismatch),
    }
}

fn wall_clock_is_subset(
    child: Option<WallClockGrant>,
    parent: Option<WallClockGrant>,
) -> Result<(), GrantWidening> {
    let parent = match parent {
        None | Some(WallClockGrant::Unbounded) => return Ok(()),
        Some(WallClockGrant::Secs { secs }) => secs.get(),
    };
    match child {
        None => Err(GrantWidening::WallClockBoundDropped),
        Some(WallClockGrant::Unbounded) => Err(GrantWidening::WallClockUnbounded { parent }),
        Some(WallClockGrant::Secs { secs }) if secs.get() > parent => {
            Err(GrantWidening::WallClockExceeded {
                child: secs.get(),
                parent,
            })
        }
        Some(WallClockGrant::Secs { .. }) => Ok(()),
    }
}

fn egress_is_subset(
    child: Option<&EgressGrant>,
    parent: Option<&EgressGrant>,
) -> Result<(), GrantWidening> {
    // Set containment on the allowlist. An absent grant is deny-all on either
    // side, so an absent parent admits only an empty child and an absent child
    // reaches nothing — the inverse of the CPU rule, deliberately.
    let parent_allow: &[HostPort] = parent.map(|e| e.allow.as_slice()).unwrap_or(&[]);
    let child_allow: &[HostPort] = child.map(|e| e.allow.as_slice()).unwrap_or(&[]);
    for want in child_allow {
        if !parent_allow.contains(want) {
            return Err(GrantWidening::EgressNotAdmitted(want.clone()));
        }
    }
    Ok(())
}

fn drive_is_subset(
    child: Option<&DriveGrant>,
    parent: Option<&DriveGrant>,
) -> Result<(), GrantWidening> {
    let Some(child) = child else {
        return Ok(());
    };
    let Some(parent) = parent else {
        return Err(GrantWidening::DriveNotAdmitted);
    };
    if child.program_id != parent.program_id {
        return Err(GrantWidening::DriveProgramMismatch {
            child: child.program_id.clone(),
            parent: parent.program_id.clone(),
        });
    }
    for root in &child.workspace_roots {
        if !parent
            .workspace_roots
            .iter()
            .any(|parent_root| root.is_within(parent_root))
        {
            return Err(GrantWidening::DriveWorkspaceRootNotAdmitted(root.clone()));
        }
    }
    if child.max_bytes_in > parent.max_bytes_in {
        return Err(GrantWidening::DriveInputExceeded {
            child: child.max_bytes_in.get(),
            parent: parent.max_bytes_in.get(),
        });
    }
    if child.max_bytes_out > parent.max_bytes_out {
        return Err(GrantWidening::DriveOutputExceeded {
            child: child.max_bytes_out.get(),
            parent: parent.max_bytes_out.get(),
        });
    }
    if child.ttl > parent.ttl {
        return Err(GrantWidening::DriveTtlExceeded {
            child: child.ttl.get(),
            parent: parent.ttl.get(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::num::{NonZeroU32, NonZeroU64};

    fn share(millicores: u32) -> Option<CpuGrant> {
        Some(CpuGrant::Share { millicores })
    }

    fn secs(secs: u32) -> Option<WallClockGrant> {
        Some(WallClockGrant::Secs {
            secs: NonZeroU32::new(secs).expect("nonzero"),
        })
    }

    fn egress(hosts: &[(&str, u16)]) -> Option<EgressGrant> {
        Some(EgressGrant {
            allow: hosts
                .iter()
                .map(|(h, p)| HostPort::new(*h, *p))
                .collect::<alloc::vec::Vec<_>>(),
        })
    }

    fn drive(root: &str, program: &str, input: u64, output: u64, ttl: u32) -> Option<DriveGrant> {
        Some(
            DriveGrant::builder()
                .workspace_root(WorkspaceRoot::parse(root).expect("absolute workspace root"))
                .program_id(DriveProgramId::parse(program).expect("valid program id"))
                .max_bytes_in(NonZeroU64::new(input).expect("nonzero input bound"))
                .max_bytes_out(NonZeroU64::new(output).expect("nonzero output bound"))
                .ttl(NonZeroU32::new(ttl).expect("nonzero ttl"))
                .build()
                .expect("complete drive grant"),
        )
    }

    #[test]
    fn a_child_may_narrow_every_dimension_at_once() {
        let parent = Grants {
            cpu: share(4000),
            wall_clock: secs(600),
            egress: egress(&[("api.example.com", 443), ("pypi.org", 443)]),
            drive: drive("/workspace", "agent", 1_000, 2_000, 300),
        };
        let child = Grants {
            cpu: share(1000),
            wall_clock: secs(60),
            egress: egress(&[("api.example.com", 443)]),
            drive: drive("/workspace/src", "agent", 500, 1_000, 60),
        };
        assert_eq!(grants_are_subset(&child, &parent), Ok(()));
    }

    #[test]
    fn an_identical_child_is_a_subset_of_its_parent() {
        let g = Grants {
            cpu: share(1000),
            wall_clock: secs(60),
            egress: egress(&[("api.example.com", 443)]),
            drive: drive("/workspace", "agent", 1_000, 2_000, 300),
        };
        assert_eq!(grants_are_subset(&g, &g), Ok(()));
    }

    #[test]
    fn a_child_may_not_widen_its_parents_cpu_share() {
        let parent = Grants {
            cpu: share(1000),
            ..Default::default()
        };
        let child = Grants {
            cpu: share(4000),
            ..Default::default()
        };
        assert_eq!(
            grants_are_subset(&child, &parent),
            Err(GrantWidening::CpuShareExceeded {
                child: 4000,
                parent: 1000
            })
        );
    }

    #[test]
    fn a_child_may_not_widen_its_parents_fuel_budget() {
        let parent = Grants {
            cpu: Some(CpuGrant::Fuel {
                instructions: 1_000,
            }),
            ..Default::default()
        };
        let child = Grants {
            cpu: Some(CpuGrant::Fuel {
                instructions: 1_001,
            }),
            ..Default::default()
        };
        assert_eq!(
            grants_are_subset(&child, &parent),
            Err(GrantWidening::CpuFuelExceeded {
                child: 1_001,
                parent: 1_000
            })
        );
    }

    #[test]
    fn a_child_may_not_drop_a_cpu_bound_its_parent_carried() {
        // Absent means unbounded for CPU, so dropping the bound is the widest
        // possible ask, not a narrowing.
        let parent = Grants {
            cpu: share(1000),
            ..Default::default()
        };
        assert_eq!(
            grants_are_subset(&Grants::default(), &parent),
            Err(GrantWidening::CpuBoundDropped)
        );
    }

    #[test]
    fn a_child_may_bound_cpu_where_its_parent_did_not() {
        let child = Grants {
            cpu: share(1000),
            ..Default::default()
        };
        assert_eq!(grants_are_subset(&child, &Grants::default()), Ok(()));
    }

    #[test]
    fn mismatched_cpu_units_are_refused_rather_than_converted() {
        let parent = Grants {
            cpu: Some(CpuGrant::Fuel {
                instructions: u64::MAX,
            }),
            ..Default::default()
        };
        let child = Grants {
            cpu: share(1),
            ..Default::default()
        };
        assert_eq!(
            grants_are_subset(&child, &parent),
            Err(GrantWidening::CpuUnitMismatch)
        );
        // Symmetric: neither direction has a defined conversion.
        assert_eq!(
            grants_are_subset(&parent, &child),
            Err(GrantWidening::CpuUnitMismatch)
        );
    }

    #[test]
    fn a_child_may_not_widen_its_parents_wall_clock() {
        let parent = Grants {
            wall_clock: secs(60),
            ..Default::default()
        };
        let child = Grants {
            wall_clock: secs(61),
            ..Default::default()
        };
        assert_eq!(
            grants_are_subset(&child, &parent),
            Err(GrantWidening::WallClockExceeded {
                child: 61,
                parent: 60
            })
        );
    }

    #[test]
    fn an_unbounded_child_wall_clock_is_refused_under_a_bounded_parent() {
        let parent = Grants {
            wall_clock: secs(60),
            ..Default::default()
        };
        let child = Grants {
            wall_clock: Some(WallClockGrant::Unbounded),
            ..Default::default()
        };
        assert_eq!(
            grants_are_subset(&child, &parent),
            Err(GrantWidening::WallClockUnbounded { parent: 60 })
        );
    }

    #[test]
    fn a_child_may_not_drop_a_wall_clock_bound_its_parent_carried() {
        let parent = Grants {
            wall_clock: secs(60),
            ..Default::default()
        };
        assert_eq!(
            grants_are_subset(&Grants::default(), &parent),
            Err(GrantWidening::WallClockBoundDropped)
        );
    }

    #[test]
    fn any_child_wall_clock_sits_under_an_unbounded_parent() {
        let parent = Grants {
            wall_clock: Some(WallClockGrant::Unbounded),
            ..Default::default()
        };
        for child in [
            Grants::default(),
            Grants {
                wall_clock: Some(WallClockGrant::Unbounded),
                ..Default::default()
            },
            Grants {
                wall_clock: secs(u32::MAX),
                ..Default::default()
            },
        ] {
            assert_eq!(grants_are_subset(&child, &parent), Ok(()));
        }
    }

    #[test]
    fn a_child_may_not_reach_a_destination_its_parent_could_not() {
        let parent = Grants {
            egress: egress(&[("api.example.com", 443)]),
            ..Default::default()
        };
        let child = Grants {
            egress: egress(&[("api.example.com", 443), ("evil.example.com", 443)]),
            ..Default::default()
        };
        assert_eq!(
            grants_are_subset(&child, &parent),
            Err(GrantWidening::EgressNotAdmitted(HostPort::new(
                "evil.example.com",
                443
            )))
        );
    }

    #[test]
    fn a_child_may_not_reach_another_port_on_an_admitted_host() {
        // Containment is on the (host, port) pair; an admitted host does not
        // carry the whole port range with it.
        let parent = Grants {
            egress: egress(&[("api.example.com", 443)]),
            ..Default::default()
        };
        let child = Grants {
            egress: egress(&[("api.example.com", 8443)]),
            ..Default::default()
        };
        assert_eq!(
            grants_are_subset(&child, &parent),
            Err(GrantWidening::EgressNotAdmitted(HostPort::new(
                "api.example.com",
                8443
            )))
        );
    }

    #[test]
    fn dropping_egress_narrows_because_absent_egress_is_deny_all() {
        // The inverse of the CPU rule, and the reason the two dimensions
        // cannot share one absence rule.
        let parent = Grants {
            egress: egress(&[("api.example.com", 443)]),
            ..Default::default()
        };
        assert_eq!(grants_are_subset(&Grants::default(), &parent), Ok(()));
    }

    #[test]
    fn a_parent_without_egress_admits_no_child_destination() {
        let child = Grants {
            egress: egress(&[("api.example.com", 443)]),
            ..Default::default()
        };
        assert_eq!(
            grants_are_subset(&child, &Grants::default()),
            Err(GrantWidening::EgressNotAdmitted(HostPort::new(
                "api.example.com",
                443
            )))
        );
        // An empty allowlist is also deny-all, so it admits nothing either.
        let empty_parent = Grants {
            egress: Some(EgressGrant { allow: vec![] }),
            ..Default::default()
        };
        assert!(grants_are_subset(&child, &empty_parent).is_err());
    }

    #[test]
    fn cpu_is_reported_before_wall_clock_and_egress() {
        // A child widening several dimensions must report a stable reason.
        let parent = Grants {
            cpu: share(1000),
            wall_clock: secs(60),
            egress: None,
            drive: None,
        };
        let child = Grants {
            cpu: share(2000),
            wall_clock: Some(WallClockGrant::Unbounded),
            egress: egress(&[("evil.example.com", 443)]),
            drive: drive("/workspace", "agent", 1, 1, 1),
        };
        assert_eq!(
            grants_are_subset(&child, &parent),
            Err(GrantWidening::CpuShareExceeded {
                child: 2000,
                parent: 1000
            })
        );
    }

    #[test]
    fn two_empty_grants_contain_each_other() {
        assert_eq!(
            grants_are_subset(&Grants::default(), &Grants::default()),
            Ok(())
        );
    }

    #[test]
    fn drive_authority_is_closed_when_the_parent_has_no_grant() {
        let child = Grants {
            drive: drive("/workspace", "agent", 1, 1, 1),
            ..Default::default()
        };
        assert_eq!(
            grants_are_subset(&child, &Grants::default()),
            Err(GrantWidening::DriveNotAdmitted)
        );
        assert_eq!(grants_are_subset(&Grants::default(), &child), Ok(()));
    }

    #[test]
    fn drive_child_may_narrow_roots_and_resource_bounds() {
        let parent = Grants {
            drive: drive("/workspace", "agent", 1_000, 2_000, 300),
            ..Default::default()
        };
        let child = Grants {
            drive: drive("/workspace/src", "agent", 500, 1_000, 60),
            ..Default::default()
        };
        assert_eq!(grants_are_subset(&child, &parent), Ok(()));
    }

    #[test]
    fn drive_child_may_not_change_program_or_escape_roots() {
        let parent = Grants {
            drive: drive("/workspace", "agent", 1_000, 2_000, 300),
            ..Default::default()
        };
        let other_program = Grants {
            drive: drive("/workspace", "other-agent", 1_000, 2_000, 300),
            ..Default::default()
        };
        assert_eq!(
            grants_are_subset(&other_program, &parent),
            Err(GrantWidening::DriveProgramMismatch {
                child: DriveProgramId::parse("other-agent").expect("program id"),
                parent: DriveProgramId::parse("agent").expect("program id"),
            })
        );

        let outside_root = Grants {
            drive: drive("/workspace-other", "agent", 1_000, 2_000, 300),
            ..Default::default()
        };
        assert_eq!(
            grants_are_subset(&outside_root, &parent),
            Err(GrantWidening::DriveWorkspaceRootNotAdmitted(
                WorkspaceRoot::parse("/workspace-other").expect("workspace root")
            ))
        );
    }

    #[test]
    fn drive_child_may_not_widen_any_resource_bound() {
        let parent = Grants {
            drive: drive("/workspace", "agent", 100, 200, 30),
            ..Default::default()
        };
        for (child, expected) in [
            (
                drive("/workspace", "agent", 101, 200, 30),
                GrantWidening::DriveInputExceeded {
                    child: 101,
                    parent: 100,
                },
            ),
            (
                drive("/workspace", "agent", 100, 201, 30),
                GrantWidening::DriveOutputExceeded {
                    child: 201,
                    parent: 200,
                },
            ),
            (
                drive("/workspace", "agent", 100, 200, 31),
                GrantWidening::DriveTtlExceeded {
                    child: 31,
                    parent: 30,
                },
            ),
        ] {
            assert_eq!(
                grants_are_subset(
                    &Grants {
                        drive: child,
                        ..Default::default()
                    },
                    &parent
                ),
                Err(expected)
            );
        }
    }
}
