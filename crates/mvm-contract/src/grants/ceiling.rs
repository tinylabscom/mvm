//! The bound on what a grant may ask for.
//!
//! Separate from [`Grants`](crate::grants::Grants) because the two have
//! different trust roots. A grant is signed by whoever launches the workload;
//! a ceiling is resolved at admission from host or fleet configuration and
//! never read out of the plan. Collapsing them would let a plan signer who is
//! also the grant author grant itself the whole machine.

use serde::{Deserialize, Serialize};

use crate::grants::{CpuGrant, Grants, WallClockGrant};

/// A dimension in which a grant exceeded what it was allowed to ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeilingViolation {
    /// Dotted path of the offending dimension, for the refusal message.
    pub dimension: &'static str,
    pub requested: u64,
    pub ceiling: u64,
}

/// The per-host or per-tenant bound. `None` in a dimension means unbounded
/// *in that dimension*; it does not open the others.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantCeiling {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cpu_millicores: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory_mib: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_wall_clock_secs: Option<u32>,
}

impl GrantCeiling {
    /// Check `grants` and the separately-supplied `memory_mib` against this
    /// ceiling. Memory is a parameter rather than a grant field because it is
    /// fixed at VM creation rather than granted, but it still has to be
    /// bounded or a caller could reserve the entire host.
    pub fn admits(&self, grants: &Grants, memory_mib: u64) -> Result<(), CeilingViolation> {
        self.admits_cpu(grants)?;
        self.admits_memory(memory_mib)?;
        self.admits_wall_clock(grants)
    }

    fn admits_cpu(&self, grants: &Grants) -> Result<(), CeilingViolation> {
        // Only `Share` is comparable to a millicore ceiling. `Fuel` is an
        // instruction count in a different unit, so a share ceiling says
        // nothing about it and must not be applied.
        let (Some(max), Some(CpuGrant::Share { millicores })) =
            (self.max_cpu_millicores, grants.cpu)
        else {
            return Ok(());
        };
        if millicores > max {
            return Err(CeilingViolation {
                dimension: "cpu.share_millicores",
                requested: u64::from(millicores),
                ceiling: u64::from(max),
            });
        }
        Ok(())
    }

    fn admits_memory(&self, memory_mib: u64) -> Result<(), CeilingViolation> {
        let Some(max) = self.max_memory_mib else {
            return Ok(());
        };
        if memory_mib > max {
            return Err(CeilingViolation {
                dimension: "memory_mib",
                requested: memory_mib,
                ceiling: max,
            });
        }
        Ok(())
    }

    fn admits_wall_clock(&self, grants: &Grants) -> Result<(), CeilingViolation> {
        let Some(max) = self.max_wall_clock_secs else {
            return Ok(());
        };
        // An unbounded request under a bounded ceiling is a refusal, not a
        // silent clamp: the caller asked for something the host forbids and
        // has to learn that rather than get a different answer than requested.
        let requested = match grants.wall_clock {
            None => return Ok(()),
            Some(WallClockGrant::Unbounded) => u64::MAX,
            Some(WallClockGrant::Secs { secs }) => u64::from(secs.get()),
        };
        if requested > u64::from(max) {
            return Err(CeilingViolation {
                dimension: "wall_clock.secs",
                requested,
                ceiling: u64::from(max),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::{CpuGrant, Grants, WallClockGrant};
    use core::num::NonZeroU32;

    fn ceiling() -> GrantCeiling {
        GrantCeiling {
            max_cpu_millicores: Some(4000),
            max_memory_mib: Some(8192),
            max_wall_clock_secs: Some(3600),
        }
    }

    #[test]
    fn a_grant_within_the_ceiling_is_admitted() {
        let g = Grants {
            cpu: Some(CpuGrant::Share { millicores: 1500 }),
            ..Default::default()
        };
        assert!(ceiling().admits(&g, 512).is_ok());
    }

    #[test]
    fn a_cpu_grant_exceeding_the_ceiling_is_refused() {
        let g = Grants {
            cpu: Some(CpuGrant::Share { millicores: 64_000 }),
            ..Default::default()
        };
        let v = ceiling().admits(&g, 512).expect_err("must refuse");
        assert_eq!(v.dimension, "cpu.share_millicores");
        assert_eq!(v.requested, 64_000);
        assert_eq!(v.ceiling, 4000);
    }

    #[test]
    fn memory_is_checked_even_though_it_is_not_a_grant_field() {
        // Memory is fixed at VM creation rather than granted, but the ceiling
        // still has to bound it or a caller could reserve the whole host.
        let v = ceiling()
            .admits(&Grants::default(), 65_536)
            .expect_err("must refuse");
        assert_eq!(v.dimension, "memory_mib");
    }

    #[test]
    fn an_unbounded_wall_clock_is_refused_under_a_wall_clock_ceiling() {
        let g = Grants {
            wall_clock: Some(WallClockGrant::Unbounded),
            ..Default::default()
        };
        let v = ceiling().admits(&g, 512).expect_err("must refuse");
        assert_eq!(v.dimension, "wall_clock.secs");
    }

    #[test]
    fn an_absent_ceiling_dimension_admits_anything_in_that_dimension() {
        let open = GrantCeiling {
            max_cpu_millicores: None,
            max_memory_mib: None,
            max_wall_clock_secs: None,
        };
        let g = Grants {
            cpu: Some(CpuGrant::Share {
                millicores: 999_999,
            }),
            wall_clock: Some(WallClockGrant::Unbounded),
            ..Default::default()
        };
        assert!(open.admits(&g, u64::MAX).is_ok());
    }

    #[test]
    fn a_fuel_grant_is_not_bounded_by_a_share_ceiling() {
        // Fuel and share are different units; a share ceiling says nothing
        // about an instruction budget and must not be applied to one.
        let g = Grants {
            cpu: Some(CpuGrant::Fuel {
                instructions: u64::MAX,
            }),
            ..Default::default()
        };
        assert!(ceiling().admits(&g, 512).is_ok());
    }

    #[test]
    fn wall_clock_within_the_ceiling_is_admitted() {
        let g = Grants {
            wall_clock: Some(WallClockGrant::Secs {
                secs: NonZeroU32::new(600).expect("nonzero"),
            }),
            ..Default::default()
        };
        assert!(ceiling().admits(&g, 512).is_ok());
    }
}
