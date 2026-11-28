//! Fit check: does a declared deployment fit on a host?
//!
//! Pure arithmetic over a [`HostCapacity`] and one [`Section`] of a resource
//! report. Resources are checked in a fixed order (memory, vCPU, disk) and the
//! first one that does not fit is reported. Every quantity is carried in MiB
//! (vCPUs as a count) in `u128`, so the largest unit count cannot overflow.
//!
//! The vCPU check allows no overcommit: every declared vCPU needs a host
//! thread. A topology unit holding cores exclusively is charged those cores
//! instead of its vCPU count, and a core shared by a standby pair once. Each
//! exclusive core ID is then checked against the host's vCPU count, the only
//! core information an inventory carries.

use std::collections::BTreeMap;

use mvm_contract::plan::topology::{CoreId, CorePlacement, Topology};
use mvm_contract::plan::types::WorkloadId;
use mvm_core::mvmd_iface::host_inventory::HostCapacity;
use mvm_core::spawn_scope::VMM_MEMORY_OVERHEAD_MIB;

use super::resource_report::Section;

const BYTES_PER_MIB: u64 = 1024 * 1024;
const MIB_PER_GIB: u128 = 1024;

/// A declared deployment: `units` identical machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deployment {
    pub units: u32,
    pub vcpus_per_unit: u32,
    pub memory_mib_per_unit: u64,
    /// Declared disk per unit; the report's measurement is used when absent.
    pub disk_mib_per_unit: Option<u64>,
}

/// What a deployment charges the host, summed over its units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Demand {
    pub units: u128,
    pub vcpus: u128,
    pub memory_mib: u128,
    /// Declared disk for all units; the report's per-unit measurement is
    /// used when absent.
    pub disk_mib: Option<u128>,
    /// Every exclusive core, once, with the first unit that holds it.
    pub cores: BTreeMap<CoreId, WorkloadId>,
}

impl From<&Deployment> for Demand {
    fn from(d: &Deployment) -> Self {
        let n = u128::from(d.units);
        Self {
            units: n,
            vcpus: n * u128::from(d.vcpus_per_unit),
            memory_mib: n * u128::from(d.memory_mib_per_unit),
            disk_mib: d.disk_mib_per_unit.map(|disk| n * u128::from(disk)),
            cores: BTreeMap::new(),
        }
    }
}

impl From<&Topology> for Demand {
    /// Sums every unit, standbys included. Structure is not checked here:
    /// validate the topology first, or a core held by two unrelated units is
    /// charged once as if they were a pair.
    fn from(t: &Topology) -> Self {
        let mut demand = Self {
            units: t.units.len() as u128,
            vcpus: 0,
            memory_mib: 0,
            disk_mib: Some(0),
            cores: BTreeMap::new(),
        };
        for unit in &t.units {
            demand.memory_mib += u128::from(unit.resources.mem_mib);
            demand.disk_mib = demand
                .disk_mib
                .map(|d| d + u128::from(unit.resources.disk_mib));
            match &unit.placement {
                CorePlacement::Floating => demand.vcpus += u128::from(unit.resources.cpus),
                CorePlacement::Exclusive(cores) => {
                    for core in cores {
                        demand
                            .cores
                            .entry(*core)
                            .or_insert_with(|| unit.workload.clone());
                    }
                }
            }
        }
        demand.vcpus += demand.cores.len() as u128;
        demand
    }
}

/// Where a figure used in the check came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Measured,
    Declared,
    /// Not measured; a constant (or zero) stood in.
    Fallback,
}

/// Provenance of every report-dependent input the check used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provenance {
    pub fixed_memory: Source,
    pub unit_overhead: Source,
    pub fixed_disk: Source,
    /// `None` when no per-unit disk figure existed.
    pub unit_disk: Option<Source>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    Memory,
    Vcpu,
    Disk,
    /// An exclusive core ID the host does not have.
    Core,
}

/// Required vs available for one resource (MiB, or a vCPU count).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Headroom {
    pub required: u128,
    pub available: u128,
}

impl Headroom {
    const fn fits(&self) -> bool {
        self.required <= self.available
    }

    /// Spare capacity; zero when the resource does not fit.
    pub const fn spare(&self) -> u128 {
        self.available.saturating_sub(self.required)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiskCheck {
    Checked(Headroom),
    NotChecked { reason: &'static str },
}

/// The deployment fits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fit {
    pub memory: Headroom,
    pub vcpu: Headroom,
    pub disk: DiskCheck,
    pub provenance: Provenance,
}

/// The first resource that does not fit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shortfall {
    pub resource: Resource,
    /// For [`Resource::Core`], `required` is the core ID plus one and
    /// `available` the host's vCPU count.
    pub headroom: Headroom,
    pub provenance: Provenance,
    /// The missing core and the unit that holds it, for [`Resource::Core`].
    pub core: Option<(CoreId, WorkloadId)>,
}

const DISK_UNKNOWN: &str = "no declared per-unit disk and the report has no measured one";

#[must_use]
pub const fn bytes_to_mib_ceil(bytes: u64) -> u128 {
    (bytes as u128).div_ceil(BYTES_PER_MIB as u128)
}

#[must_use]
pub const fn gib_to_mib(gib: u64) -> u128 {
    gib as u128 * MIB_PER_GIB
}

fn measured_mib(
    figure: &super::resource_report::Figure<u64>,
    fallback: Option<u128>,
) -> (Option<u128>, Source) {
    match figure.value() {
        Some(b) => (Some(bytes_to_mib_ceil(*b)), Source::Measured),
        None => (fallback, Source::Fallback),
    }
}

/// Check `deployment` against `host`, using `section` for host costs.
///
/// # Errors
/// A [`Shortfall`] naming the first of memory, vCPU, disk that does not fit.
pub fn check_fit(
    deployment: &Deployment,
    host: &HostCapacity,
    section: &Section,
) -> Result<Fit, Shortfall> {
    check_demand(&Demand::from(deployment), host, section)
}

/// Check `demand` against `host`, using `section` for host costs.
///
/// # Errors
/// A [`Shortfall`] naming the first of memory, vCPU, disk, exclusive core
/// that does not fit.
pub fn check_demand(
    demand: &Demand,
    host: &HostCapacity,
    section: &Section,
) -> Result<Fit, Shortfall> {
    let n = demand.units;
    let running = &section.by_residency.running;

    let (fixed_mem, fixed_memory) = measured_mib(&section.fixed_host_cost.memory_bytes, Some(0));
    // A measured running footprint includes guest pages, so it cannot be added to
    // configured memory; admission charges configured memory plus this same margin.
    let unit_over = u128::from(VMM_MEMORY_OVERHEAD_MIB);
    let unit_overhead = Source::Fallback;
    let (fixed_disk_mib, fixed_disk) = measured_mib(&section.fixed_host_cost.disk_bytes, Some(0));
    let (measured_unit_disk, _) = measured_mib(&running.disk_bytes, None);

    let (units_disk_mib, unit_disk) = match (demand.disk_mib, measured_unit_disk) {
        (Some(d), _) => (Some(d), Some(Source::Declared)),
        (None, Some(m)) => (Some(n * m), Some(Source::Measured)),
        (None, None) => (None, None),
    };

    let provenance = Provenance {
        fixed_memory,
        unit_overhead,
        fixed_disk,
        unit_disk,
    };

    let memory = Headroom {
        required: fixed_mem.unwrap_or(0) + demand.memory_mib + n * unit_over,
        available: u128::from(host.total_mem_mib),
    };
    let vcpu = Headroom {
        required: demand.vcpus,
        available: u128::from(host.total_vcpus),
    };
    let disk = units_disk_mib.map(|u| Headroom {
        required: fixed_disk_mib.unwrap_or(0) + u,
        available: gib_to_mib(host.total_disk_gib),
    });

    let short = |resource, headroom| Shortfall {
        resource,
        headroom,
        provenance,
        core: None,
    };
    if !memory.fits() {
        return Err(short(Resource::Memory, memory));
    }
    if !vcpu.fits() {
        return Err(short(Resource::Vcpu, vcpu));
    }
    if let Some(d) = disk.filter(|d| !d.fits()) {
        return Err(short(Resource::Disk, d));
    }
    if let Some((core, unit)) = demand.cores.range(CoreId(host.total_vcpus)..).next() {
        return Err(Shortfall {
            core: Some((*core, unit.clone())),
            ..short(
                Resource::Core,
                Headroom {
                    required: u128::from(core.0) + 1,
                    available: u128::from(host.total_vcpus),
                },
            )
        });
    }
    Ok(Fit {
        memory,
        vcpu,
        disk: disk.map_or(
            DiskCheck::NotChecked {
                reason: DISK_UNKNOWN,
            },
            DiskCheck::Checked,
        ),
        provenance,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::resource_report::{Figure, Section, WakeupQuantity};
    use super::*;
    use mvm_contract::assurance::Sha256Digest;
    use mvm_contract::plan::topology::{
        CryptoSuite, SealedTransitions, StandbyClass, StandbyPair, TOPOLOGY_SCHEMA_VERSION, Unit,
        UnitResources, UnitRole,
    };
    use mvm_contract::plan::types::TenantId;

    fn section(
        fixed_mem: Figure<u64>,
        unit_mem: Figure<u64>,
        fixed_disk: Figure<u64>,
        unit_disk: Figure<u64>,
    ) -> Section {
        let mut s = Section::unmeasured("test", "test", WakeupQuantity::MacosLibproc);
        s.fixed_host_cost.memory_bytes = fixed_mem;
        s.fixed_host_cost.disk_bytes = fixed_disk;
        s.by_residency.running.memory_bytes = unit_mem;
        s.by_residency.running.disk_bytes = unit_disk;
        s
    }

    fn unmeasured() -> Section {
        section(
            Figure::default(),
            Figure::default(),
            Figure::default(),
            Figure::default(),
        )
    }

    fn host(vcpus: u32, mem_mib: u64, disk_gib: u64) -> HostCapacity {
        HostCapacity {
            total_vcpus: vcpus,
            total_mem_mib: mem_mib,
            total_disk_gib: disk_gib,
        }
    }

    fn dep(units: u32, vcpus: u32, mem: u64, disk: Option<u64>) -> Deployment {
        Deployment {
            units,
            vcpus_per_unit: vcpus,
            memory_mib_per_unit: mem,
            disk_mib_per_unit: disk,
        }
    }

    #[test]
    fn unit_conversions() {
        assert_eq!(bytes_to_mib_ceil(0), 0);
        assert_eq!(bytes_to_mib_ceil(1), 1);
        assert_eq!(bytes_to_mib_ceil(BYTES_PER_MIB), 1);
        assert_eq!(bytes_to_mib_ceil(BYTES_PER_MIB + 1), 2);
        assert_eq!(gib_to_mib(2), 2048);
        assert_eq!(gib_to_mib(u64::MAX), u128::from(u64::MAX) * 1024);
    }

    #[test]
    fn everything_fits_and_records_fallbacks() {
        // 4 units x (512 + 256 fallback) = 3072 MiB.
        let fit = check_fit(
            &dep(4, 2, 512, Some(100)),
            &host(8, 4096, 10),
            &unmeasured(),
        )
        .unwrap();
        assert_eq!(
            fit.memory,
            Headroom {
                required: 3072,
                available: 4096
            }
        );
        assert_eq!(fit.memory.spare(), 1024);
        assert_eq!(fit.vcpu.required, 8);
        assert_eq!(
            fit.disk,
            DiskCheck::Checked(Headroom {
                required: 400,
                available: 10240
            })
        );
        assert_eq!(fit.provenance.unit_overhead, Source::Fallback);
        assert_eq!(fit.provenance.fixed_memory, Source::Fallback);
        assert_eq!(fit.provenance.unit_disk, Some(Source::Declared));
    }

    #[test]
    fn measured_figures_are_used_and_labelled() {
        let mib = BYTES_PER_MIB;
        let s = section(
            Figure::measured(100 * mib),
            Figure::measured(10 * mib),
            Figure::measured(50 * mib),
            Figure::measured(20 * mib),
        );
        let fit = check_fit(&dep(2, 1, 90, None), &host(4, 4096, 1), &s).unwrap();
        assert_eq!(
            fit.memory.required,
            100 + 2 * (90 + u128::from(VMM_MEMORY_OVERHEAD_MIB))
        );
        assert_eq!(
            fit.disk,
            DiskCheck::Checked(Headroom {
                required: 50 + 40,
                available: 1024
            })
        );
        assert_eq!(fit.provenance.fixed_memory, Source::Measured);
        assert_eq!(fit.provenance.unit_overhead, Source::Fallback);
        assert_eq!(fit.provenance.unit_disk, Some(Source::Measured));
    }

    #[test]
    fn measured_running_memory_never_replaces_the_constant_overhead() {
        let s = section(
            Figure::default(),
            Figure::measured(900 * BYTES_PER_MIB),
            Figure::default(),
            Figure::default(),
        );
        let fit = check_fit(&dep(3, 1, 512, Some(1)), &host(8, 10_000, 10), &s).unwrap();
        assert_eq!(
            fit.memory.required,
            3 * (512 + u128::from(VMM_MEMORY_OVERHEAD_MIB))
        );
        assert_eq!(fit.provenance.unit_overhead, Source::Fallback);
    }

    #[test]
    fn memory_fails_first_even_when_others_fail() {
        let e = check_fit(
            &dep(10, 100, 1000, Some(u64::MAX)),
            &host(1, 10, 0),
            &unmeasured(),
        )
        .unwrap_err();
        assert_eq!(e.resource, Resource::Memory);
        assert_eq!(
            e.headroom,
            Headroom {
                required: 12560,
                available: 10
            }
        );
    }

    #[test]
    fn vcpu_fails_before_disk() {
        let e = check_fit(
            &dep(3, 2, 1, Some(u64::MAX)),
            &host(5, 100_000, 0),
            &unmeasured(),
        )
        .unwrap_err();
        assert_eq!(e.resource, Resource::Vcpu);
        assert_eq!(
            e.headroom,
            Headroom {
                required: 6,
                available: 5
            }
        );
    }

    #[test]
    fn disk_fails_last() {
        let e = check_fit(
            &dep(2, 1, 1, Some(2048)),
            &host(8, 100_000, 3),
            &unmeasured(),
        )
        .unwrap_err();
        assert_eq!(e.resource, Resource::Disk);
        assert_eq!(
            e.headroom,
            Headroom {
                required: 4096,
                available: 3072
            }
        );
    }

    #[test]
    fn unknown_disk_is_not_checked() {
        let fit = check_fit(&dep(1, 1, 1, None), &host(1, 1000, 0), &unmeasured()).unwrap();
        assert_eq!(
            fit.disk,
            DiskCheck::NotChecked {
                reason: DISK_UNKNOWN
            }
        );
        assert_eq!(fit.provenance.unit_disk, None);
    }

    #[test]
    fn huge_unit_count_neither_overflows_nor_panics() {
        let e = check_fit(
            &dep(u32::MAX, u32::MAX, u64::MAX, Some(u64::MAX)),
            &host(u32::MAX, u64::MAX, u64::MAX),
            &unmeasured(),
        )
        .unwrap_err();
        assert_eq!(e.resource, Resource::Memory);
        assert!(e.headroom.required > e.headroom.available);
    }

    #[test]
    fn mixed_unit_sizes_are_summed() {
        let t = topology(
            vec![
                unit("a", 2, 1024, 100, &[]),
                unit("b", 1, 256, 50, &[]),
                unit("c", 4, 512, 10, &[]),
            ],
            vec![],
        );
        let fit = check_demand(&Demand::from(&t), &host(8, 100_000, 10), &unmeasured()).unwrap();
        assert_eq!(
            fit.memory.required,
            1024 + 256 + 512 + 3 * u128::from(VMM_MEMORY_OVERHEAD_MIB)
        );
        assert_eq!(fit.vcpu.required, 7);
        assert_eq!(
            fit.disk,
            DiskCheck::Checked(Headroom {
                required: 160,
                available: 10240
            })
        );
        assert_eq!(fit.provenance.unit_disk, Some(Source::Declared));
    }

    #[test]
    fn identical_topology_units_match_the_n_unit_path() {
        let t = topology(
            (0..5)
                .map(|i| unit(&format!("w{i}"), 2, 512, 100, &[]))
                .collect(),
            vec![],
        );
        let h = host(16, 8192, 10);
        let s = section(
            Figure::measured(100 * BYTES_PER_MIB),
            Figure::default(),
            Figure::measured(30 * BYTES_PER_MIB),
            Figure::default(),
        );
        assert_eq!(
            check_demand(&Demand::from(&t), &h, &s),
            check_fit(&dep(5, 2, 512, Some(100)), &h, &s)
        );
        // And when they do not fit, the same shortfall.
        let small = host(9, 8192, 10);
        assert_eq!(
            check_demand(&Demand::from(&t), &small, &s),
            check_fit(&dep(5, 2, 512, Some(100)), &small, &s)
        );
    }

    #[test]
    fn a_missing_exclusive_core_is_named_with_its_unit() {
        let t = topology(
            vec![unit("a", 1, 256, 1, &[1]), unit("b", 1, 256, 1, &[6, 9])],
            vec![],
        );
        let e = check_demand(&Demand::from(&t), &host(8, 100_000, 10), &unmeasured()).unwrap_err();
        assert_eq!(e.resource, Resource::Core);
        assert_eq!(e.core, Some((CoreId(9), WorkloadId("b".to_string()))));
        assert_eq!(
            e.headroom,
            Headroom {
                required: 10,
                available: 8
            }
        );
    }

    #[test]
    fn a_standby_pair_sharing_cores_is_charged_them_once() {
        let t = topology(
            vec![
                unit("a", 2, 256, 1, &[2, 3]),
                unit("a-standby", 2, 256, 1, &[2, 3]),
                unit("w", 1, 256, 1, &[]),
            ],
            vec![StandbyPair {
                active: WorkloadId("a".to_string()),
                standby: WorkloadId("a-standby".to_string()),
                class: StandbyClass::None,
                recovery_bound_ms: None,
            }],
        );
        t.validate().unwrap();
        let demand = Demand::from(&t);
        assert_eq!(demand.vcpus, 3);
        assert_eq!(demand.cores.len(), 2);
        assert_eq!(demand.cores[&CoreId(2)], WorkloadId("a".to_string()));
        assert_eq!(
            check_demand(&demand, &host(4, 100_000, 10), &unmeasured())
                .unwrap()
                .vcpu,
            Headroom {
                required: 3,
                available: 4
            }
        );
    }

    pub(crate) fn unit(name: &str, cpus: u32, mem_mib: u64, disk_mib: u64, cores: &[u32]) -> Unit {
        Unit {
            workload: WorkloadId(name.to_string()),
            role: UnitRole::Worker,
            recipe: Sha256Digest::from_bytes(&[1; 32]),
            resources: UnitResources {
                cpus,
                mem_mib,
                disk_mib,
            },
            placement: if cores.is_empty() {
                CorePlacement::Floating
            } else {
                CorePlacement::Exclusive(cores.iter().copied().map(CoreId).collect())
            },
            min_isolation: None,
            permits: SealedTransitions::default(),
            liveness_period_ms: None,
            require_isolated_cores: false,
        }
    }

    pub(crate) fn topology(units: Vec<Unit>, standby_pairs: Vec<StandbyPair>) -> Topology {
        Topology {
            schema_version: TOPOLOGY_SCHEMA_VERSION,
            tenant: TenantId("t".to_string()),
            generation: 1,
            valid_from: "2026-01-01T00:00:00Z".parse().unwrap(),
            valid_until: "2027-01-01T00:00:00Z".parse().unwrap(),
            suite: CryptoSuite::CLASSICAL,
            units,
            standby_pairs,
            cells: vec![],
            edges: vec![],
            succession: vec![],
        }
    }
}
