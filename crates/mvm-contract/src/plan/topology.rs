//! The critical-systems topology: one document naming every unit of a
//! deployment, where each one runs, which unit stands by for which, the state
//! cells only one unit may write, the controller succession and the
//! cryptographic suite.
//!
//! This module is the format, its structural rules, in [`signing`] its signed
//! envelope and in [`requirements`] the comparison of what it requires with
//! what a backend declares it enforces. Admission and enforcement themselves
//! live elsewhere.
//!
//! ## Determinism
//!
//! Every collection except the succession is a `Vec` that [`Topology::validate`]
//! requires to be strictly ascending by its key, so a topology has exactly one
//! encoding and a reordered copy is refused rather than silently normalised.
//! The succession is ordered by priority, so it is checked only for duplicates.
//! [`Topology::digest`] hashes the same canonical JSON the plan's content
//! address uses: the value is serialized, its object keys sorted, and the
//! bytes hashed with SHA-256.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::num::{NonZeroU32, NonZeroU64};

use serde::{Deserialize, Serialize};

use crate::assurance::Sha256Digest;
use crate::plan::types::{TenantId, WorkloadId};
use crate::timestamp::UtcTimestamp;

pub mod binding;
pub mod requirements;
pub mod signing;
pub use binding::{TopologyBinding, TopologyBindingRefusal, check_topology_binding, plan_recipe};
pub use requirements::{MeasuredFailoverMs, UnmetRequirement, check_requirements};
pub use signing::{SignedTopology, TopologySignatureError, sign_topology, verify_topology};

/// The topology wire-format version this build writes and the newest it
/// verifies.
pub const TOPOLOGY_SCHEMA_VERSION: u32 = 1;

/// A signed description of a whole deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Topology {
    /// Wire-format version, inside the signed body as a plan's is. See
    /// [`TOPOLOGY_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The one tenant every unit and cell belongs to.
    pub tenant: TenantId,
    /// Monotonic generation. A host refuses a generation lower than the last
    /// one it admitted; that check belongs to admission, not to this type.
    pub generation: u64,
    /// The topology is admissible from this instant.
    pub valid_from: UtcTimestamp,
    /// The topology is not admissible at or after this instant.
    pub valid_until: UtcTimestamp,
    /// Signature and key-establishment algorithms.
    pub suite: CryptoSuite,
    /// Every unit, strictly ascending by workload ID.
    pub units: Vec<Unit>,
    /// Failover pairs, strictly ascending by `(active, standby)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub standby_pairs: Vec<StandbyPair>,
    /// Host-held state cells, strictly ascending by name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cells: Vec<StateCell>,
    /// Routes between units, strictly ascending by `(kind, from, to)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<Edge>,
    /// Controllers in the order they take over. Order is meaningful.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub succession: Vec<WorkloadId>,
}

/// One unit of the deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unit {
    pub workload: WorkloadId,
    pub role: UnitRole,
    /// Digest of the image or bundle the unit boots from. Never a plan ID:
    /// the plan names the topology digest, so a plan ID here would be
    /// circular.
    pub recipe: Sha256Digest,
    pub resources: UnitResources,
    #[serde(default, skip_serializing_if = "CorePlacement::is_floating")]
    pub placement: CorePlacement,
    /// The weakest isolation tier the unit may run under. Absent places no
    /// floor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_isolation: Option<IsolationTier>,
    /// The post-admission transitions this unit permits. None by default.
    #[serde(default, skip_serializing_if = "SealedTransitions::is_none")]
    pub permits: SealedTransitions,
    /// The longest the unit may stay silent, in milliseconds, before the host
    /// treats it as failed. Absent declares no liveness deadline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness_period_ms: Option<NonZeroU32>,
    /// The unit's exclusive cores must be isolated from the general scheduler
    /// (`isolcpus=`), so processes MVM does not start are kept off them too.
    /// Valid only with exclusive placement. Absent requires nothing.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub require_isolated_cores: bool,
}

/// What a unit is sized at. The wall-clock bound is not here: it is a grant
/// in the unit's plan, and a second statement of it could disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitResources {
    pub cpus: u32,
    pub mem_mib: u64,
    pub disk_mib: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitRole {
    /// Decides when to start, stop and fail over other units.
    Controller,
    Worker,
}

/// A host CPU core identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CoreId(pub u32);

/// Where a unit's vCPUs run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorePlacement {
    /// Scheduling is left to the host.
    #[default]
    Floating,
    /// The unit's vCPU threads get these cores and no other unit is admitted
    /// to them, except the other member of the unit's standby pair. Strictly
    /// ascending and non-empty.
    Exclusive(Vec<CoreId>),
}

impl CorePlacement {
    #[must_use]
    pub fn is_floating(&self) -> bool {
        matches!(self, Self::Floating)
    }

    fn exclusive_cores(&self) -> &[CoreId] {
        match self {
            Self::Floating => &[],
            Self::Exclusive(cores) => cores,
        }
    }
}

/// Isolation mechanisms, weakest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationTier {
    /// Memory protection without virtualization.
    Task,
    /// A partition of a hypervisor MVM does not own.
    Partition,
    /// Hardware virtualization.
    Vm,
}

impl IsolationTier {
    /// The wire spelling, the same string serde writes.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Task => "task",
            Self::Partition => "partition",
            Self::Vm => "vm",
        }
    }
}

/// The transitions a sealed unit permits after admission.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedTransitions {
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub sleep: bool,
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub wake: bool,
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub pause: bool,
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub checkpoint: bool,
}

impl SealedTransitions {
    #[must_use]
    pub fn is_none(&self) -> bool {
        *self == Self::default()
    }
}

/// A failover standby for one named unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandbyPair {
    pub active: WorkloadId,
    pub standby: WorkloadId,
    pub class: StandbyClass,
    /// The longest failover the deployment accepts, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_bound_ms: Option<NonZeroU32>,
}

/// What exists of the standby while the active unit runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandbyClass {
    /// A booted, admitted standby under its own epoch, idle.
    Resident,
    /// A preloaded or snapshot standby, not running.
    Warm,
    /// Nothing; rebuilt from the recipe.
    Cold,
    /// No standby is kept, so no recovery bound can be met.
    None,
}

/// A fixed-size piece of state the host holds, with exactly one writer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateCell {
    pub name: String,
    pub writer: WorkloadId,
    /// Units that may read the cell, strictly ascending. Readers cannot
    /// write, so the writer is never listed here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub readers: Vec<WorkloadId>,
    pub size_bytes: NonZeroU64,
    #[serde(default, skip_serializing_if = "CellUpdate::is_at_promotion")]
    pub update: CellUpdate,
    /// An audit entry per write instead of the periodic signed digest.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub per_write_audit: bool,
}

/// How a failover standby learns the cell's value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellUpdate {
    /// The standby reads the cell once, when it is promoted.
    #[default]
    AtPromotion,
    /// The host signals each change; signals coalesce, and the standby reads
    /// the latest value when it next runs.
    Follow,
}

impl CellUpdate {
    #[must_use]
    pub fn is_at_promotion(&self) -> bool {
        matches!(self, Self::AtPromotion)
    }
}

/// A route between two units.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub kind: EdgeKind,
    pub from: WorkloadId,
    pub to: WorkloadId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Mailbox,
    Stream,
}

/// The algorithms a topology is signed and keyed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoSuite {
    pub signature: SignatureSuite,
    pub key_establishment: KeyEstablishmentSuite,
}

impl CryptoSuite {
    /// The suite the build implements today.
    pub const CLASSICAL: Self = Self {
        signature: SignatureSuite::Ed25519,
        key_establishment: KeyEstablishmentSuite::X25519,
    };
}

/// Signature algorithms. Every post-quantum entry is hybrid with Ed25519; no
/// suite without the classical half is representable. Only `Ed25519` is
/// implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureSuite {
    Ed25519,
    Ed25519MlDsa65,
    Ed25519MlDsa87,
}

/// Key-establishment algorithms, hybrid in the same way. Only `X25519` is
/// implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyEstablishmentSuite {
    X25519,
    X25519MlKem768,
    X25519MlKem1024,
}

/// A collection [`Topology::validate`] requires to be strictly ascending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Collection {
    Units,
    StandbyPairs,
    Cells,
    Edges,
    Succession,
    CellReaders { cell: String },
    Cores { unit: WorkloadId },
}

/// The element that named a unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitReference {
    CellWriter { cell: String },
    CellReader { cell: String },
    StandbyActive,
    StandbyMember,
    Succession,
    EdgeFrom,
    EdgeTo,
}

/// Why a topology is structurally inadmissible.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TopologyValidationError {
    #[error("the topology declares no units")]
    NoUnits,
    #[error("the validity window is empty: valid_from equals valid_until")]
    EmptyValidityWindow,
    #[error("the validity window is inverted: valid_until precedes valid_from")]
    InvertedValidityWindow,
    #[error("{collection:?} is not in ascending order")]
    Unsorted { collection: Collection },
    #[error("unit {} is declared twice", .unit.0)]
    DuplicateUnit { unit: WorkloadId },
    #[error("cell {cell} is declared twice")]
    DuplicateCell { cell: String },
    #[error("{entry} appears twice in {collection:?}")]
    DuplicateEntry {
        collection: Collection,
        entry: String,
    },
    #[error("{reference:?} names unknown unit {}", .unit.0)]
    UnknownUnit {
        reference: UnitReference,
        unit: WorkloadId,
    },
    #[error("cell {cell} lists its writer {} as a reader", .unit.0)]
    WriterIsReader { cell: String, unit: WorkloadId },
    #[error("unit {} declares an empty exclusive core set", .unit.0)]
    EmptyCoreSet { unit: WorkloadId },
    #[error("unit {} requires isolated cores but holds none exclusively", .unit.0)]
    IsolationWithoutExclusiveCores { unit: WorkloadId },
    #[error(
        "units {} and {} both hold core {} exclusively and are not a standby pair",
        .first.0, .second.0, .core.0
    )]
    SharedExclusiveCore {
        first: WorkloadId,
        second: WorkloadId,
        core: CoreId,
    },
    #[error("succession entry {} is not a controller", .unit.0)]
    SuccessorNotController { unit: WorkloadId },
    #[error("unit {} is its own standby", .unit.0)]
    SelfStandby { unit: WorkloadId },
    #[error("unit {} appears in more than one standby pair", .unit.0)]
    UnitInTwoPairs { unit: WorkloadId },
    #[error("the pair for {} declares a recovery bound with no standby kept", .active.0)]
    RecoveryBoundWithoutStandby { active: WorkloadId },
    #[error(
        "the pair for {} states a {bound_ms} ms recovery bound, no longer than the unit's \
         {period_ms} ms liveness period; detecting a failure alone takes the whole period, \
         so the bound must exceed it",
        .active.0
    )]
    RecoveryBoundWithinLivenessPeriod {
        active: WorkloadId,
        bound_ms: NonZeroU32,
        period_ms: NonZeroU32,
    },
}

/// Where a strictly-ascending check first failed.
enum OrderFault {
    Unsorted,
    Duplicate(usize),
}

fn strictly_ascending<'a, T, K: Ord>(
    items: &'a [T],
    key: impl Fn(&'a T) -> K,
) -> Result<(), OrderFault> {
    for (index, pair) in items.windows(2).enumerate() {
        match key(&pair[0]).cmp(&key(&pair[1])) {
            core::cmp::Ordering::Less => {}
            core::cmp::Ordering::Equal => return Err(OrderFault::Duplicate(index + 1)),
            core::cmp::Ordering::Greater => return Err(OrderFault::Unsorted),
        }
    }
    Ok(())
}

impl Topology {
    /// Check every structural rule, returning the first violation found.
    pub fn validate(&self) -> Result<(), TopologyValidationError> {
        use TopologyValidationError as E;

        if self.valid_until == self.valid_from {
            return Err(E::EmptyValidityWindow);
        }
        if self.valid_until < self.valid_from {
            return Err(E::InvertedValidityWindow);
        }
        if self.units.is_empty() {
            return Err(E::NoUnits);
        }
        strictly_ascending(&self.units, |u| &u.workload).map_err(|fault| match fault {
            OrderFault::Unsorted => E::Unsorted {
                collection: Collection::Units,
            },
            OrderFault::Duplicate(i) => E::DuplicateUnit {
                unit: self.units[i].workload.clone(),
            },
        })?;
        for unit in &self.units {
            if unit.require_isolated_cores && unit.placement.is_floating() {
                return Err(E::IsolationWithoutExclusiveCores {
                    unit: unit.workload.clone(),
                });
            }
            if let CorePlacement::Exclusive(cores) = &unit.placement {
                if cores.is_empty() {
                    return Err(E::EmptyCoreSet {
                        unit: unit.workload.clone(),
                    });
                }
                strictly_ascending(cores, |c| *c).map_err(|fault| {
                    let collection = Collection::Cores {
                        unit: unit.workload.clone(),
                    };
                    match fault {
                        OrderFault::Unsorted => E::Unsorted { collection },
                        OrderFault::Duplicate(i) => E::DuplicateEntry {
                            collection,
                            entry: alloc::format!("core {}", cores[i].0),
                        },
                    }
                })?;
            }
        }
        self.validate_pairs()?;
        self.validate_exclusive_cores()?;
        self.validate_cells()?;
        self.validate_edges()?;
        self.validate_succession()
    }

    /// SHA-256 over the canonical JSON encoding, in the `sha256:<hex>` form.
    /// Two topologies that pass [`Topology::validate`] have the same digest
    /// exactly when they are equal.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        use sha2::Digest;
        let value = serde_json::to_value(self).expect("a topology serializes to JSON");
        let bytes = serde_json::to_vec(&value).expect("a JSON value re-serializes");
        Sha256Digest::from_bytes(&sha2::Sha256::digest(&bytes).into())
    }

    fn unit(&self, id: &WorkloadId) -> Option<&Unit> {
        self.units
            .binary_search_by(|u| u.workload.cmp(id))
            .ok()
            .map(|i| &self.units[i])
    }

    fn require_unit(
        &self,
        id: &WorkloadId,
        reference: UnitReference,
    ) -> Result<&Unit, TopologyValidationError> {
        self.unit(id)
            .ok_or_else(|| TopologyValidationError::UnknownUnit {
                reference,
                unit: id.clone(),
            })
    }

    fn is_pair(&self, a: &WorkloadId, b: &WorkloadId) -> bool {
        self.standby_pairs
            .iter()
            .any(|p| (&p.active == a && &p.standby == b) || (&p.active == b && &p.standby == a))
    }

    fn validate_pairs(&self) -> Result<(), TopologyValidationError> {
        use TopologyValidationError as E;
        strictly_ascending(&self.standby_pairs, |p| (&p.active, &p.standby)).map_err(|fault| {
            match fault {
                OrderFault::Unsorted => E::Unsorted {
                    collection: Collection::StandbyPairs,
                },
                OrderFault::Duplicate(i) => E::UnitInTwoPairs {
                    unit: self.standby_pairs[i].active.clone(),
                },
            }
        })?;
        let mut members = BTreeSet::new();
        for pair in &self.standby_pairs {
            let active = self.require_unit(&pair.active, UnitReference::StandbyActive)?;
            self.require_unit(&pair.standby, UnitReference::StandbyMember)?;
            if pair.active == pair.standby {
                return Err(E::SelfStandby {
                    unit: pair.active.clone(),
                });
            }
            for member in [&pair.active, &pair.standby] {
                if !members.insert(member) {
                    return Err(E::UnitInTwoPairs {
                        unit: member.clone(),
                    });
                }
            }
            if pair.class == StandbyClass::None && pair.recovery_bound_ms.is_some() {
                return Err(E::RecoveryBoundWithoutStandby {
                    active: pair.active.clone(),
                });
            }
            if let (Some(bound_ms), Some(period_ms)) =
                (pair.recovery_bound_ms, active.liveness_period_ms)
                && bound_ms <= period_ms
            {
                return Err(E::RecoveryBoundWithinLivenessPeriod {
                    active: pair.active.clone(),
                    bound_ms,
                    period_ms,
                });
            }
        }
        Ok(())
    }

    fn validate_exclusive_cores(&self) -> Result<(), TopologyValidationError> {
        for (i, first) in self.units.iter().enumerate() {
            let first_cores = first.placement.exclusive_cores();
            for second in &self.units[i + 1..] {
                let shared = second
                    .placement
                    .exclusive_cores()
                    .iter()
                    .find(|core| first_cores.binary_search(core).is_ok());
                if let Some(core) = shared
                    && !self.is_pair(&first.workload, &second.workload)
                {
                    return Err(TopologyValidationError::SharedExclusiveCore {
                        first: first.workload.clone(),
                        second: second.workload.clone(),
                        core: *core,
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_cells(&self) -> Result<(), TopologyValidationError> {
        use TopologyValidationError as E;
        strictly_ascending(&self.cells, |c| &c.name).map_err(|fault| match fault {
            OrderFault::Unsorted => E::Unsorted {
                collection: Collection::Cells,
            },
            OrderFault::Duplicate(i) => E::DuplicateCell {
                cell: self.cells[i].name.clone(),
            },
        })?;
        for cell in &self.cells {
            self.require_unit(
                &cell.writer,
                UnitReference::CellWriter {
                    cell: cell.name.clone(),
                },
            )?;
            strictly_ascending(&cell.readers, |r| r).map_err(|fault| {
                let collection = Collection::CellReaders {
                    cell: cell.name.clone(),
                };
                match fault {
                    OrderFault::Unsorted => E::Unsorted { collection },
                    OrderFault::Duplicate(i) => E::DuplicateEntry {
                        collection,
                        entry: cell.readers[i].0.clone(),
                    },
                }
            })?;
            for reader in &cell.readers {
                self.require_unit(
                    reader,
                    UnitReference::CellReader {
                        cell: cell.name.clone(),
                    },
                )?;
                if reader == &cell.writer {
                    return Err(E::WriterIsReader {
                        cell: cell.name.clone(),
                        unit: reader.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_edges(&self) -> Result<(), TopologyValidationError> {
        use TopologyValidationError as E;
        strictly_ascending(&self.edges, |e| e).map_err(|fault| match fault {
            OrderFault::Unsorted => E::Unsorted {
                collection: Collection::Edges,
            },
            OrderFault::Duplicate(i) => E::DuplicateEntry {
                collection: Collection::Edges,
                entry: alloc::format!("{:?}", self.edges[i]),
            },
        })?;
        for edge in &self.edges {
            self.require_unit(&edge.from, UnitReference::EdgeFrom)?;
            self.require_unit(&edge.to, UnitReference::EdgeTo)?;
        }
        Ok(())
    }

    fn validate_succession(&self) -> Result<(), TopologyValidationError> {
        use TopologyValidationError as E;
        let mut seen = BTreeSet::new();
        for id in &self.succession {
            if !seen.insert(id) {
                return Err(E::DuplicateEntry {
                    collection: Collection::Succession,
                    entry: id.0.clone(),
                });
            }
            if self.require_unit(id, UnitReference::Succession)?.role != UnitRole::Controller {
                return Err(E::SuccessorNotController { unit: id.clone() });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
