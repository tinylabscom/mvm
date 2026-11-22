//! Host-held state cells.
//!
//! A cell is a fixed-size value that a topology declares with one writer unit
//! and its reader units. The host holds it in a store of its own, one
//! directory per tenant under `<mvm_home>/state-cells`, apart from the
//! workload ledger and every journal. Its storage is reserved when the
//! topology is admitted, so a write never needs space the host did not already
//! set aside, and a cell outlives every epoch of the units that use it.
//!
//! What a caller may do comes from the admitted topology: the caller names a
//! cell and presents its unit and epoch, and the topology says whether that
//! unit writes the cell, reads it, or neither. Whether the epoch may act is the
//! epoch gate's decision over the durable workload record, asked afresh on
//! every call. A write must also carry a version greater than the stored one
//! and fit the cell.
//!
//! Every operation holds the cell's lock from before it asks the gate until
//! its write is synced, which is what keeps a cell to one writer at a time
//! across threads and processes. Because the gate is asked inside the lock, a
//! write admitted just before its epoch was replaced can still complete, but
//! never after a write from the epoch that replaced it.
//!
//! Refusals of authority (an unknown cell, a unit without the role, an epoch
//! the gate refuses) are written to the tenant's chain. A stale version or an
//! oversized value is the writer's own error and is not. Accepted writes are
//! not audited here one by one; the writer's owner digests them periodically
//! ([`digest`]).

pub mod digest;
mod slots;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use mvm_contract::plan::topology::{StateCell, Topology};
use mvm_contract::protocol::mailbox::ExecutionEpoch;
use mvm_core::atomic_io::{self, FileLock, NewFile, write_private_new};
use mvm_core::host_interface::Denial;
use mvm_core::host_interface::epoch_gate::CommandGate;
use mvm_core::plan::{TenantId, WorkloadId};
use mvm_core::protocol::lifecycle_audit::{LifecycleEvent, LifecycleLabel, LifecycleLabels};
use sha2::{Digest as _, Sha256};

use crate::audit::refusal::RefusalAudit;

/// Chain event for a refused cell operation.
pub const STATE_CELL_REFUSED_EVENT: &str = LifecycleEvent::StateCellRefused.as_str();

/// The largest cell this host reserves. A cell is a small piece of control
/// state copied whole on every update, not a volume, and its whole value has
/// to cross the broker in one frame.
pub const MAX_CELL_BYTES: u64 = 32 * 1024;

/// What a broker frame carries besides a cell value: the call or response
/// envelope, a cell name of the longest accepted length and the version.
const BROKER_FRAME_HEADROOM: usize = 8 * 1024;

// A full cell, base64-encoded as the service carries it, fits one broker frame.
const _: () = assert!(
    (MAX_CELL_BYTES as usize).div_ceil(3) * 4 + BROKER_FRAME_HEADROOM
        <= mvm_core::framing::DEFAULT_MAX_FRAME_BYTES
);

/// The most cells one topology may declare.
pub const MAX_CELLS_PER_TOPOLOGY: usize = 64;

/// The most disk one tenant's cells may take, both slots of every cell
/// counted. The store keeps only the cells of the tenant's admitted
/// generation, so this bounds the tenant's whole directory, lock files aside.
pub const MAX_RESERVED_BYTES_PER_TENANT: u64 = 2 * 1024 * 1024;

/// A topology whose cells exceed what this host reserves.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReservationLimit {
    #[error("cell {cell} declares {size} bytes and this host reserves at most {MAX_CELL_BYTES}")]
    CellTooLarge { cell: String, size: u64 },
    #[error(
        "the topology declares {count} cells and this host reserves at most \
         {MAX_CELLS_PER_TOPOLOGY}"
    )]
    TooManyCells { count: usize },
    #[error(
        "the cells need {bytes} bytes on disk and this host reserves at most \
         {MAX_RESERVED_BYTES_PER_TENANT} per tenant"
    )]
    TooManyBytes { bytes: u64 },
}

fn check_limits(topology: &Topology) -> Result<(), ReservationLimit> {
    let count = topology.cells.len();
    if count > MAX_CELLS_PER_TOPOLOGY {
        return Err(ReservationLimit::TooManyCells { count });
    }
    let mut bytes: u64 = 0;
    for cell in &topology.cells {
        let size = cell.size_bytes.get();
        if size > MAX_CELL_BYTES {
            return Err(ReservationLimit::CellTooLarge {
                cell: cell.name.clone(),
                size,
            });
        }
        // At most 64 cells of at most MAX_CELL_BYTES each: no overflow.
        bytes += slots::file_len(size);
    }
    if bytes > MAX_RESERVED_BYTES_PER_TENANT {
        return Err(ReservationLimit::TooManyBytes { bytes });
    }
    Ok(())
}

/// A cell operation the host refused. The returned error's root cause, so a
/// caller can `downcast_ref` it even when the refusal's audit write failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CellRefusal {
    #[error("no admitted topology of this tenant declares cell {cell}")]
    UnknownCell { cell: String },
    #[error("unit {} does not write cell {cell}", .unit.0)]
    NotWriter { cell: String, unit: WorkloadId },
    #[error("unit {} neither writes nor reads cell {cell}", .unit.0)]
    NotReader { cell: String, unit: WorkloadId },
    #[error("unit {} may not use cell {cell}: {denial}", .unit.0)]
    Epoch {
        cell: String,
        unit: WorkloadId,
        denial: Denial,
    },
    #[error("version {got} of cell {cell} is not greater than the stored version {stored}")]
    VersionNotIncreasing { cell: String, got: u64, stored: u64 },
    #[error("{len} bytes do not fit cell {cell}, which holds {size}")]
    TooLarge { cell: String, len: u64, size: u64 },
}

impl CellRefusal {
    /// Whether the refusal answers who may act, and so goes on the chain.
    fn is_authority(&self) -> bool {
        !matches!(
            self,
            Self::VersionNotIncreasing { .. } | Self::TooLarge { .. }
        )
    }

    /// The refusal's variant, without its fields.
    fn kind(&self) -> &'static str {
        match self {
            Self::UnknownCell { .. } => "unknown_cell",
            Self::NotWriter { .. } => "not_writer",
            Self::NotReader { .. } => "not_reader",
            Self::Epoch { .. } => "epoch",
            Self::VersionNotIncreasing { .. } => "version_not_increasing",
            Self::TooLarge { .. } => "too_large",
        }
    }
}

/// A cell's committed value. Version 0 is the empty value a cell holds from
/// reservation until its first write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellValue {
    pub version: u64,
    pub value: Vec<u8>,
}

/// Who is asking. The unit and epoch are the ones the caller's channel was
/// admitted under; the role is never the caller's to state.
#[derive(Debug, Clone, Copy)]
pub struct CellCaller<'a> {
    pub tenant: &'a TenantId,
    pub unit: &'a WorkloadId,
    pub epoch: ExecutionEpoch,
    pub cell: &'a str,
}

#[derive(Debug, Clone, Copy)]
enum Operation {
    Write,
    Read,
}

impl Operation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Read => "read",
        }
    }
}

/// The host's cell service.
pub struct StateCells<'a> {
    /// Where the host signer lives; `None` for the default keys directory.
    pub host_signer_keys_dir: Option<&'a Path>,
    /// Where refusals are recorded.
    pub audit: &'a dyn RefusalAudit,
}

impl StateCells<'_> {
    /// Commit `value` at `version` for the cell's writer.
    ///
    /// # Errors
    ///
    /// A [`CellRefusal`] for a caller that is not the cell's writer, an epoch
    /// the gate refuses, a version not greater than the stored one, or a value
    /// larger than the cell; otherwise any failure to read the topology, the
    /// gate's record or the cell, including a cell file that does not verify.
    pub fn write(&self, caller: &CellCaller<'_>, version: u64, value: &[u8]) -> Result<()> {
        let home = mvm_core::config::mvm_home_strict().context("resolving the mvm home")?;
        let cell = self.cell(&home, caller, Operation::Write)?;
        let path = cell_path(&home, caller.tenant, &cell.name);
        let _lock = FileLock::acquire(&path)?;
        self.admit(&home, caller, Operation::Write)?;
        let size = cell.size_bytes.get();
        let len = value.len() as u64;
        if len > size {
            return Err(self.refuse(
                caller,
                Operation::Write,
                CellRefusal::TooLarge {
                    cell: cell.name,
                    len,
                    size,
                },
            ));
        }
        let file = slots::CellFile::open(&path, size)?;
        let stored = file.current().version;
        if version <= stored {
            return Err(self.refuse(
                caller,
                Operation::Write,
                CellRefusal::VersionNotIncreasing {
                    cell: cell.name,
                    got: version,
                    stored,
                },
            ));
        }
        file.commit(version, value)
            .with_context(|| format!("committing cell {}", cell.name))
    }

    /// The cell's committed value, for its writer or one of its readers.
    ///
    /// # Errors
    ///
    /// A [`CellRefusal`] for a caller that neither writes nor reads the cell
    /// or an epoch the gate refuses; otherwise any failure to read the
    /// topology, the gate's record or the cell.
    pub fn read(&self, caller: &CellCaller<'_>) -> Result<CellValue> {
        let home = mvm_core::config::mvm_home_strict().context("resolving the mvm home")?;
        let cell = self.cell(&home, caller, Operation::Read)?;
        let path = cell_path(&home, caller.tenant, &cell.name);
        let _lock = FileLock::acquire(&path)?;
        self.admit(&home, caller, Operation::Read)?;
        Ok(slots::CellFile::open(&path, cell.size_bytes.get())?.into_current())
    }

    /// The cell as the admitted topology declares it, if the caller holds the
    /// role the operation needs.
    fn cell(&self, home: &Path, caller: &CellCaller<'_>, op: Operation) -> Result<StateCell> {
        let topology = crate::topology_admission::last_admitted_topology(
            home,
            caller.tenant,
            self.host_signer_keys_dir,
        )?;
        let Some(cell) = topology.and_then(|t| t.cells.into_iter().find(|c| c.name == caller.cell))
        else {
            return Err(self.refuse(
                caller,
                op,
                CellRefusal::UnknownCell {
                    cell: caller.cell.to_string(),
                },
            ));
        };
        let is_writer = cell.writer == *caller.unit;
        let refusal = match op {
            Operation::Write if !is_writer => CellRefusal::NotWriter {
                cell: cell.name.clone(),
                unit: caller.unit.clone(),
            },
            Operation::Read if !is_writer && !cell.readers.contains(caller.unit) => {
                CellRefusal::NotReader {
                    cell: cell.name.clone(),
                    unit: caller.unit.clone(),
                }
            }
            _ => return Ok(cell),
        };
        Err(self.refuse(caller, op, refusal))
    }

    /// Ask the epoch gate, over the record as committed now.
    fn admit(&self, home: &Path, caller: &CellCaller<'_>, op: Operation) -> Result<()> {
        let gate = CommandGate::load_at(home).context("loading the epoch gate's record")?;
        gate.admit(&caller.unit.0, caller.epoch)
            .map(drop)
            .map_err(|denial| {
                self.refuse(
                    caller,
                    op,
                    CellRefusal::Epoch {
                        cell: caller.cell.to_string(),
                        unit: caller.unit.clone(),
                        denial,
                    },
                )
            })
    }

    fn refuse(
        &self,
        caller: &CellCaller<'_>,
        op: Operation,
        refusal: CellRefusal,
    ) -> anyhow::Error {
        if !refusal.is_authority() {
            return refusal.into();
        }
        let audit = self.audit.record_refusal(
            caller.tenant,
            LifecycleEvent::StateCellRefused,
            refusal.kind(),
            LifecycleLabels::from([
                (LifecycleLabel::Operation, op.as_str().to_string()),
                (LifecycleLabel::Cell, caller.cell.to_string()),
                (LifecycleLabel::Unit, caller.unit.0.clone()),
                (LifecycleLabel::Epoch, caller.epoch.get().to_string()),
                (LifecycleLabel::Reason, refusal.to_string()),
            ]),
        );
        match audit {
            Ok(()) => refusal.into(),
            Err(e) => anyhow::Error::new(refusal).context(format!(
                "the refusal could not be written to the audit chain: {e:#}"
            )),
        }
    }
}

fn tenant_dir(home: &Path, tenant: &TenantId) -> PathBuf {
    mvm_core::config::state_cells_dir_at(home).join(&tenant.0)
}

/// Named by the hash of the cell's name, which the topology does not restrict
/// to a path component.
fn cell_path(home: &Path, tenant: &TenantId, name: &str) -> PathBuf {
    tenant_dir(home, tenant).join(format!("{}.cell", hex::encode(Sha256::digest(name))))
}

/// Reserve every cell `topology` declares, at full size, before it is
/// admitted. A cell already reserved at the same size keeps its value, so a
/// later generation that declares it again inherits it; one reserved at
/// another size is refused. The caller has validated the tenant.
///
/// Returns the files this call created, which [`release`] removes if
/// admission fails after it. Anything it created before failing is removed
/// already.
pub(crate) fn reserve(home: &Path, topology: &Topology) -> Result<Vec<PathBuf>> {
    let mut created = Vec::new();
    if topology.cells.is_empty() {
        return Ok(created);
    }
    check_limits(topology)?;
    let dir = tenant_dir(home, &topology.tenant);
    mvm_core::config::create_private_dir(&dir)
        .with_context(|| format!("creating {} privately", dir.display()))?;
    for cell in &topology.cells {
        let path = cell_path(home, &topology.tenant, &cell.name);
        match reserve_one(&path, cell) {
            Ok(true) => created.push(path),
            Ok(false) => {}
            Err(e) => {
                release(&created);
                return Err(e.context(format!("reserving cell {}", cell.name)));
            }
        }
    }
    Ok(created)
}

/// Returns whether the file was created.
fn reserve_one(path: &Path, cell: &StateCell) -> Result<bool> {
    let size = cell.size_bytes.get();
    match write_private_new(path, &slots::reserved(size))
        .with_context(|| format!("writing {}", path.display()))?
    {
        NewFile::Created => Ok(true),
        NewFile::AlreadyPresent => {
            let held = std::fs::metadata(path)
                .with_context(|| format!("reading {}", path.display()))?
                .len();
            ensure!(
                held == slots::file_len(size),
                "it is already reserved at another size ({held} bytes on disk)"
            );
            Ok(false)
        }
    }
}

/// Remove cells a failed admission reserved.
pub(crate) fn release(created: &[PathBuf]) {
    for path in created {
        if let Err(e) = std::fs::remove_file(path) {
            tracing::warn!(path = %path.display(), "removing a reserved cell: {e}");
        }
    }
}

/// Remove the cells of `topology`'s tenant that `topology` no longer
/// declares. Called only once `topology` is admitted and audited: from then
/// on every operation looks its cell up in this generation and refuses one it
/// does not declare, so nothing can still be authorized to use a removed
/// cell. Each removal holds the cell's lock, so it waits out an operation
/// that read the previous generation; one that takes the lock afterwards
/// finds no file and fails. A generation that declares the cell again later
/// starts it empty. Lock files are left in place, since removing one would
/// let two holders lock different inodes.
pub(crate) fn remove_undeclared(home: &Path, topology: &Topology) -> Result<()> {
    let dir = tenant_dir(home, &topology.tenant);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let declared: std::collections::BTreeSet<PathBuf> = topology
        .cells
        .iter()
        .map(|c| cell_path(home, &topology.tenant, &c.name))
        .collect();
    for entry in entries {
        let path = entry
            .with_context(|| format!("reading {}", dir.display()))?
            .path();
        if path.extension().is_none_or(|e| e != "cell") || declared.contains(&path) {
            continue;
        }
        let _lock = FileLock::acquire(&path)?;
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        let marker = digest::marker_path(&path);
        if let Err(e) = std::fs::remove_file(&marker)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            return Err(e).with_context(|| format!("removing {}", marker.display()));
        }
    }
    atomic_io::sync_dir(&dir)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod latency_tests;
