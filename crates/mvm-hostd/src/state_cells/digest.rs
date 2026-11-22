//! The periodic signed digest of a unit's cells.
//!
//! Accepted writes are not audited one by one. Instead the host process that
//! owns a writer unit runs a pass once a [`CELL_DIGEST_PERIOD`]: for each cell
//! the admitted topology names the unit as writer, it reads the committed slot
//! under the cell's lock and, if the cell changed since the last digest of it,
//! writes one `state_cell.digest` entry to the tenant's chain carrying the
//! cell, its version, the version digested before it and a SHA-256 of the
//! value. Never the value itself.
//!
//! What was last digested is kept in a marker file beside the cell,
//! `<cell>.digest`, written under the same lock after the chain entry. A
//! restarted owner reads it and so neither repeats an entry nor skips a change.
//! A crash between the entry and the marker repeats that one entry on the next
//! pass; the order is chosen so that a change is never lost. Because the whole
//! pass for a cell holds its lock, two owners of the same cell (a fenced epoch
//! and its successor) never digest the same change twice.
//!
//! The marker holds the value's hash as well as its version, so a cell removed
//! by one generation and declared again by a later one, which starts again at
//! version 0, is digested when it changes even at a version already seen.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use mvm_contract::plan::topology::StateCell;
use mvm_contract::protocol::lifecycle_audit::MAX_LIFECYCLE_LABEL_BYTES;
use mvm_core::atomic_io::{self, FileLock};
use mvm_core::plan::{TenantId, WorkloadId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{cell_path, slots};
use crate::audit::emitter::AuditEmitter;

/// Chain event for one digested cell.
pub const STATE_CELL_DIGEST_EVENT: &str = "state_cell.digest";

/// How often a writer's cells are digested. A cell changed within one period
/// is recorded at most once, so this bounds both the chain growth per cell
/// (1,440 entries a day) and how stale the chain's view of a cell can be.
/// A minute keeps an audit reader within one minute of every committed value
/// while a cell written many times a second still costs one entry a minute.
pub const CELL_DIGEST_PERIOD: Duration = Duration::from_secs(60);

/// The largest marker file read. One holds a version and a hex digest.
const MAX_MARKER_BYTES: u64 = 256;

/// What was last digested for one cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u64,
    value_sha256: String,
}

impl Marker {
    fn of(version: u64, value: &[u8]) -> Self {
        Self {
            version,
            value_sha256: hex::encode(Sha256::digest(value)),
        }
    }
}

/// One writer unit's digest.
pub struct CellDigest {
    pub tenant: TenantId,
    pub unit: WorkloadId,
    /// Where the host signer lives; `None` for the default keys directory.
    pub host_signer_keys_dir: Option<PathBuf>,
    pub emitter: Arc<AuditEmitter>,
    pub period: Duration,
}

impl CellDigest {
    /// Digest every cell the unit writes that changed since its last digest.
    /// Returns how many entries were written.
    ///
    /// # Errors
    ///
    /// The topology cannot be read, or a cell could not be read, audited or
    /// marked. The other cells are still digested; the first error is
    /// returned and the failed cell is retried by the next pass.
    pub fn pass(&self) -> Result<usize> {
        let home = mvm_core::config::mvm_home_strict().context("resolving the mvm home")?;
        let Some(topology) = crate::topology_admission::last_admitted_topology(
            &home,
            &self.tenant,
            self.host_signer_keys_dir.as_deref(),
        )?
        else {
            return Ok(0);
        };
        let mut written = 0;
        let mut first_error = None;
        for cell in topology.cells.iter().filter(|c| c.writer == self.unit) {
            match self.digest_one(&home, cell) {
                Ok(true) => written += 1,
                Ok(false) => {}
                Err(e) => {
                    first_error.get_or_insert(e.context(format!("digesting cell {}", cell.name)));
                }
            }
        }
        first_error.map_or(Ok(written), Err)
    }

    /// Returns whether an entry was written.
    fn digest_one(&self, home: &Path, cell: &StateCell) -> Result<bool> {
        let path = cell_path(home, &self.tenant, &cell.name);
        let _lock = FileLock::acquire(&path)?;
        // Removed by a generation admitted after this pass read the topology.
        if !path.exists() {
            return Ok(false);
        }
        let current = slots::CellFile::open(&path, cell.size_bytes.get())?.into_current();
        let marker_path = marker_path(&path);
        // A cell never written and never digested holds the empty value at 0.
        let last = read_marker(&marker_path).unwrap_or_else(|| Marker::of(0, &[]));
        let now = Marker::of(current.version, &current.value);
        if now == last {
            return Ok(false);
        }
        let cell_id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .context("a cell file is named by its hash")?;
        let mut labels = vec![
            ("cell_sha256".to_string(), cell_id.to_string()),
            ("unit".to_string(), self.unit.0.clone()),
            ("version".to_string(), now.version.to_string()),
            ("previous_version".to_string(), last.version.to_string()),
            ("value_sha256".to_string(), now.value_sha256.clone()),
        ];
        // The topology does not bound a cell's name; its hash identifies it
        // either way.
        if cell.name.len() <= MAX_LIFECYCLE_LABEL_BYTES {
            labels.push(("cell".to_string(), cell.name.clone()));
        }
        self.emitter
            .emit_topology_decision(&self.tenant, STATE_CELL_DIGEST_EVENT, labels)?;
        let bytes = serde_json::to_vec(&now).context("encoding the digest marker")?;
        atomic_io::atomic_write_durable(&marker_path, &bytes)
            .with_context(|| format!("writing {}", marker_path.display()))?;
        Ok(true)
    }
}

/// The marker at `path`, or `None` when there is none or it does not decode.
/// An unreadable marker makes the next pass write an entry again, which is
/// the safe direction.
fn read_marker(path: &Path) -> Option<Marker> {
    let len = std::fs::metadata(path).ok()?.len();
    if len > MAX_MARKER_BYTES {
        tracing::warn!(path = %path.display(), "ignoring an oversized cell digest marker");
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let marker = serde_json::from_slice(&bytes);
    if marker.is_err() {
        tracing::warn!(path = %path.display(), "ignoring a cell digest marker that does not decode");
    }
    marker.ok()
}

/// The marker of the cell at `cell_path`, removed with the cell.
pub(super) fn marker_path(cell_path: &Path) -> PathBuf {
    cell_path.with_extension("digest")
}
