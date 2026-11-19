//! Sealed records of admitted topology generations.
//!
//! One file per generation under `<mvm_home>/topologies/<tenant>/`, named so
//! the generation sorts lexically, written once and never rewritten. A higher
//! generation is a new file; earlier ones stay. Each record carries the
//! signed topology exactly as admitted, so it can be verified again later.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use mvm_contract::assurance::Sha256Digest;
use mvm_contract::plan::topology::SignedTopology;
use mvm_core::atomic_io;
use serde::{Deserialize, Serialize};

const PREFIX: &str = "generation-";
const SUFFIX: &str = ".json";
/// A record is a signed topology plus a few fields; anything larger is not one.
const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;

/// What the host sealed when it admitted a generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedTopologyRecord {
    pub generation: u64,
    pub digest: Sha256Digest,
    pub signer_id: String,
    pub admitted_at: DateTime<Utc>,
    pub signed: SignedTopology,
}

fn file_name(generation: u64) -> String {
    format!("{PREFIX}{generation:020}{SUFFIX}")
}

fn parse_file_name(name: &str) -> Option<u64> {
    let digits = name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?;
    (digits.len() == 20).then(|| digits.parse().ok()).flatten()
}

/// `<mvm_home>/topologies/<tenant>`. The caller has validated `tenant` as a
/// single path component.
pub(super) fn tenant_dir(home: &Path, tenant: &str) -> PathBuf {
    mvm_core::config::topologies_dir_at(home).join(tenant)
}

pub(super) fn record_path(home: &Path, tenant: &str, generation: u64) -> PathBuf {
    tenant_dir(home, tenant).join(file_name(generation))
}

/// Serialize admissions across tenants. Admission is rare, and one lock keeps
/// a refusal from creating anything under the tenant's own directory.
pub(super) fn lock(home: &Path) -> Result<atomic_io::FileLock> {
    let dir = mvm_core::config::topologies_dir_at(home);
    mvm_core::config::create_private_dir(&dir)
        .with_context(|| format!("creating {} privately", dir.display()))?;
    atomic_io::FileLock::acquire(&dir.join("admission"))
}

/// The highest generation on record for `tenant`, if any.
pub(super) fn last_admitted(home: &Path, tenant: &str) -> Result<Option<AdmittedTopologyRecord>> {
    let dir = tenant_dir(home, tenant);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let mut highest = None;
    for entry in entries {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        if let Some(generation) = entry.file_name().to_str().and_then(parse_file_name) {
            highest = highest.max(Some(generation));
        }
    }
    highest.map(|g| read(home, tenant, g)).transpose()
}

fn read(home: &Path, tenant: &str, generation: u64) -> Result<AdmittedTopologyRecord> {
    use std::io::Read as _;
    let path = record_path(home, tenant, generation);
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .with_context(|| format!("opening {}", path.display()))?
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= MAX_RECORD_BYTES,
        "{} is larger than any topology record",
        path.display()
    );
    let record: AdmittedTopologyRecord =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    ensure!(
        record.generation == generation,
        "{} records generation {}",
        path.display(),
        record.generation
    );
    Ok(record)
}

/// Seal `record` as a new file. Refuses to replace an existing one.
pub(super) fn persist(
    home: &Path,
    tenant: &str,
    record: &AdmittedTopologyRecord,
) -> Result<PathBuf> {
    let dir = tenant_dir(home, tenant);
    mvm_core::config::create_private_dir(&dir)
        .with_context(|| format!("creating {} privately", dir.display()))?;
    let path = dir.join(file_name(record.generation));
    let bytes = serde_json::to_vec_pretty(record).context("serializing the topology record")?;
    atomic_io::atomic_write_new(&path, &bytes)
        .with_context(|| format!("sealing {}", path.display()))?;
    atomic_io::sync_dir(&dir)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_topology_record_file_name_round_trips_and_sorts_by_generation() {
        assert_eq!(parse_file_name(&file_name(7)), Some(7));
        assert_eq!(parse_file_name(&file_name(u64::MAX)), Some(u64::MAX));
        assert!(file_name(9) < file_name(10));
        assert_eq!(parse_file_name("admission.lock"), None);
        assert_eq!(parse_file_name("generation-7.json"), None);
    }
}
