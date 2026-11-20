//! Per-workload containment: quarantine one workload, then replace it under a
//! fresh execution epoch, without touching the rest of the node.
//!
//! The ledger is owned by the policy coordinator, which is its only writer:
//! the canonical copy lives in the coordinator's store and readers load it
//! through [`WorkloadLedger::load_at`]. Absent means no workload has been
//! contained, so a plain local run is unaffected. A malformed ledger, or one
//! whose commit is unresolved, fails closed. A ledger that was never migrated
//! is still read from its legacy file until the coordinator moves it.

use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use super::{
    ExecutionEpoch,
    error::{Denial, HostInterfaceError},
};

pub use super::destination::{
    DestinationCommit, DestinationEnrollment, DestinationEntry, DestinationTip, MAX_DESTINATIONS,
    PreparedHead, SignedPreparedHead,
};

/// File name of the canonical ledger inside [`canonical_dir_at`].
pub const LEDGER_FILE: &str = "ledger.json";
/// File name of the commit or migration obligation beside the ledger.
pub const PENDING_FILE: &str = "pending.json";
/// Largest canonical or legacy ledger the reader or the writer accepts.
pub const MAX_LEDGER_BYTES: u64 = 4 * 1024 * 1024;

/// A commit in flight resolves in milliseconds, so a reader waits for it up to
/// `PENDING_WAIT_ROUNDS` times `PENDING_WAIT_INTERVAL` rather than failing a launch.
const PENDING_WAIT_ROUNDS: u32 = 100;
const PENDING_WAIT_INTERVAL: Duration = Duration::from_millis(10);

const LEGACY_FILE: &str = "workloads.json";
const ARCHIVE_FILE: &str = "workloads.legacy.json";

/// Directory of the canonical ledger and its obligation.
pub fn canonical_dir_at(home: &Path) -> PathBuf {
    crate::config::policy_generations_dir_at(home).join("workloads")
}

/// The pre-coordinator ledger file; once migrated it is a fenced directory.
pub fn legacy_path_at(home: &Path) -> PathBuf {
    home.join("host-interface").join(LEGACY_FILE)
}

/// Where migration keeps the original legacy file.
pub fn archive_path_at(home: &Path) -> PathBuf {
    home.join("host-interface").join(ARCHIVE_FILE)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadEntry {
    pub epoch: ExecutionEpoch,
    pub quarantined: bool,
}

impl Default for WorkloadEntry {
    fn default() -> Self {
        Self {
            epoch: ExecutionEpoch(1),
            quarantined: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkloadLedger(BTreeMap<String, WorkloadEntry>);

/// The canonical ledger file: the entries and the count of commits behind them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalLedger {
    pub sequence: u64,
    pub workloads: WorkloadLedger,
    /// Mailbox destinations, keyed by their 64-hex destination id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub destinations: BTreeMap<String, DestinationEntry>,
}

/// One ledger change a caller asks the coordinator to commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkloadChange {
    Quarantine {
        workload: String,
    },
    /// Replace only if the workload is still at `from_epoch`.
    Replace {
        workload: String,
        from_epoch: ExecutionEpoch,
    },
}

/// The durable result of a commit: its sequence and the workload's entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadCommit {
    pub sequence: u64,
    pub entry: WorkloadEntry,
}

impl WorkloadLedger {
    /// The ledger as committed on `home`: canonical when it exists, otherwise
    /// the legacy file. Reads create nothing, and refuse while a commit or
    /// migration is unresolved.
    pub fn load_at(home: &Path) -> Result<Self, HostInterfaceError> {
        Self::load_waiting(home, PENDING_WAIT_ROUNDS, PENDING_WAIT_INTERVAL)
    }

    fn load_waiting(
        home: &Path,
        rounds: u32,
        interval: Duration,
    ) -> Result<Self, HostInterfaceError> {
        let mut waited = 0;
        loop {
            match Self::load_once(home) {
                Err(_) if waited < rounds && has_unresolved_commit_at(home).unwrap_or(false) => {
                    waited += 1;
                    std::thread::sleep(interval);
                }
                result => return result,
            }
        }
    }

    fn load_once(home: &Path) -> Result<Self, HostInterfaceError> {
        refuse_if_pending(home)?;
        let ledger = read_canonical(home)?;
        // The obligation is written before the ledger rename and removed only
        // after it is durable, so one appearing mid-read must not be trusted.
        refuse_if_pending(home)?;
        if let Some(canonical) = ledger {
            return Ok(canonical.workloads);
        }
        let path = legacy_path_at(home);
        match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| unreadable(&path, &e.to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(unreadable(&path, &e.to_string())),
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }

    /// Has containment ever recorded `workload`?
    pub fn knows(&self, workload: &str) -> bool {
        self.0.contains_key(workload)
    }

    pub fn entry(&self, workload: &str) -> WorkloadEntry {
        self.0.get(workload).copied().unwrap_or_default()
    }

    /// Contain one workload: it may not launch again until it is replaced.
    pub fn quarantine(&mut self, workload: &str) {
        self.0.entry(workload.to_owned()).or_default().quarantined = true;
    }

    /// Authorize a fresh start under a new epoch; the old epoch is dead.
    pub fn replace(&mut self, workload: &str) -> ExecutionEpoch {
        let e = self.0.entry(workload.to_owned()).or_default();
        e.epoch = e.epoch.next();
        e.quarantined = false;
        e.epoch
    }

    /// Local launch gate: refuses a quarantined workload. It cannot check
    /// staleness because a local start carries no epoch of its own; that is
    /// enforced by [`Self::authorize`] where a command or replacement presents
    /// one (the managed and reconnect paths).
    pub fn authorize_local_start(&self, workload: &str) -> Result<(), Denial> {
        self.authorize(workload, self.entry(workload).epoch)
    }

    /// May `workload` start presenting `epoch`? Quarantine and staleness both
    /// refuse; only the current epoch of a contained-free workload passes.
    pub fn authorize(&self, workload: &str, epoch: ExecutionEpoch) -> Result<(), Denial> {
        let e = self.entry(workload);
        if epoch != e.epoch {
            return Err(Denial::StaleEpoch {
                got: epoch.0,
                current: e.epoch.0,
            });
        }
        if e.quarantined {
            return Err(Denial::WorkloadQuarantined(workload.to_owned()));
        }
        Ok(())
    }
}

/// Is a ledger commit or migration obligation present on `home`?
pub fn has_unresolved_commit_at(home: &Path) -> Result<bool, HostInterfaceError> {
    let path = canonical_dir_at(home).join(PENDING_FILE);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(unreadable(&path, &e.to_string())),
    }
}

fn refuse_if_pending(home: &Path) -> Result<(), HostInterfaceError> {
    if has_unresolved_commit_at(home)? {
        return Err(unreadable(
            &canonical_dir_at(home).join(PENDING_FILE),
            "a workload ledger commit is unresolved and needs recovery",
        ));
    }
    Ok(())
}

/// The canonical ledger's exact bytes, bounded; `None` when it does not exist.
/// Anything but a regular file, or an oversize one, is an error.
pub fn read_ledger_bytes_at(home: &Path) -> Result<Option<Vec<u8>>, HostInterfaceError> {
    let path = canonical_dir_at(home).join(LEDGER_FILE);
    let fail = |why: &str| unreadable(&path, why);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(fail(&e.to_string())),
    };
    if !meta.is_file() {
        return Err(fail("not a regular file"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .and_then(|f| f.take(MAX_LEDGER_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|e| fail(&e.to_string()))?;
    if bytes.len() as u64 > MAX_LEDGER_BYTES {
        return Err(fail("exceeds its size limit"));
    }
    Ok(Some(bytes))
}

fn read_canonical(home: &Path) -> Result<Option<CanonicalLedger>, HostInterfaceError> {
    let Some(bytes) = read_ledger_bytes_at(home)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| unreadable(&canonical_dir_at(home).join(LEDGER_FILE), &e.to_string()))
}

fn unreadable(path: &Path, why: &str) -> HostInterfaceError {
    HostInterfaceError::Denied(Denial::StateUnreadable(format!(
        "{}: {why}",
        path.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contain_replace_cycle_only_affects_the_suspect_workload() {
        let mut l = WorkloadLedger::default();
        let start = l.entry("a").epoch;
        assert!(l.authorize("a", start).is_ok() && l.authorize("b", start).is_ok());

        l.quarantine("a");
        assert_eq!(
            l.authorize("a", start),
            Err(Denial::WorkloadQuarantined("a".into()))
        );
        assert!(l.authorize("b", start).is_ok(), "bystander unaffected");

        let fresh = l.replace("a");
        assert!(fresh > start);
        assert!(l.authorize("a", fresh).is_ok());
        assert_eq!(
            l.authorize("a", start),
            Err(Denial::StaleEpoch {
                got: start.0,
                current: fresh.0
            }),
            "the old epoch stays dead after replacement"
        );
    }

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn canonical_bytes(sequence: u64, quarantined: &[&str]) -> Vec<u8> {
        let mut workloads = WorkloadLedger::default();
        for w in quarantined {
            workloads.quarantine(w);
        }
        serde_json::to_vec(&CanonicalLedger {
            sequence,
            workloads,
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn an_absent_ledger_reads_empty_and_the_reader_creates_nothing() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(
            WorkloadLedger::load_at(d.path()).unwrap(),
            WorkloadLedger::default()
        );
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_legacy_only_ledger_still_reads_and_a_malformed_one_fails_closed() {
        let d = tempfile::tempdir().unwrap();
        let legacy = legacy_path_at(d.path());
        write(&legacy, br#"{"a":{"epoch":3,"quarantined":true}}"#);
        let l = WorkloadLedger::load_at(d.path()).unwrap();
        assert!(l.entry("a").quarantined && l.entry("a").epoch == ExecutionEpoch(3));
        write(&legacy, b"[");
        assert!(WorkloadLedger::load_at(d.path()).is_err());
    }

    #[test]
    fn the_canonical_ledger_wins_over_a_stale_legacy_file() {
        let d = tempfile::tempdir().unwrap();
        write(
            &legacy_path_at(d.path()),
            br#"{"a":{"epoch":1,"quarantined":false}}"#,
        );
        write(
            &canonical_dir_at(d.path()).join(LEDGER_FILE),
            &canonical_bytes(4, &["b"]),
        );
        let l = WorkloadLedger::load_at(d.path()).unwrap();
        assert!(l.entry("b").quarantined && !l.knows("a"));
    }

    #[test]
    fn a_pending_obligation_refuses_even_beside_a_valid_ledger() {
        let d = tempfile::tempdir().unwrap();
        let dir = canonical_dir_at(d.path());
        write(&dir.join(LEDGER_FILE), &canonical_bytes(1, &[]));
        write(&dir.join(PENDING_FILE), b"{}");
        assert!(WorkloadLedger::load_at(d.path()).is_err());
    }

    #[test]
    fn a_directory_at_the_legacy_path_fails_closed_without_a_canonical_ledger() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(legacy_path_at(d.path())).unwrap();
        assert!(WorkloadLedger::load_at(d.path()).is_err());
    }

    #[test]
    fn a_malformed_or_oversize_canonical_ledger_fails_closed() {
        let d = tempfile::tempdir().unwrap();
        let path = canonical_dir_at(d.path()).join(LEDGER_FILE);
        write(&path, b"{");
        assert!(WorkloadLedger::load_at(d.path()).is_err());
        write(&path, br#"{"sequence":1,"workloads":{},"extra":1}"#);
        assert!(WorkloadLedger::load_at(d.path()).is_err());
        write(&path, &vec![b' '; MAX_LEDGER_BYTES as usize + 1]);
        assert!(WorkloadLedger::load_at(d.path()).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(WorkloadLedger::load_at(d.path()).is_err());
    }

    #[test]
    fn the_wire_types_round_trip() {
        let change = WorkloadChange::Replace {
            workload: "a".into(),
            from_epoch: ExecutionEpoch(2),
        };
        let bytes = serde_json::to_vec(&change).unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains(r#""kind":"replace""#));
        assert_eq!(
            serde_json::from_slice::<WorkloadChange>(&bytes).unwrap(),
            change
        );
        let q = WorkloadChange::Quarantine {
            workload: "a".into(),
        };
        assert_eq!(
            serde_json::from_slice::<WorkloadChange>(&serde_json::to_vec(&q).unwrap()).unwrap(),
            q
        );
        let commit = WorkloadCommit {
            sequence: 7,
            entry: WorkloadEntry::default(),
        };
        assert_eq!(
            serde_json::from_slice::<WorkloadCommit>(&serde_json::to_vec(&commit).unwrap())
                .unwrap(),
            commit
        );
        let ledger = CanonicalLedger {
            sequence: 3,
            workloads: WorkloadLedger::default(),
            ..Default::default()
        };
        assert_eq!(
            serde_json::from_slice::<CanonicalLedger>(&serde_json::to_vec(&ledger).unwrap())
                .unwrap(),
            ledger
        );
        assert!(
            serde_json::from_str::<WorkloadChange>(r#"{"kind":"quarantine","workload":"a","x":1}"#)
                .is_err()
        );
    }

    #[test]
    fn a_commit_in_flight_is_waited_out_and_a_stranded_one_still_refuses() {
        let d = tempfile::tempdir().unwrap();
        let dir = canonical_dir_at(d.path());
        write(&dir.join(LEDGER_FILE), &canonical_bytes(1, &["a"]));
        let pending = dir.join(PENDING_FILE);
        write(&pending, b"{}");
        assert!(has_unresolved_commit_at(d.path()).unwrap());
        let remover = {
            let pending = pending.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                std::fs::remove_file(pending).unwrap();
            })
        };
        assert!(
            WorkloadLedger::load_at(d.path())
                .unwrap()
                .entry("a")
                .quarantined
        );
        remover.join().unwrap();
        assert!(!has_unresolved_commit_at(d.path()).unwrap());

        write(&pending, b"{}");
        assert!(WorkloadLedger::load_waiting(d.path(), 3, Duration::from_millis(1)).is_err());
    }
}
