//! The only writer of the per-workload containment ledger.
//!
//! The canonical ledger lives beside the generation store, in
//! `policy-generations/workloads/ledger.json`, and changes only through
//! [`WorkloadStore::commit`], which the policy coordinator calls under its
//! owner lock. Every commit writes a durable obligation first and removes it
//! only after the new ledger is durable, so readers refuse in between and a
//! restart can tell which side of the rename a crash fell on.
//!
//! The first commit migrates the pre-coordinator file. Migration exchanges
//! `host-interface/workloads.json` with a directory, so any binary that still
//! writes that path by rename, or reads it as a file, fails from then on. The
//! old file is kept as `workloads.legacy.json` and is never rewritten.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

use anyhow::{Context, Result, bail, ensure};
use mvm_core::host_interface::destination::{is_hex64, parse_key};
use mvm_core::host_interface::workload::{
    CanonicalLedger, DestinationCommit, DestinationEnrollment, DestinationEntry, MAX_DESTINATIONS,
    MAX_LEDGER_BYTES, PENDING_FILE, SignedPreparedHead, WorkloadChange, WorkloadCommit,
    WorkloadLedger, archive_path_at, canonical_dir_at, legacy_path_at, read_ledger_bytes_at,
};
use mvm_core::util::atomic_io::{FileLock, atomic_write_durable, atomic_write_new, sync_dir};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Most workloads the ledger records.
pub(crate) const MAX_WORKLOADS: usize = 16_384;
/// Entries only a quarantine may create, so replacements cannot use up the
/// room containment needs.
pub(crate) const QUARANTINE_RESERVE: usize = 1_024;
const MAX_NAME_BYTES: usize = 256;
/// Room kept for the quarantines the count reserve promises: a worst-case
/// JSON-escaped name plus its entry, for every reserved slot.
pub(crate) const QUARANTINE_RESERVE_BYTES: u64 =
    (QUARANTINE_RESERVE * (6 * MAX_NAME_BYTES + 64)) as u64;
const MAX_OBLIGATION_BYTES: u64 = 4096;
/// Rounds migration re-inspects the legacy path when a writer races it.
const MIGRATE_ROUNDS: usize = 3;
const MOVED_NOTE: &str = "The workload ledger moved to the policy coordinator. \
The previous contents of this path are kept in workloads.legacy.json beside this directory.\n";

/// A ledger commit whose outcome is unknown: readers refuse and further
/// commits are refused until recovery resolves it.
#[derive(Debug)]
pub(crate) struct CommitUnresolved(String);

impl CommitUnresolved {
    #[cfg(test)]
    pub(super) fn new(message: &str) -> Self {
        Self(message.to_owned())
    }
}

impl std::fmt::Display for CommitUnresolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "workload ledger commit outcome is unknown and requires recovery: {}",
            self.0
        )
    }
}

impl std::error::Error for CommitUnresolved {}

/// A destination request the ledger's owner definitely refused: nothing was
/// written, and asking again with the same request is answered the same way
/// until the ledger changes. Any other failure of a destination request leaves
/// its outcome unknown.
#[derive(Debug)]
pub(crate) struct DestinationRefusal {
    not_enrolled: bool,
    message: String,
}

impl DestinationRefusal {
    fn new(message: &str) -> Self {
        Self {
            not_enrolled: false,
            message: message.to_owned(),
        }
    }

    fn not_enrolled() -> Self {
        Self {
            not_enrolled: true,
            message: "destination is not enrolled".into(),
        }
    }

    fn wrap(error: anyhow::Error) -> anyhow::Error {
        anyhow::Error::new(Self::new(&format!("{error:#}")))
    }

    /// A ledger that cannot hold the change is a refusal; other failures are not.
    fn if_too_large(error: anyhow::Error) -> anyhow::Error {
        if error.downcast_ref::<LedgerTooLarge>().is_some() {
            Self::wrap(error)
        } else {
            error
        }
    }

    pub(crate) fn is_not_enrolled(&self) -> bool {
        self.not_enrolled
    }
}

impl std::fmt::Display for DestinationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DestinationRefusal {}

fn refuse_unless(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(anyhow::Error::new(DestinationRefusal::new(message)))
    }
}

#[derive(Debug)]
struct LedgerTooLarge;

impl std::fmt::Display for LedgerTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("workload ledger exceeds its size limit")
    }
}

impl std::error::Error for LedgerTooLarge {}

fn ensure_fits(len: usize, limit: u64) -> Result<()> {
    if len as u64 <= limit {
        Ok(())
    } else {
        Err(anyhow::Error::new(LedgerTooLarge))
    }
}

fn bump_sequence(canonical: &mut CanonicalLedger) -> Result<()> {
    canonical.sequence = canonical
        .sequence
        .checked_add(1)
        .context("workload ledger sequence exhausted")?;
    Ok(())
}

/// A new destination keeps the byte reserve a quarantine needs.
const DESTINATION_LEDGER_LIMIT: u64 = MAX_LEDGER_BYTES - QUARANTINE_RESERVE_BYTES;

/// Drop destinations until the ledger, which already holds `keep`, fits both
/// bounds: first those whose workload has moved to another epoch, since they
/// can never commit again, then the least recently changed. Re-serializing per
/// removal is quadratic, which is acceptable at 4096 entries.
fn make_room(canonical: &mut CanonicalLedger, keep: &str) -> Result<()> {
    let fits = |c: &CanonicalLedger| -> Result<bool> {
        Ok(c.destinations.len() <= MAX_DESTINATIONS
            && serde_json::to_vec(c)?.len() as u64 <= DESTINATION_LEDGER_LIMIT)
    };
    if fits(canonical)? {
        return Ok(());
    }
    let workloads = &canonical.workloads;
    canonical
        .destinations
        .retain(|id, d| id == keep || workloads.entry(&d.workload).epoch == d.epoch);
    while !fits(canonical)? {
        let oldest = canonical
            .destinations
            .iter()
            .filter(|(id, _)| id.as_str() != keep)
            .min_by_key(|(_, d)| d.changed)
            .map(|(id, _)| id.clone());
        let Some(oldest) = oldest else {
            return Err(anyhow::Error::new(DestinationRefusal::new(
                "destination ledger is full",
            )));
        };
        canonical.destinations.remove(&oldest);
    }
    Ok(())
}

/// Is `error` an interrupted commit rather than a refusal?
#[cfg(test)]
pub(crate) fn is_commit_unresolved(error: &anyhow::Error) -> bool {
    error.downcast_ref::<CommitUnresolved>().is_some()
}

fn unresolved(error: anyhow::Error) -> anyhow::Error {
    if error.downcast_ref::<CommitUnresolved>().is_some() {
        error
    } else {
        anyhow::Error::new(CommitUnresolved(format!("{error:#}")))
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Obligation {
    Migrate,
    Commit { sequence: u64, sha256: String },
}

/// A point after which a test makes the operation stop without cleaning up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::policy_generation) enum Step {
    MigrateObligation,
    MigrateArchiveDir,
    MigrateExchanged,
    MigrateCanonical,
    CommitObligation,
    CommitLedger,
}

/// The one writer of a home's ledger for as long as it lives.
pub(crate) struct WorkloadStore {
    home: PathBuf,
    lane: Mutex<()>,
    /// Exclusive for the store's life, on a file inside the ledger directory,
    /// so ownership follows the directory however the home path is spelled.
    _owner: FileLock,
    #[cfg(test)]
    fault: Mutex<Option<Step>>,
}

impl WorkloadStore {
    pub(crate) fn open(home: &Path) -> Result<Self> {
        for dir in [
            home.to_path_buf(),
            mvm_core::config::policy_generations_dir_at(home),
            canonical_dir_at(home),
        ] {
            mvm_core::private_fs::create_owned_private_dir(&dir)
                .with_context(|| format!("securing {}", dir.display()))?;
        }
        let owner = FileLock::try_acquire(&canonical_dir_at(home).join("owner"))?.context(
            "the workload ledger already has an owner; is the policy coordinator running?",
        )?;
        Ok(Self {
            home: home.to_path_buf(),
            lane: Mutex::new(()),
            _owner: owner,
            #[cfg(test)]
            fault: Mutex::new(None),
        })
    }

    #[cfg(test)]
    pub(in crate::policy_generation) fn fail_after(&self, step: Step) {
        *self.fault.lock().unwrap() = Some(step);
    }

    #[cfg(test)]
    fn inject(&self, step: Step) -> Result<()> {
        let hit = self.fault.lock().unwrap().take_if(|armed| *armed == step);
        ensure!(hit.is_none(), "injected fault after {step:?}");
        Ok(())
    }

    #[cfg(not(test))]
    fn inject(&self, _step: Step) -> Result<()> {
        Ok(())
    }

    fn dir(&self) -> PathBuf {
        canonical_dir_at(&self.home)
    }

    fn ledger_path(&self) -> PathBuf {
        self.dir()
            .join(mvm_core::host_interface::workload::LEDGER_FILE)
    }

    fn pending_path(&self) -> PathBuf {
        self.dir().join(PENDING_FILE)
    }

    /// The canonical ledger after recovery and, if needed, migration. The
    /// caller holds the lane.
    fn load_canonical(&self) -> Result<CanonicalLedger> {
        self.recover_locked().map_err(unresolved)?;
        if read_ledger_bytes_at(&self.home)?.is_none() {
            self.migrate()?;
        }
        let bytes = read_ledger_bytes_at(&self.home)?.context("workload ledger vanished")?;
        serde_json::from_slice(&bytes).context("reading the canonical workload ledger")
    }

    /// Write `canonical`, whose sequence the caller has already advanced,
    /// durably, obligation first. A refusal before the obligation changes
    /// nothing; a failure after it is unresolved.
    fn persist(&self, canonical: &CanonicalLedger, limit: u64) -> Result<()> {
        let bytes = serde_json::to_vec(canonical).context("serializing the workload ledger")?;
        ensure_fits(bytes.len(), limit)?;
        let obligation = Obligation::Commit {
            sequence: canonical.sequence,
            sha256: hex::encode(Sha256::digest(&bytes)),
        };
        self.apply(&obligation, &bytes).map_err(unresolved)
    }

    /// Apply one change durably and return what the workload's entry is now.
    pub(crate) fn commit(&self, change: &WorkloadChange) -> Result<WorkloadCommit> {
        let _lane = self.lane.lock().unwrap_or_else(PoisonError::into_inner);
        let mut canonical = self.load_canonical()?;
        let workload = match change {
            WorkloadChange::Quarantine { workload } | WorkloadChange::Replace { workload, .. } => {
                validate_name(workload)?;
                workload.as_str()
            }
        };
        let known = canonical.workloads.knows(workload);
        match change {
            WorkloadChange::Quarantine { .. } => {
                let entry = canonical.workloads.entry(workload);
                if entry.quarantined {
                    return Ok(WorkloadCommit {
                        sequence: canonical.sequence,
                        entry,
                    });
                }
                ensure!(
                    known || canonical.workloads.len() < MAX_WORKLOADS,
                    "workload ledger is full"
                );
                canonical.workloads.quarantine(workload);
            }
            WorkloadChange::Replace { from_epoch, .. } => {
                let current = canonical.workloads.entry(workload).epoch;
                ensure!(
                    current == *from_epoch,
                    "workload epoch changed: expected {}, current {}",
                    from_epoch.0,
                    current.0
                );
                ensure!(
                    known || canonical.workloads.len() < MAX_WORKLOADS - QUARANTINE_RESERVE,
                    "workload ledger has no room for another replacement"
                );
                canonical.workloads.replace(workload);
            }
        }
        bump_sequence(&mut canonical)?;
        let creates_by_replace = !known && matches!(change, WorkloadChange::Replace { .. });
        let limit = if creates_by_replace {
            MAX_LEDGER_BYTES - QUARANTINE_RESERVE_BYTES
        } else {
            MAX_LEDGER_BYTES
        };
        self.persist(&canonical, limit)?;
        Ok(WorkloadCommit {
            sequence: canonical.sequence,
            entry: canonical.workloads.entry(workload),
        })
    }

    /// Record a mailbox destination under a workload epoch. A destination's
    /// key and binding never change, so a repeat is answered without a write,
    /// even after its workload was quarantined: a commit that landed first
    /// must still be anchored.
    pub(crate) fn enroll_destination(
        &self,
        enrollment: &DestinationEnrollment,
    ) -> Result<DestinationCommit> {
        validate_name(&enrollment.workload).map_err(DestinationRefusal::wrap)?;
        refuse_unless(
            is_hex64(&enrollment.destination),
            "destination id is malformed",
        )?;
        parse_key(&enrollment.key).map_err(DestinationRefusal::wrap)?;
        enrollment
            .tip
            .validate()
            .map_err(DestinationRefusal::wrap)?;
        let _lane = self.lane.lock().unwrap_or_else(PoisonError::into_inner);
        let mut canonical = self.load_canonical()?;
        if let Some(existing) = canonical.destinations.get(&enrollment.destination) {
            refuse_unless(
                existing.workload == enrollment.workload
                    && existing.epoch == enrollment.epoch
                    && existing.key == enrollment.key,
                "destination is enrolled under a different binding",
            )?;
            return Ok(DestinationCommit {
                sequence: existing.changed,
                tip: existing.tip.clone(),
            });
        }
        let workload = canonical.workloads.entry(&enrollment.workload);
        refuse_unless(!workload.quarantined, "workload is quarantined")?;
        refuse_unless(
            workload.epoch == enrollment.epoch,
            &format!(
                "workload epoch changed: expected {}, current {}",
                enrollment.epoch.0, workload.epoch.0
            ),
        )?;
        bump_sequence(&mut canonical)?;
        canonical.destinations.insert(
            enrollment.destination.clone(),
            DestinationEntry {
                workload: enrollment.workload.clone(),
                epoch: enrollment.epoch,
                key: enrollment.key.clone(),
                tip: enrollment.tip.clone(),
                changed: canonical.sequence,
            },
        );
        make_room(&mut canonical, &enrollment.destination)?;
        self.persist(&canonical, DESTINATION_LEDGER_LIMIT)
            .map_err(DestinationRefusal::if_too_large)?;
        Ok(DestinationCommit {
            sequence: canonical.sequence,
            tip: enrollment.tip.clone(),
        })
    }

    /// Move a destination's tip one step, ordered against containment.
    pub(crate) fn commit_destination(
        &self,
        prepared: &SignedPreparedHead,
    ) -> Result<DestinationCommit> {
        let head = &prepared.head;
        let _lane = self.lane.lock().unwrap_or_else(PoisonError::into_inner);
        let mut canonical = self.load_canonical()?;
        let Some(entry) = canonical.destinations.get(&head.destination) else {
            return Err(DestinationRefusal::not_enrolled().into());
        };
        refuse_unless(
            head.workload == entry.workload && head.epoch == entry.epoch,
            "prepared head names a different workload or epoch than the enrollment",
        )?;
        parse_key(&entry.key)
            .and_then(|key| prepared.verify(&key))
            .map_err(DestinationRefusal::wrap)?;
        if entry.tip == head.next {
            // A historical acceptance stays accepted after a quarantine or replacement.
            return Ok(DestinationCommit {
                sequence: entry.changed,
                tip: entry.tip.clone(),
            });
        }
        head.next.validate().map_err(DestinationRefusal::wrap)?;
        refuse_unless(
            entry.tip == head.expected
                && head.expected.cursor.checked_add(1) == Some(head.next.cursor),
            "prepared head diverges from the destination's committed tip",
        )?;
        let workload = canonical.workloads.entry(&entry.workload);
        refuse_unless(!workload.quarantined, "workload is quarantined")?;
        refuse_unless(
            workload.epoch == entry.epoch,
            &format!(
                "workload epoch changed: expected {}, current {}",
                entry.epoch.0, workload.epoch.0
            ),
        )?;
        bump_sequence(&mut canonical)?;
        let sequence = canonical.sequence;
        let destination = canonical
            .destinations
            .get_mut(&head.destination)
            .context("destination vanished under the lane")?;
        destination.tip = head.next.clone();
        destination.changed = sequence;
        self.persist(&canonical, MAX_LEDGER_BYTES)
            .map_err(DestinationRefusal::if_too_large)?;
        Ok(DestinationCommit {
            sequence,
            tip: head.next.clone(),
        })
    }

    /// Everything from the obligation to its removal; any failure leaves the
    /// obligation for recovery.
    fn apply(&self, obligation: &Obligation, bytes: &[u8]) -> Result<()> {
        self.write_obligation(obligation)?;
        self.inject(Step::CommitObligation)?;
        atomic_write_durable(&self.ledger_path(), bytes).context("writing the workload ledger")?;
        self.inject(Step::CommitLedger)?;
        self.clear_obligation()
    }

    /// Resolve an interrupted commit or migration from what is on disk.
    pub(crate) fn recover(&self) -> Result<()> {
        let _lane = self.lane.lock().unwrap_or_else(PoisonError::into_inner);
        self.recover_locked().map_err(unresolved)
    }

    fn recover_locked(&self) -> Result<()> {
        match self.read_obligation()? {
            None => Ok(()),
            Some(Obligation::Migrate) => self.migrate(),
            Some(Obligation::Commit { sequence, sha256 }) => {
                sync_dir(&self.dir()).context("syncing the ledger directory before recovery")?;
                let bytes =
                    read_ledger_bytes_at(&self.home)?.context("workload ledger is missing")?;
                if hex::encode(Sha256::digest(&bytes)) != sha256 {
                    let current: CanonicalLedger = serde_json::from_slice(&bytes)
                        .context("reading the canonical workload ledger")?;
                    ensure!(
                        sequence.checked_sub(1) == Some(current.sequence),
                        "workload ledger matches neither side of the interrupted commit"
                    );
                }
                self.clear_obligation()
            }
        }
    }

    fn read_obligation(&self) -> Result<Option<Obligation>> {
        let path = self.pending_path();
        match fs::symlink_metadata(&path) {
            Ok(meta) => ensure!(meta.is_file(), "{} is not a regular file", path.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("checking {}", path.display()));
            }
        }
        let mut bytes = Vec::new();
        fs::File::open(&path)
            .and_then(|file| file.take(MAX_OBLIGATION_BYTES + 1).read_to_end(&mut bytes))
            .with_context(|| format!("reading {}", path.display()))?;
        ensure!(
            bytes.len() as u64 <= MAX_OBLIGATION_BYTES,
            "workload ledger obligation exceeds its size limit"
        );
        serde_json::from_slice(&bytes)
            .map(Some)
            .with_context(|| format!("corrupt workload ledger obligation {}", path.display()))
    }

    fn write_obligation(&self, obligation: &Obligation) -> Result<()> {
        let path = self.pending_path();
        atomic_write_new(&path, &serde_json::to_vec(obligation)?)
            .with_context(|| format!("recording {}", path.display()))?;
        sync_dir(&self.dir()).context("making the workload ledger obligation durable")
    }

    fn clear_obligation(&self) -> Result<()> {
        let path = self.pending_path();
        fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        sync_dir(&self.dir()).context("making the workload ledger resolution durable")
    }

    /// Move the legacy ledger into the canonical store and fence its path.
    /// Idempotent: a crashed run is resumed by running it again.
    fn migrate(&self) -> Result<()> {
        if read_ledger_bytes_at(&self.home)?.is_some() {
            if self.read_obligation()? == Some(Obligation::Migrate) {
                self.clear_obligation()?;
            }
            return Ok(());
        }
        let resumed = self.read_obligation()? == Some(Obligation::Migrate);
        self.fence_legacy(resumed)?;
        self.finish_migration().map_err(unresolved)
    }

    /// Leave the legacy path a directory. Failures before the obligation is
    /// written change nothing; after it they are unresolved.
    fn fence_legacy(&self, resumed: bool) -> Result<()> {
        let legacy = legacy_path_at(&self.home);
        let archive = archive_path_at(&self.home);
        let mut obligated = resumed;
        for _ in 0..MIGRATE_ROUNDS {
            let found = fs::symlink_metadata(&legacy);
            match &found {
                Ok(meta) if meta.is_dir() => {
                    // A fenced path with no migration under way means the
                    // canonical file was lost after migrating; the archive is
                    // older than every commit since, so it must not seed it.
                    ensure!(
                        obligated,
                        "the workload ledger was already migrated but its canonical file is missing; refusing to rebuild it from the archive"
                    );
                    return Ok(());
                }
                Ok(meta) if meta.is_file() => {
                    if !obligated {
                        read_legacy_ledger(&legacy)?;
                        archive_is_ready(&archive)?;
                        self.obligate()?;
                    }
                    return self
                        .exchange_into_archive(&legacy, &archive)
                        .map_err(unresolved);
                }
                Ok(_) => bail!("{} is neither a file nor a directory", legacy.display()),
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    bail!("inspecting {}: {error}", legacy.display())
                }
                Err(_) => {}
            }
            if !obligated {
                ensure!(
                    fs::symlink_metadata(&archive).is_err(),
                    "{} exists but {} does not",
                    archive.display(),
                    legacy.display()
                );
                self.obligate()?;
                obligated = true;
            }
            let created = (|| {
                mvm_core::private_fs::ensure_private_dir(
                    legacy
                        .parent()
                        .context("legacy ledger path has no parent")?,
                )?;
                fs::create_dir(&legacy).map_err(anyhow::Error::from)
            })();
            match created {
                Ok(()) => return Ok(()),
                Err(error) if is_already_exists(&error) => {}
                Err(error) => return Err(unresolved(error)),
            }
        }
        Err(unresolved(anyhow::anyhow!(
            "{} kept changing during migration",
            legacy.display()
        )))
    }

    fn obligate(&self) -> Result<()> {
        self.write_obligation(&Obligation::Migrate)
            .map_err(unresolved)?;
        self.inject(Step::MigrateObligation).map_err(unresolved)
    }

    fn exchange_into_archive(&self, legacy: &Path, archive: &Path) -> Result<()> {
        if !archive_is_ready(archive)? {
            mvm_core::private_fs::create_owned_private_dir(archive)?;
        }
        self.inject(Step::MigrateArchiveDir)?;
        exchange(archive, legacy).context("fencing the legacy workload ledger")?;
        self.inject(Step::MigrateExchanged)
    }

    fn finish_migration(&self) -> Result<()> {
        let legacy = legacy_path_at(&self.home);
        let archive = archive_path_at(&self.home);
        let note = legacy.join("MOVED");
        if fs::symlink_metadata(&note).is_err() {
            atomic_write_new(&note, MOVED_NOTE.as_bytes()).context("writing the fence note")?;
        }
        sync_dir(
            legacy
                .parent()
                .context("legacy ledger path has no parent")?,
        )?;
        let workloads = match fs::symlink_metadata(&archive) {
            Ok(_) => read_legacy_ledger(&archive)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => WorkloadLedger::default(),
            Err(error) => return Err(error).context("inspecting the legacy archive"),
        };
        let bytes = serde_json::to_vec(&CanonicalLedger {
            sequence: 0,
            workloads,
            ..Default::default()
        })?;
        atomic_write_new(&self.ledger_path(), &bytes).context("writing the canonical ledger")?;
        sync_dir(&self.dir())?;
        self.inject(Step::MigrateCanonical)?;
        self.clear_obligation()
    }
}

/// Is there an empty archive directory left by an interrupted run? `false`
/// means none exists yet; anything else at the path is refused.
fn archive_is_ready(archive: &Path) -> Result<bool> {
    match fs::symlink_metadata(archive) {
        Ok(meta) if meta.is_dir() => {
            ensure!(
                fs::read_dir(archive)?.next().is_none(),
                "{} is not empty",
                archive.display()
            );
            Ok(true)
        }
        Ok(_) => bail!("{} already exists", archive.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("inspecting the legacy archive"),
    }
}

fn is_already_exists(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists)
}

fn validate_name(name: &str) -> Result<()> {
    ensure!(!name.is_empty(), "workload name is empty");
    ensure!(
        name.len() <= MAX_NAME_BYTES,
        "workload name exceeds {MAX_NAME_BYTES} bytes"
    );
    Ok(())
}

/// A legacy ledger file, strictly parsed within the same bounds the canonical
/// ledger keeps.
fn read_legacy_ledger(path: &Path) -> Result<WorkloadLedger> {
    let meta =
        fs::symlink_metadata(path).with_context(|| format!("inspecting {}", path.display()))?;
    ensure!(meta.is_file(), "{} is not a regular file", path.display());
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(MAX_LEDGER_BYTES + 1).read_to_end(&mut bytes))
        .with_context(|| format!("reading {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= MAX_LEDGER_BYTES,
        "{} exceeds its size limit",
        path.display()
    );
    let ledger: WorkloadLedger = serde_json::from_slice(&bytes)
        .with_context(|| format!("legacy workload ledger {} is malformed", path.display()))?;
    ensure!(
        ledger.len() <= MAX_WORKLOADS,
        "legacy workload ledger has too many workloads"
    );
    ledger.names().try_for_each(validate_name)?;
    Ok(ledger)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn exchange(a: &Path, b: &Path) -> Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        a,
        rustix::fs::CWD,
        b,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .map_err(|errno| anyhow::Error::from(std::io::Error::from(errno)))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn exchange(_a: &Path, _b: &Path) -> Result<()> {
    bail!("fencing the legacy workload ledger is supported only on Linux and macOS")
}

/// A [`WorkloadStore`] owned by this process: the writer of a home with no
/// coordinator running.
pub struct OwnedWorkloadStore {
    store: WorkloadStore,
}

impl OwnedWorkloadStore {
    /// # Errors
    ///
    /// A coordinator, or another owned store, already owns this home's ledger.
    pub fn open(home: &Path) -> Result<Self> {
        Ok(Self {
            store: WorkloadStore::open(home)?,
        })
    }

    pub(crate) fn home(&self) -> &Path {
        &self.store.home
    }

    /// # Errors
    ///
    /// The change is refused, or its outcome is unknown.
    pub fn commit(&self, change: &WorkloadChange) -> Result<WorkloadCommit> {
        self.store.commit(change)
    }

    /// # Errors
    ///
    /// An interrupted commit cannot be resolved from what is on disk.
    pub fn recover(&self) -> Result<()> {
        self.store.recover()
    }

    /// # Errors
    ///
    /// The enrollment is refused, or its outcome is unknown.
    pub fn enroll_destination(
        &self,
        enrollment: &DestinationEnrollment,
    ) -> Result<DestinationCommit> {
        self.store.enroll_destination(enrollment)
    }

    /// # Errors
    ///
    /// The head is refused, or its outcome is unknown.
    pub fn commit_destination(&self, prepared: &SignedPreparedHead) -> Result<DestinationCommit> {
        self.store.commit_destination(prepared)
    }
}

#[cfg(test)]
mod tests;
