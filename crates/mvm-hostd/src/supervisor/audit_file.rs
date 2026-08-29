//! Chain-signed file-backed [`AuditSigner`].
//!
//! Each emitted [`PlanAuditEntry`] is wrapped in a [`SignedEnvelope`] that carries
//! the exact bytes the signature covers, the SHA-256 hash of the previous
//! envelope on disk, and an Ed25519 signature over
//! `signed_bytes || prev_hash`. Tampering with any entry — re-ordering,
//! modifying, deleting, or swapping between tenants — breaks the chain, the
//! signature, or the agreement between an entry and the bytes beside it, all
//! of which are checked by [`verify_audit_chain`].
//!
//! Per-tenant streams live at `<audit_dir>/<tenant>.jsonl`. The chain
//! seed (`prev_hash` for the first entry) is `[0u8; 32]`. The signer
//! restores its in-memory cursor from the last line on disk so that
//! a process restart resumes the chain without gaps.
//!
//! # Two verifiers, on purpose
//!
//! [`verify_audit_chain`] walks from the genesis seed every time. That zero
//! prefix is an anchor, not a formality: it is what makes a *removed* prefix
//! detectable, because a truncated file's new first line claims a non-zero
//! predecessor and fails at line 0.
//!
//! [`verify_audit_chain_incremental`] can resume from a [`ChainCheckpoint`],
//! verifying only what was appended since. It is sound in the sense that
//! matters — the resumed line's signature covers its `prev_hash`, so the state
//! the prefix ended in is authenticated and cannot be forged without the host
//! key. What it gives up is the anchor: whoever can write the checkpoint can
//! drop history and have the remainder verify clean, since every surviving
//! line really is signed. Cost is O(entries since the checkpoint) instead of
//! O(all history), on a log that never shrinks.
//!
//! So the fast path is confined to the routine `mvmctl doctor` health check,
//! which reports that it resumed. `mvmctl trust audit verify` — the on-demand
//! integrity check — always walks from genesis.

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::supervisor::audit::{AuditError, AuditSigner, PlanAuditEntry, SignedEnvelope};
use mvm_contract::verify::{hash_line, seal, signed_bytes_for};

/// Chain-signed file signer. Holds an Ed25519 private key, a base
/// directory, and an in-memory `tenant -> last_envelope_hash` cursor
/// that is lazily restored from disk on first emit per tenant.
pub struct FileAuditSigner {
    signing_key: SigningKey,
    audit_dir: PathBuf,
    fixed_file: Option<PathBuf>,
    rotation: RotationPolicy,
    cursors: Mutex<HashMap<String, [u8; 32]>>,
    /// Files carrying entries that have been written but not yet fsynced.
    ///
    /// Emptied whenever a barrier entry syncs the file it is on, since
    /// `sync_data` is file-wide and carries every earlier write with it. What
    /// remains at drop is flushed there.
    pending_sync: Arc<Mutex<HashSet<PathBuf>>>,
    /// While set, a barrier entry is written but its fsync is held for the
    /// batch's single flush. See [`FileAuditSigner::begin_batch`].
    batching: Arc<AtomicBool>,
}

/// When the active segment is sealed and a fresh one opened.
///
/// A type rather than a bare `Option<u64>` so the disabled case has to be
/// spelled out at the call site. A signer constructed with rotation silently
/// off is how a log goes back to growing forever without anyone noticing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationPolicy {
    max_bytes: Option<u64>,
}

impl RotationPolicy {
    /// Rotate once the active segment reaches `bytes`.
    #[must_use]
    pub fn at_bytes(bytes: u64) -> Self {
        Self {
            max_bytes: Some(bytes),
        }
    }

    /// Never rotate. The chain stays one file and grows without bound.
    #[must_use]
    pub fn never() -> Self {
        Self { max_bytes: None }
    }

    /// The configured threshold, honouring `MVM_AUDIT_SEGMENT_BYTES`.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            max_bytes: mvm_core::config::audit_segment_max_bytes(),
        }
    }

    /// Whether a segment of `len` bytes has reached the threshold.
    #[must_use]
    pub fn should_rotate(&self, len: u64) -> bool {
        self.max_bytes.is_some_and(|max| len >= max)
    }
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self::from_env()
    }
}

/// Whether an entry must be on disk before this call returns.
///
/// Distinct from [`crate::audit::durability::AuditDurability`], which decides
/// whether a *failure* to record an admission blocks the boot. This decides
/// when the fsync happens for a write that succeeded. They meet at
/// `plan.admitted`: `AuditDurability::Required` means a sealed run may not
/// proceed unless its admission reached the chain, which is only true if that
/// entry is a [`SyncPolicy::Barrier`] here. It is, and the test below pins it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPolicy {
    /// fsync before returning. The caller is about to do something that must
    /// not happen without this record already durable.
    Barrier,
    /// Write now, fsync at the next barrier on the same file (or at drop).
    Deferred,
}

/// Events that authorize nothing and may ride to disk on a later fsync.
///
/// The list is of *deferrable* events rather than of barriers, so the default
/// for anything unrecognised — including every event added after this — is to
/// sync. A new event that should have been durable and silently was not is the
/// failure this ordering prevents.
const DEFERRABLE_EVENTS: &[&str] = &[
    // Resolution and posture records: descriptions of a decision already made
    // and already covered by the admission that authorized the boot.
    "plan.policy_resolved",
    "plan.boot_posture",
    "plan.shares_admitted",
    // Provenance for an admission that has already been synced.
    "plan.oci_provenance",
    // States that the admitted plan did start. Nothing is authorized by it;
    // the authorization was `plan.admitted`, which is a barrier.
    "plan.launched",
];

/// How durably `event` must land.
///
/// The rule is what an entry authorizes, not how interesting it is. An entry
/// that permits a subsequent action has to be on disk before that action can
/// take effect, or a crash can leave the action having happened with no record
/// that it was allowed to. Everything else is a record of something that has
/// already happened, and a crash losing the tail of the log is a truncation —
/// detectable, and not the same as a forged or missing authorization.
///
/// Command bookends split: `cmd.<verb>.invoked` announces an intention and
/// authorizes nothing, while the terminal `completed`/`failed` is both a real
/// outcome and the natural flush point for everything the command deferred.
#[must_use]
pub fn sync_policy_for(event: &str) -> SyncPolicy {
    if DEFERRABLE_EVENTS.contains(&event) || event.ends_with(".invoked") {
        SyncPolicy::Deferred
    } else {
        SyncPolicy::Barrier
    }
}

/// How much of a chain file's tail one cursor restore reads before widening.
///
/// Comfortably larger than a signed audit record, so the common case is a
/// single read; a record longer than this only costs extra reads, never a
/// wrong answer.
const CURSOR_TAIL_WINDOW: u64 = 64 * 1024;

/// What a backwards scan found at the end of a chain file.
enum TailScan<'a> {
    /// The last non-empty line.
    Line(&'a [u8]),
    /// Nothing but terminators — the file holds no record.
    Empty,
    /// The file does not end at a record boundary.
    Truncated,
    /// The window did not reach the start of the last line.
    NeedMore,
}

/// Read the last `window` bytes of `file`, which is `len` bytes long.
fn read_tail(file: &mut std::fs::File, len: u64, window: u64) -> Result<Vec<u8>, AuditError> {
    use std::io::{Read, Seek, SeekFrom};
    let window = window.min(len);
    file.seek(SeekFrom::Start(len - window))
        .map_err(|e| AuditError::Io(e.to_string()))?;
    let mut buf = vec![0u8; usize::try_from(window).unwrap_or(usize::MAX)];
    file.read_exact(&mut buf)
        .map_err(|e| AuditError::Io(e.to_string()))?;
    Ok(buf)
}

/// Find the last non-empty line in `tail`, the trailing bytes of a chain file.
///
/// Byte-oriented on purpose: `\n` is ASCII and cannot occur inside a UTF-8
/// multi-byte sequence, so a window that starts mid-character still yields a
/// whole, correctly-delimited final line — and the hash is over bytes anyway.
fn last_line(tail: &[u8], at_file_start: bool) -> TailScan<'_> {
    // A file whose last byte is not a terminator ended mid-record: some
    // previous append died between writing the record and its newline.
    // Chaining onto a fragment would make a crash indistinguishable from
    // tampering to every downstream verifier, so it is reported instead.
    let Some(body) = tail.strip_suffix(b"\n") else {
        return TailScan::Truncated;
    };
    // Skip any trailing blank lines the way `str::lines().rfind()` did.
    let body = {
        let mut end = body.len();
        while end > 0 && body[end - 1] == b'\n' {
            end -= 1;
        }
        &body[..end]
    };
    match body.iter().rposition(|b| *b == b'\n') {
        Some(start) => TailScan::Line(&body[start + 1..]),
        None if body.is_empty() => TailScan::Empty,
        // No terminator before the final record. If the window reaches the
        // start of the file this *is* the only record — the state every chain
        // is in after its first append — and not a short read.
        None if at_file_start => TailScan::Line(body),
        None => TailScan::NeedMore,
    }
}

impl FileAuditSigner {
    /// Create the signer rooted at `audit_dir`. The directory is
    /// created if missing (mode 0700-equivalent — `OpenOptions` later
    /// applies platform defaults, callers wanting tighter perms should
    /// pre-create the dir).
    pub fn open(signing_key: SigningKey, audit_dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let audit_dir = audit_dir.into();
        std::fs::create_dir_all(&audit_dir)?;
        Ok(Self {
            signing_key,
            audit_dir,
            fixed_file: None,
            rotation: RotationPolicy::from_env(),
            cursors: Mutex::new(HashMap::new()),
            pending_sync: Arc::new(Mutex::new(HashSet::new())),
            batching: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Replace the rotation policy. Consuming rather than mutating, so a signer
    /// cannot have its rotation behaviour changed out from under a writer that
    /// is already appending to it.
    #[must_use]
    pub fn with_rotation(mut self, rotation: RotationPolicy) -> Self {
        self.rotation = rotation;
        self
    }

    /// Create a signer rooted at one exact JSONL file instead of a
    /// per-tenant directory. This is used for policy
    /// `file:///.../audit.jsonl` stream destinations where the
    /// operator supplied a literal stream path.
    pub fn open_file(
        signing_key: SigningKey,
        audit_file: impl Into<PathBuf>,
    ) -> std::io::Result<Self> {
        let audit_file = audit_file.into();
        if let Some(parent) = audit_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Self {
            signing_key,
            audit_dir: audit_file
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from(".")),
            fixed_file: Some(audit_file),
            rotation: RotationPolicy::from_env(),
            cursors: Mutex::new(HashMap::new()),
            pending_sync: Arc::new(Mutex::new(HashSet::new())),
            batching: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Public verifying key matching the embedded signing key. Use
    /// when handing the verifier to operators / test code.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn tenant_path(&self, tenant: &str) -> PathBuf {
        self.fixed_file
            .clone()
            .unwrap_or_else(|| self.audit_dir.join(format!("{tenant}.jsonl")))
    }

    /// Re-seed the in-memory cursor from disk on first emit per tenant.
    /// Hashes the last on-disk line; returns `[0; 32]` (genesis) if no
    /// file exists or the file is empty.
    ///
    /// A file whose last byte is not `\n` ended mid-record: some previous
    /// append died between writing the record and writing its terminator.
    /// `str::lines` would hand back that partial record as though it were
    /// whole, and we would chain onto the hash of a fragment. Report it as
    /// [`AuditError::TruncatedTail`] instead — a crash has to be
    /// distinguishable from tampering, and silently chaining onto a fragment
    /// makes the two identical to every downstream verifier.
    fn restore_cursor(&self, path: &Path) -> Result<[u8; 32], AuditError> {
        if !path.exists() {
            return Ok([0u8; 32]);
        }
        let mut file = std::fs::File::open(path).map_err(|e| AuditError::Io(e.to_string()))?;
        let len = file
            .metadata()
            .map_err(|e| AuditError::Io(e.to_string()))?
            .len();
        if len == 0 {
            return Ok([0u8; 32]);
        }

        // Read backwards from the end rather than reading the file.
        //
        // Only the final line is needed, but this runs on every append, and the
        // active segment grows to `AUDIT_SEGMENT_DEFAULT_BYTES` before it
        // rotates. Reading it whole made each append cost the size of the
        // chain so far — so admission got steadily slower as the segment
        // filled and abruptly cheap again at every rotation.
        let mut window = CURSOR_TAIL_WINDOW.min(len);
        loop {
            let tail = read_tail(&mut file, len, window)?;
            match last_line(&tail, window >= len) {
                TailScan::Line(line) => return Ok(hash_line(line)),
                TailScan::Empty => return Ok([0u8; 32]),
                TailScan::Truncated => {
                    return Err(AuditError::TruncatedTail {
                        path: path.display().to_string(),
                    });
                }
                // The window landed inside the final record. Widen and retry;
                // a window covering the file reports `Line`, not `NeedMore`,
                // so this cannot spin.
                TailScan::NeedMore => window = (window * 4).min(len),
            }
        }
    }
}

impl FileAuditSigner {
    /// fsync every file still carrying deferred entries.
    ///
    /// A deferred entry is already written; this is what makes it survive the
    /// machine losing power rather than only the process exiting. Called from
    /// `Drop`, and available to a caller that wants an explicit flush point.
    ///
    /// Best-effort by signature: a failure here cannot be reported to whoever
    /// emitted the entry, because they were told it succeeded when it was
    /// written. It is logged instead of swallowed.
    /// Hold barrier fsyncs until the caller takes and syncs the batch paths.
    pub(crate) fn begin_batch(&self) {
        self.batching.store(true, Ordering::SeqCst);
    }

    /// Stop holding barriers and sync everything the batch deferred.
    ///
    /// Unlike [`flush_deferred`](Self::flush_deferred) this reports failure,
    /// and it has to: the entries it is syncing include barriers whose emitters
    /// have not yet been told they succeeded. A caller that ignored this would
    /// be strictly worse off than syncing each entry separately.
    #[cfg(test)]
    pub(crate) fn end_batch(&self) -> Result<(), AuditError> {
        let pending = self.take_batched_paths();
        for path in pending {
            OpenOptions::new()
                .append(true)
                .open(&path)
                .and_then(|f| f.sync_data())
                .map_err(|e| AuditError::Io(format!("{}: {e}", path.display())))?;
        }
        Ok(())
    }

    /// Stop holding barriers and hand the files that need syncing to a
    /// coordinator.
    ///
    /// The caller owns the durability wait. This lets one admission wait for
    /// several independent files in parallel while still completing every
    /// wait before the admitted action begins.
    pub(crate) fn take_batched_paths(&self) -> Vec<PathBuf> {
        self.batching.store(false, Ordering::SeqCst);
        let mut guard = self.pending_sync.lock().expect("pending_sync poisoned");
        guard.drain().collect()
    }

    pub fn flush_deferred(&self) {
        let pending: Vec<PathBuf> = {
            let mut guard = self.pending_sync.lock().expect("pending_sync poisoned");
            guard.drain().collect()
        };
        for path in pending {
            let synced = OpenOptions::new()
                .append(true)
                .open(&path)
                .and_then(|f| f.sync_data());
            if let Err(e) = synced {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "flushing deferred audit entries failed; the tail of this chain may not survive power loss"
                );
            }
        }
    }
}

impl Drop for FileAuditSigner {
    fn drop(&mut self) {
        self.flush_deferred();
    }
}

impl FileAuditSigner {
    /// The lock guarding one chain's read-cursor / rotate / sign / append
    /// section.
    ///
    /// Deliberately a file *beside* the chain rather than the chain itself.
    /// The lock used to be taken on the data file, which was correct while
    /// that file was immortal — but rotation renames it, and a `flock` follows
    /// the inode. A second process opening `<tenant>.jsonl` immediately after
    /// the rename would create a brand-new inode, take an uncontended lock on
    /// it, and append concurrently with the rotation still in progress. The
    /// lock file is never renamed, so it stays the one thing both writers
    /// agree to contend on.
    ///
    /// Not `.jsonl`-suffixed, so it never enters lifecycle-chain sweep scope.
    fn lock_path(active: &Path) -> PathBuf {
        let mut name = active.as_os_str().to_os_string();
        name.push(".lock");
        PathBuf::from(name)
    }

    fn acquire_lock(active: &Path) -> Result<std::fs::File, AuditError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(Self::lock_path(active))
            .map_err(|e| AuditError::Io(e.to_string()))?;
        flock_exclusive(&file).map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(file)
    }

    /// The name this chain's segments are filed under: `local` for
    /// `local.jsonl`. Derived from the file rather than from the tenant so the
    /// `file:///…` fixed-file destination rotates under its own stem instead
    /// of scattering segments named after whichever tenant emitted first.
    fn segment_base(active: &Path) -> String {
        active
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("audit")
            .to_string()
    }

    /// Append one signed entry to `path`, assuming the chain lock is held.
    /// Returns the new chain tip.
    fn append_locked(&self, path: &Path, entry: &PlanAuditEntry) -> Result<[u8; 32], AuditError> {
        // Refresh the cursor under the lock — another process may have appended
        // between our last in-memory snapshot and this call. The in-memory
        // cursor cache stays a fast-path hint; restoration here is the source
        // of truth.
        let prev_hash = self.restore_cursor(path)?;
        self.write_signed(path, entry, prev_hash, sync_policy_for(&entry.event))
    }

    /// Sign `entry` against `prev_hash` and append it to `path`.
    fn write_signed(
        &self,
        path: &Path,
        entry: &PlanAuditEntry,
        prev_hash: [u8; 32],
        sync: SyncPolicy,
    ) -> Result<[u8; 32], AuditError> {
        let envelope = seal(entry.clone(), prev_hash, &self.signing_key)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        let line = serde_json::to_string(&envelope).map_err(|e| AuditError::Io(e.to_string()))?;
        let new_hash = hash_line(line.as_bytes());

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| AuditError::Io(e.to_string()))?;

        // One `write_all` of record-plus-terminator, then fsync.
        //
        // `writeln!` goes through `write_fmt`, which issues a syscall per
        // format fragment — the record, then the newline. A crash between the
        // two leaves a record with no terminator, and the next append
        // concatenates onto it: one corrupt line where there should be two
        // valid ones, reported by the verifier as a chain break. The audit log
        // is the evidence that a tamper would have to defeat, so a crash must
        // not be able to produce a tamper's signature.
        //
        // The fsync is what makes "the emitter returned Ok" mean the record
        // survives the machine losing power, which is the property every
        // admission decision downstream is assuming.
        let mut record = line.into_bytes();
        record.push(b'\n');
        file.write_all(&record)
            .map_err(|e| AuditError::Io(e.to_string()))?;

        // Sync only where the record has to precede an action. One launch
        // emits seven entries, and fsync is tens of milliseconds on a real
        // disk, so syncing each one charged the launch for durability it did
        // not need at that instant. `sync_data` is file-wide, so a barrier
        // carries every deferred write on the same file with it.
        // Inside a batch, a barrier is downgraded to deferred: the record is
        // written now and the fsync is the batch's single flush. This does not
        // relax the rule barriers exist for — an entry must be durable before
        // the action it authorizes takes effect — because the batch is closed,
        // and its flush checked, before that action. It relaxes only *how many
        // times* the same file is synced to get there.
        let sync = match sync {
            SyncPolicy::Barrier if self.batching.load(Ordering::SeqCst) => SyncPolicy::Deferred,
            other => other,
        };
        match sync {
            SyncPolicy::Barrier => {
                file.sync_data()
                    .map_err(|e| AuditError::Io(e.to_string()))?;
                self.pending_sync
                    .lock()
                    .expect("pending_sync poisoned")
                    .remove(path);
            }
            SyncPolicy::Deferred => {
                self.pending_sync
                    .lock()
                    .expect("pending_sync poisoned")
                    .insert(path.to_path_buf());
            }
        }
        Ok(new_hash)
    }

    /// A handoff record, which belongs to the chain's structure rather than to
    /// any plan. Uses the same unbound sentinels every other non-plan-bound
    /// event uses, so `plan_id == UNBOUND_PLAN_ID` keeps meaning exactly one
    /// thing across the whole stream.
    fn handoff_entry(
        &self,
        tenant: &mvm_core::plan::TenantId,
        event: &str,
        labels: std::collections::BTreeMap<String, String>,
    ) -> PlanAuditEntry {
        PlanAuditEntry {
            timestamp: chrono::Utc::now(),
            tenant: tenant.clone(),
            plan_id: mvm_core::plan::PlanId(
                crate::supervisor::audit_recorder::UNBOUND_PLAN_ID.to_string(),
            ),
            plan_version: 0,
            bundle_id: None,
            bundle_version: None,
            image_name: crate::supervisor::audit_recorder::UNBOUND_IMAGE_NAME.to_string(),
            image_sha256: crate::supervisor::audit_recorder::UNBOUND_IMAGE_SHA256.to_string(),
            event: event.to_string(),
            labels,
        }
    }

    /// The sequence number of the segment currently in `active`.
    ///
    /// A file whose first line is a continuation says so itself; anything else
    /// is the genesis segment. Read back off disk rather than cached so a
    /// second writer's rotation is visible to this one.
    fn active_segment_seq(active: &Path) -> Result<u64, AuditError> {
        let content = std::fs::read_to_string(active).map_err(|e| AuditError::Io(e.to_string()))?;
        let Some(first) = content.lines().find(|l| !l.is_empty()) else {
            return Ok(1);
        };
        Ok(serde_json::from_str::<SignedEnvelope>(first)
            .ok()
            .and_then(|e| crate::supervisor::audit_segment::continuation_from_entry(&e.entry))
            .map_or(1, |c| c.segment))
    }

    /// Seal the active segment and open its successor. Assumes the chain lock
    /// is held.
    ///
    /// Ordering is seal (fsynced) → rename → continue. A crash anywhere in that
    /// sequence leaves a state [`Self::recover_active`] can finish, and never
    /// leaves a sealed segment that nothing points at.
    fn rotate(&self, active: &Path, tenant: &mvm_core::plan::TenantId) -> Result<(), AuditError> {
        let seq = Self::active_segment_seq(active)?;
        let base = Self::segment_base(active);
        let content = std::fs::read_to_string(active).map_err(|e| AuditError::Io(e.to_string()))?;
        // Counting this segment's own sealing record, which is about to be
        // appended, so the number a successor cross-checks needs no adjustment
        // at the reading end.
        let entries = content.lines().filter(|l| !l.is_empty()).count() as u64 + 1;

        let sealed = crate::supervisor::audit_segment::Sealed {
            segment: seq,
            next_segment: seq + 1,
            entries,
        };
        let seal_entry = self.handoff_entry(
            tenant,
            crate::supervisor::audit_segment::CHAIN_SEALED,
            crate::supervisor::audit_segment::sealed_labels(seq, entries),
        );
        let tip = self.append_locked(active, &seal_entry)?;

        let sealed_path =
            active.with_file_name(mvm_core::config::audit_segment_file_name(&base, seq));
        std::fs::rename(active, &sealed_path).map_err(|e| AuditError::Io(e.to_string()))?;
        self.pending_sync
            .lock()
            .expect("pending_sync poisoned")
            .remove(active);

        self.write_continuation(active, tenant, &sealed, tip)
    }

    /// Open a fresh active segment continuing `sealed`.
    fn write_continuation(
        &self,
        active: &Path,
        tenant: &mvm_core::plan::TenantId,
        sealed: &crate::supervisor::audit_segment::Sealed,
        tip: [u8; 32],
    ) -> Result<(), AuditError> {
        let entry = self.handoff_entry(
            tenant,
            crate::supervisor::audit_segment::CHAIN_CONTINUED,
            crate::supervisor::audit_segment::continuation_labels(sealed, tip),
        );
        // The one append in this file that signs against a hash it did not read
        // off the file being written: the seed is the *previous* segment's tip.
        // Always a barrier, because everything appended after this depends on
        // it being the file's first line, so it must not be able to arrive
        // second.
        self.write_signed(active, &entry, tip, SyncPolicy::Barrier)
            .map(|_| ())
    }

    /// Delete segments `1..=through` after recording the removal in the chain.
    ///
    /// The order is the whole design: **verify, then record, then delete.**
    ///
    /// Verifying first is not politeness. Pruning a chain that is already
    /// broken would destroy the evidence of whatever broke it, and it would do
    /// so under the banner of routine maintenance — so a set that does not
    /// verify is refused before anything is unlinked.
    ///
    /// Recording before deleting is what makes a crash safe in the right
    /// direction. If the process dies between the two, the chain carries a
    /// prune record for segments that are still on disk: the record is then
    /// simply unused, because the front is still genesis and nothing needs
    /// explaining. The opposite order would leave files deleted with no record,
    /// which is indistinguishable from tampering and unrecoverable.
    ///
    /// Only a prefix may be pruned. That leaves exactly one boundary between
    /// what was removed and what survives, and it is the one boundary the
    /// surviving chain can still corroborate.
    pub fn prune_through(
        &self,
        tenant: &mvm_core::plan::TenantId,
        through: u64,
    ) -> Result<crate::supervisor::audit_segment::Pruned, AuditError> {
        let active = self.tenant_path(&tenant.0);
        let base = Self::segment_base(&active);
        let dir = active
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let _lock = Self::acquire_lock(&active)?;

        let vk = self.signing_key.verifying_key();
        let verified =
            crate::supervisor::audit_set::verify_segment_set(&dir, &base, &vk).map_err(|e| {
                AuditError::Io(format!(
                    "refusing to prune a chain that does not verify: {e}. Pruning a broken \
                 chain would delete the evidence of whatever broke it"
                ))
            })?;

        // Already-pruned prefixes are not re-prunable, and the range must start
        // where the surviving history starts.
        let floor = verified.pruned.map_or(1, |p| p.through + 1);
        let sealed: Vec<&crate::supervisor::audit_set::SegmentReport> =
            verified.segments.iter().filter(|s| !s.active).collect();

        if through < floor {
            return Err(AuditError::Io(format!(
                "segments through {through} are already pruned; the surviving chain starts \
                 at segment {floor}"
            )));
        }
        let Some(last_kept) = verified.segments.iter().find(|s| s.seq > through) else {
            return Err(AuditError::Io(format!(
                "pruning through segment {through} would leave no chain behind; at least \
                 the active segment must survive"
            )));
        };
        let _ = last_kept;
        // Every segment in the range must actually be here, or the "prefix"
        // being claimed is not the prefix being deleted.
        for seq in floor..=through {
            if !sealed.iter().any(|s| s.seq == seq) {
                return Err(AuditError::Io(format!(
                    "segment {seq} is in the range being pruned but is not on disk; \
                     refusing to describe a removal that does not match the files"
                )));
            }
        }

        // The tip of the highest segment being removed is the one fact the
        // surviving successor independently attests, so it is what the record
        // has to carry.
        let top = dir.join(mvm_core::config::audit_segment_file_name(&base, through));
        let content = std::fs::read_to_string(&top).map_err(|e| AuditError::Io(e.to_string()))?;
        let last = content
            .lines()
            .rfind(|l| !l.is_empty())
            .ok_or_else(|| AuditError::Io(format!("{} is empty", top.display())))?;
        let entries: u64 = verified
            .segments
            .iter()
            .filter(|s| s.seq <= through && !s.active)
            .filter_map(|s| s.entries)
            .sum::<usize>() as u64;

        let pruned = crate::supervisor::audit_segment::Pruned {
            through,
            tip: hash_line(last.as_bytes()),
            entries,
        };
        let entry = self.handoff_entry(
            tenant,
            crate::supervisor::audit_segment::CHAIN_PRUNED,
            crate::supervisor::audit_segment::pruned_labels(&pruned),
        );
        // Barrier: the record must be durable before the files it explains stop
        // existing.
        let prev = self.restore_cursor(&active)?;
        self.write_signed(&active, &entry, prev, SyncPolicy::Barrier)?;

        for seq in floor..=through {
            let path = dir.join(mvm_core::config::audit_segment_file_name(&base, seq));
            std::fs::remove_file(&path).map_err(|e| AuditError::Io(e.to_string()))?;
        }
        Ok(pruned)
    }

    /// Finish an interrupted rotation.
    ///
    /// A crash between the rename and the continuation write leaves a sealed
    /// segment and no active file. Without this, the next append would find an
    /// absent file, seed from genesis, and start a fresh chain that claims to
    /// be the beginning of history — silently orphaning every sealed segment
    /// behind it, each of which still verifies perfectly alone. That is the one
    /// failure mode of this design that would destroy evidence without anyone
    /// getting an error, so it is repaired before any append rather than
    /// detected afterwards.
    fn recover_active(
        &self,
        active: &Path,
        tenant: &mvm_core::plan::TenantId,
    ) -> Result<(), AuditError> {
        let live = std::fs::metadata(active).map(|m| m.len()).unwrap_or(0);
        if live > 0 {
            return Ok(());
        }
        let base = Self::segment_base(active);
        let dir = active.parent().unwrap_or(Path::new("."));
        let Some((seq, sealed_path)) = highest_sealed_segment(dir, &base)? else {
            // No sealed segments: this really is a fresh genesis chain.
            return Ok(());
        };
        let content =
            std::fs::read_to_string(&sealed_path).map_err(|e| AuditError::Io(e.to_string()))?;
        let Some(last) = content.lines().rfind(|l| !l.is_empty()) else {
            return Ok(());
        };
        let envelope: SignedEnvelope =
            serde_json::from_str(last).map_err(|e| AuditError::Io(e.to_string()))?;
        let Some(sealed) = crate::supervisor::audit_segment::sealed_from_entry(&envelope.entry)
        else {
            // The newest segment on disk does not end with a sealing record, so
            // it was never retired. Refuse rather than guess: appending a
            // continuation onto an unsealed predecessor would fabricate a
            // handoff the writer never made.
            return Err(AuditError::Io(format!(
                "audit segment {} is the newest on disk but carries no sealing record; \
                 refusing to continue a chain that was never sealed",
                sealed_path.display()
            )));
        };
        if sealed.segment != seq {
            return Err(AuditError::Io(format!(
                "audit segment {} seals segment {} but is filed as {seq}",
                sealed_path.display(),
                sealed.segment
            )));
        }
        self.write_continuation(active, tenant, &sealed, hash_line(last.as_bytes()))
    }
}

/// The highest-numbered sealed segment for `base` in `dir`, if any.
pub(crate) fn highest_sealed_segment(
    dir: &Path,
    base: &str,
) -> Result<Option<(u64, PathBuf)>, AuditError> {
    let mut best: Option<(u64, PathBuf)> = None;
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(AuditError::Io(e.to_string())),
    };
    for entry in entries {
        let entry = entry.map_err(|e| AuditError::Io(e.to_string()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(seq) = mvm_core::config::audit_segment_seq(name, base) else {
            continue;
        };
        if best.as_ref().is_none_or(|(b, _)| seq > *b) {
            best = Some((seq, entry.path()));
        }
    }
    Ok(best)
}

#[async_trait]
impl AuditSigner for FileAuditSigner {
    async fn sign_and_emit(&self, entry: &PlanAuditEntry) -> Result<(), AuditError> {
        let tenant = entry.tenant.0.clone();
        let path = self.tenant_path(&tenant);
        let cursor_key = self
            .fixed_file
            .as_ref()
            .map(|p| format!("file:{}", p.display()))
            .unwrap_or_else(|| format!("tenant:{tenant}"));

        // Cross-process chain integrity.
        //
        // The in-memory `cursors` HashMap only serializes writers inside *this*
        // process. Two `mvm-libkrun-supervisor` instances for the same tenant
        // would otherwise both restore the same on-disk prev_hash, both append,
        // and break the chain. The lock covers the whole read-cursor / rotate /
        // sign / append section, so a rotation is atomic against a concurrent
        // writer too — two processes cannot both seal the same segment.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AuditError::Io(e.to_string()))?;
        }
        let _lock = Self::acquire_lock(&path)?;

        self.recover_active(&path, &entry.tenant)?;

        let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if self.rotation.should_rotate(len) {
            self.rotate(&path, &entry.tenant)?;
        }

        let new_hash = self.append_locked(&path, entry)?;
        self.cursors
            .lock()
            .expect("cursors poisoned")
            .insert(cursor_key, new_hash);
        Ok(())
        // `_lock` drop releases the flock here.
    }
}

/// Take an exclusive advisory lock on `file`. Blocks until acquired.
/// Released when the OwnedFd backing `file` is dropped. This is what
/// gives the per-tenant audit chain cross-process integrity.
///
/// `flock` is held per open file description rather than per process, so two
/// threads that each opened the file are serialized against one another the
/// same way two processes are. `fcntl` record locks are not — they are owned
/// by the process and grant a second thread the lock it is already holding.
pub(crate) fn flock_exclusive(file: &std::fs::File) -> std::io::Result<()> {
    use rustix::fs::{FlockOperation, flock};
    use std::os::fd::AsFd;
    flock(file.as_fd(), FlockOperation::LockExclusive).map_err(std::io::Error::from)
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("io error: {0}")]
    Io(String),
    #[error("malformed envelope at line {line}: {reason}")]
    Malformed { line: usize, reason: String },
    #[error("prev_hash mismatch at line {line}: chain broken")]
    PrevHashMismatch { line: usize },
    #[error("signature invalid at line {line}")]
    SignatureInvalid { line: usize },
    #[error("line {line}: the readable entry disagrees with the bytes that were signed")]
    EntryCanonicalMismatch { line: usize },
    /// The file ends mid-record: a writer died between the record and its
    /// terminating newline. Distinct from [`Self::Malformed`] on purpose — an
    /// operator triaging a broken chain needs to know whether they are looking
    /// at a crash or at an edit, and the two are otherwise identical on disk.
    /// Entries before the truncation point are still verified and returned by
    /// the count; only the incomplete tail is refused.
    #[error("audit stream ends mid-record at line {line}: last append did not complete")]
    TruncatedTail { line: usize },
}

/// Walk a chain-signed audit file, verifying each envelope's
/// `prev_hash` against the running chain hash and each signature
/// against `verifying_key`. Returns the number of valid entries on
/// success. Stops at the first failure and reports its line index.
pub fn verify_audit_chain(path: &Path, verifying_key: &VerifyingKey) -> Result<usize, VerifyError> {
    verify_audit_chain_entries(path, verifying_key).map(|entries| entries.len())
}

/// Verify a chain-signed audit file and return its authenticated entries in
/// chain order. Consumers use this when a decision depends on signed labels,
/// rather than parsing an already-verified file a second time.
#[tracing::instrument(skip_all, fields(path = %path.display()))]
pub fn verify_audit_chain_entries(
    path: &Path,
    verifying_key: &VerifyingKey,
) -> Result<Vec<PlanAuditEntry>, VerifyError> {
    let content = std::fs::read_to_string(path).map_err(|e| VerifyError::Io(e.to_string()))?;
    let walk = walk_chain(&content, verifying_key, ChainStart::Genesis)?;
    Ok(walk.entries)
}

/// One verified segment: its entries and the chain hash it ends on.
///
/// The segment-set checker needs the tip so it can match the successor's
/// claimed predecessor hash. Recomputing it by re-reading the file would open
/// the read/verify/re-read window this module is careful to avoid elsewhere,
/// so the walk reports it from the same bytes it verified.
#[derive(Debug, Clone)]
pub struct SegmentWalk {
    /// Authenticated entries, in chain order.
    pub entries: Vec<PlanAuditEntry>,
    /// SHA-256 of the final line — what a successor segment must claim.
    pub tip: [u8; 32],
}

/// Verify an already-read segment, from genesis or from its authenticated
/// handoff, returning its entries and its tip.
///
/// Callers that also need the raw lines — the Merkle leaf builder, the
/// segment-set walker — read the file once and verify from that buffer, so
/// what is attested and what is used are provably the same bytes.
pub fn verify_chain_bytes(
    content: &str,
    verifying_key: &VerifyingKey,
) -> Result<SegmentWalk, VerifyError> {
    let walk = walk_chain(content, verifying_key, ChainStart::Genesis)?;
    Ok(SegmentWalk {
        entries: walk.entries,
        tip: walk.chain_hash,
    })
}

/// Verify an already-read segment from `resume_line`, seeding the running
/// chain hash with `chain_hash` instead of the genesis anchor.
///
/// The suffix counterpart of [`verify_chain_bytes`], for a caller that already
/// holds an authenticated statement about the prefix and needs only what was
/// appended after it. Cost is `O(lines - resume_line)`.
///
/// Sound in the same narrow sense [`verify_audit_chain_incremental`] is: the
/// resumed line's signature covers its `prev_hash`, so a valid signature there
/// authenticates the state the prefix ended in. What it does not do is anchor
/// that prefix, so **every caller owes an account of what authenticates the
/// seed** — and a caller whose account is a bare stored integer is choosing
/// the trade this module confines to `doctor`.
///
/// A truncated final line is still reported as [`VerifyError::TruncatedTail`]:
/// the check reads `content`'s terminating byte, which a resumed walk has in
/// hand exactly as a genesis walk does.
pub fn verify_chain_bytes_resuming(
    content: &str,
    verifying_key: &VerifyingKey,
    resume_line: usize,
    chain_hash: [u8; 32],
) -> Result<SegmentWalk, VerifyError> {
    let walk = walk_chain(
        content,
        verifying_key,
        ChainStart::Resume {
            line: resume_line,
            chain_hash,
        },
    )?;
    Ok(SegmentWalk {
        entries: walk.entries,
        tip: walk.chain_hash,
    })
}

/// Where a chain walk begins.
enum ChainStart {
    /// Line 0, with the all-zero chain hash. The zero prefix is the anchor
    /// that makes a removed prefix detectable: a truncated file's new first
    /// line claims a non-zero predecessor and fails immediately.
    Genesis,
    /// Line `line`, with `chain_hash` as the running hash. Sound only because
    /// the resumed line's signature covers its `prev_hash`, so a valid
    /// signature there authenticates the state the prefix ended in.
    Resume { line: usize, chain_hash: [u8; 32] },
}

/// What a completed walk established.
struct ChainWalk {
    entries: Vec<PlanAuditEntry>,
    /// Total lines consumed, including any skipped prefix.
    lines: usize,
    /// Running chain hash after the last line.
    chain_hash: [u8; 32],
}

/// Verify every line from `start` to the end of `content`.
fn walk_chain(
    content: &str,
    verifying_key: &VerifyingKey,
    start: ChainStart,
) -> Result<ChainWalk, VerifyError> {
    // A record is only complete once its terminator is on disk. `str::lines`
    // does not distinguish "last line" from "last line so far", so check the
    // final byte before walking: without this, a half-written record is
    // reported as malformed JSON or a bad signature, and a crash becomes
    // indistinguishable from someone having edited the log.
    let truncated_tail = !content.is_empty() && !content.ends_with('\n');
    let (skip_to, mut prev_hash) = match start {
        ChainStart::Genesis => (0, [0u8; 32]),
        ChainStart::Resume { line, chain_hash } => (line, chain_hash),
    };
    let mut entries = Vec::new();
    let total = content.lines().count();
    let last_idx = total.saturating_sub(1);
    let mut at_genesis_head = matches!(start, ChainStart::Genesis);
    for (idx, line) in content.lines().enumerate() {
        if idx < skip_to || line.is_empty() {
            continue;
        }
        if truncated_tail && idx == last_idx {
            return Err(VerifyError::TruncatedTail { line: idx });
        }
        // The opening line of a rotated segment does not claim genesis; it
        // claims its predecessor's final line hash. Adopt that as the seed, but
        // only when the entry is a continuation record whose *signed body*
        // names the identical hash.
        //
        // It is still only a claim here: `verify_line` checks the signature
        // over `signed_bytes || prev_hash`, so an adopted seed that was never
        // signed fails there. That keeps the cost of forging a handoff equal to
        // the cost of forging any other line rather than reducing it to editing
        // one field.
        //
        // Only ever the first line of a genesis walk. A continuation record
        // appearing mid-file would otherwise splice a chain restart into the
        // middle of a segment and orphan everything before it — and a *resumed*
        // walk must not do this at all, because its seed came from a checkpoint
        // rather than from the anchor.
        if at_genesis_head && let Some(tip) = adopted_continuation_seed(line) {
            prev_hash = tip;
        }
        at_genesis_head = false;
        prev_hash = verify_line(line, idx, &prev_hash, verifying_key, &mut entries)?;
    }
    Ok(ChainWalk {
        entries,
        lines: total,
        chain_hash: prev_hash,
    })
}

/// The chain hash `line` authorizes as a segment's starting point, if it is a
/// well-formed continuation record whose envelope and signed body agree.
///
/// Both copies must match before the seed is adopted. The envelope `prev_hash`
/// is what the walk consumes; the copy inside the entry is what the signature
/// covers. Checking only the envelope would let anyone restart a chain
/// anywhere by editing one field, which is the whole property rotation must
/// not give away.
fn adopted_continuation_seed(line: &str) -> Option<[u8; 32]> {
    let envelope: SignedEnvelope = serde_json::from_str(line).ok()?;
    let claimed = URL_SAFE_NO_PAD.decode(&envelope.prev_hash).ok()?;
    let tip = crate::supervisor::audit_segment::continuation_start_hash(&envelope.entry)?;
    (claimed == tip).then_some(tip)
}

/// Verify one line against the running chain hash, push its entry, and return
/// the advanced chain hash.
fn verify_line(
    line: &str,
    idx: usize,
    prev_hash: &[u8; 32],
    verifying_key: &VerifyingKey,
    entries: &mut Vec<PlanAuditEntry>,
) -> Result<[u8; 32], VerifyError> {
    let envelope: SignedEnvelope =
        serde_json::from_str(line).map_err(|e| VerifyError::Malformed {
            line: idx,
            reason: e.to_string(),
        })?;
    let claimed_prev =
        URL_SAFE_NO_PAD
            .decode(&envelope.prev_hash)
            .map_err(|e| VerifyError::Malformed {
                line: idx,
                reason: format!("prev_hash b64: {e}"),
            })?;
    if claimed_prev.as_slice() != prev_hash.as_slice() {
        return Err(VerifyError::PrevHashMismatch { line: idx });
    }
    let sig_bytes =
        URL_SAFE_NO_PAD
            .decode(&envelope.signature)
            .map_err(|e| VerifyError::Malformed {
                line: idx,
                reason: format!("signature b64: {e}"),
            })?;
    let sig_arr: [u8; 64] =
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::Malformed {
                line: idx,
                reason: "signature must be 64 bytes".to_string(),
            })?;
    let signature = Signature::from_bytes(&sig_arr);
    let mut to_verify = signed_bytes_for(&envelope, idx).map_err(|e| match e {
        mvm_contract::verify::AuditVerifyError::Malformed { reason, .. } => {
            VerifyError::Malformed { line: idx, reason }
        }
        mvm_contract::verify::AuditVerifyError::PrevHashMismatch { .. } => {
            VerifyError::PrevHashMismatch { line: idx }
        }
        mvm_contract::verify::AuditVerifyError::SignatureInvalid { .. } => {
            VerifyError::SignatureInvalid { line: idx }
        }
        mvm_contract::verify::AuditVerifyError::EntryCanonicalMismatch { .. } => {
            VerifyError::EntryCanonicalMismatch { line: idx }
        }
        mvm_contract::verify::AuditVerifyError::KeyDecode(reason) => VerifyError::Malformed {
            line: idx,
            reason: format!("key: {reason}"),
        },
    })?;
    to_verify.extend_from_slice(prev_hash);
    verifying_key
        .verify(&to_verify, &signature)
        .map_err(|_| VerifyError::SignatureInvalid { line: idx })?;
    entries.push(envelope.entry);
    Ok(hash_line(line.as_bytes()))
}

/// How far a chain has already been verified, so a later run can resume.
///
/// Persisted between runs. Resuming trades the genesis anchor for this stored
/// value: whoever can write it can have a prefix-truncated chain accepted,
/// because every surviving line is still genuinely signed. That is why only
/// the routine health check resumes, and `mvmctl trust audit verify` — claim
/// 8's witness — always walks from genesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainCheckpoint {
    /// Lines already verified; the next walk resumes at this index.
    pub verified_lines: usize,
    /// Running chain hash after `verified_lines`, base64url unpadded.
    pub chain_hash: String,
}

impl ChainCheckpoint {
    fn new(verified_lines: usize, chain_hash: [u8; 32]) -> Self {
        Self {
            verified_lines,
            chain_hash: URL_SAFE_NO_PAD.encode(chain_hash),
        }
    }

    /// Decode the stored hash, or `None` when it is not 32 base64url bytes.
    /// An undecodable checkpoint is treated as absent rather than as an error:
    /// it is a cache, and the fallback is a full walk.
    fn hash_bytes(&self) -> Option<[u8; 32]> {
        let raw = URL_SAFE_NO_PAD.decode(&self.chain_hash).ok()?;
        raw.as_slice().try_into().ok()
    }
}

/// What an incremental verification established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementalVerification {
    /// Checkpoint to persist for the next run.
    pub checkpoint: ChainCheckpoint,
    /// Entries verified on this pass.
    pub verified_now: usize,
    /// Whether the whole chain was walked from genesis. False means the
    /// prefix was taken on the checkpoint's word, which callers must not
    /// report as a full-chain guarantee.
    pub walked_from_genesis: bool,
}

/// Verify a chain, resuming from `checkpoint` when one is supplied.
///
/// A checkpoint that does not fit the file — too long, undecodable, or failing
/// to verify at the resume point — is **discarded, not reported as tampering**.
/// A mismatch is equally consistent with log rotation, a replaced file, or a
/// stale checkpoint, and only a full walk can tell those apart; falling back
/// keeps the fast path from ever manufacturing a false alarm, and leaves every
/// refusal backed by a genesis-anchored verification.
pub fn verify_audit_chain_incremental(
    path: &Path,
    verifying_key: &VerifyingKey,
    checkpoint: Option<&ChainCheckpoint>,
) -> Result<IncrementalVerification, VerifyError> {
    let content = std::fs::read_to_string(path).map_err(|e| VerifyError::Io(e.to_string()))?;
    let total = content.lines().count();

    if let Some(resume) = usable_resume(checkpoint, total)
        && let Ok(walk) = walk_chain(&content, verifying_key, resume)
    {
        return Ok(IncrementalVerification {
            checkpoint: ChainCheckpoint::new(walk.lines, walk.chain_hash),
            verified_now: walk.entries.len(),
            walked_from_genesis: false,
        });
    }

    let walk = walk_chain(&content, verifying_key, ChainStart::Genesis)?;
    Ok(IncrementalVerification {
        checkpoint: ChainCheckpoint::new(walk.lines, walk.chain_hash),
        verified_now: walk.entries.len(),
        walked_from_genesis: true,
    })
}

/// A resume point, when the checkpoint is decodable and within the file.
///
/// A checkpoint at or beyond the line count means the file shrank (rotation,
/// truncation, replacement) and there is nothing to resume onto.
fn usable_resume(checkpoint: Option<&ChainCheckpoint>, total_lines: usize) -> Option<ChainStart> {
    let checkpoint = checkpoint?;
    if checkpoint.verified_lines == 0 || checkpoint.verified_lines >= total_lines {
        return None;
    }
    Some(ChainStart::Resume {
        line: checkpoint.verified_lines,
        chain_hash: checkpoint.hash_bytes()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_line_checkpoint_cannot_replace_the_genesis_anchor() {
        let checkpoint = ChainCheckpoint::new(0, [0_u8; 32]);

        assert!(usable_resume(Some(&checkpoint), 3).is_none());
    }

    mod highest_sealed_segment_tests {
        use super::super::highest_sealed_segment;
        use mvm_core::config::audit_segment_file_name;

        /// Write the named segments and return the directory holding them.
        fn dir_with(base: &str, seqs: &[u64]) -> tempfile::TempDir {
            let dir = tempfile::tempdir().expect("tempdir");
            for seq in seqs {
                std::fs::write(
                    dir.path().join(audit_segment_file_name(base, *seq)),
                    b"{}\n",
                )
                .expect("write segment");
            }
            dir
        }

        /// The point of the function: the *highest* sequence wins.
        ///
        /// This kills a sign flip (`>` becoming `<`) but deliberately does not
        /// claim to kill `>` becoming `==`. Under `==` the function keeps
        /// whatever `read_dir` yields first, and `read_dir` order is
        /// unspecified — a test asserting otherwise would pass or fail on the
        /// filesystem's whim, which is worse than not asserting it. That
        /// mutant is declared an accepted miss with the reason spelled out.
        #[test]
        fn the_highest_sequence_wins_not_the_lowest() {
            let dir = dir_with("local", &[3, 1, 7, 2]);
            let (seq, path) = highest_sealed_segment(dir.path(), "local")
                .expect("scan")
                .expect("a segment exists");
            assert_eq!(seq, 7);
            assert!(path.ends_with(audit_segment_file_name("local", 7)));
        }

        /// One segment is the degenerate case the comparison never runs on.
        #[test]
        fn a_lone_segment_is_the_highest() {
            let dir = dir_with("local", &[4]);
            let (seq, _) = highest_sealed_segment(dir.path(), "local")
                .expect("scan")
                .expect("a segment exists");
            assert_eq!(seq, 4);
        }

        /// A tenant whose name prefixes another must not adopt its segments —
        /// `local` and `local-two` share a prefix but not a chain.
        #[test]
        fn segments_of_a_similarly_named_tenant_are_not_adopted() {
            let dir = dir_with("local", &[2]);
            std::fs::write(
                dir.path().join(audit_segment_file_name("local-two", 9)),
                b"{}\n",
            )
            .expect("write other tenant");

            let (seq, _) = highest_sealed_segment(dir.path(), "local")
                .expect("scan")
                .expect("a segment exists");
            assert_eq!(seq, 2, "9 belongs to local-two");
        }

        #[test]
        fn an_empty_directory_has_no_sealed_segment() {
            let dir = tempfile::tempdir().expect("tempdir");
            assert!(
                highest_sealed_segment(dir.path(), "local")
                    .expect("scan")
                    .is_none()
            );
        }

        /// A missing directory is not an error — a chain that never rotated
        /// has no segment directory to read.
        #[test]
        fn a_missing_directory_reports_no_segment_rather_than_failing() {
            let dir = tempfile::tempdir().expect("tempdir");
            let gone = dir.path().join("never-created");
            assert!(
                highest_sealed_segment(&gone, "local")
                    .expect("scan")
                    .is_none()
            );
        }

        /// Files that are not segments of this chain are skipped, including
        /// the active chain file itself.
        #[test]
        fn non_segment_files_are_ignored() {
            let dir = dir_with("local", &[1]);
            for junk in ["local.jsonl", "local.seg-notanumber.jsonl", "README.md"] {
                std::fs::write(dir.path().join(junk), b"x").expect("write junk");
            }
            let (seq, _) = highest_sealed_segment(dir.path(), "local")
                .expect("scan")
                .expect("a segment exists");
            assert_eq!(seq, 1);
        }
    }
    use rand::Rng;

    use chrono::Utc;
    use ed25519_dalek::SigningKey;
    use mvm_core::plan::{PlanId, TenantId};
    use std::collections::BTreeMap;

    fn fresh_key() -> SigningKey {
        {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        }
    }

    fn make_entry(tenant: &str, event: &str) -> PlanAuditEntry {
        PlanAuditEntry {
            timestamp: Utc::now(),
            tenant: TenantId(tenant.to_string()),
            plan_id: PlanId("plan-1".to_string()),
            plan_version: 1,
            bundle_id: None,
            bundle_version: None,
            image_name: "img".to_string(),
            image_sha256: "abc123".to_string(),
            event: event.to_string(),
            labels: BTreeMap::new(),
        }
    }

    /// The rule is what an entry authorizes. `plan.admitted` permits a boot,
    /// so it must be on disk before one can happen; the records around it
    /// describe things that already did.
    #[test]
    fn only_entries_that_authorize_something_are_barriers() {
        for authorizing in [
            "plan.admitted",
            "plan.failed",
            "plan.verb_denied",
            "plan.grant_required",
            "stream.input_refused",
            "cmd.machine.completed",
            "cmd.machine.failed",
        ] {
            assert_eq!(
                sync_policy_for(authorizing),
                SyncPolicy::Barrier,
                "{authorizing} must be durable before what follows it"
            );
        }

        for record in [
            "plan.policy_resolved",
            "plan.boot_posture",
            "plan.oci_provenance",
            "plan.launched",
            "plan.shares_admitted",
            "cmd.machine.invoked",
            "cmd.image.invoked",
        ] {
            assert_eq!(
                sync_policy_for(record),
                SyncPolicy::Deferred,
                "{record} authorizes nothing and need not stall the launch"
            );
        }
    }

    /// The list is of deferrable events, so anything unrecognised syncs. An
    /// event added later that should have been durable and silently was not is
    /// the failure this ordering exists to prevent.
    #[test]
    fn an_unrecognised_event_defaults_to_syncing() {
        assert_eq!(
            sync_policy_for("plan.some_event_added_next_year"),
            SyncPolicy::Barrier
        );
        assert_eq!(sync_policy_for(""), SyncPolicy::Barrier);
    }

    /// A launch's entries must all be on disk once its terminal entry returns,
    /// even though only two of them synced. `sync_data` is file-wide, so the
    /// barrier carries the deferred writes before it.
    #[tokio::test]
    async fn a_barrier_leaves_nothing_pending_on_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let signer = FileAuditSigner::open(fresh_key(), dir.path()).unwrap();

        signer
            .sign_and_emit(&make_entry("t1", "cmd.machine.invoked"))
            .await
            .unwrap();
        assert_eq!(
            signer.pending_sync.lock().unwrap().len(),
            1,
            "a deferred entry leaves its file pending"
        );

        signer
            .sign_and_emit(&make_entry("t1", "plan.admitted"))
            .await
            .unwrap();
        assert!(
            signer.pending_sync.lock().unwrap().is_empty(),
            "a barrier clears the file it synced"
        );

        // The deferred records after the barrier are pending again, and the
        // terminal entry is what flushes them.
        for event in ["plan.policy_resolved", "plan.launched", "plan.boot_posture"] {
            signer
                .sign_and_emit(&make_entry("t1", event))
                .await
                .unwrap();
        }
        assert_eq!(signer.pending_sync.lock().unwrap().len(), 1);
        signer
            .sign_and_emit(&make_entry("t1", "cmd.machine.completed"))
            .await
            .unwrap();
        assert!(signer.pending_sync.lock().unwrap().is_empty());
    }

    /// fsync is per-file, so a barrier on one tenant's chain says nothing
    /// about another's. Both have to be tracked or the second tenant's tail
    /// silently never syncs.
    #[tokio::test]
    async fn a_barrier_on_one_tenant_does_not_flush_another() {
        let dir = tempfile::tempdir().unwrap();
        let signer = FileAuditSigner::open(fresh_key(), dir.path()).unwrap();

        signer
            .sign_and_emit(&make_entry("t1", "plan.launched"))
            .await
            .unwrap();
        signer
            .sign_and_emit(&make_entry("t2", "plan.launched"))
            .await
            .unwrap();
        assert_eq!(signer.pending_sync.lock().unwrap().len(), 2);

        signer
            .sign_and_emit(&make_entry("t1", "plan.admitted"))
            .await
            .unwrap();
        let pending = signer.pending_sync.lock().unwrap();
        assert_eq!(pending.len(), 1, "t2 must still be pending");
        assert!(pending.iter().any(|p| p.to_string_lossy().contains("t2")));
    }

    /// Every entry is readable and chain-valid regardless of when it synced —
    /// deferring changes durability, never content or ordering.
    #[tokio::test]
    async fn deferred_entries_are_still_written_and_chain_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let signer = FileAuditSigner::open(fresh_key(), dir.path()).unwrap();
        let events = [
            "cmd.machine.invoked",
            "plan.admitted",
            "plan.policy_resolved",
            "plan.launched",
            "cmd.machine.completed",
        ];
        for event in events {
            signer
                .sign_and_emit(&make_entry("t1", event))
                .await
                .unwrap();
        }
        signer.flush_deferred();
        assert!(
            signer.pending_sync.lock().unwrap().is_empty(),
            "an explicit flush drains every pending file"
        );

        let body = std::fs::read_to_string(dir.path().join("t1.jsonl")).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), events.len(), "every entry is on disk");
        for (line, expected) in lines.iter().zip(events) {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["entry"]["event"], expected, "order is preserved");
        }
    }

    #[tokio::test]
    async fn dropping_the_signer_flushes_every_deferred_file() {
        let dir = tempfile::tempdir().unwrap();
        let pending = {
            let signer = FileAuditSigner::open(fresh_key(), dir.path()).unwrap();
            signer
                .sign_and_emit(&make_entry("t1", "plan.launched"))
                .await
                .unwrap();
            let pending = Arc::clone(&signer.pending_sync);
            assert_eq!(pending.lock().unwrap().len(), 1);
            drop(signer);
            pending
        };

        assert!(
            pending.lock().unwrap().is_empty(),
            "drop must flush and drain every deferred file"
        );
    }

    #[tokio::test]
    async fn first_entry_uses_genesis_prev_hash() {
        let dir = tempfile::tempdir().unwrap();
        let signer = FileAuditSigner::open(fresh_key(), dir.path()).unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "plan.verified"))
            .await
            .unwrap();

        let content = std::fs::read_to_string(signer.tenant_path("tenant-a")).unwrap();
        let envelope: SignedEnvelope = serde_json::from_str(content.trim()).unwrap();
        let prev = URL_SAFE_NO_PAD.decode(&envelope.prev_hash).unwrap();
        assert_eq!(prev, vec![0u8; 32], "genesis prev_hash must be all zeros");
    }

    #[tokio::test]
    async fn second_entry_chains_to_first() {
        let dir = tempfile::tempdir().unwrap();
        let signer = FileAuditSigner::open(fresh_key(), dir.path()).unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "plan.verified"))
            .await
            .unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "plan.admitted"))
            .await
            .unwrap();

        let path = signer.tenant_path("tenant-a");
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        let first_hash = hash_line(lines[0].as_bytes());
        let second: SignedEnvelope = serde_json::from_str(lines[1]).unwrap();
        let second_prev = URL_SAFE_NO_PAD.decode(&second.prev_hash).unwrap();
        assert_eq!(second_prev, first_hash, "chain links must match");
    }

    #[tokio::test]
    async fn full_chain_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let vk = key.verifying_key();
        let signer = FileAuditSigner::open(key, dir.path()).unwrap();
        for i in 0..5 {
            signer
                .sign_and_emit(&make_entry("tenant-a", &format!("event-{i}")))
                .await
                .unwrap();
        }
        let count = verify_audit_chain(&signer.tenant_path("tenant-a"), &vk).unwrap();
        assert_eq!(count, 5);
        let entries = verify_audit_chain_entries(&signer.tenant_path("tenant-a"), &vk).unwrap();
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].event, "event-0");
        assert_eq!(entries[4].event, "event-4");
    }

    // Pin the wasm-clean `mvm_contract::verify` re-implementation to the
    // bytes this crate actually writes. If `PlanAuditEntry`'s serde shape
    // drifts from `mvm_contract::verify::MirrorEntry`, a genuine line
    // stops verifying and this fails here (loudly, in CI) rather than
    // only in the browser tool.
    /// A signed audit chain frozen on disk, so both verifiers can be checked
    /// against the *same bytes* rather than each against a chain generated for
    /// it.
    ///
    /// The parity test below is real but keyed randomly per run, so its bytes
    /// exist only inside that process. That cannot be shared with a verifier
    /// which does not link the host signer — the `no_std` mirror under wasm,
    /// or the bare-metal build — and an oracle bar means little if each
    /// implementation only ever sees input it produced itself.
    ///
    /// Determinism comes from a fixed signing seed and fixed timestamps;
    /// Ed25519 signing is deterministic per RFC 8032, so the bytes are stable.
    /// `MVM_REGEN_AUDIT_CORPUS=1` rewrites the committed files.
    mod frozen_corpus {
        use super::*;

        /// Fixed seed. Test-only: it signs nothing outside this corpus.
        const SEED: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];

        fn vectors_dir() -> PathBuf {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(|p| p.parent())
                .expect("workspace root above crates/mvm-hostd")
                .join("tests")
                .join("vectors")
        }

        fn fixed_entry(tenant: &str, event: &str, ts: &str) -> PlanAuditEntry {
            PlanAuditEntry {
                timestamp: ts.parse().expect("valid RFC 3339"),
                tenant: TenantId(tenant.to_string()),
                plan_id: PlanId("plan-frozen".to_string()),
                plan_version: 1,
                bundle_id: None,
                bundle_version: None,
                image_name: "img".to_string(),
                image_sha256: "d".repeat(64),
                event: event.to_string(),
                labels: BTreeMap::new(),
            }
        }

        /// Build the chain the corpus pins: a plain entry, one exercising the
        /// optional bundle fields and a label, and a `checkpoint.forked`
        /// carrying content-address labels — the shapes whose serialization
        /// the two implementations must agree on.
        async fn build_chain(dir: &Path) -> (String, String) {
            let key = SigningKey::from_bytes(&SEED);
            let vk_hex = hex::encode(key.verifying_key().to_bytes());
            let signer = FileAuditSigner::open(key, dir).unwrap();

            signer
                .sign_and_emit(&fixed_entry(
                    "tenant-frozen",
                    "plan.launched",
                    "2020-01-01T00:00:00Z",
                ))
                .await
                .unwrap();

            let mut bundled = fixed_entry("tenant-frozen", "plan.admitted", "2020-01-01T00:00:01Z");
            bundled.bundle_id = Some(mvm_core::policy::PolicyId("bundle-frozen".to_string()));
            bundled.bundle_version = Some(3);
            bundled
                .labels
                .insert("workflow".to_string(), "wf-1".to_string());
            signer.sign_and_emit(&bundled).await.unwrap();

            let mut forked =
                fixed_entry("tenant-frozen", "checkpoint.forked", "2020-01-01T00:00:02Z");
            forked.labels.insert(
                "parent_digest".to_string(),
                format!("sha256:{}", "b".repeat(64)),
            );
            forked.labels.insert(
                "child_digest".to_string(),
                format!("sha256:{}", "c".repeat(64)),
            );
            signer.sign_and_emit(&forked).await.unwrap();

            let content = std::fs::read_to_string(signer.tenant_path("tenant-frozen")).unwrap();
            (content, vk_hex)
        }

        /// The v1 corpus was written before the signed bytes were stored on
        /// the line. It must keep verifying forever, unchanged.
        ///
        /// This is the whole no-cutover promise, in one assertion: a log
        /// somebody already holds does not stop being evidence because the
        /// writer got better. Note it is asserted by *verifying*, not by
        /// byte-comparing against what today's signer emits — today's signer
        /// no longer emits this shape, and that is fine.
        #[test]
        fn the_pre_stored_bytes_corpus_still_verifies() {
            let committed = std::fs::read_to_string(vectors_dir().join("audit-chain-v1.jsonl"))
                .expect("v1 corpus is committed");
            assert!(
                !committed.contains("\"canonical\""),
                "the v1 corpus must stay in its original shape; regenerating it would \
                 destroy the only evidence that old logs still verify"
            );
            let vk_hex = std::fs::read_to_string(vectors_dir().join("audit-chain-v1.pubkey"))
                .expect("v1 corpus key is committed");
            let vk = VerifyingKey::from_bytes(
                &<[u8; 32]>::try_from(hex::decode(vk_hex.trim()).unwrap().as_slice()).unwrap(),
            )
            .unwrap();

            let dir = tempfile::tempdir().unwrap();
            let written = dir.path().join("v1.jsonl");
            std::fs::write(&written, &committed).unwrap();
            assert_eq!(
                verify_audit_chain(&written, &vk).expect("the host verifier accepts the v1 corpus"),
                3
            );
            assert_eq!(
                mvm_contract::verify::verify_audit_chain_bytes(&committed, &vk)
                    .expect("the wasm verifier accepts the v1 corpus")
                    .count,
                3,
                "both verifiers must keep accepting pre-stored-bytes logs"
            );
        }

        #[tokio::test]
        async fn frozen_chain_matches_what_the_signer_produces_and_the_host_verifier_accepts() {
            let dir = tempfile::tempdir().unwrap();
            let (content, vk_hex) = build_chain(dir.path()).await;

            let chain_path = vectors_dir().join("audit-chain-v2.jsonl");
            let key_path = vectors_dir().join("audit-chain-v2.pubkey");

            if std::env::var_os("MVM_REGEN_AUDIT_CORPUS").is_some() {
                std::fs::create_dir_all(vectors_dir()).unwrap();
                std::fs::write(&chain_path, &content).unwrap();
                std::fs::write(&key_path, format!("{vk_hex}\n")).unwrap();
                return;
            }

            let committed = std::fs::read_to_string(&chain_path)
                .expect("frozen audit chain corpus is committed");
            assert_eq!(
                committed, content,
                "the committed corpus no longer matches what the signer emits — either the \
                 signed serialization changed (every existing chain just became unverifiable) \
                 or the corpus needs a deliberate regen"
            );
            assert_eq!(
                std::fs::read_to_string(&key_path).unwrap().trim(),
                vk_hex,
                "corpus verifying key drifted from the fixed seed"
            );

            // The host implementation, over the committed bytes.
            let vk = VerifyingKey::from_bytes(
                &<[u8; 32]>::try_from(hex::decode(&vk_hex).unwrap().as_slice()).unwrap(),
            )
            .unwrap();
            let written = dir.path().join("committed.jsonl");
            std::fs::write(&written, &committed).unwrap();
            assert_eq!(
                verify_audit_chain(&written, &vk).expect("host verifier accepts the corpus"),
                3
            );
        }
    }

    #[tokio::test]
    async fn mvm_verify_matches_supervisor_chain() {
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let vk = key.verifying_key();
        let signer = FileAuditSigner::open(key, dir.path()).unwrap();
        let mut entry = make_entry("tenant-a", "plan.launched");
        // Exercise the optional bundle fields + a label so the
        // skip_serializing_if / BTreeMap mirroring is covered.
        entry.bundle_id = Some(mvm_core::policy::PolicyId("bundle-x".to_string()));
        entry.bundle_version = Some(3);
        entry
            .labels
            .insert("workflow".to_string(), "wf-1".to_string());
        signer.sign_and_emit(&entry).await.unwrap();
        // A checkpoint.forked entry carrying content-address labels. These ride
        // opaquely inside the signed bytes as ordinary BTreeMap labels, so the
        // wasm mirror must accept them with no change to its MirrorEntry shape.
        let mut forked = make_entry("tenant-a", "checkpoint.forked");
        forked.labels.insert(
            "parent_digest".to_string(),
            format!("sha256:{}", "b".repeat(64)),
        );
        forked.labels.insert(
            "child_digest".to_string(),
            format!("sha256:{}", "c".repeat(64)),
        );
        signer.sign_and_emit(&forked).await.unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "plan.failed"))
            .await
            .unwrap();

        let content = std::fs::read_to_string(signer.tenant_path("tenant-a")).unwrap();
        let verified = mvm_contract::verify::verify_audit_chain_bytes(&content, &vk)
            .expect("mvm-contract's verifier must accept a chain mvm-supervisor wrote");
        assert_eq!(verified.count, 3);
        assert_eq!(verified.entries[0].event, "plan.launched");
        assert_eq!(verified.entries[0].tenant, "tenant-a");
        assert_eq!(verified.entries[1].event, "checkpoint.forked");

        // The digest label VALUES must survive the wasm mirror intact (they are
        // exactly what chain-anchored lineage verification reads back). Parse the
        // forked line through the mirror's own SignedEnvelope and assert the
        // labels round-trip.
        let forked_line = content.lines().nth(1).expect("second entry present");
        let mirrored: mvm_contract::verify::SignedEnvelope =
            serde_json::from_str(forked_line).expect("mirror parses the forked entry");
        assert_eq!(
            mirrored
                .entry
                .labels
                .get("parent_digest")
                .map(String::as_str),
            Some(format!("sha256:{}", "b".repeat(64)).as_str())
        );
        assert_eq!(
            mirrored
                .entry
                .labels
                .get("child_digest")
                .map(String::as_str),
            Some(format!("sha256:{}", "c".repeat(64)).as_str())
        );

        // And it must reject a tampered stream just like the native path. An
        // in-place edit reaches the readable entry but not the base64 bytes
        // beside it, so the two stop agreeing — a sharper refusal than a bad
        // signature, and the same verdict both verifiers now reach.
        let tampered = content.replacen("plan.launched", "plan.hijacked", 1);
        assert_eq!(
            mvm_contract::verify::verify_audit_chain_bytes(&tampered, &vk).unwrap_err(),
            mvm_contract::verify::AuditVerifyError::EntryCanonicalMismatch { line: 0 }
        );
        let tampered_path = dir.path().join("tampered.jsonl");
        std::fs::write(&tampered_path, &tampered).unwrap();
        assert!(
            matches!(
                verify_audit_chain(&tampered_path, &vk),
                Err(VerifyError::EntryCanonicalMismatch { line: 0 })
            ),
            "the host verifier must reach the same verdict as the wasm one"
        );
    }

    #[tokio::test]
    async fn tampering_with_entry_breaks_signature() {
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let vk = key.verifying_key();
        let signer = FileAuditSigner::open(key, dir.path()).unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "real-event"))
            .await
            .unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "real-event-2"))
            .await
            .unwrap();

        // Flip a byte in the first line's `event` field. The edit lands in the
        // readable entry; the base64 copy of the signed bytes beside it is
        // untouched, so the line is refused for the two disagreeing — which
        // names the tamper more precisely than a bad signature would.
        let path = signer.tenant_path("tenant-a");
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replacen("real-event", "fake-event", 1);
        std::fs::write(&path, tampered).unwrap();

        let err = verify_audit_chain(&path, &vk).expect_err("tamper must break verify");
        match err {
            VerifyError::EntryCanonicalMismatch { line } => assert_eq!(line, 0),
            other => panic!("expected EntryCanonicalMismatch at line 0, got {other:?}"),
        }
    }

    /// A forger who rewrites *both* copies consistently still cannot sign
    /// them. The disagreement check is a sharper diagnostic, not the security
    /// boundary — the signature is.
    #[tokio::test]
    async fn a_consistently_rewritten_line_still_fails_the_signature() {
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let vk = key.verifying_key();
        let signer = FileAuditSigner::open(key, dir.path()).unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "real-event"))
            .await
            .unwrap();

        let path = signer.tenant_path("tenant-a");
        let content = std::fs::read_to_string(&path).unwrap();
        let mut envelope: SignedEnvelope = serde_json::from_str(content.trim()).unwrap();
        envelope.entry.event = "fake-event".to_string();
        envelope.canonical =
            Some(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&envelope.entry).unwrap()));
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&envelope).unwrap()),
        )
        .unwrap();

        match verify_audit_chain(&path, &vk).expect_err("a forgery must not verify") {
            VerifyError::SignatureInvalid { line } => assert_eq!(line, 0),
            other => panic!("expected SignatureInvalid at line 0, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn deleting_a_middle_line_breaks_chain() {
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let vk = key.verifying_key();
        let signer = FileAuditSigner::open(key, dir.path()).unwrap();
        for i in 0..3 {
            signer
                .sign_and_emit(&make_entry("tenant-a", &format!("e-{i}")))
                .await
                .unwrap();
        }
        let path = signer.tenant_path("tenant-a");
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        // Drop the middle line — the third line now claims a prev_hash
        // computed over the (now-missing) second line.
        let truncated = format!("{}\n{}\n", lines[0], lines[2]);
        std::fs::write(&path, truncated).unwrap();

        let err = verify_audit_chain(&path, &vk).expect_err("drop must break chain");
        match err {
            VerifyError::PrevHashMismatch { line } => assert_eq!(line, 1),
            other => panic!("expected PrevHashMismatch at line 1, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn restart_resumes_chain_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let vk = key.verifying_key();

        {
            let signer = FileAuditSigner::open(key.clone(), dir.path()).unwrap();
            signer
                .sign_and_emit(&make_entry("tenant-a", "before-restart"))
                .await
                .unwrap();
        }
        // Drop signer, open a fresh one with the same key + dir.
        let signer2 = FileAuditSigner::open(key, dir.path()).unwrap();
        signer2
            .sign_and_emit(&make_entry("tenant-a", "after-restart"))
            .await
            .unwrap();

        // Both lines should still verify as one continuous chain.
        let count = verify_audit_chain(&signer2.tenant_path("tenant-a"), &vk).unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn separate_tenants_have_independent_chains() {
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let vk = key.verifying_key();
        let signer = FileAuditSigner::open(key, dir.path()).unwrap();

        signer
            .sign_and_emit(&make_entry("tenant-a", "e1"))
            .await
            .unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-b", "e1"))
            .await
            .unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "e2"))
            .await
            .unwrap();

        let count_a = verify_audit_chain(&signer.tenant_path("tenant-a"), &vk).unwrap();
        let count_b = verify_audit_chain(&signer.tenant_path("tenant-b"), &vk).unwrap();
        assert_eq!(count_a, 2);
        assert_eq!(count_b, 1);
    }

    #[tokio::test]
    async fn fixed_file_destination_writes_exact_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom-audit.jsonl");
        let key = fresh_key();
        let vk = key.verifying_key();
        let signer = FileAuditSigner::open_file(key, &path).unwrap();

        signer
            .sign_and_emit(&make_entry("tenant-a", "e1"))
            .await
            .unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "e2"))
            .await
            .unwrap();

        assert!(path.exists(), "fixed file destination must be literal");
        assert_eq!(signer.tenant_path("tenant-a"), path);
        let count = verify_audit_chain(&path, &vk).unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn verifier_rejects_wrong_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let signer = FileAuditSigner::open(fresh_key(), dir.path()).unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "e1"))
            .await
            .unwrap();

        let other_vk = fresh_key().verifying_key();
        let err = verify_audit_chain(&signer.tenant_path("tenant-a"), &other_vk)
            .expect_err("wrong key must fail");
        assert!(matches!(err, VerifyError::SignatureInvalid { line: 0 }));
    }

    /// Cross-instance race regression.
    ///
    /// Simulates the "two `mvm-libkrun-supervisor` processes for the
    /// same tenant" race by constructing two independent
    /// `FileAuditSigner` instances pointed at the same audit dir,
    /// sharing the same signing key (one per host), and interleaving
    /// their writes from concurrent tokio tasks. Without the flock
    /// precursor each instance's in-memory cursor cache would let
    /// both append using the same stale `prev_hash`, breaking the
    /// chain at verify time. With flock, every write re-reads the
    /// chain tail under an exclusive lock — the chain stays valid.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn flock_serializes_two_signer_instances_on_same_tenant_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let vk = key.verifying_key();

        // Two signer instances over the same dir — like two processes.
        let signer_a = std::sync::Arc::new(FileAuditSigner::open(key.clone(), dir.path()).unwrap());
        let signer_b = std::sync::Arc::new(FileAuditSigner::open(key, dir.path()).unwrap());

        const N: usize = 50;
        let a = signer_a.clone();
        let task_a = tokio::spawn(async move {
            for i in 0..N {
                a.sign_and_emit(&make_entry("tenant-shared", &format!("a-{i}")))
                    .await
                    .unwrap();
            }
        });
        let b = signer_b.clone();
        let task_b = tokio::spawn(async move {
            for i in 0..N {
                b.sign_and_emit(&make_entry("tenant-shared", &format!("b-{i}")))
                    .await
                    .unwrap();
            }
        });
        task_a.await.unwrap();
        task_b.await.unwrap();

        // Chain must verify cleanly: all 2 * N envelopes link
        // correctly and every signature checks.
        let path = signer_a.tenant_path("tenant-shared");
        let count = verify_audit_chain(&path, &vk)
            .expect("chain must verify under concurrent two-instance writers");
        assert_eq!(
            count,
            2 * N,
            "all entries must land — flock serializes writers, no drops"
        );
    }

    /// The key handed to operators has to be the key the chain was signed
    /// with. Returning a default instead survived every test: nothing
    /// asked this accessor to agree with the signer, so the audit chain
    /// could have been verified against a key that signed nothing.
    #[test]
    fn the_published_verifying_key_is_the_one_the_chain_was_signed_with() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let key = fresh_key();
        let expected = key.verifying_key();
        let signer = FileAuditSigner::open(key, tmp.path()).expect("open signer");

        assert_eq!(
            signer.verifying_key().to_bytes(),
            expected.to_bytes(),
            "the published key must be the signing key's own public half"
        );
        assert_ne!(
            signer.verifying_key().to_bytes(),
            ed25519_dalek::VerifyingKey::default().to_bytes(),
            "a default key verifies nothing this signer ever wrote"
        );

        // Two signers must not publish the same key, which a constant
        // return would make them do.
        let other_tmp = tempfile::tempdir().expect("tempdir");
        let other = FileAuditSigner::open(fresh_key(), other_tmp.path()).expect("open signer");
        assert_ne!(
            signer.verifying_key().to_bytes(),
            other.verifying_key().to_bytes()
        );
    }

    /// Every completed append leaves the stream terminated, which is what
    /// makes "ends without a newline" a reliable truncation signal rather
    /// than a coincidence of the last entry's content.
    #[tokio::test]
    async fn every_append_lands_terminated() {
        let dir = tempfile::tempdir().unwrap();
        let signer = FileAuditSigner::open(fresh_key(), dir.path()).unwrap();
        for event in ["plan.verified", "plan.admitted", "plan.launched"] {
            signer
                .sign_and_emit(&make_entry("tenant-a", event))
                .await
                .unwrap();
        }

        let content = std::fs::read_to_string(signer.tenant_path("tenant-a")).unwrap();
        assert!(
            content.ends_with('\n'),
            "a completed append must leave the record terminated on disk"
        );
        assert_eq!(content.lines().count(), 3);
    }

    /// A crash between the record and its terminator must not be able to
    /// masquerade as tampering, and must not be silently extended.
    ///
    /// Before the single-`write_all` change this was reachable in production:
    /// `writeln!` emitted the record and the newline as separate syscalls.
    /// The torn state is simulated here because a real interleaving is not
    /// deterministically reproducible.
    #[tokio::test]
    async fn a_torn_tail_is_refused_not_chained_onto() {
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let verifying = key.verifying_key();
        let signer = FileAuditSigner::open(key, dir.path()).unwrap();
        signer
            .sign_and_emit(&make_entry("tenant-a", "plan.verified"))
            .await
            .unwrap();

        // Simulate the crash: append a record that never got its terminator.
        let path = signer.tenant_path("tenant-a");
        let mut torn = std::fs::read_to_string(&path).unwrap();
        torn.push_str(r#"{"entry":{"event":"plan.admi"#);
        std::fs::write(&path, &torn).unwrap();

        // The verifier names it truncation, not a bad signature and not a
        // chain break — an operator has to be able to tell a crash from an
        // edit.
        let err = verify_audit_chain(&path, &verifying).expect_err("torn tail must not verify");
        assert!(
            matches!(err, VerifyError::TruncatedTail { line: 1 }),
            "expected TruncatedTail at the partial second record, got {err:?}"
        );

        // And the signer refuses to extend the chain from a partial record
        // rather than hashing the fragment as though it were an entry.
        let err = signer
            .sign_and_emit(&make_entry("tenant-a", "plan.launched"))
            .await
            .expect_err("must not append onto a torn tail");
        assert!(
            matches!(err, AuditError::TruncatedTail { .. }),
            "expected TruncatedTail, got {err:?}"
        );
    }

    /// The truncation check must not fire on healthy files — otherwise it
    /// would refuse every append and the test above would pass vacuously.
    #[tokio::test]
    async fn an_intact_chain_still_verifies_and_extends() {
        let dir = tempfile::tempdir().unwrap();
        let key = fresh_key();
        let verifying = key.verifying_key();
        let signer = FileAuditSigner::open(key, dir.path()).unwrap();
        for event in ["plan.verified", "plan.admitted"] {
            signer
                .sign_and_emit(&make_entry("tenant-a", event))
                .await
                .unwrap();
        }
        let path = signer.tenant_path("tenant-a");
        assert_eq!(verify_audit_chain(&path, &verifying).unwrap(), 2);

        signer
            .sign_and_emit(&make_entry("tenant-a", "plan.launched"))
            .await
            .expect("an intact chain must still accept appends");
        assert_eq!(verify_audit_chain(&path, &verifying).unwrap(), 3);
    }

    /// Chain files are appended to on every admission, so the cursor restore
    /// runs constantly. These pin the backwards scan against the whole-file
    /// read it replaced: same answer, including on the cases where "read less"
    /// is exactly how you get a wrong one.
    mod cursor_tail {
        use super::*;

        fn cursor_of(bytes: &[u8]) -> Result<[u8; 32], AuditError> {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("chain.jsonl");
            std::fs::write(&path, bytes).expect("write chain");
            FileAuditSigner::open(fresh_key(), dir.path())
                .expect("signer")
                .restore_cursor(&path)
        }

        #[test]
        fn the_tail_scan_agrees_with_hashing_the_last_line() {
            let body = b"{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n";
            assert_eq!(cursor_of(body).expect("cursor"), hash_line(b"{\"c\":3}"));
        }

        #[test]
        fn a_record_longer_than_the_window_widens_instead_of_guessing() {
            // The failure this guards: a window that lands inside the final
            // record sees no terminator, and a scan that treated that as
            // "first record in the file" would chain onto a fragment.
            let huge = "x".repeat(usize::try_from(CURSOR_TAIL_WINDOW).unwrap() * 3);
            let last = format!("{{\"big\":\"{huge}\"}}");
            let body = format!("{{\"a\":1}}\n{last}\n");
            assert_eq!(
                cursor_of(body.as_bytes()).expect("cursor"),
                hash_line(last.as_bytes()),
            );
        }

        #[test]
        fn a_single_record_shorter_than_the_window_is_still_found() {
            let body = b"{\"only\":1}\n";
            assert_eq!(cursor_of(body).expect("cursor"), hash_line(b"{\"only\":1}"));
        }

        #[test]
        fn a_missing_terminator_is_truncation_not_a_shorter_chain() {
            let err = cursor_of(b"{\"a\":1}\n{\"partial\":").expect_err("must refuse");
            assert!(
                matches!(err, AuditError::TruncatedTail { .. }),
                "a crash mid-append must stay distinguishable from tampering, got {err:?}",
            );
        }

        #[test]
        fn an_empty_or_blank_file_restores_to_genesis() {
            assert_eq!(cursor_of(b"").expect("cursor"), [0u8; 32]);
            assert_eq!(cursor_of(b"\n\n").expect("cursor"), [0u8; 32]);
        }

        #[test]
        fn trailing_blank_lines_do_not_hide_the_last_record() {
            let body = b"{\"a\":1}\n{\"b\":2}\n\n\n";
            assert_eq!(cursor_of(body).expect("cursor"), hash_line(b"{\"b\":2}"));
        }

        #[test]
        fn a_multibyte_character_spanning_the_window_edge_is_not_corrupted() {
            // The window starts at an arbitrary byte offset. `\n` is ASCII and
            // cannot appear inside a UTF-8 sequence, so the extracted line is
            // still whole — this pins that reasoning.
            let pad = "é".repeat(usize::try_from(CURSOR_TAIL_WINDOW).unwrap());
            let last = "{\"tail\":\"ünïcøde\"}";
            let body = format!("{{\"pad\":\"{pad}\"}}\n{last}\n");
            assert_eq!(
                cursor_of(body.as_bytes()).expect("cursor"),
                hash_line(last.as_bytes()),
            );
        }
    }

    /// Batching exists to cut fsyncs, not durability. These pin the parts that
    /// would make it a weakening rather than an optimization.
    mod barrier_batching {
        use super::*;

        #[test]
        fn a_batch_writes_every_record_and_leaves_none_unsynced() {
            let dir = tempfile::tempdir().expect("tempdir");
            let signer = FileAuditSigner::open(fresh_key(), dir.path()).unwrap();
            let path = dir.path().join("local.jsonl");

            signer.begin_batch();
            for event in ["plan.admitted", "decision_record", "plan.grant_required"] {
                signer
                    .append_locked(&path, &make_entry("local", event))
                    .expect("append");
            }
            // Held, not skipped: every barrier is still owed a sync.
            assert_eq!(
                signer.pending_sync.lock().unwrap().len(),
                1,
                "the batch should owe exactly one file a sync",
            );
            signer.end_batch().expect("flush");
            assert!(
                signer.pending_sync.lock().unwrap().is_empty(),
                "ending a batch must leave nothing owed",
            );

            let written = std::fs::read_to_string(&path).expect("read chain");
            assert_eq!(
                written.lines().filter(|l| !l.is_empty()).count(),
                3,
                "batching must not drop records",
            );
        }

        #[test]
        fn a_batch_chain_still_verifies_end_to_end() {
            // The records are written the same way and chained the same way;
            // only the fsync count changes. If batching perturbed the chain at
            // all, the verifier is what would notice.
            let dir = tempfile::tempdir().expect("tempdir");
            let key = fresh_key();
            let verifying = key.verifying_key();
            let signer = FileAuditSigner::open(key, dir.path()).unwrap();
            let path = dir.path().join("local.jsonl");

            signer.begin_batch();
            for event in ["plan.admitted", "decision_record", "plan.grant_required"] {
                signer
                    .append_locked(&path, &make_entry("local", event))
                    .expect("append");
            }
            signer.end_batch().expect("flush");

            verify_audit_chain(&path, &verifying).expect("a batched chain must verify");
        }

        #[test]
        fn a_barrier_outside_a_batch_still_syncs_immediately() {
            // The batch is a scope, not a mode switch. Once it closes, the
            // default is back to syncing every barrier as it lands.
            let dir = tempfile::tempdir().expect("tempdir");
            let signer = FileAuditSigner::open(fresh_key(), dir.path()).unwrap();
            let path = dir.path().join("local.jsonl");

            signer.begin_batch();
            signer
                .append_locked(&path, &make_entry("local", "plan.admitted"))
                .expect("append");
            signer.end_batch().expect("flush");

            signer
                .append_locked(&path, &make_entry("local", "plan.admitted"))
                .expect("append");
            assert!(
                signer.pending_sync.lock().unwrap().is_empty(),
                "a barrier after the batch closed must have synced on the spot",
            );
        }

        #[test]
        fn a_deferrable_event_is_unaffected_by_batching() {
            let dir = tempfile::tempdir().expect("tempdir");
            let signer = FileAuditSigner::open(fresh_key(), dir.path()).unwrap();
            let path = dir.path().join("local.jsonl");
            signer
                .append_locked(&path, &make_entry("local", "plan.launched"))
                .expect("append");
            assert_eq!(
                signer.pending_sync.lock().unwrap().len(),
                1,
                "a deferrable event defers with or without a batch",
            );
        }
    }
}
