//! Fixture journal, NOT MailboxJournal's format or admission implementation.
//! All reconstructed handles read disk. Shared locks model one process only.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use mvm_core::atomic_io::{atomic_write_durable, sync_dir};
use mvm_core::crypto::aead::{self, Key};
use mvm_hostd::supervisor::audit::audit_file::{FileAuditSigner, verify_chain_bytes};
use mvm_hostd::supervisor::audit::signer::{AuditSigner, PlanAuditEntry};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CAPACITY: usize = 4;
pub const MAX_CIPHERTEXT: usize = 256;
pub const MAX_AUDIT_BYTES: usize = 32 * 1024;
const MAX_STATE_BYTES: usize = 32 * 1024;
pub const PLAINTEXT: &str = "private coordination payload";
const HISTORY: [u8; 16] = [17; 16];

type Result<T> = std::result::Result<T, &'static str>;
type Evidence = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Call,
    Reply,
    Cast,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endpoint {
    Host,
    VmA,
    VmB,
    AuditService,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    Accepted,
    Expired,
}

impl Event {
    fn name(self) -> &'static str {
        match self {
            Self::Accepted => "mailbox.accepted",
            Self::Expired => "mailbox.expired",
        }
    }
}

/// Fixture inputs stand for an already-authorized transition, not a new policy gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub message: u64,
    pub kind: Kind,
    pub sender: Endpoint,
    pub recipient: Endpoint,
    pub event: Event,
    pub ciphertext: Vec<u8>,
}

impl Request {
    pub fn sample(message: u64) -> Self {
        Self {
            message,
            kind: Kind::Call,
            sender: Endpoint::VmA,
            recipient: Endpoint::VmB,
            event: Event::Accepted,
            ciphertext: aead::seal(&Key::from_bytes([23; 32]), PLAINTEXT.as_bytes(), b"fixture"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    None,
    BeforeCommit,
    AfterCommit,
    AfterAudit,
    AuditSyncUnknown,
    AfterCompletion,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Refused(&'static str),
    Pending(&'static str),
    Complete(Evidence),
}

impl Outcome {
    pub fn complete(self) -> Evidence {
        match self {
            Self::Complete(evidence) => evidence,
            other => panic!("expected durable completion, got {other:?}"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Record {
    request: Request,
    cursor: u64,
    previous: Evidence,
    hash: Evidence,
    obligation: PlanAuditEntry,
    completion: Option<Evidence>,
}

#[derive(Clone, Serialize, Deserialize)]
struct State {
    history: [u8; 16],
    records: Vec<Record>,
}

#[derive(Default)]
struct Locks {
    journal: Mutex<()>,
    publisher: Mutex<()>,
    sync_repairs: AtomicUsize,
}

pub struct Fixture {
    dir: tempfile::TempDir,
    locks: Arc<Locks>,
}

impl Fixture {
    pub fn new() -> Self {
        let fixture = Self {
            dir: tempfile::tempdir().unwrap(),
            locks: Arc::new(Locks::default()),
        };
        fixture
            .open()
            .save(&State {
                history: HISTORY,
                records: vec![],
            })
            .unwrap();
        fixture
    }

    pub fn open(&self) -> Store {
        Store {
            root: self.dir.path().to_owned(),
            locks: self.locks.clone(),
        }
    }

    pub fn audit_path(&self) -> PathBuf {
        self.dir.path().join("audit.jsonl")
    }

    pub fn snapshot_bytes(&self) -> Vec<u8> {
        std::fs::read(self.dir.path().join("journal.json")).unwrap()
    }

    pub fn corrupt_completion(&self) {
        let _journal = self.locks.journal.lock().unwrap();
        let store = self.open();
        let mut state = store.load().unwrap();
        state.records[0].completion.as_mut().unwrap()[0] ^= 1;
        store.save(&state).unwrap();
    }

    pub fn sync_repairs(&self) -> usize {
        self.locks.sync_repairs.load(Ordering::SeqCst)
    }

    pub fn append_signed(&self, entry: &PlanAuditEntry) {
        self.append(entry, [7; 32]);
    }

    pub fn append_with_wrong_key(&self, entry: &PlanAuditEntry) {
        self.append(entry, [8; 32]);
    }

    fn append(&self, entry: &PlanAuditEntry, seed: [u8; 32]) {
        let _guard = self.locks.publisher.lock().unwrap();
        let signer =
            FileAuditSigner::open_file(SigningKey::from_bytes(&seed), self.audit_path()).unwrap();
        runtime().block_on(signer.sign_and_emit(entry)).unwrap();
    }

    pub fn assert_journal_available_while_publication_waits(&self, request: Request) {
        let publisher = self.locks.publisher.lock().unwrap();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                self.open()
                    .submit_with(&request, Stop::None, || tx.send(()).unwrap())
            });
            rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            // The worker has jointly committed and is about to wait for publication.
            let journal = self
                .locks
                .journal
                .try_lock()
                .expect("audit wait must release journal");
            assert_eq!(self.open().load().unwrap().records.len(), 2);
            drop(journal);
            drop(publisher);
            worker.join().unwrap().complete();
        });
    }
}

/// Only paths and synchronization, never a cached journal or audit cursor.
pub struct Store {
    root: PathBuf,
    locks: Arc<Locks>,
}

pub fn commitment(ciphertext: &[u8]) -> String {
    hex::encode(Sha256::digest(ciphertext))
}

pub fn plaintext_hash() -> String {
    commitment(PLAINTEXT.as_bytes())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|_| "read unavailable")?;
    let mut bytes = Vec::new();
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "read failed")?;
    if bytes.len() > maximum {
        return Err("read bound");
    }
    Ok(bytes)
}

fn transition_hash(request: &Request, cursor: u64, previous: Evidence) -> Evidence {
    Sha256::digest(serde_json::to_vec(&(HISTORY, cursor, previous, request)).unwrap()).into()
}

fn obligation(request: &Request, cursor: u64, hash: Evidence) -> PlanAuditEntry {
    let labels = BTreeMap::from([
        ("history".into(), hex::encode(HISTORY)),
        ("cursor".into(), cursor.to_string()),
        ("transition_hash".into(), hex::encode(hash)),
        (
            "transition_id".into(),
            format!(
                "{}:{cursor}:{}:{}",
                hex::encode(HISTORY),
                hex::encode(hash),
                request.event.name()
            ),
        ),
        ("message_id".into(), request.message.to_string()),
        ("kind".into(), format!("{:?}", request.kind)),
        ("sender".into(), format!("{:?}", request.sender)),
        ("recipient".into(), format!("{:?}", request.recipient)),
        (
            "ciphertext_commitment".into(),
            commitment(&request.ciphertext),
        ),
    ]);
    PlanAuditEntry {
        timestamp: "2026-01-01T00:00:00Z".parse().unwrap(),
        tenant: mvm_core::plan::TenantId("fixture".into()),
        plan_id: mvm_core::plan::PlanId("fixture-plan".into()),
        plan_version: 1,
        bundle_id: None,
        bundle_version: None,
        image_name: "fixture".into(),
        image_sha256: "0".repeat(64),
        event: request.event.name().into(),
        caller_commitment: None,
        labels,
    }
}

fn same_entry(left: &PlanAuditEntry, right: &PlanAuditEntry) -> bool {
    serde_json::to_vec(left).unwrap() == serde_json::to_vec(right).unwrap()
}

impl Store {
    fn load(&self) -> Result<State> {
        let bytes = read_bounded(&self.root.join("journal.json"), MAX_STATE_BYTES)?;
        let state: State = serde_json::from_slice(&bytes).map_err(|_| "invalid journal")?;
        if state.history != HISTORY || state.records.len() > CAPACITY {
            return Err("invalid history");
        }
        let mut previous = [0; 32];
        for (index, record) in state.records.iter().enumerate() {
            let cursor = index as u64 + 1;
            let hash = transition_hash(&record.request, cursor, previous);
            if record.request.ciphertext.len() > MAX_CIPHERTEXT
                || record.cursor != cursor
                || record.previous != previous
                || record.hash != hash
                || !same_entry(
                    &record.obligation,
                    &obligation(&record.request, cursor, hash),
                )
            {
                return Err("invalid transition");
            }
            previous = hash;
        }
        Ok(state)
    }

    fn save(&self, state: &State) -> Result<()> {
        let bytes = serde_json::to_vec(state).map_err(|_| "encode journal")?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err("journal bound");
        }
        atomic_write_durable(&self.root.join("journal.json"), &bytes)
            .map_err(|_| "journal sync unknown")
    }

    pub fn record_count(&self) -> usize {
        let _guard = self.locks.journal.lock().unwrap();
        self.load().unwrap().records.len()
    }

    pub fn obligation(&self, index: usize) -> PlanAuditEntry {
        let _guard = self.locks.journal.lock().unwrap();
        self.load().unwrap().records[index].obligation.clone()
    }

    pub fn submit(&self, request: &Request, stop: Stop) -> Outcome {
        self.submit_with(request, stop, || {})
    }

    fn submit_with(&self, request: &Request, stop: Stop, before_publish: impl FnOnce()) -> Outcome {
        if request.ciphertext.len() > MAX_CIPHERTEXT {
            return Outcome::Refused("oversized");
        }
        let record =
            {
                let _journal = self.locks.journal.lock().unwrap();
                let mut state = match self.load() {
                    Ok(state) => state,
                    Err(reason) => return Outcome::Pending(reason),
                };
                if let Some(record) = state.records.iter().find(|r| {
                    r.request.message == request.message && r.request.event == request.event
                }) {
                    if record.request != *request {
                        return Outcome::Refused("request conflict");
                    }
                    record.clone()
                } else {
                    if state.records.len() >= CAPACITY {
                        return Outcome::Refused("full");
                    }
                    let cursor = state.records.len() as u64 + 1;
                    let previous = state.records.last().map_or([0; 32], |r| r.hash);
                    let hash = transition_hash(request, cursor, previous);
                    let record = Record {
                        request: request.clone(),
                        cursor,
                        previous,
                        hash,
                        obligation: obligation(request, cursor, hash),
                        completion: None,
                    };
                    // Dedicated chain: reserve one bounded signed envelope per transition.
                    // Three entry copies plus 1 KiB cover JSON, base64 canonical bytes,
                    // signatures and hashes; completion never appends a second audit line.
                    if serde_json::to_vec(&record.obligation).unwrap().len() * 3 + 1024
                        > MAX_AUDIT_BYTES / CAPACITY
                    {
                        return Outcome::Refused("full");
                    }
                    state.records.push(record.clone());
                    // Reserve worst-case completion bytes for every accepted record now.
                    let mut reserved = state.clone();
                    for record in &mut reserved.records {
                        record.completion = Some([255; 32]);
                    }
                    if serde_json::to_vec(&reserved).unwrap().len() > MAX_STATE_BYTES {
                        return Outcome::Refused("full");
                    }
                    if stop == Stop::BeforeCommit {
                        return Outcome::Refused("before commit");
                    }
                    if let Err(reason) = self.save(&state) {
                        return Outcome::Pending(reason);
                    }
                    record
                }
            };
        if stop == Stop::AfterCommit {
            return Outcome::Pending("joint commit");
        }
        before_publish();
        let evidence = match self.publish(&record, stop) {
            Ok(evidence) => evidence,
            Err(reason) => return Outcome::Pending(reason),
        };
        let _journal = self.locks.journal.lock().unwrap();
        let mut state = match self.load() {
            Ok(state) => state,
            Err(reason) => return Outcome::Pending(reason),
        };
        let Some(current) = state.records.iter_mut().find(|r| r.hash == record.hash) else {
            return Outcome::Pending("transition disappeared");
        };
        if current
            .completion
            .is_some_and(|previous| previous != evidence)
        {
            return Outcome::Pending("completion conflict");
        }
        current.completion = Some(evidence);
        // Also re-sync exact completed retries: a previous rename may have succeeded
        // while its directory sync returned an ambiguous error.
        if let Err(reason) = self.save(&state) {
            return Outcome::Pending(reason);
        }
        if stop == Stop::AfterCompletion {
            return Outcome::Pending("response lost");
        }
        Outcome::Complete(evidence)
    }

    fn verified(&self) -> Result<Vec<(PlanAuditEntry, Evidence)>> {
        let path = self.root.join("audit.jsonl");
        let bytes = match File::open(&path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take((MAX_AUDIT_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|_| "audit unavailable")?;
                if bytes.len() > MAX_AUDIT_BYTES {
                    return Err("bounded audit read");
                }
                bytes
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(_) => return Err("audit unavailable"),
        };
        let text = std::str::from_utf8(&bytes).map_err(|_| "corrupt audit")?;
        if text.lines().count() > CAPACITY {
            return Err("bounded audit records");
        }
        let walk = verify_chain_bytes(text, &SigningKey::from_bytes(&[7; 32]).verifying_key())
            .map_err(|_| "corrupt or wrong-key audit")?;
        Ok(walk
            .entries
            .into_iter()
            .zip(
                text.lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(|l| mvm_contract::verify::hash_line(l.as_bytes())),
            )
            .collect())
    }

    fn lookup(&self, record: &Record) -> Result<Option<Evidence>> {
        let entries = self.verified()?;
        let matching: Vec<_> = entries
            .iter()
            .filter(|(entry, _)| {
                entry.labels.get("transition_id") == record.obligation.labels.get("transition_id")
                    || (entry.labels.get("history") == record.obligation.labels.get("history")
                        && entry.labels.get("cursor") == record.obligation.labels.get("cursor")
                        && entry.event == record.obligation.event)
            })
            .collect();
        match matching.as_slice() {
            [] if record.completion.is_none() => Ok(None),
            [] => Err("completed evidence missing"),
            [(entry, evidence)]
                if same_entry(entry, &record.obligation)
                    && record.completion.is_none_or(|prior| prior == *evidence) =>
            {
                Ok(Some(*evidence))
            }
            _ => Err("conflicting audit evidence"),
        }
    }

    fn publish(&self, record: &Record, stop: Stop) -> Result<Evidence> {
        // Dedicated test protocol lock, NOT FileAuditSigner's private sidecar lock.
        // Every fixture writer participates; arbitrary production writers do not.
        let _publisher = self.locks.publisher.lock().unwrap();
        if self.lookup(record)?.is_none() {
            if self.verified()?.len() >= CAPACITY {
                return Err("bounded audit records");
            }
            let signer = FileAuditSigner::open_file(
                SigningKey::from_bytes(&[7; 32]),
                self.root.join("audit.jsonl"),
            )
            .map_err(|_| "audit unavailable")?;
            runtime()
                .block_on(signer.sign_and_emit(&record.obligation))
                .map_err(|_| "audit append unknown")?;
        }
        if matches!(stop, Stop::AfterAudit | Stop::AuditSyncUnknown) {
            return Err("audit outcome unknown");
        }
        let evidence = self.lookup(record)?.ok_or("audit append missing")?;
        // A matching signed line is not proof its earlier sync succeeded.
        File::open(self.root.join("audit.jsonl"))
            .and_then(|f| f.sync_all())
            .map_err(|_| "audit sync unknown")?;
        sync_dir(&self.root).map_err(|_| "audit directory sync unknown")?;
        self.locks.sync_repairs.fetch_add(1, Ordering::SeqCst);
        Ok(evidence)
    }

    pub fn audit_entries(&self) -> Result<Vec<PlanAuditEntry>> {
        let _publisher = self.locks.publisher.lock().unwrap();
        self.verified()
            .map(|entries| entries.into_iter().map(|(entry, _)| entry).collect())
    }

    pub fn visible(&self) -> Result<Vec<Evidence>> {
        let records = {
            let _journal = self.locks.journal.lock().unwrap();
            let state = self.load()?;
            self.save(&state)?;
            state.records
        };
        records
            .iter()
            .filter(|record| record.completion.is_some())
            .map(|record| self.publish(record, Stop::None))
            .collect()
    }
}
