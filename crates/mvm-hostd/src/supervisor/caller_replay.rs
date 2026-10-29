//! Bounded consumed-registration bookkeeping independent of VM teardown.
//! The ledger cannot register a caller: only an already verified cold launch
//! can consume a slot, before any owner or guest is activated.
//!
//! Initialization states: neither file is first use; marker alone refuses;
//! ledger alone preserves consumed entries and can complete initialization with
//! a fresh record; both files must validate. Corruption never authorizes reset.
//! This is crash recovery, not protection against host-controlled rollback.

use anyhow::{Context, Result};
use mvm_core::crypto::entrypoint_delegation::RegistrationChallenge;
use mvm_core::transcript::secure_cleanup::CaptureDirectory;
use mvm_core::{atomic_io, config};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MAX_ENTRIES: usize = 4096;
const MAX_BYTES: usize = 1024 * 1024;
const DOMAIN: &[u8] = b"mvm.entrypoint-caller.consumed.v1\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    commitment: [u8; 32],
    not_after: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u32,
    high_water: u64,
    entries: Vec<Entry>,
}

impl Default for Ledger {
    fn default() -> Self {
        Self {
            version: 1,
            high_water: 0,
            entries: Vec::new(),
        }
    }
}

pub(super) fn consume(caller: &super::RegisteredCaller, now: u64) -> Result<()> {
    consume_challenge(caller.challenge(), now)
}

fn consume_challenge(challenge: &RegistrationChallenge, now: u64) -> Result<()> {
    anyhow::ensure!(
        now >= challenge.binding.not_before && now < challenge.binding.not_after,
        "caller registration is outside its validity window"
    );
    let root = config::mvm_home_strict()?.join("caller-registration");
    match std::fs::symlink_metadata(&root) {
        Ok(metadata) => anyhow::ensure!(
            metadata.file_type().is_dir(),
            "caller replay directory must not be a link"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    config::create_private_dir(&root)?;
    // Reuse the existing private, host-owned, nofollow directory lease. This
    // fixed purpose directory is never removed by runtime VM teardown.
    let lease =
        CaptureDirectory::for_writer(&root).context("caller replay ledger unavailable or busy")?;
    sync_directory_chain(&root)?;
    let path = root.join("ledger.json");
    let initialized = match lease.read_private_member("initialized", 3) {
        Ok(bytes) => {
            anyhow::ensure!(bytes == b"v1\n", "caller replay initialization is invalid");
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let mut ledger = read(&lease, initialized)?;
    anyhow::ensure!(
        now >= ledger.high_water,
        "caller replay clock moved backwards"
    );
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(serde_jcs::to_vec(challenge)?);
    let commitment: [u8; 32] = digest.finalize().into();
    anyhow::ensure!(
        !ledger
            .entries
            .iter()
            .any(|entry| entry.commitment == commitment),
        super::CALLER_REGISTRATION_REPLAY_DENIED
    );
    // Expiry pruning and the high-water advance are one durable transaction.
    // Clock rollback can therefore never revive a registration we pruned.
    ledger.entries.retain(|entry| now < entry.not_after);
    anyhow::ensure!(
        ledger.entries.len() < MAX_ENTRIES,
        "caller replay ledger is full"
    );
    ledger.entries.push(Entry {
        commitment,
        not_after: challenge.binding.not_after,
    });
    ledger.high_water = now;
    let bytes = serde_json::to_vec(&ledger)?;
    anyhow::ensure!(
        bytes.len() <= MAX_BYTES,
        "caller replay ledger exceeds its bound"
    );
    #[cfg(test)]
    crash_at(Phase::BeforeCommit);
    atomic_io::write_private(&path, &bytes).context("caller replay commit failed")?;
    #[cfg(test)]
    crash_at(Phase::AfterLedger);
    if !initialized {
        anyhow::ensure!(
            matches!(
                atomic_io::write_private_new(&root.join("initialized"), b"v1\n")
                    .context("caller replay initialization commit failed")?,
                atomic_io::NewFile::Created
            ),
            "caller replay initialization changed during commit"
        );
    }
    #[cfg(test)]
    crash_at(Phase::AfterCommit);
    Ok(())
}

fn sync_directory_chain(root: &std::path::Path) -> Result<()> {
    // File/inner-directory fsync cannot anchor a newly created directory's own
    // name. Sync the complete canonical ancestor chain, including any newly
    // created MVM home ancestors, before a record can authorize activation.
    let root = std::fs::canonicalize(root)?;
    for directory in root.ancestors() {
        #[cfg(test)]
        if directory != root && FAIL_PARENT_SYNC.with(std::cell::Cell::get) {
            anyhow::bail!("injected caller replay parent directory sync failure");
        }
        atomic_io::sync_dir(directory)
            .map_err(|_| anyhow::anyhow!("caller replay directory durability failed"))?;
        #[cfg(test)]
        SYNCED_DIRECTORIES.with(|paths| paths.borrow_mut().push(directory.to_path_buf()));
    }
    Ok(())
}

fn read(lease: &CaptureDirectory, initialized: bool) -> Result<Ledger> {
    let bytes = match lease.read_private_member("ledger.json", MAX_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if !initialized && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Ledger::default());
        }
        Err(error) => return Err(error.into()),
    };
    let ledger: Ledger = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("caller replay ledger is invalid"))?;
    anyhow::ensure!(
        ledger.version == 1 && ledger.entries.len() <= MAX_ENTRIES,
        "caller replay ledger is invalid"
    );
    let mut seen = std::collections::HashSet::new();
    anyhow::ensure!(
        ledger
            .entries
            .iter()
            .all(|entry| entry.not_after > ledger.high_water && seen.insert(entry.commitment)),
        "caller replay ledger is invalid"
    );
    Ok(ledger)
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    BeforeCommit,
    AfterLedger,
    AfterCommit,
}

#[cfg(test)]
thread_local! {
    static CRASH: std::cell::Cell<Option<Phase>> = const { std::cell::Cell::new(None) };
    static FAIL_PARENT_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static SYNCED_DIRECTORIES: std::cell::RefCell<Vec<std::path::PathBuf>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn crash_at(phase: Phase) {
    if CRASH.with(|selected| selected.get() == Some(phase)) {
        // A real process exit intentionally bypasses Rust destructors.
        std::process::exit(67);
    }
}

#[cfg(test)]
#[path = "caller_replay_tests.rs"]
mod tests;
