//! Expiry for a quarantined workload's mailbox store after its VM and helper
//! are gone.
//!
//! A quarantined workload never launches again at its epoch, so no helper will
//! ever expire what its store still holds. This opens the store the way the
//! helper does, under the custody record the host signed at the production
//! launch, and commits only expiry and compaction, each marked retention-only
//! and ordered by the workload ledger.

use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxAddress};
use mvm_core::crypto::aead::Key;
use mvm_core::mailbox::journal::{FileJournalAnchor, MailboxJournal};

use super::{LOCAL_JOURNAL_LIMITS, load_admitted_plan, vm_is_alive, workload_is_quarantined};
use crate::mailbox_commit::{
    Coordinated, CoordinatorSocket, Destination, OrderingFlags, coordinate_with, require_reached,
    stop_if_unordered,
};
use crate::mailbox_custody::RetainedMailboxKeys;
use crate::mailbox_launch::derive_launch_keys;

/// Journal commits one call makes before it reports the store unfinished.
const MAX_COMMITS: u64 = 4096;

/// What one expiry call did to a quarantined workload's mailbox store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxExpiry {
    /// Messages past their deadline that were expired.
    pub expired: u64,
    /// Compactions that retired records past their signed retention.
    pub compactions: u64,
    /// False when the call stopped at its commit bound with work still due;
    /// call again. True says nothing is due now, not that the store is empty:
    /// a record whose deadline or retention ends later needs a later call.
    pub complete: bool,
}

/// Where one VM's mailbox store and its authorities live.
pub(super) struct Store<'a> {
    pub(super) keys_dir: &'a Path,
    pub(super) home: &'a Path,
    pub(super) state_dir: &'a Path,
    pub(super) coordinator: PathBuf,
}

/// Expire and compact what is due in the mailbox store of the stopped VM
/// `vm_name`, whose workload is quarantined.
///
/// # Errors
///
/// `PermissionDenied` when the workload is not quarantined or the ledger
/// refuses a commit, `ResourceBusy` while the VM or its mailbox helper is
/// alive, `Unsupported` for an actor mailbox, and any failure to open the
/// store. A commit whose outcome stayed unknown is an error; calling again
/// reconciles it.
pub fn expire_quarantined_mailbox(vm_name: &str) -> Result<MailboxExpiry> {
    let home = PathBuf::from(mvm_core::config::mvm_home());
    let state_dir = mvm_core::config::vm_state_dir(vm_name);
    let keys_dir = mvm_core::config::mvm_keys_dir();
    // Refuse before starting a coordinator for a store this cannot touch.
    preflight(&home, Path::new(&state_dir))?;
    let coordinator = crate::policy_generation::coordinator::ensure(&home).map_err(Error::other)?;
    expire(&Store {
        keys_dir: &keys_dir,
        home: &home,
        state_dir: Path::new(&state_dir),
        coordinator,
    })
}

struct Admitted {
    plan: mvm_core::plan::ExecutionPlan,
    epoch: ExecutionEpoch,
}

fn preflight(home: &Path, state_dir: &Path) -> Result<Admitted> {
    let plan = load_admitted_plan(state_dir)?;
    if plan.workflow.is_some() {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "an actor mailbox has no offline expiry",
        ));
    }
    let epoch = ExecutionEpoch::new(plan.execution_epoch).map_err(Error::other)?;
    if !workload_is_quarantined(home, &plan.workload.0, epoch) {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "the workload is not quarantined; its next launch expires its mailbox",
        ));
    }
    let helper = mvm_vmm::host::process_liveness::read_pid_file(
        &state_dir.join(mvm_vmm::host::vm_helpers::MAILBOX_PID_FILE),
    );
    if vm_is_alive(state_dir) || helper.is_some_and(mvm_vmm::host::process_liveness::pid_is_alive) {
        return Err(Error::new(
            ErrorKind::ResourceBusy,
            "the VM or its mailbox helper is still running; stop the VM first",
        ));
    }
    Ok(Admitted { plan, epoch })
}

pub(super) fn expire(store: &Store<'_>) -> Result<MailboxExpiry> {
    let Admitted { plan, epoch } = preflight(store.home, store.state_dir)?;
    let vm_name = store
        .state_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "mailbox VM identity is invalid"))?;
    let grant = plan
        .mailbox
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "the stored plan grants no mailbox"))?;
    let retention = grant.retention.ok_or_else(|| {
        Error::new(
            ErrorKind::NotFound,
            "the mailbox has no signed retention, so no production store",
        )
    })?;
    // The per-launch secret is gone with the VM; nothing here seals or opens a
    // frame, so a throwaway one stands in for it.
    let keys = derive_launch_keys(store.keys_dir, &grant, &Key::random())?;
    let address = MailboxAddress {
        mailbox: grant.mailbox,
        ..keys.address()
    };
    let retained = RetainedMailboxKeys::open_bound(store.keys_dir, &plan, vm_name, address)
        .map_err(Error::other)?;
    let paths = retained
        .storage_paths(store.keys_dir)
        .map_err(Error::other)?;
    let (signer, _, _) = keys.with_retained(&retained)?.durable_material();
    let (commit_key, _) =
        mvm_core::crypto::ed25519_keypair::load_existing(&paths.commit_key, &paths.commit_key_pub)
            .map_err(Error::other)?;
    let flags = OrderingFlags::default();
    flags.retention.store(true, Ordering::SeqCst);
    let Coordinated {
        anchor,
        refused,
        unknown,
        enrolled,
        ..
    } = coordinate_with(
        FileJournalAnchor::open(&paths.anchor, address, retained.anchor_key())
            .map_err(Error::other)?,
        Arc::new(CoordinatorSocket(store.coordinator.clone())),
        Destination {
            id: paths.destination,
            workload: plan.workload.0.clone(),
            epoch,
            key: commit_key,
        },
        flags,
    )
    .map_err(Error::other)?;
    let ordered = |error: mvm_core::mailbox::journal::JournalError| {
        stop_if_unordered(&refused, &unknown)
            .err()
            .unwrap_or_else(|| match error {
                // The journal admits one writer, so a second call lands here.
                mvm_core::mailbox::journal::JournalError::Busy => Error::new(
                    ErrorKind::ResourceBusy,
                    "another writer holds this mailbox store",
                ),
                other => Error::other(other),
            })
    };
    let mut journal = MailboxJournal::open_local_with_custody(
        &paths.journal,
        retained.history_reference(),
        signer.verifying_key(),
        LOCAL_JOURNAL_LIMITS,
        &retained,
        &anchor,
        retention,
    )
    .map_err(ordered)?;
    require_reached(&anchor, &enrolled).map_err(Error::other)?;
    let now = crate::mailbox_launch::actor_template::current_time_ms()?;
    let mut done = MailboxExpiry {
        expired: 0,
        compactions: 0,
        complete: false,
    };
    while done.expired + done.compactions < MAX_COMMITS {
        if journal.local_compaction_due(now).map_err(ordered)? {
            journal
                .compact_local(now, &signer, &anchor)
                .map_err(ordered)?;
            done.compactions += 1;
        }
        if journal
            .expire_next(now, &signer, |tip| anchor.advance(tip))
            .map_err(ordered)?
            .is_none()
        {
            done.complete = !journal.local_compaction_due(now).map_err(ordered)?;
            break;
        }
        done.expired += 1;
    }
    Ok(done)
}
