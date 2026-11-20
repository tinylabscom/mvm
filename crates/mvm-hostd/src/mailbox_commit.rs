//! Orders a production mailbox destination's journal commits through the
//! workload ledger's owner.
//!
//! The helper prepares and signs a journal record outside any lane. The final
//! step of each commit, the anchor advance, first asks the ledger's owner to
//! move this destination's tip. The owner refuses once the workload is
//! quarantined or replaced, so a containment decision and a destination commit
//! have one order, and a refused helper stops serving.

use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use ed25519_dalek::SigningKey;
use mvm_core::host_interface::{
    ExecutionEpoch,
    workload::{
        DestinationCommit, DestinationEnrollment, DestinationTip, PreparedHead, SignedPreparedHead,
    },
};
use mvm_core::mailbox::journal::{FileJournalAnchor, JournalError, JournalTip};

use crate::policy_generation::coordinator::{self, DestinationOutcome, Request};

/// Sends of one signed head before the commit is reported as failed.
const ATTEMPTS: usize = 3;
/// Wait before a re-send, so a coordinator that is restarting can answer.
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

/// The owner of the workload ledger, as a destination sees it.
pub(crate) trait DestinationAuthority: Send + Sync {
    fn enroll(&self, enrollment: &DestinationEnrollment) -> DestinationOutcome;
    fn commit(&self, prepared: &SignedPreparedHead) -> DestinationOutcome;
    /// Ask the owner to resolve an interrupted commit; best effort.
    fn recover(&self);
}

/// The coordinator listening on `socket`.
pub(crate) struct CoordinatorSocket(pub(crate) PathBuf);

impl DestinationAuthority for CoordinatorSocket {
    fn enroll(&self, enrollment: &DestinationEnrollment) -> DestinationOutcome {
        coordinator::enroll_destination(&self.0, enrollment)
    }

    fn commit(&self, prepared: &SignedPreparedHead) -> DestinationOutcome {
        coordinator::commit_destination(&self.0, prepared)
    }

    fn recover(&self) {
        let _ = coordinator::call(&self.0, &Request::Recover);
    }
}

/// What a destination is bound to for its whole life.
pub(crate) struct Destination {
    pub(crate) id: String,
    pub(crate) workload: String,
    pub(crate) epoch: ExecutionEpoch,
    pub(crate) key: SigningKey,
}

/// An anchor whose every advance is ordered by the ledger's owner.
pub(crate) struct Coordinated {
    pub(crate) anchor: FileJournalAnchor,
    /// Set when the owner definitely refused a commit; the helper must stop.
    pub(crate) refused: Arc<AtomicBool>,
    /// Set when a commit's outcome stayed unknown after every attempt; the
    /// helper must stop, and the next start reconciles from the journal.
    pub(crate) unknown: Arc<AtomicBool>,
    /// The tip the owner holds for this destination at enrollment.
    pub(crate) enrolled: DestinationTip,
}

fn wire(tip: JournalTip) -> DestinationTip {
    DestinationTip {
        cursor: tip.cursor,
        head: hex::encode(tip.head),
    }
}

/// After the journal is open, its anchor must have reached the tip the owner
/// holds; a journal with no suffix to explain a commit the owner took fails.
///
/// # Errors
///
/// [`JournalError::Rollback`] when the anchor is not at the enrolled tip.
pub(crate) fn require_reached(
    anchor: &FileJournalAnchor,
    enrolled: &DestinationTip,
) -> Result<(), JournalError> {
    if wire(anchor.tip()) == *enrolled {
        Ok(())
    } else {
        Err(JournalError::Rollback)
    }
}

enum Failure {
    Refused(String),
    Unknown(String),
}

impl Failure {
    fn into_journal(self) -> JournalError {
        match self {
            Self::Refused(message) => {
                tracing::warn!(%message, "the workload ledger refused a mailbox destination request");
                JournalError::WrongAuthority
            }
            Self::Unknown(message) => {
                tracing::warn!(%message, "the outcome of a mailbox destination request is unknown");
                JournalError::Storage(std::io::Error::other(message))
            }
        }
    }
}

/// Send until the owner answers definitely, up to [`ATTEMPTS`] times. The
/// same request is sent each time, so a lost reply is answered consistently.
fn resolve(
    authority: &dyn DestinationAuthority,
    send: impl Fn() -> DestinationOutcome,
) -> Result<DestinationCommit, Failure> {
    let mut last = String::new();
    for attempt in 1..=ATTEMPTS {
        match send() {
            DestinationOutcome::Committed(commit) => return Ok(commit),
            DestinationOutcome::Refused(message) | DestinationOutcome::NotEnrolled(message) => {
                return Err(Failure::Refused(message));
            }
            DestinationOutcome::Unknown {
                message,
                needs_recovery,
            } => {
                last = message;
                if attempt < ATTEMPTS {
                    std::thread::sleep(RETRY_DELAY);
                    if needs_recovery {
                        authority.recover();
                    }
                }
            }
        }
    }
    Err(Failure::Unknown(last))
}

/// Enroll `destination` at the anchor's tip and return the anchor with its
/// final commit routed through `authority`. Enrolling again is idempotent, so
/// every helper start does it.
///
/// # Errors
///
/// The owner refuses or cannot be reached, or its recorded tip is neither the
/// anchor's nor one commit ahead of it.
pub(crate) fn coordinate(
    anchor: FileJournalAnchor,
    authority: Arc<dyn DestinationAuthority>,
    destination: Destination,
) -> Result<Coordinated, JournalError> {
    let template = DestinationEnrollment {
        destination: destination.id.clone(),
        workload: destination.workload.clone(),
        epoch: destination.epoch,
        key: hex::encode(destination.key.verifying_key().to_bytes()),
        tip: wire(JournalTip::genesis()),
    };
    let enroll_at = move |tip: JournalTip| DestinationEnrollment {
        tip: wire(tip),
        ..template.clone()
    };
    let enrollment = enroll_at(anchor.tip());
    let enrolled = resolve(authority.as_ref(), || authority.enroll(&enrollment))
        .map_err(Failure::into_journal)?;
    let local = anchor.tip();
    // One ahead is a commit the owner took before this helper wrote its anchor.
    if enrolled.tip != wire(local) && enrolled.tip.cursor != local.cursor.saturating_add(1) {
        return Err(JournalError::Rollback);
    }
    let refused = Arc::new(AtomicBool::new(false));
    let unknown = Arc::new(AtomicBool::new(false));
    let (refused_flag, unknown_flag) = (Arc::clone(&refused), Arc::clone(&unknown));
    let anchor = anchor.with_final_commit(Box::new(move |current, next| {
        let prepared = PreparedHead {
            destination: destination.id.clone(),
            workload: destination.workload.clone(),
            epoch: destination.epoch,
            expected: wire(current),
            next: wire(next),
        }
        .sign(&destination.key)
        .map_err(|_| JournalError::Corrupt)?;
        // An entry retired from the owner's table is enrolled again at the
        // tip this commit starts from, then the same head is sent once more.
        let send = || match authority.commit(&prepared) {
            DestinationOutcome::NotEnrolled(_) => match authority.enroll(&enroll_at(current)) {
                DestinationOutcome::Committed(_) => match authority.commit(&prepared) {
                    DestinationOutcome::NotEnrolled(message) => {
                        DestinationOutcome::Refused(message)
                    }
                    other => other,
                },
                DestinationOutcome::NotEnrolled(message) => DestinationOutcome::Refused(message),
                other => other,
            },
            other => other,
        };
        resolve(authority.as_ref(), send)
            .map(|_| ())
            .map_err(|failure| {
                match failure {
                    Failure::Refused(_) => refused_flag.store(true, Ordering::SeqCst),
                    Failure::Unknown(_) => unknown_flag.store(true, Ordering::SeqCst),
                }
                failure.into_journal()
            })
    }));
    Ok(Coordinated {
        anchor,
        refused,
        unknown,
        enrolled: enrolled.tip,
    })
}

#[cfg(test)]
mod tests;
