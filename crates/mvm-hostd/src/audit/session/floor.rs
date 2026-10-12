//! Where a freshly admitted session's entries can first appear.
//!
//! Sealing a session needs every one of its lines. On a chain that has rotated,
//! some of them could in principle sit in a sealed segment, and the only way to
//! rule that out from the chain alone is to read every sealed segment — a cost
//! that grows with the host's whole history and was paid at every exit.
//!
//! The process that synthesizes a plan can rule it out without reading
//! anything. A plan id is the content address of a plan carrying a fresh
//! 128-bit nonce, so no line written before the plan existed can carry it. If
//! the live segment was segment `S` before anything was recorded for the plan,
//! every one of its lines is in segment `S` or later; and if the live segment
//! is still `S` when the session is sealed, every one of its lines is in the
//! live segment.
//!
//! The note lives in this process's memory and nowhere else, because it is a
//! fact about this process's own history and nothing on disk could vouch for
//! it. A session sealed by a different process has no note, and is sealed from
//! the whole chain as before. A missing or stale note costs that read and
//! nothing else: a wrong one could only produce a seal the whole-chain
//! verifier refuses, and the note is only ever written by the code that just
//! synthesized the plan.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// The live segment each noted session's entries can first appear in.
type Floors = HashMap<SessionKey, u64>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SessionKey {
    audit_dir: PathBuf,
    tenant: String,
    plan_id: String,
}

impl SessionKey {
    fn new(audit_dir: &Path, tenant: &str, plan_id: &str) -> Self {
        Self {
            audit_dir: audit_dir.to_path_buf(),
            tenant: tenant.to_string(),
            plan_id: plan_id.to_string(),
        }
    }
}

fn floors() -> &'static Mutex<Floors> {
    static FLOORS: OnceLock<Mutex<Floors>> = OnceLock::new();
    FLOORS.get_or_init(Mutex::default)
}

/// The live segment's sequence number now, or `None` when it cannot be read.
///
/// A chain that does not exist yet opens at segment 1, which is what its
/// first line will be written to.
fn live_segment(audit_dir: &Path, tenant: &str) -> Option<u64> {
    match crate::supervisor::audit_set::segment_shape(audit_dir, tenant) {
        Ok(shape) => Some(shape.active.0),
        Err(crate::supervisor::audit_set::SegmentSetError::NoChain { .. }) => Some(1),
        Err(_) => None,
    }
}

/// Note where `plan_id`'s session can first land in `tenant`'s chain under
/// `audit_dir`.
///
/// Call only for a plan this process has just synthesized, before anything is
/// recorded for it: that is what makes the note true. Calling it later, or for
/// a plan that came from elsewhere, would state a floor the session may already
/// be below.
pub fn note_new_session(audit_dir: &Path, tenant: &str, plan_id: &str) {
    let Some(segment) = live_segment(audit_dir, tenant) else {
        return;
    };
    if let Ok(mut floors) = floors().lock() {
        floors.insert(SessionKey::new(audit_dir, tenant, plan_id), segment);
    }
}

/// Whether every line of `plan_id`'s session is known to be in the live
/// segment, `live_segment`.
pub(super) fn confined_to(
    audit_dir: &Path,
    tenant: &str,
    plan_id: &str,
    live_segment: u64,
) -> bool {
    floors().lock().is_ok_and(|floors| {
        floors.get(&SessionKey::new(audit_dir, tenant, plan_id)) == Some(&live_segment)
    })
}

/// Drop the note for a session that has been sealed.
pub(super) fn forget(audit_dir: &Path, tenant: &str, plan_id: &str) {
    if let Ok(mut floors) = floors().lock() {
        floors.remove(&SessionKey::new(audit_dir, tenant, plan_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_noted_before_any_chain_is_confined_to_the_first_segment() {
        let dir = tempfile::tempdir().unwrap();
        note_new_session(dir.path(), "local", "sha256:floor-genesis");
        assert!(confined_to(dir.path(), "local", "sha256:floor-genesis", 1));
        assert!(!confined_to(dir.path(), "local", "sha256:floor-genesis", 2));
    }

    #[test]
    fn an_unnoted_or_forgotten_session_is_never_confined() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!confined_to(dir.path(), "local", "sha256:floor-unnoted", 1));
        note_new_session(dir.path(), "local", "sha256:floor-forgotten");
        forget(dir.path(), "local", "sha256:floor-forgotten");
        assert!(!confined_to(
            dir.path(),
            "local",
            "sha256:floor-forgotten",
            1
        ));
    }

    #[test]
    fn a_note_is_scoped_to_its_own_chain() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        note_new_session(dir.path(), "local", "sha256:floor-scoped");
        assert!(!confined_to(
            other.path(),
            "local",
            "sha256:floor-scoped",
            1
        ));
        assert!(!confined_to(dir.path(), "other", "sha256:floor-scoped", 1));
    }
}
