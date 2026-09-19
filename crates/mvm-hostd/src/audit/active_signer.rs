//! The chain signer this process already holds open for an audit directory.
//!
//! Two `FileAuditSigner`s appending to one chain from the same process would
//! each extend their own idea of its tail and fork it. A process that keeps a
//! signer open across an operation registers it here, and any code that would
//! otherwise open a second signer on the same directory takes this one
//! instead.
//!
//! One slot, not a map: the only long-lived signer a process holds is the one
//! for its primary audit directory, and a policy replica elsewhere owns its own.
//! The slot holds a weak reference, so a registration never keeps a signer
//! alive past its owner.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use crate::supervisor::FileAuditSigner;

struct Registered {
    audit_dir: PathBuf,
    signer: Weak<FileAuditSigner>,
}

static ACTIVE: Mutex<Option<Registered>> = Mutex::new(None);

/// Keeps a signer registered. Dropping it clears the registration.
#[must_use = "the signer stays registered only while this guard lives"]
pub struct ActiveSignerGuard {
    _private: (),
}

impl Drop for ActiveSignerGuard {
    fn drop(&mut self) {
        *ACTIVE.lock().expect("active signer registry poisoned") = None;
    }
}

/// Register `signer` as the one this process uses for `audit_dir`, for as
/// long as the returned guard lives.
pub fn register_active_signer(
    audit_dir: &Path,
    signer: &Arc<FileAuditSigner>,
) -> ActiveSignerGuard {
    *ACTIVE.lock().expect("active signer registry poisoned") = Some(Registered {
        audit_dir: audit_dir.to_path_buf(),
        signer: Arc::downgrade(signer),
    });
    ActiveSignerGuard { _private: () }
}

/// The registered signer, when it was registered for exactly `audit_dir` and
/// is still alive.
pub fn active_signer_for(audit_dir: &Path) -> Option<Arc<FileAuditSigner>> {
    let active = ACTIVE.lock().expect("active signer registry poisoned");
    let active = active.as_ref()?;
    (active.audit_dir == audit_dir)
        .then(|| active.signer.upgrade())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer_in(dir: &Path, seed: u8) -> Arc<FileAuditSigner> {
        Arc::new(
            FileAuditSigner::open(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]), dir)
                .expect("open signer"),
        )
    }

    /// Registered for one directory, offered for that directory only, and
    /// gone once the guard drops.
    #[test]
    fn a_registered_signer_is_scoped_to_its_directory_and_its_guard() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let signer = signer_in(dir.path(), 41);

        let guard = register_active_signer(dir.path(), &signer);
        let active = active_signer_for(dir.path()).expect("matching directory shares the signer");
        assert!(Arc::ptr_eq(&active, &signer));
        assert!(active_signer_for(other.path()).is_none());

        drop(guard);
        assert!(active_signer_for(dir.path()).is_none());
    }

    /// The registration does not keep the signer alive.
    #[test]
    fn a_dropped_signer_is_not_offered() {
        let dir = tempfile::tempdir().unwrap();
        let signer = signer_in(dir.path(), 42);
        let _guard = register_active_signer(dir.path(), &signer);
        drop(signer);
        assert!(active_signer_for(dir.path()).is_none());
    }
}
