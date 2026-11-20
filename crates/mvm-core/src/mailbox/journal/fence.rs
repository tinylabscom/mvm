//! A durable marker that closes a journal store to every future writer.

use std::fs;
use std::path::Path;

use super::JournalError;
use crate::util::atomic_io::{FileLock, atomic_write_new, is_already_exists, sync_dir};

const FENCE: &str = "journal.fence";
const FENCE_CONTENT: &[u8] = b"mailbox-journal-fence-v1\n";

fn storage(error: impl ToString) -> JournalError {
    JournalError::Storage(std::io::Error::other(error.to_string()))
}

/// Presence alone decides: a file, directory or dangling symlink all fence.
pub(super) fn is_fenced(root: &Path) -> Result<bool, JournalError> {
    match fs::symlink_metadata(root.join(FENCE)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(JournalError::Storage(error)),
    }
}

/// Holds the store's writer lock, so no writer can open the store while it
/// lives. Dropping it leaves the store fenced.
pub struct JournalFence {
    _lock: FileLock,
}

impl JournalFence {
    /// Fence an existing store. Fails with `Busy` while any writer has it open.
    pub fn fence(root: &Path) -> Result<Self, JournalError> {
        let metadata = fs::symlink_metadata(root).map_err(JournalError::Storage)?;
        if !metadata.is_dir() {
            return Err(JournalError::Storage(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "journal root is not a real directory",
            )));
        }
        let lock = FileLock::try_acquire(&root.join("journal"))
            .map_err(storage)?
            .ok_or(JournalError::Busy)?;
        if !is_fenced(root)? {
            match atomic_write_new(&root.join(FENCE), FENCE_CONTENT) {
                Ok(()) => {}
                Err(error) if is_already_exists(&error) => {}
                Err(error) => return Err(storage(error)),
            }
        }
        // Also on a repeat call, so a retry after a failed sync makes it durable.
        sync_dir(root).map_err(storage)?;
        Ok(Self { _lock: lock })
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::FENCE;
    use mvm_contract::protocol::mailbox::{
        AuthorizationDomainId, MailboxId, PrincipalId, TenantId,
    };
    use std::path::PathBuf;

    fn address() -> MailboxAddress {
        MailboxAddress {
            tenant: TenantId::from_bytes([1; 32]),
            authorization_domain: AuthorizationDomainId::from_bytes([2; 32]),
            mailbox: MailboxId::from_bytes([3; 32]),
            recipient: PrincipalId::from_bytes([4; 32]),
        }
    }

    fn open(root: &Path) -> Result<MailboxJournal, JournalError> {
        MailboxJournal::open(
            root,
            address(),
            ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key(),
            [5; 32],
            JournalLimits {
                max_records: 4,
                max_bytes: 64 * 1024,
            },
            JournalTip::genesis(),
        )
    }

    fn store() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("journal");
        drop(open(&root).expect("create store"));
        (dir, root)
    }

    #[test]
    fn a_fenced_store_refuses_every_later_open_even_after_the_guard_drops() {
        let (_dir, root) = store();
        let guard = JournalFence::fence(&root).expect("fence");
        drop(guard);
        assert!(matches!(open(&root), Err(JournalError::Fenced)));
        assert!(matches!(open(&root), Err(JournalError::Fenced)));
    }

    #[test]
    fn fencing_an_open_store_is_busy_and_writes_nothing() {
        let (_dir, root) = store();
        let journal = open(&root).expect("open");
        assert!(matches!(
            JournalFence::fence(&root),
            Err(JournalError::Busy)
        ));
        assert!(!root.join(FENCE).exists());
        drop(journal);
        JournalFence::fence(&root).expect("fence after drop");
    }

    #[test]
    fn a_live_guard_excludes_openers_and_drop_leaves_the_store_fenced() {
        let (_dir, root) = store();
        let guard = JournalFence::fence(&root).expect("fence");
        assert!(matches!(
            open(&root),
            Err(JournalError::Busy | JournalError::Fenced)
        ));
        drop(guard);
        assert!(matches!(open(&root), Err(JournalError::Fenced)));
    }

    #[test]
    fn fencing_twice_succeeds_both_times() {
        let (_dir, root) = store();
        drop(JournalFence::fence(&root).expect("first"));
        drop(JournalFence::fence(&root).expect("second"));
    }

    #[test]
    fn fencing_a_missing_root_errors_and_creates_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("absent");
        assert!(matches!(
            JournalFence::fence(&root),
            Err(JournalError::Storage(_))
        ));
        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn fencing_a_symlinked_root_errors() {
        let (dir, root) = store();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&root, &link).expect("symlink");
        assert!(matches!(
            JournalFence::fence(&link),
            Err(JournalError::Storage(_))
        ));
        assert!(!root.join(FENCE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_at_the_fence_path_fences_the_store() {
        let (dir, root) = store();
        std::os::unix::fs::symlink(dir.path().join("nowhere"), root.join(FENCE)).expect("symlink");
        assert!(matches!(open(&root), Err(JournalError::Fenced)));
    }

    #[test]
    fn fencing_changes_only_the_fence_and_lock_files() {
        let (_dir, root) = store();
        let entry = root.join("entry-00000000000000000001.bin");
        fs::write(&entry, b"opaque record bytes").expect("entry");
        let before = fs::read(&entry).expect("read");
        drop(JournalFence::fence(&root).expect("fence"));
        assert_eq!(fs::read(&entry).expect("read"), before);
        let mut names: Vec<_> = fs::read_dir(&root)
            .expect("dir")
            .map(|e| e.expect("entry").file_name().into_string().expect("utf8"))
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["entry-00000000000000000001.bin", FENCE, "journal.lock"]
        );
    }
}
