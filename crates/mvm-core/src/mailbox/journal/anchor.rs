//! The same-host, fsynced high-water mark for local durability.

use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use hmac::{Hmac, Mac, digest::KeyInit};
use mvm_contract::protocol::mailbox::MailboxAddress;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{JournalError, JournalTip};
use crate::private_fs;
use crate::util::atomic_io::{FileLock, atomic_write_durable};

const ANCHOR_DOMAIN: &[u8] = b"mvm.mailbox.anchor.v1\0";
const MAX_ANCHOR_BYTES: u64 = 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorBody {
    version: u8,
    address: MailboxAddress,
    tip: JournalTip,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorRecord {
    body: AnchorBody,
    tag: [u8; 32],
}

/// A software-first, locally fsynced anchor. Keep its file outside the
/// journal directory. It detects journal-only rollback, not simultaneous
/// rollback of the entire trusted host and its anchor storage.
pub struct FileJournalAnchor {
    path: PathBuf,
    pub(super) address: MailboxAddress,
    key: Zeroizing<[u8; 32]>,
    tip: Mutex<JournalTip>,
    _lock: FileLock,
}

impl FileJournalAnchor {
    /// Open a private anchor file, or genesis if none exists.
    pub fn open(path: &Path, address: MailboxAddress, key: [u8; 32]) -> Result<Self, JournalError> {
        let parent = path.parent().ok_or(JournalError::Corrupt)?;
        private_fs::ensure_private_dir(parent)?;
        let lock = FileLock::try_acquire(path)
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .ok_or(JournalError::Busy)?;
        let tip = match fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => JournalTip::genesis(),
            Err(e) => return Err(e.into()),
            Ok(meta) if !meta.file_type().is_file() || meta.len() > MAX_ANCHOR_BYTES => {
                return Err(JournalError::Corrupt);
            }
            Ok(_) => {
                let file = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(path)?;
                let meta = file.metadata()?;
                if !meta.file_type().is_file() || meta.nlink() != 1 || meta.len() > MAX_ANCHOR_BYTES
                {
                    return Err(JournalError::Corrupt);
                }
                let mut bytes = Vec::new();
                file.take(MAX_ANCHOR_BYTES + 1).read_to_end(&mut bytes)?;
                if bytes.len() as u64 > MAX_ANCHOR_BYTES {
                    return Err(JournalError::Corrupt);
                }
                let record: AnchorRecord =
                    serde_json::from_slice(&bytes).map_err(|_| JournalError::Corrupt)?;
                let body = serde_json::to_vec(&record.body).map_err(|_| JournalError::Corrupt)?;
                if record.body.version != 1
                    || record.body.address != address
                    || anchor_mac(&key, &body) != record.tag
                {
                    return Err(JournalError::Corrupt);
                }
                record.body.tip
            }
        };
        Ok(Self {
            path: path.to_owned(),
            address,
            key: Zeroizing::new(key),
            tip: Mutex::new(tip),
            _lock: lock,
        })
    }

    #[must_use]
    pub fn tip(&self) -> JournalTip {
        *self.tip.lock().expect("mailbox anchor lock poisoned")
    }

    /// Advance by one committed journal entry, fsyncing the file and its
    /// containing directory before returning.
    pub fn advance(&self, tip: JournalTip) -> Result<(), JournalError> {
        let mut current = self.tip.lock().expect("mailbox anchor lock poisoned");
        if current.cursor.checked_add(1) != Some(tip.cursor) {
            return Err(JournalError::Rollback);
        }
        let body = AnchorBody {
            version: 1,
            address: self.address,
            tip,
        };
        let tag = anchor_mac(
            &self.key[..],
            &serde_json::to_vec(&body).map_err(|_| JournalError::Corrupt)?,
        );
        let bytes =
            serde_json::to_vec(&AnchorRecord { body, tag }).map_err(|_| JournalError::Corrupt)?;
        atomic_write_durable(&self.path, &bytes)
            .map_err(|e| JournalError::Storage(std::io::Error::other(e.to_string())))?;
        *current = tip;
        Ok(())
    }
}

fn anchor_mac(key: &[u8], body: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("a 32-byte HMAC key is valid");
    mac.update(ANCHOR_DOMAIN);
    mac.update(body);
    mac.finalize().into_bytes().into()
}
