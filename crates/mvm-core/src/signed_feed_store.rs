//! Durable, fail-closed local cache for one signed revocation feed.
//!
//! A feed is a signed document, its detached signature bundle, and a
//! checkpoint that records how far the feed has advanced. The checkpoint is
//! persisted in its own file *before* the signed bytes. A crash between those
//! writes can make the cache unusable until a verified refresh, but cannot make
//! an older feed appear current. The owner-only directory protects the local
//! checkpoint from other accounts; it is not a hardware rollback counter.
//!
//! This module owns only the file mechanics. What a checkpoint contains, how
//! one is ordered against another, and how the signed bytes are authenticated
//! are supplied by each feed's own module, so two feeds signed by different
//! authorities never share a checkpoint or a directory.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::packs::Sha256Hex;
use crate::util::atomic_io::{FileLock, write_private};

const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;
const MAX_STATE_BYTES: usize = 3 * 1024 * 1024;
const MAX_CHECKPOINT_BYTES: usize = 1024;

/// A durable position in a signed feed.
pub(crate) trait FeedCheckpoint: Serialize + DeserializeOwned + Clone + Eq {
    /// SHA-256 of the exact signed document bytes this checkpoint accepted.
    fn document_sha256(&self) -> &Sha256Hex;

    /// Whether a value read back from disk could have been produced by a
    /// successful verification. A false answer means the file was edited.
    fn is_well_formed(&self) -> bool;

    /// Whether `self` is strictly later in the feed than `earlier`.
    fn supersedes(&self, earlier: &Self) -> bool;
}

/// Why the local cache itself, as opposed to the signed feed it holds, cannot
/// be used. Each feed's error type wraps these.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum FeedStoreFault {
    #[error("cache is missing")]
    Missing,
    #[error("cache is incomplete")]
    Incomplete,
    #[error("cache is corrupt or was modified")]
    Corrupt,
    #[error("cache exceeds its size limit")]
    TooLarge,
    #[error("cache storage failed: {0}")]
    Storage(String),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredFeed<C> {
    pub(crate) document_base64: String,
    pub(crate) bundle_base64: String,
    pub(crate) bundle_sha256: Sha256Hex,
    pub(crate) checkpoint: C,
}

struct FeedBytes<C> {
    document: Vec<u8>,
    bundle: Vec<u8>,
    checkpoint: C,
}

/// File layout and crash ordering for one feed directory.
#[derive(Debug, Clone)]
pub(crate) struct SignedFeedStore {
    root: PathBuf,
}

impl SignedFeedStore {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Verify `document` and `bundle` against the persisted checkpoint, then
    /// persist the checkpoint `verify` returns followed by the signed bytes.
    ///
    /// Nothing is written unless `verify` accepts, so a rollback or an
    /// equivocation leaves the cache exactly as it was.
    pub(crate) fn update_with<C, E, F>(
        &self,
        document: &[u8],
        bundle: &[u8],
        verify: F,
    ) -> Result<C, E>
    where
        C: FeedCheckpoint,
        E: From<FeedStoreFault>,
        F: FnOnce(&[u8], &[u8], Option<&C>) -> Result<C, E>,
    {
        check_sizes(document, bundle)?;
        self.ensure_root()?;
        let _lock = self.lock()?;
        let previous = self.read_checkpoint_for_update::<C>()?;
        let checkpoint = verify(document, bundle, previous.as_ref())?;
        if checkpoint.document_sha256() != &Sha256Hex::from_bytes(document) {
            return Err(FeedStoreFault::Corrupt.into());
        }
        let stored = StoredFeed {
            document_base64: base64::engine::general_purpose::STANDARD.encode(document),
            bundle_base64: base64::engine::general_purpose::STANDARD.encode(bundle),
            bundle_sha256: Sha256Hex::from_bytes(bundle),
            checkpoint: checkpoint.clone(),
        };
        let checkpoint_bytes = serde_json::to_vec(&checkpoint).map_err(storage)?;
        let state_bytes = serde_json::to_vec(&stored).map_err(storage)?;
        if state_bytes.len() > MAX_STATE_BYTES {
            return Err(FeedStoreFault::TooLarge.into());
        }
        write_private(&self.checkpoint_path(), &checkpoint_bytes).map_err(storage)?;
        write_private(&self.state_path(), &state_bytes).map_err(storage)?;
        Ok(checkpoint)
    }

    /// Hand the cached bytes and their checkpoint to `verify`, which must
    /// re-authenticate them. A missing cache is an error, never an empty feed.
    pub(crate) fn load_with<C, T, E, F>(&self, verify: F) -> Result<T, E>
    where
        C: FeedCheckpoint,
        E: From<FeedStoreFault>,
        F: FnOnce(&[u8], &[u8], &C) -> Result<T, E>,
    {
        self.ensure_root()?;
        let _lock = self.lock()?;
        let feed = self.read_state::<C>()?.ok_or(FeedStoreFault::Missing)?;
        verify(&feed.document, &feed.bundle, &feed.checkpoint)
    }

    pub(crate) fn state_path(&self) -> PathBuf {
        self.root.join("feed.json")
    }

    pub(crate) fn checkpoint_path(&self) -> PathBuf {
        self.root.join("checkpoint.json")
    }

    fn ensure_root(&self) -> Result<(), FeedStoreFault> {
        match fs::symlink_metadata(&self.root) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(FeedStoreFault::Corrupt);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(storage(error)),
        }
        crate::config::create_private_dir(&self.root).map_err(storage)
    }

    fn lock(&self) -> Result<FileLock, FeedStoreFault> {
        FileLock::acquire(&self.state_path()).map_err(storage)
    }

    fn read_state<C: FeedCheckpoint>(&self) -> Result<Option<FeedBytes<C>>, FeedStoreFault> {
        let checkpoint = read_limited(&self.checkpoint_path(), MAX_CHECKPOINT_BYTES)?;
        let state = read_limited(&self.state_path(), MAX_STATE_BYTES)?;
        let (Some(checkpoint), Some(state)) = (checkpoint, state) else {
            return if !self.checkpoint_path().exists() && !self.state_path().exists() {
                Ok(None)
            } else {
                Err(FeedStoreFault::Incomplete)
            };
        };
        let checkpoint = parse_checkpoint::<C>(&checkpoint)?;
        let feed = decode_state::<C>(&state)?;
        if feed.checkpoint != checkpoint {
            return Err(FeedStoreFault::Incomplete);
        }
        Ok(Some(feed))
    }

    fn read_checkpoint_for_update<C: FeedCheckpoint>(&self) -> Result<Option<C>, FeedStoreFault> {
        let checkpoint = read_limited(&self.checkpoint_path(), MAX_CHECKPOINT_BYTES)?;
        let state = read_limited(&self.state_path(), MAX_STATE_BYTES)?;
        match (checkpoint, state) {
            (None, None) => Ok(None),
            (None, Some(_)) => Err(FeedStoreFault::Incomplete),
            (Some(checkpoint), state) => {
                let checkpoint = parse_checkpoint::<C>(&checkpoint)?;
                if let Some(state) = state {
                    let feed = decode_state::<C>(&state)?;
                    // The checkpoint is written first, so the stored feed may
                    // lag it after a crash but can never be ahead of it.
                    if feed.checkpoint != checkpoint && !checkpoint.supersedes(&feed.checkpoint) {
                        return Err(FeedStoreFault::Incomplete);
                    }
                }
                Ok(Some(checkpoint))
            }
        }
    }
}

fn storage(error: impl std::fmt::Display) -> FeedStoreFault {
    FeedStoreFault::Storage(error.to_string())
}

fn parse_checkpoint<C: FeedCheckpoint>(bytes: &[u8]) -> Result<C, FeedStoreFault> {
    let checkpoint: C = serde_json::from_slice(bytes).map_err(|_| FeedStoreFault::Corrupt)?;
    if !checkpoint.is_well_formed() {
        return Err(FeedStoreFault::Corrupt);
    }
    Ok(checkpoint)
}

fn decode_state<C: FeedCheckpoint>(bytes: &[u8]) -> Result<FeedBytes<C>, FeedStoreFault> {
    let stored: StoredFeed<C> =
        serde_json::from_slice(bytes).map_err(|_| FeedStoreFault::Corrupt)?;
    if !stored.checkpoint.is_well_formed() {
        return Err(FeedStoreFault::Corrupt);
    }
    let document = decode_limited(&stored.document_base64, MAX_DOCUMENT_BYTES)?;
    let bundle = decode_limited(&stored.bundle_base64, MAX_BUNDLE_BYTES)?;
    if &Sha256Hex::from_bytes(&document) != stored.checkpoint.document_sha256()
        || Sha256Hex::from_bytes(&bundle) != stored.bundle_sha256
    {
        return Err(FeedStoreFault::Corrupt);
    }
    Ok(FeedBytes {
        document,
        bundle,
        checkpoint: stored.checkpoint,
    })
}

fn check_sizes(document: &[u8], bundle: &[u8]) -> Result<(), FeedStoreFault> {
    if document.len() > MAX_DOCUMENT_BYTES || bundle.len() > MAX_BUNDLE_BYTES {
        return Err(FeedStoreFault::TooLarge);
    }
    Ok(())
}

fn decode_limited(encoded: &str, limit: usize) -> Result<Vec<u8>, FeedStoreFault> {
    if encoded.len() > limit.div_ceil(3) * 4 + 4 {
        return Err(FeedStoreFault::TooLarge);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| FeedStoreFault::Corrupt)?;
    if bytes.len() > limit {
        return Err(FeedStoreFault::TooLarge);
    }
    Ok(bytes)
}

fn read_limited(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, FeedStoreFault> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(storage(error)),
    };
    if !metadata.file_type().is_file() {
        return Err(FeedStoreFault::Corrupt);
    }
    let size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if size > limit {
        return Err(FeedStoreFault::TooLarge);
    }
    let mut file = fs::File::open(path).map_err(storage)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(u64::try_from(limit).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(storage)?;
    if bytes.len() > limit {
        return Err(FeedStoreFault::TooLarge);
    }
    Ok(Some(bytes))
}
