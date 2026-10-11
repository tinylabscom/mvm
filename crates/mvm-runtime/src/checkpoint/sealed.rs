//! Protected checkpoint content at rest.
//!
//! A protected checkpoint stores every content blob the same way, whatever it
//! is — a rootfs, a memory image, a backend's machine state, a launch config,
//! a sidecar:
//!
//! * the blob is cut into [`CHUNK_SIZE`] chunks; each chunk that is not all
//!   zeros is sealed as a checkpoint object (`ObjectKind::Chunk`) under the
//!   record's key domain, filed in that domain's object pool under its keyed
//!   reference, and hard-linked into the checkpoint's membership tree;
//! * a [`SealedIndex`] naming the chunks in order is sealed as an
//!   `ObjectKind::Index` object and written beside them as `<blob>.sealed`;
//! * the record's [`ContentBlob::sha256`] for the blob is the SHA-256 of that
//!   sealed index file. The record is digest-sealed and chain-signed, so the
//!   index is pinned before anything in it is believed; the index then pins
//!   each chunk by reference, kind, and length.
//!
//! Nothing here persists plaintext. Opening is done only into a destination
//! the caller owns ([`materialize_blob`]), into a private temporary file that
//! is renamed into place once every chunk has authenticated, and removed on
//! any failure. There is no shared materialization cache for this content.
//!
//! Deduplication happens only inside a key domain: references are keyed by
//! the domain's reference key, and each domain has its own pool directory. An
//! object already filed under a reference is reused only after it opens under
//! this domain's keys as exactly the chunk being stored.

use std::io::{Seek as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::checkpoint::ContentBlob;
use mvm_core::crypto::checkpoint_object::{
    DomainKeys, ObjectExpectation, ObjectFrame, ObjectKind, ObjectRef, open, seal,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::chunks::{
    CHUNK_SIZE, MEMBERSHIP_DIR, ObjectPool, checked_regular_file, membership_path_for,
    validate_blob_name,
};

/// Suffix of a blob's sealed index file in a checkpoint's content dir.
pub(super) const SEALED_INDEX_SUFFIX: &str = ".sealed";
/// Prefix of a plaintext file being opened into a caller's destination.
const OPENING_PREFIX: &str = ".opening-";
/// Chunks opened concurrently before they are written out in order.
const OPEN_WINDOW: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SealedChunk {
    Zero,
    Object(ObjectRef),
}

/// The plaintext of a blob's sealed index. Carries the blob's own name so an
/// index can never be read as another blob's, even before the record's digest
/// pin is consulted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedIndex {
    blob: String,
    length_bytes: u64,
    chunk_size: u64,
    chunks: Vec<SealedChunk>,
    /// SHA-256 of the whole plaintext, when the capture recorded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    materialized_sha256: Option<String>,
}

impl SealedIndex {
    fn validate(&self, blob_name: &str) -> Result<()> {
        anyhow::ensure!(
            self.blob == blob_name,
            "sealed index names blob {:?}, not {blob_name:?}",
            self.blob
        );
        anyhow::ensure!(
            self.chunk_size == CHUNK_SIZE as u64,
            "sealed index chunk size must be {CHUNK_SIZE}, got {}",
            self.chunk_size
        );
        let expected = usize::try_from(self.length_bytes.div_ceil(self.chunk_size))
            .context("sealed index chunk count does not fit this host")?;
        anyhow::ensure!(
            self.chunks.len() == expected,
            "sealed index for {} bytes requires {expected} chunks, got {}",
            self.length_bytes,
            self.chunks.len()
        );
        Ok(())
    }

    fn chunk_len(&self, position: usize) -> usize {
        let offset = position as u64 * self.chunk_size;
        usize::try_from((self.length_bytes - offset).min(self.chunk_size))
            .expect("a chunk is at most CHUNK_SIZE bytes")
    }
}

/// Seals capture output into a key domain's pool.
pub(super) struct Sealer<'a> {
    pool: ObjectPool,
    keys: &'a DomainKeys,
}

impl<'a> Sealer<'a> {
    pub(super) fn new(store_root: &Path, keys: &'a DomainKeys) -> Result<Self> {
        Ok(Self {
            pool: ObjectPool::new(store_root, keys.domain())?,
            keys,
        })
    }

    /// Seal `source` as blob `name` of the checkpoint whose content dir is
    /// `content_dir`, then remove `source`. Records the plaintext's whole-file
    /// digest in the index when `retain_digest` is set.
    pub(super) fn seal_file(
        &self,
        content_dir: &Path,
        name: &str,
        source: &Path,
        retain_digest: bool,
    ) -> Result<ContentBlob> {
        validate_blob_name(name)?;
        let length = std::fs::metadata(source)
            .with_context(|| format!("reading {}", source.display()))?
            .len();
        let count = usize::try_from(length.div_ceil(CHUNK_SIZE as u64))
            .context("blob chunk count does not fit this host")?;
        let chunks = mvm_fs::parallel::par_map((0..count).collect(), |position| {
            let plaintext = read_chunk(source, position, length)?;
            self.store_chunk(content_dir, &plaintext)
        })
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
        let materialized_sha256 = retain_digest
            .then(|| super::sha256_file_hex(source))
            .transpose()?;
        let index = SealedIndex {
            blob: name.to_string(),
            length_bytes: length,
            chunk_size: CHUNK_SIZE as u64,
            chunks,
            materialized_sha256,
        };
        let blob = self.write_index(content_dir, &index)?;
        std::fs::remove_file(source)
            .with_context(|| format!("removing sealed source {}", source.display()))?;
        Ok(blob)
    }

    fn store_chunk(&self, content_dir: &Path, plaintext: &[u8]) -> Result<SealedChunk> {
        if plaintext.iter().all(|byte| *byte == 0) {
            return Ok(SealedChunk::Zero);
        }
        let sealed = seal(self.keys, ObjectKind::Chunk, plaintext)?;
        let reference = sealed.reference;
        let expectation = ObjectExpectation::new(ObjectKind::Chunk, reference)
            .plaintext_len(plaintext.len() as u64);
        self.pool.link_named(
            content_dir,
            &reference.to_string(),
            &sealed.bytes,
            &|path| open_object_file(self.keys, &expectation, path).map(drop),
        )?;
        Ok(SealedChunk::Object(reference))
    }

    fn write_index(&self, content_dir: &Path, index: &SealedIndex) -> Result<ContentBlob> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(index).context("serializing a sealed checkpoint index")?,
        );
        let sealed = seal(self.keys, ObjectKind::Index, &plaintext)?;
        let path = index_path(content_dir, &index.blob);
        mvm_core::atomic_io::atomic_write(&path, &sealed.bytes)
            .with_context(|| format!("writing sealed index {}", path.display()))?;
        Ok(ContentBlob {
            name: index.blob.clone(),
            sha256: hex::encode(Sha256::digest(&sealed.bytes)),
        })
    }
}

/// Where blob `name`'s sealed index lives in a content dir.
pub(super) fn index_path(content_dir: &Path, name: &str) -> PathBuf {
    content_dir.join(format!("{name}{SEALED_INDEX_SUFFIX}"))
}

/// Refuse a protected content dir that holds anything but sealed indexes for
/// the recorded blobs and the membership tree: a plaintext file left behind
/// by a capture would otherwise be published, and later mirrored, as part of
/// the checkpoint.
pub(super) fn ensure_only_sealed(content_dir: &Path, content: &[ContentBlob]) -> Result<()> {
    let expected: std::collections::BTreeSet<String> = content
        .iter()
        .map(|blob| format!("{}{SEALED_INDEX_SUFFIX}", blob.name))
        .collect();
    for entry in std::fs::read_dir(content_dir)
        .with_context(|| format!("reading {}", content_dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == MEMBERSHIP_DIR && entry.file_type()?.is_dir() {
            continue;
        }
        anyhow::ensure!(
            expected.contains(&name) && entry.file_type()?.is_file(),
            "protected checkpoint content holds {name:?}, which is not a sealed index of a \
             recorded blob; refusing to publish it"
        );
    }
    Ok(())
}

/// Authenticate every byte of `blob` without writing any of it anywhere.
pub(super) fn verify_blob(keys: &DomainKeys, content_dir: &Path, blob: &ContentBlob) -> Result<()> {
    let index = open_index(keys, content_dir, blob)?;
    for_each_chunk(keys, content_dir, &index, |_, _| Ok(()))
}

/// The whole-file digest the capture recorded for `blob`.
pub(super) fn materialized_sha256(
    keys: &DomainKeys,
    content_dir: &Path,
    blob: &ContentBlob,
) -> Result<String> {
    open_index(keys, content_dir, blob)?
        .materialized_sha256
        .context("sealed index does not record the materialized blob digest")
}

/// Open `blob` into `destination`, which must not exist, returning the
/// SHA-256 of the plaintext written.
///
/// The plaintext goes to a private (0600) temporary file beside
/// `destination` and is renamed into place only after every chunk has
/// authenticated and the whole matches any recorded digest. On failure the
/// temporary file is removed and `destination` is never created.
pub(super) fn materialize_blob(
    keys: &DomainKeys,
    content_dir: &Path,
    blob: &ContentBlob,
    destination: &Path,
) -> Result<String> {
    let index = open_index(keys, content_dir, blob)?;
    let parent = destination
        .parent()
        .context("materialization destination has no parent")?;
    let mut staged = tempfile::Builder::new()
        .prefix(OPENING_PREFIX)
        .tempfile_in(parent)
        .with_context(|| format!("staging {} in {}", blob.name, parent.display()))?;
    staged
        .as_file()
        .set_len(index.length_bytes)
        .with_context(|| format!("sizing {}", staged.path().display()))?;
    let mut hasher = Sha256::new();
    let zeros = vec![0u8; CHUNK_SIZE];
    for_each_chunk(keys, content_dir, &index, |position, plaintext| {
        let len = index.chunk_len(position);
        let Some(bytes) = plaintext else {
            // Already zero in the sized file; leave the hole.
            hasher.update(&zeros[..len]);
            staged
                .seek(std::io::SeekFrom::Current(len as i64))
                .with_context(|| format!("seeking {}", staged.path().display()))?;
            return Ok(());
        };
        hasher.update(bytes);
        staged
            .write_all(bytes)
            .with_context(|| format!("writing {}", staged.path().display()))
    })?;
    let digest = hex::encode(hasher.finalize());
    if let Some(recorded) = &index.materialized_sha256 {
        anyhow::ensure!(
            *recorded == digest,
            "checkpoint blob {:?} opened to bytes whose digest {digest} is not the recorded \
             {recorded}",
            blob.name
        );
    }
    staged
        .persist_noclobber(destination)
        .map_err(|error| error.error)
        .with_context(|| format!("placing {}", destination.display()))?;
    Ok(digest)
}

fn open_index(keys: &DomainKeys, content_dir: &Path, blob: &ContentBlob) -> Result<SealedIndex> {
    validate_blob_name(&blob.name)?;
    let path = index_path(content_dir, &blob.name);
    let bytes = read_regular(&path)
        .with_context(|| format!("checkpoint blob {:?} has no sealed index", blob.name))?;
    let actual = hex::encode(Sha256::digest(&bytes));
    anyhow::ensure!(
        actual == blob.sha256,
        "checkpoint blob {:?} sealed index failed integrity: expected {}, got {actual}",
        blob.name,
        blob.sha256
    );
    // The bytes are now the ones the authenticated record pins, so the
    // reference their header carries is the one to expect.
    let reference = ObjectFrame::parse(&bytes)?.reference();
    let plaintext = Zeroizing::new(
        open(
            keys,
            &ObjectExpectation::new(ObjectKind::Index, reference),
            &bytes,
        )
        .with_context(|| format!("opening the sealed index of {:?}", blob.name))?,
    );
    let index: SealedIndex =
        serde_json::from_slice(&plaintext).context("parsing a sealed checkpoint index")?;
    index.validate(&blob.name)?;
    Ok(index)
}

/// Open the index's chunks in order, a window at a time, handing each to
/// `visit` — `None` for an all-zero chunk. Stops at the first failure.
fn for_each_chunk<F>(
    keys: &DomainKeys,
    content_dir: &Path,
    index: &SealedIndex,
    mut visit: F,
) -> Result<()>
where
    F: FnMut(usize, Option<&[u8]>) -> Result<()>,
{
    let positions: Vec<usize> = (0..index.chunks.len()).collect();
    for window in positions.chunks(OPEN_WINDOW) {
        let opened = mvm_fs::parallel::par_map(window.to_vec(), |position| {
            open_chunk(keys, content_dir, index, position).map(|bytes| (position, bytes))
        });
        for result in opened {
            let (position, bytes) = result?;
            visit(position, bytes.as_deref().map(|b| &b[..]))?;
        }
    }
    Ok(())
}

fn open_chunk(
    keys: &DomainKeys,
    content_dir: &Path,
    index: &SealedIndex,
    position: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let SealedChunk::Object(reference) = &index.chunks[position] else {
        return Ok(None);
    };
    let expectation = ObjectExpectation::new(ObjectKind::Chunk, *reference)
        .plaintext_len(index.chunk_len(position) as u64);
    let path = membership_path_for(content_dir, &reference.to_string());
    open_object_file(keys, &expectation, &path)
        .with_context(|| {
            format!(
                "opening chunk {position} of checkpoint blob {:?}",
                index.blob
            )
        })
        .map(Some)
}

fn open_object_file(
    keys: &DomainKeys,
    expectation: &ObjectExpectation,
    path: &Path,
) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = read_regular(path)?;
    Ok(Zeroizing::new(
        open(keys, expectation, &bytes)
            .with_context(|| format!("checkpoint object {} did not open", path.display()))?,
    ))
}

fn read_regular(path: &Path) -> Result<Vec<u8>> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("{} is missing", path.display())
        }
        _ => checked_regular_file(path)?,
    }
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

fn read_chunk(source: &Path, position: usize, length: u64) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::{Read as _, Seek as _};
    let offset = position as u64 * CHUNK_SIZE as u64;
    let len = usize::try_from((length - offset).min(CHUNK_SIZE as u64))
        .expect("a chunk is at most CHUNK_SIZE bytes");
    let mut file =
        std::fs::File::open(source).with_context(|| format!("opening {}", source.display()))?;
    file.seek(std::io::SeekFrom::Start(offset))
        .with_context(|| format!("seeking {}", source.display()))?;
    let mut bytes = Zeroizing::new(vec![0; len]);
    file.read_exact(&mut bytes)
        .with_context(|| format!("reading {}", source.display()))?;
    Ok(bytes)
}
