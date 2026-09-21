use std::io::{Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::checkpoint::{CheckpointKeyDomain, ContentBlob};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub(super) const CHUNK_SIZE: usize = 1024 * 1024;
pub(super) const MEMBERSHIP_DIR: &str = ".chunks";
const OBJECTS_DIR: &str = ".objects";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(super) struct ChunkDigest(String);

impl ChunkDigest {
    pub(super) fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ChunkDigest {
    type Error = ChunkDigestParseError;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        if value.len() != 64 {
            return Err(ChunkDigestParseError::WrongLength { len: value.len() });
        }
        if let Some(ch) = value
            .chars()
            .find(|ch| !matches!(ch, '0'..='9' | 'a'..='f'))
        {
            return Err(ChunkDigestParseError::NonHex { ch });
        }
        Ok(Self(value))
    }
}

impl From<ChunkDigest> for String {
    fn from(digest: ChunkDigest) -> Self {
        digest.0
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(super) enum ChunkDigestParseError {
    #[error("chunk digest must be 64 lowercase hexadecimal characters, got {len}")]
    WrongLength { len: usize },
    #[error("chunk digest must be lowercase hexadecimal, found {ch:?}")]
    NonHex { ch: char },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ChunkEntry {
    Zero,
    Object(ChunkDigest),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChunkIndex {
    length_bytes: u64,
    chunk_size: u64,
    chunks: Vec<ChunkEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    materialized_sha256: Option<ChunkDigest>,
}

impl ChunkIndex {
    pub(super) fn new(length_bytes: u64, chunks: Vec<ChunkEntry>) -> Result<Self> {
        let index = Self {
            length_bytes,
            chunk_size: CHUNK_SIZE as u64,
            chunks,
            materialized_sha256: None,
        };
        index.validate()?;
        Ok(index)
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).context("serializing checkpoint chunk index")
    }

    pub(super) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let index: Self =
            serde_json::from_slice(bytes).context("parsing checkpoint chunk index")?;
        index.validate()?;
        anyhow::ensure!(
            index.canonical_bytes()? == bytes,
            "checkpoint chunk index is not canonically encoded"
        );
        Ok(index)
    }

    pub(super) fn content_address(&self) -> Result<ChunkDigest> {
        Ok(ChunkDigest::from_bytes(&self.canonical_bytes()?))
    }

    fn with_materialized_sha256(mut self, digest: Option<String>) -> Result<Self> {
        self.materialized_sha256 = digest.map(ChunkDigest::try_from).transpose()?;
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.chunk_size == CHUNK_SIZE as u64,
            "checkpoint chunk size must be {CHUNK_SIZE}, got {}",
            self.chunk_size
        );
        let expected_u64 = self.length_bytes.div_ceil(self.chunk_size);
        let expected = usize::try_from(expected_u64)
            .context("checkpoint chunk count does not fit this host")?;
        anyhow::ensure!(
            self.chunks.len() == expected,
            "checkpoint chunk index for {} bytes requires {expected} entries, got {}",
            self.length_bytes,
            self.chunks.len()
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct ChunkRead {
    offset: u64,
    len: usize,
}

pub(super) fn chunk_blob(
    pool: &ObjectPool,
    content_dir: &Path,
    blob_name: &str,
    source: &Path,
    retain_materialized_digest: bool,
) -> Result<ContentBlob> {
    validate_blob_name(blob_name)?;
    let length = std::fs::metadata(source)
        .with_context(|| format!("reading checkpoint blob metadata {}", source.display()))?
        .len();
    let chunk_count = usize::try_from(length.div_ceil(CHUNK_SIZE as u64))
        .context("checkpoint chunk count does not fit this host")?;
    let tasks: Vec<ChunkRead> = (0..chunk_count)
        .map(|index| {
            let index = u64::try_from(index).expect("chunk index fits in u64");
            let offset = index * (CHUNK_SIZE as u64);
            let remaining = length - offset;
            ChunkRead {
                offset,
                len: usize::try_from(remaining.min(CHUNK_SIZE as u64))
                    .expect("chunk length never exceeds usize"),
            }
        })
        .collect();
    let entries: Vec<ChunkEntry> = mvm_fs::parallel::par_map(tasks, |task| {
        let bytes = read_chunk(source, task)?;
        pool.store_and_link(content_dir, &bytes)
    })
    .into_iter()
    .collect::<Result<_>>()?;
    let materialized = retain_materialized_digest
        .then(|| super::sha256_file_hex(source))
        .transpose()?;
    let index = ChunkIndex::new(length, entries)?.with_materialized_sha256(materialized)?;
    let digest = index.content_address()?;
    let path = index_path(content_dir, blob_name);
    mvm_core::atomic_io::atomic_write(&path, &index.canonical_bytes()?)
        .with_context(|| format!("writing checkpoint chunk index {}", path.display()))?;
    Ok(ContentBlob {
        name: blob_name.to_string(),
        sha256: digest.as_str().to_string(),
    })
}

fn read_chunk(path: &Path, task: ChunkRead) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("opening checkpoint blob {}", path.display()))?;
    file.seek(std::io::SeekFrom::Start(task.offset))
        .with_context(|| format!("seeking checkpoint blob {}", path.display()))?;
    let mut bytes = vec![0; task.len];
    file.read_exact(&mut bytes)
        .with_context(|| format!("reading checkpoint blob {}", path.display()))?;
    Ok(bytes)
}

pub(super) fn verify_blob(content_dir: &Path, blob: &ContentBlob) -> Result<()> {
    let index = load_index(content_dir, blob)?;
    let tasks: Vec<(ChunkDigest, PathBuf, usize)> = index
        .chunks
        .iter()
        .enumerate()
        .filter_map(|(position, entry)| match entry {
            ChunkEntry::Zero => None,
            ChunkEntry::Object(digest) => Some((
                digest.clone(),
                membership_path(content_dir, digest),
                position,
            )),
        })
        .collect();
    mvm_fs::parallel::par_map(tasks, |(digest, path, position)| {
        let expected_len = expected_chunk_len(&index, position)?;
        verify_chunk_file(&path, &digest, expected_len)
    })
    .into_iter()
    .collect::<Result<Vec<_>>>()?;
    Ok(())
}

pub(super) fn materialize_blob(
    content_dir: &Path,
    blob: &ContentBlob,
    destination: &Path,
) -> Result<()> {
    let index = load_index(content_dir, blob)?;
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .with_context(|| {
            format!(
                "creating materialized checkpoint blob {}",
                destination.display()
            )
        })?;
    output.set_len(index.length_bytes).with_context(|| {
        format!(
            "sizing materialized checkpoint blob {}",
            destination.display()
        )
    })?;

    for (position, entry) in index.chunks.iter().enumerate() {
        let ChunkEntry::Object(digest) = entry else {
            continue;
        };
        let path = membership_path(content_dir, digest);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("reading checkpoint chunk {}", path.display()))?;
        let expected_len = expected_chunk_len(&index, position)?;
        anyhow::ensure!(
            bytes.len() == expected_len,
            "checkpoint chunk {} has length {}, expected {expected_len}",
            path.display(),
            bytes.len()
        );
        let actual = ChunkDigest::from_bytes(&bytes);
        anyhow::ensure!(
            actual == *digest,
            "checkpoint chunk {} failed integrity: expected {}, got {}",
            path.display(),
            digest.as_str(),
            actual.as_str()
        );
        output
            .seek(std::io::SeekFrom::Start(
                u64::try_from(position)
                    .context("checkpoint chunk position does not fit in u64")?
                    .checked_mul(index.chunk_size)
                    .context("checkpoint chunk offset overflow")?,
            ))
            .with_context(|| format!("seeking {}", destination.display()))?;
        output
            .write_all(&bytes)
            .with_context(|| format!("writing {}", destination.display()))?;
    }
    output
        .flush()
        .with_context(|| format!("flushing {}", destination.display()))
}

fn expected_chunk_len(index: &ChunkIndex, position: usize) -> Result<usize> {
    let offset = u64::try_from(position)
        .context("checkpoint chunk position does not fit in u64")?
        .checked_mul(index.chunk_size)
        .context("checkpoint chunk offset overflow")?;
    let remaining = index
        .length_bytes
        .checked_sub(offset)
        .context("checkpoint chunk starts after blob end")?;
    usize::try_from(remaining.min(index.chunk_size))
        .context("checkpoint chunk length does not fit this host")
}

pub(super) fn materialized_sha256(content_dir: &Path, blob: &ContentBlob) -> Result<String> {
    if !index_path(content_dir, &blob.name).is_file() {
        return Ok(blob.sha256.clone());
    }
    load_index(content_dir, blob)?
        .materialized_sha256
        .map(|digest| digest.as_str().to_string())
        .context("chunk index does not record the materialized blob digest")
}

pub(super) fn load_index(content_dir: &Path, blob: &ContentBlob) -> Result<ChunkIndex> {
    validate_blob_name(&blob.name)?;
    let path = index_path(content_dir, &blob.name);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading checkpoint chunk index {}", path.display()))?;
    let index = ChunkIndex::from_canonical_bytes(&bytes)
        .with_context(|| format!("validating checkpoint chunk index {}", path.display()))?;
    let actual = index.content_address()?;
    anyhow::ensure!(
        actual.as_str() == blob.sha256,
        "checkpoint blob {:?} index failed integrity: expected {}, got {}",
        blob.name,
        blob.sha256,
        actual.as_str()
    );
    Ok(index)
}

pub(super) fn is_chunked_blob(content_dir: &Path, blob: &ContentBlob) -> bool {
    index_path(content_dir, &blob.name).is_file()
}

pub(super) fn index_path(content_dir: &Path, blob_name: &str) -> PathBuf {
    content_dir.join(format!("{blob_name}.chunks.json"))
}

pub(super) fn validate_blob_name(blob_name: &str) -> Result<()> {
    anyhow::ensure!(
        !blob_name.is_empty() && !blob_name.contains('/') && !blob_name.contains('\\'),
        "invalid checkpoint blob name {blob_name:?}"
    );
    Ok(())
}

fn verify_chunk_file(path: &Path, expected: &ChunkDigest, expected_len: usize) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("checkpoint chunk {} is missing", path.display())
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("reading checkpoint chunk {}", path.display()));
        }
    };
    anyhow::ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "checkpoint chunk {} is not a regular file",
        path.display()
    );
    anyhow::ensure!(
        metadata.len() == u64::try_from(expected_len).context("chunk length does not fit u64")?,
        "checkpoint chunk {} failed integrity: length {}, expected {expected_len}",
        path.display(),
        metadata.len()
    );
    let actual = super::sha256_file_hex(path)
        .with_context(|| format!("hashing checkpoint chunk {}", path.display()))?;
    anyhow::ensure!(
        actual == expected.as_str(),
        "checkpoint chunk {} failed integrity: expected {}, got {actual}",
        path.display(),
        expected.as_str()
    );
    Ok(())
}

#[cfg(test)]
pub(super) fn stored_chunk_paths(content_dir: &Path, blob: &ContentBlob) -> Result<Vec<PathBuf>> {
    Ok(load_index(content_dir, blob)?
        .chunks
        .iter()
        .filter_map(|entry| match entry {
            ChunkEntry::Zero => None,
            ChunkEntry::Object(digest) => Some(membership_path(content_dir, digest)),
        })
        .collect())
}

#[cfg(test)]
pub(super) fn verify_blob_serial(content_dir: &Path, blob: &ContentBlob) -> Result<()> {
    let index = load_index(content_dir, blob)?;
    for (position, entry) in index.chunks.iter().enumerate() {
        let ChunkEntry::Object(digest) = entry else {
            continue;
        };
        verify_chunk_file(
            &membership_path(content_dir, digest),
            digest,
            expected_chunk_len(&index, position)?,
        )?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn repeated_chunk_blob_for_benchmark(
    pool: &ObjectPool,
    content_dir: &Path,
    blob_name: &str,
    length_bytes: u64,
) -> Result<ContentBlob> {
    anyhow::ensure!(
        length_bytes > 0 && length_bytes.is_multiple_of(CHUNK_SIZE as u64),
        "benchmark blob length must be a nonzero multiple of {CHUNK_SIZE}"
    );
    let entry = pool.store_and_link(content_dir, &vec![0x5a; CHUNK_SIZE])?;
    let count = usize::try_from(length_bytes / CHUNK_SIZE as u64)
        .context("benchmark chunk count does not fit this host")?;
    let index = ChunkIndex::new(length_bytes, vec![entry; count])?;
    let digest = index.content_address()?;
    let path = index_path(content_dir, blob_name);
    mvm_core::atomic_io::atomic_write(&path, &index.canonical_bytes()?)?;
    Ok(ContentBlob {
        name: blob_name.to_string(),
        sha256: digest.as_str().to_string(),
    })
}

#[cfg(test)]
fn pool_bytes(pool: &ObjectPool) -> Result<u64> {
    regular_files_recursive(pool.root())?
        .into_iter()
        .try_fold(0u64, |total, path| {
            let len = std::fs::metadata(&path)
                .with_context(|| format!("reading checkpoint object {}", path.display()))?
                .len();
            total
                .checked_add(len)
                .context("checkpoint object pool byte count overflow")
        })
}

pub(super) struct ObjectPool {
    root: PathBuf,
}

impl ObjectPool {
    pub(super) fn new(store_root: &Path, domain: &CheckpointKeyDomain) -> Result<Self> {
        let objects = store_root.join(OBJECTS_DIR);
        create_private_dir_durable(&objects, store_root)
            .with_context(|| format!("creating checkpoint object pool {}", objects.display()))?;
        let domain_name = hex::encode(Sha256::digest(domain.as_str().as_bytes()));
        let root = objects.join(domain_name);
        create_private_dir_durable(&root, &objects)
            .with_context(|| format!("creating checkpoint key-domain pool {}", root.display()))?;
        Ok(Self { root })
    }

    #[cfg(test)]
    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    pub(super) fn store_and_link(
        &self,
        checkpoint_content: &Path,
        bytes: &[u8],
    ) -> Result<ChunkEntry> {
        anyhow::ensure!(
            !bytes.is_empty() && bytes.len() <= CHUNK_SIZE,
            "checkpoint chunks must contain 1..={CHUNK_SIZE} bytes, got {}",
            bytes.len()
        );
        if bytes.iter().all(|byte| *byte == 0) {
            return Ok(ChunkEntry::Zero);
        }

        let digest = ChunkDigest::from_bytes(bytes);
        let object = self.ensure_object(&digest, bytes)?;
        let membership = membership_path(checkpoint_content, &digest);
        let membership_parent = membership
            .parent()
            .context("checkpoint chunk membership path has no parent")?;
        mvm_core::config::create_private_dir(membership_parent).with_context(|| {
            format!(
                "creating checkpoint chunk membership {}",
                membership_parent.display()
            )
        })?;
        match std::fs::hard_link(&object, &membership) {
            Ok(()) => mvm_core::atomic_io::sync_dir(membership_parent)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.verify_object(&membership, &digest)?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "linking checkpoint object {} into {}",
                        object.display(),
                        membership.display()
                    )
                });
            }
        }
        Ok(ChunkEntry::Object(digest))
    }

    fn ensure_object(&self, digest: &ChunkDigest, bytes: &[u8]) -> Result<PathBuf> {
        let path = self.object_path(digest);
        let parent = path
            .parent()
            .context("checkpoint object path has no parent")?;
        create_private_dir_durable(parent, &self.root)
            .with_context(|| format!("creating checkpoint object shard {}", parent.display()))?;

        if path.exists() {
            self.verify_object(&path, digest)?;
            return Ok(path);
        }

        let mut staged = tempfile::Builder::new()
            .prefix(".object-")
            .tempfile_in(parent)
            .with_context(|| format!("staging checkpoint object in {}", parent.display()))?;
        staged
            .write_all(bytes)
            .with_context(|| format!("writing checkpoint object {}", digest.as_str()))?;
        staged
            .as_file()
            .sync_all()
            .with_context(|| format!("syncing checkpoint object {}", digest.as_str()))?;
        make_read_only(staged.path())?;
        staged
            .as_file()
            .sync_all()
            .with_context(|| format!("syncing checkpoint object mode {}", digest.as_str()))?;

        match std::fs::hard_link(staged.path(), &path) {
            Ok(()) => mvm_core::atomic_io::sync_dir(parent)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.verify_object(&path, digest)?;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("publishing checkpoint object {}", path.display()));
            }
        }
        Ok(path)
    }

    fn verify_object(&self, path: &Path, digest: &ChunkDigest) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("reading checkpoint object {}", path.display()))?;
        anyhow::ensure!(
            metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
            "checkpoint object {} is not a regular file",
            path.display()
        );
        let actual = super::sha256_file_hex(path)
            .with_context(|| format!("hashing checkpoint object {}", path.display()))?;
        anyhow::ensure!(
            actual == digest.as_str(),
            "checkpoint object {} failed integrity: expected {}, got {actual}",
            path.display(),
            digest.as_str()
        );
        Ok(())
    }

    pub(super) fn object_path(&self, digest: &ChunkDigest) -> PathBuf {
        self.root.join(&digest.as_str()[..2]).join(digest.as_str())
    }
}

fn create_private_dir_durable(path: &Path, parent: &Path) -> Result<()> {
    let existed = path.is_dir();
    mvm_core::config::create_private_dir(path)?;
    if !existed {
        mvm_core::atomic_io::sync_dir(parent)?;
    }
    Ok(())
}

pub(super) fn membership_path(content_dir: &Path, digest: &ChunkDigest) -> PathBuf {
    content_dir
        .join(MEMBERSHIP_DIR)
        .join(&digest.as_str()[..2])
        .join(digest.as_str())
}

#[cfg(test)]
pub(super) fn regular_files_recursive(root: &Path) -> Result<Vec<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in
            std::fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))?
        {
            let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    Ok(files)
}

#[cfg(unix)]
fn make_read_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))
        .with_context(|| format!("making checkpoint object read-only {}", path.display()))
}

#[cfg(not(unix))]
fn make_read_only(path: &Path) -> Result<()> {
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(path, permissions)
        .with_context(|| format!("making checkpoint object read-only {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::io::{Seek as _, SeekFrom, Write as _};
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use mvm_core::checkpoint::CheckpointKeyDomain;

    use super::*;

    fn nonzero(byte: u8) -> Vec<u8> {
        vec![byte; CHUNK_SIZE]
    }

    #[test]
    fn index_encoding_is_canonical_deterministic_and_round_trips() {
        let index = ChunkIndex::new(
            CHUNK_SIZE as u64 + 17,
            vec![
                ChunkEntry::Object(ChunkDigest::from_bytes(&nonzero(7))),
                ChunkEntry::Zero,
            ],
        )
        .unwrap();

        let encoded = index.canonical_bytes().unwrap();
        assert_eq!(ChunkIndex::from_canonical_bytes(&encoded).unwrap(), index);
        assert_eq!(index.canonical_bytes().unwrap(), encoded);
        assert_eq!(index.content_address().unwrap().as_str().len(), 64);

        let mut noncanonical = encoded.clone();
        noncanonical.push(b'\n');
        assert!(ChunkIndex::from_canonical_bytes(&noncanonical).is_err());
    }

    #[test]
    fn index_rejects_the_wrong_entry_count() {
        assert!(ChunkIndex::new(CHUNK_SIZE as u64 + 1, vec![ChunkEntry::Zero]).is_err());
    }

    #[test]
    fn index_rejects_a_malformed_materialized_digest() {
        let bytes = br#"{"length_bytes":0,"chunk_size":1048576,"chunks":[],"materialized_sha256":"not-a-digest"}"#;
        assert!(ChunkIndex::from_canonical_bytes(bytes).is_err());
    }

    #[test]
    fn blob_names_cannot_escape_the_checkpoint_content_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let content = tmp.path().join("content");
        std::fs::create_dir(&content).unwrap();
        let index = ChunkIndex::new(0, Vec::new()).unwrap();
        std::fs::write(
            tmp.path().join("outside.chunks.json"),
            index.canonical_bytes().unwrap(),
        )
        .unwrap();
        let blob = ContentBlob {
            name: "../outside".into(),
            sha256: index.content_address().unwrap().as_str().to_string(),
        };

        assert!(load_index(&content, &blob).is_err());
    }

    #[test]
    fn a_zero_chunk_has_no_pool_or_membership_object() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = ObjectPool::new(tmp.path(), &CheckpointKeyDomain::host()).unwrap();
        let membership = tmp.path().join("checkpoint/content");

        assert_eq!(
            pool.store_and_link(&membership, &vec![0; CHUNK_SIZE])
                .unwrap(),
            ChunkEntry::Zero
        );
        assert!(regular_files_recursive(pool.root()).unwrap().is_empty());
        assert!(!membership.join(MEMBERSHIP_DIR).exists());
    }

    #[test]
    #[cfg(unix)]
    fn checkpoints_in_one_domain_share_the_pool_object_inode() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = ObjectPool::new(
            tmp.path(),
            &CheckpointKeyDomain::tenant("tenant-a").unwrap(),
        )
        .unwrap();
        let first = tmp.path().join("first/content");
        let second = tmp.path().join("second/content");
        let entry = pool.store_and_link(&first, &nonzero(3)).unwrap();
        assert_eq!(pool.store_and_link(&second, &nonzero(3)).unwrap(), entry);
        let ChunkEntry::Object(digest) = entry else {
            panic!("non-zero bytes must be stored");
        };

        let object = pool.object_path(&digest);
        let first_link = membership_path(&first, &digest);
        let second_link = membership_path(&second, &digest);
        let object_meta = std::fs::metadata(&object).unwrap();
        let first_meta = std::fs::metadata(first_link).unwrap();
        let second_meta = std::fs::metadata(second_link).unwrap();
        assert_eq!(
            (object_meta.dev(), object_meta.ino()),
            (first_meta.dev(), first_meta.ino())
        );
        assert_eq!(
            (object_meta.dev(), object_meta.ino()),
            (second_meta.dev(), second_meta.ino())
        );
        assert_eq!(object_meta.permissions().mode() & 0o777, 0o400);
    }

    #[test]
    #[cfg(unix)]
    fn identical_bytes_in_two_domains_never_share_an_inode() {
        let tmp = tempfile::tempdir().unwrap();
        let a = ObjectPool::new(
            tmp.path(),
            &CheckpointKeyDomain::tenant("tenant-a").unwrap(),
        )
        .unwrap();
        let b = ObjectPool::new(
            tmp.path(),
            &CheckpointKeyDomain::tenant("tenant-b").unwrap(),
        )
        .unwrap();
        let a_content = tmp.path().join("a/content");
        let b_content = tmp.path().join("b/content");
        let entry = a.store_and_link(&a_content, &nonzero(9)).unwrap();
        assert_eq!(b.store_and_link(&b_content, &nonzero(9)).unwrap(), entry);
        let ChunkEntry::Object(digest) = entry else {
            panic!("non-zero bytes must be stored");
        };

        let a_meta = std::fs::metadata(a.object_path(&digest)).unwrap();
        let b_meta = std::fs::metadata(b.object_path(&digest)).unwrap();
        assert_ne!((a_meta.dev(), a_meta.ino()), (b_meta.dev(), b_meta.ino()));
        assert_ne!(a.root(), b.root());
    }

    fn write_chunks(path: &Path, chunks: &[Vec<u8>]) {
        let mut file = std::fs::File::create(path).unwrap();
        for chunk in chunks {
            file.write_all(chunk).unwrap();
        }
    }

    #[test]
    fn chunked_blob_round_trips_zero_and_partial_chunks() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = ObjectPool::new(tmp.path(), &CheckpointKeyDomain::host()).unwrap();
        let content = tmp.path().join("checkpoint/content");
        std::fs::create_dir_all(&content).unwrap();
        let source = content.join("memory.bin");
        let expected = [nonzero(1), vec![0; CHUNK_SIZE * 64], vec![5; 117]].concat();
        std::fs::write(&source, &expected).unwrap();

        let blob = chunk_blob(&pool, &content, "memory.bin", &source, false).unwrap();
        std::fs::remove_file(&source).unwrap();
        verify_blob(&content, &blob).unwrap();
        let restored = tmp.path().join("restored-memory.bin");
        materialize_blob(&content, &blob, &restored).unwrap();

        assert_eq!(std::fs::read(&restored).unwrap(), expected);
        assert!(index_path(&content, "memory.bin").is_file());
        assert_eq!(regular_files_recursive(pool.root()).unwrap().len(), 2);
        #[cfg(unix)]
        {
            let allocated = std::fs::metadata(&restored).unwrap().blocks() * 512;
            assert!(
                allocated < u64::try_from(expected.len()).unwrap(),
                "allocated={allocated}, logical={}",
                expected.len()
            );
        }
    }

    #[test]
    fn a_five_percent_change_grows_the_pool_by_less_than_ten_percent() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = ObjectPool::new(tmp.path(), &CheckpointKeyDomain::host()).unwrap();
        let first_content = tmp.path().join("first/content");
        let second_content = tmp.path().join("second/content");
        std::fs::create_dir_all(&first_content).unwrap();
        std::fs::create_dir_all(&second_content).unwrap();
        let mut chunks: Vec<Vec<u8>> = (0..20u8)
            .map(|value| {
                let mut chunk = nonzero(value.saturating_add(1));
                chunk[..8].copy_from_slice(&(value as u64).to_le_bytes());
                chunk
            })
            .collect();
        let first = first_content.join("memory.bin");
        write_chunks(&first, &chunks);
        chunk_blob(&pool, &first_content, "memory.bin", &first, false).unwrap();
        let first_bytes = pool_bytes(&pool).unwrap();

        chunks[7].fill(0xa5);
        let second = second_content.join("memory.bin");
        write_chunks(&second, &chunks);
        chunk_blob(&pool, &second_content, "memory.bin", &second, false).unwrap();
        let second_bytes = pool_bytes(&pool).unwrap();
        let index_bytes = std::fs::metadata(index_path(&second_content, "memory.bin"))
            .unwrap()
            .len();

        assert!(
            (second_bytes - first_bytes) + index_bytes < first_bytes / 10,
            "first={first_bytes}, growth={}, index={index_bytes}",
            second_bytes - first_bytes
        );
    }

    #[test]
    fn tampered_missing_and_index_tampering_are_each_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = ObjectPool::new(tmp.path(), &CheckpointKeyDomain::host()).unwrap();
        let content = tmp.path().join("checkpoint/content");
        std::fs::create_dir_all(&content).unwrap();
        let source = content.join("memory.bin");
        write_chunks(&source, &[nonzero(1), nonzero(2), nonzero(3)]);
        let blob = chunk_blob(&pool, &content, "memory.bin", &source, false).unwrap();
        std::fs::remove_file(&source).unwrap();
        let index = load_index(&content, &blob).unwrap();
        let ChunkEntry::Object(first) = &index.chunks[0] else {
            panic!("test chunk must be stored");
        };
        let first_path = membership_path(&content, first);
        let original = std::fs::read(&first_path).unwrap();

        #[cfg(unix)]
        std::fs::set_permissions(&first_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        #[cfg(not(unix))]
        {
            let mut permissions = std::fs::metadata(&first_path).unwrap().permissions();
            permissions.set_readonly(false);
            std::fs::set_permissions(&first_path, permissions).unwrap();
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&first_path)
            .unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"tampered").unwrap();
        assert!(verify_blob(&content, &blob).is_err());
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&original).unwrap();
        file.set_len(u64::try_from(original.len()).unwrap())
            .unwrap();

        std::fs::remove_file(&first_path).unwrap();
        assert!(verify_blob(&content, &blob).is_err());
        std::fs::hard_link(pool.object_path(first), &first_path).unwrap();

        let index_file = index_path(&content, "memory.bin");
        let mut bytes = std::fs::read(&index_file).unwrap();
        bytes.push(b'\n');
        std::fs::write(index_file, bytes).unwrap();
        assert!(verify_blob(&content, &blob).is_err());
    }

    #[test]
    fn rootfs_index_retains_the_materialized_image_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = ObjectPool::new(tmp.path(), &CheckpointKeyDomain::host()).unwrap();
        let content = tmp.path().join("checkpoint/content");
        std::fs::create_dir_all(&content).unwrap();
        let source = content.join("rootfs.ext4");
        std::fs::write(&source, nonzero(4)).unwrap();
        let expected = super::super::sha256_file_hex(&source).unwrap();

        let blob = chunk_blob(&pool, &content, "rootfs.ext4", &source, true).unwrap();
        assert_eq!(materialized_sha256(&content, &blob).unwrap(), expected);
        assert_ne!(blob.sha256, expected);
    }
}
