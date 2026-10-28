//! Versioned, chunked content manifests for the snapshot store (v2).
//!
//! The v1 content address ([`crate::hash::hash_source`]) hashes every byte of
//! every file on every call: a CoW-chain child that differs from its parent
//! by a few blocks pays its parent's full bill. A v2 manifest instead records
//! one digest per fixed-size file chunk, so a child derived from a parent
//! ([`Manifest::compute_from_base`]) reuses the parent's chunk digests
//! wherever the child's bytes are *proven* unchanged:
//!
//! * a chunk the kernel reports as CoW-shared with the same logical range of
//!   the parent's stored file ([`crate::extent`]) is byte-identical to it —
//!   a write to either side would have forced a private copy first;
//! * a chunk that is a hole (or unwritten preallocation) provably reads as
//!   zeros, so its digest is the digest of the zero bytes, with no I/O.
//!
//! Anything without such proof — and every host without extent maps — is
//! read and hashed in full, which is exactly the v1 cost. Reuse can never
//! substitute a digest for bytes that differ.
//!
//! Determinism: the v2 digest is domain-separated from v1
//! ([`DOMAIN_MANIFEST`]), so no v2 id can equal any v1 id of any tree; and
//! within v2 the full and base-derived paths produce identical ids for
//! identical bytes, because reuse only fires on byte-identity proof.
//!
//! Trust boundary: a base manifest is trusted to describe the base tree's
//! bytes. The store writes it when the base is created and re-anchors it to
//! the base's snapshot id on load, so using it can never rename content —
//! but it shares the store's standing assumption that sealed snapshot
//! content is not rewritten in place (a tampered base is the checkpoint
//! layer's refuse-before-materialize gate, unchanged by this module). A
//! manifest that fails its own internal consistency checks is rejected at
//! parse time, never partially trusted.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::extent::{self, ChunkPlan};
use crate::hash::{self, WalkEntry, WalkEntryKind};

/// Fixed file-chunk size for v2 manifests. One MiB balances delta
/// granularity (a touched guest page rehashes one chunk) against sidecar
/// size (~64 KiB of chunk digests per GiB of content).
pub const MANIFEST_CHUNK_LEN: u64 = 1024 * 1024;

/// Domain separator for the manifest-level digest: a v2 id is the SHA-256 of
/// this prefix followed by the chunk length and the sorted entry lines, so it
/// can never equal a v1 id, which hashes the unprefixed whole-file-digest
/// lines of the same shape.
const DOMAIN_MANIFEST: &[u8] = b"mvmfs.manifest.v2\0";
/// Domain separator for a file's chunk-root digest; the file length and
/// chunk length are load-bearing in the digest so the same chunk digests
/// under different parameters address different content.
const DOMAIN_FILE: &[u8] = b"mvmfs.file.v2\0";

const SIDECAR_VERSION: u32 = 2;

/// One manifest entry: a `/`-joined relative path (raw bytes) and its kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    relpath: Vec<u8>,
    kind: EntryKind,
}

/// The per-kind payload of a manifest entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    /// A directory; carries no payload, like v1.
    Dir,
    /// A symlink; the payload is the target's raw bytes, like v1.
    Symlink(Vec<u8>),
    /// A regular file: the chunk-root digest plus one digest per chunk, so a
    /// derived manifest can reuse unchanged chunks by reference.
    File {
        len: u64,
        digest: [u8; 32],
        chunks: Vec<[u8; 32]>,
    },
}

/// A content manifest for a directory tree (or a single file, whose sole
/// entry carries an empty relative path). The root digest is the v2 content
/// address: what the snapshot store names the snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    chunk_len: u64,
    entries: Vec<ManifestEntry>,
    root_digest: String,
}

/// What a base-derived computation actually did, so tests and benchmarks can
/// observe the reuse instead of guessing from wall time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeltaStats {
    /// File entries in the computed manifest.
    pub files: u64,
    /// File chunks across all files.
    pub chunks: u64,
    /// Chunks whose digest came from the base manifest under a CoW-sharing
    /// proof: no read, no hash.
    pub chunks_reused: u64,
    /// Chunks that provably read as zeros: no read, digest of the zero bytes.
    pub chunks_zero: u64,
    /// Chunks read and hashed in full — the v1 cost for those bytes.
    pub chunks_hashed: u64,
}

impl Manifest {
    /// Compute the v2 manifest of `source` (a regular file or a directory),
    /// reading every byte that has no cheap proof. This path never reuses
    /// another manifest's digests; it is the reference every derived
    /// computation must agree with.
    pub fn compute(source: &Path) -> io::Result<Self> {
        Ok(Self::build(source, None)?.0)
    }

    /// Compute the manifest of `source`, reusing `base`'s chunk digests for
    /// chunks the base tree's bytes prove identical. `base_content` is the
    /// tree (or bare file) `base` was computed from: for a directory base it
    /// is the content root an entry's relative path resolves against; for a
    /// bare-file base it is the file itself (its sole entry's empty relative
    /// path resolves to it).
    ///
    /// The result is always the manifest a plain [`Manifest::compute`] of
    /// `source` would produce: reuse only ever substitutes a digest where
    /// the bytes are provably the ones that digest was computed from.
    pub fn compute_from_base(
        source: &Path,
        base: &Manifest,
        base_content: &Path,
    ) -> io::Result<(Self, DeltaStats)> {
        Self::build(source, Some((base, base_content)))
    }

    /// The v2 content address: 64 lowercase hex digits of the
    /// domain-separated manifest digest.
    pub fn root_digest(&self) -> &str {
        &self.root_digest
    }

    /// Serialize for the snapshot store's sidecar. Hex-encoded throughout so
    /// non-UTF-8 path bytes survive JSON.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(&ManifestSerde::from(self))
    }

    /// Parse a persisted sidecar. Fail-closed: a version, chunk-length, or
    /// internal-consistency mismatch is an error, never a partial manifest.
    pub fn from_json(json: &str) -> io::Result<Self> {
        let parsed: ManifestSerde = serde_json::from_str(json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        parsed.into_manifest()
    }

    fn build(source: &Path, base: Option<(&Manifest, &Path)>) -> io::Result<(Self, DeltaStats)> {
        let entries = walk_entries(source)?;
        let base_files: HashMap<&[u8], &Vec<[u8; 32]>> = match base {
            Some((base, _)) => base
                .entries
                .iter()
                .filter_map(|entry| match &entry.kind {
                    EntryKind::File { chunks, .. } => Some((entry.relpath.as_slice(), chunks)),
                    _ => None,
                })
                .collect(),
            None => HashMap::new(),
        };

        let mut stats = DeltaStats::default();
        let mut zero_cache = ZeroDigests::default();
        let mut files: HashMap<PathBuf, FileHash> = HashMap::new();
        for entry in &entries {
            let WalkEntryKind::File(abs) = &entry.kind else {
                continue;
            };
            stats.files += 1;
            let file_base = match base {
                Some((_, base_content)) => base_files
                    .get(entry.rel.as_slice())
                    .map(|chunks| (chunks.as_slice(), resolve_relpath(base_content, &entry.rel))),
                None => None,
            };
            let hashed = hash_file(abs, file_base, &mut zero_cache)?;
            stats.chunks += hashed.stats.chunks;
            stats.chunks_reused += hashed.stats.reused;
            stats.chunks_zero += hashed.stats.zero;
            stats.chunks_hashed += hashed.stats.hashed;
            files.insert(abs.clone(), hashed);
        }

        let mut entries = entries;
        entries.sort_by(|a, b| a.rel.cmp(&b.rel));
        let entries: Vec<ManifestEntry> = entries
            .into_iter()
            .map(|entry| {
                let kind = match entry.kind {
                    WalkEntryKind::Dir => EntryKind::Dir,
                    WalkEntryKind::Symlink(target) => EntryKind::Symlink(target),
                    WalkEntryKind::File(abs) => {
                        let hashed = files.remove(&abs).expect("every walked file was hashed");
                        EntryKind::File {
                            len: hashed.len,
                            digest: hashed.digest,
                            chunks: hashed.chunks,
                        }
                    }
                };
                ManifestEntry {
                    relpath: entry.rel,
                    kind,
                }
            })
            .collect();
        let manifest = Self {
            chunk_len: MANIFEST_CHUNK_LEN,
            root_digest: root_digest(MANIFEST_CHUNK_LEN, &entries),
            entries,
        };
        Ok((manifest, stats))
    }
}

/// Walk `source` (a directory or a bare file) into manifest-order-agnostic
/// entries. A bare file becomes one entry with an empty relative path, which
/// no real walk can produce (file names are never empty), so the two source
/// shapes can never share a manifest.
fn walk_entries(source: &Path) -> io::Result<Vec<WalkEntry>> {
    let meta = fs::symlink_metadata(source)?;
    if meta.is_dir() {
        return hash::walk_tree(source);
    }
    if meta.is_file() {
        return Ok(vec![WalkEntry {
            rel: Vec::new(),
            kind: WalkEntryKind::File(source.to_path_buf()),
        }]);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "manifest source must be a regular file or directory: {}",
            source.display()
        ),
    ))
}

/// Resolve an entry's raw-byte relative path against the base tree. The
/// empty relative path is a bare-file source: `base` is the file itself.
fn resolve_relpath(base: &Path, rel: &[u8]) -> PathBuf {
    if rel.is_empty() {
        return base.to_path_buf();
    }
    base.join(hash::os_str_from_bytes(rel))
}

/// The digest of a chunk that provably reads as `len` zero bytes, computed
/// once per distinct length: hashing zeros costs the same CPU as hashing any
/// other bytes, so a sparse file would otherwise still pay O(file size) of
/// SHA-256 over zeros.
#[derive(Default)]
struct ZeroDigests {
    cache: HashMap<u64, [u8; 32]>,
}

impl ZeroDigests {
    fn get(&mut self, len: u64) -> [u8; 32] {
        *self.cache.entry(len).or_insert_with(|| {
            let mut hasher = Sha256::new();
            let zeros = [0u8; 65536];
            let mut remaining = len;
            while remaining > 0 {
                let n = usize::try_from(remaining.min(zeros.len() as u64)).unwrap_or(zeros.len());
                hasher.update(&zeros[..n]);
                remaining -= n as u64;
            }
            hasher.finalize().into()
        })
    }
}

/// The chunk-root digest identifying a file's bytes: SHA-256 over the domain
/// separator, the file length, the chunk length, and each chunk's raw digest
/// in order.
fn file_digest(len: u64, chunk_len: u64, chunks: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_FILE);
    hasher.update(len.to_le_bytes());
    hasher.update(chunk_len.to_le_bytes());
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

/// The manifest-level digest: SHA-256 over the domain separator, the chunk
/// length, and one line per entry in sorted relative-path order, in the same
/// `{relpath}\0{kind}\0{payload}\n` shape v1 hashes.
fn root_digest(chunk_len: u64, entries: &[ManifestEntry]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_MANIFEST);
    hasher.update(chunk_len.to_le_bytes());
    for entry in entries {
        let (kind, payload): (&'static str, Vec<u8>) = match &entry.kind {
            EntryKind::Dir => ("d", Vec::new()),
            EntryKind::Symlink(target) => ("l", target.clone()),
            EntryKind::File { digest, .. } => ("f", hex::encode(digest).into_bytes()),
        };
        hasher.update(&entry.relpath);
        hasher.update(b"\0");
        hasher.update(kind.as_bytes());
        hasher.update(b"\0");
        hasher.update(&payload);
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

/// Per-file chunk counters, aggregated into [`DeltaStats`] by the caller.
#[derive(Default)]
struct FileChunkStats {
    chunks: u64,
    reused: u64,
    zero: u64,
    hashed: u64,
}

struct FileHash {
    len: u64,
    digest: [u8; 32],
    chunks: Vec<[u8; 32]>,
    stats: FileChunkStats,
}

/// Hash one file chunk by chunk, reusing `base`'s chunk digests where the
/// base file's extent map proves chunk-byte identity. Any missing proof —
/// no extent maps on this host, a filesystem without reflink sharing, a base
/// file that vanished or shrank — falls back to reading the bytes, the v1
/// cost for exactly those bytes.
fn hash_file(
    path: &Path,
    base: Option<(&[[u8; 32]], PathBuf)>,
    zero_cache: &mut ZeroDigests,
) -> io::Result<FileHash> {
    let mut stats = FileChunkStats::default();
    let base_chunks = base.as_ref().map(|(chunks, _)| *chunks);
    let base_path = base.as_ref().map(|(_, path)| path.as_path());

    let map = extent::extent_map(path).ok();
    let base_map = base_path.and_then(|path| extent::extent_map(path).ok());
    let len = match &map {
        Some(map) => map.len,
        None => fs::metadata(path)?.len(),
    };
    let plans = match &map {
        Some(map) => extent::plan_file_chunks(map, MANIFEST_CHUNK_LEN, base_map.as_ref()),
        None => {
            vec![ChunkPlan::Read; usize::try_from(len.div_ceil(MANIFEST_CHUNK_LEN)).unwrap_or(0)]
        }
    };

    let mut file = fs::File::open(path)?;
    let mut chunks: Vec<[u8; 32]> = Vec::with_capacity(plans.len());
    for (index, plan) in plans.iter().enumerate() {
        let lo = index as u64 * MANIFEST_CHUNK_LEN;
        let hi = (lo + MANIFEST_CHUNK_LEN).min(len);
        let chunk_len = hi - lo;
        stats.chunks += 1;
        let digest = match plan {
            ChunkPlan::ReuseBase => match base_chunks.and_then(|chunks| chunks.get(index)) {
                Some(digest) => {
                    stats.reused += 1;
                    *digest
                }
                // The planner's proof ran against the base file's current
                // bytes; a base manifest that no longer matches them (a
                // shrunk or replaced base) has no digest to reuse here.
                None => {
                    stats.hashed += 1;
                    read_chunk(&mut file, lo, chunk_len)?
                }
            },
            ChunkPlan::Zero => {
                stats.zero += 1;
                zero_cache.get(chunk_len)
            }
            ChunkPlan::Read => {
                stats.hashed += 1;
                read_chunk(&mut file, lo, chunk_len)?
            }
        };
        chunks.push(digest);
    }
    let digest = file_digest(len, MANIFEST_CHUNK_LEN, &chunks);
    Ok(FileHash {
        len,
        digest,
        chunks,
        stats,
    })
}

fn read_chunk(file: &mut fs::File, offset: u64, len: u64) -> io::Result<[u8; 32]> {
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; usize::try_from(len).unwrap_or(0)];
    file.read_exact(&mut buf)?;
    Ok(Sha256::digest(&buf).into())
}

/// The serde shape of the persisted sidecar. Hex-encoded so non-UTF-8 path
/// and target bytes round-trip through JSON unchanged.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestSerde {
    version: u32,
    chunk_len: u64,
    root_digest: String,
    entries: Vec<EntrySerde>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EntrySerde {
    /// Hex of the raw relative-path bytes.
    path: String,
    kind: String,
    /// Hex: the file chunk-root digest (`f`), the symlink target bytes
    /// (`l`), or empty (`d`).
    payload: String,
    /// File length; `f` entries only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    len: Option<u64>,
    /// Hex of each chunk digest; `f` entries only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chunks: Option<Vec<String>>,
}

impl From<&Manifest> for ManifestSerde {
    fn from(manifest: &Manifest) -> Self {
        Self {
            version: SIDECAR_VERSION,
            chunk_len: manifest.chunk_len,
            root_digest: manifest.root_digest.clone(),
            entries: manifest
                .entries
                .iter()
                .map(|entry| {
                    let (kind, payload, len, chunks) = match &entry.kind {
                        EntryKind::Dir => ("d".to_string(), String::new(), None, None),
                        EntryKind::Symlink(target) => {
                            ("l".to_string(), hex::encode(target), None, None)
                        }
                        EntryKind::File {
                            len,
                            digest,
                            chunks,
                        } => (
                            "f".to_string(),
                            hex::encode(digest),
                            Some(*len),
                            Some(chunks.iter().map(hex::encode).collect()),
                        ),
                    };
                    EntrySerde {
                        path: hex::encode(&entry.relpath),
                        kind,
                        payload,
                        len,
                        chunks,
                    }
                })
                .collect(),
        }
    }
}

impl ManifestSerde {
    fn into_manifest(self) -> io::Result<Manifest> {
        if self.version != SIDECAR_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported manifest version {}", self.version),
            ));
        }
        if self.chunk_len != MANIFEST_CHUNK_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported manifest chunk length {} (expected {MANIFEST_CHUNK_LEN})",
                    self.chunk_len
                ),
            ));
        }
        let mut entries = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let relpath = decode_hex(&entry.path, "path")?;
            let kind = match entry.kind.as_str() {
                "d" => EntryKind::Dir,
                "l" => EntryKind::Symlink(decode_hex(&entry.payload, "symlink target")?),
                "f" => {
                    let digest = decode_digest(&entry.payload)?;
                    let len = entry.len.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "file entry lacks a length")
                    })?;
                    let chunks = entry
                        .chunks
                        .as_ref()
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "file entry lacks chunks")
                        })?
                        .iter()
                        .map(|c| decode_digest(c))
                        .collect::<io::Result<Vec<_>>>()?;
                    if len.div_ceil(self.chunk_len) != chunks.len() as u64 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "file entry chunk count does not match its length",
                        ));
                    }
                    if file_digest(len, self.chunk_len, &chunks) != digest {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "file entry digest does not match its chunks",
                        ));
                    }
                    EntryKind::File {
                        len,
                        digest,
                        chunks,
                    }
                }
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unknown manifest entry kind {other:?}"),
                    ));
                }
            };
            entries.push(ManifestEntry { relpath, kind });
        }
        if root_digest(self.chunk_len, &entries) != self.root_digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "manifest root digest does not match its entries",
            ));
        }
        Ok(Manifest {
            chunk_len: self.chunk_len,
            entries,
            root_digest: self.root_digest,
        })
    }
}

fn decode_hex(text: &str, what: &str) -> io::Result<Vec<u8>> {
    hex::decode(text).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("manifest {what} is not hex: {e}"),
        )
    })
}

fn decode_digest(text: &str) -> io::Result<[u8; 32]> {
    let bytes = decode_hex(text, "digest")?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("manifest digest is {} bytes, expected 32", bytes.len()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tree(root: &Path) {
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("top.txt"), b"top").unwrap();
        fs::write(root.join("sub").join("nested.txt"), b"nested").unwrap();
        let mut blob = vec![0xAB_u8; 4096];
        blob.extend(std::iter::repeat_n(0u8, 2 * 1024 * 1024));
        blob.extend(vec![0xCD_u8; 4096]);
        fs::write(root.join("blob.bin"), &blob).unwrap();
    }

    /// Byte-copy a tree (a reflink clone's fallback), so the agreement
    /// property is exercised on every host, reflink-capable or not.
    fn copy_tree(src: &Path, dst: &Path) {
        fs::create_dir_all(dst).unwrap();
        for entry in fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let to = dst.join(entry.file_name());
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                copy_tree(&entry.path(), &to);
            } else if file_type.is_file() {
                fs::copy(entry.path(), &to).unwrap();
            } else if file_type.is_symlink() {
                let target = fs::read_link(entry.path()).unwrap();
                #[cfg(unix)]
                std::os::unix::fs::symlink(&target, &to).unwrap();
                #[cfg(not(unix))]
                fs::copy(entry.path(), &to).unwrap();
            }
        }
    }

    #[test]
    fn v2_full_is_deterministic_and_content_sensitive() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        write_tree(&a);
        let b = tmp.path().join("b");
        write_tree(&b);
        let c = tmp.path().join("c");
        write_tree(&c);
        fs::write(c.join("top.txt"), b"t0p").unwrap();

        assert_eq!(
            Manifest::compute(&a).unwrap().root_digest(),
            Manifest::compute(&b).unwrap().root_digest(),
            "identical trees hash identically regardless of path"
        );
        assert_ne!(
            Manifest::compute(&a).unwrap().root_digest(),
            Manifest::compute(&c).unwrap().root_digest(),
            "a changed file changes the root digest"
        );
    }

    #[test]
    fn v2_id_is_domain_separated_from_v1() {
        let tmp = tempfile::tempdir().unwrap();
        let tree = tmp.path().join("tree");
        write_tree(&tree);
        let v1 = crate::hash::hash_source(&tree).unwrap();
        let v2 = Manifest::compute(&tree).unwrap();
        assert_ne!(v1, v2.root_digest());
    }

    #[test]
    fn base_derived_manifest_agrees_with_full_on_an_unchanged_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("parent");
        write_tree(&parent);
        let base = Manifest::compute(&parent).unwrap();

        let child = tmp.path().join("child");
        copy_tree(&parent, &child);
        let (derived, stats) = Manifest::compute_from_base(&child, &base, &parent).unwrap();

        assert_eq!(
            derived.root_digest(),
            Manifest::compute(&child).unwrap().root_digest(),
            "derived and full computations of the same bytes must agree"
        );
        assert_eq!(derived, base);
        assert!(stats.chunks > 0);
        assert_eq!(
            stats.chunks_reused + stats.chunks_zero + stats.chunks_hashed,
            stats.chunks
        );
    }

    #[test]
    fn base_derived_manifest_agrees_with_full_after_mutation() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("parent");
        write_tree(&parent);
        let base = Manifest::compute(&parent).unwrap();

        let child = tmp.path().join("child");
        copy_tree(&parent, &child);
        // Every delta class: a changed file, a new file, a removed file, a
        // new directory, an added symlink, and a mid-file block write.
        fs::write(child.join("top.txt"), b"edited").unwrap();
        fs::write(child.join("new.txt"), b"new").unwrap();
        fs::remove_file(child.join("sub").join("nested.txt")).unwrap();
        fs::create_dir(child.join("fresh-dir")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("top.txt", child.join("link")).unwrap();
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut blob = fs::OpenOptions::new()
                .write(true)
                .open(child.join("blob.bin"))
                .unwrap();
            blob.seek(SeekFrom::Start(2048)).unwrap();
            blob.write_all(&[0x42; 512]).unwrap();
        }

        let (derived, stats) = Manifest::compute_from_base(&child, &base, &parent).unwrap();
        assert_eq!(
            derived.root_digest(),
            Manifest::compute(&child).unwrap().root_digest()
        );
        assert_ne!(derived.root_digest(), base.root_digest());
        assert!(
            stats.chunks_hashed > 0,
            "the mutation must be hashed, not missed"
        );
    }

    #[test]
    fn base_derived_manifest_survives_a_missing_base_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("parent");
        write_tree(&parent);
        let base = Manifest::compute(&parent).unwrap();
        let child = tmp.path().join("child");
        copy_tree(&parent, &child);
        fs::remove_dir_all(&parent).unwrap();

        let (derived, stats) = Manifest::compute_from_base(&child, &base, &parent).unwrap();
        assert_eq!(
            derived.root_digest(),
            Manifest::compute(&child).unwrap().root_digest(),
            "no base bytes on disk: every chunk is read, and the id is still right"
        );
        assert_eq!(stats.chunks_reused, 0);
    }

    #[test]
    fn a_single_file_source_manifests_as_one_empty_named_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("mem.bin");
        fs::write(&file, vec![0x5A_u8; 3 * 1024 * 1024 + 17]).unwrap();

        let manifest = Manifest::compute(&file).unwrap();
        let (derived, _) = Manifest::compute_from_base(&file, &manifest, &file).unwrap();
        assert_eq!(derived.root_digest(), manifest.root_digest());
        assert_ne!(
            manifest.root_digest(),
            crate::hash::hash_source(&file).unwrap(),
            "v2 file ids are domain-separated from v1 file hashes"
        );
    }

    #[test]
    fn serde_roundtrip_preserves_the_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let tree = tmp.path().join("tree");
        write_tree(&tree);
        #[cfg(unix)]
        std::os::unix::fs::symlink("top.txt", tree.join("link")).unwrap();
        let manifest = Manifest::compute(&tree).unwrap();

        let json = manifest.to_json().unwrap();
        let parsed = Manifest::from_json(&json).unwrap();
        assert_eq!(parsed, manifest);
    }

    #[test]
    fn serde_rejects_a_wrong_version_and_unknown_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let tree = tmp.path().join("tree");
        write_tree(&tree);
        let manifest = Manifest::compute(&tree).unwrap();
        let json = manifest.to_json().unwrap();

        let wrong_version = json.replace("\"version\":2", "\"version\":3");
        assert!(Manifest::from_json(&wrong_version).is_err());

        let unknown_field = format!("{},\"extra\":1}}", json.trim_end_matches('}'));
        assert!(Manifest::from_json(&unknown_field).is_err());
    }

    #[test]
    fn serde_rejects_a_tampered_chunk_digest_and_a_tampered_root() {
        let tmp = tempfile::tempdir().unwrap();
        let tree = tmp.path().join("tree");
        write_tree(&tree);
        let manifest = Manifest::compute(&tree).unwrap();
        let json = manifest.to_json().unwrap();

        // Flip one hex digit of a chunk digest: the entry's chunk root no
        // longer matches its chunks and the sidecar is refused, not trusted.
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let chunks = value["entries"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find_map(|e| e["chunks"].as_array_mut())
            .unwrap();
        let first = chunks[0].as_str().unwrap().to_string();
        let flipped = format!(
            "{}{}",
            if first.starts_with('0') { "1" } else { "0" },
            &first[1..]
        );
        chunks[0] = serde_json::Value::String(flipped);
        assert!(Manifest::from_json(&value.to_string()).is_err());

        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["root_digest"] = serde_json::Value::String("0".repeat(64));
        assert!(Manifest::from_json(&value.to_string()).is_err());
    }

    /// The hole-skipping invariant: a chunk that is a hole and a chunk that
    /// is stored zero bytes are the same bytes, so they must carry the same
    /// digest — otherwise identical content would hash differently by storage
    /// layout.
    #[test]
    fn zero_chunk_digest_equals_hashing_the_zero_bytes() {
        let mut cache = ZeroDigests::default();
        for len in [1u64, 4096, MANIFEST_CHUNK_LEN] {
            let expected: [u8; 32] =
                Sha256::digest(vec![0u8; usize::try_from(len).unwrap()]).into();
            assert_eq!(cache.get(len), expected);
        }
    }

    #[test]
    fn non_utf8_names_stay_distinct_through_the_manifest() {
        // In-memory only: APFS rejects non-UTF-8 filenames, so a
        // filesystem-backed version could not run on macOS (the same
        // constraint as the v1 test for this property).
        let entry = |relpath: &[u8]| ManifestEntry {
            relpath: relpath.to_vec(),
            kind: EntryKind::File {
                len: 1,
                digest: [1; 32],
                chunks: vec![[2; 32]],
            },
        };
        assert_ne!(
            root_digest(MANIFEST_CHUNK_LEN, &[entry(b"f\xFF")]),
            root_digest(MANIFEST_CHUNK_LEN, &[entry(b"f\xFE")])
        );
    }

    #[test]
    fn empty_inputs_have_stable_domain_separated_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let empty_dir = tmp.path().join("empty");
        fs::create_dir(&empty_dir).unwrap();
        let empty_file = tmp.path().join("empty.bin");
        fs::write(&empty_file, b"").unwrap();

        let dir = Manifest::compute(&empty_dir).unwrap();
        let file = Manifest::compute(&empty_file).unwrap();
        assert_eq!(
            dir.root_digest(),
            Manifest::compute(&empty_dir).unwrap().root_digest()
        );
        assert_ne!(dir.root_digest(), file.root_digest());
    }

    // Live end-to-end reuse on reflink-capable Linux: a FICLONE clone shares
    // physical extents with its source, so the derived manifest must reuse
    // proven chunks AND still equal the full computation. Byte-copy hosts
    // (stock ext4) have nothing to reuse; the run skips rather than fails.
    #[cfg(target_os = "linux")]
    #[test]
    fn reflinked_child_reuses_proven_chunks_and_stays_deterministic() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("parent");
        write_tree(&parent);
        let base = Manifest::compute(&parent).unwrap();

        let child = tmp.path().join("child");
        if crate::clone::reflink_or_copy_dir(&parent, &child).unwrap()
            != crate::clone::CloneStrategy::Reflink
        {
            return;
        }
        let (derived, stats) = Manifest::compute_from_base(&child, &base, &parent).unwrap();
        assert_eq!(
            derived.root_digest(),
            Manifest::compute(&child).unwrap().root_digest()
        );
        assert!(
            stats.chunks_reused > 0,
            "a pristine reflink clone must reuse at least one proven chunk: {stats:?}"
        );
        // And a mutation below one chunk leaves the rest reusable.
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut blob = fs::OpenOptions::new()
                .write(true)
                .open(child.join("blob.bin"))
                .unwrap();
            blob.seek(SeekFrom::Start(2048)).unwrap();
            blob.write_all(&[0x42; 512]).unwrap();
        }
        let (derived, stats) = Manifest::compute_from_base(&child, &base, &parent).unwrap();
        assert_eq!(
            derived.root_digest(),
            Manifest::compute(&child).unwrap().root_digest(),
            "derived ids track the child's real bytes after mutation"
        );
        assert!(stats.chunks_hashed > 0);
        assert!(stats.chunks_reused > 0);
    }
}
