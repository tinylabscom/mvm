//! The two sides of a diff, as flat maps from relative path to entry, and the
//! reads the comparison needs.
//!
//! The ext4 side reads an image the guest wrote, so it is read the way output
//! collection reads one: never through a symlink, every name checked by the
//! same rules, an entry whose directory listing and inode disagree refused
//! rather than believed. A symlink is recorded with its target as text and is
//! never resolved.

use std::collections::BTreeMap;
use std::path::Path;

use ext4_view::{Ext4, Ext4Error, FileType, Metadata};
use sha2::{Digest, Sha256};

use super::TreeDiffError;
use super::model::{EntryInfo, EntryKind};
use crate::output::rules::{validate_name, validate_relative_path};

/// Bytes read per call when hashing or reading a file.
const READ_CHUNK: usize = 64 * 1024;

/// A tree flattened to `relative path → entry`, in path order.
pub type Tree = BTreeMap<String, EntryInfo>;

/// A readable tree.
pub trait TreeSource {
    /// Every entry, refusing a tree with more than `max_entries`.
    fn entries(&self, max_entries: u64) -> Result<Tree, TreeDiffError>;
    /// Up to `limit` bytes of the regular file at `path`.
    fn read_prefix(&self, path: &str, limit: u64) -> Result<Vec<u8>, TreeDiffError>;
    /// Copy the whole regular file at `path` into `sink`, returning its size
    /// in bytes. The default reads through `read_prefix`; sources backed by
    /// streamed readers override it so a large file never sits in memory.
    fn copy_file_to(
        &self,
        path: &str,
        sink: &mut dyn std::io::Write,
    ) -> Result<u64, TreeDiffError> {
        let bytes = self.read_prefix(path, u64::MAX)?;
        sink.write_all(&bytes).map_err(|e| TreeDiffError::Refused {
            path: path.to_string(),
            reason: format!("copy failed: {e}"),
        })?;
        Ok(bytes.len() as u64)
    }
    /// The SHA-256 of the whole regular file at `path`, hex.
    fn sha256(&self, path: &str) -> Result<String, TreeDiffError>;
    /// The target of the symlink at `path`, as text.
    fn link_target(&self, path: &str) -> Result<String, TreeDiffError>;
}

/// An ext4 image read without mounting it.
pub struct Ext4Tree {
    fs: Ext4,
}

impl Ext4Tree {
    /// Open the image at `path`. Its journal is replayed in memory, so an
    /// image that was synced but not unmounted reads as its last commit.
    pub fn open(path: &Path) -> Result<Self, TreeDiffError> {
        let fs = Ext4::load_from_path(path).map_err(|error| TreeDiffError::Unreadable {
            image: path.display().to_string(),
            reason: error.to_string(),
        })?;
        Ok(Self { fs })
    }
}

fn unreadable(path: &str, error: Ext4Error) -> TreeDiffError {
    TreeDiffError::Unreadable {
        image: path.to_string(),
        reason: error.to_string(),
    }
}

fn kind_of(file_type: FileType) -> EntryKind {
    match file_type {
        FileType::Regular => EntryKind::File,
        FileType::Directory => EntryKind::Directory,
        FileType::Symlink => EntryKind::Symlink,
        FileType::CharacterDevice | FileType::BlockDevice | FileType::Fifo | FileType::Socket => {
            EntryKind::Special
        }
    }
}

fn info(metadata: &Metadata) -> EntryInfo {
    let kind = kind_of(metadata.file_type());
    EntryInfo {
        kind,
        size: if kind == EntryKind::File {
            metadata.len()
        } else {
            0
        },
        mode: u32::from(metadata.mode()) & 0o7777,
    }
}

impl Ext4Tree {
    /// The inode at `path`, which must be of `expected` kind. Looked up
    /// without following a final symlink.
    fn inode(&self, path: &str, expected: FileType) -> Result<Metadata, TreeDiffError> {
        let image_path = format!("/{path}");
        let metadata = self
            .fs
            .symlink_metadata(image_path.as_str())
            .map_err(|e| unreadable(path, e))?;
        if metadata.file_type() != expected {
            return Err(TreeDiffError::Refused {
                path: path.to_string(),
                reason: "its type changed between the listing and the read".into(),
            });
        }
        Ok(metadata)
    }

    fn open_file(&self, path: &str) -> Result<ext4_view::File, TreeDiffError> {
        self.inode(path, FileType::Regular)?;
        self.fs
            .open(format!("/{path}").as_str())
            .map_err(|e| unreadable(path, e))
    }
}

impl TreeSource for Ext4Tree {
    fn entries(&self, max_entries: u64) -> Result<Tree, TreeDiffError> {
        let mut tree = Tree::new();
        let mut pending = vec![String::new()];
        while let Some(directory) = pending.pop() {
            let listing = self
                .fs
                .read_dir(format!("/{directory}").as_str())
                .map_err(|e| unreadable(&directory, e))?;
            for entry in listing {
                let entry = entry.map_err(|e| unreadable(&directory, e))?;
                let raw = entry.file_name();
                let raw = raw.as_ref();
                let listed = entry.file_type().map_err(|e| unreadable(&directory, e))?;
                if (raw == b"." || raw == b"..") && listed == FileType::Directory {
                    continue;
                }
                let name = validate_name(raw).map_err(|refusal| TreeDiffError::Refused {
                    path: String::from_utf8_lossy(raw).into_owned(),
                    reason: refusal.to_string(),
                })?;
                if directory.is_empty() && name == "lost+found" && listed == FileType::Directory {
                    continue;
                }
                let path = if directory.is_empty() {
                    name.to_string()
                } else {
                    format!("{directory}/{name}")
                };
                validate_relative_path(path.as_bytes()).map_err(|refusal| {
                    TreeDiffError::Refused {
                        path: path.clone(),
                        reason: refusal.to_string(),
                    }
                })?;
                let metadata = entry.metadata().map_err(|e| unreadable(&path, e))?;
                if metadata.file_type() != listed {
                    return Err(TreeDiffError::Refused {
                        path,
                        reason: "its directory entry and inode disagree about its type".into(),
                    });
                }
                if tree.len() as u64 >= max_entries {
                    return Err(TreeDiffError::TooManyEntries { max_entries });
                }
                if listed == FileType::Directory {
                    pending.push(path.clone());
                }
                if tree.insert(path.clone(), info(&metadata)).is_some() {
                    return Err(TreeDiffError::Refused {
                        path,
                        reason: "the name is listed twice".into(),
                    });
                }
            }
        }
        Ok(tree)
    }

    fn read_prefix(&self, path: &str, limit: u64) -> Result<Vec<u8>, TreeDiffError> {
        let mut file = self.open_file(path)?;
        let mut out = Vec::new();
        let mut buffer = vec![0u8; READ_CHUNK];
        while (out.len() as u64) < limit {
            let want = (limit - out.len() as u64).min(READ_CHUNK as u64) as usize;
            let n = file
                .read_bytes(&mut buffer[..want])
                .map_err(|e| unreadable(path, e))?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buffer[..n]);
        }
        Ok(out)
    }

    fn sha256(&self, path: &str) -> Result<String, TreeDiffError> {
        let mut file = self.open_file(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; READ_CHUNK];
        loop {
            let n = file
                .read_bytes(&mut buffer)
                .map_err(|e| unreadable(path, e))?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    fn copy_file_to(
        &self,
        path: &str,
        sink: &mut dyn std::io::Write,
    ) -> Result<u64, TreeDiffError> {
        let mut file = self.open_file(path)?;
        let mut size = 0u64;
        let mut buffer = vec![0u8; READ_CHUNK];
        loop {
            let n = file
                .read_bytes(&mut buffer)
                .map_err(|e| unreadable(path, e))?;
            if n == 0 {
                break;
            }
            sink.write_all(&buffer[..n])
                .map_err(|e| TreeDiffError::Refused {
                    path: path.to_string(),
                    reason: format!("copy failed: {e}"),
                })?;
            size += n as u64;
        }
        Ok(size)
    }

    fn link_target(&self, path: &str) -> Result<String, TreeDiffError> {
        self.inode(path, FileType::Symlink)?;
        let target = self
            .fs
            .read_link(format!("/{path}").as_str())
            .map_err(|e| unreadable(path, e))?;
        Ok(String::from_utf8_lossy(target.as_ref()).into_owned())
    }
}

/// An in-memory tree: the comparison's logic tested without images.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub(crate) struct MemTree {
    pub entries: Tree,
    pub contents: BTreeMap<String, Vec<u8>>,
    pub links: BTreeMap<String, String>,
}

#[cfg(test)]
impl MemTree {
    pub fn file(mut self, path: &str, bytes: &[u8]) -> Self {
        self.entries.insert(
            path.into(),
            EntryInfo {
                kind: EntryKind::File,
                size: bytes.len() as u64,
                mode: 0o644,
            },
        );
        self.contents.insert(path.into(), bytes.to_vec());
        self
    }

    pub fn dir(mut self, path: &str) -> Self {
        self.entries.insert(
            path.into(),
            EntryInfo {
                kind: EntryKind::Directory,
                size: 0,
                mode: 0o755,
            },
        );
        self
    }

    pub fn link(mut self, path: &str, target: &str) -> Self {
        self.entries.insert(
            path.into(),
            EntryInfo {
                kind: EntryKind::Symlink,
                size: 0,
                mode: 0o777,
            },
        );
        self.links.insert(path.into(), target.into());
        self
    }

    pub fn mode(mut self, path: &str, mode: u32) -> Self {
        if let Some(entry) = self.entries.get_mut(path) {
            entry.mode = mode;
        }
        self
    }
}

#[cfg(test)]
impl TreeSource for MemTree {
    fn entries(&self, max_entries: u64) -> Result<Tree, TreeDiffError> {
        if self.entries.len() as u64 > max_entries {
            return Err(TreeDiffError::TooManyEntries { max_entries });
        }
        Ok(self.entries.clone())
    }

    fn read_prefix(&self, path: &str, limit: u64) -> Result<Vec<u8>, TreeDiffError> {
        let bytes = &self.contents[path];
        Ok(bytes[..bytes.len().min(limit as usize)].to_vec())
    }

    fn sha256(&self, path: &str) -> Result<String, TreeDiffError> {
        Ok(hex::encode(Sha256::digest(&self.contents[path])))
    }

    fn link_target(&self, path: &str) -> Result<String, TreeDiffError> {
        Ok(self.links[path].clone())
    }
}
