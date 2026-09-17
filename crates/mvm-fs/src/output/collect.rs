//! Collect a workload's outputs out of the ext4 image it wrote.
//!
//! Two passes, so a refusal never leaves a partial tree behind it:
//!
//! 1. **Plan.** Walk the whole image and validate every entry — its name, its
//!    joined path, its type as both its directory entry and its inode report
//!    it, and the running byte and entry counts against the bounds. Nothing on
//!    the host is touched, so a hostile tree is refused before it costs a
//!    single write.
//! 2. **Extract.** Open the destination once, without following a link, and
//!    create every directory and file relative to directory handles, each
//!    opened with `O_NOFOLLOW`. No host path is re-resolved per entry, so a
//!    symlink planted in the destination mid-collection cannot redirect a
//!    write. Files are created exclusively and hashed as they are copied; if
//!    anything fails, what this collection created is removed.
//!
//! One limit of the reader is worth stating: it does not expose inode
//! identity, so a file linked under two names is indistinguishable from two
//! files with equal contents. It is collected as two independent host files,
//! each charged against the byte bound — the host never receives an alias.

use std::collections::HashSet;
use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use ext4_view::{Ext4, Ext4Error, FileType};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

use super::manifest::{OutputEntry, OutputEntryKind, OutputManifest};
use super::rules::{validate_name, validate_relative_path};
use super::{OutputBounds, OutputRefusal};

/// Bytes read from the image per write to the host.
const COPY_CHUNK: usize = 64 * 1024;

/// One collection: which image, where its contents land, and the bounds.
#[derive(Debug, Clone, Copy)]
pub struct OutputCollection<'a> {
    pub image: &'a Path,
    /// Absolute destination whose parent is already resolved. Absent or empty.
    pub destination: &'a Path,
    pub bounds: OutputBounds,
}

/// A successful collection.
#[derive(Debug, Clone)]
pub struct CollectedOutputs {
    pub manifest: OutputManifest,
    /// Where the full manifest was written, beside the destination.
    pub manifest_path: PathBuf,
}

/// The manifest path for `destination`: a sibling named
/// `<destination>.manifest.json`. Kept outside the destination so no file the
/// workload chose can collide with it.
pub fn manifest_path_for(destination: &Path) -> PathBuf {
    let mut name = destination
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_default();
    name.push(".manifest.json");
    destination.with_file_name(name)
}

/// Refuse a destination a collection could not write without overwriting:
/// anything but an absent path or an empty real directory, or a manifest
/// path that already exists. Called before boot, so a run is not spent on
/// outputs that have nowhere to go, and again at collection time.
pub fn check_destination_available(destination: &Path) -> Result<(), OutputRefusal> {
    if destination.file_name().is_none() {
        return Err(OutputRefusal::DestinationNotDirectory {
            path: destination.to_path_buf(),
        });
    }
    match std::fs::symlink_metadata(destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(OutputRefusal::io(
                format!("inspecting {}", destination.display()),
                error,
            ));
        }
        Ok(meta) if !meta.file_type().is_dir() => {
            return Err(OutputRefusal::DestinationNotDirectory {
                path: destination.to_path_buf(),
            });
        }
        Ok(_) => {
            let mut children = std::fs::read_dir(destination).map_err(|error| {
                OutputRefusal::io(format!("listing {}", destination.display()), error)
            })?;
            if children.next().is_some() {
                return Err(OutputRefusal::DestinationNotEmpty {
                    path: destination.to_path_buf(),
                });
            }
        }
    }
    let manifest = manifest_path_for(destination);
    match std::fs::symlink_metadata(&manifest) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(OutputRefusal::io(
            format!("inspecting {}", manifest.display()),
            error,
        )),
        Ok(_) => Err(OutputRefusal::ManifestExists { path: manifest }),
    }
}

/// Validate and extract the outputs in `collection.image`.
pub fn collect_from_ext4(
    collection: &OutputCollection<'_>,
) -> Result<CollectedOutputs, OutputRefusal> {
    check_destination_available(collection.destination)?;
    let fs = Ext4::load_from_path(collection.image).map_err(unreadable)?;
    let planned = plan_tree(&fs, collection.bounds)?;

    let destination = Destination::open(collection.destination)?;
    let manifest_path = manifest_path_for(collection.destination);
    let finished = extract(&fs, &planned, &destination.fd).and_then(|entries| {
        let manifest = OutputManifest::from_entries(entries)?;
        manifest.write_new(&manifest_path)?;
        Ok(manifest)
    });
    match finished {
        Ok(manifest) => Ok(CollectedOutputs {
            manifest,
            manifest_path,
        }),
        Err(refusal) => {
            destination.discard();
            Err(refusal)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PlannedKind {
    Directory,
    File { size: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Planned {
    path: String,
    kind: PlannedKind,
}

fn unreadable(error: Ext4Error) -> OutputRefusal {
    OutputRefusal::Unreadable {
        reason: error.to_string(),
    }
}

/// The name a refused special entry is recorded under, which is also its
/// audit tag.
fn special_kind(file_type: FileType) -> Option<&'static str> {
    match file_type {
        FileType::Regular | FileType::Directory => None,
        FileType::Symlink => Some("symlink"),
        FileType::CharacterDevice => Some("character_device"),
        FileType::BlockDevice => Some("block_device"),
        FileType::Fifo => Some("fifo"),
        FileType::Socket => Some("socket"),
    }
}

/// Pass one: validate the entire image against the rules and bounds, touching
/// nothing on the host. Parents always precede their children in the result.
fn plan_tree(fs: &Ext4, bounds: OutputBounds) -> Result<Vec<Planned>, OutputRefusal> {
    let mut planned = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut pending = vec![String::new()];

    while let Some(directory) = pending.pop() {
        let image_dir = format!("/{directory}");
        // Every name on the way here was checked unique and a directory, so a
        // lookup by path lands on the entry that was validated. Checking the
        // final component without following it holds that even for an image
        // whose index disagrees with its own listing.
        if !directory.is_empty()
            && fs
                .symlink_metadata(image_dir.as_str())
                .map_err(unreadable)?
                .file_type()
                != FileType::Directory
        {
            return Err(OutputRefusal::TypeMismatch { path: directory });
        }
        let mut seen = HashSet::new();
        for entry in fs.read_dir(image_dir.as_str()).map_err(unreadable)? {
            let entry = entry.map_err(unreadable)?;
            let raw = entry.file_name();
            let raw = raw.as_ref();
            // Every ext4 directory lists itself and its parent once, as
            // directories. Those two are skipped and never followed; a second
            // copy, or one that is not a directory, is something a guest
            // planted and falls through to the name rules, which refuse it.
            if (raw == b"." || raw == b"..")
                && entry.file_type().map_err(unreadable)? == FileType::Directory
                && seen.insert(String::from_utf8_lossy(raw).into_owned())
            {
                continue;
            }
            let name = validate_name(raw)?;
            let path = if directory.is_empty() {
                name.to_string()
            } else {
                format!("{directory}/{name}")
            };
            validate_relative_path(path.as_bytes())?;
            if !seen.insert(name.to_string()) {
                return Err(OutputRefusal::DuplicateName { path });
            }
            if planned.len() as u64 >= bounds.max_entries {
                return Err(OutputRefusal::EntryBound {
                    max_entries: bounds.max_entries,
                });
            }

            // The inode is what a read would act on, so it decides the type;
            // a listing that says otherwise is refused rather than believed.
            let metadata = entry.metadata().map_err(unreadable)?;
            let inode_type = metadata.file_type();
            if entry.file_type().map_err(unreadable)? != inode_type {
                return Err(OutputRefusal::TypeMismatch { path });
            }
            if let Some(kind) = special_kind(inode_type) {
                return Err(OutputRefusal::EntryType { path, kind });
            }
            if inode_type == FileType::Directory {
                pending.push(path.clone());
                planned.push(Planned {
                    path,
                    kind: PlannedKind::Directory,
                });
            } else {
                let size = metadata.len();
                total_bytes = total_bytes.saturating_add(size);
                if total_bytes > bounds.max_bytes {
                    return Err(OutputRefusal::ByteBound {
                        max_bytes: bounds.max_bytes,
                    });
                }
                planned.push(Planned {
                    path,
                    kind: PlannedKind::File { size },
                });
            }
        }
    }
    Ok(planned)
}

/// The destination directory, held open for the whole extraction.
struct Destination {
    path: PathBuf,
    fd: OwnedFd,
    created: bool,
}

impl Destination {
    /// Create the destination if absent, then open it without following a
    /// link and confirm it is empty. The destination's parent is resolved when
    /// the grant is made; if it now resolves elsewhere, something moved it.
    fn open(path: &Path) -> Result<Self, OutputRefusal> {
        let parent = path
            .parent()
            .ok_or(OutputRefusal::DestinationNotDirectory {
                path: path.to_path_buf(),
            })?;
        let resolved_parent = std::fs::canonicalize(parent)
            .map_err(|error| OutputRefusal::io(format!("resolving {}", parent.display()), error))?;
        if resolved_parent != parent {
            return Err(OutputRefusal::DestinationMoved {
                granted: path.to_path_buf(),
                resolved: resolved_parent.join(path.file_name().unwrap_or_default()),
            });
        }

        let created = match std::fs::create_dir(path) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => {
                return Err(OutputRefusal::io(
                    format!("creating {}", path.display()),
                    error,
                ));
            }
        };
        let fd = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| match errno {
            Errno::LOOP | Errno::NOTDIR => OutputRefusal::DestinationNotDirectory {
                path: path.to_path_buf(),
            },
            other => OutputRefusal::io(format!("opening {}", path.display()), other.into()),
        })?;
        if !created {
            let listing = rustix::fs::Dir::read_from(&fd).map_err(|errno| {
                OutputRefusal::io(format!("listing {}", path.display()), errno.into())
            })?;
            for child in listing {
                let child = child.map_err(|errno| {
                    OutputRefusal::io(format!("listing {}", path.display()), errno.into())
                })?;
                let name = child.file_name().to_bytes();
                if name != b"." && name != b".." {
                    return Err(OutputRefusal::DestinationNotEmpty {
                        path: path.to_path_buf(),
                    });
                }
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            fd,
            created,
        })
    }

    /// Remove what this collection wrote. Only reached after the destination
    /// was confirmed empty, so nothing here predates the collection.
    fn discard(self) {
        if self.created {
            let _ = std::fs::remove_dir_all(&self.path);
            return;
        }
        let Ok(children) = std::fs::read_dir(&self.path) else {
            return;
        };
        for child in children.flatten() {
            let child = child.path();
            let is_dir = std::fs::symlink_metadata(&child)
                .map(|meta| meta.file_type().is_dir())
                .unwrap_or(false);
            let _ = if is_dir {
                std::fs::remove_dir_all(&child)
            } else {
                std::fs::remove_file(&child)
            };
        }
    }
}

fn collision_or_io(path: &str, errno: Errno) -> OutputRefusal {
    match errno {
        Errno::EXIST | Errno::LOOP | Errno::NOTDIR => OutputRefusal::HostCollision {
            path: path.to_string(),
        },
        other => OutputRefusal::io(format!("writing output {path:?}"), other.into()),
    }
}

/// Open the directory that will hold `path`'s last component, walking from the
/// destination handle one `O_NOFOLLOW` component at a time.
fn open_parent<'p>(root: &OwnedFd, path: &'p str) -> Result<(OwnedFd, &'p str), OutputRefusal> {
    let dir_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let (parents, leaf) = match path.rsplit_once('/') {
        Some((parents, leaf)) => (Some(parents), leaf),
        None => (None, path),
    };
    let mut current = rustix::fs::openat(root, ".", dir_flags, Mode::empty())
        .map_err(|e| collision_or_io(path, e))?;
    for component in parents.into_iter().flat_map(|p| p.split('/')) {
        current = rustix::fs::openat(&current, component, dir_flags, Mode::empty())
            .map_err(|e| collision_or_io(path, e))?;
    }
    Ok((current, leaf))
}

/// Pass two: materialize the planned tree under `root`, hashing each file.
fn extract(
    fs: &Ext4,
    planned: &[Planned],
    root: &OwnedFd,
) -> Result<Vec<OutputEntry>, OutputRefusal> {
    let mut entries = Vec::with_capacity(planned.len());
    let mut buffer = vec![0u8; COPY_CHUNK];
    for item in planned {
        let (parent, leaf) = open_parent(root, &item.path)?;
        match item.kind {
            PlannedKind::Directory => {
                rustix::fs::mkdirat(&parent, leaf, Mode::from_raw_mode(0o755))
                    .map_err(|e| collision_or_io(&item.path, e))?;
                entries.push(OutputEntry {
                    path: item.path.clone(),
                    kind: OutputEntryKind::Directory,
                });
            }
            PlannedKind::File { size } => {
                let fd = rustix::fs::openat(
                    &parent,
                    leaf,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o644),
                )
                .map_err(|e| collision_or_io(&item.path, e))?;
                let sha256 = copy_file(fs, &item.path, size, fd, &mut buffer)?;
                entries.push(OutputEntry {
                    path: item.path.clone(),
                    kind: OutputEntryKind::File { size, sha256 },
                });
            }
        }
    }
    Ok(entries)
}

/// Copy one image file into `fd`, refusing if it yields other than `size`
/// bytes, and return the lowercase-hex SHA-256 of what was written.
fn copy_file(
    fs: &Ext4,
    path: &str,
    size: u64,
    fd: OwnedFd,
    buffer: &mut [u8],
) -> Result<String, OutputRefusal> {
    let image_path = format!("/{path}");
    if fs
        .symlink_metadata(image_path.as_str())
        .map_err(unreadable)?
        .file_type()
        != FileType::Regular
    {
        return Err(OutputRefusal::TypeMismatch {
            path: path.to_string(),
        });
    }
    let mut source = fs.open(image_path.as_str()).map_err(unreadable)?;
    let mut target = std::fs::File::from(fd);
    let mut hasher = Sha256::new();
    let mut read: u64 = 0;
    loop {
        let n = source.read_bytes(buffer).map_err(unreadable)?;
        if n == 0 {
            break;
        }
        read = read.saturating_add(n as u64);
        if read > size {
            break;
        }
        hasher.update(&buffer[..n]);
        target
            .write_all(&buffer[..n])
            .map_err(|error| OutputRefusal::io(format!("writing output {path:?}"), error))?;
    }
    if read != size {
        return Err(OutputRefusal::SizeMismatch {
            path: path.to_string(),
            declared: size,
            read,
        });
    }
    target
        .sync_all()
        .map_err(|error| OutputRefusal::io(format!("flushing output {path:?}"), error))?;
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests;
