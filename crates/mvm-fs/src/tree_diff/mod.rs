//! What changed between two file trees, with the text of every text file that
//! changed.
//!
//! The trees are read on the host: a workload's writable volume is an ext4
//! image, and its baseline is the image the volume started from, so both are
//! read here with the same reader and the same refusals output collection
//! uses. No file content crosses the guest channel to produce a diff.
//!
//! Every read is bounded. A tree with too many entries is refused; a file over
//! [`DiffLimits::max_file_bytes`] is compared by digest and not shown; once
//! [`DiffLimits::max_output_bytes`] of diff text has been produced, later
//! changes are listed without their text; past [`DiffLimits::max_files`]
//! changes are counted but not listed. Whenever a limit takes something out,
//! [`TreeDiff::truncated`] says what and how much.

mod lines;
pub mod model;
mod tree;

use std::path::Path;

pub use model::{
    ChangeKind, DiffContent, DiffStats, EntryInfo, EntryKind, FileDiff, Hunk, HunkLine, LineKind,
    TreeDiff, Truncation, TruncationReason,
};
pub use tree::{Ext4Tree, Tree, TreeSource};

/// Bytes examined for a NUL when deciding whether a file is text.
const BINARY_PROBE_BYTES: usize = 8000;

/// Why two trees could not be compared.
#[derive(Debug, thiserror::Error)]
pub enum TreeDiffError {
    #[error("cannot read {image}: {reason}")]
    Unreadable { image: String, reason: String },
    #[error("refusing to diff {path:?}: {reason}")]
    Refused { path: String, reason: String },
    #[error("a tree has more than {max_entries} entries")]
    TooManyEntries { max_entries: u64 },
}

/// The bounds a diff stays within.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiffLimits {
    /// Entries either tree may hold before the diff is refused.
    pub max_entries: u64,
    /// Changed entries listed; the rest are counted only.
    pub max_files: u64,
    /// Largest file whose text is shown; larger ones are compared by digest.
    pub max_file_bytes: u64,
    /// Diff text produced across all files before later ones are omitted.
    pub max_output_bytes: u64,
    /// Unchanged lines shown around each change.
    pub context_lines: usize,
}

impl Default for DiffLimits {
    fn default() -> Self {
        Self {
            max_entries: 500_000,
            max_files: 5_000,
            max_file_bytes: 1024 * 1024,
            max_output_bytes: 8 * 1024 * 1024,
            context_lines: 3,
        }
    }
}

impl DiffLimits {
    #[must_use]
    pub fn with_max_files(mut self, max_files: u64) -> Self {
        self.max_files = max_files;
        self
    }

    #[must_use]
    pub fn with_max_file_bytes(mut self, max_file_bytes: u64) -> Self {
        self.max_file_bytes = max_file_bytes;
        self
    }

    #[must_use]
    pub fn with_max_output_bytes(mut self, max_output_bytes: u64) -> Self {
        self.max_output_bytes = max_output_bytes;
        self
    }

    #[must_use]
    pub fn with_max_entries(mut self, max_entries: u64) -> Self {
        self.max_entries = max_entries;
        self
    }

    #[must_use]
    pub fn with_context_lines(mut self, context_lines: usize) -> Self {
        self.context_lines = context_lines;
        self
    }
}

/// Diff the ext4 image at `new` against the one at `old`.
pub fn diff_images(old: &Path, new: &Path, limits: DiffLimits) -> Result<TreeDiff, TreeDiffError> {
    diff_trees(&Ext4Tree::open(old)?, &Ext4Tree::open(new)?, limits)
}

/// Diff `new` against `old`.
pub fn diff_trees(
    old: &dyn TreeSource,
    new: &dyn TreeSource,
    limits: DiffLimits,
) -> Result<TreeDiff, TreeDiffError> {
    let old_tree = old.entries(limits.max_entries)?;
    let new_tree = new.entries(limits.max_entries)?;
    let mut builder = DiffBuilder::new(limits);
    let mut paths: Vec<&String> = old_tree.keys().chain(new_tree.keys()).collect();
    paths.sort_unstable();
    paths.dedup();
    let sides = Sides { old, new };
    for path in paths {
        let change = classify(&sides, path, old_tree.get(path), new_tree.get(path), limits)?;
        if let Some(change) = change {
            builder.push(&sides, path, change)?;
        }
    }
    Ok(builder.finish())
}

struct Sides<'a> {
    old: &'a dyn TreeSource,
    new: &'a dyn TreeSource,
}

/// A change found for one path, before its content is rendered.
struct Found {
    change: ChangeKind,
    old: Option<EntryInfo>,
    new: Option<EntryInfo>,
    /// Same bytes, only the mode moved.
    mode_only: bool,
}

fn classify(
    sides: &Sides<'_>,
    path: &str,
    old: Option<&EntryInfo>,
    new: Option<&EntryInfo>,
    limits: DiffLimits,
) -> Result<Option<Found>, TreeDiffError> {
    let found = |change, mode_only| Found {
        change,
        old: old.cloned(),
        new: new.cloned(),
        mode_only,
    };
    let (old_entry, new_entry) = match (old, new) {
        (None, None) => return Ok(None),
        (None, Some(_)) => return Ok(Some(found(ChangeKind::Added, false))),
        (Some(_), None) => return Ok(Some(found(ChangeKind::Removed, false))),
        (Some(old), Some(new)) => (old, new),
    };
    if old_entry.kind != new_entry.kind {
        return Ok(Some(found(ChangeKind::TypeChanged, false)));
    }
    let same_content = match old_entry.kind {
        EntryKind::File => same_file(sides, path, old_entry, new_entry, limits)?,
        EntryKind::Symlink => sides.old.link_target(path)? == sides.new.link_target(path)?,
        EntryKind::Directory | EntryKind::Special => true,
    };
    if !same_content {
        return Ok(Some(found(ChangeKind::Modified, false)));
    }
    if old_entry.mode != new_entry.mode && old_entry.kind != EntryKind::Symlink {
        return Ok(Some(found(ChangeKind::Modified, true)));
    }
    Ok(None)
}

fn same_file(
    sides: &Sides<'_>,
    path: &str,
    old: &EntryInfo,
    new: &EntryInfo,
    limits: DiffLimits,
) -> Result<bool, TreeDiffError> {
    if old.size != new.size {
        return Ok(false);
    }
    if old.size <= limits.max_file_bytes {
        return Ok(sides.old.read_prefix(path, old.size)? == sides.new.read_prefix(path, new.size)?);
    }
    Ok(sides.old.sha256(path)? == sides.new.sha256(path)?)
}

/// Whether `bytes` read as text: valid UTF-8 with no NUL in the probe window.
fn is_text(bytes: &[u8]) -> bool {
    !bytes[..bytes.len().min(BINARY_PROBE_BYTES)].contains(&0) && std::str::from_utf8(bytes).is_ok()
}

struct DiffBuilder {
    limits: DiffLimits,
    files: Vec<FileDiff>,
    stats: DiffStats,
    output_bytes: u64,
    omitted_files: u64,
    omitted_content: u64,
    reason: Option<TruncationReason>,
}

impl DiffBuilder {
    fn new(limits: DiffLimits) -> Self {
        Self {
            limits,
            files: Vec::new(),
            stats: DiffStats::default(),
            output_bytes: 0,
            omitted_files: 0,
            omitted_content: 0,
            reason: None,
        }
    }

    fn truncate(&mut self, reason: TruncationReason) {
        // The first limit hit is the one reported; both counters keep counting.
        self.reason.get_or_insert(reason);
    }

    fn push(&mut self, sides: &Sides<'_>, path: &str, found: Found) -> Result<(), TreeDiffError> {
        match found.change {
            ChangeKind::Added => self.stats.added += 1,
            ChangeKind::Removed => self.stats.removed += 1,
            ChangeKind::Modified => self.stats.modified += 1,
            ChangeKind::TypeChanged => self.stats.type_changed += 1,
        }
        if self.files.len() as u64 >= self.limits.max_files {
            self.omitted_files += 1;
            self.truncate(TruncationReason::FileLimit);
            return Ok(());
        }
        let content = self.content(sides, path, &found)?;
        self.files.push(FileDiff {
            path: path.to_string(),
            change: found.change,
            old: found.old,
            new: found.new,
            content,
        });
        Ok(())
    }

    fn content(
        &mut self,
        sides: &Sides<'_>,
        path: &str,
        found: &Found,
    ) -> Result<DiffContent, TreeDiffError> {
        if found.mode_only {
            return Ok(DiffContent::ModeOnly);
        }
        if found.change == ChangeKind::TypeChanged {
            return Ok(DiffContent::Entry);
        }
        // Past a type change, a side that is present has the same kind as the
        // other, so either one names it.
        let kind = found.new.as_ref().or(found.old.as_ref()).map(|e| e.kind);
        match kind {
            Some(EntryKind::Symlink) => Ok(DiffContent::Symlink {
                old_target: found
                    .old
                    .as_ref()
                    .map(|_| sides.old.link_target(path))
                    .transpose()?,
                new_target: found
                    .new
                    .as_ref()
                    .map(|_| sides.new.link_target(path))
                    .transpose()?,
            }),
            Some(EntryKind::File) => self.file_content(sides, path, found),
            _ => Ok(DiffContent::Entry),
        }
    }

    fn file_content(
        &mut self,
        sides: &Sides<'_>,
        path: &str,
        found: &Found,
    ) -> Result<DiffContent, TreeDiffError> {
        let old_size = found.old.as_ref().map(|e| e.size);
        let new_size = found.new.as_ref().map(|e| e.size);
        let too_large = [old_size, new_size]
            .into_iter()
            .flatten()
            .any(|size| size > self.limits.max_file_bytes);
        if too_large {
            return Ok(DiffContent::TooLarge {
                limit_bytes: self.limits.max_file_bytes,
                old_sha256: old_size.map(|_| sides.old.sha256(path)).transpose()?,
                new_sha256: new_size.map(|_| sides.new.sha256(path)).transpose()?,
            });
        }
        let old_bytes = old_size
            .map(|size| sides.old.read_prefix(path, size))
            .transpose()?;
        let new_bytes = new_size
            .map(|size| sides.new.read_prefix(path, size))
            .transpose()?;
        let text = [old_bytes.as_deref(), new_bytes.as_deref()]
            .into_iter()
            .flatten()
            .all(is_text);
        if !text {
            let digest = |bytes: &Option<Vec<u8>>| {
                bytes.as_ref().map(|b| {
                    use sha2::Digest as _;
                    hex::encode(sha2::Sha256::digest(b))
                })
            };
            return Ok(DiffContent::Binary {
                old_sha256: digest(&old_bytes),
                new_sha256: digest(&new_bytes),
            });
        }
        let as_text = |bytes: &Option<Vec<u8>>| {
            bytes
                .as_deref()
                .map(|b| std::str::from_utf8(b).unwrap_or_default().to_string())
                .unwrap_or_default()
        };
        let diff = lines::diff_text(
            &as_text(&old_bytes),
            &as_text(&new_bytes),
            self.limits.context_lines,
        );
        self.stats.lines_added += diff.lines_added;
        self.stats.lines_removed += diff.lines_removed;
        let bytes: u64 = diff.hunks.iter().map(Hunk::text_bytes).sum();
        if self.output_bytes.saturating_add(bytes) > self.limits.max_output_bytes {
            self.omitted_content += 1;
            self.truncate(TruncationReason::OutputLimit);
            return Ok(DiffContent::Omitted);
        }
        self.output_bytes += bytes;
        Ok(DiffContent::Text {
            hunks: diff.hunks,
            lines_added: diff.lines_added,
            lines_removed: diff.lines_removed,
        })
    }

    fn finish(self) -> TreeDiff {
        TreeDiff {
            files: self.files,
            stats: self.stats,
            truncated: self.reason.map(|reason| Truncation {
                reason,
                omitted_files: self.omitted_files,
                omitted_content: self.omitted_content,
            }),
        }
    }
}

#[cfg(test)]
mod tests;
