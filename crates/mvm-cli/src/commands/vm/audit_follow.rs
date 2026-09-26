//! Incremental reads of a tenant's live audit chain, for anything that has to
//! watch it grow: `trust audit tail --chain -f` and the live egress-denial
//! notices a foreground run prints.
//!
//! The chain rotates. Once the live `<tenant>.jsonl` reaches its size limit it
//! is sealed and renamed to a numbered segment, and a fresh live file takes its
//! place. A reader that re-opened the path and seeked to its old offset would
//! skip every entry written after the new file started until the new file grew
//! past that offset. This one follows the open file across the rename instead,
//! drains it, and only then moves to the replacement — the way `tail -F` does.
//!
//! Entries are parsed with the chain's own envelope type and nothing else: a
//! line that is not a signed envelope is returned as text for the caller to
//! show, never guessed at.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use mvm_hostd::supervisor::{PlanAuditEntry, SignedEnvelope};

/// One line of a chain file: the entry it carries, or the raw text of a line
/// that is not a signed envelope.
#[derive(Debug, Clone)]
pub(in crate::commands) enum ChainLine {
    Entry(Box<PlanAuditEntry>),
    Foreign(String),
}

/// Parse one chain line through the chain's own envelope type.
pub(in crate::commands) fn parse_chain_line(line: &str) -> ChainLine {
    match serde_json::from_str::<SignedEnvelope>(line) {
        Ok(envelope) => ChainLine::Entry(Box::new(envelope.entry)),
        Err(_) => ChainLine::Foreign(line.to_string()),
    }
}

/// An open handle on the live chain file and how far into it has been read.
struct Cursor {
    file: File,
    inode: u64,
    pos: u64,
}

impl Cursor {
    fn open_at(path: &Path, from_end: bool) -> Option<Self> {
        let mut file = File::open(path).ok()?;
        let meta = file.metadata().ok()?;
        let pos = if from_end { meta.len() } else { 0 };
        file.seek(SeekFrom::Start(pos)).ok()?;
        Some(Self {
            file,
            inode: meta.ino(),
            pos,
        })
    }

    /// Every byte appended since the last read.
    fn drain(&mut self, into: &mut Vec<u8>) {
        let before = into.len();
        if self.file.read_to_end(into).is_ok() {
            self.pos += (into.len() - before) as u64;
        }
    }
}

/// Follows a tenant's live chain file, returning each complete line appended
/// since the previous poll.
pub(in crate::commands) struct ChainFollower {
    path: PathBuf,
    cursor: Option<Cursor>,
    /// A line the writer had not finished when it was read. Held until its
    /// newline arrives, so a caller never parses half an entry.
    partial: Vec<u8>,
}

impl ChainFollower {
    /// Follow from the file's current end: only entries written from now on.
    /// A file that does not exist yet is followed from its first byte once it
    /// appears.
    pub(in crate::commands) fn from_end(path: PathBuf) -> Self {
        let cursor = Cursor::open_at(&path, true);
        Self {
            path,
            cursor,
            partial: Vec::new(),
        }
    }

    /// Complete lines appended since the last poll, across a rotation.
    pub(in crate::commands) fn poll(&mut self) -> Vec<String> {
        let mut bytes = std::mem::take(&mut self.partial);
        match self.cursor.as_mut() {
            Some(cursor) => cursor.drain(&mut bytes),
            None => {
                self.cursor = Cursor::open_at(&self.path, false);
                if let Some(cursor) = self.cursor.as_mut() {
                    cursor.drain(&mut bytes);
                }
            }
        }
        if self.rotated() {
            // The writer seals the old file before renaming it, so once the
            // path names a different file nothing more will reach the old one:
            // drain it a last time, then start the replacement from its start.
            if let Some(cursor) = self.cursor.as_mut() {
                cursor.drain(&mut bytes);
            }
            self.cursor = Cursor::open_at(&self.path, false);
            if let Some(cursor) = self.cursor.as_mut() {
                cursor.drain(&mut bytes);
            }
        }
        self.split_lines(bytes)
    }

    /// Whether the path now names a different file from the one being read.
    fn rotated(&self) -> bool {
        let Some(cursor) = self.cursor.as_ref() else {
            return false;
        };
        std::fs::metadata(&self.path).is_ok_and(|meta| meta.ino() != cursor.inode)
    }

    fn split_lines(&mut self, bytes: Vec<u8>) -> Vec<String> {
        let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        self.partial = bytes[complete..].to_vec();
        String::from_utf8_lossy(&bytes[..complete])
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Bytes read so far from the file currently followed. Test-visible.
    #[cfg(test)]
    fn position(&self) -> Option<u64> {
        self.cursor.as_ref().map(|cursor| cursor.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn append(path: &Path, text: &str) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        file.write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn following_from_the_end_skips_what_was_already_there() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("local.jsonl");
        append(&path, "old-1\nold-2\n");
        let mut follower = ChainFollower::from_end(path.clone());
        assert!(follower.poll().is_empty());
        append(&path, "new-1\n");
        assert_eq!(follower.poll(), ["new-1"]);
    }

    #[test]
    fn a_half_written_line_is_held_until_its_newline_arrives() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("local.jsonl");
        append(&path, "");
        let mut follower = ChainFollower::from_end(path.clone());
        append(&path, "first\nsec");
        assert_eq!(follower.poll(), ["first"]);
        append(&path, "ond\n");
        assert_eq!(follower.poll(), ["second"]);
    }

    #[test]
    fn a_file_that_appears_later_is_read_from_its_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("local.jsonl");
        let mut follower = ChainFollower::from_end(path.clone());
        assert!(follower.poll().is_empty());
        append(&path, "born\n");
        assert_eq!(follower.poll(), ["born"]);
    }

    /// Rotation renames the live file and starts a new one. Re-opening the
    /// path at the old offset would skip the new file's first entries; the
    /// follower instead drains the renamed file and reads the new one whole.
    #[test]
    fn rotation_loses_nothing_on_either_side_of_the_rename() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("local.jsonl");
        append(&path, "before-follow\n");
        let mut follower = ChainFollower::from_end(path.clone());
        append(&path, "last-in-old\n");
        std::fs::rename(&path, dir.path().join("local.seg-000001.jsonl")).unwrap();
        append(&path, "first-in-new\n");
        assert_eq!(follower.poll(), ["last-in-old", "first-in-new"]);
        assert_eq!(follower.position(), Some("first-in-new\n".len() as u64));
        append(&path, "second-in-new\n");
        assert_eq!(follower.poll(), ["second-in-new"]);
    }

    #[test]
    fn a_line_that_is_not_an_envelope_is_kept_as_text() {
        assert!(matches!(
            parse_chain_line("not json"),
            ChainLine::Foreign(text) if text == "not json"
        ));
    }
}
