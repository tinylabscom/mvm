//! What a tree diff reports. Serialized as the `--json` form of `vm diff`, so
//! every type refuses fields it does not know.

use serde::{Deserialize, Serialize};

/// Every change between two trees, in path order, with the text of the ones
/// that are text and fit the limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeDiff {
    pub files: Vec<FileDiff>,
    pub stats: DiffStats,
    /// Present when a limit stopped the diff from showing everything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated: Option<Truncation>,
}

/// Counts across the whole diff, including entries a limit left out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffStats {
    pub added: u64,
    pub removed: u64,
    pub modified: u64,
    pub type_changed: u64,
    pub lines_added: u64,
    pub lines_removed: u64,
}

impl DiffStats {
    /// Entries changed in any way.
    #[must_use]
    pub fn changed(&self) -> u64 {
        self.added + self.removed + self.modified + self.type_changed
    }
}

/// Why the diff is not complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Truncation {
    pub reason: TruncationReason,
    /// Changed entries counted in [`DiffStats`] but not listed in `files`.
    pub omitted_files: u64,
    /// Listed entries whose text was left out to stay within the output
    /// budget.
    pub omitted_content: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TruncationReason {
    /// More changed entries than [`super::DiffLimits::max_files`].
    FileLimit,
    /// More diff text than [`super::DiffLimits::max_output_bytes`].
    OutputLimit,
}

/// One changed entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileDiff {
    /// Path relative to the tree root, `/`-separated.
    pub path: String,
    pub change: ChangeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<EntryInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<EntryInfo>,
    pub content: DiffContent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
    /// The same path is a different kind of entry — a file became a directory.
    TypeChanged,
}

/// What an entry is on one side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryInfo {
    pub kind: EntryKind,
    pub size: u64,
    /// Permission bits (`0o7777`).
    pub mode: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    /// A device, FIFO or socket: reported, never read.
    Special,
}

/// The content side of a change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DiffContent {
    /// A line diff.
    Text {
        hunks: Vec<Hunk>,
        lines_added: u64,
        lines_removed: u64,
    },
    /// Not text: sizes and digests only.
    Binary {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old_sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        new_sha256: Option<String>,
    },
    /// Larger than [`super::DiffLimits::max_file_bytes`]: compared by digest,
    /// not shown.
    TooLarge {
        limit_bytes: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old_sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        new_sha256: Option<String>,
    },
    /// A symbolic link; its target is text the guest chose, shown as-is and
    /// never followed.
    Symlink {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old_target: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        new_target: Option<String>,
    },
    /// Same bytes, different permission bits.
    ModeOnly,
    /// A directory, a special file, or a type change: nothing to show but the
    /// entry itself.
    Entry,
    /// Left out to stay within the output budget.
    Omitted,
}

/// One unified-diff hunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hunk {
    /// 1-based first old line, or 0 for an empty old file.
    pub old_start: u64,
    pub old_lines: u64,
    pub new_start: u64,
    pub new_lines: u64,
    pub lines: Vec<HunkLine>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HunkLine {
    pub kind: LineKind,
    pub text: String,
    /// The line ends its file without a newline.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_newline: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineKind {
    Context,
    Removed,
    Added,
}

impl Hunk {
    /// Bytes of line text this hunk carries, for the output budget.
    pub(super) fn text_bytes(&self) -> u64 {
        self.lines.iter().map(|l| l.text.len() as u64 + 1).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_diff_roundtrips_through_json_and_refuses_unknown_fields() {
        let diff = TreeDiff {
            files: vec![FileDiff {
                path: "src/main.rs".into(),
                change: ChangeKind::Modified,
                old: Some(EntryInfo {
                    kind: EntryKind::File,
                    size: 3,
                    mode: 0o644,
                }),
                new: Some(EntryInfo {
                    kind: EntryKind::File,
                    size: 4,
                    mode: 0o644,
                }),
                content: DiffContent::Text {
                    hunks: vec![Hunk {
                        old_start: 1,
                        old_lines: 1,
                        new_start: 1,
                        new_lines: 1,
                        lines: vec![
                            HunkLine {
                                kind: LineKind::Removed,
                                text: "ab".into(),
                                no_newline: false,
                            },
                            HunkLine {
                                kind: LineKind::Added,
                                text: "abc".into(),
                                no_newline: false,
                            },
                        ],
                    }],
                    lines_added: 1,
                    lines_removed: 1,
                },
            }],
            stats: DiffStats {
                modified: 1,
                lines_added: 1,
                lines_removed: 1,
                ..DiffStats::default()
            },
            truncated: None,
        };
        let json = serde_json::to_value(&diff).unwrap();
        assert_eq!(json["files"][0]["content"]["kind"], "text");
        assert_eq!(json["files"][0]["change"], "modified");
        assert!(json.get("truncated").is_none());
        let back: TreeDiff = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(back, diff);

        let mut extra = json;
        extra["files"][0]["surprise"] = serde_json::json!(1);
        assert!(serde_json::from_value::<TreeDiff>(extra).is_err());
    }
}
