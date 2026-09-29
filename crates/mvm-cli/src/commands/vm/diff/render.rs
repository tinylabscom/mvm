//! Turn a tree diff into what `vm diff` prints: a unified diff, a `--stat`
//! summary, or two columns side by side.
//!
//! Every renderer writes to a `String` so its output can be checked exactly.
//! Nothing here reads a file: the content is already in the diff, bounded by
//! the limits it was computed under.

use std::fmt::Write as _;

use mvm_fs::tree_diff::{
    ChangeKind, DiffContent, EntryKind, FileDiff, Hunk, HunkLine, LineKind, TreeDiff,
    TruncationReason,
};

/// One volume's diff and the prefix its paths print under.
pub(super) struct VolumeDiff<'a> {
    /// Prefix for every path: the volume name when several are shown, empty
    /// for one.
    pub prefix: &'a str,
    pub diff: &'a TreeDiff,
}

fn display_path(prefix: &str, path: &str) -> String {
    if prefix.is_empty() {
        path.to_string()
    } else {
        format!("{prefix}/{path}")
    }
}

fn kind_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::File => "file",
        EntryKind::Directory => "directory",
        EntryKind::Symlink => "symlink",
        EntryKind::Special => "special file",
    }
}

fn short(digest: Option<&String>) -> &str {
    digest.map_or("-", |d| &d[..d.len().min(12)])
}

fn hunk_header(hunk: &Hunk) -> String {
    format!(
        "@@ -{},{} +{},{} @@",
        hunk.old_start, hunk.old_lines, hunk.new_start, hunk.new_lines
    )
}

fn marker(kind: LineKind) -> char {
    match kind {
        LineKind::Context => ' ',
        LineKind::Removed => '-',
        LineKind::Added => '+',
    }
}

/// The unified diff of every volume, in path order.
pub(super) fn unified(volumes: &[VolumeDiff<'_>]) -> String {
    let mut out = String::new();
    for volume in volumes {
        for file in &volume.diff.files {
            unified_file(&mut out, &display_path(volume.prefix, &file.path), file);
        }
    }
    out
}

fn unified_file(out: &mut String, path: &str, file: &FileDiff) {
    let old_name = match file.change {
        ChangeKind::Added => "/dev/null".to_string(),
        _ => format!("a/{path}"),
    };
    let new_name = match file.change {
        ChangeKind::Removed => "/dev/null".to_string(),
        _ => format!("b/{path}"),
    };
    match &file.content {
        DiffContent::Text { hunks, .. } => {
            let _ = writeln!(out, "--- {old_name}\n+++ {new_name}");
            for hunk in hunks {
                let _ = writeln!(out, "{}", hunk_header(hunk));
                for line in &hunk.lines {
                    let _ = writeln!(out, "{}{}", marker(line.kind), line.text);
                    if line.no_newline {
                        let _ = writeln!(out, "\\ No newline at end of file");
                    }
                }
            }
        }
        DiffContent::Binary {
            old_sha256,
            new_sha256,
        } => {
            let _ = writeln!(
                out,
                "Binary files {old_name} and {new_name} differ (sha256 {} -> {})",
                short(old_sha256.as_ref()),
                short(new_sha256.as_ref())
            );
        }
        DiffContent::TooLarge {
            limit_bytes,
            old_sha256,
            new_sha256,
        } => {
            let _ = writeln!(
                out,
                "{path}: larger than {limit_bytes} bytes, not shown (sha256 {} -> {})",
                short(old_sha256.as_ref()),
                short(new_sha256.as_ref())
            );
        }
        DiffContent::Symlink {
            old_target,
            new_target,
        } => {
            let _ = writeln!(
                out,
                "symlink {path}: {} -> {}",
                old_target.as_deref().unwrap_or("(none)"),
                new_target.as_deref().unwrap_or("(none)")
            );
        }
        DiffContent::ModeOnly => {
            let _ = writeln!(
                out,
                "mode change {:o} -> {:o} {path}",
                file.old.as_ref().map_or(0, |e| e.mode),
                file.new.as_ref().map_or(0, |e| e.mode)
            );
        }
        DiffContent::Entry => {
            let _ = writeln!(out, "{}", entry_line(path, file));
        }
        DiffContent::Omitted => {
            let _ = writeln!(
                out,
                "{path}: changed (text left out: the output limit was reached)"
            );
        }
    }
}

fn entry_line(path: &str, file: &FileDiff) -> String {
    let old = file.old.as_ref().map(|e| kind_name(e.kind));
    let new = file.new.as_ref().map(|e| kind_name(e.kind));
    match (file.change, old, new) {
        (ChangeKind::Added, _, Some(kind)) => format!("new {kind} {path}"),
        (ChangeKind::Removed, Some(kind), _) => format!("deleted {kind} {path}"),
        (ChangeKind::TypeChanged, Some(old), Some(new)) => {
            format!("{path}: {old} became a {new}")
        }
        _ => format!("changed {path}"),
    }
}

/// `--stat`: one line per change with its line counts, then the totals.
pub(super) fn stat(volumes: &[VolumeDiff<'_>]) -> String {
    let rows: Vec<(String, String)> = volumes
        .iter()
        .flat_map(|volume| {
            volume.diff.files.iter().map(move |file| {
                let path = display_path(volume.prefix, &file.path);
                let detail = match &file.content {
                    DiffContent::Text {
                        lines_added,
                        lines_removed,
                        ..
                    } => format!("+{lines_added} -{lines_removed}"),
                    DiffContent::Binary { .. } => "binary".to_string(),
                    DiffContent::TooLarge { .. } => "too large".to_string(),
                    DiffContent::Symlink { .. } => "symlink".to_string(),
                    DiffContent::ModeOnly => "mode".to_string(),
                    DiffContent::Omitted => "changed".to_string(),
                    DiffContent::Entry => match file.change {
                        ChangeKind::Added => "added".to_string(),
                        ChangeKind::Removed => "removed".to_string(),
                        _ => "type changed".to_string(),
                    },
                };
                (path, detail)
            })
        })
        .collect();
    let width = rows.iter().map(|(path, _)| path.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (path, detail) in &rows {
        let _ = writeln!(out, " {path:<width$} | {detail}");
    }
    let (mut changed, mut added, mut removed) = (0u64, 0u64, 0u64);
    for volume in volumes {
        changed += volume.diff.stats.changed();
        added += volume.diff.stats.lines_added;
        removed += volume.diff.stats.lines_removed;
    }
    let _ = writeln!(
        out,
        " {changed} {} changed, {added} insertion{}(+), {removed} deletion{}(-)",
        if changed == 1 { "entry" } else { "entries" },
        if added == 1 { "" } else { "s" },
        if removed == 1 { "" } else { "s" },
    );
    out
}

/// Two columns: the old text on the left, the new on the right. Removed and
/// added runs are paired line by line; a context line appears on both sides.
pub(super) fn side_by_side(volumes: &[VolumeDiff<'_>], width: usize) -> String {
    let column = (width.saturating_sub(3) / 2).max(20);
    let mut out = String::new();
    for volume in volumes {
        for file in &volume.diff.files {
            let path = display_path(volume.prefix, &file.path);
            let DiffContent::Text { hunks, .. } = &file.content else {
                // Non-text changes have no columns to show.
                unified_file(&mut out, &path, file);
                continue;
            };
            let _ = writeln!(out, "=== {path}");
            for hunk in hunks {
                let _ = writeln!(out, "{}", hunk_header(hunk));
                for (left, gutter, right) in paired_rows(&hunk.lines) {
                    if gutter == ' ' {
                        // A context line carries no change mark, so it gets
                        // the plain two-column gap rather than an empty
                        // gutter column.
                        let _ = writeln!(out, "{} {}", fit(&left, column), clip(&right, column));
                    } else {
                        let _ = writeln!(
                            out,
                            "{} {gutter} {}",
                            fit(&left, column),
                            clip(&right, column)
                        );
                    }
                }
            }
        }
    }
    // Trailing padding on a row whose right side is empty is noise.
    out.lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
        + if out.is_empty() { "" } else { "\n" }
}

fn clip(text: &str, column: usize) -> String {
    let mut clipped: String = text.chars().take(column).collect();
    if text.chars().count() > column {
        clipped.pop();
        clipped.push('>');
    }
    clipped
}

fn fit(text: &str, column: usize) -> String {
    let clipped = clip(text, column);
    let pad = column - clipped.chars().count();
    format!("{clipped}{}", " ".repeat(pad))
}

/// Rows of `(left, gutter, right)`. The gutter is `|` for a changed pair, `<`
/// for a line only on the left, `>` for one only on the right, and a space
/// for context.
fn paired_rows(lines: &[HunkLine]) -> Vec<(String, char, String)> {
    let mut rows = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].kind == LineKind::Context {
            rows.push((lines[i].text.clone(), ' ', lines[i].text.clone()));
            i += 1;
            continue;
        }
        let removed: Vec<&HunkLine> = lines[i..]
            .iter()
            .take_while(|l| l.kind == LineKind::Removed)
            .collect();
        i += removed.len();
        let added: Vec<&HunkLine> = lines[i..]
            .iter()
            .take_while(|l| l.kind == LineKind::Added)
            .collect();
        i += added.len();
        for row in 0..removed.len().max(added.len()) {
            let left = removed.get(row).map(|l| l.text.clone());
            let right = added.get(row).map(|l| l.text.clone());
            let gutter = match (&left, &right) {
                (Some(_), Some(_)) => '|',
                (Some(_), None) => '<',
                _ => '>',
            };
            rows.push((left.unwrap_or_default(), gutter, right.unwrap_or_default()));
        }
    }
    rows
}

/// The notice for a diff a limit cut short, or `None` when it is complete.
pub(super) fn truncation_notice(volumes: &[VolumeDiff<'_>]) -> Option<String> {
    let mut files = 0u64;
    let mut content = 0u64;
    let mut reasons = Vec::new();
    for volume in volumes {
        if let Some(truncation) = &volume.diff.truncated {
            files += truncation.omitted_files;
            content += truncation.omitted_content;
            reasons.push(truncation.reason);
        }
    }
    if reasons.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    if files > 0 {
        parts.push(format!(
            "{files} more changed {} not listed",
            if files == 1 { "entry" } else { "entries" }
        ));
    }
    if content > 0 {
        parts.push(format!(
            "the text of {content} {} left out",
            if content == 1 { "file" } else { "files" }
        ));
    }
    let limit = if reasons.contains(&TruncationReason::FileLimit) {
        "--max-files"
    } else {
        "--max-output-bytes"
    };
    Some(format!(
        "diff truncated: {}; raise {limit} to see more, or use --stat",
        parts.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_fs::tree_diff::{DiffStats, EntryInfo, Truncation};

    fn file(bytes: u64) -> EntryInfo {
        EntryInfo {
            kind: EntryKind::File,
            size: bytes,
            mode: 0o644,
        }
    }

    fn line(kind: LineKind, text: &str) -> HunkLine {
        HunkLine {
            kind,
            text: text.into(),
            no_newline: false,
        }
    }

    fn sample() -> TreeDiff {
        TreeDiff {
            files: vec![
                FileDiff {
                    path: "notes.txt".into(),
                    change: ChangeKind::Added,
                    old: None,
                    new: Some(file(3)),
                    content: DiffContent::Text {
                        hunks: vec![Hunk {
                            old_start: 0,
                            old_lines: 0,
                            new_start: 1,
                            new_lines: 1,
                            lines: vec![line(LineKind::Added, "hi")],
                        }],
                        lines_added: 1,
                        lines_removed: 0,
                    },
                },
                FileDiff {
                    path: "src/lib.rs".into(),
                    change: ChangeKind::Modified,
                    old: Some(file(10)),
                    new: Some(file(11)),
                    content: DiffContent::Text {
                        hunks: vec![Hunk {
                            old_start: 1,
                            old_lines: 2,
                            new_start: 1,
                            new_lines: 2,
                            lines: vec![
                                line(LineKind::Context, "fn a() {}"),
                                line(LineKind::Removed, "fn b() {}"),
                                line(LineKind::Added, "fn b() { 1 }"),
                            ],
                        }],
                        lines_added: 1,
                        lines_removed: 1,
                    },
                },
                FileDiff {
                    path: "logo.png".into(),
                    change: ChangeKind::Modified,
                    old: Some(file(4)),
                    new: Some(file(4)),
                    content: DiffContent::Binary {
                        old_sha256: Some("a".repeat(64)),
                        new_sha256: Some("b".repeat(64)),
                    },
                },
            ],
            stats: DiffStats {
                added: 1,
                modified: 2,
                lines_added: 2,
                lines_removed: 1,
                ..DiffStats::default()
            },
            truncated: None,
        }
    }

    #[test]
    fn unified_output_reads_like_a_patch() {
        let diff = sample();
        let out = unified(&[VolumeDiff {
            prefix: "",
            diff: &diff,
        }]);
        assert_eq!(
            out,
            "--- /dev/null\n+++ b/notes.txt\n@@ -0,0 +1,1 @@\n+hi\n\
             --- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,2 +1,2 @@\n fn a() {}\n-fn b() {}\n+fn b() { 1 }\n\
             Binary files a/logo.png and b/logo.png differ (sha256 aaaaaaaaaaaa -> bbbbbbbbbbbb)\n"
        );
    }

    #[test]
    fn several_volumes_prefix_their_paths() {
        let diff = sample();
        let out = unified(&[VolumeDiff {
            prefix: "src-vol",
            diff: &diff,
        }]);
        assert!(out.contains("+++ b/src-vol/src/lib.rs"), "{out}");
    }

    #[test]
    fn stat_lists_counts_and_totals() {
        let diff = sample();
        let out = stat(&[VolumeDiff {
            prefix: "",
            diff: &diff,
        }]);
        assert_eq!(
            out,
            " notes.txt  | +1 -0\n src/lib.rs | +1 -1\n logo.png   | binary\n \
             3 entries changed, 2 insertions(+), 1 deletion(-)\n"
        );
    }

    #[test]
    fn side_by_side_pairs_removed_with_added() {
        let diff = sample();
        let out = side_by_side(
            &[VolumeDiff {
                prefix: "",
                diff: &diff,
            }],
            43,
        );
        assert!(out.contains("fn a() {}            fn a() {}"), "{out}");
        assert!(out.contains("fn b() {}            | fn b() { 1 }"), "{out}");
        assert!(out.contains("                     > hi"), "{out}");
        assert!(out.contains("Binary files a/logo.png"), "{out}");
    }

    #[test]
    fn a_complete_diff_has_no_notice_and_a_cut_one_says_what_was_left_out() {
        let mut diff = sample();
        let complete = [VolumeDiff {
            prefix: "",
            diff: &diff,
        }];
        assert!(truncation_notice(&complete).is_none());
        diff.truncated = Some(Truncation {
            reason: TruncationReason::FileLimit,
            omitted_files: 4,
            omitted_content: 1,
        });
        let notice = truncation_notice(&[VolumeDiff {
            prefix: "",
            diff: &diff,
        }])
        .unwrap();
        assert_eq!(
            notice,
            "diff truncated: 4 more changed entries not listed, the text of 1 file left out; \
             raise --max-files to see more, or use --stat"
        );
    }

    #[test]
    fn non_text_entries_describe_themselves() {
        let dir = FileDiff {
            path: "build".into(),
            change: ChangeKind::TypeChanged,
            old: Some(file(1)),
            new: Some(EntryInfo {
                kind: EntryKind::Directory,
                size: 0,
                mode: 0o755,
            }),
            content: DiffContent::Entry,
        };
        let mut out = String::new();
        unified_file(&mut out, "build", &dir);
        assert_eq!(out, "build: file became a directory\n");
    }
}
