//! A line diff: the shortest edit script between two texts, grouped into
//! unified-diff hunks.
//!
//! Myers' O((N+M)·D) algorithm over the lines left after trimming the common
//! prefix and suffix. The search keeps one frontier per edit distance, so its
//! memory is proportional to (N+M)·D; past [`MAX_TRACE_CELLS`] it stops looking
//! for the shortest script and reports the region as a whole replacement. That
//! is still a correct diff — applying it yields the new text — only not a
//! minimal one, and it bounds what a pathological pair of files can cost.

use super::model::{Hunk, HunkLine, LineKind};

/// Frontier cells the search may keep before settling for a replacement.
const MAX_TRACE_CELLS: usize = 4_000_000;

/// One line of a text, and whether it ended with a newline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Line<'a> {
    text: &'a str,
    terminated: bool,
}

fn split_lines(text: &str) -> Vec<Line<'_>> {
    let mut lines = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        match rest.find('\n') {
            Some(end) => {
                lines.push(Line {
                    text: &rest[..end],
                    terminated: true,
                });
                rest = &rest[end + 1..];
            }
            None => {
                lines.push(Line {
                    text: rest,
                    terminated: false,
                });
                rest = "";
            }
        }
    }
    lines
}

/// One step of an edit script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Edit {
    Keep { old: usize, new: usize },
    Delete { old: usize },
    Insert { new: usize },
}

/// The edit script turning `old` into `new`.
fn edit_script(old: &[Line<'_>], new: &[Line<'_>]) -> Vec<Edit> {
    let prefix = old.iter().zip(new).take_while(|(a, b)| a == b).count();
    let suffix = old[prefix..]
        .iter()
        .rev()
        .zip(new[prefix..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let old_mid = &old[prefix..old.len() - suffix];
    let new_mid = &new[prefix..new.len() - suffix];

    let mut script: Vec<Edit> = (0..prefix).map(|i| Edit::Keep { old: i, new: i }).collect();
    let middle = myers(old_mid, new_mid).unwrap_or_else(|| replacement(old_mid, new_mid));
    script.extend(middle.into_iter().map(|edit| match edit {
        Edit::Keep { old, new } => Edit::Keep {
            old: old + prefix,
            new: new + prefix,
        },
        Edit::Delete { old } => Edit::Delete { old: old + prefix },
        Edit::Insert { new } => Edit::Insert { new: new + prefix },
    }));
    let old_tail = old.len() - suffix;
    let new_tail = new.len() - suffix;
    script.extend((0..suffix).map(|i| Edit::Keep {
        old: old_tail + i,
        new: new_tail + i,
    }));
    script
}

/// Every old line deleted, then every new line inserted.
fn replacement(old: &[Line<'_>], new: &[Line<'_>]) -> Vec<Edit> {
    (0..old.len())
        .map(|old| Edit::Delete { old })
        .chain((0..new.len()).map(|new| Edit::Insert { new }))
        .collect()
}

/// The shortest edit script, or `None` when finding it would take more than
/// [`MAX_TRACE_CELLS`] of frontier.
fn myers(old: &[Line<'_>], new: &[Line<'_>]) -> Option<Vec<Edit>> {
    let n = old.len() as isize;
    let m = new.len() as isize;
    let max = (n + m) as usize;
    if max == 0 {
        return Some(Vec::new());
    }
    let width = 2 * max + 1;
    let offset = max as isize;
    let mut frontier = vec![0isize; width];
    let mut trace: Vec<Vec<isize>> = Vec::new();
    for d in 0..=max as isize {
        if trace.len().saturating_mul(width) > MAX_TRACE_CELLS {
            return None;
        }
        trace.push(frontier.clone());
        let mut k = -d;
        while k <= d {
            let index = (k + offset) as usize;
            let mut x = if k == -d || (k != d && frontier[index - 1] < frontier[index + 1]) {
                frontier[index + 1]
            } else {
                frontier[index - 1] + 1
            };
            let mut y = x - k;
            while x < n && y < m && old[x as usize] == new[y as usize] {
                x += 1;
                y += 1;
            }
            frontier[index] = x;
            if x >= n && y >= m {
                return Some(backtrack(&trace, offset, n, m));
            }
            k += 2;
        }
    }
    None
}

fn backtrack(trace: &[Vec<isize>], offset: isize, n: isize, m: isize) -> Vec<Edit> {
    let mut edits = Vec::new();
    let (mut x, mut y) = (n, m);
    for (d, frontier) in trace.iter().enumerate().rev() {
        let d = d as isize;
        let k = x - y;
        let index = (k + offset) as usize;
        let previous_k = if k == -d || (k != d && frontier[index - 1] < frontier[index + 1]) {
            k + 1
        } else {
            k - 1
        };
        let previous_x = frontier[(previous_k + offset) as usize];
        let previous_y = previous_x - previous_k;
        while x > previous_x && y > previous_y {
            x -= 1;
            y -= 1;
            edits.push(Edit::Keep {
                old: x as usize,
                new: y as usize,
            });
        }
        if d > 0 {
            if x == previous_x {
                edits.push(Edit::Insert {
                    new: previous_y as usize,
                });
            } else {
                edits.push(Edit::Delete {
                    old: previous_x as usize,
                });
            }
        }
        x = previous_x;
        y = previous_y;
    }
    edits.reverse();
    edits
}

/// A text diff: its hunks and how many lines each side lost and gained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TextDiff {
    pub hunks: Vec<Hunk>,
    pub lines_added: u64,
    pub lines_removed: u64,
}

/// Diff `old` against `new`, with `context` unchanged lines around each change.
pub(super) fn diff_text(old: &str, new: &str, context: usize) -> TextDiff {
    let old_lines = split_lines(old);
    let new_lines = split_lines(new);
    let script = edit_script(&old_lines, &new_lines);
    let lines_added = script
        .iter()
        .filter(|e| matches!(e, Edit::Insert { .. }))
        .count() as u64;
    let lines_removed = script
        .iter()
        .filter(|e| matches!(e, Edit::Delete { .. }))
        .count() as u64;
    TextDiff {
        hunks: hunks(&script, &old_lines, &new_lines, context),
        lines_added,
        lines_removed,
    }
}

/// Group an edit script into hunks: each change with up to `context` kept
/// lines either side, and changes closer than twice that merged into one.
fn hunks(script: &[Edit], old: &[Line<'_>], new: &[Line<'_>], context: usize) -> Vec<Hunk> {
    let changed: Vec<usize> = script
        .iter()
        .enumerate()
        .filter(|(_, e)| !matches!(e, Edit::Keep { .. }))
        .map(|(i, _)| i)
        .collect();
    let mut hunks = Vec::new();
    let mut i = 0;
    while i < changed.len() {
        let start = changed[i].saturating_sub(context);
        let mut end = changed[i];
        while i + 1 < changed.len() && changed[i + 1] <= end + 2 * context + 1 {
            i += 1;
            end = changed[i];
        }
        let end = (end + context + 1).min(script.len());
        hunks.push(hunk(&script[start..end], old, new));
        i += 1;
    }
    hunks
}

fn hunk(edits: &[Edit], old: &[Line<'_>], new: &[Line<'_>]) -> Hunk {
    // Positions are 1-based. A side with no line in the hunk can only occur
    // when that whole file is empty — any other change carries context lines
    // from both sides — so it reports 0, as unified diff does for an empty
    // file.
    let old_start = edits
        .iter()
        .find_map(|e| match e {
            Edit::Keep { old, .. } | Edit::Delete { old } => Some(*old as u64 + 1),
            Edit::Insert { .. } => None,
        })
        .unwrap_or(0);
    let new_start = edits
        .iter()
        .find_map(|e| match e {
            Edit::Keep { new, .. } | Edit::Insert { new } => Some(*new as u64 + 1),
            Edit::Delete { .. } => None,
        })
        .unwrap_or(0);
    let old_lines = edits
        .iter()
        .filter(|e| !matches!(e, Edit::Insert { .. }))
        .count() as u64;
    let new_lines = edits
        .iter()
        .filter(|e| !matches!(e, Edit::Delete { .. }))
        .count() as u64;
    let lines = edits
        .iter()
        .map(|edit| {
            let (kind, line) = match *edit {
                Edit::Keep { new: index, .. } => (LineKind::Context, new[index]),
                Edit::Delete { old: index } => (LineKind::Removed, old[index]),
                Edit::Insert { new: index } => (LineKind::Added, new[index]),
            };
            HunkLine {
                kind,
                text: line.text.to_string(),
                no_newline: !line.terminated,
            }
        })
        .collect();
    Hunk {
        old_start,
        old_lines,
        new_start,
        new_lines,
        lines,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Apply a diff's hunks to `old` and return the result, to check that a
    /// diff is correct rather than merely plausible.
    fn apply(old: &str, diff: &TextDiff) -> String {
        let old_lines = split_lines(old);
        let mut out = String::new();
        let mut cursor = 0usize;
        for hunk in &diff.hunks {
            let start = if hunk.old_lines == 0 {
                hunk.old_start as usize
            } else {
                hunk.old_start as usize - 1
            };
            for line in &old_lines[cursor..start] {
                out.push_str(line.text);
                if line.terminated {
                    out.push('\n');
                }
            }
            cursor = start;
            for line in &hunk.lines {
                match line.kind {
                    LineKind::Context | LineKind::Added => {
                        out.push_str(&line.text);
                        if !line.no_newline {
                            out.push('\n');
                        }
                        if line.kind == LineKind::Context {
                            cursor += 1;
                        }
                    }
                    LineKind::Removed => cursor += 1,
                }
            }
        }
        for line in &old_lines[cursor..] {
            out.push_str(line.text);
            if line.terminated {
                out.push('\n');
            }
        }
        out
    }

    fn roundtrip(old: &str, new: &str) -> TextDiff {
        let diff = diff_text(old, new, 3);
        assert_eq!(apply(old, &diff), new, "diff of {old:?} -> {new:?}");
        diff
    }

    #[test]
    fn identical_texts_have_no_hunks() {
        let diff = roundtrip("a\nb\n", "a\nb\n");
        assert!(diff.hunks.is_empty());
        assert_eq!((diff.lines_added, diff.lines_removed), (0, 0));
    }

    #[test]
    fn one_changed_line_is_one_removal_and_one_addition_with_context() {
        let old = "1\n2\n3\n4\n5\n6\n7\n";
        let new = "1\n2\n3\nfour\n5\n6\n7\n";
        let diff = roundtrip(old, new);
        assert_eq!(diff.hunks.len(), 1);
        let hunk = &diff.hunks[0];
        assert_eq!((hunk.old_start, hunk.old_lines), (1, 7));
        assert_eq!((hunk.new_start, hunk.new_lines), (1, 7));
        assert_eq!((diff.lines_added, diff.lines_removed), (1, 1));
    }

    #[test]
    fn distant_changes_become_separate_hunks() {
        let old: String = (1..=40).map(|i| format!("line {i}\n")).collect();
        let new = old
            .replace("line 5\n", "five\n")
            .replace("line 35\n", "thirty-five\n");
        let diff = roundtrip(&old, &new);
        assert_eq!(diff.hunks.len(), 2);
        assert_eq!(diff.hunks[1].old_start, 32);
    }

    #[test]
    fn added_and_removed_files_and_edges_roundtrip() {
        roundtrip("", "new\nfile\n");
        roundtrip("gone\n", "");
        roundtrip("a\nb", "a\nb\n");
        roundtrip("a\nb\n", "a\nb");
        roundtrip("x\n", "y\n");
        roundtrip("a\nb\nc\n", "b\nc\nd\n");
        roundtrip("a\nb\nc\nd\n", "a\nx\nc\ny\n");
    }

    #[test]
    fn a_missing_final_newline_is_marked() {
        let diff = roundtrip("a\n", "a\nb");
        let last = diff.hunks[0].lines.last().unwrap();
        assert_eq!(last.kind, LineKind::Added);
        assert!(last.no_newline);
    }

    #[test]
    fn an_insertion_into_an_empty_file_starts_at_zero() {
        let diff = roundtrip("", "a\n");
        assert_eq!((diff.hunks[0].old_start, diff.hunks[0].old_lines), (0, 0));
        assert_eq!((diff.hunks[0].new_start, diff.hunks[0].new_lines), (1, 1));
    }

    /// Past the frontier budget the region is reported as a replacement: not
    /// minimal, still exact.
    #[test]
    fn a_pair_too_costly_to_minimise_is_still_an_exact_diff() {
        let old: String = (0..5000).map(|i| format!("old {i}\n")).collect();
        let new: String = (0..5000).map(|i| format!("new {i}\n")).collect();
        let diff = roundtrip(&old, &new);
        assert_eq!((diff.lines_added, diff.lines_removed), (5000, 5000));
    }

    #[test]
    fn the_script_is_minimal_where_it_is_affordable() {
        let diff = roundtrip("a\nb\nc\na\nb\nb\na\n", "c\nb\na\nb\na\nc\n");
        // The classic Myers example has edit distance 5.
        assert_eq!(diff.lines_added + diff.lines_removed, 5);
    }
}
