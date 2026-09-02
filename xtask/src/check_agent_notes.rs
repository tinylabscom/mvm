//! `xtask check-agent-notes`
//!
//! Keeps `.agent-memory/notes/` from rotting into a folder of undated
//! fragments.
//!
//! The notes are committed so that a finding — especially a *negative* one —
//! outlives the session that paid for it, travels with the code, and shows up
//! in a diff. That only works if the corpus stays uniform enough to grep and
//! honest enough to trust, which is four properties:
//!
//! 1. Frontmatter parses, and the slug matches the filename. Recall is
//!    `rg` over these files; a note whose title and path disagree is found
//!    under one name and cited under another.
//! 2. `date` is a real calendar date. A finding without a date is not a
//!    finding, it is a rumour.
//! 3. `tags` is non-empty. The tag is the only index there is.
//! 4. `superseded_by` and every `[[slug]]` link name a note that exists.
//!    A dangling link in a committed corpus is a dead end for the next
//!    reader.
//!
//! # What it does not check
//!
//! Whether the date is in the past. Comparing against the wall clock makes the
//! gate's verdict depend on when it runs, which is the property that made
//! `check-claim-witness-freshness` split its PR behaviour from its scheduled
//! behaviour. A calendar-valid date is the part that can be checked the same
//! way everywhere.
//!
//! It also does not judge content. Nothing here can tell a good finding from a
//! bad one; the gate holds the shape, and review holds the substance.

use anyhow::{Result, bail};
use std::collections::BTreeSet;
use std::path::Path;

/// Where the committed notes live.
const NOTES_DIR: &str = ".agent-memory/notes";

/// A parsed note.
#[derive(Debug, PartialEq, Eq)]
pub struct Note {
    /// Filename stem, which is the note's slug.
    pub slug: String,
    /// One-line summary.
    pub title: String,
    /// ISO-8601 calendar date.
    pub date: String,
    /// Non-empty tag set.
    pub tags: Vec<String>,
    /// Slug of the note that replaces this one, when it has been replaced.
    pub superseded_by: Option<String>,
    /// Slugs this note links to with `[[…]]`.
    pub links: Vec<String>,
}

/// Split the leading `---` block off a note.
fn frontmatter(text: &str) -> Option<(&str, &str)> {
    let rest = text.strip_prefix("---\n")?;
    let end = rest.find("\n---\n")?;
    Some((&rest[..end], &rest[end + 5..]))
}

/// Read `key: value` out of a frontmatter block.
fn field<'a>(block: &'a str, key: &str) -> Option<&'a str> {
    block.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name.trim() == key).then(|| value.trim())
    })
}

/// Parse the inline `[a, b]` list form.
fn inline_list(value: &str) -> Option<Vec<String>> {
    let inner = value.strip_prefix('[')?.strip_suffix(']')?;
    Some(
        inner
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

/// Whether `s` is a real `YYYY-MM-DD` calendar date.
#[must_use]
pub fn is_calendar_date(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    let [y, m, d] = parts[..] else { return false };
    if y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return false;
    }
    let (Ok(year), Ok(month), Ok(day)) = (y.parse::<u32>(), m.parse::<u32>(), d.parse::<u32>())
    else {
        return false;
    };
    if !(1..=12).contains(&month) || day == 0 {
        return false;
    }
    day <= days_in_month(year, month)
}

/// Length of `month` in `year`.
fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        _ => 28,
    }
}

/// Slugs named by `[[…]]` links in `body`.
fn wiki_links(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(open) = rest.find("[[") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("]]") else { break };
        out.push(after[..close].trim().to_string());
        rest = &after[close + 2..];
    }
    out
}

/// Parse one note.
///
/// # Errors
///
/// When the frontmatter is missing, a required field is absent or empty, or
/// the date is not a calendar date.
pub fn parse(slug: &str, text: &str) -> Result<Note> {
    let Some((block, body)) = frontmatter(text) else {
        bail!("no `---` frontmatter block");
    };
    let title = field(block, "title").unwrap_or_default();
    if title.is_empty() {
        bail!("`title` is missing or empty");
    }
    let date = field(block, "date").unwrap_or_default();
    if !is_calendar_date(date) {
        bail!("`date` is `{date}`, which is not a YYYY-MM-DD calendar date");
    }
    let tags = field(block, "tags")
        .and_then(inline_list)
        .unwrap_or_default();
    if tags.is_empty() {
        bail!("`tags` is missing or empty; the tag is the only index there is");
    }
    Ok(Note {
        slug: slug.to_string(),
        title: title.to_string(),
        date: date.to_string(),
        tags,
        superseded_by: field(block, "superseded_by")
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        links: wiki_links(body),
    })
}

/// Run the gate.
///
/// # Errors
///
/// When a note fails to parse, or names a note that does not exist.
pub fn run(root: &Path) -> Result<()> {
    let dir = root.join(NOTES_DIR);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        println!("check-agent-notes: no {NOTES_DIR} directory; nothing to check");
        return Ok(());
    };

    let mut errors = Vec::new();
    let mut notes = Vec::new();

    let mut paths: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .collect();
    paths.sort();

    for path in paths {
        let slug = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) => {
                errors.push(format!("{NOTES_DIR}/{slug}.md: unreadable: {err}"));
                continue;
            }
        };
        match parse(&slug, &text) {
            Ok(note) => notes.push(note),
            Err(err) => errors.push(format!("{NOTES_DIR}/{slug}.md: {err}")),
        }
    }

    let slugs: BTreeSet<&str> = notes.iter().map(|n| n.slug.as_str()).collect();
    for note in &notes {
        if let Some(target) = &note.superseded_by {
            if target == &note.slug {
                errors.push(format!("{NOTES_DIR}/{}.md: supersedes itself", note.slug));
            } else if !slugs.contains(target.as_str()) {
                errors.push(format!(
                    "{NOTES_DIR}/{}.md: superseded_by names `{target}`, which is not a note",
                    note.slug
                ));
            }
        }
        for link in &note.links {
            if !slugs.contains(link.as_str()) {
                errors.push(format!(
                    "{NOTES_DIR}/{}.md: links to [[{link}]], which is not a note. A dangling \
                     link in a committed corpus is a dead end for the next reader.",
                    note.slug
                ));
            }
        }
    }

    if !errors.is_empty() {
        for err in &errors {
            eprintln!("[error] {err}");
        }
        bail!("check-agent-notes: {} note(s) are malformed", errors.len());
    }

    println!("check-agent-notes: clean ({} note(s))", notes.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "---\ntitle: A finding\ndate: 2026-09-01\ntags: [perf, hvf]\n---\n\nBody.\n";

    #[test]
    fn a_well_formed_note_parses() {
        let note = parse("a-finding", GOOD).expect("parses");
        assert_eq!(note.title, "A finding");
        assert_eq!(note.date, "2026-09-01");
        assert_eq!(note.tags, vec!["perf", "hvf"]);
        assert_eq!(note.superseded_by, None);
    }

    #[test]
    fn a_note_without_frontmatter_is_refused() {
        let err = parse("x", "just prose\n").unwrap_err().to_string();
        assert!(err.contains("frontmatter"), "{err}");
    }

    #[test]
    fn an_empty_tag_list_is_refused() {
        let text = GOOD.replace("tags: [perf, hvf]", "tags: []");
        let err = parse("x", &text).unwrap_err().to_string();
        assert!(err.contains("tags"), "{err}");
    }

    #[test]
    fn a_date_that_is_not_a_calendar_date_is_refused() {
        assert!(is_calendar_date("2026-02-28"));
        assert!(is_calendar_date("2024-02-29"));
        assert!(!is_calendar_date("2026-02-30"));
        assert!(!is_calendar_date("2026-13-01"));
        assert!(!is_calendar_date("2026-9-1"));
        assert!(!is_calendar_date("yesterday"));
        let text = GOOD.replace("2026-09-01", "2026-02-30");
        assert!(parse("x", &text).is_err());
    }

    #[test]
    fn wiki_links_are_extracted() {
        assert_eq!(
            wiki_links("see [[one-note]] and [[two-note]]"),
            vec!["one-note", "two-note"]
        );
        // An unterminated link must not swallow the rest of the note.
        assert_eq!(wiki_links("see [[unclosed"), Vec::<String>::new());
    }

    /// The gate must pass on the corpus as it stands.
    #[test]
    fn the_committed_notes_are_well_formed() {
        run(&crate::workspace_root()).expect("committed notes parse and link");
    }
}
