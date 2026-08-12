//! `xtask sprint`
//!
//! Renders the per-file delivery entries as one document, newest first.
//!
//! Prints to stdout rather than writing a file. A committed aggregate would be
//! a second thing every session touches on every change — which is the exact
//! shape of the problem `specs/sprint/delivery/` exists to remove. Anyone who
//! wants it in a file can redirect it somewhere untracked.

use std::path::Path;

use anyhow::{Context, Result};

const DELIVERY_DIR: &str = "specs/sprint/delivery";

pub fn run(workspace: &Path) -> Result<()> {
    let dir = workspace.join(DELIVERY_DIR);
    let mut entries: Vec<(String, String)> = Vec::new();
    let listing = std::fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in listing {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".md") || name == "README.md" {
            continue;
        }
        let body = std::fs::read_to_string(entry.path())
            .with_context(|| format!("reading {}", entry.path().display()))?;
        entries.push((name, body));
    }

    // Newest first by the ordering the filenames already carry, which is the
    // issue or plan number. Falling back to the name keeps it total and stable
    // for anything that does not lead with a number.
    entries.sort_by(|a, b| {
        leading_number(&b.0)
            .cmp(&leading_number(&a.0))
            .then(a.0.cmp(&b.0))
    });

    println!("# Delivery log\n");
    println!(
        "Rendered from `{DELIVERY_DIR}/` — {} entr{}. Not a committed file; see that \
         directory's README for why.\n",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" }
    );
    for (name, body) in &entries {
        println!("<!-- {name} -->");
        println!("{}\n", body.trim_end());
    }
    Ok(())
}

/// The leading integer in a filename, for ordering. `0` when absent.
fn leading_number(name: &str) -> u64 {
    let digits: String = name.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_by_leading_number_descending() {
        let mut names = vec!["319-a.md", "2365-b.md", "no-number.md", "42-c.md"];
        names.sort_by(|a, b| leading_number(b).cmp(&leading_number(a)).then(a.cmp(b)));
        assert_eq!(
            names,
            vec!["2365-b.md", "319-a.md", "42-c.md", "no-number.md"]
        );
    }

    #[test]
    fn a_name_without_a_number_sorts_last_rather_than_erroring() {
        assert_eq!(leading_number("no-number.md"), 0);
        assert_eq!(leading_number("2365-audit-log-rotation.md"), 2365);
    }
}
