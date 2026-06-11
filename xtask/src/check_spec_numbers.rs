//! `xtask check-spec-numbers`
//!
//! ADR and plan filenames use a numeric prefix as their stable
//! reference handle. Parallel PRs can race and pick the same prefix,
//! leaving a numeric reference ambiguous. This lint fails when
//! any prefix repeats within `specs/plans/` or within `specs/adrs/`.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::Path;

pub fn run(workspace: &Path) -> Result<()> {
    let mut failures = Vec::new();
    for kind in [SpecKind::Plan, SpecKind::Adr] {
        let duplicates = duplicate_numbers(&workspace.join("specs").join(kind.dir_name()))?;
        for (number, files) in duplicates {
            failures.push(format!(
                "{} number {number} is used by: {}",
                kind.label(),
                files.join(", ")
            ));
        }
    }

    if !failures.is_empty() {
        bail!(
            "check-spec-numbers: duplicate spec number(s):\n{}",
            failures.join("\n")
        );
    }

    eprintln!("check-spec-numbers: clean (plan and ADR prefixes are unique)");
    Ok(())
}

#[derive(Clone, Copy)]
enum SpecKind {
    Plan,
    Adr,
}

impl SpecKind {
    fn dir_name(self) -> &'static str {
        match self {
            Self::Plan => "plans",
            Self::Adr => "adrs",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Adr => "ADR",
        }
    }
}

fn duplicate_numbers(dir: &Path) -> Result<BTreeMap<u32, Vec<String>>> {
    let mut by_number: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry.with_context(|| format!("reading entry under {}", dir.display()))?;
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("md") {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(number) = spec_number(name) else {
            continue;
        };
        by_number.entry(number).or_default().push(name.to_string());
    }

    Ok(by_number
        .into_iter()
        .filter_map(|(number, mut files)| {
            if files.len() < 2 {
                return None;
            }
            files.sort();
            Some((number, files))
        })
        .collect())
}

fn spec_number(name: &str) -> Option<u32> {
    let (prefix, rest) = name.split_once('-')?;
    if prefix.is_empty() || rest.is_empty() || !prefix.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    prefix.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn spec_number_accepts_numeric_prefix() {
        assert_eq!(spec_number("074-sandbox.md"), Some(74));
        assert_eq!(spec_number("74-sandbox.md"), Some(74));
    }

    #[test]
    fn spec_number_rejects_non_spec_names() {
        assert_eq!(spec_number("README.md"), None);
        assert_eq!(spec_number("adr-001.md"), None);
        assert_eq!(spec_number("001.md"), None);
        assert_eq!(spec_number("-missing.md"), None);
    }

    #[test]
    fn duplicate_numbers_reports_collisions_only() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        write(dir.join("001-alpha.md"));
        write(dir.join("001-beta.md"));
        write(dir.join("002-gamma.md"));
        write(dir.join("README.md"));

        let duplicates = duplicate_numbers(dir).unwrap();
        assert_eq!(
            duplicates.get(&1).unwrap(),
            &vec!["001-alpha.md".to_string(), "001-beta.md".to_string()]
        );
        assert!(!duplicates.contains_key(&2));
    }

    fn write(path: PathBuf) {
        std::fs::write(path, "# test\n").unwrap();
    }
}
