//! Finding instruction files under a root.
//!
//! The walk never follows a symlinked directory: what it reports is what sits
//! under the root, not whatever a link inside it points at. A symlinked *file*
//! whose own path matches is reported, and [`super::verify`] decides what its
//! content is. `.git` is skipped — it holds no file an agent reads as an
//! instruction, and it is the one directory in a checkout that is routinely
//! enormous.

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::is_sidecar_name;
use super::policy::EffectivePolicy;

/// Why a root is being scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootKind {
    /// A `--mount` source directory copied into the guest.
    Mount,
    /// A declared `--asset` file or tree.
    Asset,
    /// The workload's own source directory.
    Workload,
    /// A path named on the command line.
    Explicit,
}

impl RootKind {
    /// The audit-label spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RootKind::Mount => "mount",
            RootKind::Asset => "asset",
            RootKind::Workload => "workload",
            RootKind::Explicit => "explicit",
        }
    }
}

/// A file or directory to look for instruction files in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRoot {
    pub path: PathBuf,
    pub kind: RootKind,
}

impl ScanRoot {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, kind: RootKind) -> Self {
        Self {
            path: path.into(),
            kind,
        }
    }
}

/// One instruction file found under a root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstructionFile {
    /// The root it was found under.
    pub root: PathBuf,
    /// Why that root was scanned.
    pub root_kind: RootKind,
    /// Its path relative to the root, `/`-separated.
    pub relative: String,
    /// Its full path.
    pub path: PathBuf,
}

/// Every instruction file under `root`, sorted by relative path.
///
/// A root that is itself a file is matched by its own name, so an asset that
/// *is* a `SKILL.md` is found. A root that does not exist is an error: the
/// caller is about to copy it into a guest, and a scan that quietly found
/// nothing there would read as a clean result.
pub fn find_instruction_files(
    root: &ScanRoot,
    policy: &EffectivePolicy,
) -> std::io::Result<Vec<InstructionFile>> {
    let meta = std::fs::symlink_metadata(&root.path)?;
    let mut found = Vec::new();
    if meta.is_dir() {
        walk(root, &root.path, "", policy, &mut found)?;
    } else if let Some(name) = root.path.file_name().and_then(|n| n.to_str())
        && !is_sidecar_name(name)
        && policy.includes(Path::new(name))
    {
        found.push(InstructionFile {
            root: root.path.clone(),
            root_kind: root.kind,
            relative: name.to_string(),
            path: root.path.clone(),
        });
    }
    found.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok(found)
}

fn walk(
    root: &ScanRoot,
    dir: &Path,
    prefix: &str,
    policy: &EffectivePolicy,
    found: &mut Vec<InstructionFile>,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let relative = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if name != ".git" {
                walk(root, &entry.path(), &relative, policy, found)?;
            }
            continue;
        }
        if (file_type.is_file() || file_type.is_symlink())
            && !is_sidecar_name(&name)
            && policy.includes(Path::new(&relative))
        {
            found.push(InstructionFile {
                root: root.path.clone(),
                root_kind: root.kind,
                relative,
                path: entry.path(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, relative: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"# instructions\n").unwrap();
    }

    fn relatives(root: &Path) -> Vec<String> {
        find_instruction_files(
            &ScanRoot::new(root, RootKind::Explicit),
            &EffectivePolicy::builtin(),
        )
        .unwrap()
        .into_iter()
        .map(|f| f.relative)
        .collect()
    }

    #[test]
    fn the_default_includes_find_every_common_agent_file_at_any_depth() {
        let dir = tempfile::tempdir().unwrap();
        for relative in [
            "CLAUDE.md",
            "CLAUDE.local.md",
            "AGENTS.md",
            "sub/pkg/AGENT.md",
            "GEMINI.md",
            "skills/deploy/SKILL.md",
            ".claude/commands/review.md",
            ".claude/agents/nested/helper.md",
            "tools/.cursor/rules/style.mdc",
            ".cursorrules",
        ] {
            write(dir.path(), relative);
        }
        assert_eq!(
            relatives(dir.path()),
            vec![
                ".claude/agents/nested/helper.md",
                ".claude/commands/review.md",
                ".cursorrules",
                "AGENTS.md",
                "CLAUDE.local.md",
                "CLAUDE.md",
                "GEMINI.md",
                "skills/deploy/SKILL.md",
                "sub/pkg/AGENT.md",
                "tools/.cursor/rules/style.mdc",
            ]
        );
    }

    #[test]
    fn ordinary_files_sidecars_and_git_internals_are_not_instruction_files() {
        let dir = tempfile::tempdir().unwrap();
        for relative in [
            "README.md",
            "docs/CLAUDE.txt",
            ".claude/settings.json",
            "CLAUDE.md.sigstore.json",
            ".cursor/rules/style.mdc.mvmsig.json",
            ".git/CLAUDE.md",
        ] {
            write(dir.path(), relative);
        }
        assert!(relatives(dir.path()).is_empty());
    }

    #[test]
    fn matching_ignores_case_because_the_host_filesystem_may() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "sub/claude.MD");
        assert_eq!(relatives(dir.path()), vec!["sub/claude.MD"]);
    }

    #[test]
    fn a_file_root_is_matched_by_its_own_name() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "SKILL.md");
        write(dir.path(), "notes.md");
        let policy = EffectivePolicy::builtin();
        let skill = find_instruction_files(
            &ScanRoot::new(dir.path().join("SKILL.md"), RootKind::Asset),
            &policy,
        )
        .unwrap();
        assert_eq!(skill.len(), 1);
        assert_eq!(skill[0].root_kind, RootKind::Asset);
        let notes = find_instruction_files(
            &ScanRoot::new(dir.path().join("notes.md"), RootKind::Asset),
            &policy,
        )
        .unwrap();
        assert!(notes.is_empty());
    }

    #[test]
    fn a_missing_root_is_an_error_not_an_empty_result() {
        let dir = tempfile::tempdir().unwrap();
        let err = find_instruction_files(
            &ScanRoot::new(dir.path().join("absent"), RootKind::Mount),
            &EffectivePolicy::builtin(),
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_is_not_followed() {
        let outside = tempfile::tempdir().unwrap();
        write(outside.path(), "CLAUDE.md");
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("linked")).unwrap();
        assert!(relatives(dir.path()).is_empty());
    }
}
