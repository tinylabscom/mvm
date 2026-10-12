//! Staging and collection that never follow a symlink.

use super::ScenarioError;
use mvm_contract::pack_scenario::PackScenario;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Outputs copied out of a finished run's workspace.
#[derive(Debug, Clone)]
pub struct Collected {
    /// Directory holding the copies, laid out by workspace-relative path.
    pub root: PathBuf,
    /// Workspace-relative path of every collected regular file, with its size.
    pub files: BTreeMap<String, u64>,
    pub bytes: u64,
}

impl Collected {
    /// The copy of a collected regular file, if one was collected.
    pub fn file(&self, relative: &str) -> Option<PathBuf> {
        self.files
            .contains_key(relative)
            .then(|| self.root.join(relative))
    }
}

/// Copy each initial file from `public` into `workspace`, which must be an
/// existing empty directory.
pub fn stage_workspace(
    public: &Path,
    scenario: &PackScenario,
    workspace: &Path,
) -> Result<(), ScenarioError> {
    let fresh = fs::read_dir(workspace)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(false);
    if !fresh {
        return Err(ScenarioError::WorkspaceNotFresh(workspace.to_path_buf()));
    }
    for file in &scenario.initial_files {
        let source = resolve(public, &file.source)?;
        let destination = workspace.join(&file.destination);
        make_parents(workspace, &file.destination)?;
        copy_tree(
            &source,
            &destination,
            &file.source,
            &mut Budget::unbounded(),
        )?;
    }
    Ok(())
}

/// Copy the declared outputs out of `workspace` into `dest`, within the
/// scenario's limits. An absent output collects nothing; its checks fail.
pub fn collect_outputs(
    workspace: &Path,
    scenario: &PackScenario,
    dest: &Path,
) -> Result<Collected, ScenarioError> {
    let mut budget = Budget {
        bytes_left: scenario.limits.max_output_bytes,
        files_left: u64::from(scenario.limits.max_output_files),
        byte_limit: scenario.limits.max_output_bytes,
        file_limit: u64::from(scenario.limits.max_output_files),
        files: BTreeMap::new(),
    };
    for output in &scenario.outputs {
        let source = match resolve(workspace, output) {
            Ok(source) => source,
            Err(ScenarioError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        make_parents(dest, output)?;
        copy_tree(&source, &dest.join(output), output, &mut budget)?;
    }
    let bytes = scenario.limits.max_output_bytes - budget.bytes_left;
    Ok(Collected {
        root: dest.to_path_buf(),
        files: budget.files,
        bytes,
    })
}

struct Budget {
    bytes_left: u64,
    files_left: u64,
    byte_limit: u64,
    file_limit: u64,
    files: BTreeMap<String, u64>,
}

impl Budget {
    fn unbounded() -> Self {
        Self {
            bytes_left: u64::MAX,
            files_left: u64::MAX,
            byte_limit: u64::MAX,
            file_limit: u64::MAX,
            files: BTreeMap::new(),
        }
    }
}

/// Join `relative` under `root`, refusing a symlink at any component.
fn resolve(root: &Path, relative: &str) -> Result<PathBuf, ScenarioError> {
    let mut path = root.to_path_buf();
    for component in relative.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(escape(relative, "non-normal path component"));
        }
        path.push(component);
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| ScenarioError::io(format!("reading {relative:?}"), e))?;
        if meta.file_type().is_symlink() {
            return Err(escape(relative, "symbolic link"));
        }
    }
    Ok(path)
}

fn make_parents(root: &Path, relative: &str) -> Result<(), ScenarioError> {
    let mut path = root.to_path_buf();
    let mut parts: Vec<&str> = relative.split('/').collect();
    parts.pop();
    for part in parts {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return Err(escape(relative, "parent is not a directory")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs::create_dir(&path)
                .map_err(|e| ScenarioError::io(format!("creating parent of {relative:?}"), e))?,
            Err(e) => return Err(ScenarioError::io(format!("reading {relative:?}"), e)),
        }
    }
    Ok(())
}

fn copy_tree(
    source: &Path,
    destination: &Path,
    relative: &str,
    budget: &mut Budget,
) -> Result<(), ScenarioError> {
    let meta = fs::symlink_metadata(source)
        .map_err(|e| ScenarioError::io(format!("reading {relative:?}"), e))?;
    let kind = meta.file_type();
    if kind.is_symlink() {
        return Err(escape(relative, "symbolic link"));
    }
    if kind.is_dir() {
        fs::create_dir(destination)
            .map_err(|e| ScenarioError::io(format!("creating {relative:?}"), e))?;
        let mut entries: Vec<_> = fs::read_dir(source)
            .map_err(|e| ScenarioError::io(format!("listing {relative:?}"), e))?
            .collect::<Result<_, _>>()
            .map_err(|e| ScenarioError::io(format!("listing {relative:?}"), e))?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| escape(relative, "non-UTF-8 file name"))?;
            copy_tree(
                &entry.path(),
                &destination.join(name),
                &format!("{relative}/{name}"),
                budget,
            )?;
        }
        return Ok(());
    }
    if !kind.is_file() {
        return Err(escape(relative, "neither a regular file nor a directory"));
    }
    if budget.files_left == 0 {
        return Err(ScenarioError::OutputLimit {
            limit: budget.file_limit,
            unit: "files",
        });
    }
    budget.files_left -= 1;
    let copied = copy_bounded(source, destination, relative, budget)?;
    budget.files.insert(relative.to_string(), copied);
    Ok(())
}

/// Copy at most the remaining byte budget, refusing a file that is longer
/// rather than truncating it. The length is measured while reading, not taken
/// from metadata.
fn copy_bounded(
    source: &Path,
    destination: &Path,
    relative: &str,
    budget: &mut Budget,
) -> Result<u64, ScenarioError> {
    let input =
        File::open(source).map_err(|e| ScenarioError::io(format!("opening {relative:?}"), e))?;
    let mut output = File::create_new(destination)
        .map_err(|e| ScenarioError::io(format!("creating copy of {relative:?}"), e))?;
    let mut limited = input.take(budget.bytes_left.saturating_add(1));
    let mut buffer = [0u8; 64 * 1024];
    let mut copied: u64 = 0;
    loop {
        let read = limited
            .read(&mut buffer)
            .map_err(|e| ScenarioError::io(format!("reading {relative:?}"), e))?;
        if read == 0 {
            break;
        }
        copied += read as u64;
        if copied > budget.bytes_left {
            return Err(ScenarioError::OutputLimit {
                limit: budget.byte_limit,
                unit: "bytes",
            });
        }
        output
            .write_all(&buffer[..read])
            .map_err(|e| ScenarioError::io(format!("writing copy of {relative:?}"), e))?;
    }
    budget.bytes_left -= copied;
    Ok(copied)
}

pub(super) fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, ScenarioError> {
    let meta = fs::symlink_metadata(path)
        .map_err(|e| ScenarioError::io(format!("reading {}", path.display()), e))?;
    if !meta.is_file() {
        return Err(escape(&path.display().to_string(), "not a regular file"));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|f| f.take(limit + 1).read_to_end(&mut bytes))
        .map_err(|e| ScenarioError::io(format!("reading {}", path.display()), e))?;
    if bytes.len() as u64 > limit {
        return Err(ScenarioError::OutputLimit {
            limit,
            unit: "bytes",
        });
    }
    Ok(bytes)
}

pub(super) fn require_real_dir(path: &Path, name: &'static str) -> Result<(), ScenarioError> {
    let meta = fs::symlink_metadata(path)
        .map_err(|e| ScenarioError::io(format!("opening scenario {name}/"), e))?;
    if meta.is_dir() {
        Ok(())
    } else {
        Err(escape(name, "not a real directory"))
    }
}

fn escape(path: &str, reason: &'static str) -> ScenarioError {
    ScenarioError::PathEscape {
        path: path.to_string(),
        reason,
    }
}
