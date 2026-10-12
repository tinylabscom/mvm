//! Staging and collection that never follow a symlink and never read past a
//! bound.
//!
//! Every walk is held to a [`Budget`] while it reads, not after: a directory
//! listing stops at the first entry over the remaining entry count, a copy
//! stops at the first byte over the remaining byte count, and recursion stops
//! at [`MAX_TREE_DEPTH`]. Directories count as entries, so a tree of empty
//! directories is bounded like a tree of files. Files are opened without
//! following a final symlink and without blocking, and the opened handle is
//! checked to be a regular file, so a path swapped for a symlink or a FIFO
//! after it was inspected is refused rather than read.

use super::ScenarioError;
use mvm_contract::pack_scenario::{MAX_OUTPUT_BYTES, MAX_OUTPUT_FILES, PackScenario};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Deepest directory nesting walked below a staged or collected path.
pub const MAX_TREE_DEPTH: usize = 32;

/// Outputs copied out of a finished run's workspace.
#[derive(Debug, Clone)]
pub struct Collected {
    /// Directory holding the copies, laid out by workspace-relative path.
    pub root: PathBuf,
    /// Workspace-relative path of every collected regular file, with its size.
    pub files: BTreeMap<String, u64>,
    pub bytes: u64,
    /// The scenario's byte limit, which also bounds every read of a copy.
    pub byte_limit: u64,
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
/// existing empty directory. Staging is held to the schema's output ceilings,
/// so a public tree cannot stage more than a run could ever collect.
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
    let mut budget = Budget::new("staged files", MAX_OUTPUT_BYTES, MAX_OUTPUT_FILES);
    for file in &scenario.initial_files {
        let source = resolve(public, &file.source)?;
        let destination = workspace.join(&file.destination);
        make_parents(workspace, &file.destination)?;
        copy_tree(&source, &destination, &file.source, 0, &mut budget)?;
    }
    Ok(())
}

/// Copy the declared outputs out of `workspace` into `dest`, within the
/// scenario's limits. An absent output collects nothing; its checks fail.
/// `max_output_files` counts every collected entry, directories included.
pub fn collect_outputs(
    workspace: &Path,
    scenario: &PackScenario,
    dest: &Path,
) -> Result<Collected, ScenarioError> {
    let limits = &scenario.limits;
    let mut budget = Budget::new(
        "collected outputs",
        limits.max_output_bytes,
        limits.max_output_files,
    );
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
        copy_tree(&source, &dest.join(output), output, 0, &mut budget)?;
    }
    Ok(Collected {
        root: dest.to_path_buf(),
        bytes: limits.max_output_bytes - budget.bytes_left,
        byte_limit: limits.max_output_bytes,
        files: budget.files,
    })
}

struct Budget {
    tree: &'static str,
    bytes_left: u64,
    entries_left: u64,
    byte_limit: u64,
    entry_limit: u64,
    files: BTreeMap<String, u64>,
}

impl Budget {
    fn new(tree: &'static str, bytes: u64, entries: u32) -> Self {
        Self {
            tree,
            bytes_left: bytes,
            entries_left: u64::from(entries),
            byte_limit: bytes,
            entry_limit: u64::from(entries),
            files: BTreeMap::new(),
        }
    }

    fn take_entry(&mut self) -> Result<(), ScenarioError> {
        if self.entries_left == 0 {
            return Err(self.entries_exceeded());
        }
        self.entries_left -= 1;
        Ok(())
    }

    fn entries_exceeded(&self) -> ScenarioError {
        ScenarioError::Limit {
            tree: self.tree,
            limit: self.entry_limit,
            unit: "files and directories",
        }
    }

    fn bytes_exceeded(&self) -> ScenarioError {
        ScenarioError::Limit {
            tree: self.tree,
            limit: self.byte_limit,
            unit: "bytes",
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
    depth: usize,
    budget: &mut Budget,
) -> Result<(), ScenarioError> {
    budget.take_entry()?;
    let meta = fs::symlink_metadata(source)
        .map_err(|e| ScenarioError::io(format!("reading {relative:?}"), e))?;
    let kind = meta.file_type();
    if kind.is_symlink() {
        return Err(escape(relative, "symbolic link"));
    }
    if kind.is_dir() {
        if depth >= MAX_TREE_DEPTH {
            return Err(ScenarioError::Limit {
                tree: budget.tree,
                limit: MAX_TREE_DEPTH as u64,
                unit: "levels of nesting",
            });
        }
        fs::create_dir(destination)
            .map_err(|e| ScenarioError::io(format!("creating {relative:?}"), e))?;
        for name in list_bounded(source, relative, budget)? {
            copy_tree(
                &source.join(&name),
                &destination.join(&name),
                &format!("{relative}/{name}"),
                depth + 1,
                budget,
            )?;
        }
        return Ok(());
    }
    if !kind.is_file() {
        return Err(escape(relative, "neither a regular file nor a directory"));
    }
    let copied = copy_bounded(source, destination, relative, budget)?;
    budget.files.insert(relative.to_string(), copied);
    Ok(())
}

/// The sorted names in `dir`, refusing a listing longer than the entries the
/// budget has left before holding more of it in memory.
fn list_bounded(dir: &Path, relative: &str, budget: &Budget) -> Result<Vec<String>, ScenarioError> {
    let mut names = Vec::new();
    let entries =
        fs::read_dir(dir).map_err(|e| ScenarioError::io(format!("listing {relative:?}"), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| ScenarioError::io(format!("listing {relative:?}"), e))?;
        if names.len() as u64 >= budget.entries_left {
            return Err(budget.entries_exceeded());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| escape(relative, "non-UTF-8 file name"))?;
        names.push(name);
    }
    names.sort();
    Ok(names)
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
    let input = open_regular(source, relative)?;
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
            return Err(budget.bytes_exceeded());
        }
        output
            .write_all(&buffer[..read])
            .map_err(|e| ScenarioError::io(format!("writing copy of {relative:?}"), e))?;
    }
    budget.bytes_left -= copied;
    Ok(copied)
}

/// Open `path` for reading only if it is a regular file: a final symlink is
/// refused by the open itself, a FIFO or device cannot block the open, and
/// the handle's own metadata, not the path's, decides.
fn open_regular(path: &Path, relative: &str) -> Result<File, ScenarioError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| open_error(relative, e))?;
    let meta = file
        .metadata()
        .map_err(|e| ScenarioError::io(format!("reading {relative:?}"), e))?;
    if !meta.is_file() {
        return Err(escape(relative, "neither a regular file nor a directory"));
    }
    Ok(file)
}

fn open_error(relative: &str, error: std::io::Error) -> ScenarioError {
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::ELOOP) {
        return escape(relative, "symbolic link");
    }
    ScenarioError::io(format!("opening {relative:?}"), error)
}

/// Read a regular file of at most `limit` bytes, refusing a longer one after
/// reading one byte past the limit and no more.
pub(super) fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, ScenarioError> {
    let display = path.display().to_string();
    let file = open_regular(path, &display)?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| ScenarioError::io(format!("reading {display}"), e))?;
    if bytes.len() as u64 > limit {
        return Err(ScenarioError::Limit {
            tree: "a read file",
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
