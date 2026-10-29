//! Versioned checkout identities, observed in-process without tool pipelines.
use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use mvm_core::image_set::GitCommit;
pub use mvm_core::image_set::{RepoIdentity, WorktreeState};
use mvm_core::packs::Sha256Hex;
use sha2::{Digest, Sha256};

const MAGIC: &[u8] = b"mvm-checkout-v2\0";
#[derive(Debug, Clone)]
struct IndexEntry {
    path: Vec<u8>,
    mode: u32,
    stage: u32,
    flags: u32,
    oid: Vec<u8>,
}
#[derive(Debug)]
struct FileEntry {
    path: Vec<u8>,
    mode: u32,
    body: Vec<u8>,
}
fn message(e: impl std::fmt::Display) -> String {
    e.to_string()
}

pub fn probe_identity(root: &Path) -> Result<RepoIdentity, String> {
    observe(root, &mut BTreeSet::new())
}
pub fn toplevel(dir: &Path) -> Result<String, String> {
    let repo = repository(dir)?;
    git_rules::Rules::open(&repo, &[])?
        .workdir()?
        .canonicalize()
        .map_err(message)?
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| "checkout root is not UTF-8".to_owned())
}
fn repository(dir: &Path) -> Result<PathBuf, String> {
    let dir = dir.canonicalize().map_err(message)?;
    let mut root = None;
    for ancestor in dir.ancestors() {
        match ancestor.join(".git").symlink_metadata() {
            Ok(_) => {
                root = Some(ancestor);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(format!(
                    "reading repository metadata in {}: {e}",
                    ancestor.display()
                ));
            }
        }
    }
    let root = root.ok_or_else(|| format!("{} is not a Git worktree", dir.display()))?;
    Ok(root.to_path_buf())
}
fn tree_entries(
    repo: &git_rules::Rules,
    oid: [u8; 20],
    prefix: &[u8],
    out: &mut Vec<IndexEntry>,
) -> Result<(), String> {
    for entry in repo.tree(oid)? {
        let path = [prefix, entry.name.as_slice()].concat();
        validate_path(&path)?;
        let mode = entry.mode;
        if mode == 0o040000 {
            tree_entries(repo, entry.id, &[path.as_slice(), b"/"].concat(), out)?;
        } else {
            out.push(IndexEntry {
                path,
                mode,
                stage: 0,
                flags: 0,
                oid: entry.id.to_vec(),
            });
        }
    }
    Ok(())
}
fn expanded_index(
    repo: &git_rules::Rules,
    index: Vec<IndexEntry>,
) -> Result<Vec<IndexEntry>, String> {
    let mut out = Vec::new();
    for entry in index {
        if entry.mode == 0o040000 {
            let path = entry.path.strip_suffix(b"/").unwrap_or(&entry.path);
            validate_path(path)?;
            let mut children = Vec::new();
            tree_entries(
                repo,
                entry.oid.as_slice().try_into().map_err(message)?,
                &[path, b"/"].concat(),
                &mut children,
            )?;
            for mut child in children {
                child.flags = entry.flags | 4;
                child.stage = entry.stage;
                out.push(child);
            }
        } else {
            validate_path(&entry.path)?;
            out.push(entry);
        }
    }
    out.sort_by(|a, b| (&a.path, a.stage).cmp(&(&b.path, b.stage)));
    Ok(out)
}
fn distinct(index: &[IndexEntry]) -> BTreeMap<Vec<u8>, &IndexEntry> {
    let mut out: BTreeMap<Vec<u8>, &IndexEntry> = BTreeMap::new();
    for entry in index {
        if out.get(&entry.path).is_none_or(|old| old.stage != 2) || entry.stage == 2 {
            out.insert(entry.path.clone(), entry);
        }
    }
    out
}
fn observe(root: &Path, active: &mut BTreeSet<PathBuf>) -> Result<RepoIdentity, String> {
    let repo = repository(root)?;
    let mut rules = git_rules::Rules::open(&repo, &[])?;
    let index = expanded_index(&rules, git_index::read(&rules.git_dir()?.join("index"))?)?;
    let selected = distinct(&index)
        .values()
        .map(|entry| {
            let mut entry = (**entry).clone();
            entry.stage = 0;
            entry
        })
        .collect::<Vec<_>>();
    rules.install_index(&selected)?;
    let root = rules.workdir()?.canonicalize().map_err(message)?;
    if active.len() >= 64 || !active.insert(root.clone()) {
        return Err("recursive submodule cycle or maximum depth exceeded".to_owned());
    }
    let result = observe_repo(&rules, &index, &root, active);
    active.remove(&root);
    result
}
fn observe_repo(
    rules: &git_rules::Rules,
    index: &[IndexEntry],
    root: &Path,
    active: &mut BTreeSet<PathBuf>,
) -> Result<RepoIdentity, String> {
    let (head, tree) = rules.head()?;
    let commit = GitCommit::new(hex::encode(head)).map_err(message)?;
    let mut committed = Vec::new();
    tree_entries(rules, tree, &[], &mut committed)?;
    committed.sort_by(|a, b| a.path.cmp(&b.path));
    let mut dirty = index.iter().any(|e| e.stage != 0 || e.flags & 2 != 0)
        || index.len() != committed.len()
        || index.iter().zip(&committed).any(|(a, b)| {
            a.path != b.path || a.mode != b.mode || a.oid != b.oid || a.stage != b.stage
        });
    let distinct = distinct(index);
    let mut working = Vec::new();
    for (path, entry) in &distinct {
        let file = if entry.mode == 0o160000 {
            submodule(root, entry, active)?
        } else {
            read_file(root, path)?
        };
        if entry.mode == 0o160000 {
            dirty |= file.mode != entry.mode || file.body != [entry.oid.clone(), vec![0]].concat();
        } else {
            let indexed = if entry.flags & 2 != 0 {
                Vec::new()
            } else {
                rules.blob(entry.oid.as_slice().try_into().map_err(message)?)?
            };
            let normalized = if entry.mode == 0o120000 {
                file.body.clone()
            } else {
                normalize(rules, path, &file, &indexed)?
            };
            // Sparse omissions are intentional. Present content is always read,
            // even when assume-valid/skip-worktree would hide a status change.
            if file.mode != 0 || entry.flags & 4 == 0 {
                dirty |= effective_mode(rules, entry.mode, file.mode)? != entry.mode
                    || normalized != indexed;
            }
        }
        working.push(file);
    }
    let mut untracked = Vec::new();
    walk_untracked(root, Path::new(""), &distinct, rules, &mut untracked)?;
    untracked.sort_by(|a, b| a.path.cmp(&b.path));
    dirty |= !untracked.is_empty();
    let worktree = if dirty {
        WorktreeState::Dirty {
            fingerprint: Sha256Hex::new(hex::encode(fingerprint(
                &head, index, &working, &untracked,
            )))
            .map_err(message)?,
        }
    } else {
        WorktreeState::Clean
    };
    Ok(RepoIdentity { commit, worktree })
}
fn effective_mode(rules: &git_rules::Rules, indexed: u32, actual: u32) -> Result<u32, String> {
    if indexed == 0o120000
        && matches!(actual, 0o100644 | 0o100755)
        && !rules.boolean("core.symlinks")?.unwrap_or(true)
    {
        return Ok(indexed);
    }
    if matches!(indexed, 0o100644 | 0o100755)
        && matches!(actual, 0o100644 | 0o100755)
        && !rules.boolean("core.filemode")?.unwrap_or(true)
    {
        Ok(indexed)
    } else {
        Ok(actual)
    }
}
fn submodule(
    root: &Path,
    entry: &IndexEntry,
    active: &mut BTreeSet<PathBuf>,
) -> Result<FileEntry, String> {
    let path = root.join(bytes_as_path(&entry.path)?);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if !meta.is_dir() || meta.file_type().is_symlink() => {
            return read_file(root, &entry.path);
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(message(e)),
    }
    let administrative = path.join(".git").symlink_metadata().is_ok();
    let empty = match std::fs::read_dir(&path) {
        Ok(mut entries) => match entries.next() {
            None => true,
            Some(Ok(_)) => false,
            Some(Err(e)) => return Err(message(e)),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => return Err(message(e)),
    };
    let body = if empty && !administrative {
        [entry.oid.clone(), vec![0]].concat()
    } else {
        if !administrative {
            return Err(format!(
                "submodule {} has no repository metadata",
                path.display()
            ));
        }
        let identity = observe(&path, active)?;
        let mut body = hex::decode(identity.commit.as_str()).map_err(message)?;
        match identity.worktree {
            WorktreeState::Clean => body.push(0),
            WorktreeState::Dirty { fingerprint } => {
                body.push(1);
                body.extend(hex::decode(fingerprint.as_str()).map_err(message)?);
            }
        }
        body
    };
    Ok(FileEntry {
        path: entry.path.clone(),
        mode: 0o160000,
        body,
    })
}
fn read_file(root: &Path, name: &[u8]) -> Result<FileEntry, String> {
    let relative = bytes_as_path(name)?;
    let missing = || FileEntry {
        path: name.to_vec(),
        mode: 0,
        body: Vec::new(),
    };
    if let Some(parent) = relative.parent() {
        let mut ancestor = root.to_path_buf();
        for component in parent.components() {
            ancestor.push(component);
            match std::fs::symlink_metadata(&ancestor) {
                Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
                Ok(_) => return Ok(missing()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(missing()),
                Err(e) => return Err(message(e)),
            }
        }
    }
    let path = root.join(relative);
    let (mode, body) = match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(missing()),
        Err(e) => return Err(message(e)),
        Ok(meta) if meta.file_type().is_symlink() => (
            0o120000,
            std::fs::read_link(&path)
                .map_err(message)?
                .as_os_str()
                .as_encoded_bytes()
                .to_vec(),
        ),
        Ok(meta) if meta.is_file() => {
            #[cfg(unix)]
            let executable = {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode() & 0o100 != 0
            };
            #[cfg(not(unix))]
            let executable = false;
            (
                if executable { 0o100755 } else { 0o100644 },
                std::fs::read(&path).map_err(message)?,
            )
        }
        Ok(meta) if meta.is_dir() => (0o040000, Vec::new()),
        Ok(_) => return Err(format!("unsupported special file {}", path.display())),
    };
    Ok(FileEntry {
        path: name.to_vec(),
        mode,
        body,
    })
}
fn walk_untracked(
    root: &Path,
    relative: &Path,
    index: &BTreeMap<Vec<u8>, &IndexEntry>,
    rules: &git_rules::Rules,
    out: &mut Vec<FileEntry>,
) -> Result<(), String> {
    let mut children = std::fs::read_dir(root.join(relative))
        .map_err(message)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(message)?;
    children.sort_by_key(|e| e.file_name());
    let ignore_case = rules.boolean("core.ignorecase")?.unwrap_or(false);
    for child in children {
        if child
            .file_name()
            .as_encoded_bytes()
            .eq_ignore_ascii_case(b".git")
        {
            continue;
        }
        let path = relative.join(child.file_name());
        let raw = repository_path_bytes(&path)?;
        if index.contains_key(&raw)
            || (ignore_case && index.keys().any(|p| p.eq_ignore_ascii_case(&raw)))
        {
            continue;
        }
        let kind = child.file_type().map_err(message)?;
        let tracked = index.keys().any(|p| {
            p.get(..raw.len()).is_some_and(|prefix| {
                prefix == raw.as_slice() || (ignore_case && prefix.eq_ignore_ascii_case(&raw))
            }) && p.get(raw.len()) == Some(&b'/')
        });
        if !tracked && rules.ignored(&path)? {
            continue;
        }
        if kind.is_dir() {
            walk_untracked(root, &path, index, rules, out)?;
        } else {
            out.push(read_file(root, &raw)?);
        }
    }
    Ok(())
}
fn normalize(
    rules: &git_rules::Rules,
    path: &[u8],
    file: &FileEntry,
    indexed: &[u8],
) -> Result<Vec<u8>, String> {
    use git_rules::Attribute;
    for name in ["filter", "working-tree-encoding"] {
        if matches!(
            rules.attribute(path, name)?,
            Attribute::Set | Attribute::Value(_)
        ) {
            return Err(format!(
                "unsupported external filter or working-tree-encoding for {:?}",
                path
            ));
        }
    }
    let text = rules.attribute(path, "text")?;
    let auto = text == Attribute::Value(b"auto".to_vec());
    let mut text = match text {
        Attribute::Set => Some(true),
        Attribute::Unset => Some(false),
        Attribute::Value(v) if v == b"input" => Some(true),
        _ => None,
    };
    if text.is_none() && !auto {
        text = match rules.attribute(path, "crlf")? {
            Attribute::Set => Some(true),
            Attribute::Unset => Some(false),
            Attribute::Value(v) if v == b"input" => Some(true),
            _ => None,
        };
    }
    let eol = matches!(rules.attribute(path,"eol")?,Attribute::Value(v) if v==b"lf" || v==b"crlf");
    let ident = matches!(
        rules.attribute(path, "ident")?,
        Attribute::Set | Attribute::Value(_)
    );
    if !matches!(file.mode, 0o100644 | 0o100755) {
        return Ok(file.body.clone());
    }
    let autocrlf = rules
        .string("core.autocrlf")?
        .is_some_and(|v| v.eq_ignore_ascii_case(b"true") || v.eq_ignore_ascii_case(b"input"));
    let automatic = text.is_none() && (auto || autocrlf);
    let (binary, _) = text_stats(&file.body);
    let (indexed_binary, indexed_crlf) = text_stats(indexed);
    let convert = text == Some(true)
        || (text.is_none() && eol && !auto)
        || (automatic && !binary && (indexed_binary || indexed_crlf == 0));
    let mut body = if convert {
        file.body
            .windows(2)
            .enumerate()
            .filter_map(|(i, w)| (w != b"\r\n").then_some(file.body[i]))
            .chain(file.body.last().copied())
            .collect()
    } else {
        file.body.clone()
    };
    if ident {
        body = collapse_ident(&body);
    }
    Ok(body)
}
fn text_stats(body: &[u8]) -> (bool, usize) {
    let mut printable = 0usize;
    let mut nonprintable = 0usize;
    let mut crlf = 0usize;
    let mut lone_cr = false;
    let mut null = false;
    let mut i = 0usize;
    while i < body.len() {
        let byte = body[i];
        i += 1;
        match byte {
            13 => {
                if body.get(i) == Some(&10) {
                    crlf += 1;
                    i += 1;
                } else {
                    lone_cr = true;
                }
            }
            10 => {}
            0 => {
                null = true;
                nonprintable += 1;
            }
            8 | 9 | 27 | 12 => printable += 1,
            1..=31 | 127 => nonprintable += 1,
            _ => printable += 1,
        }
    }
    (lone_cr || null || (printable >> 7) < nonprintable, crlf)
}
fn collapse_ident(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < body.len() {
        if body[i..].starts_with(b"$Id:")
            && let Some(end) = body[i + 4..].iter().position(|b| *b == b'$' || *b == b'\n')
            && body[i + 4 + end] == b'$'
        {
            out.extend_from_slice(b"$Id$");
            i += 5 + end;
            continue;
        }
        out.push(body[i]);
        i += 1;
    }
    out
}
fn fingerprint(
    head: &[u8],
    index: &[IndexEntry],
    working: &[FileEntry],
    untracked: &[FileEntry],
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(MAGIC);
    h.update(head);
    h.update(b"I");
    h.update((index.len() as u64).to_le_bytes());
    for e in index {
        field(&mut h, &e.path);
        h.update(e.mode.to_le_bytes());
        h.update(e.stage.to_le_bytes());
        h.update(e.flags.to_le_bytes());
        h.update(&e.oid);
    }
    for (tag, files) in [(b"W", working), (b"U", untracked)] {
        h.update(tag);
        h.update((files.len() as u64).to_le_bytes());
        for e in files {
            field(&mut h, &e.path);
            h.update(e.mode.to_le_bytes());
            field(&mut h, &e.body);
        }
    }
    h.finalize().to_vec()
}
fn field(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}
#[cfg(unix)]
fn bytes_as_path(name: &[u8]) -> Result<&Path, String> {
    use std::os::unix::ffi::OsStrExt;
    validate_path(name)?;
    Ok(Path::new(OsStr::from_bytes(name)))
}
#[cfg(not(unix))]
fn bytes_as_path(name: &[u8]) -> Result<&Path, String> {
    validate_path(name)?;
    std::str::from_utf8(name).map(Path::new).map_err(message)
}
fn validate_path(name: &[u8]) -> Result<(), String> {
    if name.contains(&0)
        || (cfg!(windows) && (name.contains(&b'\\') || name.contains(&b':')))
        || name
            .split(|b| *b == b'/')
            .any(|p| p.is_empty() || p == b"." || p == b".." || p.eq_ignore_ascii_case(b".git"))
    {
        Err("unsafe repository path".to_owned())
    } else {
        Ok(())
    }
}
#[cfg(unix)]
fn repository_path_bytes(path: &Path) -> Result<Vec<u8>, String> {
    use std::os::unix::ffi::OsStrExt;
    Ok(path.as_os_str().as_bytes().to_vec())
}
#[cfg(not(unix))]
fn repository_path_bytes(path: &Path) -> Result<Vec<u8>, String> {
    path.to_str()
        .map(|p| p.replace('\\', "/").into_bytes())
        .ok_or_else(|| "repository path is not UTF-8".to_owned())
}
#[path = "git_index.rs"]
mod git_index;
#[path = "git_rules.rs"]
mod git_rules;
#[path = "repository_config.rs"]
mod repository_config;
#[cfg(test)]
#[path = "tests/git_identity.rs"]
mod tests;
