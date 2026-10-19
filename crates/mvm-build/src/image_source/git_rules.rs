//! Private rule/config boundary. Pure-Rust gix crate replaces the former
//! libgit2 C FFI. Only data/config/index/attribute APIs are entered; all
//! attached indexes and workdirs are process-local.
use std::cell::OnceCell;
use std::path::{Path, PathBuf};

use super::{IndexEntry, bytes_as_path, message, repository_config, validate_path};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Attribute {
    Unspecified,
    Set,
    Unset,
    Value(Vec<u8>),
}

pub(super) struct TreeEntry {
    pub name: Vec<u8>,
    pub mode: u32,
    pub id: [u8; 20],
}

type RuleIdMappings = Vec<(gix::bstr::BString, gix::ObjectId)>;

#[derive(Default)]
struct AttributeIdMappings {
    sensitive: OnceCell<RuleIdMappings>,
    folded: OnceCell<RuleIdMappings>,
    #[cfg(test)]
    preparations: std::cell::Cell<usize>,
}

pub(super) struct Rules {
    repo: gix::Repository,
    config: gix::config::File,
    index_state: gix::index::State,
    attribute_id_mappings: AttributeIdMappings,
    prefix: Option<PathBuf>,
    system_attributes: Option<PathBuf>,
    worktree_hint: PathBuf,
}

const CONFIG_BYTE_BUDGET: usize = 4 * 1024 * 1024;
type ConfigValue = (Vec<u8>, Option<Vec<u8>>);

#[derive(Default)]
struct IncludeExpansion {
    active: Vec<PathBuf>,
    bytes: usize,
    files: usize,
}

/// Parse Git configuration bytes into a sequence of key-value pairs.
/// Sections, keys and values follow the standard git-config grammar.
/// Include directives are not followed — the caller handles expansion.
///
/// Section names and value names are lowercased; subsection names retain their
/// original case. Implicit booleans (key with no `=`) are represented as
/// `(key, None)`. Quoted values are unquoted; backslash escapes are resolved.
///
/// Parse errors (such as invalid escapes) fail closed, and the serializer
/// checks exact parsed-entry round trips.
fn parsed_config(bytes: &[u8]) -> Result<Vec<ConfigValue>, String> {
    if bytes.contains(&0) {
        return Err("NUL in Git configuration".to_owned());
    }
    use gix::config::parse::{EventRef, Events};
    let events = Events::from_bytes(bytes, None).map_err(message)?;
    let mut result = Vec::new();
    let mut section = Vec::new();
    let mut key = None;
    let mut separated = false;
    let mut value = Vec::new();
    for event in events.iter() {
        match event {
            EventRef::SectionHeader {
                name,
                subsection_name,
                ..
            } => {
                section = name.iter().map(u8::to_ascii_lowercase).collect();
                if let Some(subsection) = subsection_name {
                    section.push(b'.');
                    section.extend_from_slice(subsection);
                }
            }
            EventRef::SectionValueName(name) => {
                if let Some(key) = key.take() {
                    result.push((key, None));
                }
                key = Some([section.as_slice(), b".", &name.to_ascii_lowercase()].concat());
                separated = false;
                value.clear();
            }
            EventRef::KeyValueSeparator => separated = true,
            EventRef::ValueNotDone(part) => value.extend_from_slice(part),
            EventRef::Value(part) | EventRef::ValueDone(part) => {
                value.extend_from_slice(part);
                if let Some(key) = key.take() {
                    result.push((
                        key,
                        separated.then(|| {
                            gix::config::value::normalize(value.as_slice())
                                .into_owned()
                                .to_vec()
                        }),
                    ));
                }
            }
            _ => {}
        }
    }
    if let Some(key) = key {
        result.push((key, None));
    }
    Ok(result)
}

/// Serialize already parsed entries, not source-text substitution. Quoting every
/// subsection/value preserves punctuation, multiline values and implicit bools.
/// Round-tripping through the same public parser verifies the writer's boundary.
fn serialize_config(values: &[ConfigValue]) -> Result<Vec<u8>, String> {
    fn quoted(out: &mut Vec<u8>, value: &[u8], subsection: bool) {
        out.push(b'"');
        for &byte in value {
            match byte {
                b'"' | b'\\' => {
                    out.push(b'\\');
                    out.push(byte);
                }
                b'\n' if !subsection => out.extend_from_slice(b"\\n"),
                b'\t' if !subsection => out.extend_from_slice(b"\\t"),
                b'\x08' if !subsection => out.extend_from_slice(b"\\b"),
                _ => out.push(byte),
            }
        }
        out.push(b'"');
    }
    let mut out = Vec::new();
    for (name, value) in values {
        let first = name
            .iter()
            .position(|&b| b == b'.')
            .ok_or_else(|| "Git configuration key has no section".to_owned())?;
        let last = name.iter().rposition(|&b| b == b'.').unwrap_or(first);
        out.push(b'[');
        out.extend_from_slice(&name[..first]);
        if first != last {
            out.push(b' ');
            quoted(&mut out, &name[first + 1..last], true);
        }
        out.extend_from_slice(b"]\n");
        out.extend_from_slice(&name[last + 1..]);
        if let Some(value) = value {
            out.push(b'=');
            quoted(&mut out, value, false);
        }
        out.push(b'\n');
    }
    if parsed_config(&out)? != values {
        return Err("Git configuration serialization changed parsed entries".to_owned());
    }
    Ok(out)
}

/// Byte-oriented WM_PATHNAME matching, independently implemented from the
/// operators used by pinned libgit2 1.9.7 config_file.c's do_match_gitdir and
/// conditional_match_onbranch. Tests compare the public native config backend;
/// no private matcher symbol, source adaptation or ABI is used.
/// Bottom-up states avoid recursive/exponential backtracking. Hard bounds limit
/// both allocation and work, including adversarial config patterns.
fn pathname_match(pattern: &[u8], target: &[u8], insensitive: bool) -> Result<bool, String> {
    if pattern.len() > 1024 || target.len() > 4096 {
        return Err("Git include condition matcher budget exceeded".to_owned());
    }
    let width = target.len() + 1;
    let mut states = vec![false; (pattern.len() + 1) * width];
    states[pattern.len() * width + target.len()] = true;
    let fold = |b: u8| {
        if insensitive {
            b.to_ascii_lowercase()
        } else {
            b
        }
    };
    let mut star_ends = vec![pattern.len(); pattern.len() + 1];
    for p in (0..pattern.len()).rev() {
        star_ends[p] = if pattern[p] == b'*' {
            star_ends[p + 1]
        } else {
            p
        };
    }
    let mut classes = std::collections::HashMap::new();
    let mut work = 8 * 1024 * 1024;
    for p in (0..pattern.len()).rev() {
        for t in (0..=target.len()).rev() {
            match_work(&mut work, 1)?;
            let byte = target.get(t).copied();
            let matched = match pattern[p] {
                b'*' => {
                    let end = star_ends[p];
                    let slash = end > p + 1
                        && (p == 0 || pattern[p - 1] == b'/')
                        && (end == pattern.len()
                            || pattern[end] == b'/'
                            || pattern.get(end..end + 2) == Some(b"\\/"));
                    states[end * width + t]
                        || (slash
                            && pattern.get(end) == Some(&b'/')
                            && states[(end + 1) * width + t])
                        || (byte.is_some_and(|b| slash || b != b'/') && states[p * width + t + 1])
                }
                b'?' => byte.is_some_and(|b| b != b'/') && states[(p + 1) * width + t + 1],
                b'\\' => {
                    pattern
                        .get(p + 1)
                        .is_some_and(|&b| byte.map(fold) == Some(b))
                        && states[(p + 2) * width + t + 1]
                }
                b'[' => {
                    if let Some(byte) = byte.filter(|&b| b != b'/') {
                        let key = (p, fold(byte));
                        let class = if let Some(&class) = classes.get(&key) {
                            class
                        } else {
                            let class =
                                character_class(pattern, p + 1, key.1, insensitive, &mut work)?;
                            classes.insert(key, class);
                            class
                        };
                        match class {
                            Some((end, yes)) => yes && states[end * width + t + 1],
                            None => false,
                        }
                    } else {
                        false
                    }
                }
                b => byte.is_some_and(|v| fold(b) == fold(v)) && states[(p + 1) * width + t + 1],
            };
            states[p * width + t] = matched;
        }
    }
    Ok(states[0])
}

fn match_work(work: &mut usize, amount: usize) -> Result<(), String> {
    *work = work
        .checked_sub(amount)
        .ok_or_else(|| "Git include condition matcher work budget exceeded".to_owned())?;
    Ok(())
}

fn character_class(
    pattern: &[u8],
    mut pos: usize,
    byte: u8,
    insensitive: bool,
    work: &mut usize,
) -> Result<Option<(usize, bool)>, String> {
    let negated = matches!(pattern.get(pos), Some(b'!' | b'^'));
    if negated {
        pos += 1;
    }
    let mut matched = false;
    let mut first = true;
    let mut previous = None;
    while let Some(&mut_byte) = pattern.get(pos) {
        match_work(work, 1)?;
        let mut current = mut_byte;
        if current == b']' && !first {
            return Ok(Some((pos + 1, matched != negated)));
        }
        first = false;
        if current == b'\\' {
            pos += 1;
            let Some(&escaped) = pattern.get(pos) else {
                return Ok(None);
            };
            current = escaped;
            matched |= current == byte;
        } else if current == b'-'
            && previous.is_some()
            && pattern.get(pos + 1).is_some_and(|&b| b != b']')
        {
            pos += 1;
            let Some(&end) = pattern.get(pos) else {
                return Ok(None);
            };
            current = end;
            if current == b'\\' {
                pos += 1;
                let Some(&end) = pattern.get(pos) else {
                    return Ok(None);
                };
                current = end;
            }
            let start = previous.unwrap_or(0);
            matched |= start <= byte && byte <= current;
            if insensitive {
                let upper = byte.to_ascii_uppercase();
                matched |= start <= upper && upper <= current;
            }
            previous = None;
            pos += 1;
            continue;
        } else if pattern.get(pos..pos + 2) == Some(b"[:") {
            match_work(work, pattern.len() - pos)?;
            let Some(close) = pattern[pos + 2..].iter().position(|&b| b == b']') else {
                return Ok(None);
            };
            if close > 0 && pattern[pos + 1 + close] == b':' {
                let name = &pattern[pos + 2..pos + 1 + close];
                matched |= match name {
                    b"alnum" => byte.is_ascii_alphanumeric(),
                    b"alpha" => byte.is_ascii_alphabetic(),
                    b"blank" => matches!(byte, b' ' | b'\t'),
                    b"cntrl" => byte.is_ascii_control(),
                    b"digit" => byte.is_ascii_digit(),
                    b"graph" => byte.is_ascii_graphic(),
                    b"lower" => byte.is_ascii_lowercase(),
                    b"print" => byte.is_ascii_graphic() || byte == b' ',
                    b"punct" => byte.is_ascii_punctuation(),
                    b"space" => matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 11 | 12),
                    b"upper" => {
                        byte.is_ascii_uppercase() || (insensitive && byte.is_ascii_lowercase())
                    }
                    b"xdigit" => byte.is_ascii_hexdigit(),
                    _ => return Err("unsupported Git include condition character class".to_owned()),
                };
                pos += close + 3;
                previous = None;
                continue;
            }
            matched |= byte == current;
        } else {
            matched |= byte == current;
        }
        previous = Some(current);
        pos += 1;
    }
    Ok(None)
}

fn path_bytes(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        path.to_str()
            .map(|p| p.replace('\\', "/").into_bytes())
            .unwrap_or_else(|| path.as_os_str().as_encoded_bytes().to_vec())
    }
}

fn without_trailing_slashes(mut bytes: &[u8]) -> &[u8] {
    while let Some(prefix) = bytes.strip_suffix(b"/") {
        bytes = prefix;
    }
    bytes
}

impl Rules {
    pub(super) fn git_dir(&self) -> Result<PathBuf, String> {
        Ok(self.repo.git_dir().to_path_buf())
    }

    pub(super) fn head(&self) -> Result<([u8; 20], [u8; 20]), String> {
        let head_ref = self.repo.head().map_err(message)?;
        let commit_id = head_ref.into_peeled_id().map_err(message)?;
        let commit_oid: [u8; 20] = commit_id.as_bytes().try_into().map_err(message)?;
        let commit_obj = self.repo.find_commit(commit_id).map_err(message)?;
        let tree_id = commit_obj.tree_id().map_err(message)?;
        let tree_oid: [u8; 20] = tree_id.as_bytes().try_into().map_err(message)?;
        Ok((commit_oid, tree_oid))
    }

    pub(super) fn tree(&self, id: [u8; 20]) -> Result<Vec<TreeEntry>, String> {
        let oid = gix::ObjectId::from_bytes_or_panic(&id);
        let tree = self.repo.find_tree(oid).map_err(message)?;
        let mut entries = Vec::new();
        for entry in tree.iter() {
            let entry = entry.map_err(message)?;
            let entry_id: [u8; 20] = entry.oid().as_bytes().try_into().map_err(message)?;
            entries.push(TreeEntry {
                name: entry.filename().to_vec(),
                mode: entry.mode().value() as u32,
                id: entry_id,
            });
        }
        Ok(entries)
    }

    pub(super) fn blob(&self, id: [u8; 20]) -> Result<Vec<u8>, String> {
        let oid = gix::ObjectId::from_bytes_or_panic(&id);
        let blob = self.repo.find_blob(oid).map_err(message)?;
        Ok(blob.data.to_vec())
    }

    pub(super) fn open(path: &Path, entries: &[IndexEntry]) -> Result<Self, String> {
        let (metadata, worktree_hint) = if path.join(".git").symlink_metadata().is_ok() {
            (path.join(".git"), path.to_path_buf())
        } else if path.file_name().is_some_and(|name| name == ".git") {
            (
                path.to_path_buf(),
                path.parent()
                    .ok_or_else(|| "Git metadata has no worktree".to_owned())?
                    .to_path_buf(),
            )
        } else {
            let backlink = std::fs::read(path.join("gitdir")).map_err(message)?;
            let backlink = backlink.strip_suffix(b"\n").unwrap_or(&backlink);
            let backlink = backlink.strip_suffix(b"\r").unwrap_or(backlink);
            let backlink = unvalidated_path(backlink)?;
            let backlink = if backlink.is_absolute() {
                backlink
            } else {
                path.join(backlink)
            };
            (
                path.to_path_buf(),
                backlink
                    .parent()
                    .ok_or_else(|| "linked metadata has no worktree".to_owned())?
                    .to_path_buf(),
            )
        };
        // Open the repository with gix, suppressing config discovery and
        // environment overrides. We build our own config below.
        let repo = gix::open_opts(
            &metadata,
            gix::open::Options::isolated()
                .open_path_as_is(true)
                .permissions(gix::open::Permissions::isolated()),
        )
        .map_err(message)?;
        let config = gix::config::File::new(gix::config::file::Metadata::from(
            gix::config::Source::Local,
        ));
        let mut rules = Self {
            repo,
            config,
            index_state: gix::index::State::new(gix::hash::Kind::Sha1),
            attribute_id_mappings: AttributeIdMappings::default(),
            prefix: None,
            system_attributes: None,
            worktree_hint,
        };
        rules.configure()?;
        for key in [
            "core.filemode",
            "core.ignorecase",
            "core.symlinks",
            "extensions.worktreeconfig",
            "core.bare",
        ] {
            rules.boolean(key)?;
        }
        if let Some(value) = rules.string("core.autocrlf")?
            && !value.eq_ignore_ascii_case(b"input")
        {
            rules.boolean("core.autocrlf")?;
        }
        rules.resolve_rule_paths()?;
        let workdir = rules.workdir()?;
        rules.validate_rules(Path::new(""))?;
        // Inject our custom config into the gix repo so attribute/ignore
        // resolution reads the correct core.attributesfile / core.excludesfile.
        {
            let mut overrides = Vec::new();
            for key in [
                "core.attributesfile",
                "core.excludesfile",
                "core.autocrlf",
                "core.eol",
                "core.symlinks",
                "core.ignorecase",
                "core.filemode",
            ] {
                if matches!(key, "core.symlinks" | "core.ignorecase" | "core.filemode")
                    || (key == "core.autocrlf"
                        && !rules
                            .string(key)?
                            .is_some_and(|v| v.eq_ignore_ascii_case(b"input")))
                {
                    if let Some(value) = rules.boolean(key)? {
                        overrides.push((
                            key.as_bytes().to_vec(),
                            Some(value.to_string().into_bytes()),
                        ));
                    }
                    continue;
                }
                if let Some(val) = rules.config.string(key) {
                    overrides.push((key.as_bytes().to_vec(), Some(val.to_vec())));
                }
            }
            // Set the workdir path in the repo config.
            overrides.push((b"core.worktree".to_vec(), Some(path_bytes(&workdir))));
            // CLI-style overrides trim values before escaping them. Use native
            // config parsing instead so every path keeps its complete bytes.
            let serialized = serialize_config(&overrides)?;
            let file = gix::config::File::from_bytes_no_includes(
                &serialized,
                gix::config::file::Metadata::from(gix::config::Source::Api),
                gix::config::file::init::Options::default(),
            )
            .map_err(message)?;
            let mut snap = rules.repo.config_snapshot_mut();
            snap.append(file).map_err(message)?;
            snap.commit().map_err(message)?;
        }
        rules.install_index(entries)?;
        Ok(rules)
    }

    pub(super) fn install_index(&mut self, entries: &[IndexEntry]) -> Result<(), String> {
        // Even a rejected replacement must not retain mappings from the old index.
        self.attribute_id_mappings = AttributeIdMappings::default();
        self.validate_configured_rule_resources()?;
        // Build a gix-index State from the provided entries and store it.
        // The state is passed explicitly to attribute/ignore resolution.
        let mut state = gix::index::State::new(gix::hash::Kind::Sha1);
        for e in entries {
            validate_path(&e.path)?;
            self.validate_rules(bytes_as_path(&e.path)?)?;
            let id: [u8; 20] = e.oid.as_slice().try_into().map_err(message)?;
            let oid = gix::ObjectId::from_bytes_or_panic(&id);
            let mut flags = gix::index::entry::Flags::from_bits_retain(
                (e.path.len().min(0xFFF) as u32) | (e.stage << 12),
            );
            if e.flags & 1 != 0 {
                flags |= gix::index::entry::Flags::ASSUME_VALID;
            }
            if e.flags & 2 != 0 {
                flags |= gix::index::entry::Flags::INTENT_TO_ADD;
            }
            if e.flags & 4 != 0 {
                flags |= gix::index::entry::Flags::SKIP_WORKTREE;
            }
            let mode = gix::index::entry::Mode::from_bits_truncate(e.mode);
            let stat = gix::index::entry::Stat::default();
            state.dangerously_push_entry(stat, oid, flags, mode, e.path.as_slice().into());
        }
        self.index_state = state;
        Ok(())
    }

    fn resolve_rule_paths(&mut self) -> Result<(), String> {
        let home = repository_config::home();
        let xdg = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| home.map(|p| p.join(".config")));
        let root = self.workdir()?;
        for (key, basename) in [
            ("core.attributesfile", "attributes"),
            ("core.excludesfile", "ignore"),
        ] {
            let path = match self.string(key)? {
                Some(value) => self.expand_path(&value)?,
                None => xdg
                    .as_ref()
                    .map(|p| p.join("git").join(basename))
                    .unwrap_or_else(|| {
                        PathBuf::from(if cfg!(windows) { "NUL" } else { "/dev/null" })
                    }),
            };
            let path = if path.is_absolute()
                || (cfg!(windows) && path.to_str().is_some_and(|p| p.eq_ignore_ascii_case("NUL")))
            {
                path
            } else {
                root.join(path)
            };
            let path_value = path_bytes(&path);
            let serialized = serialize_config(&[(key.as_bytes().to_vec(), Some(path_value))])?;
            let meta = gix::config::file::Metadata::from(gix::config::Source::Api);
            let file = gix::config::File::from_bytes_no_includes(
                &serialized,
                meta,
                gix::config::file::init::Options::default(),
            )
            .map_err(|e| format!("parsing resolved rule path: {e}"))?;
            self.config.append(file).map_err(message)?;
        }
        Ok(())
    }

    fn configure(&mut self) -> Result<(), String> {
        for name in ["GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"] {
            if std::env::var_os(name).is_some() {
                return Err(format!("unsupported environment config injection {name}"));
            }
        }
        let system = repository_config::system()?;
        self.prefix = system.prefix;
        self.system_attributes = system.attributes;
        let gitdir = self.repo.git_dir().to_path_buf();
        let common = self.repo.common_dir().to_path_buf();
        let home = repository_config::home();
        let xdg = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|p| p.join(".config")));
        let explicit = std::env::var_os("GIT_CONFIG_SYSTEM").is_some()
            && !repository_config::env_boolean("GIT_CONFIG_NOSYSTEM")?;
        if let Some(path) = system.path {
            self.add_file(&path, gix::config::Source::System, explicit)?;
        }
        if let Some(path) = std::env::var_os("GIT_CONFIG_GLOBAL") {
            self.add_file(Path::new(&path), gix::config::Source::Git, true)?;
        } else {
            if let Some(path) = xdg {
                self.add_file(&path.join("git/config"), gix::config::Source::Git, false)?;
            }
            if let Some(path) = home {
                self.add_file(&path.join(".gitconfig"), gix::config::Source::User, false)?;
            }
        }
        self.add_file(&common.join("config"), gix::config::Source::Local, false)?;
        if self.boolean("extensions.worktreeconfig")?.unwrap_or(false) {
            self.add_file(
                &gitdir.join("config.worktree"),
                gix::config::Source::Worktree,
                false,
            )?;
        }
        Ok(())
    }

    fn add_file(
        &mut self,
        path: &Path,
        source: gix::config::Source,
        required: bool,
    ) -> Result<(), String> {
        match std::fs::metadata(path) {
            Err(e) if !required && e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(format!(
                    "reading configured Git data {}: {e}",
                    path.display()
                ));
            }
            Ok(meta) if meta.is_file() || path == Path::new("/dev/null") => {}
            Ok(_) => {
                return Err(format!(
                    "configured Git data {} is not a regular file",
                    path.display()
                ));
            }
        }
        let mut expansion = IncludeExpansion::default();
        let mut values = Vec::new();
        self.expand_config(path, &mut expansion, &mut values)?;
        let serialized = serialize_config(&values)?;
        let meta = gix::config::file::Metadata::from(source);
        let file = gix::config::File::from_bytes_no_includes(
            &serialized,
            meta,
            gix::config::file::init::Options::default(),
        )
        .map_err(|e| format!("parsing serialized config: {e}"))?;
        self.config.append(file).map_err(message)?;
        Ok(())
    }

    fn expand_config(
        &self,
        path: &Path,
        expansion: &mut IncludeExpansion,
        values: &mut Vec<ConfigValue>,
    ) -> Result<(), String> {
        if expansion.active.len() >= 10 {
            return Err("Git config include depth exceeds 10".to_owned());
        }
        expansion.files += 1;
        if expansion.files > 1024 {
            return Err("Git config include file budget exceeded".to_owned());
        }
        let canonical = match std::fs::canonicalize(path) {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("reading Git include {}: {error}", path.display())),
        };
        if expansion.active.contains(&canonical) {
            return Err(format!("cyclic Git config include: {}", path.display()));
        }
        let metadata = std::fs::metadata(path).map_err(message)?;
        if !metadata.is_file() && path != Path::new("/dev/null") {
            return Err(format!(
                "Git include {} is not a regular file",
                path.display()
            ));
        }
        let file = std::fs::File::open(path).map_err(message)?;
        use std::io::Read;
        let remaining = CONFIG_BYTE_BUDGET.saturating_sub(expansion.bytes);
        let mut bytes = Vec::new();
        file.take((remaining + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(message)?;
        if bytes.len() > remaining {
            return Err("Git config include byte budget exceeded".to_owned());
        }
        expansion.bytes += bytes.len();
        let entries = parsed_config(&bytes)
            .map_err(|error| format!("parsing Git data {}: {error}", path.display()))?;
        expansion.active.push(canonical);
        for (name, value) in entries {
            let conditional = name
                .strip_prefix(b"includeif.")
                .and_then(|n| n.strip_suffix(b".path"));
            let include = name == b"include.path" || conditional.is_some();
            if conditional.is_some_and(|condition| {
                !condition.starts_with(b"gitdir:")
                    && !condition.starts_with(b"gitdir/i:")
                    && !condition.starts_with(b"onbranch:")
                    && !condition.starts_with(b"hasconfig:")
            }) {
                return Err("unsupported conditional include form".to_owned());
            }
            if include {
                if conditional.is_some_and(|condition| condition.starts_with(b"hasconfig:")) {
                    return Err("unsupported hasconfig conditional include".to_owned());
                }
                if name.windows(9).any(|part| part == b"%(prefix)")
                    || value
                        .as_deref()
                        .is_some_and(|v| v.starts_with(b"%(prefix)"))
                {
                    return Err(
                        "unsupported %(prefix) include; name an absolute include data path"
                            .to_owned(),
                    );
                }
            }
            // Keep the directive itself, duplicate keys and their position.
            values.push((name.clone(), value.clone()));
            if include && let Some(value) = value {
                if let Some(condition) = conditional
                    && !self.include_matches(condition, path)?
                {
                    continue;
                }
                let include_path = self.expand_path(&value)?;
                let include_path = if include_path.is_absolute() {
                    include_path
                } else {
                    path.parent().unwrap_or(Path::new(".")).join(include_path)
                };
                self.expand_config(&include_path, expansion, values)?;
            }
        }
        expansion.active.pop();
        Ok(())
    }

    fn include_matches(&self, condition: &[u8], source: &Path) -> Result<bool, String> {
        let (pattern, target, insensitive) = if let Some(pattern) =
            condition.strip_prefix(b"onbranch:")
        {
            use std::io::Read;
            let mut head = Vec::new();
            std::fs::File::open(self.git_dir()?.join("HEAD"))
                .map_err(message)?
                .take(4097)
                .read_to_end(&mut head)
                .map_err(message)?;
            if head.len() > 4096 {
                return Err("Git include branch context byte budget exceeded".to_owned());
            }
            let Some(branch) = head.strip_prefix(b"ref: refs/heads/") else {
                return Ok(false);
            };
            let branch = branch.trim_ascii_end();
            (pattern.to_vec(), branch.to_vec(), false)
        } else {
            let (pattern, insensitive) = if let Some(pattern) = condition.strip_prefix(b"gitdir:") {
                (pattern, false)
            } else if let Some(pattern) = condition.strip_prefix(b"gitdir/i:") {
                (pattern, true)
            } else {
                return Err("unsupported conditional include form".to_owned());
            };
            let mut expanded = if let Some(relative) = pattern.strip_prefix(b"./") {
                let source = std::path::absolute(source).map_err(message)?;
                let base = path_bytes(source.parent().unwrap_or(Path::new(".")));
                [without_trailing_slashes(&base), b"/", relative].concat()
            } else if let Some(relative) = pattern.strip_prefix(b"~/") {
                let home = repository_config::home().ok_or_else(|| {
                    "HOME is required for configured ~/ include condition".to_owned()
                })?;
                let base = path_bytes(&home);
                [without_trailing_slashes(&base), b"/", relative].concat()
            } else {
                pattern.to_vec()
            };
            if !pattern.starts_with(b"./")
                && !pattern.starts_with(b"~/")
                && !unvalidated_path(pattern)?.is_absolute()
            {
                expanded = [b"**/".as_slice(), &expanded].concat();
            }
            let mut target = path_bytes(&self.git_dir()?);
            while target.ends_with(b"/") {
                target.pop();
            }
            (expanded, target, insensitive)
        };
        let mut pattern = pattern;
        if pattern.ends_with(b"/") {
            pattern.extend_from_slice(b"**");
        }
        pathname_match(&pattern, &target, insensitive)
    }

    pub(super) fn boolean(&self, name: &str) -> Result<Option<bool>, String> {
        let (section_name, value_name) = name
            .split_once('.')
            .ok_or_else(|| format!("invalid boolean key {name}"))?;
        let mut value = None;
        if let Some(sections) = self.config.sections_by_name(section_name) {
            for section in sections {
                if section.header().subsection_name().is_none()
                    && let Some(found) = section.value_implicit(value_name)
                {
                    value = Some(found);
                }
            }
        }
        match value {
            None => Ok(None),
            Some(None) => Ok(Some(true)),
            Some(Some(value)) => repository_config::parse_boolean(&value)
                .map(Some)
                .map_err(|e| format!("reading boolean config {name}: {e}")),
        }
    }

    pub(super) fn string(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        match self.config.string(name) {
            Some(value) => Ok(Some(value.to_vec())),
            None => Ok(None),
        }
    }

    pub(super) fn workdir(&self) -> Result<PathBuf, String> {
        if self.boolean("core.bare")?.unwrap_or(false) {
            return Err("checkout has no working tree".to_owned());
        }
        if let Some(path) = self.string("core.worktree")? {
            let path = self.expand_path(&path)?;
            let base = self.repo.git_dir().to_path_buf();
            return Ok(if path.is_absolute() {
                path
            } else {
                base.join(path)
            });
        }
        // Deferred/bare opening deliberately suppresses native default config
        // discovery. The explicit worktree hint supplies its physical location.
        Ok(self.worktree_hint.clone())
    }

    fn expand_path(&self, bytes: &[u8]) -> Result<PathBuf, String> {
        if let Some(suffix) = bytes.strip_prefix(b"%(prefix)") {
            let prefix = self.prefix.clone();
            #[cfg(windows)]
            let prefix = match prefix {
                Some(prefix) => Some(prefix),
                None => repository_config::windows_prefix()?,
            };
            let prefix = prefix.ok_or_else(|| {
                "configured path needs a Git installation prefix; name an absolute data path"
                    .to_owned()
            })?;
            let suffix = suffix.strip_prefix(b"/").unwrap_or(suffix);
            return Ok(prefix.join(unvalidated_path(suffix)?));
        }
        if let Some(suffix) = bytes.strip_prefix(b"~/") {
            let home = repository_config::home()
                .ok_or_else(|| "HOME is required for configured ~/ data path".to_owned())?;
            return Ok(home.join(unvalidated_path(suffix)?));
        }
        unvalidated_path(bytes)
    }

    pub(super) fn attribute(&self, path: &[u8], name: &str) -> Result<Attribute, String> {
        use gix::worktree::stack::state::attributes::Source as AttrSource;
        let rela_path = bytes_as_path(path)?;
        self.validate_rules(rela_path)?;
        // Build global sources from the resolved policy, never gix's implicit
        // installation discovery (which may execute Git).
        let mut files = self.system_attributes.iter().cloned().collect::<Vec<_>>();
        if let Some(path) = self.string("core.attributesfile")? {
            files.push(unvalidated_path(&path)?);
        }
        let mut collection = gix::attrs::search::MetadataCollection::default();
        let mut buf = Vec::new();
        let globals =
            gix::attrs::Search::new_globals(files, &mut buf, &mut collection).map_err(message)?;
        let attributes = gix::worktree::stack::state::Attributes::new(
            globals,
            Some(self.repo.common_dir().join("info/attributes")),
            AttrSource::WorktreeThenIdMapping,
            collection,
        );
        let state = gix::worktree::stack::State::AttributesStack(attributes);
        let (case, cache) = if self.boolean("core.ignorecase")?.unwrap_or(false) {
            (
                gix::glob::pattern::Case::Fold,
                &self.attribute_id_mappings.folded,
            )
        } else {
            (
                gix::glob::pattern::Case::Sensitive,
                &self.attribute_id_mappings.sensitive,
            )
        };
        // Only filtered index paths and blob IDs are reused. Globals, validation,
        // attribute state and the stack above/below remain fresh for every query.
        let mappings = cache
            .get_or_init(|| {
                #[cfg(test)]
                self.attribute_id_mappings
                    .preparations
                    .set(self.attribute_id_mappings.preparations.get() + 1);
                state.id_mappings_from_index(
                    &self.index_state,
                    self.index_state.path_backing(),
                    case,
                )
            })
            .clone();
        let mut stack = gix::worktree::Stack::new(self.workdir()?, state, case, buf, mappings);
        let mut outcome = stack.selected_attribute_matches([name]);
        let platform = stack
            .at_path(rela_path, None, &self.repo.objects)
            .map_err(message)?;
        platform.matching_attributes(&mut outcome);
        let m = outcome.iter_selected().next();
        match m {
            None => Ok(Attribute::Unspecified),
            Some(m) => match m.assignment.state {
                gix::attrs::StateRef::Unspecified => Ok(Attribute::Unspecified),
                gix::attrs::StateRef::Set => Ok(Attribute::Set),
                gix::attrs::StateRef::Unset => Ok(Attribute::Unset),
                gix::attrs::StateRef::Value(v) => Ok(Attribute::Value(
                    AsRef::<[u8]>::as_ref(v.as_bstr()).to_vec(),
                )),
            },
        }
    }

    pub(super) fn ignored(&self, path: &Path) -> Result<bool, String> {
        use gix::worktree::stack::state::ignore::Source as IgnSource;
        self.validate_rules(path)?;
        let mut stack = self
            .repo
            .excludes(
                &self.index_state,
                None,
                IgnSource::WorktreeThenIdMappingIfNotSkipped,
            )
            .map_err(message)?;
        let platform = stack.at_path(path, None).map_err(message)?;
        Ok(platform.is_excluded())
    }

    fn validate_configured_rule_resources(&self) -> Result<(), String> {
        for key in ["core.attributesfile", "core.excludesfile"] {
            if let Some(path) = self.string(key)? {
                validate_global_rule_resource(&unvalidated_path(&path)?)?;
            }
        }
        Ok(())
    }

    fn validate_rules(&self, path: &Path) -> Result<(), String> {
        self.validate_configured_rule_resources()?;
        let root = self.workdir()?;
        for ancestor in path.parent().unwrap_or(Path::new("")).ancestors() {
            for name in [".gitattributes", ".gitignore"] {
                let file = root.join(ancestor).join(name);
                match file.symlink_metadata() {
                    Ok(meta) if !meta.is_file() => {
                        return Err(format!("Git rule {} is not a regular file", file.display()));
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(format!("reading Git rule {}: {e}", file.display())),
                }
            }
        }
        Ok(())
    }
}

fn validate_global_rule_resource(path: &Path) -> Result<(), String> {
    // Global rules follow symlinks, unlike per-directory rules. The loader treats
    // directories as absent, so enforce our regular-file boundary before loading.
    let null_sink = (cfg!(unix) && path == Path::new("/dev/null"))
        || (cfg!(windows) && path.to_str().is_some_and(|p| p.eq_ignore_ascii_case("NUL")));
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() || null_sink => Ok(()),
        Ok(_) => Err(format!("Git rule {} is not a regular file", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("reading Git rule {}: {error}", path.display())),
    }
}

fn unvalidated_path(bytes: &[u8]) -> Result<PathBuf, String> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(Path::new(std::ffi::OsStr::from_bytes(bytes)).to_path_buf())
    }
    #[cfg(not(unix))]
    {
        let path = PathBuf::from(std::str::from_utf8(bytes).map_err(message)?);
        #[cfg(windows)]
        if !path.is_absolute()
            && (path.has_root()
                || matches!(
                    path.components().next(),
                    Some(std::path::Component::Prefix(_))
                ))
        {
            return Err("ambiguous Windows drive-relative or slash-rooted data path".to_owned());
        }
        Ok(path)
    }
}

#[cfg(test)]
mod include_tests {
    use super::*;
    use crate::image_source::{WorktreeState, probe_identity, repository_fixture as fixture};
    use mvm_core::util::test_env::TestEnv;

    fn isolated(env: &mut TestEnv, home: &Path) {
        env.set("HOME", home);
        env.remove("USERPROFILE");
        env.remove("XDG_CONFIG_HOME");
        env.set("GIT_CONFIG_NOSYSTEM", "1");
        env.remove("GIT_CONFIG_SYSTEM");
        let global = home.join("empty-global");
        std::fs::write(&global, b"").unwrap();
        env.set("GIT_CONFIG_GLOBAL", global);
    }

    fn repository(root: &Path) {
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(root.join("a"), b"base\n").unwrap();
        fixture::commit_all(root, "include fixture");
    }

    fn append(root: &Path, body: &str) {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(root.join(".git/config"))
            .unwrap()
            .write_all(body.as_bytes())
            .unwrap();
    }

    fn read_index(root: &Path) -> Vec<IndexEntry> {
        super::super::git_index::read(&root.join(".git/index")).unwrap()
    }

    fn set_case_policy(rules: &mut Rules, folded: bool) {
        let bytes = format!("[core]\nignorecase = {folded}\n");
        let config = gix::config::File::from_bytes_no_includes(
            bytes.as_bytes(),
            gix::config::file::Metadata::from(gix::config::Source::Api),
            gix::config::file::init::Options::default(),
        )
        .unwrap();
        rules.config.append(config).unwrap();
    }

    #[test]
    fn global_rule_resources_are_revalidated_after_replacement() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        isolated(&mut env, tmp.path());
        for source in ["configured", "default"] {
            let root = tmp.path().join(source);
            repository(&root);
            for (key, name, attribute) in [
                ("core.attributesfile", "attributes", true),
                ("core.excludesfile", "ignore", false),
            ] {
                let resource = if source == "configured" {
                    tmp.path().join(name)
                } else {
                    tmp.path().join(".config/git").join(name)
                };
                std::fs::create_dir_all(resource.parent().unwrap()).unwrap();
                if source == "configured" {
                    let bytes =
                        serialize_config(&[(key.as_bytes().to_vec(), Some(path_bytes(&resource)))])
                            .unwrap();
                    append(&root, std::str::from_utf8(&bytes).unwrap());
                }
                let query = |rules: &Rules| {
                    if attribute {
                        rules.attribute(b"a", "text").map(|_| ())
                    } else {
                        rules.ignored(Path::new("untracked")).map(|_| ())
                    }
                };
                let rules = Rules::open(&root, &read_index(&root)).unwrap();
                query(&rules).unwrap(); // Missing optional resources remain absent.
                std::fs::write(&resource, b"").unwrap();
                query(&rules).unwrap();
                std::fs::remove_file(&resource).unwrap();
                std::fs::create_dir(&resource).unwrap();
                assert!(
                    query(&rules).unwrap_err().contains("regular"),
                    "{key} source={source}"
                );
                assert!(Rules::open(&root, &read_index(&root)).is_err());
                std::fs::remove_dir(&resource).unwrap();
                std::fs::write(&resource, b"").unwrap();
                query(&rules).unwrap();
                std::fs::remove_file(&resource).unwrap();
                query(&rules).unwrap();
            }
        }
    }

    #[test]
    fn empty_index_replacement_revalidates_globals_and_discards_mappings() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        isolated(&mut env, tmp.path());
        for key in ["core.attributesfile", "core.excludesfile"] {
            let root = tmp.path().join(key);
            repository(&root);
            let attributes = root.join(".gitattributes");
            std::fs::write(&attributes, b"a text\n").unwrap();
            fixture::commit_all(&root, "indexed attributes");
            let resource = tmp.path().join("global-rule");
            std::fs::write(&resource, b"").unwrap();
            let config =
                serialize_config(&[(key.as_bytes().to_vec(), Some(path_bytes(&resource)))])
                    .unwrap();
            append(&root, std::str::from_utf8(&config).unwrap());
            let entries = read_index(&root);
            let mut rules = Rules::open(&root, &entries).unwrap();
            std::fs::remove_file(attributes).unwrap();
            assert_eq!(rules.attribute(b"a", "text").unwrap(), Attribute::Set);
            set_case_policy(&mut rules, true);
            assert_eq!(rules.attribute(b"a", "text").unwrap(), Attribute::Set);
            assert!(rules.attribute_id_mappings.sensitive.get().is_some());
            assert!(rules.attribute_id_mappings.folded.get().is_some());
            std::fs::remove_file(&resource).unwrap();
            std::fs::create_dir(&resource).unwrap();
            assert!(rules.install_index(&[]).unwrap_err().contains("regular"));
            assert!(rules.attribute_id_mappings.sensitive.get().is_none());
            assert!(rules.attribute_id_mappings.folded.get().is_none());
            assert_eq!(rules.attribute_id_mappings.preparations.get(), 0);
            assert_eq!(rules.index_state.entries().len(), entries.len());
            std::fs::remove_dir(&resource).unwrap();
            std::fs::write(&resource, b"").unwrap();
            assert_eq!(rules.attribute(b"a", "text").unwrap(), Attribute::Set);
            rules.install_index(&[]).unwrap();
            assert!(rules.index_state.entries().is_empty());
            assert!(rules.attribute_id_mappings.folded.get().is_none());
            assert_eq!(
                rules.attribute(b"a", "text").unwrap(),
                Attribute::Unspecified
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn configured_global_rules_accept_the_platform_null_sink() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        isolated(&mut env, tmp.path());
        let root = tmp.path().join("repo");
        repository(&root);
        let sink = if cfg!(windows) { "NUL" } else { "/dev/null" };
        append(
            &root,
            &format!("\n[core]\nattributesfile={sink}\nexcludesfile={sink}\n"),
        );
        let rules = Rules::open(&root, &read_index(&root)).unwrap();
        assert_eq!(
            rules.attribute(b"a", "text").unwrap(),
            Attribute::Unspecified
        );
        assert!(!rules.ignored(Path::new("untracked")).unwrap());
    }

    #[test]
    fn attribute_mappings_are_reused_without_caching_rule_files() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        isolated(&mut env, tmp.path());
        let root = tmp.path().join("repo");
        repository(&root);
        let attributes = root.join(".gitattributes");
        std::fs::write(&attributes, b"a text\n").unwrap();
        fixture::commit_all(&root, "attribute snapshot");
        let global = tmp.path().join(".config/git/attributes");
        std::fs::create_dir_all(global.parent().unwrap()).unwrap();
        std::fs::write(&global, b"a eol=lf\n").unwrap();
        let rules = Rules::open(&root, &read_index(&root)).unwrap();
        for _ in 0..3 {
            assert_eq!(rules.attribute(b"a", "text").unwrap(), Attribute::Set);
            assert_eq!(
                rules.attribute(b"a", "eol").unwrap(),
                Attribute::Value(b"lf".to_vec())
            );
        }
        assert_eq!(rules.attribute_id_mappings.preparations.get(), 1);

        std::fs::write(&attributes, b"a -text\n").unwrap();
        std::fs::write(&global, b"a eol=crlf\n").unwrap();
        assert_eq!(rules.attribute(b"a", "text").unwrap(), Attribute::Unset);
        assert_eq!(
            rules.attribute(b"a", "eol").unwrap(),
            Attribute::Value(b"crlf".to_vec())
        );
        std::fs::remove_file(&attributes).unwrap();
        assert_eq!(rules.attribute(b"a", "text").unwrap(), Attribute::Set);
        assert_eq!(rules.attribute_id_mappings.preparations.get(), 1);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&global, &attributes).unwrap();
            assert!(rules.attribute(b"a", "text").is_err());
        }
    }

    #[test]
    fn attribute_mapping_cache_is_keyed_by_case_policy() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        isolated(&mut env, tmp.path());
        let root = tmp.path().join("repo");
        repository(&root);
        std::fs::write(root.join(".gitattributes"), b"a text\n").unwrap();
        fixture::commit_all(&root, "attribute snapshot");
        let entries = read_index(&root);
        let mut rules = Rules::open(&root, &entries).unwrap();
        assert_eq!(rules.attribute(b"a", "text").unwrap(), Attribute::Set);
        assert!(rules.attribute_id_mappings.sensitive.get().is_some());
        assert!(rules.attribute_id_mappings.folded.get().is_none());
        set_case_policy(&mut rules, true);
        assert_eq!(rules.attribute(b"a", "text").unwrap(), Attribute::Set);
        assert!(rules.attribute_id_mappings.folded.get().is_some());
        assert_eq!(rules.attribute_id_mappings.preparations.get(), 2);
        set_case_policy(&mut rules, false);
        assert_eq!(rules.attribute(b"a", "text").unwrap(), Attribute::Set);
        assert_eq!(rules.attribute_id_mappings.preparations.get(), 2);

        let independent = Rules::open(&root, &entries).unwrap();
        assert!(independent.attribute_id_mappings.sensitive.get().is_none());
        assert_eq!(independent.attribute_id_mappings.preparations.get(), 0);
        assert_eq!(independent.attribute(b"a", "text").unwrap(), Attribute::Set);
        assert_eq!(independent.attribute_id_mappings.preparations.get(), 1);
    }

    #[test]
    fn replacing_or_rejecting_an_index_discards_cached_mappings() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        isolated(&mut env, tmp.path());
        let root = tmp.path().join("repo");
        repository(&root);
        let attributes = root.join(".gitattributes");
        std::fs::write(&attributes, b"a text\n").unwrap();
        fixture::commit_all(&root, "old attribute snapshot");
        let old_entries = read_index(&root);
        let old_id = old_entries
            .iter()
            .find(|entry| entry.path == b".gitattributes")
            .unwrap()
            .oid
            .clone();
        let mut rules = Rules::open(&root, &old_entries).unwrap();
        std::fs::remove_file(&attributes).unwrap();
        assert_eq!(rules.attribute(b"a", "text").unwrap(), Attribute::Set);
        set_case_policy(&mut rules, true);
        assert_eq!(rules.attribute(b"a", "text").unwrap(), Attribute::Set);
        set_case_policy(&mut rules, false);
        assert_eq!(rules.attribute_id_mappings.preparations.get(), 2);

        std::fs::write(&attributes, b"a -text\n").unwrap();
        fixture::commit_all(&root, "new attribute snapshot");
        let new_entries = read_index(&root);
        let new_id = &new_entries
            .iter()
            .find(|entry| entry.path == b".gitattributes")
            .unwrap()
            .oid;
        assert_ne!(&old_id, new_id);
        std::fs::remove_file(&attributes).unwrap();
        rules.install_index(&new_entries).unwrap();
        assert!(rules.attribute_id_mappings.sensitive.get().is_none());
        assert!(rules.attribute_id_mappings.folded.get().is_none());
        assert_eq!(rules.attribute(b"a", "text").unwrap(), Attribute::Unset);
        assert!(
            rules
                .attribute_id_mappings
                .sensitive
                .get()
                .unwrap()
                .iter()
                .any(|(path, id)| {
                    AsRef::<[u8]>::as_ref(path) == b".gitattributes"
                        && *id == gix::ObjectId::from_bytes_or_panic(new_id)
                })
        );
        set_case_policy(&mut rules, true);
        assert_eq!(rules.attribute(b"a", "text").unwrap(), Attribute::Unset);
        set_case_policy(&mut rules, false);
        let mut invalid = new_entries.clone();
        invalid[0].oid.pop();
        assert!(rules.install_index(&invalid).is_err());
        assert!(rules.attribute_id_mappings.sensitive.get().is_none());
        assert!(rules.attribute_id_mappings.folded.get().is_none());
        assert_eq!(rules.attribute_id_mappings.preparations.get(), 0);

        rules.install_index(&new_entries).unwrap();
        assert_eq!(rules.attribute(b"a", "text").unwrap(), Attribute::Unset);
        let without_attributes = new_entries
            .into_iter()
            .filter(|entry| entry.path != b".gitattributes")
            .collect::<Vec<_>>();
        rules.install_index(&without_attributes).unwrap();
        assert_eq!(
            rules.attribute(b"a", "text").unwrap(),
            Attribute::Unspecified
        );
        assert!(
            rules
                .attribute_id_mappings
                .sensitive
                .get()
                .unwrap()
                .is_empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn native_path_merge_commits_exact_snapshot_values() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        isolated(&mut env, tmp.path());
        let root = tmp.path().join("repo=\\ \t\n");
        repository(&root);
        let mut values = Vec::new();
        for (key, name) in [
            ("core.excludesfile", " ignore=\\ \t\n"),
            ("core.attributesfile", " attributes=\\ \t\n"),
        ] {
            let path = tmp.path().join(name);
            std::fs::write(&path, b"").unwrap();
            values.push((key.as_bytes().to_vec(), Some(path_bytes(&path))));
        }
        let serialized = serialize_config(&values).unwrap();
        append(&root, std::str::from_utf8(&serialized).unwrap());
        let rules = Rules::open(&root, &[]).unwrap();
        values.push((b"core.worktree".to_vec(), Some(path_bytes(&root))));
        let snapshot = rules.repo.config_snapshot();
        for (key, value) in values {
            assert_eq!(
                snapshot
                    .string(std::str::from_utf8(&key).unwrap())
                    .map(|value| value.to_vec()),
                value
            );
        }
    }

    #[test]
    fn current_home_include_uses_declared_home_not_cached_value() {
        // gix has no process-global HOME cache; changing HOME always takes
        // effect immediately. This test verifies the correct behavior.
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let a = base.join("home-a");
        let b = base.join("home-b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        isolated(&mut env, &a);
        std::fs::write(b.join("empty-global"), b"").unwrap();
        let root = b.join("repo");
        repository(&root);
        std::fs::write(a.join("rules.config"), b"[core]\nautocrlf=false\n").unwrap();
        std::fs::write(b.join("rules.config"), b"[core]\nautocrlf=true\n").unwrap();
        let baseline = std::fs::read(root.join(".git/config")).unwrap();
        append(&root, "\n[include]\npath=~/rules.config\n");
        std::fs::write(root.join("a"), b"base\r\n").unwrap();
        assert!(probe_identity(&root).unwrap().worktree.is_dirty());
        env.set("HOME", &b);
        env.set("GIT_CONFIG_GLOBAL", b.join("empty-global"));
        // gix sees the current HOME immediately — no stale cache.
        assert_eq!(
            probe_identity(&root).unwrap().worktree,
            WorktreeState::Clean
        );
        std::fs::remove_dir_all(&a).unwrap();
        assert_eq!(
            probe_identity(&root).unwrap().worktree,
            WorktreeState::Clean
        );

        // The current HOME also controls gitdir:~/, not just include paths.
        // A later false value must be overridden only by a matching condition.
        std::fs::write(root.join(".git/config"), &baseline).unwrap();
        append(
            &root,
            "\n[core]\nautocrlf=false\n[includeIf \"gitdir:~/repo/\"]\npath=~/rules.config\n",
        );
        assert_eq!(
            probe_identity(&root).unwrap().worktree,
            WorktreeState::Clean
        );
        env.set("HOME", &a);
        assert!(probe_identity(&root).unwrap().worktree.is_dirty());
        env.remove("HOME");
        env.remove("USERPROFILE");
        assert!(probe_identity(&root).unwrap_err().contains("HOME"));
        env.set("USERPROFILE", &b);
        assert_eq!(
            probe_identity(&root).unwrap().worktree,
            WorktreeState::Clean
        );
    }

    #[test]
    fn includes_keep_relative_origins_order_duplicates_and_native_grammar() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        isolated(&mut env, tmp.path());
        let root = tmp.path().join("repo");
        repository(&root);

        std::fs::create_dir(root.join(".git/nested")).unwrap();
        std::fs::write(root.join(".git/nested/first.config"),
            b"[probe \"sub.with=punctuation\"]\nvalue=\"a # ; \\\\ \\\"\\n\\t\\b\"\nflag\n[include]\npath=second.config\n[core]\nautocrlf=false\n").unwrap();
        std::fs::write(
            root.join(".git/nested/second.config"),
            b"[core]\nautocrlf=true\n[probe]\nvalue=one\nvalue=two\n",
        )
        .unwrap();
        append(
            &root,
            "\n[core]\nautocrlf=true\n[include]\npath=nested/first.config\n",
        );
        let rules = Rules::open(&root, &[]).unwrap();
        assert_eq!(rules.boolean("core.autocrlf").unwrap(), Some(false));
        let mut expanded = Vec::new();
        rules
            .expand_config(
                &root.join(".git/config"),
                &mut IncludeExpansion::default(),
                &mut expanded,
            )
            .unwrap();
        let duplicates = expanded
            .iter()
            .filter(|(key, _)| key == b"probe.value")
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>();
        assert_eq!(duplicates, [Some(b"one".to_vec()), Some(b"two".to_vec())]);
        assert!(
            expanded
                .iter()
                .any(|(key, value)| key == b"probe.sub.with=punctuation.flag" && value.is_none())
        );
        assert_eq!(
            parsed_config(&serialize_config(&expanded).unwrap()).unwrap(),
            expanded
        );
        append(&root, "\n[core]\nautocrlf=true\n");
        assert_eq!(
            Rules::open(&root, &[])
                .unwrap()
                .boolean("core.autocrlf")
                .unwrap(),
            Some(true)
        );
    }

    #[test]
    fn include_expansion_preserves_system_global_local_worktree_precedence() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        isolated(&mut env, tmp.path());
        let root = tmp.path().join("repo");
        repository(&root);
        let system = tmp.path().join("system.config");
        let global = tmp.path().join("global.config");
        std::fs::write(&system, b"[include]\npath=system.values\n").unwrap();
        std::fs::write(tmp.path().join("system.values"), b"[probe]\nlayer=system\n").unwrap();
        std::fs::write(&global, b"[include]\npath=global.values\n").unwrap();
        std::fs::write(tmp.path().join("global.values"), b"[probe]\nlayer=global\n").unwrap();
        env.set("GIT_CONFIG_NOSYSTEM", "0");
        env.set("GIT_CONFIG_SYSTEM", &system);
        env.set("GIT_CONFIG_GLOBAL", &global);
        let layer = || {
            Rules::open(&root, &[])
                .unwrap()
                .string("probe.layer")
                .unwrap()
                .unwrap()
        };
        assert_eq!(layer(), b"global");
        env.set("GIT_CONFIG_GLOBAL", tmp.path().join("absent-global"));
        // An explicit missing global is an error, not native fallback discovery.
        assert!(Rules::open(&root, &[]).is_err());
        env.remove("GIT_CONFIG_GLOBAL");
        assert_eq!(layer(), b"system");
        env.set("GIT_CONFIG_GLOBAL", &global);
        std::fs::write(root.join(".git/local.values"), b"[probe]\nlayer=local\n").unwrap();
        append(&root, "\n[include]\npath=local.values\n");
        assert_eq!(layer(), b"local");
        append(&root, "\n[extensions]\nworktreeconfig=true\n");
        std::fs::write(
            root.join(".git/config.worktree"),
            b"[include]\npath=worktree.values\n",
        )
        .unwrap();
        std::fs::write(
            root.join(".git/worktree.values"),
            b"[probe]\nlayer=worktree\n",
        )
        .unwrap();
        assert_eq!(layer(), b"worktree");
    }

    #[test]
    fn include_cycles_depth_bytes_files_and_unsupported_conditions_fail_closed() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        isolated(&mut env, tmp.path());
        let root = tmp.path().join("repo");
        repository(&root);
        let rules = Rules::open(&root, &[]).unwrap();
        let first = tmp.path().join("first");
        let second = tmp.path().join("second");
        std::fs::write(&first, b"[include]\npath=second\n").unwrap();
        std::fs::write(&second, b"[include]\npath=first\n").unwrap();
        let expand = |path: &Path| {
            rules.expand_config(path, &mut IncludeExpansion::default(), &mut Vec::new())
        };
        assert!(expand(&first).unwrap_err().contains("cyclic"));
        std::fs::write(&second, vec![b' '; CONFIG_BYTE_BUDGET]).unwrap();
        assert!(expand(&first).unwrap_err().contains("byte budget"));
        std::fs::write(&second, b"").unwrap();
        let mut budget = IncludeExpansion {
            files: 1024,
            ..Default::default()
        };
        assert!(
            rules
                .expand_config(&first, &mut budget, &mut Vec::new())
                .unwrap_err()
                .contains("file budget")
        );
        for n in 0..12 {
            std::fs::write(
                tmp.path().join(format!("depth{n}")),
                format!("[include]\npath=depth{}\n", n + 1),
            )
            .unwrap();
        }
        assert!(
            expand(&tmp.path().join("depth0"))
                .unwrap_err()
                .contains("depth")
        );
        for body in [
            "[includeIf \"hasconfig:remote.*.url:*\"]\npath=second\n",
            "[includeIf \"unknown:condition\"]\npath=second\n",
            "[includeIf \"unknown:condition\"]\npath\n",
            "[include]\npath=%(prefix)/second\n",
            "[includeIf \"gitdir:%(prefix)/\"]\npath=second\n",
        ] {
            std::fs::write(&first, body).unwrap();
            assert!(expand(&first).unwrap_err().contains("unsupported"));
        }
        std::fs::write(&first, b"[include]\npath=absent\n").unwrap();
        expand(&first).unwrap();
        std::fs::write(&first, b"[include]\npath=\"unterminated\n").unwrap();
        // gix and native Git reject malformed unterminated quoted values.
        assert!(parsed_config(b"[include]\npath=\"unterminated\n").is_err());
        assert!(expand(&first).is_err());
        // unescape_line explicitly rejects escapes outside its fixed table.
        std::fs::write(&first, b"[include]\npath=\"invalid\\q\"\n").unwrap();
        assert!(expand(&first).is_err());
        assert!(
            pathname_match(&vec![b'*'; 1025], b"x", false)
                .unwrap_err()
                .contains("budget")
        );
    }

    #[test]
    fn include_condition_matcher_vectors_and_native_differential() {
        for (pattern, target, insensitive, expected) in [
            (
                b"**/repo/.git".as_slice(),
                b"repo/.git".as_slice(),
                false,
                true,
            ),
            (b"**/repo/.git", b"a/b/repo/.git", false, true),
            (b"*/repo/.git", b"a/b/repo/.git", false, false),
            (b"a/**/b", b"a/b", false, true),
            (b"a/**/b", b"a/x/y/b", false, true),
            (b"a**b", b"a/x/b", false, false),
            (b"A/[A-Z]", b"a/z", true, true),
            (b"[!a-c]?", b"z1", false, true),
            (b"[^a-c]", b"b", false, false),
            (b"[[:digit:]]", b"7", false, true),
            (b"[[:upper:]]", b"z", true, true),
            (b"[]]", b"]", false, true),
            (b"\\*", b"*", false, true),
            (b"\\A", b"a", true, false),
            (b"\\a", b"A", true, true),
            (b"\\A", b"A", true, false),
            (b"?", b"/", false, false),
            (b"[\xff]", b"\xff", false, true),
        ] {
            assert_eq!(
                pathname_match(pattern, target, insensitive).unwrap(),
                expected,
                "{pattern:?} {target:?}"
            );
        }
        // Native Git is a tests-only differential oracle, not a fixture
        // producer or observer dependency. `config` enters no hooks/filters.
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        isolated(&mut env, tmp.path());
        let root = tmp.path().join("repo");
        repository(&root);
        let rules = Rules::open(&root, &[]).unwrap();
        let source = tmp.path().join("conditions.config");
        let included = tmp.path().join("condition.values");
        std::fs::write(&included, b"[probe]\nenabled=true\n").unwrap();
        for (condition, expected) in [
            ("gitdir:**/repo/.git", true),
            ("gitdir:*/repo/.git", true),
            ("gitdir:**/r?po/.git", true),
            ("gitdir:**/r[ae]po/.git", true),
            ("gitdir:**/r[!a]po/.git", true),
            ("gitdir:**/r[[:lower:]]po/.git", true),
            ("gitdir/i:**/REPO/.GIT", true),
            ("gitdir:**/repo/", true),
            ("gitdir:**/repo/**/.git", true),
            ("gitdir:./repo/.git", true),
            ("gitdir:**/r\\epo/.git", true),
            ("onbranch:main", true),
            ("onbranch:m*", true),
            ("onbranch:m[ae]in", true),
            ("onbranch:other", false),
            ("onbranch:main/", false),
        ] {
            assert_eq!(
                rules
                    .include_matches(condition.as_bytes(), &source)
                    .unwrap(),
                expected,
                "{condition}"
            );
            let key = format!("includeif.{condition}.path").into_bytes();
            std::fs::write(
                &source,
                serialize_config(&[(key, Some(path_bytes(&included)))]).unwrap(),
            )
            .unwrap();
            let native = std::process::Command::new("git")
                .arg("-C")
                .arg(&root)
                .arg("config")
                .arg("--file")
                .arg(&source)
                .args(["--includes", "--get", "probe.enabled"])
                .env_remove("GIT_CONFIG_COUNT")
                .env_remove("GIT_CONFIG_PARAMETERS")
                .output()
                .unwrap();
            assert!(
                matches!(native.status.code(), Some(0 | 1)),
                "{condition}: {:?}",
                native
            );
            assert_eq!(native.status.success(), expected, "native {condition}");
        }
    }
}
